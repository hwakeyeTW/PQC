"""Private SSH S1 static acquisition; no native SSH execution or dispatch.

The fixed config/public-key grammar is carried forward from #17. The caller
owns eligibility and authorization; only one closed file slot is acquired.
"""
import base64
import binascii
import hashlib
import json
import os
import re
import signal
import stat
import struct
import sys
import time
import zipimport

from ansible.module_utils.basic import AnsibleModule

STAGES = ('config', 'keys')
ROOT_DIRECTORY = '/'
_TRUSTED_UID = 0
INNER_SECONDS = 23
# Shared runner reserves one second for cleanup: work <=27s, total <=28s.
STAGE_SECONDS = 28
SLOT_BYTES = 256 * 1024
CHILD_BYTES = SLOT_BYTES + 1
WIRE_BYTES = 1024 * 1024
NATIVE_Q_QUALIFIED = False
NATIVE_T_QUALIFIED = False
_MODULE_NAMES = ('ansible.legacy.pqc_ssh_acquire', 'ansible.modules.pqc_ssh_acquire',
                 'ansible_collections.security.compliance_pqc_readiness.plugins.modules.pqc_ssh_acquire')
_CHILD = ('import importlib,sys; sys.path.insert(0,sys.argv[1]); '
          'importlib.import_module(sys.argv[2])._child(sys.argv[3])')
_REASONS = {
    'COMMAND_OK', 'INVALID_COMMAND_CONTRACT', 'PROCESS_CONTROL_UNAVAILABLE',
    'COMMAND_START_FAILED', 'COMMAND_FAILED', 'COMMAND_TIMEOUT', 'COMMAND_OUTPUT_LIMIT',
    'COMMAND_IO_FAILED', 'RESIDUAL_PROCESS', 'INTERRUPTED', 'REMOTE_CLEANUP_UNCONFIRMED',
}

LIMIT = 16384
MAX_ROWS = 256
MAX_CONFIG_ROWS = 512
TOKEN = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.+@-]{0,127}\Z', re.ASCII)
KEY_FILE = re.compile(r'ssh_host_[A-Za-z0-9_-]{1,64}_key\.pub\Z', re.ASCII)
DROPIN = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,100}\.conf\Z', re.ASCII)
SETTINGS = {'kexalgorithms', 'ciphers', 'macs', 'hostkeyalgorithms', 'pubkeyacceptedalgorithms',
            'pubkeyacceptedkeytypes', 'hostbasedacceptedalgorithms', 'hostbasedacceptedkeytypes',
            'casignaturealgorithms', 'gssapikexalgorithms'}
HAZARDS = {'hostkeyagent', 'authorizedkeyscommand', 'authorizedkeyscommanduser',
           'authorizedprincipalscommand', 'authorizedprincipalscommanduser', 'hostcertificate',
           'authorizedkeysfile', 'authorizedprincipalsfile', 'revokedkeys', 'trustedusercakeys',
           'forcecommand', 'subsystem', 'chrootdirectory', 'modulifile', 'banner', 'usepam'}
PATTERN = re.compile(r'[A-Za-z0-9*?][A-Za-z0-9_.+@*?-]{0,127}\Z', re.ASCII)
HEX = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
CONFIG_GAPS = {'SOURCE_MISSING', 'SOURCE_PERMISSION', 'SOURCE_UNSAFE', 'FORMAT_GAP',
               'INCLUDE_REJECTED', 'INCLUDE_REPEATED', 'INCLUDE_EMPTY', 'MATCH_UNRESOLVED',
               'NATIVE_DEPENDENCY', 'HOSTKEY_PATH_REJECTED'}
KEY_GAPS = {'SOURCE_MISSING', 'SOURCE_PERMISSION', 'SOURCE_UNSAFE', 'KEY_INVALID', 'KEY_TYPE_UNKNOWN'}

def result(state, reason, rc=None, rows=None, gaps=None):
    return dict(state=state, reason=reason, rc=rc, rows=[] if rows is None else rows,
                gaps=[] if gaps is None else sorted(set(gaps)))


def digest(prefix, parts):
    wire = json.dumps(parts, ensure_ascii=True, separators=(',', ':')).encode('ascii')
    return prefix + '-' + hashlib.sha256(wire).hexdigest()


def key_ref(name):
    return digest('key', ['ssh-host-public-source-v1', name])


def trusted(st):
    return st.st_uid == _TRUSTED_UID and not st.st_mode & 0o022


class ReadFailure(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


class LimitFailure(ReadFailure):
    pass


def signature(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_nlink, st.st_uid, st.st_gid,
            st.st_size, st.st_mtime_ns, st.st_ctime_ns)


class Reader:
    """Linux descriptor-anchored bounded read. No arbitrary paths from a caller.

    O_PATH pins the inode before opening for data; reject links, special files,
    hard links and drift before any read. /proc/self/fd refers only to our FD.
    Directory and file identities are checked again after the whole traversal.
    """
    def __init__(self, root, aggregate, purpose):
        self.purpose = purpose
        self.root = root
        self.aggregate = aggregate
        self.total = 0
        initial = os.fstat(root)
        if not stat.S_ISDIR(initial.st_mode) or not trusted(initial):
            raise ReadFailure('SOURCE_UNSAFE')
        self.dirs = {(): (root, signature(initial))}
        self.files = {}
        self.listings = {}
        self.end = time.monotonic() + INNER_SECONDS

    def __enter__(self):
        return self

    def __exit__(self, *_):
        for parts, (fd, _) in reversed(list(self.dirs.items())):
            if parts:
                os.close(fd)

    def deadline(self):
        if time.monotonic() >= self.end:
            raise LimitFailure('TIMEOUT')

    def directory(self, parts):
        allowed = {(), ('etc',), ('etc', 'ssh')}
        if self.purpose == 'config':
            allowed.update({('etc', 'ssh', 'sshd_config.d'), ('etc', 'crypto-policies'),
                            ('etc', 'crypto-policies', 'back-ends')})
        if parts not in allowed:
            raise ReadFailure('SOURCE_UNSAFE')
        self.deadline()
        if parts in self.dirs:
            return self.dirs[parts][0]
        parent = self.directory(parts[:-1])
        fd = os.open(parts[-1], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=parent)
        try:
            st = os.fstat(fd)
            if not trusted(st):
                raise ReadFailure('SOURCE_UNSAFE')
            if not stat.S_ISDIR(st.st_mode) or signature(os.stat(parts[-1], dir_fd=parent,
                                                                  follow_symlinks=False)) != signature(st):
                raise LimitFailure('SOURCE_DRIFT')
            self.dirs[parts] = (fd, signature(st))
            return fd
        except BaseException:
            os.close(fd)
            raise

    def names(self, parts):
        if parts not in self.listings:
            fd = self.directory(parts)
            names = []
            with os.scandir(fd) as entries:
                for entry in entries:
                    self.deadline()
                    if len(names) >= 256:
                        raise LimitFailure('DIRECTORY_LIMIT')
                    names.append(entry.name)
            self.listings[parts] = sorted(names)
        return self.listings[parts]

    def read(self, parts, name):
        self.deadline()
        if self.purpose == 'keys':
            allowed = parts == ('etc', 'ssh') and KEY_FILE.fullmatch(name)
        else:
            allowed = ((parts == ('etc', 'ssh') and name == 'sshd_config') or
                       (parts == ('etc', 'ssh', 'sshd_config.d') and DROPIN.fullmatch(name)) or
                       (parts == ('etc', 'crypto-policies', 'back-ends') and name == 'opensshserver.config'))
        if not allowed:
            raise ReadFailure('SOURCE_UNSAFE')
        fd = self.directory(parts)
        pin = os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        try:
            st = os.fstat(pin)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or not trusted(st):
                raise ReadFailure('SOURCE_UNSAFE')
            if st.st_size > LIMIT or self.total + st.st_size > self.aggregate:
                raise LimitFailure('INPUT_LIMIT')
            expected = signature(st)
            try:
                path_signature = signature(os.stat(name, dir_fd=fd, follow_symlinks=False))
            except OSError:
                raise LimitFailure('SOURCE_DRIFT') from None
            if path_signature != expected:
                raise LimitFailure('SOURCE_DRIFT')
            data_fd = os.open('/proc/self/fd/' + str(pin), os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
            try:
                if signature(os.fstat(data_fd)) != expected:
                    raise LimitFailure('SOURCE_DRIFT')
                data = bytearray()
                while len(data) <= st.st_size:
                    self.deadline()
                    chunk = os.read(data_fd, min(4096, st.st_size + 1 - len(data)))
                    if not chunk:
                        break
                    data.extend(chunk)
                if len(data) != st.st_size or signature(os.fstat(data_fd)) != expected:
                    raise LimitFailure('SOURCE_DRIFT')
            finally:
                os.close(data_fd)
            self.total += len(data)
            self.files[(parts, name)] = expected
            return bytes(data)
        finally:
            os.close(pin)

    def verify(self):
        try:
            for parts, (fd, expected) in self.dirs.items():
                self.deadline()
                if signature(os.fstat(fd)) != expected:
                    raise LimitFailure('SOURCE_DRIFT')
                if parts and signature(os.stat(parts[-1], dir_fd=self.dirs[parts[:-1]][0],
                                               follow_symlinks=False)) != expected:
                    raise LimitFailure('SOURCE_DRIFT')
            for (parts, name), expected in self.files.items():
                self.deadline()
                if signature(os.stat(name, dir_fd=self.dirs[parts][0], follow_symlinks=False)) != expected:
                    raise LimitFailure('SOURCE_DRIFT')
        except OSError:
            raise LimitFailure('SOURCE_DRIFT') from None


def read_gap(exc):
    if isinstance(exc, ReadFailure):
        return exc.code
    if isinstance(exc, FileNotFoundError):
        return 'SOURCE_MISSING'
    if isinstance(exc, PermissionError):
        return 'SOURCE_PERMISSION'
    return 'SOURCE_UNSAFE'


def collect_config(root):
    ssh = ('etc', 'ssh')
    drop = ssh + ('sshd_config.d',)
    backend = ('etc', 'crypto-policies', 'back-ends')
    rows, gaps, seen = [], set(), set()
    with Reader(root, 65536, 'config') as reader:
        def emit(kind, src, line, ctx, **payload):
            if len(rows) >= MAX_CONFIG_ROWS:
                raise LimitFailure('ROW_LIMIT')
            rows.append(dict(kind=kind, order=len(rows), source_ref=src, line=line,
                             context_ref=ctx, **payload))

        def visit(parts, name, kind, parent, include_line, depth, ctx):
            if depth > 4 or len(seen) >= 32:
                raise LimitFailure('SOURCE_LIMIT')
            identity = (parts, name)
            if identity in seen:
                gaps.add('INCLUDE_REPEATED')
                return ctx
            seen.add(identity)
            try:
                raw = reader.read(parts, name)
            except LimitFailure:
                raise
            except (ReadFailure, OSError) as exc:
                gaps.add(read_gap(exc))
                return ctx
            if b'PRIVATE KEY-----' in raw or b'\x00' in raw:
                gaps.add('SOURCE_UNSAFE')
                return ctx
            raw = raw.replace(b'\r\n', b'\n')
            if any(x < 32 and x not in (9, 10) or x == 127 for x in raw):
                gaps.add('FORMAT_GAP')
                return ctx
            try:
                lines = raw.decode('utf-8').split('\n')
            except UnicodeError:
                gaps.add('FORMAT_GAP')
                return ctx
            ref = digest('src', ['ssh-config-v1', list(parts), name])
            emit('SOURCE', ref, 0, ctx, source_kind=kind, parent_ref=parent,
                 include_line=include_line, depth=depth)
            for number, raw_line in enumerate(lines, 1):
                reader.deadline()
                line = raw_line.strip(' \t')
                if not line or line.startswith('#'):
                    continue
                match = re.fullmatch(r'([A-Za-z][A-Za-z0-9]*)(?:[ \t]*=[ \t]*|[ \t]+)(.*)', line)
                if not match:
                    gaps.add('FORMAT_GAP')
                    continue
                setting, value = match[1].lower(), match[2].strip(' \t')
                if setting == 'match':
                    ctx = digest('ctx', [ref, number])
                    emit('MATCH', ref, number, ctx, match_kind='ALL' if value.lower() == 'all' else 'CONDITIONAL')
                    if value.lower() != 'all':
                        gaps.add('MATCH_UNRESOLVED')
                elif setting == 'include':
                    # No shlex, glob expansion or arbitrary path evaluation. Only exact approved forms.
                    args = value.split()
                    if not args or any(x not in ('/etc/ssh/sshd_config.d/*.conf', 'sshd_config.d/*.conf',
                        '/etc/crypto-policies/back-ends/opensshserver.config') for x in args):
                        emit('INCLUDE', ref, number, ctx, outcome='REJECTED')
                        gaps.add('INCLUDE_REJECTED')
                        continue
                    emit('INCLUDE', ref, number, ctx, outcome='ALLOWLISTED')
                    for arg in args:
                        if arg.endswith('/*.conf'):
                            try:
                                names = reader.names(drop)
                            except LimitFailure:
                                raise
                            except (ReadFailure, OSError) as exc:
                                gaps.add(read_gap(exc))
                                continue
                            candidates = [n for n in names if n.endswith('.conf') and not n.startswith('.')]
                            if not candidates:
                                gaps.add('INCLUDE_EMPTY')
                            for candidate in candidates:
                                if not DROPIN.fullmatch(candidate):
                                    gaps.add('SOURCE_UNSAFE')
                                    continue
                                ctx = visit(drop, candidate, 'DROPIN', ref, number, depth + 1, ctx)
                        else:
                            ctx = visit(backend, 'opensshserver.config', 'POLICY_BACKEND', ref, number, depth + 1, ctx)
                elif setting in SETTINGS:
                    op = value[0] if value and value[0] in '+-^' else ''
                    names = (value[1:] if op else value).split(',')
                    # Preserve operator/wildcard as declarations only; no evaluation.
                    if len(names) > MAX_ROWS:
                        raise LimitFailure('ROW_LIMIT')
                    if not all(re.fullmatch(r'[A-Za-z0-9*?][A-Za-z0-9_.+@*?-]{0,127}', n, re.ASCII) for n in names):
                        gaps.add('FORMAT_GAP')
                        continue
                    if len(set(names)) != len(names):
                        gaps.add('FORMAT_GAP')
                        continue
                    emit('DIRECTIVE', ref, number, ctx, setting=setting, operator=op or 'EXACT', values=names)
                elif setting == 'hostkey':
                    name = value.removeprefix('/etc/ssh/') + '.pub'
                    if value.startswith('/etc/ssh/') and KEY_FILE.fullmatch(name):
                        emit('KEY_REFERENCE', ref, number, ctx, key_source_ref=key_ref(name))
                    else:
                        emit('HAZARD', ref, number, ctx, hazard='HOSTKEY_PATH_REJECTED')
                        gaps.add('HOSTKEY_PATH_REJECTED')
                elif setting in HAZARDS:
                    emit('HAZARD', ref, number, ctx, hazard='NATIVE_DEPENDENCY')
                    gaps.add('NATIVE_DEPENDENCY')
            return ctx

        try:
            visit(ssh, 'sshd_config', 'MAIN', None, None, 0, 'global-default')
            reader.verify()
        except LimitFailure as exc:
            return result('ERROR', exc.code)
        except OSError:
            return result('ERROR', 'SOURCE_DRIFT')
    if not rows:
        code = 'SOURCE_PERMISSION' if 'SOURCE_PERMISSION' in gaps else 'SOURCE_MISSING' if 'SOURCE_MISSING' in gaps else 'SOURCE_UNSAFE' if 'SOURCE_UNSAFE' in gaps else 'UNRECOGNIZED_OUTPUT'
        return result('PERMISSION_DENIED' if code == 'SOURCE_PERMISSION' else 'UNKNOWN', code)
    return result('PARTIAL' if gaps else 'COLLECTED', 'CONFIG_GAP' if gaps else 'OK', rows=rows, gaps=gaps)


def parse_public(raw):
    # No PEM, private-key marker, comments, raw base64 or wire bytes are exported.
    if b'PRIVATE KEY-----' in raw or b'\x00' in raw or len(raw) > LIMIT:
        raise ReadFailure('KEY_INVALID')
    line = raw[:-1] if raw.endswith(b'\n') else raw
    if raw.endswith(b'\r\n'):
        line = line[:-1]
    if any(x < 32 and x != 9 or x == 127 for x in line):
        raise ReadFailure('KEY_INVALID')
    fields = re.split(rb'[ \t]+', line, maxsplit=2)
    try:
        if len(fields) < 2:
            raise ValueError
        name = fields[0].decode('ascii')
        if not TOKEN.fullmatch(name) or not name.startswith(('ssh-', 'ecdsa-', 'sk-')) or 'private' in name.lower():
            raise ValueError
        wire = base64.b64decode(fields[1], validate=True)
        if base64.b64encode(wire) != fields[1]:
            raise ValueError
        offset = 0

        def string():
            nonlocal offset
            if offset + 4 > len(wire):
                raise ValueError
            length = struct.unpack_from('>I', wire, offset)[0]
            offset += 4
            if length > LIMIT or offset + length > len(wire):
                raise ValueError
            item = wire[offset:offset + length]
            offset += length
            return item

        def positive():
            item = string()
            if not item or item[0] & 128 or (item[0] == 0 and (len(item) == 1 or not item[1] & 128)):
                raise ValueError
            return int.from_bytes(item, 'big').bit_length()

        if string() != fields[0]:
            raise ValueError
        bits = None
        if name == 'ssh-rsa':
            positive()
            bits = positive()
        elif name == 'ssh-dss':
            bits = positive()
            for _ in range(3):
                positive()
        elif name == 'ssh-ed25519':
            if len(string()) != 32:
                raise ValueError
            bits = 256
        elif name in ('ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521'):
            curve = name.removeprefix('ecdsa-sha2-')
            bits = int(curve[5:])
            if string() != curve.encode('ascii'):
                raise ValueError
            point = string()
            if len(point) != 1 + 2 * ((bits + 7) // 8) or point[:1] != b'\x04':
                raise ValueError
        else:
            # Unknown layout: validate only the type envelope and nonempty payload;
            # this remains a partial syntactic observation, not proof of key validity.
            if offset == len(wire):
                raise ValueError
        if bits is not None and (offset != len(wire) or not 1 <= bits <= 16384):
            raise ValueError
    except (ValueError, UnicodeError, binascii.Error, struct.error):
        raise ReadFailure('KEY_INVALID') from None
    return dict(key_type=name, bits=bits, fingerprint_sha256=hashlib.sha256(wire).hexdigest(),
                grammar='KNOWN' if bits is not None else 'UNKNOWN_TYPE')


def collect_keys(root):
    rows, gaps = [], set()
    parts = ('etc', 'ssh')
    with Reader(root, 524288, 'keys') as reader:
        try:
            names = reader.names(parts)
            candidates = [name for name in names if name.startswith('ssh_host_') and name.endswith('_key.pub')]
            if len(candidates) > 32:
                raise LimitFailure('SOURCE_LIMIT')
            for name in candidates:
                if not KEY_FILE.fullmatch(name):
                    gaps.add('SOURCE_UNSAFE')
                    continue
                try:
                    value = parse_public(reader.read(parts, name))
                except LimitFailure:
                    raise
                except (OSError, ReadFailure) as exc:
                    gaps.add(read_gap(exc))
                    continue
                if value['grammar'] == 'UNKNOWN_TYPE':
                    gaps.add('KEY_TYPE_UNKNOWN')
                rows.append(dict(source_ref=key_ref(name), **value))
            reader.verify()
        except LimitFailure as exc:
            return result('ERROR', exc.code)
        except (OSError, ReadFailure) as exc:
            code = read_gap(exc)
            return result('PERMISSION_DENIED' if code == 'SOURCE_PERMISSION' else 'UNKNOWN', code)
    if not rows and gaps:
        code = 'SOURCE_PERMISSION' if 'SOURCE_PERMISSION' in gaps else 'KEY_INVALID' if 'KEY_INVALID' in gaps else 'SOURCE_UNSAFE'
        return result('PERMISSION_DENIED' if code == 'SOURCE_PERMISSION' else 'UNKNOWN', code)
    return result('PARTIAL' if gaps else 'COLLECTED', 'KEY_GAP' if gaps else 'OK',
                  rows=sorted(rows, key=lambda r: r['source_ref']), gaps=gaps)


def require(ok, code='SSH_INPUT'):
    if not ok:
        raise ValueError(code)


def mapping(value, keys):
    require(type(value) is dict and value.keys() == set(keys))
    return value


def matches(value, pattern):
    return type(value) is str and bool(pattern.fullmatch(value))


def integer(value, lo, hi):
    return type(value) is int and lo <= value <= hi


def ref(value, prefix):
    return type(value) is str and value.startswith(prefix + '-') and matches(value[len(prefix) + 1:], HEX)


def context(value):
    return (type(value) is str and value == 'global-default') or ref(value, 'ctx')


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')


def validate_config(rows, gaps):
    require(1 <= len(rows) <= 512 and type(rows[0]) is dict and rows[0].get('kind') == 'SOURCE')
    sources, lines, stack, includes = {}, {}, [], set()
    current = 'global-default'
    required_gaps = set()
    common = {'kind', 'order', 'source_ref', 'line', 'context_ref'}
    shapes = {'SOURCE': {'source_kind', 'parent_ref', 'include_line', 'depth'},
              'MATCH': {'match_kind'}, 'INCLUDE': {'outcome'},
              'DIRECTIVE': {'setting', 'operator', 'values'},
              'KEY_REFERENCE': {'key_source_ref'}, 'HAZARD': {'hazard'}}
    for index, row in enumerate(rows):
        require(type(row) is dict and type(row.get('kind')) is str and row['kind'] in shapes)
        kind = row['kind']
        mapping(row, common | shapes[kind])
        src, line, ctx = row['source_ref'], row['line'], row['context_ref']
        require(integer(row['order'], index, index) and ref(src, 'src') and integer(line, 0, 16384) and context(ctx))
        if kind == 'SOURCE':
            require(line == 0 and src not in sources and len(sources) < 32 and ctx == current)
            parent, depth, inc = row['parent_ref'], row['depth'], row['include_line']
            require(integer(depth, 0, 4))
            if index == 0:
                require(parent is None and inc is None and depth == 0 and row['source_kind'] == 'MAIN' and
                        src == digest('src', ['ssh-config-v1', ['etc', 'ssh'], 'sshd_config']))
            else:
                require(ref(parent, 'src') and parent in stack and integer(inc, 1, 16384) and
                        (parent, inc) in includes and lines[parent] == inc and
                        row['source_kind'] in ('DROPIN', 'POLICY_BACKEND') and depth == sources[parent] + 1)
                stack = stack[:stack.index(parent) + 1]
                if row['source_kind'] == 'POLICY_BACKEND':
                    require(src == digest('src', ['ssh-config-v1', ['etc', 'crypto-policies', 'back-ends'],
                                                  'opensshserver.config']))
            sources[src], lines[src] = depth, 0
            stack.append(src)
            continue
        require(src in stack and line > lines[src])
        stack = stack[:stack.index(src) + 1]
        lines[src] = line
        if kind == 'MATCH':
            require(row['match_kind'] in ('ALL', 'CONDITIONAL') and ctx == digest('ctx', [src, line]))
            current = ctx
            if row['match_kind'] == 'CONDITIONAL':
                required_gaps.add('MATCH_UNRESOLVED')
        else:
            require(ctx == current)
            if kind == 'INCLUDE':
                require(row['outcome'] in ('ALLOWLISTED', 'REJECTED'))
                if row['outcome'] == 'ALLOWLISTED':
                    includes.add((src, line))
                else:
                    required_gaps.add('INCLUDE_REJECTED')
            elif kind == 'DIRECTIVE':
                require(type(row['setting']) is str and row['setting'] in SETTINGS and
                        row['operator'] in ('EXACT', '+', '-', '^'))
                names = row['values']
                require(type(names) is list and 1 <= len(names) <= 256 and
                        all(matches(n, PATTERN) for n in names) and len(set(names)) == len(names))
            elif kind == 'KEY_REFERENCE':
                require(ref(row['key_source_ref'], 'key'))
            elif kind == 'HAZARD':
                require(row['hazard'] in ('HOSTKEY_PATH_REJECTED', 'NATIVE_DEPENDENCY'))
                required_gaps.add(row['hazard'])
    require(required_gaps <= set(gaps))


def validate_keys(rows, gaps):
    require(len(rows) <= 32)
    seen, fingerprints = set(), {}
    fixed = {'ssh-ed25519': 256, 'ecdsa-sha2-nistp256': 256, 'ecdsa-sha2-nistp384': 384,
             'ecdsa-sha2-nistp521': 521}
    for row in rows:
        mapping(row, {'source_ref', 'key_type', 'bits', 'fingerprint_sha256', 'grammar'})
        name, bits, fp, src, grammar = (row[k] for k in ('key_type', 'bits', 'fingerprint_sha256', 'source_ref', 'grammar'))
        require(ref(src, 'key') and src not in seen and matches(name, TOKEN) and
                name.startswith(('ssh-', 'ecdsa-', 'sk-')) and 'private' not in name.lower() and matches(fp, HEX))
        seen.add(src)
        if name in fixed or name in ('ssh-rsa', 'ssh-dss'):
            require(grammar == 'KNOWN' and integer(bits, 1, 16384) and (name not in fixed or bits == fixed[name]))
        else:
            require(grammar == 'UNKNOWN_TYPE' and bits is None and 'KEY_TYPE_UNKNOWN' in gaps)
        key = (name, bits, grammar)
        require(fp not in fingerprints or fingerprints[fp] == key, 'SSH_FINGERPRINT_CONFLICT')
        fingerprints[fp] = key
    require([r['source_ref'] for r in rows] == sorted(seen))


def _stage(stage):
    require(type(stage) is str and stage in STAGES)
    return stage


def _slot_payload(stage, slot):
    _stage(stage)
    mapping(slot, {'state', 'reason', 'rc', 'rows', 'gaps'})
    state, reason, rc, rows, gaps = (slot[k] for k in ('state', 'reason', 'rc', 'rows', 'gaps'))
    require(type(state) is str and type(reason) is str and rc is None)
    require(type(rows) is list and len(rows) <= MAX_CONFIG_ROWS and type(gaps) is list and len(gaps) <= 16
            and all(type(x) is str for x in gaps) and gaps == sorted(set(gaps)))
    if state in ('COLLECTED', 'PARTIAL'):
        require(bool(rows) or (state == 'COLLECTED' and stage == 'keys'))
        require((state == 'PARTIAL') == bool(gaps))
        require(reason == ('OK' if state == 'COLLECTED' else 'CONFIG_GAP' if stage == 'config' else 'KEY_GAP'))
        require(set(gaps) <= (CONFIG_GAPS if stage == 'config' else KEY_GAPS))
        (validate_config if stage == 'config' else validate_keys)(rows, gaps)
    else:
        require(not rows and not gaps)
        require((state == 'ERROR' and reason in ('INPUT_LIMIT', 'SOURCE_LIMIT', 'DIRECTORY_LIMIT', 'SOURCE_DRIFT',
                                                   'ROW_LIMIT', 'TIMEOUT', 'OUTPUT_LIMIT', 'EXECUTION_ERROR'))
                or (state == 'UNKNOWN' and reason in ('SOURCE_MISSING', 'SOURCE_UNSAFE',
                                                      'UNRECOGNIZED_OUTPUT' if stage == 'config' else 'KEY_INVALID'))
                or (state == 'PERMISSION_DENIED' and reason == 'SOURCE_PERMISSION'))


def _acquire(stage):
    _stage(stage)
    try:
        root = os.open(ROOT_DIRECTORY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            return collect_config(root) if stage == 'config' else collect_keys(root)
        finally:
            os.close(root)
    except LimitFailure as exc:
        return result('ERROR', exc.code)
    except (ReadFailure, OSError) as exc:
        code = read_gap(exc)
        return result('PERMISSION_DENIED' if code == 'SOURCE_PERMISSION' else 'UNKNOWN', code)


def _json_bytes(value):
    return canonical(value)


def _decode(raw):
    def unique(pairs):
        value = dict(pairs)
        require(len(value) == len(pairs))
        return value

    def reject(_):
        raise ValueError('INVALID_SSH_STAGE_RECEIPT')

    require(type(raw) is bytes and len(raw) <= CHILD_BYTES and raw.endswith(b'\n'))
    value = json.loads(raw.decode('ascii'), object_pairs_hook=unique, parse_constant=reject, parse_float=reject)
    require(canonical(value) + b'\n' == raw)
    return value


def _receipt(stage, reason, rc, clean, payload):
    return dict(format=1, stage=stage, reason_code=reason, rc=rc, cleanup_confirmed=clean, payload=payload)


def _wrapper_size(receipt):
    # Native Ansible's normal result JSON includes invocation and two LFs.
    frame = dict(changed=False, receipt=receipt, invocation={'module_args': {'stage': receipt['stage']}})
    return len(json.dumps(frame, ensure_ascii=True, allow_nan=False).encode('ascii')) + 2


# Exact fixed envelope overhead for a compact maximum slot. In normal JSON
# each separator adds at most one space per compact slot byte; this is a
# conservative stage allocation, while _wrapper_size measures the exact frame.
RECEIPT_BYTES = SLOT_BYTES + max(len(canonical(_receipt(s, 'COMMAND_OK', 0, True, None))) - 4 for s in STAGES)
WRAPPER_BYTES = 2 * SLOT_BYTES + max(_wrapper_size(_receipt(s, 'COMMAND_OK', 0, True, None)) - 4 for s in STAGES)
assert RECEIPT_BYTES < WRAPPER_BYTES < WIRE_BYTES


def _fits(receipt):
    return len(canonical(receipt)) <= RECEIPT_BYTES and _wrapper_size(receipt) <= WRAPPER_BYTES


def validate_receipt(receipt, stage):
    """Closed S1 receipt, not authority to dispatch or evidence of host identity."""
    _stage(stage)
    mapping(receipt, ('format', 'stage', 'reason_code', 'rc', 'cleanup_confirmed', 'payload'))
    require(type(receipt['format']) is int and receipt['format'] == 1 and receipt['stage'] == stage)
    reason, rc, clean, payload = (receipt[k] for k in ('reason_code', 'rc', 'cleanup_confirmed', 'payload'))
    require(type(reason) is str and reason in _REASONS and (rc is None or integer(rc, -255, 255)) and type(clean) is bool)
    require(clean == (reason not in ('PROCESS_CONTROL_UNAVAILABLE', 'REMOTE_CLEANUP_UNCONFIRMED')))
    if reason == 'COMMAND_OK':
        require(type(rc) is int and rc == 0 and clean)
        _slot_payload(stage, payload)
        require(len(canonical(payload)) <= SLOT_BYTES)
    else:
        require(payload is None)
        if reason in ('INVALID_COMMAND_CONTRACT', 'PROCESS_CONTROL_UNAVAILABLE', 'COMMAND_START_FAILED'):
            require(rc is None)
        if reason == 'COMMAND_FAILED':
            require(type(rc) is int and rc != 0)
        if reason in ('COMMAND_TIMEOUT', 'COMMAND_OUTPUT_LIMIT', 'COMMAND_IO_FAILED', 'RESIDUAL_PROCESS'):
            require(type(rc) is int)
    require(_fits(receipt))
    return receipt


def _payload_archive():
    spec = __spec__
    require(spec is not None and spec.name in _MODULE_NAMES and isinstance(spec.loader, zipimport.zipimporter))
    archive = spec.loader.archive
    require(os.path.isabs(archive) and spec.origin == archive + '/' + spec.name.replace('.', '/') + '.py')
    parent = os.lstat(os.path.dirname(archive))
    entry = os.lstat(archive)
    require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid() and parent.st_mode & 0o077 == 0)
    require(stat.S_ISREG(entry.st_mode) and entry.st_uid == os.geteuid() and entry.st_nlink == 1 and entry.st_mode & 0o022 == 0)
    return archive


def _bounded_runner(archive):
    if __spec__.name == _MODULE_NAMES[-1]:
        from ansible_collections.security.compliance_pqc_readiness.plugins.module_utils import pqc_bounded_execution as helper
    else:
        from ansible.module_utils import pqc_bounded_execution as helper
    loader = getattr(getattr(helper, '__spec__', None), 'loader', None)
    require(isinstance(loader, zipimport.zipimporter) and loader.archive == archive)
    return helper._run_bounded


def _child_argv(stage):
    archive = _payload_archive()
    require(os.path.isabs(sys.executable))
    return [sys.executable, '-I', '-S', '-B', '-c', _CHILD, archive, __spec__.name, _stage(stage)]


def _from_result(stage, outcome):
    payload = None
    if outcome.reason_code == 'COMMAND_OK':
        require(outcome.stderr == b'' and outcome.cleanup_confirmed is True)
        payload = _decode(outcome.stdout)
    else:
        require(outcome.stdout == outcome.stderr == b'')
    return validate_receipt(_receipt(stage, outcome.reason_code, outcome.rc, outcome.cleanup_confirmed, payload), stage)


def _run_stage(stage):
    argv = _child_argv(stage)
    return _from_result(stage, _bounded_runner(argv[6])(argv, STAGE_SECONDS, CHILD_BYTES))


def _typed_payload(stage, payload):
    _slot_payload(stage, payload)
    if len(canonical(payload)) > SLOT_BYTES or not _fits(_receipt(stage, 'COMMAND_OK', 0, True, payload)):
        payload = result('ERROR', 'OUTPUT_LIMIT')
    validate_receipt(_receipt(stage, 'COMMAND_OK', 0, True, payload), stage)
    return payload


def _alarm(_signum, _frame):
    raise LimitFailure('TIMEOUT')


def _child(stage):
    _stage(stage)
    _payload_archive()
    require(sys.platform == 'linux' and sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode)
    end = time.monotonic() + INNER_SECONDS
    signal.signal(signal.SIGALRM, _alarm)
    signal.setitimer(signal.ITIMER_REAL, INNER_SECONDS)
    try:
        raw = canonical(_typed_payload(stage, _acquire(stage))) + b'\n'
        if time.monotonic() >= end:
            raise LimitFailure('TIMEOUT')
    except LimitFailure:
        raw = canonical(result('ERROR', 'TIMEOUT')) + b'\n'
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
    require(len(raw) <= CHILD_BYTES)
    sys.stdout.buffer.write(raw)


def main():
    module = AnsibleModule(argument_spec={'stage': dict(type='str', required=True, choices=list(STAGES))},
                           supports_check_mode=True, no_log=True)
    try:
        receipt = _run_stage(_stage(module.params['stage']))
    except (ImportError, OSError, ValueError, TypeError, AttributeError, KeyError, RecursionError):
        module.fail_json(changed=False, msg='SSH_STAGE_CONTRACT_FAILED')
    module.exit_json(changed=False, receipt=receipt)


if __name__ == '__main__':
    main()
