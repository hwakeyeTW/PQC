"""PQC M0-08 S1: private Controller run store. No dispatch or public CLI.

The caller supplies authorized scope and typed data, not file names or loaders.
Linux local POSIX only. The final manifest is the immutable commit marker.
"""
from collections import Counter
from contextlib import contextmanager
import ctypes
from datetime import datetime, timezone
import errno
import fcntl
from functools import wraps
import hashlib
import json
import math
import os
import re
import secrets
import stat
import sys
import time
from typing import NamedTuple

from tools import assessment, evidence

VERSION = '1.0.0'
MAX_EVIDENCE = 32 * 1024 * 1024
MAX_DETAIL = 1024 * 1024
MAX_CFF = 128 * 1024 * 1024
MAX_CORE = 256 * 1024 * 1024
MAX_MANIFEST = 16 * 1024 * 1024
MAX_CHECKPOINT = MAX_EVIDENCE + 8 * MAX_DETAIL
MAX_SLOTS = 8192
MAX_ROOT_ENTRIES = 100000
MAX_STAGES = 4
HOST_STATES = evidence.HOST_STATES
RUN_STATES = ('COMPLETE', 'PARTIAL', 'ERROR')
KINDS = {'NATIVE_SCAN': 'NATIVE_COLLECTOR', 'LEGACY_IMPORT': 'LEGACY_IMPORT',
         'SYNTHETIC': 'SYNTHETIC'}
COLLECTORS = ('packages', 'openssl', 'sshd', 'ssh_host_keys', 'system_certs',
              'crypto_policy', 'nginx_certs', 'tls_services')
DETAIL_SLOTS = ('platform', 'openssl-runtime', 'crypto-policy', 'ssh-posture',
                'certificate-inventory', 'service-inventory')
FORMATS = ('legacy-per-host', 'legacy-fleet', 'legacy-ol-run-summary')
STATES = evidence.ACQUISITIONS
GOOD = frozenset(('COLLECTED', 'PARTIAL', 'NOT_APPLICABLE'))
HEX = r'[0-9a-f]{64}'
RID = r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}'
TARGET = r'[A-Za-z0-9_:][A-Za-z0-9_.:@+-]{0,511}'
SLUG = r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}'
REASON = r'[A-Z][A-Z0-9_]{0,95}'
RESERVED = {'con', 'prn', 'aux', 'nul', *(f'com{i}' for i in range(1, 10)),
            *(f'lpt{i}' for i in range(1, 10))}
FILES = {'evidence': ('evidence.json', MAX_EVIDENCE),
         'assessed': ('assessed_evidence.json', MAX_EVIDENCE),
         'rules': ('assessment_rules.json', 64 * 1024),
         'batch': ('batch_manifest.json', MAX_MANIFEST),
         'cff': ('cff_projection.json', MAX_CFF),
         'legacy': ('legacy_provenance.json', MAX_DETAIL)}
# Local Linux filesystem types. Overlay/tmpfs are useful for engineering only;
# this list is not a claim of persistence or of production mount approval.
LOCAL_FS = {0xEF53, 0x58465342, 0x9123683E, 0x01021994, 0x794C7630}
SECRET_KEYS = {'privatekey', 'privatekeydata', 'privatekeyfile', 'password',
               'passwd', 'passphrase', 'credentials', 'credential', 'token',
               'apikey', 'secret', 'hostvars', 'rawhostvars', 'groupvars',
               'inventory', 'inventorydata', 'ansiblepassword', 'ansiblesshpass',
               'ansiblebecomepassword', 'ansiblesshprivatekeyfile'}


class StoreError(ValueError):
    """Fixed reason only; never echoes a path or input value."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)


class PublishedRun(NamedTuple):
    manifest: dict
    document: dict
    assessed: dict | None
    artifacts: dict


def require(ok, code='INVALID_STORE_DATA'):
    if not ok:
        raise StoreError(code)


def _public(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except StoreError as exc:
            if args and isinstance(args[0], RunWriter) and exc.code in {
                    'SIZE_LIMIT', 'JSON_LIMIT', 'CORE_SIZE_LIMIT', 'ARTIFACT_SIZE',
                    'SLOT_LIMIT', 'DIRECTORY_LIMIT', 'RECOVERY_STAGE_LIMIT',
                    'DURABILITY_UNCONFIRMED', 'STORE_IO', 'UNSAFE_DIRECTORY',
                    'UNSAFE_FILE', 'UNSUPPORTED_ATOMIC_PUBLISH', 'UNSUPPORTED_LOCK',
                    'CORRUPT_CHECKPOINT', 'FOREIGN_CHECKPOINT'}:
                args[0]._poisoned = True
            raise
        except OSError:
            if args and isinstance(args[0], RunWriter): args[0]._poisoned = True
            raise StoreError('STORE_IO') from None
        except evidence.EvidenceError as exc:
            if args and isinstance(args[0], RunWriter) and exc.code in ('SIZE_LIMIT', 'DEPTH_LIMIT'):
                args[0]._poisoned = True
            raise StoreError('EVIDENCE_' + exc.code) from None
        except assessment.AssessmentError as exc:
            raise StoreError('ASSESSMENT_' + exc.code) from None
    return wrapped


def _match(v, pattern):
    return type(v) is str and re.fullmatch(pattern, v) is not None


def _keys(v, names):
    require(type(v) is dict and v.keys() == set(names.split()), 'INVALID_SHAPE')


def _enum(v, values):
    require(type(v) is str and v in values, 'INVALID_ENUM')


def _bool(v):
    require(type(v) is bool, 'INVALID_TYPE')


def _int(v, lo, hi):
    require(type(v) is int and lo <= v <= hi, 'INVALID_INTEGER')


def _reason(v):
    require(_match(v, REASON), 'INVALID_REASON')


def _rid(v):
    require(_match(v, RID) and v.casefold() not in RESERVED, 'INVALID_RUN_ID')
    return v


def _id(v, kind='host'):
    require(_match(v, re.escape(evidence.PREFIXES[kind]) + HEX), 'INVALID_ID')
    return v


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _json_bytes(value, limit=MAX_MANIFEST):
    """Bound plain data before serialization; no arbitrary object hooks."""
    nodes = 0
    def visit(v, depth):
        nonlocal nodes
        nodes += 1
        require(depth <= 64 and nodes <= 4000000, 'JSON_LIMIT')
        if type(v) is dict:
            for k, x in v.items():
                require(type(k) is str and len(k) <= 512, 'INVALID_TYPE')
                require(re.sub('[^a-z0-9]', '', k.lower()) not in SECRET_KEYS,
                        'FORBIDDEN_FIELD')
                visit(x, depth + 1)
        elif type(v) is list:
            for x in v:
                visit(x, depth + 1)
        elif type(v) is str:
            require(len(v) <= 4096, 'JSON_LIMIT')
            require(not re.search(r'-----BEGIN [^-\r\n]*PRIVATE KEY-----', v, re.I),
                    'FORBIDDEN_FIELD')
        elif type(v) is int:
            require(abs(v) <= 9007199254740991, 'INVALID_INTEGER')
        elif type(v) is float:
            require(math.isfinite(v), 'INVALID_TYPE')
        else:
            require(v is None or type(v) is bool, 'INVALID_TYPE')
    visit(value, 1)
    out = bytearray()
    try:
        for chunk in json.JSONEncoder(ensure_ascii=False, sort_keys=True,
                separators=(',', ':'), allow_nan=False).iterencode(value):
            data = chunk.encode('utf-8')
            require(len(out) + len(data) <= limit, 'SIZE_LIMIT')
            out.extend(data)
    except (UnicodeError, OverflowError):
        raise StoreError('INVALID_JSON') from None
    return bytes(out)


def _pairs(items):
    out = {}
    for k, v in items:
        require(k not in out, 'DUPLICATE_KEY')
        out[k] = v
    return out


def _loads(raw, limit=MAX_MANIFEST):
    require(type(raw) is bytes and len(raw) <= limit, 'SIZE_LIMIT')
    depth, quoted, escaped, structural = 0, False, False, 0
    for b in raw:
        if quoted:
            if escaped:
                escaped = False
            elif b == 92:
                escaped = True
            elif b == 34:
                quoted = False
        elif b == 34:
            quoted = True
        elif b in (91, 123):
            depth += 1; structural += 1
            require(depth <= 64 and structural <= 4000000, 'JSON_LIMIT')
        elif b in (93, 125):
            depth -= 1
        elif b in (44, 58):
            structural += 1
            require(structural <= 4000000, 'JSON_LIMIT')
    try:
        obj = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs)
    except StoreError:
        raise
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        raise StoreError('INVALID_JSON') from None
    _json_bytes(obj, limit)
    return obj


def _seal(body, limit):
    return _json_bytes({'body': body, 'sha256': _digest(_json_bytes(body, limit))}, limit)


def _unseal(raw, limit):
    wrapper = _loads(raw, limit)
    _keys(wrapper, 'body sha256')
    require(_seal(wrapper['body'], limit) == raw, 'CORRUPT_CHECKPOINT')
    return wrapper['body']


def _same(a, b, limit=MAX_MANIFEST):
    return _json_bytes(a, limit) == _json_bytes(b, limit)


def _canonical(doc):
    # Shared model remains authoritative; the store also rejects explicit secret
    # field names/PEM and bounds its own private JSON copies, not a general DLP.
    _json_bytes(doc, MAX_EVIDENCE)
    return evidence.canonical_bytes(doc)


def _evidence_bytes(raw):
    doc = evidence.parse_evidence_bytes(raw)
    require(_canonical(doc) == raw, 'NONCANONICAL_EVIDENCE')
    return doc


# Filesystem primitives. All names after the trusted root are generated here.
def _linux():
    require(sys.platform == 'linux' and hasattr(os, 'O_NOFOLLOW'), 'UNSUPPORTED_FILESYSTEM')
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        rename = libc.renameat2
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                           ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        fstatfs = libc.fstatfs
        fstatfs.argtypes = [ctypes.c_int, ctypes.c_void_p]
        fstatfs.restype = ctypes.c_int
    except (AttributeError, OSError):
        raise StoreError('UNSUPPORTED_FILESYSTEM') from None
    return rename, fstatfs


def _fs_type(fd):
    _, fstatfs = _linux()
    # Linux struct statfs starts with a native long f_type; allocate an aligned
    # buffer larger than the kernel ABI structure (no pathname lookup).
    buf = (ctypes.c_long * 64)()
    require(fstatfs(fd, ctypes.byref(buf)) == 0, 'UNSUPPORTED_FILESYSTEM')
    return buf[0] & 0xffffffff


def _check_dir(fd, device=None, *, ancestor=False):
    s = os.fstat(fd)
    require(stat.S_ISDIR(s.st_mode) and (device is None or s.st_dev == device),
            'UNSAFE_DIRECTORY')
    mode = stat.S_IMODE(s.st_mode)
    if ancestor:
        require(s.st_uid in (0, os.geteuid()) and
                (not mode & 0o022 or (s.st_uid == 0 and bool(mode & stat.S_ISVTX))),
                'UNSAFE_ANCESTOR')
    else:
        require(s.st_uid == os.geteuid() and mode == 0o700, 'UNSAFE_DIRECTORY')
    return s


def _open_dir(parent, name, device, *, ancestor=False):
    try:
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=parent)
    except FileNotFoundError:
        raise
    except OSError:
        raise StoreError('UNSAFE_DIRECTORY') from None
    try:
        _check_dir(fd, device, ancestor=ancestor)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _root(path):
    _linux()
    try: path = os.fspath(path)
    except TypeError: raise StoreError('INVALID_ROOT') from None
    require(type(path) is str and path.startswith('/') and len(path) <= 4096 and
            '\x00' not in path, 'INVALID_ROOT')
    parts = path[1:].split('/')
    require(all(p not in ('', '.', '..') for p in parts), 'INVALID_ROOT')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        _check_dir(fd, ancestor=True)
        for i, name in enumerate(parts):
            nxt = _open_dir(fd, name, None, ancestor=i < len(parts)-1)
            os.close(fd)
            fd = nxt
        require(_fs_type(fd) in LOCAL_FS, 'UNSUPPORTED_FILESYSTEM')
        return fd
    except BaseException:
        os.close(fd)
        raise


def _check_file_stat(s, device):
    require(stat.S_ISREG(s.st_mode) and s.st_dev == device and s.st_uid == os.geteuid()
            and stat.S_IMODE(s.st_mode) == 0o600 and s.st_nlink == 1,
            'UNSAFE_FILE')
    return s


def _stat_file(fd, device):
    return _check_file_stat(os.fstat(fd), device)


def _open_file(parent, name, device, flags=os.O_RDONLY):
    try:
        before = _check_file_stat(os.stat(name, dir_fd=parent, follow_symlinks=False), device)
        fd = os.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=parent)
    except FileNotFoundError:
        raise
    except OSError:
        raise StoreError('UNSAFE_FILE') from None
    try:
        after = _stat_file(fd, device)
        require(before.st_ino == after.st_ino, 'ARTIFACT_CHANGED')
        return fd
    except BaseException:
        os.close(fd)
        raise


def _exists(parent, name):
    try:
        os.stat(name, dir_fd=parent, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def _sync(fd):
    try:
        os.fsync(fd)
    except OSError:
        raise StoreError('DURABILITY_UNCONFIRMED') from None


def _mkdir(parent, name, device):
    os.mkdir(name, mode=0o700, dir_fd=parent)
    # Only the just-created exclusive directory in a checked private parent.
    # Do not change the process umask, or repair an existing destination.
    created = os.stat(name, dir_fd=parent, follow_symlinks=False)
    require(stat.S_ISDIR(created.st_mode) and created.st_uid == os.geteuid() and
            created.st_dev == device, 'UNSAFE_DIRECTORY')
    if stat.S_IMODE(created.st_mode) != 0o700:
        try: os.chmod(name, 0o700, dir_fd=parent, follow_symlinks=False)
        except (NotImplementedError, ValueError):
            raise StoreError('UNSUPPORTED_FILESYSTEM') from None
    fd = _open_dir(parent, name, device)
    try:
        require(os.fstat(fd).st_ino == created.st_ino, 'UNSAFE_DIRECTORY')
        _sync(fd)
        _sync(parent)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _new_file(parent, name, device):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                 os.O_CLOEXEC, 0o600, dir_fd=parent)
    try:
        # Only the freshly exclusively-created inode; never chmod an existing file.
        os.fchmod(fd, 0o600)
        _stat_file(fd, device)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read(parent, name, device, limit, size=None):
    fd = _open_file(parent, name, device)
    try:
        s = _stat_file(fd, device)
        require(0 <= s.st_size <= limit and (size is None or size == s.st_size),
                'ARTIFACT_SIZE')
        out = bytearray()
        while len(out) <= s.st_size:
            b = os.read(fd, min(1024*1024, s.st_size + 1 - len(out)))
            if not b:
                break
            out.extend(b)
        require(len(out) == s.st_size, 'ARTIFACT_SIZE')
        end = _stat_file(fd, device)
        require((s.st_size, s.st_mtime_ns, s.st_ctime_ns) ==
                (end.st_size, end.st_mtime_ns, end.st_ctime_ns), 'ARTIFACT_CHANGED')
        return bytes(out)
    finally:
        os.close(fd)


def _rename_noreplace(src_fd, src, dest_fd, dest):
    rename, _ = _linux()
    if rename(src_fd, os.fsencode(src), dest_fd, os.fsencode(dest), 1) != 0:
        err = ctypes.get_errno()
        if err == errno.EEXIST:
            raise StoreError('ALREADY_EXISTS')
        if err in (errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP, errno.EXDEV):
            raise StoreError('UNSUPPORTED_ATOMIC_PUBLISH')
        raise StoreError('STORE_IO')


def _write(parent, name, raw, device, *, replace_journal=False):
    # A temporary file is never a published artifact. Only journal.json may be
    # replaced, under the caller's exclusive per-run lock.
    temp = '.tmp-' + secrets.token_hex(16)
    fd = _new_file(parent, temp, device)
    try:
        try:
            view = memoryview(raw)
            while view:
                count = os.write(fd, view)
                require(count > 0, 'STORE_IO')
                view = view[count:]
            _sync(fd)
        finally:
            os.close(fd)
        if replace_journal:
            require(name == 'journal.json', 'INVALID_SLOT')
            check = _open_file(parent, name, device)
            os.close(check)
            os.replace(temp, name, src_dir_fd=parent, dst_dir_fd=parent)
        else:
            _rename_noreplace(parent, temp, parent, name)
        _sync(parent)
    finally:
        # This name was exclusively created by this invocation. Never delete a
        # destination or another writer's file. SIGKILL may leave a private temp.
        if _exists(parent, temp):
            os.unlink(temp, dir_fd=parent)
            _sync(parent)


def _lock_file(parent, name, device, *, create=False):
    if create:
        try:
            fd = _new_file(parent, name, device)
        except FileExistsError:
            pass
        else:
            try: _sync(fd)
            finally: os.close(fd)
            _sync(parent)
    return _open_file(parent, name, device, os.O_RDWR)


def _flock(fd, *, shared=False, wait=False):
    deadline = time.monotonic() + 5.0
    while True:
        try:
            fcntl.flock(fd, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            require(wait and time.monotonic() < deadline, 'RUN_BUSY')
            time.sleep(0.01)
        except OSError:
            raise StoreError('UNSUPPORTED_LOCK') from None


@contextmanager
def _directory(parent, components, device, *, create=False):
    fd = os.dup(parent)
    try:
        for name in components:
            try:
                nxt = _open_dir(fd, name, device)
            except FileNotFoundError:
                if not create:
                    raise
                nxt = _mkdir(fd, name, device)
            os.close(fd)
            fd = nxt
        yield fd
    finally:
        os.close(fd)


def _entries(fd, limit):
    names = []
    with os.scandir(fd) as it:
        for entry in it:
            require(len(names) < limit, 'DIRECTORY_LIMIT')
            names.append(entry.name)
    return names


# Frozen scope, synthetic B04 contract and typed attachment validation.
def _ids(rows, kind='host', limit=MAX_SLOTS):
    require(type(rows) is list and len(rows) <= limit, 'INVALID_REFS')
    for v in rows:
        _id(v, kind)
    require(len(set(rows)) == len(rows), 'DUPLICATE_REF')
    return set(rows)


def _host_identity(h):
    return {k: h[k] for k in ('host_id', 'target_id', 'identity_scope',
                              'inventory_authority_id', 'identity_key')}


def _new_hosts(rid, inputs):
    require(type(inputs) is list and 0 < len(inputs) <= 1000, 'HOST_LIMIT')
    hosts = []
    for item in inputs:
        _keys(item, 'target_id inventory_authority_id identity_key')
        target, authority, key = (item[k] for k in ('target_id', 'inventory_authority_id', 'identity_key'))
        require(target is None or _match(target, TARGET), 'INVALID_TARGET')
        require(key is None or _match(key, TARGET), 'INVALID_TARGET')
        host = {'host_id': evidence.host_id(authority, target, run_id=rid, identity_key=key),
                **item, 'identity_scope': 'STABLE' if authority is not None else 'RUN_SCOPED',
                'host_state': 'NOT_ATTEMPTED', 'reason_code': 'NOT_ATTEMPTED'}
        hosts.append(host)
    return sorted(hosts, key=lambda h: h['host_id'])


def _requirements(value, hosts, kind):
    _keys(value, 'assessment cff details')
    _bool(value['assessment']); _bool(value['cff'])
    require(not value['cff'] or value['assessment'], 'MISSING_ASSESSMENT_PAIR')
    require(type(value['details']) is list and len(value['details']) <= MAX_SLOTS-6,
            'SLOT_LIMIT')
    slots = set()
    for item in value['details']:
        _keys(item, 'host_id slot')
        _id(item['host_id'])
        _enum(item['slot'], DETAIL_SLOTS)
        key = (item['host_id'], item['slot'])
        require(key[0] in hosts and key not in slots, 'INVALID_DETAIL_REQUIREMENT')
        slots.add(key)
    require(kind == 'SYNTHETIC' or (not value['cff'] and not slots),
            'UNVERIFIED_PRODUCER_FORMAT')
    return slots


def _scope(s):
    _keys(s, 'run_id run_kind evidence_schema_version source started_at recorded_at hosts limits profile flags requirements')
    _rid(s['run_id']); _enum(s['run_kind'], KINDS)
    _enum(s['evidence_schema_version'], ('1.0.0', '1.1.0'))
    hs = s['hosts']
    require(type(hs) is list and 0 < len(hs) <= (1000 if s['run_kind'] == 'LEGACY_IMPORT' else 10), 'HOST_LIMIT')
    for h in hs:
        _keys(h, 'host_id target_id identity_scope inventory_authority_id identity_key host_state reason_code')
        require(h['host_state'] == 'NOT_ATTEMPTED' and h['reason_code'] == 'NOT_ATTEMPTED', 'FROZEN_HOST')
        require(h['target_id'] is None or _match(h['target_id'], TARGET), 'INVALID_TARGET')
        require(h['identity_key'] is None or _match(h['identity_key'], TARGET), 'INVALID_TARGET')
    ids = _ids([h['host_id'] for h in hs], limit=1000)
    targets = [h['target_id'] for h in hs if h['target_id'] is not None]
    require(len(set(targets)) == len(targets), 'DUPLICATE_TARGET')
    require([h['host_id'] for h in hs] == sorted(ids), 'HOST_ORDER')
    # Validate the frozen metadata and every ID via the actual Evidence model.
    _canonical(_doc(s, hs, 'PLANNED'))
    require(s['source']['source_kind'] == KINDS[s['run_kind']], 'SOURCE_KIND')
    if s['run_kind'] == 'LEGACY_IMPORT':
        require(s['limits'] is None and s['profile'] is None and s['flags'] is None and
                all(h['identity_scope'] == 'RUN_SCOPED' for h in hs), 'LEGACY_SCOPE')
        require(s['source']['producer_id'] in FORMATS and
                _match(s['source']['input_sha256'], HEX), 'LEGACY_SOURCE')
    else:
        require(len(targets) == len(hs), 'INVALID_TARGET')
        _keys(s['limits'], 'max_hosts forks serial ssh_timeout_s command_timeout_s')
        lim = s['limits']
        _int(lim['max_hosts'], 1, 10); _int(lim['forks'], 1, 2)
        _int(lim['serial'], 2, 2); _int(lim['ssh_timeout_s'], 15, 15)
        _int(lim['command_timeout_s'], 30, 30)
        require(len(hs) <= lim['max_hosts'], 'HOST_LIMIT')
        _enum(s['profile'], ('baseline', 'extended'))
        require(type(s['flags']) is dict and set(s['flags']) == ids, 'PROFILE_FLAGS')
        for flags in s['flags'].values():
            require(type(flags) is dict and set(flags) == set(COLLECTORS), 'PROFILE_FLAGS')
            for v in flags.values(): _bool(v)
            require(not flags['tls_services'] and (s['profile'] == 'extended' or
                    not flags['nginx_certs']), 'PROFILE_FLAGS')
    _requirements(s['requirements'], ids, s['run_kind'])
    return s


def _doc(s, hosts, state, *, finished_at=None, coverage_reason=None, scope_reason=None):
    run = {'run_id': s['run_id'], 'run_state': state, 'recorded_at': s['recorded_at'],
           'started_at': s['started_at'], 'finished_at': finished_at,
           'source': s['source'], 'expected_host_ids': sorted(h['host_id'] for h in hosts)}
    if coverage_reason is not None: run['coverage_reason'] = coverage_reason
    if scope_reason is not None: run['scope_reason'] = scope_reason
    return {'schema_version': s['evidence_schema_version'], 'run': run, 'hosts': hosts,
            **{k: [] for k in evidence.REGISTRIES if k != 'hosts'}}


def _match_doc(s, doc, *, fragment=False):
    _canonical(doc)
    run = doc['run']
    require(doc['schema_version'] == s['evidence_schema_version'] and
            all(run[k] == s[k] for k in ('run_id', 'recorded_at', 'started_at', 'source')) and
            not doc['claims'] and not doc['findings'], 'EVIDENCE_SCOPE')
    allowed = {h['host_id']: _host_identity(h) for h in s['hosts']}
    ids = set(run['expected_host_ids'])
    require((len(ids) == 1 and ids <= allowed.keys()) if fragment else ids == allowed.keys(),
            'HOST_MANIFEST')
    require(all(_host_identity(h) == allowed[h['host_id']] for h in doc['hosts']), 'HOST_IDENTITY')
    require(all(x['source']['source_kind'] == s['source']['source_kind']
                for x in doc['collections'] + doc['evidence']), 'SOURCE_KIND')
    if s['run_kind'] == 'LEGACY_IMPORT':
        require(all(x['source'] == s['source'] for x in doc['collections'] + doc['evidence']),
                'LEGACY_SOURCE')
    good = {c['host_id'] for c in doc['collections'] if c['collection_state'] in GOOD}
    gaps = {c['host_id'] for c in doc['collections'] if c['collection_state'] not in
            ('COLLECTED', 'NOT_APPLICABLE', 'NOT_SCANNED')}
    for h in doc['hosts']:
        require((h['host_state'] in ('COMPLETE', 'PARTIAL')) == (h['host_id'] in good),
                'HOST_COVERAGE')
        require(h['host_state'] != 'COMPLETE' or h['host_id'] not in gaps, 'HOST_COVERAGE')
        if s['run_kind'] == 'LEGACY_IMPORT':
            require(h['host_state'] != 'UNREACHABLE', 'LEGACY_OUTCOME')
    return doc


def host_fragment(document, host_id):
    """Pure helper for trusted callers: a complete one-host Evidence envelope."""
    _id(host_id)
    _canonical(document)
    require(not document['claims'] and not document['findings'], 'EVIDENCE_SCOPE')
    rows = [h for h in document['hosts'] if h['host_id'] == host_id]
    require(len(rows) == 1, 'HOST_MANIFEST')
    state = rows[0]['host_state']
    run = {**document['run'], 'expected_host_ids': [host_id],
           'run_state': state if state in ('COMPLETE', 'PARTIAL') else 'ERROR'}
    out = {**document, 'run': run, 'hosts': rows}
    for k in ('collections', 'assets', 'evidence'):
        out[k] = [r for r in document[k] if r['host_id'] == host_id]
    return _evidence_bytes(_canonical(out))


def _legacy(s, value):
    _keys(value, 'format_version source original_run_id original_generated_at diagnostics')
    require(value['format_version'] == VERSION and value['source'] == s['source'], 'LEGACY_SOURCE')
    if s['source']['producer_id'] == 'legacy-ol-run-summary':
        require(_match(value['original_run_id'], RID), 'INVALID_LEGACY_PROVENANCE')
    else:
        require(value['original_run_id'] is None, 'INVALID_LEGACY_PROVENANCE')
    if value['original_generated_at'] is not None:
        evidence.STAMP.check(value['original_generated_at'], '$legacy.timestamp')
    require(type(value['diagnostics']) is list and len(value['diagnostics']) <= 128,
            'INVALID_LEGACY_PROVENANCE')
    seen = set()
    for x in value['diagnostics']:
        _keys(x, 'reason_code count'); _reason(x['reason_code']); _int(x['count'], 0, 1000000)
        require(x['reason_code'] not in seen, 'DUPLICATE_REF'); seen.add(x['reason_code'])
    return value


def _refs(doc, host, value):
    for key, registry, kind in (('collection_ids', 'collections', 'collection'),
                                ('asset_ids', 'assets', 'asset'), ('evidence_ids', 'evidence', 'evidence')):
        ids = _ids(value[key], kind, limit=20000)
        require(ids <= {r[evidence.REGISTRIES[registry]] for r in doc[registry]
                        if r['host_id'] == host}, 'FOREIGN_REF')
    index = {r['evidence_id']: r for r in doc['evidence']}
    for eid in value['evidence_ids']:
        row = index[eid]
        require(row['collection_id'] in value['collection_ids'] and
                (row['asset_id'] is None or row['asset_id'] in value['asset_ids']), 'FOREIGN_REF')


def _detail(s, doc, value):
    _keys(value, 'format_version format run_id host_id slot collection_ids asset_ids evidence_ids records')
    require(s['run_kind'] == 'SYNTHETIC' and value['format'] == 'S1_TYPED_FIXTURE' and
            value['format_version'] == VERSION, 'UNVERIFIED_PRODUCER_FORMAT')
    require(value['run_id'] == s['run_id'] and value['host_id'] in doc['run']['expected_host_ids'], 'FOREIGN_REF')
    _id(value['host_id']); _enum(value['slot'], DETAIL_SLOTS)
    _refs(doc, value['host_id'], value)
    require(type(value['records']) is list and 0 < len(value['records']) <= 1024,
            'INVALID_DETAIL')
    index = {r['evidence_id']: r for r in doc['evidence']}
    collections = {c['collection_id']: c for c in doc['collections']}
    seen = set()
    for r in value['records']:
        _keys(r, 'record_kind evidence_id state reason_code rc')
        _enum(r['record_kind'], ('DIAGNOSTIC', 'ASSET', 'CONFIGURATION'))
        _id(r['evidence_id'], 'evidence'); _enum(r['state'], STATES); _reason(r['reason_code'])
        if r['rc'] is not None: _int(r['rc'], -255, 255)
        require(r['evidence_id'] in value['evidence_ids'] and r['evidence_id'] not in seen, 'FOREIGN_REF')
        row = index[r['evidence_id']]
        c = collections[row['collection_id']]
        require(r['state'] == c['collection_state'] and r['reason_code'] == c['reason_code'], 'DETAIL_STATE')
        if r['record_kind'] == 'ASSET': require(row['asset_id'] is not None, 'FOREIGN_REF')
        if r['record_kind'] == 'CONFIGURATION': require(row['evidence_kind'] == 'EFFECTIVE_CONFIGURATION', 'FOREIGN_REF')
        seen.add(r['evidence_id'])
    require(seen == set(value['evidence_ids']), 'DETAIL_COVERAGE')
    _json_bytes(value, MAX_DETAIL)
    return value


def _terminal(s, doc, h, row, attempted):
    """Validate one exact synthetic B04 terminal row with its Evidence."""
    _keys(row, 'target_id host_state attempted reason_code collectors')
    require(row['target_id'] == h['target_id'], 'BATCH_HOST_STATE')
    hid = h['host_id']
    _bool(row['attempted']); _reason(row['reason_code'])
    require(row['host_state'] == h['host_state'] and row['reason_code'] == h['reason_code'] and
            row['attempted'] is attempted, 'BATCH_HOST_STATE')
    require(row['reason_code'] not in ('OUTCOME_UNKNOWN', 'RECOVERY_INCOMPLETE'), 'BATCH_HOST_STATE')
    if row['host_state'] == 'UNREACHABLE':
        require(row['reason_code'] == 'CONNECTION_FAILED', 'BATCH_HOST_STATE')
    flags = s['flags'][hid]
    coll = {c['collection_id']: c for c in doc['collections'] if c['host_id'] == hid}
    require(type(row['collectors']) is list and len(row['collectors']) == len(COLLECTORS), 'BATCH_COLLECTORS')
    seen, used, requested = set(), set(), []
    for c in row['collectors']:
        _keys(c, 'collector_id requested state reason_code rc collection_ids')
        _enum(c['collector_id'], COLLECTORS); _bool(c['requested']); _enum(c['state'], STATES); _reason(c['reason_code'])
        if c['rc'] is not None: _int(c['rc'], -255, 255)
        require(c['collector_id'] not in seen and c['requested'] is flags[c['collector_id']], 'BATCH_COLLECTORS')
        seen.add(c['collector_id'])
        refs = _ids(c['collection_ids'], 'collection', 20000)
        require(refs <= coll.keys() and not refs & used, 'FOREIGN_REF'); used |= refs
        require(all(coll[x]['collector_id'] == c['collector_id'] for x in refs), 'FOREIGN_COLLECTOR')
        states = [coll[x]['collection_state'] for x in refs]
        if states:
            if all(x == 'NOT_APPLICABLE' for x in states): derived = 'NOT_APPLICABLE'
            elif all(x in ('COLLECTED', 'NOT_APPLICABLE') for x in states): derived = 'COLLECTED'
            elif any(x in GOOD for x in states): derived = 'PARTIAL'
            else: derived = next(x for x in ('ERROR', 'PERMISSION_DENIED', 'UNREACHABLE', 'UNKNOWN', 'NOT_SCANNED') if x in states)
            require(c['state'] == derived, 'BATCH_COVERAGE')
        else:
            require(c['state'] not in GOOD, 'BATCH_COVERAGE')
        if c['requested']:
            requested.append(c['state'])
        else:
            require(c['state'] == 'NOT_SCANNED' and c['rc'] is None, 'BATCH_COLLECTORS')
        if not row['attempted']:
            require(c['state'] == 'NOT_SCANNED' and c['rc'] is None, 'BATCH_COVERAGE')
    require(used == coll.keys(), 'BATCH_COVERAGE')
    has_good = any(x in GOOD for x in requested)
    full = bool(requested) and all(x in ('COLLECTED', 'NOT_APPLICABLE') for x in requested)
    require((row['host_state'] in ('COMPLETE', 'PARTIAL')) == has_good and
            (row['host_state'] == 'COMPLETE') == full, 'BATCH_COVERAGE')
    require(row['attempted'] == (row['host_state'] != 'NOT_ATTEMPTED'), 'BATCH_HOST_STATE')
    if not requested: require(not row['attempted'], 'BATCH_COVERAGE')
    return row


def _batch(s, doc, batch, rc, attempts):
    """S1 closed B04 fixture contract. Actual #8 API binding belongs to S2."""
    require(s['run_kind'] != 'LEGACY_IMPORT', 'LEGACY_BATCH')
    _keys(batch, 'batch_manifest_version target_ids target_count limits profile run_state reason_code hosts')
    _int(batch['batch_manifest_version'], 1, 1); _int(rc, 0, 7)
    _reason(batch['reason_code'])
    index = {h['target_id']: h for h in doc['hosts']}
    require(batch['target_ids'] == sorted(index), 'BATCH_TARGETS')
    _int(batch['target_count'], len(index), len(index))
    require(_same(batch['limits'], s['limits']) and batch['profile'] == s['profile'], 'BATCH_SCOPE')
    require(type(batch['hosts']) is list and len(batch['hosts']) == len(index), 'BATCH_HOSTS')
    require(all(type(x) is dict for x in batch['hosts']), 'INVALID_SHAPE')
    require([x.get('target_id') for x in batch['hosts']] == sorted(index), 'BATCH_HOSTS')
    for row in batch['hosts']:
        h = index[row['target_id']]; att = attempts[h['host_id']]
        require(_same(row, att['terminal']), 'TERMINAL_MISMATCH')
        _terminal(s, doc, h, row, att['attempted'])
    state = _run_state(doc['hosts'], interrupted=rc == 7)
    require(batch['run_state'] == doc['run']['run_state'] == state, 'BATCH_RUN_STATE')
    require(rc == 7 or rc == {'COMPLETE': 0, 'PARTIAL': 5, 'ERROR': 6}[state], 'BATCH_RC')
    if rc == 7: require(batch['reason_code'] == 'INTERRUPTED', 'BATCH_RC')
    if doc['run'].get('coverage_reason') is not None:
        require(doc['run']['coverage_reason'] == batch['reason_code'], 'BATCH_RUN_REASON')
    return batch


def _run_state(hosts, *, interrupted=False):
    if not interrupted and hosts and all(h['host_state'] == 'COMPLETE' for h in hosts):
        return 'COMPLETE'
    return 'PARTIAL' if any(h['host_state'] in ('COMPLETE', 'PARTIAL') for h in hosts) else 'ERROR'


def _cff(s, assessed, digest, value):
    # The actual #13 implementation is not an S1 dependency. This is a closed
    # synthetic common pair, not a third-party CFF wire/schema certification.
    _keys(value, 'format projection_version evidence_document_sha256 per_host')
    require(s['run_kind'] == 'SYNTHETIC' and value['format'] == 'S1_CFF_PAIR' and
            value['projection_version'] == VERSION, 'UNVERIFIED_PRODUCER_FORMAT')
    require(value['evidence_document_sha256'] == digest, 'CFF_EVIDENCE_HASH')
    hs = set(assessed['run']['expected_host_ids'])
    require(type(value['per_host']) is list and len(value['per_host']) == len(hs), 'CFF_HOSTS')
    seen = set()
    for entry in value['per_host']:
        _keys(entry, 'host_id cff companion'); hid = _id(entry['host_id'])
        require(hid in hs and hid not in seen, 'CFF_HOSTS'); seen.add(hid)
        cff, comp = entry['cff'], entry['companion']
        _keys(cff, 'version findings summary'); _keys(comp, 'evidence_document_sha256 findings score_semantics')
        require(cff['version'] == VERSION and comp['evidence_document_sha256'] == digest and
                comp['score_semantics'] == 'FACT_STATUS_RATIO_NOT_READINESS', 'CFF_PAIR')
        findings = {f['finding_id']: f for f in assessed['findings'] if f['subject']['host_id'] == hid}
        require(type(comp['findings']) is list and type(cff['findings']) is list and
                len(comp['findings']) == len(cff['findings']) == len(findings), 'CFF_PAIR')
        mapped = {}
        for f in comp['findings']:
            _keys(f, 'finding_id assessment_state reason_code claim_ids evidence_ids')
            fid = _id(f['finding_id'], 'finding')
            require(fid in findings and fid not in mapped and all(f[k] == findings[fid][k]
                for k in ('assessment_state', 'reason_code', 'claim_ids', 'evidence_ids')), 'CFF_PAIR')
            mapped[fid] = f
        counts = dict.fromkeys(('pass', 'fail', 'error', 'not_applicable', 'not_checked'), 0)
        visited = set()
        for f in cff['findings']:
            _keys(f, 'rule_id status'); fid = _id(f['rule_id'], 'finding')
            require(fid in mapped and fid not in visited, 'CFF_PAIR'); visited.add(fid)
            _enum(f['status'], counts)
            state = mapped[fid]['assessment_state']
            # Synthetic common fixture only: no second production evaluator.
            expected = {'PASS': 'pass', 'FAIL': 'fail', 'NOT_APPLICABLE': 'not_applicable'}.get(state, 'not_checked')
            require(f['status'] == expected or (state == 'UNKNOWN' and f['status'] == 'error'), 'CFF_PAIR')
            counts[f['status']] += 1
        denom = counts['pass'] + counts['fail']
        require(_same(cff['summary'], {**counts, 'total': len(findings), 'denominator': denom,
                                       'score_available': denom > 0}), 'CFF_COUNTS')
    return value


def _slot(kind, host=None, slot=None):
    if kind == 'detail':
        _id(host); _enum(slot, DETAIL_SLOTS)
        return ('details', host, slot + '.json'), MAX_DETAIL
    require(type(kind) is str and kind in FILES and host is None and slot is None,
            'INVALID_SLOT')
    name, limit = FILES[kind]
    return (name,), limit


def _artifact(kind, raw, *, version=VERSION, host=None, slot=None,
              refs=None, required=True):
    parts, limit = _slot(kind, host, slot)
    require(type(raw) is bytes and 0 < len(raw) <= limit, 'ARTIFACT_SIZE')
    return {'kind': kind, 'format_version': version, 'host_id': host, 'slot': slot,
            'path': '/'.join(parts), 'size': len(raw), 'sha256': _digest(raw),
            'required': required, **{k: [] if refs is None else sorted(refs[k])
                                      for k in ('collection_ids', 'asset_ids', 'evidence_ids')}}


def _attempt(s, host, attempted, intent):
    if s['run_kind'] == 'LEGACY_IMPORT':
        require(attempted is None and intent is None, 'LEGACY_ATTEMPT')
        return {'attempted': None, 'dispatch_intent': None, 'attempt_status': 'NOT_APPLICABLE'}
    _bool(intent)
    state = host['host_state']
    if attempted is None:
        require(intent and state == 'ERROR' and host['reason_code'] == 'OUTCOME_UNKNOWN', 'UNKNOWN_ATTEMPT')
        status = 'UNKNOWN'
    else:
        _bool(attempted)
        require((not attempted or intent) and attempted == (state != 'NOT_ATTEMPTED'), 'ATTEMPT_STATE')
        status = 'ATTEMPTED' if attempted else 'NOT_ATTEMPTED'
    return {'attempted': attempted, 'dispatch_intent': intent, 'attempt_status': status}


def _assemble(s, payloads, attempts, *, recovery, batch_rc):
    """Derive every manifest field from validated data, not caller summaries.

    Used both before publication and on the read/recovery path. Payload keys
    are fixed (kind, host_id, slot) tuples, not caller-provided paths.
    """
    _scope(s); _bool(recovery)
    require(type(payloads) is dict and 0 < len(payloads) <= MAX_SLOTS, 'SLOT_LIMIT')
    require(sum(len(raw) for raw in payloads.values()) <= MAX_CORE, 'CORE_SIZE_LIMIT')
    for (kind, host, slot), raw in payloads.items():
        _, cap = _slot(kind, host, slot)
        require(type(raw) is bytes and 0 < len(raw) <= cap, 'ARTIFACT_SIZE')
    def get(kind): return payloads.get((kind, None, None))
    raw = get('evidence'); require(raw is not None, 'MISSING_EVIDENCE')
    doc = _match_doc(s, _evidence_bytes(raw))
    run = doc['run']; state = run['run_state']
    _enum(state, RUN_STATES)
    hs = {h['host_id']: h for h in doc['hosts']}
    require(type(attempts) is dict and set(attempts) == set(hs), 'HOST_MANIFEST')
    rows = []
    for hid, h in sorted(hs.items()):
        entry = attempts[hid]
        _keys(entry, 'attempted dispatch_intent attempt_status terminal')
        require(_same({k: entry[k] for k in ('attempted', 'dispatch_intent', 'attempt_status')},
                      _attempt(s, h, entry['attempted'], entry['dispatch_intent'])), 'ATTEMPT_STATE')
        if s['run_kind'] == 'LEGACY_IMPORT':
            require(entry['terminal'] is None, 'LEGACY_BATCH')
        elif entry['terminal'] is not None:
            _terminal(s, doc, h, entry['terminal'], entry['attempted'])
        else:
            require(recovery and entry['attempted'] is not True and
                    h['host_state'] in ('ERROR', 'NOT_ATTEMPTED'), 'MISSING_TERMINAL_CHECKPOINT')
        require(recovery or entry['attempt_status'] != 'UNKNOWN', 'UNKNOWN_ATTEMPT')
        rows.append({**h, **entry})
    batch_raw, legacy_raw = get('batch'), get('legacy')
    batch_hash, batch_contract, batch_missing_reason = None, None, None
    run_reason = run.get('coverage_reason', 'RUN_COMPLETE' if state == 'COMPLETE' else 'RUN_INCOMPLETE')
    if s['run_kind'] == 'LEGACY_IMPORT':
        require(batch_raw is None and batch_rc is None and legacy_raw is not None, 'LEGACY_BATCH')
        _legacy(s, _loads(legacy_raw, MAX_DETAIL))
        require(state == _run_state(doc['hosts'], interrupted=recovery), 'RUN_STATE')
    else:
        require(legacy_raw is None, 'SOURCE_KIND')
        if recovery:
            require(batch_raw is None and batch_rc is None and state == _run_state(doc['hosts'], interrupted=True), 'RECOVERY_STATE')
            require(run.get('coverage_reason') == 'RECOVERY_INCOMPLETE', 'RECOVERY_STATE')
            batch_missing_reason = 'BATCH_MANIFEST_UNAVAILABLE'
        else:
            require(batch_raw is not None, 'MISSING_BATCH')
            batch = _batch(s, doc, _loads(batch_raw), batch_rc, attempts)
            batch_hash = _digest(_json_bytes(batch))
            batch_contract = 'B04_S1_CONTRACT_ONLY'
            run_reason = batch['reason_code']
    assessed_raw, rules_raw, cff_raw = get('assessed'), get('rules'), get('cff')
    require((assessed_raw is None) == (rules_raw is None), 'MISSING_ASSESSMENT_PAIR')
    assessed = None; rule_version = None; rules_sha = None
    if assessed_raw is not None:
        assessed = _evidence_bytes(assessed_raw)
        rules = assessment.load_rules(rules_raw)
        # Exact recomputation also binds all observations, IDs, source and rule
        # version. No assessment is generated by a second evaluation engine.
        require(_canonical(assessment.evaluate_document(doc, rules)) == assessed_raw,
                'ASSESSMENT_MISMATCH')
        rule_version, rules_sha = rules['rule_version'], _digest(rules_raw)
    if cff_raw is not None:
        require(assessed is not None, 'MISSING_ASSESSMENT_PAIR')
        _cff(s, assessed, _digest(assessed_raw), _loads(cff_raw, MAX_CFF))
    required_details = _requirements(s['requirements'], set(hs), s['run_kind'])
    have_details = set(); entries = []
    for (kind, host, slot), data in payloads.items():
        if kind == 'detail':
            detail = _detail(s, doc, _loads(data, MAX_DETAIL))
            require(detail['host_id'] == host and detail['slot'] == slot, 'INVALID_SLOT')
            have_details.add((host, slot))
            entries.append(_artifact(kind, data, host=host, slot=slot, refs=detail,
                                     required=(host, slot) in required_details))
        else:
            version = doc['schema_version'] if kind in ('evidence', 'assessed') else (
                rule_version if kind == 'rules' else VERSION)
            entries.append(_artifact(kind, data, version=version))
    missing = []
    if recovery and s['run_kind'] != 'LEGACY_IMPORT':
        missing.append({'path': FILES['batch'][0], 'reason_code': 'BATCH_MANIFEST_UNAVAILABLE'})
    if s['requirements']['assessment'] and assessed is None:
        for k in ('assessed', 'rules'):
            missing.append({'path': FILES[k][0], 'reason_code': 'REQUIRED_ARTIFACT_MISSING'})
    if s['requirements']['cff'] and cff_raw is None:
        missing.append({'path': FILES['cff'][0], 'reason_code': 'REQUIRED_ARTIFACT_MISSING'})
    for hid, slot in sorted(required_details - have_details):
        missing.append({'path': '/'.join(_slot('detail', hid, slot)[0]), 'reason_code': 'REQUIRED_DETAIL_MISSING'})
    require(state != 'COMPLETE' or not missing, 'REQUIRED_ARTIFACT_MISSING')
    counts = Counter(h['host_state'] for h in rows)
    manifest = {'manifest_version': VERSION, 'publication_state': 'PUBLISHED',
                'run_id': s['run_id'], 'run_kind': s['run_kind'], 'run_state': state,
                'reason_code': run_reason,
                'recovery': recovery, 'source': run['source'], 'started_at': run['started_at'],
                'finished_at': run['finished_at'], 'recorded_at': run['recorded_at'],
                'expected_host_ids': sorted(hs), 'hosts': rows,
                'counts': {'total': len(rows), **{k: counts[k] for k in HOST_STATES}},
                'limits': s['limits'], 'profile': s['profile'], 'flags': s['flags'],
                'requirements': s['requirements'], 'evidence_schema_version': doc['schema_version'],
                'rule_version': rule_version, 'rules_sha256': rules_sha,
                'batch_rc': batch_rc, 'batch_contract': batch_contract,
                'batch_canonical_sha256': batch_hash, 'batch_missing_reason': batch_missing_reason,
                'artifacts': sorted(entries, key=lambda x: x['path']),
                'missing_artifacts': sorted(missing, key=lambda x: x['path'])}
    _json_bytes(manifest)
    return PublishedRun(manifest, doc, assessed, {'/'.join(_slot(*key)[0]): value
                                                  for key, value in payloads.items()})


MANIFEST_KEYS = ('manifest_version publication_state run_id run_kind run_state reason_code recovery '
                 'source started_at finished_at recorded_at expected_host_ids hosts counts limits '
                 'profile flags requirements evidence_schema_version rule_version rules_sha256 batch_rc '
                 'batch_contract batch_canonical_sha256 batch_missing_reason artifacts missing_artifacts')
ENTRY_KEYS = 'kind format_version host_id slot path size sha256 required collection_ids asset_ids evidence_ids'


def _manifest_header(manifest, rid):
    _keys(manifest, MANIFEST_KEYS)
    require(manifest['manifest_version'] == VERSION, 'UNSUPPORTED_MANIFEST_VERSION')
    require(manifest['publication_state'] == 'PUBLISHED' and manifest['run_id'] == rid, 'MANIFEST_IDENTITY')
    _rid(rid); _enum(manifest['run_kind'], KINDS); _enum(manifest['run_state'], RUN_STATES)
    _bool(manifest['recovery']); _reason(manifest['reason_code'])
    require(type(manifest['hosts']) is list and 0 < len(manifest['hosts']) <= 1000, 'HOST_LIMIT')
    hs = []; attempts = {}
    for row in manifest['hosts']:
        _keys(row, 'host_id target_id identity_scope inventory_authority_id identity_key host_state reason_code attempted dispatch_intent attempt_status terminal')
        hid = _id(row['host_id']); require(hid not in attempts, 'DUPLICATE_REF')
        hs.append({**_host_identity(row), 'host_state': 'NOT_ATTEMPTED', 'reason_code': 'NOT_ATTEMPTED'})
        attempts[hid] = {k: row[k] for k in ('attempted', 'dispatch_intent', 'attempt_status', 'terminal')}
    require(manifest['expected_host_ids'] == sorted(attempts), 'HOST_MANIFEST')
    s = {k: manifest[k] for k in ('run_id', 'run_kind', 'evidence_schema_version', 'source',
                                 'started_at', 'recorded_at', 'limits', 'profile', 'flags', 'requirements')}
    s['hosts'] = hs
    _scope(s)
    require(type(manifest['artifacts']) is list and 0 < len(manifest['artifacts']) <= MAX_SLOTS, 'SLOT_LIMIT')
    total = 0; entries = {}
    for row in manifest['artifacts']:
        _keys(row, ENTRY_KEYS)
        parts, cap = _slot(row['kind'], row['host_id'], row['slot'])
        require(row['path'] == '/'.join(parts), 'INVALID_SLOT_PATH')
        key = (row['kind'], row['host_id'], row['slot'])
        require(key not in entries, 'DUPLICATE_SLOT')
        if row['kind'] == 'detail': require(row['host_id'] in attempts, 'FOREIGN_REF')
        _int(row['size'], 1, cap); _bool(row['required'])
        require(_match(row['sha256'], HEX), 'ARTIFACT_HASH')
        total += row['size']; require(total <= MAX_CORE, 'CORE_SIZE_LIMIT')
        entries[key] = row
    return s, attempts, entries


def _file_at(parent, parts, device, entry):
    with _directory(parent, parts[:-1], device) as d:
        raw = _read(d, parts[-1], device, _slot(entry['kind'], entry['host_id'], entry['slot'])[1], entry['size'])
    require(_digest(raw) == entry['sha256'], 'ARTIFACT_HASH')
    return raw


def _has_at(parent, parts, device):
    try:
        with _directory(parent, parts[:-1], device) as d:
            return _exists(d, parts[-1])
    except FileNotFoundError:
        return False


def _read_publication(fd, device, manifest, rid, stage_fd=None, verified=None):
    s, attempts, entries = _manifest_header(manifest, rid)
    payloads = {}
    for key, entry in entries.items():
        parts, _ = _slot(*key)
        if stage_fd is None:
            raw = _file_at(fd, parts, device, entry)
        else:
            final = _has_at(fd, parts, device)
            staged = _has_at(stage_fd, parts, device)
            require(final != staged, 'INCOMPLETE_PREPARED_ARTIFACT')
            raw = _file_at(fd if final else stage_fd, parts, device, entry)
        if verified is None:
            payloads[key] = raw
        else:
            require(verified.artifacts.get('/'.join(parts)) == raw, 'ARTIFACT_CHANGED')
    if verified is None:
        result = _assemble(s, payloads, attempts, recovery=manifest['recovery'], batch_rc=manifest['batch_rc'])
    else:
        require(len(entries) == len(verified.artifacts), 'ARTIFACT_CHANGED')
        result = verified
    require(_same(result.manifest, manifest), 'MANIFEST_MISMATCH')
    # An index cannot hide a present core slot; do not traverse untrusted names.
    for kind, (name, _) in FILES.items():
        if _exists(fd, name): require((kind, None, None) in entries, 'UNINDEXED_ARTIFACT')
    if stage_fd is None:
        expected = {}
        for kind, host, slot in entries:
            if kind == 'detail': expected.setdefault(host, set()).add(slot + '.json')
        if _exists(fd, 'details'):
            with _directory(fd, ('details',), device) as d:
                require(set(_entries(d, 1000)) == set(expected), 'UNINDEXED_ARTIFACT')
                for host, files in expected.items():
                    with _directory(d, (host,), device) as h:
                        require(set(_entries(h, len(DETAIL_SLOTS))) == files, 'UNINDEXED_ARTIFACT')
        else:
            require(not expected, 'MISSING_ARTIFACT')
    return result


class RunStore:
    """Open an existing Owner-approved 0700 root; no automatic root repair.

    API arguments are trusted caller data, never Inventory or report paths.
    Use as a context manager. Writers have independent pinned descriptors.
    """
    @_public
    def __init__(self, root):
        self._fd = _root(root)
        self._device = os.fstat(self._fd).st_dev

    def __enter__(self): return self
    def __exit__(self, *exc): self.close()
    def close(self):
        if self._fd is not None:
            os.close(self._fd); self._fd = None

    def _check(self):
        require(self._fd is not None, 'STORE_CLOSED')
        _check_dir(self._fd, self._device)

    @_public
    def begin(self, *, run_id=None, run_kind, evidence_schema_version, source,
              recorded_at, started_at, expected_hosts, limits=None, profile=None,
              requested_flags=None, requirements=None, legacy_raw=None, legacy_provenance=None):
        """Reserve exactly one directory; explicit IDs never change on collision.

        requested_flags is keyed by literal target_id; requirements.details is
        keyed by derived host_id (explicit IDs) or can be empty. No dispatch.
        """
        self._check(); _enum(run_kind, KINDS)
        if run_id is not None: _rid(run_id)
        explicit = run_id is not None
        # Validate a fixed candidate scope before filesystem reservation. A
        # generated ID is chosen again only when an actual collision occurs.
        for _ in range(8 if not explicit else 1):
            rid = run_id if explicit else datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ-') + secrets.token_hex(16)
            hosts = _new_hosts(rid, expected_hosts)
            if requested_flags is None:
                flags = None
            else:
                require(type(requested_flags) is dict and set(requested_flags) == {h['target_id'] for h in hosts}, 'PROFILE_FLAGS')
                flags = {h['host_id']: requested_flags[h['target_id']] for h in hosts}
            s = {'run_id': rid, 'run_kind': run_kind, 'evidence_schema_version': evidence_schema_version,
                 'source': source, 'started_at': started_at, 'recorded_at': recorded_at,
                 'hosts': hosts, 'limits': limits, 'profile': profile, 'flags': flags,
                 'requirements': {'assessment': False, 'cff': False, 'details': []} if requirements is None else requirements}
            s = _loads(_json_bytes(s)); _scope(s)
            if run_kind == 'LEGACY_IMPORT':
                require(type(legacy_raw) is bytes and len(legacy_raw) <= MAX_EVIDENCE and
                        _digest(legacy_raw) == s['source']['input_sha256'], 'LEGACY_INPUT_HASH')
                provenance = _loads(_json_bytes(_legacy(s, legacy_provenance), MAX_DETAIL), MAX_DETAIL)
            else:
                require(legacy_raw is None and legacy_provenance is None, 'SOURCE_KIND')
                provenance = None
            root_lock = _lock_file(self._fd, '.reservation.lock', self._device, create=True)
            run_fd = lock = None
            try:
                _flock(root_lock, wait=True)
                names = _entries(self._fd, MAX_ROOT_ENTRIES)
                if any(x.casefold() == rid.casefold() for x in names):
                    if explicit: raise StoreError('RUN_ID_COLLISION')
                    continue
                try:
                    run_fd = _mkdir(self._fd, rid, self._device)
                except FileExistsError:
                    if explicit: raise StoreError('RUN_ID_COLLISION') from None
                    continue
                lock = _lock_file(run_fd, '.writer.lock', self._device, create=True)
                _flock(lock)
                # The directory itself is the reservation and is never removed
                # on failure. Initial journal becomes durable before return.
                with _directory(run_fd, ('checkpoints',), self._device, create=True): pass
                journal = {'journal_version': VERSION, 'scope': s, 'intents': [], 'legacy_provenance': provenance}
                _write(run_fd, 'journal.json', _seal(journal, MAX_MANIFEST), self._device)
                writer = RunWriter(run_fd, lock, self._device, journal)
                run_fd = lock = None
                return writer
            finally:
                if lock is not None: os.close(lock)
                if run_fd is not None: os.close(run_fd)
                os.close(root_lock)
        raise StoreError('RUN_ID_COLLISION')

    @contextmanager
    def _locked_run(self, rid, *, shared):
        self._check(); _rid(rid)
        try:
            fd = _open_dir(self._fd, rid, self._device)
        except FileNotFoundError:
            raise StoreError('RUN_NOT_FOUND') from None
        lock = None
        try:
            try:
                lock = _lock_file(fd, '.writer.lock', self._device)
            except FileNotFoundError:
                raise StoreError('INCOMPLETE_RUN') from None
            _flock(lock, shared=shared)
            yield fd, lock
        finally:
            if lock is not None: os.close(lock)
            os.close(fd)

    @_public
    def open(self, run_id):
        """Read only a fully verified manifest/core set; never trust a directory."""
        with self._locked_run(run_id, shared=True) as (fd, _):
            if not _exists(fd, 'run_manifest.json'): raise StoreError('INCOMPLETE_RUN')
            try:
                raw = _read(fd, 'run_manifest.json', self._device, MAX_MANIFEST)
                manifest = _loads(raw)
                require(raw == _json_bytes(manifest), 'NONCANONICAL_MANIFEST')
                return _read_publication(fd, self._device, manifest, run_id)
            except FileNotFoundError:
                raise StoreError('MISSING_ARTIFACT') from None

    @_public
    def recover(self, run_id):
        """Explicit recovery only, never re-dispatch. Refuse any existing marker."""
        with self._locked_run(run_id, shared=False) as (fd, lock):
            require(not _exists(fd, 'run_manifest.json'), 'ALREADY_PUBLISHED')
            try:
                journal = _unseal(_read(fd, 'journal.json', self._device, MAX_MANIFEST), MAX_MANIFEST)
            except FileNotFoundError:
                raise StoreError('INCOMPLETE_RUN') from None
            _journal(journal, run_id)
            # Duplicate open descriptions share the exclusive flock. Close the
            # writer's duplicates before releasing the outer lock.
            with RunWriter(os.dup(fd), os.dup(lock), self._device, journal) as writer:
                if _exists(fd, 'prepared.json'):
                    return writer._resume()
                return writer._recover_unprepared()


def _journal(j, rid):
    _keys(j, 'journal_version scope intents legacy_provenance')
    require(j['journal_version'] == VERSION, 'UNSUPPORTED_JOURNAL_VERSION')
    s = _scope(j['scope']); require(s['run_id'] == rid, 'MANIFEST_IDENTITY')
    ids = _ids(j['intents'], limit=1000)
    require(ids <= {h['host_id'] for h in s['hosts']} and j['intents'] == sorted(ids), 'FOREIGN_REF')
    if s['run_kind'] == 'LEGACY_IMPORT':
        require(not ids, 'LEGACY_ATTEMPT'); _legacy(s, j['legacy_provenance'])
    else:
        require(j['legacy_provenance'] is None, 'SOURCE_KIND')
    return j


class RunWriter:
    """An exclusive run writer; one immutable terminal checkpoint per host."""
    def __init__(self, fd, lock, device, journal):
        self._fd, self._lock, self._device = fd, lock, device
        self._j = journal
        self._poisoned = False

    def __enter__(self): return self
    def __exit__(self, *exc): self.close()
    def close(self):
        if self._fd is not None:
            os.close(self._lock); os.close(self._fd); self._fd = None

    @property
    def run_id(self): return self._j['scope']['run_id']
    @property
    def scope(self): return _loads(_json_bytes(self._j['scope']))

    def _check(self, *, mutable=True):
        require(self._fd is not None and not self._poisoned, 'WRITER_CLOSED_OR_FAILED')
        _check_dir(self._fd, self._device)
        require(not _exists(self._fd, 'run_manifest.json'), 'ALREADY_PUBLISHED')
        if mutable: require(not _exists(self._fd, 'prepared.json'), 'PUBLICATION_PREPARED')

    def _host(self, hid):
        _id(hid)
        h = next((x for x in self._j['scope']['hosts'] if x['host_id'] == hid), None)
        require(h is not None, 'FOREIGN_HOST')
        return h

    @_public
    def dispatch_intent(self, host_id):
        """Persist intent before the caller dispatches; not proof of dispatch."""
        self._check(); self._host(host_id)
        s = self._j['scope']
        require(s['run_kind'] != 'LEGACY_IMPORT', 'LEGACY_ATTEMPT')
        require(any(s['flags'][host_id].values()), 'NO_EXECUTABLE_COLLECTORS')
        require(host_id not in self._j['intents'], 'DUPLICATE_INTENT')
        with _directory(self._fd, ('checkpoints',), self._device) as d:
            require(not _exists(d, host_id + '.json'), 'TERMINAL_EXISTS')
        j = {**self._j, 'intents': sorted([*self._j['intents'], host_id])}
        try:
            _write(self._fd, 'journal.json', _seal(j, MAX_MANIFEST), self._device, replace_journal=True)
        except BaseException:
            self._poisoned = True
            raise
        self._j = j

    def _checkpoint(self, body, hid):
        _keys(body, 'checkpoint_version document attempted terminal details')
        require(body['checkpoint_version'] == VERSION, 'UNSUPPORTED_CHECKPOINT_VERSION')
        s = self._j['scope']; doc = _match_doc(s, body['document'], fragment=True)
        h = doc['hosts'][0]
        require(h['host_id'] == hid, 'FOREIGN_HOST')
        require(doc['run']['run_state'] == _run_state(doc['hosts']), 'RUN_STATE')
        if s['run_kind'] != 'LEGACY_IMPORT':
            _bool(body['attempted'])
        att = _attempt(s, h, body['attempted'], None if s['run_kind'] == 'LEGACY_IMPORT' else hid in self._j['intents'])
        if s['run_kind'] == 'LEGACY_IMPORT':
            require(body['terminal'] is None, 'LEGACY_BATCH')
        else:
            _terminal(s, doc, h, body['terminal'], body['attempted'])
        att['terminal'] = body['terminal']
        require(type(body['details']) is list and len(body['details']) <= len(DETAIL_SLOTS), 'SLOT_LIMIT')
        slots = set()
        for d in body['details']:
            _detail(s, doc, d)
            require(d['host_id'] == hid and d['slot'] not in slots, 'DUPLICATE_SLOT')
            slots.add(d['slot'])
        required = {x['slot'] for x in s['requirements']['details'] if x['host_id'] == hid}
        require(h['host_state'] != 'COMPLETE' or required <= slots, 'REQUIRED_DETAIL_MISSING')
        return doc, att, body['details']

    @_public
    def record_host(self, fragment, *, attempted=None, terminal=None, details=None):
        self._check()
        # Canonicalize and validate before touching the filesystem.
        doc = _evidence_bytes(_canonical(fragment))
        require(len(doc['hosts']) == 1, 'HOST_MANIFEST')
        hid = doc['hosts'][0]['host_id']; self._host(hid)
        body = {'checkpoint_version': VERSION, 'document': doc, 'attempted': attempted,
                'terminal': terminal, 'details': [] if details is None else details}
        self._checkpoint(body, hid)
        raw = _seal(body, MAX_CHECKPOINT)
        with _directory(self._fd, ('checkpoints',), self._device) as d:
            name = hid + '.json'
            require(not _exists(d, name), 'TERMINAL_EXISTS')
            allowed = {h['host_id'] + '.json' for h in self._j['scope']['hosts']}
            size = len(raw)
            for n in _entries(d, 3000):
                if re.fullmatch(r'\.tmp-[0-9a-f]{32}', n):
                    # Private crash remnants are not terminal results.
                    continue
                require(n in allowed, 'FOREIGN_CHECKPOINT')
                f = _open_file(d, n, self._device)
                try: size += _stat_file(f, self._device).st_size
                finally: os.close(f)
                require(size <= MAX_CORE, 'CORE_SIZE_LIMIT')
            try:
                _write(d, name, raw, self._device)
            except BaseException:
                self._poisoned = True
                raise

    def _checkpoints(self):
        hs = {h['host_id'] for h in self._j['scope']['hosts']}; result = {}; total = 0
        try:
            with _directory(self._fd, ('checkpoints',), self._device) as d:
                for name in _entries(d, 3000):
                    if re.fullmatch(r'\.tmp-[0-9a-f]{32}', name):
                        continue
                    require(name.endswith('.json') and name[:-5] in hs, 'FOREIGN_CHECKPOINT')
                    raw = _read(d, name, self._device, MAX_CHECKPOINT)
                    total += len(raw); require(total <= MAX_CORE, 'CORE_SIZE_LIMIT')
                    body = _unseal(raw, MAX_CHECKPOINT)
                    result[name[:-5]] = self._checkpoint(body, name[:-5])
        except FileNotFoundError:
            raise StoreError('INCOMPLETE_RUN') from None
        return result

    def _payloads(self, document, checkpoints):
        payloads = {('evidence', None, None): _canonical(document)}
        for _, _, details in checkpoints.values():
            for detail in details:
                key = ('detail', detail['host_id'], detail['slot'])
                require(key not in payloads, 'DUPLICATE_SLOT')
                payloads[key] = _json_bytes(detail, MAX_DETAIL)
        if self._j['legacy_provenance'] is not None:
            payloads['legacy', None, None] = _json_bytes(self._j['legacy_provenance'], MAX_DETAIL)
        return payloads

    @_public
    def finalize(self, document, *, batch_raw=None, batch_rc=None,
                 assessed=None, rules_raw=None, cff=None):
        """Publish validated final Evidence and mandatory paired artifacts.

        batch_raw preserves original bytes of the S1 B04 synthetic contract.
        Actual #8 producer integration is not performed in S1.
        """
        self._check(); s = self._j['scope']
        doc = _evidence_bytes(_canonical(_match_doc(s, document)))
        checkpoints = self._checkpoints()
        require(set(checkpoints) == set(doc['run']['expected_host_ids']), 'MISSING_TERMINAL_CHECKPOINT')
        attempts = {}
        by_host = {hid: {k: [] for k in evidence.REGISTRIES} for hid in checkpoints}
        for registry in evidence.REGISTRIES:
            for row in doc[registry]:
                if registry in ('claims', 'findings'): continue
                by_host[row['host_id']][registry].append(row)
        for hid, (fragment, att, _) in checkpoints.items():
            for registry in evidence.REGISTRIES:
                require(by_host[hid][registry] == fragment[registry], 'CHECKPOINT_MISMATCH')
            if fragment['run']['finished_at'] is not None:
                require(doc['run']['finished_at'] is not None and
                        evidence._timestamp_key(fragment['run']['finished_at']) <=
                        evidence._timestamp_key(doc['run']['finished_at']), 'CHECKPOINT_TIME')
            attempts[hid] = att
        payloads = self._payloads(doc, checkpoints)
        require((assessed is None) == (rules_raw is None), 'MISSING_ASSESSMENT_PAIR')
        if assessed is not None:
            payloads['assessed', None, None] = _canonical(assessed)
            require(type(rules_raw) is bytes, 'INVALID_TYPE')
            payloads['rules', None, None] = rules_raw
        if cff is not None: payloads['cff', None, None] = _json_bytes(cff, MAX_CFF)
        if batch_raw is not None:
            require(type(batch_raw) is bytes, 'INVALID_TYPE')
            payloads['batch', None, None] = batch_raw
        result = _assemble(s, payloads, attempts, recovery=False, batch_rc=batch_rc)
        return self._prepare(result)

    def _recover_unprepared(self):
        self._check(); s = self._j['scope']; checkpoints = self._checkpoints()
        hosts, attempts = [], {}
        for frozen in s['hosts']:
            hid = frozen['host_id']
            if hid in checkpoints:
                fragment, att, _ = checkpoints[hid]; host = fragment['hosts'][0]
            elif s['run_kind'] == 'LEGACY_IMPORT':
                host = {**frozen, 'host_state': 'ERROR', 'reason_code': 'LEGACY_OUTCOME_UNKNOWN'}
                att = _attempt(s, host, None, None)
            elif hid in self._j['intents']:
                host = {**frozen, 'host_state': 'ERROR', 'reason_code': 'OUTCOME_UNKNOWN'}
                att = _attempt(s, host, None, True)
            else:
                host = frozen
                att = _attempt(s, host, False, False)
            hosts.append(host); attempts[hid] = {**att, 'terminal': att.get('terminal')}
        doc = _doc(s, hosts, _run_state(hosts, interrupted=True), coverage_reason='RECOVERY_INCOMPLETE')
        for fragment, _, _ in checkpoints.values():
            for registry in ('collections', 'assets', 'evidence'):
                doc[registry].extend(fragment[registry])
        payloads = self._payloads(doc, checkpoints)
        result = _assemble(s, payloads, attempts, recovery=True, batch_rc=None)
        return self._prepare(result)

    def _prepare(self, result):
        self._check()
        # Before prepare, no final core files may exist. Orphan staging from a
        # crash is ignored, private, and bounded; no deletion of old outputs.
        require(not any(_exists(self._fd, name) for name, _ in FILES.values()) and
                not _exists(self._fd, 'details'), 'UNPREPARED_CORE_ARTIFACT')
        stages = [n for n in _entries(self._fd, MAX_SLOTS) if n.startswith('.stage-')]
        require(len(stages) < MAX_STAGES, 'RECOVERY_STAGE_LIMIT')
        stage = '.stage-' + secrets.token_hex(16)
        stage_fd = None
        try:
            stage_fd = _mkdir(self._fd, stage, self._device)
            for row in result.manifest['artifacts']:
                parts, _ = _slot(row['kind'], row['host_id'], row['slot'])
                with _directory(stage_fd, parts[:-1], self._device, create=True) as d:
                    _write(d, parts[-1], result.artifacts[row['path']], self._device)
            # Durable immutable prepare marker comes BEFORE moving any core file.
            _write(self._fd, 'prepared.json', _seal({'stage': stage, 'manifest': result.manifest}, MAX_MANIFEST), self._device)
            return self._resume(verified=result)
        except BaseException:
            self._poisoned = True
            raise
        finally:
            if stage_fd is not None: os.close(stage_fd)

    def _verify_prepared_checkpoints(self, result):
        checkpoints = self._checkpoints()
        doc, manifest = result.document, result.manifest
        rows = {h['host_id']: h for h in manifest['hosts']}
        require(manifest['recovery'] or set(checkpoints) == set(rows), 'MISSING_TERMINAL_CHECKPOINT')
        indexed = {hid: {k: [] for k in ('hosts', 'collections', 'assets', 'evidence')} for hid in rows}
        for k in ('hosts', 'collections', 'assets', 'evidence'):
            for x in doc[k]: indexed[x['host_id']][k].append(x)
        for hid, row in rows.items():
            if hid in checkpoints:
                fragment, att, details = checkpoints[hid]
                require(_same(att, {k: row[k] for k in ('attempted', 'dispatch_intent', 'attempt_status', 'terminal')}),
                        'CHECKPOINT_MISMATCH')
                for registry in ('hosts', 'collections', 'assets', 'evidence'):
                    require(indexed[hid][registry] == fragment[registry],
                            'CHECKPOINT_MISMATCH')
                for detail in details:
                    path = '/'.join(_slot('detail', hid, detail['slot'])[0])
                    require(result.artifacts.get(path) == _json_bytes(detail, MAX_DETAIL), 'CHECKPOINT_MISMATCH')
            else:
                require(row['terminal'] is None and row['attempted'] is not True and
                        (row['dispatch_intent'] is None or row['dispatch_intent'] == (hid in self._j['intents'])) and
                        not any(indexed[hid][k] for k in ('collections', 'assets', 'evidence')),
                        'CHECKPOINT_MISMATCH')
        expected_details = {'/'.join(_slot('detail', d['host_id'], d['slot'])[0])
                            for _, _, ds in checkpoints.values() for d in ds}
        require({p for p in result.artifacts if p.startswith('details/')} == expected_details, 'CHECKPOINT_MISMATCH')
        if self._j['legacy_provenance'] is not None:
            require(result.artifacts.get(FILES['legacy'][0]) == _json_bytes(self._j['legacy_provenance'], MAX_DETAIL),
                    'CHECKPOINT_MISMATCH')

    def _resume(self, verified=None):
        self._check(mutable=False)
        try:
            prepared = _unseal(_read(self._fd, 'prepared.json', self._device, MAX_MANIFEST), MAX_MANIFEST)
            _keys(prepared, 'stage manifest')
            require(_match(prepared['stage'], r'\.stage-[0-9a-f]{32}'), 'INVALID_STAGE')
            manifest = prepared['manifest']; s, _, entries = _manifest_header(manifest, self.run_id)
            require(_same(s, self._j['scope']), 'FROZEN_SCOPE_MISMATCH')
            with _directory(self._fd, (prepared['stage'],), self._device) as stage:
                result = _read_publication(self._fd, self._device, manifest, self.run_id, stage, verified=verified)
                if verified is None:
                    # A recovered plan must still agree with the sealed journal
                    # and all terminal checkpoints. No guess from final files.
                    self._verify_prepared_checkpoints(result)
                for key, row in entries.items():
                    parts, _ = _slot(*key)
                    already = _has_at(self._fd, parts, self._device)
                    with _directory(stage, parts[:-1], self._device) as src:
                        with _directory(self._fd, parts[:-1], self._device, create=True) as dest:
                            if not already:
                                _rename_noreplace(src, parts[-1], dest, parts[-1])
                            # A prior process may have died just after rename.
                            _sync(dest); _sync(src)
                # Re-read all final bytes, including an exact index check, before
                # publishing the single no-replace marker. A crash before this
                # point leaves no published run, but a resumable prepared plan.
                result = _read_publication(self._fd, self._device, manifest, self.run_id, verified=result)
                _write(self._fd, 'run_manifest.json', _json_bytes(manifest), self._device)
                return result
        except FileNotFoundError:
            self._poisoned = True
            raise StoreError('INCOMPLETE_PREPARED_ARTIFACT') from None
        except BaseException:
            self._poisoned = True
            raise


def manifest_schema():
    """Local closed shape; cross-record and filesystem semantics use the API."""
    def obj(fields):
        return {'type': 'object', 'additionalProperties': False,
                'required': list(fields), 'properties': fields}
    def ref(name): return {'$ref': '#/$defs/' + name}
    def string(pattern, limit):
        return {'type': 'string', 'pattern': '^(?:' + pattern + r')$(?![\s\S])',
                'minLength': 1, 'maxLength': limit}
    def en(values): return {'type': 'string', 'enum': list(values)}
    def const(value): return {'const': value}
    def nullable(value): return {'anyOf': [value, {'type': 'null'}]}
    def integer(lo, hi): return {'type': 'integer', 'minimum': lo, 'maximum': hi}
    def arr(items, max_items, min_items=0, unique=True):
        return {'type': 'array', 'items': items, 'maxItems': max_items,
                'minItems': min_items, 'uniqueItems': unique}
    boolean = {'type': 'boolean'}
    hid = string('h-' + HEX, 66)
    cid = string('c-' + HEX, 66)
    aid = string('a-' + HEX, 66)
    eid = string('e-' + HEX, 66)
    reason = string(REASON, 96)
    sha = string(HEX, 64)
    target = string(TARGET, 512)
    version = string(r'[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}', 128)
    timestamp = {**string(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?(?:Z|\+00:00)', 40),
                 'format': 'date-time'}
    path = string(r'(?:' + '|'.join(re.escape(x[0]) for x in FILES.values()) +
                  r'|details/h-' + HEX + '/(?:' + '|'.join(DETAIL_SLOTS) + r')\.json)', 150)
    defs = {
        'source': evidence.model_schema('1.0.0')['$defs']['source'],
        'limits': obj({'max_hosts': integer(1, 10), 'forks': integer(1, 2), 'serial': const(2),
                       'ssh_timeout_s': const(15), 'command_timeout_s': const(30)}),
        'collector_flags': obj(dict.fromkeys(COLLECTORS, boolean)),
        'collector_outcome': obj({'collector_id': en(COLLECTORS), 'requested': boolean, 'state': en(STATES),
                                  'reason_code': reason, 'rc': nullable(integer(-255, 255)),
                                  'collection_ids': arr(cid, 20000)}),
        'terminal': obj({'target_id': target, 'host_state': en(HOST_STATES), 'attempted': boolean,
                         'reason_code': reason, 'collectors': arr(ref('collector_outcome'), 8, 8)}),
        'host': obj({'host_id': hid, 'target_id': nullable(target), 'identity_scope': en(('STABLE', 'RUN_SCOPED')),
                     'inventory_authority_id': nullable(string(SLUG, 128)), 'identity_key': nullable(target),
                     'host_state': en(HOST_STATES), 'reason_code': reason, 'attempted': nullable(boolean),
                     'dispatch_intent': nullable(boolean), 'attempt_status': en(('ATTEMPTED', 'NOT_ATTEMPTED', 'UNKNOWN', 'NOT_APPLICABLE')),
                     'terminal': nullable(ref('terminal'))}),
        'detail_requirement': obj({'host_id': hid, 'slot': en(DETAIL_SLOTS)}),
        'requirements': obj({'assessment': boolean, 'cff': boolean,
                             'details': arr(ref('detail_requirement'), MAX_SLOTS-6)}),
        'artifact': obj({'kind': en((*FILES, 'detail')), 'format_version': version,
                         'host_id': nullable(hid), 'slot': nullable(en(DETAIL_SLOTS)), 'path': path,
                         'size': integer(1, MAX_CFF), 'sha256': sha, 'required': boolean,
                         'collection_ids': arr(cid, 20000), 'asset_ids': arr(aid, 20000),
                         'evidence_ids': arr(eid, 20000)}),
        'missing': obj({'path': path, 'reason_code': en(('BATCH_MANIFEST_UNAVAILABLE',
                          'REQUIRED_ARTIFACT_MISSING', 'REQUIRED_DETAIL_MISSING'))}),
    }
    fields = {'manifest_version': const(VERSION), 'publication_state': const('PUBLISHED'),
              'run_id': {**string(RID, 64), 'not': {'pattern': r'^(?:[Cc][Oo][Nn]|[Pp][Rr][Nn]|[Aa][Uu][Xx]|[Nn][Uu][Ll]|[Cc][Oo][Mm][1-9]|[Ll][Pp][Tt][1-9])$(?![\s\S])'}},
              'run_kind': en(KINDS), 'run_state': en(RUN_STATES), 'reason_code': reason,
              'recovery': boolean, 'source': ref('source'), 'started_at': nullable(timestamp),
              'finished_at': nullable(timestamp), 'recorded_at': timestamp,
              'expected_host_ids': arr(hid, 1000, 1), 'hosts': arr(ref('host'), 1000, 1),
              'counts': obj(dict.fromkeys(('total', *HOST_STATES), integer(0, 1000))),
              'limits': nullable(ref('limits')), 'profile': nullable(en(('baseline', 'extended'))),
              'flags': nullable({'type': 'object', 'additionalProperties': False, 'maxProperties': 10,
                                 'patternProperties': {hid['pattern']: ref('collector_flags')}}),
              'requirements': ref('requirements'), 'evidence_schema_version': en(('1.0.0', '1.1.0')),
              'rule_version': nullable(version), 'rules_sha256': nullable(sha),
              'batch_rc': nullable({'type': 'integer', 'enum': [0, 5, 6, 7]}),
              'batch_contract': nullable(const('B04_S1_CONTRACT_ONLY')),
              'batch_canonical_sha256': nullable(sha),
              'batch_missing_reason': nullable(const('BATCH_MANIFEST_UNAVAILABLE')),
              'artifacts': arr(ref('artifact'), MAX_SLOTS, 1), 'missing_artifacts': arr(ref('missing'), MAX_SLOTS)}
    return {'$schema': 'https://json-schema.org/draft/2020-12/schema',
            '$id': 'urn:pqc:run-manifest:1.0.0',
            'title': 'PQC Run Store S1 manifest',
            'description': 'Local closed shape; Run Store also validates hashes, references, ownership, exact counts and publication state.',
            **obj(fields), '$defs': defs}
