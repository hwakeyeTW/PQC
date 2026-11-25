"""Internal fixed OpenSSL acquisition stages (I1b O1).

Only a trusted caller may bind a stage to an authorized target and profile.
This module does not authorize targets, scan hosts, or establish PQC readiness.
"""
import json
import os
import re
import selectors
import stat
import subprocess
import sys
import time
import zipimport

from ansible.module_utils.basic import AnsibleModule

RPM_STAGES = ('rpm-openssl', 'rpm-openssl-libs')
LIST_STAGES = ('providers', 'kem', 'signature', 'tls-groups')
STAGES = (*RPM_STAGES, 'version', *LIST_STAGES)
STAGE_SECONDS = 30
INNER_SECONDS = 27
OUTPUT_BYTES = 16 * 1024
WRAPPER_BYTES = 32 * 1024
RPM_EXECUTABLE = '/usr/bin/rpm'
OPENSSL_EXECUTABLE = '/usr/bin/openssl'
COMMANDS = {
    'rpm-openssl': (RPM_EXECUTABLE, '-q', '--queryformat', '%{NAME}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n', 'openssl'),
    'rpm-openssl-libs': (RPM_EXECUTABLE, '-q', '--queryformat', '%{NAME}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n', 'openssl-libs'),
    'version': (OPENSSL_EXECUTABLE, 'version'),
    'providers': (OPENSSL_EXECUTABLE, 'list', '-providers'),
    'kem': (OPENSSL_EXECUTABLE, 'list', '-kem-algorithms'),
    'signature': (OPENSSL_EXECUTABLE, 'list', '-signature-algorithms'),
    'tls-groups': (OPENSSL_EXECUTABLE, 'list', '-tls-groups', '-tls1_3'),
}
_MODULE_NAMES = ('ansible.legacy.pqc_openssl_acquire', 'ansible.modules.pqc_openssl_acquire',
                 'ansible_collections.security.compliance_pqc_readiness.plugins.modules.pqc_openssl_acquire')
_CHILD = ('import importlib,sys; sys.path.insert(0,sys.argv[1]); '
          'importlib.import_module(sys.argv[2])._child(sys.argv[3])')
_REASONS = {
    'COMMAND_OK', 'INVALID_COMMAND_CONTRACT', 'PROCESS_CONTROL_UNAVAILABLE',
    'COMMAND_START_FAILED', 'COMMAND_FAILED', 'COMMAND_TIMEOUT', 'COMMAND_OUTPUT_LIMIT',
    'COMMAND_IO_FAILED', 'RESIDUAL_PROCESS', 'INTERRUPTED', 'REMOTE_CLEANUP_UNCONFIRMED',
}
_SLOT_REASONS = {
    'COLLECTED': {'OK', 'PACKAGE_ABSENT'}, 'PARTIAL': {'FORMAT_GAP'},
    'UNKNOWN': {'TOOL_UNAVAILABLE', 'UNSUPPORTED_FLAG', 'NO_OUTPUT', 'UNRECOGNIZED_OUTPUT'},
    'ERROR': {'OUTPUT_LIMIT', 'ROW_LIMIT', 'INCOMPLETE_OUTPUT', 'INVALID_ENCODING',
              'COMMAND_FAILED', 'TIMEOUT', 'EXECUTION_ERROR'},
    'PERMISSION_DENIED': {'PERMISSION_DENIED'},
}
TOKEN = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}\Z', re.ASCII)
ARCH = re.compile(r'[a-z0-9][a-z0-9_-]{0,63}\Z', re.ASCII)
VERSION = re.compile(r'[0-9][A-Za-z0-9_.+-]{0,63}\Z', re.ASCII)


def _require(condition):
    if not condition:
        raise ValueError('INVALID_STAGE_RECEIPT')


def _stage(stage):
    _require(type(stage) is str and stage in STAGES)
    return stage


def _json_bytes(value):
    return json.dumps(value, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode('ascii')


def _decode(raw):
    def unique(pairs):
        result = dict(pairs)
        _require(len(result) == len(pairs))
        return result
    _require(type(raw) is bytes and len(raw) <= OUTPUT_BYTES)
    def reject(_):
        raise ValueError('INVALID_STAGE_RECEIPT')
    return json.loads(raw.decode('ascii'), object_pairs_hook=unique, parse_constant=reject)


def _shape(value, keys):
    _require(type(value) is dict and value.keys() == set(keys))


def _rc(value):
    return value is None or (type(value) is int and -255 <= value <= 255)


def _token(value, pattern=TOKEN):
    return type(value) is str and pattern.fullmatch(value) is not None


def _row_key(row):
    return json.dumps(row, ensure_ascii=True, sort_keys=True, separators=(',', ':'))


def _slot_payload(stage, payload):
    """Closed #15 typed slot; reject invalid or contradictory positive rows."""
    _shape(payload, ('state', 'reason', 'rc', 'rows'))
    state, reason, rc, rows = (payload[k] for k in ('state', 'reason', 'rc', 'rows'))
    _require(type(state) is str and state in _SLOT_REASONS and
             type(reason) is str and reason in _SLOT_REASONS[state] and _rc(rc))
    good = state in ('COLLECTED', 'PARTIAL')
    _require(type(rows) is list and len(rows) <= (32 if stage in RPM_STAGES else 256))
    _require(bool(rows) == good)
    if good:
        _require(type(rc) is int and rc == (1 if reason == 'PACKAGE_ABSENT' else 0))
    if reason == 'PACKAGE_ABSENT':
        _require(stage in RPM_STAGES and rows == [[stage[4:], None, None, None]])
    if reason == 'TOOL_UNAVAILABLE':
        _require(rc is None)
    if reason in ('NO_OUTPUT', 'UNRECOGNIZED_OUTPUT', 'ROW_LIMIT', 'INCOMPLETE_OUTPUT', 'INVALID_ENCODING'):
        _require(rc == 0)
    if reason == 'UNSUPPORTED_FLAG':
        _require(stage in LIST_STAGES and type(rc) is int)
    if reason in ('TIMEOUT', 'OUTPUT_LIMIT', 'COMMAND_FAILED'):
        _require(type(rc) is int)
    names = set()
    for row in rows:
        _require(type(row) is list)
        if stage in RPM_STAGES:
            _require(len(row) == 4 and row[0] == stage[4:])
            if reason != 'PACKAGE_ABSENT':
                _require(_token(row[1]) and _token(row[2]) and _token(row[3], ARCH))
        elif stage == 'version':
            _require(len(rows) == 1 and len(row) == 2 and state == 'COLLECTED')
            _require(_token(row[0], VERSION) and (row[1] is None or _token(row[1], VERSION)))
        elif stage == 'providers':
            _require(len(row) == 3 and _token(row[0]) and row[0] not in names)
            _require(row[1] is None or _token(row[1], VERSION))
            _require(row[2] is None or (type(row[2]) is str and row[2] in ('active', 'inactive')))
            _require(state == 'PARTIAL' or None not in row)
            names.add(row[0])
        else:
            _require(len(row) == 2 and (row[0] is None if stage == 'tls-groups' else _token(row[0])))
            aliases = row[1]
            _require(type(aliases) is list and 1 <= len(aliases) <= (1 if stage == 'tls-groups' else 32))
            _require(all(_token(x) for x in aliases) and aliases == sorted(set(aliases)))
    keys = [_row_key(row) for row in rows]
    _require(keys == sorted(set(keys)) and sum(map(len, keys)) <= 32768)


def _receipt(stage, reason, rc, clean, payload):
    return dict(format=1, stage=stage, reason_code=reason, rc=rc,
                cleanup_confirmed=clean, payload=payload)


def _fits(receipt):
    # The typed compact receipt is bounded separately from the standard native
    # JSON wrapper (which adds whitespace, changed and invocation metadata).
    frame = dict(changed=False, receipt=receipt, invocation={'module_args': {'stage': receipt['stage']}})
    return len(_json_bytes(receipt)) <= OUTPUT_BYTES and len(json.dumps(frame, ensure_ascii=True)) + 1 <= WRAPPER_BYTES


def validate_receipt(receipt, stage):
    """Validate a fixed typed receipt; this is not proof of host identity."""
    _stage(stage)
    _shape(receipt, ('format', 'stage', 'reason_code', 'rc', 'cleanup_confirmed', 'payload'))
    _require(type(receipt['format']) is int and receipt['format'] == 1 and receipt['stage'] == stage)
    reason, rc, clean, payload = (receipt[k] for k in ('reason_code', 'rc', 'cleanup_confirmed', 'payload'))
    _require(type(reason) is str and reason in _REASONS and _rc(rc) and type(clean) is bool)
    _require(clean == (reason not in ('PROCESS_CONTROL_UNAVAILABLE', 'REMOTE_CLEANUP_UNCONFIRMED')))
    if reason == 'COMMAND_OK':
        _require(type(rc) is int and rc == 0 and clean)
        _slot_payload(stage, payload)
    else:
        _require(payload is None)
        if reason in ('INVALID_COMMAND_CONTRACT', 'PROCESS_CONTROL_UNAVAILABLE', 'COMMAND_START_FAILED'):
            _require(rc is None)
        if reason == 'COMMAND_FAILED':
            _require(type(rc) is int and rc != 0)
        if reason in ('COMMAND_TIMEOUT', 'COMMAND_OUTPUT_LIMIT', 'COMMAND_IO_FAILED', 'RESIDUAL_PROCESS'):
            _require(type(rc) is int)
    _require(_fits(receipt))
    return receipt


def _payload_archive():
    """Only the actual trusted Ansible zip loader, not caller-selected code."""
    spec = __spec__
    _require(spec is not None and spec.name in _MODULE_NAMES and isinstance(spec.loader, zipimport.zipimporter))
    archive = spec.loader.archive
    _require(os.path.isabs(archive) and spec.origin == archive + '/' + spec.name.replace('.', '/') + '.py')
    parent = os.lstat(os.path.dirname(archive))
    entry = os.lstat(archive)
    _require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid() and parent.st_mode & 0o077 == 0)
    _require(stat.S_ISREG(entry.st_mode) and entry.st_uid == os.geteuid() and entry.st_nlink == 1 and entry.st_mode & 0o022 == 0)
    return archive


def _same_bundle(module, archive):
    loader = getattr(getattr(module, '__spec__', None), 'loader', None)
    _require(isinstance(loader, zipimport.zipimporter) and loader.archive == archive)


def _bounded_runner(archive):
    # Both imports are visible to AnsiballZ; standalone requires only its own
    # module_utils, not an installed collection. Do not search arbitrary paths.
    if __spec__.name == _MODULE_NAMES[-1]:
        from ansible_collections.security.compliance_pqc_readiness.plugins.module_utils import pqc_bounded_execution as helper
    else:
        from ansible.module_utils import pqc_bounded_execution as helper
    _same_bundle(helper, archive)
    return helper.run_bounded


def _child_argv(stage):
    archive = _payload_archive()
    _require(os.path.isabs(sys.executable))
    return [sys.executable, '-I', '-S', '-B', '-c', _CHILD, archive, __spec__.name, _stage(stage)]


def _from_result(stage, result):
    payload = None
    if result.reason_code == 'COMMAND_OK':
        _require(result.stderr == b'' and result.cleanup_confirmed is True)
        payload = _decode(result.stdout)
    else:
        _require(result.stdout == result.stderr == b'')
    return validate_receipt(_receipt(stage, result.reason_code, result.rc,
                                      result.cleanup_confirmed, payload), stage)


def _run_stage(stage):
    argv = _child_argv(stage)
    runner = _bounded_runner(argv[6])
    return _from_result(stage, runner(argv, timeout_s=STAGE_SECONDS))


def _result(state, reason, rc=None, rows=None):
    return dict(state=state, reason=reason, rc=rc, rows=[] if rows is None else rows)


def _parse(stage, rc, out, err):
    # The #15 parser grammar is intentionally preserved, including its gaps.
    _stage(stage)
    if len(out) + len(err) > OUTPUT_BYTES:
        return _result('ERROR', 'OUTPUT_LIMIT', rc)
    if stage in RPM_STAGES and rc == 1:
        absent = ('package ' + stage[4:] + ' is not installed\n').encode('ascii')
        if (out, err) in ((absent, b''), (b'', absent)):
            return _result('COLLECTED', 'PACKAGE_ABSENT', rc, [[stage[4:], None, None, None]])
    if rc != 0 or err:
        if b'Permission denied' in err:
            return _result('PERMISSION_DENIED', 'PERMISSION_DENIED', rc)
        if stage in LIST_STAGES and any(err.startswith(p) for p in (
                b'list: Unknown option:', b'list: Unrecognized option:', b'list: Use -help')):
            return _result('UNKNOWN', 'UNSUPPORTED_FLAG', rc)
        return _result('ERROR', 'COMMAND_FAILED', rc)
    if not out:
        return _result('UNKNOWN', 'NO_OUTPUT', rc)
    if not out.endswith(b'\n'):
        return _result('ERROR', 'INCOMPLETE_OUTPUT', rc)
    try:
        lines = out.decode('ascii').split('\n')[:-1]
    except UnicodeError:
        return _result('ERROR', 'INVALID_ENCODING', rc)
    if any(any(ord(c) < 32 and c != '\t' or ord(c) == 127 for c in line) for line in lines):
        return _result('ERROR', 'INVALID_ENCODING', rc)
    cap = 32 if stage in RPM_STAGES else 256
    if len(lines) > (cap if stage in RPM_STAGES else cap * 5 + 1 if stage == 'providers' else cap + 2):
        return _result('ERROR', 'ROW_LIMIT', rc)
    rows = []
    gap = False
    if stage in RPM_STAGES:
        for line in lines:
            parts = line.split('\t')
            if len(parts) == 4 and parts[0] == stage[4:] and all(TOKEN.fullmatch(x) for x in parts[:3]) and ARCH.fullmatch(parts[3]):
                rows.append(parts)
            else:
                gap = True
    elif stage == 'version':
        m = re.fullmatch(r'OpenSSL ([0-9][A-Za-z0-9_.+-]{0,63})(?: +FIPS)?(?: +[0-9]{1,2} [A-Za-z]{3} [0-9]{4})?(?: \(Library: OpenSSL ([0-9][A-Za-z0-9_.+-]{0,63})(?: +FIPS)?(?: +[0-9]{1,2} [A-Za-z]{3} [0-9]{4})?\))?', '\n'.join(lines))
        if m:
            rows = [[m[1], m[2]]]
        else:
            gap = True
    elif stage == 'providers':
        if not lines or lines[0] != 'Providers:':
            return _result('UNKNOWN', 'UNRECOGNIZED_OUTPUT', rc)
        blocks = []
        current = None
        for line in lines[1:]:
            m = re.fullmatch(r'  ([A-Za-z0-9][A-Za-z0-9_.+-]{0,127})', line)
            if m:
                current = {}
                blocks.append([m[1], current])
            elif current is not None and (m := re.fullmatch(r'    (name|version|status|build info): (.{1,512})', line)):
                fields = current
                if m[1] in fields:
                    fields['invalid'] = True
                fields[m[1]] = m[2]
            else:
                gap = True
                if current is not None and line.startswith('    '):
                    current['invalid'] = True
                current = None
        counts = {}
        for name, fields in blocks:
            counts[name] = counts.get(name, 0) + 1
        for name, fields in blocks:
            ver, status = fields.get('version'), fields.get('status')
            if counts[name] != 1 or fields.get('invalid') or (ver is not None and not VERSION.fullmatch(ver)) or status not in (None, 'active', 'inactive'):
                gap = True
                continue
            if ver is None or status is None:
                gap = True
            rows.append([name, ver, status])
    elif stage in ('kem', 'signature'):
        # Provider-attributed forms only. Legacy/unknown headers are gaps.
        header = {'kem': ('KEM Algorithms:', 'Provided:'), 'signature': ('Signature Algorithms:', 'Provided:')}[stage]
        for line in lines:
            line = line.strip()
            if not line or line in header:
                continue
            m = re.fullmatch(r'(\{ [^{}]{1,4096} \}|[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}) @ ([A-Za-z0-9][A-Za-z0-9_.+-]{0,127})', line)
            if not m:
                gap = True
                continue
            aliases = m[1][2:-2].split(', ') if m[1].startswith('{') else [m[1]]
            if len(aliases) > 32:
                return _result('ERROR', 'ROW_LIMIT', rc)
            # Never salvage a subset of a malformed alias row (#15 F-R1-01).
            if not all(TOKEN.fullmatch(x) for x in aliases):
                gap = True
                continue
            good = sorted(set(aliases))
            if len(good) != len(aliases):
                gap = True
            rows.append([m[2], good])
    else:
        if lines[0] in ('TLS 1.3 groups:', 'TLS1.3 groups:', 'TLS groups:'):
            lines = lines[1:]
        for line in lines:
            names = line.strip().split(':')
            if all(TOKEN.fullmatch(x) for x in names):
                rows.extend([[None, [x]] for x in names])
            else:
                gap = True
    if len(rows) > cap:
        return _result('ERROR', 'ROW_LIMIT', rc)
    unique = {_row_key(row): row for row in rows}
    if len(unique) != len(rows):
        gap = True
    if sum(len(k) for k in unique) > 32768:
        return _result('ERROR', 'OUTPUT_LIMIT', rc)
    if not unique:
        return _result('UNKNOWN', 'UNRECOGNIZED_OUTPUT' if gap else 'NO_OUTPUT', rc)
    return _result('PARTIAL' if gap else 'COLLECTED', 'FORMAT_GAP' if gap else 'OK', rc,
                   [unique[k] for k in sorted(unique)])


def _capture(stage):
    """Capture only a fixed command inside the independent supervisor's group."""
    argv = COMMANDS[_stage(stage)]
    deadline = time.monotonic() + INNER_SECONDS
    # Keep time for direct reap inside the 27 second budget. The outer helper
    # independently owns and verifies the entire process group.
    work_end = deadline - min(1.0, INNER_SECONDS / 2)
    try:
        before = os.lstat(argv[0])
        if not stat.S_ISREG(before.st_mode):
            return _result('UNKNOWN', 'TOOL_UNAVAILABLE')
        if os.access not in os.supports_effective_ids or os.access not in os.supports_follow_symlinks:
            return _result('ERROR', 'EXECUTION_ERROR')
        if not os.access(argv[0], os.X_OK, effective_ids=True, follow_symlinks=False):
            return _result('UNKNOWN', 'TOOL_UNAVAILABLE')
        after = os.lstat(argv[0])
        attrs = ('st_dev', 'st_ino', 'st_mode', 'st_ctime_ns', 'st_mtime_ns')
        if any(getattr(before, k) != getattr(after, k) for k in attrs):
            return _result('ERROR', 'EXECUTION_ERROR')
        # No new session: descendants remain in the outer helper's owned group.
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, shell=False, close_fds=True,
                                cwd='/', env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
    except PermissionError:
        return _result('PERMISSION_DENIED', 'PERMISSION_DENIED')
    except FileNotFoundError:
        return _result('UNKNOWN', 'TOOL_UNAVAILABLE')
    except (OSError, NotImplementedError):
        return _result('ERROR', 'EXECUTION_ERROR')
    buffers = [bytearray(), bytearray()]
    failure = None
    try:
        with selectors.DefaultSelector() as sel:
            for i, stream in enumerate((proc.stdout, proc.stderr)):
                sel.register(stream, selectors.EVENT_READ, i)
            while sel.get_map() or proc.poll() is None:
                remaining = work_end - time.monotonic()
                if remaining <= 0:
                    failure = 'TIMEOUT'
                    break
                if not sel.get_map():
                    time.sleep(min(0.02, remaining))
                    continue
                for key, _ in sel.select(min(0.05, remaining)):
                    room = OUTPUT_BYTES - sum(map(len, buffers))
                    chunk = os.read(key.fd, min(4096, room + 1))
                    if len(chunk) > room:
                        failure = 'OUTPUT_LIMIT'
                        break
                    if chunk:
                        buffers[key.data].extend(chunk)
                    else:
                        sel.unregister(key.fileobj)
                if failure:
                    break
            if failure is None and time.monotonic() >= work_end:
                failure = 'TIMEOUT'
    except (OSError, ValueError):
        failure = 'EXECUTION_ERROR'
    finally:
        try:
            if proc.poll() is None:
                proc.kill()
                # Unconfirmed direct reap raises; outer cleanup is authoritative.
                proc.wait(timeout=max(0, deadline - time.monotonic()))
        finally:
            proc.stdout.close()
            proc.stderr.close()
    rc = proc.returncode
    _require(type(rc) is int)
    if time.monotonic() >= deadline and failure is None:
        failure = 'TIMEOUT'
    return _result('ERROR', failure, rc) if failure else _parse(stage, rc, *map(bytes, buffers))


def _typed_payload(stage, payload):
    _slot_payload(stage, payload)
    # Account for receipt overhead before serializing into the bounded helper.
    # Overflow produces an explicit gap with the real fixed-command rc, never
    # a truncated success. The helper's own raw cap is unchanged.
    if not _fits(_receipt(stage, 'COMMAND_OK', 0, True, payload)):
        payload = _result('ERROR', 'OUTPUT_LIMIT', payload['rc'])
        _slot_payload(stage, payload)
    _require(_fits(_receipt(stage, 'COMMAND_OK', 0, True, payload)))
    return payload


def _child(stage):
    _stage(stage)
    _payload_archive()
    _require(sys.platform == 'linux' and sys.flags.isolated and sys.flags.no_site)
    payload = _typed_payload(stage, _capture(stage))
    raw = _json_bytes(payload) + b'\n'
    _require(len(raw) <= OUTPUT_BYTES)
    sys.stdout.buffer.write(raw)


def main():
    module = AnsibleModule(argument_spec={'stage': dict(type='str', required=True, choices=list(STAGES))},
                           supports_check_mode=True, no_log=True)
    try:
        receipt = _run_stage(_stage(module.params['stage']))
    except (ImportError, OSError, ValueError, TypeError, AttributeError, KeyError, RecursionError):
        # No raw child stderr, command line, paths or data-directed exception.
        module.fail_json(changed=False, msg='OPENSSL_STAGE_CONTRACT_FAILED')
    module.exit_json(changed=False, receipt=receipt)


if __name__ == '__main__':
    main()
