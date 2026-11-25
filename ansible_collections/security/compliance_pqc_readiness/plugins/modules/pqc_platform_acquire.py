"""Internal fixed platform acquisition stages (I1b P1).

The trusted controller owns authorization, target binding, eligibility, stage
ordering and observation timestamps. This module is not a scanner entry point.
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

PACKAGES = ('oraclelinux-release', 'oraclelinux-release-el9')
RPM_STAGES = {'release-rpm-' + name: name for name in PACKAGES}
STAGES = ('metadata', *RPM_STAGES)
STAGE_SECONDS = 30
OUTPUT_BYTES = 16 * 1024
RPM_EXECUTABLE = '/usr/bin/rpm'
FACT_NAMES = ('distribution', 'os_family', 'distribution_version',
              'distribution_major_version', 'architecture')
TOOL_PATHS = {
    'rpm': ('/usr/bin/rpm',), 'openssl': ('/usr/bin/openssl',),
    'ssh': ('/usr/bin/ssh',), 'sshd': ('/usr/sbin/sshd',),
    'ssh-keygen': ('/usr/bin/ssh-keygen',),
    'update-crypto-policies': ('/usr/bin/update-crypto-policies', '/usr/sbin/update-crypto-policies'),
    'timeout': ('/usr/bin/timeout',),
}
_MODULE_NAMES = ('ansible.legacy.pqc_platform_acquire', 'ansible.modules.pqc_platform_acquire',
                 'ansible_collections.security.compliance_pqc_readiness.plugins.modules.pqc_platform_acquire')
_CHILD = ('import importlib,sys; sys.path.insert(0,sys.argv[1]); '
          'importlib.import_module(sys.argv[2])._child(sys.argv[3])')
_FAILURE = ('UNKNOWN', 'ERROR', 'PERMISSION_DENIED', 'UNREACHABLE')
_REASONS = {
    'COMMAND_OK', 'INVALID_COMMAND_CONTRACT', 'PROCESS_CONTROL_UNAVAILABLE',
    'COMMAND_START_FAILED', 'COMMAND_FAILED', 'COMMAND_TIMEOUT', 'COMMAND_OUTPUT_LIMIT',
    'COMMAND_IO_FAILED', 'RESIDUAL_PROCESS', 'INTERRUPTED', 'REMOTE_CLEANUP_UNCONFIRMED',
}
_RPM_REASONS = {
    'COLLECTED': {'OK'}, 'PARTIAL': {'INCOMPLETE_RPM_ROWS'}, 'ABSENT': {'PACKAGE_ABSENT'},
    'UNKNOWN': {'NO_DATA', 'TOOL_UNAVAILABLE'}, 'PERMISSION_DENIED': {'PERMISSION_DENIED'},
    'ERROR': {'COMMAND_FAILED', 'MALFORMED_OUTPUT', 'OUTPUT_LIMIT', 'TIMEOUT'},
}
_FACT_VALUE = re.compile(r'[A-Za-z0-9][A-Za-z0-9 ._+~-]{0,127}', re.ASCII)
_RPM_VERSION = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.+~^-]{0,127}', re.ASCII)
_RPM_RELEASE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}', re.ASCII)
_RPM_ARCH = re.compile(r'[a-z0-9][a-z0-9_-]{0,63}', re.ASCII)


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
    return json.loads(raw.decode('ascii'), object_pairs_hook=unique)


def _shape(value, keys):
    _require(type(value) is dict and value.keys() == set(keys))


def _rc(value):
    return value is None or (type(value) is int and -255 <= value <= 255)


def _valid_fact(value):
    return value is None or (type(value) is str and _FACT_VALUE.fullmatch(value) is not None)


def _metadata_payload(payload):
    _shape(payload, ('facts_state', 'facts', 'tools'))
    state, facts, tools = payload['facts_state'], payload['facts'], payload['tools']
    _require(state in ('OK', *_FAILURE))
    _shape(facts, FACT_NAMES if state == 'OK' else ())
    _require(all(_valid_fact(v) for v in facts.values()))
    _shape(tools, TOOL_PATHS)
    for tool, paths in TOOL_PATHS.items():
        rows = tools[tool]
        _require(type(rows) is list and len(rows) == len(paths))
        for row in rows:
            _require(type(row) is dict and row.get('state') in ('OK', *_FAILURE))
            if row['state'] != 'OK':
                _shape(row, ('state',))
                continue
            _shape(row, ('state', 'exists', 'isreg', 'islnk', 'executable'))
            exists, regular, link, executable = (row[k] for k in ('exists', 'isreg', 'islnk', 'executable'))
            _require(type(exists) is bool)
            if not exists:
                _require(regular is link is executable is None)
            else:
                _require(type(regular) is bool and type(link) is bool and not (regular and link))
                _require(type(executable) is bool if regular else executable is None)


def _valid_row(name, row):
    return (type(row) in (list, tuple) and len(row) == 4 and
            all(type(v) is str for v in row) and row[0] == name and
            _RPM_VERSION.fullmatch(row[1]) is not None and _RPM_RELEASE.fullmatch(row[2]) is not None and
            _RPM_ARCH.fullmatch(row[3]) is not None)


def _rpm_payload(name, payload, rpm_rc):
    _shape(payload, ('state', 'reason', 'rows'))
    state, reason, rows = (payload[k] for k in ('state', 'reason', 'rows'))
    _require(type(state) is str and state in _RPM_REASONS and type(reason) is str and reason in _RPM_REASONS[state])
    _require(type(rows) is list and len(rows) <= 32 and all(type(row) is list and _valid_row(name, row) for row in rows))
    _require(rows == sorted(rows) and len({tuple(row) for row in rows}) == len(rows))
    _require(sum(sum(map(len, row)) + 4 for row in rows) <= OUTPUT_BYTES)
    _require(bool(rows) == (state in ('COLLECTED', 'PARTIAL')) and _rc(rpm_rc))
    if state in ('COLLECTED', 'PARTIAL') or reason in ('NO_DATA', 'MALFORMED_OUTPUT'):
        _require(rpm_rc == 0)
    elif state == 'ABSENT':
        _require(rpm_rc == 1)
    elif reason == 'TOOL_UNAVAILABLE':
        _require(rpm_rc is None)
    elif reason in ('TIMEOUT', 'OUTPUT_LIMIT'):
        _require(rpm_rc is not None)


def validate_receipt(receipt, stage):
    """Validate one fixed stage's typed receipt, never authorization/host identity."""
    _stage(stage)
    _shape(receipt, ('format', 'stage', 'reason_code', 'rc', 'cleanup_confirmed', 'payload', 'rpm_rc'))
    _require(type(receipt['format']) is int and receipt['format'] == 1 and receipt['stage'] == stage)
    reason, rc, clean, payload, rpm_rc = (receipt[k] for k in
        ('reason_code', 'rc', 'cleanup_confirmed', 'payload', 'rpm_rc'))
    _require(type(reason) is str and reason in _REASONS and _rc(rc) and type(clean) is bool)
    _require(clean == (reason not in ('PROCESS_CONTROL_UNAVAILABLE', 'REMOTE_CLEANUP_UNCONFIRMED')))
    if reason == 'COMMAND_OK':
        _require(type(rc) is int and rc == 0 and clean)
        if stage == 'metadata':
            _require(rpm_rc is None)
            _metadata_payload(payload)
        else:
            _rpm_payload(RPM_STAGES[stage], payload, rpm_rc)
    else:
        _require(payload is None and rpm_rc is None)
        if reason in ('INVALID_COMMAND_CONTRACT', 'PROCESS_CONTROL_UNAVAILABLE', 'COMMAND_START_FAILED'):
            _require(rc is None)
        if reason == 'COMMAND_FAILED':
            _require(type(rc) is int and rc != 0)
        if reason in ('COMMAND_TIMEOUT', 'COMMAND_OUTPUT_LIMIT', 'COMMAND_IO_FAILED', 'RESIDUAL_PROCESS'):
            _require(type(rc) is int)
    _require(len(_json_bytes(receipt)) <= OUTPUT_BYTES)
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
    payload = rpm_rc = None
    if result.reason_code == 'COMMAND_OK':
        _require(result.stderr == b'' and result.cleanup_confirmed is True)
        value = _decode(result.stdout)
        _shape(value, ('payload', 'rpm_rc'))
        payload, rpm_rc = value['payload'], value['rpm_rc']
    else:
        _require(result.stdout == result.stderr == b'')
    return validate_receipt(dict(format=1, stage=stage, reason_code=result.reason_code,
        rc=result.rc, cleanup_confirmed=result.cleanup_confirmed, payload=payload, rpm_rc=rpm_rc), stage)


def _run_stage(stage):
    argv = _child_argv(stage)
    runner = _bounded_runner(argv[6])
    return _from_result(stage, runner(argv, timeout_s=STAGE_SECONDS))


class _ReadOnlyFacts:
    """Native distribution collector interface; no optional command fallback."""
    def debug(self, msg):
        pass

    def get_bin_path(self, *args, **kwargs):
        return None

    def run_command(self, *args, **kwargs):
        raise ValueError('UNEXPECTED_FACT_COMMAND')


def _facts(archive):
    # The full native platform collector performs DNS and reads machine-id;
    # use its Linux architecture expression, not the unrelated fact fields.
    # Use the native distribution collector with the bundled distro library's
    # file-only mode. Never execute optional lsb_release/uname/oslevel fallbacks.
    from ansible.module_utils.facts.system.distribution import DistributionFactCollector
    from ansible.module_utils import distro
    _same_bundle(sys.modules[DistributionFactCollector.__module__], archive)
    _same_bundle(distro, archive)
    try:
        distro._distro = distro.LinuxDistribution(include_lsb=False, include_uname=False, include_oslevel=False)
        raw = DistributionFactCollector().collect(module=_ReadOnlyFacts())
        facts = {key: raw.get(key) for key in FACT_NAMES}
        facts['architecture'] = os.uname().machine
        if not all(_valid_fact(v) for v in facts.values()):
            return 'UNKNOWN', {}
        return 'OK', facts
    except PermissionError:
        return 'PERMISSION_DENIED', {}
    except (OSError, ValueError, TypeError, AttributeError, KeyError):
        return 'ERROR', {}


def _stat(path):
    # No open, content read, checksum, MIME or arbitrary PATH lookup.
    try:
        before = os.lstat(path)
    except FileNotFoundError:
        return dict(state='OK', exists=False, isreg=None, islnk=None, executable=None)
    except PermissionError:
        return dict(state='PERMISSION_DENIED')
    except OSError:
        return dict(state='ERROR')
    regular, link = stat.S_ISREG(before.st_mode), stat.S_ISLNK(before.st_mode)
    executable = None
    if regular:
        try:
            if os.access not in os.supports_effective_ids or os.access not in os.supports_follow_symlinks:
                return dict(state='UNKNOWN')
            executable = os.access(path, os.X_OK, effective_ids=True, follow_symlinks=False)
            after = os.lstat(path)
            attrs = ('st_dev', 'st_ino', 'st_mode', 'st_ctime_ns', 'st_mtime_ns')
            if any(getattr(before, k) != getattr(after, k) for k in attrs):
                return dict(state='UNKNOWN')
        except PermissionError:
            return dict(state='PERMISSION_DENIED')
        except (OSError, NotImplementedError):
            return dict(state='ERROR')
    return dict(state='OK', exists=True, isreg=regular, islnk=link, executable=executable)


def _metadata(archive):
    state, facts = _facts(archive)
    return dict(facts_state=state, facts=facts,
                tools={key: [_stat(path) for path in paths] for key, paths in TOOL_PATHS.items()})


def _rpm_result(state, reason, rows=()):
    return dict(state=state, reason=reason, rows=[list(row) for row in rows])


def _parse_rpm(name, rc, out, err):
    # Same narrow parser grammar as the fixed #14 wrapper; no raw strings leave.
    if len(out) + len(err) > OUTPUT_BYTES:
        return _rpm_result('ERROR', 'OUTPUT_LIMIT')
    absent = ('package ' + name + ' is not installed\n').encode('ascii')
    if rc == 1 and ((out == absent and not err) or (err == absent and not out)):
        return _rpm_result('ABSENT', 'PACKAGE_ABSENT')
    if rc != 0 or err:
        if b'Permission denied' in err:
            return _rpm_result('PERMISSION_DENIED', 'PERMISSION_DENIED')
        return _rpm_result('ERROR', 'COMMAND_FAILED')
    if not out:
        return _rpm_result('UNKNOWN', 'NO_DATA')
    lines = out.splitlines(keepends=True)
    if len(lines) > 32:
        return _rpm_result('ERROR', 'OUTPUT_LIMIT')
    good, gap = set(), False
    for line in lines:
        try:
            row = tuple(line[:-1].decode('ascii').split('\t')) if line.endswith(b'\n') else ()
        except UnicodeError:
            row = ()
        if not _valid_row(name, row) or row in good:
            gap = True
        else:
            good.add(row)
    if not good:
        return _rpm_result('ERROR', 'MALFORMED_OUTPUT')
    return _rpm_result('PARTIAL' if gap else 'COLLECTED', 'INCOMPLETE_RPM_ROWS' if gap else 'OK', sorted(good))


def _rpm(name):
    _require(name in PACKAGES)
    # Child belongs to the outer bounded runner's group. Never start a new
    # session or detach. The outer helper owns group termination and reaping.
    deadline = time.monotonic() + 27
    argv = [RPM_EXECUTABLE, '-q', '--queryformat', '%{NAME}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n', name]
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                shell=False, close_fds=True, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
    except PermissionError:
        return _rpm_result('PERMISSION_DENIED', 'PERMISSION_DENIED'), None
    except FileNotFoundError:
        return _rpm_result('UNKNOWN', 'TOOL_UNAVAILABLE'), None
    except OSError:
        return _rpm_result('ERROR', 'COMMAND_FAILED'), None
    buffers = [bytearray(), bytearray()]
    failure = None
    try:
        with selectors.DefaultSelector() as sel:
            for i, stream in enumerate((proc.stdout, proc.stderr)):
                sel.register(stream, selectors.EVENT_READ, i)
            while sel.get_map() or proc.poll() is None:
                remaining = deadline - time.monotonic()
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
    except (OSError, ValueError):
        failure = 'COMMAND_FAILED'
    finally:
        try:
            if proc.poll() is None:
                proc.kill()
                # If local reap cannot be established, fail the wrapper. The
                # outer helper still verifies the whole group before receipt.
                proc.wait(timeout=0.5)
        finally:
            proc.stdout.close()
            proc.stderr.close()
    rc = proc.returncode
    _require(type(rc) is int)
    return (_rpm_result('ERROR', failure) if failure else _parse_rpm(name, rc, *map(bytes, buffers))), rc


def _child(stage):
    _stage(stage)
    archive = _payload_archive()
    _require(sys.platform == 'linux' and sys.flags.isolated and sys.flags.no_site)
    if stage == 'metadata':
        payload, rpm_rc = _metadata(archive), None
    else:
        payload, rpm_rc = _rpm(RPM_STAGES[stage])
    raw = _json_bytes(dict(payload=payload, rpm_rc=rpm_rc))
    _require(len(raw) + 1 <= OUTPUT_BYTES)
    sys.stdout.buffer.write(raw + b'\n')


def main():
    module = AnsibleModule(argument_spec={'stage': dict(type='str', required=True)},
                           supports_check_mode=True, no_log=True)
    try:
        receipt = _run_stage(_stage(module.params['stage']))
    except (ImportError, OSError, ValueError, TypeError, AttributeError, KeyError):
        # No raw child stderr, command line, paths or data-directed exception.
        module.fail_json(changed=False, msg='PLATFORM_STAGE_CONTRACT_FAILED')
    module.exit_json(changed=False, receipt=receipt)


if __name__ == '__main__':
    main()
