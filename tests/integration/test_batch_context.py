"""S1 native synthetic context tests; never dispatch a real SSH command."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('batch_execution', ROOT / 'tools/batch_execution.py')
batch = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(batch)
A, B, C = 'a.example.invalid', 'b.example.invalid', 'unselected.example.invalid'
PKG = 'pqc_collect_packages'
TLS = 'pqc_collect_tls_services'


@pytest.fixture
def native(tmp_path):
    cfg = tmp_path / 'ssh_config'
    cfg.write_text('Host *\n StrictHostKeyChecking yes\n ControlMaster no\n ConnectTimeout 10\n BatchMode yes\n')
    path = tmp_path / 'provider'
    trace = tmp_path / 'trace'
    marker = tmp_path / 'dispatch'

    def source(mode='inline', overrides=None, behavior='normal'):
        hv = {A: {PKG: False, 'ansible_host': 'a-address.example.invalid', 'ansible_port': 2222},
              B: {'ansible_user': 'dummy-b'}, C: {'ansible_connection': 'local'}}
        for name, values in (overrides or {}).items():
            hv[name].update(values)
        raw = {'all': {'vars': {'ansible_user': 'dummy', 'ansible_connection': 'ssh',
                               'ansible_ssh_args': f'-F {cfg} -o ControlMaster=no -o ControlPath=none',
                               'ansible_ssh_common_args': '-o ProxyJump=jump.example.invalid', PKG: True}},
               'pqc_targets': {'hosts': [A], 'children': ['nested']},
               'nested': {'hosts': [A, B], 'vars': {'ansible_user': 'dummy-group'}},
               'excluded': {'hosts': [C]}}
        if mode == 'inline':
            raw['_meta'] = {'hostvars': hv}
        script = f'''#!{sys.executable}
import json, sys, pathlib, time, os
p = pathlib.Path({str(trace)!r})
previous = p.read_text().splitlines() if p.exists() else []
with p.open('a') as f:
    f.write(json.dumps(sys.argv[1:]) + '\\n')
if {behavior!r} == 'timeout':
    time.sleep(30)
if {behavior!r} == 'residual':
    if os.fork() == 0:
        os.close(1); os.close(2); time.sleep(0.4)
        pathlib.Path({str(marker)!r}).write_text('LATE_CHILD')
        os._exit(0)
if {behavior!r} == 'flood':
    sys.stdout.write('x' * 4096); sys.exit(0)
if {behavior!r} == 'error':
    print('DUMMY_PRIVATE_SENTINEL', file=sys.stderr); sys.exit(7)
if {behavior!r} == 'duplicate':
    print('{{"duplicate":{{}},"duplicate":{{}}}}'); sys.exit(0)
if sys.argv[1:] == ['--list']:
    if any(json.loads(x) == ['--list'] for x in previous):
        print(json.dumps({{'changed':{{'hosts':['drift.example.invalid']}}}}))
    else:
        print(json.dumps({raw!r}))
elif len(sys.argv) == 3 and sys.argv[1] == '--host':
    print(json.dumps({hv!r}[sys.argv[2]]))
else:
    sys.exit(8)
'''
        path.write_text(script)
        path.chmod(0o700)
        return str(path)

    def calls():
        return [json.loads(line) for line in trace.read_text().splitlines()] if trace.exists() else []

    def request(**extra):
        return batch._scope.parse_scope({'pqc_scan_groups': ['pqc_targets'], **extra})

    def trap():
        # Positive control: an actual subprocess writes a synthetic marker.
        exe = tmp_path / 'ssh'
        exe.write_text(f'#!{sys.executable}\nfrom pathlib import Path\nPath({str(marker)!r}).write_text("TRIGGERED")\nraise SystemExit(91)\n')
        exe.chmod(0o700)
        assert subprocess.run([str(exe)], timeout=5, capture_output=True).returncode == 91
        assert marker.read_text() == 'TRIGGERED'
        marker.unlink()
        return str(exe)

    return source, calls, request, cfg, marker, trap


@pytest.mark.parametrize('mode', ['inline', 'lookup'])
def test_native_context_once_and_precedence(native, mode):
    source, calls, request, _, _, _ = native
    path = source(mode)
    before = Path(path).read_bytes()
    ctx = batch._Context(path, request(pqc_scan_hosts=[A]))
    assert ctx._targets == (A, B)
    assert ctx._variables._inventory is ctx._inventory
    assert ctx._flags == {A: {PKG: False}, B: {PKG: True}}
    assert ctx._decisions[A]['requested_flags'][PKG] is False
    assert ctx._decisions[B]['requested_flags'][PKG] is True
    binding = batch._native_binding(ctx, A)
    assert binding.get_option('host') == 'a-address.example.invalid'
    assert binding.get_option('port') == 2222
    assert binding.get_option('remote_user') == 'dummy-group'
    binding_b = batch._native_binding(ctx, B)
    assert binding_b.get_option('remote_user') == 'dummy-b'
    argv, _ = batch._native_argv(binding)
    assert b'ProxyJump=jump.example.invalid' in argv
    assert b'Port=2222' in argv and b'User="dummy-group"' in argv
    assert argv[-2:] == (b'a-address.example.invalid', b':')
    assert calls().count(['--list']) == 1
    if mode == 'inline':
        assert calls() == [['--list']]
    else:
        assert sorted(c[1] for c in calls() if c[0] == '--host') == sorted((A, B, C))
    assert Path(path).read_bytes() == before


def test_native_group_host_vars_precedence(native, tmp_path):
    source, calls, request, _, _, _ = native
    p = source()
    group = tmp_path / 'group_vars'
    group.mkdir()
    (group / 'nested.yml').write_text('pqc_collect_openssl: false\n')
    host = tmp_path / 'host_vars'
    host.mkdir()
    (host / (B + '.yml')).write_text('pqc_collect_openssl: true\n')
    ctx = batch._Context(p, request())
    assert ctx._flags[A]['pqc_collect_openssl'] is False
    assert ctx._flags[B]['pqc_collect_openssl'] is True
    assert calls() == [['--list']]


@pytest.mark.parametrize('values', [
    {'ansible_connection': 'local'}, {'ansible_connection': 'paramiko'},
    {'ansible_host': '127.0.0.1'}, {'ansible_ssh_host': 'localhost'},
    {'ansible_become': True}, {'ansible_become': 'yes'},
    {'ansible_ssh_host_key_checking': False},
    {'ansible_ssh_common_args': '-o StrictHostKeyChecking=no'},
    {'ansible_ssh_common_args': '-o ProxyCommand=bad'},
    {'ansible_ssh_common_args': '-o LocalCommand=bad'},
    {'ansible_ssh_common_args': '-o HostName=localhost'},
    {'ansible_ssh_common_args': '-o ProxyJump=127.0.0.1'},
    {'ansible_ssh_common_args': '-o ControlPersist=60qq'},
    {'ansible_ssh_common_args': '-o ControlPersist="60s'},
    {'ansible_ssh_common_args': '-o ConnectTimeout=60'},
    {'ansible_ssh_common_args': '{{ unsafe }}'},
    {'ansible_ssh_retries': 1}, {'ansible_password': 'DUMMY_PRIVATE_SENTINEL'},
    {'ansible_shell_type': 'powershell'}, {'pqc_target_ids': [C]},
    {'pqc_collect_tls_services': True},
])
def test_before_connect_rejects_negative(native, values, capsys, monkeypatch):
    source, calls, request, _, marker, trap = native
    exe = trap()
    monkeypatch.setenv('PATH', str(Path(exe).parent) + ':' + os.environ['PATH'])
    # This witness isolates the native Ansible guard from the unavailable
    # OpenSSH -G verification. It is not an effective OpenSSH proof.
    monkeypatch.setattr(batch, '_effective_ssh', lambda argv, fingerprint: ('SYNTHETIC_ONLY',))
    # A first, valid host must not permit partial batch dispatch.
    with pytest.raises(batch.Denied) as error:
        ctx = batch._Context(source(overrides={B: values}), request())
        ctx._preflight()
    assert error.value.code in (3, 4)
    assert calls().count(['--list']) <= 1
    assert not marker.exists()
    assert 'DUMMY_PRIVATE_SENTINEL' not in str(error.value)
    assert 'DUMMY_PRIVATE_SENTINEL' not in ''.join(capsys.readouterr())


def test_forged_plan_active_extra_vars(native):
    source, calls, request, _, _, _ = native
    p = source()
    for forged in ({'plan_status': 'READY', 'target_ids': [C], 'execution_allowed': True},
                   dict(request(), extra_vars={'ansible_become': True}),
                   request(pqc_scan_profile='active', pqc_active_opt_in=True,
                           pqc_active_endpoints=[{'source_host': A, 'protocol': 'ssh',
                                                  'address': A, 'port': 22, 'sni': None}])):
        with pytest.raises(batch.Denied) as error:
            batch._Context(p, forged)
        assert error.value.code == 2
    assert calls() == []


@pytest.mark.parametrize('behavior, reason', [('error', 'INVENTORY_PROVIDER_ERROR'),
    ('duplicate', 'DUPLICATE_INVENTORY_KEY'), ('timeout', 'INVENTORY_TIMEOUT'),
    ('flood', 'INVENTORY_OUTPUT_LIMIT'), ('residual', 'INVENTORY_RESIDUAL_PROCESS')])
def test_bounded_native_provider(native, monkeypatch, behavior, reason, capsys):
    source, calls, request, _, marker, _ = native
    if behavior == 'timeout':
        monkeypatch.setattr(batch, '_PROVIDER_SECONDS', 2)
    if behavior == 'flood':
        monkeypatch.setattr(batch._scope, 'OUT_BYTES', 1024)
    with pytest.raises(batch.Denied) as error:
        batch._Context(source(behavior=behavior), request())
    assert error.value.reason == reason
    assert calls() == [['--list']]
    assert 'DUMMY_PRIVATE_SENTINEL' not in ''.join(capsys.readouterr())
    if behavior == 'residual':
        time.sleep(0.6)
        assert not marker.exists()


def test_no_public_live_contract(native):
    source, calls, request, _, marker, trap = native
    trap()
    ctx = batch._Context(source(), request())
    for name in (A, C):
        with pytest.raises(batch.Denied) as error:
            ctx._boundary(name)
        assert error.value.reason == 'BATCH_GUARD_DENIED'
    assert not marker.exists()
    assert calls() == [['--list']]
    assert len(batch._scope.PUBLIC_FIELDS) == 12


def test_native_boundary_instrumentation_without_openssh_proof(native, monkeypatch):
    source, calls, request, _, marker, trap = native
    exe = trap()
    monkeypatch.setenv('PATH', str(Path(exe).parent) + ':' + os.environ['PATH'])
    ctx = batch._Context(source(), request())
    # Positive control uses the *actual* native Connection.exec_command with
    # the test-only ssh executable. No network or managed host is involved.
    raw = batch._native_binding(ctx, A)
    try:
        raw.exec_command(batch.COMMAND, sudoable=False)
    except Exception:
        pass
    assert marker.read_text() == 'TRIGGERED'
    marker.unlink()
    # Only the unavailable OpenSSH effective-config proof is substituted in
    # this structural witness. Native connection option consumption, argv
    # construction, all-target guard and _run boundary are real.
    monkeypatch.setattr(batch, '_effective_ssh', lambda argv, fingerprint: ('SYNTHETIC_ONLY',))
    ctx._preflight()
    original = ctx._bound[A]
    seen = []
    monkeypatch.setattr(batch, '_stop_s1', lambda: seen.append('guarded') or (0, b'', b''))
    assert ctx._boundary(A) == (0, b'', b'')
    assert ctx._bound[A] is original and ctx._variables._inventory is ctx._inventory
    assert seen == ['guarded'] and not marker.exists()
    assert calls().count(['--list']) == 1
    with pytest.raises(batch.Denied):
        ctx._boundary(C)
    ctx._inventory.hosts[B].set_variable('ansible_user', 'drift')
    with pytest.raises(batch.Denied):
        ctx._boundary(A)
    assert seen == ['guarded'] and not marker.exists()


def test_actual_openssh_effective_config_required(native, monkeypatch):
    source, calls, request, _, marker, _ = native
    ctx = batch._Context(source(), request())
    if not Path('/usr/bin/ssh').is_file():
        with pytest.raises(batch.Denied) as error:
            ctx._preflight()
        assert error.value.reason == 'OPENSSH_EFFECTIVE_CONFIG_UNAVAILABLE'
        assert ctx._bound == ctx._proofs == {}
        assert not marker.exists()
        pytest.skip('NOT_TESTED: actual OpenSSH effective config and positive guarded boundary unavailable')
    ctx._preflight()
    seen = []
    monkeypatch.setattr(batch, '_stop_s1', lambda: seen.append('guarded') or (0, b'', b''))
    assert ctx._boundary(A) == (0, b'', b'')
    assert seen == ['guarded'] and not marker.exists()
    assert calls().count(['--list']) == 1


def test_original_plan_only_cli_unchanged(native):
    source, calls, _, _, marker, trap = native
    trap()
    path = source()
    prefix = [sys.executable, '-I', '-B', str(ROOT / 'tools/pqc_scan.py'), '-i', path,
              '--group', 'pqc_targets']
    denied = subprocess.run(prefix, capture_output=True, timeout=15)
    assert denied.returncode == 2 and not denied.stdout
    assert b'LIVE_NOT_AVAILABLE' in denied.stderr and calls() == []
    result = subprocess.run(prefix + ['--plan-only'], capture_output=True, timeout=30)
    assert result.returncode == 0, result.stderr
    plan = json.loads(result.stdout)
    assert set(plan) == set(batch._scope.PUBLIC_FIELDS) and len(plan) == 12
    assert plan['target_ids'] == [A, B] and plan['plan_only'] is True
    assert plan['execution_allowed'] is False and plan['active_dispatch_allowed'] is False
    assert plan['profile_status'] == 'VALIDATED' and calls() == [['--list']]
    assert not marker.exists()


@pytest.mark.parametrize('config_line', ['Match exec /bin/false', 'Include /tmp/another.conf',
    'HostName localhost', 'ProxyCommand /bin/false', 'UserKnownHostsFile /dev/null'])
def test_config_file_unsafe_syntax(native, config_line, monkeypatch):
    source, calls, request, cfg, marker, trap = native
    exe = trap()
    monkeypatch.setenv('PATH', str(Path(exe).parent) + ':' + os.environ['PATH'])
    cfg.write_text(cfg.read_text() + config_line + '\n')
    ctx = batch._Context(source(), request())
    with pytest.raises(batch.Denied) as error:
        ctx._preflight()
    assert error.value.code == 4
    assert ctx._bound == ctx._proofs == {} and not marker.exists()
    assert calls() == [['--list']]


def test_native_cli_extra_vars_denied(native, monkeypatch):
    from ansible import context
    source, calls, request, _, _, _ = native
    path = source()
    monkeypatch.setattr(context, 'CLIARGS', {'extra_vars': ['ansible_become=true']})
    with pytest.raises(batch.Denied) as error:
        batch._Context(path, request())
    assert error.value.reason == 'NATIVE_CONTEXT_UNVERIFIED' and calls() == []


@pytest.fixture
def snapshot_source(tmp_path):
    # The ordered Host blocks, whitespace and absolute identity paths are
    # intentional: the snapshot must copy the validated bytes, not re-render
    # or interpret the OpenSSH config. All values are synthetic.
    source = tmp_path / 'source_config'
    source.write_bytes(b'# ordered configuration\nHost destination.example.invalid\n'
                       b' User dummy-destination\n IdentityFile /dummy/destination-id\n'
                       b'Host jump-one.example.invalid\n User dummy-jump\n'
                       b' IdentityFile /dummy/jump-one-id\nHost *\n'
                       b' StrictHostKeyChecking yes\n ControlMaster no\n'
                       b' ConnectTimeout 10\n BatchMode yes\n')
    argv = (b'ssh', b'-C', b'-o', b'User="dummy-cli"', b'-F', os.fsencode(source),
            b'-o', b'Port=2222', b'-o',
            b'ProxyJump=jumpuser@jump-one.example.invalid:2201,jump-two.example.invalid:2202',
            b'destination.example.invalid', b':')
    return source, argv


@pytest.fixture
def snapshot_consumer(monkeypatch):
    # Fixed-binary availability seam only. Never launch OpenSSH in these
    # cases; the real bounded child reads the actual -F path and returns its
    # bytes. The synthetic -G output is explicitly NOT an OpenSSH proof.
    original_is_file = Path.is_file
    original_access = os.access
    original_which = batch.shutil.which
    original_command = batch._scope.bounded_command
    monkeypatch.setattr(Path, 'is_file', lambda p: str(p) == '/usr/bin/ssh' or original_is_file(p))
    monkeypatch.setattr(os, 'access', lambda p, *a, **kw: str(p) == '/usr/bin/ssh'
                        or original_access(p, *a, **kw))
    monkeypatch.setattr(batch.shutil, 'which', lambda exe, *a, **kw: '/usr/bin/ssh'
                        if exe in ('ssh', '/usr/bin/ssh') else original_which(exe, *a, **kw))
    calls = []
    controls = {'before': lambda i: None, 'after': lambda i: None, 'error': None}

    def consume(argv, env, **limits):
        if argv[:2] != ['/usr/bin/ssh', '-G']:
            return original_command(argv, env, **limits)
        assert limits == {'timeout': 5, 'out_cap': 65536, 'err_cap': 65536}
        args = argv[2:]
        p = Path(args[args.index('-F') + 1])
        i = len(calls)
        controls['before'](i)
        try:
            # Record the exact file a consumer reopened, not just a hash or
            # the ultimate guard status. No unsafe config is interpreted.
            code = ('import pathlib,sys; p=pathlib.Path(sys.argv[1]); '
                    'sys.stdout.buffer.write(p.read_bytes())')
            rc, raw, err = original_command([sys.executable, '-I', '-B', '-c', code, str(p)],
                                            env, **limits)
            assert rc == 0 and not err
            calls.append((tuple(args), p, raw, p.parent.stat().st_mode & 0o777,
                          p.stat().st_mode & 0o777, p.stat().st_uid, p.is_symlink()))
            if controls['error'] is not None:
                raise controls['error']
            opts = dict(x.split('=', 1) for x in args if '=' in x)
            # Fixed, synthetic records exercise the existing output parser;
            # input option preservation is independently asserted below.
            fields = {'hostname': args[-1], 'user': opts.get('User', 'dummy').strip('"'),
                      'port': opts.get('Port', '22'), 'connecttimeout': '10',
                      'stricthostkeychecking': 'yes', 'controlmaster': 'no',
                      'controlpersist': 'no', 'canonicalizehostname': 'no',
                      'batchmode': 'yes', 'hashknownhosts': 'no', 'forwardagent': 'no', 'forwardx11': 'no',
                      'permitlocalcommand': 'no', 'identityfile': '/dummy/identity',
                      'userknownhostsfile': '/dummy/known_hosts',
                      'globalknownhostsfile': '/dummy/system_known_hosts',
                      'proxyjump': opts.get('ProxyJump', 'none')}
            out = ''.join(f'{k} {v}\n' for k, v in fields.items()).encode('ascii')
            return 0, out, b''
        finally:
            controls['after'](i)

    monkeypatch.setattr(batch._scope, 'bounded_command', consume)
    return calls, controls


def _assert_snapshot_calls(calls, source, validated):
    assert calls
    for args, p, raw, dm, fm, owner, symlink in calls:
        assert args.count('-F') == 1 and args[args.index('-F') + 1] == str(p)
        assert str(source) not in args and p != source
        assert raw == validated and (dm, fm, owner, symlink) == (0o700, 0o600, os.geteuid(), False)
        assert not p.exists() and not p.parent.exists()


def test_validated_snapshot_preserves_consumer_argv_and_bytes(snapshot_source, snapshot_consumer):
    source, argv = snapshot_source
    calls, _ = snapshot_consumer
    validated = source.read_bytes()
    fingerprint = batch._config(str(source))
    first = batch._effective_ssh(argv, fingerprint)
    assert len(first) == len(calls) == 3
    _assert_snapshot_calls(calls, source, validated)
    snapshot = calls[0][1]
    assert all(c[1] == snapshot for c in calls)
    original_args = [os.fsdecode(x) for x in argv[1:-1]]
    expected = original_args[:]
    expected[expected.index('-F') + 1] = str(snapshot)
    assert calls[0][0] == tuple(expected)
    assert calls[1][0] == ('-F', str(snapshot), '-o', 'Port=2202', '-o',
                           'ProxyJump=jumpuser@jump-one.example.invalid:2201', 'jump-two.example.invalid')
    assert calls[2][0] == ('-F', str(snapshot), '-o', 'Port=2201', '-o', 'User=jumpuser',
                           'jump-one.example.invalid')
    assert source.read_bytes() == validated and argv[5] == os.fsencode(source)
    assert batch._effective_ssh(argv, fingerprint) == first
    _assert_snapshot_calls(calls, source, validated)
    assert len(calls) == 6 and calls[3][1] != snapshot
    assert all(c[1] == calls[3][1] for c in calls[3:])


@pytest.mark.parametrize('consumer_index', [0, 1, 2], ids=['destination', 'jump-one', 'jump-two'])
@pytest.mark.parametrize('transient', [False, True], ids=['permanent', 'transient'])
def test_snapshot_source_reopen_race(snapshot_source, snapshot_consumer, consumer_index, transient):
    source, argv = snapshot_source
    calls, controls = snapshot_consumer
    validated = source.read_bytes()
    fingerprint = batch._config(str(source))
    unsafe = validated + b'Include /dummy/unvalidated.conf\n'

    def before(i):
        if i == consumer_index:
            source.write_bytes(unsafe)

    def after(i):
        if i == consumer_index and transient:
            source.write_bytes(validated)

    controls.update(before=before, after=after)
    # The stronger closure identity detects a restored transient edit as
    # well as a permanent change; every completed consumer still read only
    # the validated snapshot, never the changed source pathname.
    with pytest.raises(batch.Denied) as error:
        batch._effective_ssh(argv, fingerprint)
    assert error.value.code == 4
    assert error.value.reason == ('CONNECTION_CONTEXT_DRIFT' if transient else 'SSH_CONFIG_INCLUDE_UNVERIFIED')
    assert len(calls) == consumer_index + 1
    assert source.read_bytes() == (validated if transient else unsafe)
    _assert_snapshot_calls(calls, source, validated)
    assert len({c[1] for c in calls}) == 1


@pytest.mark.parametrize('unsafe', [False, True], ids=['valid-but-changed', 'unvalidated-include'])
def test_snapshot_refuses_source_drift_before_first_consumer(snapshot_source, snapshot_consumer, unsafe):
    source, argv = snapshot_source
    calls, _ = snapshot_consumer
    fingerprint = batch._config(str(source))
    source.write_bytes(source.read_bytes() + (b'Include /dummy/unvalidated.conf\n' if unsafe
                                             else b'# changed source\n'))
    with pytest.raises(batch.Denied) as error:
        batch._effective_ssh(argv, fingerprint)
    assert error.value.code == 4
    assert error.value.reason == ('SSH_CONFIG_INCLUDE_UNVERIFIED' if unsafe else 'CONNECTION_CONTEXT_DRIFT')
    assert calls == []


def test_snapshot_drift_after_validation_before_child(snapshot_source, snapshot_consumer, monkeypatch):
    source, argv = snapshot_source
    calls, _ = snapshot_consumer
    validated = source.read_bytes()
    fingerprint = batch._config(str(source))
    original = batch.tempfile.TemporaryDirectory
    paths = []

    def create(*a, **kw):
        directory = original(*a, **kw)
        paths.append(Path(directory.name))
        source.write_bytes(validated + b'# changed after validated read\n')
        return directory

    monkeypatch.setattr(batch.tempfile, 'TemporaryDirectory', create)
    with pytest.raises(batch.Denied) as error:
        batch._effective_ssh(argv, fingerprint)
    assert error.value.reason == 'CONNECTION_CONTEXT_DRIFT' and calls == []
    assert len(paths) == 1 and not paths[0].exists()


@pytest.mark.parametrize('failure', ['timeout', 'exception', 'interrupt'])
def test_snapshot_cleanup_on_consumer_failure(snapshot_source, snapshot_consumer, failure):
    source, argv = snapshot_source
    calls, controls = snapshot_consumer
    exc = {'timeout': batch.Denied(3, 'INVENTORY_TIMEOUT'), 'exception': RuntimeError('synthetic'),
           'interrupt': KeyboardInterrupt()}[failure]
    controls['error'] = exc
    validated = source.read_bytes()
    with pytest.raises(type(exc)) as error:
        batch._effective_ssh(argv, batch._config(str(source)))
    assert error.value is exc and len(calls) == 1
    _assert_snapshot_calls(calls, source, validated)
    assert source.read_bytes() == validated


def test_snapshot_creation_failure_is_closed(snapshot_source, snapshot_consumer, monkeypatch):
    source, argv = snapshot_source
    calls, _ = snapshot_consumer
    original = os.open
    paths = []

    def deny(path, flags, *args, **kwargs):
        p = Path(path)
        if p.name == 'config' and p.parent.name.startswith('pqc-ssh-'):
            paths.append(p.parent)
            raise PermissionError('synthetic creation failure')
        return original(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, 'open', deny)
    with pytest.raises(batch.Denied) as error:
        batch._effective_ssh(argv, batch._config(str(source)))
    assert error.value.reason == 'SSH_CONFIG_SNAPSHOT_ERROR' and calls == []
    assert len(paths) == 1 and not paths[0].exists()


def test_snapshot_cleanup_failure_discards_completed_proof(snapshot_source, snapshot_consumer, monkeypatch):
    source, argv = snapshot_source
    calls, _ = snapshot_consumer
    original = batch.tempfile.TemporaryDirectory.cleanup

    def fail_after_cleanup(directory):
        original(directory)
        if Path(directory.name).name.startswith('pqc-ssh-'):
            # Reported cleanup failure must deny even after all valid output.
            # Remove the test directory first so this oracle leaks no files.
            raise OSError('synthetic cleanup failure')

    monkeypatch.setattr(batch.tempfile.TemporaryDirectory, 'cleanup', fail_after_cleanup)
    with pytest.raises(batch.Denied) as error:
        batch._effective_ssh(argv, batch._config(str(source)))
    assert error.value.reason == 'SSH_CONFIG_SNAPSHOT_CLEANUP_FAILED' and len(calls) == 3
    _assert_snapshot_calls(calls, source, source.read_bytes())


def test_native_guard_uses_snapshots_and_terminal_stop(native, snapshot_consumer, monkeypatch):
    from ansible.plugins.connection import ssh
    source, provider_calls, request, cfg, marker, _ = native
    calls, controls = snapshot_consumer
    validated = cfg.read_bytes()
    ctx = batch._Context(source(), request())
    original_runs = []

    def deny_run(*args, **kwargs):
        original_runs.append(True)
        pytest.fail('original native _run must not be called')

    monkeypatch.setattr(ssh.Connection, '_run', deny_run)
    ctx._preflight()
    assert len(calls) == 4 and set(ctx._proofs) == {A, B}
    assert all(os.fsencode(cfg) in proof[0] for proof in ctx._proofs.values())
    # Clean positive path: all original native transport calls remain blocked.
    with pytest.raises(batch.Denied) as error:
        ctx._boundary(A)
    assert error.value.code == 2 and error.value.reason == 'LIVE_NOT_AVAILABLE'
    assert len(calls) == 10 and original_runs == [] and not marker.exists()
    assert provider_calls() == [['--list']] and cfg.read_bytes() == validated
    _assert_snapshot_calls(calls, cfg, validated)
    assert len({c[1] for c in calls}) == 5
    # Inject a restored edit on the retained connection's last jump proof.
    controls['before'] = lambda i: cfg.write_bytes(validated + b'Include /dummy/unvalidated.conf\n') if i == 15 else None
    controls['after'] = lambda i: cfg.write_bytes(validated) if i == 15 else None
    with pytest.raises(batch.Denied) as error:
        ctx._boundary(A)
    assert error.value.code == 4 and error.value.reason == 'CONNECTION_CONTEXT_DRIFT'
    assert len(calls) == 16 and original_runs == [] and not marker.exists()
    assert provider_calls() == [['--list']] and cfg.read_bytes() == validated
    _assert_snapshot_calls(calls, cfg, validated)
    # Persistent drift must stop before another consumer.
    cfg.write_bytes(validated + b'# persistent edit\n')
    with pytest.raises(batch.Denied) as error:
        ctx._boundary(A)
    assert error.value.reason == 'CONNECTION_CONTEXT_DRIFT'
    assert original_runs == [] and not marker.exists() and len(calls) == 16
    _assert_snapshot_calls(calls, cfg, validated)


@pytest.mark.parametrize('line, reason', [
    (b'Include /dummy/unvalidated.conf\n', 'SSH_CONFIG_INCLUDE_UNVERIFIED'),
    (b'Match exec /dummy/never-execute\n', 'SSH_CONFIG_UNVERIFIED'),
])
def test_snapshot_stable_unsafe_zero_child(snapshot_source, snapshot_consumer, line, reason):
    import hashlib
    source, argv = snapshot_source
    calls, _ = snapshot_consumer
    raw = source.read_bytes() + line
    source.write_bytes(raw)
    # Even an exact hash of stable disallowed content is not validation.
    with pytest.raises(batch.Denied) as error:
        batch._effective_ssh(argv, hashlib.sha256(raw).hexdigest())
    assert error.value.code == 4 and error.value.reason == reason and calls == []


# Only a private engineering harness may replace this test fixture's path.
# No product option, environment variable or inventory field selects it.
_TEST_NATIVE_CLIENT = Path('/usr/bin/ssh')


@pytest.fixture
def native_client(monkeypatch):
    if not _TEST_NATIVE_CLIENT.is_file():
        pytest.skip('NOT_TESTED: approved actual OpenSSH client unavailable')
    if _TEST_NATIVE_CLIENT != Path('/usr/bin/ssh'):
        monkeypatch.setattr(batch, '_fixed_ssh', lambda argv: _TEST_NATIVE_CLIENT)
    original = batch._scope.bounded_command
    calls = []

    def observed(argv, env, **limits):
        result = original(argv, env, **limits)
        if argv[:2] == [str(_TEST_NATIVE_CLIENT), '-G']:
            assert limits['timeout'] <= 5 and limits['out_cap'] == limits['err_cap'] == 65536
            assert result[0] == 0
            p = Path(argv[argv.index('-F') + 1])
            fields = {}
            for line in result[1].decode('utf-8').splitlines():
                key, value = line.split(' ', 1)
                fields.setdefault(key, []).append(value)
            calls.append((tuple(argv[2:]), p, fields))
        return result

    monkeypatch.setattr(batch._scope, 'bounded_command', observed)
    return original, calls


def _native_fields(command, args):
    rc, out, _ = command([str(_TEST_NATIVE_CLIENT), '-G', *args], dict(os.environ),
                         timeout=5, out_cap=65536, err_cap=65536)
    assert rc == 0
    fields = {}
    for line in out.decode('utf-8').splitlines():
        k, v = line.split(' ', 1)
        fields.setdefault(k, []).append(v)
    return fields


def _without_mux(fields):
    return {k: v for k, v in fields.items() if k not in ('controlmaster','controlpersist','controlpath')}


def _assert_no_mux(fields):
    assert fields['controlmaster'] == ['false'] and fields['controlpersist'] == ['no']
    assert fields.get('controlpath', ['none']) == ['none']


def test_b_native_explicit_closure_and_no_mux(native, native_client, tmp_path, monkeypatch):
    from ansible.plugins.connection import ssh
    source, provider_calls, request, cfg, marker, _ = native
    command, consumers = native_client
    mux = tmp_path / 'mux-must-not-exist'
    parts = tmp_path / 'parts'; parts.mkdir(mode=0o700)
    inner = parts / 'inner'; inner.mkdir(mode=0o700)
    (inner / '00.conf').write_text('Host jump-two.example.invalid\n User jump-second\n Host *\n Ciphers aes256-ctr\n')
    (parts / '10.conf').write_text(f'Include {inner}/*.conf\nHost *\nPort 2233\n')
    (parts / '20.conf').write_text('Host *\nPort 2244\n')
    cfg.write_text(f'Include {parts}/*.conf {parts}/empty-*.conf\n'
                   'Host *\nBatchMode yes\nStrictHostKeyChecking yes\nConnectTimeout 10\n'
                   'ControlMaster auto\nControlPersist 60s\n'
                   f'ControlPath {mux}/%C\nMatch final all\nIdentityFile /dummy/identity\n')
    raw = f'-C -o ControlMaster=auto -o ControlPersist=60s -F {cfg}'
    chain = 'jumpuser@jump-one.example.invalid:2201,jump-two.example.invalid:2202'
    override = {h: {'ansible_ssh_args': raw, 'ansible_ssh_common_args': f'-o ProxyJump={chain}',
                    'ansible_control_path_dir': str(mux), 'ansible_control_path': '%(directory)s/%%h-%%p-%%r'}
                for h in (A, B)}
    ctx = batch._Context(source(overrides=override), request())
    ran = []
    def deny_run(*a, **kw):
        ran.append(True)
        pytest.fail('original _run must not execute')
    monkeypatch.setattr(ssh.Connection, '_run', deny_run)
    ctx._preflight()
    assert len(consumers) == 6 and not mux.exists() and ran == []
    assert provider_calls() == [['--list']]
    dest, last, first = consumers[:3]
    assert dest[1] == last[1] == first[1] and not dest[1].parent.exists()
    for _, _, f in (dest, last, first):
        _assert_no_mux(f)
        assert f['ciphers'] == ['aes256-ctr']
    assert last[2]['user'] == ['jump-second'] and last[2]['port'] == ['2202']
    assert last[2]['proxyjump'] == ['jumpuser@jump-one.example.invalid:2201']
    assert first[2]['user'] == ['jumpuser'] and first[2]['port'] == ['2201']
    for args, snapshot, f in (dest, last, first):
        # Direct real OpenSSH baseline on the validated synthetic source;
        # compare every effective field except the owner-approved mux change.
        baseline = list(args); baseline[baseline.index('-F') + 1] = str(cfg)
        assert _without_mux(_native_fields(command, baseline)) == _without_mux(f)
    assert not mux.exists()
    conn = ctx._bound[A]
    saved = batch._native_raw(conn)[0]
    with pytest.raises(batch.Denied) as exc:
        ctx._boundary(A)
    assert exc.value.reason == 'LIVE_NOT_AVAILABLE' and ran == [] and not marker.exists()
    assert batch._native_raw(conn)[0] == saved and not mux.exists()
    # Same effective no-mux argv, but a different raw intent is still drift.
    conn.set_option('ssh_args', raw.replace('60s', '90s'))
    with pytest.raises(batch.Denied) as exc:
        ctx._boundary(A)
    assert exc.value.reason == 'CONNECTION_CONTEXT_DRIFT' and ran == [] and not mux.exists()


def test_b_native_synthetic_implicit_source_selection(native, native_client, tmp_path, monkeypatch):
    # Controlled source-selection oracle; does not qualify the installed
    # client's real compiled implicit system pathname.
    source, provider_calls, request, _, _, _ = native
    command, consumers = native_client
    user, system = tmp_path/'user', tmp_path/'system'
    user.mkdir(mode=0o700); system.mkdir(mode=0o700)
    monkeypatch.setattr(batch, '_implicit_roots', lambda: (user, system, ('synthetic-selection-only',)))
    (user/'10.conf').write_text('Host *\n Port 2233\n Ciphers aes256-ctr\n')
    (system/'10.conf').write_text('Host *\n Port 2244\n BatchMode yes\n StrictHostKeyChecking yes\n')
    (user/'config').write_text('Include 10.conf empty-*.conf\nHost *\n ControlMaster auto\n ControlPersist 60s\n')
    (system/'ssh_config').write_text('Include 10.conf\nHost *\nConnectTimeout 10\n')
    raw = '-C -o ControlMaster=auto -o ControlPersist=60s'
    overrides = {h: {'ansible_ssh_args': raw, 'ansible_ssh_common_args': ''} for h in (A,B)}
    ctx = batch._Context(source(overrides=overrides), request())
    ctx._preflight()
    assert len(consumers) == 2 and provider_calls() == [['--list']]
    assert all(b'-F' not in ctx._proofs[h][0] for h in (A,B))
    assert consumers[1][2]['port'] == ['2233'] and consumers[1][2]['batchmode'] == ['yes']
    _assert_no_mux(consumers[1][2])
    baseline = tmp_path/'baseline'
    baseline.write_text(f'Include {user}/10.conf\nControlMaster auto\nControlPersist 60s\n'
                        f'Include {system}/10.conf\nConnectTimeout 10\n')
    for args, snapshot, fields in consumers:
        ba = list(args); ba[ba.index('-F') + 1] = str(baseline)
        assert _without_mux(_native_fields(command, ba)) == _without_mux(fields)
        assert not snapshot.parent.exists()
    (user/'empty-new.conf').write_text('Host *\n User drift\n')
    with pytest.raises(batch.Denied) as exc:
        ctx._boundary(B)
    assert exc.value.reason == 'CONNECTION_CONTEXT_DRIFT'


@pytest.mark.parametrize('case', ['cycle','depth','files','bytes','aggregate','enumeration','symlink','secret','exec','foreign'])
def test_b_closure_rejects_unsafe_or_unbounded(tmp_path, case):
    root = tmp_path/'config'
    root.write_text('Host *\nBatchMode yes\n')
    if case == 'cycle':
        root.write_text(f'Include {root}\n')
    elif case == 'depth':
        prev = root
        for i in range(9):
            nxt = tmp_path/f'{i}.conf'; prev.write_text(f'Include {nxt}\n'); prev = nxt
        prev.write_text('Host *\n')
    elif case == 'files':
        for i in range(32):
            (tmp_path/f'{i}.conf').write_text('Host *\n')
        root.write_text(f'Include {tmp_path}/*.conf\n')
    elif case == 'bytes':
        root.write_bytes(b'#'+b'x'*65536)
    elif case == 'aggregate':
        for i in range(5):
            (tmp_path/f'{i}.conf').write_bytes(b'#'+b'x'*65534+b'\n')
        root.write_text(f'Include {tmp_path}/*.conf\n')
    elif case == 'enumeration':
        for i in range(257):
            (tmp_path/f'item-{i}').touch()
        root.write_text(f'Include {tmp_path}/empty-*.conf\n')
    elif case == 'symlink':
        other = tmp_path/'link.conf'; other.symlink_to(root)
        root.write_text(f'Include {other}\n')
    elif case == 'secret':
        # Synthetic name only; do not create or read a private key.
        root.write_text(f'Include {tmp_path}/id_rsa\n')
    elif case == 'exec':
        root.write_text('Host never.example.invalid\n Match exec /dummy/never-execute\n')
    else:
        root.write_text('Include /dummy/unvalidated.conf\n')
    with pytest.raises(batch.Denied) as exc:
        batch._config(str(root))
    assert exc.value.code == 4


def test_b_native_worker_consumption_no_mux(native, native_client, tmp_path, monkeypatch):
    from ansible.plugins.connection import ssh
    source, provider_calls, request, cfg, marker, _ = native
    _, consumers = native_client
    mux = tmp_path/'worker-mux-must-not-exist'
    raw = f'-C -F {cfg} -o ControlMaster=auto -o ControlPersist=60s'
    overrides = {h: {PKG: True, 'ansible_ssh_args': raw, 'ansible_control_path_dir': str(mux)}
                 for h in (A,B)}
    ctx = batch._Context(source(overrides=overrides), request(**{f:f == PKG for f in batch._COLLECTORS}))
    parent = os.getpid()
    command = batch._scope.bounded_command
    def proof(argv, env, **limits):
        result = command(argv, env, **limits)
        if argv[:2] == [str(_TEST_NATIVE_CLIENT), '-G']:
            assert result[0] == 0
            f = dict(x.split(' ',1) for x in result[1].decode().splitlines())
            assert f['controlmaster'] == 'false' and f['controlpersist'] == 'no'
            assert f.get('controlpath','none') == 'none'
            if os.getpid() != parent:
                with (tmp_path/f'proof-{os.getpid()}').open('a') as stream:
                    stream.write('native-proof\n')
        return result
    monkeypatch.setattr(batch._scope, 'bounded_command', proof)
    def forbidden(*a, **kw):
        marker.write_text('ORIGINAL_RUN_FORBIDDEN')
        raise AssertionError('original _run')
    monkeypatch.setattr(ssh.Connection, '_run', forbidden)
    monkeypatch.setattr(batch, '_restricted_connection', lambda name: 'CONNECTED')
    def adapter(name):
        (tmp_path/f'adapter-{name}').write_text(str(os.getpid()))
        return {'state':'COLLECTED','reason_code':'COLLECTED','rc':0,'collection_ids':[]}
    monkeypatch.setattr(batch, '_passive_adapters', lambda: {PKG:adapter})
    rc, manifest = batch.execute_batch(ctx)
    assert rc == 0 and batch.validate_terminal_manifest(manifest, rc) is None
    assert [h['host_state'] for h in manifest['hosts']] == ['COMPLETE','COMPLETE']
    pids = [int((tmp_path/f'adapter-{h}').read_text()) for h in (A,B)]
    assert len(set(pids)) == 2 and parent not in pids
    for pid in pids:
        assert len((tmp_path/f'proof-{pid}').read_text().splitlines()) == 2
    assert not marker.exists() and not mux.exists() and provider_calls() == [['--list']]
    assert consumers


def test_b_unqualified_implicit_entry_stops_before_consumer(native, monkeypatch, tmp_path):
    source, provider_calls, request, _, marker, _ = native
    raw = '-C -o ControlMaster=auto -o ControlPersist=60s'
    ctx = batch._Context(source(overrides={A: {'ansible_ssh_args': raw}}), request())
    # An unknown binary must fail regardless of whether a qualified stock
    # client happens to be installed on the test host.
    unknown = tmp_path/'unqualified-client'; unknown.write_bytes(b'not an approved ELF'); unknown.chmod(0o700)
    monkeypatch.setattr(batch, '_fixed_ssh', lambda argv: unknown)
    monkeypatch.setattr(batch, '_effective_ssh', lambda *a: pytest.fail('unqualified consumer'))
    with pytest.raises(batch.Denied) as exc:
        ctx._preflight()
    assert exc.value.reason == 'SSH_IMPLICIT_ROOT_UNQUALIFIED' and exc.value.code == 4
    assert not ctx._bound and not ctx._proofs and not marker.exists()
    assert provider_calls() == [['--list']]


@pytest.fixture
def qualified_native_client(native_client):
    import hashlib
    if hashlib.sha256(_TEST_NATIVE_CLIENT.read_bytes()).hexdigest() not in {digest for _,digest in batch._IMPLICIT_BUILDS}:
        pytest.skip('NOT_TESTED: qualified stock client build unavailable')
    return native_client


def _qualified_test_roots(monkeypatch, user, system):
    # The real resolver must qualify the actual selected ELF and its passwd
    # home before the test maps its two source roots into synthetic storage.
    # No qualification result, digest, or installed build identity is mocked.
    resolver = batch._implicit_roots
    def select():
        real_user, real_system, binding = resolver()
        assert real_system == Path('/etc/ssh')
        return user, system, binding
    monkeypatch.setattr(batch, '_implicit_roots', select)


def _managed_fixture(tmp_path, monkeypatch):
    system = tmp_path/'system-ssh'
    crypto = tmp_path/'etc'/'crypto-policies'
    policies = tmp_path/'usr'/'share'/'crypto-policies'
    for p in (system, crypto/'back-ends', crypto/'bridge', policies/'DEFAULT'):
        p.mkdir(mode=0o700, parents=True)
    # Fixture maps the OS trust roots and owner, not stat/link verification.
    # Product roots remain literal system paths with root ownership.
    monkeypatch.setattr(batch, '_managed_config_roots', lambda: ((system, crypto, policies), os.geteuid()))
    return system, crypto, policies


def test_b_native_qualified_implicit_client_identity(qualified_native_client, tmp_path, monkeypatch):
    import pwd
    user, system, binding = batch._implicit_roots()
    assert user == Path(pwd.getpwuid(os.geteuid()).pw_dir)/'.ssh'
    assert system == Path('/etc/ssh') and binding[1] == 'af3b04ec5653755032fc18ad02445e4e51170e75d8bac4265647d423caa9a83e'
    monkeypatch.setenv('HOME', str(tmp_path/'untrusted-home'))
    assert batch._implicit_roots() == (user, system, binding)
    # Unknown binary of the same size (no execution), and an unsafe mode.
    copy = tmp_path/'client-copy'
    raw = _TEST_NATIVE_CLIENT.read_bytes()
    copy.write_bytes(raw); copy.chmod(0o700)
    monkeypatch.setattr(batch, '_fixed_ssh', lambda argv: copy)
    assert batch._implicit_roots()[2][1] == binding[1]
    copy.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
    with pytest.raises(batch.Denied) as exc:
        batch._implicit_roots()
    assert exc.value.reason == 'SSH_IMPLICIT_ROOT_UNQUALIFIED'
    copy.write_bytes(raw); copy.chmod(0o722)
    with pytest.raises(batch.Denied) as exc:
        batch._implicit_roots()
    assert exc.value.reason == 'SSH_IMPLICIT_ROOT_UNQUALIFIED'
    copy.chmod(0o700)
    def unknown_home(uid):
        raise KeyError(uid)
    monkeypatch.setattr(pwd, 'getpwuid', unknown_home)
    with pytest.raises(batch.Denied) as exc:
        batch._implicit_roots()
    assert exc.value.reason == 'SSH_IMPLICIT_ROOT_UNQUALIFIED'


def test_b_native_qualified_implicit_absence_and_binary_drift(native, qualified_native_client, tmp_path, monkeypatch):
    source, provider_calls, request, _, marker, _ = native
    _, consumers = qualified_native_client
    user, system = tmp_path/'user-ssh', tmp_path/'system-ssh'
    user.mkdir(mode=0o700); system.mkdir(mode=0o700)
    # Use the same approved bytes at a private test path so replacement is
    # safe to exercise, never alter the reused client or installed binary.
    client = tmp_path/'client-copy'; data = _TEST_NATIVE_CLIENT.read_bytes()
    client.write_bytes(data); client.chmod(0o700)
    monkeypatch.setattr(batch, '_fixed_ssh', lambda argv: client)
    _qualified_test_roots(monkeypatch, user, system)
    baseline = batch._config(None)
    (system/'ssh_config').write_text('Host *\nBatchMode yes\nStrictHostKeyChecking yes\nConnectTimeout 10\n')
    assert batch._config(None) != baseline
    root_state = batch._config(None)
    # The fixture's observation follows the exact copied binary as well.
    monkeypatch.setattr(sys.modules[__name__], '_TEST_NATIVE_CLIENT', client)
    raw = '-C -o ControlMaster=auto -o ControlPersist=60s'
    ctx = batch._Context(source(overrides={h:{'ansible_ssh_args':raw} for h in (A,B)}),request())
    ctx._preflight()
    assert len(consumers)==4
    # A previously absent user config is part of the fingerprint too.
    (user/'config').write_text('Host *\nUser drift\n')
    with pytest.raises(batch.Denied) as exc:
        ctx._boundary(A)
    assert exc.value.reason == 'CONNECTION_CONTEXT_DRIFT' and len(consumers)==4
    (user/'config').unlink(); ctx._preflight()
    before=len(consumers); assert before==8
    root_state=batch._config(None)
    # Same-byte replacement changes the qualified identity, not the build.
    replacement = tmp_path/'replacement'; replacement.write_bytes(data); replacement.chmod(0o700)
    replacement.replace(client)
    assert batch._config(None) != root_state
    with pytest.raises(batch.Denied) as exc:
        ctx._boundary(A)
    assert exc.value.reason == 'CONNECTION_CONTEXT_DRIFT' and len(consumers)==before
    # Re-preflight rejects a changed client before any builder/consumer.
    # Do not execute the changed file.
    bad = data[:-1] + bytes([data[-1] ^ 1]); client.write_bytes(bad)
    with pytest.raises(batch.Denied) as exc:
        ctx._preflight()
    assert exc.value.reason == 'SSH_IMPLICIT_ROOT_UNQUALIFIED'
    assert len(consumers)==before and not marker.exists() and not ctx._bound and not ctx._proofs
    assert provider_calls() == [['--list']]


def test_b_native_qualified_implicit_os_link_worker(native, qualified_native_client, tmp_path, monkeypatch):
    from ansible.plugins.connection import ssh
    source, provider_calls, request, _, marker, _ = native
    command, consumers = qualified_native_client
    system, crypto, policies = _managed_fixture(tmp_path, monkeypatch)
    user = tmp_path/'user-ssh'; user.mkdir(mode=0o700)
    _qualified_test_roots(monkeypatch, user, system)
    (user/'10.conf').write_text('Host *\nPort 2233\n')
    (user/'config').write_text('Include 10.conf empty-*.conf\nHost *\nControlMaster auto\nControlPersist 60s\n')
    link = crypto/'back-ends'/'openssh.config'
    bridge = crypto/'bridge'/'openssh.config'
    target = policies/'DEFAULT'/'openssh.txt'
    target.write_text('Host *\nCiphers aes256-ctr\nMatch final all\nMACs hmac-sha2-256\n')
    bridge.symlink_to(target)
    link.symlink_to('../bridge/openssh.config')
    (system/'10.conf').write_text(f'Include {link}\nHost *\nPort 2244\nBatchMode yes\nStrictHostKeyChecking yes\n')
    (system/'ssh_config').write_text('Include 10.conf\nHost *\nConnectTimeout 10\n')
    graph = batch._ConfigClosure(None)
    assert len([e for e in graph.events if e[0]=='os-link']) == 2
    assert any(e[0]=='file' and e[1]==str(target) for e in graph.events)
    baseline = tmp_path/'baseline'
    baseline.write_text(f'Include {user}/10.conf\nControlMaster auto\nControlPersist 60s\n'
                        f'Include {system}/10.conf\nHost *\nConnectTimeout 10\n')
    raw = '-C -o ControlMaster=auto -o ControlPersist=60s'
    mux = tmp_path/'must-not-exist'
    chain = 'jumpuser@jump.example.invalid:2201'
    overrides = {h:{PKG:True,'ansible_ssh_args':raw,'ansible_ssh_common_args':f'-o ProxyJump={chain}',
                    'ansible_control_path_dir':str(mux)} for h in (A,B)}
    ctx = batch._Context(source(overrides=overrides), request(**{f:f==PKG for f in batch._COLLECTORS}))
    parent = os.getpid()
    def proof(argv, env, **limits):
        result = command(argv,env,**limits)
        if argv[:2] == [str(_TEST_NATIVE_CLIENT),'-G']:
            assert result[0] == 0 and limits['timeout'] <= 5
            fields = dict(x.split(' ',1) for x in result[1].decode().splitlines())
            assert fields['ciphers']=='aes256-ctr' and fields['macs']=='hmac-sha2-256'
            assert fields['controlmaster']=='false' and fields['controlpersist']=='no'
            assert fields.get('controlpath','none')=='none'
            if os.getpid()!=parent:
                with (tmp_path/f'proof-{os.getpid()}').open('a') as stream:
                    stream.write('native-proof\n')
        return result
    # Keep the actual native_client capture for parent baseline comparisons.
    observed = batch._scope.bounded_command
    def both(argv,env,**limits):
        if os.getpid()==parent:
            return observed(argv,env,**limits)
        return proof(argv,env,**limits)
    monkeypatch.setattr(batch._scope,'bounded_command',both)
    def forbidden(*a,**kw):
        marker.write_text('FORBIDDEN'); raise AssertionError('original _run')
    monkeypatch.setattr(ssh.Connection,'_run',forbidden)
    monkeypatch.setattr(batch,'_restricted_connection',lambda name:'CONNECTED')
    def adapter(name):
        (tmp_path/f'adapter-{name}').write_text(str(os.getpid()))
        return {'state':'COLLECTED','reason_code':'COLLECTED','rc':0,'collection_ids':[]}
    monkeypatch.setattr(batch,'_passive_adapters',lambda:{PKG:adapter})
    rc, manifest = batch.execute_batch(ctx)
    assert rc==0 and batch.validate_terminal_manifest(manifest,rc) is None
    assert [h['host_state'] for h in manifest['hosts']]==['COMPLETE','COMPLETE']
    pids=[int((tmp_path/f'adapter-{h}').read_text()) for h in (A,B)]
    assert len(set(pids))==2 and parent not in pids
    for pid in pids:
        assert len((tmp_path/f'proof-{pid}').read_text().splitlines())==2
    # Preflight and both dispatch checks deliberately re-prove the whole
    # target set. Every parent proof must still be a native consumer.
    assert len(consumers)>=4 and len(consumers)%4==0 and not marker.exists() and not mux.exists()
    for args,snapshot,fields in consumers:
        _assert_no_mux(fields)
        ba=list(args);ba[ba.index('-F')+1]=str(baseline)
        assert _without_mux(_native_fields(command,ba))==_without_mux(fields)
        assert not snapshot.parent.exists()
    assert provider_calls()==[['--list']]


@pytest.mark.parametrize('case', ['foreign','secret','cycle','dangling','unsafe-dir','unsafe-file','hardlink','depth','ambiguous','user-link','wrong-owner','dir-link'])
def test_b_managed_link_rejects_untrusted_or_unbounded(tmp_path, monkeypatch, case):
    system,crypto,policies=_managed_fixture(tmp_path,monkeypatch)
    cfg=tmp_path/'config'; link=crypto/'back-ends'/'openssh.config'
    target=policies/'DEFAULT'/'openssh.txt'; target.write_text('Host *\nCiphers aes256-ctr\n')
    cfg.write_text(f'Include {link}\n')
    if case=='foreign':
        outside=tmp_path/'outside.conf';outside.write_text('Host *\n');link.symlink_to(outside)
    elif case=='secret':
        link.symlink_to(policies/'DEFAULT'/'id_rsa')  # do not create a key
    elif case=='cycle':
        link.symlink_to(link)
    elif case=='dangling':
        link.symlink_to(policies/'DEFAULT'/'missing.conf')
    elif case=='unsafe-dir':
        target.parent.chmod(0o777);link.symlink_to(target)
    elif case=='unsafe-file':
        target.chmod(0o666);link.symlink_to(target)
    elif case=='hardlink':
        os.link(target,target.parent/'copy.conf');link.symlink_to(target)
    elif case=='depth':
        last=link
        for i in range(8):
            nxt=crypto/'bridge'/str(i)/'openssh.config'; nxt.parent.mkdir(mode=0o700);last.symlink_to(nxt);last=nxt
        last.symlink_to(target)
    elif case=='ambiguous':
        link.symlink_to('unknown/../openssh.config')
    elif case=='wrong-owner':
        link.symlink_to(target)
        monkeypatch.setattr(batch,'_managed_config_roots',lambda:((system,crypto,policies),os.geteuid()+1))
    elif case=='dir-link':
        alias=crypto/'alias'; alias.symlink_to(target.parent,target_is_directory=True)
        link.symlink_to(alias/'openssh.txt')
    else:
        private=tmp_path/'private.conf';private.symlink_to(target)
        cfg.write_text(f'Include {private}\n')
    monkeypatch.setattr(batch._scope,'bounded_command',lambda *a,**kw:pytest.fail('unsafe native child'))
    with pytest.raises(batch.Denied) as exc:
        batch._config(str(cfg))
    assert exc.value.code==4
    if case in ('foreign','secret','cycle','depth','ambiguous'):
        assert exc.value.reason=='SSH_CONFIG_OS_LINK_UNQUALIFIED'


def test_b_native_managed_link_snapshot_drift(native, native_client, tmp_path, monkeypatch):
    source,calls,request,cfg,marker,_=native
    _,consumers=native_client
    system,crypto,policies=_managed_fixture(tmp_path,monkeypatch)
    target=policies/'DEFAULT'/'openssh.txt';raw=b'Host *\nCiphers aes256-ctr\n';target.write_bytes(raw)
    alt=policies/'DEFAULT'/'openssh.config';alt.write_text('Host *\nCiphers aes128-ctr\n')
    link=crypto/'back-ends'/'openssh.config';link.symlink_to(target)
    cfg.write_text(cfg.read_text()+f'Include {link}\n')
    ctx=batch._Context(source(),request());ctx._preflight()
    assert len(consumers)==4 and all(c[2]['ciphers']==['aes256-ctr'] for c in consumers)
    # Actual retained boundary must reject even a retargeted-and-restored link.
    link.unlink();link.symlink_to(alt);link.unlink();link.symlink_to(target)
    with pytest.raises(batch.Denied) as exc:
        ctx._boundary(A)
    assert exc.value.reason=='CONNECTION_CONTEXT_DRIFT' and len(consumers)==4 and not marker.exists()
    # Separate, direct snapshot consumer: transient mutation cannot change
    # the private native parser bytes, and the late check must see drift.
    fp=batch._config(str(cfg))
    argv=ctx._proofs[A][0]
    original=batch._scope.bounded_command
    seen=[]
    def mutate(argv,env,**limits):
        if argv[:2]==[str(_TEST_NATIVE_CLIENT),'-G']:
            target.write_text('Host *\nCiphers aes128-ctr\n')
            try:
                rc,out,err=original(argv,env,**limits)
                assert b'ciphers aes256-ctr\n' in out
                seen.append(True)
                return rc,out,err
            finally:
                target.write_bytes(raw)
        return original(argv,env,**limits)
    monkeypatch.setattr(batch._scope,'bounded_command',mutate)
    with pytest.raises(batch.Denied) as exc:
        batch._effective_ssh(argv,fp)
    assert exc.value.reason=='CONNECTION_CONTEXT_DRIFT' and seen==[True]
    assert all(not snap.parent.exists() for _,snap,_ in consumers)


def test_b_native_qualified_duration_literal_equivalence(native_client, tmp_path):
    # This is the existing no-mux vocabulary, not a new duration budget.
    # The package-backed native parser admits compound literal durations.
    command, _ = native_client
    cfg = tmp_path/'config'
    for value, seconds in (('60s', '60'), ('1w', '604800'), ('604800', '604800'),
                           ('1h30m', '5400'), ('1H30M', '5400'), ('1m30', '90')):
        cfg.write_text('Host *\nControlMaster auto\nControlPersist '+value+'\n')
        fp = batch._config(str(cfg))
        baseline = _native_fields(command, ['-F', str(cfg), 'dummy.example.invalid'])
        assert baseline['controlpersist'] == [seconds]
        with batch._validated_snapshot(str(cfg), fp) as snapshot:
            fields = _native_fields(command, ['-F', snapshot, 'dummy.example.invalid'])
            _assert_no_mux(fields)
            assert _without_mux(fields) == _without_mux(baseline)
    for value in ('1w1s','1hX','1.5h','1h30m-1s','1s'*33):
        cfg.write_text('Host *\nControlMaster auto\nControlPersist '+value+'\n')
        with pytest.raises(batch.Denied) as exc:
            batch._config(str(cfg))
        assert exc.value.reason == 'UNSUPPORTED_SSH_OPTION'


# R2: stock settings are syntax/proof only, never a live environment grant.
def test_b_native_stock_config_and_consumed_argv(native, native_client, tmp_path, monkeypatch):
    from ansible.plugins.connection import ssh
    import shlex
    source, provider_calls, request, cfg, marker, _ = native
    command, consumers = native_client
    part = tmp_path/'stock.conf'
    kh = tmp_path/'synthetic-known-hosts'; kh.write_bytes(b'SYNTHETIC_ONLY\n')
    kh_before = (kh.read_bytes(), kh.stat().st_mtime_ns, kh.stat().st_ctime_ns)
    part.write_text('Host *\nSendEnv LANG LC_* COLORTERM NO_COLOR\nHashKnownHosts YES\n'
                    'SendEnv -LC_*\nSendEnv LC_TIME\n')
    cfg.write_text(f'Include {part}\nHost *\nBatchMode yes\nStrictHostKeyChecking yes\n'
                   f'ConnectTimeout 10\nUserKnownHostsFile {kh}\nControlMaster auto\n'
                   'ControlPersist 60s\nMatch final all\nSendEnv XMODIFIERS\n')
    # Explicit synthetic value must never be inherited by the proof child.
    monkeypatch.setenv('LC_PQC_SYNTHETIC_SENTINEL', 'synthetic-never-forward')
    observed = batch._scope.bounded_command
    def checked(argv, env, **limits):
        if argv[:2] == [str(_TEST_NATIVE_CLIENT), '-G']:
            assert env == {'PATH':'/usr/bin:/bin','LC_ALL':'C.UTF-8'}
        return observed(argv, env, **limits)
    monkeypatch.setattr(batch._scope, 'bounded_command', checked)
    raw = shlex.join(['-F',str(cfg),'-o','ControlMaster=auto','-o','ControlPersist=60s',
                      '-o','SendEnv=LANGUAGE LC_ALL','-o','HashKnownHosts=No'])
    mux = tmp_path/'mux-must-not-exist'
    overrides = {h:{'ansible_ssh_args':raw,'ansible_control_path_dir':str(mux)} for h in (A,B)}
    ctx = batch._Context(source(overrides=overrides), request())
    monkeypatch.setattr(ssh.Connection,'_run',lambda *a,**kw:pytest.fail('original _run'))
    ctx._preflight()
    assert len(consumers)==4 and provider_calls()==[['--list']]
    assert b'SendEnv=LANGUAGE LC_ALL' in ctx._proofs[A][0]
    for i,(args,snapshot,fields) in enumerate(consumers):
        baseline=list(args); baseline[baseline.index('-F')+1]=str(cfg)
        assert _without_mux(_native_fields(command,baseline))==_without_mux(fields)
        _assert_no_mux(fields)
        assert fields['hashknownhosts']==['no' if i%2==0 else 'yes']
        assert fields['sendenv'].count('LANG')==2 and 'LC_*' not in fields['sendenv']
        assert 'LC_TIME' in fields['sendenv'] and 'XMODIFIERS' in fields['sendenv']
        assert not snapshot.parent.exists()
    with pytest.raises(batch.Denied) as exc:
        ctx._boundary(A)
    assert exc.value.reason=='LIVE_NOT_AVAILABLE' and not marker.exists() and not mux.exists()
    assert (kh.read_bytes(),kh.stat().st_mtime_ns,kh.stat().st_ctime_ns)==kh_before
    # Even a benign admitted source edit invalidates the retained proof.
    part.write_text(part.read_text().replace('HashKnownHosts YES','HashKnownHosts no'))
    with pytest.raises(batch.Denied) as exc:
        ctx._boundary(A)
    assert exc.value.reason=='CONNECTION_CONTEXT_DRIFT'
    assert not marker.exists() and not mux.exists()


@pytest.mark.parametrize('key,value', [('SendEnv','PATH'),('SendEnv','SSH_AUTH_SOCK'),
    ('SendEnv','LC_X*'),('SendEnv','*'),('SendEnv','-PATH'),('SendEnv','lc_*'),
    ('SendEnv','LANG=secret'),('SendEnv','${LANG}'),('SendEnv','--LANG'),
    ('SendEnv','"LANG LC_*"'),('SendEnv',''),('SendEnv','LANG '*32+'LANG'),
    ('HashKnownHosts','maybe'),('SetEnv','LANG=en_US')])
def test_b_stock_syntax_rejects_both_sources(tmp_path,key,value):
    cfg=tmp_path/'config';cfg.write_text(f'Host *\n{key} {value}\n')
    with pytest.raises(batch.Denied) as exc:
        batch._config(str(cfg))
    assert exc.value.code==4
    with pytest.raises(batch.Denied) as exc:
        batch._args(['-o',key+'='+value])
    assert exc.value.code==4


def test_b_stock_sendenv_aggregate_limit(tmp_path):
    cfg=tmp_path/'config'; part=tmp_path/'part.conf'
    part.write_text('SendEnv '+' '.join(['LANG']*32)+'\n')
    cfg.write_text(('Include '+str(part)+'\n')*4)
    assert batch._ConfigClosure(str(cfg)).sendenv==128
    cfg.write_text(cfg.read_text()+'SendEnv LC_TIME\n')
    with pytest.raises(batch.Denied) as exc:
        batch._config(str(cfg))
    assert exc.value.reason=='SSH_CONFIG_LIMIT'
    options=['-o','SendEnv='+' '.join(['LANG']*32)]*4
    assert len(batch._args(options)[1])==4
    with pytest.raises(batch.Denied) as exc:
        batch._args(options+['-o','SendEnv=LC_TIME'])
    assert exc.value.reason=='SSH_CONFIG_LIMIT'


def test_b_native_stock_guard_rejects_raw_drift(native,native_client,tmp_path,monkeypatch):
    source, calls, request, cfg, marker, _ = native
    _, consumers = native_client
    cfg.write_text(cfg.read_text()+'SendEnv LANG LC_*\nHashKnownHosts yes\n')
    raw = f'-F {cfg} -o "SendEnv=LANGUAGE LC_ALL"'
    ctx = batch._Context(source(overrides={A:{'ansible_ssh_args':raw}}),request())
    ctx._preflight(); before=len(consumers)
    ctx._bound[A].set_option('ssh_args',raw.replace('LANGUAGE','LC_TIME'))
    with pytest.raises(batch.Denied) as exc:ctx._boundary(A)
    assert exc.value.reason=='CONNECTION_CONTEXT_DRIFT' and not marker.exists()
    assert len(consumers)>=before and calls()==[['--list']]


@pytest.fixture
def ol9_local_package(tmp_path,monkeypatch):
    """Private typed RPM records emitted by a real bounded fixture process.

    No installed OL RPM, RPM DB or vendor ELF is claimed by this test.
    Only fixed-path/owner inputs are mapped; product qualification is real.
    """
    import hashlib
    root=tmp_path/'rpm-fixture';root.mkdir(mode=0o700)
    bindir=root/'bin';bindir.mkdir(mode=0o700)
    db=root/'rpmdb';db.mkdir(mode=0o700)
    etc=root/'etc';etc.mkdir(mode=0o700)
    usr=root/'usr'/'lib';usr.mkdir(mode=0o700,parents=True)
    os_release=etc/'os-release'; target=usr/'os-release'
    target.write_text('ID="ol"\nVERSION_ID="9.7"\n');os_release.symlink_to('../usr/lib/os-release')
    rpm=bindir/'rpm'; client=bindir/'ssh';client.write_bytes(b'SYNTHETIC ELF CONTENT FOR METADATA TEST');client.chmod(0o700)
    dbfile=db/'rpmdb.sqlite';dbfile.write_bytes(b'SYNTHETIC RPMDB')
    rc=usr/'rpmrc';rc.write_text('# synthetic trusted rpmrc\n')
    macros=usr/'macros';macros.write_text('# synthetic trusted macros\n')
    calls=root/'queries';pid=root/'query-pid'
    paths={'_OL9_SSH':client,'_OL9_RPM':rpm,'_OL9_OS_RELEASE':os_release,'_OL9_OS_RELEASE_TARGET':target,
           '_OL9_RPM_DB':db,'_OL9_RPM_RC':rc,'_OL9_RPM_MACROS':macros}
    for key,value in paths.items():monkeypatch.setattr(batch,key,value)
    monkeypatch.setattr(batch,'_OL9_OWNER',os.geteuid())
    monkeypatch.setattr(batch,'_fixed_ssh',lambda argv:client)
    # Force the tested RPM branch even when a native consumer copies the
    # existing approved Debian engineering ELF into the private fixture.
    monkeypatch.setattr(batch,'_IMPLICIT_BUILDS',{})
    def emit(version='8.7p1',release='46.0.2.el9',mode='normal',change=None,algo='8'):
        name='openssh-clients';vendor='Oracle America';arch=os.uname().machine;epoch='1'
        source=f'openssh-{version}-{release}.src.rpm'; data=client.read_bytes()
        digest=hashlib.new(batch._OL9_DIGESTS.get(algo,'sha256'),data).hexdigest();size=str(len(data))
        header=[name,epoch,version,release,arch,vendor,source,algo]
        if change:
            i,value=change
            if i<8: header[i]=value
            elif i==8:size=value
            elif i==9:digest=value
        metadata='PQC_PACKAGE\t'+'\t'.join(header)+'\n'+f'PQC_FILE\t/usr/bin/ssh\t{size}\t{digest}\nPQC_FILE\t/etc/ssh/ssh_config\t10\t'+'a'*64+'\n'
        if mode=='multi':metadata+=metadata
        if mode=='wrong-owner-file':metadata=metadata.replace('/usr/bin/ssh','/usr/bin/other')
        if mode=='duplicate-file':metadata+=metadata.splitlines()[1]+'\n'
        if mode=='missing-config':metadata='\n'.join(metadata.splitlines()[:2])+'\n'
        args=['--noplugins','--rcfile',str(rc),'--macros',str(macros),'--dbpath',str(db),
              '--define','_db_backend sqlite','-qf','--queryformat',batch._OL9_QF,'/usr/bin/ssh']
        # This fixture asserts the real invocation, not the requested result.
        code=f'''#!{sys.executable}
import os,sys,time,pathlib
assert sys.argv[1:]=={args!r},repr(sys.argv[1:])
assert os.environ.get('HOME')=='/' and os.environ.get('LC_ALL')=='C'
assert 'LC_PQC_SYNTHETIC_SENTINEL' not in os.environ
with pathlib.Path({str(calls)!r}).open('a') as f:f.write(str(os.getpid())+'\\n')
pathlib.Path({str(pid)!r}).write_text(str(os.getpid()))
if {mode!r}=='timeout':time.sleep(10)
if {mode!r}=='cap':sys.stdout.write('x'*70000);sys.exit(0)
if {mode!r}=='db-drift':pathlib.Path({str(dbfile)!r}).write_bytes(b'CHANGED SYNTHETIC RPMDB')
if {mode!r}=='binary-drift':pathlib.Path({str(client)!r}).write_bytes(b'CHANGED SYNTHETIC CLIENT')
if {mode!r}=='error':sys.exit(1)
if {mode!r}=='stderr':sys.stderr.write('synthetic warning')
sys.stdout.write({metadata!r})
'''
        rpm.write_text(code);rpm.chmod(0o700)
    return {'emit':emit,'client':client,'rpm':rpm,'target':target,'os_release':os_release,
            'db':db,'dbfile':dbfile,'calls':calls,'pid':pid,'root':root,'rc':rc,'macros':macros}


@pytest.mark.parametrize('version,release,algo',[('8.7p1','46.0.2.el9','8'),('9.9p1','7.0.2.el9_8','8'),
                                               ('9.9p1','8.0.1.el9_9','10')])
def test_b_ol9_local_package_qualification(ol9_local_package,version,release,algo,monkeypatch):
    f=ol9_local_package;f['emit'](version,release,algo=algo)
    monkeypatch.setenv('LC_PQC_SYNTHETIC_SENTINEL','synthetic-never-inherit')
    user,system,binding=batch._implicit_roots()
    assert system==Path('/etc/ssh') and user==batch._passwd_ssh_dir()
    assert binding[0]=='Oracle Linux 9 installed openssh-clients'
    assert binding[1][0][2:4]==(version,release)
    assert binding[1][0][-1]==algo and len(f['calls'].read_text().splitlines())==1
    assert batch._implicit_roots()==(user,system,binding)
    assert len(f['calls'].read_text().splitlines())==2
    # There is no persistent cache; legitimate later package updates
    # receive a new identity even when a test fixture keeps its ELF bytes.
    f['emit'](version,'99.1.el9_9',algo=algo)
    assert batch._implicit_roots()[2]!=binding


@pytest.mark.parametrize('case',['os','os-version','os-link','unsafe-rpm','unsafe-db','unsafe-db-dir','db-link','wrong-owner',
    'missing-db','missing-rpm','unsafe-client','unsafe-macros','package','vendor','release','arch','source','epoch',
    'version','digest-algorithm','size','digest','multi','wrong-owner-file','duplicate-file','missing-config',
    'error','stderr','db-drift','binary-drift','timeout','cap'])
def test_b_ol9_local_package_rejects(ol9_local_package,case,monkeypatch):
    f=ol9_local_package
    changes={'package':(0,'gsi-openssh-clients'),'vendor':(5,'Other Vendor'),'release':(3,'1.el8'),
             'arch':(4,'i686'),'source':(6,'other.src.rpm'),'epoch':(1,'unknown'),
             'version':(2,'10.0p1'),'digest-algorithm':(7,'1'),'size':(8,'1'),'digest':(9,'0'*64)}
    modes={'multi','wrong-owner-file','duplicate-file','missing-config','error','stderr','db-drift','binary-drift','timeout','cap'}
    f['emit'](change=changes.get(case),mode=case if case in modes else 'normal')
    if case=='os':f['target'].write_text('ID=rhel\nVERSION_ID=9.7\n')
    if case=='os-version':f['target'].write_text('ID=ol\nVERSION_ID=10\n')
    if case=='os-link':
        f['os_release'].unlink();f['os_release'].symlink_to('/untrusted/os-release')
    if case=='unsafe-rpm':f['rpm'].chmod(0o722)
    if case=='unsafe-client':f['client'].chmod(0o722)
    if case=='unsafe-db':f['dbfile'].chmod(0o622)
    if case=='unsafe-db-dir':f['db'].chmod(0o722)
    if case=='db-link':
        f['dbfile'].unlink();f['dbfile'].symlink_to(f['target'])
    if case=='missing-db':f['dbfile'].unlink()
    if case=='missing-rpm':f['rpm'].unlink()
    if case=='unsafe-macros':f['macros'].chmod(0o622)
    if case=='wrong-owner':monkeypatch.setattr(batch,'_OL9_OWNER',os.geteuid()+1)
    started=time.monotonic()
    with pytest.raises(batch.Denied) as exc:
        if case=='timeout':
            with batch._deadline(1.0):batch._implicit_roots()
        else:batch._implicit_roots()
    assert exc.value.reason=='SSH_IMPLICIT_ROOT_UNQUALIFIED'
    if case in changes or case in modes:
        assert len(f['calls'].read_text().splitlines())==1
        p=int(f['pid'].read_text());assert not Path(f'/proc/{p}').exists() and not batch._scope.group_exists(p)
    else:assert not f['calls'].exists()
    if case=='timeout':assert time.monotonic()-started<1.0


def test_b_native_ol9_stock_worker_and_late_drift(native,native_client,ol9_local_package,tmp_path,monkeypatch):
    from ansible.plugins.connection import ssh
    source,provider_calls,request,_,marker,_=native
    command,_=native_client;f=ol9_local_package
    # Synthetic RPM identity, actual approved native consumer (not an OL ELF).
    f['client'].write_bytes(_TEST_NATIVE_CLIENT.read_bytes());f['client'].chmod(0o700)
    f['emit']('9.9p1','7.0.2.el9_8');client=f['client']
    user=tmp_path/'user';system=tmp_path/'system';user.mkdir(mode=0o700);system.mkdir(mode=0o700)
    _qualified_test_roots(monkeypatch,user,system)
    (user/'config').write_text('Host *\nSendEnv LANG LC_*\nControlMaster auto\nControlPersist 60s\n')
    kh=tmp_path/'known-hosts-test';kh.write_text('SYNTHETIC_ONLY\n');kh_before=(kh.read_bytes(),kh.stat().st_mtime_ns,kh.stat().st_ctime_ns)
    (system/'ssh_config').write_text(f'Host *\nBatchMode yes\nStrictHostKeyChecking yes\nConnectTimeout 10\n'
                                     f'UserKnownHostsFile {kh}\nHashKnownHosts yes\nSendEnv -LC_* LC_TIME\n')
    raw='-C -o ControlMaster=auto -o ControlPersist=60s -o "SendEnv=LANGUAGE LC_ALL"'
    mux=tmp_path/'must-not-exist'
    chain='jumpuser@jump.example.invalid:2201'
    overrides={h:{PKG:True,'ansible_ssh_args':raw,'ansible_ssh_common_args':f'-o ProxyJump={chain}',
                  'ansible_control_path_dir':str(mux)} for h in (A,B)}
    parent=os.getpid();observations=[]
    baseline=tmp_path/'baseline';baseline.write_text(f'Include {user}/config\nInclude {system}/ssh_config\n')
    def proof(argv,env,**limits):
        r=command(argv,env,**limits)
        if argv[:2]==[str(client),'-G']:
            assert env=={'PATH':'/usr/bin:/bin','LC_ALL':'C.UTF-8'} and r[0]==0
            fields={}
            for line in r[1].decode().splitlines():
                k,v=line.split(' ',1);fields.setdefault(k,[]).append(v)
            _assert_no_mux(fields);assert fields['hashknownhosts']==['yes']
            assert 'LANG' in fields['sendenv'] and 'LC_*' not in fields['sendenv'] and 'LC_TIME' in fields['sendenv']
            if os.getpid()==parent:observations.append((tuple(argv[2:]),fields))
            else:
                with (tmp_path/f'worker-proof-{os.getpid()}').open('a') as stream:stream.write('native\n')
        return r
    monkeypatch.setattr(batch._scope,'bounded_command',proof)
    monkeypatch.setattr(ssh.Connection,'_run',lambda *a,**k:pytest.fail('original _run'))
    ctx=batch._Context(source(overrides=overrides),request(**{f:f==PKG for f in batch._COLLECTORS}))
    # A destination+one jump consumes exactly one package query inside the
    # proof; _native_argv and each later dispatch still freshly qualify.
    binding=batch._native_binding(ctx,A);argv,fp=batch._native_argv(binding)
    count=len(f['calls'].read_text().splitlines());assert count==1
    assert len(batch._effective_ssh(argv,fp))==2
    assert len(f['calls'].read_text().splitlines())==count+1
    ctx._preflight()
    before=len(observations); f['dbfile'].write_bytes(b'LATE SYNTHETIC RPM DB CHANGE')
    with pytest.raises(batch.Denied) as exc:ctx._boundary(A)
    assert exc.value.reason=='CONNECTION_CONTEXT_DRIFT' and len(observations)==before
    # Requalify the changed but trusted synthetic DB only through a fresh
    # preflight. Real native WorkerProcess path still consumes the proof.
    monkeypatch.setattr(batch,'_restricted_connection',lambda name:'CONNECTED')
    def adapter(name):
        (tmp_path/f'adapter-{name}').write_text(str(os.getpid()))
        return {'state':'COLLECTED','reason_code':'COLLECTED','rc':0,'collection_ids':[]}
    monkeypatch.setattr(batch,'_passive_adapters',lambda:{PKG:adapter})
    rc,manifest=batch.execute_batch(ctx)
    assert rc==0 and batch.validate_terminal_manifest(manifest,rc) is None
    assert [h['host_state'] for h in manifest['hosts']]==['COMPLETE','COMPLETE']
    pids=[int((tmp_path/f'adapter-{h}').read_text()) for h in (A,B)]
    assert len(set(pids))==2 and parent not in pids
    for pid in pids:assert len((tmp_path/f'worker-proof-{pid}').read_text().splitlines())==2
    assert not mux.exists() and not marker.exists() and provider_calls()==[['--list']]
    assert (kh.read_bytes(),kh.stat().st_mtime_ns,kh.stat().st_ctime_ns)==kh_before
    # Every observed real -G input agrees with the original ordered roots.
    for args,fields in observations:
        ba=list(args);ba[ba.index('-F')+1]=str(baseline)
        rr=command([str(client),'-G',*ba],{'PATH':'/usr/bin:/bin','LC_ALL':'C.UTF-8'},timeout=5,out_cap=65536,err_cap=65536)
        assert rr[0]==0
        expected={}
        for line in rr[1].decode().splitlines():
            k,v=line.split(' ',1);expected.setdefault(k,[]).append(v)
        assert _without_mux(expected)==_without_mux(fields)


def test_b_native_ol9_stock_in_proof_db_drift(native,native_client,ol9_local_package,tmp_path,monkeypatch):
    source,provider_calls,request,_,marker,_=native
    command,_=native_client;f=ol9_local_package
    f['client'].write_bytes(_TEST_NATIVE_CLIENT.read_bytes());f['client'].chmod(0o700)
    f['emit']('8.7p1','46.0.2.el9');client=f['client']
    user=tmp_path/'user';system=tmp_path/'system';user.mkdir(mode=0o700);system.mkdir(mode=0o700)
    _qualified_test_roots(monkeypatch,user,system)
    (system/'ssh_config').write_text('Host *\nBatchMode yes\nStrictHostKeyChecking yes\nConnectTimeout 10\n'
                                    'SendEnv LANG LC_*\nHashKnownHosts yes\n')
    raw='-C -o ControlMaster=auto -o ControlPersist=60s'
    ctx=batch._Context(source(overrides={h:{'ansible_ssh_args':raw} for h in (A,B)}),request())
    conn=batch._native_binding(ctx,A);argv,fp=batch._native_argv(conn)
    consumed=[];original=f['dbfile'].read_bytes()
    def changed(argv,env,**limits):
        r=command(argv,env,**limits)
        if argv[:2]==[str(client),'-G']:
            consumed.append(Path(argv[argv.index('-F')+1]))
            assert r[0]==0
            # Simulate transient package DB drift after the first actual
            # consumer. Content restored does not restore identity/ctime.
            f['dbfile'].write_bytes(b'TEMPORARY SYNTHETIC CHANGE')
            f['dbfile'].write_bytes(original)
        return r
    monkeypatch.setattr(batch._scope,'bounded_command',changed)
    with pytest.raises(batch.Denied) as exc:batch._effective_ssh(argv,fp)
    assert exc.value.reason=='SSH_IMPLICIT_ROOT_UNQUALIFIED'
    assert len(consumed)==1 and not consumed[0].parent.exists() and f['dbfile'].read_bytes()==original
    assert len(f['calls'].read_text().splitlines())==2 and provider_calls()==[['--list']]
    assert not marker.exists() and batch._RPM_PROOF.get() is None
