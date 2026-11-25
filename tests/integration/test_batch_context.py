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
    {'ansible_ssh_common_args': '-o ControlPersist=60s'},
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
                      'batchmode': 'yes', 'forwardagent': 'no', 'forwardx11': 'no',
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
    assert calls[1][0] == ('-F', str(snapshot), '-o', 'Port=2201', '-o', 'User=jumpuser',
                           'jump-one.example.invalid')
    assert calls[2][0] == ('-F', str(snapshot), '-o', 'Port=2202', 'jump-two.example.invalid')
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
    if transient:
        # Restoring the source can still satisfy the fingerprint, but no
        # consumer may ever reopen the transiently unsafe original bytes.
        assert len(batch._effective_ssh(argv, fingerprint)) == len(calls) == 3
        assert source.read_bytes() == validated
    else:
        with pytest.raises(batch.Denied) as error:
            batch._effective_ssh(argv, fingerprint)
        assert error.value.code == 4 and error.value.reason == 'UNSUPPORTED_SSH_OPTION'
        assert len(calls) == consumer_index + 1  # no further consumer after observed drift
        assert source.read_bytes() == unsafe
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
    assert error.value.reason == ('UNSUPPORTED_SSH_OPTION' if unsafe else 'CONNECTION_CONTEXT_DRIFT')
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
    # Inject a short-lived change on the first jump consumer during the final
    # retained native connection's _run guard. Its -F still reads the snapshot.
    controls['before'] = lambda i: cfg.write_bytes(validated + b'Include /dummy/unvalidated.conf\n') if i == 9 else None
    controls['after'] = lambda i: cfg.write_bytes(validated) if i == 9 else None
    with pytest.raises(batch.Denied) as error:
        ctx._boundary(A)
    assert error.value.code == 2 and error.value.reason == 'LIVE_NOT_AVAILABLE'
    assert len(calls) == 10 and original_runs == [] and not marker.exists()
    assert provider_calls() == [['--list']] and cfg.read_bytes() == validated
    _assert_snapshot_calls(calls, cfg, validated)
    assert len({c[1] for c in calls}) == 5
    # Persistent drift after a valid proof must stop before a new consumer.
    cfg.write_bytes(validated + b'# persistent edit\n')
    with pytest.raises(batch.Denied) as error:
        ctx._boundary(A)
    assert error.value.reason == 'CONNECTION_CONTEXT_DRIFT'
    assert original_runs == [] and not marker.exists()
    assert len(calls) == 10
    _assert_snapshot_calls(calls, cfg, validated)


@pytest.mark.parametrize('line, reason', [
    (b'Include /dummy/unvalidated.conf\n', 'UNSUPPORTED_SSH_OPTION'),
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
