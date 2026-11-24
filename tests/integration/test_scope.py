"""SCOPE-R1: native synthetic Inventory, literal plans and no managed dispatch."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import textwrap

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = ROOT / 'tools/pqc_scan.py'
FIXTURE = ROOT / 'tests/fixtures/inventory_synthetic.py'
CONFIG = ROOT / 'ansible.cfg'
A, B, C, D = [f'host-{letter}.example.invalid' for letter in 'abcd']
SECRET = 'SYNTHETIC_SECRET_SENTINEL'
PKG = 'pqc_collect_packages'
SSL = 'pqc_collect_openssl'
SPEC = importlib.util.spec_from_file_location('pqc_scan', LAUNCHER)
scan = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scan)


def snapshot(path):
    return hashlib.sha256(path.read_bytes()).hexdigest(), stat.S_IMODE(path.stat().st_mode)


def request(hosts=(), groups=(), **kwargs):
    return scan.parse_scope(dict(pqc_scan_hosts=list(hosts), pqc_scan_groups=list(groups), **kwargs))


def basic_inventory():
    return {'_meta': {'hostvars': {A: {'ansible_connection': 'ssh'}, B: {}, C: {}}},
            'all': {'children': ['g', 'outside', 'ungrouped', 'empty']},
            'g': {'children': ['sub'], 'hosts': [A]}, 'sub': {'hosts': [A, B]},
            'outside': {'hosts': [C]}}


def reject(call, code, reason=None):
    with pytest.raises(scan.Denied) as exc:
        call()
    assert exc.value.code == code
    if reason:
        assert exc.value.reason == reason


def script(path, body):
    path.write_text(f'#!{sys.executable}\n' + textwrap.dedent(body), encoding='utf-8')
    path.chmod(0o700)
    return path


@pytest.fixture
def native(tmp_path):
    """Trace actual installed Ansible CLI, and detect every forbidden executable."""
    real = {name: shutil.which(name) for name in ('ansible-inventory', 'ansible-config', 'ansible-playbook')}
    assert all(real.values()), 'Required actual Ansible tools are missing'
    work = tmp_path / 'bin'
    work.mkdir()
    trace, traps, provider_trace = [tmp_path / n for n in ('native.trace', 'forbidden.trace', 'provider.trace')]
    env = dict(os.environ)
    env.update(PATH=str(work) + os.pathsep + env['PATH'], ANSIBLE_CONFIG=str(CONFIG),
               ANSIBLE_NOCOLOR='1', PYTHONDONTWRITEBYTECODE='1')
    for name in ('ansible-inventory', 'ansible-config'):
        script(work / name, f'''
            import json, os, sys
            with open({str(trace)!r}, 'a') as log:
                log.write(json.dumps([{name!r}, sys.argv[1:], {{k: os.environ.get(k) for k in {list(scan.FATAL_ENV)!r}}}]) + '\\n')
            os.execv({real[name]!r}, [{real[name]!r}] + sys.argv[1:])
        ''')
    for name in ('ssh', 'scp', 'sftp', 'ansible', 'ansible-playbook', 'curl', 'wget', 'openssl', 'sshd', 'rpm'):
        script(work / name, f'''
            import sys
            with open({str(traps)!r}, 'a') as log:
                log.write({name!r} + '\\n')
            sys.exit(91)
        ''')
    # Positive control: a real call to the tripwire is detected. Reset before launch.
    assert subprocess.run([str(work / 'ssh')], env=env, capture_output=True, timeout=5).returncode == 91
    assert traps.read_text() == 'ssh\n'
    traps.unlink()
    original = {p: snapshot(p) for p in (FIXTURE, CONFIG)}
    provider = script(tmp_path / 'synthetic provider.py', f'''
        import json, os, runpy, sys
        f = runpy.run_path({str(FIXTURE)!r})
        mode = os.environ.get('PQC_SYNTHETIC_INVENTORY_MODE', 'inline')
        with open({str(provider_trace)!r}, 'a') as log:
            log.write(json.dumps(sys.argv[1:]) + '\\n')
        hostvars = f['hostvars']()
        for h, values in hostvars.items():
            values['ansible_connection'] = 'ssh'
            values['ansible_password'] = {SECRET!r}
        hostvars[{B!r}][{PKG!r}] = 'false'
        hostvars[{A!r}][{SSL!r}] = True
        if sys.argv[1:] == ['--list']:
            data = f['inventory'](mode)
            if mode != 'empty':
                data['pqc_targets']['vars'][{PKG!r}] = True
                if mode == 'inline':
                    data['_meta']['hostvars'] = hostvars
        elif len(sys.argv) == 3 and sys.argv[1] == '--host':
            data = hostvars.get(sys.argv[2], {{}})
        else:
            sys.exit(9)
        print(json.dumps(data))
    ''')
    original[provider] = snapshot(provider)
    def launch(*args, source=provider, mode='inline', extra_env=None):
        result = subprocess.run([sys.executable, str(LAUNCHER), '-i', str(source), *args],
                                cwd=ROOT, env=dict(env, PQC_SYNTHETIC_INVENTORY_MODE=mode, **(extra_env or {})),
                                capture_output=True, timeout=65)
        assert SECRET.encode() not in result.stdout + result.stderr
        assert str(tmp_path).encode() not in result.stdout + result.stderr
        assert not traps.exists(), 'unexpected managed execution or service tool'
        return result
    def records(path):
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
    yield {'launch': launch, 'provider': provider, 'env': env, 'trace': trace,
           'records': lambda: records(trace), 'provider_records': lambda: records(provider_trace),
           'bin': work, 'real': real, 'traps': traps}
    assert all(snapshot(p) == before for p, before in original.items())
    assert not traps.exists()


def assert_ready(result, targets):
    assert result.returncode == 0, result.stderr.decode(errors='replace')
    assert result.stderr == b''
    plan = json.loads(result.stdout)
    assert set(plan) == set(scan.PUBLIC_FIELDS)
    assert plan == {'scope_plan_version': 1, 'plan_status': 'READY', 'reason_code': 'TARGET_PLAN_READY',
                    'plan_only': True, 'execution_allowed': False, 'active_dispatch_allowed': False,
                    'target_ids': targets, 'target_count': len(targets)}
    return plan


def assert_denied(result, rc, reason):
    assert result.returncode == rc
    assert result.stdout == b''
    assert result.stderr == (reason + '\n').encode()


@pytest.mark.parametrize('mode', ['inline', 'lookup'])
def test_native_nested_scope_and_effective_flags(native, monkeypatch, mode):
    for key, value in native['env'].items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv('PQC_SYNTHETIC_INVENTORY_MODE', mode)
    # Actual native CLI uses one explicit source even if config/env names another.
    monkeypatch.setenv('ANSIBLE_INVENTORY', '/not-a-real-inventory')
    data = scan.load_effective_inventory(str(native['provider']))
    assert data['_meta']['hostvars'][B]['fixture_precedence'] == 'host'
    assert data['_meta']['hostvars'][A]['fixture_precedence'] == 'group'
    plan = scan.build_plan(data, request([B], ['pqc_targets', 'fixture_a'],
                                       pqc_collect_packages=False, pqc_run_id='Run_1'))
    assert plan['target_ids'] == [A, B, C] and D not in plan['target_ids']
    assert plan['run_flags'] == {PKG: False}
    assert plan['inventory_flags'] == {A: {PKG: True, SSL: True}, B: {PKG: False}, C: {PKG: True}}
    assert plan['inventory_flags_source'] == 'INVENTORY_EFFECTIVE'
    assert plan['limits'] == {'max_hosts': 10, 'forks': 2, 'serial': 2,
                              'ssh_timeout_s': 15, 'command_timeout_s': 30}
    assert SECRET not in json.dumps(plan) and 'ansible_password' not in json.dumps(plan)
    assert not plan['execution_allowed'] and not plan['active_dispatch_allowed']
    assert native['records']() == [
        ['ansible-config', ['dump', '--format', 'json'], scan.FATAL_ENV],
        ['ansible-inventory', ['-i', str(native['provider']), '--list'], scan.FATAL_ENV]]
    calls = native['provider_records']()
    assert calls.count(['--list']) == 1
    if mode == 'lookup':
        assert sorted(a[1] for a in calls if a[0] == '--host') == [A, B, C, D]
    else:
        assert calls == [['--list']]
    assert_ready(native['launch']('--group', 'pqc_targets', '--host', B, '--plan-only', mode=mode), [A, B, C])


@pytest.mark.parametrize('args,targets', [(['--host', A], [A]), (['--group', 'fixture_b'], [B, C])])
def test_native_literal_selection(native, args, targets):
    assert_ready(native['launch'](*args, '--plan-only'), targets)


@pytest.mark.parametrize('alias', [False, True])
def test_native_scope_file(native, tmp_path, alias):
    scope = tmp_path / 'scope.yml'
    scope.write_text('pqc_scan_groups: [fixture_a]\npqc_max_hosts: 2\npqc_collect_packages: "FALSE"\n'
                     'pqc_scan_profile: extended\npqc_active_opt_in: false\npqc_active_endpoints: []\n')
    before = snapshot(scope)
    args = ['-e', '@' + str(scope)] if alias else ['--scope-file', str(scope)]
    assert_ready(native['launch'](*args, '--plan-only', '--forks', '1'), [A, B])
    assert snapshot(scope) == before


@pytest.mark.parametrize('args,rc,reason', [
    (['--host', 'HOST-A.example.invalid'], 4, 'UNKNOWN_TARGET'),
    (['--group', A], 4, 'UNKNOWN_TARGET'),
    (['--host', 'fixture_a'], 4, 'UNKNOWN_TARGET'),
    (['--group', 'missing'], 4, 'UNKNOWN_TARGET'),
])
def test_native_unknown(native, args, rc, reason):
    assert_denied(native['launch'](*args, '--plan-only'), rc, reason)


def test_native_empty_local_and_cap(native, tmp_path):
    assert_denied(native['launch']('--group', 'pqc_targets', '--plan-only', mode='empty'), 4, 'EMPTY_SCOPE')
    assert_denied(native['launch']('--host', A, '--plan-only', source=FIXTURE), 4, 'LOCAL_TARGET')
    hosts = [f'node-{i}.example.invalid' for i in range(11)]
    provider = script(tmp_path / 'eleven.py', f'''
        import json
        print(json.dumps({{'all': {{'children': ['g']}}, 'g': {{'hosts': {hosts!r}}}, '_meta': {{'hostvars': {{}}}}}}))
    ''')
    assert_denied(native['launch']('--group', 'g', '--plan-only', source=provider), 4, 'HOST_LIMIT_EXCEEDED')
    assert_ready(native['launch']('--host', hosts[0], '--plan-only', source=provider), [hosts[0]])


@pytest.mark.parametrize('kind', ['malformed', 'exit7'])
def test_native_provider_failure(native, tmp_path, kind):
    body = 'print("not-json")' if kind == 'malformed' else 'import sys; print("' + SECRET + '", file=sys.stderr); sys.exit(7)'
    bad = script(tmp_path / 'bad.py', body)
    assert_denied(native['launch']('--host', A, '--plan-only', source=bad), 3, 'INVENTORY_PROVIDER_ERROR')
    assert native['records']()[-1][0] == 'ansible-inventory'


def test_native_rc_zero_with_parse_warning(native):
    # Controlled diagnostic injection around a genuinely executed native --list.
    script(native['bin'] / 'ansible-inventory', f'''
        import subprocess, sys
        result = subprocess.run([{native['real']['ansible-inventory']!r}] + sys.argv[1:], capture_output=True)
        assert result.returncode == 0
        sys.stdout.buffer.write(result.stdout)
        sys.stderr.buffer.write(result.stderr)
        print("[WARNING]: Failed to parse inventory with 'script' plugin: {SECRET}", file=sys.stderr)
    ''')
    assert_denied(native['launch']('--host', A, '--plan-only'), 3, 'INVENTORY_PARSE_FAILURE')


@pytest.mark.parametrize('args,rc,reason', [
    (['--limit', A], 2, 'INVALID_CLI'), (['-l', A], 2, 'INVALID_CLI'),
    (['--limit=' + A], 2, 'INVALID_CLI'), (['-e', 'x=y'], 2, 'INVALID_EXTRA_VARS'),
    (['--extra-vars', 'x=y'], 2, 'INVALID_CLI'), (['--tags', 'x'], 2, 'INVALID_CLI'),
    (['--skip-tags', 'x'], 2, 'INVALID_CLI'), (['--start-at-task', 'x'], 2, 'INVALID_CLI'),
    (['--check'], 2, 'INVALID_CLI'), (['--step'], 2, 'INVALID_CLI'),
    (['--connection', 'local'], 2, 'INVALID_CLI'), (['--become'], 2, 'INVALID_CLI'),
    (['--ssh-common-args', 'x'], 2, 'INVALID_CLI'), (['-v'], 2, 'INVALID_CLI'),
    (['--for', '1'], 2, 'INVALID_CLI'), (['--forks', '3'], 2, 'INVALID_FORKS'),
    (['--forks', '1', '--forks', '2'], 2, 'DUPLICATE_OPTION'),
    (['--plan-only'], 2, 'DUPLICATE_OPTION'), (['-i', 'another'], 2, 'DUPLICATE_OPTION'),
    (['--group', 'all'], 4, 'RESERVED_TARGET'), (['--group', 'ungrouped'], 4, 'RESERVED_TARGET'),
    (['--group', 'pqc_runtime_targets'], 4, 'RESERVED_TARGET'),
    (['--host', 'localhost'], 4, 'LOCAL_TARGET'), (['--host', '127.1'], 4, 'LOCAL_TARGET'),
    (['--group', 'g:*'], 4, 'UNSAFE_TARGET_NAME'), (['--host', 'a,b'], 4, 'UNSAFE_TARGET_NAME'),
])
def test_invalid_cli_before_inventory(native, args, rc, reason):
    assert_denied(native['launch']('--host', A, '--plan-only', *args), rc, reason)
    assert native['records']() == [] and native['provider_records']() == []


def test_missing_plan_and_scope_conflict(native, tmp_path):
    assert_denied(native['launch']('--host', A), 2, 'LIVE_NOT_AVAILABLE')
    assert_denied(native['launch']('--plan-only'), 4, 'EMPTY_SCOPE')
    assert_denied(native['launch']('--host', A, '--scope-file', str(tmp_path / 'missing'), '--plan-only'),
                  2, 'CONFLICTING_SCOPE')
    assert native['records']() == [] and native['provider_records']() == []


@pytest.mark.parametrize('data,reason', [
    ('pqc_scan_hosts: [a]\npqc_scan_hosts: [b]', 'DUPLICATE_SCOPE_KEY'),
    ('pqc_scan_hosts: &x [a]\npqc_scan_groups: *x', 'UNSAFE_SCOPE_YAML'),
    ('pqc_scan_hosts: !tag [a]', 'UNSAFE_SCOPE_YAML'),
    ('pqc_scan_hosts: ["{{ x }}"]', 'UNSAFE_SCOPE_YAML'),
    ('pqc_scan_hosts: [a]\npqc_max_hosts: true', 'INVALID_MAX_HOSTS'),
    ('pqc_scan_hosts: [a]\npqc_max_hosts: 11', 'INVALID_MAX_HOSTS'),
    ('pqc_scan_hosts: [a]\npqc_collect_packages: yes', 'INVALID_COLLECTOR_FLAG'),
    ('pqc_scan_hosts: [a]\npqc_collect_unknown: true', 'UNSUPPORTED_SCOPE_FIELD'),
    ('pqc_scan_hosts: [a]\nexecution_allowed: true', 'UNSUPPORTED_SCOPE_FIELD'),
    ('pqc_scan_hosts: [a]\nreport_root: secret', 'UNSUPPORTED_SCOPE_FIELD'),
    ('pqc_scan_hosts: [a]\npqc_scan_profile: active', 'PROFILE_INTEGRATION_REQUIRED'),
    ('pqc_scan_hosts: [a]\npqc_active_opt_in: true', 'PROFILE_INTEGRATION_REQUIRED'),
    ('pqc_scan_hosts: [a]\npqc_active_endpoints: [x]', 'PROFILE_INTEGRATION_REQUIRED'),
    ('pqc_scan_hosts: [a]\npqc_run_id: ../x', 'INVALID_RUN_ID'),
    ('[a]', 'INVALID_SCOPE'),
    ('pqc_scan_hosts: [a]\nother: ' + '[' * 20 + '0' + ']' * 20, 'SCOPE_COMPLEXITY'),
    pytest.param(' ' * (scan.SCOPE_BYTES + 1), 'SCOPE_TOO_LARGE', id='scope-size-cap'),
])
def test_invalid_scope_file(native, tmp_path, data, reason):
    path = tmp_path / 'scope.yml'
    path.write_text(data)
    assert_denied(native['launch']('--scope-file', str(path), '--plan-only'), 2, reason)
    assert native['records']() == [] and native['provider_records']() == []


def test_unsafe_sources_and_missing_config(native, tmp_path):
    for source in ('localhost,', str(tmp_path), 'a;echo x', str(tmp_path / 'missing')):
        assert_denied(native['launch']('--host', A, '--plan-only', source=source), 4, 'UNSAFE_INVENTORY_SOURCE')
    assert_denied(native['launch']('--host', A, '--plan-only',
                                  extra_env={'ANSIBLE_CONFIG': str(tmp_path / 'absent')}), 3, 'INVENTORY_CONFIG_MISSING')
    assert native['records']() == []
    assert_denied(native['launch']('--host', A, '--plan-only', extra_env={'PATH': str(tmp_path / 'empty')}),
                  3, 'INVENTORY_TOOL_MISSING')


def test_native_typed_ambiguity(native, tmp_path):
    provider = script(tmp_path / 'ambiguous.py', f'''
        import json
        print(json.dumps({{'all': {{'children': ['g', {A!r}]}}, 'g': {{'hosts': [{A!r}]}},
                           {A!r}: {{'hosts': [{B!r}]}}, '_meta': {{'hostvars': {{}}}}}}))
    ''')
    assert_ready(native['launch']('--host', A, '--plan-only', source=provider), [A])
    assert_ready(native['launch']('--group', A, '--plan-only', source=provider), [B])


def test_json_scope_and_lower_cap(native, tmp_path):
    scope = tmp_path / 'scope.json'
    scope.write_text(json.dumps({'pqc_scan_groups': ['fixture_a'], 'pqc_max_hosts': 1}))
    assert_denied(native['launch']('--scope-file', str(scope), '--plan-only'), 4, 'HOST_LIMIT_EXCEEDED')
    scope.write_text(json.dumps({'pqc_scan_groups': ['fixture_a'], 'pqc_max_hosts': 2}))
    assert_ready(native['launch']('--scope-file', str(scope), '--plan-only'), [A, B])


def test_native_bad_config(native, tmp_path):
    bad = tmp_path / 'ansible.cfg'
    bad.write_text('this is not an INI config\n')
    assert_denied(native['launch']('--host', A, '--plan-only', extra_env={'ANSIBLE_CONFIG': str(bad)}),
                  3, 'INVENTORY_CONFIG_ERROR')
    assert native['provider_records']() == []


def test_typed_ambiguity_and_unknown_connection():
    data = basic_inventory()
    data[A] = {'hosts': [B]}
    data['all']['children'].append(A)
    assert scan.build_plan(data, request([A]))['target_ids'] == [A]
    assert scan.build_plan(data, request(groups=[A]))['target_ids'] == [B]
    assert scan.build_plan(data, request(groups=[A]))['connection_status'] == {B: 'UNKNOWN'}
    # Actual native formatter can omit hostvars for hosts with no variables.
    del data['_meta']['hostvars'][B]
    assert scan.build_plan(data, request(groups=[A]))['target_ids'] == [B]
    assert scan.build_plan(data, request(groups=[A]))['inventory_flags'] == {B: {}}


@pytest.mark.parametrize('change,reason', [
    ('cycle', 'INVENTORY_CYCLE'), ('orphan', 'ORPHAN_INVENTORY_GROUP'),
    ('hostvars', 'INCONSISTENT_INVENTORY_HOSTS'), ('bad-group', 'INVALID_INVENTORY_STRUCTURE'),
    ('bad-meta', 'INVALID_INVENTORY_STRUCTURE'), ('duplicate-host', 'INVALID_INVENTORY_STRUCTURE'),
])
def test_invalid_effective_topology(change, reason):
    data = basic_inventory()
    if change == 'cycle':
        data['sub']['children'] = ['g']
    elif change == 'orphan':
        data['orphan'] = {'hosts': []}
    elif change == 'hostvars':
        data['_meta']['hostvars']['orphan.example.invalid'] = {}
    elif change == 'bad-group':
        data['g']['children'] = 'sub'
    elif change == 'bad-meta':
        data['_meta']['hostvars'] = []
    elif change == 'duplicate-host':
        data['g']['hosts'] = [A, A]
    reject(lambda: scan.build_plan(data, request(groups=['g'])), 3, reason)


@pytest.mark.parametrize('key,value,reason', [
    ('ansible_connection', 'ansible.builtin.local', 'LOCAL_TARGET'),
    ('ansible_connection', '{{ transport }}', 'UNRESOLVED_CONNECTION'),
    ('ansible_host', '::ffff:127.0.0.1', 'LOCAL_TARGET'),
    ('ansible_host', 'LOCALHOST.', 'LOCAL_TARGET'),
    ('ansible_ssh_host', '127.0.0.2', 'LOCAL_TARGET'),
    ('ansible_host', '0.0.0.0', 'LOCAL_TARGET'),
    ('pqc_scan_profile', 'baseline', 'INVENTORY_SCOPE_CONFLICT'),
    ('execution_allowed', True, 'INVENTORY_SCOPE_CONFLICT'),
    ('pqc_collect_unknown', True, 'INVENTORY_SCOPE_CONFLICT'),
    (PKG, 1, 'INVALID_COLLECTOR_FLAG'), (PKG, '{{ flag }}', 'INVALID_COLLECTOR_FLAG'),
])
def test_effective_local_or_conflict(key, value, reason):
    data = basic_inventory()
    data['_meta']['hostvars'][A][key] = value
    reject(lambda: scan.build_plan(data, request([A])), 4, reason)


@pytest.mark.parametrize('data', [b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e999}', b'\xff', b'{'])
def test_strict_effective_json(data):
    reject(lambda: scan.strict_json(data), 3)


@pytest.mark.parametrize('diagnostic', [b'ERROR! Completely failed to parse inventory source x',
    b'[WARNING]: No inventory was parsed, only implicit localhost is available',
    b'[WARNING]: Inventory script returned non-zero exit code 7.',
    b'[WARNING]: Unable to get JSON decoder for inventory script result: x',
    b'[WARNING]: plugin failed to load', b'[WARNING]: inventory source was ignored',
    b'[WARNING]: inventory parser emitted an unfamiliar diagnostic', b'unclassified raw diagnostic'])
def test_parse_diagnostic_families(diagnostic):
    reject(lambda: scan.check_diagnostics(diagnostic), 3)


def test_unrelated_warning_is_not_failure():
    scan.check_diagnostics(b'[WARNING]: An unrelated deprecation notice.')
    scan.check_diagnostics(b'[WARNING]: Found both group and host with same name: a')


@pytest.mark.parametrize('kind,reason', [('timeout', 'INVENTORY_TIMEOUT'),
    ('stdout', 'INVENTORY_OUTPUT_LIMIT'), ('stderr', 'INVENTORY_OUTPUT_LIMIT'),
    ('residual', 'INVENTORY_RESIDUAL_PROCESS')])
def test_bounded_process_group(tmp_path, kind, reason):
    # Child handshake guarantees a same-group descendant exists before leader exit/overflow.
    # It cannot write a late marker unless released after the command returns.
    ready, release, late = [tmp_path / n for n in ('ready', 'release', 'late')]
    child = f'''
import os, pathlib, time
pathlib.Path({str(ready)!r}).write_text(str(os.getpid()))
for _ in range(500):
    if pathlib.Path({str(release)!r}).exists():
        pathlib.Path({str(late)!r}).write_text('late'); break
    time.sleep(.01)
'''
    code = f'''
import os, pathlib, subprocess, sys, time
subprocess.Popen([sys.executable, '-c', {child!r}], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
while not pathlib.Path({str(ready)!r}).exists(): time.sleep(.005)
'''
    code += {'timeout': 'time.sleep(10)', 'stdout': 'os.write(1,b"x"*8192)',
             'stderr': 'os.write(2,b"x"*8192)', 'residual': 'pass'}[kind]
    reject(lambda: scan.bounded_command([sys.executable, '-c', code], os.environ.copy(),
                                        timeout=2, out_cap=4096, err_cap=4096), 3, reason)
    pid = int(ready.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)
    release.touch()
    assert not late.exists()


def test_controller_only_stubs():
    entry = yaml.safe_load((ROOT / 'playbooks/scan_ol9.yml').read_text())
    assert len(entry) == 1 and entry[0]['ansible.builtin.import_playbook'] == 'preflight.yml'
    assert set(entry[0]) == {'name', 'ansible.builtin.import_playbook'}
    preflight = yaml.safe_load((ROOT / 'playbooks/preflight.yml').read_text())
    assert len(preflight) == 1
    play = preflight[0]
    assert set(play) == {'name', 'hosts', 'connection', 'gather_facts', 'become', 'tasks'}
    assert play['hosts'] == 'localhost' and play['connection'] == 'local'
    assert play['gather_facts'] is False and play['become'] is False
    assert len(play['tasks']) == 1 and set(play['tasks'][0]) == {'name', 'ansible.builtin.fail', 'tags'}
    assert 'LIVE_NOT_AVAILABLE' in play['tasks'][0]['ansible.builtin.fail']['msg']
