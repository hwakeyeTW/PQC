"""Native S2 adapter tests; only synthetic controller inputs and traps.

Run with the approved offline development runtime. No legacy source role,
real inventory, service endpoint or managed host is used by this harness.
"""
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[2]
COLLECTION = Path('ansible_collections/security/compliance_pqc_readiness')
ROLE = Path('roles/pqc_execution_scope/tasks/profile.yml')
MODULE = Path('plugins/modules/resolve_scan_profile.py')
POLICY = Path('config/scan_profiles.yml')
SOURCES = (POLICY, MODULE, COLLECTION / MODULE, ROLE, COLLECTION / ROLE,
           COLLECTION / 'meta/runtime.yml')
FQCN = 'security.compliance_pqc_readiness'
TLS = 'pqc_collect_tls_services'
NGINX = 'pqc_collect_nginx_certs'
PACKAGES = 'pqc_collect_packages'
OPENSSL = 'pqc_collect_openssl'
SECRET = 'S2_DUMMY_PRIVATE_SENTINEL'
ENDPOINT = 's2-dummy-private.invalid'
TARGET = 'synthetic-target.invalid'
RESULT = 'pqc_profile_result'
ROLE_TASK = 'Resolve the controller scan profile without dispatch'


@pytest.fixture(scope='module')
def resolver():
    spec = importlib.util.spec_from_file_location('s2_resolver', ROOT / MODULE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write(path, text, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(text, encoding='utf-8')
    path.chmod(mode)
    return path


def dump(path, data):
    return write(path, json.dumps(data, ensure_ascii=True))


def task(name, action, args, **kwargs):
    return {'name': name, action: args, **kwargs}


@pytest.fixture
def harness(tmp_path):
    # Copy only the exact narrow S1/S2 inputs; never load old roles or inventory.
    tmp_path.chmod(0o700)
    src = tmp_path / 'source'
    for relative in SOURCES:
        dest = src / relative
        dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        shutil.copyfile(ROOT / relative, dest)
        dest.chmod(0o644)
    home = tmp_path / 'home'
    for part in ('', 'config', 'cache', 'data', 'tmp'):
        (home / part).mkdir(parents=True, exist_ok=True, mode=0o700)
    cfg = write(tmp_path / 'ansible.cfg', '[defaults]\n'
                'roles_path = ' + str(src / 'roles') + '\n'
                'library = ' + str(src / MODULE.parent) + '\n'
                'collections_path = ' + str(src) + '\n'
                'collections_scan_sys_path = False\n'
                'interpreter_python = ' + sys.executable + '\n'
                'retry_files_enabled = False\nhost_key_checking = True\n'
                '[inventory]\nenable_plugins = yaml\n')
    marker = tmp_path / 'dispatch-attempted'
    trap = write(tmp_path / 'bin' / 'ssh', '#!/bin/sh\n'
                 'printf "synthetic dispatch\\n" >> "$PQC_TEST_MARKER"\nexit 91\n', 0o700)
    for executable in ('scp', 'sftp', 'openssl', 'ssh-keygen', 'ss', 'curl'):
        shutil.copyfile(trap, trap.parent / executable)
        (trap.parent / executable).chmod(0o700)
    # A legacy-role fallback or a true dispatch permission would hit this trap.
    mock_tasks = [task('Synthetic collector tripwire', 'ansible.builtin.command',
                       {'argv': [str(trap), 'collector']}, check_mode=False)]
    for prefix in (Path(), COLLECTION):
        dump(src / prefix / 'roles/crypto_posture_snapshot/tasks/main.yml', mock_tasks)
    inv = dump(tmp_path / 'synthetic.yml', {'all': {'vars': {
        TLS: True, NGINX: True, 'pqc_scan_profile': 'active',
        'pqc_active_opt_in': True, 'pqc_active_endpoints': [SECRET],
        'pqc_tls_probe_ports': [443], 'pqc_collect_packages': True,
    }, 'hosts': {
        'localhost': {'ansible_connection': 'local', 'ansible_python_interpreter': sys.executable},
        TARGET: {'ansible_connection': 'ssh', 'ansible_host': TARGET,
                 'ansible_ssh_executable': str(trap),
                 'ansible_scp_executable': str(trap.parent / 'scp'),
                 'ansible_sftp_executable': str(trap.parent / 'sftp')},
    }}})
    env = {'PATH': str(trap.parent) + ':' + str(Path(sys.executable).parent) + ':/usr/bin:/bin',
           'HOME': str(home), 'XDG_CONFIG_HOME': str(home / 'config'),
           'XDG_CACHE_HOME': str(home / 'cache'), 'XDG_DATA_HOME': str(home / 'data'),
           'TMPDIR': str(home / 'tmp'), 'ANSIBLE_CONFIG': str(cfg),
           'ANSIBLE_LOCAL_TEMP': str(home / 'tmp'), 'ANSIBLE_REMOTE_TEMP': str(home / 'tmp'),
           'ANSIBLE_COLLECTIONS_PATH': str(src), 'ANSIBLE_COLLECTIONS_SCAN_SYS_PATH': 'false',
           'ANSIBLE_INVENTORY_ANY_UNPARSED_IS_FAILED': 'true',
           'ANSIBLE_INVENTORY_UNPARSED_IS_FAILED': 'true', 'ANSIBLE_NOCOLOR': '1',
           'LC_ALL': 'C.UTF-8', 'LANG': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1',
           'PQC_TEST_MARKER': str(marker)}
    return src, inv, env, marker


def run(harness, executable, args, timeout=20):
    src, _, env, _ = harness
    command = shutil.which(executable, path=env['PATH'])
    assert command, 'approved native Ansible runtime required'
    return subprocess.run([command, *map(str, args)], cwd=src, env=env,
                          text=True, capture_output=True, timeout=timeout)


def play(tasks, variables=None, host='localhost'):
    return [{'name': 'Synthetic controller profile test', 'hosts': host,
             'connection': 'local' if host == 'localhost' else 'ssh',
             'gather_facts': False, 'become': False, 'vars': variables or {},
             'tasks': tasks}]


def role_task(loader):
    name = 'pqc_execution_scope' if loader == 'short' else FQCN + '.pqc_execution_scope'
    return task('Load explicit profile tasks', 'ansible.builtin.import_role',
                {'name': name, 'tasks_from': 'profile'})


def assert_result(expected, denied):
    conditions = [f'{RESULT}.{key} == expected_decision.{key}' for key in expected]
    conditions += [f'{RESULT}.changed is false', f'{RESULT}.execution_allowed is false',
                   f'{RESULT}.active_dispatch_allowed is false',
                   f'({RESULT}.failed | default(false)) is {str(denied).lower()}',
                   f'({RESULT}.per_collector | length) == 8',
                   f'({RESULT}.per_collector | map(attribute="collection_state") | unique | list) == ["NOT_SCANNED"]',
                   f'"{SECRET}" not in ({RESULT} | string)',
                   f'"{ENDPOINT}" not in ({RESULT} | string)']
    return task('Verify exact safe decision', 'ansible.builtin.assert',
                {'that': conditions, 'quiet': True}, no_log=True)


def cases(resolver, case):
    off = dict.fromkeys(resolver.FLAGS, False)
    on = dict.fromkeys(resolver.FLAGS, True)
    active = {'profile': 'active', 'plan_only': True, 'active_opt_in': True,
              'target_ids': [TARGET], 'active_endpoints': [
                  {'source_host': TARGET, 'protocol': 'tls', 'address': ENDPOINT,
                   'port': 443, 'sni': None}]}
    table = {
        'baseline': ({}, 'VALIDATED', 'AWAITING_COLLECTOR'),
        'extended': ({'profile': 'extended'}, 'VALIDATED', 'AWAITING_COLLECTOR'),
        'extended-narrowing': ({'profile': 'extended', 'plan_only': True,
                               'run_flags': {PACKAGES: 'FALSE', OPENSSL: True},
                               'inventory_flags': {PACKAGES: True, OPENSSL: False, NGINX: False}},
                              'VALIDATED', 'PLAN_ONLY'),
        'baseline-all-off': ({'run_flags': off, 'inventory_flags': on}, 'VALIDATED', 'AWAITING_COLLECTOR'),
        'extended-all-off': ({'profile': 'extended', 'plan_only': True, 'inventory_flags': off}, 'VALIDATED', 'PLAN_ONLY'),
        'passive-conflict': ({'run_flags': {TLS: True}, 'inventory_flags': {TLS: False}}, 'DENIED', 'PROFILE_CONFLICT'),
        'active-tls-plan': (active, 'DEFERRED', 'ACTIVE_NOT_AVAILABLE_V2_0'),
        'active-tls-run-conflict': ({**active, 'run_flags': off}, 'DENIED', 'PROFILE_CONFLICT'),
        'active-tls-inventory-conflict': ({**active, 'inventory_flags': off}, 'DENIED', 'PROFILE_CONFLICT'),
        'active-ssh-plan': ({**active, 'active_endpoints': [dict(active['active_endpoints'][0], protocol='ssh', port=22)],
                             'run_flags': off}, 'DEFERRED', 'ACTIVE_NOT_AVAILABLE_V2_0'),
        'active-ssh-live': ({**active, 'plan_only': False, 'active_endpoints': [dict(active['active_endpoints'][0], protocol='ssh', port=22)],
                             'run_flags': off}, 'DENIED', 'ACTIVE_NOT_AVAILABLE_V2_0'),
        'missing-opt-in': ({**active, 'active_opt_in': False}, 'DENIED', 'ACTIVE_OPT_IN_REQUIRED'),
        'foreign-source': ({**active, 'target_ids': ['different.invalid']}, 'DENIED', 'TARGET_NOT_AUTHORIZED'),
        'invalid-type': ({'run_flags': {PACKAGES: 1}}, 'DENIED', 'INVALID_INPUT'),
        'invalid-source-field': ({SECRET: SECRET}, 'DENIED', 'INVALID_INPUT'),
        'invalid-policy': ({}, 'DENIED', 'INVALID_POLICY'),
    }
    return copy.deepcopy(table[case])


def test_changed_pair_and_explicit_task_contract():
    a, b = ROOT / ROLE, ROOT / COLLECTION / ROLE
    assert a.read_bytes() == b.read_bytes()
    assert a.stat().st_mode & 0o777 == b.stat().st_mode & 0o777 == 0o644
    assert yaml.safe_load(a.read_text()) == [task(ROLE_TASK, 'resolve_scan_profile',
        {'policy': '{{ pqc_profile_policy }}', 'request': '{{ pqc_profile_request }}'},
        connection='local', become=False, no_log=True, register=RESULT)]
    assert not (a.parent / 'main.yml').exists() and not (b.parent / 'main.yml').exists()


@pytest.mark.parametrize('loader', ['short', 'fqcn'])
def test_native_loader_and_syntax(harness, resolver, loader):
    src, inv, _, marker = harness
    fqcn = loader == 'fqcn'
    name = FQCN + '.resolve_scan_profile' if fqcn else 'ansible.legacy.resolve_scan_profile'
    proc = run(harness, 'ansible-doc', ['-t', 'module', '-F'] + ([FQCN] if fqcn else []), 5)
    assert proc.returncode == 0, proc.stderr
    paths = [line.split(None, 1)[1] for line in proc.stdout.splitlines()
             if line.split() and line.split()[0] == name]
    assert len(paths) == 1
    assert Path(paths[0]).resolve() == (src / (COLLECTION / MODULE if fqcn else MODULE)).resolve()
    variables = {'pqc_profile_policy': resolver.load_policy((src / POLICY).read_text()), 'pqc_profile_request': {}}
    path = dump(src.parent / 'syntax.yml', play([role_task(loader)], variables))
    proc = run(harness, 'ansible-playbook', ['-i', inv, path, '--syntax-check'])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert not marker.exists() and 'TASK [' not in proc.stdout


SCENARIOS = ['baseline', 'extended', 'extended-narrowing', 'baseline-all-off', 'extended-all-off',
             'passive-conflict', 'active-tls-plan', 'active-tls-run-conflict', 'active-tls-inventory-conflict',
             'active-ssh-plan', 'active-ssh-live', 'missing-opt-in', 'foreign-source',
             'invalid-type', 'invalid-source-field', 'invalid-policy']


@pytest.mark.parametrize('loader', ['short', 'fqcn'])
@pytest.mark.parametrize('case,check', [(c, False) for c in SCENARIOS] + [
    ('baseline', True), ('active-ssh-plan', True), ('active-tls-run-conflict', True)],
    ids=SCENARIOS + ['baseline-check', 'ssh-plan-check', 'tls-conflict-check'])
def test_native_role_decisions(harness, resolver, loader, case, check):
    src, inv, _, marker = harness
    policy = resolver.load_policy((src / POLICY).read_text())
    request, decision, reason = cases(resolver, case)
    if case == 'invalid-policy':
        policy['policy_version'] = True
    expected = resolver.resolve_scan_profile(policy, request)
    assert (expected['decision'], expected['reason_code']) == (decision, reason)
    denied = decision == 'DENIED'
    if case in ('baseline', 'extended'):
        assert expected['requested_flags'][NGINX] is (case == 'extended')
        assert expected['requested_flags'][TLS] is False
    if case.endswith('all-off') or case.startswith('active-ssh'):
        assert not any(expected['requested_flags'].values())
    if case == 'extended-narrowing':
        rows = {row['id']: row for row in expected['per_collector']}
        assert rows[PACKAGES]['reason_code'] == 'DISABLED_BY_USER'
        assert rows[PACKAGES]['request_source'] == 'RUN'
        assert rows[OPENSSL]['reason_code'] == 'NARROWED_BY_INVENTORY'
        assert rows[OPENSSL]['request_source'] == 'NARROWED'
    variables = {'pqc_profile_policy': policy, 'pqc_profile_request': request, 'expected_decision': expected}
    # A successful resolver is not authorization. A reachable positive marker
    # proves this play did not silently skip its entire adapter/verification.
    guard = f'{RESULT}.execution_allowed or {RESULT}.active_dispatch_allowed'
    mock = 'crypto_posture_snapshot' if loader == 'short' else FQCN + '.crypto_posture_snapshot'
    block = {'block': [role_task(loader),
                       task('S2_AFTER_ADAPTER', 'ansible.builtin.debug', {'msg': 'S2_RETURNED'}),
                       assert_result(expected, False),
                       task('Synthetic dispatch guard', 'ansible.builtin.include_role', {'name': mock}, when=guard)],
             'rescue': [task('Require actual resolver denial', 'ansible.builtin.assert',
                             {'that': ['expected_decision.decision == "DENIED"',
                                       f'{RESULT}.failed is true',
                                       f'ansible_failed_task.name.endswith("{ROLE_TASK}")'], 'quiet': True}, no_log=True),
                        assert_result(expected, True),
                        task('S2_DENIAL_CONFIRMED', 'ansible.builtin.fail', {'msg': 'S2_FIXED_DENIAL'})]}
    path = dump(src.parent / 'case.yml', play([block], variables))
    proc = run(harness, 'ansible-playbook', ['-i', inv, path, '-vvv'] + (['--check'] if check else []))
    output = proc.stdout + proc.stderr
    assert SECRET not in output and ENDPOINT not in output
    assert not marker.exists(), 'unexpected synthetic collector/probe/transport attempt'
    assert 'Gathering Facts' not in output and 'ESTABLISH SSH CONNECTION' not in output
    role = COLLECTION / ROLE if loader == 'fqcn' else ROLE
    module = COLLECTION / MODULE if loader == 'fqcn' else MODULE
    assert f'task path: {src / role}:' in output
    assert f'Using module file {src / module}' in output
    assert 'ESTABLISH LOCAL CONNECTION' in output
    if denied:
        assert proc.returncode != 0 and 'S2_FIXED_DENIAL' in output, output
        assert 'S2_AFTER_ADAPTER' not in output
    else:
        assert proc.returncode == 0, output
        assert 'S2_RETURNED' in output and 'Verify exact safe decision' in output
        assert 'S2_DENIAL_CONFIRMED' not in output


def test_tripwire_positive_controls(harness):
    src, inv, env, marker = harness
    # All controls are local synthetic failures, including the fake SSH binary.
    trap = Path(env['PATH'].split(':')[0]) / 'openssl'
    proc = subprocess.run([str(trap)], env=env, cwd=src, capture_output=True, timeout=5)
    assert proc.returncode == 91 and marker.exists()
    marker.unlink()
    path = dump(src.parent / 'mock.yml', play([
        task('Exercise synthetic collector', 'ansible.builtin.include_role', {'name': 'crypto_posture_snapshot'})]))
    proc = run(harness, 'ansible-playbook', ['-i', inv, path, '--check'])
    assert proc.returncode != 0 and marker.exists(), proc.stdout + proc.stderr
    marker.unlink()
    path = dump(src.parent / 'transport.yml', play([
        task('Exercise fake SSH executable', 'ansible.builtin.command', {'argv': ['/bin/true']})], host=TARGET))
    proc = run(harness, 'ansible-playbook', ['-i', inv, path])
    assert proc.returncode != 0 and marker.exists(), proc.stdout + proc.stderr


@pytest.mark.parametrize('loader', ['short', 'fqcn'])
@pytest.mark.parametrize('missing', ['pqc_profile_policy', 'pqc_profile_request'])
def test_missing_caller_input_fails_closed(harness, resolver, loader, missing):
    src, inv, _, marker = harness
    variables = {'pqc_profile_policy': resolver.load_policy((src / POLICY).read_text()),
                 'pqc_profile_request': {}}
    del variables[missing]
    path = dump(src.parent / 'missing.yml', play([role_task(loader),
        task('S2_UNREACHABLE', 'ansible.builtin.debug', {'msg': 'S2_UNREACHABLE'})], variables))
    proc = run(harness, 'ansible-playbook', ['-i', inv, path, '-vvv'])
    output = proc.stdout + proc.stderr
    assert proc.returncode != 0 and ROLE_TASK in output and 'S2_UNREACHABLE' not in output
    assert 'Using module file' not in output and not marker.exists()
    assert SECRET not in output and ENDPOINT not in output


@pytest.mark.parametrize('loader', ['short', 'fqcn'])
def test_fresh_registered_result_each_call(harness, resolver, loader):
    src, inv, _, marker = harness
    policy = resolver.load_policy((src / POLICY).read_text())
    active, _, _ = cases(resolver, 'active-tls-plan')
    passive, _, _ = cases(resolver, 'baseline-all-off')
    # Static block vars provide a new caller request, not a set_fact or cache.
    tasks = []
    for request, decision in ((active, 'DEFERRED'), (passive, 'VALIDATED')):
        expected = resolver.resolve_scan_profile(policy, request)
        assert expected['decision'] == decision
        tasks.append({'block': [role_task(loader), assert_result(expected, False)],
                      'vars': {'pqc_profile_request': request, 'expected_decision': expected}})
    tasks.append(task('S2_FRESH_RESULT', 'ansible.builtin.assert', {'that': [
        f'{RESULT}.decision == "VALIDATED"', f'{RESULT}.active_intent_validated is false',
        f'not ({RESULT}.requested_flags.values() | select("true") | list)']}))
    path = dump(src.parent / 'fresh.yml', play(tasks, {'pqc_profile_policy': policy}))
    proc = run(harness, 'ansible-playbook', ['-i', inv, path, '-vvv'])
    output = proc.stdout + proc.stderr
    assert proc.returncode == 0, output
    assert output.count('Using module file ') == 2 and 'S2_FRESH_RESULT' in output
    assert SECRET not in output and ENDPOINT not in output and not marker.exists()
