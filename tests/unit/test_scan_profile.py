"""S1 policy contract, raw module and disposable localhost loader controls.

The native checks intentionally fail when the approved Ansible runtime is
missing. No optional skip, external inventory, managed host or collector.
"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
COLLECTION = 'ansible_collections/security/compliance_pqc_readiness'
CANONICAL = ROOT / COLLECTION / 'plugins/modules/resolve_scan_profile.py'
MIRROR = ROOT / 'plugins/modules/resolve_scan_profile.py'
POLICY = ROOT / 'config/scan_profiles.yml'
SPEC = importlib.util.spec_from_file_location('scan_profile_under_test', CANONICAL)
resolver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(resolver)

# Independent literal oracle, not derived from implementation constants.
PASSIVE = tuple('pqc_collect_' + key for key in ('packages', 'openssl', 'sshd',
                 'ssh_host_keys', 'system_certs', 'crypto_policy'))
NGINX = 'pqc_collect_nginx_certs'
TLS = 'pqc_collect_tls_services'
CERTS = 'pqc_collect_system_certs'
ALL = set(PASSIVE) | {NGINX, TLS}


@pytest.fixture
def policy():
    return resolver.load_policy(POLICY.read_text(encoding='utf-8'))


def endpoint(**changes):
    row = {'source_host': 'DummyHost', 'protocol': 'tls', 'address': 'scan.example.invalid',
           'port': 443, 'sni': None}
    row.update(changes)
    return row


def active(rows=None, **changes):
    request = {'profile': 'active', 'plan_only': True, 'active_opt_in': True,
               'target_ids': ['DummyHost'], 'active_endpoints': [endpoint()] if rows is None else rows}
    request.update(changes)
    return request


def check_result(result, decision, reason=None):
    assert result['profile_decision_version'] == 1
    assert type(result['profile_decision_version']) is int
    assert result['decision'] == decision
    if reason is not None:
        assert result['reason_code'] == reason
    assert result['active_dispatch_allowed'] is False
    assert result['execution_allowed'] is False
    assert len(result['per_collector']) == 8
    assert set(result['requested_flags']) == ALL
    assert {r['id'] for r in result['per_collector']} == ALL
    for row in result['per_collector']:
        assert row['collection_state'] == 'NOT_SCANNED'
        assert row['requested'] is result['requested_flags'][row['id']]
        assert type(row['requested']) is type(row['allowed_by_profile']) is bool
        assert row['planned_scope'] in ('baseline', 'extended', 'active')
        assert row['request_source'] in ('PROFILE_DEFAULT', 'RUN', 'INVENTORY_EFFECTIVE', 'NARROWED')
        if decision == 'DENIED':
            assert not row['requested'] and not row['allowed_by_profile']
            assert row['reason_code'] == result['reason_code']
    return {row['id']: row for row in result['per_collector']}


def test_policy_document_and_mirror(policy):
    # YAML compatibility check uses the existing Ansible/PyYAML dev tool,
    # while the product's strict parser intentionally accepts JSON-subset YAML.
    import yaml
    assert yaml.safe_load(POLICY.read_text()) == policy
    assert type(policy['policy_version']) is int and policy['policy_version'] == 1
    assert set(policy['profiles']) == {'baseline', 'extended', 'active'}
    assert policy['collector_classes'] == {**dict.fromkeys(PASSIVE, 'passive'), NGINX: 'extended', TLS: 'active'}
    for name, values in policy['profiles'].items():
        assert values == {**dict.fromkeys(PASSIVE, True), NGINX: name != 'baseline', TLS: False}
        assert all(type(v) is bool for v in values.values())
    assert CANONICAL.read_bytes() == MIRROR.read_bytes()
    assert CANONICAL.stat().st_mode & 0o777 == MIRROR.stat().st_mode & 0o777 == 0o644


@pytest.mark.parametrize('edit', ['version', 'bool_version', 'extra', 'missing', 'class', 'default',
                                  'number_bool', 'string_bool', 'profile_extra', 'flag_missing', 'active_tls'])
def test_policy_drift_denied(policy, edit):
    if edit == 'version': policy['policy_version'] = 2
    elif edit == 'bool_version': policy['policy_version'] = True
    elif edit == 'extra': policy['extra'] = {}
    elif edit == 'missing': del policy['collector_classes']
    elif edit == 'class': policy['collector_classes'][TLS] = 'passive'
    elif edit == 'default': policy['profiles']['baseline'][NGINX] = True
    elif edit == 'number_bool': policy['profiles']['baseline'][PASSIVE[0]] = 1
    elif edit == 'string_bool': policy['profiles']['baseline'][PASSIVE[0]] = 'true'
    elif edit == 'profile_extra': policy['profiles']['other'] = {}
    elif edit == 'flag_missing': del policy['profiles']['active'][PASSIVE[0]]
    else: policy['profiles']['active'][TLS] = True
    check_result(resolver.resolve_scan_profile(policy, {}), 'DENIED', 'INVALID_POLICY')
    with pytest.raises(resolver.PolicyError, match='^INVALID_POLICY$'):
        resolver.load_policy(json.dumps(policy))


@pytest.mark.parametrize('raw', [None, '', '[]', '{}', '{"policy_version":1,"policy_version":1}',
    '{"a":{"b":true,"b":false}}', '{"a": NaN}', '{"a": Infinity}',
    'policy_version: 1\npolicy_version: 1\n', '!!python/object:bad {}',
    '{"a": 1,}', '[' * 3000 + ']' * 3000, ' ' * 16385])
def test_strict_policy_parser(raw):
    with pytest.raises(resolver.PolicyError, match='^INVALID_POLICY$'):
        resolver.load_policy(raw)


def test_duplicate_in_real_policy_text():
    raw = POLICY.read_text()
    for bad in (raw.replace('"policy_version": 1', '"policy_version": 1, "policy_version": 1'),
                raw.replace('"pqc_collect_packages": true', '"pqc_collect_packages": false, "pqc_collect_packages": true', 1)):
        with pytest.raises(resolver.PolicyError, match='^INVALID_POLICY$'):
            resolver.load_policy(bad)


@pytest.mark.parametrize('profile', [None, 'baseline', 'extended'])
@pytest.mark.parametrize('plan', [False, True])
def test_passive_defaults(policy, profile, plan):
    request = {'plan_only': plan}
    if profile is not None: request['profile'] = profile
    value = resolver.resolve_scan_profile(policy, request)
    rows = check_result(value, 'VALIDATED', 'PLAN_ONLY' if plan else 'AWAITING_COLLECTOR')
    assert value['profile'] == (profile or 'baseline') and value['plan_only'] is plan
    assert value['active_intent_validated'] is False
    assert value['requested_flags'] == {**dict.fromkeys(PASSIVE, True), NGINX: profile == 'extended', TLS: False}
    assert rows[CERTS]['reason_code'] == 'ADAPTER_NOT_AVAILABLE'
    assert rows[CERTS]['planned_scope'] == ('extended' if profile == 'extended' else 'baseline')
    assert rows[NGINX]['reason_code'] == ('ADAPTER_NOT_AVAILABLE' if profile == 'extended' else 'DISABLED_BY_PROFILE')
    assert rows[TLS]['allowed_by_profile'] is False
    assert all(r['request_source'] == 'PROFILE_DEFAULT' for r in rows.values())


@pytest.mark.parametrize('value', [None, '', 'Baseline', 'BASELINE', 'extended ', 'unknown', 1, True, [], {}])
def test_invalid_selector(policy, value):
    result = resolver.resolve_scan_profile(policy, {'profile': value})
    check_result(result, 'DENIED', 'INVALID_INPUT')
    assert result['profile'] is None


@pytest.mark.parametrize('value', [True, False, 'true', 'false', 'TrUe', 'FaLsE'])
@pytest.mark.parametrize('where', ['run_flags', 'inventory_flags'])
def test_legacy_boolean_forms(policy, value, where):
    result = resolver.resolve_scan_profile(policy, {where: {PASSIVE[0]: value}})
    rows = check_result(result, 'VALIDATED')
    assert rows[PASSIVE[0]]['requested'] is (value is True or type(value) is str and value.lower() == 'true')


@pytest.mark.parametrize('value', [None, 0, 1, -1, 1.0, 'yes', 'no', 'on', 'off', '1', '0', '',
                                  ' true', 'false ', [], {}, '{{ true }}'])
@pytest.mark.parametrize('where', ['run_flags', 'inventory_flags', 'active_opt_in'])
def test_bad_boolean_types(policy, value, where):
    request = {where: value if where == 'active_opt_in' else {PASSIVE[0]: value}}
    check_result(resolver.resolve_scan_profile(policy, request), 'DENIED', 'INVALID_INPUT')


@pytest.mark.parametrize('request_data', [None, [], 'baseline', 1, {'plan_only': 'true'},
    {'plan_only': 1}, {'plan_only': None}, {'run_flags': None}, {'inventory_flags': []},
    {'run_flags': {'pqc_collect_unknown': False}}, {'inventory_flags': {'profile': 'active'}},
    {'compliance_profile': 'baseline'}, {'pqc_tls_probe_ports': [443]}, {'pqc_tls_probe_timeout': 5},
    {'command': 'DUMMY'}, {'pqc_write_html_report': True}, {'target_ids': None},
    {'target_ids': ['a', 'a']}, {'target_ids': ['*']}, {'target_ids': ['a:b']},
    {'target_ids': ['a,b']}, {'target_ids': ['a[1:2]']}, {'target_ids': ['a\n']},
    {'target_ids': ['a'*256]}, {'target_ids': ['{{ dummy }}']}, {'target_ids': ['fe80::1%eth0']},
    {'target_ids': [False]}, {'hostvars': {'synthetic_secret': 'DUMMY_SECRET_SENTINEL'}},
    {'execution_allowed': True}, {'active_dispatch_allowed': True}])
def test_reject_unknown_or_invalid_request(policy, request_data):
    value = resolver.resolve_scan_profile(policy, request_data)
    check_result(value, 'DENIED', 'INVALID_INPUT')
    assert 'DUMMY_SECRET_SENTINEL' not in json.dumps(value)


@pytest.mark.parametrize('flag', PASSIVE + (NGINX,))
@pytest.mark.parametrize('run,inv,expected,source,reason', [
    (False, True, False, 'RUN', 'DISABLED_BY_USER'),
    (True, False, False, 'NARROWED', 'NARROWED_BY_INVENTORY'),
    (None, False, False, 'NARROWED', 'NARROWED_BY_INVENTORY'),
    (False, False, False, 'RUN', 'DISABLED_BY_USER'),
    (True, None, True, 'RUN', None),
    (None, True, True, 'INVENTORY_EFFECTIVE', None),
])
def test_source_precedence(policy, flag, run, inv, expected, source, reason):
    request = {'profile': 'extended', 'run_flags': {} if run is None else {flag: run},
               'inventory_flags': {} if inv is None else {flag: inv}}
    row = check_result(resolver.resolve_scan_profile(policy, request), 'VALIDATED')[flag]
    assert row['requested'] is expected and row['request_source'] == source
    if reason: assert row['reason_code'] == reason


@pytest.mark.parametrize('profile,flag', [('baseline', NGINX), ('baseline', TLS), ('extended', TLS)])
@pytest.mark.parametrize('run,inv,decision', [(True, False, 'DENIED'), (True, None, 'DENIED'),
    (None, True, 'DENIED'), (False, True, 'VALIDATED'), (None, False, 'VALIDATED')])
def test_profile_ceiling(policy, profile, flag, run, inv, decision):
    request = {'profile': profile, 'run_flags': {} if run is None else {flag: run},
               'inventory_flags': {} if inv is None else {flag: inv}}
    row = check_result(resolver.resolve_scan_profile(policy, request), decision,
                       'PROFILE_CONFLICT' if decision == 'DENIED' else None)[flag]
    assert row['requested'] is False and row['allowed_by_profile'] is False


@pytest.mark.parametrize('profile', ['baseline', 'extended'])
@pytest.mark.parametrize('changes', [{'active_opt_in': True}, {'active_endpoints': [endpoint()]},
                                     {'active_opt_in': 'TRUE', 'active_endpoints': []}])
def test_passive_active_intent_denied(policy, profile, changes):
    check_result(resolver.resolve_scan_profile(policy, {'profile': profile, **changes}), 'DENIED', 'PROFILE_CONFLICT')


@pytest.mark.parametrize('address,sni', [('192.0.2.10', None), ('2001:db8::1', 'a.example.invalid'),
    ('SCAN.Example.INVALID.', 'SNI.Example.INVALID.'), ('host-1.example.invalid', None), ('singlelabel', None)])
def test_active_valid_intent_only(policy, address, sni):
    request = active([endpoint(address=address, sni=sni)])
    before = copy.deepcopy(request), copy.deepcopy(policy)
    result = resolver.resolve_scan_profile(policy, request)
    rows = check_result(result, 'DEFERRED', 'ACTIVE_NOT_AVAILABLE_V2_0')
    assert result['active_intent_validated'] is True and result['requested_flags'][TLS] is True
    assert rows[TLS]['planned_scope'] == 'active' and rows[TLS]['allowed_by_profile'] is True
    assert rows[TLS]['request_source'] == 'RUN'
    assert (request, policy) == before
    assert result == resolver.resolve_scan_profile(policy, request)
    assert 'DummyHost' not in json.dumps(result) and address not in json.dumps(result)
    if sni: assert sni not in json.dumps(result)
    live = resolver.resolve_scan_profile(policy, {**request, 'plan_only': False})
    check_result(live, 'DENIED', 'ACTIVE_NOT_AVAILABLE_V2_0')
    assert live['active_intent_validated'] is True


@pytest.mark.parametrize('changes,reason', [({'active_opt_in': False}, 'ACTIVE_OPT_IN_REQUIRED'),
    ({'active_opt_in': 'false'}, 'ACTIVE_OPT_IN_REQUIRED'), ({'active_endpoints': []}, 'ENDPOINT_INVALID'),
    ({'active_endpoints': None}, 'ENDPOINT_INVALID'), ({'target_ids': []}, 'TARGET_NOT_AUTHORIZED'),
    ({'target_ids': ['dummyhost']}, 'TARGET_NOT_AUTHORIZED'), ({'target_ids': ['Other']}, 'TARGET_NOT_AUTHORIZED')])
def test_active_requires_intent_and_fixed_targets(policy, changes, reason):
    check_result(resolver.resolve_scan_profile(policy, active(**changes)), 'DENIED', reason)


@pytest.mark.parametrize('field,value', [('address', x) for x in [None, '', 'https://x.invalid', '*.x.invalid',
    '192.0.2.0/24', '192.0.2.1-5', '192.0.2.999', '127.1', 'fe80::1%eth0', '[2001:db8::1]',
    'x.invalid,y.invalid', 'x.invalid;dummy', 'x.invalid\n', '{{x}}', '-bad.invalid', 'bad_.invalid',
    'a'*64+'.invalid', 'x..invalid', '域.invalid', 'a'*254]] + [('port', x) for x in
    [True, False, 0, 65536, -1, '443', 443.0, None]] + [('protocol', x) for x in
    ['TLS', 'http', None, [], 'ssh;dummy']] + [('sni', x) for x in
    ['', '192.0.2.1', '2001:db8::1', 'x.invalid/path', '*.invalid', 123, True, 'x\r.invalid']])
def test_endpoint_validation(policy, field, value):
    check_result(resolver.resolve_scan_profile(policy, active([endpoint(**{field: value})])),
                 'DENIED', 'ENDPOINT_INVALID')


@pytest.mark.parametrize('row', [None, [], 'x', {'source_host': 'DummyHost'},
    {**endpoint(), 'override': 'DUMMY_SECRET_SENTINEL'},
    {k: v for k, v in endpoint().items() if k != 'sni'},
    endpoint(protocol='ssh', sni='x.invalid'), endpoint(source_host='*')])
def test_endpoint_row_shape(policy, row):
    check_result(resolver.resolve_scan_profile(policy, active([row])), 'DENIED', 'ENDPOINT_INVALID')


@pytest.mark.parametrize('rows', [[endpoint(), endpoint()],
    [endpoint(address='scan.example.invalid'), endpoint(address='SCAN.EXAMPLE.INVALID.')],
    [endpoint(address='2001:db8::1'), endpoint(address='2001:0db8:0:0:0:0:0:1')],
    [endpoint(sni='a.invalid'), endpoint(sni='A.INVALID.')]])
def test_duplicate_canonical_endpoint(policy, rows):
    check_result(resolver.resolve_scan_profile(policy, active(rows)), 'DENIED', 'ENDPOINT_INVALID')


def test_distinct_tuples_and_bound(policy):
    rows = [endpoint(port=i+1) for i in range(200)]
    check_result(resolver.resolve_scan_profile(policy, active(rows)), 'DEFERRED')
    check_result(resolver.resolve_scan_profile(policy, active(rows+[endpoint(port=201)])), 'DENIED', 'ENDPOINT_INVALID')
    rows = [endpoint(), endpoint(protocol='ssh'), endpoint(sni='a.invalid'), endpoint(source_host='Other')]
    check_result(resolver.resolve_scan_profile(policy, active(rows, target_ids=['DummyHost', 'Other'])), 'DEFERRED')


@pytest.mark.parametrize('where', ['run_flags', 'inventory_flags'])
def test_active_tls_intent_conflict(policy, where):
    check_result(resolver.resolve_scan_profile(policy, active(**{where: {TLS: False}})), 'DENIED', 'PROFILE_CONFLICT')
    ssh = [endpoint(protocol='ssh', port=22)]
    check_result(resolver.resolve_scan_profile(policy, active(ssh, **{where: {TLS: True}})), 'DENIED', 'PROFILE_CONFLICT')
    valid = resolver.resolve_scan_profile(policy, active(ssh, **{where: {TLS: False}}))
    assert check_result(valid, 'DEFERRED')[TLS]['requested'] is False
    check_result(resolver.resolve_scan_profile(policy, active(**{where: {TLS: 'TRUE'}})), 'DEFERRED')


def test_active_ssh_only_and_no_stale_state(policy):
    before = resolver.resolve_scan_profile(policy, active())
    after = resolver.resolve_scan_profile(policy, active([endpoint(protocol='ssh', port=22)]))
    assert before['requested_flags'][TLS] is True
    assert check_result(after, 'DEFERRED')[TLS]['requested'] is False
    assert check_result(resolver.resolve_scan_profile(policy, {}), 'VALIDATED')[TLS]['requested'] is False
    assert before['requested_flags'][TLS] is True


def test_pure_resolver_no_external_operations(policy, monkeypatch):
    import builtins
    import socket
    import pathlib
    import subprocess as sp
    calls = []
    def trap(*args, **kwargs):
        calls.append(True)
        raise AssertionError('forbidden external operation')
    monkeypatch.setattr(builtins, 'open', trap)
    monkeypatch.setattr(pathlib.Path, 'open', trap)
    monkeypatch.setattr(socket, 'socket', trap)
    monkeypatch.setattr(socket, 'getaddrinfo', trap)
    monkeypatch.setattr(sp, 'Popen', trap)
    monkeypatch.setattr(os, 'system', trap)
    check_result(resolver.resolve_scan_profile(policy, {}), 'VALIDATED')
    check_result(resolver.resolve_scan_profile(policy, {'profile': 'extended'}), 'VALIDATED')
    check_result(resolver.resolve_scan_profile(policy, active()), 'DEFERRED')
    check_result(resolver.resolve_scan_profile(policy, active(plan_only=False)), 'DENIED')
    assert calls == []
    with pytest.raises(AssertionError, match='forbidden'):
        socket.getaddrinfo('synthetic.invalid', None)
    assert calls == [True]  # trap positive control, not a real lookup


def native_env(tmp_path):
    home = tmp_path / 'home'
    for part in ('', 'config', 'cache', 'data', 'tmp'):
        (home / part).mkdir(parents=True, exist_ok=True, mode=0o700)
    cfg = tmp_path / 'ansible.cfg'
    cfg.write_text('[defaults]\ninterpreter_python = '+sys.executable+'\n'
                   'retry_files_enabled = False\nhost_key_checking = True\n'
                   'inventory = localhost,\n[inventory]\nenable_plugins = host_list\n')
    return {'PATH': str(Path(sys.executable).parent) + ':/usr/bin:/bin', 'HOME': str(home),
            'XDG_CONFIG_HOME': str(home/'config'), 'XDG_CACHE_HOME': str(home/'cache'),
            'XDG_DATA_HOME': str(home/'data'), 'TMPDIR': str(home/'tmp'),
            'LC_ALL': 'C.UTF-8', 'LANG': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1',
            'ANSIBLE_CONFIG': str(cfg), 'ANSIBLE_LOCAL_TEMP': str(home/'tmp'),
            'ANSIBLE_REMOTE_TEMP': str(home/'tmp'), 'ANSIBLE_COLLECTIONS_PATH': str(ROOT),
            'ANSIBLE_COLLECTIONS_SCAN_SYS_PATH': 'false', 'ANSIBLE_LIBRARY': str(MIRROR.parent),
            'ANSIBLE_INVENTORY_ANY_UNPARSED_IS_FAILED': 'true',
            'ANSIBLE_INVENTORY_UNPARSED_IS_FAILED': 'true', 'ANSIBLE_NOCOLOR': '1'}


@pytest.mark.parametrize('module_path', [CANONICAL, MIRROR], ids=['canonical','mirror'])
@pytest.mark.parametrize('case', ['baseline', 'extended', 'active_plan', 'active_live', 'bad_type',
                                  'bad_key', 'bad_policy', 'missing_arg', 'outer_unknown'])
@pytest.mark.parametrize('check_mode', [False, True], ids=['normal','check'])
def test_native_module_raw(policy, tmp_path, module_path, case, check_mode):
    request = {}
    args = {'policy': policy, 'request': request, '_ansible_check_mode': check_mode}
    reason = None
    if case == 'extended': request['profile'] = 'extended'
    elif case == 'active_plan': request.update(active([endpoint(address='DUMMY-PRIVATE.invalid')]))
    elif case == 'active_live': request.update(active(plan_only=False)); reason = 'ACTIVE_NOT_AVAILABLE_V2_0'
    elif case == 'bad_type': request['run_flags'] = {PASSIVE[0]: 1}; reason = 'INVALID_INPUT'
    elif case == 'bad_key': request['DUMMY_PRIVATE_KEY'] = 'DUMMY_PRIVATE_VALUE'; reason = 'INVALID_INPUT'
    elif case == 'bad_policy': policy['policy_version'] = True; reason = 'INVALID_POLICY'
    elif case == 'missing_arg': del args['policy']; reason = 'INVALID_INPUT'
    elif case == 'outer_unknown': args['DUMMY_PRIVATE_KEY'] = 'DUMMY_PRIVATE_VALUE'; reason = 'INVALID_INPUT'
    proc = subprocess.run([sys.executable, str(module_path)], cwd=tmp_path, env=native_env(tmp_path),
                          input=json.dumps({'ANSIBLE_MODULE_ARGS': args}), text=True,
                          capture_output=True, timeout=5)
    assert 'DUMMY_PRIVATE_' not in proc.stdout + proc.stderr and 'DUMMY-PRIVATE.invalid' not in proc.stdout + proc.stderr
    assert proc.returncode == (1 if reason else 0), proc.stderr
    value = json.loads(proc.stdout)
    assert value['changed'] is False and value['invocation'] == {'module_args': {}}
    check_result(value, 'DENIED' if reason else 'DEFERRED' if case == 'active_plan' else 'VALIDATED', reason)
    if case not in ('missing_arg','outer_unknown'):
        expected = resolver.resolve_scan_profile(policy, request)
        assert {k: value[k] for k in expected} == expected
    assert bool(value.get('failed', False)) is bool(reason)


@pytest.mark.parametrize('module_name,source_path', [('resolve_scan_profile', MIRROR),
    ('security.compliance_pqc_readiness.resolve_scan_profile', CANONICAL)], ids=['short','fqcn'])
def test_native_loader_and_local_play(policy, tmp_path, module_name, source_path):
    env = native_env(tmp_path)
    doc = shutil.which('ansible-doc', path=env['PATH'])
    playbook = shutil.which('ansible-playbook', path=env['PATH'])
    assert doc and playbook, 'approved Ansible runtime is required, not a skip'
    args = [doc, '-t', 'module', '-F']
    if '.' in module_name: args.append('security.compliance_pqc_readiness')
    proc = subprocess.run(args, cwd=tmp_path, env=env, text=True, capture_output=True, timeout=5)
    assert proc.returncode == 0, proc.stderr
    # Native ansible-doc reports short-name modules as ansible.legacy.*.
    listed_name = module_name if '.' in module_name else 'ansible.legacy.' + module_name
    matches = [line.split(None, 1)[1] for line in proc.stdout.splitlines()
               if line.split() and line.split()[0] == listed_name]
    assert len(matches) == 1 and Path(matches[0]).resolve() == source_path.resolve(), matches
    # JSON is YAML syntax. All arguments are literal data, no external vars.
    request = {'profile': 'baseline', 'plan_only': True}
    play = [{'name': 'Synthetic controller policy only', 'hosts': 'localhost', 'connection': 'local',
             'gather_facts': False, 'become': False,
             'vars': {'ansible_python_interpreter': sys.executable}, 'tasks': [
                 {'name': 'Resolve', module_name: {'policy': policy, 'request': request}, 'register': 'result'},
                 {'name': 'Verify fixed contract', 'ansible.builtin.assert': {'that': [
                     'result.profile_decision_version == 1', 'result.profile == "baseline"',
                     'result.decision == "VALIDATED"', 'not result.changed', 'not result.execution_allowed',
                     'not result.active_dispatch_allowed', 'not result.requested_flags.pqc_collect_tls_services',
                     'result.per_collector | length == 8']}}]}]
    path = tmp_path/'synthetic-play.yml'
    path.write_text(json.dumps(play))
    command = [playbook, '-i', 'localhost,', str(path)]
    for opts in (['--syntax-check'], ['--check'], []):
        proc = subprocess.run(command+opts, cwd=tmp_path, env=env, text=True, capture_output=True, timeout=20)
        assert proc.returncode == 0, proc.stdout + proc.stderr
    # Negative control: actual failure prevents the following marker task.
    play[0]['tasks'][0][module_name]['request'] = {'profile': 'active', 'plan_only': True}
    play[0]['tasks'][1] = {'name': 'UNREACHABLE_SYNTHETIC_MARKER', 'ansible.builtin.debug': {'msg': 'SHOULD_NOT_DISPATCH'}}
    path.write_text(json.dumps(play))
    proc = subprocess.run(command, cwd=tmp_path, env=env, text=True, capture_output=True, timeout=20)
    assert proc.returncode != 0 and 'ACTIVE_OPT_IN_REQUIRED' in proc.stdout
    assert 'UNREACHABLE_SYNTHETIC_MARKER' not in proc.stdout and 'SHOULD_NOT_DISPATCH' not in proc.stdout
