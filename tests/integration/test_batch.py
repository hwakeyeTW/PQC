"""Native S2 synthetic scheduling and independent remote-surrogate tests.

No real SSH, endpoint, inventory, adapter registration or live entry point.
The only substituted production decision is the unavailable real -G proof;
the test-only registry and connection outcomes are fixed trusted Python code.
"""
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

import pytest

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj


batch = load('batch_execution_s2', ROOT / 'tools/batch_execution.py')
helper = load('bounded_execution', ROOT / 'plugins/module_utils/pqc_bounded_execution.py')
PKG, SSL = 'pqc_collect_packages', 'pqc_collect_openssl'


def cmd(code):
    return (sys.executable, '-I', '-B', '-c', code)


def selected_flags(*names):
    return {f: f in names for f in batch._COLLECTORS}


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    cfg = tmp_path / 'ssh_config'
    cfg.write_text('Host *\n StrictHostKeyChecking yes\n ControlMaster no\n ConnectTimeout 10\n BatchMode yes\n')
    trace, trap = tmp_path / 'trace', tmp_path / 'ssh-triggered'
    fake = tmp_path / 'ssh'
    fake.write_text(f'#!{sys.executable}\nfrom pathlib import Path\nPath({str(trap)!r}).write_text("FORBIDDEN")\nraise SystemExit(97)\n')
    fake.chmod(0o700)
    assert subprocess.run([str(fake)], timeout=5, capture_output=True).returncode == 97
    assert trap.read_text() == 'FORBIDDEN'
    trap.unlink()
    monkeypatch.setenv('PATH', str(tmp_path) + ':' + os.environ['PATH'])
    # S1 tests separately exercise validated config bytes and native _run.
    monkeypatch.setattr(batch, '_effective_ssh', lambda argv, fingerprint: ('SYNTHETIC_ONLY',))

    def make(count=3, forks=2, flags=None, overrides=None, lookup=False, profile='baseline'):
        names = [f'h{i:02d}.example.invalid' for i in range(count)]
        hv = {n: {'ansible_host': n, 'ansible_user': 'dummy'} for n in names}
        hv['excluded.example.invalid'] = {'ansible_connection': 'local'}
        for n, values in (overrides or {}).items():
            hv[n].update(values)
        raw = {'all': {'vars': {'ansible_user': 'dummy', 'ansible_connection': 'ssh',
                               'ansible_ssh_args': f'-F {cfg} -o ControlMaster=no -o ControlPath=none',
                               'ansible_ssh_common_args': '-o ProxyJump=jump.example.invalid'}},
               'selected': {'hosts': names}, 'excluded': {'hosts': ['excluded.example.invalid']}}
        if not lookup:
            raw['_meta'] = {'hostvars': hv}
        provider = tmp_path / 'provider'
        provider.write_text(f'''#!{sys.executable}
import json,sys,pathlib
p=pathlib.Path({str(trace)!r})
old=p.read_text().splitlines() if p.exists() else []
with p.open('a') as f: f.write(json.dumps(sys.argv[1:])+'\\n')
if sys.argv[1:]==['--list']:
    print(json.dumps({{'drift':{{'hosts':['drift.example.invalid']}}}} if '["--list"]' in old else {raw!r}))
elif len(sys.argv)==3 and sys.argv[1]=='--host': print(json.dumps({hv!r}[sys.argv[2]]))
else: sys.exit(8)
''')
        provider.chmod(0o700)
        request = batch._scope.parse_scope({'pqc_scan_groups': ['selected'], 'pqc_scan_profile': profile,
                                           **(selected_flags(PKG) if flags is None else flags)}, forks)
        return batch._Context(str(provider), request), names

    def register(slots=(PKG,), modes=None, delay=0.35, connection=None):
        modes = modes or {}
        def invoke(name, slot):
            mode = modes.get((name, slot), modes.get(name, 'ok'))
            marker = tmp_path / (name + '.' + slot + '.json')
            if mode == 'missing':
                os._exit(12)
            if mode == 'bad':
                return {'state': 'COLLECTED', 'reason_code': 'COLLECTED', 'rc': False, 'collection_ids': []}
            if mode == 'unknown-cleanup':
                return {'state': 'ERROR', 'reason_code': 'REMOTE_CLEANUP_UNCONFIRMED',
                        'rc': None, 'collection_ids': []}
            code = f'''import json, pathlib, time, os
p=pathlib.Path({str(marker)!r})
start=time.monotonic_ns()
p.write_text(json.dumps([start,None,os.getpid()]))
time.sleep({delay!r})
p.write_text(json.dumps([start,time.monotonic_ns(),os.getpid()]))
raise SystemExit({7 if mode == 'error' else 0})
'''
            result = helper.run_bounded(cmd(code), timeout_s=3)
            if result.reason_code == 'COMMAND_OK':
                return {'state': 'NOT_APPLICABLE' if mode == 'na' else 'COLLECTED',
                        'reason_code': 'NOT_APPLICABLE' if mode == 'na' else 'COLLECTED',
                        'rc': result.rc, 'collection_ids': []}
            return {'state': 'ERROR', 'reason_code': result.reason_code,
                    'rc': result.rc, 'collection_ids': []}
        monkeypatch.setattr(batch, '_passive_adapters', lambda: {
            f: (lambda name, f=f: invoke(name, f)) for f in slots})
        monkeypatch.setattr(batch, '_restricted_connection', connection or (lambda name: 'CONNECTED'))

    return make, register, trace, trap, cfg


def checked(ctx):
    rc, manifest = batch.execute_batch(ctx)
    assert batch.validate_terminal_manifest(manifest, rc) is None
    assert 'DUMMY_PRIVATE_SENTINEL' not in json.dumps(manifest)
    return rc, manifest


def states(manifest):
    return [h['host_state'] for h in manifest['hosts']]


def test_native_smoke(fixture):
    make, register, trace, trap, _ = fixture
    ctx, names = make(count=2)
    register()
    rc, out = checked(ctx)
    assert rc == 0, out
    assert states(out) == ['COMPLETE', 'COMPLETE']
    assert trace.read_text().splitlines() == ['["--list"]']
    assert not trap.exists()


def _markers(root, names, slot=PKG):
    return [json.loads((root / (n + '.' + slot + '.json')).read_text()) for n in names]


def _peak(intervals):
    events = sorted([(a, 1) for a, b, pid in intervals] + [(b, -1) for a, b, pid in intervals])
    live = peak = 0
    for _, change in events:
        live += change
        peak = max(peak, live)
    assert live == 0
    return peak


@pytest.mark.parametrize('forks,count', [(1, 3), (2, 4), (2, 10)])
def test_native_resource_limits(fixture, forks, count):
    make, register, trace, trap, _ = fixture
    ctx, names = make(count=count, forks=forks, lookup=count == 4)
    register(delay=0.8 if count == 4 else 0.4)
    rc, out = checked(ctx)
    assert rc == 0 and out['target_ids'] == names and out['target_count'] == count
    assert states(out) == ['COMPLETE'] * count
    intervals = _markers(trace.parent, names)
    assert len({p for _, _, p in intervals}) == count
    assert _peak(intervals) <= forks
    if count == 4:
        assert _peak(intervals) == 2  # observed overlap, not configuration-only
    for i in range(forks, count, forks):
        assert max(x[1] for x in intervals[i-forks:i]) <= min(x[0] for x in intervals[i:i+forks])
    assert trace.read_text().splitlines().count('["--list"]') == 1
    assert len(list(trace.parent.glob('*.pqc_collect_packages.json'))) == count
    assert not trap.exists()


def test_native_host_limit_rejected(fixture):
    make, register, trace, trap, _ = fixture
    register()
    with pytest.raises(batch.Denied) as error:
        make(count=11)
    assert error.value.code == 4
    assert not list(trace.parent.glob('*.pqc_collect_packages.json')) and not trap.exists()


@pytest.mark.parametrize('forks', [0, 3, True])
def test_forks_invalid(fixture, forks):
    make, register, trace, trap, _ = fixture
    register()
    with pytest.raises(batch.Denied) as error:
        make(forks=forks)
    assert error.value.code == 2 and not trace.exists() and not trap.exists()


@pytest.mark.parametrize('disabled', [False, True])
def test_no_adapter_or_all_disabled(fixture, disabled, monkeypatch):
    make, register, trace, trap, _ = fixture
    ctx, names = make(flags=selected_flags() if disabled else selected_flags(PKG))
    if disabled:
        register()
    def forbidden(*args):
        pytest.fail('no native dispatch is permitted')
    monkeypatch.setattr(batch._Context, '_preflight', forbidden)
    rc, out = checked(ctx)
    assert rc == 6 and out['reason_code'] == 'NO_EXECUTABLE_COLLECTORS'
    assert states(out) == ['NOT_ATTEMPTED'] * len(names)
    assert all(not h['attempted'] for h in out['hosts'])
    assert not trap.exists()


def test_partial_and_ordinary_failure_continue(fixture):
    make, register, trace, trap, _ = fixture
    ctx, names = make(count=3, forks=1, flags=selected_flags(PKG, SSL))
    register(slots=(PKG, SSL), modes={(names[0], SSL): 'error', names[1]: 'error', names[2]: 'na'})
    rc, out = checked(ctx)
    assert rc == 5 and states(out) == ['PARTIAL', 'ERROR', 'COMPLETE']
    assert all(h['attempted'] for h in out['hosts'])
    assert len(list(trace.parent.glob('*.pqc_collect_packages.json'))) == 3
    assert not trap.exists()


def test_unavailable_requested_slot_is_gap(fixture):
    make, register, _, trap, _ = fixture
    ctx, names = make(count=1, flags=selected_flags(PKG, SSL))
    register()
    rc, out = checked(ctx)
    assert rc == 5 and states(out) == ['PARTIAL']
    assert any(r['collector_id'] == SSL and r['state'] == 'NOT_SCANNED'
               and r['reason_code'] == 'ADAPTER_NOT_AVAILABLE' for r in out['hosts'][0]['collectors'])
    assert not trap.exists()


def test_zero_success(fixture):
    make, register, trace, trap, _ = fixture
    ctx, names = make(count=3)
    register(modes={n: 'error' for n in names})
    rc, out = checked(ctx)
    assert rc == 6 and states(out) == ['ERROR'] * 3 and all(h['attempted'] for h in out['hosts'])
    assert not trap.exists()


def test_confirmed_synthetic_connection_failure(fixture):
    make, register, trace, trap, _ = fixture
    ctx, names = make(count=2, forks=1)
    def connect(name):
        if name != names[0]:
            return 'CONNECTED'
        result = helper.run_bounded(cmd('raise SystemExit(7)'), timeout_s=2)
        assert result.rc == 7 and result.cleanup_confirmed
        return 'CONNECTION_FAILED'
    register(connection=connect)
    rc, out = checked(ctx)
    assert rc == 5 and states(out) == ['UNREACHABLE', 'COMPLETE']
    assert out['hosts'][0]['reason_code'] == 'CONNECTION_FAILED'
    assert not (trace.parent / (names[0] + '.' + PKG + '.json')).exists()
    assert not trap.exists()


def test_preflight_guard_rejects_before_dispatch(fixture):
    make, register, trace, trap, cfg = fixture
    ctx, names = make(count=2)
    register()
    cfg.write_text(cfg.read_text() + 'Include /tmp/dummy.conf\n')
    with pytest.raises(batch.Denied) as error:
        checked(ctx)
    assert error.value.code == 4
    assert not list(trace.parent.glob('*.pqc_collect_packages.json')) and not trap.exists()


def test_late_guard_drift_stops_new_dispatch(fixture, monkeypatch):
    make, register, trace, trap, _ = fixture
    ctx, names = make(count=3, forks=1)
    register()
    original = batch._guard
    def drift(c, n):
        if n == names[1]:
            c._inventory.hosts[n].set_variable('ansible_user', 'changed')
        return original(c, n)
    monkeypatch.setattr(batch, '_guard', drift)
    rc, out = checked(ctx)
    assert rc == 5 and out['reason_code'] == 'GUARD_REJECTED'
    assert states(out) == ['COMPLETE', 'NOT_ATTEMPTED', 'NOT_ATTEMPTED']
    assert len(list(trace.parent.glob('*.pqc_collect_packages.json'))) == 1 and not trap.exists()


def test_actual_worker_argv_drift_denies_adapter(fixture, monkeypatch):
    make, register, trace, trap, _ = fixture
    ctx, names = make(count=2, forks=1)
    register()
    original = batch._task
    def changed(c, names):
        c._inventory.hosts[names[0]].set_variable('ansible_user', 'changed')
        return original(c, names)
    monkeypatch.setattr(batch, '_task', changed)
    rc, out = checked(ctx)
    assert rc == 6 and states(out) == ['ERROR', 'NOT_ATTEMPTED']
    assert out['reason_code'] == 'INVALID_NATIVE_RESULT'
    assert not list(trace.parent.glob('*.pqc_collect_packages.json')) and not trap.exists()


@pytest.mark.parametrize('mode,reason', [('missing', 'OUTCOME_UNKNOWN'), ('bad', 'INVALID_ADAPTER_RESULT'),
                                         ('unknown-cleanup', 'REMOTE_CLEANUP_UNCONFIRMED')])
def test_severe_failure_stops_dispatch(fixture, mode, reason):
    make, register, trace, trap, _ = fixture
    ctx, names = make(count=3, forks=1)
    register(modes={names[0]: mode})
    rc, out = checked(ctx)
    assert rc == 6 and out['reason_code'] == reason, out
    assert states(out) == ['ERROR', 'NOT_ATTEMPTED', 'NOT_ATTEMPTED']
    assert out['hosts'][0]['attempted'] is True
    assert not list(trace.parent.glob('*.pqc_collect_packages.json')) and not trap.exists()


def test_cleanup_uncertain_after_valid_slot_not_complete(fixture):
    make, register, _, trap, _ = fixture
    ctx, names = make(count=2, forks=1, flags=selected_flags(PKG, SSL))
    register(slots=(PKG, SSL), modes={(names[0], PKG): 'unknown-cleanup'})
    rc, out = checked(ctx)
    assert rc == 6 and states(out) == ['ERROR', 'NOT_ATTEMPTED']
    assert out['reason_code'] == 'REMOTE_CLEANUP_UNCONFIRMED'
    assert any(r['state'] == 'COLLECTED' for r in out['hosts'][0]['collectors'])
    assert not trap.exists()


@pytest.mark.parametrize('mutation', ['foreign', 'duplicate', 'wrong-task', 'invalid-payload'])
def test_actual_native_callback_rejected(fixture, monkeypatch, mutation):
    make, register, trace, trap, _ = fixture
    ctx, names = make(count=3, forks=1)
    register()
    original = batch._make_queue
    def queue():
        q = original()
        put = q.put
        def corrupt(data):
            value = json.loads(data)
            if mutation == 'duplicate':
                put(data)
            elif mutation == 'foreign':
                value['target_id'] = 'excluded.example.invalid'
            elif mutation == 'wrong-task':
                value['task_uuid'] = 'foreign-task'
            else:
                value['row']['collectors'][0]['rc'] = 'DUMMY_PRIVATE_SENTINEL'
            put(json.dumps(value, separators=(',', ':')).encode())
        q.put = corrupt
        return q
    monkeypatch.setattr(batch, '_make_queue', queue)
    rc, out = checked(ctx)
    assert rc in (5, 6) and out['reason_code'] == 'INVALID_NATIVE_RESULT'
    assert states(out)[1:] == ['NOT_ATTEMPTED', 'NOT_ATTEMPTED']
    assert len(list(trace.parent.glob('*.pqc_collect_packages.json'))) == 1 and not trap.exists()


def test_manifest_semantic_rejection(fixture):
    import copy
    make, register, _, trap, _ = fixture
    ctx, names = make(count=2)
    register()
    rc, out = checked(ctx)
    assert rc == 0
    mutations = [
        lambda x: x.update(target_count=True), lambda x: x.update(batch_manifest_version=True),
        lambda x: x.update(target_ids=list(reversed(x['target_ids']))),
        lambda x: x['hosts'].append(x['hosts'][0]), lambda x: x['hosts'][1].update(target_id=names[0]),
        lambda x: x['limits'].update(forks=3), lambda x: x.update(profile='active'),
        lambda x: x['hosts'][0].update(attempted=False), lambda x: x.update(run_state='PARTIAL'),
        lambda x: x['hosts'][0]['collectors'][0].update(rc=9),
        lambda x: x['hosts'][0]['collectors'][0].update(collection_ids=['../secret']),
        lambda x: x['hosts'][0]['collectors'][1].update(collector_id=x['hosts'][0]['collectors'][0]['collector_id']),
        lambda x: x.update(raw_hostvars='DUMMY_PRIVATE_SENTINEL'),
    ]
    for mutate in mutations:
        altered = copy.deepcopy(out)
        mutate(altered)
        with pytest.raises(batch.Denied) as error:
            batch.validate_terminal_manifest(altered, rc)
        assert error.value.reason == 'INVALID_TERMINAL_MANIFEST'
    with pytest.raises(batch.Denied):
        batch.validate_terminal_manifest(out, 7)
    with pytest.raises(batch.Denied):
        batch.execute_batch(ctx)  # cannot reuse an invocation
    with pytest.raises(batch.Denied):
        batch.execute_batch(out)  # public/serialized output is no grant
    assert not trap.exists()


def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def wait_file(p, seconds=5):
    end = time.monotonic() + seconds
    while not p.exists() and time.monotonic() < end:
        time.sleep(0.02)
    assert p.exists()


@pytest.mark.parametrize('sig', [signal.SIGINT, signal.SIGTERM])
def test_caught_interrupt_native_worker(fixture, sig):
    make, register, trace, trap, _ = fixture
    ctx, names = make(count=3, forks=1)
    register(delay=2)
    marker = trace.parent / (names[0] + '.' + PKG + '.json')
    sender = subprocess.Popen(cmd(f'''import os,time,pathlib
p=pathlib.Path({str(marker)!r});end=time.monotonic()+8
while not p.exists() and time.monotonic()<end:time.sleep(.02)
if not p.exists(): raise SystemExit(8)
os.kill({os.getpid()},{int(sig)})'''), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        rc, out = checked(ctx)
        assert sender.wait(timeout=10) == 0
        assert rc == 7 and out['reason_code'] == 'INTERRUPTED' and out['run_state'] != 'COMPLETE'
        assert states(out)[1:] == ['NOT_ATTEMPTED', 'NOT_ATTEMPTED']
        assert not alive(json.loads(marker.read_text())[2]) and not trap.exists()
    finally:
        if sender.poll() is None:
            sender.kill(); sender.wait(timeout=5)


def test_interrupt_after_worker_result_not_complete(fixture, monkeypatch):
    make, register, _, trap, _ = fixture
    ctx, _ = make(count=1)
    register()
    original = batch._stop_workers
    def stop(workers):
        result = original(workers)
        os.kill(os.getpid(), signal.SIGTERM)
        return result
    monkeypatch.setattr(batch, '_stop_workers', stop)
    rc, out = checked(ctx)
    assert rc == 7 and out['run_state'] == 'PARTIAL' and out['reason_code'] == 'INTERRUPTED'
    assert states(out) == ['COMPLETE'] and not trap.exists()


@pytest.mark.parametrize('extra', [0, 1, 100000])
def test_remote_combined_output_cap(extra):
    result = helper.run_bounded(cmd(f'import os;os.write(1,b"a"*8192);os.write(2,b"b"*{8192+extra})'), timeout_s=3)
    assert result.cleanup_confirmed
    if extra == 0:
        assert result.reason_code == 'COMMAND_OK' and len(result.stdout) + len(result.stderr) == 16384
    else:
        assert result.reason_code == 'COMMAND_OUTPUT_LIMIT' and not result.stdout and not result.stderr


def test_remote_timeout_term_kill(tmp_path):
    marker = tmp_path / 'pid'
    code = f'import os,time,signal,pathlib;signal.signal(signal.SIGTERM,signal.SIG_IGN);pathlib.Path({str(marker)!r}).write_text(str(os.getpid()));time.sleep(20)'
    started = time.monotonic()
    result = helper.run_bounded(cmd(code), timeout_s=1.2)
    elapsed = time.monotonic() - started
    assert result.reason_code == 'COMMAND_TIMEOUT' and result.rc == -signal.SIGKILL
    assert result.cleanup_confirmed and elapsed <= 1.7 and not alive(int(marker.read_text()))


def _tree_code(marker, leader_exits):
    return f'''import os,time,signal,pathlib
signal.signal(signal.SIGTERM,signal.SIG_IGN)
pid=os.fork()
if pid==0:
    grand=os.fork()
    if grand==0:
        os.close(1);os.close(2);time.sleep(90);os._exit(0)
    pathlib.Path({str(marker)!r}).write_text(f"{{os.getppid()}} {{os.getpid()}} {{grand}}")
    os.close(1);os.close(2);time.sleep(90);os._exit(0)
p=pathlib.Path({str(marker)!r})
end=time.monotonic()+3
while not p.exists() and time.monotonic()<end:time.sleep(.01)
if {leader_exits!r}:os._exit(0)
time.sleep(90)
'''


def test_remote_residual_child_grandchild(tmp_path):
    marker = tmp_path / 'pids'
    result = helper.run_bounded(cmd(_tree_code(marker, True)), timeout_s=3)
    assert result.reason_code == 'RESIDUAL_PROCESS' and result.rc == 0 and result.cleanup_confirmed
    assert all(not alive(int(p)) for p in marker.read_text().split())


@pytest.mark.parametrize('argv,timeout', [(('relative',), 30), (('/bin/true',), 31), (('/bin/true',), True), ((), 30)])
def test_remote_contract_rejects(argv, timeout):
    assert helper.run_bounded(argv, timeout_s=timeout).reason_code == 'INVALID_COMMAND_CONTRACT'


def test_native_loader_both_paths(tmp_path):
    # Generate the test-only modules and playbook in private scratch. The
    # actual loader/AnsiballZ packaging must resolve both helper imports.
    import shutil
    coll = tmp_path / 'ansible_collections/security/compliance_pqc_readiness/plugins'
    (coll / 'modules').mkdir(parents=True)
    (coll / 'module_utils').mkdir()
    shutil.copyfile(ROOT / 'ansible_collections/security/compliance_pqc_readiness/plugins/module_utils/pqc_bounded_execution.py',
                    coll / 'module_utils/pqc_bounded_execution.py')
    library = tmp_path / 'library'; library.mkdir()
    for module, prefix in [(library / 'pqc_synthetic_short.py', 'ansible.module_utils'),
                           (coll / 'modules/pqc_synthetic_fqcn.py', 'ansible_collections.security.compliance_pqc_readiness.plugins.module_utils')]:
        module.write_text(f'''from ansible.module_utils.basic import AnsibleModule
from {prefix}.pqc_bounded_execution import run_bounded
import sys
m=AnsibleModule(argument_spec={{}})
r=run_bounded((sys.executable,'-I','-B','-c','print("SYNTHETIC_LOADER_OK")'),timeout_s=2)
m.exit_json(changed=False,reason=r.reason_code,rc=r.rc,clean=r.cleanup_confirmed,output=r.stdout.decode())
''')
    play = tmp_path / 'test.yml'
    play.write_text(f'''- hosts: localhost
  connection: local
  gather_facts: false
  become: false
  vars:
    ansible_python_interpreter: {sys.executable}
  tasks:
    - pqc_synthetic_short:
      register: short_result
    - security.compliance_pqc_readiness.pqc_synthetic_fqcn:
      register: fqcn_result
    - ansible.builtin.assert:
        that:
          - short_result.reason == 'COMMAND_OK'
          - fqcn_result.reason == 'COMMAND_OK'
          - short_result.clean and fqcn_result.clean
          - short_result.rc == 0 and fqcn_result.rc == 0
          - short_result.output.strip() == 'SYNTHETIC_LOADER_OK'
          - fqcn_result.output.strip() == 'SYNTHETIC_LOADER_OK'
''')
    cfg = tmp_path / 'ansible.cfg'; cfg.write_text('[defaults]\nretry_files_enabled = False\n')
    env = dict(os.environ, ANSIBLE_CONFIG=str(cfg), ANSIBLE_INVENTORY_ENABLED='host_list',
               ANSIBLE_COLLECTIONS_PATH=str(tmp_path), ANSIBLE_LIBRARY=str(library),
               ANSIBLE_MODULE_UTILS=str(ROOT / 'plugins/module_utils'),
               ANSIBLE_REMOTE_TEMP=str(tmp_path / 'remote'))
    argv = [str(Path(sys.executable).parent / 'ansible-playbook'), '-i', 'localhost,', str(play)]
    syntax = subprocess.run(argv + ['--syntax-check'], env=env, capture_output=True, timeout=30)
    assert syntax.returncode == 0, syntax.stderr.decode(errors='replace')
    run = subprocess.run(argv, env=env, capture_output=True, timeout=45)
    assert run.returncode == 0, run.stdout.decode(errors='replace') + run.stderr.decode(errors='replace')
    assert b'All assertions passed' in run.stdout


def test_full_synthetic_connection_deadline(fixture):
    # Two sequential handshake stages: each is below 15 s, their sum is not.
    # Use the actual one-session budget and a positive first-stage witness.
    make, register, trace, trap, _ = fixture
    ctx, names = make(count=2, forks=1)
    marker, receipt = trace.parent / 'chain-stage', trace.parent / 'chain-receipt'
    def connect(name):
        if name != names[0]:
            return 'CONNECTED'
        code = f'''import os,time,pathlib
p=pathlib.Path({str(marker)!r});p.write_text("stage1:"+str(os.getpid()))
time.sleep(8);p.write_text("stage2:"+str(os.getpid()));time.sleep(8)
'''
        start = time.monotonic()
        result = helper.run_bounded(cmd(code), timeout_s=batch._SSH_SECONDS)
        elapsed = time.monotonic() - start
        receipt.write_text(json.dumps([result.reason_code, result.cleanup_confirmed, elapsed]))
        assert result.reason_code == 'COMMAND_TIMEOUT' and result.cleanup_confirmed
        return 'CONNECTION_TIMEOUT'
    register(connection=connect)
    rc, out = checked(ctx)
    reason, clean, elapsed = json.loads(receipt.read_text())
    assert reason == 'COMMAND_TIMEOUT' and clean and 13 <= elapsed <= 15.5
    stage, pid = marker.read_text().split(':')
    assert stage == 'stage2' and not alive(int(pid))
    assert rc == 5 and states(out) == ['ERROR', 'COMPLETE']
    assert out['hosts'][0]['reason_code'] == 'CONNECTION_TIMEOUT'
    assert not (trace.parent / (names[0] + '.' + PKG + '.json')).exists() and not trap.exists()


def test_connection_missing_cleanup_stops(fixture, monkeypatch):
    make, register, trace, trap, _ = fixture
    ctx, _ = make(count=3, forks=1)
    monkeypatch.setattr(batch, '_SSH_SECONDS', .5)  # narrow test deadline only
    register(connection=lambda name: time.sleep(5))
    rc, out = checked(ctx)
    assert rc == 6 and out['reason_code'] == 'REMOTE_CLEANUP_UNCONFIRMED'
    assert states(out) == ['ERROR', 'NOT_ATTEMPTED', 'NOT_ATTEMPTED']
    assert not list(trace.parent.glob('*.pqc_collect_packages.json')) and not trap.exists()


def test_callback_does_not_prove_worker_exit(fixture, monkeypatch):
    make, register, trace, trap, _ = fixture
    ctx, _ = make(count=3, forks=1)
    register()
    original = batch._make_queue
    def queue():
        q = original()
        send = q.send_task_result
        def crash(result):
            send(result)
            os._exit(12)
        q.send_task_result = crash
        return q
    monkeypatch.setattr(batch, '_make_queue', queue)
    rc, out = checked(ctx)
    assert rc == 6 and out['reason_code'] == 'CONTROLLER_WORKER_FAILED'
    assert states(out) == ['ERROR', 'NOT_ATTEMPTED', 'NOT_ATTEMPTED']
    assert any(r['state'] == 'COLLECTED' for r in out['hosts'][0]['collectors'])
    assert len(list(trace.parent.glob('*.pqc_collect_packages.json'))) == 1 and not trap.exists()


def test_controller_worker_deadline(fixture, monkeypatch):
    make, register, trace, trap, _ = fixture
    ctx, _ = make(count=2, forks=1)
    register()
    # Narrow trusted constants in this test only, and withhold the native
    # worker result entirely. Full 15/30 s budgets are tested separately.
    monkeypatch.setattr(batch, '_GUARD_SECONDS', 2)
    monkeypatch.setattr(batch, '_SSH_SECONDS', .5)
    monkeypatch.setattr(batch, '_COMMAND_SECONDS', .5)
    monkeypatch.setattr(batch, '_WORKER_GRACE', .5)
    marker = trace.parent / 'hung-worker'
    def hang(*args):
        marker.write_text(str(os.getpid()))
        time.sleep(60)
    monkeypatch.setattr(batch, '_collect', hang)
    start = time.monotonic()
    rc, out = checked(ctx)
    assert time.monotonic() - start < 15
    assert rc == 6 and out['reason_code'] == 'CONTROLLER_TIMEOUT'
    assert states(out) == ['ERROR', 'NOT_ATTEMPTED']
    assert not alive(int(marker.read_text())) and not trap.exists()


def test_remote_30s_deadline_survives_transport_loss(tmp_path):
    # Separate, trusted remote surrogate. Kill only the transport process;
    # the remote worker has no controller heartbeat or timeout dependency.
    marker, receipt = tmp_path / 'remote-pids', tmp_path / 'remote-receipt'
    read_fd, write_fd = os.pipe()
    remote = transport = None
    try:
        code = f'''import importlib.util,sys,time,pathlib,json
s=importlib.util.spec_from_file_location('remote_helper',{str(ROOT / 'plugins/module_utils/pqc_bounded_execution.py')!r})
h=importlib.util.module_from_spec(s);s.loader.exec_module(h)
assert sys.stdin.readline() == 'GO\\n'
start=time.monotonic();r=h.run_bounded({cmd(_tree_code(marker, False))!r})
pathlib.Path({str(receipt)!r}).write_text(json.dumps([r.reason_code,r.rc,r.cleanup_confirmed,time.monotonic()-start,sys.stdin.read()]))
'''
        remote = subprocess.Popen(cmd(code), stdin=read_fd, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL, start_new_session=True)
        transport = subprocess.Popen(cmd('import sys,time;print("GO",flush=True);time.sleep(60)'),
                                     stdout=write_fd, stderr=subprocess.DEVNULL, start_new_session=True)
    finally:
        os.close(read_fd); os.close(write_fd)
    try:
        wait_file(marker)
        transport.kill()
        assert transport.wait(timeout=5) == -signal.SIGKILL
        assert remote.poll() is None  # remote deadline still active
        assert remote.wait(timeout=35) == 0
        reason, rc, clean, elapsed, eof = json.loads(receipt.read_text())
        assert reason == 'COMMAND_TIMEOUT' and rc == -signal.SIGKILL and clean
        assert 28 <= elapsed <= 30.5 and eof == ''
        pids = list(map(int, marker.read_text().split()))
        assert len(set(pids)) == 3 and all(not alive(p) for p in pids)
    finally:
        for p in (transport, remote):
            if p is not None and p.poll() is None:
                p.terminate()
                p.wait(timeout=5)
