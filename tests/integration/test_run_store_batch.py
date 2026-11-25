"""S2: actual restricted native batch receipts -> Evidence -> private storage.

Only fixed synthetic adapters and transport outcomes are injected in tests.
No production registry, real SSH, live entry point, or fake terminal producer.
"""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools import batch_execution as b, evidence as e, run_store as m
from plugins.module_utils import pqc_bounded_execution as helper

PKG, SSL = 'pqc_collect_packages', 'pqc_collect_openssl'
STAMP = '2026-01-03T00:00:00Z'
RID = 'native-v1-fixture'


def reject(code, fn, *args, **kwargs):
    with pytest.raises(m.StoreError) as exc:
        fn(*args, **kwargs)
    assert exc.value.code == code


def raw(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


@pytest.fixture
def harness(tmp_path, monkeypatch):
    # Positive control for the forbidden transport marker; the actual native
    # worker must never call this executable, even after a failed adapter.
    cfg = tmp_path / 'ssh_config'
    cfg.write_text('Host *\n StrictHostKeyChecking yes\n ControlMaster no\n ConnectTimeout 10\n BatchMode yes\n')
    trap = tmp_path / 'ssh-triggered'
    fake = tmp_path / 'ssh'
    fake.write_text(f'#!{sys.executable}\nfrom pathlib import Path\nPath({str(trap)!r}).write_text("FORBIDDEN")\nraise SystemExit(97)\n')
    fake.chmod(0o700)
    assert subprocess.run([str(fake)], timeout=5, capture_output=True).returncode == 97
    assert trap.read_text() == 'FORBIDDEN'
    trap.unlink()
    monkeypatch.setenv('PATH', str(tmp_path) + ':' + os.environ['PATH'])
    assert b._passive_adapters() == {}
    with pytest.raises(b.Denied, match='LIVE_NOT_AVAILABLE'):
        b._restricted_connection('h00.example.invalid')
    # Existing #8 S1 proof is not repeated: synthetic effective-config seam
    # only, actual option/argv checks and native WorkerProcess remain intact.
    monkeypatch.setattr(b, '_effective_ssh', lambda argv, fingerprint: ('SYNTHETIC_ONLY',))
    trace = tmp_path / 'trace'
    receipts = tmp_path / 'receipts'
    receipts.mkdir(mode=0o700)

    def make(count, selected):
        names = [f'h{i:02d}.example.invalid' for i in range(count)]
        hv = {n: {'ansible_host': n, 'ansible_user': 'dummy'} for n in names}
        hv['excluded.example.invalid'] = {'ansible_connection': 'local'}
        inventory = {'all': {'vars': {'ansible_user': 'dummy', 'ansible_connection': 'ssh',
                                     'ansible_ssh_args': f'-F {cfg} -o ControlMaster=no -o ControlPath=none',
                                     'ansible_ssh_common_args': '-o ProxyJump=jump.example.invalid'}},
                     'selected': {'hosts': names}, 'excluded': {'hosts': ['excluded.example.invalid']},
                     '_meta': {'hostvars': hv}}
        provider = tmp_path / 'provider'
        provider.write_text(f'#!{sys.executable}\nimport json,sys,pathlib\n'
                            f'p=pathlib.Path({str(trace)!r})\n'
                            'with p.open("a") as f: f.write(json.dumps(sys.argv[1:])+"\\n")\n'
                            f'assert sys.argv[1:]==["--list"]\nprint(json.dumps({inventory!r}))\n')
        provider.chmod(0o700)
        request = b._scope.parse_scope({'pqc_scan_groups': ['selected'], 'pqc_scan_profile': 'baseline',
                                        **{f: f in selected for f in b._COLLECTORS}}, 1)
        return b._Context(str(provider), request)

    def options(ctx):
        return dict(run_id=RID, run_kind='SYNTHETIC', evidence_schema_version='1.1.0',
                    batch_contract=m.NATIVE_BATCH_CONTRACT, started_at=STAMP, recorded_at=STAMP,
                    source={'source_kind': 'SYNTHETIC', 'producer_id': 'fixture-runner',
                            'producer_version': '1.0.0', 'origin_ref': 'fixture-source', 'input_sha256': None},
                    expected_hosts=[{'target_id': n, 'inventory_authority_id': None, 'identity_key': n}
                                    for n in ctx._targets],
                    limits={'max_hosts': ctx._request['max_hosts'], 'forks': ctx._request['forks'],
                            'serial': 2, 'ssh_timeout_s': 15, 'command_timeout_s': 30},
                    profile=ctx._request['profile'],
                    requested_flags={n: dict(ctx._decisions[n]['requested_flags']) for n in ctx._targets})

    def execute(ctx, writer, root, *, modes=None, stop=None, slots=(PKG,), unreachable=()):
        modes = modes or {}
        scope = writer.scope
        hosts = {h['target_id']: h for h in scope['hosts']}
        queued = []
        controller = os.getpid()
        original_strategy = b._queue_strategy

        def strategy(tqm):
            obj = original_strategy(tqm)
            queue = obj._queue_task
            def queue_with_intent(host, task, vals, pc):
                writer.dispatch_intent(hosts[host.name]['host_id'])
                queued.append(host.name)
                return queue(host, task, vals, pc)
            obj._queue_task = queue_with_intent
            return obj
        monkeypatch.setattr(b, '_queue_strategy', strategy)

        def collect(name, flag):
            # Read the actual persisted intent before acquiring any observation.
            # The worker never updates the store journal or terminal checkpoints.
            hid = hosts[name]['host_id']
            journal = m._unseal((root / RID / 'journal.json').read_bytes(), m.MAX_MANIFEST)
            assert hid in journal['intents'] and journal['scope'] == scope
            assert os.getpid() != controller
            mode = modes.get((name, flag), modes.get(name, 'ok'))
            if mode == 'lost':
                os._exit(12)
            if mode == 'fatal':
                return dict(state='ERROR', reason_code='REMOTE_CLEANUP_UNCONFIRMED', rc=None, collection_ids=[])
            # Fixed bounded child returns typed synthetic observation, not a
            # collection ID invented from the returned terminal receipt.
            short = m.NATIVE_COLLECTORS[flag]
            code = ('raise SystemExit(7)' if mode == 'error' else
                    'import json; print(json.dumps({"scope": '+repr(short)+', "attempted": True, '
                    '"coverage": "COMPLETE", "observation_count": 1, "applicable": True}))')
            result = helper.run_bounded((sys.executable, '-I', '-B', '-c', code), timeout_s=3)
            assert result.cleanup_confirmed
            if mode == 'error':
                assert result.reason_code == 'COMMAND_FAILED' and result.rc == 7
                return dict(state='ERROR', reason_code=result.reason_code, rc=result.rc, collection_ids=[])
            assert result.reason_code == 'COMMAND_OK' and result.rc == 0 and result.stderr == b''
            data = json.loads(result.stdout)
            assert data == {'scope': short, 'attempted': True, 'coverage': 'COMPLETE',
                            'observation_count': 1, 'applicable': True}
            cid = e.collection_id(RID, hid, short, short)
            eid = e.evidence_id(RID, hid, cid, 'fixture-summary')
            src = {**scope['source'], 'producer_id': short}
            collection = {'collection_id': cid, 'host_id': hid, 'collector_id': short,
                          'collector_version': '1.0.0', 'scope_key': short, 'collection_state': 'COLLECTED',
                          'reason_code': 'COLLECTED', 'source': src, 'observed_at': STAMP, 'evidence_ids': [eid]}
            observation = {'evidence_id': eid, 'host_id': hid, 'collection_id': cid, 'asset_id': None,
                           'observation_key': 'fixture-summary', 'evidence_kind': 'COLLECTION_SUMMARY',
                           'source': src, 'observed_at': STAMP, 'data': data, 'algorithm': None}
            fragment = m._doc(scope, [{**hosts[name], 'host_state': 'COMPLETE', 'reason_code': 'COMPLETE'}], 'COMPLETE')
            fragment['collections'] = [collection]; fragment['evidence'] = [observation]
            validated = e.canonical_bytes(fragment)
            fd = os.open(receipts / (name + '.' + flag + '.json'),
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as f:
                f.write(validated); f.flush(); os.fsync(f.fileno())
            return dict(state='COLLECTED', reason_code='COLLECTED', rc=0, collection_ids=[cid])

        monkeypatch.setattr(b, '_passive_adapters', lambda: {f: lambda n, f=f: collect(n, f) for f in slots})
        monkeypatch.setattr(b, '_restricted_connection', lambda n: 'CONNECTION_FAILED' if n in unreachable else 'CONNECTED')
        if stop:
            # Deterministic fault after the last genuine worker completion.
            # Do not mutate a terminal or fake a returned manifest. The actual
            # ledger/validator own the stop state and rc, even for all COMPLETE.
            finish = b._WorkerWave.finish
            def finish_with_stop(wave, workers):
                quiet = finish(wave, workers)
                if len(wave.ledger.rows) == len(hosts):
                    if stop == 'INTERRUPTED':
                        os.kill(controller, signal.SIGINT)
                    else:
                        wave.ledger.fail(stop)
                return quiet
            monkeypatch.setattr(b._WorkerWave, 'finish', finish_with_stop)
        rc, manifest = b.execute_batch(ctx)
        assert b.validate_terminal_manifest(manifest, rc) is None
        assert trace.read_text().splitlines() == ['["--list"]'] and not trap.exists()
        assert set(queued) <= set(hosts)
        assert set(queued) == {r['target_id'] for r in manifest['hosts'] if r['attempted']}
        rows = [{**hosts[r['target_id']], 'host_state': r['host_state'], 'reason_code': r['reason_code']}
                for r in manifest['hosts']]
        doc = m._doc(scope, rows, manifest['run_state'], coverage_reason=manifest['reason_code'])
        # Read only the fixed fixture receipts, independently of manifest refs;
        # validate the original bytes again, and bind actual collection IDs.
        for n in hosts:
            for flag in slots:
                path = receipts / (n + '.' + flag + '.json')
                if path.exists():
                    assert stat.S_IMODE(path.stat().st_mode) == 0o600
                    fragment = json.loads(path.read_bytes())
                    assert e.canonical_bytes(fragment) == path.read_bytes()
                    doc['collections'].extend(fragment['collections'])
                    doc['evidence'].extend(fragment['evidence'])
        return rc, manifest, json.loads(e.canonical_bytes(doc))

    return make, options, execute


@pytest.fixture
def root():
    with tempfile.TemporaryDirectory(prefix='pqc-store-native-', dir='/tmp') as base:
        path = Path(base) / 'reports'; path.mkdir(mode=0o700)
        yield path


def persist(w, manifest, doc):
    for row in manifest['hosts']:
        hid = next(h['host_id'] for h in doc['hosts'] if h['target_id'] == row['target_id'])
        w.record_host(m.host_fragment(doc, hid), attempted=row['attempted'], terminal=row)


def check_roundtrip(store, root, rc, manifest, doc, result, batch_raw):
    out = result.manifest
    assert out['batch_contract'] == m.NATIVE_BATCH_CONTRACT
    assert (out['run_state'], out['reason_code'], out['batch_rc']) == (manifest['run_state'], manifest['reason_code'], rc)
    assert result.document == doc and result.artifacts['batch_manifest.json'] == batch_raw
    assert out['batch_canonical_sha256'] == hashlib.sha256(raw(manifest)).hexdigest()
    assert next(x for x in out['artifacts'] if x['kind'] == 'batch')['sha256'] == hashlib.sha256(batch_raw).hexdigest()
    assert {r['target_id']: r['terminal'] for r in out['hosts']} == {r['target_id']: r for r in manifest['hosts']}
    assert out['counts']['total'] == len(manifest['hosts'])
    for state in m.HOST_STATES:
        assert out['counts'][state] == sum(r['host_state'] == state for r in manifest['hosts'])
    assert store.open(RID) == result
    for path in (root / RID).rglob('*'):
        assert stat.S_IMODE(path.stat().st_mode) == (0o700 if path.is_dir() else 0o600)
    assert (root / RID / 'batch_manifest.json').read_bytes() == batch_raw


@pytest.mark.parametrize('case,selected,count,rc_expected,states', [
    ('complete', (PKG,), 2, 0, ('COMPLETE', 'COMPLETE')),
    ('partial', (PKG,), 3, 5, ('COMPLETE', 'UNREACHABLE', 'ERROR')),
    ('host_partial', (SSL, PKG), 1, 5, ('PARTIAL',)),
    ('zero', (PKG,), 1, 6, ('ERROR',)),
    ('disabled', (), 2, 6, ('NOT_ATTEMPTED', 'NOT_ATTEMPTED')),
    ('empty_registry', (PKG,), 1, 6, ('NOT_ATTEMPTED',)),
    ('fatal', (SSL, PKG), 2, 6, ('ERROR', 'NOT_ATTEMPTED')),
    ('lost', (PKG,), 2, 6, ('ERROR', 'NOT_ATTEMPTED')),
    ('abnormal_complete', (PKG,), 1, 5, ('COMPLETE',)),
    ('interrupted', (PKG,), 1, 7, ('COMPLETE',)),
])
def test_actual_native_batch_roundtrip(root, harness, tmp_path, case, selected, count, rc_expected, states):
    make, options, execute = harness
    ctx = make(count, selected); args = options(ctx)
    modes = {}; stop = None; unreachable = (); slots = (PKG,)
    if case == 'partial':
        unreachable = (ctx._targets[1],); modes[ctx._targets[2]] = 'error'
    elif case == 'host_partial':
        slots = (SSL, PKG); modes[ctx._targets[0], PKG] = 'error'
    elif case == 'zero': modes[ctx._targets[0]] = 'error'
    elif case == 'fatal':
        slots = (SSL, PKG); modes[ctx._targets[0], PKG] = 'fatal'
    elif case == 'lost': modes[ctx._targets[0]] = 'lost'
    elif case == 'empty_registry': slots = ()
    elif case == 'abnormal_complete': stop = 'CONTROLLER_TIMEOUT'
    elif case == 'interrupted': stop = 'INTERRUPTED'
    with m.RunStore(root) as store:
        with store.begin(**args) as w:
            reject('RUN_BUSY', store.open, RID)
            rc, batch, doc = execute(ctx, w, root, modes=modes, stop=stop, slots=slots, unreachable=unreachable)
            assert rc == rc_expected and tuple(r['host_state'] for r in batch['hosts']) == states
            if case == 'fatal':
                assert batch['hosts'][0]['reason_code'] == 'REMOTE_CLEANUP_UNCONFIRMED'
                assert len(doc['evidence']) == 1 and doc['collections'][0]['collector_id'] == 'openssl'
            if case == 'lost':
                assert any(c['reason_code'] == 'OUTCOME_UNKNOWN' for c in batch['hosts'][0]['collectors'])
            if case in ('abnormal_complete', 'interrupted'):
                assert batch['run_state'] == 'PARTIAL' and batch['reason_code'] == stop
            persist(w, batch, doc)
            batch_raw = json.dumps(batch, indent=2).encode()
            result = w.finalize(doc, batch_raw=batch_raw, batch_rc=rc)
        check_roundtrip(store, root, rc, batch, doc, result, batch_raw)
        reject('RUN_ID_COLLISION', store.begin, **args)
        # Private synthetic result for optional external schema checks.
        fd = os.open(tmp_path / 'verified-manifest.json', os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(raw(result.manifest))


def test_actual_native_rejects_mismatches_and_corruption(root, harness):
    make, options, execute = harness
    ctx = make(2, (PKG,)); args = options(ctx)
    with m.RunStore(root) as store:
        with store.begin(**args) as w:
            rc, batch, doc = execute(ctx, w, root)
            row = batch['hosts'][0]; hid = next(h['host_id'] for h in doc['hosts'] if h['target_id'] == row['target_id'])
            fragment = m.host_fragment(doc, hid)
            def slot(r): return next(c for c in r['collectors'] if c['collector_id'] == PKG)
            other = next(c['collection_id'] for c in doc['collections'] if c['host_id'] != hid)
            bad = deepcopy(row); slot(bad)['collection_ids'] = [other]
            reject('FOREIGN_REF', w.record_host, fragment, attempted=True, terminal=bad)
            bad = deepcopy(row); slot(bad)['collection_ids'] = []
            reject('BATCH_COVERAGE', w.record_host, fragment, attempted=True, terminal=bad)
            # Recompute genuine Evidence IDs for a different producer/scope;
            # these are valid Evidence documents but not this B04 fixture slot.
            for collector, scope_key in [('pqc-platform', 'platform'), ('packages', 'another-scope')]:
                wrong = deepcopy(fragment)
                coll, obs = wrong['collections'][0], wrong['evidence'][0]
                cid = e.collection_id(RID, hid, collector, scope_key)
                eid = e.evidence_id(RID, hid, cid, obs['observation_key'])
                coll.update(collection_id=cid, collector_id=collector, scope_key=scope_key,
                            evidence_ids=[eid])
                obs.update(collection_id=cid, evidence_id=eid)
                coll['source']['producer_id'] = obs['source']['producer_id'] = collector
                obs['data']['scope'] = scope_key
                e.validate_document(wrong)
                bad = deepcopy(row); slot(bad)['collection_ids'] = [cid]
                reject('FOREIGN_COLLECTOR', w.record_host, wrong, attempted=True, terminal=bad)
            bad = deepcopy(row); slot(bad)['requested'] = False
            reject('INVALID_TERMINAL_MANIFEST', w.record_host, fragment, attempted=True, terminal=bad)
            bad = deepcopy(row)
            for c in bad['collectors']: c['collector_id'] = m.NATIVE_COLLECTORS[c['collector_id']]
            reject('INVALID_TERMINAL_MANIFEST', w.record_host, fragment, attempted=True, terminal=bad)
            persist(w, batch, doc)
            for k, val in [('target_count', 1), ('run_state', 'ERROR'), ('reason_code', 'INTERRUPTED')]:
                bad = {**batch, k: val}
                reject('INVALID_TERMINAL_MANIFEST', w.finalize, doc, batch_raw=raw(bad), batch_rc=rc)
            reject('INVALID_TERMINAL_MANIFEST', w.finalize, doc, batch_raw=raw(batch), batch_rc=7)
            bad = deepcopy(batch); slot(bad['hosts'][0])['collection_ids'] = []
            reject('TERMINAL_MISMATCH', w.finalize, doc, batch_raw=raw(bad), batch_rc=rc)
            bad_doc = deepcopy(doc); bad_doc['run'].pop('coverage_reason')
            reject('BATCH_RUN_REASON', w.finalize, bad_doc, batch_raw=raw(batch), batch_rc=rc)
            result = w.finalize(doc, batch_raw=raw(batch), batch_rc=rc)
        check_roundtrip(store, root, rc, batch, doc, result, raw(batch))
        p = root / RID / 'batch_manifest.json'; original = p.read_bytes()
        p.write_bytes(original[:-1] + b' ')
        reject('ARTIFACT_HASH', store.open, RID)


def test_actual_native_recovery_without_final_batch(root, harness):
    make, options, execute = harness
    ctx = make(2, (PKG,)); args = options(ctx)
    with m.RunStore(root) as store:
        with store.begin(**args) as w:
            rc, batch, doc = execute(ctx, w, root)
            assert rc == 0
            row = batch['hosts'][0]; hid = next(h['host_id'] for h in doc['hosts'] if h['target_id'] == row['target_id'])
            w.record_host(m.host_fragment(doc, hid), attempted=True, terminal=row)
            # Deliberately retain the other durable intent but no checkpoint.
        reject('INCOMPLETE_RUN', store.open, RID)
        result = store.recover(RID)
        out = result.manifest
        assert out['recovery'] and out['batch_contract'] == m.NATIVE_BATCH_CONTRACT
        assert out['batch_rc'] is out['batch_canonical_sha256'] is None
        assert out['batch_missing_reason'] == 'BATCH_MANIFEST_UNAVAILABLE'
        assert out['run_state'] == 'PARTIAL' and out['counts']['total'] == 2
        assert len(result.document['evidence']) == 1
        unknown = next(h for h in out['hosts'] if h['host_state'] == 'ERROR')
        assert unknown['attempted'] is None and unknown['attempt_status'] == 'UNKNOWN'
        assert unknown['terminal'] is None and unknown['reason_code'] == 'OUTCOME_UNKNOWN'
        assert 'batch_manifest.json' not in result.artifacts
        assert store.open(RID) == result


def test_native_contract_rejects_wrong_scope_before_reservation(root, harness):
    make, options, _ = harness
    ctx = make(1, (PKG,)); args = options(ctx)
    with m.RunStore(root) as store:
        reject('BATCH_CONTRACT', store.begin, **{**args, 'batch_contract': 'B04_UNKNOWN'})
        reject('UNVERIFIED_PRODUCER_FORMAT', store.begin, **{**args, 'evidence_schema_version': '1.0.0'})
        bad = deepcopy(args); bad['requested_flags'][ctx._targets[0]] = dict.fromkeys(m.COLLECTORS, False)
        reject('PROFILE_FLAGS', store.begin, **bad)
        bad = deepcopy(args); bad.update(run_kind='NATIVE_SCAN'); bad['source']['source_kind'] = 'NATIVE_COLLECTOR'
        reject('UNVERIFIED_PRODUCER_FORMAT', store.begin, **bad)
        assert not (root / RID).exists()


def test_actual_native_prepared_recovery_and_required_detail(root, harness, monkeypatch):
    make, options, execute = harness
    ctx = make(2, (PKG,)); args = options(ctx)
    hid = e.host_id(None, ctx._targets[0], run_id=RID, identity_key=ctx._targets[0])
    args['requirements'] = {'assessment': False, 'cff': False,
                            'details': [{'host_id': hid, 'slot': 'platform'}]}
    with m.RunStore(root) as store:
        with store.begin(**args) as w:
            rc, batch, doc = execute(ctx, w, root, modes={ctx._targets[1]: 'error'})
            assert rc == 5 and batch['hosts'][0]['host_state'] == 'COMPLETE'
            frag = m.host_fragment(doc, hid); terminal = batch['hosts'][0]
            reject('REQUIRED_DETAIL_MISSING', w.record_host, frag, attempted=True, terminal=terminal)
            obs = frag['evidence'][0]
            detail = {'format_version': '1.0.0', 'format': 'S1_TYPED_FIXTURE', 'run_id': RID,
                      'host_id': hid, 'slot': 'platform', 'collection_ids': [obs['collection_id']],
                      'asset_ids': [], 'evidence_ids': [obs['evidence_id']],
                      'records': [{'record_kind': 'DIAGNOSTIC', 'evidence_id': obs['evidence_id'],
                                   'state': 'COLLECTED', 'reason_code': 'COLLECTED', 'rc': 0}]}
            w.record_host(frag, attempted=True, terminal=terminal, details=[detail])
            row = batch['hosts'][1]
            other = next(h['host_id'] for h in doc['hosts'] if h['target_id'] == row['target_id'])
            w.record_host(m.host_fragment(doc, other), attempted=True, terminal=row)
            batch_raw = json.dumps(batch, indent=2).encode()
            # Inject a failure only after the real durable prepare marker has
            # been written. Reader must refuse until actual recovery publishes.
            with monkeypatch.context() as patch:
                def stop_before_commit(self, verified=None):
                    raise m.StoreError('TEST_STOP_AFTER_PREPARE')
                patch.setattr(m.RunWriter, '_resume', stop_before_commit)
                reject('TEST_STOP_AFTER_PREPARE', w.finalize, doc, batch_raw=batch_raw, batch_rc=rc)
            assert (root / RID / 'prepared.json').is_file()
            assert not (root / RID / 'run_manifest.json').exists()
        reject('INCOMPLETE_RUN', store.open, RID)
        result = store.recover(RID)
        assert not result.manifest['recovery']
        assert result.artifacts[f'details/{hid}/platform.json'] == raw(detail)
        check_roundtrip(store, root, rc, batch, doc, result, batch_raw)


def test_native_collector_mapping_and_schema():
    assert set(m.NATIVE_COLLECTORS) == set(b._COLLECTORS)
    assert set(m.NATIVE_COLLECTORS.values()) == set(m.COLLECTORS)
    assert len(m.NATIVE_COLLECTORS) == len(set(m.NATIVE_COLLECTORS.values())) == 8
    assert all(key == 'pqc_collect_' + short for key, short in m.NATIVE_COLLECTORS.items())
    assert json.loads((ROOT / 'schemas/run-manifest-1.0.0.schema.json').read_bytes()) == m.manifest_schema()
