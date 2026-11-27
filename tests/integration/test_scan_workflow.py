"""C3b actual native synthetic Worker/Store integration; no live transport."""
import errno
import fcntl
import hashlib
import json
import os
import signal
import time

import pytest

from tools import batch_execution as batch, run_store as store, run_store_v3 as v3
from tools import scan_collectors as bridge, evidence, scan_workflow as workflow
import test_batch as original_batch
import test_scan_collectors as fixtures

RULES_RAW = (fixtures.ROOT / 'config/assessment_rules.yml').read_bytes()


@pytest.fixture
def native(tmp_path, monkeypatch):
    # Use the canonical module for the private exact-type Controller contract.
    # The original fixture normally loads its own test-only module instance.
    monkeypatch.setattr(original_batch, 'batch', batch)
    monkeypatch.setattr(fixtures, 'batch', batch)
    make, _, trace, trap, cfg = original_batch.fixture.__wrapped__(tmp_path, monkeypatch)
    root = tmp_path / 'reports'
    root.mkdir(mode=0o700)
    return make, trace, trap, cfg, root


def published(root, s, result):
    assert type(result) is workflow._Result and type(result.late_interrupted) is bool
    p = result.published
    m = p.manifest
    assert m['manifest_version'] == '1.1.0' and m['batch_contract'] == v3.CONTRACT
    assert m['batch_rc'] == result.batch_rc and m['run_state'] == result.batch_manifest['run_state']
    assert not m['recovery']
    assert m['producer_rules_sha256'] == hashlib.sha256(RULES_RAW).hexdigest()
    assert [h['terminal'] for h in sorted(m['hosts'], key=lambda h: h['target_id'])] == result.batch_manifest['hosts']
    run = root / m['run_id']
    import jsonschema
    schema = json.loads((fixtures.ROOT / 'schemas/run-manifest-1.1.0.schema.json').read_bytes())
    assert schema == v3.manifest_schema_v3()
    jsonschema.Draft202012Validator(schema).validate(m)
    entries = {e['path']: e for e in m['artifacts']}
    assert set(entries) == set(p.artifacts)
    for path, raw in p.artifacts.items():
        assert (run / path).read_bytes() == raw and entries[path]['size'] == len(raw)
        assert entries[path]['sha256'] == hashlib.sha256(raw).hexdigest()
    assert evidence._canonical_v3_raw(p.document) == p.artifacts['evidence.json']
    assert evidence._canonical_v3_assessed(p.assessed) == p.artifacts['assessed_evidence.json']
    projected = json.loads(p.artifacts['cff_projection.json'])
    cff_schema = json.loads((fixtures.ROOT / 'schemas/cff-projection-1.0.0.schema.json').read_bytes())
    jsonschema.Draft202012Validator(cff_schema).validate(projected)
    assert projected['evidence_document_sha256'] == hashlib.sha256(p.artifacts['assessed_evidence.json']).hexdigest()
    assert [h['host_id'] for h in projected['per_host']] == m['expected_host_ids']
    assert s._open_v3(m['run_id']) == p
    with pytest.raises(store.StoreError):
        s.open(m['run_id'])
    with pytest.raises(store.StoreError):
        s.recover(m['run_id'])
    return p


@pytest.mark.parametrize('fqcn', [False, True])
def test_c3b_actual_five(native, monkeypatch, tmp_path_factory, fqcn):
    make, trace, trap, cfg, root = native
    ctx, names = make(count=1, flags=fixtures.ALL)
    n = names[0]
    certs = fixtures._cert_s2_fixture_module().certs.__wrapped__(tmp_path_factory)
    drivers = fixtures._cert_s2_register(monkeypatch, ctx, trace, all_prior=True,
                                         fqcn=fqcn, certificates=certs)
    write, read = bridge.Handoff.write, bridge.Handoff.read
    receipts, projections = [], []
    def read_once(self, name, receipt):
        value = read(self, name, receipt)
        receipts.append((name, receipt))
        return value
    accept = batch._ProducerLedger.accept
    def retained(self, message):
        value = accept(self, message)
        projections.append(self.projections[message['target_id']])
        assert self.wire_total == len(self.wires[message['target_id']])
        assert self.metrics[message['target_id']]['ipc_bytes'] <= 3500
        return value
    monkeypatch.setattr(bridge.Handoff, 'read', read_once)
    monkeypatch.setattr(batch._ProducerLedger, 'accept', retained)
    def observed(self, target, value):
        (trace.parent / 'envelope').write_bytes(bridge.wire_bytes(value))
        return write(self, target, value)
    monkeypatch.setattr(bridge.Handoff, 'write', observed)
    # Exact original per-host binder remains legal; prohibit the legacy final
    # Controller aggregate call, including the one-host case by caller frame.
    from inspect import currentframe
    old = bridge.validate_bindings
    def bound(*args, **kwargs):
        assert currentframe().f_back.f_code is not batch._ProducerSession.finish.__code__
        return old(*args, **kwargs)
    monkeypatch.setattr(bridge, 'validate_bindings', bound)
    before = original_batch._signal_state()
    with store.RunStore(root) as s:
        result = workflow._execute_scan_workflow(ctx, s, RULES_RAW)
        p = published(root, s, result)
    launches = [fixtures._p2_rows(d, n) for d in drivers]
    assert [[x['ordinal'] for x in xs] for xs in launches] == [[0,1,2], list(range(7)), [0,1], [0,1], [0]]
    assert len({x['worker'] for xs in launches for x in xs}) == len({x['task'] for xs in launches for x in xs}) == 1
    for prior, next_stage in zip(drivers, launches[1:]):
        assert fixtures._p2_rows(prior, n, 'done')[-1]['ended'] <= next_stage[0]['began']
    hid = p.manifest['expected_host_ids'][0]
    raw = (trace.parent / 'envelope').read_bytes()
    assert p.artifacts[f'details/{hid}/{v3.HANDOFF}.json'] == raw and len(raw) <= bridge.MAX_WIRE
    assert len(receipts) == len(projections) == 1
    assert receipts[0][0] == n and receipts[0][1]['byte_count'] == len(raw)
    assert receipts[0][1]['sha256'] == hashlib.sha256(raw).hexdigest()
    projection = projections[0]
    assert p.manifest['flags'][hid] == {short: ctx._decisions[n]['requested_flags'][long]
                                        for long, short in store.NATIVE_COLLECTORS.items()}
    for producer, value in projection.companions.items():
        slot = v3.PRODUCER_SLOTS[producer]
        assert p.artifacts[f'details/{hid}/{slot}.json'] == v3._detail_bytes(slot, value)
    # The original Evidence canonicalizer sorts registry rows and the
    # evidence_ids/claim_ids set fields. Compare every other value exactly.
    for key, ident in [('collections', 'collection_id'), ('assets', 'asset_id'), ('evidence', 'evidence_id')]:
        rows = [{k: sorted(v) if k in ('evidence_ids', 'claim_ids') else v
                 for k, v in row.items()} for row in projection.document[key]]
        assert p.document[key] == sorted(rows, key=lambda row: row[ident])
    details = [e for e in p.manifest['artifacts'] if e['kind'] == 'detail']
    assert len(details) == 6
    for entry in details:
        assert entry['host_id'] == hid
        for k, field in [('collections', 'collection_ids'), ('assets', 'asset_ids'), ('evidence', 'evidence_ids')]:
            assert set(entry[field]) <= {row[field[:-1]] for row in p.document[k]}
    assert not trap.exists() and original_batch._signal_state() == before


def test_c3b_disabled(native):
    make, trace, trap, cfg, root = native
    ctx, names = make(count=2, flags=original_batch.selected_flags())
    with store.RunStore(root) as s:
        with pytest.raises(store.StoreError, match='BATCH_CONTRACT'):
            s.begin(run_id='public-v3-forbidden', run_kind='SYNTHETIC', evidence_schema_version='1.1.0',
                    source={}, recorded_at=bridge.stamp(), started_at=bridge.stamp(), expected_hosts=[],
                    batch_contract=v3.CONTRACT, producer_rules_raw=RULES_RAW)
        assert not list(root.iterdir())
        result = workflow._execute_scan_workflow(ctx, s, RULES_RAW)
        p = published(root, s, result)
    assert result.batch_rc == 6 and result.batch_manifest['reason_code'] == 'NO_EXECUTABLE_COLLECTORS'
    assert all(h['attempted'] is False and h['dispatch_intent'] is False for h in p.manifest['hosts'])
    assert not trap.exists()


def journal(root):
    run, = (p for p in root.iterdir() if p.is_dir())
    j = store._unseal((run / 'journal.json').read_bytes(), v3.MANIFEST_BYTES)
    return run, j


def check_stopped(launches, trap, before):
    assert not trap.exists() and original_batch._signal_state() == before
    for _, pid in launches:
        with pytest.raises(ProcessLookupError):
            os.kill(pid, 0)


def test_c3b_intent_fd_complete(native, monkeypatch):
    from ansible.executor.process.worker import WorkerProcess
    from multiprocessing.process import BaseProcess
    make, trace, trap, _, root = native
    ctx, names = make(count=1, flags=original_batch.selected_flags(bridge.PACKAGES))
    drivers = fixtures._o2_register(monkeypatch, ctx, trace)
    begin, start, run = store.RunStore._begin_v3, BaseProcess.start, WorkerProcess.run
    seen, held, locked_after = [], [], []
    marker = trace.parent / 'fd-proof'
    def reserve(self, **kw):
        w = begin(self, **kw)
        held.append((w, tuple((fd, workflow._identity(os.fstat(fd)))
                            for fd in (self._fd, w._fd, w._lock))))
        return w
    def observe_start(worker):
        try:
            w, fds = held[0]
            actual = v3._read_journal(w._fd, w._device, w.run_id)
            hid = bridge.host_record(w.run_id, str(worker._host.name))['host_id']
            assert actual['intents'] == [hid] and actual == w._j
            assert not list((root / w.run_id / 'checkpoints').iterdir())
            for fd, identity in fds:
                assert workflow._identity(os.fstat(fd)) == identity
            probe = os.open('.writer.lock', os.O_RDWR | os.O_NOFOLLOW, dir_fd=w._fd)
            try:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(probe)
            seen.append(hid)
            return start(worker)
        except BaseException as exc:
            (trace.parent / "start-test-error").write_text(repr(exc))
            raise
    def child(worker):
        assert os.getpid() != parent
        _, fds = held[0]
        for fd, _ in fds:
            with pytest.raises(OSError) as error:
                os.fstat(fd)
            assert error.value.errno == errno.EBADF
        marker.write_text(json.dumps({'pid': os.getpid(), 'closed': len(fds)}))
        return run(worker)
    parent = os.getpid()
    poll = batch._ProducerWorkerWave.poll
    def observe_after_close(self):
        if marker.exists() and not locked_after:
            w, fds = held[0]
            for fd, identity in fds:
                assert workflow._identity(os.fstat(fd)) == identity
            probe = os.open('.writer.lock', os.O_RDWR | os.O_NOFOLLOW, dir_fd=w._fd)
            try:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(probe)
            locked_after.append(True)
        return poll(self)
    monkeypatch.setattr(batch._ProducerWorkerWave, 'poll', observe_after_close)
    monkeypatch.setattr(store.RunStore, '_begin_v3', reserve)
    monkeypatch.setattr(BaseProcess, 'start', observe_start)
    monkeypatch.setattr(WorkerProcess, 'run', child)
    launches = original_batch._observe_native_queue(monkeypatch)
    before = original_batch._signal_state()
    with store.RunStore(root) as s:
        result = workflow._execute_scan_workflow(ctx, s, RULES_RAW)
        w, fds = held[0]
        assert w._fd is None
        with pytest.raises(OSError):
            os.fstat(fds[2][0])
        assert workflow._identity(os.fstat(s._fd)) == fds[0][1]
        assert WorkerProcess.run is child and BaseProcess.start is observe_start
        p = published(root, s, result)
    assert result.batch_rc == 0, result.batch_manifest
    assert seen == p.manifest['expected_host_ids'] and locked_after == [True]
    assert json.loads(marker.read_text()) == {'pid': launches[0][1], 'closed': 3}
    assert [x['ordinal'] for x in fixtures._p2_rows(drivers[1], names[0])] == [0, 1]
    check_stopped(launches, trap, before)


@pytest.mark.parametrize('kind', ['missing', 'generic', 'guard', 'alias', 'unsupported', 'reservation'])
def test_c3b_before_worker_rejection(native, monkeypatch, kind):
    make, trace, trap, cfg, root = native
    flag = bridge.NGINX if kind == 'unsupported' else bridge.CERT_FLAG
    ctx, names = make(count=1, flags=original_batch.selected_flags(flag),
                      profile='extended' if kind == 'unsupported' else 'baseline')
    if kind == 'generic':
        fixtures.register(monkeypatch, trace, p=0)
    elif kind != 'missing':
        fixtures._cert_s2_register(monkeypatch, ctx, trace)
    if kind == 'reservation':
        write = store._write
        def reject_reserve(parent, name, raw, device, **kw):
            if name == 'journal.json':
                raise store.StoreError('STORE_IO')
            return write(parent, name, raw, device, **kw)
        monkeypatch.setattr(store, '_write', reject_reserve)
    if kind == 'guard':
        cfg.write_text(cfg.read_text() + 'Include /tmp/dummy.conf\n')
    launches = original_batch._observe_native_queue(monkeypatch)
    before = original_batch._signal_state()
    with store.RunStore(root) as s:
        alias = os.dup(s._fd) if kind == 'alias' else None
        try:
            with pytest.raises(workflow._WorkflowError if kind in ('alias', 'reservation') else batch.Denied):
                workflow._execute_scan_workflow(ctx, s, RULES_RAW)
        finally:
            if alias is not None:
                os.close(alias)
    assert launches == []
    if kind == 'reservation':
        assert not list(root.glob('*/run_manifest.json'))
    elif kind != 'alias':
        assert not list(root.iterdir())
    else:
        run, j = journal(root)
        assert not j['intents'] and not (run / 'run_manifest.json').exists()
    check_stopped(launches, trap, before)


@pytest.mark.parametrize('number', [1, 2])
def test_c3b_intent_write_failure_recovery(native, monkeypatch, number):
    make, trace, trap, _, root = native
    ctx, names = make(count=2, forks=1, flags=original_batch.selected_flags(bridge.CERT_FLAG))
    fixtures._cert_s2_register(monkeypatch, ctx, trace)
    original = store._write
    attempts = []
    def write(parent, name, raw, device, **kw):
        if name == 'journal.json' and kw.get('replace_journal'):
            attempts.append(name)
            if len(attempts) == number:
                raise store.StoreError('STORE_IO')
        return original(parent, name, raw, device, **kw)
    monkeypatch.setattr(store, '_write', write)
    launches = original_batch._observe_native_queue(monkeypatch)
    before = original_batch._signal_state()
    with store.RunStore(root) as s:
        with pytest.raises(workflow._WorkflowError) as err:
            workflow._execute_scan_workflow(ctx, s, RULES_RAW)
        assert err.value.stage == 'DISPATCH_INTENT' and err.value.reason == 'INTENT_FAILED'
        run, j = journal(root)
        assert len(j['intents']) == number - 1 and len(launches) == number - 1
        assert not list((run / 'checkpoints').iterdir()) and not (run / 'run_manifest.json').exists()
        monkeypatch.setattr(store, '_write', original)
        p = s._recover_v3(run.name)
        assert p.manifest['recovery']
        assert sorted(h['attempt_status'] for h in p.manifest['hosts']) == sorted(
            ['UNKNOWN'] * (number - 1) + ['NOT_ATTEMPTED'] * (3 - number))
    check_stopped(launches, trap, before)


@pytest.mark.parametrize('mode', ['cancel', 'guard'])
def test_c3b_durable_intent_without_fork(native, monkeypatch, mode):
    make, trace, trap, cfg, root = native
    ctx, names = make(count=2, forks=1, flags=original_batch.selected_flags(bridge.CERT_FLAG))
    fixtures._cert_s2_register(monkeypatch, ctx, trace)
    intent = v3.Writer.dispatch_intent
    def stop(self, hid):
        intent(self, hid)
        assert hid in v3._read_journal(self._fd, self._device, self.run_id)['intents']
        if mode == 'cancel':
            os.kill(os.getpid(), signal.SIGINT)
        else:
            cfg.write_text(cfg.read_text() + '\n# changed\n')
    monkeypatch.setattr(v3.Writer, 'dispatch_intent', stop)
    launches = original_batch._observe_native_queue(monkeypatch)
    before = original_batch._signal_state()
    with store.RunStore(root) as s:
        result = workflow._execute_scan_workflow(ctx, s, RULES_RAW)
        p = published(root, s, result)
        assert result.batch_rc == (7 if mode == 'cancel' else 6)
        assert not result.late_interrupted
        assert sum(h['dispatch_intent'] for h in p.manifest['hosts']) == 1
        assert all(not h['attempted'] and h['attempt_status'] == 'NOT_ATTEMPTED' for h in p.manifest['hosts'])
    assert not launches
    check_stopped(launches, trap, before)


def test_c3b_actual_mixed_hosts(native, monkeypatch):
    make, trace, trap, _, root = native
    ctx, names = make(count=2, forks=1, flags=original_batch.selected_flags(bridge.CERT_FLAG))
    p2, d = fixtures._cert_s2_register(monkeypatch, ctx, trace, modes={(names[0], 0): 'rc17'})
    with store.RunStore(root) as s:
        result = workflow._execute_scan_workflow(ctx, s, RULES_RAW)
        p = published(root, s, result)
    assert result.batch_rc == 5
    rows = [next(c for c in h['collectors'] if c['collector_id'] == bridge.CERT_FLAG)
            for h in result.batch_manifest['hosts']]
    assert rows[0]['rc'] == 17 and rows[0]['reason_code'] == 'COMMAND_FAILED'
    assert not rows[0]['collection_ids'] and len(rows[1]['collection_ids']) == 3
    assert [fixtures._p2_rows(d, h)[0]['stage'] for h in names] == ['system', 'system']
    assert not trap.exists()


@pytest.mark.parametrize('mode', ['cancel', 'write-fault', 'deadline'])
def test_c3b_checkpoint_failure_recovery(native, monkeypatch, mode):
    make, trace, trap, _, root = native
    if mode == 'cancel':
        ctx, names = make(count=2, flags=original_batch.selected_flags(bridge.CERT_FLAG))
        fixtures._cert_s2_register(monkeypatch, ctx, trace)
    else:
        ctx, names = make(count=2, flags=original_batch.selected_flags())
    record = v3.Writer.record_host
    calls = []
    def observed(self, *args, **kw):
        record(self, *args, **kw)
        calls.append(kw['terminal']['target_id'])
        if len(calls) == 1:
            if mode == 'cancel':
                os.kill(os.getpid(), signal.SIGTERM)
            elif mode == 'deadline':
                time.sleep(1)
    if mode == 'write-fault':
        write = store._write
        def fail_second(parent, name, raw, device, **kw):
            if name.startswith('h-') and name.endswith('.json') and calls:
                raise store.StoreError('STORE_IO')
            return write(parent, name, raw, device, **kw)
        monkeypatch.setattr(store, '_write', fail_second)
    if mode == 'deadline':
        monkeypatch.setattr(workflow, '_PERSIST_SECONDS', .8)
    monkeypatch.setattr(v3.Writer, 'record_host', observed)
    before = original_batch._signal_state()
    with store.RunStore(root) as s:
        with pytest.raises(workflow._WorkflowError) as err:
            workflow._execute_scan_workflow(ctx, s, RULES_RAW)
        assert err.value.stage == 'CHECKPOINT' and not err.value.publication_unconfirmed
        assert err.value.reason == {'cancel': 'PERSISTENCE_CANCELLED', 'write-fault': 'CHECKPOINT_FAILED',
                                    'deadline': 'STORAGE_DEADLINE'}[mode]
        run, _ = journal(root)
        cp, = (run / 'checkpoints').glob('h-*.json')
        raw = cp.read_bytes()
        assert calls == names[:1] and not (run / 'run_manifest.json').exists()
        p = s._recover_v3(run.name)
        assert p.manifest['recovery'] and cp.read_bytes() == raw
        saved = next(h for h in p.manifest['hosts'] if h['host_id'] == cp.stem)
        assert saved['terminal'] == store._unseal(raw, v3.CHECKPOINT_BYTES)['terminal']
        if mode == 'cancel':
            assert saved['attempted'] is True and len(p.document['collections']) > 0
            assert sorted(h['attempt_status'] for h in p.manifest['hosts']) == ['ATTEMPTED', 'UNKNOWN']
    assert original_batch._signal_state() == before and not trap.exists()


@pytest.mark.parametrize('mode', ['late-cancel', 'after-marker', 'prepared', 'capacity'])
def test_c3b_publication_disposition(native, monkeypatch, mode):
    make, trace, trap, _, root = native
    ctx, names = make(count=1, flags=original_batch.selected_flags())
    finish, resume = v3.Writer.finalize, v3.Writer._resume
    def finalize(self, **kw):
        if mode == 'late-cancel':
            os.kill(os.getpid(), signal.SIGINT)
        if mode == 'capacity':
            with monkeypatch.context() as mp:
                mp.setattr(v3, 'RAW_BYTES', 1)
                return finish(self, **kw)
        p = finish(self, **kw)
        if mode == 'after-marker':
            raise store.StoreError('STORE_IO')
        return p
    def fail_resume(self, *a, **kw):
        raise store.StoreError('STORE_IO')
    monkeypatch.setattr(v3.Writer, 'finalize', finalize)
    if mode == 'prepared':
        monkeypatch.setattr(v3.Writer, '_resume', fail_resume)
    before = original_batch._signal_state()
    with store.RunStore(root) as s:
        if mode == 'late-cancel':
            result = workflow._execute_scan_workflow(ctx, s, RULES_RAW)
            assert result.late_interrupted and result.batch_rc == 6
            published(root, s, result)
        else:
            with pytest.raises(workflow._WorkflowError) as err:
                workflow._execute_scan_workflow(ctx, s, RULES_RAW)
            assert err.value.stage == 'FINALIZE' and err.value.publication_unconfirmed
            assert err.value.batch_rc == 6
            run, j = journal(root)
            if mode == 'after-marker':
                assert (run / 'run_manifest.json').exists()
                assert not s._open_v3(run.name).manifest['recovery']
            elif mode == 'prepared':
                prepared = (run / 'prepared.json').read_bytes()
                assert not (run / 'run_manifest.json').exists()
                monkeypatch.setattr(v3.Writer, '_resume', resume)
                p = s._recover_v3(run.name)
                assert not p.manifest['recovery'] and (run / 'prepared.json').read_bytes() == prepared
            else:
                assert err.value.capacity_stage == 'RAW_EVIDENCE'
                assert j['blocked_capacity_stage'] == 'RAW_EVIDENCE'
                assert not (run / 'run_manifest.json').exists()
    assert original_batch._signal_state() == before and not trap.exists()


def test_c3b_intent_deadline(native, monkeypatch):
    make, trace, trap, _, root = native
    ctx, names = make(count=2, forks=1, flags=original_batch.selected_flags(bridge.CERT_FLAG))
    fixtures._cert_s2_register(monkeypatch, ctx, trace)
    intent = v3.Writer.dispatch_intent
    horizons = []
    def expire(self, hid):
        intent(self, hid)
        horizons.append(signal.getitimer(signal.ITIMER_REAL)[0])
        assert horizons[-1] > 0
        time.sleep(horizons[-1] + .2)
    monkeypatch.setattr(batch, '_GUARD_SECONDS', 3)
    monkeypatch.setattr(v3.Writer, 'dispatch_intent', expire)
    launches = original_batch._observe_native_queue(monkeypatch)
    before = original_batch._signal_state()
    with store.RunStore(root) as s:
        with pytest.raises(workflow._WorkflowError) as err:
            workflow._execute_scan_workflow(ctx, s, RULES_RAW)
        assert err.value.stage == 'DISPATCH_INTENT' and err.value.reason == 'STORAGE_DEADLINE'
        run, j = journal(root)
        assert len(j['intents']) == 1 and not list((run / 'checkpoints').iterdir())
        assert not (run / 'run_manifest.json').exists()
        p = s._recover_v3(run.name)
        assert sorted(h['attempt_status'] for h in p.manifest['hosts']) == ['NOT_ATTEMPTED', 'UNKNOWN']
    assert not launches and len(horizons) == 1 and horizons[0] <= 3
    check_stopped(launches, trap, before)


@pytest.mark.parametrize('mode', ['fd-fault', 'postfork', 'uncertain-start'])
def test_c3b_start_failure(native, monkeypatch, mode):
    from ansible.executor.process.worker import WorkerProcess
    from multiprocessing.process import BaseProcess
    make, trace, trap, _, root = native
    ctx, names = make(count=2, forks=1, flags=original_batch.selected_flags(bridge.CERT_FLAG))
    drivers = fixtures._cert_s2_register(monkeypatch, ctx, trace)
    close_inherited, start, run = workflow._close_inherited, BaseProcess.start, WorkerProcess.run
    marker = trace.parent / 'fd-close-fault'
    parent = os.getpid()
    def faulty_close(fds):
        assert os.getpid() != parent
        close = os.close
        # A real child has the original inherited identity. Simulate a failed
        # close only on one expected FD, then run the real verification.
        assert workflow._identity(os.fstat(fds[0][0])) == fds[0][1]
        marker.write_text(str(os.getpid()))
        def no_close(fd):
            if fd != fds[0][0]:
                close(fd)
        os.close = no_close
        try:
            close_inherited(fds)
        finally:
            os.close = close
    def broken_start(worker):
        if mode == 'postfork':
            start(worker)
        raise OSError('synthetic start receipt failure')
    if mode == 'fd-fault':
        monkeypatch.setattr(workflow, '_close_inherited', faulty_close)
    else:
        monkeypatch.setattr(BaseProcess, 'start', broken_start)
    launches = original_batch._observe_native_queue(monkeypatch)
    before = original_batch._signal_state()
    with store.RunStore(root) as s:
        root_identity = workflow._identity(os.fstat(s._fd))
        if mode == 'uncertain-start':
            with pytest.raises(workflow._WorkflowError) as err:
                workflow._execute_scan_workflow(ctx, s, RULES_RAW)
            assert err.value.reason == 'START_UNCONFIRMED' and err.value.batch_rc is None
            path, j = journal(root)
            assert len(j['intents']) == 1 and not list((path / 'checkpoints').iterdir())
            assert not (path / 'run_manifest.json').exists()
            p = s._recover_v3(path.name)
            assert sorted(h['attempt_status'] for h in p.manifest['hosts']) == ['NOT_ATTEMPTED', 'UNKNOWN']
            assert not launches
        else:
            result = workflow._execute_scan_workflow(ctx, s, RULES_RAW)
            p = published(root, s, result)
            assert result.batch_rc == 6
            assert [h['host_state'] for h in result.batch_manifest['hosts']] == ['ERROR', 'NOT_ATTEMPTED']
            assert len(launches) == 1
            if mode == 'fd-fault':
                assert int(marker.read_text()) == launches[0][1]
                assert not any(fixtures._p2_rows(d, n) for d in drivers for n in names)
        assert workflow._identity(os.fstat(s._fd)) == root_identity
        assert WorkerProcess.run is run and BaseProcess.start is (start if mode == 'fd-fault' else broken_start)
    check_stopped(launches, trap, before)


def test_c3b_worker_interrupt(native, monkeypatch):
    make, trace, trap, _, root = native
    ctx, names = make(count=2, forks=1, flags=original_batch.selected_flags(bridge.CERT_FLAG))
    n = names[0]
    p2, d = fixtures._cert_s2_register(monkeypatch, ctx, trace, modes={(n, 0): 'outer-timeout'})
    d.stage_seconds = 3
    sent = []
    before = original_batch._signal_state()
    launches = original_batch._observe_native_queue(monkeypatch)
    poll = batch._ProducerWorkerWave.poll
    def interrupt(self):
        if not sent and (d.tmp / f'{n}-0-group.json').exists():
            sent.append(time.monotonic())
            os.kill(os.getpid(), signal.SIGINT)
        return poll(self)
    monkeypatch.setattr(batch._ProducerWorkerWave, 'poll', interrupt)
    with store.RunStore(root) as s:
        with fixtures._p2_owned_supervisors(d) as reaped:
            result = workflow._execute_scan_workflow(ctx, s, RULES_RAW)
        p = published(root, s, result)
    assert result.batch_rc == 7 and result.batch_manifest['reason_code'] == 'INTERRUPTED'
    assert sent and [h for h, _ in launches] == names[:1]
    assert result.batch_manifest['hosts'][1]['host_state'] == 'NOT_ATTEMPTED'
    assert fixtures._p2_rows(d, n)[0]['supervisor'] in reaped and not p.document['collections']
    check_stopped(launches, trap, before)


def test_c3b_dual_earliest_lease(native, monkeypatch):
    make, trace, trap, _, root = native
    ctx, names = make(count=3, forks=2, flags=original_batch.selected_flags(bridge.CERT_FLAG))
    a, b, _ = names
    ready, verified = trace.parent / 'a-ready', trace.parent / 'b-verified'
    marks, delays = {}, []
    def synchronize(when, binding, completion):
        if when == 'prepare' and binding.target_id == a:
            ready.write_text('ready')
            fixtures._p2_wait(verified)
            worker = batch._PLATFORM_WORKER.get()
            (trace.parent / 'child-lease.json').write_text(json.dumps(
                dict(end=worker.lease.limit(a), now=time.monotonic())))
        return completion
    p2, d = fixtures._cert_s2_register(monkeypatch, ctx, trace,
        platform_kwargs={'versions': {b: {'distribution': 'Debian', 'os_family': 'Debian'}}},
        fault=synchronize)
    d.stage_seconds = 6
    intent = v3.Writer.dispatch_intent
    def delayed(self, hid):
        before = signal.getitimer(signal.ITIMER_REAL)[0]
        intent(self, hid)
        if self._j['intents'] and len(self._j['intents']) == 2:
            time.sleep(.15)
            delays.append((before, signal.getitimer(signal.ITIMER_REAL)[0]))
    monkeypatch.setattr(v3.Writer, 'dispatch_intent', delayed)
    make_queue = batch._make_queue
    def queue(validator=None):
        q = make_queue(validator)
        send = q.send_task_result
        def hold(result):
            if result.as_wire_task_result().host_name == b:
                fixtures._p2_wait(ready)
                send(result)
                time.sleep(15)
            else:
                send(result)
        q.send_task_result = hold
        return q
    monkeypatch.setattr(batch, '_make_queue', queue)
    accepted = batch._ProducerWorkerWave._receipt_accepted
    def observe(self):
        result = accepted(self)
        if b in self.ledger.projections and not verified.exists():
            assert b not in self.confirmed and self.workers[b].is_alive()
            end = self.limit()
            assert end == min(self.ends[b], self.grace[b]) < self.ends[a]
            assert self.lease.limit(a) == end
            marks.update(earliest=end, verified=time.monotonic())
            verified.write_text('verified')
        return result
    monkeypatch.setattr(batch._ProducerWorkerWave, '_receipt_accepted', observe)
    launches = original_batch._observe_native_queue(monkeypatch)
    before = original_batch._signal_state()
    record = v3.Writer.record_host
    def after_cleanup(self, *args, **kw):
        assert not trap.exists()
        for _, pid in launches:
            with pytest.raises(ProcessLookupError):
                os.kill(pid, 0)
        return record(self, *args, **kw)
    monkeypatch.setattr(v3.Writer, 'record_host', after_cleanup)
    with store.RunStore(root) as s:
        with fixtures._p2_owned_supervisors(d):
            result = workflow._execute_scan_workflow(ctx, s, RULES_RAW)
        p = published(root, s, result)
    assert marks['verified'] < marks['earliest'] and [n for n, _ in launches] == names[:2]
    assert delays[0][0] - delays[0][1] >= .15
    assert [h['host_state'] for h in result.batch_manifest['hosts']] == ['ERROR', 'ERROR', 'NOT_ATTEMPTED']
    assert result.batch_rc == 6 and result.batch_manifest['reason_code'] == 'CONTROLLER_TIMEOUT'
    child = json.loads((trace.parent / 'child-lease.json').read_bytes())
    assert child['end'] == marks['earliest'] and 0 < child['end'] - child['now'] <= batch._WORKER_GRACE
    assert not any(fixtures._p2_rows(d, n) for n in names)
    assert not fixtures._p2_rows(p2, names[2])
    for name in (a, b):
        hid = next(h['host_id'] for h in p.manifest['hosts'] if h['target_id'] == name)
        assert f'details/{hid}/{v3.HANDOFF}.json' in p.artifacts
    check_stopped(launches, trap, before)


@pytest.mark.parametrize('mode', ['cleanup', 'acquisition-cancel', 'frozen-cancel'])
def test_c3b_final_terminal_boundary(native, monkeypatch, mode):
    make, trace, trap, _, root = native
    ctx, names = make(count=1, flags=original_batch.selected_flags(bridge.CERT_FLAG))
    fixtures._cert_s2_register(monkeypatch, ctx, trace)
    close = bridge.Handoff.close
    freeze = workflow._Control.freeze
    order = []
    def observed_close(self):
        confirmed = close(self)
        assert confirmed
        order.append('cleanup')
        if mode == 'acquisition-cancel':
            os.kill(os.getpid(), signal.SIGTERM)
        return mode != 'cleanup'
    def frozen(self, rc):
        assert order == ['cleanup']
        freeze(self, rc)
        if mode == 'frozen-cancel':
            os.kill(os.getpid(), signal.SIGINT)
    monkeypatch.setattr(bridge.Handoff, 'close', observed_close)
    monkeypatch.setattr(workflow._Control, 'freeze', frozen)
    launches = original_batch._observe_native_queue(monkeypatch)
    before = original_batch._signal_state()
    with store.RunStore(root) as s:
        if mode == 'frozen-cancel':
            with pytest.raises(workflow._WorkflowError) as err:
                workflow._execute_scan_workflow(ctx, s, RULES_RAW)
            assert err.value.reason == 'PERSISTENCE_CANCELLED' and err.value.batch_rc in (0, 5)
            run, j = journal(root)
            assert len(j['intents']) == 1 and not list((run / 'checkpoints').iterdir())
            assert not (run / 'run_manifest.json').exists()
        else:
            result = workflow._execute_scan_workflow(ctx, s, RULES_RAW)
            p = published(root, s, result)
            assert result.batch_rc == (6 if mode == 'cleanup' else 7)
            assert result.batch_manifest['reason_code'] == ('CONTROLLER_CLEANUP_UNCONFIRMED' if mode == 'cleanup' else 'INTERRUPTED')
            assert not result.late_interrupted and p.document['collections']
            hid = p.manifest['expected_host_ids'][0]
            assert f'details/{hid}/{v3.HANDOFF}.json' in p.artifacts
    assert len(launches) == 1
    check_stopped(launches, trap, before)


# S-C3B-PENDING-SIGNAL-FREEZE: exercise the actual Controller handler,
# producer ledger/validators and V3 writer with real blocked POSIX signals.
@pytest.mark.parametrize('mode,signum', [
    ('none', signal.SIGTERM), ('before-mask', signal.SIGTERM),
    ('during-validation', signal.SIGTERM), ('during-validation', signal.SIGINT),
    ('after-validation', signal.SIGTERM), ('after-validation', signal.SIGINT),
    ('during-revalidation', signal.SIGTERM), ('prior-and-pending', signal.SIGTERM),
    ('late-only', signal.SIGTERM), ('prior-and-late', signal.SIGTERM),
    ('pending-and-late', signal.SIGTERM), ('after-sample', signal.SIGTERM),
    ('after-consume', signal.SIGTERM),
])
def test_c3b_pending_signal_freeze(native, monkeypatch, mode, signum):
    make, trace, trap, _, root = native
    ctx, names = make(count=1, flags=original_batch.selected_flags())
    control, validated, sent, checkpoints = [], [], [], []
    frozen, inside = [], False
    cancellation = {signal.SIGINT, signal.SIGTERM}
    before = original_batch._signal_state()
    reserve = workflow._Control.reserve
    close = batch._ProducerSession.close
    validator = batch.validate_producer_manifest
    outcome = batch._valid_v2_outcome
    freeze = workflow._Control.freeze
    record = v3.Writer.record_host
    pending = signal.sigpending
    wait = signal.sigtimedwait

    def send(label, sig, *, masked=True):
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, ())
        assert (cancellation <= mask) is masked
        assert sig not in pending()
        assert control[0].frozen is (label == 'after-freeze')
        sent.append((label, sig, control[0].frozen))
        os.kill(os.getpid(), sig)
        assert (sig in pending()) is masked

    def reserved(self, ledger):
        reserve(self, ledger)
        control.append(self)

    def closed(self):
        result = close(self)
        if not sent and mode in ('before-mask', 'prior-and-pending', 'prior-and-late'):
            assert result and not control[0].frozen
            send('before-mask', signum, masked=False)
        return result

    def observed_outcome(*args, **kwargs):
        if inside and not sent and mode == 'during-validation':
            send('during-validation', signum)
        if (inside and mode == 'during-revalidation' and validated == [6]
                and len(sent) == 1):
            send('during-revalidation', signal.SIGINT)
        return outcome(*args, **kwargs)

    def observed_validator(manifest, rc):
        nonlocal inside
        if control[0].frozen:
            return validator(manifest, rc)
        inside = True
        try:
            result = validator(manifest, rc)
        finally:
            inside = False
        validated.append(rc)
        if ((mode in ('after-validation', 'during-revalidation', 'pending-and-late',
                      'after-sample', 'after-consume') and not sent)
                or (mode == 'prior-and-pending' and len(sent) == 1)):
            send('after-validation', signum)
        return result

    def observed_pending():
        snapshot = pending()
        # A distinct new signal arriving after the final snapshot is not
        # part of the sampled acquisition set, even before frozen=True.
        if (mode == 'after-sample' and validated == [6, 7]
                and not control[0].frozen and len(sent) == 1):
            assert snapshot == {signum}
            send('after-sample', signal.SIGINT)
        return snapshot

    def observed_wait(sigset, timeout):
        info = wait(sigset, timeout)
        # A new instance of the same ordinary signal *after* the sampled
        # instance was consumed is independently observable, not coalesced.
        if mode == 'after-consume' and len(sent) == 1:
            assert info is not None and info.si_signo == signum
            send('after-consume', signum)
        return info

    def observed_freeze(self, rc):
        assert self is control[0] and not self.frozen and validated[-1] == rc
        freeze(self, rc)
        frozen.append(rc)
        if mode in ('late-only', 'prior-and-late', 'pending-and-late'):
            send('after-freeze', signal.SIGINT if mode == 'pending-and-late' else signum)

    def observed_record(self, fragment, **kwargs):
        assert control[0].frozen and not cancellation & pending()
        result = record(self, fragment, **kwargs)
        checkpoints.append(kwargs['terminal'])
        return result

    monkeypatch.setattr(workflow._Control, 'reserve', reserved)
    monkeypatch.setattr(batch._ProducerSession, 'close', closed)
    monkeypatch.setattr(batch, '_valid_v2_outcome', observed_outcome)
    monkeypatch.setattr(batch, 'validate_producer_manifest', observed_validator)
    monkeypatch.setattr(workflow._Control, 'freeze', observed_freeze)
    monkeypatch.setattr(v3.Writer, 'record_host', observed_record)
    monkeypatch.setattr(signal, 'sigpending', observed_pending)
    monkeypatch.setattr(signal, 'sigtimedwait', observed_wait)
    launches = original_batch._observe_native_queue(monkeypatch)
    late = mode in ('late-only', 'prior-and-late', 'pending-and-late', 'after-sample', 'after-consume')
    rc = 6 if mode in ('none', 'late-only') else 7
    expected_validated = [6, 7] if mode in ('during-validation', 'after-validation',
        'during-revalidation', 'pending-and-late', 'after-sample', 'after-consume') else [rc]
    with store.RunStore(root) as s:
        if late:
            with pytest.raises(workflow._WorkflowError) as err:
                workflow._execute_scan_workflow(ctx, s, RULES_RAW)
            assert (err.value.stage, err.value.reason, err.value.batch_rc) == (
                'CHECKPOINT', 'PERSISTENCE_CANCELLED', rc)
            assert not err.value.publication_unconfirmed and control[0].late_interrupted
            run, j = journal(root)
            assert not checkpoints and not list((run / 'checkpoints').iterdir())
            assert not (run / 'run_manifest.json').exists() and not j['intents']
            p = s._recover_v3(run.name)
            assert p.manifest['recovery'] and p.manifest['hosts'][0]['attempt_status'] == 'NOT_ATTEMPTED'
        else:
            try:
                result = workflow._execute_scan_workflow(ctx, s, RULES_RAW)
            except workflow._WorkflowError as exc:
                pytest.fail(f'expected acquisition rc{rc} publication, got {exc.stage}/{exc.reason}, '
                            f'rc={exc.batch_rc}, validated={validated}, frozen={frozen}, sent={sent}')
            assert result.batch_rc == rc and not result.late_interrupted
            assert result.batch_manifest['reason_code'] == ('INTERRUPTED' if rc == 7 else 'NO_EXECUTABLE_COLLECTORS')
            p = published(root, s, result)
            run, j = journal(root)
            assert (run / 'run_manifest.json').is_file() and not j['intents']
            cp, = (run / 'checkpoints').glob('h-*.json')
            body = store._unseal(cp.read_bytes(), v3.CHECKPOINT_BYTES)
            assert checkpoints == result.batch_manifest['hosts'] == [body['terminal']]
            assert body['attempted'] is False and p.manifest['hosts'][0]['attempted'] is False
    assert validated == expected_validated and frozen == [rc]
    assert len(sent) == (0 if mode == 'none' else 2 if mode in ('during-revalidation',
        'prior-and-pending', 'prior-and-late', 'pending-and-late', 'after-sample', 'after-consume') else 1)
    assert not launches and not cancellation & pending()
    check_stopped(launches, trap, before)


def test_c3b_pending_with_native_observations(native, monkeypatch):
    make, trace, trap, _, root = native
    ctx, names = make(count=1, flags=original_batch.selected_flags(bridge.CERT_FLAG))
    fixtures._cert_s2_register(monkeypatch, ctx, trace)
    reserve, validator = workflow._Control.reserve, batch.validate_producer_manifest
    owned, decisions = [], []
    launches = original_batch._observe_native_queue(monkeypatch)
    before = original_batch._signal_state()

    def reserved(self, ledger):
        reserve(self, ledger)
        owned.append((self, ledger))

    def observe(manifest, rc):
        result = validator(manifest, rc)
        control, ledger = owned[0]
        if not control.frozen:
            assert control.session.handoff is None and len(launches) == 1
            with pytest.raises(ProcessLookupError):
                os.kill(launches[0][1], 0)
            assert ledger.wires[names[0]] and ledger.projections[names[0]].document['collections']
            decisions.append((rc, json.loads(json.dumps(manifest['hosts']))))
            if len(decisions) == 1:
                assert signal.SIGTERM in signal.pthread_sigmask(signal.SIG_BLOCK, ())
                os.kill(os.getpid(), signal.SIGTERM)
                assert signal.SIGTERM in signal.sigpending() and not control.frozen
        return result

    monkeypatch.setattr(workflow._Control, 'reserve', reserved)
    monkeypatch.setattr(batch, 'validate_producer_manifest', observe)
    with store.RunStore(root) as s:
        result = workflow._execute_scan_workflow(ctx, s, RULES_RAW)
        p = published(root, s, result)
    assert len(decisions) == 2 and decisions[0][0] in (0, 5) and decisions[1][0] == 7
    assert decisions[0][1] == decisions[1][1] == result.batch_manifest['hosts']
    assert result.batch_rc == 7 and result.batch_manifest['reason_code'] == 'INTERRUPTED'
    assert not result.late_interrupted and p.document['collections']
    hid = p.manifest['expected_host_ids'][0]
    assert p.artifacts[f'details/{hid}/{v3.HANDOFF}.json'] == owned[0][1].wires[names[0]]
    check_stopped(launches, trap, before)
