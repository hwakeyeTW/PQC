"""R01-R03: actual private local filesystem, both Evidence models, and crashes.

All data and subprocesses are synthetic. No Inventory, Ansible or network.
"""
from collections import Counter
from copy import deepcopy
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import select
import stat
import subprocess
import sys
import tempfile

import pytest
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools import assessment as a, evidence as e, run_store as m

STAMP = '2026-01-03T00:00:00Z'
END = '2026-01-03T00:01:00Z'
RID = 'fixture-run'
TARGETS = ('host-a.example.invalid', 'host-b.example.invalid', 'host-c.example.invalid')
LIMITS = {'max_hosts': 10, 'forks': 2, 'serial': 2, 'ssh_timeout_s': 15, 'command_timeout_s': 30}
RULES_RAW = (ROOT / 'config/assessment_rules.yml').read_bytes()
RULES = a.load_rules(RULES_RAW)


def raw(x):
    return json.dumps(x, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(x): return hashlib.sha256(x).hexdigest()


def error(code, action, *args, **kwargs):
    with pytest.raises(m.StoreError) as ex:
        action(*args, **kwargs)
    assert ex.value.code == code
    assert str(ex.value) == code


@pytest.fixture
def root():
    # /tmp's root-owned sticky parent is permitted; all other components
    # are private. Do not use the shared container/project mount as the store.
    with tempfile.TemporaryDirectory(prefix='pqc-store-', dir='/tmp') as p:
        path = Path(p) / 'reports'
        path.mkdir(mode=0o700)
        yield path


@pytest.fixture(scope='module')
def schema():
    s = json.loads((ROOT / 'schemas/run-manifest-1.0.0.schema.json').read_bytes())
    assert s == m.manifest_schema()
    Draft202012Validator.check_schema(s)
    assert all(ref.startswith('#/$defs/') for ref in re.findall(r'"\$ref":\s*"([^"]+)"', json.dumps(s)))
    return Draft202012Validator(s, format_checker=FormatChecker())


def kwargs(rid=RID, targets=TARGETS[:1], version='1.1.0', kind='SYNTHETIC', *, stable=False,
           requested=('packages',), requirements=None):
    source = {'source_kind': m.KINDS[kind], 'producer_id': 'fixture-runner',
              'producer_version': '1.0.0', 'origin_ref': 'fixture-source', 'input_sha256': None}
    value = {'run_id': rid, 'run_kind': kind, 'evidence_schema_version': version, 'source': source,
             'recorded_at': STAMP, 'started_at': STAMP,
             'expected_hosts': [{'target_id': h, 'inventory_authority_id': 'fixture-authority' if stable else None,
                                 'identity_key': None if stable else h} for h in targets],
             'limits': deepcopy(LIMITS), 'profile': 'baseline',
             'requested_flags': {h: {k: k in requested for k in m.COLLECTORS} for h in targets}}
    if requirements is not None: value['requirements'] = requirements
    if kind == 'LEGACY_IMPORT':
        original = raw({'fixture': 'legacy-original', 'selected': list(targets)})
        source.update(producer_id='legacy-ol-run-summary', producer_version=None, input_sha256=digest(original))
        value.update(started_at=None, limits=None, profile=None, requested_flags=None,
                     legacy_raw=original, legacy_provenance={'format_version': '1.0.0', 'source': deepcopy(source),
                      'original_run_id': 'old-run', 'original_generated_at': STAMP,
                      'diagnostics': [{'reason_code': 'LEGACY_REPORT_MISSING', 'count': 1}]})
    return value


def make_host(scope, target, state='COMPLETE', reason=None):
    """Construct a one-host envelope using the actual Evidence ID helpers."""
    h = deepcopy(next(h for h in scope['hosts'] if h['target_id'] == target))
    hid = h['host_id']; rid = scope['run_id']; legacy = scope['run_kind'] == 'LEGACY_IMPORT'
    reasons = {'COMPLETE': 'HOST_COMPLETE', 'PARTIAL': 'INCOMPLETE_COLLECTION',
               'ERROR': 'COMMAND_TIMEOUT', 'UNREACHABLE': 'CONNECTION_FAILED',
               'NOT_ATTEMPTED': 'NOT_ATTEMPTED'}
    h.update(host_state=state, reason_code=reason or reasons[state])
    doc = {'schema_version': scope['evidence_schema_version'], 'run': {'run_id': rid,
           'run_state': state if state in ('COMPLETE', 'PARTIAL') else 'ERROR',
           'recorded_at': scope['recorded_at'], 'started_at': scope['started_at'],
           'finished_at': None if legacy else END, 'source': deepcopy(scope['source']),
           'expected_host_ids': [hid]}, 'hosts': [h], 'collections': [], 'assets': [],
           'evidence': [], 'claims': [], 'findings': []}
    if state != 'NOT_ATTEMPTED':
        src = deepcopy(scope['source'])
        if not legacy: src['producer_id'] = 'packages'
        cid = e.collection_id(rid, hid, 'packages', 'packages')
        cstate = {'COMPLETE': 'COLLECTED', 'PARTIAL': 'PARTIAL', 'ERROR': 'ERROR', 'UNREACHABLE': 'UNREACHABLE'}[state]
        collection = {'collection_id': cid, 'host_id': hid, 'collector_id': 'packages',
            'collector_version': src['producer_version'], 'scope_key': 'packages', 'collection_state': cstate,
            'reason_code': 'COLLECTED' if cstate == 'COLLECTED' else h['reason_code'], 'source': src,
            'observed_at': None if legacy else STAMP, 'evidence_ids': []}
        doc['collections'] = [collection]
        if state in ('COMPLETE', 'PARTIAL'):
            aid = e.asset_id(hid, 'package', 'fixture-package', run_id=rid)
            eid = e.evidence_id(rid, hid, cid, 'fixture-package')
            asset = {'asset_id': aid, 'host_id': hid, 'asset_kind': 'package', 'identity_scope': 'RUN_SCOPED',
                     'identity_key': 'fixture-package', 'evidence_ids': [eid]}
            row = {'evidence_id': eid, 'host_id': hid, 'collection_id': cid, 'asset_id': aid,
                   'observation_key': 'fixture-package', 'evidence_kind': 'PACKAGE_INVENTORY',
                   'source': deepcopy(src), 'observed_at': None if legacy else STAMP,
                   'data': {'name': 'openssl', 'version': '3.5.0', 'present': True}, 'algorithm': None}
            collection['evidence_ids'] = [eid]; doc['assets'] = [asset]; doc['evidence'] = [row]
    return json.loads(e.canonical_bytes(doc))


def terminal(scope, doc):
    h = doc['hosts'][0]; hid = h['host_id']; states = {c['collector_id']: c for c in doc['collections']}
    attempted = h['host_state'] != 'NOT_ATTEMPTED'
    rows = []
    for key, requested in scope['flags'][hid].items():
        c = states.get(key)
        state = c['collection_state'] if c else ('UNKNOWN' if requested and attempted else 'NOT_SCANNED')
        reason = c['reason_code'] if c else ('NO_EVIDENCE' if state == 'UNKNOWN' else 'NOT_ATTEMPTED' if requested else 'DISABLED_BY_PROFILE')
        rc = 0 if state in ('COLLECTED', 'PARTIAL', 'NOT_APPLICABLE') else (124 if state == 'ERROR' else None)
        rows.append({'collector_id': key, 'requested': requested, 'state': state, 'reason_code': reason,
                     'rc': rc, 'collection_ids': [c['collection_id']] if c else []})
    return {'target_id': h['target_id'], 'host_state': h['host_state'], 'attempted': attempted,
            'reason_code': h['reason_code'], 'collectors': rows}


def detail(scope, doc, slot='platform'):
    row = doc['evidence'][0]; c = doc['collections'][0]
    return {'format_version': '1.0.0', 'format': 'S1_TYPED_FIXTURE', 'run_id': scope['run_id'],
            'host_id': row['host_id'], 'slot': slot, 'collection_ids': [row['collection_id']],
            'asset_ids': [row['asset_id']], 'evidence_ids': [row['evidence_id']],
            'records': [{'record_kind': 'ASSET', 'evidence_id': row['evidence_id'], 'state': c['collection_state'],
                         'reason_code': c['reason_code'], 'rc': 0}]}


def combined(scope, docs, *, interrupted=False):
    states = [d['hosts'][0]['host_state'] for d in docs]
    state = ('COMPLETE' if all(s == 'COMPLETE' for s in states) and not interrupted else
             'PARTIAL' if any(s in ('COMPLETE', 'PARTIAL') for s in states) else 'ERROR')
    run = {**docs[0]['run'], 'run_state': state, 'expected_host_ids': sorted(d['hosts'][0]['host_id'] for d in docs),
           'coverage_reason': 'INTERRUPTED' if interrupted else 'RUN_COMPLETE' if state == 'COMPLETE' else 'RUN_INCOMPLETE'}
    out = {'schema_version': scope['evidence_schema_version'], 'run': run,
           **{k: [row for d in docs for row in d[k]] for k in e.REGISTRIES}}
    return json.loads(e.canonical_bytes(out))


def batch(scope, document, terminals, rc):
    return {'batch_manifest_version': 1, 'target_ids': sorted(x['target_id'] for x in document['hosts']),
            'target_count': len(document['hosts']), 'limits': scope['limits'], 'profile': scope['profile'],
            'run_state': document['run']['run_state'], 'reason_code': 'INTERRUPTED' if rc == 7 else document['run']['coverage_reason'],
            'hosts': sorted(terminals, key=lambda x: x['target_id'])}


def cff_pair(assessed):
    sha = digest(e.canonical_bytes(assessed)); hosts = []
    for hid in assessed['run']['expected_host_ids']:
        findings = [f for f in assessed['findings'] if f['subject']['host_id'] == hid]
        selected = [{'rule_id': f['finding_id'], 'status': {'PASS': 'pass', 'FAIL': 'fail',
                    'NOT_APPLICABLE': 'not_applicable'}.get(f['assessment_state'], 'not_checked')} for f in findings]
        counts = Counter(f['status'] for f in selected); denom = counts['pass'] + counts['fail']
        hosts.append({'host_id': hid, 'cff': {'version': '1.0.0', 'findings': selected,
                      'summary': {**{k: counts[k] for k in ('pass', 'fail', 'error', 'not_applicable', 'not_checked')},
                                  'total': len(findings), 'denominator': denom, 'score_available': denom > 0}},
                      'companion': {'evidence_document_sha256': sha, 'score_semantics': 'FACT_STATUS_RATIO_NOT_READINESS',
                       'findings': [{k: f[k] for k in ('finding_id', 'assessment_state', 'reason_code', 'claim_ids', 'evidence_ids')}
                                    for f in findings]}})
    return {'format': 'S1_CFF_PAIR', 'projection_version': '1.0.0', 'evidence_document_sha256': sha, 'per_host': hosts}


def record(writer, states, *, use_details=False):
    scope = writer.scope; docs = []; rows = []
    for target, state in states:
        d = make_host(scope, target, state); docs.append(d)
        if scope['run_kind'] == 'LEGACY_IMPORT':
            writer.record_host(d)
        else:
            row = terminal(scope, d); rows.append(row)
            if row['attempted']: writer.dispatch_intent(d['hosts'][0]['host_id'])
            writer.record_host(d, attempted=row['attempted'], terminal=row,
                               details=[detail(scope, d)] if use_details and d['evidence'] else None)
    return scope, docs, rows


def complete(store, **options):
    args = kwargs(**options)
    with store.begin(**args) as w:
        s, docs, rows = record(w, [(x['target_id'], 'COMPLETE') for x in args['expected_hosts']])
        doc = combined(s, docs)
        return w.finalize(doc, batch_raw=raw(batch(s, doc, rows, 0)), batch_rc=0)


@pytest.mark.parametrize('version', ('1.0.0', '1.1.0'))
def test_r01_r03_actual_complete_roundtrip(root, schema, version):
    hid = e.host_id(None, TARGETS[0], run_id=RID, identity_key=TARGETS[0])
    req = {'assessment': True, 'cff': True, 'details': [{'host_id': hid, 'slot': 'platform'}]}
    with m.RunStore(root) as store:
        with store.begin(**kwargs(version=version, requirements=req)) as w:
            s, docs, rows = record(w, [(TARGETS[0], 'COMPLETE')], use_details=True)
            doc = combined(s, docs); original = deepcopy(doc)
            assessed = a.evaluate_document(doc, RULES); projection = cff_pair(assessed)
            # Preserve original batch and rules bytes, not just reserialization.
            batch_raw = json.dumps(batch(s, doc, rows, 0), indent=2).encode()
            result = w.finalize(doc, batch_raw=batch_raw, batch_rc=0, assessed=assessed,
                                rules_raw=RULES_RAW, cff=projection)
            assert doc == original and result.document == doc
            assert result.manifest['run_state'] == 'COMPLETE'
            assert result.manifest['publication_state'] == 'PUBLISHED'
            assert result.manifest['batch_contract'] == 'B04_S1_CONTRACT_ONLY'
            assert result.manifest['batch_rc'] == 0
            assert result.artifacts['batch_manifest.json'] == batch_raw
            assert result.artifacts['assessment_rules.json'] == RULES_RAW
            assert result.manifest['rules_sha256'] == digest(RULES_RAW)
            assert len(result.manifest['artifacts']) == 6
            assert result.manifest['missing_artifacts'] == []
            error('ALREADY_PUBLISHED', w.record_host, docs[0], attempted=True, terminal=rows[0])
        loaded = store.open(RID)
        assert loaded == result and loaded.assessed == assessed
        assert schema.is_valid(loaded.manifest)
        schema_name = 'evidence.schema.json' if version == '1.0.0' else 'evidence-1.1.0.schema.json'
        ev_schema = json.loads((ROOT / 'schemas' / schema_name).read_bytes())
        assert ev_schema == e.model_schema(version)
        ev_validator = Draft202012Validator(ev_schema, format_checker=FormatChecker())
        ev_validator.validate(loaded.document); ev_validator.validate(loaded.assessed)
        assert e.parse_evidence_bytes(loaded.artifacts['evidence.json']) == doc
        assert all(row['sha256'] == digest(loaded.artifacts[row['path']]) and row['size'] == len(loaded.artifacts[row['path']])
                   for row in loaded.manifest['artifacts'])
        error('ALREADY_PUBLISHED', store.recover, RID)
        error('RUN_ID_COLLISION', store.begin, **kwargs())
    for p in root.rglob('*'):
        assert stat.S_IMODE(p.stat().st_mode) == (0o700 if p.is_dir() else 0o600)
        assert p.stat().st_uid == os.geteuid()
        if p.is_file(): assert p.stat().st_nlink == 1


@pytest.mark.parametrize('rid', ('', '.', '..', '../escape', 'a/b', 'a\\b', 'x y', 'a\n', 'a%2f', 'a:b', 'a'*65,
                                 'CON', 'prn', 'AUX', 'nul', 'com1', 'Lpt9', 'a.'))
def test_r01_invalid_run_id(root, rid):
    with m.RunStore(root) as store:
        error('INVALID_RUN_ID', store.begin, **kwargs(rid=rid))
    assert not list(root.iterdir())


@pytest.mark.parametrize('name', ('../host', 'host/child', '<script>', 'host\\child', '{{ x }}', 'a\x00', 'https://host', 'host\n'))
def test_r01_hostile_target(root, name):
    with m.RunStore(root) as store:
        error('INVALID_TARGET', store.begin, **kwargs(targets=(name,)))
    assert not list(root.iterdir())


@pytest.mark.parametrize('existing', ('directory', 'file', 'symlink', 'broken-symlink'))
def test_r01_existing_casefold_never_reused(root, existing):
    p = root / RID.upper()
    if existing == 'directory': p.mkdir(mode=0o700)
    elif existing == 'file': p.write_bytes(b'original')
    elif existing == 'symlink': p.symlink_to(root, target_is_directory=True)
    else: p.symlink_to(root / 'absent')
    before = p.lstat()
    with m.RunStore(root) as store:
        error('RUN_ID_COLLISION', store.begin, **kwargs())
    after = p.lstat()
    assert before.st_ino == after.st_ino and before.st_mode == after.st_mode
    assert not (root / RID).exists()
    if existing == 'file': assert p.read_bytes() == b'original'


@pytest.mark.parametrize('mask', (0, 0o777))
def test_r01_generated_id_stable_and_private_umask(root, mask):
    previous = os.umask(mask)
    try:
        with m.RunStore(root) as store:
            ids = []
            for _ in range(2):
                with store.begin(**kwargs(rid=None, stable=True)) as w:
                    ids.append((w.run_id, w.scope['hosts'][0]['host_id']))
                    assert re.fullmatch(r'\d{8}T\d{6}Z-[0-9a-f]{32}', w.run_id)
                    assert w.scope['hosts'][0]['identity_scope'] == 'STABLE'
                store.recover(ids[-1][0])
            assert ids[0][0] != ids[1][0] and ids[0][1] == ids[1][1]
            for p in root.rglob('*'):
                assert stat.S_IMODE(p.stat().st_mode) == (0o700 if p.is_dir() else 0o600)
    finally: os.umask(previous)


def test_r01_run_scoped_identity_changes_between_runs(root):
    with m.RunStore(root) as store:
        with store.begin(**kwargs(rid='one')) as first: hid = first.scope['hosts'][0]['host_id']
        with store.begin(**kwargs(rid='two')) as second:
            assert second.scope['hosts'][0]['host_id'] != hid
            assert second.scope['hosts'][0]['host_id'] == e.host_id(None, TARGETS[0], run_id='two', identity_key=TARGETS[0])


@pytest.mark.parametrize('mode', (0o755, 0o770, 0o777, 0o710, 0o2750))
def test_r01_unsafe_existing_root_not_repaired(root, mode):
    root.chmod(mode)
    try:
        error('UNSAFE_DIRECTORY', m.RunStore, root)
        assert stat.S_IMODE(root.stat().st_mode) == mode
    finally: root.chmod(0o700)


def test_r01_root_and_ancestor_symlinks_and_traversal(root):
    link = root.parent / 'alias'; link.symlink_to(root, target_is_directory=True)
    error('UNSAFE_DIRECTORY', m.RunStore, link)
    (root / 'child').mkdir(mode=0o700)
    error('UNSAFE_DIRECTORY', m.RunStore, link / 'child')
    error('INVALID_ROOT', m.RunStore, str(root) + '/../reports')
    error('INVALID_ROOT', m.RunStore, 'relative-root')
    error('INVALID_ROOT', m.RunStore, str(root) + '//child')


def test_r01_unsafe_ancestor_no_repair(root):
    root.parent.chmod(0o777)
    try:
        error('UNSAFE_ANCESTOR', m.RunStore, root)
        assert stat.S_IMODE(root.parent.stat().st_mode) == 0o777
    finally: root.parent.chmod(0o700)


def test_r01_native_limits_profile_all_disabled_and_identity(root):
    with m.RunStore(root) as store:
        error('HOST_LIMIT', store.begin, **kwargs(targets=tuple(f'host-{i}.example.invalid' for i in range(11))))
        bad = kwargs(); bad['limits']['forks'] = True
        error('INVALID_INTEGER', store.begin, **bad)
        bad = kwargs(); bad['profile'] = 'active'
        error('INVALID_ENUM', store.begin, **bad)
        bad = kwargs(requested=('tls_services',)); error('PROFILE_FLAGS', store.begin, **bad)
        error('DUPLICATE_REF', store.begin, **kwargs(targets=(TARGETS[0], TARGETS[0])))
        with store.begin(**kwargs(requested=())) as w:
            hid = w.scope['hosts'][0]['host_id']
            error('NO_EXECUTABLE_COLLECTORS', w.dispatch_intent, hid)
            s, docs, rows = record(w, [(TARGETS[0], 'NOT_ATTEMPTED')])
            d = combined(s, docs)
            result = w.finalize(d, batch_raw=raw(batch(s, d, rows, 6)), batch_rc=6)
            assert result.manifest['run_state'] == 'ERROR' and result.manifest['counts']['NOT_ATTEMPTED'] == 1


def _child(mode, root, *arguments):
    # A new Python interpreter inherits the process-local offline filter. This
    # avoids fork of a multi-threaded pytest interpreter.
    return subprocess.Popen([sys.executable, '-I', '-B', __file__, '__child__', mode,
                             str(root), *arguments], cwd=ROOT, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)


@pytest.mark.parametrize('ids,expected', (((RID, RID), 1), ((RID, RID.upper()), 1), (('run-a', 'run-b'), 2), ((None, None), 2)))
def test_r01_actual_two_process_reservations(root, ids, expected):
    # Independent processes, actual flock/mkdir and simultaneous start.
    children = [_child('reserve', root, json.dumps(rid)) for rid in ids]
    try:
        for child in children: child.stdin.write(b'X'); child.stdin.flush()
        results = []
        for child in children:
            output, err = child.communicate(timeout=15)
            assert child.returncode == 0, err.decode(errors='replace')
            results.append(json.loads(output))
        assert sum(x['ok'] for x in results) == expected
        assert all(x['ok'] or x['code'] == 'RUN_ID_COLLISION' for x in results)
        assert len([x for x in root.iterdir() if x.is_dir()]) == expected
        with m.RunStore(root) as store:
            for x in results:
                if x['ok']: assert store.recover(x['id']).manifest['run_state'] == 'ERROR'
    finally:
        for child in children:
            if child.poll() is None: child.kill(); child.communicate()


def test_r02_actual_active_writer_and_abrupt_exit(root):
    child = _child('active', root)
    try:
        assert select.select([child.stdout], [], [], 15)[0], 'child did not report'
        assert child.stdout.readline() == b'READY\n'
        with m.RunStore(root) as store:
            error('RUN_BUSY', store.recover, RID)
            error('RUN_BUSY', store.open, RID)
            _, err = child.communicate(b'X', timeout=15)
            assert child.returncode == 23, err.decode(errors='replace')
            error('INCOMPLETE_RUN', store.open, RID)
            result = store.recover(RID)
            h = {x['target_id']: x for x in result.manifest['hosts']}
            assert result.manifest['run_state'] == 'PARTIAL' and result.manifest['recovery'] is True
            assert result.manifest['batch_rc'] is None and result.manifest['batch_missing_reason'] == 'BATCH_MANIFEST_UNAVAILABLE'
            assert h[TARGETS[0]]['host_state'] == 'COMPLETE' and h[TARGETS[0]]['attempted'] is True
            assert next(x for x in h[TARGETS[0]]['terminal']['collectors'] if x['collector_id'] == 'packages')['rc'] == 0
            assert h[TARGETS[1]]['host_state'] == 'ERROR' and h[TARGETS[1]]['attempted'] is None
            assert h[TARGETS[1]]['reason_code'] == 'OUTCOME_UNKNOWN' and h[TARGETS[1]]['dispatch_intent'] is True
            assert h[TARGETS[2]]['host_state'] == 'NOT_ATTEMPTED' and h[TARGETS[2]]['attempted'] is False
            assert h[TARGETS[2]]['dispatch_intent'] is False
            assert len(result.document['evidence']) == 1 and len(result.document['hosts']) == 3
            assert result.document['run']['finished_at'] is None
            assert store.open(RID) == result
    finally:
        if child.poll() is None: child.kill(); child.communicate()


@pytest.mark.parametrize('crash_at', ('before_prepared', 'after_prepared', 'after_move', 'before_manifest'))
def test_r02_actual_crash_publication_boundaries(root, crash_at, schema):
    child = _child('crash', root, crash_at)
    try:
        _, err = child.communicate(timeout=15)
        assert child.returncode == 31, err.decode(errors='replace')
    finally:
        if child.poll() is None: child.kill(); child.communicate()
    assert not (root / RID / 'run_manifest.json').exists()
    before = {p.name: p.stat().st_ino for p in (root / RID).iterdir() if p.name in ('evidence.json', 'batch_manifest.json')}
    with m.RunStore(root) as store:
        error('INCOMPLETE_RUN', store.open, RID)
        recovered = store.recover(RID)
        assert recovered.manifest['run_state'] == ('PARTIAL' if crash_at == 'before_prepared' else 'COMPLETE')
        assert recovered.manifest['recovery'] is (crash_at == 'before_prepared')
        assert recovered.manifest['batch_rc'] == (None if crash_at == 'before_prepared' else 0)
        assert len(recovered.document['evidence']) == 1
        schema.validate(recovered.manifest)
        assert store.open(RID) == recovered
    assert all((root / RID / name).stat().st_ino == ino for name, ino in before.items())


@pytest.mark.parametrize('states,rc', ((('COMPLETE', 'PARTIAL', 'UNREACHABLE'),5),
                                      (('ERROR', 'UNREACHABLE', 'NOT_ATTEMPTED'),6),
                                      (('COMPLETE', 'COMPLETE', 'COMPLETE'),7),
                                      (('NOT_ATTEMPTED', 'NOT_ATTEMPTED', 'NOT_ATTEMPTED'),7)))
def test_r02_native_batch_states_and_rc(root, schema, states, rc):
    with m.RunStore(root) as store:
        with store.begin(**kwargs(targets=TARGETS)) as w:
            s, docs, rows = record(w, list(zip(TARGETS, states)))
            doc = combined(s, docs, interrupted=rc == 7)
            b = batch(s, doc, rows, rc)
            result = w.finalize(doc, batch_raw=raw(b), batch_rc=rc)
            assert result.manifest['batch_rc'] == rc
            assert result.manifest['counts']['total'] == 3
            assert all(result.manifest['counts'][x] == states.count(x) for x in e.HOST_STATES)
            assert result.manifest['run_state'] == doc['run']['run_state']
            assert result.manifest['batch_canonical_sha256'] == digest(raw(b))
        schema.validate(store.open(RID).manifest)


def test_r02_no_intent_or_duplicate_terminal_or_unknown_host(root):
    with m.RunStore(root) as store:
        with store.begin(**kwargs()) as w:
            s = w.scope; doc = make_host(s, TARGETS[0]); row = terminal(s, doc); hid = doc['hosts'][0]['host_id']
            error('ATTEMPT_STATE', w.record_host, doc, attempted=True, terminal=row)
            error('FOREIGN_HOST', w.dispatch_intent, 'h-'+'0'*64)
            w.dispatch_intent(hid); error('DUPLICATE_INTENT', w.dispatch_intent, hid)
            error('INVALID_SHAPE', w.record_host, doc, attempted=True)
            w.record_host(doc, attempted=True, terminal=row)
            error('TERMINAL_EXISTS', w.record_host, doc, attempted=True, terminal=row)
            error('DUPLICATE_INTENT', w.dispatch_intent, hid)


@pytest.mark.parametrize('defect,code', (('target_count', 'INVALID_INTEGER'), ('duplicate_host', 'BATCH_HOSTS'),
    ('foreign_target', 'BATCH_TARGETS'), ('scope', 'BATCH_SCOPE'), ('rc', 'BATCH_RC'),
    ('state', 'BATCH_RUN_STATE'), ('terminal', 'TERMINAL_MISMATCH')))
def test_r02_batch_rejects_contradictions(root, defect, code):
    with m.RunStore(root) as store:
        with store.begin(**kwargs()) as w:
            s, docs, rows = record(w, [(TARGETS[0], 'COMPLETE')]); d = combined(s, docs); b = batch(s, d, rows, 0); rc = 0
            if defect == 'target_count': b['target_count'] = True
            elif defect == 'duplicate_host': b['hosts'] *= 2
            elif defect == 'foreign_target': b['target_ids'] = ['foreign.example.invalid']
            elif defect == 'scope': b['limits'] = {**LIMITS, 'forks': 1}
            elif defect == 'rc': rc = 5
            elif defect == 'state': b['run_state'] = 'PARTIAL'
            else: b['hosts'][0]['reason_code'] = 'FORGED'
            error(code, w.finalize, d, batch_raw=raw(b), batch_rc=rc)
            assert not (root/RID/'prepared.json').exists()
            assert not (root/RID/'run_manifest.json').exists()


@pytest.mark.parametrize('defect,code', (('foreign_ref','FOREIGN_REF'),('collector','FOREIGN_COLLECTOR'),('state','BATCH_COVERAGE'),
                                        ('duplicate','BATCH_COLLECTORS'),('requested','BATCH_COLLECTORS')))
def test_r02_checkpoint_native_terminal_validates_before_write(root, defect, code):
    with m.RunStore(root) as store:
        with store.begin(**kwargs()) as w:
            s=w.scope; d=make_host(s,TARGETS[0]); row=terminal(s,d); hid=d['hosts'][0]['host_id'];w.dispatch_intent(hid)
            package=next(x for x in row['collectors'] if x['collector_id']=='packages')
            if defect=='foreign_ref': package['collection_ids']=['c-'+'0'*64]
            elif defect=='collector':
                other=next(x for x in row['collectors'] if x['collector_id']=='openssl')
                package['collection_ids'],other['collection_ids']=[],package['collection_ids']
                package['state']='UNKNOWN';other['state']='COLLECTED'
            elif defect=='state': package['state']='UNKNOWN'
            elif defect=='duplicate': row['collectors'][0]=deepcopy(row['collectors'][1])
            else: package['requested']=False
            error(code,w.record_host,d,attempted=True,terminal=row)
            assert not (root/RID/'checkpoints'/(hid+'.json')).exists()


def test_r02_missing_checkpoint_and_immutable_observations(root):
    with m.RunStore(root) as store:
        with store.begin(**kwargs(targets=TARGETS[:2])) as w:
            s, docs, rows = record(w, [(TARGETS[0], 'COMPLETE')]); d2=make_host(s,TARGETS[1]); r2=terminal(s,d2)
            doc=combined(s,docs+[d2]); b=batch(s,doc,rows+[r2],0)
            error('MISSING_TERMINAL_CHECKPOINT', w.finalize, doc,batch_raw=raw(b),batch_rc=0)
            w.dispatch_intent(d2['hosts'][0]['host_id']);w.record_host(d2,attempted=True,terminal=r2)
            forged=deepcopy(doc);forged['evidence'][0]['data']['version']='9.9'
            error('CHECKPOINT_MISMATCH',w.finalize,forged,batch_raw=raw(b),batch_rc=0)
            result=w.finalize(doc,batch_raw=raw(b),batch_rc=0);assert len(result.document['evidence'])==2


def test_r02_journal_failure_stops_new_dispatch(root, monkeypatch):
    with m.RunStore(root) as store:
        with store.begin(**kwargs(targets=TARGETS[:2])) as w:
            h=w.scope['hosts'];old=m._sync
            def fail(fd): raise m.StoreError('DURABILITY_UNCONFIRMED')
            with monkeypatch.context() as mp:
                mp.setattr(m,'_sync',fail)
                error('DURABILITY_UNCONFIRMED',w.dispatch_intent,h[0]['host_id'])
            assert m._sync is old
            error('WRITER_CLOSED_OR_FAILED',w.dispatch_intent,h[1]['host_id'])
        result=store.recover(RID)
        assert result.manifest['counts']['NOT_ATTEMPTED']==2 and result.manifest['run_state']=='ERROR'


def test_r02_real_short_writes_no_truncation(root, monkeypatch):
    write=os.write
    def short(fd, data): return write(fd,data[:97])
    with monkeypatch.context() as mp:
        mp.setattr(os,'write',short)
        with m.RunStore(root) as store: result=complete(store)
    with m.RunStore(root) as store: assert store.open(RID)==result


@pytest.mark.parametrize('defect,code', (('path','INVALID_SLOT_PATH'), ('duplicate','DUPLICATE_SLOT'),
    ('version','UNSUPPORTED_MANIFEST_VERSION'), ('count','MANIFEST_MISMATCH'),('foreign_host','HOST_MANIFEST'),
    ('hash','ARTIFACT_HASH'),('missing','MISSING_ARTIFACT'),('mode','UNSAFE_FILE'),('hardlink','UNSAFE_FILE'),
    ('symlink','UNSAFE_FILE'),('fifo','UNSAFE_FILE'),('unindexed','UNINDEXED_ARTIFACT'),('duplicate_key','DUPLICATE_KEY')))
def test_r03_reader_rejects_tampered_core(root, defect, code):
    with m.RunStore(root) as store:
        result=complete(store); directory=root/RID; marker=directory/'run_manifest.json';p=directory/'evidence.json';
        changed=deepcopy(result.manifest)
        if defect=='path': changed['artifacts'][0]['path']='../../foreign.json'
        elif defect=='duplicate': changed['artifacts'].append(deepcopy(changed['artifacts'][0]))
        elif defect=='version':changed['manifest_version']='9.0.0'
        elif defect=='count':changed['counts']['COMPLETE']=0
        elif defect=='foreign_host':changed['expected_host_ids']=['h-'+'0'*64]
        elif defect=='hash': changed['artifacts'][0]['sha256']='0'*64
        elif defect=='missing':p.unlink()
        elif defect=='mode':p.chmod(0o644)
        elif defect=='hardlink':os.link(p,directory/'alias')
        elif defect=='symlink':
            p.rename(directory/'real');p.symlink_to(directory/'real')
        elif defect=='fifo':p.unlink();os.mkfifo(p,0o600)
        elif defect=='unindexed':
            (directory/'assessed_evidence.json').write_bytes(b'{}');(directory/'assessed_evidence.json').chmod(0o600)
        if defect=='duplicate_key':marker.write_bytes(b'{"run_id":"one","run_id":"two"}')
        elif changed!=result.manifest:marker.write_bytes(raw(changed))
        error(code,store.open,RID)
        error('ALREADY_PUBLISHED',store.recover,RID)


@pytest.mark.parametrize('file,code', (('journal.json','CORRUPT_CHECKPOINT'),('checkpoint','CORRUPT_CHECKPOINT')))
def test_r02_recover_corrupt_checkpoint_or_journal(root,file,code):
    with m.RunStore(root) as store:
        with store.begin(**kwargs()) as w:
            s,docs,rows=record(w,[(TARGETS[0],'COMPLETE')]);hid=docs[0]['hosts'][0]['host_id']
        p=root/RID/(file if file!='checkpoint' else 'checkpoints/'+hid+'.json')
        v=json.loads(p.read_bytes());v['sha256']='0'*64;p.write_bytes(raw(v))
        error(code,store.recover,RID)
        assert not (root/RID/'run_manifest.json').exists()


@pytest.mark.parametrize('defect,code',(('missing_detail','REQUIRED_DETAIL_MISSING'),('foreign_ref','FOREIGN_REF'),
    ('bad_version','UNVERIFIED_PRODUCER_FORMAT'),('raw_attachment','INVALID_SHAPE'),('detail_state','DETAIL_STATE')))
def test_r03_closed_detail_validation(root,defect,code):
    hid=e.host_id(None,TARGETS[0],run_id=RID,identity_key=TARGETS[0]);req={'assessment':False,'cff':False,'details':[{'host_id':hid,'slot':'platform'}]}
    with m.RunStore(root) as store:
        with store.begin(**kwargs(requirements=req)) as w:
            s=w.scope;d=make_host(s,TARGETS[0]);row=terminal(s,d);v=detail(s,d);w.dispatch_intent(hid)
            if defect=='missing_detail': values=[]
            else:
                if defect=='foreign_ref':v['evidence_ids']=['e-'+'0'*64]
                elif defect=='bad_version':v['format_version']='2.0.0'
                elif defect=='raw_attachment':v['stdout']='arbitrary raw data'
                elif defect=='detail_state':v['records'][0]['state']='ERROR'
                values=[v]
            error(code,w.record_host,d,attempted=True,terminal=row,details=values)


@pytest.mark.parametrize('defect,code',(('assessed_only','MISSING_ASSESSMENT_PAIR'),('rules_only','MISSING_ASSESSMENT_PAIR'),
    ('cff_only','MISSING_ASSESSMENT_PAIR'),('bad_hash','CFF_EVIDENCE_HASH'),('bad_companion','CFF_PAIR'),('bad_counts','CFF_COUNTS'),
    ('forged_assessed','ASSESSMENT_MISMATCH'),('missing_required','REQUIRED_ARTIFACT_MISSING')))
def test_r03_assessment_and_cff_pair_binding(root,defect,code):
    req={'assessment':True,'cff':True,'details':[]}
    with m.RunStore(root) as store:
        with store.begin(**kwargs(requirements=req)) as w:
            s,ds,rs=record(w,[(TARGETS[0],'COMPLETE')]);d=combined(s,ds);b=raw(batch(s,d,rs,0))
            assessed=a.evaluate_document(d,RULES);cff=cff_pair(assessed);rules=RULES_RAW
            if defect=='assessed_only':rules=None;cff=None
            elif defect=='rules_only':assessed=None;cff=None
            elif defect=='cff_only':assessed=None;rules=None
            elif defect=='bad_hash':cff['evidence_document_sha256']='0'*64
            elif defect=='bad_companion':cff['per_host'][0]['companion']['findings']=[]
            elif defect=='bad_counts':cff['per_host'][0]['cff']['summary']['denominator']=999
            elif defect=='forged_assessed':
                assessed['evidence'][0]['data']['version']='9.9';cff=None
            elif defect=='missing_required':assessed=None;rules=None;cff=None
            error(code,w.finalize,d,batch_raw=b,batch_rc=0,assessed=assessed,rules_raw=rules,cff=cff)
            assert not (root/RID/'run_manifest.json').exists()


def test_r03_legacy_missing_report_no_native_attempt_or_raw_copy(root,schema):
    args=kwargs(kind='LEGACY_IMPORT',version='1.0.0',targets=TARGETS[:2]);original=args['legacy_raw']
    with m.RunStore(root) as store:
        with store.begin(**args) as w:
            s=w.scope;good=make_host(s,TARGETS[0],'PARTIAL','LEGACY_COVERAGE_UNKNOWN')
            missing=make_host(s,TARGETS[1],'ERROR','LEGACY_REPORT_MISSING');missing['collections'][0]['collection_state']='UNKNOWN'
            w.record_host(good);w.record_host(missing)
            error('LEGACY_ATTEMPT',w.dispatch_intent,good['hosts'][0]['host_id'])
            d=combined(s,[good,missing]);d['run']['scope_reason']='LEGACY_SELECTED_MANIFEST'
            assessed=a.evaluate_document(d,RULES)
            result=w.finalize(d,assessed=assessed,rules_raw=RULES_RAW)
            assert result.manifest['run_kind']=='LEGACY_IMPORT' and result.manifest['run_state']=='PARTIAL'
            assert result.manifest['profile'] is result.manifest['limits'] is result.manifest['flags'] is None
            assert result.manifest['batch_rc'] is None and 'batch_manifest.json' not in result.artifacts
            assert all(x['attempted'] is None and x['dispatch_intent'] is None and x['attempt_status']=='NOT_APPLICABLE' for x in result.manifest['hosts'])
            assert {h['reason_code'] for h in result.manifest['hosts']}=={'LEGACY_REPORT_MISSING','LEGACY_COVERAGE_UNKNOWN'}
            assert result.manifest['source']['input_sha256']==digest(original)
            assert json.loads(result.artifacts['legacy_provenance.json'])==args['legacy_provenance']
            assert all(original not in v for v in result.artifacts.values())
        assert store.open(RID)==result;schema.validate(result.manifest)


def test_r03_legacy_hash_and_recovery(root):
    args=kwargs(kind='LEGACY_IMPORT',targets=TARGETS[:2]);bad=deepcopy(args);bad['legacy_raw']=b'changed'
    with m.RunStore(root) as store:
        error('LEGACY_INPUT_HASH',store.begin,**bad)
        with store.begin(**args) as w:
            d=make_host(w.scope,TARGETS[0],'PARTIAL');w.record_host(d)
        result=store.recover(RID)
        assert result.manifest['run_state']=='PARTIAL'
        assert any(h['reason_code']=='LEGACY_OUTCOME_UNKNOWN' and h['attempted'] is None for h in result.manifest['hosts'])
        assert result.manifest['batch_rc'] is None and result.manifest['batch_missing_reason'] is None


def test_r01_legacy_host_limit_and_scope(root):
    targets=tuple(f'legacy-{i}.example.invalid' for i in range(1000))
    with m.RunStore(root) as store:
        with store.begin(**kwargs(kind='LEGACY_IMPORT',targets=targets)) as w:
            assert len(w.scope['hosts'])==1000
        error('HOST_LIMIT',store.begin,**kwargs(rid='other',kind='LEGACY_IMPORT',targets=targets+('extra.example.invalid',)))


def test_r03_shape_schema_negative_and_closed_keys(root,schema):
    with m.RunStore(root) as store: result=complete(store)
    for mutate in (lambda m:m.update(raw_stdout='secret'),lambda m:m.update(manifest_version='2.0.0'),
                   lambda m:m.update(run_state='PLANNED'),lambda m:m['artifacts'][0].update(path='../x'),
                   lambda m:m['hosts'][0].update(attempt_status='PASS'),lambda m:m['artifacts'][0].update(size=0)):
        v=deepcopy(result.manifest);mutate(v);assert not schema.is_valid(v)


@pytest.mark.parametrize('where', ('root', 'lock', 'artifact'))
def test_r01_actual_foreign_owner_rejected(root, where):
    # This sandbox's existing uid 0 can create a deliberately foreign-owned
    # synthetic fixture. No product chown and no privilege elevation.
    if os.geteuid() != 0:
        pytest.skip('foreign-owner fixture creation requires the existing uid 0')
    if where == 'root':
        os.chown(root, 65534, -1)
        try:
            error('UNSAFE_DIRECTORY', m.RunStore, root)
            assert root.stat().st_uid == 65534
        finally: os.chown(root, os.geteuid(), -1)
    else:
        with m.RunStore(root) as store:
            complete(store)
            p = root/RID/('.writer.lock' if where == 'lock' else 'evidence.json')
            os.chown(p,65534,-1)
            try:
                error('UNSAFE_FILE',store.open,RID)
                assert p.stat().st_uid == 65534
            finally: os.chown(p,os.geteuid(),-1)


@pytest.mark.parametrize('defect', ('mode', 'hardlink', 'symlink', 'fifo'))
def test_r01_existing_reservation_lock_not_repaired(root, defect):
    p = root/'.reservation.lock'
    if defect == 'symlink': p.symlink_to(root/'missing')
    elif defect == 'fifo': os.mkfifo(p,0o600)
    else:
        p.write_bytes(b'original-lock');p.chmod(0o600)
        if defect == 'mode':p.chmod(0o644)
        else:os.link(p,root/'lock-alias')
    before=p.lstat()
    with m.RunStore(root) as store: error('UNSAFE_FILE',store.begin,**kwargs())
    after=p.lstat()
    assert (after.st_ino,after.st_mode,after.st_nlink)==(before.st_ino,before.st_mode,before.st_nlink)
    assert not (root/RID).exists()


@pytest.mark.parametrize('existing', ('regular', 'symlink', 'empty-directory'))
def test_r02_existing_marker_never_overwritten(root, existing):
    with m.RunStore(root) as store:
        with store.begin(**kwargs()) as w:
            s,ds,rs=record(w,[(TARGETS[0],'COMPLETE')]);d=combined(s,ds)
            marker=root/RID/'run_manifest.json'
            if existing=='regular':marker.write_bytes(b'broken-marker');marker.chmod(0o600)
            elif existing=='symlink':marker.symlink_to(root/'nonexistent')
            else:marker.mkdir(mode=0o700)
            before=marker.lstat()
            error('ALREADY_PUBLISHED',w.finalize,d,batch_raw=raw(batch(s,d,rs,0)),batch_rc=0)
        error('ALREADY_PUBLISHED',store.recover,RID)
        error('RUN_ID_COLLISION',store.begin,**kwargs())
        assert marker.lstat().st_ino==before.st_ino
        if existing=='regular':assert marker.read_bytes()==b'broken-marker'


def test_r02_actual_noreplace_primitive_preserves_existing_destination(root):
    # No mocked rename oracle; directly exercise the production primitive on
    # private files and verify the destination inode/content do not change.
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
    try:
        (root/'a').write_bytes(b'first');(root/'b').write_bytes(b'original')
        (root/'a').chmod(0o600);(root/'b').chmod(0o600);before=(root/'b').stat().st_ino
        error('ALREADY_EXISTS',m._rename_noreplace,fd,'a',fd,'b')
        assert (root/'a').read_bytes()==b'first' and (root/'b').read_bytes()==b'original'
        assert (root/'b').stat().st_ino==before
    finally:os.close(fd)


def test_r02_prepared_corruption_refuses_recover(root):
    child=_child('crash',root,'after_prepared')
    _,err=child.communicate(timeout=15);assert child.returncode==31,err.decode(errors='replace')
    stage=next((root/RID).glob('.stage-*'));p=stage/'evidence.json'
    data=p.read_bytes();p.write_bytes(data.replace(b'openssl',b'forged!'))
    with m.RunStore(root) as store:
        error('ARTIFACT_HASH',store.recover,RID)
    assert not (root/RID/'run_manifest.json').exists()


def test_r02_prepared_recovery_rechecks_terminal_checkpoint(root):
    child=_child('crash',root,'after_prepared')
    _,err=child.communicate(timeout=15);assert child.returncode==31,err.decode(errors='replace')
    p=next((root/RID/'checkpoints').glob('h-*.json'));p.unlink()
    with m.RunStore(root) as store:error('MISSING_TERMINAL_CHECKPOINT',store.recover,RID)
    assert not (root/RID/'run_manifest.json').exists()


def test_r02_intent_written_but_not_fsynced_becomes_unknown(root,monkeypatch):
    # Inject a failure after the real journal rename. Visible intent is not
    # evidence of dispatch. The writer is poisoned, recovery is conservative.
    with m.RunStore(root) as store:
        with store.begin(**kwargs()) as w:
            hid=w.scope['hosts'][0]['host_id'];old=os.replace
            def replaced(*a,**k):
                old(*a,**k)
                raise m.StoreError('DURABILITY_UNCONFIRMED')
            with monkeypatch.context() as mp:
                mp.setattr(os,'replace',replaced)
                error('DURABILITY_UNCONFIRMED',w.dispatch_intent,hid)
            error('WRITER_CLOSED_OR_FAILED',w.dispatch_intent,hid)
        result=store.recover(RID)
        h=result.manifest['hosts'][0]
        assert h['host_state']=='ERROR' and h['attempted'] is None and h['dispatch_intent'] is True


def test_r02_required_missing_on_recovery_is_explicit(root,schema):
    req={'assessment':True,'cff':True,'details':[]}
    with m.RunStore(root) as store:
        with store.begin(**kwargs(requirements=req)) as w:record(w,[(TARGETS[0],'COMPLETE')])
        result=store.recover(RID)
        assert result.manifest['run_state']=='PARTIAL'
        assert {x['path'] for x in result.manifest['missing_artifacts']}=={'batch_manifest.json','assessed_evidence.json','assessment_rules.json','cff_projection.json'}
        schema.validate(result.manifest);assert store.open(RID)==result


def test_r03_legacy_per_row_source_digest_bound(root):
    with m.RunStore(root) as store:
        with store.begin(**kwargs(kind='LEGACY_IMPORT')) as w:
            d=make_host(w.scope,TARGETS[0],'PARTIAL')
            for r in d['collections']+d['evidence']:r['source']['input_sha256']='0'*64
            e.validate_document(d)  # common shape alone is not source binding
            error('LEGACY_SOURCE',w.record_host,d)


def test_r03_reject_unverified_real_detail_and_cff_formats(root):
    req={'assessment':True,'cff':True,'details':[]}
    with m.RunStore(root) as store:
        error('UNVERIFIED_PRODUCER_FORMAT',store.begin,**kwargs(kind='NATIVE_SCAN',requirements=req))
        with store.begin(**kwargs(kind='NATIVE_SCAN')) as w:
            s=w.scope;d=make_host(s,TARGETS[0]);t=terminal(s,d);w.dispatch_intent(d['hosts'][0]['host_id'])
            error('UNVERIFIED_PRODUCER_FORMAT',w.record_host,d,attempted=True,terminal=t,details=[detail(s,d)])
            w.record_host(d,attempted=True,terminal=t);d=combined(s,[d]);assessed=a.evaluate_document(d,RULES)
            error('UNVERIFIED_PRODUCER_FORMAT',w.finalize,d,batch_raw=raw(batch(s,d,[t],0)),batch_rc=0,
                  assessed=assessed,rules_raw=RULES_RAW,cff=cff_pair(assessed))
            result=w.finalize(d,batch_raw=raw(batch(s,d,[t],0)),batch_rc=0)
        assert result.manifest['batch_contract']=='B04_S1_CONTRACT_ONLY'


def test_r03_explicit_secret_key_and_pem_rejected(root):
    with m.RunStore(root) as store:
        with store.begin(**kwargs()) as w:
            s=w.scope;d=make_host(s,TARGETS[0]);t=terminal(s,d);w.dispatch_intent(d['hosts'][0]['host_id'])
            bad=deepcopy(d);bad['hostvars']={'ansible_password':'dummy-sentinel'}
            error('FORBIDDEN_FIELD',w.record_host,bad,attempted=True,terminal=t)
            bad=deepcopy(d);bad['evidence'][0]['data']['version']='-----BEGIN PRIVATE KEY-----'
            e.validate_document(bad)
            error('FORBIDDEN_FIELD',w.record_host,bad,attempted=True,terminal=t)


@pytest.mark.parametrize('limit', (m.MAX_DETAIL,m.MAX_EVIDENCE,m.MAX_CFF))
def test_r03_actual_sparse_file_limit_before_payload_read(root,limit):
    p=root/'oversized';fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    try:os.ftruncate(fd,limit+1)
    finally:os.close(fd)
    d=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
    try:error('ARTIFACT_SIZE',m._read,d,'oversized',os.fstat(d).st_dev,limit)
    finally:os.close(d)
    assert p.stat().st_size==limit+1


def test_r03_index_enforces_core_and_slot_bounds_before_io(root):
    with m.RunStore(root) as store:
        result=complete(store);marker=root/RID/'run_manifest.json';v=deepcopy(result.manifest)
        # Large declared sizes are individually valid, but exceed total cap.
        by_kind={x['kind']:x for x in v['artifacts']};by_kind['evidence']['size']=m.MAX_EVIDENCE
        template=deepcopy(by_kind['evidence']);v['artifacts'].extend([
            {**template,'kind':'assessed','path':'assessed_evidence.json','size':m.MAX_EVIDENCE},
            {**template,'kind':'cff','path':'cff_projection.json','size':m.MAX_CFF}])
        # A valid-looking set of 65 detail slots cannot exist for one host; use
        # existing slot bounds via oversized index test, and aggregate cap using
        # all allowed fixed slots across a full legacy host registry below.
        oversized=deepcopy(v);oversized['artifacts']=[template]*(m.MAX_SLOTS+1)
        marker.write_bytes(raw(oversized));error('SLOT_LIMIT',store.open,RID)
        # Real aggregate guard using the fixed payload budget at the internal
        # assembly boundary; the sparse-file tests separately exercise FS sizes.
        # Avoid allocating hundreds of MiB: actual bytes are independently
        # bounded in _assemble and _manifest_header; the latter must reject
        # oversized index before opening any nonexistent detail files.
        # Construct 70 distinct allowed (host, slot) rows on a synthetic 10-host
        # manifest: 60 detail slots plus core cannot exceed 256 MiB, so use the
        # legacy 1000-host index (unknown detail types still fail closed later).
        scope_args=kwargs(rid='many',kind='LEGACY_IMPORT',targets=tuple(f'host-{i}.example.invalid' for i in range(100)))
        with store.begin(**scope_args) as w:pass
        many=store.recover('many');mi=deepcopy(many.manifest)
        for h in mi['hosts']:
            for slot in m.DETAIL_SLOTS:
                mi['artifacts'].append({**template,'kind':'detail','host_id':h['host_id'],'slot':slot,
                   'path':f'details/{h["host_id"]}/{slot}.json','size':m.MAX_DETAIL})
        (root/'many'/'run_manifest.json').write_bytes(raw(mi))
        error('CORE_SIZE_LIMIT',store.open,'many')


# Child entry points exist only in this test file; no product fault-injection
# parameter, CLI or dynamically selected callback is exposed.
if __name__ == '__main__' and len(sys.argv) >= 4 and sys.argv[1] == '__child__':
    mode, path = sys.argv[2:4]
    if mode == 'reserve':
        assert sys.stdin.buffer.read(1) == b'X'
        with m.RunStore(path) as store:
            try:
                with store.begin(**kwargs(rid=json.loads(sys.argv[4]))) as w:
                    value = {'ok': True, 'id': w.run_id}
            except m.StoreError as ex: value = {'ok': False, 'code': ex.code}
        sys.stdout.buffer.write(raw(value)); sys.stdout.buffer.flush()
        sys.exit(0)
    if mode == 'active':
        store = m.RunStore(path); w = store.begin(**kwargs(targets=TARGETS)); s = w.scope
        d = make_host(s, TARGETS[0]); row = terminal(s, d)
        w.dispatch_intent(d['hosts'][0]['host_id']); w.record_host(d, attempted=True, terminal=row)
        w.dispatch_intent(next(h['host_id'] for h in s['hosts'] if h['target_id'] == TARGETS[1]))
        print('READY', flush=True)
        assert sys.stdin.buffer.read(1) == b'X'
        os._exit(23)
    if mode == 'crash':
        crash_at = sys.argv[4]
        store = m.RunStore(path); w = store.begin(**kwargs())
        s, docs, rows = record(w, [(TARGETS[0], 'COMPLETE')]); d = combined(s, docs)
        old_write, old_rename = m._write, m._rename_noreplace
        def write(parent, name, data, device, **options):
            if crash_at == 'before_prepared' and name == 'prepared.json': os._exit(31)
            if crash_at == 'before_manifest' and name == 'run_manifest.json': os._exit(31)
            old_write(parent, name, data, device, **options)
            if crash_at == 'after_prepared' and name == 'prepared.json': os._exit(31)
        def rename(srcfd, src, dstfd, dst):
            old_rename(srcfd, src, dstfd, dst)
            if crash_at == 'after_move' and src == dst and srcfd != dstfd: os._exit(31)
        m._write, m._rename_noreplace = write, rename
        w.finalize(d, batch_raw=raw(batch(s, d, rows, 0)), batch_rc=0)
        sys.exit(92)
    sys.exit(93)
