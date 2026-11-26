"""B1 integration: actual private Store publication and official A validator."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import socket
import sys
import urllib.request

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools import assessment, cbom_generation as generation, cbom_validation as validation
from tools import evidence as e, portal_indexes, run_store as rs

RID = 'cbom-fixture'
STAMP = '2026-01-01T00:00:00Z'
END = '2026-01-01T00:00:02Z'
LIMITS = dict(max_hosts=10, forks=2, serial=2, ssh_timeout_s=15, command_timeout_s=30)
RULES_RAW = (ROOT / 'config/assessment_rules.yml').read_bytes()
RULES = assessment.load_rules(RULES_RAW)
SECRET = 'anonymous-test-secret-DO-NOT-ECHO'
URL = 'https://example.invalid/' + SECRET
PRIVATE_PATH = '/anonymous/' + SECRET
TARGETS = ('fixture-a.example.invalid', 'fixture-b.example.invalid', 'fixture-unreachable.example.invalid',
           'fixture-disabled.example.invalid')


def raw(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode('ascii')


@pytest.fixture
def root(tmp_path):
    p = tmp_path / 'reports'; p.mkdir(mode=0o700); return p


def options(*, saved=True, cff=False, rid=RID):
    return dict(run_id=rid, run_kind='SYNTHETIC', evidence_schema_version='1.1.0',
        source=dict(source_kind='SYNTHETIC', producer_id='fixture', producer_version='1.0.0',
                    origin_ref='fixture', input_sha256=None), started_at=STAMP, recorded_at=END,
        expected_hosts=[dict(target_id=t, inventory_authority_id=None, identity_key=t) for t in TARGETS],
        limits=LIMITS, profile='baseline', requested_flags={t: {f: t != TARGETS[3] and f in
            ('packages', 'openssl', 'sshd', 'system_certs') for f in rs.COLLECTORS} for t in TARGETS},
        requirements=dict(assessment=saved, cff=cff, details=[]))


def asset(doc, host, kind, literal):
    aid = e.asset_id(host['host_id'], kind, literal, run_id=doc['run']['run_id'])
    a = dict(asset_id=aid, host_id=host['host_id'], asset_kind=kind, identity_scope='RUN_SCOPED',
             identity_key=literal, evidence_ids=[])
    doc['assets'].append(a)
    return a


def scope(doc, host, collector, name, records, state='COLLECTED'):
    hid, rid = host['host_id'], doc['run']['run_id']
    source = dict(doc['run']['source'])
    if source['source_kind'] != 'LEGACY_IMPORT':
        source['producer_id'] = collector
    cid = e.collection_id(rid, hid, collector, name)
    c = dict(collection_id=cid, host_id=hid, collector_id=collector, collector_version='1.0.0',
        scope_key=name, collection_state=state, reason_code={'COLLECTED': 'COLLECTED',
        'PARTIAL': 'INCOMPLETE_COLLECTION', 'UNKNOWN': 'NO_EVIDENCE', 'ERROR': 'COMMAND_FAILED'}[state],
        source=source, observed_at=STAMP, evidence_ids=[])
    doc['collections'].append(c)
    for key, kind, data, algorithm, a in records:
        eid = e.evidence_id(rid, hid, cid, key)
        doc['evidence'].append(dict(evidence_id=eid, host_id=hid, collection_id=cid,
            asset_id=None if a is None else a['asset_id'], observation_key=key, evidence_kind=kind,
            source=source, observed_at=STAMP, data=data, algorithm=algorithm))
        c['evidence_ids'].append(eid)
        if a is not None:
            a['evidence_ids'].append(eid)


def alg(name, context):
    return assessment.classify_algorithm(name, context, RULES)


def runtime(key, algorithm, supported, a=None):
    return key, 'RUNTIME_CAPABILITY', dict(capability=key, supported=supported), algorithm, a


def package(key, name, version, present, a=None):
    return key, 'PACKAGE_INVENTORY', dict(name=name, version=version, present=present), None, a


def metadata(key, name, version, a=None):
    return key, 'ASSET_METADATA', dict(name=name, version=version), None, a


def populate(doc, host, second):
    kem = alg('MLKEM768' if second else 'ML-KEM-768', 'KEM_CAPABILITY')
    hybrid = alg('mlkem768x25519-sha256', 'SSH_KEX')
    classical = alg('curve25519-sha256', 'SSH_KEX')
    conflict = alg('ML-KEM-512', 'KEM_CAPABILITY')
    if second:
        conflict.update(family='CLASSICAL', primitive='SIGNATURE')
    unknown = dict(algorithm_id=None, family='UNKNOWN', primitive='UNKNOWN', observed_name=SECRET,
                   taxonomy_version=None)
    unsafe = dict(algorithm_id=None, family='UNKNOWN', primitive='UNKNOWN', observed_name=URL,
                  taxonomy_version=SECRET)
    lib = asset(doc, host, 'library', 'fixture-library')
    svc = asset(doc, host, 'service', 'fixture-service')
    cert = asset(doc, host, 'certificate', 'fixture-certificate')
    scope(doc, host, 'packages', 'inventory', [package('pkg', 'openssl', '3.5.0', True),
        package('absent', 'openssl-libs', '3.5.0', False), package('unknown', SECRET, None, None)])
    scope(doc, host, 'openssl', 'openssl-version', [metadata('cli-version', 'openssl-cli', '3.5.0'),
        metadata('library-version', 'openssl-linked-library', None)])
    scope(doc, host, 'openssl', 'runtime', [runtime('kem', kem, True, lib),
        metadata('lib-meta', SECRET, '1.0', lib), metadata('lib-conflict', SECRET, '2.0', lib),
        runtime('conflict', conflict, True), runtime('unknown-alg', unknown, None),
        runtime('unsafe-alg', unsafe, None), metadata('free-metadata', URL, PRIVATE_PATH),
        runtime('signature', alg('ML-DSA-44', 'SIGNATURE'), True),
        runtime('public-key', alg('ML-DSA-44', 'CERT_PUBLIC_KEY'), True),
        runtime('symmetric', alg('AES', 'SYMMETRIC_CIPHER'), True),
        runtime('classical', classical, False),
        ('legacy', 'LEGACY_OBSERVATION', dict(field='tls-group', value=SECRET), kem, None)])
    scope(doc, host, 'openssl', 'failed', [runtime('failure', kem, True)], 'ERROR')
    ctx = dict(host_id=host['host_id'], service_asset_id=svc['asset_id'], endpoint_ref='fixture-endpoint',
               protocol='SSH', context_ref='fixture-context', authorization_ref='fixture-authorization')
    scope(doc, host, 'sshd', 'service', [
        ('neg', 'AUTHORIZED_NEGOTIATION', dict(conditions=ctx, outcome='REJECTED' if second else 'NEGOTIATED'), hybrid, svc),
        ('usage', 'OBSERVED_USAGE', dict(conditions=dict(host_id=host['host_id'], service_asset_id=svc['asset_id'],
            business_source_ref='fixture-audit', method='SERVICE_AUDIT_RECORD', started_at=STAMP, finished_at=END),
            outcome='CONTRADICTED' if second else 'OBSERVED'), hybrid, svc)])
    scope(doc, host, 'system_certs', 'certificate', [metadata('cert-metadata', SECRET, None, cert)])


def s1_pair(assessed):
    digest = hashlib.sha256(e.canonical_bytes(assessed)).hexdigest()
    entries = []
    for hid in assessed['run']['expected_host_ids']:
        findings = [{k: f[k] for k in ('finding_id', 'assessment_state', 'reason_code', 'claim_ids', 'evidence_ids')}
                    for f in assessed['findings'] if f['subject']['host_id'] == hid]
        wire = [dict(rule_id=f['finding_id'], status={'PASS': 'pass', 'FAIL': 'fail',
                'NOT_APPLICABLE': 'not_applicable'}.get(f['assessment_state'], 'not_checked')) for f in findings]
        counts = {state: sum(r['status'] == state for r in wire) for state in
                  ('pass', 'fail', 'error', 'not_applicable', 'not_checked')}
        denom = counts['pass'] + counts['fail']
        entries.append(dict(host_id=hid, cff=dict(version='1.0.0', findings=wire,
            summary={**counts, 'total': len(wire), 'denominator': denom, 'score_available': denom > 0}),
            companion=dict(evidence_document_sha256=digest, findings=findings,
                           score_semantics='FACT_STATUS_RATIO_NOT_READINESS')))
    return dict(format='S1_CFF_PAIR', projection_version='1.0.0', evidence_document_sha256=digest, per_host=entries)


def publish(root, *, saved=True, cff=False, reverse=False, rid=RID):
    with rs.RunStore(root) as store, store.begin(**options(saved=saved, cff=cff, rid=rid)) as w:
        s = w.scope
        hosts = s['hosts']
        for h in hosts:
            t = h['target_id']
            if t in TARGETS[:2]:
                h.update(host_state='PARTIAL', reason_code='INCOMPLETE_COLLECTION')
            elif t == TARGETS[2]:
                h.update(host_state='UNREACHABLE', reason_code='CONNECTION_FAILED')
        doc = rs._doc(s, hosts, 'PARTIAL', finished_at=END, coverage_reason='INCOMPLETE_COLLECTION')
        for h in hosts:
            if h['target_id'] in TARGETS[:2]:
                populate(doc, h, h['target_id'] == TARGETS[1])
        if reverse:
            for k in ('collections', 'assets', 'evidence'):
                doc[k].reverse()
            for row in doc['assets'] + doc['collections']:
                row['evidence_ids'].reverse()
        doc = json.loads(e.canonical_bytes(doc))
        terminals = []
        for h in doc['hosts']:
            hid = h['host_id']; attempted = h['host_state'] != 'NOT_ATTEMPTED'
            fragment = rs.host_fragment(doc, hid)
            terminal = dict(target_id=h['target_id'], host_state=h['host_state'], attempted=attempted,
                            reason_code=h['reason_code'], collectors=[])
            for col, requested in sorted(s['flags'][hid].items()):
                coll = [c for c in fragment['collections'] if c['collector_id'] == col]
                state = ('NOT_SCANNED' if not requested else 'UNREACHABLE' if h['host_state'] == 'UNREACHABLE'
                         else 'COLLECTED' if all(c['collection_state'] == 'COLLECTED' for c in coll) else 'PARTIAL')
                terminal['collectors'].append(dict(collector_id=col, requested=requested, state=state,
                    reason_code={'NOT_SCANNED': 'DISABLED', 'UNREACHABLE': 'CONNECTION_FAILED',
                                 'COLLECTED': 'COLLECTED', 'PARTIAL': 'INCOMPLETE_COLLECTION'}[state],
                    rc=0 if requested and state != 'UNREACHABLE' else None,
                    collection_ids=sorted(c['collection_id'] for c in coll)))
            if attempted:
                w.dispatch_intent(hid)
            w.record_host(fragment, attempted=attempted, terminal=terminal)
            terminals.append(terminal)
        batch = raw(dict(batch_manifest_version=1, target_ids=sorted(TARGETS), target_count=len(TARGETS),
            limits=LIMITS, profile='baseline', run_state='PARTIAL', reason_code='INCOMPLETE_COLLECTION',
            hosts=sorted(terminals, key=lambda h: h['target_id'])))
        assessed = assessment.evaluate_document(doc, RULES) if saved else None
        w.finalize(doc, batch_raw=batch, batch_rc=5, assessed=assessed, rules_raw=RULES_RAW if saved else None,
                   cff=s1_pair(assessed) if cff else None)
    with rs.RunStore(root) as store:
        return store.open(rid)


def host_id(pub, target):
    return next(h['host_id'] for h in pub.document['hosts'] if h['target_id'] == target)


def build(root, hid, rid=RID):
    with rs.RunStore(root) as store:
        b, p = generation.build_cbom_bytes(store, rid, hid)
    # Independently consume the real returned bytes using the original A API.
    status = validation.validate_cbom_bytes(b)
    assert (status.schema_status, status.reference_status) == ('PASS', 'PASS')
    assert raw(json.loads(b)) == b and raw(json.loads(p)) == p
    assert json.loads(p)['bom_sha256'] == hashlib.sha256(b).hexdigest()
    return json.loads(b), json.loads(p)


def nodes(p, kind):
    return {ref: n for ref, n in p['nodes'].items() if n['kind'] == kind}


def test_actual_store_multi_host_projection(root):
    pub = publish(root, cff=True)
    results = [build(root, host_id(pub, t)) for t in TARGETS]
    idx = portal_indexes.project_crypto_indexes(pub)
    all_refs = set()
    for t, (bom, p) in zip(TARGETS, results):
        hid = host_id(pub, t)
        assert p['host_id'] == hid and bom['metadata']['component']['bom-ref'] == hid
        assert p['coverage']['cff_state'] == 'VERIFIED_SAVED_PAIR'
        assert p['coverage']['certificate_key_scope'] == 'DEFERRED_B2'
        definitions = {x['bom-ref'] for x in bom['components'] + bom['services']} | {hid}
        assert definitions == set(p['nodes']) and not definitions & all_refs
        all_refs |= definitions
        actual_rows = {r['evidence_id'] for r in pub.document['evidence'] if r['host_id'] == hid}
        assert set(p['observations']) == actual_rows
        actual_claims = {r['claim_id'] for r in pub.assessed['claims'] if r['subject']['host_id'] == hid}
        assert set(p['claims']) == actual_claims
        for n in p['nodes'].values():
            assert n['host_id'] == hid and set(n['evidence_ids']) <= actual_rows
            assert set(n['claim_ids']) <= actual_claims
            if n['portal_group_id']:
                g = next(g for key in ('algorithms', 'libraries') for g in idx[key]['groups']
                         if g['id'] == n['portal_group_id'])
                assert set(n['evidence_ids']) == set(g['evidence_ids']) & actual_rows
        assert all(value not in raw(bom).decode() + raw(p).decode()
                   for value in (SECRET, URL, PRIVATE_PATH))
        assert not any(target in raw(bom).decode() + raw(p).decode() for target in TARGETS)
        if t in TARGETS[:2]:
            assert nodes(p, 'ALGORITHM') and nodes(p, 'SERVICE') and nodes(p, 'PROTOCOL')
            assert {n['family'] for n in nodes(p, 'ALGORITHM').values()} >= {'PQC', 'HYBRID', 'CLASSICAL', 'UNKNOWN'}
            assert {n['classification'] for n in nodes(p, 'ALGORITHM').values()} >= {'CANONICAL', 'CONFLICT', 'LEGACY', 'UNKNOWN'}
            assert {'PACKAGE_ABSENT', 'PACKAGE_PRESENCE_UNKNOWN', 'LIBRARY_CONFLICT', 'DEFERRED_B2'} <= {x['reason'] for x in p['omitted']}
            assert p['coverage']['deferred_asset_ids'] and not set(p['coverage']['deferred_asset_ids']) & definitions
            assert not any(n['kind'] in ('PACKAGE', 'RPM_PACKAGE') and n['presence'] != 'PRESENT' for n in p['nodes'].values())
            assert {n['observation_state'] for n in p['observations'].values()} >= {'ABSENT', 'UNKNOWN', 'PRESENT'}
        else:
            assert bom['components'] == bom['services'] == bom['dependencies'] == []
            assert p['coverage']['host_state'] == ('UNREACHABLE' if t == TARGETS[2] else 'NOT_ATTEMPTED')
    a, b = results[:2]
    assert a[0]['dependencies'] and b[0]['dependencies'] == []
    assert {r['kind'] for r in a[1]['relationships']} == {'SERVICE_PROTOCOL_NEGOTIATED', 'PROTOCOL_ALGORITHM_NEGOTIATED'}
    assert b[1]['relationships'] == []
    for bom, p in (a, b):
        algorithms = {x['bom-ref']: x for x in bom['components'] if x.get('cryptoProperties', {}).get('assetType') == 'algorithm'}
        for ref, n in nodes(p, 'ALGORITHM').items():
            primitive = algorithms[ref]['cryptoProperties']['algorithmProperties']['primitive']
            if n['classification'] != 'CANONICAL' or n['primitive'] in ('PUBLIC_KEY', 'SYMMETRIC') or n['family'] == 'HYBRID':
                assert primitive == 'unknown'
        assert {x['cryptoProperties']['algorithmProperties']['primitive'] for x in algorithms.values()} >= {'kem', 'signature', 'key-agree', 'unknown'}


def test_same_input_and_order_no_writes(root, tmp_path, monkeypatch):
    pub = publish(root)
    other = tmp_path / 'other'; other.mkdir(mode=0o700)
    publish(other, reverse=True)
    hid = host_id(pub, TARGETS[0]); before = deepcopy(pub)
    def snapshot(p):
        return {str(x.relative_to(p)): x.read_bytes() for x in p.rglob('*') if x.is_file()}
    files = snapshot(root)
    def deny(*args, **kwargs):
        pytest.fail('network attempted')
    monkeypatch.setattr(socket, 'socket', deny)
    monkeypatch.setattr(urllib.request, 'urlopen', deny)
    first = build(root, hid)
    assert build(root, hid) == first == build(other, hid)
    assert snapshot(root) == files and pub == before
    with rs.RunStore(root) as store:
        assert store.open(RID) == pub
        assert generation.build_cbom(store, RID, hid) == first


def test_no_saved_assessment_no_taxonomy_name_promotion(root):
    pub = publish(root, saved=False)
    b, p = build(root, host_id(pub, TARGETS[0]))
    assert not p['claims'] and p['coverage']['cff_state'] == 'NOT_AVAILABLE'
    assert not p['coverage']['assessment_saved']
    assert all(n['taxonomy_id_state'] == 'OPAQUE_RECORDED_ID' for n in nodes(p, 'ALGORITHM').values())
    assert all(x['cryptoProperties']['algorithmProperties']['primitive'] == 'unknown' for x in b['components']
               if x.get('cryptoProperties', {}).get('assetType') == 'algorithm')


def test_reject_non_store_foreign_unpublished_and_invalid_ids(root):
    pub = publish(root)
    hid = host_id(pub, TARGETS[0])
    with rs.RunStore(root) as store:
        for args, code in [(('fake-path', RID, hid), 'CBOM_INPUT_TYPE'),
                           ((pub, RID, hid), 'CBOM_INPUT_TYPE'),
                           ((dict(pub.manifest), RID, hid), 'CBOM_INPUT_TYPE'),
                           ((store, '../secret', hid), 'CBOM_INPUT_TYPE'),
                           ((store, RID, 'https://example.invalid/'), 'CBOM_INPUT_TYPE'),
                           ((store, RID, 'h-' + '0' * 64), 'CBOM_HOST_NOT_FOUND'),
                           ((store, 'not-present', hid), 'CBOM_SOURCE_INVALID')]:
            with pytest.raises(generation.CBOMGenerationError) as caught:
                generation.build_cbom_bytes(*args)
            assert caught.value.code == code
        with store.begin(**options(saved=False, rid='unpublished')):
            with pytest.raises(generation.CBOMGenerationError, match='CBOM_SOURCE_INVALID'):
                generation.build_cbom_bytes(store, 'unpublished', hid)


def test_budget_and_actual_validator_failure(root, monkeypatch):
    pub = publish(root)
    hid = host_id(pub, TARGETS[0])
    with rs.RunStore(root) as store:
        with monkeypatch.context() as m:
            m.setattr(generation, 'MAX_MEMBERSHIPS', 5)
            with pytest.raises(generation.CBOMGenerationError, match='CBOM_MEMBERSHIP_LIMIT'):
                generation.build_cbom_bytes(store, RID, hid)
        with monkeypatch.context() as m:
            m.setattr(generation, 'MAX_BYTES', 100)
            with pytest.raises(generation.CBOMGenerationError, match='CBOM_SIZE_LIMIT'):
                generation.build_cbom_bytes(store, RID, hid)
        original = generation._Projection.finish
        def invalid(self):
            b, p = original(self)
            b['components'][0]['type'] = 'not-a-schema-component'
            return b, p
        with monkeypatch.context() as m:
            m.setattr(generation._Projection, 'finish', invalid)
            with pytest.raises(generation.CBOMGenerationError, match='SCHEMA_INVALID'):
                generation.build_cbom_bytes(store, RID, hid)
        def dangling(self):
            b, p = original(self)
            b['dependencies'] = [dict(ref=hid, dependsOn=['missing-ref'])]
            return b, p
        with monkeypatch.context() as m:
            m.setattr(generation._Projection, 'finish', dangling)
            with pytest.raises(generation.CBOMGenerationError, match='REFERENCE_DANGLING'):
                generation.build_cbom_bytes(store, RID, hid)


def test_actual_v2_c1_certificate_deferred(root):
    # Reuse the exact integrated C1 test's typed handoff, original certificate
    # normalization, real record/finalize and reopened Store verification.
    import test_run_store_v2_certificate as c1
    args, doc, terminal, rc, details = c1.fixture(('complete', 'partial', 'connection'))
    with rs.RunStore(root) as store, store.begin(**args) as w:
        c1.record(w, doc, terminal, details)
        c1.finalize(w, doc, terminal, rc)
    with rs.RunStore(root) as store:
        pub = store.open(c1.RID)
    for hid in pub.manifest['expected_host_ids']:
        b, p = build(root, hid, c1.RID)
        deferred = {a['asset_id'] for a in doc['assets'] if a['host_id'] == hid and a['asset_kind'] == 'certificate'}
        assert set(p['coverage']['deferred_asset_ids']) == deferred
        assert p['coverage']['cff_state'] == 'NOT_AVAILABLE'
        assert not p['claims'] and not p['coverage']['assessment_saved']
        assert all(x.get('cryptoProperties', {}).get('assetType') not in ('certificate', 'related-crypto-material')
                   for x in b['components'])
        assert not any(x['bom-ref'] in deferred for x in b['components'])


def test_actual_i3_legacy_and_saved_cff(root):
    from tools import cff
    target = TARGETS[0]
    rid = 'legacy-fixture'
    legacy_raw = b'{"fixture":"anonymous legacy bytes"}'
    source = dict(source_kind='LEGACY_IMPORT', producer_id='legacy-per-host', producer_version='1.0.0',
                  origin_ref='legacy-fixture', input_sha256=hashlib.sha256(legacy_raw).hexdigest())
    with rs.RunStore(root) as store, store.begin(run_id=rid, run_kind='LEGACY_IMPORT',
            evidence_schema_version='1.0.0', source=source, started_at=STAMP, recorded_at=END,
            expected_hosts=[dict(target_id=target, inventory_authority_id=None, identity_key=target)],
            requirements=dict(assessment=True, cff=True, details=[]), legacy_raw=legacy_raw,
            legacy_provenance=dict(format_version='1.0.0', source=source, original_run_id=None,
                                   original_generated_at=None, diagnostics=[])) as w:
        s = w.scope; h = s['hosts'][0]; h.update(host_state='PARTIAL', reason_code='INCOMPLETE_COLLECTION')
        doc = rs._doc(s, [h], 'PARTIAL', finished_at=END, coverage_reason='INCOMPLETE_COLLECTION')
        svc = asset(doc, h, 'service', 'legacy-service')
        scope(doc, h, 'legacy-import', 'tls-services', [
            ('legacy-protocol', 'LEGACY_OBSERVATION', dict(field='tls-protocol', value='TLSv1.2'), None, svc),
            ('legacy-cipher', 'LEGACY_OBSERVATION', dict(field='cipher', value=SECRET),
             alg('TLS_AES_128_GCM_SHA256', 'TLS_CIPHER'), svc),
            metadata('service-meta', SECRET, None, svc)], 'PARTIAL')
        doc = json.loads(e.canonical_bytes(doc))
        assessed = assessment.evaluate_document(doc, RULES)
        paired = cff.project_cff(assessed, RULES)
        w.record_host(rs.host_fragment(doc, h['host_id']), attempted=None, terminal=None)
        w.finalize(doc, assessed=assessed, rules_raw=RULES_RAW, cff=paired)
    b, p = build(root, h['host_id'], rid)
    assert p['coverage']['cff_state'] == 'VERIFIED_SAVED_PAIR'
    assert nodes(p, 'PROTOCOL') and b['dependencies'] == [] and p['relationships'] == []
    assert all(n['classification'] == 'LEGACY' for n in nodes(p, 'ALGORITHM').values())
    assert all(n['observation_state'] is None for n in p['observations'].values())
    assert SECRET not in raw(p).decode() + raw(b).decode()
    with rs.RunStore(root) as store:
        pub = store.open(rid)
    saved = json.loads(pub.artifacts['cff_projection.json'])['per_host'][0]['companion']
    assert set(p['observations']) == {r['evidence_id'] for r in saved['evidence']}
    assert set(p['claims']) == {r['claim_id'] for r in saved['claims']}
    for r in saved['evidence']:
        if r['algorithm'] is not None:
            recorded = p['observations'][r['evidence_id']]
            assert recorded['saved_migration_classification'] == r['algorithm']['migration_classification']
            assert all(recorded['algorithm'][k] == r['algorithm'][k] for k in ('family', 'primitive', 'taxonomy_version'))


@pytest.mark.parametrize('defect', ['source', 'version', 'foreign-host'])
def test_actual_store_rejects_tampered_input(root, defect):
    pub = publish(root)
    hid = host_id(pub, TARGETS[0])
    run = root / RID
    path = run / 'evidence.json'
    original = json.loads(path.read_bytes())
    if defect == 'source':
        original['run']['source']['source_kind'] = 'LEGACY_IMPORT'
    elif defect == 'version':
        original['schema_version'] = '99.0.0'
    else:
        row = next(x for x in original['evidence'] if x['host_id'] == hid)
        row['host_id'] = host_id(pub, TARGETS[1])
    data = raw(original)
    path.write_bytes(data)
    manifest = run / 'run_manifest.json'
    value = json.loads(manifest.read_bytes())
    entry = next(a for a in value['artifacts'] if a['path'] == 'evidence.json')
    entry.update(size=len(data), sha256=hashlib.sha256(data).hexdigest())
    manifest.write_bytes(raw(value))
    with rs.RunStore(root) as store:
        with pytest.raises(generation.CBOMGenerationError, match='CBOM_SOURCE_INVALID'):
            generation.build_cbom_bytes(store, RID, hid)


@pytest.mark.parametrize('defect,code', [('engine', 'SCHEMA_ENGINE_UNAVAILABLE'),
    ('format', 'SCHEMA_ENGINE_UNAVAILABLE'), ('schema', 'SCHEMA_UNAVAILABLE')])
def test_actual_missing_validation_material_is_not_success(root, tmp_path, monkeypatch, defect, code):
    from jsonschema import FormatChecker
    pub = publish(root)
    hid = host_id(pub, TARGETS[0])
    if defect == 'engine':
        monkeypatch.setitem(sys.modules, 'referencing', None)
    elif defect == 'format':
        monkeypatch.delitem(FormatChecker.checkers, 'uri')
    else:
        monkeypatch.setattr(validation, '_SCHEMA_DIR', tmp_path / 'missing-schemas')
    with rs.RunStore(root) as store:
        with pytest.raises(generation.CBOMGenerationError) as caught:
            generation.build_cbom_bytes(store, RID, hid)
        assert caught.value.code == code and str(caught.value) == code
        assert caught.value.__context__ is None


def test_actual_foreign_bom_reference_is_rejected(root, monkeypatch):
    pub = publish(root)
    a, b = [host_id(pub, target) for target in TARGETS[:2]]
    other, _ = build(root, b)
    foreign = other['components'][0]['bom-ref']
    original = generation._Projection.finish
    def inject(self):
        bom, prov = original(self)
        bom['dependencies'] = [dict(ref=a, dependsOn=[foreign])]
        return bom, prov
    monkeypatch.setattr(generation._Projection, 'finish', inject)
    with rs.RunStore(root) as store:
        with pytest.raises(generation.CBOMGenerationError, match='REFERENCE_DANGLING'):
            generation.build_cbom_bytes(store, RID, a)
