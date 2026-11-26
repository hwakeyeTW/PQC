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


def publish(root, *, saved=True, cff=False, reverse=False, rid=RID, populate_extra=None):
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
                if populate_extra is not None:
                    populate_extra(doc, h, h['target_id'] == TARGETS[1])
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


# R1 correction: real published Store rows, not a replacement validator or
# direct calls to a mocked projection. Keep the original fixture assertions.
def _r1_props(component):
    return {p['name']: p['value'] for p in component['properties']}


def _r1_row(pub, hid, key):
    matches = [r for r in pub.document['evidence'] if r['host_id'] == hid
               and r['observation_key'] == key]
    assert len(matches) == 1
    return matches[0]


def _r1_node(bom, prov, kind, eid):
    matches = [(ref, n) for ref, n in nodes(prov, kind).items()
               if eid in n['seed_evidence_ids']]
    assert len(matches) == 1
    ref, node = matches[0]
    return next(c for c in bom['components'] if c['bom-ref'] == ref), node


def test_b1_r1_numeric_versions(root):
    # Documentation-only IPv4 addresses, zero padding, suffixes and longer
    # dotted strings. Ordinary safe versions must survive unchanged.
    unsafe = ('192.0.2.123', '203.0.113.7', '0192.000.002.0123',
              '198.51.100.7a', '999.203.0.113.7.999', '192.0.2.123.256')
    safe = ('3.6.1', '3.6.1a', '256.1.2.3')
    versions = unsafe + safe

    def extra(doc, host, second):
        if second:
            return
        for i, version in enumerate(versions):
            suffix = str(i)
            lib = asset(doc, host, 'library', 'r1-version-' + suffix)
            scope(doc, host, 'packages', 'r1-pkg-' + suffix,
                  [package('r1-pkg-' + suffix, 'openssl', version, True)])
            scope(doc, host, 'openssl', 'r1-version-' + suffix,
                  [metadata('r1-lib-' + suffix, 'openssl', version, lib),
                   runtime('r1-alg-' + suffix, dict(alg('ML-KEM-768', 'KEM_CAPABILITY'),
                           taxonomy_version=version), True)])

    pub = publish(root, populate_extra=extra)
    hid = host_id(pub, TARGETS[0])
    bom, prov = build(root, hid)
    wire = raw(bom).decode() + raw(prov).decode()
    assert not any(v in wire for v in unsafe), 'unsafe version copied into generated wire'
    for i, version in enumerate(versions):
        allowed = version in safe
        expected = version if allowed else None
        state = 'RECORDED' if allowed else 'UNSAFE_OMITTED'
        for kind, prefix in (('PACKAGE', 'r1-pkg-'), ('LIBRARY_ASSET', 'r1-lib-')):
            row = _r1_row(pub, hid, prefix + str(i))
            c, n = _r1_node(bom, prov, kind, row['evidence_id'])
            assert c.get('version') == expected
            assert n['version_state'] == _r1_props(c)['pqc:b1:version_state'] == state
            assert n['version_evidence_ids'] == ([row['evidence_id']] if allowed else [])
        row = _r1_row(pub, hid, 'r1-alg-' + str(i))
        eid = row['evidence_id']
        c, n = _r1_node(bom, prov, 'ALGORITHM', eid)
        observation = prov['observations'][eid]['algorithm']
        assert n['taxonomy_version'] == observation['taxonomy_version'] == expected
        assert _r1_props(c).get('pqc:b1:taxonomy_version') == expected
        assert n['taxonomy_version_state'] == observation['taxonomy_version_state'] == state
        assert _r1_props(c)['pqc:b1:taxonomy_version_state'] == state
        assert n['taxonomy_version_sha256'] == observation['taxonomy_version_sha256'] == hashlib.sha256(version.encode('ascii')).hexdigest()


def _r1_library(doc, host, label, metadata_rows):
    lib = asset(doc, host, 'library', 'r1-library-' + label)
    scope(doc, host, 'openssl', 'r1-runtime-' + label,
          [runtime('r1-runtime-' + label, alg('ML-KEM-768', 'KEM_CAPABILITY'), True, lib)])
    for i, (state, name, version) in enumerate(metadata_rows):
        key = 'r1-meta-' + label + '-' + str(i)
        scope(doc, host, 'openssl', key, [metadata(key, name, version, lib)], state)


def test_b1_r1_failed_metadata(root):
    # The same synthetic identity on a second host is not a metadata source.
    def extra(doc, host, second):
        _r1_library(doc, host, 'mixed', [('COLLECTED' if second else 'ERROR', 'openssl', '9.9.9')])
        if not second:
            _r1_library(doc, host, 'unknown', [('UNKNOWN', 'openssl', '8.8.8')])

    pub = publish(root, populate_extra=extra)
    idx = portal_indexes.project_crypto_indexes(pub)
    a, b = [host_id(pub, t) for t in TARGETS[:2]]
    bom, prov = build(root, a)
    for label, literal in (('mixed', '9.9.9'), ('unknown', '8.8.8')):
        runtime_row = _r1_row(pub, a, 'r1-runtime-' + label)
        failed = _r1_row(pub, a, 'r1-meta-' + label + '-0')
        c, n = _r1_node(bom, prov, 'LIBRARY_ASSET', runtime_row['evidence_id'])
        assert 'version' not in c and c['name'] != 'openssl', 'failed metadata promoted via runtime row'
        assert literal not in raw(bom).decode() + raw(prov).decode()
        group = next(g for g in idx['libraries']['groups'] if g['id'] == n['portal_group_id'])
        assert group['metadata_state'] == n['portal_metadata_state'] == 'RECORDED_METADATA'
        assert n['metadata_state'] == _r1_props(c)['pqc:b1:metadata_state'] == 'METADATA_UNAVAILABLE'
        assert n['version_state'] == 'UNAVAILABLE'
        assert n['metadata_evidence_ids'] == n['name_evidence_ids'] == n['version_evidence_ids'] == []
        assert set(n['seed_evidence_ids']) == set(n['evidence_ids']) == {runtime_row['evidence_id'], failed['evidence_id']}
        assert n['presence'] == 'UNKNOWN'
        assert any(o['reason'] == 'LIBRARY_METADATA_UNAVAILABLE' and o['portal_group_id'] == group['id']
                   and failed['evidence_id'] in o['evidence_ids'] for o in prov['omitted'])
    other_bom, other = build(root, b)
    good = _r1_row(pub, b, 'r1-meta-mixed-0')['evidence_id']
    c, n = _r1_node(other_bom, other, 'LIBRARY_ASSET', good)
    assert c['version'] == '9.9.9' and c['name'] == 'openssl'
    assert n['metadata_state'] == 'RECORDED_METADATA'
    assert n['metadata_evidence_ids'] == n['name_evidence_ids'] == n['version_evidence_ids'] == [good]
    assert good not in raw(prov).decode()


def test_b1_r1_metadata_qualification_controls(root):
    cases = {
        'usable': [('COLLECTED', 'openssl', '3.6.1')],
        'partial': [('PARTIAL', 'openssl', '3.6.2a')],
        'same': [('ERROR', 'openssl', '3.6.3'), ('COLLECTED', 'openssl', '3.6.3')],
        'conflict': [('COLLECTED', 'openssl', '3.6.4'), ('PARTIAL', 'openssl', '3.6.5')],
        'failed-conflict': [('COLLECTED', 'openssl', '3.6.6'), ('ERROR', 'openssl', '3.6.7')],
        'missing': [],
        'name-only': [('COLLECTED', 'openssl', None)],
        'version-only': [('PARTIAL', None, '3.6.8')],
    }

    def extra(doc, host, second):
        if not second:
            for label, rows in cases.items():
                _r1_library(doc, host, label, rows)

    pub = publish(root, populate_extra=extra)
    hid = host_id(pub, TARGETS[0])
    bom, prov = build(root, hid)
    for label, rows in cases.items():
        runtime_eid = _r1_row(pub, hid, 'r1-runtime-' + label)['evidence_id']
        c, n = _r1_node(bom, prov, 'LIBRARY_ASSET', runtime_eid)
        qualified = sorted(_r1_row(pub, hid, 'r1-meta-' + label + '-' + str(i))['evidence_id']
                           for i, (state, _, _) in enumerate(rows) if state in ('COLLECTED', 'PARTIAL'))
        conflict = label in ('conflict', 'failed-conflict')
        expected_name = None if conflict or not rows else rows[-1][1]
        expected_version = None if conflict or not rows else rows[-1][2]
        expected_state = ('CONFLICT' if conflict else 'MISSING_METADATA' if
                          expected_name is None or expected_version is None else 'RECORDED_METADATA')
        assert c['name'] == (expected_name or n['portal_group_id'])
        assert c.get('version') == expected_version
        assert n['metadata_state'] == n['portal_metadata_state'] == expected_state
        assert n['metadata_evidence_ids'] == qualified
        assert n['name_evidence_ids'] == (qualified if expected_name else [])
        assert n['version_evidence_ids'] == (qualified if expected_version else [])
        assert n['version_state'] == ('CONFLICT' if conflict else 'RECORDED' if expected_version else 'MISSING')
        assert runtime_eid not in n['metadata_evidence_ids'] and n['presence'] == 'UNKNOWN'


def test_b1_r1_package_runtime_metadata(root):
    def extra(doc, host, second):
        lib = asset(doc, host, 'library', 'r1-package-linked')
        scope(doc, host, 'openssl', 'r1-package-runtime',
              [runtime('r1-package-runtime', alg('ML-KEM-768', 'KEM_CAPABILITY'), True, lib)])
        state = 'PARTIAL' if second else 'ERROR'
        scope(doc, host, 'packages', 'r1-package',
              [package('r1-package', 'openssl', '7.8.9', True, lib)], state)
        provider = 'openssl'
        scope(doc, host, 'openssl', portal_indexes._key('openssl-provider', provider),
              [metadata('metadata', provider, '7.8.9')], state)

    pub = publish(root, populate_extra=extra)
    for target in TARGETS[:2]:
        hid = host_id(pub, target)
        bom, prov = build(root, hid)
        pkg = _r1_row(pub, hid, 'r1-package')['evidence_id']
        meta = _r1_row(pub, hid, 'metadata')['evidence_id']
        if target == TARGETS[0]:
            assert '7.8.9' not in raw(bom).decode() + raw(prov).decode()
            assert not any(pkg in n['seed_evidence_ids'] for n in nodes(prov, 'PACKAGE').values())
            assert not any(meta in n['seed_evidence_ids'] for n in nodes(prov, 'OPENSSL_PROVIDER').values())
        else:
            for kind, eid in (('PACKAGE', pkg), ('OPENSSL_PROVIDER', meta)):
                c, n = _r1_node(bom, prov, kind, eid)
                assert c['version'] == '7.8.9'
                assert n['metadata_evidence_ids'] == n['name_evidence_ids'] == n['version_evidence_ids'] == [eid]


# B2: use the actual fixed C1/C2 producer, Store and A validator. No synthetic
# PublishedRun can enter the public generator, even in a negative control.
def _b2_build(root, hid, rid):
    with rs.RunStore(root) as store:
        b, p = generation.build_cbom_bytes(store, rid, hid, include_certificates=True)
    assert validation.validate_cbom_bytes(b) == validation.ValidationResult()
    assert raw(json.loads(b)) == b and raw(json.loads(p)) == p
    assert json.loads(p)['bom_sha256'] == hashlib.sha256(b).hexdigest()
    return json.loads(b), json.loads(p)


def _b2_component(bom, ref, subtype, block):
    c = next(x for x in bom['components'] if x['bom-ref'] == ref)
    assert c['type'] == 'cryptographic-asset' and c['cryptoProperties']['assetType'] == subtype
    return c['cryptoProperties'][block]


def test_b2_actual_c2_multihost_role_identity_and_no_writes(root, monkeypatch):
    import test_run_store_v2_certificate as c1
    from tools import portal_asset_indexes as ai
    pub = c1._c2_open(root, ('complete', 'complete'), assessed=True)
    idx = ai.project_asset_indexes(pub)
    before = c1._c2_tree(root); original = deepcopy(pub)
    def deny(*args, **kwargs):
        pytest.fail('network attempted')
    monkeypatch.setattr(socket, 'socket', deny)
    monkeypatch.setattr(urllib.request, 'urlopen', deny)
    seen_refs = set()
    for hid in pub.manifest['expected_host_ids']:
        b, p = _b2_build(root, hid, c1.RID)
        assert p['coverage']['certificate_key_scope'] == 'B2_CERTIFICATE_KEY'
        assert p['coverage']['deferred_asset_ids'] == [] and b['dependencies'] == []
        assert len(nodes(p, 'CERTIFICATE')) == len(nodes(p, 'PUBLIC_KEY')) == 2
        assert not seen_refs.intersection(p['nodes']); seen_refs.update(p['nodes'])
        expected = {r['evidence_id'] for r in pub.document['evidence'] if r['host_id'] == hid}
        assert set(p['observations']) == expected
        for ref, n in nodes(p, 'CERTIFICATE').items():
            g = next(g for g in idx['certificates']['groups'] if g['id'] == n['portal_group_id'])
            occ = {oid: idx['occurrences'][oid] for oid in g['recorded_occurrence_ids']
                   if idx['occurrences'][oid]['host_id'] == hid}
            assert n['certificate_fingerprint_sha256'] == g['fingerprint']
            assert n['identity_basis'] == 'RECORDED_FINGERPRINT'
            assert set(n['recorded_occurrence_ids']) == set(n['verified_occurrence_ids']) == set(occ)
            assert len(occ) == (3 if g['fingerprint'] == c1.digest('public-fixture-0') else 1)
            assert set(n['asset_ids']) == {o['asset_id'] for o in occ.values()}
            assert set(n['evidence_ids']) == set(g['evidence_ids']) & expected
            assert set(n['occurrences']) == set(occ)
            for oid, proof in n['occurrences'].items():
                assert proof == {k: occ[oid][k] for k in ('asset_id', 'collection_id', 'detail_sha256',
                                                         'detail_state', 'role_evidence_ids')}
            cp = _b2_component(b, ref, 'certificate', 'certificateProperties')
            assert cp['notValidBefore'] == c1.START and cp['notValidAfter'] == '2027-01-01T00:00:00Z'
            assert n['validity_state'] == 'RECORDED' and set(n['validity_occurrence_ids']) == set(occ)
            assert 'issuerName' not in cp and 'subjectName' not in cp
            key_ref = cp['subjectPublicKeyRef']; sig_ref = cp['signatureAlgorithmRef']
            key = p['nodes'][key_ref]
            kp = _b2_component(b, key_ref, 'related-crypto-material', 'relatedCryptoMaterialProperties')
            assert key['identity_basis'] == 'CERTIFICATE_BOUND_SUBJECT_KEY'
            assert key['certificate_ref'] == ref and key['key_fingerprint_sha256'] is None
            assert kp['type'] == 'public-key' and kp['size'] == 2048 and 'value' not in kp
            assert set(key['size_occurrence_ids']) == set(occ)
            assert p['nodes'][sig_ref]['primitive'] == 'SIGNATURE'
            assert p['nodes'][kp['algorithmRef']]['primitive'] == 'PUBLIC_KEY'
            sig_ids = {o['role_evidence_ids']['signature'] for o in occ.values()}
            key_ids = {o['role_evidence_ids']['public-key'] for o in occ.values()}
            assert set(n['signature_role']['evidence_ids']) == sig_ids
            assert set(key['evidence_ids']) == key_ids
            for fr, to, kind, ids in ((ref, sig_ref, 'CERTIFICATE_SIGNATURE_ALGORITHM', sig_ids),
                    (ref, key_ref, 'CERTIFICATE_SUBJECT_PUBLIC_KEY', key_ids),
                    (key_ref, kp['algorithmRef'], 'PUBLIC_KEY_ALGORITHM', key_ids)):
                assert {r['evidence_id'] for r in p['relationships'] if
                        (r['from'], r['to'], r['kind']) == (fr, to, kind)} == ids
        assert {r['kind'] for r in p['relationships']} == {'CERTIFICATE_SIGNATURE_ALGORITHM',
            'CERTIFICATE_SUBJECT_PUBLIC_KEY', 'PUBLIC_KEY_ALGORITHM'}
        text = raw(b).decode() + raw(p).decode()
        assert all(x not in text for x in ('CN=Fixture issuer', 'CN=Fixture certificate', *c1.TARGETS))
        assert all(o['target_id'] not in text and o['source_id'] not in text
                   for o in idx['occurrences'].values())
    hid = pub.manifest['expected_host_ids'][0]
    first = _b2_build(root, hid, c1.RID)
    assert _b2_build(root, hid, c1.RID) == first
    with rs.RunStore(root) as store:
        assert generation.build_cbom(store, c1.RID, hid, include_certificates=True) == first
        old = generation.build_cbom_bytes(store, c1.RID, hid)
        assert generation.build_cbom_bytes(store, c1.RID, hid, include_certificates=False) == old
        assert json.loads(old[1])['coverage']['certificate_key_scope'] == 'DEFERRED_B2'
        assert not nodes(json.loads(old[1]), 'CERTIFICATE') and not nodes(json.loads(old[1]), 'PUBLIC_KEY')
        assert store.open(c1.RID) == pub
    assert pub == original and c1._c2_tree(root) == before


@pytest.mark.parametrize('variant', ['disjoint-dates', 'conflict', 'unknown', 'unknown-role'])
def test_b2_actual_c2_host_local_metadata_and_gaps(root, monkeypatch, variant):
    import test_run_store_v2_certificate as c1
    original = c1.envelope
    def varied(target, mode='complete', *, large=False):
        env = original(target, mode, large=large)
        for value in env['records'][1]['snapshot']['roots'].values():
            for src in value['sources']:
                for block in src['blocks']:
                    cert = block['certificate']
                    if variant == 'disjoint-dates':
                        cert['not_after' if target == c1.TARGETS[0] else 'not_before'] = None
                    elif target == c1.TARGETS[1] and variant == 'conflict':
                        cert.update(issuer='CN=' + SECRET, public_key_bits=4096,
                                    signature_outer='sha384WithRSAEncryption', not_before='2028-01-01T00:00:00Z')
                    elif target == c1.TARGETS[1] and variant == 'unknown-role':
                        cert.update(public_key_algorithm='opaque-fixture-key',
                                    signature_inner='opaque-fixture-signature',
                                    signature_outer='opaque-fixture-signature')
                    elif target == c1.TARGETS[1]:
                        cert.update(public_key_algorithm=None, public_key_bits=None,
                                    signature_inner=None, signature_outer=None)
                    cert['gaps'] = c1.ca.metadata_gaps(cert)
                    block['reason'] = 'METADATA_GAP' if cert['gaps'] else 'OK'
        return env
    monkeypatch.setattr(c1, 'envelope', varied)
    pub = c1._c2_open(root, ('complete', 'complete'))
    for i, target in enumerate(c1.TARGETS[:2]):
        b, p = _b2_build(root, host_id(pub, target), c1.RID)
        for ref, n in nodes(p, 'CERTIFICATE').items():
            cp = _b2_component(b, ref, 'certificate', 'certificateProperties')
            if variant == 'disjoint-dates':
                assert n['validity_state'] == 'PARTIAL' and n['validity_occurrence_ids'] == []
                assert ('notValidBefore' in cp) == (i == 0)
                assert ('notValidAfter' in cp) == (i == 1)
                assert n['field_support']['not_before']['state'] == ('RECORDED' if i == 0 else 'UNKNOWN')
                assert n['field_support']['not_after']['state'] == ('UNKNOWN' if i == 0 else 'RECORDED')
            elif i == 1 and variant == 'conflict':
                assert n['validity_state'] == 'CONFLICT' and n['validity_occurrence_ids'] == []
                assert n['signature_role']['state'] == 'CONFLICT'
                assert not {'notValidBefore', 'notValidAfter', 'signatureAlgorithmRef'} & cp.keys()
                assert {'SIGNATURE_CONFLICT', 'VALIDITY_CONFLICT'} <= set(n['metadata_gaps'])
            else:
                assert n['validity_state'] == 'RECORDED'
                assert cp['notValidBefore'] == c1.START and cp['notValidAfter'] == '2027-01-01T00:00:00Z'
            if variant in ('unknown', 'unknown-role') and i == 1:
                assert not {'subjectPublicKeyRef', 'signatureAlgorithmRef'} & cp.keys()
                assert n['public_key_role']['state'] == n['signature_role']['state'] == 'UNKNOWN'
                if variant == 'unknown':
                    assert not nodes(p, 'PUBLIC_KEY')
                else:
                    kref, key = next((r, k) for r, k in nodes(p, 'PUBLIC_KEY').items()
                                      if k['certificate_ref'] == ref)
                    assert key['key_fingerprint_sha256'] is None and key['algorithm_state'] == 'UNKNOWN'
                    assert _b2_component(b, kref, 'related-crypto-material',
                        'relatedCryptoMaterialProperties') == {'type': 'public-key', 'size': 2048}
            else:
                kp = _b2_component(b, cp['subjectPublicKeyRef'], 'related-crypto-material', 'relatedCryptoMaterialProperties')
                assert kp['size'] == (4096 if variant == 'conflict' and i == 1 else 2048)
                if not (variant == 'conflict' and i == 1):
                    assert 'signatureAlgorithmRef' in cp
        assert all(v not in raw(b).decode() + raw(p).decode() for v in
                   (SECRET, 'opaque-fixture-key', 'opaque-fixture-signature'))


def test_b2_actual_coverage_disabled_unreachable_missing(root):
    import test_run_store_v2_certificate as c1
    pub = c1._c2_open(root, ('complete', 'disabled', 'connection'))
    for i, target in enumerate(c1.TARGETS):
        b, p = _b2_build(root, host_id(pub, target), c1.RID)
        cov = next(r for r in p['coverage']['certificate_collections'] if r['slot'] == 'system_certs')
        assert cov['detail_slot_state'] == ('VERIFIED_COMPANION', 'NOT_REQUIRED', 'REQUIRED_DETAIL_MISSING')[i]
        if i:
            assert not nodes(p, 'CERTIFICATE') and not nodes(p, 'PUBLIC_KEY')
            assert b['components'] == b['dependencies'] == []
            assert cov['state'] == ('NOT_SCANNED' if i == 1 else 'UNREACHABLE')
            assert cov['requested'] is (i == 2)


def test_b2_actual_standalone_ssh_and_unqualified_metadata(root):
    from tools import ssh_posture as ssh
    rid, target = 'b2-ssh-fixture', TARGETS[0]
    source = dict(source_kind='SYNTHETIC', producer_id=ssh.PRODUCER, producer_version=ssh.VERSION,
                  origin_ref='fixture', input_sha256=None)
    fp = hashlib.sha256(b'fixture-public-key').hexdigest()
    snapshot = dict(flags=dict(zip(ssh.FLAGS, (False, True))), platform_status='UNVERIFIED',
                    context_refs=['global-default'], slots={})
    for slot in ssh.slots(snapshot):
        snapshot['slots'][slot] = dict(state='NOT_SCANNED', reason='DISABLED_BY_USER', rc=None, rows=[], gaps=[])
    snapshot['slots']['keys'] = dict(state='PARTIAL', reason='KEY_GAP', rc=None, gaps=['KEY_TYPE_UNKNOWN'], rows=sorted([
        dict(source_ref=ssh.digest('key', ['fixture', 1]), key_type='ssh-ed25519', bits=256,
             fingerprint_sha256=fp, grammar='KNOWN'),
        dict(source_ref=ssh.digest('key', ['fixture', 2]), key_type='ssh-unknown-fixture', bits=None,
             fingerprint_sha256=hashlib.sha256(b'fixture-unknown-key').hexdigest(), grammar='UNKNOWN_TYPE')],
        key=lambda r: r['source_ref']))
    # The original R V2 Store is certificate-only, and S1 binds short IDs.
    # Generate the exact #17 typed asset/metadata first, then explicitly
    # publish its synthetic S1 representation, not a fake native handoff.
    flags = {f: f == 'ssh_host_keys' for f in rs.COLLECTORS}
    with rs.RunStore(root) as store, store.begin(run_id=rid, run_kind='SYNTHETIC',
            evidence_schema_version='1.1.0', source=source, started_at=STAMP, recorded_at=END,
            expected_hosts=[dict(target_id=target, inventory_authority_id=None, identity_key=target)],
            limits=LIMITS, profile='baseline', requested_flags={target: flags},
            requirements=dict(assessment=False, cff=False, details=[])) as w:
        s = w.scope; h = s['hosts'][0]; h.update(host_state='PARTIAL', reason_code='INCOMPLETE_COLLECTION')
        doc = rs._doc(s, [h], 'PARTIAL', finished_at=END, coverage_reason='INCOMPLETE_COLLECTION')
        original, detail = ssh.normalize_ssh(doc, h['host_id'], snapshot, source, STAMP, RULES)
        original_keys = {a['asset_id']: a for a in original['assets']}
        assert len(original_keys) == 1
        key_scope = next(c for c in original['collections'] if c['scope_key'] == 'ssh-keys')
        records = []
        for r in original['evidence']:
            if r['collection_id'] != key_scope['collection_id'] or r['evidence_kind'] != 'ASSET_METADATA':
                continue
            a = None
            if r['asset_id'] is not None:
                a = asset(doc, h, 'public_key', original_keys[r['asset_id']]['identity_key'])
                assert a['asset_id'] == r['asset_id']
            records.append((r['observation_key'], r['evidence_kind'], r['data'], r['algorithm'], a))
        scope(doc, h, 'ssh_host_keys', 'ssh-keys', records, 'PARTIAL')
        fake = asset(doc, h, 'public_key', 'sha256-' + '9' * 64)
        scope(doc, h, 'ssh_host_keys', 'failed-keys', [metadata('public-' + '8' * 64, fake['identity_key'], None, fake)], 'ERROR')
        # A usable generic asset is also not #17's typed source.
        generic = asset(doc, h, 'public-key', 'sha256-' + '7' * 64)
        scope(doc, h, 'ssh_host_keys', 'generic-keys', [metadata('other-key', generic['identity_key'], None, generic)])
        doc = json.loads(e.canonical_bytes(doc))
        terminal = dict(target_id=target, host_state='PARTIAL', attempted=True,
            reason_code='INCOMPLETE_COLLECTION', collectors=[dict(collector_id=f,
                requested=flags[f], state='PARTIAL' if flags[f] else 'NOT_SCANNED',
                reason_code='INCOMPLETE_COLLECTION' if flags[f] else 'DISABLED',
                rc=0 if flags[f] else None, collection_ids=sorted(c['collection_id']
                    for c in doc['collections'] if c['collector_id'] == f)) for f in sorted(flags)])
        w.dispatch_intent(h['host_id'])
        w.record_host(rs.host_fragment(doc, h['host_id']), attempted=True, terminal=terminal)
        batch = raw(dict(batch_manifest_version=1, target_ids=[target], target_count=1,
            limits=LIMITS, profile='baseline', run_state='PARTIAL', reason_code='INCOMPLETE_COLLECTION',
            hosts=[terminal]))
        w.finalize(doc, batch_raw=batch, batch_rc=5)
    b, p = _b2_build(root, h['host_id'], rid)
    assert len(nodes(p, 'PUBLIC_KEY')) == 1 and not nodes(p, 'CERTIFICATE')
    ref, n = next(iter(nodes(p, 'PUBLIC_KEY').items()))
    assert n['identity_basis'] == 'SYNTHETIC_S1_RECORDED_PUBLIC_KEY_FINGERPRINT'
    assert n['key_fingerprint_sha256'] == fp
    assert n['algorithm_state'] == n['size_state'] == 'UNKNOWN'
    assert _b2_component(b, ref, 'related-crypto-material', 'relatedCryptoMaterialProperties') == {'type': 'public-key'}
    assert not p['relationships'] and not b['dependencies']
    assert {aid for o in p['omitted'] if o['reason'] == 'STANDALONE_PUBLIC_KEY_UNAVAILABLE'
            for aid in o['asset_ids']} == {fake['asset_id'], generic['asset_id']}
    with rs.RunStore(root) as store:
        _, old = generation.build_cbom(store, rid, h['host_id'])
    assert not nodes(old, 'PUBLIC_KEY') and len(old['coverage']['deferred_asset_ids']) == 3


def test_b2_actual_legacy_certificate_unknown_and_cff(root):
    from tools import cff
    rid, target = 'b2-legacy-fixture', TARGETS[0]
    legacy_raw = b'{"fixture":"anonymous B2 legacy bytes"}'
    source = dict(source_kind='LEGACY_IMPORT', producer_id='legacy-per-host', producer_version='1.0.0',
                  origin_ref='fixture', input_sha256=hashlib.sha256(legacy_raw).hexdigest())
    with rs.RunStore(root) as store, store.begin(run_id=rid, run_kind='LEGACY_IMPORT',
            evidence_schema_version='1.0.0', source=source, started_at=STAMP, recorded_at=END,
            expected_hosts=[dict(target_id=target, inventory_authority_id=None, identity_key=target)],
            requirements=dict(assessment=True, cff=True, details=[]), legacy_raw=legacy_raw,
            legacy_provenance=dict(format_version='1.0.0', source=source, original_run_id=None,
                                   original_generated_at=None, diagnostics=[])) as w:
        s = w.scope; h = s['hosts'][0]; h.update(host_state='PARTIAL', reason_code='INCOMPLETE_COLLECTION')
        doc = rs._doc(s, [h], 'PARTIAL', finished_at=END, coverage_reason='INCOMPLETE_COLLECTION')
        cert = asset(doc, h, 'certificate', 'legacy-opaque-identity')
        scope(doc, h, 'legacy-import', 'system-certificates', [
            metadata('legacy-' + 'a' * 64, 'system-certificates', None, cert),
            ('legacy-key', 'LEGACY_OBSERVATION', dict(field='public-key-algorithm', value='rsaEncryption'),
             alg('rsaEncryption', 'CERT_PUBLIC_KEY'), cert),
            ('legacy-key-conflict', 'LEGACY_OBSERVATION', dict(field='public-key-type', value='id-ecPublicKey'),
             alg('id-ecPublicKey', 'CERT_PUBLIC_KEY'), cert),
            ('legacy-signature', 'LEGACY_OBSERVATION', dict(field='signature-algorithm', value='sha256WithRSAEncryption'),
             alg('sha256WithRSAEncryption', 'SIGNATURE'), cert),
            ('legacy-bits', 'LEGACY_OBSERVATION', dict(field='public-key-bits', value=4096), None, cert)], 'PARTIAL')
        doc = json.loads(e.canonical_bytes(doc)); assessed = assessment.evaluate_document(doc, RULES)
        w.record_host(rs.host_fragment(doc, h['host_id']), attempted=None, terminal=None)
        w.finalize(doc, assessed=assessed, rules_raw=RULES_RAW, cff=cff.project_cff(assessed, RULES))
    b, p = _b2_build(root, h['host_id'], rid)
    assert p['coverage']['cff_state'] == 'VERIFIED_SAVED_PAIR'
    ref, n = next(iter(nodes(p, 'CERTIFICATE').items()))
    assert n['identity_basis'] == 'LEGACY_RUN_SCOPED' and n['certificate_fingerprint_sha256'] is None
    assert n['validity_state'] == 'UNKNOWN' and n['verified_occurrence_ids'] == []
    assert n['public_key_role']['state'] == 'CONFLICT' and n['signature_role']['state'] == 'UNVERIFIED'
    assert _b2_component(b, ref, 'certificate', 'certificateProperties') == {}
    ref, n = next(iter(nodes(p, 'PUBLIC_KEY').items()))
    assert n['key_fingerprint_sha256'] is None and n['size_occurrence_ids'] == []
    assert _b2_component(b, ref, 'related-crypto-material', 'relatedCryptoMaterialProperties') == {'type': 'public-key'}
    assert not p['relationships'] and not b['dependencies']


def test_b2_actual_foreign_tampered_companion_and_mode(root):
    import test_run_store_v2_certificate as c1
    pub = c1._c2_open(root, ('complete', 'complete'))
    hid, foreign = pub.manifest['expected_host_ids']
    with rs.RunStore(root) as store:
        for value in (0, 1, None, 'true', [], {}):
            with pytest.raises(generation.CBOMGenerationError, match='CBOM_INPUT_TYPE'):
                generation.build_cbom_bytes(store, c1.RID, hid, include_certificates=value)
        with pytest.raises(generation.CBOMGenerationError, match='CBOM_INPUT_TYPE'):
            generation.build_cbom(pub, c1.RID, hid, include_certificates=True)
        with pytest.raises(generation.CBOMGenerationError, match='CBOM_HOST_NOT_FOUND'):
            generation.build_cbom_bytes(store, c1.RID, 'h-' + '0' * 64, include_certificates=True)
    path = root / c1.RID
    manifest = deepcopy(pub.manifest)
    relative = f'details/{hid}/{c1.v2.CERTIFICATE}.json'
    content = json.loads(pub.artifacts[relative]); content['occurrences'][0]['host_id'] = foreign
    c1.reindex(path, manifest, relative, c1.ca.canonical(content))
    (path / 'run_manifest.json').write_bytes(raw(manifest))
    with rs.RunStore(root) as store:
        with pytest.raises(generation.CBOMGenerationError, match='CBOM_SOURCE_INVALID'):
            generation.build_cbom_bytes(store, c1.RID, hid, include_certificates=True)


def test_b2_actual_validator_typed_reference_and_combined_caps(root, monkeypatch):
    import test_run_store_v2_certificate as c1
    pub = c1._c2_open(root, ('complete',))
    hid = pub.manifest['expected_host_ids'][0]
    before = c1._c2_tree(root)
    b, p = _b2_build(root, hid, c1.RID)
    with rs.RunStore(root) as store:
        # A cap that permits B1 must still reject the additional B2 work.
        baseline = generation._Projection(store.open(c1.RID), hid)
        baseline.finish()
        with monkeypatch.context() as m:
            m.setattr(generation, 'MAX_MEMBERSHIPS', baseline.cost)
            generation.build_cbom_bytes(store, c1.RID, hid)
            with pytest.raises(generation.CBOMGenerationError, match='CBOM_MEMBERSHIP_LIMIT'):
                generation.build_cbom_bytes(store, c1.RID, hid, include_certificates=True)
        for cap, limit, code in (('MAX_BYTES', len(raw(b)) + len(raw(p)) - 1, 'CBOM_SIZE_LIMIT'),
                                 ('MAX_MEMBERSHIPS', 5, 'CBOM_MEMBERSHIP_LIMIT')):
            with monkeypatch.context() as m:
                m.setattr(generation, cap, limit)
                with pytest.raises(generation.CBOMGenerationError, match=code):
                    generation.build_cbom_bytes(store, c1.RID, hid, include_certificates=True)
        original = generation._Projection.finish
        for field, mode, code in (('signatureAlgorithmRef', 'foreign', 'REFERENCE_DANGLING'),
                                  ('signatureAlgorithmRef', 'key', 'REFERENCE_TYPE'),
                                  ('subjectPublicKeyRef', 'algorithm', 'REFERENCE_TYPE'),
                                  ('algorithmRef', 'certificate', 'REFERENCE_TYPE')):
            def invalid(self):
                bom, prov = original(self)
                cert = next(x for x in bom['components'] if x['cryptoProperties']['assetType'] == 'certificate')
                cp = cert['cryptoProperties']['certificateProperties']
                key = next(x for x in bom['components'] if x['bom-ref'] == cp['subjectPublicKeyRef'])
                targets = {'foreign': 'cbom-' + '0' * 64, 'key': key['bom-ref'],
                           'algorithm': cp['signatureAlgorithmRef'], 'certificate': cert['bom-ref']}
                if field == 'algorithmRef':
                    key['cryptoProperties']['relatedCryptoMaterialProperties'][field] = targets[mode]
                else:
                    cp[field] = targets[mode]
                return bom, prov
            with monkeypatch.context() as m:
                m.setattr(generation._Projection, 'finish', invalid)
                with pytest.raises(generation.CBOMGenerationError, match=code):
                    generation.build_cbom_bytes(store, c1.RID, hid, include_certificates=True)
    assert c1._c2_tree(root) == before


def test_b2_actual_s1_opaque_certificate_preserves_b1_graph(root):
    pub = publish(root, cff=True)
    for target in TARGETS[:2]:
        hid = host_id(pub, target)
        old, op = build(root, hid)
        b, p = _b2_build(root, hid, RID)
        assert p['coverage']['cff_state'] == op['coverage']['cff_state'] == 'VERIFIED_SAVED_PAIR'
        assert p['coverage']['cff_sha256'] == op['coverage']['cff_sha256']
        assert p['claims'] == op['claims'] and p['observations'] == op['observations']
        assert b['dependencies'] == old['dependencies'] and b['services'] == old['services']
        assert p['relationships'] == op['relationships']
        assert all(p['nodes'][ref] == n for ref, n in op['nodes'].items())
        assert all(x in b['components'] for x in old['components'])
        ref, n = next(iter(nodes(p, 'CERTIFICATE').items()))
        assert len(nodes(p, 'CERTIFICATE')) == 1 and not nodes(p, 'PUBLIC_KEY')
        assert n['identity_basis'] == 'UNVERIFIED_IDENTITY' and n['certificate_fingerprint_sha256'] is None
        assert n['recorded_occurrence_ids'] == n['verified_occurrence_ids'] == []
        assert n['validity_state'] == 'UNKNOWN' and n['public_key_role']['state'] == 'UNKNOWN'
        assert _b2_component(b, ref, 'certificate', 'certificateProperties') == {}
        assert p['coverage']['deferred_asset_ids'] == []
        assert op['coverage']['deferred_asset_ids'] == n['asset_ids']
        assert SECRET not in raw(b).decode() + raw(p).decode()
