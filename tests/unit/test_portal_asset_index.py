"""Focused #22 A: actual Store publications and original #18 typed projection.

The fixed Store cannot bind pqc-cert-assets long collector terminals or its
native companion. Exercise exact producer records at the same pure grouping
functions used by the public API, and prove Store rejection explicitly.
Never manufacture a PublishedRun to bypass that boundary.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from urllib.parse import urlsplit

import pytest

from test_portal_crypto_index import (RULESET, classified, new_asset, add_scope, record,
                                      runtime, tree_state, MALICIOUS)
from test_portal_overview import ROOT, RID, STAMP, END, LIMITS, RULES, Page, root, raw, options, publish, e, rs, assessment, portal
from test_cert_assets import doc as cert_doc, build as cert_build, merged as cert_merge, source as cert_source, platform_snapshot
from tools import cert_assets as ca, portal_asset_indexes as ai, portal_indexes as crypto, run_catalog as catalog


def sha(value):
    return hashlib.sha256(value.encode('ascii')).hexdigest()


FP = sha('anonymous-public-certificate-a')
FP2 = sha('anonymous-public-certificate-b')


def certificate(fp, key='rsaEncryption', signature='sha256WithRSAEncryption'):
    value = dict(fingerprint=fp, public_key_algorithm=key, public_key_bits=2048,
                 signature_inner=signature, signature_outer=signature,
                 issuer='CN=Fixture issuer', subject='CN=Fixture certificate',
                 not_before='2026-01-01T00:00:00Z', not_after='2027-01-01T00:00:00Z')
    return value | {'gaps': ca.metadata_gaps(value)}


def snapshot(*, conflict=False, omit_signature=False):
    a = certificate(FP, key='id-ecPublicKey' if conflict else 'rsaEncryption')
    b = certificate(FP2)
    if omit_signature:
        b.update(signature_outer='ecdsa-with-SHA256')
        b['gaps'] = ca.metadata_gaps(b)
    def source(name, certs):
        return dict(source_id='src-' + sha(name), target_id='src-' + sha(name + '-target'),
            format='PEM', gaps=[], blocks=[dict(rc=0, reason='METADATA_GAP' if c['gaps'] else 'OK',
            certificate=c) for c in certs])
    sources = sorted([source('bundle', [a, b, a]), source('second', [a])], key=lambda x: x['source_id'])
    return {k: dict(attempted=True, rc=0, entries=len(sources) if i == 0 else 0,
                    directories=0, skipped=0, root_target_id='src-' + sha(ca.ROOT_PATHS[k]), gaps=[],
                    sources=sources if i == 0 else []) for i, k in enumerate(ca.ROOTS)}


def exact_cert_doc(*, conflict=False, source_kind='SYNTHETIC', omit_signature=False):
    first = cert_doc(run=RID, target='fixture-0.example.invalid', stable=True)
    second = cert_doc(run=RID, target='fixture-1.example.invalid', stable=True)
    d = deepcopy(first)
    d['run']['source']['source_kind'] = source_kind
    d['hosts'] += second['hosts']; d['run']['expected_host_ids'] += second['run']['expected_host_ids']
    # Original #18 builder validates the typed snapshot, projection and
    # companion. These typed fixture values are not native acquisition proof.
    details = []
    for i, h in enumerate(d['hosts']):
        s = dict(cert_source(), source_kind=source_kind)
        snap = snapshot(conflict=conflict and i == 1, omit_signature=omit_signature)
        r = ca.build_cert_assets(d, h['host_id'], source=s, observed_at=STAMP, snapshot=snap,
            rules=RULESET, requested=True, platform_snapshot=platform_snapshot(),
            system_python_available=True)
        d = cert_merge(d, r); details.append(r['details'])
    e.validate_document(d)
    for detail in details:
        ca.validate_cert_details(d, detail, RULESET)
    return json.loads(e.canonical_bytes(d)), details


def cert_part(d):
    budget = ai._Budget()
    occ = ai._certificate_occurrences(d, budget)
    groups, membership = ai._certificate_groups(d, occ, budget)
    return occ, groups, membership


@pytest.mark.parametrize('kind', ['SYNTHETIC', 'NATIVE_COLLECTOR'])
def test_exact_producer_multihost_fingerprint_positions(kind):
    doc, details = exact_cert_doc(source_kind=kind)
    before = deepcopy(doc)
    occ, groups, members = cert_part(doc)
    expected = [r for d in details for r in d['occurrences']]
    assert len(occ) == len(expected) == 8
    keys = ('host_id', 'asset_id', 'collection_id', 'root', 'source_id', 'block_index', 'fingerprint', 'evidence_ids', 'observed_at')
    assert {json.dumps({k: r[k] for k in keys}, sort_keys=True) for r in occ.values()} == {
        json.dumps({k: r[k] for k in keys}, sort_keys=True) for r in expected}
    assert {r['detail_sha256'] for r in occ.values()} == {r['detail_sha256'] for r in expected}
    assert all(r['target_id'] is r['path'] is r['vhost'] is None and r['reason_code'] == 'DETAIL_NOT_RETAINED' for r in occ.values())
    assert len(groups) == 2 and len(members) == 4
    for fp, count in [(FP, 6), (FP2, 2)]:
        g = next(g for g in groups.values() if g['fingerprint'] == fp)
        assert g['kind'] == 'RECORDED_FINGERPRINT' and g['source_kind'] == kind
        assert len(g['host_ids']) == len(g['asset_ids']) == 2
        assert len(g['recorded_occurrence_ids']) == count and len(g['evidence_ids']) == count * 3
        assert g['public_key']['state'] == g['signature']['state'] == 'RECORDED'
        assert g['not_before'] is g['not_after'] is g['public_key_bits'] is None
        assert g['validity_state'] == 'UNKNOWN' and g['detail_state'] == 'DETAIL_NOT_RETAINED'
        assert g['service_group_ids'] == [] and g['service_binding_state'] == 'UNKNOWN'
    assert doc == before and cert_part(doc) == (occ, groups, members)


def test_recorded_role_conflict_and_missing_signature():
    d, _ = exact_cert_doc(conflict=True, omit_signature=True)
    occ, groups, _ = cert_part(d)
    a = next(g for g in groups.values() if g['fingerprint'] == FP)
    b = next(g for g in groups.values() if g['fingerprint'] == FP2)
    assert len(occ) == 8 and a['public_key']['state'] == 'CONFLICT'
    assert b['signature'] == {'state': 'UNKNOWN', 'evidence_ids': []}
    assert a['signature']['state'] == 'RECORDED' and a['public_key_bits'] is None


@pytest.mark.parametrize('fault', ['source', 'hash', 'ref', 'role', 'base-role', 'producer-version'])
def test_wrong_recorded_occurrence_is_not_promoted(fault):
    d, _ = exact_cert_doc()
    occ, _, _ = cert_part(d)
    target = next(iter(occ.values()))
    rows = {r['evidence_id']: r for r in d['evidence']}
    base = rows[target['role_evidence_ids']['certificate']]
    role = rows[target['role_evidence_ids']['signature']]
    if fault == 'source':
        role['source']['origin_ref'] = 'different-fixture-origin'
    elif fault == 'hash':
        role['raw_sha256'] = sha('different-record'); role['evidence_ref'] = 'cert-' + role['raw_sha256']
    elif fault == 'ref':
        role['evidence_ref'] = 'cert-' + sha('different-reference')
    elif fault == 'role':
        role['algorithm'] = classified('rsaEncryption', 'CERT_PUBLIC_KEY')
    elif fault == 'base-role':
        base['algorithm'] = classified('rsaEncryption', 'CERT_PUBLIC_KEY')
    else:
        c = next(c for c in d['collections'] if c['collection_id'] == base['collection_id'])
        c['collector_version'] = c['source']['producer_version'] = '9.9.9'
        for eid in c['evidence_ids']:
            rows[eid]['source']['producer_version'] = '9.9.9'
    e.validate_document(d)
    result, groups, _ = cert_part(d)
    assert target['id'] not in result and len(result) < len(occ)
    assert all(target['id'] not in g['recorded_occurrence_ids'] for g in groups.values())
    assert all(role['evidence_id'] not in g['signature']['evidence_ids'] for g in groups.values())
    assert role['evidence_id'] in set().union(*(g['evidence_ids'] for g in groups.values()))


def test_cross_root_source_conflict_is_not_promoted():
    d, _ = exact_cert_doc()
    before, _, _ = cert_part(d)
    target = next(o for o in before.values() if o['block_index'] == 2)
    hid, sid = target['host_id'], target['source_id']
    collections = {c['collection_id']: c for c in d['collections']}
    old = collections[target['collection_id']]
    new = next(c for c in collections.values() if c['host_id'] == hid and c is not old)
    assets = {a['asset_id']: a for a in d['assets']}
    # Disjoint block numbers must not let the same source span two roots.
    for r in d['evidence']:
        if r['evidence_id'] not in target['evidence_ids']:
            continue
        prior = r['evidence_id']
        eid = e.evidence_id(RID, hid, new['collection_id'], r['observation_key'])
        r.update(evidence_id=eid, collection_id=new['collection_id'])
        old['evidence_ids'].remove(prior); new['evidence_ids'].append(eid)
        refs = assets[r['asset_id']]['evidence_ids']
        refs[refs.index(prior)] = eid
    e.validate_document(d)
    actual, _, _ = cert_part(d)
    assert set(actual) == {oid for oid, o in before.items()
                           if (o['host_id'], o['source_id']) != (hid, sid)}


@pytest.mark.parametrize('fault', ['cross-host', 'duplicate'])
def test_original_evidence_validator_rejects_foreign_or_duplicate_records(fault):
    d, _ = exact_cert_doc()
    if fault == 'duplicate':
        d['evidence'].append(deepcopy(d['evidence'][0]))
    else:
        a = d['assets'][0]
        foreign = next(r for r in d['evidence'] if r['host_id'] != a['host_id'] and r['asset_id'] is not None)
        a['evidence_ids'].append(foreign['evidence_id'])
    with pytest.raises(e.EvidenceError):
        e.validate_document(d)


def test_actual_store_long_certificate_producer_and_companion_gap(root):
    args = options(('PARTIAL',)); args['evidence_schema_version'] = '1.1.0'
    for flags in args['requested_flags'].values():
        flags.update(system_certs=True)
    with rs.RunStore(root) as store, store.begin(**args) as writer:
        scope = writer.scope; h = scope['hosts'][0]
        h.update(host_state='PARTIAL', reason_code='INCOMPLETE_COLLECTION')
        d = rs._doc(scope, [h], 'PARTIAL', finished_at=END, coverage_reason='INCOMPLETE_COLLECTION')
        r = cert_build(d, snapshot(), RULESET, observed_at=STAMP)
        d = cert_merge(d, r); e.validate_document(d)
        assert len(cert_part(d)[0]) == 4
        hid = h['host_id']; writer.dispatch_intent(hid)
        terminal = dict(target_id=h['target_id'], host_state='PARTIAL', attempted=True,
                        reason_code='INCOMPLETE_COLLECTION', collectors=[])
        for short, requested in sorted(scope['flags'][hid].items()):
            refs = [c['collection_id'] for c in d['collections']] if short == 'system_certs' else []
            terminal['collectors'].append(dict(collector_id=short, requested=requested,
                state='COLLECTED' if refs else 'ERROR' if requested else 'NOT_SCANNED',
                reason_code='COLLECTED' if refs else 'COMMAND_FAILED' if requested else 'DISABLED',
                rc=0 if refs else 1 if requested else None, collection_ids=sorted(refs)))
        with pytest.raises(rs.StoreError, match='FOREIGN_COLLECTOR'):
            writer.record_host(rs.host_fragment(d, hid), attempted=True, terminal=terminal)
        with pytest.raises(rs.StoreError, match='INVALID_SHAPE'):
            rs._detail(scope, d, r['details'])
    assert not (root / RID / 'run_manifest.json').exists()


def synthetic_assets(doc, host, second):
    # S1 short collector records intentionally are NOT exact #18 provenance.
    hid = host['host_id']; pk = classified('rsaEncryption', 'CERT_PUBLIC_KEY')
    sig = classified('sha256WithRSAEncryption', 'SIGNATURE')
    for i, fp in enumerate((FP, FP2) if not second else (FP,)):
        a = new_asset(doc, host, 'certificate', fp)
        prefix = 'src-' + sha('s1-fixture-' + str(i)) + '-1-'
        rows = [record(prefix + 'certificate', 'ASSET_METADATA', dict(name=fp, version=None), None, a),
                record(prefix + 'public-key', 'ASSET_METADATA', dict(name=fp, version=None), pk, a),
                record(prefix + 'signature', 'ASSET_METADATA', dict(name=fp, version=None), sig, a)]
        add_scope(doc, host, 'system_certs', 'system-tls-certs-' + str(i), rows)
        for row in doc['evidence'][-3:]:
            row['raw_sha256'] = sha('fixture-record-' + str(i)); row['evidence_ref'] = 'cert-' + row['raw_sha256']
    key = new_asset(doc, host, 'public-key', 'fixture-host-key')
    add_scope(doc, host, 'ssh_host_keys', 'ssh-host-keys', [record('host-key', 'ASSET_METADATA',
        dict(name='fixture-key', version=None), pk, key)])
    ssh = classified('mlkem768x25519-sha256', 'SSH_KEX')
    service = new_asset(doc, host, 'service', 'fixture-service')
    configs = new_asset(doc, host, 'service', 'fixture-config-only')
    neg = dict(host_id=hid, service_asset_id=service['asset_id'], endpoint_ref='fixture-endpoint',
               protocol='SSH', context_ref='fixture-context', authorization_ref='fixture-authorized')
    use = dict(host_id=hid, service_asset_id=service['asset_id'], business_source_ref='fixture-audit',
               method='SERVICE_AUDIT_RECORD', started_at=STAMP, finished_at=END)
    add_scope(doc, host, 'sshd', 'service-context', [
        record('package', 'PACKAGE_INVENTORY', dict(name='fixture-package', version='1.0', present=not second), None, service),
        runtime('capability', ssh, not second, service),
        record('config', 'EFFECTIVE_CONFIGURATION', dict(setting='kex', effective_value='fixture', allowed=not second), ssh, service),
        record('negotiation', 'AUTHORIZED_NEGOTIATION', dict(conditions=neg, outcome='REJECTED' if second else 'NEGOTIATED'), ssh, service),
        record('other-endpoint', 'AUTHORIZED_NEGOTIATION', dict(conditions=dict(neg, endpoint_ref='fixture-other-endpoint'), outcome='TIMEOUT'), ssh, service),
        record('usage', 'OBSERVED_USAGE', dict(conditions=use, outcome='CONTRADICTED' if second else 'OBSERVED'), ssh, service),
        record('config-only', 'EFFECTIVE_CONFIGURATION', dict(setting='kex', effective_value='fixture', allowed=True), ssh, configs),
        record('unknown-token', 'ASSET_METADATA', dict(name='fixture-unknown', version=None),
               classified(MALICIOUS, 'SSH_KEX'), configs)])
    add_scope(doc, host, 'openssl', 'runtime-gap', [runtime('unsupported', ssh, True, configs)], 'ERROR' if second else 'UNKNOWN')


def publish_assets(root, assessed=True, coverage_extra=False):
    args = options(('PARTIAL', 'PARTIAL', 'UNREACHABLE'), negotiate=True)
    args['evidence_schema_version'] = '1.1.0'
    for flags in args['requested_flags'].values():
        flags.update(system_certs=True, ssh_host_keys=True)
    if coverage_extra:
        args['profile'] = 'extended'
        for flags in args['requested_flags'].values():
            flags.update(nginx_certs=True)
    with rs.RunStore(root) as store, store.begin(**args) as writer:
        scope = writer.scope; hosts = scope['hosts']
        for h in hosts:
            unreachable = h['target_id'].startswith('fixture-2')
            h.update(host_state='UNREACHABLE' if unreachable else 'PARTIAL',
                     reason_code='CONNECTION_FAILED' if unreachable else 'INCOMPLETE_COLLECTION')
        doc = rs._doc(scope, hosts, 'PARTIAL', finished_at=END, coverage_reason='INCOMPLETE_COLLECTION')
        for host in hosts:
            if host['host_state'] != 'UNREACHABLE':
                synthetic_assets(doc, host, host['target_id'].startswith('fixture-1'))
                if coverage_extra and host['target_id'].startswith('fixture-0'):
                    add_scope(doc, host, 'nginx_certs', 'nginx-certificate-applicability', [record(
                        'applicability', 'COLLECTION_SUMMARY', dict(scope='nginx-certificate-applicability',
                            attempted=True, applicable=False, coverage='UNKNOWN', observation_count=None))], 'UNKNOWN')
                    doc['collections'][-1].update(collection_state='NOT_APPLICABLE', reason_code='NOT_APPLICABLE')
        doc = json.loads(e.canonical_bytes(doc)); terminals = []
        for host in doc['hosts']:
            hid = host['host_id']; fragment = rs.host_fragment(doc, hid)
            terminal = dict(target_id=host['target_id'], host_state=host['host_state'], attempted=True,
                            reason_code=host['reason_code'], collectors=[])
            for collector, requested in sorted(scope['flags'][hid].items()):
                coll = [c for c in fragment['collections'] if c['collector_id'] == collector]
                if not requested: state, reason, rc = 'NOT_SCANNED', 'DISABLED', None
                elif host['host_state'] == 'UNREACHABLE': state, reason, rc = 'UNREACHABLE', 'CONNECTION_FAILED', None
                elif coverage_extra and collector == 'nginx_certs':
                    state, reason, rc = ('NOT_APPLICABLE', 'NOT_APPLICABLE', None) if coll else (
                        ('ERROR', 'COMMAND_FAILED', 1) if coverage_extra == 'ERROR' else ('UNKNOWN', 'NO_EVIDENCE', None))
                elif collector == 'openssl':
                    state = coll[0]['collection_state']; reason, rc = coll[0]['reason_code'], 1 if state == 'ERROR' else None
                else: state, reason, rc = 'COLLECTED', 'COLLECTED', 0
                terminal['collectors'].append(dict(collector_id=collector, requested=requested, state=state,
                    reason_code=reason, rc=rc, collection_ids=sorted(c['collection_id'] for c in coll)))
            details = []
            if host['target_id'].startswith('fixture-0'):
                cert = next(a for a in fragment['assets'] if a['asset_kind'] == 'certificate')
                row = next(r for r in fragment['evidence'] if r['asset_id'] == cert['asset_id'])
                c = next(c for c in fragment['collections'] if c['collection_id'] == row['collection_id'])
                details.append(dict(format_version=rs.VERSION, format='S1_TYPED_FIXTURE', run_id=RID,
                    host_id=hid, slot='certificate-inventory', collection_ids=[c['collection_id']],
                    asset_ids=[cert['asset_id']], evidence_ids=[row['evidence_id']], records=[dict(record_kind='ASSET',
                    evidence_id=row['evidence_id'], state=c['collection_state'], reason_code=c['reason_code'], rc=0)]))
            writer.dispatch_intent(hid)
            writer.record_host(fragment, attempted=True, terminal=terminal, details=details)
            terminals.append(terminal)
        batch = raw(dict(batch_manifest_version=1, target_ids=sorted(h['target_id'] for h in hosts),
            target_count=len(hosts), limits=LIMITS, profile=args['profile'], run_state='PARTIAL',
            reason_code='INCOMPLETE_COLLECTION', hosts=sorted(terminals, key=lambda h: h['target_id'])))
        writer.finalize(doc, batch_raw=batch, batch_rc=5,
            assessed=assessment.evaluate_document(doc, RULESET) if assessed else None,
            rules_raw=RULES if assessed else None)
    with rs.RunStore(root) as store:
        return store.open(RID)


@pytest.fixture
def published(root):
    return publish_assets(root)


def test_actual_s1_no_invented_fingerprint_or_binding(published):
    p = ai.project_asset_indexes(published)
    certs = p['certificates']['groups']; services = p['services']['groups']
    assert len(certs) == 3 and len(services) == 4 and len({g['id'] for g in certs}) == 3
    assert all(g['kind'] == 'UNVERIFIED_IDENTITY' and g['fingerprint'] is None for g in certs)
    assert p['occurrences'] == {} and p['certificates']['counts']['recorded_occurrence_ids'] == 0
    assert all(g['not_before'] is g['not_after'] is None and g['detail_state'] == 'DETAIL_NOT_RETAINED' for g in certs)
    assert all(g['public_key']['state'] == g['signature']['state'] == 'UNKNOWN' for g in certs)
    assert all(g['service_group_ids'] == [] for g in certs) and all(g['certificate_group_ids'] == [] for g in services)
    assert {g['detail_slot_state'] for g in p['coverage'] if g['slot'] == 'system_certs'} == {'GENERIC_DETAIL_ONLY', 'DETAIL_NOT_RETAINED'}
    assert all(p['assets'][a]['asset_kind'] in ('certificate', 'service') for a in p['assets'])
    assert set(p['assets']) == {a['asset_id'] for a in published.document['assets'] if a['asset_kind'] in ('certificate', 'service')}


def test_actual_s1_levels_endpoints_coverage(published):
    p = ai.project_asset_indexes(published)
    services = p['services']['groups']
    actual = [g for g in services if g['endpoint_state'] == 'RECORDED_CONTEXT']
    unknown = [g for g in services if g['endpoint_state'] == 'UNKNOWN']
    assert len(actual) == len(unknown) == 2
    for g in actual:
        hid = g['host_ids'][0]; positive = p['hosts'][hid]['target_id'].startswith('fixture-0')
        assert {r['endpoint_ref'] for r in g['endpoints']} == {'fixture-endpoint', 'fixture-other-endpoint'}
        for level, yes, no in [('L1', 'PRESENT', 'ABSENT'), ('L2', 'SUPPORTED', 'UNSUPPORTED'),
                               ('L3', 'ALLOWED', 'DISALLOWED'), ('L4', 'NEGOTIATED', 'REJECTED'),
                               ('L5', 'OBSERVED', 'CONTRADICTED')]:
            counts = g['levels'][level]['observation_counts']
            assert counts[yes if positive else no] == 1 and (no if positive else yes) not in counts
        assert g['levels']['L4']['observation_counts']['TIMEOUT'] == 1
        assert g['levels']['L4']['claim_counts']['PASS' if positive else 'FAIL'] == 1
        assert g['levels']['L5']['claim_counts']['PASS' if positive else 'FAIL'] == 1
    for g in unknown:
        assert not g['endpoints'] and g['levels']['L4']['observations'] == g['levels']['L5']['claims'] == {}
        assert g['levels']['L2']['observation_counts'] == {'UNKNOWN': 1}
    tls = [r for r in p['coverage'] if r['slot'] == 'tls_services']
    assert len(tls) == 3 and all(r['requested'] is False and r['state'] == 'NOT_SCANNED' for r in tls)
    assert all(r['slot_state'] == 'MISSING_SLOT' for r in tls)
    unreachable = [r for r in p['coverage'] if p['hosts'][r['host_id']]['host_state'] == 'UNREACHABLE']
    assert {r['state'] for r in unreachable if r['requested']} == {'UNREACHABLE'}


@pytest.mark.parametrize('state,rc', [('ERROR', 1), ('UNKNOWN', None)])
def test_actual_s1_coverage_gap_states(root, state, rc):
    published = publish_assets(root, coverage_extra=state)
    p = ai.project_asset_indexes(published)
    rows = {(p['hosts'][r['host_id']]['target_id'].split('.')[0], r['slot']): r for r in p['coverage']}
    for target, slot, state, rc in (('fixture-0', 'nginx_certs', 'NOT_APPLICABLE', None),
            ('fixture-1', 'nginx_certs', state, rc), ('fixture-2', 'nginx_certs', 'UNREACHABLE', None)):
        r = rows[target, slot]
        assert r['requested'] is True and r['state'] == state and r['rc'] == rc and r['basis'] == 'TERMINAL'
        assert r['slot_state'] == ('RECORDED' if state == 'NOT_APPLICABLE' else 'MISSING_SLOT')
    assert len(p['services']['groups']) == 4


def test_actual_set_oracles_algorithm_pivots_and_no_mutation(published):
    before = deepcopy(published); p = ai.project_asset_indexes(published)
    assert p == ai.project_asset_indexes(published) and published == before
    assert ai._bounded_bytes(p) == raw(p) and json.loads(ai._bounded_bytes(p)) == p
    alg = crypto.project_crypto_indexes(published)['algorithms']['groups']
    all_refs = {k: set() for k in ai._REF_KEYS}
    for name in ('certificates', 'services'):
        index = p[name]; totals = {k: set() for k in ai._REF_KEYS}
        for g in index['groups']:
            for k in totals:
                assert g[k] == sorted(set(g[k])) and g['counts'][k] == len(g[k])
                totals[k].update(g[k])
            for level, level_data in g['levels'].items():
                for key, table, field in [('observations', 'evidence', 'observation_state'), ('claims', 'claims', 'assessment_state')]:
                    assert level_data[key[:-1] + '_counts'] == {state: len(set(ids)) for state, ids in level_data[key].items()}
                    for state, ids in level_data[key].items():
                        assert all(p[table][i]['level'] == level and p[table][i][field] == state for i in ids)
            expected = {a['id']: sorted(set(a['evidence_ids']) & set(g['evidence_ids'])) for a in alg
                        if set(a['evidence_ids']) & set(g['evidence_ids'])}
            assert {link['group_id']: link['evidence_ids'] for link in g['algorithm_links']} == expected
            assert set(g['algorithm_group_ids']) == set(expected)
        for k in totals:
            assert index[k] == sorted(totals[k]) and index['counts'][k] == len(totals[k])
            all_refs[k].update(totals[k])
        assert index['counts']['groups'] == len(index['groups'])
    assert all_refs['asset_ids'] == set(p['assets']) and all_refs['evidence_ids'] == set(p['evidence'])
    assert all_refs['claim_ids'] == set(p['claims'])
    assert all_refs['recorded_occurrence_ids'] == set(p['occurrences'])


def test_no_assessment_does_not_recompute(root, monkeypatch):
    pub = publish_assets(root, assessed=False)
    def forbidden(*args, **kwargs):
        raise AssertionError('projection must not reassess or classify')
    monkeypatch.setattr(assessment, 'evaluate_document', forbidden)
    monkeypatch.setattr(assessment, 'classify_algorithm', forbidden)
    p, pages = ai.render_asset_indexes(pub)
    assert not p['assessed'] and not p['claims'] and all(b'Assessment not present' in x for x in pages.values())
    assert all(not g['claim_ids'] for name in ('certificates', 'services') for g in p[name]['groups'])


def test_actual_i3_legacy_certificate_and_tls_historical_only(root):
    hosts = ['legacy-a.example.invalid', 'legacy-b.example.invalid']
    def report(host):
        cert = dict(path='/fixture/cert.pem', subject='fixture-subject', issuer='fixture-issuer',
                    expires='2028-01-01T00:00:00Z', public_key_algorithm='rsaEncryption',
                    signature_algorithm='sha256WithRSAEncryption', public_key_size=2048, fingerprint=FP)
        return dict(host=host, collected_at=STAMP, system_certificates=[cert, deepcopy(cert), dict(cert, path='/fixture/other.pem')],
            nginx_certificates=[dict(path='/fixture/nginx.pem', public_key_type='RSA', public_key_size=2048,
                signature_algorithm='sha256WithRSAEncryption', not_before='2026-01-01T00:00:00Z', not_after='2028-01-01T00:00:00Z')],
            tls_services=[dict(port=443, protocol='TLSv1.3', cipher='TLS_AES_256_GCM_SHA384', key_exchange='X25519MLKEM768'),
                          dict(port=True, protocol='TLSv1.3')])
    old = dict(run_id='fixture-old', generated_at=STAMP, selected_hosts=hosts, successful_hosts=hosts,
               hosts_without_report=[], selected_count=2, completed_count=2, reports=[report(h) for h in hosts])
    path = root.parent / 'legacy.json'; path.write_bytes(raw(old)); path.chmod(0o600)
    result = subprocess.run([sys.executable, '-B', '-m', 'tools.import_reports', '--input', str(path),
        '--format', 'legacy-ol-run-summary', '--run-id', RID, '--recorded-at', END,
        '--origin-ref', 'fixture-source', '--source-version', '0.9.1', '--report-root', str(root)],
        cwd=ROOT, capture_output=True, timeout=30)
    assert result.returncode == 0, result.stderr
    with rs.RunStore(root) as store: pub = store.open(RID)
    p, pages = ai.render_asset_indexes(pub)
    assert len(p['certificates']['groups']) == 6 and len(p['services']['groups']) == 2
    assert all(g['kind'] == 'LEGACY_RUN_SCOPED' and g['fingerprint'] is None and g['not_before'] is g['not_after'] is None
               and g['counts']['host_ids'] == g['counts']['asset_ids'] == 1 for g in p['certificates']['groups'])
    assert all(g['public_key_bits'] == 2048 and g['public_key']['evidence_ids'] and g['signature']['evidence_ids']
               for g in p['certificates']['groups'])
    for g in p['services']['groups']:
        assert g['kind'] == 'LEGACY_SERVICE' and g['legacy_port'] == 443 and g['endpoint_state'] == 'HISTORICAL_ONLY'
        assert not g['endpoints'] and not g['levels']['L4']['observations'] and not g['levels']['L5']['claims']
        assert g['certificate_group_ids'] == []
    assert all(r['requested'] is None for r in p['coverage']) and p['occurrences'] == {}
    for value in (ai._bounded_bytes(p), *pages.values()):
        assert b'/fixture/cert.pem' not in value and b'2028-01-01' not in value and FP.encode() not in value
    assert b'historical only' in pages['services.html']


def test_actual_v4_preview_relative_links_escaping_no_writes(root, published, tmp_path):
    catalog.build_catalog(root)
    portal.render_run(root, RID, with_crypto_indexes=True)
    before = tree_state(root); p, pages = ai.render_asset_indexes(published)
    assert tree_state(root) == before
    assert set(pages) == {'certificates.html', 'services.html'}
    gen = root / RID / 'portal-v4'
    mapping = {f.name: Page(f) for f in gen.glob('*.html')}
    preview = tmp_path / 'preview'; preview.mkdir()
    for name, value in pages.items():
        assert b'<img' not in value and b'<script' not in value
        f = preview / name; f.write_bytes(value); mapping[name] = Page(f)
    assert b'&lt;img src=x onerror=alert(1)&gt;' in pages['services.html']
    for name in ('certificates', 'services'):
        page = mapping[name + '.html']; index = p[name]
        for key, count in index['counts'].items():
            assert int(page.text['count-' + key]) == count
        assert not any(tag in {'script', 'iframe', 'object', 'embed', 'base', 'form'} or
            any(k.startswith('on') or k in ('src', 'srcset', 'action', 'style') for k in attrs) for tag, attrs in page.tags)
        for href in page.links:
            u = urlsplit(href)
            assert not u.scheme and not u.netloc and not u.query and not u.path.startswith('/')
            assert '\\' not in href and '%' not in href
            if href in ('../portal.css', '../index.html', '../../index.html'):
                assert (gen / href).is_file()
            elif u.path:
                assert u.path in mapping and (not u.fragment or u.fragment in mapping[u.path].ids)
            else:
                assert u.fragment in page.ids
        for g in index['groups']:
            assert g['backlink'] == name + '.html#' + g['id'] and g['id'] in page.ids
            for key, table in [('host_ids', 'hosts'), ('asset_ids', 'assets'), ('evidence_ids', 'evidence'), ('claim_ids', 'claims')]:
                assert all(p[table][ref]['href'] in page.links for ref in g[key])
            assert all(link['href'] in page.links for link in g['algorithm_links'])
    with rs.RunStore(root) as store: assert store.open(RID) == published
    assert tree_state(root) == before


@pytest.mark.parametrize('value', [None, {}, 'evidence.json', Path('/tmp/invalid'), (None, None, None, None)])
def test_reject_non_publication(value):
    with pytest.raises(rs.StoreError, match='INVALID_ASSET_INDEX_PUBLICATION'):
        ai.project_asset_indexes(value)


@pytest.mark.parametrize('cap', ['_MAX_JSON', '_MAX_HTML', '_MAX_MEMBERSHIPS'])
def test_bounds_fail_closed_no_writes(root, published, monkeypatch, cap):
    before = tree_state(root); monkeypatch.setattr(ai, cap, 1)
    with pytest.raises(rs.StoreError, match='ASSET_INDEX_SIZE_LIMIT'):
        ai.render_asset_indexes(published)
    assert tree_state(root) == before


def test_empty_indexes_do_not_assert_absence(root):
    pub = publish(root, ('ERROR',))
    p, pages = ai.render_asset_indexes(pub)
    assert p['certificates']['counts']['groups'] == p['services']['counts']['groups'] == 0
    assert all(b'This is not a negative verdict' in v for v in pages.values())
    assert p['coverage'] and all(r['state'] != 'COLLECTED' for r in p['coverage'])
