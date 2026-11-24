"""C01-C03: actual Evidence/Assessment/CFF contracts; synthetic data only."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import sys
import time

import pytest

ROOT = Path(__file__).resolve().parents[2]
# Fixed source root for the documented isolated Python (-I) test command.
sys.path.insert(0, str(ROOT))
from tools import assessment as a, cff, evidence as e
T = '2026-01-01T00:00:00Z'
END = '2026-01-01T00:01:00Z'
REC = '2026-01-02T00:00:00Z'
VERSIONS = ('1.0.0', '1.1.0')
SECRET = 'SYNTHETIC_SECRET_SENTINEL'


@pytest.fixture(scope='module')
def rules():
    return a.load_rules((ROOT / 'config/assessment_rules.yml').read_bytes())


@pytest.fixture(scope='module')
def standard():
    try:
        import jsonschema as js
    except ImportError:
        # Keep semantic tests runnable with the stdlib runtime. Only the
        # dedicated external-validator oracle is skipped without this tool.
        return None
    schema = json.loads((ROOT / 'schemas/cff-projection-1.0.0.schema.json').read_bytes())
    js.Draft202012Validator.check_schema(schema)
    assert schema['$id'] == 'urn:pqc:cff-projection:1.0.0'
    assert schema['$schema'] == 'https://json-schema.org/draft/2020-12/schema'
    def walk(v):
        if type(v) is dict:
            if '$ref' in v:
                assert v['$ref'].startswith('#/$defs/')
                assert v['$ref'].split('/')[-1] in schema['$defs']
            if v.get('type') == 'object':
                assert v['additionalProperties'] is False
                assert set(v['required']) == set(v['properties'])
            for item in v.values():
                walk(item)
        elif type(v) is list:
            for item in v:
                walk(item)
    walk(schema)
    return js.Draft202012Validator(schema, format_checker=js.FormatChecker())


class Fixture:
    """Construct valid documents with the actual versioned public ID helpers."""
    def __init__(self, version='1.0.0', rid='fixture-run', target='host-a.example.invalid', state='PARTIAL',
                 identity=None):
        self.rid = rid
        self.doc = {'schema_version': version,
                    'run': {'run_id': rid, 'run_state': 'PARTIAL', 'recorded_at': REC,
                            'started_at': T, 'finished_at': END, 'source': self.source('fixture'),
                            'expected_host_ids': [], 'scope_reason': 'FIXTURE',
                            'coverage_reason': 'INCOMPLETE_SCOPE'},
                    **{k: [] for k in e.REGISTRIES}}
        self.h = self.host(target, state=state, identity=identity)

    @staticmethod
    def source(producer):
        return {'source_kind': 'SYNTHETIC', 'producer_id': producer, 'producer_version': '1.0.0',
                'origin_ref': 'fixture-origin', 'input_sha256': 'a' * 64}

    def host(self, target, state='PARTIAL', identity=None):
        identity = target if identity is None else identity
        hid = e.host_id(None, target, run_id=self.rid, identity_key=identity)
        self.doc['hosts'].append({'host_id': hid, 'target_id': target, 'identity_scope': 'RUN_SCOPED',
                                  'host_state': state, 'reason_code': 'FIXTURE',
                                  'inventory_authority_id': None, 'identity_key': identity})
        self.doc['run']['expected_host_ids'].append(hid)
        return hid

    def asset(self, kind='service', key='fixture-service', host=None):
        host = host or self.h
        aid = e.asset_id(host, kind, key, run_id=self.rid)
        self.doc['assets'].append({'asset_id': aid, 'host_id': host, 'asset_kind': kind,
                                   'identity_scope': 'RUN_SCOPED', 'identity_key': key,
                                   'evidence_ids': []})
        return aid

    def collection(self, scope='fixture-scope', state='COLLECTED', host=None, collector='fixture'):
        host = host or self.h
        cid = e.collection_id(self.rid, host, collector, scope)
        row = {'collection_id': cid, 'host_id': host, 'collector_id': collector,
               'collector_version': '1.0.0', 'scope_key': scope, 'collection_state': state,
               'reason_code': 'DISABLED_BY_PROFILE' if state == 'NOT_SCANNED' else 'FIXTURE',
               'source': self.source(collector), 'observed_at': None if state == 'NOT_SCANNED' else T,
               'evidence_ids': []}
        self.doc['collections'].append(row)
        return row

    def add(self, c, key, kind, data, *, asset=None, algorithm=None, observed=T):
        rid = e.evidence_id(self.rid, c['host_id'], c['collection_id'], key)
        row = {'evidence_id': rid, 'host_id': c['host_id'], 'collection_id': c['collection_id'],
               'asset_id': asset, 'observation_key': key, 'evidence_kind': kind,
               'source': deepcopy(c['source']), 'observed_at': observed, 'data': data,
               'algorithm': deepcopy(algorithm), 'evidence_ref': 'fixture-evidence', 'raw_sha256': 'b' * 64}
        c['evidence_ids'].append(rid)
        self.doc['evidence'].append(row)
        if asset:
            next(a for a in self.doc['assets'] if a['asset_id'] == asset)['evidence_ids'].append(rid)
        return row

    def direct(self, c, level, value, *, key='direct', asset=None, algorithm=None, conditions=None):
        if level == 'L1':
            kind, data = 'PACKAGE_INVENTORY', {'name': 'fixture-package', 'version': '1.0', 'present': value}
        elif level == 'L2':
            kind, data = 'RUNTIME_CAPABILITY', {'capability': 'fixture-capability', 'supported': value}
        elif level == 'L3':
            kind, data = 'EFFECTIVE_CONFIGURATION', {'setting': 'fixture-setting', 'effective_value': 'DEFAULT',
                                                       'allowed': value}
        elif level == 'L4':
            kind = 'AUTHORIZED_NEGOTIATION'
            data = {'conditions': conditions or {'host_id': c['host_id'], 'service_asset_id': asset,
                    'endpoint_ref': 'fixture-endpoint', 'protocol': 'TLS', 'context_ref': 'fixture-context',
                    'authorization_ref': 'fixture-authorization'}, 'outcome': value}
        else:
            kind = 'OBSERVED_USAGE'
            data = {'conditions': conditions or {'host_id': c['host_id'], 'service_asset_id': asset,
                    'business_source_ref': 'fixture-telemetry', 'method': 'APPLICATION_TELEMETRY',
                    'started_at': T, 'finished_at': END}, 'outcome': value}
        return self.add(c, key, kind, data, asset=asset, algorithm=algorithm)

    def summary(self, c, applicable, *, asset=None, algorithm=None):
        return self.add(c, 'summary', 'COLLECTION_SUMMARY', {'scope': c['scope_key'], 'attempted': True,
                    'coverage': 'COMPLETE' if applicable else 'UNKNOWN',
                    'observation_count': 0 if applicable else None, 'applicable': applicable},
                        asset=asset, algorithm=algorithm)

    def project(self, rules, standard=None):
        before, policy = deepcopy(self.doc), deepcopy(rules)
        e.validate_document(self.doc)
        assessed = a.evaluate_document(self.doc, rules)
        result = cff.project_cff(self.doc, rules)
        assert self.doc == before and rules == policy
        assert result['evidence_document_sha256'] == hashlib.sha256(e.canonical_bytes(assessed)).hexdigest()
        assert cff.validate_projection(result, assessed, rules) is None
        if standard is not None:
            standard.validate(result)
        assert json.loads(cff.canonical_projection_bytes(result, self.doc, rules)) == result
        assert e.parse_evidence_bytes(e.canonical_bytes(assessed)) == assessed
        return result


def host_projection(result, hid):
    return next(p for p in result['per_host'] if p['host_id'] == hid)


def by_rule(entry, rule):
    return [f for f in entry['companion']['findings'] if f['rule_id'] == rule]


def hybrid(rules):
    return a.classify_algorithm('X25519MLKEM768', 'TLS_KEX', rules)


def fact_status(level, state):
    if level in ('L1', 'L2', 'L3'):
        return state == 'PASS'
    return {('L4', 'PASS'): 'NEGOTIATED', ('L4', 'FAIL'): 'REJECTED',
            ('L5', 'PASS'): 'OBSERVED', ('L5', 'FAIL'): 'CONTRADICTED'}[(level, state)]


@pytest.mark.parametrize('version', VERSIONS)
@pytest.mark.parametrize('level', e.LEVELS)
@pytest.mark.parametrize('state', ('PASS', 'FAIL'))
def test_c01_exact_direct_fact_only(rules, standard, version, level, state):
    f = Fixture(version)
    asset = f.asset() if level in ('L4', 'L5') else None
    obs = f.direct(f.collection(), level, fact_status(level, state), asset=asset, algorithm=hybrid(rules))
    out = host_projection(f.project(rules, standard), f.h)
    comp = out['companion']
    assert comp['evidence_schema_version'] == version
    assert len(comp['claims']) == len(comp['findings']) == len(out['cff']['findings']) == 1
    cl = comp['claims'][0]
    row = comp['findings'][0]
    wire = out['cff']['findings'][0]
    assert cl['level'] == level and cl['assessment_state'] == state
    assert cl['conditions'] == obs['data'].get('conditions')
    assert cl['evidence_ids'] == [obs['evidence_id']]
    assert comp['evidence'][0]['conditions'] == cl['conditions']
    assert comp['evidence'][0]['source'] == obs['source']
    assert comp['evidence'][0]['algorithm']['migration_classification'] == 'PQC_OR_HYBRID_INVENTORY'
    assert row['claim_ids'] == [cl['claim_id']] and row['linked_evidence_ids'] == [obs['evidence_id']]
    assert row['collection_ids'] == [obs['collection_id']]
    assert row['assessment_state'] == state and wire['status'] == state.lower()
    assert row['owned'] and row['score_included']
    assert wire['rule_id'] == row['finding_id'] and wire['evidence']['scanner_rule_id'] == cl['rule_id']
    assert out['cff']['summary']['compliance_score'] == (100.0 if state == 'PASS' else 0.0)
    assert comp['score'] == {'score_semantics': 'FACT_STATUS_RATIO_NOT_READINESS',
                              'numerator': int(state == 'PASS'), 'denominator': 1,
                              'excluded': 0, 'score_available': True}


@pytest.mark.parametrize('version', VERSIONS)
@pytest.mark.parametrize('state,expected', [('UNKNOWN', 'not_checked'), ('NOT_SCANNED', 'not_checked'),
    ('ERROR', 'error'), ('PERMISSION_DENIED', 'error'), ('UNREACHABLE', 'error')])
def test_c02_empty_collection_mapping(rules, standard, version, state, expected):
    f = Fixture(version)
    c = f.collection(state=state)
    out = host_projection(f.project(rules, standard), f.h)
    row, = out['companion']['findings']
    assert row['collection_ids'] == [c['collection_id']]
    assert row['assessment_state'] == ('NOT_SCANNED' if state == 'NOT_SCANNED' else 'UNKNOWN')
    assert row['cff_status'] == expected and not row['score_included']
    assert row['error_collection_ids'] == ([c['collection_id']] if expected == 'error' else [])
    assert row['error_host_state'] is None
    assert out['companion']['score']['denominator'] == 0
    assert out['companion']['score']['score_available'] is False
    assert out['cff']['summary']['compliance_score'] == 0.0
    assert out['companion']['collections'][0]['reason_code'] == c['reason_code']


@pytest.mark.parametrize('version', VERSIONS)
@pytest.mark.parametrize('state,expected', [('ERROR', 'error'), ('UNREACHABLE', 'error'),
    ('NOT_ATTEMPTED', 'not_checked'), ('PARTIAL', 'not_checked'), ('COMPLETE', 'not_checked')])
def test_c01_host_only_coverage(rules, standard, version, state, expected):
    f = Fixture(version, state=state)
    out = host_projection(f.project(rules, standard), f.h)
    assert out['companion']['host']['host_state'] == state and out['companion']['host']['expected'] is True
    row, = out['companion']['findings']
    assert row['cff_status'] == expected and row['collection_ids'] == []
    assert row['error_host_state'] == (state if expected == 'error' else None)
    assert out['companion']['score']['score_available'] is False


@pytest.mark.parametrize('version', VERSIONS)
def test_c01_empty_manifest_has_no_invented_host(rules, standard, version):
    f = Fixture(version)
    f.doc['hosts'] = []
    f.doc['run']['expected_host_ids'] = []
    f.doc['run']['run_state'] = 'ERROR'
    out = f.project(rules, standard)
    assert out['per_host'] == []


@pytest.mark.parametrize('version', VERSIONS)
@pytest.mark.parametrize('failed', ('ERROR', 'PERMISSION_DENIED', 'UNREACHABLE'))
def test_c02_referenced_acquisition_error_not_a_fact_fail(rules, standard, version, failed):
    f = Fixture(version)
    c = f.collection(state=failed)
    row = f.direct(c, 'L2', True, algorithm=hybrid(rules))
    entry = host_projection(f.project(rules, standard), f.h)
    assert entry['companion']['claims'][0]['assessment_state'] == 'UNKNOWN'
    assert len(entry['companion']['findings']) == 2
    assert {v['cff_status'] for v in entry['companion']['findings']} == {'error'}
    for v in entry['companion']['findings']:
        assert v['linked_evidence_ids'] == [row['evidence_id']]
        assert v['error_collection_ids'] == [c['collection_id']]
    assert entry['cff']['summary']['error'] == 2
    assert entry['companion']['score']['denominator'] == 0


@pytest.mark.parametrize('version', VERSIONS)
def test_c02_no_borrowing_other_scope_asset_or_host(rules, standard, version):
    f = Fixture(version, state='ERROR')
    broken = f.collection('broken', state='ERROR')
    unknown = f.collection('unknown', state='UNKNOWN')
    asset = f.asset('certificate', 'fixture-cert')
    row = f.direct(unknown, 'L2', None, asset=asset)
    other = f.host('host-b.example.invalid', 'PARTIAL')
    other_collection = f.collection('broken', state='UNKNOWN', host=other)
    out = f.project(rules, standard)
    entry = host_projection(out, f.h)
    for finding in entry['companion']['findings']:
        if finding['collection_ids'] == [broken['collection_id']]:
            assert finding['cff_status'] == 'error'
        else:
            assert finding['collection_ids'] == [unknown['collection_id']]
            assert finding['cff_status'] == 'not_checked'
            assert finding['error_collection_ids'] == []
            assert finding['linked_evidence_ids'] == [row['evidence_id']]
    second = host_projection(out, other)
    assert second['companion']['findings'][0]['collection_ids'] == [other_collection['collection_id']]
    assert second['companion']['findings'][0]['cff_status'] == 'not_checked'
    assert entry['cff']['scan_metadata']['scan_id'] != second['cff']['scan_metadata']['scan_id']


@pytest.mark.parametrize('version', VERSIONS)
def test_c02_mixed_states_and_denominator(rules, standard, version):
    f = Fixture(version)
    f.direct(f.collection('installed'), 'L1', True)
    f.direct(f.collection('supported'), 'L2', False)
    f.direct(f.collection('unknown', 'UNKNOWN'), 'L2', None)
    f.collection('error', 'ERROR')
    f.collection('disabled', 'NOT_SCANNED')
    c = f.collection('not-applicable', 'NOT_APPLICABLE')
    f.summary(c, False)
    f.direct(c, 'L2', None)
    c = f.collection('conflict', 'PARTIAL')
    f.direct(c, 'L3', True)
    f.direct(c, 'L3', False, key='opposite')
    entry = host_projection(f.project(rules, standard), f.h)
    rows = entry['companion']['findings']
    assert {x['assessment_state'] for x in rows} == set(e.ASSESSMENTS)
    assert {x['cff_status'] for x in rows} == set(cff.STATUSES)
    s = entry['cff']['summary']; score = entry['companion']['score']
    assert s['total'] == len(rows) == sum(s[k] for k in cff.STATUSES)
    assert s['pass'] == s['fail'] == 1 and s['error'] == 1
    assert s['compliance_score'] == 50.0
    assert score == {'score_semantics': 'FACT_STATUS_RATIO_NOT_READINESS', 'numerator': 1,
                     'denominator': 2, 'excluded': len(rows) - 2, 'score_available': True}
    assert all(not x['score_included'] and x['cff_status'] == 'not_checked'
               for x in rows if x['assessment_state'] == 'PARTIAL')
    assert all(x['cff_status'] == 'not_applicable' for x in rows if x['assessment_state'] == 'NOT_APPLICABLE')


@pytest.mark.parametrize('version', VERSIONS)
@pytest.mark.parametrize('states', [('ERROR', 'PERMISSION_DENIED'), ('UNKNOWN', 'UNKNOWN'),
                                   ('NOT_SCANNED', 'NOT_SCANNED')])
def test_c02_zero_denominator(rules, standard, version, states):
    f = Fixture(version)
    for n, state in enumerate(states):
        f.collection('scope-' + str(n), state)
    entry = host_projection(f.project(rules, standard), f.h)
    assert entry['companion']['score']['denominator'] == entry['companion']['score']['numerator'] == 0
    assert entry['companion']['score']['excluded'] == 2
    assert entry['companion']['score']['score_available'] is False
    assert entry['cff']['summary']['compliance_score'] == 0.0


@pytest.mark.parametrize('version', VERSIONS)
def test_c01_certificate_public_key_not_signature_or(rules, standard, version):
    f = Fixture(version)
    c = f.collection('certificate', 'PARTIAL')
    asset = f.asset('certificate', 'fixture-certificate')
    f.add(c, 'metadata', 'ASSET_METADATA', {'name': 'fixture-cert', 'version': None}, asset=asset)
    key = a.classify_algorithm('RSA', 'CERT_PUBLIC_KEY', rules)
    sig = a.classify_algorithm('ML-DSA-65', 'SIGNATURE', rules)
    for k, alg in [('public-key', key), ('signature', sig)]:
        f.add(c, k, 'LEGACY_OBSERVATION', {'field': k, 'value': 'synthetic-algorithm'}, asset=asset, algorithm=alg)
    entry = host_projection(f.project(rules, standard), f.h)
    comp = entry['companion']
    assert comp['claims'] == []
    algorithms = {v['algorithm']['algorithm_id']: v['algorithm'] for v in comp['evidence'] if v['algorithm']}
    assert algorithms[key['algorithm_id']]['primitive'] == 'PUBLIC_KEY'
    assert algorithms[key['algorithm_id']]['migration_classification'] == 'CLASSICAL_PUBLIC_KEY_MIGRATION'
    assert algorithms[sig['algorithm_id']]['primitive'] == 'SIGNATURE'
    assert algorithms[sig['algorithm_id']]['migration_classification'] == 'PQC_OR_HYBRID_INVENTORY'
    assert {v['subject']['algorithm_id'] for v in comp['findings']} == {None, key['algorithm_id'], sig['algorithm_id']}
    assert not any(v['cff_status'] in ('pass', 'fail') for v in comp['findings'])
    assert comp['score']['score_available'] is False


@pytest.mark.parametrize('version', VERSIONS)
def test_c01_capability_does_not_prove_configuration_service_or_usage(rules, standard, version):
    f = Fixture(version)
    alg = a.classify_algorithm('ML-KEM-768', 'KEM_CAPABILITY', rules)
    f.direct(f.collection('runtime'), 'L2', True, algorithm=alg)
    c = f.collection('fips')
    f.add(c, 'fips', 'EFFECTIVE_CONFIGURATION', {'setting': 'fips', 'effective_value': 'FIPS', 'allowed': None})
    c = f.collection('platform')
    data = {'os_family': 'redhat', 'os_version': '9.9'}
    if version == '1.1.0':
        data.update(distribution='oracle-linux', major=9, minor=9, patch=None,
                    architecture='x86_64', platform_status='UNVERIFIED')
    f.add(c, 'platform', 'PLATFORM_INFO', data)
    entry = host_projection(f.project(rules, standard), f.h)
    assert {(x['level'], x['assessment_state']) for x in entry['companion']['claims']} == {('L2', 'PASS'), ('L3', 'UNKNOWN')}
    assert entry['cff']['summary']['pass'] == 1 and entry['cff']['summary']['fail'] == 0
    assert entry['companion']['score']['denominator'] == 1
    assert not any(x['level'] in ('L4', 'L5') for x in entry['companion']['claims'])


@pytest.mark.parametrize('version', VERSIONS)
@pytest.mark.parametrize('name,context,expected', [
    ('RSA', 'CERT_PUBLIC_KEY', 'CLASSICAL_PUBLIC_KEY_MIGRATION'),
    ('ML-KEM-768', 'KEM_CAPABILITY', 'PQC_OR_HYBRID_INVENTORY'),
    ('X25519MLKEM768', 'TLS_KEX', 'PQC_OR_HYBRID_INVENTORY'),
    ('Kyber768', 'KEM_CAPABILITY', 'LEGACY_PQC_REVIEW'),
    ('TLS_AES_128_GCM_SHA256', 'TLS_CIPHER', 'SYMMETRIC_REVIEW'),
    ('prefix-MLKEM768', 'TLS_KEX', 'UNKNOWN')])
def test_c01_migration_context_exact(rules, standard, version, name, context, expected):
    f = Fixture(version)
    alg = a.classify_algorithm(name, context, rules)
    f.add(f.collection('legacy', 'UNKNOWN'), 'alg', 'LEGACY_OBSERVATION',
          {'field': 'algorithm', 'value': 'fixture'}, algorithm=alg)
    entry = host_projection(f.project(rules, standard), f.h)
    row, = entry['companion']['evidence']
    assert row['algorithm']['migration_classification'] == expected
    assert row['algorithm']['primitive'] == alg['primitive']
    assert entry['companion']['claims'] == []
    assert entry['companion']['score']['denominator'] == 0


@pytest.mark.parametrize('version', VERSIONS)
def test_c01_conflicting_algorithm_annotation_not_migration_proof(rules, standard, version):
    f = Fixture(version)
    alg = hybrid(rules)
    alg['family'] = 'PQC'
    f.direct(f.collection(), 'L2', True, algorithm=alg)
    entry = host_projection(f.project(rules, standard), f.h)
    assert entry['companion']['evidence'][0]['algorithm']['migration_classification'] == 'UNKNOWN'
    assert entry['companion']['claims'][0]['assessment_state'] == 'UNKNOWN'
    assert entry['cff']['summary']['pass'] == 0


@pytest.mark.parametrize('available', (True, False, None))
def test_c01_v11_tool_metadata_not_readiness(rules, standard, available):
    f = Fixture('1.1.0')
    c = f.collection('tool', 'PARTIAL' if available is not None else 'UNKNOWN')
    f.add(c, 'tool', 'TOOL_AVAILABILITY', {'tool_id': 'openssl', 'lookup_scope': 'SYSTEM_EXECUTABLE_PATHS',
                                           'available': available})
    entry = host_projection(f.project(rules, standard), f.h)
    assert entry['companion']['claims'] == []
    row, = entry['companion']['findings']
    assert row['assessment_state'] == ('PARTIAL' if available is not None else 'UNKNOWN')
    assert row['cff_status'] == 'not_checked'
    assert entry['companion']['score']['denominator'] == 0


@pytest.mark.parametrize('version', VERSIONS)
def test_c01_same_rule_multiple_assets_scopes_hosts_and_conditions(rules, standard, version):
    f = Fixture(version)
    alg = hybrid(rules)
    other = f.host('host-b.example.invalid')
    for hid in (f.h, other):
        for i in range(2):
            asset = f.asset(key='service-' + str(i), host=hid)
            for j in range(2):
                c = f.collection('scope-' + str(j), host=hid) if i == 0 else next(
                    x for x in f.doc['collections'] if x['host_id'] == hid and x['scope_key'] == 'scope-' + str(j))
                for k in range(2):
                    conditions = {'host_id': hid, 'service_asset_id': asset, 'endpoint_ref': 'endpoint-' + str(k),
                                  'protocol': 'TLS', 'context_ref': 'context', 'authorization_ref': 'authorization'}
                    f.direct(c, 'L4', 'NEGOTIATED', key=f'obs-{i}-{j}-{k}', asset=asset, algorithm=alg,
                             conditions=conditions)
    out = f.project(rules, standard)
    ids = []
    for p in out['per_host']:
        assert len(p['cff']['findings']) == len(p['companion']['claims']) == 8
        assert {r['evidence']['scanner_rule_id'] for r in p['cff']['findings']} == {'pqc-l4-negotiable'}
        ids.extend(r['rule_id'] for r in p['cff']['findings'])
    assert len(set(ids)) == len(ids) == 16


def externalize(doc, rule='external-rule'):
    """Copy an actual validated finding (and linked claims) under a foreign rule."""
    out = deepcopy(doc)
    original = out['findings'][0]
    row = deepcopy(original)
    row['rule_id'] = rule
    row['rule_version'] = '2.0'
    row['finding_id'] = e.finding_id(row['subject'], rule, row['condition_key'])
    refs = []
    for cid in original['claim_ids']:
        cl = deepcopy(next(c for c in out['claims'] if c['claim_id'] == cid))
        cl['rule_id'] = rule
        cl['rule_version'] = '2.0'
        cl['claim_id'] = e.claim_id(out['run']['run_id'], cl['subject'], cl['level'], rule,
                                    cl['claim_key'], cl['conditions'])
        out['claims'].append(cl)
        refs.append(cl['claim_id'])
    row['claim_ids'] = refs
    out['findings'].append(row)
    return out, row


@pytest.mark.parametrize('version', VERSIONS)
@pytest.mark.parametrize('state', e.ASSESSMENTS)
def test_c01_unowned_preserved_excluded(rules, standard, version, state):
    f = Fixture(version)
    if state in ('PASS', 'FAIL'):
        f.direct(f.collection(), 'L1', state == 'PASS')
    elif state == 'PARTIAL':
        c = f.collection(state='PARTIAL'); f.direct(c, 'L2', True); f.direct(c, 'L2', False, key='other')
    elif state == 'NOT_APPLICABLE':
        f.summary(f.collection(state='NOT_APPLICABLE'), False)
    else:
        f.collection(state=state)
    assessed = a.evaluate_document(f.doc, rules)
    f.doc, foreign = externalize(assessed)
    # The first finding in PARTIAL is also PARTIAL; all others have one state.
    assert foreign['assessment_state'] == state
    e.validate_document(f.doc)
    p = host_projection(f.project(rules, standard), f.h)
    row, = by_rule(p, 'external-rule')
    assert row['finding_id'] == foreign['finding_id'] and row['assessment_state'] == state
    assert row['rule_version'] == '2.0' and row['claim_ids'] == sorted(foreign['claim_ids'])
    assert row['evidence_ids'] == sorted(foreign['evidence_ids'])
    assert row['owned'] is False and row['cff_status'] == 'not_checked' and not row['score_included']
    assert row['mapping_reason'] == 'UNOWNED_RULE'
    assert p['companion']['score']['denominator'] == int(state in ('PASS', 'FAIL'))


@pytest.mark.parametrize('version', VERSIONS)
@pytest.mark.parametrize('tamper', ('owned-finding-reason', 'owned-claim-reason', 'stale-owned-finding',
                                   'forged-owned-pass', 'dangling-ref', 'wrong-version'))
def test_c01_reject_forged_owned_or_invalid_input(rules, version, tamper):
    f = Fixture(version)
    f.direct(f.collection(), 'L2', True, algorithm=hybrid(rules))
    assessed = a.evaluate_document(f.doc, rules)
    if tamper == 'owned-finding-reason':
        assessed['findings'][0]['reason_code'] = 'FORGED'
    elif tamper == 'owned-claim-reason':
        assessed['claims'][0]['reason_code'] = 'FORGED'
    elif tamper in ('stale-owned-finding', 'forged-owned-pass'):
        x = deepcopy(assessed['findings'][0]); x['condition_key'] = 'invented'
        if tamper == 'forged-owned-pass':
            x['claim_ids'] = []
            x['evidence_ids'] = [assessed['evidence'][0]['evidence_id']]
        x['finding_id'] = e.finding_id(x['subject'], x['rule_id'], x['condition_key'])
        assessed['findings'].append(x)
    elif tamper == 'dangling-ref':
        assessed['findings'][0]['claim_ids'] = ['cl-' + '0' * 64]
    else:
        assessed['schema_version'] = '9.9.9'
    before = deepcopy(assessed)
    if tamper in ('dangling-ref', 'wrong-version'):
        with pytest.raises(e.EvidenceError): cff.project_cff(assessed, rules)
    else:
        e.validate_document(assessed)  # shape and refs valid, #11 result is not
        with pytest.raises(a.AssessmentError, match='ASSESSMENT_CONFLICT'):
            cff.project_cff(assessed, rules)
    assert assessed == before


@pytest.mark.parametrize('version', VERSIONS)
def test_c01_deterministic_canonical_and_manifest(rules, standard, version):
    f = Fixture(version)
    c = f.collection('first')
    f.direct(c, 'L1', True)
    f.direct(c, 'L2', False, key='second')
    second = f.host(None, state='UNREACHABLE', identity='missing-host')
    f.collection('scope', 'UNREACHABLE', host=second)
    f.doc['run']['finished_at'] = None
    p = f.project(rules, standard)
    assessed = a.evaluate_document(f.doc, rules)
    shuffled = deepcopy(assessed)
    for k in e.REGISTRIES:
        shuffled[k].reverse()
        for row in shuffled[k]:
            for name in ('claim_ids', 'evidence_ids'):
                if name in row: row[name].reverse()
    shuffled['run']['expected_host_ids'].reverse()
    before = deepcopy(shuffled)
    assert cff.project_cff(shuffled, rules) == p and shuffled == before
    assert cff.canonical_projection_bytes(p, f.doc, rules) == cff.canonical_projection_bytes(p, shuffled, rules)
    assert [v['host_id'] for v in p['per_host']] == sorted(f.doc['run']['expected_host_ids'])
    for v in p['per_host']:
        assert v['cff']['scan_metadata']['timestamp'] == REC
        assert v['companion']['run']['timestamp_kind'] == 'RUN_RECORDED_AT'
    assert host_projection(p, second)['cff']['scan_metadata']['host'] == second
    assert p['evidence_document_sha256'] == hashlib.sha256(e.canonical_bytes(assessed)).hexdigest()


@pytest.mark.parametrize('version', VERSIONS)
def test_c01_scan_id_run_and_host_join(rules, standard, version):
    results = []
    for rid in ('run-one', 'run-two'):
        f = Fixture(version, rid)
        # Stable host ID across runs, but scan ID includes the run.
        hid = e.host_id('fixture-authority', 'stable.example.invalid')
        host = f.doc['hosts'][0]
        host.update(host_id=hid, target_id='stable.example.invalid', identity_scope='STABLE',
                    inventory_authority_id='fixture-authority', identity_key=None)
        f.doc['run']['expected_host_ids'] = [hid]
        f.h = hid
        p = host_projection(f.project(rules, standard), hid)
        assert p['cff']['scan_metadata']['timestamp'] == END
        assert p['companion']['run']['timestamp_kind'] == 'RUN_FINISHED_AT'
        results.append(p)
    assert results[0]['host_id'] == results[1]['host_id']
    assert results[0]['cff']['scan_metadata']['scan_id'] != results[1]['cff']['scan_metadata']['scan_id']


@pytest.mark.parametrize('tamper', ['version', 'hash', 'host-hash', 'omit-host', 'duplicate-host',
    'summary', 'score', 'available', 'score-sentinel', 'duplicate-finding', 'omit-finding',
    'finding-id', 'status', 'source-rule', 'claim-ref', 'collection-ref', 'source-ref',
    'condition', 'algorithm', 'run-id', 'timestamp-kind', 'host-label', 'error-source', 'extra',
    'bool-count', 'certification', 'remediation', 'severity', 'unsafe-text'])
def test_c03_semantic_projection_tamper_rejected(rules, standard, tamper):
    f = Fixture('1.1.0')
    asset = f.asset()
    f.direct(f.collection(), 'L4', 'NEGOTIATED', asset=asset, algorithm=hybrid(rules))
    p = cff.project_cff(f.doc, rules)
    if standard is not None:
        standard.validate(p)
    q = deepcopy(p); row = q['per_host'][0]; comp = row['companion']; wire = row['cff']
    if tamper == 'version': q['projection_version'] = '2.0.0'
    elif tamper == 'hash': q['evidence_document_sha256'] = '0' * 64
    elif tamper == 'host-hash': comp['evidence_document_sha256'] = '0' * 64
    elif tamper == 'omit-host': q['per_host'] = []
    elif tamper == 'duplicate-host': q['per_host'].append(deepcopy(row))
    elif tamper == 'summary': wire['summary']['pass'] = 0
    elif tamper == 'score': comp['score']['denominator'] = 2
    elif tamper == 'available': comp['score']['score_available'] = False
    elif tamper == 'score-sentinel': wire['summary']['compliance_score'] = 0.0
    elif tamper == 'duplicate-finding': wire['findings'].append(deepcopy(wire['findings'][0]))
    elif tamper == 'omit-finding': comp['findings'].clear()
    elif tamper == 'finding-id': wire['findings'][0]['rule_id'] = 'f-' + '0' * 64
    elif tamper == 'status': wire['findings'][0]['status'] = 'fail'
    elif tamper == 'source-rule': wire['findings'][0]['evidence']['scanner_rule_id'] = 'other-rule'
    elif tamper == 'claim-ref': comp['findings'][0]['claim_ids'] = ['cl-' + '0' * 64]
    elif tamper == 'collection-ref': comp['findings'][0]['collection_ids'] = ['c-' + '0' * 64]
    elif tamper == 'source-ref': comp['evidence'][0]['source']['origin_ref'] = 'another-origin'
    elif tamper == 'condition': comp['claims'][0]['conditions']['authorization_ref'] = 'other-auth'
    elif tamper == 'algorithm': comp['evidence'][0]['algorithm']['migration_classification'] = 'UNKNOWN'
    elif tamper == 'run-id': comp['run']['run_id'] = 'other-run'
    elif tamper == 'timestamp-kind': comp['run']['timestamp_kind'] = 'RUN_RECORDED_AT'
    elif tamper == 'host-label': wire['scan_metadata']['host'] = 'other.example.invalid'
    elif tamper == 'error-source': comp['findings'][0]['error_collection_ids'] = [f.doc['collections'][0]['collection_id']]
    elif tamper == 'extra': comp['extra'] = SECRET
    elif tamper == 'bool-count': wire['summary']['pass'] = True
    elif tamper == 'certification': wire['scan_metadata']['certification']['status'] = 'certified'
    elif tamper == 'remediation': wire['findings'][0]['remediation']['available'] = True
    elif tamper == 'severity': wire['findings'][0]['severity'] = 'high'
    else: wire['findings'][0]['fix_text'] = '<script>' + SECRET
    with pytest.raises(cff.ProjectionError) as exc:
        cff.validate_projection(q, f.doc, rules)
    assert SECRET not in str(exc.value)
    assert cff.validate_projection(p, f.doc, rules) is None


@pytest.mark.parametrize('tamper', ['missing-companion', 'unknown-field', 'bad-status', 'negative-count',
    'bool-count', 'score-too-high', 'invalid-hash', 'wrong-evidence-version', 'bad-source-ref',
    'bad-conditions', 'bad-timestamp', 'bad-certification', 'bad-fix-text', 'unsafe-host', 'bad-rule-id'])
def test_c03_standard_schema_negative(rules, standard, tamper):
    if standard is None:
        pytest.skip('standard JSON Schema validator NOT_TESTED')
    f = Fixture('1.1.0')
    asset = f.asset()
    f.direct(f.collection(), 'L4', 'NEGOTIATED', asset=asset, algorithm=hybrid(rules))
    p = cff.project_cff(f.doc, rules)
    standard.validate(p)
    row = p['per_host'][0]; comp = row['companion']; wire = row['cff']
    if tamper == 'missing-companion': del row['companion']
    elif tamper == 'unknown-field': comp['new-field'] = True
    elif tamper == 'bad-status': wire['findings'][0]['status'] = 'PARTIAL'
    elif tamper == 'negative-count': wire['summary']['total'] = -1
    elif tamper == 'bool-count': wire['summary']['pass'] = True
    elif tamper == 'score-too-high': wire['summary']['compliance_score'] = 101
    elif tamper == 'invalid-hash': p['evidence_document_sha256'] = 'abc'
    elif tamper == 'wrong-evidence-version': comp['evidence_schema_version'] = '1.2.0'
    elif tamper == 'bad-source-ref': comp['evidence'][0]['source']['origin_ref'] = 'https://example.invalid'
    elif tamper == 'bad-conditions': comp['claims'][0]['conditions'] = None
    elif tamper == 'bad-timestamp': wire['scan_metadata']['timestamp'] = '2026-02-30T00:00:00Z'
    elif tamper == 'bad-certification': wire['scan_metadata']['certification']['authority'] = 'fake'
    elif tamper == 'bad-fix-text': wire['findings'][0]['fix_text'] = 'command'
    elif tamper == 'unsafe-host': wire['scan_metadata']['host'] = '<img onerror=alert(1)>'
    else: wire['findings'][0]['rule_id'] = 'short-id'
    assert not standard.is_valid(p)


@pytest.mark.parametrize('version', VERSIONS)
def test_c03_schema_source_and_wire_consumer_contract(rules, standard, version):
    schema_path = ROOT / 'schemas' / ('evidence.schema.json' if version == '1.0.0' else 'evidence-1.1.0.schema.json')
    eschema = json.loads(schema_path.read_bytes())
    assert eschema == e.model_schema(version)
    f = Fixture(version); f.direct(f.collection(), 'L1', True)
    if standard is not None:
        import jsonschema as js
        js.Draft202012Validator.check_schema(eschema)
        js.Draft202012Validator(eschema, format_checker=js.FormatChecker()).validate(a.evaluate_document(f.doc, rules))
    out = host_projection(f.project(rules, standard), f.h)['cff']
    assert set(out) == {'version', 'scan_metadata', 'findings', 'summary'}
    assert set(out['summary']) == {'total', 'pass', 'fail', 'error', 'not_applicable', 'not_checked', 'compliance_score'}
    meta = out['scan_metadata']
    assert set(meta) == {'scan_id', 'profile_id', 'profile_name', 'framework', 'scanner', 'timestamp', 'host', 'certification'}
    assert meta['profile_id'] == 'pqc_evidence_v1' and meta['framework'] == 'CUSTOM'
    assert meta['certification'] == {'status': 'uncertified', 'authority': ''}
    assert meta['scanner'] == {'name': 'custom', 'version': '1.0.0', 'tier': 1}
    row, = out['findings']
    assert set(row) == {'rule_id', 'host', 'title', 'status', 'severity', 'category', 'description',
                        'check_text', 'fix_text', 'evidence', 'remediation', 'stig_id', 'cis_id', 'cce_id',
                        'cci_id', 'actual_value', 'expected_value', 'scanner', 'disruption', 'aap_impact', 'aap_impact_reason'}
    assert set(row['evidence']) == {'actual_value', 'expected_value', 'message', 'scanner_rule_id'}
    assert row['remediation'] == {'role': '', 'available': False, 'disruption': 'low'}
    assert row['actual_value'] == row['evidence']['actual_value'] and row['expected_value'] == row['evidence']['expected_value']
    assert row['severity'] == row['disruption'] == 'low' and row['aap_impact'] == 'caution'


@pytest.mark.parametrize('version', VERSIONS)
def test_c03_unsafe_free_text_not_copied_no_io(rules, standard, version, monkeypatch):
    f = Fixture(version, target='<img onerror=' + SECRET + '>', identity='fixture-identity')
    c = f.collection('scope-' + SECRET)
    asset = f.asset('certificate', 'asset-' + SECRET)
    f.add(c, 'raw-' + SECRET, 'ASSET_METADATA', {'name': '/synthetic/' + SECRET,
          'version': '{{ ' + SECRET + ' }}'}, asset=asset)
    alg = a.classify_algorithm(SECRET, 'SIGNATURE', rules)
    f.add(c, 'raw-alg', 'LEGACY_OBSERVATION', {'field': 'fixture', 'value': '<script>' + SECRET},
          asset=asset, algorithm=alg)
    before = deepcopy(f.doc)
    def forbidden(*args, **kwargs):
        raise AssertionError('I/O or clock access forbidden')
    with monkeypatch.context() as m:
        for obj, key in ((Path, 'open'), (socket, 'socket'), (subprocess, 'Popen'), (time, 'time')):
            m.setattr(obj, key, forbidden)
        m.setattr('builtins.open', forbidden)
        m.setattr('os.system', forbidden)
        result = cff.project_cff(f.doc, rules)
        raw = cff.canonical_projection_bytes(result, f.doc, rules)
    if standard is not None:
        standard.validate(result)
    assert SECRET.encode() not in raw and b'/synthetic/' not in raw and b'<script>' not in raw
    assert b'{{' not in raw
    assert result['per_host'][0]['cff']['scan_metadata']['host'] == f.h
    assert f.doc == before and SECRET in json.dumps(f.doc)


@pytest.mark.parametrize('limit', ('MAX_HOSTS', 'MAX_ROWS', 'MAX_BYTES'))
def test_c03_resource_limits_fail_closed(rules, monkeypatch, limit):
    f = Fixture(); f.direct(f.collection(), 'L1', True)
    monkeypatch.setattr(cff, limit, 0 if limit != 'MAX_BYTES' else 128)
    with pytest.raises(cff.ProjectionError, match='PROJECTION_LIMIT'):
        cff.project_cff(f.doc, rules)


@pytest.mark.parametrize('value', [float('nan'), float('inf'), -1, object(), {'a': object()}, (1, 2)])
def test_c03_projection_non_json_values_rejected(rules, value):
    f = Fixture(); f.direct(f.collection(), 'L1', True)
    with pytest.raises(cff.ProjectionError):
        cff.validate_projection(value, f.doc, rules)


@pytest.mark.parametrize('version', VERSIONS)
@pytest.mark.parametrize('tamper', ('scope', 'cross-host', 'duplicate-host', 'duplicate-finding', 'manifest'))
def test_c03_reject_invalid_evidence_association(rules, version, tamper):
    f = Fixture(version)
    c = f.collection('scope-one')
    f.summary(c, True)
    f.direct(c, 'L2', True)
    other = f.host('host-b.example.invalid')
    b = f.collection('scope-two', host=other)
    other_obs = f.direct(b, 'L2', True)
    assessed = a.evaluate_document(f.doc, rules)
    if tamper == 'scope':
        next(x for x in assessed['evidence'] if x['evidence_kind'] == 'COLLECTION_SUMMARY')['data']['scope'] = 'scope-two'
    elif tamper == 'cross-host':
        row = next(x for x in assessed['claims'] if x['subject']['host_id'] == f.h)
        row['evidence_ids'] = [other_obs['evidence_id']]
    elif tamper == 'duplicate-host':
        assessed['hosts'].append(deepcopy(assessed['hosts'][0]))
    elif tamper == 'duplicate-finding':
        assessed['findings'].append(deepcopy(assessed['findings'][0]))
    else:
        assessed['run']['expected_host_ids'].remove(other)
    with pytest.raises(e.EvidenceError):
        cff.project_cff(assessed, rules)


@pytest.mark.parametrize('version', VERSIONS)
def test_c02_empty_same_scope_different_collectors_exact_error_link(rules, standard, version):
    f = Fixture(version)
    error = f.collection('same-scope', 'ERROR', collector='first')
    unknown = f.collection('same-scope', 'UNKNOWN', collector='second')
    p = host_projection(f.project(rules, standard), f.h)
    by_cid = {r['collection_ids'][0]: r for r in p['companion']['findings']}
    assert by_cid[error['collection_id']]['cff_status'] == 'error'
    assert by_cid[unknown['collection_id']]['cff_status'] == 'not_checked'
    assert by_cid[unknown['collection_id']]['error_collection_ids'] == []


@pytest.mark.parametrize('version', VERSIONS)
def test_c01_legacy_null_observed_at_not_replaced_by_run_clock(rules, standard, version):
    f = Fixture(version)
    c = f.collection('legacy')
    row = f.direct(c, 'L1', True)
    for source in (f.doc['run']['source'], c['source'], row['source']):
        source.update(source_kind='LEGACY_IMPORT', producer_version=None)
    c['collector_version'] = None
    c['observed_at'] = row['observed_at'] = None
    f.doc['run']['started_at'] = f.doc['run']['finished_at'] = None
    entry = host_projection(f.project(rules, standard), f.h)
    assert entry['cff']['scan_metadata']['timestamp'] == REC
    assert entry['companion']['run']['timestamp_kind'] == 'RUN_RECORDED_AT'
    assert entry['companion']['collections'][0]['observed_at'] is None
    assert entry['companion']['evidence'][0]['observed_at'] is None
    assert entry['companion']['evidence'][0]['source']['producer_version'] is None
    assert entry['companion']['score']['denominator'] == 1


@pytest.mark.parametrize('bad', [{'\ud800': 1}, {'bad': '\ud800'}, {'bad': '\u200d'}, {'\x00': 1}])
def test_c03_invalid_unicode_projection_error_constant(rules, bad):
    f = Fixture(); f.direct(f.collection(), 'L1', True)
    with pytest.raises(cff.ProjectionError, match='PROJECTION_TYPE'):
        cff.validate_projection(bad, f.doc, rules)


def test_c03_v1_rejects_v11_only_data(rules):
    f = Fixture('1.0.0')
    f.add(f.collection(), 'tool', 'TOOL_AVAILABILITY', {'tool_id': 'openssl',
            'lookup_scope': 'SYSTEM_EXECUTABLE_PATHS', 'available': True})
    with pytest.raises(e.EvidenceError):
        cff.project_cff(f.doc, rules)


@pytest.mark.parametrize('version', VERSIONS)
@pytest.mark.parametrize('positive,negative,expected', [(1, 2, 33.3), (2, 1, 66.7)])
def test_c02_fact_ratio_rounding(rules, standard, version, positive, negative, expected):
    f = Fixture(version)
    for i in range(positive + negative):
        f.direct(f.collection('scope-' + str(i)), 'L1', i < positive)
    f.collection('failure', 'PERMISSION_DENIED')
    f.collection('unknown', 'UNKNOWN')
    entry = host_projection(f.project(rules, standard), f.h)
    assert entry['cff']['summary']['compliance_score'] == expected
    assert entry['companion']['score']['denominator'] == positive + negative
    assert entry['companion']['score']['excluded'] == 2
