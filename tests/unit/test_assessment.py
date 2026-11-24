"""A01-A03: synthetic taxonomy, independent levels, and offline Evidence V1."""
from copy import deepcopy
import json
from pathlib import Path
import socket
import subprocess
import sys

import pytest

# Both `python -m pytest` and normal repository imports use the fixed root.
ROOT = Path(__file__).resolve().parents[2]
from tools import assessment as a, evidence as e

STAMP = '2026-01-01T00:00:00Z'
RECORDED = '2026-01-02T00:00:00Z'
SECRET = 'SYNTHETIC_SECRET_SENTINEL'


@pytest.fixture(scope='module')
def rules():
    return a.load_rules((ROOT / 'config/assessment_rules.yml').read_bytes())


@pytest.mark.parametrize('name,context,aid,family,primitive', [
    ('MLKEM768', 'KEM_CAPABILITY', 'ml-kem-768', 'PQC', 'KEM'),
    ('ml-kem-512', 'KEM_CAPABILITY', 'ml-kem-512', 'PQC', 'KEM'),
    ('ML-KEM-1024', 'KEM_CAPABILITY', 'ml-kem-1024', 'PQC', 'KEM'),
    ('X25519MLKEM768', 'TLS_KEX', 'tls-x25519-mlkem768', 'HYBRID', 'KEX'),
    ('SecP256r1MLKEM768', 'TLS_KEX', 'tls-secp256r1-mlkem768', 'HYBRID', 'KEX'),
    ('SecP384r1MLKEM1024', 'TLS_KEX', 'tls-secp384r1-mlkem1024', 'HYBRID', 'KEX'),
    ('mlkem768x25519-sha256', 'SSH_KEX', 'ssh-mlkem768x25519-sha256', 'HYBRID', 'KEX'),
    ('sntrup761x25519-sha512@openssh.com', 'SSH_KEX', 'ssh-sntrup761x25519-sha512', 'HYBRID', 'KEX'),
    ('Kyber768', 'KEM_CAPABILITY', 'legacy-kyber-768', 'PQC', 'KEM'),
    ('X25519Kyber768Draft00', 'TLS_KEX', 'tls-x25519-kyber768-draft00', 'HYBRID', 'KEX'),
    ('ML-DSA-65', 'SIGNATURE', 'ml-dsa-65-signature', 'PQC', 'SIGNATURE'),
    ('ML-DSA-65', 'CERT_PUBLIC_KEY', 'ml-dsa-65-public-key', 'PQC', 'PUBLIC_KEY'),
    ('Dilithium3', 'SIGNATURE', 'legacy-dilithium-3-signature', 'PQC', 'SIGNATURE'),
    ('SLH-DSA-SHA2-128s', 'SIGNATURE', 'slh-dsa-sha2-128s-signature', 'PQC', 'SIGNATURE'),
    ('SPHINCS+-SHA2-128s-simple', 'SIGNATURE', 'legacy-sphincs-plus-sha2-128s-simple-signature', 'PQC', 'SIGNATURE'),
    ('RSA', 'CERT_PUBLIC_KEY', 'rsa-public-key', 'CLASSICAL', 'PUBLIC_KEY'),
    ('RSA', 'SIGNATURE', 'rsa-signature', 'CLASSICAL', 'SIGNATURE'),
    ('sha256WithRSAEncryption', 'SIGNATURE', 'rsa-sha256-signature', 'CLASSICAL', 'SIGNATURE'),
    ('ECDSA', 'CERT_PUBLIC_KEY', 'ec-public-key', 'CLASSICAL', 'PUBLIC_KEY'),
    ('ECDSA', 'SIGNATURE', 'ecdsa-signature', 'CLASSICAL', 'SIGNATURE'),
    ('X25519', 'TLS_KEX', 'tls-x25519', 'CLASSICAL', 'KEX'),
    ('curve25519-sha256@libssh.org', 'SSH_KEX', 'ssh-curve25519-sha256', 'CLASSICAL', 'KEX'),
    ('AES', 'SYMMETRIC_CIPHER', 'aes', 'CLASSICAL', 'SYMMETRIC'),
    ('TLS_AES_128_GCM_SHA256', 'TLS_CIPHER', 'tls-aes-128-gcm-sha256', 'CLASSICAL', 'SYMMETRIC'),
    ('aes256-gcm@openssh.com', 'SSH_CIPHER', 'ssh-aes256-gcm-openssh', 'CLASSICAL', 'SYMMETRIC'),
])
def test_a01_exact_taxonomy(rules, name, context, aid, family, primitive):
    assert a.classify_algorithm(name, context, rules) == {
        'algorithm_id': aid, 'family': family, 'primitive': primitive,
        'observed_name': name, 'taxonomy_version': '1.0.0'}


@pytest.mark.parametrize('name,context', [
    ('X25519MLKEM768', 'KEM_CAPABILITY'), ('MLKEM768', 'TLS_KEX'),
    ('X25519MLKEM768', 'SSH_KEX'), ('TLS_AES_128_GCM_SHA256', 'TLS_KEX'),
    ('sha256WithRSAEncryption', 'CERT_PUBLIC_KEY'), ('rsaEncryption', 'SIGNATURE'),
    ('RSA', 'TLS_KEX'), ('AES', 'CERT_PUBLIC_KEY'), ('mlkem768x25519-sha256', 'TLS_KEX'),
    ('prefixMLKEM768', 'KEM_CAPABILITY'), ('MLKEM768-extra', 'KEM_CAPABILITY'),
    ('pqc', 'KEM_CAPABILITY'), ('  MLKEM768', 'KEM_CAPABILITY'),
    ('MLKEM768 ', 'KEM_CAPABILITY'), ('ML_KEM_768', 'KEM_CAPABILITY'),
    ('Kyber', 'KEM_CAPABILITY'), ('X25519+MLKEM768', 'TLS_KEX'),
    ('MLKEM999', 'KEM_CAPABILITY'), ('ML-DSA', 'SIGNATURE'),
    ('2.16.840.1.101.3.4.4.2', 'KEM_CAPABILITY'), ('FIPS', 'KEM_CAPABILITY'),
    ('TLSv1.3', 'TLS_KEX'), ('unknown', 'SIGNATURE'), (None, 'KEM_CAPABILITY'),
])
def test_a01_unknown_context_and_no_substring(rules, name, context):
    assert a.classify_algorithm(name, context, rules) == {
        'algorithm_id': None, 'family': 'UNKNOWN', 'primitive': 'UNKNOWN',
        'observed_name': name, 'taxonomy_version': '1.0.0'}


def test_a01_every_alias_and_migration(rules):
    for row in rules['algorithms']:
        for alias in row['aliases']:
            result = a.classify_algorithm(alias.swapcase(), row['context'], rules)
            assert result['algorithm_id'] == row['algorithm_id']
            assert result['family'] == row['family'] and result['primitive'] == row['primitive']
    cases = [('RSA', 'CERT_PUBLIC_KEY', 'CLASSICAL_PUBLIC_KEY_MIGRATION'),
             ('ECDSA', 'SIGNATURE', 'CLASSICAL_PUBLIC_KEY_MIGRATION'),
             ('AES', 'SYMMETRIC_CIPHER', 'SYMMETRIC_REVIEW'),
             ('Kyber768', 'KEM_CAPABILITY', 'LEGACY_PQC_REVIEW'),
             ('ML-KEM-768', 'KEM_CAPABILITY', 'PQC_OR_HYBRID_INVENTORY'),
             ('X25519MLKEM768', 'TLS_KEX', 'PQC_OR_HYBRID_INVENTORY'),
             ('not-pqc', 'KEM_CAPABILITY', 'UNKNOWN')]
    for name, context, category in cases:
        assert a.migration_classification(a.classify_algorithm(name, context, rules), rules) == category


@pytest.mark.parametrize('name,context,code', [
    ('RSA', 'UNKNOWN_CONTEXT', 'INVALID_OBSERVATION_CONTEXT'),
    ('RSA', [], 'INVALID_OBSERVATION_CONTEXT'), (False, 'SIGNATURE', 'INVALID_ALGORITHM_INPUT'),
    ('', 'SIGNATURE', 'INVALID_ALGORITHM_INPUT'), ('x' * 513, 'SIGNATURE', 'INVALID_ALGORITHM_INPUT'),
    ('{{ ' + SECRET + ' }}', 'SIGNATURE', 'INVALID_ALGORITHM_INPUT'),
    ('RSA\n', 'SIGNATURE', 'INVALID_ALGORITHM_INPUT'), ('RSA\u200d', 'SIGNATURE', 'INVALID_ALGORITHM_INPUT'),
])
def test_a01_bad_classifier_inputs(rules, name, context, code):
    with pytest.raises(a.AssessmentError) as exc:
        a.classify_algorithm(name, context, rules)
    assert exc.value.code == code and SECRET not in str(exc.value)


@pytest.mark.parametrize('raw', [
    b'{"rule_version":"1.0.0","rule_version":"2.0.0"}',
    b'{"algorithms":[{"aliases":[],"aliases":[]}]}',
    b'a: &a [RSA]\nb: *a', b'a: &a {x: 1}\nb: {<<: *a}', b'a: !tag RSA',
    b'{"rule_version":"{{ SYNTHETIC_SECRET_SENTINEL }}"}', b'{"x":NaN}',
    b'{"x":1}', b'{"x":true}', b'{"x":null}', b'\xff', b'\xef\xbb\xbf{}',
    b'[' * 30 + b']' * 30, b' ' * (a.MAX_RULE_BYTES + 1), b'{}', b'{',
])
def test_a01_bad_rules_bytes(raw):
    with pytest.raises(a.AssessmentError) as exc:
        a.load_rules(raw)
    assert SECRET not in str(exc.value)


@pytest.mark.parametrize('change', [
    'unknown-field', 'bad-version', 'bad-taxonomy', 'bad-type', 'bad-context',
    'primitive-mismatch', 'bad-family', 'bad-provenance', 'id-collision', 'alias-collision',
    'duplicate-alias', 'template', 'swap-rule', 'unknown-reason', 'empty-aliases',
    'unknown-row-field', 'cycle', 'oversized-scalar', 'bad-id', 'non-mapping',
])
def test_a01_bad_rules_mapping(rules, change):
    r = deepcopy(rules)
    row = r['algorithms'][0]
    if change == 'unknown-field':
        r[SECRET] = 'x'
    elif change == 'bad-version':
        r['rule_version'] = '2.0.0'
    elif change == 'bad-taxonomy':
        r['taxonomy_version'] = '1.1.0'
    elif change == 'bad-type':
        row['aliases'] = False
    elif change == 'bad-context':
        row['context'] = 'ANY'
    elif change == 'primitive-mismatch':
        row['primitive'] = 'KEX'
    elif change == 'bad-family':
        row['family'] = 'CLASSICAL'
    elif change == 'bad-provenance':
        row['provenance'] = 'UNKNOWN'
    elif change == 'id-collision':
        r['algorithms'].append(deepcopy(row))
    elif change == 'alias-collision':
        duplicate = deepcopy(row)
        duplicate['algorithm_id'] = 'collision'
        duplicate['aliases'] = [row['aliases'][0].swapcase()]
        r['algorithms'].append(duplicate)
    elif change == 'duplicate-alias':
        row['aliases'].append(row['aliases'][0])
    elif change == 'template':
        row['aliases'] = ['{{ ' + SECRET + ' }}']
    elif change == 'swap-rule':
        r['rules']['L2']['evidence_kind'] = 'PACKAGE_INVENTORY'
    elif change == 'unknown-reason':
        r['reason_codes']['positive'] = SECRET
    elif change == 'empty-aliases':
        row['aliases'] = []
    elif change == 'unknown-row-field':
        row['script'] = 'do-not-execute'
    elif change == 'cycle':
        r['loop'] = r
    elif change == 'oversized-scalar':
        row['aliases'] = ['x' * 129]
    elif change == 'bad-id':
        row['algorithm_id'] = 'a.b'
    else:
        r = []
    with pytest.raises(a.AssessmentError) as exc:
        a.validate_rules(r)
    assert SECRET not in str(exc.value)


class Fixture:
    """Generate only typed synthetic records using #10 public ID helpers."""
    def __init__(self, rid='synthetic-run'):
        self.rid = rid
        self.doc = {'schema_version': '1.0.0', 'run': {
            'run_id': rid, 'run_state': 'COMPLETE', 'recorded_at': RECORDED,
            'started_at': None, 'finished_at': None, 'source': self.source('fixture'),
            'expected_host_ids': []}, **{k: [] for k in
                ('hosts', 'collections', 'assets', 'evidence', 'claims', 'findings')}}
        self.h = self.host('host-a.example.invalid')

    @staticmethod
    def source(producer):
        return {'source_kind': 'SYNTHETIC', 'producer_id': producer,
                'producer_version': '1.0', 'origin_ref': 'fixture-origin', 'input_sha256': None}

    def host(self, name, state='COMPLETE'):
        hid = e.host_id('fixture-authority', name)
        self.doc['hosts'].append({'host_id': hid, 'target_id': name, 'identity_scope': 'STABLE',
            'host_state': state, 'reason_code': 'FIXTURE', 'inventory_authority_id': 'fixture-authority',
            'identity_key': None})
        self.doc['run']['expected_host_ids'].append(hid)
        return hid

    def asset(self, kind='service', name='fixture-asset', host=None):
        host = host or self.h
        aid = e.asset_id(host, kind, name, run_id=self.rid)
        self.doc['assets'].append({'asset_id': aid, 'host_id': host, 'asset_kind': kind,
            'identity_scope': 'RUN_SCOPED', 'identity_key': name, 'evidence_ids': []})
        return aid

    def collection(self, scope='fixture-scope', state='COLLECTED', host=None, collector='fixture'):
        host = host or self.h
        cid = e.collection_id(self.rid, host, collector, scope)
        c = {'collection_id': cid, 'host_id': host, 'collector_id': collector,
            'collector_version': '1.0', 'scope_key': scope, 'collection_state': state,
            'reason_code': 'DISABLED_BY_PROFILE' if state == 'NOT_SCANNED' else 'FIXTURE',
            'source': self.source(collector), 'observed_at': None if state == 'NOT_SCANNED' else STAMP,
            'evidence_ids': []}
        self.doc['collections'].append(c)
        return c

    def add(self, c, key, kind, data, asset=None, algorithm=None, observed_at=STAMP):
        row = {'evidence_id': e.evidence_id(self.rid, c['host_id'], c['collection_id'], key),
            'host_id': c['host_id'], 'collection_id': c['collection_id'], 'asset_id': asset,
            'observation_key': key, 'evidence_kind': kind, 'source': deepcopy(c['source']),
            'observed_at': observed_at, 'data': data, 'algorithm': deepcopy(algorithm)}
        c['evidence_ids'].append(row['evidence_id'])
        self.doc['evidence'].append(row)
        if asset:
            next(x for x in self.doc['assets'] if x['asset_id'] == asset)['evidence_ids'].append(row['evidence_id'])
        return row

    def direct(self, c, level, value, key='direct', asset=None, algorithm=None, conditions=None, observed_at=STAMP):
        if level == 'L1':
            data = {'name': 'fixture-package', 'version': '9.9', 'present': value}
        elif level == 'L2':
            data = {'capability': 'fixture-capability', 'supported': value}
        elif level == 'L3':
            data = {'setting': 'fixture-setting', 'effective_value': 'DEFAULT', 'allowed': value}
        else:
            if conditions is None:
                conditions = self.conditions(level, c['host_id'], asset)
            data = {'conditions': conditions, 'outcome': value}
        kinds = {'L1': 'PACKAGE_INVENTORY', 'L2': 'RUNTIME_CAPABILITY', 'L3': 'EFFECTIVE_CONFIGURATION',
                 'L4': 'AUTHORIZED_NEGOTIATION', 'L5': 'OBSERVED_USAGE'}
        return self.add(c, key, kinds[level], data, asset, algorithm, observed_at)

    @staticmethod
    def conditions(level, host, asset):
        common = {'host_id': host, 'service_asset_id': asset}
        if level == 'L4':
            return {**common, 'endpoint_ref': 'fixture-endpoint', 'protocol': 'TLS',
                    'context_ref': 'fixture-context', 'authorization_ref': 'fixture-authorization'}
        return {**common, 'business_source_ref': 'fixture-telemetry', 'method': 'APPLICATION_TELEMETRY',
                'started_at': STAMP, 'finished_at': '2026-01-01T00:01:00Z'}

    def summary(self, c, applicable, key='summary', asset=None, algorithm=None):
        return self.add(c, key, 'COLLECTION_SUMMARY', {'scope': c['scope_key'], 'attempted': True,
            'coverage': 'COMPLETE' if applicable else 'UNKNOWN',
            'observation_count': 0 if applicable else None, 'applicable': applicable}, asset, algorithm)

    def evaluate(self, rules):
        e.validate_document(self.doc)
        out = a.evaluate_document(self.doc, rules)
        e.validate_document(out)
        return out


def hybrid(rules):
    return a.classify_algorithm('X25519MLKEM768', 'TLS_KEX', rules)


@pytest.mark.parametrize('level,positive,negative', [
    ('L1', True, False), ('L2', True, False), ('L3', True, False),
    ('L4', 'NEGOTIATED', 'REJECTED'), ('L5', 'OBSERVED', 'CONTRADICTED'),
])
@pytest.mark.parametrize('wanted', ['PASS', 'FAIL'])
def test_a02_independent_direct_levels(rules, level, positive, negative, wanted):
    f = Fixture()
    service = f.asset() if level in ('L4', 'L5') else None
    row = f.direct(f.collection(), level, positive if wanted == 'PASS' else negative,
                   asset=service, algorithm=hybrid(rules))
    out = f.evaluate(rules)
    assert len(out['claims']) == len(out['findings']) == 1
    cl, finding = out['claims'][0], out['findings'][0]
    assert cl['level'] == level and cl['assessment_state'] == wanted
    assert cl['evidence_ids'] == [row['evidence_id']]
    assert cl['rule_version'] == '1.0.0'
    assert cl['conditions'] == row['data'].get('conditions')
    assert finding['assessment_state'] == wanted and finding['claim_ids'] == [cl['claim_id']]
    assert finding['evidence_ids'] == [] and finding['rule_id'] == cl['rule_id']
    assert cl['subject']['algorithm_id'] == hybrid(rules)['algorithm_id']


@pytest.mark.parametrize('state', ['ERROR', 'PERMISSION_DENIED', 'UNREACHABLE', 'UNKNOWN'])
@pytest.mark.parametrize('value', [True, False])
def test_a02_acquisition_not_verdict(rules, state, value):
    f = Fixture()
    f.direct(f.collection(state=state), 'L2', value, algorithm=hybrid(rules))
    out = f.evaluate(rules)
    assert out['claims'][0]['assessment_state'] == 'UNKNOWN'
    assert out['claims'][0]['reason_code'] == 'ACQUISITION_UNAVAILABLE'
    assert {x['assessment_state'] for x in out['findings']} == {'UNKNOWN'}


@pytest.mark.parametrize('level,value', [('L1', None), ('L2', None), ('L3', None),
    ('L4', 'UNKNOWN'), ('L4', 'ERROR'), ('L4', 'TIMEOUT'), ('L5', 'UNKNOWN')])
def test_a02_missing_or_failed_fact(rules, level, value):
    f = Fixture()
    c = f.collection()
    asset = f.asset() if level in ('L4', 'L5') else None
    f.direct(c, level, value, asset=asset, algorithm=hybrid(rules))
    f.add(c, 'metadata', 'ASSET_METADATA', {'name': 'fixture-metadata', 'version': '9.9'}, asset=asset)
    out = f.evaluate(rules)
    assert len(out['claims']) == 1 and out['claims'][0]['assessment_state'] == 'UNKNOWN'
    assert not any(x['assessment_state'] in ('PASS', 'FAIL') for x in out['findings'])


@pytest.mark.parametrize('changed', ['observed_name', 'family', 'primitive', 'taxonomy_version', 'algorithm_id', 'unknown'])
def test_a02_untrusted_algorithm_annotation_is_unknown(rules, changed):
    f = Fixture()
    alg = hybrid(rules)
    if changed == 'unknown':
        alg = a.classify_algorithm('prefix-pqc-MLKEM768', 'TLS_KEX', rules)
    else:
        alg[changed] = {'observed_name': 'MLKEM768', 'family': 'PQC', 'primitive': 'KEM',
                        'taxonomy_version': '2.0.0', 'algorithm_id': 'ml-kem-768'}[changed]
    f.direct(f.collection(), 'L2', True, algorithm=alg)
    out = f.evaluate(rules)
    assert out['claims'][0]['assessment_state'] == 'UNKNOWN'
    assert out['claims'][0]['reason_code'] == 'UNCLASSIFIED_ALGORITHM'


@pytest.mark.parametrize('name,context,protocol', [
    ('MLKEM768', 'KEM_CAPABILITY', 'TLS'), ('X25519MLKEM768', 'TLS_KEX', 'SSH'),
    ('mlkem768x25519-sha256', 'SSH_KEX', 'TLS'), ('RSA', 'CERT_PUBLIC_KEY', 'TLS'),
    ('AES', 'SYMMETRIC_CIPHER', 'TLS'),
])
def test_a02_negotiation_wrong_context(rules, name, context, protocol):
    f = Fixture()
    asset = f.asset()
    cond = f.conditions('L4', f.h, asset)
    cond['protocol'] = protocol
    f.direct(f.collection(), 'L4', 'NEGOTIATED', asset=asset,
             algorithm=a.classify_algorithm(name, context, rules), conditions=cond)
    assert f.evaluate(rules)['claims'][0]['assessment_state'] == 'UNKNOWN'


def test_a02_cipher_does_not_prove_kex_or_usage(rules):
    f = Fixture()
    asset = f.asset()
    alg = a.classify_algorithm('TLS_AES_128_GCM_SHA256', 'TLS_CIPHER', rules)
    f.direct(f.collection(), 'L4', 'NEGOTIATED', asset=asset, algorithm=alg)
    claims = f.evaluate(rules)['claims']
    assert len(claims) == 1 and claims[0]['level'] == 'L4'
    assert claims[0]['assessment_state'] == 'PASS'
    assert claims[0]['subject']['algorithm_id'] == alg['algorithm_id']


def test_a02_package_version_fips_and_metadata_are_not_pqc_readiness(rules):
    f = Fixture()
    c = f.collection()
    f.add(c, 'os', 'PLATFORM_INFO', {'os_family': 'Oracle Linux', 'os_version': '9.9'})
    f.add(c, 'version', 'ASSET_METADATA', {'name': 'MLKEM768', 'version': '9.9'})
    f.add(c, 'legacy', 'LEGACY_OBSERVATION', {'field': 'pqc', 'value': True})
    f.add(c, 'fips', 'EFFECTIVE_CONFIGURATION', {'setting': 'fips', 'allowed': None, 'effective_value': 'FIPS'})
    f.direct(c, 'L1', True, key='package')
    out = f.evaluate(rules)
    assert {(cl['level'], cl['assessment_state']) for cl in out['claims']} == {('L1', 'PASS'), ('L3', 'UNKNOWN')}
    assert all(cl['subject']['algorithm_id'] is None for cl in out['claims'])


def test_a02_partial_collection_can_prove_exact_fact_not_full_coverage(rules):
    f = Fixture()
    row = f.direct(f.collection(state='PARTIAL'), 'L2', True)
    out = f.evaluate(rules)
    assert out['claims'][0]['assessment_state'] == 'PASS'
    coverage = next(x for x in out['findings'] if x['rule_id'] == 'pqc-coverage')
    assert coverage['assessment_state'] == 'PARTIAL' and coverage['evidence_ids'] == [row['evidence_id']]


@pytest.mark.parametrize('level,positive,negative', [('L1', True, False), ('L2', True, False), ('L3', True, False),
    ('L4', 'NEGOTIATED', 'REJECTED'), ('L5', 'OBSERVED', 'CONTRADICTED')])
def test_a02_conflict_same_subject_scope_context(rules, level, positive, negative):
    f = Fixture()
    asset = f.asset() if level in ('L4', 'L5') else None
    alg = hybrid(rules)
    first = f.direct(f.collection(), level, positive, asset=asset, algorithm=alg)
    second = f.direct(f.collection(collector='fixture-two'), level, negative, asset=asset,
                      algorithm=alg, observed_at='2026-01-01T00:00:01Z')
    out = f.evaluate(rules)
    assert len(out['claims']) == 1
    cl = out['claims'][0]
    assert cl['assessment_state'] == 'PARTIAL' and cl['reason_code'] == 'CONFLICTING_EVIDENCE'
    assert set(cl['evidence_ids']) == {first['evidence_id'], second['evidence_id']}


@pytest.mark.parametrize('separation', ['scope', 'fact', 'asset', 'host', 'algorithm'])
def test_a02_no_cross_subject_or_scope_borrowing(rules, separation):
    f = Fixture()
    c = f.collection()
    asset = f.asset('library') if separation == 'asset' else None
    alg = hybrid(rules)
    first = f.direct(c, 'L2', True, asset=asset, algorithm=alg)
    other = f.collection('fixture-other-scope') if separation == 'scope' else c
    if separation == 'host':
        other = f.collection(host=f.host('host-b.example.invalid'))
    second = f.direct(other, 'L2', False, key='other',
        asset=f.asset('library', 'fixture-other-asset') if separation == 'asset' else None,
        algorithm=a.classify_algorithm('MLKEM768', 'KEM_CAPABILITY', rules) if separation == 'algorithm' else alg)
    if separation == 'fact':
        second['data']['capability'] = 'different-capability'
    out = f.evaluate(rules)
    assert len(out['claims']) == 2
    assert {cl['assessment_state'] for cl in out['claims']} == {'PASS', 'FAIL'}
    assert {tuple(cl['evidence_ids']) for cl in out['claims']} == {(first['evidence_id'],), (second['evidence_id'],)}


@pytest.mark.parametrize('level,field,value,yes,no', [
    ('L4', 'endpoint_ref', 'another-endpoint', 'NEGOTIATED', 'REJECTED'),
    ('L4', 'context_ref', 'another-context', 'NEGOTIATED', 'REJECTED'),
    ('L4', 'authorization_ref', 'another-authorization', 'NEGOTIATED', 'REJECTED'),
    ('L5', 'method', 'SERVICE_AUDIT_RECORD', 'OBSERVED', 'CONTRADICTED'),
    ('L5', 'business_source_ref', 'another-source', 'OBSERVED', 'CONTRADICTED'),
    ('L5', 'finished_at', '2026-01-01T00:02:00Z', 'OBSERVED', 'CONTRADICTED'),
])
def test_a02_distinct_actual_conditions(rules, level, field, value, yes, no):
    f = Fixture()
    c, asset = f.collection(), f.asset()
    one = f.direct(c, level, yes, asset=asset, algorithm=hybrid(rules))
    conditions = f.conditions(level, f.h, asset)
    conditions[field] = value
    two = f.direct(c, level, no, key='other', asset=asset, algorithm=hybrid(rules), conditions=conditions)
    out = f.evaluate(rules)
    assert len(out['claims']) == 2
    for cl in out['claims']:
        row = one if cl['assessment_state'] == 'PASS' else two
        assert cl['conditions'] == row['data']['conditions'] and cl['evidence_ids'] == [row['evidence_id']]


def test_a02_usage_time_invalid_rejected_by_original_model(rules):
    f = Fixture()
    asset = f.asset()
    f.direct(f.collection(), 'L5', 'OBSERVED', asset=asset, algorithm=hybrid(rules),
             observed_at='2026-01-03T00:00:00Z')
    with pytest.raises(e.EvidenceError) as exc:
        a.evaluate_document(f.doc, rules)
    assert exc.value.code == 'USAGE_TIME_ORDER'


@pytest.mark.parametrize('state,expected', [('NOT_SCANNED', 'NOT_SCANNED'), ('ERROR', 'UNKNOWN'),
    ('PERMISSION_DENIED', 'UNKNOWN'), ('UNKNOWN', 'UNKNOWN'), ('UNREACHABLE', 'UNKNOWN')])
def test_a02_no_observations(rules, state, expected):
    f = Fixture()
    f.collection(state=state)
    out = f.evaluate(rules)
    assert out['claims'] == []
    assert len(out['findings']) == 1 and out['findings'][0]['assessment_state'] == expected
    assert out['findings'][0]['evidence_ids'] == []
    if state == 'NOT_SCANNED':
        assert out['findings'][0]['reason_code'] == 'DISABLED_BY_PROFILE'


def test_a02_complete_empty_is_not_failure(rules):
    f = Fixture()
    f.summary(f.collection(), True)
    out = f.evaluate(rules)
    assert out['claims'] == [] and out['findings'][0]['assessment_state'] == 'UNKNOWN'


def test_a02_explicit_same_scope_applicability(rules):
    f = Fixture()
    c = f.collection(state='NOT_APPLICABLE')
    summary = f.summary(c, False)
    f.direct(c, 'L2', None)
    out = f.evaluate(rules)
    assert out['claims'][0]['assessment_state'] == 'NOT_APPLICABLE'
    assert out['claims'][0]['evidence_ids'] == [summary['evidence_id']]
    assert {x['assessment_state'] for x in out['findings']} == {'NOT_APPLICABLE'}


@pytest.mark.parametrize('foreign', ['scope', 'asset', 'algorithm', 'host'])
def test_a02_do_not_borrow_applicability(rules, foreign):
    f = Fixture()
    c = f.collection(state='UNKNOWN')
    asset = f.asset('library') if foreign == 'asset' else None
    alg = hybrid(rules) if foreign == 'algorithm' else None
    f.direct(c, 'L2', None, asset=asset, algorithm=alg)
    na = f.collection(scope='other-scope' if foreign == 'scope' else c['scope_key'], state='NOT_APPLICABLE',
        host=f.host('host-b.example.invalid') if foreign == 'host' else f.h, collector='fixture-na')
    f.summary(na, False)
    out = f.evaluate(rules)
    assert out['claims'][0]['assessment_state'] == 'UNKNOWN'
    assert any(x['assessment_state'] == 'NOT_APPLICABLE' for x in out['findings'])


def test_a02_conflicting_applicability_is_not_pass(rules):
    f = Fixture()
    c = f.collection()
    actual = f.direct(c, 'L2', True)
    summary = f.summary(c, False)
    out = f.evaluate(rules)
    cl = out['claims'][0]
    assert cl['assessment_state'] == 'PARTIAL'
    assert set(cl['evidence_ids']) == {actual['evidence_id'], summary['evidence_id']}


def test_a02_absence_of_collection(rules):
    f = Fixture()
    out = f.evaluate(rules)
    assert out['claims'] == [] and out['findings'][0]['assessment_state'] == 'UNKNOWN'
    f.doc['hosts'][0]['host_state'] = 'NOT_ATTEMPTED'
    f.doc['run']['run_state'] = 'PLANNED'
    out = f.evaluate(rules)
    assert out['claims'] == [] and out['findings'][0]['assessment_state'] == 'NOT_SCANNED'


def test_a02_partial_direct_plus_unknown(rules):
    f = Fixture()
    c = f.collection()
    f.direct(c, 'L2', True)
    f.direct(c, 'L2', None, key='unknown')
    assert f.evaluate(rules)['claims'][0]['assessment_state'] == 'PARTIAL'


def test_a03_deterministic_and_unchanged(rules):
    f = Fixture()
    c = f.collection()
    f.direct(c, 'L1', True)
    f.direct(c, 'L2', False, key='two')
    f.direct(c, 'L3', True, key='three')
    original, policy = deepcopy(f.doc), deepcopy(rules)
    out = f.evaluate(rules)
    assert f.doc == original and rules == policy
    assert out['evidence'] == json.loads(e.canonical_bytes(original))['evidence']
    assert a.evaluate_document(out, rules) == out
    shuffled = deepcopy(f.doc)
    shuffled['evidence'].reverse()
    shuffled['collections'][0]['evidence_ids'].reverse()
    assert e.canonical_bytes(a.evaluate_document(shuffled, rules)) == e.canonical_bytes(out)
    assert e.parse_evidence_bytes(e.canonical_bytes(out)) == out
    for cl in out['claims']:
        assert cl['claim_id'] == e.claim_id(f.rid, cl['subject'], cl['level'], cl['rule_id'], cl['claim_key'], cl['conditions'])
    for finding in out['findings']:
        assert finding['finding_id'] == e.finding_id(finding['subject'], finding['rule_id'], finding['condition_key'])


def test_a03_stable_finding_across_runs_not_claim_id(rules):
    results = []
    for rid in ('run-one', 'run-two'):
        f = Fixture(rid)
        f.direct(f.collection(), 'L1', True)
        results.append(f.evaluate(rules))
    x, y = results
    assert x['claims'][0]['claim_id'] != y['claims'][0]['claim_id']
    assert x['findings'][0]['finding_id'] == y['findings'][0]['finding_id']


def test_a03_preserve_other_results(rules):
    f = Fixture()
    f.direct(f.collection(), 'L1', True)
    evaluated = f.evaluate(rules)
    cl = deepcopy(evaluated['claims'][0])
    cl['rule_id'] = 'external-rule'
    cl['rule_version'] = '2.0'
    cl['claim_id'] = e.claim_id(f.rid, cl['subject'], cl['level'], cl['rule_id'], cl['claim_key'], cl['conditions'])
    finding = deepcopy(evaluated['findings'][0])
    finding['rule_id'] = cl['rule_id']
    finding['rule_version'] = cl['rule_version']
    finding['finding_id'] = e.finding_id(finding['subject'], finding['rule_id'], finding['condition_key'])
    finding['claim_ids'] = [cl['claim_id']]
    f.doc['claims'].append(cl)
    f.doc['findings'].append(finding)
    out = f.evaluate(rules)
    assert len(out['claims']) == len(out['findings']) == 2
    assert cl in out['claims'] and finding in out['findings']


@pytest.mark.parametrize('which', ['claim', 'finding', 'version', 'stale'])
def test_a03_owned_conflict_not_overwritten(rules, which):
    f = Fixture()
    f.direct(f.collection(), 'L1', True)
    out = f.evaluate(rules)
    if which == 'claim':
        out['claims'][0]['reason_code'] = 'OTHER_REASON'
    elif which == 'finding':
        out['findings'][0]['reason_code'] = 'OTHER_REASON'
    elif which == 'version':
        out['claims'][0]['rule_version'] = out['findings'][0]['rule_version'] = '2.0'
    else:
        cl = deepcopy(out['claims'][0])
        cl['claim_key'] = 'stale-fact'
        cl['claim_id'] = e.claim_id(f.rid, cl['subject'], cl['level'], cl['rule_id'], cl['claim_key'])
        out['claims'].append(cl)
    e.validate_document(out)
    before = deepcopy(out)
    with pytest.raises(a.AssessmentError) as exc:
        a.evaluate_document(out, rules)
    assert exc.value.code == 'ASSESSMENT_CONFLICT' and out == before


def test_a03_no_io_and_safe_generated_values(rules, monkeypatch):
    f = Fixture()
    c = f.collection(scope='fixture-scope-' + SECRET)
    row = f.direct(c, 'L1', True)
    row['data']['name'] = SECRET
    def forbidden(*args, **kwargs):
        raise AssertionError('I/O not permitted in pure API')
    monkeypatch.setattr('builtins.open', forbidden)
    monkeypatch.setattr(Path, 'open', forbidden)
    monkeypatch.setattr(socket, 'socket', forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    monkeypatch.setattr('os.system', forbidden)
    assert a.classify_algorithm('RSA', 'SIGNATURE', rules)['primitive'] == 'SIGNATURE'
    out = f.evaluate(rules)
    assert SECRET not in json.dumps(out['claims'] + out['findings'])
    # Existing private evidence is retained, not advertised as sanitized output.
    assert out['evidence'][0]['data']['name'] == SECRET


def test_a03_invalid_reference_is_rejected(rules):
    f = Fixture()
    row = f.direct(f.collection(), 'L2', True)
    row['collection_id'] = 'c-' + '0' * 64
    with pytest.raises(e.EvidenceError):
        a.evaluate_document(f.doc, rules)


@pytest.mark.parametrize('case', ['different-time', 'invalid-annotation', 'unclassified'])
def test_a02_applicability_needs_matching_time_and_taxonomy(rules, case):
    f = Fixture()
    c = f.collection(state='UNKNOWN')
    alg = hybrid(rules)
    if case == 'unclassified':
        alg = a.classify_algorithm('not-known-one', 'TLS_KEX', rules)
    f.direct(c, 'L2', None, algorithm=alg)
    na = f.collection(state='NOT_APPLICABLE', collector='fixture-na')
    other = deepcopy(alg)
    if case == 'invalid-annotation':
        other['family'] = 'PQC'
    elif case == 'unclassified':
        other['observed_name'] = 'not-known-two'
    summary = f.summary(na, False, algorithm=other)
    if case == 'different-time':
        summary['observed_at'] = '2026-01-01T00:00:01Z'
    out = f.evaluate(rules)
    assert out['claims'][0]['assessment_state'] == 'UNKNOWN'
    assert summary['evidence_id'] not in out['claims'][0]['evidence_ids']
    if case != 'different-time':
        assert not any(x['assessment_state'] == 'NOT_APPLICABLE' for x in out['findings'])


def test_a02_fips_boolean_only_describes_its_setting(rules):
    f = Fixture()
    f.add(f.collection(), 'fips', 'EFFECTIVE_CONFIGURATION',
          {'setting': 'fips', 'effective_value': 'FIPS', 'allowed': True})
    claims = f.evaluate(rules)['claims']
    assert len(claims) == 1 and claims[0]['level'] == 'L3'
    assert claims[0]['assessment_state'] == 'PASS' and claims[0]['subject']['algorithm_id'] is None


# F-R1-01: the two versions share the coverage contract, not readiness.
# The 1.1.0 cases are also reusable by a private, fixed-S1 validator projection.
# No optional dependency, discovery of a validator path, or skipped test is needed.
_R1_PLATFORM_NULL = {'os_family': None, 'os_version': None, 'distribution': None,
    'major': None, 'minor': None, 'patch': None, 'architecture': None,
    'platform_status': 'UNKNOWN'}
_R1_PLATFORM_KNOWN = {**_R1_PLATFORM_NULL, 'os_family': 'redhat', 'os_version': '9.10',
    'distribution': 'oracle-linux', 'major': 9, 'minor': 10,
    'architecture': 'x86_64', 'platform_status': 'UNVERIFIED'}


def r1_tool(available):
    return {'tool_id': 'openssl', 'lookup_scope': 'SYSTEM_EXECUTABLE_PATHS',
            'available': available}


@pytest.mark.parametrize('kind,data,expected', [
    ('PLATFORM_INFO', {'os_family': None, 'os_version': None}, False),
    ('PLATFORM_INFO', {'os_family': 'Oracle Linux', 'os_version': None}, True),
    ('PLATFORM_INFO', {'os_family': None, 'os_version': '9.9'}, True),
    ('PLATFORM_INFO', _R1_PLATFORM_NULL, False),
    ('PLATFORM_INFO', {**_R1_PLATFORM_NULL, 'architecture': 'x86_64'}, True),
    ('PLATFORM_INFO', _R1_PLATFORM_KNOWN, True),
    ('TOOL_AVAILABILITY', r1_tool(True), True),
    ('TOOL_AVAILABILITY', r1_tool(False), True),
    ('TOOL_AVAILABILITY', r1_tool(None), False),
])
def test_r1_coverage_nontrivial(kind, data, expected):
    assert a._coverage_nontrivial({'evidence_kind': kind, 'data': data}) is expected
    assert kind not in a.KIND_LEVEL


def check_r1_coverage_case(rules, version, state, observations, expected, reason, selected):
    """Use the actual imported validator, assessment and canonical public APIs.

    For 1.1.0, call from the fixed S1 projection; the original 1.0.0 validator
    must not be made to accept the new version or have its functions mocked.
    """
    f = Fixture()
    f.doc['schema_version'] = version
    c = f.collection(state=state)
    rows = [f.add(c, key, kind, deepcopy(data)) for key, kind, data in observations]
    before = deepcopy(f.doc)
    if expected == 'REJECT':
        with pytest.raises(e.EvidenceError) as exc:
            a.evaluate_document(f.doc, rules)
        assert exc.value.code == reason and f.doc == before
        return
    out = f.evaluate(rules)
    assert f.doc == before
    assert out['schema_version'] == version and out['claims'] == []
    assert len(out['findings']) == 1
    finding = out['findings'][0]
    assert finding['rule_id'] == 'pqc-coverage'
    assert finding['assessment_state'] == expected and finding['reason_code'] == reason
    assert finding['claim_ids'] == []
    assert finding['evidence_ids'] == sorted(rows[i]['evidence_id'] for i in selected)
    canonical = e.canonical_bytes(out)
    assert e.parse_evidence_bytes(canonical) == out
    assert e.canonical_bytes(a.evaluate_document(out, rules)) == canonical
    assert out['evidence'] == json.loads(e.canonical_bytes(before))['evidence']


@pytest.mark.parametrize('data,state,expected,reason,selected', [
    ({'os_family': 'Oracle Linux', 'os_version': '9.9'}, 'PARTIAL',
     'PARTIAL', 'INCOMPLETE_COLLECTION', (0,)),
    ({'os_family': None, 'os_version': None}, 'UNKNOWN',
     'UNKNOWN', 'ACQUISITION_UNAVAILABLE', (0,)),
    ({'os_family': None, 'os_version': None}, 'PARTIAL',
     'REJECT', 'PARTIAL_EVIDENCE_REQUIRED', ()),
])
def test_r1_original_platform_coverage(rules, data, state, expected, reason, selected):
    check_r1_coverage_case(rules, '1.0.0', state, [('platform', 'PLATFORM_INFO', data)],
                           expected, reason, selected)


def r1_v11_cases():
    """Named, bounded 1.1.0 end-to-end cases; no source/path selection."""
    unknown = ('platform', 'PLATFORM_INFO', _R1_PLATFORM_NULL)
    known = ('platform', 'PLATFORM_INFO', _R1_PLATFORM_KNOWN)
    arch = ('platform', 'PLATFORM_INFO', {**_R1_PLATFORM_NULL, 'architecture': 'x86_64'})
    yes, no, missing = [('tool', 'TOOL_AVAILABILITY', r1_tool(v)) for v in (True, False, None)]
    return [
        ('CE01', 'PARTIAL', [unknown, yes], 'PARTIAL', 'INCOMPLETE_COLLECTION', (1,)),
        ('CE02a', 'PARTIAL', [yes], 'PARTIAL', 'INCOMPLETE_COLLECTION', (0,)),
        ('CE02b', 'PARTIAL', [no], 'PARTIAL', 'INCOMPLETE_COLLECTION', (0,)),
        ('unknown-platform-known-absent', 'PARTIAL', [unknown, no], 'PARTIAL', 'INCOMPLETE_COLLECTION', (1,)),
        ('known-platform-unknown-tool', 'PARTIAL', [known, missing], 'PARTIAL', 'INCOMPLETE_COLLECTION', (0,)),
        ('known-architecture', 'PARTIAL', [arch], 'PARTIAL', 'INCOMPLETE_COLLECTION', (0,)),
        ('both-known', 'PARTIAL', [known, no], 'PARTIAL', 'INCOMPLETE_COLLECTION', (0, 1)),
        ('all-unknown', 'UNKNOWN', [unknown, missing], 'UNKNOWN', 'ACQUISITION_UNAVAILABLE', (0, 1)),
        ('unknown-tool-only', 'UNKNOWN', [missing], 'UNKNOWN', 'ACQUISITION_UNAVAILABLE', (0,)),
        ('unknown-partial-invalid', 'PARTIAL', [unknown, missing], 'REJECT', 'PARTIAL_EVIDENCE_REQUIRED', ()),
        ('unknown-collected-invalid', 'COLLECTED', [unknown], 'REJECT', 'COLLECTION_EVIDENCE_REQUIRED', ()),
        ('known-but-failed-acquisition', 'ERROR', [yes], 'UNKNOWN', 'ACQUISITION_UNAVAILABLE', (0,)),
        ('collected-present', 'COLLECTED', [yes], 'UNKNOWN', 'NO_DIRECT_EVIDENCE', (0,)),
        ('collected-absent', 'COLLECTED', [no], 'UNKNOWN', 'NO_DIRECT_EVIDENCE', (0,)),
    ]


def check_r1_release_package(rules, present):
    f = Fixture()
    f.doc['schema_version'] = '1.1.0'
    c = f.collection()
    row = f.add(c, 'rpm', 'PACKAGE_INVENTORY', {'name': 'oraclelinux-release',
        'version': '9.9' if present else None, 'present': present,
        'release': '0.1' if present else None, 'architecture': 'x86_64' if present else None})
    f.add(c, 'platform', 'PLATFORM_INFO', deepcopy(_R1_PLATFORM_KNOWN))
    f.add(c, 'tool', 'TOOL_AVAILABILITY', r1_tool(True))
    out = f.evaluate(rules)
    assert out['schema_version'] == '1.1.0'
    assert len(out['claims']) == 1
    cl = out['claims'][0]
    assert cl['level'] == 'L1' and cl['subject']['algorithm_id'] is None
    assert cl['assessment_state'] == ('PASS' if present else 'FAIL')
    assert cl['evidence_ids'] == [row['evidence_id']]
    assert len(out['findings']) == 2
    assert next(x for x in out['findings'] if x['rule_id'] == 'pqc-coverage')['assessment_state'] == 'UNKNOWN'
    assert e.parse_evidence_bytes(e.canonical_bytes(out)) == out
