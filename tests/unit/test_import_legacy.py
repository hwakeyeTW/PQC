"""L01-L03: synthetic legacy producer shapes, strict import and real assessment."""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import socket
import subprocess
import sys

import pytest
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
# Fixed source root for python -I -B -m pytest; no input-directed imports.
sys.path.insert(0, str(ROOT))
from tools import assessment as a, evidence as e, import_legacy as m

HOST = 'host-a.example.invalid'
RID = 'fixture-new-run'
STAMP = '2026-01-03T00:00:00Z'
SECRET = 'SYNTHETIC_SECRET_SENTINEL'


@pytest.fixture(scope='module')
def rules():
    return a.load_rules((ROOT / 'config/assessment_rules.yml').read_bytes())


@pytest.fixture(scope='module')
def fixtures():
    return json.loads((ROOT / 'tests/fixtures/legacy_report.json').read_bytes())


@pytest.fixture(scope='module')
def schema():
    raw = json.loads((ROOT / 'schemas/evidence.schema.json').read_bytes())
    Draft202012Validator.check_schema(raw)
    assert e.model_schema('1.0.0') == raw
    return Draft202012Validator(raw, format_checker=FormatChecker())


def raw(data):
    return json.dumps(data, ensure_ascii=False, allow_nan=False, separators=(',', ':')).encode()


def run(data, rules, fmt=m.FORMATS[0], **kwargs):
    b = data if type(data) is bytes else raw(data)
    return m.import_legacy(b, format_id=fmt, run_id=kwargs.pop('run_id', RID),
                           recorded_at=kwargs.pop('recorded_at', STAMP),
                           origin_ref=kwargs.pop('origin_ref', 'fixture-source'), rules=rules, **kwargs)


def scope(doc, name, host=None):
    hid = next(h['host_id'] for h in doc['hosts'] if host is None or h['target_id'] == host)
    return next(c for c in doc['collections'] if c['host_id'] == hid and c['scope_key'] == name)


def rows(doc, name, host=None):
    refs = scope(doc, name, host)['evidence_ids']
    return [x for x in doc['evidence'] if x['evidence_id'] in refs]


def error(data, rules, code, fmt=m.FORMATS[0], **kwargs):
    with pytest.raises(m.LegacyImportError) as exc:
        run(data, rules, fmt, **kwargs)
    assert exc.value.code == code
    assert str(exc.value) == code and SECRET not in str(exc.value)


@pytest.mark.parametrize('fmt', m.FORMATS)
def test_l01_l03_three_producers_end_to_end(rules, fixtures, schema, fmt):
    data = deepcopy(fixtures[fmt])
    before = deepcopy(data)
    b = raw(data)
    result = run(b, rules, fmt)
    doc = result.document
    assert data == before and b == raw(before)
    assert doc['schema_version'] == '1.0.0'
    assert doc['claims'] == doc['findings'] == []
    assert doc['run']['source'] == {'source_kind': 'LEGACY_IMPORT', 'producer_id': fmt,
        'producer_version': None, 'origin_ref': 'fixture-source', 'input_sha256': sha256(b).hexdigest()}
    assert result.provenance['input_sha256'] == sha256(b).hexdigest()
    assert doc['run']['recorded_at'] == STAMP and doc['run']['started_at'] is None and doc['run']['finished_at'] is None
    assert doc['run']['run_state'] == 'PARTIAL'
    assert all(h['identity_scope'] == 'RUN_SCOPED' for h in doc['hosts'])
    assert all(x['identity_scope'] == 'RUN_SCOPED' for x in doc['assets'])
    assert {h['host_id'] for h in doc['hosts']} == set(doc['run']['expected_host_ids'])
    assert all(x['observed_at'] is None and x['source'] == doc['run']['source'] for x in doc['evidence'] + doc['collections'])
    assert all(c['collection_state'] in ('UNKNOWN', 'PARTIAL') for c in doc['collections'])
    e.validate_document(doc)
    schema.validate(doc)
    canonical = e.canonical_bytes(doc)
    assert e.parse_evidence_bytes(canonical) == doc
    assert run(b, rules, fmt) == result
    out = a.evaluate_document(doc, rules)
    e.validate_document(out)
    schema.validate(out)
    assert out['schema_version'] == '1.0.0' and doc['claims'] == doc['findings'] == []
    assert {cl['level'] for cl in out['claims']} <= {'L1', 'L2'}
    assert all(cl['assessment_state'] == 'PASS' for cl in out['claims'])
    assert not any(f['assessment_state'] == 'FAIL' for f in out['findings'])
    assert e.parse_evidence_bytes(e.canonical_bytes(out)) == out
    assert a.evaluate_document(out, rules) == out


def test_l01_report_and_aggregate_times_not_observations(rules, fixtures):
    fmt = m.FORMATS[2]
    data = fixtures[fmt]
    result = run(data, rules, fmt, source_version='0.9.1')
    doc = result.document
    assert result.provenance['original_run_id'] == data['run_id']
    assert result.provenance['original_generated_at'] == data['generated_at']
    assert doc['run']['run_id'] == RID and doc['run']['source']['producer_version'] == '0.9.1'
    assert doc['run']['source']['producer_id'] == fmt
    reported = rows(doc, 'report-metadata', data['successful_hosts'][0])
    assert reported[0]['data'] == {'field': 'original-collected-at', 'value': data['reports'][0]['collected_at']}
    assert reported[0]['observed_at'] is None


@pytest.mark.parametrize('value', ['2026-02-30T00:00:00Z', 'now', '2026-01-01T00:00:00+08:00', 1, True, SECRET])
def test_l01_invalid_original_time_is_gap(rules, value):
    res = run({'host': HOST, 'collected_at': value}, rules)
    assert res.document['run']['run_state'] == 'ERROR'
    assert rows(res.document, 'report-metadata') == []
    assert res.diagnostics['MALFORMED_TIMESTAMP'] == 1
    assert SECRET not in json.dumps(res)


@pytest.mark.parametrize('kwargs', [{'run_id': '../other'}, {'run_id': True}, {'recorded_at': 'bad'},
    {'recorded_at': '2026-02-30T00:00:00Z'}, {'origin_ref': 'file:/fixture'},
    {'origin_ref': 'https://example.invalid'}, {'source_version': 'v@x'}, {'source_version': []}])
def test_l01_trusted_metadata_constraints(rules, kwargs):
    error({'host': HOST}, rules, 'CALLER_METADATA', **kwargs)


@pytest.mark.parametrize('data,code', [
    (b'{', 'INVALID_JSON'), (b'<html>fixture</html>', 'INVALID_JSON'), (b'%PDF-1.0', 'INVALID_JSON'),
    (b'\xff', 'INVALID_JSON'), (b'\xef\xbb\xbf{}', 'INVALID_JSON'), (b'[]', 'FORMAT_SHAPE'),
    (b'{"host":"a","host":"b"}', 'DUPLICATE_KEY'),
    (b'{"host":"a","nested":{"x":1,"x":2}}', 'DUPLICATE_KEY'),
    (b'{"host":"a","x":NaN}', 'NONFINITE'), (b'{"host":"a","x":Infinity}', 'NONFINITE'),
    (b'{"host":"a","x":-Infinity}', 'NONFINITE'), (b'{"host":"a","x":1e999}', 'NONFINITE'),
    (b'{"host":"a","x":9007199254740992}', 'INTEGER_LIMIT'),
    (b'{"host":"a","x":"\\ud800"}', 'INVALID_STRING'),
    (b'{"host":"a","x":"\\u0000"}', 'INVALID_STRING'),
    (b'{"host":"a","x":' + b'[' * 65 + b'0' + b']' * 65 + b'}', 'DEPTH_LIMIT'),
])
def test_l01_strict_json(rules, data, code):
    error(data, rules, code)


def test_l01_nonbytes_and_limits(rules, monkeypatch):
    with pytest.raises(m.LegacyImportError, match='^INPUT_TYPE$'):
        m.import_legacy(bytearray(b'{}'), format_id=m.FORMATS[0], run_id=RID,
            recorded_at=STAMP, origin_ref='fixture', rules=rules)
    monkeypatch.setattr(m, 'MAX_BYTES', 32)
    error(b' ' * 33, rules, 'SIZE_LIMIT')


def test_l01_actual_byte_and_depth_boundary(rules):
    error(b' ' * (m.MAX_BYTES + 1), rules, 'SIZE_LIMIT')
    # Delimiters inside strings must not be counted as nesting.
    res = run({'host': HOST, 'ignored': '[' * 100 + '\\"' + '}' * 100}, rules)
    assert res.diagnostics['UNKNOWN_FIELD'] == 1


@pytest.mark.parametrize('fmt', ['auto', '1.0.0', 'HTML', None, []])
def test_l01_explicit_dialect(rules, fmt):
    error({'host': HOST}, rules, 'UNSUPPORTED_FORMAT', fmt)


@pytest.mark.parametrize('data,fmt', [({'hosts': []}, m.FORMATS[0]),
    ({'host': HOST, 'reports': []}, m.FORMATS[0]),
    ({'host': HOST, 'selected_hosts': []}, m.FORMATS[0]),
    ({'hosts': [], 'total_hosts': 0, 'reports': []}, m.FORMATS[1]),
    ({'hosts': [], 'total_hosts': 0, 'host': HOST}, m.FORMATS[1]),
    ({'report': {'host': HOST}}, m.FORMATS[1]),
    ({'reports': [], 'run_id': 'old', 'hosts': []}, m.FORMATS[2]),
    ({'schema_version': '1.0.0', 'run': {}}, m.FORMATS[2])])
def test_l01_reject_mixed_unknown_wrapper(rules, data, fmt):
    error(data, rules, 'FORMAT_SHAPE', fmt)


@pytest.mark.parametrize('name', [None, '', False, 123, 'unknown', '../host', 'file:host',
    'https://example.invalid', '{{ ' + SECRET + ' }}', 'host\nname', 'host name', 'x' * 513])
def test_l02_literal_host_identity(rules, name):
    error({'host': name}, rules, 'HOST_IDENTITY')


@pytest.mark.parametrize('count', [True, False, '1', 1.0, -1, 0, 2, None])
def test_l02_fleet_count_strict(rules, count):
    error({'hosts': [{'host': HOST}], 'total_hosts': count}, rules, 'MANIFEST_COUNT', m.FORMATS[1])


def test_l02_fleet_not_expected_inventory(rules, fixtures):
    doc = run(fixtures[m.FORMATS[1]], rules, m.FORMATS[1]).document
    assert len(doc['hosts']) == 2 and doc['run']['scope_reason'] == 'LEGACY_SCOPE_UNKNOWN'
    states = {h['target_id']: h['host_state'] for h in doc['hosts']}
    assert states == {'host-b.example.invalid': 'PARTIAL', 'host-c.example.invalid': 'ERROR'}
    empty = run({'hosts': [], 'total_hosts': 0}, rules, m.FORMATS[1]).document
    assert empty['run']['run_state'] == 'ERROR' and empty['run']['expected_host_ids'] == []


def test_l02_missing_report_manifest(rules, fixtures):
    doc = run(fixtures[m.FORMATS[2]], rules, m.FORMATS[2]).document
    assert doc['run']['scope_reason'] == 'LEGACY_SELECTED_MANIFEST'
    assert len(doc['hosts']) == 3 and len(doc['run']['expected_host_ids']) == 3
    missing = next(h for h in doc['hosts'] if h['target_id'] == 'host-f.example.invalid')
    assert missing['host_state'] == 'ERROR' and missing['reason_code'] == 'LEGACY_REPORT_MISSING'
    c = [x for x in doc['collections'] if x['host_id'] == missing['host_id']]
    assert {x['scope_key'] for x in c} == set(m.SCOPES)
    assert all(x['collection_state'] == 'UNKNOWN' and x['reason_code'] == 'LEGACY_REPORT_MISSING' and not x['evidence_ids'] for x in c)
    assert next(h for h in doc['hosts'] if h['target_id'] == 'host-e.example.invalid')['host_state'] == 'ERROR'


@pytest.mark.parametrize('change,code', [('selected-duplicate', 'DUPLICATE_HOST'),
    ('successful-duplicate', 'DUPLICATE_HOST'), ('missing-duplicate', 'DUPLICATE_HOST'),
    ('overlap', 'MANIFEST_PARTITION'), ('foreign-missing', 'MANIFEST_PARTITION'),
    ('selected-count', 'MANIFEST_COUNT'), ('completed-bool', 'MANIFEST_COUNT'),
    ('report-missing', 'MANIFEST_REPORTS'), ('foreign-report', 'MANIFEST_REPORTS'),
    ('report-duplicate', 'DUPLICATE_HOST'), ('report-shape', 'FORMAT_SHAPE'), ('old-run-id', 'FORMAT_SHAPE')])
def test_l02_manifest_rejects_contradictions(rules, fixtures, change, code):
    fmt = m.FORMATS[2]
    d = deepcopy(fixtures[fmt])
    if change == 'selected-duplicate': d['selected_hosts'].append(d['selected_hosts'][0])
    elif change == 'successful-duplicate': d['successful_hosts'].append(d['successful_hosts'][0])
    elif change == 'missing-duplicate': d['hosts_without_report'].append(d['hosts_without_report'][0])
    elif change == 'overlap': d['hosts_without_report'].append(d['successful_hosts'][0])
    elif change == 'foreign-missing': d['hosts_without_report'][0] = 'host-z.example.invalid'
    elif change == 'selected-count': d['selected_count'] = '3'
    elif change == 'completed-bool': d['completed_count'] = True
    elif change == 'report-missing': d['reports'].pop()
    elif change == 'foreign-report': d['reports'][0]['host'] = 'host-z.example.invalid'
    elif change == 'report-duplicate': d['reports'].append(deepcopy(d['reports'][0]))
    elif change == 'report-shape': d['reports'][0] = {'hosts': []}
    else: d['run_id'] = '../../fixture'
    error(d, rules, code, fmt)


def test_l02_duplicate_hosts_and_exact_case(rules):
    error({'hosts': [{'host': HOST}, {'host': HOST}], 'total_hosts': 2}, rules, 'DUPLICATE_HOST', m.FORMATS[1])
    doc = run({'hosts': [{'host': HOST}, {'host': HOST.upper()}], 'total_hosts': 2}, rules, m.FORMATS[1]).document
    assert len({h['host_id'] for h in doc['hosts']}) == 2


def manifest(b, scope_key='tls-groups', **entry):
    return {'input_sha256': sha256(b).hexdigest(), 'run_id': RID,
            'disabled': [{'host': HOST, 'collector_id': m.COLLECTOR, 'scope_key': scope_key,
                          'reason_code': 'DISABLED_BY_PROFILE', **entry}]}


def test_l02_only_trusted_disabled_manifest(rules):
    d = {'host': HOST, 'openssl_tls1_3_groups': '', 'openssl_tls1_3_groups_rc': -1,
         'nginx_present': False, 'flags': {'tls-groups': False}, 'pqc_collect_tls_services': False}
    b = raw(d)
    base = run(b, rules)
    assert base.diagnostics['UNKNOWN_FIELD'] == 2
    assert all(c['collection_state'] == 'UNKNOWN' for c in base.document['collections'])
    res = run(b, rules, disabled_manifest=manifest(b))
    c = scope(res.document, 'tls-groups')
    assert c['collection_state'] == 'NOT_SCANNED' and c['reason_code'] == 'DISABLED_BY_PROFILE' and c['evidence_ids'] == []
    out = a.evaluate_document(res.document, rules)
    assert any(f['assessment_state'] == 'NOT_SCANNED' for f in out['findings'])
    assert out['claims'] == []
    assert res.document['hosts'][0]['host_state'] == 'ERROR'


@pytest.mark.parametrize('change,code', [('hash', 'DISABLED_BINDING'), ('run', 'DISABLED_BINDING'),
    ('scope', 'DISABLED_SCOPE'), ('host', 'DISABLED_SCOPE'), ('collector', 'DISABLED_SCOPE'),
    ('reason', 'DISABLED_SCOPE'), ('duplicate', 'DISABLED_DUPLICATE'), ('malformed', 'DISABLED_MANIFEST')])
def test_l02_disabled_manifest_bound(rules, change, code):
    b = raw({'host': HOST})
    d = manifest(b)
    if change == 'hash': d['input_sha256'] = '0' * 64
    elif change == 'run': d['run_id'] = 'different'
    elif change == 'scope': d['disabled'][0]['scope_key'] = '*'
    elif change == 'host': d['disabled'][0]['host'] = 'foreign.example.invalid'
    elif change == 'collector': d['disabled'][0]['collector_id'] = 'other'
    elif change == 'reason': d['disabled'][0]['reason_code'] = 'NOT_ATTEMPTED'
    elif change == 'duplicate': d['disabled'].append(deepcopy(d['disabled'][0]))
    else: d['disabled'][0]['scope_key'] = []
    error(b, rules, code, disabled_manifest=d)


@pytest.mark.parametrize('rc', [0, 1, -1, None])
def test_l02_disabled_conflict_with_observation(rules, rc):
    b = raw({'host': HOST, 'openssl_tls1_3_groups': 'X25519', 'openssl_tls1_3_groups_rc': rc})
    error(b, rules, 'DISABLED_CONFLICT', disabled_manifest=manifest(b))


def test_l02_empty_defaults_no_fabricated_evidence(rules, fixtures):
    d = fixtures[m.FORMATS[1]]['hosts'][1]
    result = run(d, rules)
    doc = result.document
    assert doc['run']['run_state'] == 'ERROR' and doc['hosts'][0]['host_state'] == 'ERROR'
    assert {x['evidence_kind'] for x in doc['evidence']} == {'LEGACY_OBSERVATION'}
    assert all(c['collection_state'] == 'UNKNOWN' for c in doc['collections'])
    assert a.evaluate_document(doc, rules)['claims'] == []


def test_l02_stable_ids_reordering_and_run_isolation(rules, fixtures):
    d = deepcopy(fixtures[m.FORMATS[0]])
    d['openssl_packages']['openssl'].append({'version': '3.0.7', 'release': '1.el9', 'arch': 'x86_64'})
    first = run(d, rules).document
    second = run(d, rules, run_id='other-run').document
    d['openssl_packages']['openssl'].reverse()
    d['openssl_tls1_3_groups'] = ':'.join(reversed(d['openssl_tls1_3_groups'].split(':')))
    reordered = run(d, rules).document
    for registry, key in e.REGISTRIES.items():
        if registry in ('claims', 'findings'):
            continue
        ids = {x[key] for x in first[registry]}
        assert ids == {x[key] for x in reordered[registry]}
        assert not ids & {x[key] for x in second[registry]}
    assert first['run']['source']['input_sha256'] != reordered['run']['source']['input_sha256']
    assert e.canonical_bytes(first) != e.canonical_bytes(reordered)


def test_l02_source_scope_and_exact_asset_identity(rules, fixtures):
    d = deepcopy(fixtures[m.FORMATS[0]])
    d['system_certificates'].append({**d['system_certificates'][0], 'path': '/other/server.pem'})
    result = run(d, rules)
    doc = result.document
    assets = [x for x in doc['assets'] if x['asset_kind'] == 'certificate']
    assert len(assets) == 3 and len({x['asset_id'] for x in assets}) == 3
    assert all(len(x['identity_key']) == len('legacy-') + 64 for x in assets)
    assert '/fixture/server.pem' not in json.dumps(doc) and '/other/server.pem' not in json.dumps(doc)
    assert len({x['asset_id'] for x in rows(doc, 'system-certificates')}) == 2
    assert not {x['asset_id'] for x in rows(doc, 'system-certificates')} & {x['asset_id'] for x in rows(doc, 'nginx-certificates') if x['asset_id']}
    # Identical path in another host is distinct as well.
    d2 = deepcopy(d); d2['host'] = 'host-b.example.invalid'
    fleet = run({'hosts': [d, d2], 'total_hosts': 2}, rules, m.FORMATS[1]).document
    assert len([x for x in fleet['assets'] if x['asset_kind'] == 'certificate']) == 6


@pytest.mark.parametrize('field', ['system_certificates', 'nginx_certificates', 'ssh_host_keys', 'tls_services'])
def test_l02_duplicate_asset_row_dedup(rules, fixtures, field):
    d = deepcopy(fixtures[m.FORMATS[0]])
    before = run(d, rules).document
    d[field].append(deepcopy(d[field][0]))
    result = run(d, rules)
    assert result.diagnostics['DUPLICATE_ROW'] == 1
    assert len(result.document['assets']) == len(before['assets'])
    assert {x['evidence_id'] for x in result.document['evidence']} == {x['evidence_id'] for x in before['evidence']}


@pytest.mark.parametrize('field,mutate', [('system_certificates', {'public_key_size': 4096}),
    ('nginx_certificates', {'public_key_type': 'RSA'}), ('ssh_host_keys', {'algorithm': 'ED25519'}),
    ('tls_services', {'cipher': 'TLS_AES_128_GCM_SHA256'})])
def test_l02_asset_identity_conflict(rules, fixtures, field, mutate):
    d = deepcopy(fixtures[m.FORMATS[0]])
    d[field].append({**d[field][0], **mutate})
    error(d, rules, 'IDENTITY_CONFLICT')


def test_l02_package_name_conflict_and_multiple_versions(rules):
    error({'host': HOST, 'openssl_packages': {'openssl': [{'name': 'openssl-libs', 'version': '3.0.7'}]}}, rules, 'IDENTITY_CONFLICT')
    d = {'host': HOST, 'openssl_packages': {'openssl': [{'version': '3.0.7', 'arch': 'x86_64'},
            {'version': '3.5.0', 'arch': 'x86_64'}, {'version': '3.5.0', 'arch': 'aarch64'}]}}
    out = run(d, rules).document
    assert len(out['assets']) == 3
    assert len(a.evaluate_document(out, rules)['claims']) == 3
    d['openssl_packages']['openssl'].append(deepcopy(d['openssl_packages']['openssl'][0]))
    assert run(d, rules).diagnostics['DUPLICATE_ROW'] == 1


def test_l03_package_only_own_l1(rules):
    d = {'host': HOST, 'openssl_packages': {'openssl': [{'version': '3.5.0', 'release': '1.el9', 'arch': 'x86_64'}],
             'openssl-libs': []}}
    doc = run(d, rules).document
    assert all(x['data']['present'] is True and x['algorithm'] is None for x in doc['evidence'] if x['evidence_kind'] == 'PACKAGE_INVENTORY')
    claims = a.evaluate_document(doc, rules)['claims']
    assert len(claims) == 1 and claims[0]['level'] == 'L1' and claims[0]['assessment_state'] == 'PASS'
    assert {r['data']['field'] for r in doc['evidence'] if r['evidence_kind'] == 'LEGACY_OBSERVATION'} == {'rpm-release', 'rpm-architecture'}


@pytest.mark.parametrize('row', [{}, {'version': ''}, {'version': False}, {'version': '3.5.0', 'source': 'apt'}, 'fixture'])
def test_l03_bad_package_leaf_no_installation(rules, row):
    doc = run({'host': HOST, 'openssl_packages': {'openssl': [row]}}, rules).document
    assert not any(x['evidence_kind'] == 'PACKAGE_INVENTORY' for x in doc['evidence'])
    assert a.evaluate_document(doc, rules)['claims'] == []


@pytest.mark.parametrize('rc,value', [(None, 'OpenSSL 3.5.0'), (1, 'OpenSSL 3.5.0'),
    (False, 'OpenSSL 3.5.0'), (0.0, 'OpenSSL 3.5.0'), (0, ''), (0, 'OpenSSL 3.5.0 ...'), (0, 'LibreSSL 3.5.0')])
def test_l03_version_not_capability(rules, rc, value):
    doc = run({'host': HOST, 'openssl_version_rc': rc, 'openssl_version': value}, rules).document
    assert not any(x['evidence_kind'] == 'ASSET_METADATA' for x in doc['evidence'])
    assert a.evaluate_document(doc, rules)['claims'] == []


def test_l03_version_valid_metadata_only(rules):
    doc = run({'host': HOST, 'openssl_version_rc': 0, 'openssl_version': 'OpenSSL 3.5.0 8 Apr 2025'}, rules).document
    assert rows(doc, 'openssl-version')[0]['data'] == {'name': 'OpenSSL', 'version': '3.5.0'}
    assert scope(doc, 'openssl-version')['collection_state'] == 'PARTIAL'
    assert a.evaluate_document(doc, rules)['claims'] == []


@pytest.mark.parametrize('rc,value', [(None, 'X25519MLKEM768'), (1, 'X25519MLKEM768'),
    (-1, 'X25519MLKEM768'), (False, 'X25519MLKEM768'), (0.0, 'X25519MLKEM768'),
    (0, 'X25519MLKEM768:'), (0, 'X25519MLKEM768:...'), (0, 'X25519MLKEM768:truncated'),
    (0, 'X25519MLKEM768:unknown'), (0, 'X25519MLKEM768\nerror message'),
    (0, 'prefix X25519MLKEM768'), (0, 'X25519MLKEM768\nX25519:P-256'),
    (0, ''), (0, ['X25519MLKEM768'])])
def test_l03_group_invalid_no_positive_l2(rules, rc, value):
    doc = run({'host': HOST, 'openssl_tls1_3_groups_rc': rc, 'openssl_tls1_3_groups': value}, rules).document
    assert not any(x['evidence_kind'] == 'RUNTIME_CAPABILITY' for x in doc['evidence'])
    assert scope(doc, 'tls-groups')['collection_state'] == 'UNKNOWN'
    assert a.evaluate_document(doc, rules)['claims'] == []


@pytest.mark.parametrize('value', ['X25519MLKEM768:X25519:MLKEM768:P-256', 'X25519MLKEM768\nX25519\nMLKEM768\nP-256\n'])
def test_l03_group_exact_context_hybrid(rules, value):
    doc = run({'host': HOST, 'openssl_tls1_3_groups_rc': 0, 'openssl_tls1_3_groups': value}, rules).document
    actual = {x['algorithm']['observed_name']: x for x in doc['evidence']}
    assert actual['X25519MLKEM768']['algorithm']['family'] == 'HYBRID'
    assert actual['X25519MLKEM768']['algorithm']['primitive'] == 'KEX'
    assert actual['MLKEM768']['algorithm']['family'] == 'UNKNOWN'
    assert actual['MLKEM768']['evidence_kind'] == 'LEGACY_OBSERVATION'
    assert actual['P-256']['algorithm']['algorithm_id'] is None
    claims = a.evaluate_document(doc, rules)['claims']
    assert {c['subject']['algorithm_id'] for c in claims} == {'tls-x25519-mlkem768', 'tls-x25519'}
    assert all(c['level'] == 'L2' and c['assessment_state'] == 'PASS' for c in claims)


def test_l03_group_alias_duplicate_no_conflict(rules):
    result = run({'host': HOST, 'openssl_tls1_3_groups_rc': 0,
                  'openssl_tls1_3_groups': 'X25519MLKEM768:x25519mlkem768:X25519MLKEM768'}, rules)
    assert result.diagnostics['DUPLICATE_ROW'] == 1
    claims = a.evaluate_document(result.document, rules)['claims']
    assert len(claims) == 1 and len(claims[0]['evidence_ids']) == 2 and claims[0]['assessment_state'] == 'PASS'


def test_l03_cert_ssh_and_tls_roles_independent(rules, fixtures):
    doc = run(fixtures[m.FORMATS[0]], rules).document
    cert = {x['data']['field']: x['algorithm'] for x in rows(doc, 'system-certificates') if x['algorithm']}
    assert cert['public-key-algorithm']['primitive'] == 'PUBLIC_KEY'
    assert cert['public-key-algorithm']['family'] == 'CLASSICAL'
    assert cert['signature-algorithm']['primitive'] == 'SIGNATURE' and cert['signature-algorithm']['family'] == 'PQC'
    assert a.migration_classification(cert['public-key-algorithm'], rules) == 'CLASSICAL_PUBLIC_KEY_MIGRATION'
    ssh = [x['algorithm'] for x in rows(doc, 'ssh-host-keys') if x['algorithm']]
    assert ssh[0]['primitive'] == 'PUBLIC_KEY' and ssh[0]['family'] == 'CLASSICAL'
    tls = {x['data']['field']: x['algorithm'] for x in rows(doc, 'tls-services') if x['algorithm']}
    assert tls['key-exchange']['family'] == 'HYBRID' and tls['key-exchange']['primitive'] == 'KEX'
    assert tls['cipher']['primitive'] == 'SYMMETRIC' and tls['server-signature']['primitive'] == 'SIGNATURE'
    assert tls['peer-signature']['family'] == 'UNKNOWN'  # no exact RSA-PSS alias
    assert scope(doc, 'tls-services')['collection_state'] == 'UNKNOWN'
    assert all(x['evidence_kind'] == 'LEGACY_OBSERVATION' for x in rows(doc, 'tls-services'))
    assert not any(x['evidence_kind'] in ('AUTHORIZED_NEGOTIATION', 'OBSERVED_USAGE', 'EFFECTIVE_CONFIGURATION') for x in doc['evidence'])


def test_l03_kem_not_public_key_and_default_cert_no_witness(rules):
    d = {'host': HOST, 'ssh_host_keys': [{'path': '/fixture/key.pub', 'algorithm': 'MLKEM768', 'bits': 768}],
         'system_certificates': [{'path': '/fixture/cert.pem', 'public_key_algorithm': 'unknown', 'signature_algorithm': '', 'public_key_size': 0}]}
    doc = run(d, rules).document
    alg = next(x['algorithm'] for x in doc['evidence'] if x['algorithm'])
    assert alg['family'] == 'UNKNOWN' and alg['primitive'] == 'UNKNOWN'
    assert rows(doc, 'system-certificates') == []
    assert scope(doc, 'system-certificates')['collection_state'] == 'UNKNOWN'
    assert a.evaluate_document(doc, rules)['claims'] == []


def test_l03_os_distribution_not_family(rules):
    doc = run({'host': HOST, 'os_distribution': 'OracleLinux', 'os_version': '9.10'}, rules).document
    platform = next(x for x in doc['evidence'] if x['evidence_kind'] == 'PLATFORM_INFO')
    assert platform['data'] == {'os_family': None, 'os_version': '9.10'}
    assert any(x['data'] == {'field': 'os-distribution', 'value': 'oracle-linux'} for x in rows(doc, 'platform') if x['evidence_kind'] == 'LEGACY_OBSERVATION')
    invalid = run({'host': HOST, 'os_distribution': 'RedHat', 'os_version': '9.x'}, rules).document
    assert not any(x['evidence_kind'] == 'PLATFORM_INFO' for x in invalid['evidence'])
    assert invalid['hosts'][0]['host_state'] == 'ERROR'


def test_l03_old_risk_policy_fips_do_not_prove_readiness(rules):
    d = {'host': HOST, 'crypto_policy': {'profile': 'DEFAULT:PQC', 'fips_enabled': True, 'fips_output': 'enabled'},
        'nginx_present': True, 'sshd_crypto_lines': ['KexAlgorithms mlkem768x25519-sha256'],
        'tls_services': [{'port': 443, 'key_exchange': 'X25519MLKEM768', 'key_exchange_risk': 'quantum_safe'}]}
    doc = run(d, rules).document
    assert all(x['evidence_kind'] == 'LEGACY_OBSERVATION' for x in doc['evidence'])
    assert doc['run']['run_state'] == 'ERROR'
    out = a.evaluate_document(doc, rules)
    assert out['claims'] == [] and {f['assessment_state'] for f in out['findings']} == {'UNKNOWN'}


@pytest.mark.parametrize('key', ['private_key', 'password', 'credentials', 'hostvars', 'api-key', 'ansible_ssh_private_key_file'])
def test_l01_sensitive_keys_rejected_without_echo(rules, key):
    error({'host': HOST, 'unknown': {key: SECRET}}, rules, 'SENSITIVE_INPUT')


@pytest.mark.parametrize('payload', ['-----BEGIN PRIVATE KEY-----\n' + SECRET,
    '-----BEGIN OPENSSH PRIVATE KEY-----\n' + SECRET, '-----BEGIN CERTIFICATE-----\n' + SECRET])
def test_l01_pem_rejected_even_in_unknown_field(rules, payload):
    error({'host': HOST, 'irrelevant': payload}, rules, 'SENSITIVE_INPUT')


def test_l01_no_io_no_raw_echo(rules, monkeypatch):
    d = {'host': HOST, 'irrelevant': {'x': 'https://example.invalid/' + SECRET},
         'system_certificates': [{'path': '/fixture/../' + SECRET + '.pem', 'subject': SECRET,
             'issuer': SECRET, 'public_key_algorithm': 'RSA', 'public_key_size': 2048},
            {'path': '{{ ' + SECRET + ' }}', 'public_key_algorithm': 'RSA'},
            {'path': 'file:/fixture/' + SECRET, 'public_key_algorithm': 'RSA'}],
         'sshd_crypto_lines': ['{{ ' + SECRET + ' }}', '<xml>' + SECRET + '</xml>'],
         'crypto_policy': {'fips_output': SECRET}, 'nginx_certificates': [{'path': '<xml>' + SECRET + '</xml>', 'public_key_type': 'RSA'}]}
    b = raw(d)
    def forbidden(*args, **kwargs):
        raise AssertionError('input-directed I/O forbidden')
    monkeypatch.setattr('builtins.open', forbidden)
    monkeypatch.setattr(Path, 'open', forbidden)
    monkeypatch.setattr(socket, 'socket', forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    monkeypatch.setattr('os.system', forbidden)
    result = run(b, rules)
    out = a.evaluate_document(result.document, rules)
    assert SECRET not in json.dumps(result) and SECRET not in json.dumps(out)
    assert result.diagnostics['UNKNOWN_FIELD'] == 1
    assert result.diagnostics['MALFORMED_IDENTITY'] == 3
    assert len(result.document['assets']) == 1
    assert b == raw(d)


@pytest.mark.parametrize('which,code', [('hosts', 'HOST_LIMIT'), ('row-group', 'ROW_LIMIT'),
    ('package-group', 'ROW_LIMIT'), ('group-tokens', 'ROW_LIMIT'), ('evidence', 'EVIDENCE_LIMIT'),
    ('asset', 'ASSET_LIMIT'), ('algorithms', 'ALGORITHM_LIMIT'), ('nodes', 'NODE_LIMIT')])
def test_l01_resource_limits_fail_whole_item(rules, fixtures, monkeypatch, which, code):
    fmt = m.FORMATS[0]
    d = deepcopy(fixtures[fmt])
    if which == 'hosts':
        monkeypatch.setattr(m, 'MAX_HOSTS', 1); fmt = m.FORMATS[1]; d = fixtures[fmt]
    elif which == 'row-group':
        monkeypatch.setattr(m, 'MAX_ROWS', 1); d = {'host': HOST, 'tls_services': [{'port': 443}, {'port': 8443}]}
    elif which == 'package-group':
        monkeypatch.setattr(m, 'MAX_ROWS', 1); d = {'host': HOST, 'openssl_packages': {'openssl': [{'version': '1'}, {'version': '2'}]}}
    elif which == 'group-tokens':
        monkeypatch.setattr(m, 'MAX_ROWS', 1); d = {'host': HOST, 'openssl_tls1_3_groups': 'X25519:secp256r1'}
    elif which == 'evidence': monkeypatch.setattr(m, 'MAX_EVIDENCE', 1)
    elif which == 'asset': monkeypatch.setattr(m, 'MAX_ASSETS', 1)
    elif which == 'algorithms': monkeypatch.setattr(m, 'MAX_CLASSIFICATIONS', 1)
    else: monkeypatch.setattr(m, 'MAX_NODES', 3)
    before = deepcopy(d)
    error(d, rules, code, fmt)
    assert d == before


def test_l01_output_limit_not_truncation(rules, monkeypatch):
    # Input fits the byte bound; normalized Evidence does not.
    monkeypatch.setattr(m, 'MAX_BYTES', 128)
    error({'host': HOST}, rules, 'SIZE_LIMIT')


def test_l01_report_version_and_flags_are_not_caller_metadata(rules):
    result = run({'host': HOST, 'source_version': '9.9.9', 'producer_version': '9.9.9',
                  'flags': {'pqc_collect_packages': False}}, rules)
    assert result.provenance['source_version'] is None
    assert result.document['run']['source']['producer_version'] is None
    assert result.diagnostics['UNKNOWN_FIELD'] == 3
    assert all(c['collection_state'] == 'UNKNOWN' for c in result.document['collections'])


def test_l02_disabled_scope_does_not_affect_other_scopes(rules):
    b = raw({'host': HOST, 'openssl_packages': {'openssl': [{'version': '3.5.0'}]}})
    res = run(b, rules, disabled_manifest=manifest(b, 'tls-groups'))
    assert scope(res.document, 'tls-groups')['collection_state'] == 'NOT_SCANNED'
    assert scope(res.document, 'packages')['collection_state'] == 'PARTIAL'
    assert a.evaluate_document(res.document, rules)['claims'][0]['assessment_state'] == 'PASS'


def test_l02_disabled_manifest_cannot_invent_missing_report_state(rules, fixtures):
    d = fixtures[m.FORMATS[2]]; b = raw(d)
    error(b, rules, 'DISABLED_SCOPE', m.FORMATS[2],
          disabled_manifest=manifest(b, host=d['hosts_without_report'][0]))


def test_l02_malformed_scope_is_independent_gap(rules):
    d = {'host': HOST, 'openssl_packages': {'openssl': [{'version': '3.5.0'}]},
         'system_certificates': [{'path': None, 'public_key_algorithm': 'RSA'}]}
    result = run(d, rules)
    assert scope(result.document, 'packages')['collection_state'] == 'PARTIAL'
    assert scope(result.document, 'system-certificates')['reason_code'] == 'LEGACY_MALFORMED'
    assert scope(result.document, 'system-certificates')['collection_state'] == 'UNKNOWN'
    assert result.document['hosts'][0]['host_state'] == 'PARTIAL'
    assert len(a.evaluate_document(result.document, rules)['claims']) == 1


@pytest.mark.parametrize('kind', ['hosts', 'rows', 'tokens'])
def test_l01_real_manifest_and_group_limit(rules, kind):
    if kind == 'hosts':
        d = {'hosts': [{'host': f'host-{j}.example.invalid'} for j in range(m.MAX_HOSTS + 1)],
             'total_hosts': m.MAX_HOSTS + 1}
        error(d, rules, 'HOST_LIMIT', m.FORMATS[1])
    elif kind == 'rows':
        error({'host': HOST, 'tls_services': [{'port': 443}] * (m.MAX_ROWS + 1)}, rules, 'ROW_LIMIT')
    else:
        error({'host': HOST, 'openssl_tls1_3_groups': ':'.join(['X25519'] * (m.MAX_ROWS + 1))}, rules, 'ROW_LIMIT')


def test_l03_group_unknown_only_is_not_partial_witness(rules):
    doc = run({'host': HOST, 'openssl_tls1_3_groups_rc': 0,
               'openssl_tls1_3_groups': 'MLKEM768:unlisted-group'}, rules).document
    assert all(x['algorithm']['family'] == 'UNKNOWN' for x in doc['evidence'])
    assert scope(doc, 'tls-groups')['collection_state'] == 'UNKNOWN'
    assert a.evaluate_document(doc, rules)['claims'] == []


@pytest.mark.parametrize('port', [True, False, 0, -1, 65536, '443', 443.0])
def test_l03_port_malformed_not_asset(rules, port):
    doc = run({'host': HOST, 'tls_services': [{'port': port, 'key_exchange': 'X25519MLKEM768'}]}, rules).document
    assert doc['assets'] == [] and doc['evidence'] == []
    assert scope(doc, 'tls-services')['collection_state'] == 'UNKNOWN'


def test_l02_manifest_reordering_keeps_ids_not_input_hash(rules, fixtures):
    d = deepcopy(fixtures[m.FORMATS[2]])
    first = run(d, rules, m.FORMATS[2]).document
    for key in ('selected_hosts', 'successful_hosts', 'hosts_without_report', 'reports'):
        d[key].reverse()
    second = run(d, rules, m.FORMATS[2]).document
    for registry, id_key in e.REGISTRIES.items():
        assert [x[id_key] for x in first[registry]] == [x[id_key] for x in second[registry]]
    assert first['run']['source']['input_sha256'] != second['run']['source']['input_sha256']
