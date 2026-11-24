"""Focused O01-O03 engineering tests; no managed host or endpoint access."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools import assessment, evidence, openssl_runtime as runtime

ROLE = ROOT / 'roles/pqc_platform_crypto/tasks/openssl_runtime.yml'
MIRROR = ROOT / 'ansible_collections/security/compliance_pqc_readiness/roles/pqc_platform_crypto/tasks/openssl_runtime.yml'
TASKS = yaml.safe_load(ROLE.read_text())
HELPER = next(t['ansible.builtin.command']['argv'][-2] for t in TASKS if 'ansible.builtin.command' in t)
H = {'__name__': 'test_helper'}
exec(compile(HELPER, '<fixed-role-helper>', 'exec'), H)
RULES = assessment.load_rules((ROOT / 'config/assessment_rules.yml').read_bytes())
TIME = '2026-01-01T00:00:00Z'
HOST = evidence.host_id('fixture-authority', 'fixture-host.example.invalid')
SOURCE = dict(source_kind='SYNTHETIC', producer_id=runtime.PRODUCER, producer_version=runtime.VERSION,
              origin_ref='fixture-openssl', input_sha256=None)


def document():
    return dict(schema_version='1.1.0', run=dict(run_id='fixture-run', run_state='COMPLETE',
        recorded_at=TIME, started_at=None, finished_at=None, source=SOURCE.copy(), expected_host_ids=[HOST]),
        hosts=[dict(host_id=HOST, target_id='fixture-host.example.invalid', identity_scope='STABLE',
                    host_state='COMPLETE', reason_code='FIXTURE', inventory_authority_id='fixture-authority', identity_key=None)],
        collections=[], assets=[], evidence=[], claims=[], findings=[])


def snapshot(packages=True, openssl=True, status='UNVERIFIED', **overrides):
    flags = dict(zip(runtime.FLAGS, (packages, openssl)))
    slots = {}
    for slot in runtime.SLOTS:
        flag = packages if slot in runtime.PACKAGES else openssl
        state, reason = (('NOT_SCANNED', 'DISABLED_BY_USER') if not flag else
                         ('NOT_APPLICABLE', 'PLATFORM_OUT_OF_SCOPE') if status == 'OUT_OF_SCOPE' else
                         ('UNKNOWN', 'PLATFORM_UNRESOLVED') if status == 'UNKNOWN' else
                         ('UNKNOWN', 'TOOL_UNAVAILABLE'))
        slots[slot] = H['result'](state, reason)
    slots.update(overrides)
    return dict(flags=flags, platform_status=status, slots=slots)


def parse(slot, text, rc=0, err=b''):
    return H['parse'](slot, rc, text.encode('ascii') if isinstance(text, str) else text, err)


def norm(snap, doc=None):
    return runtime.normalize_openssl(document() if doc is None else doc, HOST, snap, SOURCE, TIME, RULES)


def rows(doc, kind):
    return [r for r in doc['evidence'] if r['evidence_kind'] == kind]


@pytest.mark.parametrize('slot,raw,state,reason', [
    ('version', 'OpenSSL 1.1.1k  FIPS 25 Mar 2021\n', 'COLLECTED', 'OK'),
    ('version', 'OpenSSL 1.1.1k  25 Mar 2021\n', 'COLLECTED', 'OK'),
    ('version', 'OpenSSL 3.5.5 27 Jan 2026 (Library: OpenSSL 3.5.5 27 Jan 2026)\n', 'COLLECTED', 'OK'),
    ('version', 'LibreSSL 3.4.1\n', 'UNKNOWN', 'UNRECOGNIZED_OUTPUT'),
    ('version', 'OpenSSL 3.5.5', 'ERROR', 'INCOMPLETE_OUTPUT'),
    ('providers', 'Providers:\n', 'UNKNOWN', 'NO_OUTPUT'),
    ('providers', 'Providers:\n  default\n    name: OpenSSL Default Provider\n    version: 3.5.5\n    status: active\n', 'COLLECTED', 'OK'),
    ('providers', 'Providers:\n  default\n    name: OpenSSL Default Provider\n', 'PARTIAL', 'FORMAT_GAP'),
    ('providers', 'Providers:\n  default\n    version: 3.0.1\n    version: 3.0.2\n    status: active\n', 'UNKNOWN', 'UNRECOGNIZED_OUTPUT'),
    ('providers', 'Providers:\n  default\n  malformed provider\n    version: 3.0.1\n    status: active\n', 'PARTIAL', 'FORMAT_GAP'),
    ('kem', 'KEM Algorithms:\n  { 2.16.840.1.101.3.4.4.2, ML-KEM-768, MLKEM768 } @ default\n', 'COLLECTED', 'OK'),
    ('kem', 'unknown output\n  ML-KEM-768 @ default\n', 'PARTIAL', 'FORMAT_GAP'),
    ('signature', 'Provided:\n  ML-DSA-44 @ default\n', 'COLLECTED', 'OK'),
    ('tls-groups', 'TLS 1.3 groups:\nX25519MLKEM768\nx25519\n', 'COLLECTED', 'OK'),
    ('tls-groups', 'x25519:MLKEM768:X25519MLKEM768\n', 'COLLECTED', 'OK'),
    ('tls-groups', 'x25519:\n', 'UNKNOWN', 'UNRECOGNIZED_OUTPUT'),
    ('kem', '', 'UNKNOWN', 'NO_OUTPUT'),
    ('kem', b'\xff\n', 'ERROR', 'INVALID_ENCODING'),
    ('kem', 'ML-KEM-768 @ default\n' * 257, 'ERROR', 'ROW_LIMIT'),
    ('kem', 'x' * 16384 + '\n', 'ERROR', 'OUTPUT_LIMIT'),
])
def test_parse(slot, raw, state, reason):
    result = parse(slot, raw)
    assert (result['state'], result['reason']) == (state, reason)
    assert bool(result['rows']) == (state in ('COLLECTED', 'PARTIAL'))
    runtime.validate_snapshot(snapshot(**{slot: result}))


@pytest.mark.parametrize('rc,err,state,reason', [
    (1, b'list: Unknown option: -kem-algorithms\n', 'UNKNOWN', 'UNSUPPORTED_FLAG'),
    (1, b'Permission denied\n', 'PERMISSION_DENIED', 'PERMISSION_DENIED'),
    (1, b'failed\n', 'ERROR', 'COMMAND_FAILED'),
    (0, b'provider failed\n', 'ERROR', 'COMMAND_FAILED'),
])
def test_failure_no_positive_rows(rc, err, state, reason):
    result = parse('kem', 'ML-KEM-768 @ default\n', rc, err)
    assert result == H['result'](state, reason, rc)
    doc, _ = norm(snapshot(kem=result))
    assert not rows(doc, 'RUNTIME_CAPABILITY')


def test_rpm_exact_absence_and_multiarch():
    present = parse('rpm-openssl', 'openssl\t3.0.7\t1.el9\tx86_64\nopenssl\t3.0.7\t1.el9\ti686\n')
    absent = parse('rpm-openssl-libs', '', 1, b'package openssl-libs is not installed\n')
    doc, diag = norm(snapshot(openssl=False, **{'rpm-openssl': present, 'rpm-openssl-libs': absent}))
    assert len(rows(doc, 'PACKAGE_INVENTORY')) == 3
    assert not rows(doc, 'RUNTIME_CAPABILITY')
    assert next(d for d in diag if d['slot'] == 'rpm-openssl-libs')['rc'] == 1
    assessed = assessment.evaluate_document(doc, RULES)
    assert {c['level'] for c in assessed['claims']} == {'L1'}
    assert {c['assessment_state'] for c in assessed['claims']} == {'PASS', 'FAIL'}
    for bad in (b'package other is not installed\n', b'package openssl-libs is not installed\nextra\n'):
        assert parse('rpm-openssl-libs', '', 1, bad)['rows'] == []
    assert parse('rpm-openssl', 'openssl\t3\t1\tx86_64\n' * 33)['reason'] == 'ROW_LIMIT'


def test_real_evidence_roundtrip_context_and_provider_separation():
    s = snapshot(packages=False,
        version=parse('version', 'OpenSSL 3.5.5 (Library: OpenSSL 3.5.5)\n'),
        providers=parse('providers', 'Providers:\n  default\n    version: 3.5.5\n    status: active\n  alternate\n    version: 1.0\n    status: inactive\n'),
        kem=parse('kem', '{ MLKEM768, ML-KEM-768 } @ default\nMLKEM768 @ default\nML-KEM-768 @ alternate\nX25519MLKEM768 @ default\n'),
        signature=parse('signature', 'ML-DSA-44 @ default\nunknown-signature @ default\n'),
        **{'tls-groups': parse('tls-groups', 'X25519MLKEM768:MLKEM768\n')})
    before, saved = document(), copy.deepcopy(s)
    doc, diag = norm(s, before)
    assert s == saved and before == document()
    wire = evidence.canonical_bytes(doc)
    reread = evidence.parse_evidence_bytes(wire)
    assessed = assessment.evaluate_document(reread, RULES)
    assert evidence.parse_evidence_bytes(evidence.canonical_bytes(assessed)) == assessed
    caps = rows(doc, 'RUNTIME_CAPABILITY')
    assert sum(r['algorithm'] is not None and r['algorithm']['algorithm_id'] == 'ml-kem-768' for r in caps) == 2
    assert any(r['algorithm'] and r['algorithm']['family'] == 'HYBRID' and r['algorithm']['primitive'] == 'KEX' for r in caps)
    assert any(r['algorithm'] and r['algorithm']['primitive'] == 'SIGNATURE' for r in caps)
    assert any(r['algorithm'] and r['algorithm']['family'] == 'UNKNOWN' for r in caps)
    assert all(r['data']['supported'] is not False for r in caps)
    assert {c['level'] for c in assessed['claims']} == {'L2'}
    assert {c['assessment_state'] for c in assessed['claims']} == {'PASS', 'UNKNOWN'}
    assert all(r['algorithm'] is None and r['asset_id'] is None for r in rows(doc, 'ASSET_METADATA'))
    assert all(c['collection_id'] in {d['collection_id'] for d in diag} for c in doc['collections'])
    assert {d['status'] for d in diag if 'status' in d} == {'active', 'inactive'}
    assert evidence.canonical_bytes(norm(s)[0]) == wire


@pytest.mark.parametrize('text,expected_state', [
    ('{ ML-KEM-768, ML-KEM-512 } @ default\n', 'UNKNOWN'),
    ('{ ML-KEM-768, ML-KEM-512 } @ default\nML-KEM-1024 @ default\n', 'PARTIAL'),
    ('2.16.840.1.101.3.4.4.2 @ default\n', 'UNKNOWN'),
    ('{ ML-KEM-768, ambiguous } @ default\n{ ML-KEM-512, ambiguous } @ default\n', 'UNKNOWN'),
])
def test_ambiguous_aliases_and_oid_only(text, expected_state):
    doc, _ = norm(snapshot(kem=parse('kem', text)))
    c = next(c for c in doc['collections'] if c['scope_key'] == 'openssl-kem')
    assert c['collection_state'] == expected_state
    assert not any(r['algorithm'] and r['algorithm']['algorithm_id'] in ('ml-kem-768', 'ml-kem-512')
                   for r in rows(doc, 'RUNTIME_CAPABILITY'))


@pytest.mark.parametrize('packages,openssl,status', [(False, False, 'UNVERIFIED'), (True, False, 'OUT_OF_SCOPE'),
                                                     (False, True, 'UNKNOWN'), (True, True, 'OUT_OF_SCOPE')])
def test_disabled_and_ineligible(packages, openssl, status):
    doc, _ = norm(snapshot(packages, openssl, status))
    assert not rows(doc, 'RUNTIME_CAPABILITY') and not rows(doc, 'PACKAGE_INVENTORY')
    assessed = assessment.evaluate_document(doc, RULES)
    assert not assessed['claims']


@pytest.mark.parametrize('mutation', [
    lambda s: s.update(raw='private-key'),
    lambda s: s['flags'].update(pqc_collect_openssl=1),
    lambda s: s['slots']['kem'].update(rows=[['default', ['ML-KEM-768']]]),
    lambda s: s['slots']['kem'].update(rc=True),
    lambda s: s['slots']['kem'].update(reason='arbitrary'),
    lambda s: s['slots']['kem'].update(state='COLLECTED', reason='OK', rc=0, rows=[['default', ['ML-KEM-768']]] * 2),
    lambda s: s['slots']['kem'].update(state='COLLECTED', reason='OK', rc=0, rows=[['/secret', ['ML-KEM-768']]]),
    lambda s: s['slots']['kem'].update(state='COLLECTED', reason='OK', rc=0, rows=[['default', ['x'] * 33]]),
    lambda s: s['slots']['version'].update(state='COLLECTED', reason='OK', rc=1, rows=[['3.0', None]]),
    lambda s: s['slots']['signature'].update(state='COLLECTED', reason='OK', rc=0, rows=[['default', ['x' * 129]]]),
])
def test_reject_forged_projection(mutation):
    s = snapshot()
    mutation(s)
    with pytest.raises(ValueError, match='INVALID_OPENSSL_SNAPSHOT'):
        norm(s)


def test_reject_legacy_document_and_duplicate_scope():
    d = document()
    d['schema_version'] = '1.0.0'
    with pytest.raises(ValueError):
        norm(snapshot(), d)
    d, _ = norm(snapshot())
    with pytest.raises(ValueError):
        norm(snapshot(), d)


@pytest.mark.parametrize('code,seconds,expected', [
    ('print("ok")', 1, None),
    ('import sys; sys.exit(7)', 1, None),
    ('import time; time.sleep(8)', 0.15, 'TIMEOUT'),
    ('import os; os.write(1,b"x"*16385)', 1, 'OUTPUT_LIMIT'),
    ('import os; os.write(1,b"x"*9000); os.write(2,b"y"*9000)', 1, 'OUTPUT_LIMIT'),
    ('import os; os.write(1,b"x"*16384)', 1, None),
    ('import sys; sys.stdout.close(); sys.stderr.close(); import time; time.sleep(8)', 0.15, 'TIMEOUT'),
])
def test_actual_bounded_child(code, seconds, expected):
    start = time.monotonic()
    reason, rc, out, err = H['capture']([sys.executable, '-I', '-B', '-c', code], seconds)
    assert reason == expected and time.monotonic() - start < 3
    assert len(out) + len(err) <= 16384 and rc is not None
    if code == 'print("ok")':
        assert out == b'ok\n' and rc == 0
    if 'exit(7)' in code:
        assert rc == 7
    if expected == 'TIMEOUT':
        assert rc < 0


def test_child_environment_and_input_closed(monkeypatch):
    monkeypatch.setenv('OPENSSL_CONF', '/invalid-secret-config')
    monkeypatch.setenv('OPENSSL_MODULES', '/invalid-secret-modules')
    reason, rc, out, err = H['capture']([sys.executable, '-I', '-B', '-c',
        'import os,sys; print(sorted(os.environ)); print(len(sys.stdin.read()))'], 2)
    assert reason is None and rc == 0 and not err
    assert out == b"['LC_ALL', 'PATH']\n0\n"


def test_actual_helper_fixed_entry_and_mirror():
    assert ROLE.read_bytes() == MIRROR.read_bytes()
    assert ROLE.stat().st_mode & 0o777 == MIRROR.stat().st_mode & 0o777 == 0o644
    assert set(H['COMMANDS']) == set(runtime.SLOTS)
    bad = subprocess.run([sys.executable, '-I', '-B', '-c', HELPER, 's_client'], capture_output=True, timeout=3)
    assert bad.returncode == 2 and not bad.stdout


@pytest.mark.parametrize('role', ['pqc_platform_crypto', 'security.compliance_pqc_readiness.pqc_platform_crypto'])
def test_native_synthetic_role(role, tmp_path):
    play = tmp_path / 'play.yml'
    output = tmp_path / 'snapshot.json'
    # Synthetic caller proof exercises the internal task; no OL9 support claim.
    requests = [dict(flags=dict(zip(runtime.FLAGS, flags)), platform_status=status)
                for flags, status in [((False, False), 'UNVERIFIED'), ((True, False), 'UNVERIFIED'),
                                      ((False, True), 'OUT_OF_SCOPE'), ((False, True), 'UNVERIFIED')]]
    tasks = []
    for index, request in enumerate(requests):
        expected = (2 * request['flags'][runtime.FLAGS[0]] + 5 * request['flags'][runtime.FLAGS[1]]) if request['platform_status'] == 'UNVERIFIED' else 0
        tasks.extend([dict(name='Internal synthetic call', **{'ansible.builtin.include_role':
                      dict(name=role, tasks_from='openssl_runtime')}, vars={'pqc_openssl_request': request}),
                      dict(name='Assert actual helper invocation count', **{'ansible.builtin.assert': dict(that=[
                      'pqc_openssl_queries.results | selectattr("rc", "defined") | list | length == ' + str(expected)])}),
                      dict(name='Save synthetic closed projection', **{'ansible.builtin.copy':
                      dict(content='{{ pqc_openssl_snapshot | to_json }}', dest=str(output) + str(index), mode='0600')}, no_log=True)])
    play.write_text(yaml.safe_dump([dict(hosts='localhost', connection='local', gather_facts=False,
        vars={'ansible_python_interpreter': sys.executable}, tasks=tasks)]))
    cfg = tmp_path / 'ansible.cfg'
    cfg.write_text('[defaults]\nretry_files_enabled=False\ninterpreter_python=auto_silent\n')
    env = dict(os.environ, ANSIBLE_CONFIG=str(cfg), ANSIBLE_ROLES_PATH=str(ROOT / 'roles'),
               ANSIBLE_COLLECTIONS_PATH=str(ROOT), ANSIBLE_COLLECTIONS_SCAN_SYS_PATH='false',
               ANSIBLE_LOCAL_TEMP=str(tmp_path / 'ansible-local'), ANSIBLE_REMOTE_TEMP=str(tmp_path / 'ansible-remote'))
    command = [str(Path(sys.executable).parent / 'ansible-playbook'), '-i', 'localhost,', str(play)]
    for opts in (['--syntax-check'], []):
        result = subprocess.run(command + opts, env=env, cwd=tmp_path, capture_output=True, timeout=100)
        assert result.returncode == 0, (result.stdout[-4000:], result.stderr[-2000:])
    results = [json.loads(Path(str(output) + str(i)).read_text()) for i in range(4)]
    for s in results:
        runtime.validate_snapshot(s)
        doc, _ = norm(s)
        assessment.evaluate_document(evidence.parse_evidence_bytes(evidence.canonical_bytes(doc)), RULES)
    assert all(s['state'] == 'NOT_SCANNED' for s in results[0]['slots'].values())
    assert all(results[1]['slots'][s]['state'] == 'NOT_SCANNED' for s in runtime.SLOTS if s not in runtime.PACKAGES)
    assert results[2]['slots']['kem']['state'] == 'NOT_APPLICABLE'
    assert results[3]['slots']['rpm-openssl']['state'] == 'NOT_SCANNED'
    # This is an actual OpenSSL read-only positive control, not an OL9 validation.
    if Path('/usr/bin/openssl').is_file() and Path('/usr/bin/timeout').is_file():
        assert results[3]['slots']['version']['state'] == 'COLLECTED'


def test_actual_child_reaped_after_timeout():
    reason, rc, out, err = H['capture']([sys.executable, '-I', '-B', '-c',
        'import os,time; print(os.getpid(),flush=True); time.sleep(8)'], 0.4)
    assert reason == 'TIMEOUT' and rc < 0 and not err
    with pytest.raises(ProcessLookupError):
        os.kill(int(out), 0)


def test_context_mismatch_not_classified_as_pqc():
    doc, _ = norm(snapshot(kem=parse('kem', 'ML-DSA-44 @ default\n'),
        signature=parse('signature', 'ML-KEM-768 @ default\n'),
        **{'tls-groups': parse('tls-groups', 'TLS_AES_256_GCM_SHA384:ML-DSA-44\n')}))
    assert all(r['algorithm']['family'] == 'UNKNOWN' for r in rows(doc, 'RUNTIME_CAPABILITY'))
    assert all(c['assessment_state'] == 'UNKNOWN' for c in assessment.evaluate_document(doc, RULES)['claims'])


def test_provider_malformed_boundary_no_loaded_claim():
    doc, _ = norm(snapshot(providers=parse('providers', 'Providers:\n  default\n  bad name\n    status: active\n    version: 3.5.5\n')))
    assert not rows(doc, 'RUNTIME_CAPABILITY')


@pytest.mark.parametrize('change', ['host', 'source', 'timestamp'])
def test_invalid_identity_or_source(change):
    host, source, observed = HOST, SOURCE.copy(), TIME
    if change == 'host':
        host = evidence.host_id('fixture-authority', 'another.example.invalid')
    elif change == 'source':
        source['producer_id'] = 'other'
    else:
        observed = 'invalid'
    with pytest.raises(ValueError):
        runtime.normalize_openssl(document(), host, snapshot(), source, observed, RULES)


# F-R1-01: test the complete helper embedded in the actual role and the
# actual normalizer, validator, canonical APIs and evaluator, not a replica.
_R1_ALIAS_CASES = [
    ('kem', 'ML-KEM-768', 'ML-KEM-512', 'ML-KEM-1024', 'MLKEM768',
     'ml-kem-768', 'ml-kem-1024', '2.16.840.1.101.3.4.4.2'),
    ('signature', 'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87', 'MLDSA44',
     'ml-dsa-44-signature', 'ml-dsa-87-signature', '2.16.840.1.101.3.4.3.17'),
]


def _r1_alias_roundtrip(slot, raw, parser_state, parser_reason, parsed_rows,
                        collection_state, pass_ids=(), unknown_count=0):
    parsed = parse(slot, raw)
    assert (parsed['state'], parsed['reason'], parsed['rc']) == (parser_state, parser_reason, 0)
    assert parsed['rows'] == parsed_rows
    snap = snapshot(packages=False, **{slot: parsed})
    before, saved = document(), copy.deepcopy(snap)
    normalized, diagnostics = norm(snap, before)
    assert snap == saved and before == document()
    assert normalized['claims'] == normalized['findings'] == []
    c = next(c for c in normalized['collections'] if c['scope_key'] == 'openssl-' + slot)
    assert c['collection_state'] == collection_state
    d = next(d for d in diagnostics if d['collection_id'] == c['collection_id'])
    assert d['state'] == collection_state and d['rc'] == 0
    caps = rows(normalized, 'RUNTIME_CAPABILITY')
    assert all(r['collection_id'] == c['collection_id'] and r['data']['supported'] is True for r in caps)
    assert {r['algorithm']['algorithm_id'] for r in caps if r['algorithm']['algorithm_id'] is not None} == set(pass_ids)
    assert sum(r['algorithm']['algorithm_id'] is None for r in caps) == unknown_count
    reread = evidence.parse_evidence_bytes(evidence.canonical_bytes(normalized))
    assessed = assessment.evaluate_document(reread, RULES)
    assert evidence.parse_evidence_bytes(evidence.canonical_bytes(assessed)) == assessed
    assert all(cl['level'] == 'L2' and cl['assessment_state'] in ('PASS', 'UNKNOWN') for cl in assessed['claims'])
    assert sorted(cl['subject']['algorithm_id'] for cl in assessed['claims'] if cl['assessment_state'] == 'PASS') == sorted(pass_ids)
    assert sum(cl['assessment_state'] == 'UNKNOWN' for cl in assessed['claims']) == unknown_count
    assert all(f['assessment_state'] != 'FAIL' for f in assessed['findings'])
    # A rejected row cannot leak a retained alias to diagnostics or evidence.
    assert len(d.get('observations', [])) == len(caps)
    return normalized, assessed


@pytest.mark.parametrize('slot,one,two,other,alias,aid,other_id,oid', _R1_ALIAS_CASES)
@pytest.mark.parametrize('format_string', [
    '{one},  {two}',          # original CE01 / CE02
    '{one},\t{two}',          # tab separator is outside the grammar
    '{one},{two}',            # no separator space
    '{one}, {two}!',          # invalid punctuation
    '{one}, ',                # empty trailing alias
    '/bad, {one}',            # invalid first alias
    '{one}, {one},  {two}',   # valid duplicates must not hide invalid tokens
])
def test_r1_atomic_malformed_alias_rows(slot, one, two, other, alias, aid, other_id, oid, format_string):
    bad = '{ ' + format_string.format(one=one, two=two) + ' } @ default\n'
    _r1_alias_roundtrip(slot, bad, 'UNKNOWN', 'UNRECOGNIZED_OUTPUT', [], 'UNKNOWN')
    # Malformed and independent valid rows: preserve only the latter's proof.
    _r1_alias_roundtrip(slot, bad + other + ' @ default\n', 'PARTIAL', 'FORMAT_GAP',
                        [['default', [other]]], 'PARTIAL', (other_id,))


@pytest.mark.parametrize('slot,one,two,other,alias,aid,other_id,oid', _R1_ALIAS_CASES)
def test_r1_valid_ambiguous_and_independent_rows(slot, one, two, other, alias, aid, other_id, oid):
    ambiguous = '{ ' + one + ', ' + two + ' } @ default\n'
    row = ['default', sorted([one, two])]
    _r1_alias_roundtrip(slot, ambiguous, 'COLLECTED', 'OK', [row], 'UNKNOWN')
    both = sorted([row, ['default', [other]]], key=runtime.serial)
    _r1_alias_roundtrip(slot, ambiguous + other + ' @ default\n', 'COLLECTED', 'OK', both,
                        'PARTIAL', (other_id,))


@pytest.mark.parametrize('slot,one,two,other,alias,aid,other_id,oid', _R1_ALIAS_CASES)
def test_r1_valid_aliases_oid_duplicates_and_unknown(slot, one, two, other, alias, aid, other_id, oid):
    # Multiple aliases for exactly one ID, including a valid numeric OID.
    raw = '{ ' + ', '.join([oid, one, alias]) + ' } @ default\n'
    _r1_alias_roundtrip(slot, raw, 'COLLECTED', 'OK', [['default', sorted([oid, one, alias])]],
                        'COLLECTED', (aid,))
    _r1_alias_roundtrip(slot, '{ ' + one + ', ' + one + ' } @ default\n', 'PARTIAL', 'FORMAT_GAP',
                        [['default', [one]]], 'PARTIAL', (aid,))
    _r1_alias_roundtrip(slot, oid + ' @ default\n', 'COLLECTED', 'OK', [['default', [oid]]], 'UNKNOWN')
    _r1_alias_roundtrip(slot, 'unclassified-fixture @ default\n', 'COLLECTED', 'OK',
                        [['default', ['unclassified-fixture']]], 'COLLECTED', unknown_count=1)
    # Cap is applied to the original row, before any deduplication.
    assert parse(slot, '{ ' + ', '.join([one] * 33) + ' } @ default\n') == H['result']('ERROR', 'ROW_LIMIT', 0)
