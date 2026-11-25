"""Actual offline CLI, Evidence, assessment, CFF and private Run Store."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile

import pytest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools import assessment, cff, evidence, import_legacy, import_reports, run_store

RID = 'fixture-import'
STAMP = '2026-01-03T00:00:00Z'
OLD = '2025-12-01T00:00:00Z'
H1, H2 = 'host-a.example.invalid', 'host-b.example.invalid'
RULES_RAW = (ROOT / 'config/assessment_rules.yml').read_bytes()
RULES = assessment.load_rules(RULES_RAW)
REQ = {'assessment': True, 'cff': True, 'details': []}
REPORT = {'host': H1, 'collected_at': OLD, 'openssl_version': 'OpenSSL 3.5.0',
          'openssl_version_rc': 0, 'openssl_tls1_3_groups': 'X25519MLKEM768',
          'openssl_tls1_3_groups_rc': 0}
CASES = [
    ('legacy-per-host', REPORT, 'PARTIAL', 1, 0),
    ('legacy-fleet', {'generated_at': OLD, 'total_hosts': 1,
                      'hosts': [{'host': H1}]}, 'ERROR', 1, 0),
    ('legacy-ol-run-summary', {'run_id': 'fixture-old', 'generated_at': OLD,
        'selected_hosts': [H1, H2], 'successful_hosts': [H1],
        'hosts_without_report': [H2], 'selected_count': 2,
        'completed_count': 1, 'reports': [REPORT]}, 'PARTIAL', 2, 1),
]


def raw(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def put(path, data):
    path.write_bytes(data)
    path.chmod(0o600)
    return path


@pytest.fixture
def area():
    with tempfile.TemporaryDirectory(prefix='pqc-import-', dir='/tmp') as p:
        root = Path(p)
        (root / 'reports').mkdir(mode=0o700)
        (root / 'cwd').mkdir(mode=0o700)
        yield root


def invoke(area, path, fmt, *, install=ROOT, report_root=None, extra=(), rid=RID):
    # Run from an unrelated cwd with only the trusted code projection on the
    # module path; the CLI must not select rules relative to cwd or input.
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(area), 'LC_ALL': 'C.UTF-8',
           'PYTHONPATH': str(install), 'PYTHONDONTWRITEBYTECODE': '1'}
    return subprocess.run([sys.executable, '-B', '-m', 'tools.import_reports',
        '--input', str(path), '--format', fmt, '--run-id', rid,
        '--recorded-at', STAMP, '--origin-ref', 'fixture-source',
        '--source-version', '0.9.1', '--report-root', str(report_root or area / 'reports'),
        *extra], cwd=area / 'cwd', env=env, capture_output=True, timeout=60)


def reject_cli(result, code, rc=2):
    assert result.returncode == rc, (result.returncode, result.stderr)
    assert result.stdout == b'' and json.loads(result.stderr) == {'reason_code': code}


def reject(code, action, *args, **kwargs):
    with pytest.raises(run_store.StoreError) as exc:
        action(*args, **kwargs)
    assert exc.value.code == code


def expected(data, fmt):
    return import_legacy.import_legacy(data, format_id=fmt, run_id=RID,
        recorded_at=STAMP, origin_ref='fixture-source', source_version='0.9.1', rules=RULES)


def legacy_provenance(result):
    return {'format_version': '1.0.0', 'source': result.document['run']['source'],
            'original_run_id': result.provenance['original_run_id'],
            'original_generated_at': result.provenance['original_generated_at'],
            'diagnostics': [{'reason_code': key, 'count': val}
                            for key, val in sorted(result.diagnostics.items())]}


def begin(store, data, result, *, requirements=REQ, schema='1.0.0'):
    doc = result.document
    return store.begin(run_id=RID, run_kind='LEGACY_IMPORT', evidence_schema_version=schema,
        source=doc['run']['source'], recorded_at=STAMP, started_at=None,
        expected_hosts=[{k: h[k] for k in ('target_id', 'inventory_authority_id', 'identity_key')}
                        for h in doc['hosts']], legacy_raw=data,
        legacy_provenance=legacy_provenance(result), requirements=deepcopy(requirements))


def record(writer, doc):
    assert [h['host_id'] for h in writer.scope['hosts']] == sorted(doc['run']['expected_host_ids'])
    for hid in sorted(doc['run']['expected_host_ids']):
        writer.record_host(run_store.host_fragment(doc, hid), attempted=None, terminal=None)


def read(root):
    with run_store.RunStore(root) as store:
        return store.open(RID)


def snapshot(path):
    return {str(p.relative_to(path)): (stat.S_IMODE(p.stat().st_mode), p.stat().st_ino,
                                      p.read_bytes() if p.is_file() else None)
            for p in [path, *sorted(path.rglob('*'))]}


def assert_private(path):
    for p in [path, *path.rglob('*')]:
        st = p.lstat()
        assert st.st_uid == os.geteuid()
        assert (stat.S_ISDIR(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o700 or
                stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o600 and st.st_nlink == 1)


@pytest.mark.parametrize('fmt,value,state,hosts,missing', CASES, ids=[c[0] for c in CASES])
def test_cli_three_dialects_exact_roundtrip(area, fmt, value, state, hosts, missing):
    data = raw(value)
    path = put(area / 'source.json', data)
    orig = snapshot(path)
    # A cwd-selected policy would fail; the trusted installation rule wins.
    (area / 'cwd/config').mkdir()
    put(area / 'cwd/config/assessment_rules.yml', b'not a trusted rules file')
    result = invoke(area, path, fmt)
    assert result.returncode == 0 and result.stderr == b'', result.stderr
    root = area / 'reports'
    pub = read(root)
    expected_result = expected(data, fmt)
    doc = expected_result.document
    assessed = assessment.evaluate_document(doc, RULES)
    pair = cff.project_cff(doc, RULES)
    assert pub.document == doc and pub.assessed == assessed
    assert pub.artifacts['evidence.json'] == evidence.canonical_bytes(doc)
    assert pub.artifacts['assessed_evidence.json'] == evidence.canonical_bytes(assessed)
    assert pub.artifacts['assessment_rules.json'] == RULES_RAW
    assert pub.artifacts['cff_projection.json'] == cff.canonical_projection_bytes(pair, assessed, RULES)
    assert json.loads(pub.artifacts['legacy_provenance.json']) == legacy_provenance(expected_result)
    manifest = pub.manifest
    assert json.loads(result.stdout) == {k: manifest[k] for k in
        ('run_id', 'publication_state', 'run_kind', 'run_state', 'reason_code')}
    assert manifest['run_kind'] == 'LEGACY_IMPORT' and manifest['run_state'] == state
    assert manifest['publication_state'] == 'PUBLISHED' and not manifest['recovery']
    assert manifest['requirements'] == REQ and not manifest['missing_artifacts']
    assert manifest['source'] == doc['run']['source']
    assert manifest['source']['input_sha256'] == digest(data)
    assert manifest['source']['producer_id'] == fmt and manifest['source']['producer_version'] == '0.9.1'
    assert manifest['source']['origin_ref'] == 'fixture-source'
    assert manifest['recorded_at'] == STAMP
    assert manifest['started_at'] is manifest['finished_at'] is None
    assert all(manifest[k] is None for k in ('batch_contract', 'batch_rc', 'batch_canonical_sha256',
                                           'batch_missing_reason', 'profile', 'limits', 'flags'))
    assert len(manifest['hosts']) == hosts == len(pair['per_host'])
    assert sum(h['reason_code'] == 'LEGACY_REPORT_MISSING' for h in manifest['hosts']) == missing
    assert all(h['attempt_status'] == 'NOT_APPLICABLE' and h['attempted'] is None and
               h['dispatch_intent'] is None and h['terminal'] is None and
               h['identity_scope'] == 'RUN_SCOPED' for h in manifest['hosts'])
    assert all(e['observed_at'] is None for e in doc['evidence'])
    assert manifest['rules_sha256'] == digest(RULES_RAW) and manifest['rule_version'] == RULES['rule_version']
    assert all(p['companion']['taxonomy_version'] == RULES['taxonomy_version'] and
               p['companion']['rule_version'] == RULES['rule_version'] for p in pair['per_host'])
    assert pair['evidence_document_sha256'] == digest(pub.artifacts['assessed_evidence.json'])
    assert set(pub.artifacts) == {'evidence.json', 'assessed_evidence.json', 'assessment_rules.json',
                                  'cff_projection.json', 'legacy_provenance.json'}
    for row in manifest['artifacts']:
        artifact = pub.artifacts[row['path']]
        assert len(artifact) == row['size'] and digest(artifact) == row['sha256']
        assert (root / RID / row['path']).read_bytes() == artifact
    schema = json.loads((ROOT / 'schemas/run-manifest-1.0.0.schema.json').read_bytes())
    assert schema == run_store.manifest_schema()
    Draft202012Validator(schema).validate(manifest)
    assert snapshot(path) == orig
    assert_private(root)
    assert all(data not in content for content in pub.artifacts.values())
    # The same fixed metadata/input in a distinct root must have identical
    # published semantics, not identical internal random staging names.
    other = area / 'other'; other.mkdir(mode=0o700)
    assert invoke(area, path, fmt, report_root=other).returncode == 0
    assert read(other) == pub
    before = snapshot(root / RID)
    reject_cli(invoke(area, path, fmt), 'RUN_ID_COLLISION', rc=3)
    reject_cli(invoke(area, path, fmt, rid=RID.upper()), 'RUN_ID_COLLISION', rc=3)
    assert snapshot(root / RID) == before and snapshot(path) == orig


@pytest.mark.parametrize('defect,code', [
    ('malformed', 'INVALID_JSON'), ('secret', 'SENSITIVE_INPUT'),
    ('symlink', 'UNSAFE_INPUT_FILE'), ('parent-symlink', 'INPUT_IO'),
    ('fifo', 'UNSAFE_INPUT_FILE'), ('directory', 'UNSAFE_INPUT_FILE'),
    ('oversize', 'INPUT_SIZE_LIMIT'), ('relative', 'INVALID_INPUT_PATH'),
    ('traversal', 'INVALID_INPUT_PATH'), ('url', 'INVALID_INPUT_PATH'),
    ('bad-format', 'INVALID_ARGUMENTS'), ('reused-id', 'REUSED_ORIGINAL_RUN_ID'),
])
def test_cli_invalid_input_is_not_reserved(area, defect, code):
    path = put(area / 'source.json', raw(REPORT)); fmt = CASES[0][0]; rid = RID
    if defect == 'malformed': put(path, b'{')
    elif defect == 'secret': put(path, raw({'host': H1, 'password': 'fixture-sentinel'}))
    elif defect == 'symlink':
        link = area / 'link'; link.symlink_to(path); path = link
    elif defect == 'parent-symlink':
        link = area / 'link'; link.symlink_to(area, target_is_directory=True); path = link / path.name
    elif defect == 'fifo': path = area / 'fifo'; os.mkfifo(path, mode=0o600)
    elif defect == 'directory': path = area / 'cwd'
    elif defect == 'oversize':
        with path.open('r+b') as f: f.truncate(import_legacy.MAX_BYTES + 1)
    elif defect == 'relative': path = 'source.json'
    elif defect == 'traversal': path = str(area) + '/cwd/../source.json'
    elif defect == 'url': path = 'https://example.invalid/source.json'
    elif defect == 'bad-format': fmt = 'arbitrary'
    elif defect == 'reused-id':
        fmt = CASES[2][0]; put(path, raw(CASES[2][1])); rid = 'fixture-old'
    reject_cli(invoke(area, path, fmt, rid=rid), code)
    assert not list((area / 'reports').iterdir())


@pytest.mark.parametrize('defect', ['missing', 'invalid', 'symlink', 'parent-symlink', 'oversize'])
def test_fixed_rules_fail_closed_without_fallback(area, defect):
    # A private test installation of the exact product modules, with only
    # the fixed rules source changed; a valid cwd rule must never be used.
    install = area / 'install'; (install / 'tools').mkdir(parents=True)
    for name in ('import_reports', 'import_legacy', 'assessment', 'evidence', 'cff', 'run_store'):
        shutil.copyfile(ROOT / 'tools' / (name + '.py'), install / 'tools' / (name + '.py'))
    (area / 'cwd/config').mkdir(); put(area / 'cwd/config/assessment_rules.yml', RULES_RAW)
    (install / 'config').mkdir(); target = install / 'config/assessment_rules.yml'
    # Even valid bytes at the obsolete upstream path are not a fallback.
    upstream = install / 'ansible_collections/security/compliance_pqc_readiness/rules'
    upstream.mkdir(parents=True); put(upstream / 'pqc_readiness.yml', RULES_RAW)
    if defect == 'invalid': put(target, b'---\nprofile: {}\nrules: []\n')
    elif defect == 'symlink': target.symlink_to(ROOT / 'config/assessment_rules.yml')
    elif defect == 'parent-symlink':
        target.parent.rmdir(); target.parent.symlink_to(ROOT / 'config', target_is_directory=True)
    elif defect == 'oversize': put(target, b' ' * (assessment.MAX_RULE_BYTES + 1))
    path = put(area / 'source.json', raw(REPORT))
    reject_cli(invoke(area, path, CASES[0][0], install=install), 'INVALID_RULES_SOURCE')
    assert not list((area / 'reports').iterdir())


@pytest.mark.parametrize('state,case', [('PARTIAL', CASES[0]), ('ERROR', CASES[1])])
@pytest.mark.parametrize('omit', ['pair', 'assessment'])
def test_required_pair_even_in_historical_incomplete(area, state, case, omit):
    fmt, value, *_ = case; data = raw(value); result = expected(data, fmt)
    doc = result.document; assessed = assessment.evaluate_document(doc, RULES)
    assert doc['run']['run_state'] == state
    with run_store.RunStore(area / 'reports') as store:
        with begin(store, data, result) as writer:
            record(writer, doc)
            options = {'assessed': assessed, 'rules_raw': RULES_RAW} if omit == 'pair' else {}
            reject('REQUIRED_ARTIFACT_MISSING', writer.finalize, doc, **options)
            assert not (area / 'reports' / RID / 'run_manifest.json').exists()


@pytest.mark.parametrize('defect,code', [
    ('companion', 'CFF_PROJECTION_MISMATCH'), ('host', 'CFF_PROJECTION_MISMATCH'),
    ('ref', 'CFF_PROJECTION_MISMATCH'), ('hash', 'CFF_PROJECTION_MISMATCH'),
    ('score', 'CFF_PROJECTION_MISMATCH'), ('s1', 'CFF_PROJECTION_MISMATCH'),
    ('capacity', 'CFF_PROJECTION_LIMIT'),
])
def test_actual_pair_validator_not_opaque_storage(area, defect, code):
    data = raw(REPORT); result = expected(data, CASES[0][0]); doc = result.document
    assessed = assessment.evaluate_document(doc, RULES); pair = cff.project_cff(doc, RULES)
    bad = deepcopy(pair); entry = bad['per_host'][0]
    if defect == 'companion': del entry['companion']
    elif defect == 'host': entry['host_id'] = 'host-' + '0' * 64
    elif defect == 'ref': entry['companion']['findings'][0]['evidence_ids'] = ['evidence-' + '0' * 64]
    elif defect == 'hash': bad['evidence_document_sha256'] = '0' * 64
    elif defect == 'score': entry['companion']['score']['denominator'] = 999
    elif defect == 's1': bad['format'] = 'S1_CFF_PAIR'
    elif defect == 'capacity': bad['per_host'] = [{}] * (cff.MAX_ROWS + 1)
    with run_store.RunStore(area / 'reports') as store:
        with begin(store, data, result) as writer:
            record(writer, doc)
            reject(code, writer.finalize, doc, assessed=assessed, rules_raw=RULES_RAW, cff=bad)
            assert not (area / 'reports' / RID / 'run_manifest.json').exists()
            pub = writer.finalize(doc, assessed=assessed, rules_raw=RULES_RAW, cff=pair)
        assert store.open(RID) == pub


def test_legacy_pair_contract_not_implicit_or_version_upgrade(area):
    data = raw(REPORT); result = expected(data, CASES[0][0]); doc = result.document
    with run_store.RunStore(area / 'reports') as store:
        reject('UNVERIFIED_PRODUCER_FORMAT', begin, store, data, result, schema='1.1.0')
        with begin(store, data, result, requirements={'assessment': True, 'cff': False, 'details': []}) as writer:
            record(writer, doc)
            assessed = assessment.evaluate_document(doc, RULES)
            reject('UNVERIFIED_PRODUCER_FORMAT', writer.finalize, doc, assessed=assessed,
                   rules_raw=RULES_RAW, cff=cff.project_cff(doc, RULES))
            pub = writer.finalize(doc, assessed=assessed, rules_raw=RULES_RAW)
        assert store.open(RID) == pub and 'cff_projection.json' not in pub.artifacts


def test_unprepared_recovery_reports_missing_pair(area):
    fmt, value, *_ = CASES[2]; data = raw(value); result = expected(data, fmt)
    doc = result.document; hid = next(h['host_id'] for h in doc['hosts'] if h['target_id'] == H1)
    with run_store.RunStore(area / 'reports') as store:
        with begin(store, data, result) as writer:
            writer.record_host(run_store.host_fragment(doc, hid))
        pub = store.recover(RID)
        assert store.open(RID) == pub
        assert pub.manifest['recovery'] and pub.manifest['run_state'] == 'PARTIAL'
        assert pub.manifest['requirements'] == REQ
        assert set(x['path'] for x in pub.manifest['missing_artifacts']) == {
            'assessed_evidence.json', 'assessment_rules.json', 'cff_projection.json'}
        assert pub.assessed is None and 'cff_projection.json' not in pub.artifacts
        assert any(h['reason_code'] == 'LEGACY_OUTCOME_UNKNOWN' for h in pub.manifest['hosts'])


def corrupt_pair(path, manifest):
    pair_path = path / 'cff_projection.json'
    bad = json.loads(pair_path.read_bytes()); del bad['per_host'][0]['companion']
    payload = run_store._json_bytes(bad, run_store.MAX_CFF)
    put(pair_path, payload)
    entry = next(a for a in manifest['artifacts'] if a['kind'] == 'cff')
    entry.update(size=len(payload), sha256=digest(payload))


@pytest.mark.parametrize('corrupt', [False, True])
def test_prepared_recovery_revalidates_actual_pair(area, monkeypatch, corrupt):
    data = raw(REPORT); result = expected(data, CASES[0][0]); doc = result.document
    assessed = assessment.evaluate_document(doc, RULES); pair = cff.project_cff(doc, RULES)
    path = area / 'reports' / RID
    original = run_store._write
    def crash_before_marker(parent, name, payload, device, **kwargs):
        if name == 'run_manifest.json': raise OSError('fixture-stop')
        return original(parent, name, payload, device, **kwargs)
    with run_store.RunStore(area / 'reports') as store:
        with begin(store, data, result) as writer:
            record(writer, doc)
            with monkeypatch.context() as patch:
                patch.setattr(run_store, '_write', crash_before_marker)
                reject('STORE_IO', writer.finalize, doc, assessed=assessed, rules_raw=RULES_RAW, cff=pair)
        assert not (path / 'run_manifest.json').exists() and (path / 'prepared.json').is_file()
        if corrupt:
            prepared = run_store._unseal((path / 'prepared.json').read_bytes(), run_store.MAX_MANIFEST)
            corrupt_pair(path, prepared['manifest'])
            put(path / 'prepared.json', run_store._seal(prepared, run_store.MAX_MANIFEST))
            before = snapshot(path)
            reject('CFF_PROJECTION_MISMATCH', store.recover, RID)
            assert snapshot(path) == before
        else:
            pub = store.recover(RID)
            assert store.open(RID) == pub and pub.document == doc and pub.assessed == assessed
            assert pub.artifacts['assessment_rules.json'] == RULES_RAW
            assert json.loads(pub.artifacts['cff_projection.json']) == pair


def test_reader_rejects_reindexed_bad_pair_and_rules(area):
    path = put(area / 'source.json', raw(REPORT))
    assert invoke(area, path, CASES[0][0]).returncode == 0
    root = area / 'reports'; saved = read(root); path = root / RID
    manifest = deepcopy(saved.manifest); corrupt_pair(path, manifest)
    put(path / 'run_manifest.json', run_store._json_bytes(manifest))
    before = snapshot(path)
    with run_store.RunStore(root) as store:
        reject('CFF_PROJECTION_MISMATCH', store.open, RID)
        assert snapshot(path) == before
        put(path / 'cff_projection.json', saved.artifacts['cff_projection.json'])
        manifest = deepcopy(saved.manifest); rules = b'{"invalid": true}'
        put(path / 'assessment_rules.json', rules)
        entry = next(a for a in manifest['artifacts'] if a['kind'] == 'rules')
        entry.update(size=len(rules), sha256=digest(rules)); manifest['rules_sha256'] = digest(rules)
        put(path / 'run_manifest.json', run_store._json_bytes(manifest))
        before = snapshot(path)
        reject('ASSESSMENT_INVALID_RULES', store.open, RID)
        assert snapshot(path) == before


def test_saved_rules_survive_installation_change(area):
    # This test installation varies only insignificant policy whitespace to
    # prove preservation of raw bytes, not a hard-coded digest or re-encoding.
    install = area / 'install'; (install / 'tools').mkdir(parents=True)
    for name in ('import_reports', 'import_legacy', 'assessment', 'evidence', 'cff', 'run_store'):
        shutil.copyfile(ROOT / 'tools' / (name + '.py'), install / 'tools' / (name + '.py'))
    (install / 'config').mkdir()
    exact = RULES_RAW + b'\n  \n'
    rule_path = put(install / 'config/assessment_rules.yml', exact)
    source = put(area / 'source.json', raw(REPORT))
    result = invoke(area, source, CASES[0][0], install=install)
    assert result.returncode == 0, result.stderr
    saved = read(area / 'reports')
    assert saved.artifacts['assessment_rules.json'] == exact
    assert saved.manifest['rules_sha256'] == digest(exact)
    rule_path.unlink()
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(area), 'LC_ALL': 'C.UTF-8',
           'PYTHONPATH': str(install), 'PYTHONDONTWRITEBYTECODE': '1'}
    script = ('from tools.run_store import RunStore; import sys, hashlib, json\n'
              'with RunStore(sys.argv[1]) as store:\n'
              ' r = store.open(sys.argv[2])\n'
              ' print(json.dumps([r.manifest, hashlib.sha256(r.artifacts["assessment_rules.json"]).hexdigest()]))')
    reopened = subprocess.run([sys.executable, '-B', '-c', script, str(area / 'reports'), RID],
                              cwd=area / 'cwd', env=env, capture_output=True, timeout=60)
    assert reopened.returncode == 0 and reopened.stderr == b'', reopened.stderr
    assert json.loads(reopened.stdout) == [saved.manifest, digest(exact)]


def test_source_drift_detected_before_import(area, monkeypatch):
    source = put(area / 'source.json', raw(REPORT))
    real_read = os.read
    changed = False
    def change_during_read(fd, size):
        nonlocal changed
        chunk = real_read(fd, size)
        if not changed:
            changed = True
            with source.open('ab') as f:
                f.write(b' ')
        return chunk
    with monkeypatch.context() as patch:
        patch.setattr(import_reports.os, 'read', change_during_read)
        with pytest.raises(import_reports.ImportErrorCode) as exc:
            import_reports._read_local(source, import_legacy.MAX_BYTES)
        assert exc.value.code == 'INPUT_CHANGED' and changed
    assert not list((area / 'reports').iterdir())


def test_cli_unsafe_store_root_rejected(area):
    root = area / 'reports'; root.chmod(0o755)
    source = put(area / 'source.json', raw(REPORT))
    reject_cli(invoke(area, source, CASES[0][0]), 'UNSAFE_DIRECTORY', rc=3)
    assert not list(root.iterdir()) and stat.S_IMODE(root.stat().st_mode) == 0o755


def test_actual_import_row_capacity_precedes_reservation(area):
    # Exceed the actual importer row bound without a fleet-scale expansion.
    data = raw({'host': H1, 'openssl_packages': {'openssl': [
        {'version': f'3.5.{j}'} for j in range(import_legacy.MAX_ROWS + 1)]}})
    source = put(area / 'source.json', data)
    reject_cli(invoke(area, source, 'legacy-per-host'), 'ROW_LIMIT')
    assert not list((area / 'reports').iterdir())
    assert source.read_bytes() == data
