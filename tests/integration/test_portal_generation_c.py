"""Actual verified Store publications, fixed preview bytes, no publication."""
from collections import Counter
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tests/unit'))
import test_run_store_v2_certificate as c1
import test_cbom_generation as b
import test_summary_exports as a
from tools import cbom_generation as gen, cbom_validation as validator, export_summary as ex
from tools import portal_asset_indexes as assets, portal_indexes as crypto, portal_generation_c as ca
from tools import import_reports, run_store as rs


@pytest.fixture
def root(tmp_path):
    p = tmp_path / 'reports'
    p.mkdir(mode=0o700)
    return p


def check(root, pub, payload):
    """Compare every buffer with its existing preview/public API."""
    before = c1._c2_tree(root)
    rid, ids = pub.manifest['run_id'], pub.manifest['expected_host_ids']
    p, pages = assets.render_asset_indexes(pub)
    summary, summary_pages, exports = ex.render_summary_exports(pub)
    expected = {**pages, **summary_pages, **exports,
                'asset_indexes.json': json.dumps(p, ensure_ascii=True, sort_keys=True,
                    separators=(',', ':'), allow_nan=False).encode('ascii')}
    with rs.RunStore(root) as store:
        expected['certificates.csv'] = ex.render_certificate_csv(store, rid)
        for hid in ids:
            bom, side = gen.build_cbom_bytes(store, rid, hid, include_certificates=True)
            expected[hid + '.cbom.json'] = bom
            expected[hid + '.cbom.provenance.json'] = side
            assert validator.validate_cbom_bytes(bom) == validator.ValidationResult()
            data, prov = json.loads(bom), json.loads(side)
            assert data['metadata']['component']['bom-ref'] == hid
            assert prov['bom_sha256'] == hashlib.sha256(bom).hexdigest()
            assert prov['host_id'] == hid and prov['run_id'] == rid
            assert prov['coverage']['certificate_key_scope'] == 'B2_CERTIFICATE_KEY'
            host = next(h for h in pub.manifest['hosts'] if h['host_id'] == hid)
            assert prov['coverage']['host_state'] == host['host_state']
            assert prov['coverage']['attempted'] == host['attempted']
            eids = {e['evidence_id'] for e in pub.document['evidence'] if e['host_id'] == hid}
            aids = {x['asset_id'] for x in pub.document['assets'] if x['host_id'] == hid}
            cids = {x['claim_id'] for x in (pub.assessed or pub.document)['claims']
                    if x['subject']['host_id'] == hid}
            assert set(prov['observations']) == eids and set(prov['claims']) == cids
            for node in prov['nodes'].values():
                assert node['host_id'] == hid
                assert set(node['evidence_ids']) <= eids and set(node['asset_ids']) <= aids
                assert set(node['claim_ids']) <= cids
                if node['kind'] == 'PUBLIC_KEY':
                    assert node['identity_basis'] == 'CERTIFICATE_BOUND_SUBJECT_KEY'
                    assert node['key_fingerprint_sha256'] is None
            if not eids:
                assert not data['components'] and not data['services']
                assert not data['dependencies'] and prov['coverage']['evidence_count'] == 0
        hid = ids[0]
        default = gen.build_cbom_bytes(store, rid, hid)
        assert gen.build_cbom_bytes(store, rid, hid, include_certificates=False) == default
        assert json.loads(default[1])['coverage']['certificate_key_scope'] == 'DEFERRED_B2'
    assert payload.run_id == rid and payload.files == expected
    assert list(payload.files) == sorted(expected) and len(expected) == 9 + 2 * len(ids)
    assert payload.entries == tuple(dict(name=k, size=len(v), sha256=hashlib.sha256(v).hexdigest())
                                    for k, v in sorted(expected.items()))
    assert summary['expected_host_ids'] == ids and set(p['hosts']) == set(ids)
    for name in ca._CSV:
        raw = payload.files[name]
        assert raw.startswith(b'\xef\xbb\xbf') and raw.endswith(b'\r\n') and b'\x00' not in raw
        assert all(line.startswith(b'"') for line in raw[3:].split(b'\r\n') if line)
    assert c1._c2_tree(root) == before
    return p, summary


def test_ca_actual_v2_shared_projection(root, monkeypatch):
    c1._c2_open(root, ('complete', 'partial', 'connection'), assessed=True)
    counts = Counter()
    with monkeypatch.context() as patch:
        # Real methods remain the authority; instrumentation only counts calls.
        for module, name in ((rs.RunStore, 'open'), (crypto, 'project_crypto_indexes'),
                             (assets, 'project_asset_indexes'), (validator, 'validate_cbom_bytes'),
                             (gen, '_verified_taxonomy')):
            original = getattr(module, name)
            def call(*args, _name=name, _original=original, **kwargs):
                counts[_name] += 1
                return _original(*args, **kwargs)
            patch.setattr(module, name, call)
        with rs.RunStore(root) as store:
            pub = store.open(c1.RID)
        counts.clear()
        before, original = c1._c2_tree(root), deepcopy(pub)
        payload = ca._assemble_payload(pub)
        assert counts == {'project_asset_indexes': 1, 'project_crypto_indexes': 2,
                          'validate_cbom_bytes': 3, '_verified_taxonomy': 1}
        assert pub == original and c1._c2_tree(root) == before
    p, summary = check(root, pub, payload)
    assert len(p['occurrences']) and ca._assemble_payload(pub) == payload
    assert len(summary['artifacts']) == len(pub.manifest['artifacts'])
    for projected, retained in zip(summary['artifacts'], pub.manifest['artifacts']):
        assert all(projected[k] == retained[k] for k in ('kind', 'host_id', 'slot', 'sha256'))
    assert any(row['slot'] == c1.v2.CERTIFICATE for row in summary['artifacts'])
    assert any(row['kind'] == rs._PRODUCER_RULES_KIND for row in summary['artifacts'])
    assert summary['missing_artifacts'] == pub.manifest['missing_artifacts']


def test_ca_actual_saved_cff(root):
    pub = b.publish(root, cff=True)
    payload = ca._assemble_payload(pub)
    check(root, pub, payload)
    for hid in pub.manifest['expected_host_ids']:
        prov = json.loads(payload.files[hid + '.cbom.provenance.json'])
        assert prov['coverage']['cff_state'] == 'VERIFIED_SAVED_PAIR'
        assert prov['coverage']['cff_sha256'] == hashlib.sha256(pub.artifacts['cff_projection.json']).hexdigest()
        assert b.SECRET.encode() not in payload.files[hid + '.cbom.json'] + payload.files[hid + '.cbom.provenance.json']


def test_ca_actual_summary_and_no_raw_value(root):
    pub = a.publish(root, native=True)
    payload = ca._assemble_payload(pub)
    check(root, pub, payload)
    assert all(a.SENTINEL.encode() not in raw for raw in payload.files.values())


@pytest.mark.parametrize('assessed', [False, True])
def test_ca_zero_evidence(root, assessed):
    pub = a.publish(root, empty=True, assessed=assessed)
    _, summary = check(root, pub, ca._assemble_payload(pub))
    assert not summary['evidence'] and not summary['assets']
    assert a.metric(summary, 'host', 'all', 'completed_attempts', 'COMPLETE') == (0, 1)


def test_ca_recovery(root):
    pub = c1._c2_open(root, ('complete', 'complete', 'complete'), recovery=True)
    check(root, pub, ca._assemble_payload(pub))
    assert pub.manifest['recovery'] and pub.manifest['missing_artifacts']


def test_ca_actual_legacy(root):
    raw = json.loads((ROOT / 'tests/fixtures/legacy_report.json').read_bytes())['legacy-per-host']
    path = root.parent / 'legacy.json'; path.write_text(json.dumps(raw)); path.chmod(0o600)
    prepared = import_reports._prepare(path, 'legacy-per-host', a.RID, a.END, 'fixture', '1.0.0')
    import_reports._publish(prepared, root)
    with rs.RunStore(root) as store:
        pub = store.open(a.RID)
    p, summary = check(root, pub, ca._assemble_payload(pub))
    assert summary['flags_known'] is False and not p['occurrences']
    for row in p['certificates']['groups']:
        assert row['kind'] == 'LEGACY_RUN_SCOPED' and row['fingerprint'] is None


def test_ca_public_boundaries_and_tamper(root):
    pub = c1._c2_open(root, ('complete', 'complete'))
    hid, foreign = pub.manifest['expected_host_ids']
    class Untrusted(rs.RunStore):
        def open(self, rid):
            pytest.fail('subclass used as authority')
    for fake in (pub, {}, root, object.__new__(Untrusted)):
        with pytest.raises(rs.StoreError, match='^INVALID_SUMMARY_PUBLICATION$'):
            ex.render_certificate_csv(fake, c1.RID)
        with pytest.raises(gen.CBOMGenerationError, match='^CBOM_INPUT_TYPE$'):
            gen.build_cbom_bytes(fake, c1.RID, hid)
    with pytest.raises(rs.StoreError, match='^PORTAL_PAYLOAD_INVALID$'):
        ca._assemble_payload({})
    with rs.RunStore(root) as store:
        with pytest.raises(rs.StoreError, match='^INVALID_RUN_ID$'):
            ex.render_certificate_csv(store, '../escape')
        with pytest.raises(gen.CBOMGenerationError, match='^CBOM_INPUT_TYPE$'):
            gen.build_cbom_bytes(store, '../escape', hid)
        with pytest.raises(gen.CBOMGenerationError, match='^CBOM_HOST_NOT_FOUND$'):
            gen.build_cbom_bytes(store, c1.RID, 'h-' + '0' * 64)
    path = root / c1.RID
    manifest = deepcopy(pub.manifest)
    relative = f'details/{hid}/{c1.v2.CERTIFICATE}.json'
    data = json.loads(pub.artifacts[relative]); data['occurrences'][0]['host_id'] = foreign
    c1.reindex(path, manifest, relative, c1.ca.canonical(data))
    (path / 'run_manifest.json').write_bytes(b.raw(manifest))
    before = c1._c2_tree(root)
    with rs.RunStore(root) as store:
        with pytest.raises(rs.StoreError):
            ca._assemble_payload(store.open(c1.RID))
    assert c1._c2_tree(root) == before


def test_ca_formula_and_control(root, monkeypatch):
    # Reuse the original actual Store formula/quote/control test unchanged.
    c1.test_csv_b_actual_metadata(root, monkeypatch, 'formula')
    with rs.RunStore(root) as store:
        pub = store.open(c1.RID)
    payload = ca._assemble_payload(pub)
    check(root, pub, payload)
    assert b"'=1+1" in payload.files['certificates.csv']


def test_ca_standalone_omission(root):
    # The original generic S1 negative builds and verifies an actual run.
    b.test_b2_r1_actual_generic_ssh_metadata_without_normalizer_proof(root, 'fingerprint-conflict')
    with rs.RunStore(root) as store:
        pub = store.open('b2-r1-generic-ssh')
    payload = ca._assemble_payload(pub)
    check(root, pub, payload)
    hid = pub.manifest['expected_host_ids'][0]
    prov = json.loads(payload.files[hid + '.cbom.provenance.json'])
    assert not b.nodes(prov, 'PUBLIC_KEY')
    assert any(o['reason'] == 'STANDALONE_PUBLIC_KEY_PROOF_NOT_RETAINED' for o in prov['omitted'])
    fp = hashlib.sha256(b'generic-not-normalized-key').hexdigest().encode()
    assert fp not in payload.files[hid + '.cbom.json'] + payload.files[hid + '.cbom.provenance.json']


@pytest.mark.parametrize('cap', ['_MAX_HTML', '_MAX_HTML_TOTAL', '_MAX_JSON', '_MAX_CSV',
                                '_MAX_CSV_TOTAL', '_MAX_CBOM_PAIR', '_MAX_CBOM_TOTAL', '_MAX_BUNDLE'])
def test_ca_exact_capacity_and_overflow(root, monkeypatch, cap):
    pub = a.publish(root, assessed=False, empty=True)
    payload = ca._assemble_payload(pub)
    f = payload.files
    pairs = [len(f[h + '.cbom.json']) + len(f[h + '.cbom.provenance.json'])
             for h in pub.manifest['expected_host_ids']]
    limit = {'_MAX_HTML': max(len(f[k]) for k in ca._HTML),
             '_MAX_HTML_TOTAL': sum(len(f[k]) for k in ca._HTML),
             '_MAX_JSON': max(len(f[k]) for k in ca._JSON),
             '_MAX_CSV': max(len(f[k]) for k in ca._CSV),
             '_MAX_CSV_TOTAL': sum(len(f[k]) for k in ca._CSV),
             '_MAX_CBOM_PAIR': max(pairs), '_MAX_CBOM_TOTAL': sum(pairs),
             '_MAX_BUNDLE': sum(map(len, f.values()))}[cap]
    before = c1._c2_tree(root)
    monkeypatch.setattr(ca, cap, limit)
    assert ca._assemble_payload(pub) == payload
    monkeypatch.setattr(ca, cap, limit - 1)
    with pytest.raises(rs.StoreError, match='^PORTAL_PAYLOAD_SIZE_LIMIT$'):
        ca._assemble_payload(pub)
    assert c1._c2_tree(root) == before


def test_ca_multihost_aggregate_and_memberships(root, monkeypatch):
    pub = b.publish(root, saved=False)
    payload = ca._assemble_payload(pub)
    total = sum(len(raw) for name, raw in payload.files.items() if '.cbom.' in name)
    before = c1._c2_tree(root)
    with monkeypatch.context() as p:
        p.setattr(ca, '_MAX_CBOM_TOTAL', total)
        assert ca._assemble_payload(pub) == payload
        p.setattr(ca, '_MAX_CBOM_TOTAL', total - 1)
        with pytest.raises(rs.StoreError, match='^PORTAL_PAYLOAD_SIZE_LIMIT$'):
            ca._assemble_payload(pub)
    with monkeypatch.context() as p:
        p.setattr(gen, '_MAX_BATCH_MEMBERSHIPS', 1)
        with pytest.raises(rs.StoreError, match='^PORTAL_PAYLOAD_SIZE_LIMIT$'):
            ca._assemble_payload(pub)
    assert c1._c2_tree(root) == before


def test_ca_actual_validator_failure(root, monkeypatch):
    pub = c1._c2_open(root, ('complete',))
    before = c1._c2_tree(root)
    with monkeypatch.context() as p:
        p.setattr(validator, '_SCHEMA_DIR', root / 'missing-schema')
        with pytest.raises(rs.StoreError, match='^PORTAL_PAYLOAD_INVALID$'):
            ca._assemble_payload(pub)
    original = gen._Projection.finish
    def bad(self):
        bom, provenance = original(self)
        cert = next(c for c in bom['components'] if c['cryptoProperties']['assetType'] == 'certificate')
        cert['cryptoProperties']['certificateProperties']['signatureAlgorithmRef'] = 'cbom-' + '0' * 64
        return bom, provenance
    monkeypatch.setattr(gen._Projection, 'finish', bad)
    with pytest.raises(rs.StoreError, match='^PORTAL_PAYLOAD_INVALID$'):
        ca._assemble_payload(pub)
    assert c1._c2_tree(root) == before
