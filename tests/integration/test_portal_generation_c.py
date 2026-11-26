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


# Historical oracle: fixed, independently hashed Q source, not a second call
# to the implementation being tested. A private exact-Q checkout may be
# supplied for local focused testing without obtaining unrelated Repo files.
_CB1A_Q = '03785660e59831917e1db68d43b61aeadf8c021a'
_CB1A_Q_FILES = {
    'tools/portal_asset_indexes.py': 'f840eb62b3ac3dc977f9958c0f29fb70f8f354e6',
    'tools/portal_generation_c.py': '26c3d4ae60cdc2fc055577062092bc9271ab8d32',
    'templates/portal/certificates.html.j2': '805bf42152bc28b4adadbf499c2370b58c9f7587',
    'templates/portal/services.html.j2': 'f30f7afda70886ca5ade735b1db6199791b031a9',
    'tools/export_summary.py': '6df58cba785b6c70fbfba69ccf9151a5d5de1b04',
    'templates/portal/findings.html.j2': '6bdf8dc1911bcd2efa052d5f398f02a63c1d64f2',
    'templates/portal/coverage.html.j2': '308f81f37fa009229d178e3c400bf191d866555a',
}
_CB1B_R = '3b4018852910de33841c6768b78ec3b42eeafb05'
_CB1B_R_FILES = {**_CB1A_Q_FILES,
    'tools/portal_asset_indexes.py': '512e62ae047b3679bbe87dd81baa4c6fdcfe0661',
    'tools/portal_generation_c.py': '917267ffe374d0d72d6270cfed2ad478a22f19ac',
    'templates/portal/certificates.html.j2': '3f9c481bc2f6b7efba7a820eee3e645445b0e840',
    'templates/portal/services.html.j2': 'edc3071fd080178bc582d6567edd4f033e0dbbee',
}


def _cb1a_original(tmp_path, *, assembler=True):
    return _cb1b_original(tmp_path, _CB1A_Q, _CB1A_Q_FILES, 'q',
                           'PQC_CB1A_Q_ROOT', assembler=assembler)


def _cb1b_original(tmp_path, commit, files, label, source_var, *, assembler=True):
    import os
    import subprocess
    from types import ModuleType

    original = tmp_path / ('fixed-' + label)
    original.mkdir(mode=0o700)
    for name, oid in files.items():
        if not assembler and name in ('tools/portal_generation_c.py', 'tools/export_summary.py',
                                       'templates/portal/findings.html.j2', 'templates/portal/coverage.html.j2'):
            continue
        source = os.environ.get(source_var)
        if source:
            data = (Path(source) / name).read_bytes()
        else:
            data = subprocess.run(['git', 'show', f'{commit}:{name}'], cwd=ROOT,
                                  check=True, capture_output=True, timeout=10).stdout
        assert hashlib.sha1(f'blob {len(data)}\0'.encode('ascii') + data).hexdigest() == oid
        path = original / name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(data)
        path.chmod(0o600)

    def load(name):
        module = ModuleType('_cb1b_' + label + '_' + name)
        path = original / 'tools' / (name + '.py')
        module.__file__ = str(path)
        exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
        return module

    old_assets = load('portal_asset_indexes')
    old_ca = load('portal_generation_c') if assembler else None
    if old_ca is not None:
        old_ca.portal_asset_indexes = old_assets
        old_ca.export_summary = load('export_summary')
    return old_assets, old_ca


def _cb1a_parse(raw):
    from html.parser import HTMLParser
    from urllib.parse import urlsplit

    class Page(HTMLParser):
        def __init__(self):
            super().__init__()
            self.ids = set()
            self.links = []
            self.sections = []
            self.coverage_rows = []
            self.in_coverage = False
            self.in_sections = False
            self.row = None
            self.item = None

        def handle_starttag(self, tag, attrs):
            assert tag not in {'script', 'iframe', 'object', 'embed', 'base', 'form', 'img'}
            attrs = dict(attrs)
            assert not any(k.startswith('on') or k in ('src', 'srcset', 'action', 'style') for k in attrs)
            if 'id' in attrs:
                assert attrs['id'] not in self.ids
                self.ids.add(attrs['id'])
            if tag == 'section' and attrs.get('id') == 'coverage':
                self.in_coverage = True
            if tag == 'tr' and self.in_coverage:
                self.row = []
            if tag == 'nav' and attrs.get('aria-label') == 'Run sections':
                self.in_sections = True
            if self.in_sections and tag in ('a', 'span'):
                self.item = [tag, attrs.get('href'), attrs.get('aria-current'), '']
            if 'href' in attrs:
                href = attrs['href']; parsed = urlsplit(href)
                assert not parsed.scheme and not parsed.netloc and not parsed.query
                assert not parsed.path.startswith('/') and '\\' not in href and '%' not in href
                assert '..' not in parsed.path or href in ('../portal.css', '../index.html', '../../index.html')
                self.links.append(href)
                if self.row is not None:
                    self.row.append(href)

        def handle_data(self, data):
            if self.item is not None:
                self.item[3] += data

        def handle_endtag(self, tag):
            if self.item is not None and tag == self.item[0]:
                self.sections.append(tuple(self.item))
                self.item = None
            if tag == 'nav':
                self.in_sections = False
            if tag == 'tr' and self.row is not None:
                if self.row:
                    self.coverage_rows.append(self.row)
                self.row = None
            if tag == 'section':
                self.in_coverage = False

    page = Page()
    page.feed(raw.decode('utf-8'))
    page.close()
    return page


def _cb1a_asset_links(projection, files, *, check_coverage=True):
    sections = ('Hosts', 'Algorithms', 'Libraries', 'Certificates', 'Services', 'Findings', 'Coverage')
    names = ('certificates', 'services')
    pages = {name: _cb1a_parse(files[name + '.html']) for name in names}
    coverage = _cb1a_parse(files['coverage.html']) if check_coverage else None
    known_refs = {v['href'] for key in ('hosts', 'assets', 'evidence', 'claims')
                  for v in projection[key].values()}
    known_refs |= {link['href'] for name in names for group in projection[name]['groups']
                   for link in group['algorithm_links']}
    for name, slots in zip(names, (('system_certs', 'nginx_certs'), ('sshd', 'tls_services'))):
        page = pages[name]
        assert page.sections == [('span', None, 'page', title) if title.lower() == name else
                                 ('a', title.lower() + '.html', None, title) for title in sections]
        assert {'#main', '../portal.css', '../index.html', '../../index.html'} <= set(page.links)
        rows = [row for row in projection['coverage'] if row['slot'] in slots]
        expected = [[projection['hosts'][row['host_id']]['href'], 'coverage.html#' + row['host_id']]
                    for row in rows]
        assert page.coverage_rows == expected
        if coverage is not None:
            assert all(row['host_id'] in coverage.ids for row in rows)
        for group in projection[name]['groups']:
            assert group['id'] in page.ids
            for ids, registry in (('host_ids', 'hosts'), ('asset_ids', 'assets'),
                                  ('evidence_ids', 'evidence'), ('claim_ids', 'claims')):
                assert all(projection[registry][ref]['href'] in page.links for ref in group[ids])
            assert all(link['href'] in page.links for link in group['algorithm_links'])
        for href in page.links:
            target, _, fragment = href.partition('#')
            if not target:
                assert fragment in page.ids
            elif target in {key + '.html' for key in names} and fragment:
                assert fragment in pages[target[:-5]].ids
            elif target == 'coverage.html' and fragment:
                assert fragment in projection['hosts']
            elif fragment:
                assert href in known_refs
            else:
                assert href in ('../portal.css', '../index.html', '../../index.html',
                                *(title.lower() + '.html' for title in sections))
    return pages


@pytest.mark.parametrize('kind', ['c1', 'v1', 's1', 'legacy', 'zero', 'zero-assessed', 'recovery'])
def test_cb1a_actual_q_oracle(root, tmp_path, kind):
    if kind == 'c1':
        pub = c1._c2_open(root, ('complete', 'partial', 'connection'), assessed=True)
    elif kind == 'v1':
        pub = a.publish(root, native=True)
    elif kind == 'recovery':
        pub = c1._c2_open(root, ('complete', 'complete', 'complete'), recovery=True)
    elif kind == 's1':
        from test_portal_asset_index import publish_assets
        pub = publish_assets(root)
    elif kind == 'legacy':
        raw = json.loads((ROOT / 'tests/fixtures/legacy_report.json').read_bytes())['legacy-per-host']
        path = tmp_path / 'legacy.json'
        path.write_text(json.dumps(raw)); path.chmod(0o600)
        prepared = import_reports._prepare(path, 'legacy-per-host', a.RID, a.END, 'fixture', '1.0.0')
        import_reports._publish(prepared, root)
        with rs.RunStore(root) as store:
            pub = store.open(a.RID)
    else:
        pub = a.publish(root, assessed=kind == 'zero-assessed', empty=True)
    before, snapshot = c1._c2_tree(root), deepcopy(pub)
    old_assets, old_ca = _cb1a_original(tmp_path)
    original_projection, original_pages = old_assets.render_asset_indexes(pub)
    assert assets.render_asset_indexes(pub) == (original_projection, original_pages)
    original = old_ca._assemble_payload(pub)
    r_assets, r_ca = _cb1b_original(tmp_path, _CB1B_R, _CB1B_R_FILES, 'r', 'PQC_CB1B_R_ROOT')
    assert r_assets.render_asset_indexes(pub) == (original_projection, original_pages)
    # Keep the original two-page assertion on the historical Q -> R transition.
    default = r_ca._assemble_payload(pub)
    assert (default.run_id, default.files, default.entries) == (original.run_id, original.files, original.entries)
    assert r_ca._assemble_payload(pub, portal_v5=False) == default
    v5 = r_ca._assemble_payload(pub, portal_v5=True)
    assert v5.run_id == default.run_id and list(v5.files) == list(default.files)
    changed = {'certificates.html', 'services.html'}
    assert {name for name in default.files if default.files[name] != v5.files[name]} == changed
    assert {new['name'] for old, new in zip(default.entries, v5.entries) if old != new} == changed
    assert v5.entries == tuple(dict(name=name, size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
                               for name, raw in sorted(v5.files.items()))
    assert json.loads(v5.files['asset_indexes.json']) == original_projection
    _cb1a_asset_links(original_projection, v5.files)
    if kind == 's1':
        assert b'&lt;img src=x onerror=alert(1)&gt;' in v5.files['services.html']
    assert all(a.SENTINEL.encode() not in raw for raw in v5.files.values())
    for hid in pub.manifest['expected_host_ids']:
        assert validator.validate_cbom_bytes(v5.files[hid + '.cbom.json']) == validator.ValidationResult()
    assert r_ca._assemble_payload(pub, portal_v5=True) == v5
    # Independent R -> candidate oracle: old R summary module is explicitly
    # bound above, and reads only fixed hash-checked R templates.
    assert ex.render_summary_exports(pub) == r_ca.export_summary.render_summary_exports(pub)
    assert ex.render_summary_exports(pub) == old_ca.export_summary.render_summary_exports(pub)
    current = ca._assemble_payload(pub)
    assert tuple(current) == tuple(default)
    assert ca._assemble_payload(pub, portal_v5=False) == current
    integrated = ca._assemble_payload(pub, portal_v5=True)
    assert integrated.run_id == current.run_id and list(integrated.files) == list(v5.files)
    assert len(integrated.files) == 9 + 2 * len(pub.manifest['expected_host_ids'])
    for prior, changed_names in ((v5, {'findings.html', 'coverage.html'}),
                                 (current, set(ca._HTML))):
        assert {n for n in prior.files if prior.files[n] != integrated.files[n]} == changed_names
        assert {new['name'] for old, new in zip(prior.entries, integrated.entries) if old != new} == changed_names
    assert integrated.entries == tuple(dict(name=name, size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
                                       for name, raw in sorted(integrated.files.items()))
    assert ca._assemble_payload(pub, portal_v5=True) == integrated
    _cb1a_asset_links(original_projection, integrated.files)
    _cb1b_summary_links(pub, integrated.files, previous=v5.files)
    assert all(a.SENTINEL.encode() not in raw for raw in integrated.files.values())
    for hid in pub.manifest['expected_host_ids']:
        assert validator.validate_cbom_bytes(integrated.files[hid + '.cbom.json']) == validator.ValidationResult()
    assert pub == snapshot and c1._c2_tree(root) == before


@pytest.mark.parametrize('kind', ['s1', 'legacy'])
def test_cb1a_actual_v4_external_links(root, tmp_path, kind):
    from test_portal_asset_index import publish_assets, catalog, portal, Page
    if kind == 's1':
        pub = publish_assets(root)
    else:
        raw = json.loads((ROOT / 'tests/fixtures/legacy_report.json').read_bytes())['legacy-per-host']
        path = tmp_path / 'legacy-v4.json'
        path.write_text(json.dumps(raw)); path.chmod(0o600)
        prepared = import_reports._prepare(path, 'legacy-per-host', a.RID, a.END, 'fixture', '1.0.0')
        import_reports._publish(prepared, root)
        with rs.RunStore(root) as store:
            pub = store.open(a.RID)
    rid = pub.manifest['run_id']
    catalog.build_catalog(root)
    portal.render_run(root, rid, with_crypto_indexes=True)
    before = c1._c2_tree(root)
    payload = ca._assemble_payload(pub, portal_v5=True)
    projection = json.loads(payload.files['asset_indexes.json'])
    pages = _cb1a_asset_links(projection, payload.files)
    pages.update(_cb1b_summary_links(pub, payload.files))
    generation = root / rid / 'portal-v4'
    for page in pages.values():
        for href in page.links:
            target, _, fragment = href.partition('#')
            if target in ('certificates.html', 'services.html', 'findings.html', 'coverage.html', ''):
                continue
            if target in ('../portal.css', '../index.html', '../../index.html'):
                assert (generation / target).is_file()
            else:
                actual = generation / target
                assert actual.is_file()
                if fragment:
                    # Existing V4 host pages legitimately link back to
                    # ../index.html#host-id. Keep the strict V5 parser on
                    # the new pages; use the original unique-ID oracle for
                    # these unchanged external targets, not fake V2 pages.
                    assert fragment in Page(actual).ids
    assert c1._c2_tree(root) == before


def test_cb1a_actual_shared_validation(root, monkeypatch):
    pub = c1._c2_open(root, ('complete', 'partial', 'connection'), assessed=True)
    counts = Counter()
    for module, name in ((rs.RunStore, 'open'), (crypto, 'project_crypto_indexes'),
                         (assets, 'project_asset_indexes'), (ex, '_project_scan_summary'),
                         (validator, 'validate_cbom_bytes'),
                         (gen, '_verified_taxonomy')):
        original = getattr(module, name)
        def call(*args, _name=name, _original=original, **kwargs):
            counts[_name] += 1
            return _original(*args, **kwargs)
        monkeypatch.setattr(module, name, call)
    before = c1._c2_tree(root)
    ca._assemble_payload(pub, portal_v5=True)
    assert counts == {'project_asset_indexes': 1, 'project_crypto_indexes': 2,
                      'validate_cbom_bytes': 3, '_verified_taxonomy': 1, '_project_scan_summary': 1}
    assert c1._c2_tree(root) == before


@pytest.mark.parametrize('value', [None, 0, 1, 'true', [], {}])
def test_cb1a_strict_mode(root, value):
    pub = a.publish(root, assessed=False, empty=True)
    before = c1._c2_tree(root)
    with pytest.raises(rs.StoreError, match='^PORTAL_PAYLOAD_INVALID$'):
        ca._assemble_payload(pub, portal_v5=value)
    assert c1._c2_tree(root) == before


@pytest.mark.parametrize('cap', ['_MAX_HTML', '_MAX_HTML_TOTAL', '_MAX_BUNDLE'])
def test_cb1a_exact_capacity(root, monkeypatch, cap):
    pub = a.publish(root, assessed=False, empty=True)
    payload = ca._assemble_payload(pub, portal_v5=True)
    limit = {'_MAX_HTML': max(len(payload.files[name]) for name in ca._HTML),
             '_MAX_HTML_TOTAL': sum(len(payload.files[name]) for name in ca._HTML),
             '_MAX_BUNDLE': sum(len(raw) for raw in payload.files.values())}[cap]
    before = c1._c2_tree(root)
    monkeypatch.setattr(ca, cap, limit)
    assert ca._assemble_payload(pub, portal_v5=True) == payload
    monkeypatch.setattr(ca, cap, limit - 1)
    with pytest.raises(rs.StoreError, match='^PORTAL_PAYLOAD_SIZE_LIMIT$'):
        ca._assemble_payload(pub, portal_v5=True)
    assert c1._c2_tree(root) == before


def test_cb1a_missing_template(root, tmp_path, monkeypatch):
    pub = a.publish(root, assessed=False, empty=True)
    before = c1._c2_tree(root)
    only = tmp_path / 'one-template'
    only.mkdir(mode=0o700)
    (only / 'certificates.html.j2').write_bytes((assets._TEMPLATES / 'certificates.html.j2').read_bytes())
    monkeypatch.setattr(assets, '_TEMPLATES', only)
    with pytest.raises(rs.StoreError, match='^ASSET_INDEX_RENDER_ERROR$'):
        assets.render_asset_indexes(pub)
    with pytest.raises(rs.StoreError, match='^PORTAL_PAYLOAD_INVALID$'):
        ca._assemble_payload(pub, portal_v5=True)
    assert c1._c2_tree(root) == before


@pytest.mark.parametrize('modes', [('complete', 'partial', 'connection'), ('disabled',)])
def test_cb1a_actual_asset_only(root, tmp_path, monkeypatch, modes):
    original = c1.cert_snapshot
    sentinel = '<img src=x onerror=alert(1)>'
    def public_metadata(partial=False, large=False):
        snapshot = original(partial, large)
        for value in snapshot.values():
            for source in value['sources']:
                for block in source['blocks']:
                    cert = block['certificate']
                    cert['issuer'] = 'CN=' + sentinel
                    cert['gaps'] = c1.ca.metadata_gaps(cert)
                    block['reason'] = 'METADATA_GAP' if cert['gaps'] else 'OK'
        return snapshot
    monkeypatch.setattr(c1, 'cert_snapshot', public_metadata)
    pub = c1._c2_open(root, modes, assessed=len(modes) > 1)
    old_assets, _ = _cb1a_original(tmp_path, assembler=False)
    before, saved = c1._c2_tree(root), deepcopy(pub)
    projection, preview = old_assets.render_asset_indexes(pub)
    assert assets.render_asset_indexes(pub) == (projection, preview)
    projected, pages = assets._render_asset_indexes(pub, portal_v5=True)
    assert projected == projection
    _cb1a_asset_links(projected, pages, check_coverage=False)
    if len(modes) > 1:
        assert b'&lt;img src=x onerror=alert(1)&gt;' in pages['certificates.html']
        assert sentinel.encode() not in pages['certificates.html']
    else:
        assert not projected['occurrences'] and not projected['services']['groups']
        assert all(row['state'] != 'COLLECTED' for row in projected['coverage'])
    maximum, total = max(map(len, pages.values())), sum(map(len, pages.values()))
    assert assets._render_asset_indexes(pub, portal_v5=True, page_limit=maximum,
                                        total_limit=total) == (projected, pages)
    for limits in (dict(page_limit=maximum - 1), dict(total_limit=total - 1)):
        with pytest.raises(rs.StoreError, match='^ASSET_INDEX_SIZE_LIMIT$'):
            assets._render_asset_indexes(pub, portal_v5=True, **limits)
    assert pub == saved and c1._c2_tree(root) == before


# Strict V5 parser is reused unchanged; inspect the actual saved finding rows
# independently so that a valid host fragment on the wrong row is not enough.
def _cb1b_summary_links(pub, files, *, previous=None):
    from html.parser import HTMLParser
    from html import escape

    p = json.loads(files['scan_summary.json'])
    sections = ('Hosts', 'Algorithms', 'Libraries', 'Certificates', 'Services', 'Findings', 'Coverage')
    pages = {n: _cb1a_parse(files[n + '.html']) for n in ('findings', 'coverage')}
    finding, coverage = pages['findings'], pages['coverage']
    known = {r['href'] for key in ('hosts', 'collections', 'assets', 'evidence', 'claims', 'findings')
             for r in (p[key] or {}).values()}
    known |= {'algorithms.html#' + r['id'] for r in p['algorithms']}
    local = {name: _cb1a_parse(files[name]) for name in ca._HTML}
    for name, page in pages.items():
        assert page.sections == [('span', None, 'page', title) if title.lower() == name else
                                 ('a', title.lower() + '.html', None, title) for title in sections]
        assert {'#main', '../portal.css', '../index.html', '../../index.html'} <= set(page.links)
        for href in page.links:
            path, _, fragment = href.partition('#')
            if not path:
                assert fragment in page.ids
            elif path in local:
                assert not fragment or fragment in local[path].ids
            elif fragment:
                assert href in known
            else:
                assert href in ('../portal.css', '../index.html', '../../index.html',
                                *(title.lower() + '.html' for title in sections))
    ids = pub.manifest['expected_host_ids']
    assert p['expected_host_ids'] == ids and set(p['hosts']) == set(ids)
    assert {i for i in coverage.ids if i.startswith('h-')} == set(ids)
    assert {'summary-metrics', 'collector-results', 'recorded-collections', 'recorded-assets',
            'artifact-status', 'algorithm-summary', 'host-results'} <= coverage.ids
    for item in p['missing_artifacts']:
        assert item['path'] not in coverage.links
        assert escape(item['path']).encode() in files['coverage.html']
    assert p['missing_artifacts'] == pub.manifest['missing_artifacts']

    class FindingRows(HTMLParser):
        def __init__(self, raw):
            super().__init__()
            self.rows, self.row = {}, None
            self.feed(raw.decode('utf-8')); self.close()

        def handle_starttag(self, tag, attrs):
            attrs = dict(attrs)
            if tag == 'tr' and 'id' in attrs:
                self.row = attrs['id']
                assert self.row not in self.rows
                self.rows[self.row] = []
            if self.row is not None and 'href' in attrs:
                self.rows[self.row].append(attrs['href'])

        def handle_endtag(self, tag):
            if tag == 'tr':
                self.row = None

    rows = FindingRows(files['findings.html']).rows
    saved = {} if pub.assessed is None else {r['finding_id']: r for r in pub.assessed['findings']}
    assert set(rows) == set(saved) == set(p['findings'] or {})
    for fid, r in saved.items():
        f = p['findings'][fid]; hid = r['subject']['host_id']
        assert f['subject'] == r['subject'] and hid in ids and hid in coverage.ids
        for key in ('condition_key', 'rule_id', 'rule_version', 'assessment_state', 'reason_code'):
            assert f[key] == r[key]
        assert set(f['claim_ids']) == set(r['claim_ids']) and set(f['evidence_ids']) == set(r['evidence_ids'])
        expected = [f['href'], p['hosts'][hid]['href'], 'coverage.html#' + hid]
        if r['subject'].get('asset_id'):
            asset = p['assets'][r['subject']['asset_id']]
            assert asset['host_id'] == hid
            expected.append(asset['href'])
        for key, registry in (('claim_ids', 'claims'), ('evidence_ids', 'evidence')):
            for ref in f[key]:
                member = p[registry][ref]
                assert (member['subject']['host_id'] if registry == 'claims' else member['host_id']) == hid
                expected.append(member['href'])
        assert rows[fid] == expected
    assert sorted(h for h in finding.links if h.startswith('coverage.html#')) == sorted(
        'coverage.html#' + r['subject']['host_id'] for r in saved.values())
    if pub.assessed is None:
        assert p['findings'] is None and 'not-assessed' in finding.ids
    elif not saved:
        assert 'empty-findings' in finding.ids
    if previous is not None:
        for name, table_ids in (('findings.html', ('assessment-metrics',)),
                                ('coverage.html', ('metrics', 'algorithm-metrics'))):
            old, new = a.Page(previous[name]), a.Page(files[name])
            for table_id in table_ids:
                assert old.tables[table_id] == new.tables[table_id]
            assert old.ids == new.ids
    return pages


def test_cb1b_actual_saved_finding_and_escaping(root):
    pub = a.publish(root, native=True)
    before, snapshot = c1._c2_tree(root), deepcopy(pub)
    assert pub.assessed['findings']
    assert len({r['subject']['host_id'] for r in pub.assessed['findings']}) > 1
    payload = ca._assemble_payload(pub, portal_v5=True)
    _cb1b_summary_links(pub, payload.files)
    assert b'&lt;img' in payload.files['coverage.html']
    assert a.MALICIOUS.encode() not in payload.files['coverage.html']
    assert all(a.SENTINEL.encode() not in raw for raw in payload.files.values())
    assert pub == snapshot and c1._c2_tree(root) == before


@pytest.mark.parametrize('cap', ['page_limit', 'html_limit', 'bundle_limit'])
def test_cb1b_summary_stream_capacity(root, monkeypatch, cap):
    pub = a.publish(root, native=True)
    before, snapshot = c1._c2_tree(root), deepcopy(pub)
    p = ex.project_scan_summary(pub)
    original = deepcopy(p)
    result = ex._render_summary_projection(p, portal_v5=True)
    _, pages, exports = result
    limits = dict(page_limit=max(map(len, pages.values())), html_limit=sum(map(len, pages.values())),
                  bundle_limit=sum(map(len, pages.values())) + sum(map(len, exports.values())))
    assert ex._render_summary_projection(p, portal_v5=True, **limits) == result
    # Capture real chunk writes; even on error the buffer may never exceed cap.
    write = ex._Bytes.write
    rejected = []
    def bounded(self, text):
        try:
            return write(self, text)
        except rs.StoreError:
            rejected.append((len(self.data), self.cap, len(text.encode('utf-8'))))
            raise
        finally:
            assert len(self.data) <= self.cap
    monkeypatch.setattr(ex._Bytes, 'write', bounded)
    limits[cap] -= 1
    with pytest.raises(rs.StoreError, match='^SUMMARY_SIZE_LIMIT$'):
        ex._render_summary_projection(p, portal_v5=True, **limits)
    assert rejected and rejected[-1][0] + rejected[-1][2] > rejected[-1][1]
    assert p == original and pub == snapshot and c1._c2_tree(root) == before


def test_cb1b_remaining_bundle_before_html(root, monkeypatch):
    pub = a.publish(root, assessed=False, empty=True)
    before = c1._c2_tree(root)
    payload = ca._assemble_payload(pub, portal_v5=True)
    asset_bytes = sum(len(payload.files[n]) for n in ('certificates.html', 'services.html'))
    summary_bytes = sum(len(payload.files[n]) for n in ('scan_summary.json', 'summary.csv', 'algorithms.csv'))
    # Exactly all existing asset HTML and summary exports, no byte for HTML.
    # Failure must come from the streaming writer before CBOM generation.
    seen = []
    write = ex._Bytes.write
    def bounded(self, text):
        if self.cap == 0:
            seen.append(len(self.data))
        return write(self, text)
    monkeypatch.setattr(ex._Bytes, 'write', bounded)
    monkeypatch.setattr(ca, '_MAX_BUNDLE', asset_bytes + summary_bytes)
    with pytest.raises(rs.StoreError, match='^PORTAL_PAYLOAD_SIZE_LIMIT$'):
        ca._assemble_payload(pub, portal_v5=True)
    assert seen == [0] and c1._c2_tree(root) == before


@pytest.mark.parametrize('kind', ['foreign', 'malformed', 'registry-mismatch', 'missing-row'])
def test_cb1b_invalid_host(root, monkeypatch, kind):
    pub = a.publish(root, native=True)
    before, snapshot = c1._c2_tree(root), deepcopy(pub)
    original = ex._project_scan_summary
    def bad(*args, **kwargs):
        p = original(*args, **kwargs)
        f = next(iter(p['findings'].values()))
        hid = f['subject']['host_id']
        if kind == 'foreign':
            f['subject']['host_id'] = 'h-' + '0' * 64
        elif kind == 'malformed':
            f['subject']['host_id'] = '../index.html'
        elif kind == 'registry-mismatch':
            p['hosts'][hid]['host_id'] = 'h-' + '0' * 64
        else:
            p['expected_host_ids'].remove(hid)
        return p
    monkeypatch.setattr(ex, '_project_scan_summary', bad)
    with pytest.raises(rs.StoreError, match='^PORTAL_PAYLOAD_INVALID$'):
        ca._assemble_payload(pub, portal_v5=True)
    assert pub == snapshot and c1._c2_tree(root) == before


def test_cb1b_private_mode_and_missing_template(root, tmp_path, monkeypatch):
    pub = a.publish(root, assessed=False, empty=True)
    before, snapshot = c1._c2_tree(root), deepcopy(pub)
    old_assets, old = _cb1b_original(tmp_path, _CB1B_R, _CB1B_R_FILES, 'r', 'PQC_CB1B_R_ROOT')
    p = ex.project_scan_summary(pub)
    for value in (None, 0, 1, 'true', [], {}):
        with pytest.raises(rs.StoreError, match='^INVALID_SUMMARY_PUBLICATION$'):
            ex._render_summary_projection(p, portal_v5=value)
    with pytest.raises(rs.StoreError, match='^INVALID_SUMMARY_PUBLICATION$'):
        ex.render_summary_exports(None)
    with pytest.raises(rs.StoreError, match='^INVALID_SUMMARY_PUBLICATION$'):
        old.export_summary.render_summary_exports(None)
    only = tmp_path / 'only-findings'; only.mkdir(mode=0o700)
    (only / 'findings.html.j2').write_bytes((ex._TEMPLATES / 'findings.html.j2').read_bytes())
    old_only = tmp_path / 'old-only-findings'; old_only.mkdir(mode=0o700)
    (old_only / 'findings.html.j2').write_bytes((old.export_summary._TEMPLATES / 'findings.html.j2').read_bytes())
    monkeypatch.setattr(ex, '_TEMPLATES', only)
    monkeypatch.setattr(old.export_summary, '_TEMPLATES', old_only)
    for module in (ex, old.export_summary):
        with pytest.raises(rs.StoreError, match='^SUMMARY_RENDER_ERROR$'):
            module.render_summary_exports(pub)
    for module in (ca, old):
        with pytest.raises(rs.StoreError, match='^PORTAL_PAYLOAD_INVALID$'):
            module._assemble_payload(pub)
    with pytest.raises(rs.StoreError, match='^PORTAL_PAYLOAD_INVALID$'):
        ca._assemble_payload(pub, portal_v5=True)
    assert pub == snapshot and c1._c2_tree(root) == before



def test_cb1b_first_page_and_four_page_aggregate_streaming(root, monkeypatch):
    pub = a.publish(root, native=True)
    before, snapshot = c1._c2_tree(root), deepcopy(pub)
    payload = ca._assemble_payload(pub, portal_v5=True)
    p = ex.project_scan_summary(pub)
    finding, coverage = (payload.files[n] for n in ('findings.html', 'coverage.html'))
    assert len(finding) < len(coverage)
    write, finish = ex._Bytes.write, ex._Bytes.finish
    completed, rejected = [], []

    def bounded(self, text):
        try:
            return write(self, text)
        except rs.StoreError:
            rejected.append((self.cap, len(self.data), len(text.encode('utf-8'))))
            raise
        finally:
            assert len(self.data) <= self.cap

    def finished(self):
        raw = finish(self)
        if raw.startswith(b'<!doctype html>'):
            completed.append((self.cap, raw))
        return raw

    monkeypatch.setattr(ex._Bytes, 'write', bounded)
    monkeypatch.setattr(ex._Bytes, 'finish', finished)
    # First summary page exactly fills its cap; the later page is larger.
    with pytest.raises(rs.StoreError, match='^SUMMARY_SIZE_LIMIT$'):
        ex._render_summary_projection(p, portal_v5=True, page_limit=len(finding))
    assert completed == [(len(finding), finding)] and rejected[-1][0] == len(finding)
    completed.clear(); rejected.clear()
    with pytest.raises(rs.StoreError, match='^SUMMARY_SIZE_LIMIT$'):
        ex._render_summary_projection(p, portal_v5=True, page_limit=len(finding) - 1)
    assert not completed and rejected[-1][0] == len(finding) - 1
    # Actual four-page budget: asset bytes are already charged when streaming
    # summary, so the failure is in the second summary writer, not _Buffers.
    completed.clear(); rejected.clear()
    total = sum(len(payload.files[n]) for n in ca._HTML)
    monkeypatch.setattr(ca, '_MAX_HTML_TOTAL', total)
    assert ca._assemble_payload(pub, portal_v5=True) == payload
    assert completed[-1] == (len(coverage), coverage)
    completed.clear(); rejected.clear()
    monkeypatch.setattr(ca, '_MAX_HTML_TOTAL', total - 1)
    with pytest.raises(rs.StoreError, match='^PORTAL_PAYLOAD_SIZE_LIMIT$'):
        ca._assemble_payload(pub, portal_v5=True)
    assert completed and completed[-1][1] == finding
    assert rejected[-1][0] == len(coverage) - 1
    assert pub == snapshot and c1._c2_tree(root) == before


def test_cb1b_empty_saved_findings_presentation(root):
    pub = a.publish(root, assessed=True, empty=True)
    p = ex.project_scan_summary(pub)
    # Presentation-only negative seam, not a claimed verified empty assessment.
    assert p['findings']
    view = {**p, 'findings': {}}
    _, pages, _ = ex._render_summary_projection(view, portal_v5=True)
    parsed = _cb1a_parse(pages['findings.html'])
    assert 'empty-findings' in parsed.ids and 'finding-records' not in parsed.ids
    assert b'This does not imply PASS.' in pages['findings.html']
    assert not any(h.startswith('coverage.html#') for h in parsed.links)
