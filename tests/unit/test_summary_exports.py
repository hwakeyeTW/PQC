"""Anonymous real Store publications; never dispatch a target or publish a Portal."""
import copy
import csv
from html.parser import HTMLParser
import io
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools import assessment, evidence as ev, export_summary as ex, import_reports
from tools import portal_indexes, render_portal, run_store as rs

START = '2026-01-01T12:00:00Z'
OBS = '2026-01-01T12:01:00Z'
END = '2026-01-01T12:05:00Z'
RID = 'summary-fixture'
RULES_RAW = (ROOT / 'config/assessment_rules.yml').read_bytes()
RULES = assessment.load_rules(RULES_RAW)
LIMITS = dict(max_hosts=10, forks=2, serial=2, ssh_timeout_s=15, command_timeout_s=30)
SENTINEL = 'DUMMY_PRIVATE_DEBUG_/fixture/path'
MALICIOUS = '<img src=x onerror=alert(1)>'


def source(producer):
    return dict(source_kind='SYNTHETIC', producer_id=producer, producer_version='1.0.0',
                origin_ref='fixture', input_sha256=None)


def scope(store, requested, *, native=False, requirements=None):
    targets = [f'fixture-{i}.example.invalid' for i in range(len(requested))]
    hosts = [dict(target_id=t, identity_key=t, inventory_authority_id=None) for t in targets]
    flags = {t: {k: k in request for k in rs.COLLECTORS} for t, request in zip(targets, requested)}
    if native:
        flags = {t: {long: f[short] for long, short in rs.NATIVE_COLLECTORS.items()} for t, f in flags.items()}
    return store.begin(run_id=RID, run_kind='SYNTHETIC', evidence_schema_version='1.1.0',
                       source=source('fixture'), recorded_at=END, started_at=START,
                       expected_hosts=hosts, limits=LIMITS, profile='baseline', requested_flags=flags,
                       requirements=requirements, batch_contract=rs.NATIVE_BATCH_CONTRACT if native else rs.S1_BATCH_CONTRACT)


def collection(doc, h, collector, key, state, reason, observations=()):
    hid = h['host_id']; cid = ev.collection_id(RID, hid, collector, key)
    c = dict(collection_id=cid, host_id=hid, collector_id=collector, collector_version='1.0.0',
             scope_key=key, collection_state=state, reason_code=reason, source=source(collector),
             observed_at=OBS if state in rs.GOOD else None, evidence_ids=[])
    doc['collections'].append(c)
    for i, (kind, data, algo, asset) in enumerate(observations):
        aid = None
        if asset is not None:
            asset_kind, asset_key = asset
            aid = ev.asset_id(hid, asset_kind, asset_key, run_id=RID)
            a = next((a for a in doc['assets'] if a['asset_id'] == aid), None)
            if a is None:
                a = dict(asset_id=aid, host_id=hid, asset_kind=asset_kind, identity_key=asset_key,
                         identity_scope='RUN_SCOPED', evidence_ids=[])
                doc['assets'].append(a)
        obs = f'obs-{i}'; eid = ev.evidence_id(RID, hid, cid, obs)
        c['evidence_ids'].append(eid)
        if aid is not None:
            a['evidence_ids'].append(eid)
        doc['evidence'].append(dict(evidence_id=eid, host_id=hid, collection_id=cid,
            asset_id=aid, observation_key=obs, evidence_kind=kind, source=source(collector),
            observed_at=OBS, data=data, algorithm=algo))
    return cid


def package(present):
    return ('PACKAGE_INVENTORY', dict(name='fixture-lib', version='1.0', present=present),
            None, ('library', 'fixture-lib'))


def rich_rows(doc, h, native):
    hid = h['host_id']; service = ('service', 'fixture-service')
    aid = ev.asset_id(hid, *service, run_id=RID)
    kem = assessment.classify_algorithm('ML-KEM-768', 'KEM_CAPABILITY', RULES)
    ssh = assessment.classify_algorithm('mlkem768x25519-sha256', 'SSH_KEX', RULES)
    unknown = assessment.classify_algorithm(MALICIOUS, 'KEM_CAPABILITY', RULES)
    collection(doc, h, 'packages', 'packages', 'COLLECTED', 'COLLECTED', [package(False)])
    collection(doc, h, 'openssl', 'openssl', 'PARTIAL', 'INCOMPLETE_COLLECTION', [
        ('RUNTIME_CAPABILITY', dict(capability='kem', supported=True), kem, ('library', 'fixture-lib')),
        ('RUNTIME_CAPABILITY', dict(capability='kem', supported=False), kem, ('library', 'fixture-lib')),
        ('RUNTIME_CAPABILITY', dict(capability='kem', supported=None), unknown, ('library', 'fixture-lib'))])
    neg = dict(host_id=hid, service_asset_id=aid, endpoint_ref='fixture-endpoint', protocol='SSH',
               context_ref='fixture-context', authorization_ref='fixture-authorization')
    use = dict(host_id=hid, service_asset_id=aid, business_source_ref='fixture-audit',
               method='SERVICE_AUDIT_RECORD', started_at=START, finished_at=OBS)
    collection(doc, h, 'sshd', 'sshd', 'COLLECTED', 'COLLECTED', [
        ('EFFECTIVE_CONFIGURATION', dict(setting='kex', effective_value=SENTINEL, allowed=False), ssh, service),
        ('AUTHORIZED_NEGOTIATION', dict(conditions=neg, outcome='NEGOTIATED'), ssh, service),
        ('OBSERVED_USAGE', dict(conditions=use, outcome='CONTRADICTED'), ssh, service)])
    if not native:
        collection(doc, h, 'openssl', 'openssl-secondary', 'UNKNOWN', 'UNKNOWN_RESULT')
    collection(doc, h, 'system_certs', 'system_certs', 'NOT_APPLICABLE', 'NOT_APPLICABLE', [
        ('COLLECTION_SUMMARY', dict(scope='system_certs', attempted=False, coverage='UNKNOWN',
                                    observation_count=None, applicable=False), None, None)])


def terminal(s, doc, h, *, native=False):
    hid = h['host_id']; rows = []; attempted = h['host_state'] != 'NOT_ATTEMPTED'
    pairs = sorted(rs.NATIVE_COLLECTORS.items()) if native else [(x, x) for x in rs.COLLECTORS]
    for name, short in pairs:
        req = s['flags'][hid][short]
        cols = [c for c in doc['collections'] if c['host_id'] == hid and c['collector_id'] == short]
        states = {c['collection_state'] for c in cols}
        if not req:
            state, reason, rc = 'NOT_SCANNED', 'DISABLED', None
        elif not attempted:
            state, reason, rc = 'NOT_SCANNED', 'NOT_DISPATCHED', None
        elif h['host_state'] == 'UNREACHABLE':
            state, reason, rc = 'UNREACHABLE', 'CONNECTION_FAILED', None
        elif states == {'NOT_APPLICABLE'}:
            state, reason, rc = 'NOT_APPLICABLE', 'NOT_APPLICABLE', None
        elif states and states <= {'COLLECTED', 'NOT_APPLICABLE'}:
            state, reason, rc = 'COLLECTED', 'COLLECTED', 0
        elif states & rs.GOOD:
            state, reason, rc = 'PARTIAL', 'INCOMPLETE_COLLECTION', 0
        else:
            state, reason, rc = 'ERROR', 'COMMAND_FAILED', 1
        rows.append(dict(collector_id=name, requested=req, state=state, reason_code=reason, rc=rc,
                         collection_ids=sorted(c['collection_id'] for c in cols)))
    return dict(target_id=h['target_id'], attempted=attempted, host_state=h['host_state'],
                reason_code=h['reason_code'], collectors=rows)


def publish(root, *, native=False, assessed=True, empty=False):
    requested = [set()] if empty else [{'packages'}, {'packages', 'openssl', 'sshd', 'system_certs'},
                                        {'packages'}, {'packages'}, {'packages'}, set()]
    outcomes = [('NOT_ATTEMPTED', 'NO_EXECUTABLE_COLLECTORS')] if empty else [
        ('COMPLETE', 'COMPLETE'), ('PARTIAL', 'INCOMPLETE_COLLECTION'), ('ERROR', 'NO_VALID_RESULT'),
        ('UNREACHABLE', 'CONNECTION_FAILED'), ('NOT_ATTEMPTED', 'NOT_DISPATCHED'),
        ('NOT_ATTEMPTED', 'NO_EXECUTABLE_COLLECTORS')]
    with rs.RunStore(root) as store:
        with scope(store, requested, native=native) as w:
            s = w.scope; hosts = s['hosts']
            for h in hosts:
                h['host_state'], h['reason_code'] = outcomes[int(h['target_id'].split('-')[1].split('.')[0])]
            state, reason, rc = ('ERROR', 'NO_EXECUTABLE_COLLECTORS', 6) if empty else ('PARTIAL', 'INCOMPLETE_COLLECTION', 5)
            doc = rs._doc(s, hosts, state, finished_at=END, coverage_reason=reason)
            by_target = {h['target_id']: h for h in hosts}
            if not empty:
                h = by_target['fixture-0.example.invalid']
                collection(doc, h, 'packages', 'packages', 'COLLECTED', 'COLLECTED', [package(True), package(True)])
                rich_rows(doc, by_target['fixture-1.example.invalid'], native)
                collection(doc, by_target['fixture-2.example.invalid'], 'packages', 'packages', 'ERROR', 'COMMAND_FAILED')
            # Use canonical registry order, exactly as Store checkpoints do.
            doc = json.loads(ev.canonical_bytes(doc))
            terminals = []
            for h in sorted(doc['hosts'], key=lambda h: h['target_id']):
                row = terminal(s, doc, h, native=native); terminals.append(row)
                if row['attempted']:
                    w.dispatch_intent(h['host_id'])
                w.record_host(rs.host_fragment(doc, h['host_id']), attempted=row['attempted'], terminal=row)
            batch = dict(batch_manifest_version=1, target_ids=sorted(by_target), target_count=len(hosts),
                         limits=LIMITS, profile='baseline', run_state=state, reason_code=reason, hosts=terminals)
            saved = assessment.evaluate_document(doc, RULES) if assessed else None
            w.finalize(doc, batch_raw=rs._json_bytes(batch), batch_rc=rc,
                       assessed=saved, rules_raw=RULES_RAW if assessed else None)
        return store.open(RID)


@pytest.fixture
def root(tmp_path):
    p = tmp_path / 'reports'; p.mkdir(mode=0o700)
    return p


def metric(p, dimension, group, name, state):
    [row] = [r for r in p['metrics'] if (r['dimension'], r['group_id'], r['metric'], r['state']) ==
             (dimension, group, name, state)]
    return row['count'], row['denominator']


class Page(HTMLParser):
    def __init__(self, raw):
        super().__init__(convert_charrefs=True)
        self.ids, self.hrefs, self.tags, self.tables = set(), [], [], {}
        self.table = self.row = self.cell = None
        self.feed(raw.decode('utf-8'))

    def handle_starttag(self, tag, attrs):
        a = dict(attrs); self.tags.append(tag)
        if 'id' in a:
            assert a['id'] not in self.ids
            self.ids.add(a['id'])
        if 'href' in a:
            self.hrefs.append(a['href'])
        if tag == 'table':
            self.table = a.get('id')
            if self.table:
                self.tables[self.table] = []
        elif tag == 'tr' and self.table:
            self.row = []
        elif tag in ('td', 'th') and self.row is not None:
            self.cell = ''

    def handle_data(self, data):
        if self.cell is not None:
            self.cell += data

    def handle_endtag(self, tag):
        if tag in ('td', 'th') and self.cell is not None:
            self.row.append(self.cell.strip()); self.cell = None
        elif tag == 'tr' and self.row is not None:
            self.tables[self.table].append(self.row); self.row = None
        elif tag == 'table':
            self.table = None


def csv_rows(raw):
    assert raw.startswith(b'\xef\xbb\xbf"') and raw.endswith(b'\r\n')
    return list(csv.DictReader(io.StringIO(raw.decode('utf-8-sig'), newline='')))


def snapshot(root):
    return {str(p.relative_to(root)): (p.stat().st_mode, p.stat().st_mtime_ns,
            p.read_bytes() if p.is_file() else None) for p in root.rglob('*')}


@pytest.mark.parametrize('native', [False, True])
def test_actual_store_summary(native, root, monkeypatch):
    pub = publish(root, native=native)
    m, doc, assessed, _ = pub
    original = copy.deepcopy(pub); before = snapshot(root)
    # A second evaluation is forbidden after the trusted open result exists.
    def forbidden(*args, **kwargs):
        pytest.fail('projection must not reassess')
    monkeypatch.setattr(assessment, 'evaluate_document', forbidden)
    p, pages, exports = ex.render_summary_exports(pub)
    assert ex.render_summary_exports(pub) == (p, pages, exports)
    assert pub == original and snapshot(root) == before
    assert json.loads(exports['scan_summary.json']) == p
    assert exports['scan_summary.json'] == json.dumps(p, ensure_ascii=True, sort_keys=True,
            separators=(',', ':'), allow_nan=False).encode('ascii')
    assert set(pages) == {'findings.html', 'coverage.html'}
    assert set(exports) == {'scan_summary.json', 'summary.csv', 'algorithms.csv'}
    assert p['expected_host_ids'] == m['expected_host_ids']
    for state in ev.HOST_STATES:
        assert metric(p, 'host', 'all', 'host_state', state) == (
            len({h['host_id'] for h in doc['hosts'] if h['host_state'] == state}), 6)
    assert metric(p, 'host', 'all', 'completed_attempts', 'COMPLETE') == (1, 6)
    req = sum(sum(f.values()) for f in m['flags'].values())
    assert metric(p, 'collector_request', 'all', 'request', 'REQUESTED') == (req, 48)
    assert metric(p, 'collector_request', 'all', 'request', 'DISABLED') == (48-req, 48)
    assert metric(p, 'collector_request', 'all', 'requested_attempt', 'NOT_ATTEMPTED') == (2, req)
    assert len(p['collector_rows']) == 48
    for registry, key in [('collections', 'collection_id'), ('assets', 'asset_id'), ('evidence', 'evidence_id')]:
        assert set(p[registry]) == {r[key] for r in doc[registry]}
    assert len(p['assets']) == 3 and len(doc['evidence']) > len(p['assets'])
    groups = [('recorded', 'all', doc['collections'], doc['evidence'])]
    groups += [('host', h['host_id'], [c for c in doc['collections'] if c['host_id'] == h['host_id']],
                [r for r in doc['evidence'] if r['host_id'] == h['host_id']]) for h in doc['hosts']]
    for collector in {c['collector_id'] for c in doc['collections']}:
        cols = [c for c in doc['collections'] if c['collector_id'] == collector]
        groups.append(('collector_recorded', collector, cols,
                       [r for r in doc['evidence'] if r['collection_id'] in {c['collection_id'] for c in cols}]))
    for dimension, group, cols, rows in groups:
        for state in ev.ACQUISITIONS:
            assert metric(p, dimension, group, 'acquisition', state) == (
                len({c['collection_id'] for c in cols if c['collection_state'] == state}), len(cols))
        assert metric(p, dimension, group, 'evidence', 'RECORDED') == (len({r['evidence_id'] for r in rows}), None)
        n = len({r['asset_id'] for r in rows if r['asset_id'] is not None})
        assert metric(p, dimension, group, 'known_assets', 'RECORDED') == (n, n)
    for a in doc['assets']:
        refs = [r for r in doc['evidence'] if r['asset_id'] == a['asset_id']]
        assert set(p['assets'][a['asset_id']]['evidence_ids']) == {r['evidence_id'] for r in refs}
        assert set(p['assets'][a['asset_id']]['collection_ids']) == {r['collection_id'] for r in refs}
    assert set(p['claims']) == {c['claim_id'] for c in assessed['claims']}
    assert set(p['findings']) == {f['finding_id'] for f in assessed['findings']}
    assert {'PASS', 'FAIL', 'PARTIAL', 'UNKNOWN'} <= {c['assessment_state'] for c in assessed['claims']}
    for level in ev.LEVELS:
        claims = [c for c in assessed['claims'] if c['level'] == level]
        for state in ev.ASSESSMENTS:
            assert metric(p, 'recorded', 'all', level, state) == (
                len({c['claim_id'] for c in claims if c['assessment_state'] == state}), len(claims))
    for f in assessed['findings']:
        assert set(p['findings'][f['finding_id']]['claim_ids']) == set(f['claim_ids'])
        assert set(p['findings'][f['finding_id']]['evidence_ids']) == set(f['evidence_ids'])
    old = portal_indexes.project_crypto_indexes(pub)['algorithms']
    assert set(p['unresolved_algorithm_claim_ids']) == set(old['unresolved_claim_ids'])
    assert {g['id'] for g in p['algorithms']} == {g['id'] for g in old['groups']}
    for g in old['groups']:
        actual = next(x for x in p['algorithms'] if x['id'] == g['id'])
        for key in ('host_ids', 'asset_ids', 'evidence_ids', 'claim_ids', 'observed_names'):
            assert set(actual[key]) == set(g[key])
        rows = [r for r in p['algorithm_rows'] if r['algorithm_group_id'] == g['id']]
        for key in ('host_ids', 'asset_ids', 'evidence_ids', 'claim_ids'):
            assert [r['count'] for r in rows if r['metric'] == key] == [len(set(g[key]))]
        assert sum(r['count'] for r in rows if r['metric'] == 'source_context') == len(set(g['evidence_ids']))
        for level in ev.LEVELS:
            for key in ('claims', 'observations'):
                assert {s: set(ids) for s, ids in actual['levels'][level][key].items()} == {
                    s: set(ids) for s, ids in g['levels'][level][key].items()}
                expected = {state: len(set(ids)) for state, ids in g['levels'][level][key].items()}
                if not expected:
                    expected = {'NONE_RECORDED': 0}
                selected = [r for r in rows if r['metric'] == key[:-1] and r.get('level') == level]
                assert {r['state']: r['count'] for r in selected} == expected
                assert all(r['denominator'] == sum(expected.values()) for r in selected)
    coverage = Page(pages['coverage.html']); findings = Page(pages['findings.html'])
    def val(v): return 'Unknown / not recorded' if v is None else str(v)
    assert coverage.tables['metrics'][1:] == [[val(r[k]) for k in ex._SUMMARY_COLUMNS[1:]] for r in p['metrics']]
    assert set(findings.ids) >= set(p['findings'])
    assert coverage.tables['algorithm-metrics'][1:] == [[
        r['algorithm_group_id'] or 'Unresolved',
        ' / '.join(val(r.get(k)) for k in ('algorithm_id', 'classification')),
        ' / '.join(val(r.get(k)) for k in ('family', 'primitive', 'taxonomy_version')),
        ' / '.join(val(r.get(k)) for k in ('metric', 'level', 'state')),
        val(r.get('observed_name')),
        ' / '.join(val(r.get(k)) for k in ('source_kind', 'producer_id', 'producer_version', 'collector_id')),
        val(r['count']), val(r['denominator'])] for r in p['algorithm_rows']]
    assert findings.tables['assessment-metrics'][1:] == [[val(r[k]) for k in ('metric', 'state', 'count', 'denominator')]
        for r in p['metrics'] if r['dimension'] == 'finding' or
        (r['dimension'] == 'recorded' and r['metric'] in ('assessed_claims', *ev.LEVELS))]
    for name, columns, rows in [('summary.csv', ex._SUMMARY_COLUMNS, p['metrics']),
                                 ('algorithms.csv', ex._ALGORITHM_COLUMNS, p['algorithm_rows'])]:
        parsed = csv_rows(exports[name]); assert len(parsed) == len(rows)
        assert list(parsed[0]) == list(columns)
        assert parsed == [{k: '' if r.get(k) is None else str(r[k]) for k in columns}
                          for r in [dict(run_id=RID, **r) for r in rows]]
    # Actual existing host and crypto index targets, not synthetic anchor sets.
    _, existing, _ = render_portal._render_v2(pub, (root/RID/'run_manifest.json').read_bytes(), render_portal._render_css())
    _, crypto_pages = portal_indexes.render_crypto_indexes(pub)
    all_pages = {k: Page(v) for k, v in {**existing, **crypto_pages, **pages}.items()}
    for name in pages:
        for href in all_pages[name].hrefs:
            if href in ('../../index.html', '../index.html', '../portal.css'):
                continue
            path, _, fragment = href.partition('#')
            assert (path or name) in all_pages
            assert not fragment or fragment in all_pages[path or name].ids
        assert 'img' not in all_pages[name].tags and 'script' not in all_pages[name].tags
    assert b'&lt;img' in pages['coverage.html']
    assert all(SENTINEL.encode() not in raw for raw in [*pages.values(), *exports.values()])


def test_actual_recovery(root):
    hid = ev.host_id(None, 'fixture-1.example.invalid', run_id=RID, identity_key='fixture-1.example.invalid')
    requirements = dict(assessment=True, cff=True, details=[dict(host_id=hid, slot='platform')])
    with rs.RunStore(root) as store:
        with scope(store, [{'packages'}]*3, requirements=requirements) as w:
            s = w.scope
            h = next(h for h in s['hosts'] if h['target_id'] == 'fixture-0.example.invalid')
            h.update(host_state='COMPLETE', reason_code='COMPLETE')
            doc = rs._doc(s, [h], 'COMPLETE', finished_at=END)
            collection(doc, h, 'packages', 'packages', 'COLLECTED', 'COLLECTED', [package(True)])
            doc = json.loads(ev.canonical_bytes(doc))
            w.dispatch_intent(h['host_id'])
            w.record_host(rs.host_fragment(doc, h['host_id']), attempted=True, terminal=terminal(s, doc, h))
            w.dispatch_intent(hid)
        store.recover(RID)
        pub = store.open(RID)
    p, pages, exports = ex.render_summary_exports(pub)
    assert p['run']['recovery'] and p['claims'] is p['findings'] is None
    assert metric(p, 'host', 'all', 'attempt_status', 'UNKNOWN') == (1, 3)
    assert metric(p, 'host', 'all', 'completed_attempts', 'COMPLETE') == (1, 3)
    assert metric(p, 'collector_request', 'all', 'terminal', 'MISSING') == (16, 24)
    assert metric(p, 'collector_request', 'all', 'requested_state', 'MISSING_TERMINAL') == (2, 3)
    assert metric(p, 'recorded', 'all', 'L1', 'PASS') == (None, None)
    assert p['missing_artifacts'] == pub.manifest['missing_artifacts']
    assert len(p['missing_artifacts']) == 5
    assert all(a['path'] not in Page(pages['coverage.html']).hrefs for a in p['missing_artifacts'])
    assert 'not-assessed' in Page(pages['findings.html']).ids
    assert any(r['metric'] == 'claim' and r['count'] is None for r in p['algorithm_rows']) or not p['algorithms']


def test_legacy_actual_i3(root, tmp_path):
    raw = json.loads((ROOT/'tests/fixtures/legacy_report.json').read_bytes())['legacy-fleet']
    path = tmp_path/'legacy.json'; path.write_text(json.dumps(raw)); path.chmod(0o600)
    prepared = import_reports._prepare(path, 'legacy-fleet', RID, '2026-01-02T12:00:00Z', 'fixture', '1.0.0')
    import_reports._publish(prepared, root)
    with rs.RunStore(root) as store:
        pub = store.open(RID)
    p, pages, _ = ex.render_summary_exports(pub)
    assert p['flags_known'] is False and p['collector_rows'] == []
    assert metric(p, 'host', 'all', 'attempt_status', 'NOT_APPLICABLE') == (2, 2)
    assert metric(p, 'collector_request', 'all', 'expected_slots', 'UNKNOWN') == (None, None)
    assert metric(p, 'collector_request', 'all', 'request', 'REQUESTED') == (None, None)
    assert metric(p, 'collector_request', 'all', 'requested_attempt', 'ATTEMPTED') == (None, None)
    assert metric(p, 'recorded', 'all', 'evidence', 'RECORDED')[0] == len(pub.document['evidence'])
    assert 'flags-unknown' in Page(pages['coverage.html']).ids


@pytest.mark.parametrize('assessed', [False, True])
def test_zero_evidence(root, assessed):
    pub = publish(root, empty=True, assessed=assessed)
    p, pages, _ = ex.render_summary_exports(pub)
    assert not p['assets'] and not p['collections'] and not p['evidence']
    assert metric(p, 'host', 'all', 'completed_attempts', 'COMPLETE') == (0, 1)
    assert metric(p, 'recorded', 'all', 'known_assets', 'RECORDED') == (0, 0)
    assert metric(p, 'recorded', 'all', 'L1', 'PASS') == ((0, 0) if assessed else (None, None))
    if assessed:
        assert p['claims'] == {} and p['findings']  # rules save a coverage gap even without evidence
        # Exercise the empty-saved-list presentation independently, not by
        # calling a fabricated publication a verified Store result.
        from jinja2 import Environment, FileSystemLoader, StrictUndefined
        view = {**p, 'findings': {}}
        raw = Environment(loader=FileSystemLoader(str(ex._TEMPLATES)), autoescape=True,
                          undefined=StrictUndefined).get_template('findings.html.j2').render(p=view)
        assert 'empty-findings' in Page(raw.encode()).ids
    else:
        assert p['findings'] is None and 'not-assessed' in Page(pages['findings.html']).ids


@pytest.mark.parametrize('value, expected', [
    ('=1+1', "'=1+1"), ('+1', "'+1"), ('-1', "'-1"), ('@SUM(1)', "'@SUM(1)"),
    ('  =1', "'  =1"), ('\u3000+1', "'\u3000+1"), ('\ufeff-1', "'\\ufeff-1"),
    ('\u200b@x', "'\\u200b@x"), ('\x01=1', "'\\u0001=1"), ('\tword', "'\\u0009word"),
    ('\rword', "'\\u000dword"), ('\nword', "'\\u000aword"),
    ('\uff1d1', "'\uff1d1"), ('\uff0b1', "'\uff0b1"), ('\uff0d1', "'\uff0d1"), ('\uff201', "'\uff201"),
    ('\u6e2c\u8a66,"quoted"\nnext', '\u6e2c\u8a66,"quoted"\\u000anext'), ('normal', 'normal'),
])
def test_csv_roundtrip(value, expected):
    raw = ex._csv_bytes(RID, ex._SUMMARY_COLUMNS, [dict(group_id=value, count=5, denominator=None)])
    [row] = csv_rows(raw)
    assert row['group_id'] == expected and row['count'] == '5' and row['denominator'] == ''
    assert b'\x00' not in raw and raw.count(b'\r\n') == 2
    assert list(row) == list(ex._SUMMARY_COLUMNS)


@pytest.mark.parametrize('value', [True, -1, 1.0, '1', 2**53])
def test_invalid_numeric(value):
    with pytest.raises(rs.StoreError):
        ex._csv_number(value)


@pytest.mark.parametrize('cap', ['_MAX_MEMBERSHIPS', '_MAX_JSON', '_MAX_HTML', '_MAX_CSV', '_MAX_CSV_TOTAL'])
def test_limits_fail_closed(root, monkeypatch, cap):
    pub = publish(root, empty=True, assessed=False); before = snapshot(root); original = copy.deepcopy(pub)
    monkeypatch.setattr(ex, cap, 8)
    with pytest.raises(rs.StoreError, match='SUMMARY_SIZE_LIMIT'):
        ex.render_summary_exports(pub)
    assert snapshot(root) == before and pub == original


def test_wrong_publication_type():
    with pytest.raises(rs.StoreError, match='INVALID_SUMMARY_PUBLICATION'):
        ex.project_scan_summary({})
