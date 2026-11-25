"""Offline Portal: real private Run Store publications, not a mocked reader."""
from collections import Counter
from copy import deepcopy
import hashlib
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit

import pytest
from jinja2 import Environment, FileSystemLoader, StrictUndefined

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools import assessment, evidence as e, render_portal as portal, run_store as rs

RID = 'fixture-portal'
STAMP = '2026-01-03T00:00:00Z'
END = '2026-01-03T00:01:00Z'
LIMITS = {'max_hosts': 10, 'forks': 2, 'serial': 2, 'ssh_timeout_s': 15, 'command_timeout_s': 30}
RULES = (ROOT / 'config/assessment_rules.yml').read_bytes()


def raw(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


@pytest.fixture
def root():
    with tempfile.TemporaryDirectory(prefix='pqc-portal-', dir='/tmp') as directory:
        p = Path(directory) / 'reports'
        p.mkdir(mode=0o700)
        yield p


def options(states, *, native=False, legacy=False, negotiate=False, required=False):
    targets = [f'fixture-{i}.example.invalid' for i in range(len(states))]
    kind = 'LEGACY_IMPORT' if legacy else 'SYNTHETIC'
    source = {'source_kind': rs.KINDS[kind], 'producer_id': 'fixture-runner',
              'producer_version': '1.0.0', 'origin_ref': 'fixture-source', 'input_sha256': None}
    selected = {'openssl', 'sshd'} if negotiate else {'openssl'}
    flags = {t: {k: k in selected for k in rs.COLLECTORS} for t in targets}
    result = dict(run_id=RID, run_kind=kind, evidence_schema_version='1.1.0' if native else '1.0.0',
                  source=source, recorded_at=END, started_at=STAMP, limits=LIMITS,
                  profile='baseline', expected_hosts=[{'target_id': t, 'identity_key': t,
                   'inventory_authority_id': None} for t in targets], requested_flags=flags,
                  requirements={'assessment': required, 'cff': required, 'details': []})
    if native:
        result['batch_contract'] = rs.NATIVE_BATCH_CONTRACT
        result['requested_flags'] = {t: {k: v[s] for k, s in rs.NATIVE_COLLECTORS.items()}
                                     for t, v in flags.items()}
    if legacy:
        original = raw({'fixture': 'legacy-original', 'selected': targets})
        source.update(producer_id='legacy-ol-run-summary', producer_version=None,
                      input_sha256=hashlib.sha256(original).hexdigest())
        result.update(started_at=None, limits=None, profile=None, requested_flags=None,
                      legacy_raw=original, legacy_provenance={'format_version': rs.VERSION,
                      'source': source, 'original_run_id': 'old-fixture', 'original_generated_at': STAMP,
                      'diagnostics': [{'reason_code': 'LEGACY_REPORT_MISSING', 'count': 1}]})
    return result


def observation(doc, host, collector, state, kind, data, algorithm=None, asset_kind=None):
    rid, hid = doc['run']['run_id'], host['host_id']
    source = deepcopy(doc['run']['source'])
    legacy = source['source_kind'] == 'LEGACY_IMPORT'
    if not legacy:
        source['producer_id'] = collector
    stamp = None if legacy else STAMP
    cid = e.collection_id(rid, hid, collector, collector)
    reason = {'COLLECTED': 'COLLECTED', 'PARTIAL': 'INCOMPLETE_COLLECTION', 'ERROR': 'COMMAND_FAILED',
              'UNREACHABLE': 'CONNECTION_FAILED', 'UNKNOWN': 'NO_EVIDENCE',
              'NOT_SCANNED': 'NOT_ATTEMPTED', 'NOT_APPLICABLE': 'SCOPE_NOT_APPLICABLE',
              'PERMISSION_DENIED': 'PERMISSION_DENIED'}[state]
    collection = {'collection_id': cid, 'host_id': hid, 'collector_id': collector,
                  'collector_version': source['producer_version'], 'scope_key': collector,
                  'collection_state': state, 'reason_code': reason, 'source': source,
                  'observed_at': stamp, 'evidence_ids': []}
    doc['collections'].append(collection)
    if kind is None:
        return
    key = collector + '-fixture'
    eid = e.evidence_id(rid, hid, cid, key)
    aid = None
    if asset_kind:
        aid = e.asset_id(hid, asset_kind, key, run_id=rid)
        doc['assets'].append({'asset_id': aid, 'host_id': hid, 'asset_kind': asset_kind,
                              'identity_scope': 'RUN_SCOPED', 'identity_key': key, 'evidence_ids': [eid]})
    if kind == 'AUTHORIZED_NEGOTIATION':
        data = {'conditions': {'host_id': hid, 'service_asset_id': aid, 'endpoint_ref': 'fixture-endpoint',
                               'protocol': 'SSH', 'context_ref': 'fixture-context',
                               'authorization_ref': 'fixture-authorization'}, 'outcome': data}
    doc['evidence'].append({'evidence_id': eid, 'host_id': hid, 'collection_id': cid, 'asset_id': aid,
                            'observation_key': key, 'evidence_kind': kind, 'source': source,
                            'observed_at': stamp, 'data': data, 'algorithm': algorithm})
    collection['evidence_ids'].append(eid)


def publish(root, states=('COMPLETE',), *, native=False, legacy=False, negotiate=False, assessed=False,
            details=False, required=False, cff=False, unknown_runtime=False):
    args = options(states, native=native, legacy=legacy, negotiate=negotiate, required=required)
    targets = [x['target_id'] for x in args['expected_hosts']]
    with rs.RunStore(root) as store, store.begin(**args) as writer:
        scope = writer.scope
        hosts = scope['hosts']
        reason = {'COMPLETE': 'COMPLETE', 'PARTIAL': 'INCOMPLETE_COLLECTION',
                  'ERROR': 'NO_VALID_RESULT', 'UNREACHABLE': 'CONNECTION_FAILED',
                  'NOT_ATTEMPTED': 'NOT_DISPATCHED'}
        for h in hosts:
            state = states[targets.index(h['target_id'])]
            h.update(host_state=state, reason_code=reason[state])
        run_state = 'COMPLETE' if all(s == 'COMPLETE' for s in states) else (
            'PARTIAL' if any(s in ('COMPLETE', 'PARTIAL') for s in states) else 'ERROR')
        run_reason = {'COMPLETE': 'COMPLETE', 'PARTIAL': 'INCOMPLETE_COLLECTION', 'ERROR': 'NO_VALID_RESULT'}[run_state]
        doc = rs._doc(scope, hosts, run_state, finished_at=None if legacy else END, coverage_reason=run_reason)
        for h in hosts:
            s = h['host_state']
            if s == 'NOT_ATTEMPTED' or (native and s == 'UNREACHABLE'):
                continue
            cstate = {'COMPLETE': 'COLLECTED', 'PARTIAL': 'PARTIAL', 'ERROR': 'ERROR',
                      'UNREACHABLE': 'UNREACHABLE'}[s]
            kind = 'RUNTIME_CAPABILITY' if s in ('COMPLETE', 'PARTIAL') else None
            alg = {'algorithm_id': 'ml-kem-768', 'family': 'PQC', 'primitive': 'KEM',
                   'observed_name': 'ML-KEM-768', 'taxonomy_version': '1.0.0'}
            if legacy:
                # A preserved legacy package observation is not L2 support.
                kind, alg = 'PACKAGE_INVENTORY', None
                data = {'name': 'fixture & package <1>', 'version': '1.0', 'present': True}
            else:
                data = {'capability': 'kem', 'supported': s == 'COMPLETE'}
            observation(doc, h, 'openssl', cstate, kind, data, alg)
            if unknown_runtime:
                # Same acquired scope, an additional observation with no
                # support fact. Keep it separate from the known positive.
                row = deepcopy(doc['evidence'][-1])
                row['observation_key'] = 'unknown-capability'
                row['evidence_id'] = e.evidence_id(RID, h['host_id'], row['collection_id'], row['observation_key'])
                row['algorithm'] = {'algorithm_id': None, 'family': 'UNKNOWN', 'primitive': 'UNKNOWN',
                                    'observed_name': 'fixture-unknown', 'taxonomy_version': None}
                row['data'] = {'capability': 'unknown-capability', 'supported': None}
                doc['collections'][-1]['evidence_ids'].append(row['evidence_id'])
                doc['evidence'].append(row)
            if legacy:
                observation(doc, h, 'sshd', 'UNKNOWN', None, None)
                observation(doc, h, 'crypto_policy', 'NOT_SCANNED', None, None)
            if negotiate:
                observation(doc, h, 'sshd', 'COLLECTED', 'AUTHORIZED_NEGOTIATION', 'REJECTED',
                            {'algorithm_id': 'ssh-mlkem768x25519-sha256', 'family': 'HYBRID',
                             'primitive': 'KEX', 'observed_name': 'mlkem768x25519-sha256',
                             'taxonomy_version': '1.0.0'}, 'service')
        doc = json.loads(e.canonical_bytes(doc))
        terminals = []
        for h in doc['hosts']:
            hid, attempted = h['host_id'], h['host_state'] != 'NOT_ATTEMPTED'
            fragment = rs.host_fragment(doc, hid)
            detail = []
            if details and fragment['evidence']:
                row = fragment['evidence'][0]
                c = next(c for c in fragment['collections'] if c['collection_id'] == row['collection_id'])
                detail = [{'format_version': rs.VERSION, 'format': 'S1_TYPED_FIXTURE', 'run_id': RID,
                           'host_id': hid, 'slot': 'platform', 'collection_ids': [c['collection_id']],
                           'asset_ids': [row['asset_id']] if row['asset_id'] else [],
                           'evidence_ids': [row['evidence_id']],
                           'records': [{'record_kind': 'DIAGNOSTIC', 'evidence_id': row['evidence_id'],
                                        'state': c['collection_state'], 'reason_code': c['reason_code'], 'rc': 0}]}]
            if legacy:
                writer.record_host(fragment)
                continue
            rows = []
            for key, requested in sorted(scope['flags'][hid].items()):
                c = next((c for c in fragment['collections'] if c['collector_id'] == key), None)
                state = c['collection_state'] if c else 'NOT_SCANNED'
                reason_code = c['reason_code'] if c else ('NOT_DISPATCHED' if requested else 'DISABLED')
                if native and h['host_state'] == 'UNREACHABLE' and requested:
                    state, reason_code = 'UNREACHABLE', 'CONNECTION_FAILED'
                rc = 0 if state in ('COLLECTED', 'PARTIAL') else 7 if state == 'ERROR' else None
                rows.append({'collector_id': 'pqc_collect_' + key if native else key, 'requested': requested,
                             'state': state, 'reason_code': reason_code, 'rc': rc,
                             'collection_ids': [c['collection_id']] if c else []})
            row = {'target_id': h['target_id'], 'host_state': h['host_state'], 'reason_code': h['reason_code'],
                   'attempted': attempted, 'collectors': rows}
            if attempted:
                writer.dispatch_intent(hid)
            writer.record_host(fragment, attempted=attempted, terminal=row, details=detail)
            terminals.append(row)
        batch = None if legacy else raw({'batch_manifest_version': 1, 'target_ids': sorted(targets),
                 'target_count': len(targets), 'limits': LIMITS, 'profile': 'baseline',
                 'run_state': run_state, 'reason_code': run_reason,
                 'hosts': sorted(terminals, key=lambda h: h['target_id'])})
        evaluated = assessment.evaluate_document(doc, assessment.load_rules(RULES)) if assessed else None
        writer.finalize(doc, batch_raw=batch, batch_rc=None if legacy else {'COMPLETE': 0, 'PARTIAL': 5, 'ERROR': 6}[run_state],
                        assessed=evaluated, rules_raw=RULES if assessed else None,
                        cff=synthetic_cff(evaluated) if cff else None)
    with rs.RunStore(root) as store:
        return store.open(RID)



def synthetic_cff(assessed):
    # The actual Store S1_CFF_PAIR fixture contract, not a CFF evaluator.
    sha = hashlib.sha256(e.canonical_bytes(assessed)).hexdigest()
    hosts = []
    for hid in assessed['run']['expected_host_ids']:
        findings = [f for f in assessed['findings'] if f['subject']['host_id'] == hid]
        mapped = [{'rule_id': f['finding_id'], 'status': {'PASS': 'pass', 'FAIL': 'fail',
                   'NOT_APPLICABLE': 'not_applicable'}.get(f['assessment_state'], 'not_checked')} for f in findings]
        counts = Counter(f['status'] for f in mapped)
        denom = counts['pass'] + counts['fail']
        hosts.append({'host_id': hid, 'cff': {'version': rs.VERSION, 'findings': mapped,
                     'summary': {**{k: counts[k] for k in ('pass', 'fail', 'error', 'not_applicable', 'not_checked')},
                                 'total': len(findings), 'denominator': denom, 'score_available': denom > 0}},
                      'companion': {'evidence_document_sha256': sha, 'score_semantics': 'FACT_STATUS_RATIO_NOT_READINESS',
                                    'findings': [{k: f[k] for k in ('finding_id', 'assessment_state', 'reason_code',
                                                  'claim_ids', 'evidence_ids')} for f in findings]}})
    return {'format': 'S1_CFF_PAIR', 'projection_version': rs.VERSION,
            'evidence_document_sha256': sha, 'per_host': hosts}


class Page(HTMLParser):
    def __init__(self, path):
        super().__init__(convert_charrefs=True)
        self.ids, self.links, self.tags = set(), [], []
        self.stack, self.text, self.tables = [], {}, {}
        self.table = self.row = self.cell = None
        self.feed(path.read_text(encoding='utf-8'))

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.tags.append((tag, attrs))
        ident = attrs.get('id')
        if ident:
            assert ident not in self.ids
            self.ids.add(ident)
            self.text[ident] = ''
        if tag not in ('meta', 'link', 'br', 'hr', 'img', 'input', 'area', 'source', 'wbr'):
            self.stack.append((tag, ident))
        if tag == 'table':
            self.table = ident
            self.tables[ident] = []
        elif tag == 'tr' and self.table is not None:
            self.row = []
            self.tables[self.table].append(self.row)
        elif tag in ('td', 'th') and self.row is not None:
            self.cell = ''
        if 'href' in attrs:
            self.links.append(attrs['href'])

    def handle_endtag(self, tag):
        if tag in ('td', 'th') and self.cell is not None:
            self.row.append(self.cell.strip())
            self.cell = None
        elif tag == 'tr':
            self.row = None
        elif tag == 'table':
            self.table = None
        if self.stack and self.stack[-1][0] == tag:
            self.stack.pop()

    def handle_data(self, data):
        if self.cell is not None:
            self.cell += data
        for _, ident in self.stack:
            if ident:
                self.text[ident] += data


def snapshot(root):
    return {str(p.relative_to(root)): (p.read_bytes(), stat.S_IMODE(p.stat().st_mode), p.stat().st_ino)
            for p in root.rglob('*') if p.is_file() and p.name not in ('index.html', 'portal.css')}


def check_page(root, published):
    before = snapshot(root)
    path = portal.render_run(root, RID)
    assert path == root / RID / 'index.html'
    page = Page(path)
    m = published.manifest
    assert page.text['run-state'] == m['run_state']
    assert int(page.text['expected-hosts']) == len(m['expected_host_ids'])
    for state in e.HOST_STATES:
        assert int(page.text['host-' + state]) == m['counts'][state]
    collections = published.document['collections']
    counts = Counter(c['collection_state'] for c in collections)
    assert int(page.text['collection-total']) == len(collections)
    for state in e.ACQUISITIONS:
        assert int(page.text['collection-' + state]) == counts[state]
    for row in m['hosts']:
        assert row['host_state'] in page.text[row['host_id']]
        assert row['reason_code'] in page.text[row['host_id']]
        assert row['attempt_status'] in page.text[row['host_id']]
    assert set(page.links) - {x for x in page.links if x.startswith('#')} == set(published.artifacts) | {'portal.css'}
    for href in page.links:
        u = urlsplit(href)
        assert not u.scheme and not u.netloc and not u.query
        if href.startswith('#'):
            assert href[1:] in page.ids
        else:
            assert not href.startswith('/') and '..' not in Path(href).parts
            assert (path.parent / href).is_file()
    assert not any(tag in {'script', 'iframe', 'object', 'embed', 'base', 'form'} or
                   any(k.startswith('on') or k in ('src', 'srcset', 'action', 'style') for k in attrs)
                   for tag, attrs in page.tags)
    css = (path.parent / 'portal.css').read_bytes()
    assert not re.search(rb'(?i)url\s*\(|@import|https?:|@font-face', css)
    assert snapshot(root) == before
    for p in (path, path.parent / 'portal.css'):
        assert stat.S_IMODE(p.stat().st_mode) == 0o600 and p.stat().st_nlink == 1
    with rs.RunStore(root) as store:
        assert store.open(RID) == published
    return page


def test_actual_assessed_runtime_negotiation_detail_and_relocation(root):
    published = publish(root, negotiate=True, assessed=True, details=True, cff=True, unknown_runtime=True)
    page = check_page(root, published)
    assert page.tables['runtime-observations'][1:] == [['PQC', 'KEM', '1', '0', '0', '1'],
                                                       ['UNKNOWN', 'UNKNOWN', '0', '0', '1', '1']]
    assert 'cff_projection.json' in page.links
    assert page.tables['algorithm-counts'][1:] == [['HYBRID', 'KEX', '1'], ['PQC', 'KEM', '1'],
                                                   ['UNKNOWN', 'UNKNOWN', '1']]
    assert page.tables['negotiation-observations'][1:] == [['HYBRID', 'KEX', '0', '1', '0', '0', '0', '1']]
    counts = Counter((c['level'], c['assessment_state']) for c in published.assessed['claims'])
    for level, row in zip(e.LEVELS, page.tables['claim-counts'][1:]):
        assert row[0].startswith(level + ' ')
        expected = [counts[level, s] for s in e.ASSESSMENTS]
        assert list(map(int, row[1:])) == expected + [sum(expected)]
    assert counts['L2', 'PASS'] == 1 and counts['L2', 'UNKNOWN'] == 1 and counts['L4', 'FAIL'] == 1
    for state in e.ASSESSMENTS:
        assert int(page.text['finding-' + state]) == sum(f['assessment_state'] == state for f in published.assessed['findings'])
    index = root / RID / 'index.html'; css = root / RID / 'portal.css'
    original = [(p.read_bytes(), p.stat().st_ino, p.stat().st_mtime_ns) for p in (index, css)]
    assert portal.render_run(root, RID) == index
    assert original == [(p.read_bytes(), p.stat().st_ino, p.stat().st_mtime_ns) for p in (index, css)]
    moved = root.parent / 'moved reports'
    shutil.copytree(root, moved)
    # Test-only fresh reconstruction from copied core artifacts. The product
    # never deletes or replaces an existing derived page.
    (moved / RID / 'index.html').unlink()
    (moved / RID / 'portal.css').unlink()
    assert portal.render_run(moved, RID).read_bytes() == original[0][0]
    assert (moved / RID / 'portal.css').read_bytes() == original[1][0]
    moved_page = Page(moved / RID / 'index.html')
    assert all((moved / RID / href).is_file() for href in moved_page.links if not href.startswith('#'))


@pytest.mark.parametrize('states', [('COMPLETE',), tuple(e.HOST_STATES), ('ERROR',)])
def test_actual_native_v1_states_and_missing_assessment(root, states):
    published = publish(root, states, native=True)
    page = check_page(root, published)
    assert published.manifest['batch_contract'] == rs.NATIVE_BATCH_CONTRACT
    assert 'not-assessed' in page.ids and 'negotiation-observations-empty' in page.ids
    assert 'collector-rows' in page.ids and 'claim-counts' not in page.ids


def test_actual_legacy_publication(root):
    published = publish(root, ('PARTIAL',), legacy=True)
    page = check_page(root, published)
    assert 'collector-rows' not in page.ids and 'not-assessed' in page.ids
    assert page.text['collection-UNKNOWN'] == '1' and page.text['collection-NOT_SCANNED'] == '1'
    assert 'runtime-observations-empty' in page.ids and 'negotiation-observations-empty' in page.ids
    assert 'legacy_provenance.json' in page.links and 'batch_manifest.json' not in page.links
    assert 'Not applicable' in page.text[published.manifest['hosts'][0]['host_id']]
    # The real legacy observation contains legal HTML metacharacters; the
    # dashboard does not dump arbitrary evidence text into an HTML page.
    assert published.document['evidence'][0]['data']['name'] == 'fixture & package <1>'
    assert 'fixture & package <1>' not in (root / RID / 'index.html').read_text()


def test_recovered_unknown_attempt_empty_scope_required_gaps(root):
    with rs.RunStore(root) as store:
        with store.begin(**options(('ERROR', 'NOT_ATTEMPTED'), native=True, required=True)) as writer:
            writer.dispatch_intent(writer.scope['hosts'][0]['host_id'])
        store.recover(RID)
        published = store.open(RID)
    page = check_page(root, published)
    assert published.manifest['recovery'] and page.text['collection-total'] == '0'
    unknown = next(h for h in published.manifest['hosts'] if h['attempt_status'] == 'UNKNOWN')
    assert 'Unknown / not recorded' in page.text[unknown['host_id']]
    assert 'missing-artifacts' in page.ids and 'not-assessed' in page.ids
    assert 'assessed_evidence.json' not in page.links and 'cff_projection.json' not in page.links
    assert 'BATCH_MANIFEST_UNAVAILABLE' in page.text['missing-artifacts']


def test_css_only_resume_and_preflight_collision(root, monkeypatch):
    published = publish(root)
    run = root / RID
    before = snapshot(root)
    original = rs._write
    def interrupted(fd, name, content, device, **kwargs):
        if name == 'index.html':
            raise rs.StoreError('FIXTURE_INTERRUPTION')
        return original(fd, name, content, device, **kwargs)
    monkeypatch.setattr(rs, '_write', interrupted)
    with pytest.raises(rs.StoreError, match='FIXTURE_INTERRUPTION'):
        portal.render_run(root, RID)
    assert (run / 'portal.css').is_file() and not (run / 'index.html').exists()
    monkeypatch.setattr(rs, '_write', original)
    css_inode = (run / 'portal.css').stat().st_ino
    check_page(root, published)
    assert (run / 'portal.css').stat().st_ino == css_inode and snapshot(root) == before
    (run / 'index.html').write_bytes(b'old historical page')
    with pytest.raises(rs.StoreError, match='PORTAL_OUTPUT_COLLISION'):
        portal.render_run(root, RID)
    assert (run / 'index.html').read_bytes() == b'old historical page'


@pytest.mark.parametrize('fault', ['index-collision', 'css-collision', 'symlink', 'hardlink', 'directory', 'mode'])
def test_output_rejected_without_other_write(root, fault):
    publish(root)
    run = root / RID
    other = root.parent / 'sentinel'; other.write_bytes(b'keep'); other.chmod(0o600)
    name = 'portal.css' if fault == 'css-collision' else 'index.html'
    dest = run / name
    if fault == 'symlink': dest.symlink_to(other)
    elif fault == 'hardlink': os.link(other, dest)
    elif fault == 'directory': dest.mkdir(mode=0o700)
    else:
        dest.write_bytes(b'different'); dest.chmod(0o644 if fault == 'mode' else 0o600)
    before = snapshot(root)
    with pytest.raises(rs.StoreError):
        portal.render_run(root, RID)
    assert not (run / ('index.html' if name == 'portal.css' else 'portal.css')).exists()
    assert other.read_bytes() == b'keep' and snapshot(root) == before


@pytest.mark.parametrize('fault', ['marker', 'journal', 'hash', 'root-link', 'run-link', 'traversal', 'unpublished'])
def test_invalid_publication_is_not_rendered(root, fault):
    if fault == 'unpublished':
        with rs.RunStore(root) as store, store.begin(**options(('ERROR',))):
            pass
    else:
        publish(root)
    run = root / RID; target, rid = root, RID
    if fault in ('marker', 'journal', 'hash'):
        p = run / {'marker': 'run_manifest.json', 'journal': 'journal.json', 'hash': 'evidence.json'}[fault]
        p.write_bytes(p.read_bytes() + b' ')
    elif fault == 'root-link':
        target = root.parent / 'link'; target.symlink_to(root, target_is_directory=True)
    elif fault == 'run-link':
        run.rename(root / 'original-run'); run.symlink_to(root / 'original-run', target_is_directory=True)
    elif fault == 'traversal': rid = '../' + RID
    before = snapshot(root)
    with pytest.raises(rs.StoreError): portal.render_run(target, rid)
    assert not (run / 'index.html').exists() and not (run / 'portal.css').exists()
    assert snapshot(root) == before


@pytest.mark.parametrize('fault', ['marker', 'core', 'journal', 'directory'])
def test_recheck_after_render_before_exclusive_write(root, monkeypatch, fault):
    publish(root)
    run = root / RID
    original = portal._render
    def changed(published):
        data = original(published)
        if fault == 'directory':
            run.rename(root / 'old'); shutil.copytree(root / 'old', run)
        else:
            p = run / {'marker': 'run_manifest.json', 'core': 'evidence.json', 'journal': 'journal.json'}[fault]
            p.write_bytes(p.read_bytes() + b' ')
        return data
    monkeypatch.setattr(portal, '_render', changed)
    with pytest.raises(rs.StoreError): portal.render_run(root, RID)
    assert not (run / 'index.html').exists() and not (run / 'portal.css').exists()


def test_pure_layout_escaping_and_bounded_output(root, monkeypatch):
    published = publish(root)
    v = portal._view(published)
    attack = '<script>alert("fixture")</script> &'
    v['hosts'][0]['target_id'] = attack
    v['run']['source'] = {**v['run']['source'], 'origin_ref': attack}
    env = Environment(loader=FileSystemLoader(str(portal._TEMPLATES)), autoescape=True, undefined=StrictUndefined)
    html = env.get_template('run_index.html.j2').render(v=v)
    assert attack not in html and '&lt;script&gt;' in html and '&amp;' in html
    monkeypatch.setattr(portal, '_MAX_HTML', 32)
    with pytest.raises(rs.StoreError, match='PORTAL_SIZE_LIMIT'): portal.render_run(root, RID)
    assert not (root / RID / 'index.html').exists() and not (root / RID / 'portal.css').exists()
    monkeypatch.setattr(portal, '_MAX_HTML', 16 * 1024 * 1024)
    monkeypatch.setattr(portal, '_MAX_CSS', 32)
    with pytest.raises(rs.StoreError, match='PORTAL_SIZE_LIMIT'): portal.render_run(root, RID)
    assert not (root / RID / 'index.html').exists() and not (root / RID / 'portal.css').exists()


def test_cli_actual_publication(root):
    published = publish(root)
    argv = [sys.executable, '-B', '-m', 'tools.render_portal', '--report-root', str(root), '--run-id']
    result = subprocess.run(argv + [RID], cwd=ROOT, capture_output=True, timeout=15)
    assert result.returncode == 0 and result.stdout.strip() == b'PORTAL_RENDERED'
    invalid = subprocess.run(argv + ['../invalid'], cwd=ROOT, capture_output=True, timeout=15)
    assert invalid.returncode != 0 and str(root).encode() not in invalid.stderr
    check_page(root, published)


def test_exclusive_lock_refusal(root):
    publish(root)
    before = snapshot(root)
    with rs.RunStore(root) as store, store._locked_run(RID, shared=True):
        with pytest.raises(rs.StoreError, match='RUN_BUSY'):
            portal.render_run(root, RID)
    assert not (root / RID / 'index.html').exists() and not (root / RID / 'portal.css').exists()
    assert snapshot(root) == before
