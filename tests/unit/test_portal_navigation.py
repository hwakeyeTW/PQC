"""Focused #20 regression: actual private publications and exact derived slots."""
from collections import Counter, defaultdict
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
from urllib.parse import urlsplit

import pytest
from jinja2 import Environment, FileSystemLoader, StrictUndefined

from test_portal_overview import (ROOT, RID, STAMP, END, LIMITS, RULES, Page, root, raw,
                                  options, observation, publish, snapshot, check_page,
                                  e, rs, assessment, portal)

GEN = 'portal-v2'
RECEIPT = 'portal_receipt.json'
CSS_SHA = 'f4d7737a3f86617d69542b477a2e4b3775ad113e75d34677a2dc01eb9e24089f'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def put(path, data):
    path.write_bytes(data)
    path.chmod(0o600)
    return path


def read(root):
    with rs.RunStore(root) as store:
        return store.open(RID)


def derived_snapshot(run):
    return {str(p.relative_to(run)): (p.read_bytes(), p.stat().st_ino, p.stat().st_mtime_ns,
                                      stat.S_IMODE(p.stat().st_mode))
            for p in (run / 'index.html', run / 'portal.css', *sorted((run / GEN).iterdir()))}


class NavigationPage(Page):
    def __init__(self, path):
        self.references = defaultdict(set)
        super().__init__(path)

    def handle_starttag(self, tag, attrs):
        super().handle_starttag(tag, attrs)
        href = dict(attrs).get('href')
        if href is not None:
            for _, ident in self.stack:
                if ident:
                    self.references[ident].add(href)


def check_navigation(root, pub):
    run = root / RID
    ids = pub.manifest['expected_host_ids']
    gen = run / GEN
    names = {'hosts.html', *(h + '.html' for h in ids)}
    assert {p.name for p in gen.iterdir()} == names | {RECEIPT}
    assert stat.S_IMODE(gen.stat().st_mode) == 0o700
    for path in [run / 'index.html', run / 'portal.css', *gen.iterdir()]:
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
        assert info.st_uid == os.geteuid() and info.st_nlink == 1
    receipt = json.loads((gen / RECEIPT).read_bytes())
    assert receipt == {'format': 2, 'run_id': RID, 'manifest_sha256': digest((run / 'run_manifest.json').read_bytes()),
                       'index_sha256': digest((run / 'index.html').read_bytes()), 'css_sha256': CSS_SHA,
                       'pages': [{'name': name, 'size': (gen / name).stat().st_size,
                                  'sha256': digest((gen / name).read_bytes())} for name in sorted(names)]}
    pages = {run / 'index.html': NavigationPage(run / 'index.html')}
    pages.update({gen / name: NavigationPage(gen / name) for name in names})
    allowed = set(pages) | {run / 'portal.css', *(run / p for p in pub.artifacts)}
    for path, page in pages.items():
        for link in page.links:
            u = urlsplit(link)
            assert not u.scheme and not u.netloc and not u.query and not u.path.startswith('/')
            assert '\\' not in link and '%' not in u.path
            dest = (path.parent / u.path).resolve() if u.path else path
            assert dest in allowed and dest.is_file()
            if u.fragment:
                assert dest in pages and u.fragment in pages[dest].ids
        assert not any(tag in {'script', 'iframe', 'object', 'embed', 'base', 'form'} or
                       any(k.startswith('on') or k in ('src', 'srcset', 'action', 'style') for k in attrs)
                       for tag, attrs in page.tags)
    hostlist = pages[gen / 'hosts.html']
    assert [attrs['id'] for tag, attrs in hostlist.tags if tag == 'tr' and 'id' in attrs] == ids
    assert set(x for x in hostlist.links if not x.startswith('#')) == {
        '../portal.css', '../index.html', *(h + '.html' for h in ids)}
    all_records = {}
    for key in ('collections', 'assets', 'evidence', 'claims', 'findings'):
        source = pub.assessed if key in ('claims', 'findings') else pub.document
        all_records[key] = [] if source is None else source[key]
    for i, row in enumerate(pub.manifest['hosts']):
        hid = ids[i]
        assert row['host_id'] == hid
        page = pages[gen / (hid + '.html')]
        assert page.text['host-state'] == row['host_state']
        assert row['reason_code'] in page.text[hid]
        assert row['attempt_status'] in hostlist.text[hid]
        assert {x for x in ids if x in page.ids} == {hid}
        assert [a['href'] for tag, a in page.tags if tag == 'a' and a.get('rel') == 'prev'] == (
            [ids[i-1] + '.html'] if i else [])
        assert [a['href'] for tag, a in page.tags if tag == 'a' and a.get('rel') == 'next'] == (
            [ids[i+1] + '.html'] if i+1 < len(ids) else [])
        expected_links = {'../portal.css', '../index.html', 'hosts.html',
                          '../index.html#' + hid, 'hosts.html#' + hid}
        if i: expected_links.add(ids[i-1] + '.html')
        if i+1 < len(ids): expected_links.add(ids[i+1] + '.html')
        expected_links.update('../' + x['path'] for x in pub.manifest['artifacts'] if x['host_id'] in (None, hid))
        assert set(x for x in page.links if not x.startswith('#')) == expected_links
        for key, records in all_records.items():
            id_key = e.REGISTRIES[key]
            own = [r for r in records if (r['subject']['host_id'] if key in ('claims','findings') else r['host_id']) == hid]
            assert {r[id_key] for r in records} & page.ids == {r[id_key] for r in own}
            for r in own:
                ident = r[id_key]
                refs = set(r.get('evidence_ids', [])) | set(r.get('claim_ids', []))
                if key == 'evidence' and r.get('asset_id'): refs.add(r['asset_id'])
                if r.get('collection_id') and key == 'evidence': refs.add(r['collection_id'])
                if r.get('subject', {}).get('asset_id'): refs.add(r['subject']['asset_id'])
                conditions = r.get('conditions') or r.get('data', {}).get('conditions')
                if conditions: refs.add(conditions['service_asset_id'])
                assert {href for href in page.references[ident] if href.startswith('#')} == {'#' + x for x in refs}
                for field in ('assessment_state', 'reason_code', 'collection_state', 'evidence_kind'):
                    if field in r: assert r[field] in page.text[ident]
        counts = Counter(c['collection_state'] for c in pub.document['collections'] if c['host_id'] == hid)
        assert all(int(page.text['scope-' + state]) == counts[state] for state in e.ACQUISITIONS)
    return pages


@pytest.mark.parametrize('kwargs,sha', [
    (dict(negotiate=True, assessed=True, details=True, cff=True, unknown_runtime=True),
     '5364efca812161dc7edf5b2fee955d45719fa5ce73e7ab85e48d90680379f4f5'),
    (dict(states=tuple(e.HOST_STATES), native=True), '9fe807d7a7f2b54a7c542aafd920da425ee387e6634e228feb5d6e10c5fc776c'),
    (dict(states=('PARTIAL',), legacy=True), '5b5fddcb86d0bb9b247c18f330a1436de498f0410f56796bd756e381b8bceb1c'),
], ids=('assessed-detail', 'native-five-states', 'legacy'))
def test_exact_v1_refresh_and_v2_noop(root, kwargs, sha):
    # Hashes captured from fixed #19 renderer/templates, with actual N Store.
    pub = publish(root, **kwargs)
    old, css = portal._render(pub)
    assert digest(old) == sha and digest(css) == CSS_SHA
    run = root / RID
    index = put(run / 'index.html', old)
    css_path = put(run / 'portal.css', css)
    old_inode, css_inode = index.stat().st_ino, css_path.stat().st_ino
    core = snapshot(root, pub)
    with pytest.raises(rs.StoreError, match='PORTAL_OUTPUT_COLLISION'):
        portal.render_run(root, RID)
    assert not (run / GEN).exists() and index.read_bytes() == old and index.stat().st_ino == old_inode
    assert portal.render_run(root, RID, refresh_portal=True) == index
    assert index.read_bytes() != old and index.stat().st_ino != old_inode
    assert css_path.stat().st_ino == css_inode and css_path.read_bytes() == css
    check_navigation(root, pub)
    v2 = derived_snapshot(run)
    for flag in (False, True):
        assert portal.render_run(root, RID, refresh_portal=flag) == index
        assert derived_snapshot(run) == v2
    assert snapshot(root, pub) == core and read(root) == pub


def test_typed_host_sections_and_moved_root(root):
    # Actual S1 terminal contract admits typed scopes without a live producer.
    args = options(('COMPLETE', 'COMPLETE'))
    args['evidence_schema_version'] = '1.1.0'
    targets = [x['target_id'] for x in args['expected_hosts']]
    args['requested_flags'][targets[0]] = {k: k not in ('nginx_certs', 'tls_services') for k in rs.COLLECTORS}
    args['requested_flags'][targets[1]] = {k: k == 'packages' for k in rs.COLLECTORS}
    with rs.RunStore(root) as store, store.begin(**args) as w:
        scope = w.scope
        hs = scope['hosts']
        for h in hs: h.update(host_state='COMPLETE', reason_code='COMPLETE')
        doc = rs._doc(scope, hs, 'COMPLETE', finished_at=END, coverage_reason='COMPLETE')
        first = next(h for h in hs if h['target_id'] == targets[0]); second = next(h for h in hs if h['target_id'] == targets[1])
        observation(doc, first, 'packages', 'COLLECTED', 'PLATFORM_INFO',
                    {'os_family': 'redhat', 'os_version': '9.8', 'distribution': 'oracle-linux', 'major': 9,
                     'minor': 8, 'patch': None, 'architecture': 'x86_64', 'platform_status': 'UNVERIFIED'})
        observation(doc, second, 'packages', 'COLLECTED', 'PACKAGE_INVENTORY',
                    {'name': 'second-host <fixture> & package', 'version': '1.0', 'present': True})
        observation(doc, first, 'openssl', 'COLLECTED', 'RUNTIME_CAPABILITY', {'capability':'kem', 'supported': True},
                    {'algorithm_id':'ml-kem-768', 'family':'PQC', 'primitive':'KEM', 'observed_name':'ML-KEM-768', 'taxonomy_version':'1.0.0'})
        observation(doc, first, 'crypto_policy', 'COLLECTED', 'EFFECTIVE_CONFIGURATION',
                    {'setting':'fips-enabled', 'effective_value':'enabled', 'allowed':None})
        observation(doc, first, 'sshd', 'COLLECTED', 'AUTHORIZED_NEGOTIATION', 'REJECTED',
                    {'algorithm_id':'ssh-mlkem768x25519-sha256', 'family':'HYBRID', 'primitive':'KEX',
                     'observed_name':'mlkem768x25519-sha256', 'taxonomy_version':'1.0.0'}, 'service')
        observation(doc, first, 'system_certs', 'COLLECTED', 'ASSET_METADATA',
                    {'name':'fixture-certificate <tag>', 'version':None}, asset_kind='certificate')
        observation(doc, first, 'ssh_host_keys', 'COLLECTED', 'ASSET_METADATA',
                    {'name':'fixture-public-key', 'version':None}, asset_kind='public-key')
        # Synthetic typed TLS evidence, not a V2.0 Active collector. Use a
        # separate S1 scope in the already permitted openssl collector.
        observation(doc, first, 'openssl', 'COLLECTED', 'AUTHORIZED_NEGOTIATION', 'NEGOTIATED',
                    {'algorithm_id':'tls-x25519-mlkem768', 'family':'HYBRID', 'primitive':'KEX',
                     'observed_name':'X25519MLKEM768', 'taxonomy_version':'1.0.0'}, 'service')
        c, r, a = doc['collections'][-1], doc['evidence'][-1], doc['assets'][-1]
        c['scope_key'] = 'fixture-tls-observation'
        c['collection_id'] = e.collection_id(RID, first['host_id'], 'openssl', c['scope_key'])
        r['collection_id'] = c['collection_id']
        r['evidence_id'] = e.evidence_id(RID, first['host_id'], c['collection_id'], r['observation_key'])
        c['evidence_ids'] = a['evidence_ids'] = [r['evidence_id']]
        r['data']['conditions']['protocol'] = 'TLS'
        doc = json.loads(e.canonical_bytes(doc))
        terminals = []
        for h in doc['hosts']:
            hid = h['host_id']; fragment = rs.host_fragment(doc, hid); rows=[]
            for key, requested in sorted(scope['flags'][hid].items()):
                ids = [c['collection_id'] for c in fragment['collections'] if c['collector_id'] == key]
                rows.append({'collector_id':key, 'requested':requested, 'state':'COLLECTED' if ids else 'NOT_SCANNED',
                             'reason_code':'COLLECTED' if ids else 'DISABLED', 'rc':0 if ids else None, 'collection_ids':ids})
            row = {k:h[k] for k in ('target_id','host_state','reason_code')} | {'attempted':True,'collectors':rows}
            w.dispatch_intent(hid); w.record_host(fragment, attempted=True, terminal=row); terminals.append(row)
        batch = {'batch_manifest_version':1,'target_ids':sorted(targets),'target_count':2,'limits':LIMITS,
                 'profile':'baseline','run_state':'COMPLETE','reason_code':'COMPLETE','hosts':sorted(terminals,key=lambda x:x['target_id'])}
        w.finalize(doc, batch_raw=raw(batch), batch_rc=0, assessed=assessment.evaluate_document(doc, assessment.load_rules(RULES)), rules_raw=RULES)
    pub = read(root); core = snapshot(root,pub)
    check_page(root,pub); pages = check_navigation(root,pub)
    page = pages[root/RID/GEN/(first['host_id']+'.html')]
    assert 'PLATFORM_INFO' in page.text['platform'] and 'RUNTIME_CAPABILITY' in page.text['runtime']
    assert 'fips-enabled' in page.text['policy'] and 'independent of PQC readiness' in page.text['policy']
    assert 'REJECTED' in page.text['ssh'] and 'NEGOTIATED' in page.text['tls']
    assert 'fixture-certificate <tag>' in page.text['certificates']
    assert 'second-host' not in page.text['platform']
    other = pages[root/RID/GEN/(second['host_id']+'.html')]
    assert 'second-host <fixture> & package' in other.text['platform']
    assert 'fixture-certificate' not in other.text['certificates'] and 'No observations recorded' in other.text['tls']
    assert '&lt;fixture&gt; &amp; package' in (root/RID/GEN/(second['host_id']+'.html')).read_text()
    moved = root.parent / 'moved reports \u6e2c\u8a66'
    shutil.copytree(root,moved)
    check_navigation(moved,pub)
    assert read(moved)==pub and snapshot(root,pub)==core and read(root)==pub


def test_actual_i3_import_to_portal(root):
    from tools import cff
    report = {'host':'fixture-legacy.example.invalid','collected_at':STAMP,
              'openssl_version':'OpenSSL 3.5.0','openssl_version_rc':0,
              'openssl_tls1_3_groups':'X25519MLKEM768','openssl_tls1_3_groups_rc':0}
    missing = 'missing.example.invalid'
    value = {'run_id':'fixture-old','generated_at':STAMP,'selected_hosts':[report['host'],missing],
             'successful_hosts':[report['host']],'hosts_without_report':[missing],
             'selected_count':2,'completed_count':1,'reports':[report]}
    source = put(root.parent/'legacy.json',raw(value)); original = source.read_bytes()
    result = subprocess.run([sys.executable,'-B','-m','tools.import_reports','--input',str(source),
        '--format','legacy-ol-run-summary','--run-id',RID,'--recorded-at',END,
        '--origin-ref','fixture-source','--source-version','0.9.1','--report-root',str(root)],
        cwd=ROOT,capture_output=True,timeout=30)
    assert result.returncode == 0 and not result.stderr, result.stderr
    pub = read(root); core = snapshot(root,pub)
    projection = json.loads(pub.artifacts['cff_projection.json'])
    cff.validate_projection(projection,pub.assessed,assessment.load_rules(RULES))
    assert all(h['attempt_status']=='NOT_APPLICABLE' and h['attempted'] is None for h in pub.manifest['hosts'])
    check_page(root,pub); pages = check_navigation(root,pub)
    for h in pub.manifest['hosts']:
        page = pages[root/RID/GEN/(h['host_id']+'.html')]
        assert '../cff_projection.json' in page.links and 'batch-wide' in page.text['artifacts']
        assert 'CBOM not available' in page.text['artifacts']
        assert not any(r['evidence_kind']=='AUTHORIZED_NEGOTIATION' for r in pub.document['evidence'])
        if h['target_id']==missing:
            assert h['reason_code']=='LEGACY_REPORT_MISSING' and page.text['host-state']=='ERROR'
        else:
            assert 'openssl-tls13-group' in page.text['runtime'] and 'L2 observation' in page.text['runtime']
            assert 'L4 observation' not in page.text['tls']
    assert snapshot(root,pub)==core and read(root)==pub and source.read_bytes()==original


def test_same_display_identity_empty_scopes_and_escaping(root):
    # Store disallows duplicate non-null targets. Two unidentified legacy
    # hosts can have the same display label but distinct valid scoped IDs.
    args=options(('ERROR','ERROR'),legacy=True)
    args['expected_hosts']=[{'target_id':None,'identity_key':'fixture-a','inventory_authority_id':None},
                            {'target_id':None,'identity_key':'fixture-b','inventory_authority_id':None}]
    with rs.RunStore(root) as store, store.begin(**args) as w:
        hs=w.scope['hosts']
        for h in hs:h.update(host_state='ERROR',reason_code='LEGACY_NO_EVIDENCE')
        doc=rs._doc(w.scope,hs,'ERROR',coverage_reason='LEGACY_NO_EVIDENCE')
        for h in hs:w.record_host(rs.host_fragment(doc,h['host_id']))
        w.finalize(doc)
    pub=read(root); check_page(root,pub); pages=check_navigation(root,pub)
    for hid in pub.manifest['expected_host_ids']:
        p=pages[root/RID/GEN/(hid+'.html')]
        assert 'Unknown / not recorded' in p.text[hid] and 'No observations recorded' in p.text['platform']
    v=portal._view(pub); hosts, views=portal._host_views(pub,v)
    # Layout-only adversarial text, not an assertion that invalid target IDs
    # are accepted by the Store.
    hostile='<img src="https://fixture.invalid/a"> &'
    for h in hosts+views:h['target_id']=hostile
    env=Environment(loader=FileSystemLoader(str(portal._TEMPLATES)),autoescape=True,undefined=StrictUndefined)
    for template,ctx in [('hosts.html.j2',{'hosts':hosts}),('host.html.j2',{'host':views[0]})]:
        html=env.get_template(template).render(v=v,nested=True,**ctx)
        assert hostile not in html and '&lt;img' in html and '&amp;' in html


@pytest.mark.parametrize('fault',['directory-link','directory-mode','page-link','page-hardlink','page-mode','page-directory',
                                  'page-content','extra','receipt-corrupt','receipt-missing-page','index-missing-receipt',
                                  'complete-page-tamper','complete-receipt-tamper','complete-missing-page'])
def test_generation_rejects_without_publishing(root,fault):
    pub=publish(root); run=root/RID; old,css=portal._render(pub)
    index,pages,receipt=portal._render_v2(pub,(run/'run_manifest.json').read_bytes(),css)
    gen=run/GEN; outside=root.parent/'outside';outside.mkdir(mode=0o700)
    sentinel=put(outside/'keep',b'fixture-keep')
    if fault.startswith('complete-'):
        portal.render_run(root,RID)
        if fault=='complete-page-tamper':put(gen/'hosts.html',b'changed')
        elif fault=='complete-receipt-tamper':put(gen/RECEIPT,receipt.replace(b'"format":2',b'"format":3'))
        else:(gen/'hosts.html').unlink()
    elif fault=='directory-link':gen.symlink_to(outside,target_is_directory=True)
    else:gen.mkdir(mode=0o755 if fault=='directory-mode' else 0o700)
    if fault=='page-link':(gen/'hosts.html').symlink_to(sentinel)
    elif fault=='page-hardlink':os.link(sentinel,gen/'hosts.html')
    elif fault=='page-mode':put(gen/'hosts.html',pages['hosts.html']).chmod(0o644)
    elif fault=='page-directory':(gen/'hosts.html').mkdir(mode=0o700)
    elif fault=='page-content':put(gen/'hosts.html',b'different')
    elif fault=='extra':put(gen/'unknown.html',b'extra')
    elif fault=='receipt-corrupt':
        for name,data in pages.items():put(gen/name,data)
        put(gen/RECEIPT,b'{}')
    elif fault=='receipt-missing-page':put(gen/RECEIPT,receipt)
    elif fault=='index-missing-receipt':
        put(run/'portal.css',css);put(run/'index.html',index)
        for name,data in pages.items():put(gen/name,data)
    before=snapshot(root); expected_index=(run/'index.html').read_bytes() if (run/'index.html').exists() else None
    with pytest.raises(rs.StoreError):portal.render_run(root,RID,refresh_portal=True)
    assert ((run/'index.html').read_bytes() if (run/'index.html').exists() else None)==expected_index
    assert snapshot(root)==before and sentinel.read_bytes()==b'fixture-keep' and read(root)==pub
    if fault!='index-missing-receipt' and not fault.startswith('complete-'):
        assert not (run/'portal.css').exists()


@pytest.mark.parametrize('fault',['unrelated','marker-only','bad-css','index-only','index-link','index-hardlink','index-mode'])
def test_refresh_is_only_exact_v1(root,fault):
    pub=publish(root); run=root/RID; old,css=portal._render(pub)
    sentinel=put(root.parent/'sentinel',old)
    if fault!='index-only':put(run/'portal.css',b'different' if fault=='bad-css' else css)
    if fault=='index-link':(run/'index.html').symlink_to(sentinel)
    elif fault=='index-hardlink':os.link(sentinel,run/'index.html')
    else:put(run/'index.html',b'unrelated' if fault=='unrelated' else b'<html>Run '+RID.encode()+b'</html>' if fault=='marker-only' else old)
    if fault=='index-mode':(run/'index.html').chmod(0o644)
    before=(run/'index.html').lstat(); core=snapshot(root,pub)
    with pytest.raises(rs.StoreError):portal.render_run(root,RID,refresh_portal=True)
    after=(run/'index.html').lstat()
    assert (before.st_ino,before.st_mode,before.st_size)==(after.st_ino,after.st_mode,after.st_size)
    assert not (run/GEN).exists() and snapshot(root,pub)==core and sentinel.read_bytes()==old


@pytest.mark.parametrize('boundary',['page','receipt','replace','durability'])
def test_refresh_failure_order_and_resume(root,monkeypatch,boundary):
    pub=publish(root); run=root/RID; old,css=portal._render(pub)
    put(run/'index.html',old);put(run/'portal.css',css);core=snapshot(root,pub)
    original_write,original_replace,original_sync=rs._write,os.replace,rs._sync
    observed=[]
    def write(fd,name,data,device,**kw):
        observed.append(name)
        if (boundary=='page' and name=='hosts.html') or (boundary=='receipt' and name==RECEIPT):
            raise rs.StoreError('FIXTURE_INTERRUPTION')
        assert (run/'index.html').read_bytes()==old
        return original_write(fd,name,data,device,**kw)
    def replace(src,dst,**kw):
        if dst=='index.html':
            assert (run/GEN/RECEIPT).is_file()
            if boundary=='replace':raise OSError('fixture-before-replace')
            original_replace(src,dst,**kw);observed.append('replace')
        else:return original_replace(src,dst,**kw)
    def sync(fd):
        if boundary=='durability' and observed and observed[-1]=='replace':
            raise rs.StoreError('DURABILITY_UNCONFIRMED')
        return original_sync(fd)
    with monkeypatch.context() as patch:
        patch.setattr(rs,'_write',write);patch.setattr(os,'replace',replace);patch.setattr(rs,'_sync',sync)
        with pytest.raises(rs.StoreError,match={'page':'FIXTURE_INTERRUPTION','receipt':'FIXTURE_INTERRUPTION',
                           'replace':'STORE_IO','durability':'DURABILITY_UNCONFIRMED'}[boundary]):
            portal.render_run(root,RID,refresh_portal=True)
    assert ((run/'index.html').read_bytes()!=old)==(boundary=='durability')
    assert not list(run.glob('.portal-index-*')) and snapshot(root,pub)==core and read(root)==pub
    existing={p.name:(p.read_bytes(),p.stat().st_ino) for p in (run/GEN).iterdir()}
    portal.render_run(root,RID,refresh_portal=True);check_navigation(root,pub)
    assert all((run/GEN/name).read_bytes()==data and (run/GEN/name).stat().st_ino==inode
               for name,(data,inode) in existing.items())
    assert snapshot(root,pub)==core and read(root)==pub


def test_total_bound_precedes_outputs(root,monkeypatch):
    pub=publish(root); run=root/RID; before=snapshot(root,pub)
    old,css=portal._render(pub);idx,pages,receipt=portal._render_v2(pub,(run/'run_manifest.json').read_bytes(),css)
    total=len(idx)+sum(map(len,pages.values()))
    monkeypatch.setattr(portal,'_MAX_TOTAL_HTML',total-1)
    with pytest.raises(rs.StoreError,match='PORTAL_SIZE_LIMIT'):portal.render_run(root,RID)
    assert not any((run/name).exists() for name in ('index.html','portal.css',GEN)) and snapshot(root,pub)==before
    monkeypatch.setattr(portal,'_MAX_TOTAL_HTML',total)
    portal.render_run(root,RID);check_navigation(root,pub)


def test_multiple_host_details_are_not_cross_linked(root):
    pub = publish(root, ('COMPLETE', 'PARTIAL'), details=True, assessed=True)
    check_page(root,pub); pages = check_navigation(root,pub)
    details = [x for x in pub.manifest['artifacts'] if x['kind']=='detail']
    assert len(details)==2 and len({x['host_id'] for x in details})==2
    for item in details:
        page=pages[root/RID/GEN/(item['host_id']+'.html')]
        assert [x for x in page.links if x.startswith('../details/')] == ['../'+item['path']]


@pytest.mark.parametrize('native',[True,False])
def test_recovery_host_attempt_and_required_gaps(root,native):
    args=options(('ERROR','NOT_ATTEMPTED'),native=native,required=True)
    if not native:
        first=args['expected_hosts'][0]['target_id']
        hid=e.host_id(None,first,run_id=RID,identity_key=first)
        args['requirements']['details']=[{'host_id':hid,'slot':'platform'}]
    with rs.RunStore(root) as store:
        with store.begin(**args) as w:
            selected=w.scope['hosts'][0]['host_id']
            w.dispatch_intent(selected)
        store.recover(RID); pub=store.open(RID)
    core=snapshot(root,pub);check_page(root,pub);pages=check_navigation(root,pub)
    assert pub.manifest['recovery']
    for h in pub.manifest['hosts']:
        page=pages[root/RID/GEN/(h['host_id']+'.html')]
        text=' '.join(page.text.values())
        assert h['attempt_status'] in text and 'No collections recorded' in text
        assert 'host-not-assessed' in page.ids and '../assessed_evidence.json' not in page.links
        assert 'BATCH_MANIFEST_UNAVAILABLE' in page.text['artifacts'] or 'batch_manifest.json' in page.text['artifacts']
        for missing in pub.manifest['missing_artifacts']:
            if missing['path'].startswith('details/'):
                assert (missing['path'] in page.text['artifacts']) == (('/'+h['host_id']+'/') in missing['path'])
    assert snapshot(root,pub)==core and read(root)==pub


def test_cli_explicit_refresh_only(root):
    pub=publish(root);run=root/RID;old,css=portal._render(pub)
    put(run/'index.html',old);put(run/'portal.css',css)
    args=[sys.executable,'-B','-m','tools.render_portal','--report-root',str(root),'--run-id',RID]
    for extra in ([],['--refresh-porta']):
        result=subprocess.run(args+extra,cwd=ROOT,capture_output=True,timeout=15)
        assert result.returncode!=0 and (run/'index.html').read_bytes()==old and not (run/GEN).exists()
    result=subprocess.run(args+['--refresh-portal'],cwd=ROOT,capture_output=True,timeout=15)
    assert result.returncode==0 and result.stdout.strip()==b'PORTAL_RENDERED'
    check_navigation(root,pub)
