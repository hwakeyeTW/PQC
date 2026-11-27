"""SEARCH-A: actual Store and generated HTML/Chromium controls, no publication.

Use installed browser tools only. Missing JS engine is a test failure, not a
skip. The engineering invocation supplies a private offline process guard.
"""
from collections import defaultdict
from copy import deepcopy
from hashlib import sha256
from html.parser import HTMLParser
import json
from pathlib import Path
import shutil
import sys
from urllib.parse import urlsplit

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / 'tests/unit'), str(ROOT / 'tests/integration')]
import test_portal_generation_c as original
import test_portal_crypto_index as crypto_fixture
from test_portal_asset_index import publish_assets
from tools import (portal_search as search, portal_generation_c as ca, portal_indexes as crypto,
                   portal_asset_indexes as assets, export_summary as summary, run_store as rs,
                   render_portal as portal, run_catalog as catalog, assessment, cbom_validation)

CAPS = dict(page_limit=16*2**20, html_limit=128*2**20, bundle_limit=512*2**20)
KINDS = ('c1-assessed', 'c1-unassessed', 'recovery', 'native-v1', 's1', 'legacy', 'zero', 'assets')
EVIL = 'ＭＬ-ＫＥＭ Ｆｉｘｔｕｒｅ </script><img src=x onerror=alert(1)> & "\''


def digest(raw): return sha256(raw).hexdigest()


class HTML(HTMLParser):
    def __init__(self, raw):
        super().__init__(); self.ids = set(); self.links = []; self.rows = defaultdict(list)
        self.category = None; self.tags = []; self.feed(raw.decode('utf-8'))

    def handle_starttag(self, tag, attrs):
        a = dict(attrs); self.tags.append((tag, a))
        if 'id' in a:
            assert a['id'] not in self.ids; self.ids.add(a['id'])
        if tag == 'section' and 'data-category' in a: self.category = a['data-category']
        if tag == 'tr' and 'data-result' in a: self.rows[self.category].append(a)
        if tag == 'a' and 'href' in a: self.links.append(a['href'])


def write(p, raw):
    p.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    p.write_bytes(raw); p.chmod(0o600)


def fixture(tmp_path, monkeypatch, kind, *, history=False):
    root = tmp_path / 'reports'; root.mkdir(mode=0o700)
    pub = (publish_assets(root, assessed=True, coverage_extra=True) if kind == 'assets'
           else original._cb2a_publication(root, tmp_path, kind))
    if history: catalog.build_catalog(root)
    before = original.c1._c2_tree(root); saved = deepcopy(pub)
    marker = (root / pub.manifest['run_id'] / 'run_manifest.json').read_bytes()
    seen = {}; validated = []
    def capture(name, actual, unpack=lambda x: x):
        def call(*args, **kwargs):
            result = actual(*args, **kwargs); seen[name] = unpack(result); return result
        return call
    validate = cbom_validation.validate_cbom_bytes
    def checked(raw):
        result = validate(raw); validated.append(digest(raw)); return result
    with monkeypatch.context() as m:
        m.setattr(assets, '_render_asset_indexes', capture('assets', assets._render_asset_indexes, lambda x: x[0]))
        m.setattr(crypto, 'project_crypto_indexes', capture('crypto', crypto.project_crypto_indexes))
        m.setattr(summary, '_project_scan_summary', capture('summary', summary._project_scan_summary))
        m.setattr(cbom_validation, 'validate_cbom_bytes', checked)
        index, css, pages, receipt = portal._render_v5(pub, marker)
    assert sorted(validated) == sorted(digest(raw) for name,raw in pages.items() if name.endswith('.cbom.json'))
    receipt_json = json.loads(receipt)
    assert receipt_json['format'] == 5 and receipt_json['manifest_sha256'] == digest(marker)
    assert receipt_json['index_sha256'] == digest(index) and receipt_json['css_sha256'] == digest(css)
    assert receipt_json['pages'] == [dict(name=k,size=len(v),sha256=digest(v)) for k,v in sorted(pages.items())]
    assert 'search.html' not in pages
    pp = tuple(seen[n] for n in ('crypto','assets','summary'))
    limits = dict(page_limit=CAPS['page_limit'],
                  html_limit=CAPS['html_limit']-len(index)-sum(len(v) for k,v in pages.items() if k.endswith('.html')),
                  bundle_limit=CAPS['bundle_limit']-len(index)-len(css)-len(receipt)-sum(map(len,pages.values())))
    projection_snapshot = deepcopy(pp); buffers = deepcopy((index,css,pages,receipt))
    def forbidden(*args, **kwargs): pytest.fail('SEARCH-A must not open, reassess or reproject')
    with monkeypatch.context() as m:
        for obj, name in [(rs.RunStore,'open'),(assessment,'evaluate_document'),(crypto,'project_crypto_indexes'),
                          (assets,'project_asset_indexes'),(summary,'_project_scan_summary'),(ca,'_assemble_v5_render_payload')]:
            m.setattr(obj,name,forbidden)
        raw = search._render_search_page(pub,*pp,**limits)
        assert raw == search._render_search_page(pub,*pp,**limits)
    assert pub == saved and pp == projection_snapshot and (index,css,pages,receipt) == buffers
    assert original.c1._c2_tree(root) == before
    return pub, pp, raw, root, (index,css,pages,receipt), limits


def expected(pub, pp):
    cp, ap, sp = pp
    result = {'hosts': set(pub.manifest['expected_host_ids'])}
    for n,p in [('algorithms',cp),('libraries',cp),('certificates',ap),('services',ap)]:
        result[n] = {g['id']+':'+hid for g in p[n]['groups'] for hid in g['host_ids']}
    result['findings'] = set() if pub.assessed is None else {f['finding_id'] for f in pub.assessed['findings']}
    result['coverage'] = ({r['host_id']+':'+r['collector_id'] for r in sp['collector_rows']} if sp['flags_known']
                          else {r['collection_id'] for r in pub.document['collections']})
    return result


def preview(tmp_path, data):
    pub, pp, raw, root, (index,css,pages,receipt), _ = data
    base = tmp_path / 'relocated' / 'run archive'; base.mkdir(mode=0o700, parents=True)
    run = base / pub.manifest['run_id']; nested = run / 'portal-v5'
    write(base/'index.html', (root/'index.html').read_bytes())
    for name, value in pub.artifacts.items(): write(run/name,value)
    write(run/'run_manifest.json',(root/pub.manifest['run_id']/'run_manifest.json').read_bytes())
    write(run/'index.html',index); write(run/'portal.css',css)
    for name,value in pages.items(): write(nested/name,value)
    write(nested/portal._RECEIPT,receipt); write(nested/'search.html',raw)
    path = nested/'search.html'; parsed = HTML(raw); anchors = {}
    for href in parsed.links:
        u = urlsplit(href); assert not (u.scheme or u.netloc or u.query or u.path.startswith('/'))
        target = (path.parent/u.path).resolve() if u.path else path
        assert target.is_relative_to(base) and target.is_file(), href
        if u.fragment:
            if target not in anchors: anchors[target] = HTML(target.read_bytes()).ids
            assert u.fragment in anchors[target], href
    return path


@pytest.mark.parametrize('kind', KINDS)
def test_search_actual_store_v5(kind,tmp_path,monkeypatch):
    data = fixture(tmp_path,monkeypatch,kind,history=True); pub,pp,raw,root,old,limits = data
    parsed = HTML(raw); counts = expected(pub,pp)
    for n in search._CATEGORIES:
        rows = parsed.rows[n]; assert {r['data-key'] for r in rows} == counts[n]
        assert [r['data-key'] for r in rows] == sorted(counts[n])
        assert len(rows) == len(counts[n]); assert all(r['data-host'] in pub.manifest['expected_host_ids'] for r in rows)
        for row in rows:
            for basis,level,state in json.loads(row['data-pairs']): assert basis in ('claim','observation') and level in ('L1','L2','L3','L4','L5')
    assert b'Inventory group: not recorded' in raw
    assert (b'id="not-assessed"' in raw) == (pub.assessed is None)
    assert (b'id="flags-unknown"' in raw) == (not pp[2]['flags_known'])
    assert len([1 for tag,a in parsed.tags if tag == 'script']) == 1
    assert all(not any(k.startswith('on') or k in ('src','srcset','action','formaction') for k in a) for tag,a in parsed.tags)
    assert all(tag not in ('iframe','object','embed','base','form','img') for tag,a in parsed.tags)
    preview(tmp_path,data)
    # Full unchanged original output, including real CBOM and receipt, not a
    # comparison with the search implementation or a replacement renderer.
    marker = (root/pub.manifest['run_id']/'run_manifest.json').read_bytes()
    assert portal._render_v5(pub,marker) == old
    print('ACTUAL',kind,'rows',[len(counts[n]) for n in search._CATEGORIES],'bytes',len(raw),'sha256',digest(raw),flush=True)


@pytest.fixture(scope='module')
def browser():
    from playwright.sync_api import sync_playwright
    exe = shutil.which('chromium') or shutil.which('chromium-browser')
    assert exe, 'Required installed offline Chromium unavailable'
    with sync_playwright() as pw:
        b = pw.chromium.launch(executable_path=exe, chromium_sandbox=True, headless=True,
            timeout=15000, args=['--disable-background-networking','--disable-component-update','--no-first-run'])
        print('BROWSER',b.version,'sandbox=True',flush=True)
        yield b
        b.close()


def open_page(browser,path,js=True):
    ctx = browser.new_context(offline=True, java_script_enabled=js); requests=[]; errors=[]
    ctx.on('request',lambda req: requests.append(req.url))
    ctx.route('**/*',lambda route: route.continue_() if urlsplit(route.request.url).scheme == 'file' else route.abort())
    page=ctx.new_page(); page.on('pageerror',lambda err:errors.append(str(err)))
    # Load the exact generated document. This engineering DOM lane does not
    # need file:// navigation permissions; actual file/anchor closure is checked
    # separately in preview(). Do not disable browser policy or sandbox.
    page.set_content(path.read_bytes().decode('utf-8'), wait_until='load')
    return ctx,page,requests,errors


def section(page,name): return page.locator('#search-'+name)
def control(s,name): return s.locator('[data-filter="'+name+'"]')
def visible(s): return s.locator('tr[data-result]:visible')
def keys(s): return visible(s).evaluate_all('(nodes)=>nodes.map(n=>n.dataset.key)')
def count(s,rows,hosts):
    assert visible(s).count() == rows
    assert s.locator('[data-matched]').inner_text() == str(rows)
    assert s.locator('[data-hosts]').inner_text() == str(hosts)


def test_search_browser_unicode_typed_sort_and_no_js(tmp_path,monkeypatch,browser):
    monkeypatch.setattr(crypto_fixture,'MALICIOUS',EVIL)
    populate=crypto_fixture.populate
    def os_fixture(doc,host,second):
        populate(doc,host,second)
        if not second:
            for version in ('9.9','9.10'):
                data=dict(os_family='redhat',os_version=version,distribution='oracle-linux',major=9,
                          minor=int(version.split('.')[1]),patch=None,architecture='x86_64',platform_status='UNVERIFIED')
                crypto_fixture.add_scope(doc,host,'packages','platform-'+version,[crypto_fixture.record('os','PLATFORM_INFO',data)])
    monkeypatch.setattr(crypto_fixture,'populate',os_fixture)
    data=fixture(tmp_path,monkeypatch,'s1',history=True); pub,pp,raw,*_=data; path=preview(tmp_path,data)
    ctx,p,requests,errors=open_page(browser,path)
    try:
        totals=expected(pub,pp)
        for name in search._CATEGORIES:
            s=section(p,name); count(s,len(totals[name]),len(set(visible(s).evaluate_all('(ns)=>ns.map(n=>n.dataset.host)'))))
            assert s.locator('[data-controls]').is_visible(); assert keys(s)==sorted(totals[name])
        h=section(p,'hosts'); control(h,'osversion').fill('CONFLICT'); count(h,1,1)
        h.locator('[data-reset]').click(); control(h,'osversion').fill('UNKNOWN'); count(h,1,1)
        h.locator('[data-reset]').click(); control(h,'sort').select_option('version'); control(h,'direction').select_option('desc')
        assert visible(h).evaluate_all('(ns)=>ns.map(n=>n.dataset.version)')==['CONFLICT','UNKNOWN'] or set(visible(h).evaluate_all('(ns)=>ns.map(n=>n.dataset.version)'))=={'CONFLICT','UNKNOWN'}
        alg=section(p,'algorithms'); control(alg,'query').fill('  ml-kem fixture  ')
        assert visible(alg).count()>0; assert 'onerror=alert(1)' in visible(alg).first.inner_text()
        assert p.locator('img').count()==0
        control(alg,'query').fill('no-such-record'); count(alg,0,0); assert alg.locator('[data-no-results]').is_visible()
        alg.locator('[data-reset]').click()
        groups=visible(alg).evaluate_all('(ns)=>ns.map(n=>[n.dataset.key,n.dataset.host,JSON.parse(n.dataset.pairs)])')
        # Pick actual saved group evidence with two distinct observed/claim levels.
        selected=None
        for key,hid,pairs in groups:
            for a in pairs:
                for b in pairs:
                    if a[0]==b[0] and a[1]!=b[1] and a[2]!=b[2] and [a[0],a[1],b[2]] not in pairs:
                        selected=(key,hid,a,b);break
                if selected: break
            if selected: break
        assert selected
        key,hid,a,b=selected;control(alg,'query').fill(key.split(':')[0]);control(alg,'host').select_option(hid)
        control(alg,'basis').select_option(a[0]);control(alg,'level').select_option(a[1]);control(alg,'typed-state').select_option(a[2]);count(alg,1,1)
        control(alg,'typed-state').select_option(b[2]);count(alg,0,0)
        alg.locator('[data-reset]').click();assert keys(alg)==sorted(totals['algorithms'])
        lib=section(p,'libraries'); control(lib,'query').fill('fixture-library'); assert visible(lib).count()==2; count(lib,2,2)
        lib.locator('[data-reset]').click(); control(lib,'sort').select_option('refs')
        for direction in ('asc','desc'):
            control(lib,'direction').select_option(direction)
            values=visible(lib).evaluate_all('(ns)=>ns.map(n=>[Number(n.dataset.refs),n.dataset.key])')
            assert values==sorted(values,key=lambda x:(x[0] if direction=='asc' else -x[0],x[1]))
        lib.locator('[data-reset]').click(); assert keys(lib)==sorted(totals['libraries'])
        print('DOM unicode literal / host AND typed pair / numeric sort / reset / count',len(requests),'requests',flush=True)
        assert not errors and all(urlsplit(u).scheme=='file' for u in requests)
        # Real DOM href and original target anchor (no claim of file://
        # navigation in this engineering DOM lane).
        href=p.locator('#search-hosts tbody a').first.get_attribute('href')
        u=urlsplit(href); assert u.fragment==pub.manifest['expected_host_ids'][0]
        p.set_content((path.parent/u.path).read_text(encoding='utf-8'))
        assert p.locator('[id="'+u.fragment+'"]').count()==1
    finally: ctx.close()
    ctx,p,requests,errors=open_page(browser,path,js=False)
    try:
        assert p.locator('#no-js').is_visible()
        for n in search._CATEGORIES:
            s=section(p,n); assert visible(s).count()==len(totals[n]); assert not s.locator('[data-controls]').is_visible()
        assert not errors and all(urlsplit(u).scheme=='file' for u in requests)
        assert p.locator('#search-hosts tbody a').first.is_visible()
        print('DOM no-JS fallback full rows and links',len(requests),'requests',flush=True)
    finally:ctx.close()


def test_search_browser_certificate_pair_dates(tmp_path,monkeypatch,browser):
    c1=original.c1; old=c1.cert_snapshot
    def snapshot(partial=False,large=False):
        roots=old(partial,large)
        for root in roots.values():
            for src in root['sources']:
                for block in src['blocks']:
                    c=block['certificate']; fp0=c['fingerprint']==c1.digest('public-fixture-0')
                    c.update(not_before=('2025-01-01T00:00:00Z' if partial else '2026-01-01T00:00:00Z'),
                             not_after=('2028-01-01T00:00:00Z' if partial else '2027-01-01T00:00:00Z'))
                    if not fp0: c['not_after' if partial else 'not_before']=None
                    c['gaps']=c1.ca.metadata_gaps(c);block['reason']='METADATA_GAP' if c['gaps'] else 'OK'
        return roots
    monkeypatch.setattr(c1,'cert_snapshot',snapshot)
    data=fixture(tmp_path,monkeypatch,'c1-assessed',history=True);pub,pp,raw,*_=data;path=preview(tmp_path,data)
    ctx,p,requests,errors=open_page(browser,path)
    try:
        s=section(p,'certificates'); count(s,4,2)
        assert 'Group validity (all members): CONFLICT' in s.inner_text()
        control(s,'before-min').fill('2025-01-01'); control(s,'before-max').fill('2025-01-01');count(s,1,1)
        assert visible(s).first.get_attribute('data-after')=='2028-01-01T00:00:00Z'
        control(s,'after-max').fill('2027-01-01');count(s,0,0)
        s.locator('[data-reset]').click();control(s,'before-min').fill('2026-01-01');control(s,'before-max').fill('2025-01-01')
        assert s.locator('[data-error]').is_visible();count(s,0,0)
        s.locator('[data-reset]').click();control(s,'state').select_option('PARTIAL');count(s,2,2)
        assert visible(s).evaluate_all('(ns)=>ns.every(n=>!n.dataset.before&&!n.dataset.after)')
        s.locator('[data-reset]').click();control(s,'sort').select_option('before')
        for direction,first in [('asc','2025'),('desc','2026')]:
            control(s,'direction').select_option(direction)
            vals=visible(s).evaluate_all('(ns)=>ns.map(n=>n.dataset.before)'); assert vals[0].startswith(first) and vals[2:]==['','']
        s.locator('[data-reset]').click();count(s,4,2)
        assert not errors and all(urlsplit(u).scheme=='file' for u in requests)
        print('DOM cert per-host paired UTC inclusive dates, incomplete pairs, invalid ranges, asc/desc missing-last',len(requests),'requests',flush=True)
    finally:ctx.close()


@pytest.mark.parametrize('fault',['foreign-host','foreign-evidence','duplicate-group','source','typed-state','cert-date','cert-role','wrong-version','unsafe-href','coverage'])
def test_search_negative(tmp_path,monkeypatch,fault):
    pub,pp,raw,root,_,_=fixture(tmp_path,monkeypatch,'c1-assessed'); cp,ap,sp=deepcopy(pp); g=cp['algorithms']['groups'][0]
    if fault=='foreign-host':g['host_ids']=['h-'+'0'*64]
    elif fault=='foreign-evidence':g['evidence_ids']=['e-'+'0'*64]
    elif fault=='duplicate-group':cp['algorithms']['groups'].append(deepcopy(g))
    elif fault=='source':sp['run']['source']['producer_id']='foreign'
    elif fault=='typed-state':g['levels']['L1']['observations']['FORGED']=g['evidence_ids']
    elif fault=='cert-date':next(o for o in ap['occurrences'].values() if o['certificate_metadata'])['certificate_metadata']['not_after']='2030-01-01T00:00:00Z'
    elif fault=='cert-role':
        c=ap['certificates']['groups'][0];c['signature']['evidence_ids']=c['public_key']['evidence_ids']
    elif fault=='wrong-version':ap['projection_version']=True
    elif fault=='unsafe-href':g['backlink']='javascript:alert(1)'
    else:sp['collector_rows'][0]['attempt_status']='ATTEMPTED' if sp['collector_rows'][0]['attempt_status']!='ATTEMPTED' else 'UNKNOWN'
    before=original.c1._c2_tree(root)
    with pytest.raises(rs.StoreError,match='^PORTAL_PAYLOAD_INVALID$'):search._render_search_page(pub,cp,ap,sp,**CAPS)
    assert original.c1._c2_tree(root)==before


def test_search_fixed_and_remaining_capacity(tmp_path,monkeypatch):
    rows=search._Rows()
    for n in range(20000): rows.reserve(search._CATEGORIES[n%7],str(n))
    assert rows.count==20000
    with pytest.raises(rs.StoreError,match='^PORTAL_PAYLOAD_SIZE_LIMIT$'): rows.reserve('hosts','20000')
    cap=16*2**20
    assert search._byte_limit(99*2**20,128*2**20,512*2**20)==cap
    assert len(search._stream(('a'*(cap-3),'界'),cap))==cap
    with pytest.raises(rs.StoreError,match='^PORTAL_PAYLOAD_SIZE_LIMIT$'):search._stream(('a'*(cap-3),'界','x'),cap)
    pub,pp,raw,root,_,_=fixture(tmp_path,monkeypatch,'zero');before=original.c1._c2_tree(root)
    for capname in CAPS:
        limits=dict(CAPS,**{capname:len(raw)})
        assert search._render_search_page(pub,*pp,**limits)==raw
        limits[capname]-=1
        with pytest.raises(rs.StoreError,match='^PORTAL_PAYLOAD_SIZE_LIMIT$'):search._render_search_page(pub,*pp,**limits)
    # Exercise actual admission with a reduced test-only combined row cap.
    monkeypatch.setattr(search,'_MAX_ROWS',9)
    assert search._render_search_page(pub,*pp,**CAPS)==raw
    monkeypatch.setattr(search,'_MAX_ROWS',8)
    with pytest.raises(rs.StoreError,match='^PORTAL_PAYLOAD_SIZE_LIMIT$'):search._render_search_page(pub,*pp,**CAPS)
    assert original.c1._c2_tree(root)==before


def test_search_rejects_bidi_at_original_store_boundary(tmp_path,monkeypatch):
    # The existing model rejects Unicode format/control characters. Do not
    # relax it to construct a malicious positive; legal printable Unicode and
    # HTML delimiters are exercised in the actual browser fixture above.
    monkeypatch.setattr(crypto_fixture,'MALICIOUS',EVIL+'\u202e')
    root=tmp_path/'reports';root.mkdir(mode=0o700)
    with pytest.raises(crypto_fixture.e.EvidenceError) as exc:
        crypto_fixture.publish_crypto(root)
    assert exc.value.code=='STRING'
    assert not list(root.glob('*/run_manifest.json'))
