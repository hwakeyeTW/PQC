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


# SEARCH-B: actual publication of the unchanged SEARCH-A page. External
# engineering oracle separately compares the original K renderers on the
# same immutable input bytes, before any candidate modifications.

def _search_b_setup(tmp_path, kind='zero', *, history=True):
    root = tmp_path / 'reports'; root.mkdir(mode=0o700)
    pub = (publish_assets(root, assessed=True, coverage_extra=True) if kind == 'assets'
           else original._cb2a_publication(root, tmp_path, kind))
    if history:
        catalog.build_catalog(root)
    rid = pub.manifest['run_id']
    return root, pub, rid, root / rid


def _search_b_receipt(run, pub):
    gen = run / 'portal-v6'; names = set(p.name for p in gen.iterdir())
    pages = {n: (gen / n).read_bytes() for n in names - {portal._RECEIPT}}
    assert names == set(portal._v6_layout(pub)[0]) - {'index.html', 'portal.css'}
    h = len(pub.manifest['expected_host_ids'])
    assert len(pages) == 14 + 3*h and len(names) == 15 + 3*h
    assert (run / 'index.html').read_bytes().startswith(b'<!-- PQC portal-v6 -->\n')
    receipt = rs._json_bytes(dict(format=6, run_id=pub.manifest['run_id'],
        manifest_sha256=digest((run / 'run_manifest.json').read_bytes()),
        index_sha256=digest((run / 'index.html').read_bytes()),
        css_sha256=digest((run / 'portal.css').read_bytes()),
        pages=[dict(name=n,size=len(raw),sha256=digest(raw)) for n,raw in sorted(pages.items())]), 1024**2)
    assert (gen / portal._RECEIPT).read_bytes() == receipt
    assert gen.stat().st_mode & 0o777 == 0o700
    assert all(p.stat().st_mode & 0o777 == 0o600 and p.stat().st_nlink == 1 for p in gen.iterdir())
    return pages


def _search_b_links(root, rid):
    # Check the actual active files after relocation, not a synthetic URL map.
    run = root / rid; gen = run / 'portal-v6'
    anchors = {}
    for path in [root/'index.html', run/'index.html', *sorted(gen.glob('*.html'))]:
        parsed = HTML(path.read_bytes())
        hrefs = parsed.links + [a['href'] for tag,a in parsed.tags if tag=='link' and 'href' in a]
        for href in hrefs:
            u = urlsplit(href)
            assert not (u.scheme or u.netloc or u.query or u.path.startswith('/')), href
            target = (path.parent/u.path).resolve() if u.path else path
            assert target.is_relative_to(root) and target.is_file(), (path.name, href)
            if u.fragment:
                if target not in anchors: anchors[target] = HTML(target.read_bytes()).ids
                assert u.fragment in anchors[target], (path.name,href)
    root_html = HTML((run/'index.html').read_bytes())
    assert 'portal-v6/search.html' in root_html.links
    assert all(not u.startswith('portal-v5/') for u in root_html.links)
    search_html=HTML((gen/'search.html').read_bytes())
    assert '../index.html' in search_html.links and '../../index.html' in search_html.links
    assert sum(tag=='script' for tag,a in search_html.tags)==1
    assert all(tag!='script' for tag,a in root_html.tags)
    assert any(tag=='noscript' for tag,a in search_html.tags)
    assert all(not any(k.startswith('on') or k in ('src','srcset','action','formaction') for k in a)
               for tag,a in search_html.tags)


@pytest.mark.parametrize('kind', KINDS)
def test_search_b_actual_store_publication(tmp_path, monkeypatch, kind):
    pub,pp,raw,root,old,_=fixture(tmp_path,monkeypatch,kind,history=True)
    rid=pub.manifest['run_id'];run=root/rid;before=original._cc_bytes(run)
    calls=defaultdict(int); captured={}
    def watch(name, fn, unpack=lambda x:x):
        def call(*args, **kwargs):
            calls[name]+=1
            result=fn(*args, **kwargs);captured[name]=unpack(result)
            return result
        return call
    actual_search=search._render_search_page
    def render_search(p,c,a,s,**limits):
        calls['search']+=1
        assert p is captured['open'] and c is captured['crypto'] and a is captured['asset'] and s is captured['summary']
        assert limits['page_limit']==ca._MAX_HTML and 0<limits['html_limit']<ca._MAX_HTML_TOTAL
        assert 0<limits['bundle_limit']<ca._MAX_BUNDLE
        return actual_search(p,c,a,s,**limits)
    with monkeypatch.context() as m:
        for obj,name,label,unpack in [(rs.RunStore,'open','open',lambda x:x),
            (crypto,'project_crypto_indexes','crypto',lambda x:x),
            (assets,'_render_asset_indexes','asset',lambda x:x[0]),
            (summary,'_render_summary_projection','summary',lambda x:x[0]),
            (cbom_validation,'validate_cbom_bytes','cbom',lambda x:x)]:
            m.setattr(obj,name,watch(label,getattr(obj,name),unpack))
        m.setattr(search,'_render_search_page',render_search)
        assert portal.render_run(root,rid,with_portal_search=True)==run/'index.html'
    # Original C-C test_cb2b2_actual_call_through expects exactly two
    # crypto projections: C2's internal membership check and the shared
    # assembler projection. SEARCH-B must not add a third.
    assert calls=={'open':1,'crypto':2,'asset':1,'summary':1,'cbom':len(pub.manifest['expected_host_ids']),'search':1}
    after=original._cc_bytes(run)
    assert all(after[n]==v for n,v in before.items())
    pages=_search_b_receipt(run,pub)
    assert pages.pop('search.html')==raw and pages==old[2]
    assert (run/'portal.css').read_bytes()==old[1]
    assert b'Verified generated downloads (published)' in (run/'index.html').read_bytes()
    assert b'not published' not in (run/'index.html').read_bytes()
    assert b'Private buffered report' not in (run/'index.html').read_bytes()
    assert b'Use the History breadcrumb to return to the run catalog' in (run/'index.html').read_bytes()
    assert {n:{r['data-key'] for r in HTML(raw).rows[n]} for n in search._CATEGORIES}==expected(pub,pp)
    with rs.RunStore(root) as store: assert store.open(rid)==pub
    catalog.build_catalog(root); row=original._cc_row(root,rid)
    assert row['portal_status']=='AVAILABLE' and row['portal_generation']=='portal-v6' and row['href']==rid+'/index.html'
    assert catalog.check_catalog(root)==json.loads((root/catalog.JSON).read_bytes())['generation']
    relocated=tmp_path/'relocated archive';shutil.copytree(root,relocated)
    _search_b_links(relocated,rid)
    print('V6_ACTUAL',kind,'hosts',len(pub.manifest['expected_host_ids']), 'search',len(raw),digest(raw),flush=True)


@pytest.mark.parametrize('version',[1,2,3,4,5])
def test_search_b_upgrade_exact_prior_and_no_downgrade(tmp_path,monkeypatch,version):
    import itertools
    from test_run_catalog import v1
    root,pub,rid,run=_search_b_setup(tmp_path,'native-v1' if version==5 else 'zero')
    if version==1:v1(root,rid,pub)
    else:portal.render_run(root,rid,with_history=version==3,with_crypto_indexes=version==4,with_portal_v5=version==5)
    catalog.build_catalog(root);assert original._cc_row(root,rid)['portal_generation']=='portal-v'+str(version)
    before=original._cc_bytes(root)
    with pytest.raises(rs.StoreError,match='PORTAL_OUTPUT_COLLISION'):
        portal.render_run(root,rid,with_portal_search=True)
    assert original._cc_bytes(root)==before
    # Bounded equivalent of a V5 receipt above the legacy 256 KiB cap. Only
    # the legacy receipt limit is lowered; actual valid V5 bytes stay intact.
    if version==5:
        size=(run/'portal-v5'/portal._RECEIPT).stat().st_size
        monkeypatch.setattr(portal,'_MAX_RECEIPT',size-1)
    core=original._cc_bytes(run)
    portal.render_run(root,rid,refresh_portal=True,with_history=True,with_crypto_indexes=True,
                      with_portal_v5=True,with_portal_search=True)
    after=original._cc_bytes(run)
    assert all(after[n]==v for n,v in core.items() if n!='index.html')
    assert after['index.html'][1]!=core['index.html'][1]
    _search_b_receipt(run,pub);catalog.build_catalog(root)
    assert original._cc_row(root,rid)['portal_generation']=='portal-v6'
    (root/catalog.JSON).unlink();(root/catalog.HTML).unlink();(root/catalog.LOCK).unlink()
    snap=original._cc_bytes(root)
    # All legal flag combinations on the small actual prior V4 case; the
    # other prior generations exercise default and all-on no-op separately.
    flags=itertools.product((False,True),repeat=5) if version==4 else [(False,)*5,(True,)*5]
    for refresh,history,crypto_mode,v5,search_mode in flags:
        portal.render_run(root,rid,refresh_portal=refresh,with_history=history,with_crypto_indexes=crypto_mode,
                          with_portal_v5=v5,with_portal_search=search_mode)
        assert original._cc_bytes(root)==snap


@pytest.mark.parametrize('kind',['unicode','certificates'])
def test_search_b_prior_dom_same_input_bytes(tmp_path,monkeypatch,kind):
    # Exact original A DOM fixture construction. Compare its actual output to
    # the previously executed A DOM page digest, not a regenerated JS oracle.
    if kind=='unicode':
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
        source='s1';prior='21f55370b970ba01c1bd74140abe70a1e80808da55a55b7e5eb6e8a3f182fd5b'
    else:
        c1=original.c1;old=c1.cert_snapshot
        def snapshot(partial=False,large=False):
            roots=old(partial,large)
            for root in roots.values():
                for src in root['sources']:
                    for block in src['blocks']:
                        c=block['certificate'];fp0=c['fingerprint']==c1.digest('public-fixture-0')
                        c.update(not_before=('2025-01-01T00:00:00Z' if partial else '2026-01-01T00:00:00Z'),
                                 not_after=('2028-01-01T00:00:00Z' if partial else '2027-01-01T00:00:00Z'))
                        if not fp0:c['not_after' if partial else 'not_before']=None
                        c['gaps']=c1.ca.metadata_gaps(c);block['reason']='METADATA_GAP' if c['gaps'] else 'OK'
            return roots
        monkeypatch.setattr(c1,'cert_snapshot',snapshot)
        source='c1-assessed';prior='264794ab82b9e0117d2374ce6df5859d2bf31cd04baad4735310ba0d02f943a7'
    pub,_,raw,root,_,_=fixture(tmp_path,monkeypatch,source,history=True)
    rid=pub.manifest['run_id'];portal.render_run(root,rid,with_portal_search=True)
    actual=(root/rid/'portal-v6/search.html').read_bytes()
    assert actual==raw and digest(actual)==prior
    print('V6_SAME_A_DOM_BYTES',kind,len(actual),digest(actual),flush=True)


def test_search_b_cli_flag_and_catalog_gate(tmp_path):
    import subprocess
    from test_run_catalog import publish
    root,pub,rid,run=_search_b_setup(tmp_path,history=False)
    for value in (1,None,'true',[]):
        with pytest.raises(rs.StoreError,match='INVALID_PORTAL_SEARCH_FLAG'):
            portal.render_run(root,rid,with_portal_search=value)
    for flag,code in [('refresh_portal','INVALID_REFRESH_FLAG'),('with_history','INVALID_HISTORY_FLAG'),
                     ('with_crypto_indexes','INVALID_CRYPTO_INDEXES_FLAG'),('with_portal_v5','INVALID_PORTAL_V5_FLAG')]:
        with pytest.raises(rs.StoreError,match=code):portal.render_run(root,rid,with_portal_search=1,**{flag:1})
    before=original._cc_bytes(run)
    with pytest.raises(rs.StoreError):portal.render_run(root,rid,with_portal_search=True)
    assert original._cc_bytes(run)==before and not (run/'portal-v6').exists()
    def cli(*flags):
        return subprocess.run([sys.executable,'-B','-m','tools.render_portal','--report-root',str(root),'--run-id',rid,*flags],
                              cwd=ROOT,capture_output=True,timeout=40)
    assert cli('--with-portal-searc').returncode==2
    catalog.build_catalog(root);p=cli('--with-portal-search','--with-portal-v5','--with-history','--with-crypto-indexes')
    assert (p.returncode,p.stdout,p.stderr)==(0,b'PORTAL_RENDERED\n',b'')
    _search_b_receipt(run,pub)
    # A corrupt catalog cannot admit a new V6; an existing exact V6 no-op
    # does not read or repair that catalog.
    with pytest.MonkeyPatch.context() as m:publish(root,m,'fixture-new')
    catalog.build_catalog(root);(root/catalog.JSON).write_bytes(b'{}')
    before=original._cc_bytes(root)
    with pytest.raises(rs.StoreError):portal.render_run(root,'fixture-new',with_portal_search=True)
    portal.render_run(root,rid,refresh_portal=True)
    assert original._cc_bytes(root)==before and not (root/'fixture-new/portal-v6').exists()


def test_search_b_private_v3_public_rejected(tmp_path):
    from tools import run_store_v3 as v3, scan_collectors as bridge, batch_execution as batch
    root=tmp_path/'reports';root.mkdir(mode=0o700);rid='fixture-private-v3';target='fixture-v3.example.invalid'
    limits=dict(max_hosts=10,forks=2,serial=2,ssh_timeout_s=15,command_timeout_s=30)
    flags={f:False for f in bridge.FLAGS};rules=(ROOT/'config/assessment_rules.yml').read_bytes()
    # A real complete all-disabled private publication, using actual terminal
    # validator and V3 writer, not a forged marker/manifest or remote worker.
    with rs.RunStore(root) as store:
        with store._begin_v3(run_id=rid,expected_hosts=[dict(target_id=target,inventory_authority_id=None,identity_key=target)],
                requested_flags={target:flags},limits=limits,profile='baseline',producer_rules_raw=rules) as w:
            row=batch._blank(target,flags,'NO_EXECUTABLE_COLLECTORS',False)
            row['platform']=batch._outcome(bridge.PLATFORM,False,'NOT_SCANNED','DISABLED')
            host=bridge.host_record(rid,target,row['host_state'],row['reason_code'])
            doc=bridge.document(rid,w.scope['started_at'],[host],rs._run_state([host]),None)
            doc['run']['recorded_at']=v3._clock()
            w.record_host(doc,attempted=False,terminal=row,details={})
            state,reason,rc=batch._run_state([row]);term=dict(batch_manifest_version=2,target_ids=[target],target_count=1,
                   limits=limits,profile='baseline',run_state=state,reason_code=reason,hosts=[row])
            batch.validate_producer_manifest(term,rc)
            pub=w.finalize(batch_raw=bridge.wire_bytes(term),batch_rc=rc,finished_at=v3._clock())
        assert store._open_v3(rid)==pub and pub.manifest['manifest_version']=='1.1.0'
        with pytest.raises(rs.StoreError):store.open(rid)
    catalog.build_catalog(root);row=original._cc_row(root,rid)
    assert row['publication_status']=='INVALID' and row['portal_status']=='NOT_VERIFIED' and row['href'] is None
    before=original._cc_bytes(root/rid)
    for kwargs in ({},{'with_portal_v5':True},{'with_portal_search':True}):
        with pytest.raises(rs.StoreError):portal.render_run(root,rid,**kwargs)
    assert original._cc_bytes(root/rid)==before and not (root/rid/'portal-v6').exists()


@pytest.mark.parametrize('cap',['rows','page','html','bundle','receipt'])
def test_search_b_exact_limits_before_write(tmp_path,monkeypatch,cap):
    root,pub,rid,run=_search_b_setup(tmp_path)
    index,css,pages,receipt=portal._render_v6(pub,(run/'run_manifest.json').read_bytes())
    html=len(index)+sum(len(raw) for name,raw in pages.items() if name.endswith('.html'))
    bundle=len(index)+len(css)+len(receipt)+sum(map(len,pages.values()))
    rows=sum(len(v) for v in HTML(pages['search.html']).rows.values())
    mod,key,exact={'rows':(search,'_MAX_ROWS',rows),'page':(ca,'_MAX_HTML',max([len(index),*[len(v) for n,v in pages.items() if n.endswith('.html')]])),
                   'html':(ca,'_MAX_HTML_TOTAL',html),'bundle':(ca,'_MAX_BUNDLE',bundle),
                   'receipt':(portal,'_MAX_V5_RECEIPT',len(receipt))}[cap]
    before=original._cc_bytes(root)
    with monkeypatch.context() as m:
        m.setattr(mod,key,exact-1)
        with pytest.raises(rs.StoreError,match='PORTAL_PAYLOAD_SIZE_LIMIT'):portal.render_run(root,rid,with_portal_search=True)
        assert original._cc_bytes(root)==before and not (run/'portal-v6').exists()
        m.setattr(mod,key,exact);portal.render_run(root,rid,with_portal_search=True)
        catalog.build_catalog(root);assert original._cc_row(root,rid)['portal_generation']=='portal-v6'
    assert _search_b_receipt(run,pub)==pages
    print('V6_EXACT_LIMIT',cap,exact,flush=True)


@pytest.mark.parametrize('fault',['missing','extra','receipt','payload','symlink','hardlink','marker','missing-generation','css'])
def test_search_b_active_tamper_no_link_no_repair(tmp_path,fault):
    import os
    root,pub,rid,run=_search_b_setup(tmp_path)
    portal.render_run(root,rid,with_portal_v5=True)
    portal.render_run(root,rid,with_portal_search=True,refresh_portal=True)
    catalog.build_catalog(root);gen=run/'portal-v6';p=gen/'search.html'
    if fault=='missing':p.unlink()
    elif fault=='extra':write(gen/'foreign.html',b'fixture')
    elif fault=='receipt':
        rec=json.loads((gen/portal._RECEIPT).read_bytes());rec['pages'][0]['name']='../foreign.html';write(gen/portal._RECEIPT,rs._json_bytes(rec))
    elif fault=='payload':p.write_bytes(p.read_bytes()+b' ')
    elif fault=='symlink':p.unlink();p.symlink_to(run/'portal-v5/hosts.html')
    elif fault=='hardlink':p.unlink();os.link(run/'portal-v5/hosts.html',p)
    elif fault=='marker':(run/'index.html').write_bytes(b'<!-- PQC portal-v7 -->\n'+(run/'index.html').read_bytes())
    elif fault=='missing-generation':gen.rename(root.parent/'inactive-copy')
    else:(run/'portal.css').write_bytes(b'foreign-css')
    before=original._cc_bytes(run)
    with pytest.raises(rs.StoreError):portal.render_run(root,rid,refresh_portal=True,with_portal_search=True)
    assert original._cc_bytes(run)==before
    catalog.build_catalog(root);row=original._cc_row(root,rid)
    assert row['portal_status']=='INVALID' and row['portal_generation'] is None and row['href'] is None
    assert original._cc_bytes(run)==before


def test_search_b_catalog_budget_active_only_and_unsafe(tmp_path,monkeypatch):
    import os
    from test_run_catalog import catalog_state
    root,pub,rid,run=_search_b_setup(tmp_path)
    portal.render_run(root,rid,with_portal_v5=True)
    portal.render_run(root,rid,with_portal_search=True,refresh_portal=True)
    catalog.build_catalog(root);before=catalog_state(root)
    total=sum(r['size'] for r in pub.manifest['artifacts'])+sum((run/n).stat().st_size for n in ('run_manifest.json','journal.json','index.html','portal.css'))
    gen=run/'portal-v6';total+=sum(p.stat().st_size for p in gen.iterdir())
    (run/'portal-v5/foreign').symlink_to(run/'index.html')
    actual=rs._open_dir
    def guarded(fd,name,*args,**kwargs):
        assert name!='portal-v5'
        return actual(fd,name,*args,**kwargs)
    monkeypatch.setattr(rs,'_open_dir',guarded)
    with monkeypatch.context() as m:
        m.setattr(catalog,'MAX_ADMITTED',total);catalog.build_catalog(root);assert catalog_state(root)==before
        m.setattr(catalog,'MAX_ADMITTED',total-1)
        with pytest.raises(rs.StoreError,match='CATALOG_CAPACITY'):catalog.build_catalog(root)
        assert catalog_state(root)==before
    p=gen/'search.html';size=p.stat().st_size
    # Isolate the search slot: a legitimate coverage page can be larger than
    # search on an empty run. Keep every other HTML slot within the test cap,
    # then deliberately make only the persisted search slot one byte too large.
    cap=max(size,(run/'index.html').stat().st_size,
            *(q.stat().st_size for q in gen.glob('*.html') if q!=p))
    with p.open('ab') as f:f.write(b' '*(cap+1-size))
    assert p.stat().st_size==cap+1
    # Safe actual oversized slot, before any read; reduced cap avoids giant files.
    original_read=rs._read;parent=gen.stat().st_ino
    def guarded_read(fd,name,*args,**kwargs):
        assert not (name=='search.html' and os.fstat(fd).st_ino==parent)
        return original_read(fd,name,*args,**kwargs)
    with monkeypatch.context() as m:
        m.setattr(ca,'_MAX_HTML',cap);m.setattr(rs,'_read',guarded_read)
        with pytest.raises(rs.StoreError,match='CATALOG_CAPACITY'):catalog.build_catalog(root)
        assert catalog_state(root)==before
        # Same size and unsafe inode: safety is checked before size admission.
        p.chmod(0o644);catalog.build_catalog(root)
        row=original._cc_row(root,rid);assert row['portal_status']=='INVALID' and row['href'] is None


@pytest.mark.parametrize('boundary',['page','receipt','stable','after-switch'])
def test_search_b_interruption_resume(tmp_path,monkeypatch,boundary):
    root,pub,rid,run=_search_b_setup(tmp_path)
    portal.render_run(root,rid,with_portal_v5=True);catalog.build_catalog(root)
    old=original._cc_bytes(run);actual_write,actual_replace,actual_sync=rs._write,portal._replace_v1_index,rs._sync
    injected=[]
    with monkeypatch.context() as m:
        def put(fd,name,raw,device,**kwargs):
            if boundary=='page' and name=='search.html' or boundary=='receipt' and name==portal._RECEIPT:
                injected.append(name);raise rs.StoreError('STORE_IO')
            return actual_write(fd,name,raw,device,**kwargs)
        def replace(*args,**kwargs):
            if boundary=='stable':injected.append(boundary);raise rs.StoreError('STORE_IO')
            return actual_replace(*args,**kwargs)
        def sync(fd):
            if boundary=='after-switch' and portal._identity(fd)==(run.stat().st_dev,run.stat().st_ino) and (run/'index.html').read_bytes().startswith(portal._V6_MARKER):
                injected.append(boundary);raise rs.StoreError('DURABILITY_UNCONFIRMED')
            return actual_sync(fd)
        m.setattr(rs,'_write',put);m.setattr(portal,'_replace_v1_index',replace);m.setattr(rs,'_sync',sync)
        with pytest.raises(rs.StoreError,match='DURABILITY_UNCONFIRMED' if boundary=='after-switch' else 'STORE_IO'):
            portal.render_run(root,rid,with_portal_search=True,refresh_portal=True)
    assert injected
    if boundary!='after-switch':assert original._cc_bytes(run)['index.html']==old['index.html']
    else:assert (run/'index.html').read_bytes().startswith(portal._V6_MARKER)
    stage=original._cc_bytes(run/'portal-v6')
    assert (portal._RECEIPT in stage)==(boundary in ('stable','after-switch'))
    portal.render_run(root,rid,with_portal_search=True,refresh_portal=True)
    after=original._cc_bytes(run/'portal-v6');assert all(after[n]==v for n,v in stage.items())
    assert all(original._cc_bytes(run)[n]==v for n,v in old.items() if n!='index.html')
    _search_b_receipt(run,pub);catalog.build_catalog(root);assert original._cc_row(root,rid)['portal_generation']=='portal-v6'


@pytest.mark.parametrize('fault',['old-page','old-inode','target-page','target-incomplete','css','catalog-slot','core','run-lock'])
def test_search_b_prior_and_target_drift(tmp_path,monkeypatch,fault):
    root,pub,rid,run=_search_b_setup(tmp_path)
    portal.render_run(root,rid,with_portal_v5=True);catalog.build_catalog(root)
    old=original._cc_bytes(run)['index.html'];replace=portal._replace_v1_index;render=portal._render_v6
    def same_bytes_new_inode(p):
        raw=p.read_bytes();p.rename(tmp_path/'old-inode');write(p,raw)
    if fault=='old-page':
        p=run/'portal-v5/hosts.html';p.write_bytes(p.read_bytes()+b' ')
    elif fault in ('catalog-slot','core','run-lock'):
        def drift_render(*args):
            value=render(*args)
            same_bytes_new_inode({'catalog-slot':root/catalog.JSON,'core':run/'evidence.json','run-lock':run/'.writer.lock'}[fault])
            return value
        monkeypatch.setattr(portal,'_render_v6',drift_render)
    else:
        def drift(*args,**kwargs):
            if fault=='target-incomplete':(run/'portal-v6/search.html').unlink()
            else:same_bytes_new_inode({'old-inode':run/'portal-v5/hosts.html','target-page':run/'portal-v6/search.html','css':run/'portal.css'}[fault])
            return replace(*args,**kwargs)
        monkeypatch.setattr(portal,'_replace_v1_index',drift)
    with pytest.raises(rs.StoreError):portal.render_run(root,rid,with_portal_search=True,refresh_portal=True)
    assert original._cc_bytes(run)['index.html']==old
    if fault in ('old-page','catalog-slot','core','run-lock'):assert not (run/'portal-v6').exists()


def test_search_b_catalog_lock_order_and_switch(tmp_path,monkeypatch):
    import fcntl,os
    from contextlib import contextmanager
    root,pub,rid,run=_search_b_setup(tmp_path)
    portal.render_run(root,rid,with_portal_v5=True);catalog.build_catalog(root)
    observed=[];ctx,render,replace=catalog._history_root,portal._render_v6,os.replace
    def probe(path,held):
        fd=os.open(path,os.O_RDWR|os.O_NOFOLLOW)
        try:
            if held:
                with pytest.raises(BlockingIOError):fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            else:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        finally:os.close(fd)
    @contextmanager
    def history(path):
        probe(run/'.writer.lock',False);observed.append('probe-released')
        with ctx(path) as value:yield value
    def assembly(*args):
        probe(root/catalog.LOCK,True);observed.append('catalog-held');return render(*args)
    def switch(src,dst,**kwargs):
        if dst=='index.html':
            probe(root/catalog.LOCK,True);probe(run/'.writer.lock',True);observed.append('switch-held')
        return replace(src,dst,**kwargs)
    with monkeypatch.context() as m:
        m.setattr(catalog,'_history_root',history);m.setattr(portal,'_render_v6',assembly);m.setattr(os,'replace',switch)
        portal.render_run(root,rid,with_portal_search=True,refresh_portal=True)
    assert observed==['probe-released','catalog-held','switch-held']
    probe(root/catalog.LOCK,False);probe(run/'.writer.lock',False)
    snapshot=original._cc_bytes(run)
    with rs.RunStore(root) as store,store._locked_run(rid,shared=False):
        with pytest.raises(rs.StoreError,match='RUN_BUSY'):portal.render_run(root,rid)
    fd=os.open(root/catalog.LOCK,os.O_RDWR|os.O_NOFOLLOW)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);portal.render_run(root,rid)
    finally:os.close(fd)
    assert original._cc_bytes(run)==snapshot


def test_search_b_fresh_stable_noreplace_race(tmp_path,monkeypatch):
    import os
    root,pub,rid,run=_search_b_setup(tmp_path);before=original._cc_bytes(run)
    rename=rs._rename_noreplace;raced=[]
    def collide(src_fd,src,dst_fd,dst):
        if dst=='index.html':
            assert (run/'portal-v6'/portal._RECEIPT).is_file() and not (run/'index.html').exists()
            fd=os.open(dst,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600,dir_fd=dst_fd)
            try:os.write(fd,b'foreign-stable-index');os.fsync(fd)
            finally:os.close(fd)
            raced.append(True)
        return rename(src_fd,src,dst_fd,dst)
    with monkeypatch.context() as m:
        m.setattr(rs,'_rename_noreplace',collide)
        with pytest.raises(rs.StoreError):portal.render_run(root,rid,with_portal_search=True)
    assert raced and (run/'index.html').read_bytes()==b'foreign-stable-index'
    assert all(original._cc_bytes(run)[n]==v for n,v in before.items()) and not list(run.glob('.portal-index-*'))
    with pytest.raises(rs.StoreError):portal.render_run(root,rid,with_portal_search=True,refresh_portal=True)
    catalog.build_catalog(root);assert original._cc_row(root,rid)['portal_status']=='INVALID'
