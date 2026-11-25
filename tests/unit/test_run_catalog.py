"""History uses actual Store publications and exact v1/v2 portal output."""
from collections import Counter
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import time

import pytest

import test_portal_overview as fixture
from test_portal_overview import ROOT, STAMP, END, Page, root, raw, rs, portal
from tools import run_catalog as cat


def put(path, content):
    path.write_bytes(content)
    path.chmod(0o600)
    return path


def publish(root, monkeypatch, rid, states=('COMPLETE',), *, native=False):
    with monkeypatch.context() as m:
        m.setattr(fixture, 'RID', rid)
        return fixture.publish(root, states, native=native)


def recover(root, monkeypatch, rid):
    with monkeypatch.context() as m:
        m.setattr(fixture, 'RID', rid)
        args = fixture.options(('ERROR', 'NOT_ATTEMPTED'), native=True, required=True)
        with rs.RunStore(root) as store:
            with store.begin(**args) as writer:
                writer.dispatch_intent(writer.scope['hosts'][0]['host_id'])
            store.recover(rid)
            return store.open(rid)


def legacy(root, rid):
    host, missing = 'fixture-history.example.invalid', 'missing-history.example.invalid'
    report = {'host': host, 'collected_at': STAMP, 'openssl_version': 'OpenSSL 3.5.0',
              'openssl_version_rc': 0, 'openssl_tls1_3_groups': 'X25519MLKEM768',
              'openssl_tls1_3_groups_rc': 0}
    value = {'run_id': 'fixture-old', 'generated_at': STAMP,
             'selected_hosts': [host, missing], 'successful_hosts': [host],
             'hosts_without_report': [missing], 'selected_count': 2,
             'completed_count': 1, 'reports': [report]}
    source = put(root.parent / 'legacy.json', raw(value))
    before = source.read_bytes()
    p = subprocess.run([sys.executable, '-B', '-m', 'tools.import_reports', '--input', str(source),
        '--format', 'legacy-ol-run-summary', '--run-id', rid, '--recorded-at', '2026-01-03T00:02:00Z',
        '--origin-ref', 'fixture-source', '--source-version', '0.9.1', '--report-root', str(root)],
        cwd=ROOT, capture_output=True, timeout=30)
    assert p.returncode == 0 and not p.stderr, p.stderr
    assert source.read_bytes() == before
    with rs.RunStore(root) as store:
        return store.open(rid)


def v1(root, rid, pub):
    index, css = portal._render(pub)
    put(root / rid / 'index.html', index)
    put(root / rid / 'portal.css', css)


def tree_bytes(path):
    result = {}
    for p in sorted(path.rglob('*')):
        s = p.lstat()
        if stat.S_ISREG(s.st_mode):
            result[str(p.relative_to(path))] = (p.read_bytes(), s.st_ino, s.st_mtime_ns, stat.S_IMODE(s.st_mode))
    return result


def data(root):
    return json.loads((root / cat.JSON).read_bytes())


def stable(root):
    return {n: ((root / n).read_bytes(), (root / n).stat().st_ino, (root / n).stat().st_mtime_ns)
            for n in (cat.JSON, cat.HTML) if (root / n).is_file()}


def assert_html_snapshot(root, html=None):
    path = root / cat.HTML if html is None else html
    page = Page(path)
    generation = page.text['generation']
    snapshot = root / cat.GENERATIONS / generation
    assert set(p.name for p in snapshot.iterdir()) == {cat.JSON, cat.SNAPSHOT, cat.RECEIPT}
    content = json.loads((snapshot / cat.JSON).read_bytes())
    payload = {k: v for k, v in content.items() if k != 'generation'}
    assert generation == content['generation'] == hashlib.sha256(rs._json_bytes(payload)).hexdigest()
    assert (snapshot / cat.SNAPSHOT).read_bytes() == path.read_bytes()
    receipt = json.loads((snapshot / cat.RECEIPT).read_bytes())
    assert receipt == {'catalog_version': 1, 'render_format': 1, 'generation': generation,
        'files': {name: {'size': (snapshot / name).stat().st_size,
                         'sha256': hashlib.sha256((snapshot / name).read_bytes()).hexdigest()}
                  for name in (cat.JSON, cat.SNAPSHOT)}}
    assert page.links == [f'{cat.GENERATIONS}/{generation}/{cat.JSON}'] + [r['href'] for r in content['rows'] if r['href']]
    assert page.text['total'] == str(len(content['rows']))
    assert len(page.tables['runs']) == len(content['rows']) + 1
    for row, cells in zip(content['rows'], page.tables['runs'][1:]):
        assert cells[:3] == [row['run_id'], row['publication_status'], row['run_state'] or 'Unknown']
        assert cells[-1] == row['reason_code'] and cells[-2].startswith(row['portal_status'])
    for axis in ('publication', 'outcome', 'portal'):
        for state, count in content['summary'][axis].items():
            assert page.text[axis + '-' + state] == f'{state}: {count}'
    for href in page.links:
        assert not href.startswith('/') and ':' not in href and '..' not in href.split('/')
        assert (root / href).is_file()
    assert '<script' not in path.read_text() and '<link ' not in path.read_text()
    return content


def cli(root, *args):
    return subprocess.run([sys.executable, '-B', '-m', 'tools.run_catalog', '--report-root', str(root), *args],
                          cwd=ROOT, capture_output=True, timeout=30)


def test_actual_native_s1_legacy_recovery_history(root, monkeypatch):
    pubs = {'native-complete': publish(root, monkeypatch, 'native-complete', native=True),
            's1-partial': publish(root, monkeypatch, 's1-partial', ('COMPLETE', 'ERROR')),
            's1-error': publish(root, monkeypatch, 's1-error', ('ERROR',)),
            'legacy-partial': legacy(root, 'legacy-partial'),
            'recovered': recover(root, monkeypatch, 'recovered')}
    assert pubs['native-complete'].manifest['batch_contract'] == rs.NATIVE_BATCH_CONTRACT
    assert pubs['legacy-partial'].manifest['run_kind'] == 'LEGACY_IMPORT'
    assert pubs['recovered'].manifest['recovery'] is True
    v1(root, 'native-complete', pubs['native-complete'])
    # Unreferenced staging must not invalidate an exact old v1 page.
    (root / 'native-complete' / portal._GENERATION).symlink_to(root.parent / 'nonexistent')
    portal.render_run(root, 's1-partial')
    portal.render_run(root, 'legacy-partial')
    portal.render_run(root, 'recovered')
    before = {rid: tree_bytes(root / rid) for rid in pubs}
    assert cli(root).returncode == 0
    c = assert_html_snapshot(root)
    assert c == data(root) and cat.check_catalog(root) == c['generation']
    assert c['rows'][0]['run_id'] == 'legacy-partial'
    assert [r['run_id'] for r in c['rows'][1:]] == sorted(set(pubs) - {'legacy-partial'})
    for row in c['rows']:
        rid, m = row['run_id'], pubs[row['run_id']].manifest
        assert row['publication_status'] == 'PUBLISHED'
        assert row['run_state'] == m['run_state'] and row['run_kind'] == m['run_kind']
        assert row['source_kind'] == m['source']['source_kind'] and row['recovery'] == m['recovery']
        assert row['expected_host_count'] == len(m['hosts'])
        assert row['host_state_counts'] == {k: m['counts'][k] for k in rs.HOST_STATES}
        assert row['missing_artifact_count'] == len(m['missing_artifacts'])
        assert row['manifest_sha256'] == hashlib.sha256((root / rid / 'run_manifest.json').read_bytes()).hexdigest()
        expected = {'native-complete': 'portal-v1', 's1-error': None}.get(rid, 'portal-v2')
        assert row['portal_generation'] == expected
        assert row['href'] == (rid + '/index.html' if expected else None)
        with rs.RunStore(root) as store:
            assert store.open(rid) == pubs[rid]
    assert c['summary']['outcome'] == dict(Counter(m.manifest['run_state'] for m in pubs.values()))
    assert c['summary']['portal']['AVAILABLE'] == 4
    assert {rid: tree_bytes(root / rid) for rid in pubs} == before
    for name in (cat.JSON, cat.HTML):
        assert b'example.invalid' not in (root / name).read_bytes()
    moved = root.parent / 'moved reports \u6e2c\u8a66'
    shutil.copytree(root, moved, symlinks=True)
    assert cat.check_catalog(moved) == c['generation'] and assert_html_snapshot(moved) == c


def test_unpublished_busy_collision_unsafe_and_corrupt(root, monkeypatch):
    for rid in ('bad-manifest', 'bad-core', 'bad-portal', 'missing-portal', 'Case-ID'):
        pub = publish(root, monkeypatch, rid)
        if rid in ('bad-portal', 'missing-portal', 'Case-ID'):
            portal.render_run(root, rid)
    put(root / 'bad-manifest' / 'run_manifest.json', b'{}')
    core = root / 'bad-core' / 'evidence.json'
    original = core.read_bytes()
    put(core, b'X' + original[1:])
    put(root / 'bad-portal' / portal._GENERATION / portal._RECEIPT, b'{}')
    (root / 'missing-portal' / portal._GENERATION / 'hosts.html').unlink()
    for name in ('case-id', 'empty', 'CON', '.temporary', 'fixture<script>'):
        (root / name).mkdir(mode=0o700)
    put(root / 'regular', b'sentinel')
    (root / 'link').symlink_to(root / 'Case-ID')
    os.mkfifo(root / 'fifo', 0o600)
    (root / 'unsafe-mode').mkdir(mode=0o755)
    pub = publish(root, monkeypatch, 'busy')
    with rs.RunStore(root) as store, store._locked_run('busy', shared=False):
        cat.build_catalog(root)
    c = assert_html_snapshot(root)
    rows = {r['run_id']: r for r in c['rows']}
    assert c['diagnostics']['ignored_entries'] == 3
    assert rows['busy']['publication_status'] == 'BUSY'
    assert rows['empty']['publication_status'] == 'UNPUBLISHED_OR_INCOMPLETE'
    for name in ('Case-ID', 'case-id'):
        assert rows[name]['reason_code'] == 'RUN_ID_COLLISION'
    for name in ('regular', 'fifo', 'link', 'unsafe-mode'):
        assert rows[name]['reason_code'] == 'UNSAFE_RUN_ENTRY'
    for name in ('bad-manifest', 'bad-core'):
        assert rows[name]['publication_status'] == 'INVALID'
    for name in ('bad-portal', 'missing-portal'):
        assert rows[name]['publication_status'] == 'PUBLISHED' and rows[name]['portal_status'] == 'INVALID'
    assert all(r['href'] is None for r in rows.values())
    assert all(r['run_state'] is None for r in rows.values() if r['publication_status'] != 'PUBLISHED')
    assert b'fixture<script>' not in (root / cat.HTML).read_bytes()
    assert (root / 'regular').read_bytes() == b'sentinel' and core.read_bytes() == b'X' + original[1:]
    with rs.RunStore(root) as store:
        assert store.open('busy') == pub
    # Busy was only a snapshot, not a failed scan. The next build discovers it.
    cat.build_catalog(root)
    assert next(r for r in data(root)['rows'] if r['run_id'] == 'busy')['publication_status'] == 'PUBLISHED'


@pytest.mark.parametrize('fault', ['index-link', 'index-hardlink', 'index-mode', 'index-foreign', 'css-bad',
                                   'page-link', 'page-hardlink', 'extra-page', 'generation-link', 'receipt-mode'])
def test_portal_no_link_when_not_exact(root, monkeypatch, fault):
    publish(root, monkeypatch, 'run')
    portal.render_run(root, 'run')
    run, gen = root / 'run', root / 'run' / portal._GENERATION
    victim = {'index-link': run / 'index.html', 'index-hardlink': run / 'index.html',
              'page-link': gen / 'hosts.html', 'page-hardlink': gen / 'hosts.html'}.get(fault)
    if victim is not None:
        outside = put(root.parent / 'sentinel', victim.read_bytes())
        victim.unlink()
        if fault.endswith('hardlink'):
            os.link(outside, victim)
        else:
            victim.symlink_to(outside)
    elif fault == 'generation-link':
        outside = root.parent / 'generation'
        gen.rename(outside)
        gen.symlink_to(outside)
    elif fault == 'extra-page':
        put(gen / 'extra.html', b'foreign')
    elif fault == 'index-mode':
        (run / 'index.html').chmod(0o644)
    elif fault == 'receipt-mode':
        (gen / portal._RECEIPT).chmod(0o644)
    else:
        put(run / ('portal.css' if fault == 'css-bad' else 'index.html'), b'<script>sentinel</script>')
    cat.build_catalog(root)
    row = data(root)['rows'][0]
    assert row['publication_status'] == 'PUBLISHED' and row['portal_status'] == 'INVALID'
    assert row['href'] is None and row['run_state'] == 'COMPLETE'
    assert_html_snapshot(root)


def test_check_readonly_same_generation_and_explicit_rescan(root, monkeypatch):
    assert cli(root, '--check').returncode == 1 and not list(root.iterdir())
    assert cli(root, '--check', '--recover').returncode == 2 and not list(root.iterdir())
    cat.build_catalog(root)
    initial = data(root)['generation']
    old = stable(root)
    old_gen = tree_bytes(root / cat.GENERATIONS / initial)
    cat.build_catalog(root)
    assert stable(root) == old and tree_bytes(root / cat.GENERATIONS / initial) == old_gen
    publish(root, monkeypatch, 'new')
    portal.render_run(root, 'new')
    assert cli(root, '--check').returncode == 0 and stable(root) == old
    assert data(root)['rows'] == []
    cat.build_catalog(root)
    assert data(root)['generation'] != initial and data(root)['rows'][0]['run_id'] == 'new'
    assert tree_bytes(root / cat.GENERATIONS / initial) == old_gen
    assert_html_snapshot(root)


def test_real_parallel_writers_and_held_lock(root, monkeypatch):
    cat.build_catalog(root)
    lock = os.open(root / cat.LOCK, os.O_RDWR)
    children = []
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        args = [sys.executable, '-B', '-m', 'tools.run_catalog', '--report-root', str(root)]
        for _ in range(2):
            children.append(subprocess.Popen(args, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE))
        time.sleep(.15)
        assert all(p.poll() is None for p in children)
        publish(root, monkeypatch, 'concurrent')
        fcntl.flock(lock, fcntl.LOCK_UN)
        for p in children:
            out, err = p.communicate(timeout=20)
            assert p.returncode == 0 and out == b'CATALOG_PUBLISHED\n' and not err
        assert data(root)['rows'][0]['run_id'] == 'concurrent'
        assert len([p for p in (root / cat.GENERATIONS).iterdir() if not p.name.startswith('.')]) == 2
        old = stable(root)
        fcntl.flock(lock, fcntl.LOCK_EX)
        start = time.monotonic()
        held = cli(root, '--check')
        assert held.returncode == 1 and held.stderr == b'RUN_BUSY\n'
        assert 4.5 <= time.monotonic() - start < 15 and stable(root) == old
    finally:
        os.close(lock)
        for p in children:
            if p.poll() is None:
                p.kill()
            p.communicate(timeout=5)
    assert_html_snapshot(root)


@pytest.mark.parametrize('boundary', ['stage', 'receipt', 'snapshot-rename', 'json', 'html', 'fsync-json', 'fsync-html'])
def test_fault_boundaries_and_recovery(root, monkeypatch, boundary):
    cat.build_catalog(root)
    old = stable(root)
    old_id = data(root)['generation']
    old_gen = tree_bytes(root / cat.GENERATIONS / old_id)
    publish(root, monkeypatch, 'new')
    core = tree_bytes(root / 'new')
    parent = root.stat()
    fired = []
    with monkeypatch.context() as m:
        mkdir, write, rename, replace, fsync = rs._mkdir, rs._write, rs._rename_noreplace, os.replace, os.fsync
        def fail():
            fired.append(True)
            raise rs.StoreError('INJECTED_FAILURE')
        def mkdir_fault(fd, name, device):
            if boundary == 'stage' and name.startswith('.stage-'):
                fail()
            return mkdir(fd, name, device)
        def write_fault(fd, name, content, device, **kw):
            if boundary == 'receipt' and name == cat.RECEIPT:
                fail()
            return write(fd, name, content, device, **kw)
        def rename_fault(src_fd, src, dst_fd, dst):
            if boundary == 'snapshot-rename' and src.startswith('.stage-'):
                fail()
            return rename(src_fd, src, dst_fd, dst)
        def replace_fault(src, dst, **kw):
            if (boundary, dst) in (('json', cat.JSON), ('html', cat.HTML)):
                fail()
            return replace(src, dst, **kw)
        def fsync_fault(fd):
            s = os.fstat(fd)
            if not fired and (s.st_dev, s.st_ino) == (parent.st_dev, parent.st_ino):
                changed_json = (root / cat.JSON).read_bytes() != old[cat.JSON][0]
                changed_html = (root / cat.HTML).read_bytes() != old[cat.HTML][0]
                if (boundary == 'fsync-json' and changed_json and not changed_html or
                        boundary == 'fsync-html' and changed_html):
                    fired.append(True)
                    raise OSError(errno.EIO, 'fixture fsync failure')
            return fsync(fd)
        m.setattr(rs, '_mkdir', mkdir_fault)
        m.setattr(rs, '_write', write_fault)
        m.setattr(rs, '_rename_noreplace', rename_fault)
        m.setattr(os, 'replace', replace_fault)
        m.setattr(os, 'fsync', fsync_fault)
        with pytest.raises(rs.StoreError, match='DURABILITY_UNCONFIRMED' if boundary.startswith('fsync') else 'INJECTED_FAILURE'):
            cat.build_catalog(root)
    assert fired == [True]
    assert tree_bytes(root / cat.GENERATIONS / old_id) == old_gen and tree_bytes(root / 'new') == core
    if boundary in ('html', 'fsync-json'):
        assert (root / cat.HTML).read_bytes() == old[cat.HTML][0]
        assert assert_html_snapshot(root)['generation'] == old_id
        result = cli(root, '--check')
        assert result.returncode == 1 and result.stderr == b'CATALOG_RECOVERY_REQUIRED\n'
        with pytest.raises(rs.StoreError, match='CATALOG_RECOVERY_REQUIRED'):
            cat.build_catalog(root)
    elif boundary != 'fsync-html':
        assert stable(root) == old and cat.check_catalog(root) == old_id
    else:
        assert cat.check_catalog(root) != old_id  # visible consistency, not durability proof
    assert cli(root, '--recover').returncode == 0
    assert assert_html_snapshot(root) == data(root) and data(root)['rows'][0]['run_id'] == 'new'
    assert tree_bytes(root / cat.GENERATIONS / old_id) == old_gen and tree_bytes(root / 'new') == core


@pytest.mark.parametrize('slot', [cat.JSON, cat.HTML])
def test_missing_proven_slot_requires_recover(root, slot):
    cat.build_catalog(root)
    old = stable(root)
    generation = data(root)['generation']
    (root / slot).unlink()
    assert cli(root, '--check').returncode == 1
    assert cli(root).returncode == 1
    assert cli(root, '--recover').returncode == 0 and cat.check_catalog(root) == generation
    other = cat.HTML if slot == cat.JSON else cat.JSON
    assert stable(root)[other] == old[other]


@pytest.mark.parametrize('fault', ['foreign-html', 'foreign-json', 'marker-only', 'stable-link', 'stable-hardlink',
    'stable-mode', 'snapshot-extra', 'snapshot-missing', 'snapshot-corrupt', 'generations-link', 'lock-mode'])
def test_foreign_corrupt_unsafe_never_overwritten(root, fault):
    cat.build_catalog(root)
    generation = data(root)['generation']
    gen = root / cat.GENERATIONS / generation
    if fault == 'foreign-html':
        put(root / cat.HTML, b'foreign')
    elif fault == 'foreign-json':
        put(root / cat.JSON, b'{}')
    elif fault == 'marker-only':
        put(root / cat.HTML, f'<!-- PQC catalog generation: {generation} -->\n'.encode())
    elif fault in ('stable-link', 'stable-hardlink'):
        p = root / cat.JSON
        outside = put(root.parent / 'sentinel', p.read_bytes())
        p.unlink()
        if fault == 'stable-link':
            p.symlink_to(outside)
        else:
            os.link(outside, p)
    elif fault == 'stable-mode':
        (root / cat.HTML).chmod(0o644)
    elif fault == 'snapshot-extra':
        put(gen / 'extra', b'foreign')
    elif fault == 'snapshot-missing':
        (gen / cat.RECEIPT).unlink()
    elif fault == 'snapshot-corrupt':
        put(gen / cat.RECEIPT, b'{}')
    elif fault == 'generations-link':
        target = root.parent / 'generation'
        (root / cat.GENERATIONS).rename(target)
        (root / cat.GENERATIONS).symlink_to(target)
    else:
        (root / cat.LOCK).chmod(0o644)
    old = stable(root)
    old_tree = tree_bytes(root)
    for args in (('--check',), (), ('--recover',)):
        result = cli(root, *args)
        assert result.returncode == 1 and not result.stdout
    assert stable(root) == old and tree_bytes(root) == old_tree


@pytest.mark.parametrize('limit', ['candidates', 'entries', 'admitted', 'output'])
def test_bounds_do_not_replace_valid_catalog(root, monkeypatch, limit):
    cat.build_catalog(root)
    old = stable(root)
    publish(root, monkeypatch, 'one')
    publish(root, monkeypatch, 'two')
    if limit == 'candidates':
        monkeypatch.setattr(cat, 'MAX_ROWS', 1)
    elif limit == 'entries':
        monkeypatch.setattr(rs, 'MAX_ROOT_ENTRIES', 1)
    elif limit == 'admitted':
        pub = rs.RunStore(root)
        try:
            manifest = pub.open('one').manifest
        finally:
            pub.close()
        p = root / 'one'
        # The first corrupt candidate still consumes admitted core/marker/journal.
        admitted = sum(x['size'] for x in manifest['artifacts']) + sum((p / n).stat().st_size for n in ('run_manifest.json', 'journal.json'))
        content = (p / 'evidence.json').read_bytes()
        put(p / 'evidence.json', b'X' + content[1:])
        monkeypatch.setattr(cat, 'MAX_ADMITTED', admitted)
    else:
        # Existing generation must remain valid; new rows push HTML/JSON beyond it.
        monkeypatch.setattr(cat, 'MAX_OUTPUT', max(len(v[0]) for v in old.values()))
    with pytest.raises(rs.StoreError):
        cat.build_catalog(root)
    assert stable(root) == old


@pytest.mark.parametrize('field', ['st_dev', 'st_uid'])
def test_same_device_and_owner_stat_guard(root, monkeypatch, field):
    publish(root, monkeypatch, 'one')
    target = (root / 'one').stat()
    original = os.fstat
    class Changed:
        def __init__(self, s):
            self.s = s
        def __getattr__(self, name):
            v = getattr(self.s, name)
            return v + 1 if name == field else v
    def altered(fd):
        s = original(fd)
        return Changed(s) if (s.st_dev, s.st_ino) == (target.st_dev, target.st_ino) else s
    with monkeypatch.context() as m:
        m.setattr(os, 'fstat', altered)
        cat.build_catalog(root)
    row = data(root)['rows'][0]
    assert row['reason_code'] == 'UNSAFE_RUN_ENTRY' and row['href'] is None


def test_nested_lock_identity_change_refused(root, monkeypatch):
    publish(root, monkeypatch, 'one')
    actual = rs.RunStore._locked_run
    from contextlib import contextmanager
    @contextmanager
    def swap(store, rid, *, shared):
        # Change the lock inode only on the nested public open. The original
        # outer lock stays held; a different inner lock is not authority.
        if getattr(store, 'expected', None) is not None:
            p = root / rid / '.writer.lock'
            p.rename(p.with_name('.fixture-old-lock'))
            put(p, b'')
        with actual(store, rid, shared=shared) as pair:
            yield pair
    monkeypatch.setattr(rs.RunStore, '_locked_run', swap)
    cat.build_catalog(root)
    assert data(root)['rows'][0]['reason_code'] == 'RUN_UNVERIFIED'


def test_initial_json_commit_before_html_recover(root, monkeypatch):
    publish(root, monkeypatch, 'one')
    actual = rs._write
    def interrupted(fd, name, content, device, **kw):
        if name == cat.HTML:
            raise rs.StoreError('INJECTED_FAILURE')
        return actual(fd, name, content, device, **kw)
    with monkeypatch.context() as m:
        m.setattr(rs, '_write', interrupted)
        with pytest.raises(rs.StoreError, match='INJECTED_FAILURE'):
            cat.build_catalog(root)
    assert (root / cat.JSON).is_file() and not (root / cat.HTML).exists()
    generation = data(root)['generation']
    before = stable(root)[cat.JSON]
    assert cli(root, '--check').returncode == 1
    assert cli(root, '--recover').returncode == 0
    assert stable(root)[cat.JSON] == before and cat.check_catalog(root) == generation
    assert_html_snapshot(root)


@pytest.mark.parametrize('fault', ['href', 'summary', 'ordering'])
def test_self_consistent_but_invalid_snapshot_refused(root, monkeypatch, fault):
    for rid in ('one', 'two'):
        publish(root, monkeypatch, rid)
        portal.render_run(root, rid)
    cat.build_catalog(root)
    payload = data(root)
    payload.pop('generation')
    if fault == 'href':
        payload['rows'][0]['href'] = '../sentinel.html'
    elif fault == 'summary':
        payload['summary']['total'] += 1
    else:
        payload['rows'].reverse()
    generation, content, html, receipt = cat._encoded(payload)
    gen = root / cat.GENERATIONS / generation
    gen.mkdir(mode=0o700)
    for name, value in ((cat.JSON, content), (cat.SNAPSHOT, html), (cat.RECEIPT, receipt)):
        put(gen / name, value)
    put(root / cat.JSON, content)
    put(root / cat.HTML, html)
    before = stable(root)
    assert cli(root, '--check').returncode == 1
    assert cli(root, '--recover').returncode == 1
    assert stable(root) == before


def test_root_contract_rejects_relative_symlink_and_mode(root):
    alias = root.parent / 'root-link'
    alias.symlink_to(root)
    for p in (Path('reports'), alias):
        assert cli(p).returncode == 1
        assert not list(root.iterdir())
    root.chmod(0o755)
    assert cli(root).returncode == 1 and not list(root.iterdir())
