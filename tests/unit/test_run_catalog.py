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


def catalog_state(root):
    # Only small catalog files, never traverse/read a sparse oversized run.
    return (stable(root), {name: stat.S_IMODE((root / name).stat().st_mode)
                          for name in (cat.JSON, cat.HTML)},
            tree_bytes(root / cat.GENERATIONS),
            sorted(p.name for p in (root / cat.GENERATIONS).iterdir()))


def sparse(path, size):
    with path.open('r+b') as stream:
        stream.truncate(size)
    assert path.stat().st_size == size and stat.S_IMODE(path.stat().st_mode) == 0o600


def test_per_run_capacity_does_not_publish(root, monkeypatch):
    pub = publish(root, monkeypatch, 'old')
    v1(root, 'old', pub)
    cat.build_catalog(root)
    old = catalog_state(root)
    old_run = tree_bytes(root / 'old')
    pub = publish(root, monkeypatch, 'oversized')
    v1(root, 'oversized', pub)
    pub = publish(root, monkeypatch, 'valid')
    v1(root, 'valid', pub)
    path = root / 'oversized' / cat.HTML
    sparse(path, portal._MAX_HTML + 1)
    signature = path.stat()
    for args in ((), ('--recover',)):
        result = cli(root, *args)
        assert (result.returncode, result.stdout, result.stderr) == (1, b'', b'CATALOG_CAPACITY\n')
        assert catalog_state(root) == old
    assert cli(root, '--check').returncode == 0
    assert_html_snapshot(root)
    assert tree_bytes(root / 'old') == old_run
    assert (path.stat().st_ino, path.stat().st_size, path.stat().st_mtime_ns) == (
        signature.st_ino, signature.st_size, signature.st_mtime_ns)
    # The real reader/renderer still run for the other valid publications.
    # Only the specific oversized fixed slot is forbidden to reach _read.
    actual_read, actual_render = rs._read, portal._render
    parent_stat = path.parent.stat()
    def guarded_read(fd, name, device, limit, *args, **kwargs):
        s = os.fstat(fd)
        assert not (s.st_ino == parent_stat.st_ino and name == cat.HTML)
        return actual_read(fd, name, device, limit, *args, **kwargs)
    def guarded_render(published):
        assert published.manifest['run_id'] != 'oversized'
        return actual_render(published)
    with monkeypatch.context() as m:
        m.setattr(rs, '_read', guarded_read)
        m.setattr(portal, '_render', guarded_render)
        with pytest.raises(rs.StoreError, match='CATALOG_CAPACITY'):
            cat.build_catalog(root)
    assert catalog_state(root) == old


@pytest.mark.parametrize('slot', ['marker', 'journal', 'core', 'detail', 'css', 'receipt', 'page', 'legacy-cff'])
def test_actual_fixed_slot_capacity(root, monkeypatch, slot):
    cat.build_catalog(root)
    old = catalog_state(root)
    if slot == 'legacy-cff':
        pub = legacy(root, 'run')
    else:
        with monkeypatch.context() as m:
            m.setattr(fixture, 'RID', 'run')
            pub = fixture.publish(root, details=slot == 'detail')
    run = root / 'run'
    if slot in ('css', 'receipt', 'page'):
        portal.render_run(root, 'run')
    if slot == 'legacy-cff':
        from tools import cff
        path, cap = run / rs.FILES['cff'][0], cff.MAX_BYTES
    elif slot == 'detail':
        entry = next(x for x in pub.manifest['artifacts'] if x['kind'] == 'detail')
        path, cap = run / entry['path'], rs.MAX_DETAIL
    else:
        name, cap = {'marker': ('run_manifest.json', rs.MAX_MANIFEST),
                     'journal': ('journal.json', rs.MAX_MANIFEST),
                     'core': rs.FILES['evidence'],
                     'css': ('portal.css', portal._MAX_CSS),
                     'receipt': (portal._GENERATION + '/' + portal._RECEIPT, portal._MAX_RECEIPT),
                     'page': (portal._GENERATION + '/hosts.html', portal._MAX_HTML)}[slot]
        path = run / name
    sparse(path, cap + 1)
    before = path.stat()
    actual_read = rs._read
    parent_stat = path.parent.stat()
    def guarded_read(fd, name, device, limit, *args, **kwargs):
        assert not (name == path.name and os.fstat(fd).st_ino == parent_stat.st_ino), slot
        return actual_read(fd, name, device, limit, *args, **kwargs)
    with monkeypatch.context() as m:
        m.setattr(rs, '_read', guarded_read)
        with pytest.raises(rs.StoreError, match='CATALOG_CAPACITY'):
            cat.build_catalog(root)
    assert catalog_state(root) == old and cat.check_catalog(root) == data(root)['generation']
    after = path.stat()
    assert (after.st_ino, after.st_size, after.st_mtime_ns, after.st_mode) == (
        before.st_ino, before.st_size, before.st_mtime_ns, before.st_mode)


@pytest.mark.parametrize('cap_kind', ['declared-size', 'declared-core-total', 'actual-core-total',
                                      'host-count', 'slot-count', 'legacy-cff-size'])
def test_typed_capacity_admission(root, monkeypatch, cap_kind):
    cat.build_catalog(root)
    old = catalog_state(root)
    if cap_kind == 'legacy-cff-size':
        pub = legacy(root, 'run')
    elif cap_kind == 'slot-count':
        with monkeypatch.context() as m:
            m.setattr(fixture, 'RID', 'run')
            pub = fixture.publish(root, ('COMPLETE',) * 3, details=True, assessed=True, cff=True)
    else:
        pub = publish(root, monkeypatch, 'run', ('COMPLETE', 'COMPLETE'))
    run = root / 'run'
    marker = run / 'run_manifest.json'
    value = json.loads(marker.read_bytes())
    entry = next(x for x in value['artifacts'] if x['kind'] == 'evidence')
    original_size = entry['size']
    with monkeypatch.context() as m:
        if cap_kind == 'declared-size':
            entry['size'] = rs.FILES['evidence'][1] + 1
            put(marker, rs._json_bytes(value))
        elif cap_kind == 'declared-core-total':
            m.setattr(rs, 'MAX_CORE', sum(x['size'] for x in value['artifacts']) - 1)
        elif cap_kind == 'actual-core-total':
            m.setattr(rs, 'MAX_CORE', sum(x['size'] for x in value['artifacts']))
            sparse(run / entry['path'], original_size + 1)
        elif cap_kind == 'host-count':
            value['limits']['max_hosts'] = 1
            assert len(value['hosts']) == 2
            put(marker, rs._json_bytes(value))
        elif cap_kind == 'slot-count':
            assert len(value['artifacts']) > 7
            m.setattr(rs, 'MAX_SLOTS', 7)
        else:
            from tools import cff
            size = next(x['size'] for x in value['artifacts'] if x['kind'] == 'cff')
            m.setattr(cff, 'MAX_BYTES', size - 1)
        # The original Store is still the publication authority. Capacity
        # must be proved by admitted metadata/stat before any core read.
        actual_read = rs._read
        def guarded_read(fd, name, device, limit, *args, **kwargs):
            assert name not in {rs.FILES[k][0] for k in rs.FILES}
            return actual_read(fd, name, device, limit, *args, **kwargs)
        m.setattr(rs, '_read', guarded_read)
        with pytest.raises(rs.StoreError, match='CATALOG_CAPACITY'):
            cat.build_catalog(root)
    assert catalog_state(root) == old
    assert cat.check_catalog(root) == data(root)['generation']


@pytest.mark.parametrize('cap_kind', ['v2-total', 'v1-generated', 'v2-generated', 'receipt-generated'])
def test_portal_total_and_generated_capacity(root, monkeypatch, cap_kind):
    cat.build_catalog(root)
    old = catalog_state(root)
    pub = publish(root, monkeypatch, 'run')
    portal.render_run(root, 'run')
    run, gen = root / 'run', root / 'run' / portal._GENERATION
    with monkeypatch.context() as m:
        if cap_kind == 'v2-total':
            total = (run / cat.HTML).stat().st_size + sum(p.stat().st_size for p in gen.glob('*.html'))
            m.setattr(portal, '_MAX_TOTAL_HTML', total - 1)
        elif cap_kind == 'v1-generated':
            # The persisted index fits, but actual v1 generation exceeds cap.
            old_index, _ = portal._render(pub)
            put(run / cat.HTML, b'ordinary-short-index')
            m.setattr(portal, '_MAX_HTML', len(old_index) - 1)
        elif cap_kind == 'v2-generated':
            marker = (run / 'run_manifest.json').read_bytes()
            old_index, css = portal._render(pub)
            index, pages, _ = portal._render_v2(pub, marker, css)
            total = len(index) + sum(map(len, pages.values()))
            # Actual admitted bytes fit, but deterministic v2 output does not.
            put(gen / 'hosts.html', b'short')
            m.setattr(portal, '_MAX_TOTAL_HTML', total - 1)
        else:
            size = (gen / portal._RECEIPT).stat().st_size
            put(gen / portal._RECEIPT, b'{}')
            m.setattr(portal, '_MAX_RECEIPT', size - 1)
        with pytest.raises(rs.StoreError, match='CATALOG_CAPACITY'):
            cat.build_catalog(root)
    assert catalog_state(root) == old
    assert cat.check_catalog(root) == data(root)['generation']


def test_mixed_valid_and_ordinary_invalid_publishes(root, monkeypatch):
    cat.build_catalog(root)
    initial = data(root)['generation']
    old_gen = tree_bytes(root / cat.GENERATIONS / initial)
    valid = publish(root, monkeypatch, 'valid')
    portal.render_run(root, 'valid')
    valid_tree = tree_bytes(root / 'valid')
    faults = ('size-mismatch', 'hash', 'malformed', 'wrong-type', 'bool-size', 'zero', 'negative',
              'foreign-path', 'duplicate-slot', 'foreign-host', 'wrong-identity',
              'unrelated-integer', 'unsafe-large', 'missing-core', 'portal-missing', 'portal-extra')
    for fault in faults:
        pub = publish(root, monkeypatch, fault)
        run = root / fault
        marker = run / 'run_manifest.json'
        value = json.loads(marker.read_bytes())
        entry = next(x for x in value['artifacts'] if x['kind'] == 'evidence')
        core = run / entry['path']
        if fault == 'size-mismatch':
            sparse(core, entry['size'] + 1)
        elif fault == 'hash':
            original = core.read_bytes()
            put(core, b'X' + original[1:])
        elif fault == 'malformed':
            put(marker, b'{}')
        elif fault == 'unsafe-large':
            sparse(core, rs.FILES['evidence'][1] + 1)
            core.chmod(0o644)
        elif fault == 'missing-core':
            core.unlink()
        elif fault.startswith('portal-'):
            portal.render_run(root, fault)
            gen = run / portal._GENERATION
            if fault == 'portal-missing':
                (gen / 'hosts.html').unlink()
            else:
                put(gen / 'foreign.html', b'foreign')
        else:
            if fault == 'wrong-type':
                entry['size'] = str(rs.FILES['evidence'][1] + 1)
            elif fault == 'bool-size':
                entry['size'] = True
            elif fault == 'zero':
                entry['size'] = 0
            elif fault == 'negative':
                entry['size'] = -1
            elif fault == 'unrelated-integer':
                value['limits']['forks'] = 3
            else:
                entry['size'] = rs.FILES['evidence'][1] + 1
                if fault == 'foreign-path':
                    entry['path'] = '../foreign.json'
                elif fault == 'duplicate-slot':
                    value['artifacts'].append(dict(entry))
                elif fault == 'foreign-host':
                    host = 'h-' + 'f' * 64
                    value['artifacts'].append({**entry, 'kind': 'detail', 'host_id': host,
                        'slot': 'platform', 'path': f'details/{host}/platform.json'})
                elif fault == 'wrong-identity':
                    value['run_id'] = 'foreign'
            put(marker, rs._json_bytes(value))
    result = cli(root)
    assert (result.returncode, result.stdout, result.stderr) == (0, b'CATALOG_PUBLISHED\n', b'')
    c = assert_html_snapshot(root)
    assert c == data(root) and c['generation'] != initial
    rows = {r['run_id']: r for r in c['rows']}
    assert set(rows) == set(faults) | {'valid'}
    assert rows['valid']['publication_status'] == 'PUBLISHED'
    assert rows['valid']['portal_generation'] == 'portal-v2'
    assert rows['valid']['href'] == 'valid/index.html'
    for fault in faults:
        row = rows[fault]
        assert row['href'] is None
        if fault.startswith('portal-'):
            assert row['publication_status'] == 'PUBLISHED' and row['portal_status'] == 'INVALID'
            assert row['run_state'] == 'COMPLETE'
        else:
            assert row['publication_status'] == 'INVALID' and row['reason_code'] == 'RUN_UNVERIFIED'
            assert row['run_state'] is None and row['portal_status'] == 'NOT_VERIFIED'
    assert tree_bytes(root / 'valid') == valid_tree
    assert tree_bytes(root / cat.GENERATIONS / initial) == old_gen
    assert cat.check_catalog(root) == c['generation']
    with rs.RunStore(root) as store:
        assert store.open('valid') == valid


def test_capacity_recover_preserves_proven_mixed_pair(root, monkeypatch):
    cat.build_catalog(root)
    initial = data(root)['generation']
    pub = publish(root, monkeypatch, 'new')
    v1(root, 'new', pub)
    actual = cat._replace_slot
    def interrupt(fd, device, name, old, content):
        if name == cat.HTML:
            raise rs.StoreError('INJECTED_FAILURE')
        return actual(fd, device, name, old, content)
    with monkeypatch.context() as m:
        m.setattr(cat, '_replace_slot', interrupt)
        with pytest.raises(rs.StoreError, match='INJECTED_FAILURE'):
            cat.build_catalog(root)
    assert data(root)['generation'] != initial
    assert assert_html_snapshot(root)['generation'] == initial
    mixed = catalog_state(root)
    pub = publish(root, monkeypatch, 'oversized')
    v1(root, 'oversized', pub)
    sparse(root / 'oversized' / cat.HTML, portal._MAX_HTML + 1)
    result = cli(root, '--recover')
    assert (result.returncode, result.stdout, result.stderr) == (1, b'', b'CATALOG_CAPACITY\n')
    assert catalog_state(root) == mixed and assert_html_snapshot(root)['generation'] == initial
    result = cli(root, '--check')
    assert (result.returncode, result.stdout, result.stderr) == (1, b'', b'CATALOG_RECOVERY_REQUIRED\n')


def test_legacy_projection_invalid_declaration_not_capacity(root, monkeypatch):
    cat.build_catalog(root)
    initial = data(root)['generation']
    legacy(root, 'bad-legacy')
    marker = root / 'bad-legacy' / 'run_manifest.json'
    value = json.loads(marker.read_bytes())
    entry = next(x for x in value['artifacts'] if x['kind'] == 'cff')
    from tools import cff
    # This fits the generic Store slot cap but is not a valid typed indexed
    # declaration, so the stricter projection cap alone is not proof.
    entry['size'] = cff.MAX_BYTES + 1
    entry['format_version'] = None
    put(marker, rs._json_bytes(value))
    pub = publish(root, monkeypatch, 'valid')
    v1(root, 'valid', pub)
    result = cli(root)
    assert result.returncode == 0 and result.stdout == b'CATALOG_PUBLISHED\n'
    rows = {r['run_id']: r for r in assert_html_snapshot(root)['rows']}
    assert data(root)['generation'] != initial
    assert rows['bad-legacy']['publication_status'] == 'INVALID' and rows['bad-legacy']['href'] is None
    assert rows['valid']['href'] == 'valid/index.html'


# Portal v3 history navigation. Keep all slice A oracles above unchanged.
V3 = 'portal-v3'
# Captured before any edits, from fixed N with the actual two-host native
# fixture below (including saved assessment and details), not the new renderer.
V2_GOLDEN = {
    'index.html': 'c317944557c8efd1a9df2650f93d786008b4a945a1de66034b5c2c4915f26659',
    'portal-v2/h-6d2ff9a0eef70ae56bdc5a87219edc8e8fd64b0ab5daa25c7060278f2ff29ab5.html':
        'dfb31294fb4ff6e5d16a31eb2c51b41f0a81539debe97c9b66f54fbac1432ea4',
    'portal-v2/h-d8e5f515397f29bc313a3fe0a24f704c474b33e1b2deca64e4e3586479957f7f.html':
        'e1e0a2f662012eccab5cc237db597bc40ecb5d042157119ca4263f84c361b402',
    'portal-v2/hosts.html': 'e9ba44f52ff79ff2f66c1e6f3514d825e7429230ff3fdc315a82c7495b00bd27',
    'portal-v2/portal_receipt.json': '4ecc67a7d35dc435cbcc1494101d9bc78898db9744e678a5b86567b40f2eae85',
    'portal.css': 'f4d7737a3f86617d69542b477a2e4b3775ad113e75d34677a2dc01eb9e24089f',
    'run_manifest.json': 'df54f11f7cae8185ef8ea712e02fbda1f6d09f49125c9e921804a2b5e48d46f9',
}


def render_cli(root, rid, *args):
    return subprocess.run([sys.executable, '-B', '-m', 'tools.render_portal',
        '--report-root', str(root), '--run-id', rid, *args], cwd=ROOT,
        capture_output=True, timeout=30)


def assert_v3_navigation(root, pub):
    from urllib.parse import urlsplit
    from test_portal_navigation import NavigationPage
    rid = pub.manifest['run_id']
    run, gen = root / rid, root / rid / V3
    ids = pub.manifest['expected_host_ids']
    names = {'hosts.html', *(hid + '.html' for hid in ids)}
    assert {p.name for p in gen.iterdir()} == names | {portal._RECEIPT}
    assert stat.S_IMODE(gen.stat().st_mode) == 0o700
    assert (run / 'index.html').read_bytes().startswith(b'<!-- PQC portal-v3 -->\n')
    def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()
    assert json.loads((gen / portal._RECEIPT).read_bytes()) == {
        'format': 3, 'run_id': rid, 'manifest_sha256': digest(run / 'run_manifest.json'),
        'index_sha256': digest(run / 'index.html'), 'css_sha256': digest(run / 'portal.css'),
        'pages': [{'name': n, 'size': (gen / n).stat().st_size, 'sha256': digest(gen / n)}
                  for n in sorted(names)]}
    batch = run / 'index.html'
    pages = {batch: NavigationPage(batch), **{gen / n: NavigationPage(gen / n) for n in names}}
    allowed = set(pages) | {root / 'index.html', run / 'portal.css', *(run / p for p in pub.artifacts)}
    for path, page in pages.items():
        s = path.lstat()
        assert stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode) == 0o600
        assert s.st_uid == os.geteuid() and s.st_nlink == 1
        assert ('../index.html' if path == batch else '../../index.html') in page.links
        assert not any(tag in {'script', 'iframe', 'object', 'embed', 'base', 'form'} or
                       any(k.startswith('on') or k in ('src', 'srcset', 'action', 'style') for k in attrs)
                       for tag, attrs in page.tags)
        for href in page.links:
            u = urlsplit(href)
            assert not u.scheme and not u.netloc and not u.query and not u.path.startswith('/')
            assert '\\' not in href and '%' not in u.path
            dest = (path.parent / u.path).resolve() if u.path else path
            assert dest in allowed and dest.is_file()
            if u.fragment:
                assert dest in pages and u.fragment in pages[dest].ids
    assert f'{V3}/hosts.html' in pages[batch].links
    hostlist = pages[gen / 'hosts.html']
    assert [a['id'] for t, a in hostlist.tags if t == 'tr' and 'id' in a] == ids
    for i, hid in enumerate(ids):
        assert f'{V3}/{hid}.html' in pages[batch].links and hid + '.html' in hostlist.links
        page = pages[gen / (hid + '.html')]
        assert page.text['host-state'] == pub.manifest['hosts'][i]['host_state']
        assert {'../index.html#' + hid, 'hosts.html#' + hid} <= set(page.links)
        assert [a['href'] for t, a in page.tags if t == 'a' and a.get('rel') == 'prev'] == (
            [ids[i-1] + '.html'] if i else [])
        assert [a['href'] for t, a in page.tags if t == 'a' and a.get('rel') == 'next'] == (
            [ids[i+1] + '.html'] if i+1 < len(ids) else [])
        assert {h for h in ids if h in page.ids} == {hid}
        assert {x for x in page.links if x.startswith('../details/')} == {
            '../' + a['path'] for a in pub.manifest['artifacts'] if a['kind'] == 'detail' and a['host_id'] == hid}
        for registry in ('collections', 'assets', 'evidence', 'claims', 'findings'):
            records = (pub.assessed or {}).get(registry, []) if registry in ('claims', 'findings') else pub.document[registry]
            key = fixture.e.REGISTRIES[registry]
            assert {r[key] for r in records} & page.ids == {r[key] for r in records if
                (r['subject']['host_id'] if registry in ('claims', 'findings') else r['host_id']) == hid}
    return pages


def test_history_v3_fixed_n_v2_golden_and_opt_in(root):
    pub = fixture.publish(root, ('COMPLETE', 'PARTIAL'), native=True, details=True, assessed=True)
    rid = pub.manifest['run_id']; run = root / rid
    assert render_cli(root, rid).returncode == 0
    actual = {str(p.relative_to(run)): hashlib.sha256(p.read_bytes()).hexdigest() for p in
              [run / 'index.html', run / 'portal.css', run / 'run_manifest.json',
               *sorted((run / 'portal-v2').iterdir())]}
    assert actual == V2_GOLDEN
    before = tree_bytes(run)
    cat.build_catalog(root)
    old = catalog_state(root)
    old_generation = data(root)['generation']
    old_snapshot = tree_bytes(root / cat.GENERATIONS / old_generation)
    p = render_cli(root, rid, '--with-history')
    assert (p.returncode, p.stdout, p.stderr) == (1, b'', b'PORTAL_OUTPUT_COLLISION\n')
    assert tree_bytes(run) == before and not (run / V3).exists()
    p = render_cli(root, rid, '--refresh-portal', '--with-history')
    assert (p.returncode, p.stdout, p.stderr) == (0, b'PORTAL_RENDERED\n', b'')
    assert (run / 'index.html').stat().st_ino != before['index.html'][1]
    assert {k: v for k, v in tree_bytes(run).items() if k != 'index.html' and not k.startswith(V3 + '/')} == {
        k: v for k, v in before.items() if k != 'index.html'}
    assert catalog_state(root) == old and cat.check_catalog(root) == old_generation
    assert data(root)['rows'][0]['portal_generation'] == 'portal-v2'  # consistency != freshness
    assert_v3_navigation(root, pub)
    with rs.RunStore(root) as store:
        assert store.open(rid) == pub
    cat.build_catalog(root)
    c = assert_html_snapshot(root)
    assert c['rows'][0]['portal_generation'] == V3 and c['rows'][0]['href'] == rid + '/index.html'
    assert tree_bytes(root / cat.GENERATIONS / old_generation) == old_snapshot
    # Old direct v2 pages still point at the stable batch, now v3.
    assert '../index.html' in Page(run / 'portal-v2' / 'hosts.html').links


@pytest.mark.parametrize('fault', ['missing', 'single-slot', 'corrupt'], ids=str)
def test_history_v3_catalog_precondition_and_four_flag_noop(root, monkeypatch, fault):
    pub = publish(root, monkeypatch, 'first')
    run = root / 'first'
    original = tree_bytes(run)
    assert render_cli(root, 'first', '--with-history').returncode == 1
    assert not (root / cat.LOCK).exists() and tree_bytes(run) == original
    cat.build_catalog(root)
    second = publish(root, monkeypatch, 'new')  # deliberately absent from the snapshot
    before = catalog_state(root)
    p = render_cli(root, 'new', '--with-history')
    assert (p.returncode, p.stdout, p.stderr) == (0, b'PORTAL_RENDERED\n', b'')
    assert catalog_state(root) == before and not (root / 'new' / 'portal-v2').exists()
    assert_v3_navigation(root, second)
    if fault == 'missing':
        (root / cat.HTML).unlink(); (root / cat.JSON).unlink(); (root / cat.LOCK).unlink()
        shutil.rmtree(root / cat.GENERATIONS)
    elif fault == 'single-slot':
        (root / cat.HTML).unlink()
    else:
        put(root / cat.JSON, b'foreign')
    old = tree_bytes(root)
    for refresh in (False, True):
        for history in (False, True):
            assert portal.render_run(root, 'new', refresh_portal=refresh, with_history=history) == root / 'new' / 'index.html'
            assert tree_bytes(root) == old
    assert render_cli(root, 'first', '--with-history').returncode == 1
    assert tree_bytes(root) == old
    # Default v2 remains independent of catalog existence/validity.
    portal.render_run(root, 'first')
    assert (run / 'portal-v2' / portal._RECEIPT).is_file() and not (run / V3).exists()
    with pytest.raises(rs.StoreError, match='INVALID_HISTORY_FLAG'):
        portal.render_run(root, 'first', with_history=1)
    assert render_cli(root, 'first', '--with-histor').returncode == 2
    with rs.RunStore(root) as store:
        assert store.open('first') == pub


def test_history_v3_legacy_v1_refresh_recovered_error_and_relocation(root, monkeypatch):
    pubs = {'legacy-partial': legacy(root, 'legacy-partial'),
            'recovered-error': recover(root, monkeypatch, 'recovered-error'),
            's1-error': publish(root, monkeypatch, 's1-error', ('ERROR',))}
    v1(root, 'legacy-partial', pubs['legacy-partial'])
    # A v1 default still refuses, and explicit refresh without history is v2.
    v1(root, 's1-error', pubs['s1-error'])
    with pytest.raises(rs.StoreError, match='PORTAL_OUTPUT_COLLISION'):
        portal.render_run(root, 's1-error')
    portal.render_run(root, 's1-error', refresh_portal=True)
    assert (root / 's1-error' / 'portal-v2').is_dir()
    cat.build_catalog(root)
    old = catalog_state(root)
    before = {r: tree_bytes(root / r) for r in pubs}
    with pytest.raises(rs.StoreError, match='PORTAL_OUTPUT_COLLISION'):
        portal.render_run(root, 'legacy-partial', with_history=True)
    for rid, pub in pubs.items():
        portal.render_run(root, rid, with_history=True, refresh_portal=rid != 'recovered-error')
        assert_v3_navigation(root, pub)
        assert {k: v for k, v in tree_bytes(root / rid).items() if not k.startswith(V3 + '/') and
                k not in ('index.html', 'portal.css')} == {
            k: v for k, v in before[rid].items() if k not in ('index.html', 'portal.css')}
        with rs.RunStore(root) as store:
            assert store.open(rid) == pub
    assert catalog_state(root) == old
    cat.build_catalog(root)
    c = assert_html_snapshot(root)
    assert all(r['portal_generation'] == V3 and r['href'] == r['run_id'] + '/index.html' for r in c['rows'])
    assert {r['run_id']: r['run_state'] for r in c['rows']} == {r: p.manifest['run_state'] for r, p in pubs.items()}
    moved = root.parent / 'moved reports \u6e2c\u8a66'
    shutil.copytree(root, moved)
    assert cat.check_catalog(moved) == c['generation'] and assert_html_snapshot(moved) == c
    for pub in pubs.values():
        assert_v3_navigation(moved, pub)


@pytest.mark.parametrize('fault', ['old-receipt', 'old-missing', 'old-extra', 'old-css', 'old-index-link',
                                    'stage-foreign', 'stage-unsafe'])
def test_history_v3_refresh_refuses_unproven_old_or_stage(root, monkeypatch, fault):
    publish(root, monkeypatch, 'run'); run = root / 'run'
    portal.render_run(root, 'run'); cat.build_catalog(root)
    gen = run / 'portal-v2'
    if fault == 'old-receipt': put(gen / portal._RECEIPT, b'{}')
    elif fault == 'old-missing': (gen / 'hosts.html').unlink()
    elif fault == 'old-extra': put(gen / 'foreign.html', b'x')
    elif fault == 'old-css': put(run / 'portal.css', b'x')
    elif fault == 'old-index-link':
        (run / 'index.html').rename(root.parent / 'sentinel'); (run / 'index.html').symlink_to(root.parent / 'sentinel')
    elif fault == 'stage-foreign':
        (run / V3).mkdir(mode=0o700); put(run / V3 / 'foreign.html', b'x')
    else: (run / V3).symlink_to(root.parent / 'absent')
    before = tree_bytes(root)
    with pytest.raises(rs.StoreError):
        portal.render_run(root, 'run', with_history=True, refresh_portal=True)
    assert tree_bytes(root) == before
    if not fault.startswith('stage-'):
        assert not (run / V3).exists()
    if fault == 'old-index-link': assert (run / 'index.html').is_symlink()


def test_history_v3_mixed_valid_and_ordinary_invalid(root, monkeypatch):
    cat.build_catalog(root); initial = data(root)['generation']; old_gen = tree_bytes(root / cat.GENERATIONS / initial)
    faults = ('marker-only', 'bad-receipt', 'missing-page', 'extra-page', 'unsafe-page', 'missing-gen', 'stage-only')
    for rid in ('valid', *faults):
        publish(root, monkeypatch, rid)
        portal.render_run(root, rid, with_history=True)
        run, gen = root / rid, root / rid / V3
        if rid == 'marker-only': put(run / 'index.html', portal._HISTORY_MARKER)
        elif rid == 'bad-receipt': put(gen / portal._RECEIPT, b'{}')
        elif rid == 'missing-page': (gen / 'hosts.html').unlink()
        elif rid == 'extra-page': put(gen / 'foreign.html', b'x')
        elif rid == 'unsafe-page': (gen / 'hosts.html').chmod(0o644)
        elif rid == 'missing-gen': shutil.rmtree(gen)
        elif rid == 'stage-only': (run / 'index.html').unlink()
        if rid in faults[:-1]:
            before = tree_bytes(run)
            # A declared v3 must not be treated as v1/v2 or repaired by refresh.
            for args in ({}, {'refresh_portal': True, 'with_history': True}):
                with pytest.raises(rs.StoreError): portal.render_run(root, rid, **args)
                assert tree_bytes(run) == before
            assert not (run / 'portal-v2').exists()
    before = {r: tree_bytes(root / r) for r in ('valid', *faults)}
    p = cli(root)
    assert (p.returncode, p.stdout, p.stderr) == (0, b'CATALOG_PUBLISHED\n', b'')
    c = assert_html_snapshot(root); rows = {r['run_id']: r for r in c['rows']}
    assert rows['valid']['portal_generation'] == V3 and rows['valid']['href'] == 'valid/index.html'
    for rid in faults:
        assert rows[rid]['publication_status'] == 'PUBLISHED' and rows[rid]['run_state'] == 'COMPLETE'
        assert rows[rid]['portal_status'] == 'INVALID' and rows[rid]['href'] is None
    assert {r: tree_bytes(root / r) for r in before} == before
    assert tree_bytes(root / cat.GENERATIONS / initial) == old_gen


def test_history_v3_unreferenced_versions_not_opened(root, monkeypatch):
    cat.build_catalog(root)
    for rid in ('v1-run', 'v2-run', 'v3-run'):
        pub = publish(root, monkeypatch, rid); run = root / rid
        if rid == 'v1-run':
            v1(root, rid, pub); (run / 'portal-v2').symlink_to(root.parent / 'absent')
        elif rid == 'v2-run': portal.render_run(root, rid)
        else:
            portal.render_run(root, rid, with_history=True)
            (run / 'portal-v2').symlink_to(root.parent / 'absent')
        if rid != 'v3-run':
            (run / V3).mkdir(mode=0o700)
            p = put(run / V3 / 'hosts.html', b'')
            with p.open('r+b') as f: f.truncate(portal._MAX_HTML + 1)
    actual_open = rs._open_dir
    def guarded_open(fd, name, device, **kwargs):
        # Only the currently referenced generation may be opened. Do not read
        # a sparse giant staging page or follow the unreferenced symlink.
        parent = Path(os.readlink(f'/proc/self/fd/{fd}')).name
        assert (parent, name) not in {('v1-run', 'portal-v2'), ('v1-run', V3),
                                     ('v2-run', V3), ('v3-run', 'portal-v2')}
        return actual_open(fd, name, device, **kwargs)
    monkeypatch.setattr(rs, '_open_dir', guarded_open)
    cat.build_catalog(root)
    assert {r['run_id']: r['portal_generation'] for r in data(root)['rows']} == {
        'v1-run': 'portal-v1', 'v2-run': 'portal-v2', 'v3-run': V3}
    portal.render_run(root, 'v2-run')
    portal.render_run(root, 'v3-run')


@pytest.mark.parametrize('fault', ['page', 'total', 'generated'])
def test_history_v3_capacity_preserves_catalog(root, monkeypatch, fault):
    cat.build_catalog(root); old = catalog_state(root)
    pub = publish(root, monkeypatch, 'run'); run = root / 'run'; gen = run / V3
    portal.render_run(root, 'run', with_history=True)
    total = (run / 'index.html').stat().st_size + sum(p.stat().st_size for p in gen.glob('*.html'))
    if fault == 'page':
        with (gen / 'hosts.html').open('r+b') as f: f.truncate(portal._MAX_HTML + 1)
    elif fault == 'total': monkeypatch.setattr(portal, '_MAX_TOTAL_HTML', total - 1)
    else:
        put(gen / 'hosts.html', b'short')
        monkeypatch.setattr(portal, '_MAX_TOTAL_HTML', total - 1)
    actual_read = rs._read
    def read(fd, name, device, limit, *args, **kwargs):
        if fault == 'page':
            assert not (name == 'hosts.html' and Path(os.readlink(f'/proc/self/fd/{fd}')).name == V3)
        return actual_read(fd, name, device, limit, *args, **kwargs)
    def unrelated(*args, **kwargs): raise AssertionError('unreferenced legacy renderer')
    monkeypatch.setattr(rs, '_read', read)
    monkeypatch.setattr(portal, '_render', unrelated)
    monkeypatch.setattr(portal, '_render_v2', unrelated)
    for recover in (False, True):
        with pytest.raises(rs.StoreError, match='CATALOG_CAPACITY'):
            cat.build_catalog(root, recover=recover)
        assert catalog_state(root) == old
    assert cat.check_catalog(root) == data(root)['generation']
    with rs.RunStore(root) as store: assert store.open('run') == pub


def test_history_v3_lock_order_and_shared_through_switch(root, monkeypatch):
    from contextlib import contextmanager
    publish(root, monkeypatch, 'run'); run = root / 'run'
    portal.render_run(root, 'run'); cat.build_catalog(root)
    before = catalog_state(root); observed = []
    actual_context, actual_render, actual_replace = cat._history_root, portal._render_v3, os.replace
    def probe(path, *, held):
        fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
        try:
            if held:
                with pytest.raises(BlockingIOError): fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            else:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally: os.close(fd)
    @contextmanager
    def context(report_root):
        probe(run / '.writer.lock', held=False)
        observed.append('run-released-before-catalog')
        with actual_context(report_root) as value:
            yield value
    def render(*args):
        probe(root / cat.LOCK, held=True); observed.append('render-held')
        return actual_render(*args)
    def replace(src, dst, **kwargs):
        if dst == 'index.html':
            probe(root / cat.LOCK, held=True); probe(run / '.writer.lock', held=True)
            observed.append('switch-held')
        return actual_replace(src, dst, **kwargs)
    monkeypatch.setattr(cat, '_history_root', context)
    monkeypatch.setattr(portal, '_render_v3', render)
    monkeypatch.setattr(os, 'replace', replace)
    portal.render_run(root, 'run', with_history=True, refresh_portal=True)
    assert observed == ['run-released-before-catalog', 'render-held', 'switch-held']
    probe(root / cat.LOCK, held=False); probe(run / '.writer.lock', held=False)
    assert catalog_state(root) == before


def test_history_v3_held_catalog_and_run_locks(root, monkeypatch):
    cat.build_catalog(root)
    for rid in ('v3-run', 'new', 'default'): publish(root, monkeypatch, rid)
    portal.render_run(root, 'v3-run', with_history=True)
    before = tree_bytes(root / 'new'); v3_before = tree_bytes(root / 'v3-run')
    fd = os.open(root / cat.LOCK, os.O_RDWR | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        start = time.monotonic()
        p = render_cli(root, 'new', '--with-history')
        assert (p.returncode, p.stdout, p.stderr) == (1, b'', b'RUN_BUSY\n')
        assert 4.5 <= time.monotonic() - start < 20
        assert tree_bytes(root / 'new') == before
        assert render_cli(root, 'default').returncode == 0
        for refresh in (False, True):
            for history in (False, True):
                portal.render_run(root, 'v3-run', refresh_portal=refresh, with_history=history)
                assert tree_bytes(root / 'v3-run') == v3_before
    finally: os.close(fd)
    with rs.RunStore(root) as store, store._locked_run('new', shared=False):
        with pytest.raises(rs.StoreError, match='RUN_BUSY'):
            portal.render_run(root, 'new', with_history=True)
    assert tree_bytes(root / 'new') == before
    portal.render_run(root, 'new', with_history=True)


@pytest.mark.parametrize('fault', ['catalog-lock', 'run-lock', 'root', 'stable-slot'])
def test_history_v3_identity_drift_before_output(root, monkeypatch, fault):
    publish(root, monkeypatch, 'run'); run = root / 'run'
    portal.render_run(root, 'run'); cat.build_catalog(root)
    before = tree_bytes(run); actual = portal._render_v3
    moved = root.parent / 'old-root'
    def changed(*args):
        output = actual(*args)
        if fault == 'root': root.rename(moved); root.mkdir(mode=0o700)
        else:
            path = {'catalog-lock': root / cat.LOCK, 'run-lock': run / '.writer.lock',
                    'stable-slot': root / cat.JSON}[fault]
            raw = path.read_bytes(); path.rename(root.parent / 'old-inode'); put(path, raw)
        return output
    monkeypatch.setattr(portal, '_render_v3', changed)
    with pytest.raises(rs.StoreError):
        portal.render_run(root, 'run', with_history=True, refresh_portal=True)
    target = moved / 'run' if fault == 'root' else run
    assert not (target / V3).exists()
    assert {k: v for k, v in tree_bytes(target).items() if k != '.writer.lock'} == {
        k: v for k, v in before.items() if k != '.writer.lock'}
    if fault == 'root': assert not list(root.iterdir())


@pytest.mark.parametrize('boundary', ['page', 'receipt', 'replace', 'durability', 'old-page-drift'])
def test_history_v3_refresh_faults_and_resume(root, monkeypatch, boundary):
    pub = publish(root, monkeypatch, 'run', ('COMPLETE', 'PARTIAL')); run = root / 'run'
    portal.render_run(root, 'run'); cat.build_catalog(root)
    original = tree_bytes(run); old_index = original['index.html'][0]; old_catalog = catalog_state(root)
    actual_write, actual_replace, actual_sync = rs._write, os.replace, rs._sync
    switched = False
    def write(fd, name, content, device, **kwargs):
        if boundary == 'page' and name == 'hosts.html': raise rs.StoreError('FIXTURE_INTERRUPTION')
        if boundary == 'receipt' and name == portal._RECEIPT: raise rs.StoreError('FIXTURE_INTERRUPTION')
        result = actual_write(fd, name, content, device, **kwargs)
        if boundary == 'old-page-drift' and name == portal._RECEIPT:
            put(run / 'portal-v2' / 'hosts.html', b'changed')
        assert (run / 'index.html').read_bytes() == old_index
        return result
    def replace(src, dst, **kwargs):
        nonlocal switched
        if dst == 'index.html':
            assert (run / V3 / portal._RECEIPT).is_file()
            if boundary == 'replace': raise OSError('fixture interruption')
            actual_replace(src, dst, **kwargs); switched = True
        else: return actual_replace(src, dst, **kwargs)
    def sync(fd):
        if boundary == 'durability' and switched: raise rs.StoreError('DURABILITY_UNCONFIRMED')
        return actual_sync(fd)
    with monkeypatch.context() as m:
        m.setattr(rs, '_write', write); m.setattr(os, 'replace', replace); m.setattr(rs, '_sync', sync)
        with pytest.raises(rs.StoreError, match={'page': 'FIXTURE_INTERRUPTION', 'receipt': 'FIXTURE_INTERRUPTION',
                'replace': 'STORE_IO', 'durability': 'DURABILITY_UNCONFIRMED', 'old-page-drift': 'PORTAL_OUTPUT_COLLISION'}[boundary]):
            portal.render_run(root, 'run', refresh_portal=True, with_history=True)
    assert switched == (boundary == 'durability') and ((run / 'index.html').read_bytes() != old_index) == switched
    assert catalog_state(root) == old_catalog and not list(run.glob('.portal-index-*'))
    existing = tree_bytes(run / V3)
    if boundary == 'old-page-drift':
        # A partially staged new version is not permission to replace an
        # unverified old index, even when the new receipt is exact.
        with pytest.raises(rs.StoreError): portal.render_run(root, 'run', refresh_portal=True, with_history=True)
        assert tree_bytes(run / V3) == existing and (run / 'index.html').read_bytes() == old_index
    else:
        portal.render_run(root, 'run', refresh_portal=True, with_history=True)
        assert_v3_navigation(root, pub)
        assert all(tree_bytes(run / V3)[k] == v for k, v in existing.items())
    for k, v in original.items():
        if k != 'index.html' and not (boundary == 'old-page-drift' and k == 'portal-v2/hosts.html'):
            assert tree_bytes(run)[k] == v
    with rs.RunStore(root) as store: assert store.open('run') == pub


def test_history_v3_generated_limit_precedes_any_output(root, monkeypatch):
    cat.build_catalog(root); pub = publish(root, monkeypatch, 'run'); run = root / 'run'
    old = tree_bytes(root)
    index, pages, _ = portal._render_v3(pub, (run / 'run_manifest.json').read_bytes(), portal._render_css())
    monkeypatch.setattr(portal, '_MAX_TOTAL_HTML', len(index) + sum(map(len, pages.values())) - 1)
    with pytest.raises(rs.StoreError, match='PORTAL_SIZE_LIMIT'):
        portal.render_run(root, 'run', with_history=True)
    assert tree_bytes(root) == old and not (run / V3).exists()
