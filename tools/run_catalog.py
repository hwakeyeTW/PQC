"""Offline history catalog of verified private Run Store publications.

Only the two catalog slots and immutable catalog snapshots are published here.
The caller supplies an existing approved local root; no run is repaired/rendered.
"""
import argparse
from collections import Counter
from contextlib import contextmanager
from pathlib import Path
import os
import re
import secrets
import sys

from jinja2 import Environment, FileSystemLoader, StrictUndefined, TemplateError

from tools import evidence, render_portal as portal, run_store as rs

VERSION = 1
RENDER_FORMAT = 1
MAX_ROWS = 1000
MAX_ADMITTED = 4 * 1024**3
MAX_OUTPUT = 16 * 1024**2
MAX_RECEIPT = 256 * 1024
LOCK = '.catalog.lock'
GENERATIONS = 'catalog.generations'
JSON = 'run_catalog.json'
HTML = 'index.html'
SNAPSHOT = 'index.html.snapshot'
RECEIPT = 'catalog_receipt.json'
_INTERNAL = {LOCK, GENERATIONS, JSON, HTML, '.reservation.lock'}
_MARKER = re.compile(rb'<!-- PQC catalog generation: ([0-9a-f]{64}) -->\n')
_PUBLICATIONS = ('PUBLISHED', 'UNPUBLISHED_OR_INCOMPLETE', 'INVALID', 'BUSY')
_PORTALS = ('AVAILABLE', 'NOT_GENERATED', 'INVALID', 'NOT_VERIFIED')
_REASONS = {'UNPUBLISHED_OR_INCOMPLETE': 'UNPUBLISHED_OR_INCOMPLETE',
            'BUSY': 'RUN_BUSY'}
_INVALID_REASONS = ('RUN_ID_COLLISION', 'UNSAFE_RUN_ENTRY', 'RUN_UNVERIFIED')
_ROW_KEYS = ('run_id publication_status run_state run_kind source_kind recovery started_at '
             'finished_at recorded_at expected_host_count host_state_counts missing_artifact_count '
             'manifest_sha256 portal_status portal_generation href reason_code')
_UNKNOWN_FIELDS = ('run_state run_kind source_kind recovery started_at finished_at recorded_at '
                   'expected_host_count host_state_counts missing_artifact_count manifest_sha256').split()
_TEMPLATES = Path(__file__).resolve().parents[1] / 'templates' / 'portal'


class CapacityError(rs.StoreError):
    """A whole-catalog limit, never converted to an individual invalid row."""


class _Budget:
    def __init__(self):
        self.used = 0

    def add(self, size):
        if size > MAX_ADMITTED - self.used:
            raise CapacityError('CATALOG_CAPACITY')
        self.used += size

    def file(self, fd, name, device, limit):
        size = _safe_size(fd, name, device, limit)
        self.add(size)
        return size


def _capacity_if(exceeded):
    if exceeded:
        raise CapacityError('CATALOG_CAPACITY')


def _safe_size(fd, name, device, limit):
    # An untrusted pathname or unsafe inode is not evidence of capacity.
    f = rs._open_file(fd, name, device)
    try:
        size = rs._stat_file(f, device).st_size
        rs.require(size >= 0, 'ARTIFACT_SIZE')
        _capacity_if(size > limit)
        return size
    finally:
        os.close(f)


def _identity(fd):
    s = os.fstat(fd)
    return s.st_dev, s.st_ino


def _entry_identity(fd, name):
    s = os.stat(name, dir_fd=fd, follow_symlinks=False)
    return s.st_dev, s.st_ino


def _same_entry(parent, name, fd):
    rs.require(_entry_identity(parent, name) == _identity(fd), 'ARTIFACT_CHANGED')


class _CatalogStore(rs.RunStore):
    # Public open() is inherited, including the real _read_publication. Bind
    # its nested shared lock to the outer directory AND lock identity.
    expected = None

    @contextmanager
    def _locked_run(self, rid, *, shared):
        with super()._locked_run(rid, shared=shared) as (fd, lock):
            if self.expected is not None:
                rs.require(shared and self.expected == (rid, _identity(fd), _identity(lock)),
                           'ARTIFACT_CHANGED')
            yield fd, lock


def _unknown(rid, status, reason):
    return {'run_id': rid, 'publication_status': status,
            **dict.fromkeys(_UNKNOWN_FIELDS), 'portal_status': 'NOT_VERIFIED',
            'portal_generation': None, 'href': None, 'reason_code': reason}


def _portal_status(fd, device, published, marker, budget):
    has_index = rs._exists(fd, HTML)
    has_css = rs._exists(fd, 'portal.css')
    has_v2 = rs._exists(fd, portal._GENERATION)
    has_v3 = rs._exists(fd, portal._HISTORY_GENERATION)
    if not (has_index or has_css or has_v2 or has_v3):
        return 'NOT_GENERATED', None
    try:
        index_size = budget.file(fd, HTML, device, portal._MAX_HTML) if has_index else None
        css_size = budget.file(fd, 'portal.css', device, portal._MAX_CSS) if has_css else None
        rs.require(has_index and has_css, 'PORTAL_GENERATION_INCOMPLETE')
        current = rs._read(fd, HTML, device, portal._MAX_HTML, index_size)
        css = rs._read(fd, 'portal.css', device, portal._MAX_CSS, css_size)
        history = current.startswith(portal._HISTORY_MARKER)
        try:
            if history:
                old, expected_css = None, portal._render_css()
            else:
                old, expected_css = portal._render(published)
        except rs.StoreError as exc:
            # V1 uses this code for an empty trusted CSS as well as overflow.
            # The installed renderer/templates are trusted, fixed inputs.
            if (exc.code == 'PORTAL_SIZE_LIMIT' and
                    (portal._TEMPLATES / 'portal.css').stat().st_size > 0):
                raise CapacityError('CATALOG_CAPACITY') from None
            raise
        rs.require(css == expected_css, 'PORTAL_OUTPUT_COLLISION')
        if current == old:
            # Neither unreferenced v2 nor v3 staging is opened.
            return 'AVAILABLE', 'portal-v1'
        generation = portal._HISTORY_GENERATION if history else portal._GENERATION
        rs.require(has_v3 if history else has_v2, 'PORTAL_GENERATION_INCOMPLETE')
        with rs._directory(fd, (generation,), device) as gen:
            names = {'hosts.html', *(h + '.html' for h in published.manifest['expected_host_ids'])}
            expected = names | {portal._RECEIPT}
            present = set(rs._entries(gen, len(expected)))
            total = index_size
            # Charge every admitted fixed derived slot, even when later invalid.
            for name in sorted(present & expected):
                cap = portal._MAX_RECEIPT if name == portal._RECEIPT else portal._MAX_HTML
                size = budget.file(gen, name, device, cap)
                if name != portal._RECEIPT:
                    total += size
            _capacity_if(total > portal._MAX_TOTAL_HTML)
            rs.require(present == expected, 'PORTAL_GENERATION_INCOMPLETE')
            try:
                render = portal._render_v3 if history else portal._render_v2
                index, pages, receipt = render(published, marker, expected_css)
            except rs.StoreError as exc:
                # In this fixed renderer, these are generated HTML and receipt
                # byte limits, not a persisted page/receipt mismatch.
                if exc.code in ('PORTAL_SIZE_LIMIT', 'SIZE_LIMIT'):
                    raise CapacityError('CATALOG_CAPACITY') from None
                raise
            rs.require(current == index, 'PORTAL_OUTPUT_COLLISION')
            portal._generation(gen, device, pages, receipt, complete=True)
            _same_entry(fd, generation, gen)
        return 'AVAILABLE', generation
    except CapacityError:
        raise
    except (rs.StoreError, OSError):
        return 'INVALID', None


def _core_slot(key, kind):
    parts, cap = rs._slot(*key)
    if key[0] == 'cff':
        cap = min(cap, rs.MAX_CFF)
        if kind == 'LEGACY_IMPORT':
            # The legacy projection has a stricter byte cap than the generic slot.
            from tools import cff
            cap = min(cap, cff.MAX_BYTES)
    return parts, cap


def _declared_capacity(header, rid):
    """Diagnose only a failed header's count/size admission, not publication.

    Check all original fixed identities and positive typed sizes before using
    a diagnostic projection of the header with bounded counts/sizes. Reuse
    the actual Store header/scope validators for all other scope constraints;
    no projected header is passed to open(), used for a row, or written.
    """
    rs._keys(header, rs.MANIFEST_KEYS)
    rs.require(header['manifest_version'] == rs.VERSION and
               header['publication_state'] == 'PUBLISHED' and header['run_id'] == rid,
               'MANIFEST_IDENTITY')
    rs._enum(header['run_kind'], rs.KINDS)
    kind = header['run_kind']
    hosts = header['hosts']
    rs.require(type(hosts) is list and bool(hosts), 'HOST_LIMIT')
    ids, targets = [], []
    for row in hosts:
        rs.require(type(row) is dict and 'host_id' in row and 'target_id' in row,
                   'INVALID_SHAPE')
        ids.append(rs._id(row['host_id']))
        target = row['target_id']
        rs.require(target is None or type(target) is str, 'INVALID_TARGET')
        if target is not None:
            targets.append(target)
    host_ids = set(ids)
    rs.require(len(host_ids) == len(ids) and ids == sorted(host_ids) and
               header['expected_host_ids'] == ids and len(set(targets)) == len(targets),
               'HOST_MANIFEST')
    flags = header['flags']
    if kind == 'LEGACY_IMPORT':
        host_cap = 1000
        rs.require(flags is None, 'LEGACY_SCOPE')
    else:
        rs._keys(header['limits'], 'max_hosts forks serial ssh_timeout_s command_timeout_s')
        host_cap = header['limits']['max_hosts']
        rs._int(host_cap, 1, 10)
        rs.require(type(flags) is dict and flags.keys() == host_ids, 'PROFILE_FLAGS')
    # Requirements use a separate bounded slot list. Validate all original
    # references, including duplicates across diagnostic groups.
    requirements = header['requirements']
    rs._keys(requirements, 'assessment cff details')
    details = requirements['details']
    detail_cap = rs.MAX_SLOTS - 6
    rs.require(type(details) is list and detail_cap >= 0, 'SLOT_LIMIT')
    required = set()
    step = max(1, detail_cap)
    for start in range(0, len(details) or 1, step):
        group = rs._requirements({**requirements, 'details': details[start:start + step]},
                                 host_ids, kind)
        rs.require(not required & group, 'INVALID_DETAIL_REQUIREMENT')
        required.update(group)
    rows = header['artifacts']
    rs.require(type(rows) is list and bool(rows), 'SLOT_LIMIT')
    entries, total = {}, 0
    overflow = len(hosts) > host_cap or len(rows) > rs.MAX_SLOTS or len(details) > detail_cap
    for row in rows:
        rs._keys(row, rs.ENTRY_KEYS)
        key = (row['kind'], row['host_id'], row['slot'])
        parts, cap = _core_slot(key, kind)
        rs.require(row['path'] == '/'.join(parts) and key not in entries and
                   (key[0] != 'detail' or key[1] in host_ids), 'INVALID_SLOT')
        rs.require(type(row['size']) is int and row['size'] > 0, 'INVALID_INTEGER')
        rs._bool(row['required'])
        rs.require(rs._match(row['sha256'], rs.HEX), 'ARTIFACT_HASH')
        version = (header['evidence_schema_version'] if key[0] in ('evidence', 'assessed') else
                   header['rule_version'] if key[0] == 'rules' else rs.VERSION)
        rs.require(type(version) is str and row['format_version'] == version, 'INVALID_SLOT')
        for field, ref_kind in (('collection_ids', 'collection'), ('asset_ids', 'asset'),
                                ('evidence_ids', 'evidence')):
            refs = row[field]
            rs.require(type(refs) is list and (key[0] == 'detail' or not refs), 'INVALID_REFS')
            for ref in refs:
                rs._id(ref, ref_kind)
            rs.require(refs == sorted(set(refs)), 'INVALID_REFS')
        entries[key] = row
        total += row['size']
        overflow |= row['size'] > cap
    overflow |= total > rs.MAX_CORE
    if not overflow:
        return False
    # The evidence slot is mandatory for any genuine published run. Validate
    # the original scope in bounded groups, not a truncated catalog/run. All
    # original counts/slots/identities above were checked before this probe.
    rs.require(('evidence', None, None) in entries, 'MISSING_EVIDENCE')
    evidence_slot = {**entries['evidence', None, None], 'size': 1}
    for start in range(0, len(hosts), host_cap):
        group = hosts[start:start + host_cap]
        group_ids = ids[start:start + host_cap]
        probe = {**header, 'hosts': group, 'expected_host_ids': group_ids,
                 'flags': None if flags is None else {hid: flags[hid] for hid in group_ids},
                 'requirements': {**requirements, 'details': []}, 'artifacts': [evidence_slot]}
        rs._manifest_header(probe, rid)
    return True


def _admitted_entries(header, rid):
    try:
        _, _, entries = rs._manifest_header(header, rid)
    except rs.StoreError as exc:
        if exc.code in ('INVALID_INTEGER', 'HOST_LIMIT', 'SLOT_LIMIT', 'CORE_SIZE_LIMIT'):
            try:
                overflow = _declared_capacity(header, rid)
            except (rs.StoreError, evidence.EvidenceError):
                overflow = False
            _capacity_if(overflow)
        raise
    # A CFF declaration can fit the generic Store header limit but exceed the
    # stricter actual projection byte limit. Apply the same typed proof, not
    # the ambiguous CFF_PROJECTION_LIMIT from later content validation.
    if any(row['size'] > _core_slot(key, header['run_kind'])[1]
           for key, row in entries.items()):
        _capacity_if(_declared_capacity(header, rid))
        raise rs.StoreError('INVALID_SLOT')
    return entries


def _admit_core(fd, device, header, entries):
    # Stat only: indexed declarations have already been charged once.
    total, invalid = 0, None
    for key, row in entries.items():
        parts, cap = _core_slot(key, header['run_kind'])
        _capacity_if(row['size'] > cap)
        try:
            with rs._directory(fd, parts[:-1], device) as parent:
                size = _safe_size(parent, parts[-1], device, cap)
            total += size
            _capacity_if(total > rs.MAX_CORE)
            rs.require(size == row['size'], 'ARTIFACT_SIZE')
        except CapacityError:
            raise
        except (rs.StoreError, OSError) as exc:
            # Do not open any raw/foreign path, but other admitted fixed slots
            # may still provide positive capacity evidence. No core bytes read.
            if invalid is None:
                invalid = exc
    if invalid is not None:
        raise invalid


def _published_row(store, rid, fd, lock, budget):
    device = store._device
    if not rs._exists(fd, 'run_manifest.json'):
        return _unknown(rid, 'UNPUBLISHED_OR_INCOMPLETE', 'UNPUBLISHED_OR_INCOMPLETE')
    marker_size = budget.file(fd, 'run_manifest.json', device, rs.MAX_MANIFEST)
    marker = rs._read(fd, 'run_manifest.json', device, rs.MAX_MANIFEST, marker_size)
    header = rs._loads(marker)
    rs.require(marker == rs._json_bytes(header), 'NONCANONICAL_MANIFEST')
    entries = _admitted_entries(header, rid)
    budget.add(sum(x['size'] for x in entries.values()))
    journal_size = budget.file(fd, 'journal.json', device, rs.MAX_MANIFEST)
    journal = rs._read(fd, 'journal.json', device, rs.MAX_MANIFEST, journal_size)
    _same_entry(store._fd, rid, fd)
    _same_entry(fd, '.writer.lock', lock)
    _admit_core(fd, device, header, entries)
    store.expected = (rid, _identity(fd), _identity(lock))
    try:
        pub = store.open(rid)
    finally:
        store.expected = None
    rs.require(marker == rs._json_bytes(pub.manifest), 'ARTIFACT_CHANGED')
    state, generation = _portal_status(fd, device, pub, marker, budget)
    # The reader and derived verification run under the same outer shared lock.
    rs._check_dir(fd, device)
    rs._stat_file(lock, device)
    _same_entry(store._fd, rid, fd)
    _same_entry(fd, '.writer.lock', lock)
    rs.require(rs._read(fd, 'run_manifest.json', device, rs.MAX_MANIFEST, marker_size) == marker and
               rs._read(fd, 'journal.json', device, rs.MAX_MANIFEST, journal_size) == journal,
               'ARTIFACT_CHANGED')
    m = pub.manifest
    return {'run_id': rid, 'publication_status': 'PUBLISHED',
            **{key: m[key] for key in ('run_state', 'run_kind', 'recovery', 'started_at',
                                      'finished_at', 'recorded_at')},
            'source_kind': m['source']['source_kind'], 'expected_host_count': len(m['expected_host_ids']),
            'host_state_counts': {s: m['counts'][s] for s in rs.HOST_STATES},
            'missing_artifact_count': len(m['missing_artifacts']), 'manifest_sha256': rs._digest(marker),
            'portal_status': state, 'portal_generation': generation,
            'href': rid + '/index.html' if state == 'AVAILABLE' else None,
            'reason_code': 'PUBLISHED' if state == 'AVAILABLE' else 'PORTAL_' + state}


def _read_run(store, rid, budget):
    try:
        fd = rs._open_dir(store._fd, rid, store._device)
    except (rs.StoreError, OSError):
        return _unknown(rid, 'INVALID', 'UNSAFE_RUN_ENTRY')
    try:
        marker = rs._exists(fd, 'run_manifest.json')
        if not marker and not rs._exists(fd, '.writer.lock'):
            return _unknown(rid, 'UNPUBLISHED_OR_INCOMPLETE', 'UNPUBLISHED_OR_INCOMPLETE')
        with store._locked_run(rid, shared=True) as (locked, lock):
            rs.require(_identity(locked) == _identity(fd), 'ARTIFACT_CHANGED')
            return _published_row(store, rid, locked, lock, budget)
    except CapacityError:
        raise
    except rs.StoreError as exc:
        if exc.code == 'RUN_BUSY':
            return _unknown(rid, 'BUSY', 'RUN_BUSY')
        return _unknown(rid, 'INVALID', 'RUN_UNVERIFIED')
    except (OSError, evidence.EvidenceError):
        return _unknown(rid, 'INVALID', 'RUN_UNVERIFIED')
    finally:
        os.close(fd)


def _ordered(rows):
    known = sorted((r for r in rows if r['recorded_at'] is not None), key=lambda r: r['run_id'])
    known.sort(key=lambda r: evidence._timestamp_key(r['recorded_at']), reverse=True)
    return known + sorted((r for r in rows if r['recorded_at'] is None), key=lambda r: r['run_id'])


def _summary(rows):
    def counts(field, values):
        c = Counter(r[field] for r in rows)
        return {v: c[v] for v in values}
    return {'total': len(rows), 'publication': counts('publication_status', _PUBLICATIONS),
            'outcome': counts('run_state', rs.RUN_STATES), 'portal': counts('portal_status', _PORTALS)}


def _payload(rows, ignored):
    return {'catalog_version': VERSION, 'render_format': RENDER_FORMAT, 'rows': _ordered(rows),
            'summary': _summary(rows), 'diagnostics': {'ignored_entries': ignored,
            'row_reasons': dict(sorted(Counter(r['reason_code'] for r in rows).items()))}}


def _scan(store):
    candidates = []
    ignored = 0
    for name in rs._entries(store._fd, rs.MAX_ROOT_ENTRIES):
        if name in _INTERNAL:
            continue
        try:
            rs._rid(name)
        except rs.StoreError:
            ignored += 1
            continue
        candidates.append(name)
        if len(candidates) > MAX_ROWS:
            raise CapacityError('CATALOG_CAPACITY')
    collisions = Counter(x.casefold() for x in candidates)
    budget = _Budget()
    rows = [_unknown(rid, 'INVALID', 'RUN_ID_COLLISION') if collisions[rid.casefold()] > 1
            else _read_run(store, rid, budget) for rid in sorted(candidates)]
    return _payload(rows, ignored)


def _validate_row(row):
    rs._keys(row, _ROW_KEYS)
    rid = rs._rid(row['run_id'])
    status, pstatus = row['publication_status'], row['portal_status']
    rs._enum(status, _PUBLICATIONS)
    rs._enum(pstatus, _PORTALS)
    if status != 'PUBLISHED':
        rs.require(all(row[k] is None for k in _UNKNOWN_FIELDS) and pstatus == 'NOT_VERIFIED' and
                   row['portal_generation'] is None and row['href'] is None, 'INVALID_CATALOG')
        if status == 'INVALID':
            rs._enum(row['reason_code'], _INVALID_REASONS)
        else:
            rs.require(row['reason_code'] == _REASONS[status], 'INVALID_CATALOG')
        return
    rs._enum(row['run_kind'], rs.KINDS)
    rs.require(row['source_kind'] == rs.KINDS[row['run_kind']], 'INVALID_CATALOG')
    rs._enum(row['run_state'], rs.RUN_STATES)
    rs._bool(row['recovery'])
    for k in ('started_at', 'finished_at', 'recorded_at'):
        if row[k] is not None:
            evidence.STAMP.check(row[k], '$.catalog_time')
    rs._int(row['expected_host_count'], 1, 1000)
    rs._keys(row['host_state_counts'], ' '.join(rs.HOST_STATES))
    for count in row['host_state_counts'].values():
        rs._int(count, 0, 1000)
    rs.require(sum(row['host_state_counts'].values()) == row['expected_host_count'], 'INVALID_CATALOG')
    rs._int(row['missing_artifact_count'], 0, rs.MAX_SLOTS)
    rs.require(rs._match(row['manifest_sha256'], rs.HEX), 'INVALID_CATALOG')
    if pstatus == 'AVAILABLE':
        rs._enum(row['portal_generation'], ('portal-v1', 'portal-v2', 'portal-v3'))
        rs.require(row['href'] == rid + '/index.html' and row['reason_code'] == 'PUBLISHED', 'INVALID_CATALOG')
    else:
        rs.require(pstatus in ('NOT_GENERATED', 'INVALID') and row['portal_generation'] is None and
                   row['href'] is None and row['reason_code'] == 'PORTAL_' + pstatus, 'INVALID_CATALOG')


def _encoded(payload):
    generation = rs._digest(rs._json_bytes(payload, MAX_OUTPUT))
    catalog = {**payload, 'generation': generation}
    raw = rs._json_bytes(catalog, MAX_OUTPUT)
    try:
        env = Environment(loader=FileSystemLoader(str(_TEMPLATES)), autoescape=True,
                          undefined=StrictUndefined, keep_trailing_newline=True)
        out = bytearray()
        for chunk in env.get_template('catalog.html.j2').generate(c=catalog, host_states=rs.HOST_STATES):
            data = chunk.encode('utf-8')
            rs.require(len(data) <= MAX_OUTPUT - len(out), 'CATALOG_OUTPUT_LIMIT')
            out.extend(data)
        html = bytes(out)
    except (TemplateError, UnicodeError, OSError):
        raise rs.StoreError('CATALOG_RENDER_ERROR') from None
    rs.require(_MARKER.match(html) is not None and _MARKER.match(html)[1].decode() == generation,
               'CATALOG_RENDER_ERROR')
    receipt = rs._json_bytes({'catalog_version': VERSION, 'render_format': RENDER_FORMAT,
        'generation': generation, 'files': {name: {'size': len(value), 'sha256': rs._digest(value)}
        for name, value in ((JSON, raw), (SNAPSHOT, html))}}, MAX_RECEIPT)
    return generation, raw, html, receipt


def _decode(raw):
    c = rs._loads(raw, MAX_OUTPUT)
    rs._keys(c, 'catalog_version render_format generation rows summary diagnostics')
    rs.require(type(c['catalog_version']) is int and c['catalog_version'] == VERSION and
               type(c['render_format']) is int and c['render_format'] == RENDER_FORMAT and
               rs._match(c['generation'], rs.HEX), 'INVALID_CATALOG')
    rs.require(type(c['rows']) is list and len(c['rows']) <= MAX_ROWS, 'INVALID_CATALOG')
    for r in c['rows']:
        _validate_row(r)
    rs.require(len({r['run_id'] for r in c['rows']}) == len(c['rows']), 'INVALID_CATALOG')
    groups = Counter(r['run_id'].casefold() for r in c['rows'])
    rs.require(all((groups[r['run_id'].casefold()] > 1) == (r['reason_code'] == 'RUN_ID_COLLISION')
                   for r in c['rows']), 'INVALID_CATALOG')
    rs._keys(c['diagnostics'], 'ignored_entries row_reasons')
    ignored = c['diagnostics']['ignored_entries']
    rs._int(ignored, 0, rs.MAX_ROOT_ENTRIES - len(c['rows']))
    expected = _encoded(_payload(c['rows'], ignored))
    rs.require(raw == expected[1], 'INVALID_CATALOG')
    return expected


def _snapshot(fd, device, expected=None):
    rs.require(set(rs._entries(fd, 3)) == {JSON, SNAPSHOT, RECEIPT}, 'INVALID_CATALOG_SNAPSHOT')
    raw = rs._read(fd, JSON, device, MAX_OUTPUT)
    value = _decode(raw) if expected is None else expected
    rs.require(raw == value[1] and rs._read(fd, SNAPSHOT, device, MAX_OUTPUT) == value[2] and
               rs._read(fd, RECEIPT, device, MAX_RECEIPT) == value[3], 'INVALID_CATALOG_SNAPSHOT')
    return value


def _signature(fd, name, device):
    s = rs._check_file_stat(os.stat(name, dir_fd=fd, follow_symlinks=False), device)
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def _stable_slot(root, device, name, generations):
    if not rs._exists(root, name):
        return None
    signature = _signature(root, name, device)
    raw = rs._read(root, name, device, MAX_OUTPUT)
    rs.require(signature == _signature(root, name, device), 'ARTIFACT_CHANGED')
    if name == JSON:
        generation = _decode(raw)[0]
    else:
        m = _MARKER.match(raw)
        rs.require(m is not None, 'INVALID_CATALOG_SLOT')
        generation = m[1].decode('ascii')
    rs.require(generations is not None, 'INVALID_CATALOG_SNAPSHOT')
    with rs._directory(generations, (generation,), device) as fd:
        snapshot = _snapshot(fd, device)
        rs.require(snapshot[0] == generation and raw == snapshot[1 if name == JSON else 2],
                   'INVALID_CATALOG_SLOT')
        _same_entry(generations, generation, fd)
    return generation, raw, signature


def _coherent(slots):
    a, b = slots[JSON], slots[HTML]
    return a is not None and b is not None and a[0] == b[0]


def _replace_slot(root, device, name, old, new):
    rs.require(name in (JSON, HTML), 'INVALID_CATALOG_SLOT')
    if old is None:
        rs._write(root, name, new, device)
        return
    _, raw, sig = old
    def check():
        rs.require(_signature(root, name, device) == sig and
                   rs._read(root, name, device, MAX_OUTPUT) == raw and
                   _signature(root, name, device) == sig, 'ARTIFACT_CHANGED')
    check()
    if raw == new:
        return
    temp = '.catalog-tmp-' + secrets.token_hex(16)
    fd = rs._new_file(root, temp, device)
    try:
        try:
            view = memoryview(new)
            while view:
                count = os.write(fd, view)
                rs.require(count > 0, 'STORE_IO')
                view = view[count:]
            rs._sync(fd)
        finally:
            os.close(fd)
        check()
        os.replace(temp, name, src_dir_fd=root, dst_dir_fd=root)
        rs._sync(root)
    finally:
        if rs._exists(root, temp):
            os.unlink(temp, dir_fd=root)
            rs._sync(root)


def _ensure_snapshot(generations, device, value):
    generation, raw, html, receipt = value
    if not rs._exists(generations, generation):
        stage = '.stage-' + secrets.token_hex(16)
        fd = rs._mkdir(generations, stage, device)
        try:
            for name, data in ((JSON, raw), (SNAPSHOT, html), (RECEIPT, receipt)):
                rs._write(fd, name, data, device)
            _snapshot(fd, device, value)
            rs._sync(fd)
            _same_entry(generations, stage, fd)
            rs._rename_noreplace(generations, stage, generations, generation)
            rs._sync(generations)
        finally:
            os.close(fd)
    with rs._directory(generations, (generation,), device) as fd:
        _snapshot(fd, device, value)
        rs._sync(fd)
        _same_entry(generations, generation, fd)
    rs._sync(generations)


@contextmanager
def _locked_root(report_root, *, shared):
    with _CatalogStore(report_root) as store:
        fd, device = store._fd, store._device
        if shared:
            rs.require(rs._exists(fd, LOCK), 'CATALOG_RECOVERY_REQUIRED')
        lock = rs._lock_file(fd, LOCK, device, create=not shared)
        try:
            rs._flock(lock, shared=shared, wait=True)
            def check():
                store._check()
                rs._stat_file(lock, device)
                _same_entry(fd, LOCK, lock)
                current = rs._root(report_root)
                try:
                    rs.require(_identity(current) == _identity(fd), 'ARTIFACT_CHANGED')
                finally:
                    os.close(current)
            check()
            yield store, check
            check()
        finally:
            os.close(lock)


@contextmanager
def _generations(root, device):
    fd = rs._open_dir(root, GENERATIONS, device) if rs._exists(root, GENERATIONS) else None
    try:
        yield fd
    finally:
        if fd is not None:
            os.close(fd)


def _slots(root, device, generations):
    return {name: _stable_slot(root, device, name, generations) for name in (JSON, HTML)}


@contextmanager
def _history_root(report_root):
    """Pin a coherent catalog for a single opted-in portal publication.

    No catalog creation or recovery; the caller must hold no run locks on
    entry. Keep the original stable pair and generation directory identity
    checked through the renderer's final index switch.
    """
    with _locked_root(report_root, shared=True) as (store, root_check):
        with _generations(store._fd, store._device) as gen:
            slots = _slots(store._fd, store._device, gen)
            rs.require(_coherent(slots), 'CATALOG_RECOVERY_REQUIRED')
            _same_entry(store._fd, GENERATIONS, gen)
            def check():
                root_check()
                _same_entry(store._fd, GENERATIONS, gen)
                rs.require(_slots(store._fd, store._device, gen) == slots,
                           'ARTIFACT_CHANGED')
            check()
            yield store, check
            check()


@rs._public
def check_catalog(report_root):
    """Read-only stable-pair/snapshot consistency, not live run revalidation."""
    with _locked_root(report_root, shared=True) as (store, check):
        with _generations(store._fd, store._device) as gen:
            slots = _slots(store._fd, store._device, gen)
            rs.require(_coherent(slots), 'CATALOG_RECOVERY_REQUIRED')
            _same_entry(store._fd, GENERATIONS, gen)
            check()
            return slots[HTML][0]


@rs._public
def build_catalog(report_root, *, recover=False):
    """Serialize writers; validate first; publish immutable snapshot, JSON, HTML."""
    rs.require(type(recover) is bool, 'INVALID_RECOVERY_FLAG')
    with _locked_root(report_root, shared=False) as (store, check):
        root, device = store._fd, store._device
        with _generations(root, device) as existing:
            slots = _slots(root, device, existing)
            rs.require(_coherent(slots) or not any(slots.values()) or recover,
                       'CATALOG_RECOVERY_REQUIRED')
            value = _encoded(_scan(store))
            # Validate our complete payload using exactly the snapshot reader.
            rs.require(_decode(value[1]) == value, 'INVALID_CATALOG')
            check()
            gen = rs._mkdir(root, GENERATIONS, device) if existing is None else os.dup(existing)
            try:
                _same_entry(root, GENERATIONS, gen)
                _ensure_snapshot(gen, device, value)
                _same_entry(root, GENERATIONS, gen)
                check()
                rs.require(_slots(root, device, gen) == slots, 'ARTIFACT_CHANGED')
                for name, raw in ((JSON, value[1]), (HTML, value[2])):
                    _replace_slot(root, device, name, slots[name], raw)
                final = _slots(root, device, gen)
                rs.require(_coherent(final) and final[HTML][0] == value[0], 'CATALOG_RECOVERY_REQUIRED')
                _same_entry(root, GENERATIONS, gen)
                rs._sync(root)
            finally:
                os.close(gen)
    return Path(report_root) / HTML


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, 'INVALID_ARGUMENTS\n')


def main(argv=None):
    parser = _Parser(description='Build or check a private offline run catalog', allow_abbrev=False)
    parser.add_argument('--report-root', required=True)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--check', action='store_true')
    modes.add_argument('--recover', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.check:
            check_catalog(args.report_root)
        else:
            build_catalog(args.report_root, recover=args.recover)
    except rs.StoreError as exc:
        print(exc.code, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('INTERRUPTED', file=sys.stderr)
        return 1
    print('CATALOG_CONSISTENT' if args.check else 'CATALOG_PUBLISHED')
    return 0


if __name__ == '__main__':
    sys.exit(main())
