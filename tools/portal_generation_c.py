"""C-A internal payload assembler. No publication or new public trust boundary.

Call only within a trusted, pinned Store.open chain, with its unmodified
PublishedRun. A NamedTuple's type is not verification; this module does not
accept public paths, raw reports, fabricated authority or open overrides.
"""
import hashlib
from typing import NamedTuple

from tools import cbom_generation, cbom_validation, export_summary, portal_asset_indexes
from tools import portal_indexes, render_portal, run_store

_MAX_HTML = 16 * 1024 * 1024
_MAX_HTML_TOTAL = 128 * 1024 * 1024
_MAX_JSON = 32 * 1024 * 1024
_MAX_CSV = 16 * 1024 * 1024
_MAX_CSV_TOTAL = 32 * 1024 * 1024
_MAX_CBOM_PAIR = 32 * 1024 * 1024
_MAX_CBOM_TOTAL = 256 * 1024 * 1024
_MAX_BUNDLE = 512 * 1024 * 1024
_HTML = ('certificates.html', 'coverage.html', 'findings.html', 'services.html')
_JSON = ('asset_indexes.json', 'scan_summary.json')
_CSV = ('algorithms.csv', 'certificates.csv', 'summary.csv')
_DOWNLOADS = _JSON + _CSV


def _download_entry(name, raw, rid, owner=None):
    _require(type(raw) is bytes and bool(raw))
    return dict(name=name, size=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                run_id=rid, host_id=owner)


def _download_metadata(published, files, evidence_sha256):
    # Only completed, bounded B1/B2 buffers from this assembler. Never take
    # hrefs, file paths or ownership claims from a caller or decoded BOM.
    m = published.manifest
    rid, ids = m['run_id'], m['expected_host_ids']
    expected = set(_HTML + _DOWNLOADS) | {
        hid + suffix for hid in ids for suffix in ('.cbom.json', '.cbom.provenance.json')}
    _require(set(files) == expected)
    hosts = {h['host_id']: h for h in m['hosts']}
    _require(set(hosts) == set(ids) and len(hosts) == len(m['hosts']))
    pairs = {}
    for hid in ids:
        name, side = hid + '.cbom.json', hid + '.cbom.provenance.json'
        bom, provenance = files[name], files[side]
        _require(type(bom) is bytes and type(provenance) is bytes)
        _require(len(bom) + len(provenance) <= _MAX_CBOM_PAIR, 'PORTAL_PAYLOAD_SIZE_LIMIT')
        entry = _download_entry(name, bom, rid, hid)
        # Decode one host at a time; the official schema/reference validation
        # already ran before the pair entered out.files.
        component = cbom_validation._parse_bytes(bom)['metadata']['component']
        _require(component['name'] == component['bom-ref'] == hid)
        del component
        prov = cbom_validation._parse_bytes(provenance)
        _require(set(prov) == {'version', 'run_id', 'host_id', 'evidence_schema_version',
                  'source_kind', 'evidence_sha256', 'coverage', 'nodes', 'observations', 'claims',
                  'relationships', 'omitted', 'bom_sha256'}
                 and type(prov['version']) is int and prov['version'] == cbom_generation.VERSION
                 and prov['evidence_schema_version'] == m['evidence_schema_version']
                 and prov['source_kind'] == m['source']['source_kind']
                 and all(type(prov[k]) is dict for k in ('coverage', 'nodes', 'observations', 'claims'))
                 and all(type(prov[k]) is list for k in ('relationships', 'omitted')))
        coverage = prov['coverage']
        _require(prov['run_id'] == rid and prov['host_id'] == hid
                 and prov['bom_sha256'] == entry['sha256']
                 and prov['evidence_sha256'] == evidence_sha256
                 and coverage['certificate_key_scope'] == 'B2_CERTIFICATE_KEY'
                 and coverage['host_state'] == hosts[hid]['host_state']
                 and coverage['attempted'] is hosts[hid]['attempted']
                 and coverage['run_state'] == m['run_state']
                 and coverage['recovery'] is m['recovery']
                 and coverage['assessment_saved'] is (published.assessed is not None)
                 and coverage['missing_artifact_count'] == len(m['missing_artifacts'])
                 and type(coverage['certificate_collections']) is list)
        del coverage, prov
        pairs[hid] = (entry, _download_entry(side, provenance, rid, hid))
    return tuple(_download_entry(name, files[name], rid) for name in sorted(_DOWNLOADS)), pairs


class _RenderPayload(NamedTuple):
    run_id: str
    index: bytes
    css: bytes
    files: dict
    entries: tuple


class _Payload(NamedTuple):
    run_id: str
    files: dict
    entries: tuple


def _require(ok, code='PORTAL_PAYLOAD_INVALID'):
    run_store.require(ok, code)


class _Buffers:
    def __init__(self):
        self.files = {}
        self.total = self.html = self.csv = self.cbom = 0

    def add(self, name, raw, cap):
        _require(name not in self.files and type(raw) is bytes and bool(raw))
        _require(len(raw) <= cap and len(raw) <= _MAX_BUNDLE - self.total,
                 'PORTAL_PAYLOAD_SIZE_LIMIT')
        self.files[name] = raw
        self.total += len(raw)

    def page(self, name, raw):
        _require(name in _HTML)
        self.add(name, raw, min(_MAX_HTML, _MAX_HTML_TOTAL - self.html))
        self.html += len(raw)

    def json(self, name, raw):
        _require(name in _JSON)
        self.add(name, raw, _MAX_JSON)

    def export(self, name, raw):
        _require(name in _CSV)
        self.add(name, raw, min(_MAX_CSV, _MAX_CSV_TOTAL - self.csv))
        self.csv += len(raw)

    def pair_limit(self):
        return min(_MAX_CBOM_PAIR, _MAX_CBOM_TOTAL - self.cbom, _MAX_BUNDLE - self.total)

    def pair(self, hid, bom, provenance):
        _require(type(bom) is bytes and type(provenance) is bytes)
        size = len(bom) + len(provenance)
        _require(size <= self.pair_limit(), 'PORTAL_PAYLOAD_SIZE_LIMIT')
        self.add(hid + '.cbom.json', bom, _MAX_CBOM_PAIR)
        self.add(hid + '.cbom.provenance.json', provenance, _MAX_CBOM_PAIR)
        self.cbom += size


def _assemble(published, *, portal_v5=False, complete=False, navigation=False, reverse_pivots=False):
    _require(type(reverse_pivots) is bool and (not reverse_pivots or navigation)
             and type(navigation) is bool and (not navigation or complete)
             and type(portal_v5) is bool and type(complete) is bool and (not complete or portal_v5)
             and type(published) is run_store.PublishedRun)
    m, doc, _, _ = published
    rid = run_store._rid(m['run_id'])
    ids = m['expected_host_ids']
    _require(m['publication_state'] == 'PUBLISHED' and rid == doc['run']['run_id']
             and type(ids) is list and 0 < len(ids) <= 1000)
    for hid in ids:
        run_store._id(hid)
    _require(ids == sorted(set(ids)) and ids == doc['run']['expected_host_ids'])
    expected = set(_HTML + _JSON + _CSV)
    for hid in ids:
        expected.update((hid + '.cbom.json', hid + '.cbom.provenance.json'))

    # C2 has its own #21 membership validation. Compute that projection once,
    # then share one additional #21 projection across A and all host BOMs.
    if portal_v5:
        assets, asset_pages = portal_asset_indexes._render_asset_indexes(
            published, portal_v5=True, page_limit=_MAX_HTML,
            total_limit=min(_MAX_HTML_TOTAL, _MAX_BUNDLE))
    else:
        assets, asset_pages = portal_asset_indexes.render_asset_indexes(published)
    crypto = portal_indexes.project_crypto_indexes(published)
    projected_summary = export_summary._project_scan_summary(published, crypto=crypto)
    out = _Buffers()
    if portal_v5:
        # Charge the two existing asset pages before streaming summary HTML.
        for name, raw in asset_pages.items():
            out.page(name, raw)
        summary, summary_pages, exports = export_summary._render_summary_projection(
            projected_summary, portal_v5=True, page_limit=_MAX_HTML,
            html_limit=_MAX_HTML_TOTAL - out.html, bundle_limit=_MAX_BUNDLE - out.total)
    else:
        summary, summary_pages, exports = export_summary._render_summary_projection(projected_summary)
    _require(assets['run_id'] == crypto['run_id'] == summary['run']['run_id'] == rid
             and set(assets['hosts']) == set(summary['expected_host_ids']) == set(ids)
             and assets['assessed'] == crypto['assessed'] == summary['assessed'])
    _require(set(asset_pages) == {'certificates.html', 'services.html'}
             and set(summary_pages) == {'findings.html', 'coverage.html'}
             and set(exports) == {'scan_summary.json', 'summary.csv', 'algorithms.csv'})
    if not portal_v5:
        for name, raw in asset_pages.items():
            out.page(name, raw)
    for name, raw in summary_pages.items():
        out.page(name, raw)
    out.json('asset_indexes.json', portal_asset_indexes._bounded_bytes(assets))
    out.json('scan_summary.json', exports['scan_summary.json'])
    for name in ('summary.csv', 'algorithms.csv'):
        out.export(name, exports[name])
    out.export('certificates.csv', export_summary._render_certificate_projection(
        assets, rid, limit=min(_MAX_CSV, _MAX_CSV_TOTAL - out.csv, _MAX_BUNDLE - out.total)))

    batch = cbom_generation._BatchInputs(published, crypto, assets)
    for hid in ids:
        # Bound each next pair by all remaining budgets before serializing it.
        _require(out.pair_limit() > 0, 'PORTAL_PAYLOAD_SIZE_LIMIT')
        bom, provenance = cbom_generation._build_cbom_projection_bytes(
            published, hid, include_certificates=True, batch=batch, limit=out.pair_limit())
        out.pair(hid, bom, provenance)
    _require(out.files.keys() == expected)
    if complete:
        downloads = (_download_metadata(published, out.files, batch.evidence_sha256)
                     if navigation else None)
        index, css, core = render_portal._render_v5_core(
            published, crypto, page_limit=_MAX_HTML, html_limit=_MAX_HTML_TOTAL - out.html,
            bundle_limit=_MAX_BUNDLE - out.total, json_limit=_MAX_JSON, downloads=downloads,
            reverse_inputs=(assets, summary) if reverse_pivots else None)
        core_html = {'hosts.html', 'algorithms.html', 'libraries.html'} | {hid + '.html' for hid in ids}
        _require(set(core) == core_html | {'crypto_indexes.json'} and not (set(core) & expected))
        out.add('portal.css', css, render_portal._MAX_CSS)
        out.add('crypto_indexes.json', core['crypto_indexes.json'], _MAX_JSON)
        for name, raw in [('index.html', index)] + [(name, core[name]) for name in sorted(core_html)]:
            out.add(name, raw, min(_MAX_HTML, _MAX_HTML_TOTAL - out.html))
            out.html += len(raw)
        _require(set(out.files) == expected | set(core) | {'index.html', 'portal.css'})
        files = dict(sorted((name, raw) for name, raw in out.files.items()
                            if name not in ('index.html', 'portal.css')))
        _require(len(files) == 13 + 3 * len(ids))
        entries = _entries({'index.html': index, 'portal.css': css,
                            **{'portal-v5/' + name: raw for name, raw in files.items()}})
        return _RenderPayload(rid, index, css, files, entries)
    files = dict(sorted(out.files.items()))
    return _Payload(rid, files, _entries(files))


def _entries(files):
    return tuple(dict(name=name, size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
                 for name, raw in sorted(files.items()))


def _assemble_payload(published, *, portal_v5=False):
    """Return all fixed payload bytes and sorted metadata, or a fixed error.

    No partial result escapes on failure. Existing preview/public APIs and
    their error contracts are unchanged. C-B/C-C own navigation, receipt,
    publication and catalog admission; these buffers are not a generation.
    The private exact boolean selects only the four V5 asset and summary HTML pages.
    """
    return _checked_assemble(published, portal_v5=portal_v5)


def _assemble_v5_render_payload(published, *, navigation=False, reverse_pivots=False):
    """Internal complete render buffers for a pinned verified publication.

    No generation marker, receipt, catalog operation or file write.
    """
    return _checked_assemble(published, portal_v5=True, complete=True, navigation=navigation,
                             reverse_pivots=reverse_pivots)


def _checked_assemble(published, *, portal_v5, complete=False, navigation=False, reverse_pivots=False):
    try:
        return _assemble(published, portal_v5=portal_v5, complete=complete, navigation=navigation,
                         reverse_pivots=reverse_pivots)
    except (run_store.StoreError, cbom_generation.CBOMGenerationError) as exc:
        if exc.code in ('PORTAL_PAYLOAD_SIZE_LIMIT', 'SUMMARY_SIZE_LIMIT', 'ASSET_INDEX_SIZE_LIMIT',
                        'CRYPTO_INDEX_SIZE_LIMIT', 'CBOM_SIZE_LIMIT', 'CBOM_MEMBERSHIP_LIMIT', 'PORTAL_SIZE_LIMIT'):
            code = 'PORTAL_PAYLOAD_SIZE_LIMIT'
        else:
            code = 'PORTAL_PAYLOAD_INVALID'
    except (cbom_validation.CBOMValidationError, ImportError):
        code = 'PORTAL_PAYLOAD_INVALID'
    except (ValueError, TypeError, KeyError, AttributeError, IndexError, OSError, OverflowError, RecursionError):
        code = 'PORTAL_PAYLOAD_INVALID'
    raise run_store.StoreError(code) from None
