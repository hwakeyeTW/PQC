"""C-A internal payload assembler. No publication or new public trust boundary.

Call only within a trusted, pinned Store.open chain, with its unmodified
PublishedRun. A NamedTuple's type is not verification; this module does not
accept public paths, raw reports, fabricated authority or open overrides.
"""
import hashlib
from typing import NamedTuple

from tools import cbom_generation, cbom_validation, export_summary, portal_asset_indexes
from tools import portal_indexes, run_store

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


def _assemble(published):
    _require(type(published) is run_store.PublishedRun)
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
    assets, asset_pages = portal_asset_indexes.render_asset_indexes(published)
    crypto = portal_indexes.project_crypto_indexes(published)
    summary, summary_pages, exports = export_summary._render_summary_projection(
        export_summary._project_scan_summary(published, crypto=crypto))
    _require(assets['run_id'] == crypto['run_id'] == summary['run']['run_id'] == rid
             and set(assets['hosts']) == set(summary['expected_host_ids']) == set(ids)
             and assets['assessed'] == crypto['assessed'] == summary['assessed'])
    _require(set(asset_pages) == {'certificates.html', 'services.html'}
             and set(summary_pages) == {'findings.html', 'coverage.html'}
             and set(exports) == {'scan_summary.json', 'summary.csv', 'algorithms.csv'})
    out = _Buffers()
    for name, raw in (*asset_pages.items(), *summary_pages.items()):
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
    files = dict(sorted(out.files.items()))
    entries = tuple(dict(name=name, size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
                    for name, raw in files.items())
    return _Payload(rid, files, entries)


def _assemble_payload(published):
    """Return all fixed payload bytes and sorted metadata, or a fixed error.

    No partial result escapes on failure. Existing preview/public APIs and
    their error contracts are unchanged. C-B/C-C own navigation, receipt,
    publication and catalog admission; these buffers are not a generation.
    """
    try:
        return _assemble(published)
    except (run_store.StoreError, cbom_generation.CBOMGenerationError) as exc:
        if exc.code in ('PORTAL_PAYLOAD_SIZE_LIMIT', 'SUMMARY_SIZE_LIMIT', 'ASSET_INDEX_SIZE_LIMIT',
                        'CRYPTO_INDEX_SIZE_LIMIT', 'CBOM_SIZE_LIMIT', 'CBOM_MEMBERSHIP_LIMIT'):
            code = 'PORTAL_PAYLOAD_SIZE_LIMIT'
        else:
            code = 'PORTAL_PAYLOAD_INVALID'
    except (cbom_validation.CBOMValidationError, ImportError):
        code = 'PORTAL_PAYLOAD_INVALID'
    except (ValueError, TypeError, KeyError, AttributeError, IndexError, OSError, OverflowError, RecursionError):
        code = 'PORTAL_PAYLOAD_INVALID'
    raise run_store.StoreError(code) from None
