"""Read-only findings, coverage and exports of a verified RunStore.open result.

Counts describe recorded sets and frozen request scope, not PQC readiness.
The caller owns publication; this preview API never writes to a report root.
"""
from collections import Counter, defaultdict
import csv
import json
from pathlib import Path
import re
import unicodedata

from jinja2 import Environment, FileSystemLoader, StrictUndefined, TemplateError

from tools import evidence, portal_indexes, run_store

_TEMPLATES = Path(__file__).resolve().parents[1] / 'templates' / 'portal'
_MAX_JSON = 32 * 1024 * 1024
_MAX_HTML = 16 * 1024 * 1024
_MAX_CSV = 16 * 1024 * 1024
_MAX_CSV_TOTAL = 32 * 1024 * 1024
_MAX_MEMBERSHIPS = (32 * 1024 * 1024) // 66
_SUMMARY_COLUMNS = ('run_id', 'dimension', 'group_id', 'metric', 'state', 'count',
                    'denominator', 'reason_code')
_ALGORITHM_COLUMNS = ('run_id', 'algorithm_group_id', 'algorithm_id', 'classification',
    'family', 'primitive', 'taxonomy_version', 'metric', 'level', 'state', 'observed_name',
    'source_kind', 'producer_id', 'producer_version', 'collector_id', 'count', 'denominator')
_ATTEMPTS = ('ATTEMPTED', 'NOT_ATTEMPTED', 'UNKNOWN', 'NOT_APPLICABLE')


def _require(ok, code='INVALID_SUMMARY_PUBLICATION'):
    run_store.require(ok, code)


def _id(value, kind):
    _require(type(value) is str and re.fullmatch(evidence.PREFIXES[kind] + r'[0-9a-f]{64}', value))
    return value


def _href(host, ref=None, kind='host'):
    return _id(host, 'host') + '.html#' + _id(host if ref is None else ref, kind)


def _source(row):
    return {k: row[k] for k in ('source_kind', 'producer_id', 'producer_version',
                                'origin_ref', 'input_sha256')}


class _Budget:
    def __init__(self):
        self.used = 0

    def charge(self, count=1):
        self.used += count
        _require(self.used <= _MAX_MEMBERSHIPS, 'SUMMARY_SIZE_LIMIT')

    def refs(self, refs):
        self.charge(len(refs))
        return sorted(set(refs))


class _Bytes:
    def __init__(self, cap):
        self.cap, self.data = cap, bytearray()

    def write(self, text):
        raw = text.encode('utf-8')
        _require(len(raw) <= self.cap - len(self.data), 'SUMMARY_SIZE_LIMIT')
        self.data.extend(raw)
        return len(text)

    def finish(self):
        return bytes(self.data)


def _json_bytes(p):
    out = _Bytes(_MAX_JSON)
    for chunk in json.JSONEncoder(ensure_ascii=True, sort_keys=True, separators=(',', ':'),
                                  allow_nan=False).iterencode(p):
        out.write(chunk)
    return out.finish()


def _collector_attempt(host, requested, row):
    # A host intent/attempt is not evidence of a collector attempt. A recorded
    # terminal return code or acquisition ref is evidence of a result, not
    # proof that a particular command was launched or safely cleaned up.
    if not requested or host['attempt_status'] == 'NOT_ATTEMPTED' or host['host_state'] == 'UNREACHABLE':
        return 'NOT_ATTEMPTED'
    if row is None:
        return 'UNKNOWN'
    if row['state'] in ('NOT_SCANNED', 'UNREACHABLE') or row['reason_code'] == 'CONNECTION_TIMEOUT':
        return 'NOT_ATTEMPTED'
    if row['state'] != 'NOT_APPLICABLE' and (row['rc'] is not None or row['collection_ids']):
        return 'ATTEMPTED'
    return 'UNKNOWN'


class _Projection:
    def __init__(self, published, *, crypto=None):
        # As in #21, this API is not an authenticator for a caller-created
        # NamedTuple. Supply the unmodified result of trusted RunStore.open.
        _require(type(published) is run_store.PublishedRun)
        m, doc, assessed, artifacts = published
        ids = m['expected_host_ids']
        _require(m['run_id'] == doc['run']['run_id'] and 0 < len(ids) <= 1000 and
                 ids == sorted(set(ids)) and set(ids) == set(doc['run']['expected_host_ids']))
        for name in ('evidence.json', *(['assessed_evidence.json'] if assessed is not None else [])):
            _require(type(artifacts.get(name)) is bytes and 0 < len(artifacts[name]) <= evidence.MAX_BYTES)
        self.published, self.m, self.doc, self.saved = published, m, doc, assessed
        self._crypto = crypto
        self.b = _Budget()
        self.b.charge(len(ids))
        self.host_ids = list(ids)
        self.metrics, self.algorithm_rows = [], []
        self.hosts, self.collections, self.assets, self.rows, self.claims = {}, {}, {}, {}, {}
        self.findings = None if assessed is None else {}
        self.terminals, self.artifacts, self.missing = [], [], []
        self.algorithms, self.unresolved = [], []
        self.flags_known = m['flags'] is not None

    def metric(self, dimension, group, metric, state, count, denominator, reason=None):
        self.b.charge()
        self.metrics.append(dict(dimension=dimension, group_id=group, metric=metric,
            state=state, count=count, denominator=denominator, reason_code=reason))

    def states(self, dimension, group, metric, states, values, denominator):
        counts = Counter(values) if denominator is not None else None
        for state in states:
            self.metric(dimension, group, metric, state,
                        None if counts is None else counts[state], denominator)

    def recorded(self, dimension, group, collections, assets, rows, claims):
        # These lists are generated from unique indexed IDs. A collection may
        # appear under several assets; those group counts are not additive.
        total = len(collections)
        self.states(dimension, group, 'acquisition', evidence.ACQUISITIONS,
                    (c['collection_state'] for c in collections), total)
        for (state, reason), n in sorted(Counter((c['collection_state'], c['reason_code'])
                                                 for c in collections).items()):
            self.metric(dimension, group, 'acquisition_reason', state, n, total, reason)
        self.metric(dimension, group, 'known_assets', 'RECORDED', len(assets), len(assets))
        self.metric(dimension, group, 'evidence', 'RECORDED', len(rows), None)
        self.metric(dimension, group, 'assessed_claims', 'NOT_ASSESSED' if self.saved is None else 'RECORDED',
                    None if self.saved is None else len(claims), None if self.saved is None else len(claims))
        levels = defaultdict(list)
        for cl in claims:
            levels[cl['level']].append(cl['assessment_state'])
        for level in evidence.LEVELS:
            values = levels[level]
            self.states(dimension, group, level, evidence.ASSESSMENTS, values,
                        None if self.saved is None else len(values))

    def index(self):
        # Do not copy raw data, asset identity keys, evidence payloads, conditions
        # or artifact bytes. All links are to existing fixed-ID host anchors.
        for h in self.m['hosts']:
            self.b.charge()
            hid = _id(h['host_id'], 'host')
            self.hosts[hid] = {k: h[k] for k in ('host_id', 'target_id', 'host_state', 'reason_code',
                'attempted', 'attempt_status', 'dispatch_intent')} | {'href': _href(hid)}
        _require(set(self.hosts) == set(self.host_ids))
        for c in self.doc['collections']:
            self.b.charge()
            cid, hid = _id(c['collection_id'], 'collection'), c['host_id']
            self.collections[cid] = {k: c[k] for k in ('collection_id', 'host_id', 'collector_id',
                'collector_version', 'collection_state', 'reason_code', 'observed_at')} | dict(
                source=_source(c['source']), evidence_ids=self.b.refs(c['evidence_ids']),
                href=_href(hid, cid, 'collection'))
        for r in self.doc['evidence']:
            self.b.charge()
            eid, hid = _id(r['evidence_id'], 'evidence'), r['host_id']
            self.rows[eid] = {k: r[k] for k in ('evidence_id', 'host_id', 'collection_id',
                'asset_id', 'evidence_kind')} | dict(source=_source(r['source']), href=_href(hid, eid, 'evidence'))
        for a in self.doc['assets']:
            self.b.charge()
            aid, hid = _id(a['asset_id'], 'asset'), a['host_id']
            refs = self.b.refs(a['evidence_ids'])
            cids = self.b.refs({self.rows[eid]['collection_id'] for eid in refs})
            self.assets[aid] = {k: a[k] for k in ('asset_id', 'host_id', 'asset_kind', 'identity_scope')} | dict(
                evidence_ids=refs, collection_ids=cids, href=_href(hid, aid, 'asset'))
        if self.saved is not None:
            for c in self.saved['claims']:
                self.b.charge()
                cid, subject = _id(c['claim_id'], 'claim'), dict(c['subject'])
                self.claims[cid] = {k: c[k] for k in ('claim_id', 'level', 'assessment_state',
                    'reason_code', 'rule_id', 'rule_version')} | dict(subject=subject,
                    evidence_ids=self.b.refs(c['evidence_ids']), href=_href(subject['host_id'], cid, 'claim'))
            for f in self.saved['findings']:
                self.b.charge()
                fid, subject = _id(f['finding_id'], 'finding'), dict(f['subject'])
                self.findings[fid] = {k: f[k] for k in ('finding_id', 'condition_key', 'rule_id',
                    'rule_version', 'assessment_state', 'reason_code')} | dict(subject=subject,
                    claim_ids=self.b.refs(f['claim_ids']), evidence_ids=self.b.refs(f['evidence_ids']),
                    href=_href(subject['host_id'], fid, 'finding'))

    def requests(self):
        by_collector = defaultdict(list)
        by_host = defaultdict(list)
        if self.flags_known:
            for h in sorted(self.m['hosts'], key=lambda h: h['host_id']):
                hid = h['host_id']
                terminal = {} if h['terminal'] is None else {
                    run_store.NATIVE_COLLECTORS.get(r['collector_id'], r['collector_id']): r
                    for r in h['terminal']['collectors']}
                for collector in sorted(run_store.COLLECTORS):
                    self.b.charge()
                    requested = self.m['flags'][hid][collector]
                    row = terminal.get(collector)
                    _require(row is None or row['requested'] is requested)
                    record = dict(host_id=hid, collector_id=collector, requested=requested,
                        terminal_present=row is not None, state=None if row is None else row['state'],
                        reason_code=None if row is None else row['reason_code'], rc=None if row is None else row['rc'],
                        collection_ids=None if row is None else self.b.refs(row['collection_ids']),
                        attempt_status=_collector_attempt(h, requested, row))
                    self.terminals.append(record)
                    by_collector[collector].append(record)
                    by_host[hid].append(record)
        groups = [('collector_request', 'all', self.terminals)]
        groups += [('collector_request', c, by_collector[c]) for c in sorted(run_store.COLLECTORS)]
        groups += [('host_request', hid, by_host[hid]) for hid in self.host_ids]
        for dimension, group, rows in groups:
            denom = len(rows) if self.flags_known else None
            requested = [r for r in rows if r['requested']]
            self.metric(dimension, group, 'expected_slots', 'KNOWN' if self.flags_known else 'UNKNOWN', denom, denom)
            self.states(dimension, group, 'request', ('REQUESTED', 'DISABLED'),
                        ('REQUESTED' if r['requested'] else 'DISABLED' for r in rows), denom)
            self.states(dimension, group, 'terminal', ('PRESENT', 'MISSING'),
                        ('PRESENT' if r['terminal_present'] else 'MISSING' for r in rows), denom)
            n = len(requested) if self.flags_known else None
            self.states(dimension, group, 'requested_attempt', _ATTEMPTS[:3],
                        (r['attempt_status'] for r in requested), n)
            self.states(dimension, group, 'requested_state', (*evidence.ACQUISITIONS, 'MISSING_TERMINAL'),
                        (r['state'] or 'MISSING_TERMINAL' for r in requested), n)
            for (state, reason), count in sorted(Counter((r['state'] or 'MISSING_TERMINAL',
                    r['reason_code'] or 'MISSING_TERMINAL') for r in requested).items()):
                self.metric(dimension, group, 'requested_reason', state, count, n, reason)

    def coverage(self):
        hosts = list(self.hosts.values()); n = len(hosts)
        self.states('host', 'all', 'host_state', evidence.HOST_STATES, (h['host_state'] for h in hosts), n)
        self.states('host', 'all', 'attempt_status', _ATTEMPTS, (h['attempt_status'] for h in hosts), n)
        self.states('host', 'all', 'dispatch_intent', ('INTENT', 'NO_INTENT', 'UNKNOWN'),
                    ('UNKNOWN' if h['dispatch_intent'] is None else 'INTENT' if h['dispatch_intent'] else 'NO_INTENT'
                     for h in hosts), n)
        self.metric('host', 'all', 'completed_attempts', 'COMPLETE', None if not self.flags_known else
                    sum(h['host_state'] == 'COMPLETE' and h['attempt_status'] == 'ATTEMPTED' for h in hosts), n)
        for (state, reason), count in sorted(Counter((h['host_state'], h['reason_code']) for h in hosts).items()):
            self.metric('host', 'all', 'host_reason', state, count, n, reason)
        registries = (self.collections, self.assets, self.rows, self.claims)
        by_host = defaultdict(lambda: [[], [], [], []])
        for i, registry in enumerate(registries):
            for row in registry.values():
                hid = row['subject']['host_id'] if i == 3 else row['host_id']
                by_host[hid][i].append(row)
        self.recorded('recorded', 'all', *(list(x.values()) for x in registries))
        for hid in self.host_ids:
            h = self.hosts[hid]
            self.metric('host', hid, 'host_state', h['host_state'], 1, 1, h['reason_code'])
            self.metric('host', hid, 'attempt_status', h['attempt_status'], 1, 1)
            intent = h['dispatch_intent']
            self.metric('host', hid, 'dispatch_intent',
                        'UNKNOWN' if intent is None else 'INTENT' if intent else 'NO_INTENT', 1, 1)
            self.recorded('host', hid, *by_host[hid])
        by_collector = defaultdict(list)
        for c in self.collections.values():
            by_collector[c['collector_id']].append(c)
        # A claim can refer to multiple collectors, and an asset can occur in
        # several scopes. Count each ID once within the actual group.
        collector_claims = defaultdict(set)
        for cid, claim in self.claims.items():
            for collector in {self.collections[self.rows[eid]['collection_id']]['collector_id']
                              for eid in claim['evidence_ids']}:
                self.b.charge(); collector_claims[collector].add(cid)
        for (kind, producer, version), count in sorted(Counter((c['source']['source_kind'], c['source']['producer_id'],
                c['source']['producer_version']) for c in self.collections.values()).items(),
                key=lambda item: tuple(v or '' for v in item[0])):
            self.metric('source', kind + ':' + producer, 'producer_version', version, count, len(self.collections))
        for collector, cols in sorted(by_collector.items()):
            refs = {eid for c in cols for eid in c['evidence_ids']}
            rows = [self.rows[eid] for eid in refs]
            aids = {r['asset_id'] for r in rows if r['asset_id'] is not None}
            self.recorded('collector_recorded', collector, cols, [self.assets[aid] for aid in aids], rows,
                          [self.claims[cid] for cid in collector_claims[collector]])
        by_asset = defaultdict(list)
        for c in self.claims.values():
            if c['subject'].get('asset_id') is not None:
                by_asset[c['subject']['asset_id']].append(c)
        kinds = defaultdict(list)
        for aid, a in sorted(self.assets.items()):
            kinds[a['asset_kind']].append(a)
            self.recorded('asset', aid, [self.collections[cid] for cid in a['collection_ids']], [a],
                          [self.rows[eid] for eid in a['evidence_ids']], by_asset[aid])
        for kind, assets in sorted(kinds.items()):
            self.metric('asset_kind', kind, 'known_population', 'RECORDED', len(assets), len(self.assets))
            cids = {cid for a in assets for cid in a['collection_ids']}
            eids = {eid for a in assets for eid in a['evidence_ids']}
            self.recorded('asset_kind', kind, [self.collections[cid] for cid in cids], assets,
                          [self.rows[eid] for eid in eids], [c for a in assets for c in by_asset[a['asset_id']]])
        values = [] if self.findings is None else list(self.findings.values())
        self.states('finding', 'all', 'finding_state', evidence.ASSESSMENTS,
                    (f['assessment_state'] for f in values), None if self.findings is None else len(values))
        self.metric('finding', 'all', 'finding_total', 'NOT_ASSESSED' if self.findings is None else 'RECORDED',
                    None if self.findings is None else len(values), None if self.findings is None else len(values))

    def artifact_status(self):
        for row in self.m['artifacts']:
            self.b.charge()
            parts, _ = run_store._slot(row['kind'], row['host_id'], row['slot'],
                                       producer_v2=run_store._is_producer_v2(self.m))
            _require('/'.join(parts) == row['path'] and row['path'] in self.published.artifacts)
            record = {k: row[k] for k in ('kind', 'format_version', 'host_id', 'slot', 'required', 'sha256')}
            for field, registry in (('collection_ids', self.collections), ('asset_ids', self.assets), ('evidence_ids', self.rows)):
                _require(all(ref in registry for ref in row[field]))
                record[field] = self.b.refs(row[field])
            self.artifacts.append(record)
        for row in self.m['missing_artifacts']:
            self.b.charge()
            # Original closed Store slot path is status only, never a link.
            self.missing.append(dict(path=row['path'], reason_code=row['reason_code']))
        self.metric('artifact', 'all', 'present', 'VERIFIED', len(self.artifacts), None)
        self.metric('artifact', 'all', 'missing', 'MISSING', len(self.missing), None)
        for reason, count in sorted(Counter(r['reason_code'] for r in self.missing).items()):
            self.metric('artifact', 'all', 'missing_reason', 'MISSING', count, len(self.missing), reason)
        self.metric('artifact', 'all', 'unresolved_references', 'RECORDED', 0, None)

    def algorithm_row(self, group, metric, count, denominator, **fields):
        self.b.charge()
        self.algorithm_rows.append(dict(algorithm_group_id=group.get('id'),
            **{k: group.get(k) for k in ('algorithm_id', 'classification', 'family', 'primitive', 'taxonomy_version')},
            metric=metric, count=count, denominator=denominator, **fields))

    def crypto(self):
        # #21 owns all classification/group membership decisions. Reuse it
        # once; export only its IDs, taxonomy, observed names and safe context.
        crypto = self._crypto if self._crypto is not None else portal_indexes.project_crypto_indexes(self.published)
        _require(crypto['run_id'] == self.m['run_id'])
        index = crypto['algorithms']
        self.unresolved = self.b.refs(index['unresolved_claim_ids'])
        for g in index['groups']:
            self.b.charge()
            group = {k: g[k] for k in ('id', 'algorithm_id', 'classification', 'family', 'primitive', 'taxonomy_version')}
            _require(re.fullmatch(r'alg-[0-9a-f]{64}', group['id']) is not None)
            for field in ('host_ids', 'asset_ids', 'evidence_ids', 'claim_ids', 'observed_names'):
                group[field] = self.b.refs(g[field])
            self.algorithms.append(group)
            for field in ('host_ids', 'asset_ids', 'evidence_ids', 'claim_ids'):
                self.algorithm_row(group, field, None if field == 'claim_ids' and self.saved is None
                                   else len(group[field]), None)
            # Evidence that #21 attached to a group via a saved claim is still
            # recorded evidence; it is not an extra inferred algorithm name.
            contexts = Counter()
            names = Counter()
            for eid in group['evidence_ids']:
                row = self.rows[eid]; c = self.collections[row['collection_id']]
                s = row['source']
                contexts[(s['source_kind'], s['producer_id'], s['producer_version'], c['collector_id'])] += 1
                name = self._observed.get(eid)
                if name is not None:
                    names[name] += 1
            for name in group['observed_names']:
                self.algorithm_row(group, 'observed_name', names[name], len(group['evidence_ids']), observed_name=name)
            for context, count in sorted(contexts.items(), key=lambda x: tuple(v or '' for v in x[0])):
                self.algorithm_row(group, 'source_context', count, len(group['evidence_ids']),
                    **dict(zip(('source_kind', 'producer_id', 'producer_version', 'collector_id'), context)))
            group['levels'] = {}
            for level in evidence.LEVELS:
                data = g['levels'][level]
                result = {}
                for metric, key in (('observation', 'observations'), ('claim', 'claims')):
                    result[key] = {s: self.b.refs(ids) for s, ids in data[key].items()}
                    denom = sum(len(ids) for ids in result[key].values())
                    if metric == 'claim' and self.saved is None:
                        self.algorithm_row(group, metric, None, None, level=level, state='NOT_ASSESSED')
                    elif result[key]:
                        for state, ids in sorted(result[key].items()):
                            self.algorithm_row(group, metric, len(ids), denom, level=level, state=state)
                    else:
                        self.algorithm_row(group, metric, 0, 0, level=level, state='NONE_RECORDED')
                group['levels'][level] = result
        self.algorithm_row({}, 'unresolved_claims', None if self.saved is None else len(self.unresolved), None)
        self.metric('algorithm', 'all', 'groups', 'RECORDED', len(self.algorithms), None)
        self.metric('algorithm', 'all', 'unresolved_claims', 'NOT_ASSESSED' if self.saved is None else 'RECORDED',
                    None if self.saved is None else len(self.unresolved), None)

    def finish(self):
        self.index(); self.requests(); self.coverage(); self.artifact_status()
        self._observed = {r['evidence_id']: r['algorithm']['observed_name']
                          for r in self.doc['evidence'] if r['algorithm'] is not None}
        self.crypto()
        run = {k: self.m[k] for k in ('run_id', 'run_kind', 'run_state', 'reason_code', 'recovery',
            'evidence_schema_version', 'rule_version', 'rules_sha256', 'batch_contract')}
        run['source'] = _source(self.m['source'])
        for field in ('evidence_schema_version', 'rule_version', 'batch_contract'):
            self.metric('metadata', 'run', field, run[field], None, None)
        self.metric('metadata', run['source']['producer_id'], 'source_version', run['source']['producer_version'], None, None)
        return dict(projection_version=1, run=run, expected_host_ids=self.host_ids,
            flags_known=self.flags_known, assessed=self.saved is not None, hosts=self.hosts,
            collector_rows=self.terminals, collections=self.collections, assets=self.assets, evidence=self.rows,
            claims=None if self.saved is None else self.claims, findings=self.findings,
            artifacts=self.artifacts, missing_artifacts=self.missing, unresolved_artifact_refs=[],
            algorithms=self.algorithms, unresolved_algorithm_claim_ids=self.unresolved,
            metrics=self.metrics, algorithm_rows=self.algorithm_rows)


def project_scan_summary(published):
    """Return a bounded deterministic projection, with no reassessment or I/O."""
    return _project_scan_summary(published)


def _project_scan_summary(published, *, crypto=None):
    # Private reuse within one already verified publication; no trust witness.
    result = _Projection(published, crypto=crypto).finish()
    _json_bytes(result)
    return result


def _csv_text(value):
    if value is None:
        return ''
    _require(type(value) is str)
    # Inspect the ORIGINAL leading characters before escaping controls. A BOM,
    # whitespace or invisible format character must not mask a formula prefix.
    def hidden(c):
        return c.isspace() or unicodedata.category(c) in ('Cc', 'Cf', 'Cs')
    i = 0
    while i < len(value) and hidden(value[i]):
        i += 1
    formula = bool(value and (value[0] in '\t\r\n' or
                   (i < len(value) and value[i] in '=+-@\uff1d\uff0b\uff0d\uff20')))
    clean = ''.join('\\u%04x' % ord(c) if unicodedata.category(c) in ('Cc', 'Cf', 'Cs') else c for c in value)
    return ("'" if formula else '') + clean


def _csv_number(value):
    _require(value is None or (type(value) is int and 0 <= value <= 9007199254740991))
    return '' if value is None else str(value)


def _csv_bytes(run_id, columns, rows):
    out = _Bytes(_MAX_CSV)
    out.write('\ufeff')
    writer = csv.writer(out, quoting=csv.QUOTE_ALL, lineterminator='\r\n')
    writer.writerow(columns)
    for row in rows:
        values = {'run_id': run_id, **row}
        _require(values.keys() <= set(columns))
        writer.writerow([(_csv_number if k in ('count', 'denominator') else _csv_text)(values.get(k))
                         for k in columns])
    return out.finish()


def render_summary_exports(published):
    """Return (projection, two fixed HTML byte streams, three fixed exports)."""
    return _render_summary_projection(project_scan_summary(published))


def _render_summary_projection(p):
    # The caller owns the bounded projection derived from the verified run.
    rid = p['run']['run_id']
    exports = {'scan_summary.json': _json_bytes(p),
               'summary.csv': _csv_bytes(rid, _SUMMARY_COLUMNS, p['metrics']),
               'algorithms.csv': _csv_bytes(rid, _ALGORITHM_COLUMNS, p['algorithm_rows'])}
    _require(len(exports['summary.csv']) + len(exports['algorithms.csv']) <= _MAX_CSV_TOTAL, 'SUMMARY_SIZE_LIMIT')
    pages = {}
    try:
        env = Environment(loader=FileSystemLoader(str(_TEMPLATES)), autoescape=True,
                          undefined=StrictUndefined, keep_trailing_newline=True)
        for name in ('findings', 'coverage'):
            out = _Bytes(_MAX_HTML)
            for chunk in env.get_template(name + '.html.j2').generate(p=p):
                out.write(chunk)
            pages[name + '.html'] = out.finish()
    except (OSError, TemplateError, UnicodeError):
        raise run_store.StoreError('SUMMARY_RENDER_ERROR') from None
    return p, pages, exports


# Certificate CSV B is a separate preview contract. Do not add its output to
# the already published A API or treat an in-memory buffer as a generation.
_CERT_METADATA_FIELDS = ('public_key_algorithm', 'public_key_bits', 'signature_inner',
                         'signature_outer', 'issuer', 'subject', 'not_before', 'not_after')
_CERT_COUNTS = ('host_ids', 'asset_ids', 'evidence_ids', 'claim_ids',
                'recorded_occurrence_ids', 'verified_occurrence_ids')
_CERT_COUNT_COLUMNS = tuple(k.removesuffix('_ids') + '_count' for k in _CERT_COUNTS)
_CERT_JSON_COLUMNS = frozenset((*_CERT_COUNTS, 'asset_identity_scopes', 'role_evidence_ids',
    'public_key_evidence_ids', 'signature_evidence_ids', 'public_key_bits_evidence_ids',
    'metadata_gaps', 'validity_occurrence_ids', 'algorithm_group_ids', 'algorithm_links',
    'service_group_ids', 'collection_ids', 'collection_states',
    *('metadata_' + k + '_occurrence_ids' for k in _CERT_METADATA_FIELDS)))
_CERT_NUMERIC_COLUMNS = frozenset((*_CERT_COUNT_COLUMNS, 'block_index', 'public_key_bits',
                                  'metadata_public_key_bits'))
_CERT_BOOLEAN_COLUMNS = frozenset(('assessed', 'requested', 'terminal_retained'))
_CERTIFICATE_COLUMNS = (
    'run_id', 'row_kind', 'assessed', 'group_id', 'group_kind', 'fingerprint', 'source_kind',
    'occurrence_id', 'host_id', 'asset_id', 'identity_scope', 'collection_id', 'root',
    'source_id', 'target_id', 'block_index', 'detail_ref', 'detail_sha256', 'observed_at',
    'producer_id', 'producer_version', 'origin_ref', 'input_sha256',
    'detail_state', 'reason_code', 'host_state', 'host_reason_code',
    *_CERT_COUNT_COLUMNS, *_CERT_COUNTS, 'asset_identity_scopes', 'role_evidence_ids',
    'public_key_state', 'public_key_evidence_ids', 'signature_state', 'signature_evidence_ids',
    'public_key_bits', 'public_key_bits_state', 'public_key_bits_evidence_ids',
    'issuer', 'subject', 'not_before', 'not_after', 'validity_state', 'validity_occurrence_ids',
    'signature_metadata_state', 'metadata_gaps',
    *(name for k in _CERT_METADATA_FIELDS for name in ('metadata_' + k,
        'metadata_' + k + '_state', 'metadata_' + k + '_occurrence_ids')),
    'algorithm_group_ids', 'algorithm_links', 'service_binding_state', 'service_group_ids',
    'slot', 'requested', 'state', 'rc', 'basis', 'terminal_retained', 'slot_state',
    'detail_slot_state', 'collection_ids', 'collection_states')


def _certificate_rows(p):
    """Flatten only the closed C2 certificate/coverage projection, not evidence payloads."""
    index = p['certificates']
    groups = sorted(index['groups'], key=lambda g: g['id'])
    membership = {}
    for g in groups:
        for oid in g['recorded_occurrence_ids']:
            _require(oid not in membership)
            membership[oid] = g['id']
        row = dict(row_kind='GROUP', assessed=p['assessed'], group_id=g['id'], group_kind=g['kind'])
        for k in ('fingerprint', 'source_kind', 'detail_state', 'public_key_bits', 'public_key_bits_state',
                  'public_key_bits_evidence_ids', 'issuer', 'subject', 'not_before', 'not_after',
                  'validity_state', 'validity_occurrence_ids', 'signature_metadata_state', 'metadata_gaps',
                  'algorithm_group_ids', 'algorithm_links', 'service_binding_state', 'service_group_ids',
                  *_CERT_COUNTS):
            row[k] = g[k]
        for field, column in zip(_CERT_COUNTS, _CERT_COUNT_COLUMNS):
            row[column] = g['counts'][field]
        row['asset_identity_scopes'] = {aid: p['assets'][aid]['identity_scope'] for aid in g['asset_ids']}
        for role in ('public_key', 'signature'):
            row[role + '_state'] = g[role]['state']
            row[role + '_evidence_ids'] = g[role]['evidence_ids']
        for field in _CERT_METADATA_FIELDS:
            meta = g['metadata_fields'][field]
            row['metadata_' + field] = meta['value']
            row['metadata_' + field + '_state'] = meta['state']
            row['metadata_' + field + '_occurrence_ids'] = meta['occurrence_ids']
        yield row
    _require(set(membership) == set(p['occurrences']) == set(index['recorded_occurrence_ids']))
    for oid, r in sorted(p['occurrences'].items()):
        row = dict(row_kind='OCCURRENCE', assessed=p['assessed'], group_id=membership[oid], occurrence_id=oid,
                   identity_scope=p['assets'][r['asset_id']]['identity_scope'], **_source(r['source']))
        for k in ('fingerprint', 'host_id', 'asset_id', 'collection_id', 'root', 'source_id', 'target_id',
                  'block_index', 'detail_ref', 'detail_sha256', 'observed_at', 'detail_state', 'reason_code',
                  'evidence_ids', 'role_evidence_ids', 'metadata_gaps'):
            row[k] = r[k]
        # Group field states and interval support are not occurrence claims.
        # The occurrence has its own exact metadata and gap codes (if retained).
        if r['certificate_metadata'] is not None:
            for k in _CERT_METADATA_FIELDS:
                row['metadata_' + k] = r['certificate_metadata'][k]
        yield row
    coverage = sorted((c for c in p['coverage'] if c['slot'] in ('system_certs', 'nginx_certs')),
                      key=lambda c: (c['host_id'], c['slot']))
    _require([(c['host_id'], c['slot']) for c in coverage] ==
             [(hid, slot) for hid in sorted(p['hosts']) for slot in ('nginx_certs', 'system_certs')])
    for c in coverage:
        host = p['hosts'][c['host_id']]
        yield dict(row_kind='COVERAGE', assessed=p['assessed'], host_state=host['host_state'],
                   host_reason_code=host['reason_code'], **{k: c[k] for k in ('host_id', 'slot', 'requested',
            'state', 'reason_code', 'rc', 'basis', 'terminal_retained', 'slot_state', 'detail_slot_state',
            'collection_ids', 'collection_states')})


def _certificate_json_cell(value, budget, cap):
    # C2 already validates/bounds the projection. Charge each retained member
    # again for this export (including repeated references in separate rows).
    def charge(item):
        budget.charge()
        if type(item) is list:
            for child in item:
                charge(child)
        elif type(item) is dict:
            for key, child in item.items():
                budget.charge()
                _require(type(key) is str)
                charge(child)
        else:
            _require(item is None or type(item) in (str, int, bool))
    _require(type(value) in (list, dict))
    charge(value)
    out = _Bytes(cap)
    for chunk in json.JSONEncoder(ensure_ascii=True, sort_keys=True, separators=(',', ':'),
                                  allow_nan=False).iterencode(value):
        out.write(chunk)
    return _csv_text(out.finish().decode('ascii'))


def _certificate_csv_bytes(run_id, rows, *, limit=None):
    cap = min(_MAX_CSV, _MAX_CSV_TOTAL)
    if limit is not None:
        cap = min(cap, limit)
    out, budget = _Bytes(cap), _Budget()
    out.write('\ufeff')
    writer = csv.writer(out, quoting=csv.QUOTE_ALL, lineterminator='\r\n')
    writer.writerow(_CERTIFICATE_COLUMNS)
    for row in rows:
        budget.charge()
        values = {'run_id': run_id, **row}
        _require(values.keys() <= set(_CERTIFICATE_COLUMNS))
        _require(values['row_kind'] in ('GROUP', 'OCCURRENCE', 'COVERAGE'))
        cells = []
        # Bound the whole row before csv.writer builds the quoted record.
        remaining = cap - len(out.data) - 2  # CRLF
        for i, k in enumerate(_CERTIFICATE_COLUMNS):
            remaining -= 2 + (i != 0)  # quotes and preceding delimiter
            _require(remaining >= 0, 'SUMMARY_SIZE_LIMIT')
            value = values.get(k)
            if value is None:
                cell = ''
            elif k in _CERT_JSON_COLUMNS:
                cell = _certificate_json_cell(value, budget, remaining)
            elif k in _CERT_NUMERIC_COLUMNS:
                cell = _csv_number(value)
            elif k in _CERT_BOOLEAN_COLUMNS:
                _require(type(value) is bool)
                cell = 'TRUE' if value else 'FALSE'
            elif k == 'rc':
                _require(type(value) is int and -255 <= value <= 255)
                # Negative terminal rc is a literal, not a formula exemption.
                cell = _csv_text(str(value))
            else:
                _require(type(value) is str)
                _require(len(value) <= remaining, 'SUMMARY_SIZE_LIMIT')
                cell = _csv_text(value)
            remaining -= len(cell.encode('utf-8')) + cell.count('"')
            _require(remaining >= 0, 'SUMMARY_SIZE_LIMIT')
            cells.append(cell)
        writer.writerow(cells)
    return out.finish()


def render_certificate_csv(store, run_id):
    """Return the fixed certificates.csv UTF-8 bytes from a freshly opened Store.

    No path, external input, fabricated PublishedRun, or publication interface.
    Store.open owns full retained-byte validation; C2 owns all certificate
    identity, role, provenance, metadata, conflict and coverage semantics.
    """
    _require(type(store) is run_store.RunStore)
    rid = run_store._rid(run_id)
    from tools import portal_asset_indexes
    p = portal_asset_indexes.project_asset_indexes(store.open(rid))
    return _render_certificate_projection(p, rid)


def _render_certificate_projection(p, rid, *, limit=None):
    # Internal C2 projection, not a new public PublishedRun input.
    _require(p['run_id'] == rid)
    return _certificate_csv_bytes(rid, _certificate_rows(p), limit=limit)
