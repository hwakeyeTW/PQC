"""Read-only crypto indexes of a trusted, validated RunStore.open result.

Internal A-slice API: no paths or raw input, no assessment, no publication.
The two preview pages target sibling host pages in a future generation. B owns
publication and actual backlinks; existing Portal versions do not use this API.
Counts describe recorded sets, never host readiness or service library usage.
"""
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
from types import MappingProxyType
from typing import NamedTuple

from jinja2 import Environment, FileSystemLoader, StrictUndefined, TemplateError

from tools import evidence, run_store

_TEMPLATES = Path(__file__).resolve().parents[1] / 'templates' / 'portal'
_MAX_JSON = evidence.MAX_BYTES
_MAX_HTML = 16 * 1024 * 1024
# Every membership consumes at least one ID in the resulting JSON. Bound
# construction too, not just serialization, even for repeated claim refs.
_MAX_MEMBERSHIPS = evidence.MAX_BYTES // 66
_LEVELS = dict(zip(evidence.LEVELS, ('Installed', 'Supported (runtime)',
    'Configured', 'Negotiable (service)', 'Observed in use')))
_OBSERVATIONS = {
    'PACKAGE_INVENTORY': ('L1', 'present', True, False, 'PRESENT', 'ABSENT'),
    'RUNTIME_CAPABILITY': ('L2', 'supported', True, False, 'SUPPORTED', 'UNSUPPORTED'),
    'EFFECTIVE_CONFIGURATION': ('L3', 'allowed', True, False, 'ALLOWED', 'DISALLOWED'),
    'AUTHORIZED_NEGOTIATION': ('L4', 'outcome', 'NEGOTIATED', 'REJECTED', 'NEGOTIATED', 'REJECTED'),
    'OBSERVED_USAGE': ('L5', 'outcome', 'OBSERVED', 'CONTRADICTED', 'OBSERVED', 'CONTRADICTED'),
}
_USABLE = ('COLLECTED', 'PARTIAL')
_LIBRARY_KINDS = frozenset(('library', 'crypto-library', 'crypto_library'))
_LEGACY_RPM = {'rpm-release': 'release', 'rpm-architecture': 'architecture', 'rpm-epoch': 'epoch'}
_FIELDS = {
    'PACKAGE_INVENTORY': ('name', 'version', 'present', 'release', 'architecture'),
    'ASSET_METADATA': ('name', 'version'),
    'RUNTIME_CAPABILITY': ('capability', 'supported'),
    'EFFECTIVE_CONFIGURATION': ('setting', 'effective_value', 'allowed'),
    'AUTHORIZED_NEGOTIATION': ('outcome',), 'OBSERVED_USAGE': ('outcome',),
    'LEGACY_OBSERVATION': ('field',),
    'COLLECTION_SUMMARY': ('scope', 'attempted', 'coverage', 'observation_count', 'applicable'),
}


def _require(ok, code='INVALID_CRYPTO_INDEX_PUBLICATION'):
    run_store.require(ok, code)


def _serial(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False)


def _key(prefix, value):
    return prefix + '-' + hashlib.sha256(_serial(value).encode('ascii')).hexdigest()


def _bounded_bytes(value, *, limit=None):
    cap = _MAX_JSON if limit is None else min(_MAX_JSON, limit)
    out = bytearray()
    encoder = json.JSONEncoder(ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False)
    for chunk in encoder.iterencode(value):
        part = chunk.encode('ascii')
        _require(len(part) <= cap - len(out), 'CRYPTO_INDEX_SIZE_LIMIT')
        out.extend(part)
    return bytes(out)


def _id(value, prefix):
    _require(type(value) is str and re.fullmatch(prefix + r'[0-9a-f]{64}', value) is not None)
    return value


def _href(hid, ref=None, prefix=None):
    _id(hid, 'h-')
    if ref is None:
        ref, prefix = hid, 'h-'
    return hid + '.html#' + _id(ref, prefix)


def _observation(row, collection):
    """Report typed acquisition, not a new assessment verdict."""
    spec = _OBSERVATIONS.get(row['evidence_kind'])
    if spec is None:
        return None, None
    level, field, yes, no, positive, negative = spec
    value = row['data'][field]
    state = 'UNKNOWN'
    if collection['collection_state'] in _USABLE:
        if value == yes:
            state = positive
        elif value == no:
            state = negative
        elif level == 'L4' and value in ('ERROR', 'TIMEOUT'):
            state = value
    return level, state


def _openssl_scope(c):
    # #15 producer identity, plus the explicitly synthetic S1 short collector
    # used by the current Store. Never generalize the short name to live data.
    return (c['collector_id'] == c['source']['producer_id'] and (
        c['collector_id'] == 'pqc-openssl-runtime' or
        (c['collector_id'] == 'openssl' and c['source']['source_kind'] == 'SYNTHETIC')) and
        c['source']['source_kind'] != 'LEGACY_IMPORT')


def _metadata_kind(row, c):
    if row['evidence_kind'] != 'ASSET_METADATA':
        return None
    name = row['data']['name']
    if _openssl_scope(c) and row['asset_id'] is None and row['algorithm'] is None:
        if c['scope_key'] == 'openssl-version':
            if (row['observation_key'], name) == ('cli-version', 'openssl-cli'):
                return 'OPENSSL_CLI'
            if (row['observation_key'], name) == ('library-version', 'openssl-linked-library'):
                return 'LINKED_LIBRARY_METADATA'
        if (name is not None and row['observation_key'] == 'metadata' and
                c['scope_key'] == _key('openssl-provider', name)):
            return 'OPENSSL_PROVIDER'
    if (c['source']['source_kind'] == 'LEGACY_IMPORT' and c['collector_id'] == 'legacy-import' and
            c['scope_key'] == 'openssl-version' and name == 'OpenSSL'):
        return 'LEGACY_RUNTIME_METADATA'
    return None


def _provider_status(row, c, name):
    # This is an explicit status observation in the SAME fixed provider scope,
    # not a reverse lookup of an opaque algorithm capability hash. #15 stores
    # inactive/unknown as None; never infer provider absence or non-support.
    cap = _key('openssl-provider-loaded', name)
    return (_openssl_scope(c) and c['scope_key'] == _key('openssl-provider', name) and
            row['asset_id'] is None and row['algorithm'] is None and
            row['evidence_kind'] == 'RUNTIME_CAPABILITY' and row['observation_key'] == cap and
            row['data']['capability'] == cap and row['data']['supported'] in (True, None))


def _legacy_package_scope(c):
    return (c['source']['source_kind'] == 'LEGACY_IMPORT' and c['collector_id'] == 'legacy-import'
            and c['scope_key'] == 'packages')


class _Projection:
    def __init__(self, published):
        # As in render_portal._view, this is an internal trust boundary, not
        # authentication of a caller-constructed NamedTuple. The caller MUST
        # supply the unmodified, verified result of RunStore.open.
        _require(type(published) is run_store.PublishedRun)
        m, doc, assessed, artifacts = published
        _require(m['run_id'] == doc['run']['run_id'] and m['expected_host_ids'] == sorted(set(m['expected_host_ids']))
                 and 0 < len(m['expected_host_ids']) <= 1000 and
                 set(m['expected_host_ids']) == set(doc['run']['expected_host_ids']))
        for name in ('evidence.json', *(['assessed_evidence.json'] if assessed is not None else [])):
            _require(type(artifacts.get(name)) is bytes and 0 < len(artifacts[name]) <= evidence.MAX_BYTES,
                     'CRYPTO_INDEX_SIZE_LIMIT')
        self.run_id, self.assessed = m['run_id'], assessed is not None
        self.hosts = {h['host_id']: h for h in doc['hosts']}
        _require(set(self.hosts) == set(m['expected_host_ids']))
        self.assets = {a['asset_id']: a for a in doc['assets']}
        self.collections = {c['collection_id']: c for c in doc['collections']}
        self.rows = {r['evidence_id']: r for r in doc['evidence']}
        self.claims = {} if assessed is None else {c['claim_id']: c for c in assessed['claims']}
        self.groups = {'algorithms': {}, 'libraries': {}}
        self.members = {'algorithms': defaultdict(set), 'libraries': defaultdict(set)}
        self.asset_groups = defaultdict(set)
        self.relations = defaultdict(set)
        self.cost = 0

    def charge(self, count=1):
        self.cost += count
        _require(self.cost <= _MAX_MEMBERSHIPS, 'CRYPTO_INDEX_SIZE_LIMIT')

    def group(self, index, identity, fields):
        gid = _key('alg' if index == 'algorithms' else 'lib', identity)
        groups = self.groups[index]
        if gid not in groups:
            self.charge(8)
            groups[gid] = dict(id=gid, **fields, host_ids=set(), asset_ids=set(),
                               evidence_ids=set(), claim_ids=set(), observed_names=set())
        return gid

    def add(self, index, gid, eid, *, seed=True):
        group, row = self.groups[index][gid], self.rows[eid]
        if eid not in group['evidence_ids']:
            self.charge()
            group['evidence_ids'].add(eid)
            group['host_ids'].add(row['host_id'])
            if row['asset_id'] is not None:
                group['asset_ids'].add(row['asset_id'])
            if row['algorithm'] is not None and row['algorithm']['observed_name'] is not None:
                group['observed_names'].add(row['algorithm']['observed_name'])
        if seed:
            self.members[index][eid].add(gid)

    def algorithms(self):
        variants = defaultdict(set)
        for row in self.rows.values():
            a = row['algorithm']
            if a is not None and a['algorithm_id'] is not None and a['taxonomy_version'] is not None and \
                    row['source']['source_kind'] != 'LEGACY_IMPORT':
                variants[(a['algorithm_id'], a['taxonomy_version'])].add((a['primitive'], a['family']))
        for eid, row in self.rows.items():
            a = row['algorithm']
            if a is None:
                continue
            canonical = (a['algorithm_id'], a['taxonomy_version'], a['primitive'], a['family'])
            if row['source']['source_kind'] == 'LEGACY_IMPORT' or row['evidence_kind'] == 'LEGACY_OBSERVATION':
                status = 'LEGACY'
            elif len(variants.get(canonical[:2], ())) > 1:
                status = 'CONFLICT'
            elif None in canonical[:2] or 'UNKNOWN' in canonical[2:]:
                status = 'UNKNOWN'
            else:
                status = 'CANONICAL'
            # Unknown/conflicting/legacy observations stay independent by
            # recorded context (evidence identity); no alias/name reclassification.
            identity = [status, canonical, None if status == 'CANONICAL' else eid]
            gid = self.group('algorithms', identity, dict(classification=status,
                algorithm_id=a['algorithm_id'], taxonomy_version=a['taxonomy_version'],
                primitive=a['primitive'], family=a['family']))
            self.add('algorithms', gid, eid)

    def libraries(self):
        # Legacy RPM qualifiers are explicit same-asset/same-collection refs.
        # Never join them by package name or an opaque identity key.
        legacy_meta = defaultdict(lambda: defaultdict(set))
        for eid, row in self.rows.items():
            c = self.collections[row['collection_id']]
            if (row['evidence_kind'] == 'LEGACY_OBSERVATION' and row['asset_id'] is not None and
                    _legacy_package_scope(c) and row['data']['field'] in _LEGACY_RPM):
                field, value = _LEGACY_RPM[row['data']['field']], row['data']['value']
                if ((field == 'epoch' and type(value) is int and value >= 0) or
                        (field != 'epoch' and type(value) is str)):
                    legacy_meta[(row['asset_id'], row['collection_id'])][field].add(value)
        packages = defaultdict(set)
        providers = {}
        for aid, a in self.assets.items():
            if a['asset_kind'] in _LIBRARY_KINDS:
                # Display exact same-asset metadata only; conflicting names or
                # versions do not select a winner. The asset ID stays intact.
                metadata = {(self.rows[eid]['data']['name'], self.rows[eid]['data']['version'])
                            for eid in a['evidence_ids']
                            if self.rows[eid]['evidence_kind'] == 'ASSET_METADATA'}
                name, version = next(iter(metadata)) if len(metadata) == 1 else (None, None)
                state = ('CONFLICT' if len(metadata) > 1 else 'MISSING_METADATA'
                         if version is None or name is None else 'RECORDED_METADATA')
                gid = self.group('libraries', ['LIBRARY_ASSET', a['host_id'], aid], dict(
                    kind='LIBRARY_ASSET', name=name, version=version, release=None, architecture=None,
                    epoch=None, presence='UNKNOWN', metadata_state=state))
                self.asset_groups[aid].add(gid)
                for eid in a['evidence_ids']:
                    self.add('libraries', gid, eid)
        for eid, row in self.rows.items():
            c, d = self.collections[row['collection_id']], row['data']
            kind = _metadata_kind(row, c)
            release = arch = epoch = None
            presence = 'UNKNOWN'
            state = 'RECORDED_METADATA'
            if row['evidence_kind'] == 'PACKAGE_INVENTORY':
                _, presence = _observation(row, c)
                release, arch = d.get('release'), d.get('architecture')
                kind = 'PACKAGE'
                if (_openssl_scope(c) and c['scope_key'] in ('openssl-rpm-openssl', 'openssl-rpm-openssl-libs')
                        and c['scope_key'] == 'openssl-rpm-' + d['name']) or release is not None or arch is not None:
                    kind = 'RPM_PACKAGE'
                if row['asset_id'] is not None and _legacy_package_scope(c):
                    kind = 'RPM_PACKAGE'
                    meta = legacy_meta[(row['asset_id'], row['collection_id'])]
                    if (any(len(v) > 1 for v in meta.values()) or
                            (release is not None and meta.get('release') and meta['release'] != {release}) or
                            (arch is not None and meta.get('architecture') and meta['architecture'] != {arch})):
                        state = 'CONFLICT'
                    else:
                        release = next(iter(meta.get('release', ())), release)
                        arch = next(iter(meta.get('architecture', ())), arch)
                        epoch = next(iter(meta.get('epoch', ())), None)
                if state != 'CONFLICT':
                    if presence == 'ABSENT':
                        state = 'ABSENCE_RECORDED'
                    elif d['version'] is None:
                        state = 'MISSING_METADATA'
            elif kind is not None and d['version'] is None:
                state = 'MISSING_METADATA'
            if kind is None:
                continue
            fields = dict(kind=kind, name=d['name'], version=d['version'], release=release,
                          architecture=arch, epoch=epoch, presence=presence, metadata_state=state)
            # Metadata grouping is not an asset identity. Preserve per-host
            # provenance and never merge conflicting legacy metadata.
            identity = [fields, eid if state == 'CONFLICT' else None]
            gid = self.group('libraries', identity, fields)
            self.add('libraries', gid, eid)
            aid = row['asset_id']
            if kind in ('PACKAGE', 'RPM_PACKAGE') and aid is not None:
                packages[(aid, row['collection_id'])].add(gid)
                self.asset_groups[aid].add(gid)
            if kind == 'OPENSSL_PROVIDER':
                providers[c['collection_id']] = (gid, d['name'])
        for eid, row in self.rows.items():
            c = self.collections[row['collection_id']]
            provider = providers.get(c['collection_id'])
            if provider is not None and _provider_status(row, c, provider[1]):
                self.add('libraries', provider[0], eid)
            if row['asset_id'] is not None and _legacy_package_scope(c) and row['evidence_kind'] == 'LEGACY_OBSERVATION' and \
                    row['data']['field'] in _LEGACY_RPM:
                groups = packages.get((row['asset_id'], row['collection_id']), ())
                if len(groups) == 1:
                    self.add('libraries', next(iter(groups)), eid)
            # Only an unambiguous explicitly named non-service asset may
            # connect another algorithm observation to a package/library row.
            aid = row['asset_id']
            if aid is not None and row['algorithm'] is not None and self.assets[aid]['asset_kind'] != 'service':
                groups = self.asset_groups.get(aid, ())
                if len(groups) == 1:
                    self.add('libraries', next(iter(groups)), eid)
            # No host/name/version/hash joins. A relation is recorded only
            # when this evidence ID has explicit memberships in both indexes.
            for ag in self.members['algorithms'].get(eid, ()):
                for lg in self.members['libraries'].get(eid, ()):
                    self.charge()
                    self.relations[(ag, lg)].add(eid)

    def attach_claims(self, index):
        unresolved = []
        membership = self.members[index]
        for cid, claim in self.claims.items():
            refs = claim['evidence_ids']
            groups = set()
            for eid in refs:
                groups.update(membership.get(eid, ()))
            subject = claim['subject']
            if index == 'libraries' and not groups and subject.get('asset_id') is not None:
                candidates = self.asset_groups.get(subject['asset_id'], ())
                if len(candidates) > 1:
                    self.charge(len(refs) + 1)
                    unresolved.append(cid)
                    continue
                if candidates:
                    groups.add(next(iter(candidates)))
            if len(groups) == 1:
                gid = next(iter(groups))
                # A saved service negotiation/usage claim never proves that
                # a package or library implemented the service.
                if index == 'libraries' and claim['level'] in ('L4', 'L5'):
                    self.charge(len(refs) + 1)
                    unresolved.append(cid)
                    continue
                group = self.groups[index][gid]
                self.charge(len(refs) + 1)
                group['claim_ids'].add(cid)
                group['host_ids'].add(subject['host_id'])
                if subject.get('asset_id') is not None:
                    group['asset_ids'].add(subject['asset_id'])
                for eid in refs:
                    self.add(index, gid, eid, seed=False)
            elif groups or (index == 'algorithms' and subject.get('algorithm_id') is not None):
                self.charge(len(refs) + 1)
                unresolved.append(cid)
        return sorted(unresolved)

    def finish(self):
        self.algorithms()
        self.libraries()
        indexes = {}
        all_refs = {k: set() for k in ('host_ids', 'asset_ids', 'evidence_ids', 'claim_ids')}
        for index, groups in self.groups.items():
            unresolved = self.attach_claims(index)
            totals = {k: set() for k in all_refs}
            output = []
            for gid, group in sorted(groups.items()):
                # References and level counts are exact sets, not additive
                # host or asset counts across groups or levels.
                levels = {level: {'label': label, 'observations': defaultdict(list),
                                  'claims': defaultdict(list)} for level, label in _LEVELS.items()}
                for eid in sorted(group['evidence_ids']):
                    row = self.rows[eid]
                    level, state = _observation(row, self.collections[row['collection_id']])
                    if level is not None:
                        # Library metadata/asset references are not L4/L5 usage.
                        if index != 'libraries' or level not in ('L4', 'L5'):
                            levels[level]['observations'][state].append(eid)
                for cid in sorted(group['claim_ids']):
                    cl = self.claims[cid]
                    levels[cl['level']]['claims'][cl['assessment_state']].append(cid)
                for data in levels.values():
                    for kind in ('observations', 'claims'):
                        data[kind] = dict(sorted(data[kind].items()))
                        data[kind[:-1] + '_counts'] = {k: len(v) for k, v in data[kind].items()}
                counts = {}
                for key in totals:
                    totals[key].update(group[key])
                    counts[key] = len(group[key])
                output.append({**group, **{k: sorted(group[k]) for k in (*totals, 'observed_names')},
                    'counts': counts, 'levels': levels,
                    'backlink': index + '.html#' + gid})
            for cid in unresolved:
                cl = self.claims[cid]
                totals['claim_ids'].add(cid)
                totals['host_ids'].add(cl['subject']['host_id'])
                if cl['subject'].get('asset_id') is not None:
                    totals['asset_ids'].add(cl['subject']['asset_id'])
                totals['evidence_ids'].update(cl['evidence_ids'])
            for key in totals:
                all_refs[key].update(totals[key])
            category = 'classification' if index == 'algorithms' else 'kind'
            indexes[index] = dict(groups=output, unresolved_claim_ids=unresolved,
                **{k: sorted(v) for k, v in totals.items()},
                counts={'groups': len(output), **{k: len(v) for k, v in totals.items()},
                        'unresolved_claims': len(unresolved)},
                categories=dict(sorted(Counter(g[category] for g in output).items())))
        taxonomy = defaultdict(list)
        for g in indexes['algorithms']['groups']:
            taxonomy[(g['classification'], g['family'], g['primitive'])].append(g['id'])
        indexes['algorithms']['taxonomy'] = [dict(classification=k[0], family=k[1], primitive=k[2],
                                                   group_ids=ids, count=len(ids))
                                              for k, ids in sorted(taxonomy.items())]
        # Closed, ID-based reference tables. Preserve host-scoped identity
        # (asset IDs are derived from host, never grouped by name for identity).
        hosts = {hid: dict(host_id=hid, target_id=self.hosts[hid]['target_id'],
                           host_state=self.hosts[hid]['host_state'], href=_href(hid))
                 for hid in sorted(all_refs['host_ids'])}
        assets = {aid: dict(asset_id=aid, host_id=self.assets[aid]['host_id'],
                   asset_kind=self.assets[aid]['asset_kind'], identity_scope=self.assets[aid]['identity_scope'],
                   href=_href(self.assets[aid]['host_id'], aid, 'a-')) for aid in sorted(all_refs['asset_ids'])}
        rows = {}
        for eid in sorted(all_refs['evidence_ids']):
            r = self.rows[eid]; c = self.collections[r['collection_id']]
            facts = {k: r['data'].get(k) for k in _FIELDS.get(r['evidence_kind'], ())}
            if r['evidence_kind'] == 'LEGACY_OBSERVATION' and _legacy_package_scope(c) and \
                    r['data']['field'] in _LEGACY_RPM:
                facts['value'] = r['data']['value']
            level, state = _observation(r, c)
            rows[eid] = dict(evidence_id=eid, host_id=r['host_id'], asset_id=r['asset_id'],
                evidence_kind=r['evidence_kind'], collector_id=c['collector_id'], collection_id=c['collection_id'],
                scope_key=c['scope_key'], collection_state=c['collection_state'], reason_code=c['reason_code'],
                observed_at=r['observed_at'], source=dict(r['source']), observation_key=r['observation_key'],
                algorithm=None if r['algorithm'] is None else dict(r['algorithm']), facts=facts,
                conditions=dict(r['data']['conditions']) if r['evidence_kind'] in
                    ('AUTHORIZED_NEGOTIATION', 'OBSERVED_USAGE') else None,
                level=level, observation_state=state, href=_href(r['host_id'], eid, 'e-'))
        claims = {cid: dict(claim_id=cid, subject=dict(self.claims[cid]['subject']),
                    level=self.claims[cid]['level'], assessment_state=self.claims[cid]['assessment_state'],
                    reason_code=self.claims[cid]['reason_code'], rule_id=self.claims[cid]['rule_id'],
                    rule_version=self.claims[cid]['rule_version'], evidence_ids=sorted(self.claims[cid]['evidence_ids']),
                    conditions=None if self.claims[cid]['conditions'] is None else dict(self.claims[cid]['conditions']),
                    href=_href(self.claims[cid]['subject']['host_id'], cid, 'cl-'))
                  for cid in sorted(all_refs['claim_ids'])}
        relations = [dict(algorithm_group_id=ag, library_group_id=lg, evidence_ids=sorted(refs),
                          basis='EXPLICIT_EVIDENCE_OR_ASSET_REFERENCE')
                     for (ag, lg), refs in sorted(self.relations.items())]
        by_group = defaultdict(list)
        for relation in relations:
            ag, lg = relation['algorithm_group_id'], relation['library_group_id']
            by_group[ag].append(dict(group_id=lg, href='libraries.html#' + lg,
                                     evidence_ids=relation['evidence_ids']))
            by_group[lg].append(dict(group_id=ag, href='algorithms.html#' + ag,
                                     evidence_ids=relation['evidence_ids']))
        for data in indexes.values():
            for group in data['groups']:
                group['relations'] = by_group[group['id']]
        return dict(projection_version=1, run_id=self.run_id, assessed=self.assessed,
                    **indexes, hosts=hosts, assets=assets, evidence=rows, claims=claims,
                    relations=relations)


def project_crypto_indexes(published):
    """Return a deterministic JSON-serializable projection; input is never mutated.

    The caller must supply an unmodified PublishedRun from trusted Store.open.
    Membership counts are cardinalities of recorded ID sets. Unresolved claims
    are included in index totals but not assigned to an invented group.
    """
    result = _Projection(published).finish()
    _bounded_bytes(result)
    return result


def render_crypto_indexes(published):
    """Return (projection, fixed page bytes) without writing any report files."""
    result = project_crypto_indexes(published)
    return result, _render_crypto_projection(result)


# B2b-2: a separate, bounded render-only index. Never serialize these rows
# into the crypto/asset/summary projections or infer a relationship from labels.
_MAX_PIVOT_MEMBERSHIPS = _MAX_MEMBERSHIPS
_PIVOT_ERROR = 'PORTAL_PAYLOAD_INVALID'


class _PivotBudget:
    def __init__(self):
        self.used = 0

    def charge(self, count=1):
        _require(count <= _MAX_PIVOT_MEMBERSHIPS - self.used, 'PORTAL_PAYLOAD_SIZE_LIMIT')
        self.used += count


def _pivot_ids(values, budget, registry):
    _require(type(values) is list, _PIVOT_ERROR)
    budget.charge(len(values))  # before allocating a set, even on bad input
    _require(all(type(ref) is str and ref in registry for ref in values), _PIVOT_ERROR)
    refs = set(values)
    _require(len(refs) == len(values) and values == sorted(refs), _PIVOT_ERROR)
    return refs


class _PivotRow(NamedTuple):
    kind: str
    ref: str
    owner: str | None
    basis: str
    matches: tuple
    state: str | None = None
    reason: str | None = None
    attempt_status: str | None = None
    dispatch_intent: bool | None = None

    @property
    def href(self):
        # No href is accepted from a caller. Closed target grammar only.
        if self.kind == 'collection':
            return _href(self.owner, self.ref, 'c-')
        page, prefix = {'certificate': ('certificates', 'cert-'),
                        'service': ('services', 'svc-'),
                        'occurrence': ('certificates', 'occ-'),
                        'finding': ('findings', 'f-'),
                        'host coverage': ('coverage', 'h-')}[self.kind]
        return page + '.html#' + _id(self.ref, prefix)

    @property
    def host_href(self):
        return _href(self.owner, self.ref, 'f-') if self.kind == 'finding' else None


class _ReverseContext(NamedTuple):
    run_id: str
    expected_hosts: tuple
    projection: dict
    groups: object
    host_links: object


def _reverse_pivot_context(published, projection, asset_index, summary):
    """Reuse the three actual projections of one verified PublishedRun.

    Validate identity/ownership and explicit membership, not the assessment or
    collector semantics again. Inverted refs make candidate visits proportional
    to the bounded input and actual candidate edges, not all group pairs.
    The resulting immutable rows contain only fixed IDs and recorded states.
    """
    budget = _PivotBudget()
    m, doc, saved, _ = published
    rid, ids = m['run_id'], m['expected_host_ids']
    assessed = saved is not None
    _require(projection['run_id'] == asset_index['run_id'] == summary['run']['run_id'] == rid
             and summary['expected_host_ids'] == ids
             and all(p['assessed'] is assessed for p in (projection, asset_index, summary)), _PIVOT_ERROR)
    # Summary's closed registries are checked against the actual verified rows.
    # Do not retain a copy of the document or raw facts in the render context.
    definitions = {
        'hosts': ('host_id', 'h-', ('target_id', 'host_state', 'reason_code', 'attempted',
                                   'attempt_status', 'dispatch_intent'), ()),
        'collections': ('collection_id', 'c-', ('host_id', 'collection_state', 'reason_code',
                                                 'collector_id'), ('evidence_ids',)),
        'assets': ('asset_id', 'a-', ('host_id', 'asset_kind', 'identity_scope'), ('evidence_ids',)),
        'evidence': ('evidence_id', 'e-', ('host_id', 'asset_id', 'collection_id', 'evidence_kind'), ()),
        'claims': ('claim_id', 'cl-', ('subject', 'level', 'assessment_state', 'reason_code',
                                      'rule_id', 'rule_version'), ('evidence_ids',)),
        'findings': ('finding_id', 'f-', ('subject', 'assessment_state', 'reason_code',
                                        'rule_id', 'rule_version', 'condition_key'), ('claim_ids', 'evidence_ids')),
    }
    registries = {}
    for kind, (key, prefix, fields, ref_fields) in definitions.items():
        actual = m['hosts'] if kind == 'hosts' else ((saved or {}).get(kind, [])
                    if kind in ('claims', 'findings') else doc[kind])
        table = summary[kind]
        if kind in ('claims', 'findings') and not assessed:
            _require(table is None, _PIVOT_ERROR)
            table = {}
        _require(type(table) is dict and len(table) == len(actual), _PIVOT_ERROR)
        budget.charge(len(actual) + len(table))
        seen = set()
        for raw in actual:
            ref = _id(raw[key], prefix)
            _require(ref not in seen and ref in table, _PIVOT_ERROR)
            seen.add(ref)
            row = table[ref]
            owner = ref if kind == 'hosts' else (raw['subject']['host_id']
                if kind in ('claims', 'findings') else raw['host_id'])
            _require(type(row) is dict and row[key] == ref and owner in summary['hosts']
                     and row['href'] == _href(owner, ref, prefix)
                     and all(row[f] == raw[f] for f in fields), _PIVOT_ERROR)
            for field in ref_fields:
                budget.charge(len(raw[field]))
                refs = _pivot_ids(row[field], budget, summary['claims' if field == 'claim_ids' else 'evidence'])
                _require(refs == set(raw[field]), _PIVOT_ERROR)
        registries[kind] = table
    hosts, cols, ars, evs, cls, fs = (registries[k] for k in definitions)
    _require(list(sorted(hosts)) == ids and len(ids) <= 1000, _PIVOT_ERROR)

    # The projections may have narrower registries than Summary. Their
    # common ID fields and fixed original host hrefs must agree exactly.
    for p in (projection, asset_index):
        for kind in ('hosts', 'assets', 'evidence', 'claims'):
            key, _, fields, ref_fields = definitions[kind]
            table = p[kind]
            _require(type(table) is dict, _PIVOT_ERROR)
            budget.charge(len(table))
            for ref, row in table.items():
                _require(ref in registries[kind] and type(row) is dict, _PIVOT_ERROR)
                original = registries[kind][ref]
                # Some original projections intentionally omit display fields.
                identity = ('subject',) if kind == 'claims' else (
                    ('target_id', 'host_state') if kind == 'hosts' else
                    (('host_id', 'asset_kind', 'identity_scope') if kind == 'assets' else fields))
                _require(row[key] == ref and row['href'] == original['href'] and
                         all(row[f] == original[f] for f in identity), _PIVOT_ERROR)
                if kind == 'claims':
                    refs = _pivot_ids(row['evidence_ids'], budget, evs)
                    budget.charge(len(original['evidence_ids']))
                    _require(refs == set(original['evidence_ids']), _PIVOT_ERROR)
    group_names, memberships = {}, {}
    by_ref = {k: defaultdict(set) for k in ('assets', 'evidence', 'claims')}
    edges = defaultdict(dict)
    host_edges = defaultdict(lambda: defaultdict(set))

    def group_members(p, name, group, prefix):
        gid = _id(group['id'], prefix)
        _require(group['backlink'] == name + '.html#' + gid, _PIVOT_ERROR)
        budget.charge()
        members = {kind: _pivot_ids(group[field], budget, p[kind]) for kind, field in
                   (('hosts', 'host_ids'), ('assets', 'asset_ids'),
                    ('evidence', 'evidence_ids'), ('claims', 'claim_ids'))}
        return gid, members

    def add(gid, kind, ref, owner, basis, match=None, *, state=None, reason=None,
            attempt_status=None, dispatch_intent=None):
        # Count each accepted candidate/ref and materialized edge before add.
        budget.charge(2)
        key = (kind, ref, owner or '', basis)
        if key not in edges[gid]:
            budget.charge()
            edges[gid][key] = (set(), state, reason, attempt_status, dispatch_intent)
        refs, *metadata = edges[gid][key]
        _require(tuple(metadata) == (state, reason, attempt_status, dispatch_intent), _PIVOT_ERROR)
        if match is not None:
            budget.charge()
            refs.add(match)
        if kind in ('finding', 'collection'):
            budget.charge()
            host_edges[owner][ref].add(group_names[gid] + '.html#' + gid)

    for name, prefix in (('algorithms', 'alg-'), ('libraries', 'lib-')):
        for group in projection[name]['groups']:
            gid, members = group_members(projection, name, group, prefix)
            _require(gid not in memberships, _PIVOT_ERROR)
            group_names[gid], memberships[gid] = name, members
            actual_hosts, actual_assets = set(), set()
            for kind in ('evidence', 'claims'):
                for ref in members[kind]:
                    row = registries[kind][ref]
                    subject = row['subject'] if kind == 'claims' else row
                    budget.charge(3)
                    actual_hosts.add(subject['host_id'])
                    if subject['asset_id'] is not None:
                        actual_assets.add(subject['asset_id'])
                    if kind == 'claims':
                        budget.charge(len(row['evidence_ids']))
                        _require(all(eid in members['evidence'] for eid in row['evidence_ids']), _PIVOT_ERROR)
                    by_ref[kind][ref].add(gid)
            _require(actual_hosts == members['hosts'] and actual_assets == members['assets'], _PIVOT_ERROR)
            for aid in members['assets']:
                budget.charge(); by_ref['assets'][aid].add(gid)
            for hid in members['hosts']:
                h = hosts[hid]
                add(gid, 'host coverage', hid, hid, 'HOST_MEMBERSHIP',
                    state=h['host_state'], reason=h['reason_code'], attempt_status=h['attempt_status'],
                    dispatch_intent=h['dispatch_intent'])
            for eid in members['evidence']:
                r = evs[eid]; cid = r['collection_id']; c = cols[cid]
                _require(c['host_id'] == r['host_id'], _PIVOT_ERROR)
                add(gid, 'collection', cid, r['host_id'], 'SHARED_EVIDENCE_ID', eid,
                    state=c['collection_state'], reason=c['reason_code'])

    # Preserve the explicit algorithm/library relationships. They are not
    # inputs to any asset or finding join. Reject conflicting relation refs.
    related = defaultdict(list)
    relation_pairs = set()
    for rel in projection['relations']:
        ag, lg = rel['algorithm_group_id'], rel['library_group_id']
        budget.charge(3)
        _require(rel['basis'] == 'EXPLICIT_EVIDENCE_OR_ASSET_REFERENCE'
                 and group_names.get(ag) == 'algorithms' and group_names.get(lg) == 'libraries'
                 and (ag, lg) not in relation_pairs, _PIVOT_ERROR)
        relation_pairs.add((ag, lg))
        refs = _pivot_ids(rel['evidence_ids'], budget, evs)
        _require(bool(refs) and refs <= memberships[ag]['evidence']
                 and refs <= memberships[lg]['evidence'], _PIVOT_ERROR)
        related[ag].append(dict(group_id=lg, href='libraries.html#' + lg, evidence_ids=rel['evidence_ids']))
        related[lg].append(dict(group_id=ag, href='algorithms.html#' + ag, evidence_ids=rel['evidence_ids']))
    for name in ('algorithms', 'libraries'):
        for group in projection[name]['groups']:
            budget.charge(len(group['relations']))
            _require(group['relations'] == related[group['id']], _PIVOT_ERROR)

    # Each certificate/service asset has exactly one C2 group. The algorithm
    # reverse edge must agree with the original C2 shared-evidence relation.
    # Libraries use the identical evidence-ID join independently, not A->L
    # transitivity, same-host coincidence, fingerprint or package spelling.
    seen_groups, seen_assets, seen_occ = set(), set(), set()
    occurrences = asset_index['occurrences']
    budget.charge(len(doc['evidence']))
    raw_evidence = {r['evidence_id']: r for r in doc['evidence']}
    budget.charge(len(doc['assets']))
    raw_assets = {r['asset_id']: r for r in doc['assets']}
    _require(type(occurrences) is dict, _PIVOT_ERROR)
    for name, prefix, kind in (('certificates', 'cert-', 'certificate'), ('services', 'svc-', 'service')):
        for group in asset_index[name]['groups']:
            target, members = group_members(asset_index, name, group, prefix)
            _require(target not in seen_groups and not seen_assets.intersection(members['assets']), _PIVOT_ERROR)
            budget.charge(1 + len(members['assets']))
            seen_groups.add(target); seen_assets.update(members['assets'])
            expected_hosts, expected_refs = set(), set()
            _require(bool(members['assets']), _PIVOT_ERROR)
            for aid in members['assets']:
                row = ars[aid]
                _require(row['asset_kind'] == kind, _PIVOT_ERROR)
                if kind == 'service':
                    identity = [rid, row['host_id'], aid]
                elif group['kind'] == 'RECORDED_FINGERPRINT':
                    _require(group['fingerprint'] == raw_assets[aid]['identity_key'], _PIVOT_ERROR)
                    identity = [group['kind'], group['source_kind'], group['fingerprint']]
                else:
                    _require(group['kind'] in ('LEGACY_RUN_SCOPED', 'UNVERIFIED_IDENTITY')
                             and group['fingerprint'] is None, _PIVOT_ERROR)
                    identity = [group['kind'], rid, row['host_id'], aid]
                _require(target == _key(prefix[:-1], identity), _PIVOT_ERROR)
                budget.charge(1 + len(row['evidence_ids']))
                expected_hosts.add(row['host_id']); expected_refs.update(row['evidence_ids'])
            _require(expected_hosts == members['hosts'] and expected_refs == members['evidence'], _PIVOT_ERROR)
            for cid in members['claims']:
                c = cls[cid]
                budget.charge(len(c['evidence_ids']) + 1)
                _require(c['subject']['asset_id'] in members['assets'] and
                         all(eid in members['evidence'] for eid in c['evidence_ids']), _PIVOT_ERROR)
            expected_algorithms = defaultdict(set)
            for eid in members['evidence']:
                for gid in by_ref['evidence'].get(eid, ()):
                    budget.charge()
                    add(gid, kind, target, None, 'SHARED_EVIDENCE_ID', eid)
                    if group_names[gid] == 'algorithms':
                        budget.charge(); expected_algorithms[gid].add(eid)
            links = {}
            for link in group['algorithm_links']:
                gid = link['group_id']; budget.charge()
                _require(gid in expected_algorithms and gid not in links and
                         link['basis'] == 'SHARED_EVIDENCE_ID' and link['href'] == 'algorithms.html#' + gid,
                         _PIVOT_ERROR)
                links[gid] = _pivot_ids(link['evidence_ids'], budget, evs)
            _require(links == expected_algorithms and _pivot_ids(group['algorithm_group_ids'], budget,
                     group_names) == set(expected_algorithms), _PIVOT_ERROR)
            occ_ids = _pivot_ids(group['recorded_occurrence_ids'], budget, occurrences)
            _require(kind == 'certificate' or not occ_ids, _PIVOT_ERROR)
            for oid in occ_ids:
                r = occurrences[oid]; _id(oid, 'occ-')
                budget.charge()
                aid, hid, cid = r['asset_id'], r['host_id'], r['collection_id']
                _require(oid == r['id'] == _key('occ', [hid, cid, aid, r['source_id'],
                         r['block_index'], r['detail_sha256']]) and oid not in seen_occ and aid in members['assets'] and
                         hid == ars[aid]['host_id'] == cols[cid]['host_id'] and
                         r['detail_state'] in ('VERIFIED_COMPANION', 'DETAIL_NOT_RETAINED'), _PIVOT_ERROR)
                _require(group['kind'] == 'RECORDED_FINGERPRINT'
                         and r['fingerprint'] == group['fingerprint']
                         and r['source']['source_kind'] == group['source_kind'], _PIVOT_ERROR)
                seen_occ.add(oid)
                refs = _pivot_ids(r['evidence_ids'], budget, evs)
                roles = r['role_evidence_ids']
                _require(type(roles) is dict, _PIVOT_ERROR)
                budget.charge(len(roles))
                _require('certificate' in roles and roles.keys() <= {'certificate', 'public-key', 'signature'}
                         and set(roles.values()) == refs and len(roles) == len(refs)
                         and refs <= members['evidence'], _PIVOT_ERROR)
                for role, eid in roles.items():
                    row = raw_evidence[eid]
                    _require((row['host_id'], row['asset_id'], row['collection_id']) == (hid, aid, cid)
                             and row['observation_key'] == r['source_id'] + '-' + str(r['block_index']) + '-' + role
                             and row.get('raw_sha256') == r['detail_sha256']
                             and row.get('evidence_ref') == r['detail_ref'] == 'cert-' + r['detail_sha256'], _PIVOT_ERROR)
                    for gid in by_ref['evidence'].get(eid, ()):
                        budget.charge()
                        add(gid, 'occurrence', oid, hid, 'SHARED_EVIDENCE_ID', eid, state=r['detail_state'])
    _require(seen_assets == asset_index['assets'].keys() and seen_occ == occurrences.keys(), _PIVOT_ERROR)

    # Saved findings only. Index explicit subject assets and claim/evidence
    # references, not host-only membership or a textual algorithm label.
    for fid, f in fs.items():
        hid, aid = f['subject']['host_id'], f['subject']['asset_id']
        for kind, field, basis in (('claims', 'claim_ids', 'SHARED_CLAIM_ID'),
                                    ('evidence', 'evidence_ids', 'SHARED_EVIDENCE_ID'),
                                    ('assets', None, 'EXACT_SUBJECT_ASSET_ID')):
            refs = f[field] if field is not None else (() if aid is None else (aid,))
            for ref in refs:
                budget.charge()
                row = registries[kind][ref]
                _require((row['subject'] if kind == 'claims' else row)['host_id'] == hid, _PIVOT_ERROR)
                for gid in by_ref[kind].get(ref, ()):
                    budget.charge()
                    _require(hid in memberships[gid]['hosts'], _PIVOT_ERROR)
                    add(gid, 'finding', fid, hid, basis, ref, state=f['assessment_state'], reason=f['reason_code'])

    # Freeze, with deterministic ordering. No raw rows or paths per edge.
    output = {}
    for gid in sorted(memberships):
        rows = []
        for (kind, ref, owner, basis), (refs, state, reason, attempt, dispatch) in sorted(edges[gid].items()):
            budget.charge(1 + len(refs))
            rows.append(_PivotRow(kind, ref, owner or None, basis, tuple(sorted(refs)), state, reason, attempt, dispatch))
        output[gid] = tuple(rows)
    backlinks = {}
    for hid, by_record in host_edges.items():
        budget.charge(len(by_record))
        frozen = {}
        for ref, hrefs in sorted(by_record.items()):
            budget.charge(len(hrefs))
            frozen[ref] = tuple(sorted(hrefs))
        backlinks[hid] = MappingProxyType(frozen)
    return _ReverseContext(rid, tuple(ids), projection, MappingProxyType(output), MappingProxyType(backlinks))


def _render_crypto_projection(result, *, page_limit=None, total_limit=None, pivots=None):
    """Render the same trusted projection; optional internal remaining byte caps."""
    if pivots is not None:
        _require(type(pivots) is _ReverseContext and pivots.projection is result
                 and pivots.run_id == result['run_id'] and set(result['hosts']) <= set(pivots.expected_hosts)
                 and set(pivots.groups) == {g['id'] for n in ('algorithms', 'libraries')
                                           for g in result[n]['groups']}, _PIVOT_ERROR)
    pages = {}
    cap = _MAX_HTML if page_limit is None else min(_MAX_HTML, page_limit)
    remaining = total_limit
    try:
        env = Environment(loader=FileSystemLoader(str(_TEMPLATES)), autoescape=True,
                          undefined=StrictUndefined, keep_trailing_newline=True)
        for name in ('algorithms', 'libraries'):
            limit = cap if remaining is None else min(cap, remaining)
            out = bytearray()
            for chunk in env.get_template(name + '.html.j2').generate(p=result, index=result[name], pivots=pivots.groups if pivots is not None else None):
                raw = chunk.encode('utf-8')
                _require(len(raw) <= limit - len(out), 'CRYPTO_INDEX_SIZE_LIMIT')
                out.extend(raw)
            pages[name + '.html'] = bytes(out)
            if remaining is not None:
                remaining -= len(out)
    except (OSError, TemplateError, UnicodeError):
        raise run_store.StoreError('CRYPTO_INDEX_RENDER_ERROR') from None
    return pages
