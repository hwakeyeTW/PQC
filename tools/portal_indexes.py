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


def _render_crypto_projection(result, *, page_limit=None, total_limit=None):
    """Render the same trusted projection; optional internal remaining byte caps."""
    pages = {}
    cap = _MAX_HTML if page_limit is None else min(_MAX_HTML, page_limit)
    remaining = total_limit
    try:
        env = Environment(loader=FileSystemLoader(str(_TEMPLATES)), autoescape=True,
                          undefined=StrictUndefined, keep_trailing_newline=True)
        for name in ('algorithms', 'libraries'):
            limit = cap if remaining is None else min(cap, remaining)
            out = bytearray()
            for chunk in env.get_template(name + '.html.j2').generate(p=result, index=result[name]):
                raw = chunk.encode('utf-8')
                _require(len(raw) <= limit - len(out), 'CRYPTO_INDEX_SIZE_LIMIT')
                out.extend(raw)
            pages[name + '.html'] = bytes(out)
            if remaining is not None:
                remaining -= len(out)
    except (OSError, TemplateError, UnicodeError):
        raise run_store.StoreError('CRYPTO_INDEX_RENDER_ERROR') from None
    return pages
