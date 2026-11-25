"""Read-only certificate/service index previews of a trusted Store.open result.

No discovery, assessment, companion loading, report publication or inference
from paths, names, hashes or host co-location. Recorded certificate positions
are not verified companion details. Publication and actual backlinks are later
work; the caller must supply the unmodified validated PublishedRun.
"""
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re

from jinja2 import Environment, FileSystemLoader, StrictUndefined, TemplateError

from tools import cert_assets, evidence, portal_indexes, run_store

_TEMPLATES = Path(__file__).resolve().parents[1] / 'templates' / 'portal'
_MAX_JSON = evidence.MAX_BYTES
_MAX_HTML = 16 * 1024 * 1024
_MAX_MEMBERSHIPS = evidence.MAX_BYTES // 66
_HEX = re.compile(r'[0-9a-f]{64}\Z')
_OCCURRENCE = re.compile(r'(src-[0-9a-f]{64})-([1-9][0-9]{0,2})-(certificate|public-key|signature)\Z')
_USABLE = ('COLLECTED', 'PARTIAL')
_LEGACY_CERT_SCOPES = ('system-certificates', 'nginx-certificates')
_LEGACY_ROLES = {'public-key-algorithm': 'public-key', 'public-key-type': 'public-key',
                 'signature-algorithm': 'signature'}
_TLS_FIELDS = ('legacy-tls-port', 'tls-protocol', 'cipher', 'key-exchange',
               'peer-signature', 'server-signature')
_SLOTS = {'system_certs': 'system-certificates', 'nginx_certs': 'nginx-certificates',
          'sshd': 'sshd-config', 'tls_services': 'tls-services'}
_LEVELS = dict(zip(evidence.LEVELS, ('Installed', 'Supported (runtime)',
    'Configured', 'Negotiable (service)', 'Observed in use')))
_REF_KEYS = ('host_ids', 'asset_ids', 'evidence_ids', 'claim_ids', 'recorded_occurrence_ids')


def _require(ok, code='INVALID_ASSET_INDEX_PUBLICATION'):
    run_store.require(ok, code)


def _serial(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False)


def _key(prefix, value):
    return prefix + '-' + hashlib.sha256(_serial(value).encode('ascii')).hexdigest()


def _id(value, prefix):
    _require(type(value) is str and re.fullmatch(prefix + r'[0-9a-f]{64}', value) is not None)
    return value


def _href(hid, ref=None, prefix=None):
    _id(hid, 'h-')
    return hid + '.html#' + (_id(ref, prefix) if ref is not None else hid)


def _bounded_bytes(value):
    out = bytearray()
    encoder = json.JSONEncoder(ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False)
    for chunk in encoder.iterencode(value):
        part = chunk.encode('ascii')
        _require(len(part) <= _MAX_JSON - len(out), 'ASSET_INDEX_SIZE_LIMIT')
        out.extend(part)
    return bytes(out)


class _Budget:
    def __init__(self):
        self.used = 0

    def charge(self, count=1):
        self.used += count
        _require(self.used <= _MAX_MEMBERSHIPS, 'ASSET_INDEX_SIZE_LIMIT')


def _cert_scope(c):
    s = c['source']
    return (c['collector_id'] == s['producer_id'] == cert_assets.COLLECTOR and
            c['collector_version'] == s['producer_version'] == cert_assets.VERSION and
            s['source_kind'] in ('SYNTHETIC', 'NATIVE_COLLECTOR') and
            c['scope_key'] in cert_assets.ROOTS and c['collection_state'] in _USABLE)


def _role_algorithm(row, role):
    a = row['algorithm']
    if role == 'certificate':
        return a is None
    return (a is not None and a['observed_name'] is not None and
            (a['primitive'] == ('PUBLIC_KEY' if role == 'public-key' else 'SIGNATURE') or
             (a['primitive'] == a['family'] == 'UNKNOWN' and a['algorithm_id'] is None)))


def _legacy_scope(c, scopes):
    return (c['collector_id'] == 'legacy-import' and c['source']['source_kind'] == 'LEGACY_IMPORT'
            and c['scope_key'] in scopes)


def _certificate_occurrences(document, budget):
    """Internal pure subprojection of validated #18 Evidence, not a companion.

    A location needs its exact certificate row and coherent role/ref/hash
    evidence. Opaque hashes are retained as identifiers, never decoded or
    accepted as proof of an unretained file, target, vhost or date.
    """
    assets = {a['asset_id']: a for a in document['assets'] if a['asset_kind'] == 'certificate'}
    collections = {c['collection_id']: c for c in document['collections']}
    candidates = defaultdict(list)
    source_collections = defaultdict(set)
    for r in document['evidence']:
        if r['asset_id'] not in assets:
            continue
        m = _OCCURRENCE.fullmatch(r['observation_key'])
        if m is None or int(m[2]) > cert_assets.MAX_BLOCKS:
            continue
        # #18 source IDs are unique within a host across its roots. Do not
        # let contradictory claims at a location split into two fingerprints.
        budget.charge(2)
        source_collections[(r['host_id'], m[1])].add(r['collection_id'])
        candidates[(r['host_id'], m[1], int(m[2]))].append((r, m[3]))
    result = {}
    for (hid, sid, block), members in sorted(candidates.items()):
        roles = {role: r for r, role in members}
        if (len(source_collections[(hid, sid)]) != 1 or len(roles) != len(members) or
                'certificate' not in roles):
            continue
        first = roles['certificate']; aid = first['asset_id']; a = assets[aid]
        c = collections[first['collection_id']]; fp = a['identity_key']
        sha = first.get('raw_sha256')
        if not (_cert_scope(c) and _HEX.fullmatch(fp) and type(sha) is str and _HEX.fullmatch(sha)):
            continue
        def matches(r, role):
            return (r['host_id'] == a['host_id'] == hid and r['asset_id'] == aid and
                    r['collection_id'] == c['collection_id'] and r['source'] == c['source'] and
                    r['observed_at'] == c['observed_at'] and r['evidence_kind'] == 'ASSET_METADATA' and
                    r['data'] == {'name': fp, 'version': None} and _role_algorithm(r, role) and
                    r.get('raw_sha256') == sha and r.get('evidence_ref') == 'cert-' + sha)
        if not all(matches(r, role) for role, r in roles.items()):
            continue
        oid = _key('occ', [hid, c['collection_id'], aid, sid, block, sha])
        budget.charge(8 + len(roles) * 2)
        result[oid] = dict(id=oid, host_id=hid, asset_id=aid, collection_id=c['collection_id'],
            root=c['scope_key'], source_id=sid, target_id=None, block_index=block, fingerprint=fp,
            detail_ref='cert-' + sha, detail_sha256=sha, observed_at=first['observed_at'],
            source=dict(first['source']), evidence_ids=sorted(r['evidence_id'] for r in roles.values()),
            role_evidence_ids={role: r['evidence_id'] for role, r in sorted(roles.items())},
            path=None, vhost=None, reason_code='DETAIL_NOT_RETAINED')
    return result


def _new_group(prefix, identity, kind):
    gid = _key(prefix, identity)
    return dict(id=gid, kind=kind, **{k: set() for k in _REF_KEYS},
                algorithm_group_ids=set())


def _certificate_groups(document, occurrences, budget):
    """Group only recorded fingerprint proof, else retain host-scoped assets."""
    rows = {r['evidence_id']: r for r in document['evidence']}
    collections = {c['collection_id']: c for c in document['collections']}
    by_asset = defaultdict(list)
    for oid, item in occurrences.items():
        budget.charge()
        by_asset[item['asset_id']].append(oid)
    groups, membership = {}, {}
    for a in document['assets']:
        if a['asset_kind'] != 'certificate':
            continue
        aid, hid = a['asset_id'], a['host_id']
        ids = by_asset.get(aid, ())
        legacy_cids = set()
        if not ids and a['identity_scope'] == 'RUN_SCOPED':
            for eid in a['evidence_ids']:
                r = rows[eid]; c = collections[r['collection_id']]
                if (_legacy_scope(c, _LEGACY_CERT_SCOPES) and r['source'] == c['source'] and
                        r['evidence_kind'] == 'ASSET_METADATA' and
                        re.fullmatch(r'legacy-[0-9a-f]{64}', r['observation_key']) and
                        r['data'] == {'name': c['scope_key'], 'version': None} and r['algorithm'] is None):
                    budget.charge()
                    legacy_cids.add(c['collection_id'])
        if ids:
            source_kind = occurrences[ids[0]]['source']['source_kind']
            _require(all(occurrences[oid]['source']['source_kind'] == source_kind for oid in ids))
            kind, fp = 'RECORDED_FINGERPRINT', a['identity_key']
            identity = [kind, source_kind, fp]
        else:
            kind, fp = ('LEGACY_RUN_SCOPED' if legacy_cids else 'UNVERIFIED_IDENTITY'), None
            source_kind = document['run']['source']['source_kind']
            identity = [kind, document['run']['run_id'], hid, aid]
        gid = _key('cert', identity)
        if gid not in groups:
            budget.charge(10)
            groups[gid] = _new_group('cert', identity, kind) | dict(fingerprint=fp,
                source_kind=source_kind, not_before=None, not_after=None, validity_state='UNKNOWN',
                issuer=None, subject=None, detail_state='DETAIL_NOT_RETAINED',
                service_binding_state='UNKNOWN', service_group_ids=[],
                role_ids={'public-key': set(), 'signature': set()}, bit_ids=set())
        g = groups[gid]; membership[aid] = gid
        budget.charge(3 + len(a['evidence_ids']) + len(ids))
        g['host_ids'].add(hid); g['asset_ids'].add(aid); g['evidence_ids'].update(a['evidence_ids'])
        g['recorded_occurrence_ids'].update(ids)
        for oid in ids:
            for role, eid in occurrences[oid]['role_evidence_ids'].items():
                if role in g['role_ids']:
                    budget.charge()
                    g['role_ids'][role].add(eid)
        for eid in a['evidence_ids']:
            r = rows[eid]
            if (r['collection_id'] not in legacy_cids or r['source'] != collections[r['collection_id']]['source'] or
                    r['evidence_kind'] != 'LEGACY_OBSERVATION'):
                continue
            field, value = r['data']['field'], r['data']['value']
            role = _LEGACY_ROLES.get(field)
            if (role and type(value) is str and _role_algorithm(r, role) and
                    r['algorithm']['observed_name'] == value):
                budget.charge()
                g['role_ids'][role].add(eid)
            elif field == 'public-key-bits' and type(value) is int and 0 < value <= 100000000 and r['algorithm'] is None:
                budget.charge()
                g['bit_ids'].add(eid)
    for g in groups.values():
        for role, ids in g.pop('role_ids').items():
            values = {_serial([r['algorithm_id'], r['taxonomy_version'], r['primitive'], r['family'],
                               r['observed_name'] if r['algorithm_id'] is None else None])
                      for r in (rows[eid]['algorithm'] for eid in ids)}
            known = any(rows[eid]['algorithm']['algorithm_id'] is not None for eid in ids)
            g[role.replace('-', '_')] = dict(evidence_ids=sorted(ids),
                state='CONFLICT' if len(values) > 1 else 'RECORDED' if known else 'UNKNOWN')
        bits = g.pop('bit_ids'); values = {rows[eid]['data']['value'] for eid in bits}
        g['public_key_bits'] = next(iter(values)) if len(values) == 1 else None
        g['public_key_bits_state'] = 'CONFLICT' if len(values) > 1 else 'RECORDED' if values else 'UNKNOWN'
        g['public_key_bits_evidence_ids'] = sorted(bits)
    return groups, membership


def _legacy_tls(r, c):
    if (not _legacy_scope(c, ('tls-services',)) or r['source'] != c['source'] or
            r['evidence_kind'] != 'LEGACY_OBSERVATION' or r['data']['field'] not in _TLS_FIELDS):
        return False
    field, value = r['data']['field'], r['data']['value']
    return (type(value) is int and 1 <= value <= 65535 if field == 'legacy-tls-port' else
            type(value) is str)


def _service_groups(document, budget):
    rows = {r['evidence_id']: r for r in document['evidence']}
    collections = {c['collection_id']: c for c in document['collections']}
    groups, membership = {}, {}
    for a in document['assets']:
        if a['asset_kind'] != 'service':
            continue
        aid, hid = a['asset_id'], a['host_id']
        identity = [document['run']['run_id'], hid, aid]
        g = _new_group('svc', identity, 'SERVICE_ASSET')
        groups[g['id']] = g; membership[aid] = g['id']
        budget.charge(10 + len(a['evidence_ids']))
        g['host_ids'].add(hid); g['asset_ids'].add(aid); g['evidence_ids'].update(a['evidence_ids'])
        endpoints, legacy, ports = [], [], set()
        for eid in a['evidence_ids']:
            r = rows[eid]; c = collections[r['collection_id']]
            if _legacy_tls(r, c) and a['identity_scope'] == 'RUN_SCOPED':
                budget.charge(2)
                legacy.append(eid)
                if r['data']['field'] == 'legacy-tls-port':
                    ports.add(r['data']['value'])
            elif (r['evidence_kind'] == 'AUTHORIZED_NEGOTIATION' and
                    r['source']['source_kind'] != 'LEGACY_IMPORT'):
                d = r['data']; ctx = d['conditions']
                # The existing Evidence validator already requires this
                # exact service/host binding; never join by port or name.
                _require(ctx['host_id'] == hid and ctx['service_asset_id'] == aid)
                budget.charge(3)
                endpoints.append(dict(evidence_id=eid, endpoint_ref=ctx['endpoint_ref'],
                    protocol=ctx['protocol'], context_ref=ctx['context_ref'],
                    authorization_ref=ctx['authorization_ref'], outcome=d['outcome'],
                    collection_state=c['collection_state']))
        g.update(kind='LEGACY_SERVICE' if legacy else 'SERVICE_ASSET',
                 endpoint_state='RECORDED_CONTEXT' if endpoints else 'HISTORICAL_ONLY' if len(ports) == 1 else
                     'CONFLICT' if len(ports) > 1 else 'UNKNOWN',
                 endpoints=sorted(endpoints, key=lambda x: x['evidence_id']),
                 legacy_port=next(iter(ports)) if len(ports) == 1 else None,
                 legacy_evidence_ids=sorted(legacy), certificate_binding_state='UNKNOWN', certificate_group_ids=[])
    return groups, membership


def _coverage(manifest, collections, budget):
    by_host = defaultdict(list)
    for c in collections.values():
        budget.charge()
        by_host[c['host_id']].append(c)
    slots = {(x['host_id'], x['slot']) for x in manifest['artifacts'] if x['kind'] == 'detail'}
    result = []
    for h in sorted(manifest['hosts'], key=lambda x: x['host_id']):
        hid = h['host_id']; flags = manifest['flags']; terminal = h['terminal']
        outcomes = {} if terminal is None else {x['collector_id']: x for x in terminal['collectors']}
        refs = defaultdict(list)
        for c in by_host[hid]:
            for short, legacy in _SLOTS.items():  # four fixed slots only
                if (c['collector_id'] == short or _legacy_scope(c, (legacy,)) or
                        (short == 'system_certs' and c['collector_id'] == cert_assets.COLLECTOR and
                         c['scope_key'] in cert_assets.ROOTS)):
                    budget.charge()
                    refs[short].append(c['collection_id'])
        for short in _SLOTS:
            requested = None if flags is None else flags[hid][short]
            terminal_row = outcomes.get(short, outcomes.get('pqc_collect_' + short))
            ids = sorted(set(refs[short]) | (set(terminal_row['collection_ids']) if terminal_row else set()))
            budget.charge(5 + len(ids))
            if terminal_row is not None:
                state, reason, rc = (terminal_row[k] for k in ('state', 'reason_code', 'rc'))
                basis = 'TERMINAL'
            elif requested is False:
                state, reason, rc, basis = 'NOT_SCANNED', 'DISABLED_FROZEN_FLAG', None, 'FROZEN_FLAG'
            elif h['host_state'] == 'UNREACHABLE':
                state, reason, rc, basis = 'UNREACHABLE', h['reason_code'], None, 'HOST_TERMINAL'
            elif h['host_state'] == 'NOT_ATTEMPTED':
                state, reason, rc, basis = 'NOT_SCANNED', h['reason_code'], None, 'HOST_TERMINAL'
            elif len(ids) == 1:
                c = collections[ids[0]]
                state, reason, rc, basis = c['collection_state'], c['reason_code'], None, 'COLLECTION'
            else:
                state, reason, rc, basis = 'UNKNOWN', 'TERMINAL_NOT_RETAINED', None, 'UNKNOWN'
            detail = ('certificate-inventory' if short in ('system_certs', 'nginx_certs') else
                      'ssh-posture' if short == 'sshd' else 'service-inventory')
            result.append(dict(host_id=hid, slot=short, requested=requested, state=state, reason_code=reason,
                rc=rc, basis=basis, collection_ids=ids, terminal_retained=terminal_row is not None,
                slot_state='RECORDED' if ids else 'MISSING_SLOT',
                detail_slot_state='GENERIC_DETAIL_ONLY' if (hid, detail) in slots else 'DETAIL_NOT_RETAINED',
                collection_states=[dict(collection_id=cid, state=collections[cid]['collection_state'],
                                        reason_code=collections[cid]['reason_code']) for cid in ids]))
    return result


def _finish_index(name, groups, rows, claims, budget):
    totals = {k: set() for k in _REF_KEYS}; output = []
    for gid, g in sorted(groups.items()):
        levels = {level: dict(label=label, observations=defaultdict(list), claims=defaultdict(list))
                  for level, label in _LEVELS.items()}
        for eid in sorted(g['evidence_ids']):
            r = rows[eid]; level = r['level']
            if level is not None:
                budget.charge()
                levels[level]['observations'][r['observation_state']].append(eid)
        for cid in sorted(g['claim_ids']):
            cl = claims[cid]
            budget.charge()
            levels[cl['level']]['claims'][cl['assessment_state']].append(cid)
        for level in levels.values():
            for key in ('observations', 'claims'):
                level[key] = dict(sorted(level[key].items()))
                level[key[:-1] + '_counts'] = {state: len(ids) for state, ids in level[key].items()}
        for k in totals:
            budget.charge(len(g[k])); totals[k].update(g[k])
        output.append({**g, **{k: sorted(g[k]) for k in (*totals, 'algorithm_group_ids')},
            'counts': {k: len(g[k]) for k in totals}, 'levels': levels,
            'backlink': name + '.html#' + gid})
    budget.charge(sum(len(v) for v in totals.values()))
    return dict(groups=output, **{k: sorted(v) for k, v in totals.items()},
                counts={'groups': len(output), **{k: len(v) for k, v in totals.items()}},
                categories=dict(sorted(Counter(g['kind'] for g in output).items())))


def project_asset_indexes(published):
    """Project recorded sets; never re-evaluate or open unretained companions."""
    _require(type(published) is run_store.PublishedRun)
    m, doc, assessed, artifacts = published
    _require(m['publication_state'] == 'PUBLISHED' and m['run_id'] == doc['run']['run_id'] and
             m['expected_host_ids'] == sorted(set(m['expected_host_ids'])) and
             0 < len(m['expected_host_ids']) <= 1000 and
             set(m['expected_host_ids']) == set(doc['run']['expected_host_ids']))
    for name in ('evidence.json', *(['assessed_evidence.json'] if assessed is not None else [])):
        _require(type(artifacts.get(name)) is bytes and 0 < len(artifacts[name]) <= evidence.MAX_BYTES,
                 'ASSET_INDEX_SIZE_LIMIT')
    budget = _Budget()
    occurrences = _certificate_occurrences(doc, budget)
    certs, cert_members = _certificate_groups(doc, occurrences, budget)
    services, service_members = _service_groups(doc, budget)
    groups = certs | services; membership = cert_members | service_members
    collections = {c['collection_id']: c for c in doc['collections']}
    rows, claims, assets, hosts = {}, {}, {}, {}
    for h in sorted(m['hosts'], key=lambda x: x['host_id']):
        hid = h['host_id']; budget.charge()
        hosts[hid] = dict(host_id=hid, target_id=h['target_id'], host_state=h['host_state'],
                          reason_code=h['reason_code'], href=_href(hid))
    _require(set(hosts) == set(m['expected_host_ids']))
    for a in sorted(doc['assets'], key=lambda x: x['asset_id']):
        aid, hid = a['asset_id'], a['host_id']
        if aid in membership:
            budget.charge()
            assets[aid] = dict(asset_id=aid, host_id=hid, asset_kind=a['asset_kind'],
                identity_scope=a['identity_scope'], href=_href(hid, aid, 'a-'))
    for r in sorted(doc['evidence'], key=lambda x: x['evidence_id']):
        eid, hid, aid = r['evidence_id'], r['host_id'], r['asset_id']
        if aid not in membership:
            continue
        budget.charge()
        c = collections[r['collection_id']]
        level, state = portal_indexes._observation(r, c)
        if r['source']['source_kind'] == 'LEGACY_IMPORT' and level in ('L4', 'L5'):
            level, state = None, None
        facts = {}
        if (_legacy_tls(r, c) or (aid in cert_members and r['evidence_kind'] == 'LEGACY_OBSERVATION' and
                _legacy_scope(c, _LEGACY_CERT_SCOPES) and r['data']['field'] in (*_LEGACY_ROLES, 'public-key-bits'))):
            facts = dict(r['data'])
        elif level is not None:
            facts = {k: r['data'][k] for k in ('present', 'supported', 'allowed', 'outcome') if k in r['data']}
        rows[eid] = dict(evidence_id=eid, host_id=hid, asset_id=aid, evidence_kind=r['evidence_kind'],
            collection_id=c['collection_id'], collector_id=c['collector_id'], scope_key=c['scope_key'],
            collection_state=c['collection_state'], reason_code=c['reason_code'], source=dict(r['source']),
            observed_at=r['observed_at'], algorithm=None if r['algorithm'] is None else dict(r['algorithm']),
            facts=facts, conditions=dict(r['data']['conditions']) if level in ('L4', 'L5') else None,
            level=level, observation_state=state, href=_href(hid, eid, 'e-'))
    for cl in (() if assessed is None else sorted(assessed['claims'], key=lambda x: x['claim_id'])):
        subject = cl['subject']; aid = subject.get('asset_id')
        if aid not in membership:
            continue
        cid = cl['claim_id']; hid = subject['host_id']; refs = sorted(cl['evidence_ids'])
        _require(assets[aid]['host_id'] == hid and all(eid in rows and rows[eid]['asset_id'] == aid for eid in refs))
        budget.charge(2 + len(refs))
        groups[membership[aid]]['claim_ids'].add(cid)
        claims[cid] = dict(claim_id=cid, subject=dict(subject), level=cl['level'],
            assessment_state=cl['assessment_state'], reason_code=cl['reason_code'], rule_id=cl['rule_id'],
            rule_version=cl['rule_version'], evidence_ids=refs,
            conditions=None if cl['conditions'] is None else dict(cl['conditions']), href=_href(hid, cid, 'cl-'))
    # Use #21's actual group/evidence membership. Only a shared evidence ID
    # establishes a pivot, not a matching algorithm label or host/asset name.
    crypto = portal_indexes.project_crypto_indexes(published)
    relations = defaultdict(set)
    for ag in crypto['algorithms']['groups']:
        gid = _id(ag['id'], 'alg-')
        for eid in ag['evidence_ids']:
            budget.charge()
            if eid not in rows:
                continue
            group = groups[membership[rows[eid]['asset_id']]]
            budget.charge(2)
            group['algorithm_group_ids'].add(gid)
            relations[(group['id'], gid)].add(eid)
    links = defaultdict(list)
    for (gid, ag), refs in sorted(relations.items()):
        budget.charge(3 + len(refs))
        links[gid].append(dict(group_id=ag, href='algorithms.html#' + ag, evidence_ids=sorted(refs),
                               basis='SHARED_EVIDENCE_ID'))
    for gid, group in groups.items():
        group['algorithm_links'] = links[gid]
    result = dict(projection_version=1, run_id=m['run_id'], assessed=assessed is not None,
        certificates=_finish_index('certificates', certs, rows, claims, budget),
        services=_finish_index('services', services, rows, claims, budget),
        hosts=hosts, assets=assets, evidence=rows, claims=claims, occurrences=occurrences,
        coverage=_coverage(m, collections, budget))
    _bounded_bytes(result)
    return result


def render_asset_indexes(published):
    """Return (projection, two fixed preview page buffers), with no writes."""
    result = project_asset_indexes(published)
    pages = {}
    try:
        env = Environment(loader=FileSystemLoader(str(_TEMPLATES)), autoescape=True,
                          undefined=StrictUndefined, keep_trailing_newline=True)
        for name in ('certificates', 'services'):
            out = bytearray()
            for chunk in env.get_template(name + '.html.j2').generate(p=result, index=result[name]):
                raw = chunk.encode('utf-8')
                _require(len(raw) <= _MAX_HTML - len(out), 'ASSET_INDEX_SIZE_LIMIT')
                out.extend(raw)
            pages[name + '.html'] = bytes(out)
    except (OSError, TemplateError, UnicodeError):
        raise run_store.StoreError('ASSET_INDEX_RENDER_ERROR') from None
    return result, pages
