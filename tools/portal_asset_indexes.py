"""Read-only certificate/service index previews of a trusted Store.open result.

No discovery, assessment, report publication or inference from paths, names,
hashes or host co-location. Only C1 verified certificate companion bytes may
enrich recorded positions. Publication and actual backlinks are later work;
the caller must supply the unmodified validated PublishedRun.
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


_METADATA_FIELDS = ('public_key_algorithm', 'public_key_bits', 'signature_inner',
                    'signature_outer', 'issuer', 'subject', 'not_before', 'not_after')


def _companion_require(ok):
    _require(ok, 'INVALID_ASSET_INDEX_COMPANION')


def _certificate_companions(published, occurrences, budget):
    """Join only the fixed, Store-verified C1 slot, never an external source.

    Store.open owns the handoff and frozen-rule replay. The index checks the
    retained bytes, exact references and location/role joins; it neither
    replays the producer nor classifies an algorithm from certificate text.
    """
    from tools import run_store_v2 as v2
    m, doc, _, artifacts = published
    try:
        if m.get('batch_contract') != v2.CONTRACT:
            _companion_require(not any(a.get('slot') in v2.SLOTS or a.get('kind') == v2.RULES_KIND
                                      for a in m['artifacts']) and
                not any(k.endswith('/' + slot + '.json') for k in artifacts for slot in v2.SLOTS) and
                not any(a['path'].endswith('/' + slot + '.json')
                        for a in m['missing_artifacts'] for slot in v2.SLOTS))
            return {}
        scope, _, entries = run_store._manifest_header(m, m['run_id'])
        _companion_require(m['run_kind'] == 'SYNTHETIC' and m['source'] == v2.SOURCE and
            doc['schema_version'] == m['evidence_schema_version'] == '1.1.0' and
            doc['run']['source'] == v2.SOURCE and
            set(artifacts) == {a['path'] for a in entries.values()})
        rid = m['run_id']
        cert_collections = defaultdict(dict)
        for c in doc['collections']:
            if c['collector_id'] == cert_assets.COLLECTOR:
                bucket = cert_collections[c['host_id']]
                _companion_require(c['scope_key'] in cert_assets.ROOTS and c['scope_key'] not in bucket)
                budget.charge()
                bucket[c['scope_key']] = c
        rows = defaultdict(dict)
        for r in doc['evidence']:
            if r['collection_id'] in {c['collection_id'] for c in cert_collections[r['host_id']].values()}:
                budget.charge()
                _companion_require(r['evidence_id'] not in rows[r['collection_id']])
                rows[r['collection_id']][r['evidence_id']] = r
        by_host = defaultdict(dict)
        for oid, occurrence in occurrences.items():
            key = (occurrence['root'], occurrence['source_id'], occurrence['block_index'])
            bucket = by_host[occurrence['host_id']]
            _companion_require(key not in bucket)
            budget.charge(2)
            bucket[key] = oid
        missing = {}
        for a in m['missing_artifacts']:
            if a['path'].endswith('/' + v2.CERTIFICATE + '.json'):
                _companion_require(a['path'] not in missing and set(a) == {'path', 'reason_code'} and
                                   a['reason_code'] == 'REQUIRED_DETAIL_MISSING')
                budget.charge()
                missing[a['path']] = a['reason_code']
        status = {}
        for h in m['hosts']:
            hid = _id(h['host_id'], 'h-')
            path = 'details/' + hid + '/' + v2.CERTIFICATE + '.json'
            entry = entries.get(('detail', hid, v2.CERTIFICATE))
            required = scope['flags'][hid]['system_certs']
            terminal = h['terminal']
            outcomes = [] if terminal is None else [c for c in terminal['collectors']
                                                    if c['collector_id'] == 'pqc_collect_system_certs']
            _companion_require(terminal is None or (len(outcomes) == 1 and
                outcomes[0]['requested'] is required and terminal['target_id'] == h['target_id'] and
                terminal['attempted'] is h['attempted']))
            coll = cert_collections[hid]
            ids = sorted(c['collection_id'] for c in coll.values())
            _companion_require((outcomes[0]['collection_ids'] if outcomes else []) == ids)
            if entry is None:
                _companion_require(not ids and not by_host[hid] and path not in artifacts and
                                   (path in missing) == required and
                                   (not required or h['host_state'] != 'COMPLETE'))
                status[hid] = missing.pop(path) if required else 'NOT_REQUIRED'
                continue
            _companion_require(required and h['attempted'] is True and path not in missing and
                entry['path'] == path and entry['required'] is True and
                entry['format_version'] == cert_assets.VERSION and set(coll) == set(cert_assets.ROOTS))
            es = {eid: r for cid in ids for eid, r in rows[cid].items()}
            _companion_require(entry['collection_ids'] == ids and entry['evidence_ids'] == sorted(es) and
                entry['asset_ids'] == sorted({r['asset_id'] for r in es.values() if r['asset_id'] is not None}))
            raw = artifacts[path]
            _companion_require(type(raw) is bytes and len(raw) == entry['size'] and
                0 < len(raw) <= v2.SLOTS[v2.CERTIFICATE] and hashlib.sha256(raw).hexdigest() == entry['sha256'])
            details = v2.parse_detail(hid, v2.CERTIFICATE, raw)['value']
            _companion_require(set(details) == {'detail_format', 'detail_version', 'run_id', 'host_id',
                'source', 'observed_at', 'snapshot', 'roots', 'occurrences'} and
                details['detail_format'] == cert_assets.FORMAT and details['detail_version'] == cert_assets.VERSION and
                details['host_id'] == hid and details['run_id'] == rid and details['source']['source_kind'] == 'SYNTHETIC')
            cert_assets.source_record(details['source'])
            common = {k: details[k] for k in ('run_id', 'host_id', 'source', 'observed_at')}
            snapshot = details['snapshot']
            cert_assets.validate_snapshot(snapshot)
            roots = details['roots']
            _companion_require(type(roots) is list and [r['root'] for r in roots] == list(cert_assets.ROOTS))
            blocks = {}
            for rr in roots:
                root = rr['root']; c = coll[root]; cid = c['collection_id']
                root_record = {**common, 'root': root, 'collection_id': cid, 'evidence_ids': sorted(rows[cid])}
                _companion_require(cert_assets.strict_equal(rr, {**root_record,
                    'detail_sha256': cert_assets.digest(dict(record=root_record, result=snapshot[root]))}) and
                    c['source'] == common['source'] and c['observed_at'] == common['observed_at'] and
                    c['evidence_ids'] == root_record['evidence_ids'] and
                    (c['collection_state'], c['reason_code']) == cert_assets.root_status(snapshot[root])[:2])
                for src in snapshot[root]['sources']:
                    for index, block in enumerate(src['blocks'], 1):
                        if block['certificate'] is not None:
                            budget.charge(2)
                            blocks[(root, src['source_id'], index)] = (src, block)
            _companion_require(type(details['occurrences']) is list and
                len(details['occurrences']) == len(blocks) == len(by_host[hid]))
            seen = set()
            for item in details['occurrences']:
                key = (item['root'], item['source_id'], item['block_index'])
                _companion_require(type(item['block_index']) is int and key in blocks and key not in seen and
                                   key in by_host[hid])
                seen.add(key)
                src, block = blocks[key]; cert = block['certificate']
                old = occurrences[by_host[hid][key]]
                cid = coll[key[0]]['collection_id']; aid = old['asset_id']
                prefix = src['source_id'] + '-' + str(key[2]) + '-'
                roles = {'certificate': None}
                if cert['public_key_algorithm'] is not None:
                    roles['public-key'] = cert['public_key_algorithm']
                if cert['signature_inner'] is not None and cert['signature_inner'] == cert['signature_outer']:
                    roles['signature'] = cert['signature_inner']
                role_ids = {role: evidence.evidence_id(rid, hid, cid, prefix + role) for role in roles}
                record = dict(**common, collection_id=cid, asset_id=aid, root=key[0], source_id=key[1],
                    target_id=src['target_id'], block_index=key[2], fingerprint=cert['fingerprint'],
                    evidence_ids=sorted(role_ids.values()))
                dh = cert_assets.digest(dict(record=record, block=block, format=src['format']))
                expected = {**record, 'detail_ref': 'cert-' + dh, 'detail_sha256': dh}
                _companion_require(cert_assets.strict_equal(item, expected) and
                    all(cert_assets.strict_equal(old[k], expected[k]) for k in expected if k not in ('run_id', 'target_id')) and
                    old['role_evidence_ids'] == role_ids)
                for role, eid in role_ids.items():
                    r = es[eid]
                    _companion_require(r['host_id'] == hid and r['asset_id'] == aid and r['collection_id'] == cid and
                        r['source'] == common['source'] and r['observed_at'] == common['observed_at'] and
                        r['observation_key'] == prefix + role and r['evidence_ref'] == expected['detail_ref'] and
                        r['raw_sha256'] == dh and _role_algorithm(r, role) and
                        (roles[role] is None or r['algorithm']['observed_name'] == roles[role]))
                metadata = {k: cert[k] for k in _METADATA_FIELDS}
                # Charge the new memberships, fields and escaped string bytes
                # before retaining them; the final canonical byte cap still applies.
                budget.charge(4 + len(metadata) + len(cert['gaps']) + sum(
                    (len(_serial(x)) + 65) // 66 for x in (*metadata.values(), *cert['gaps'])))
                old.update(detail_state='VERIFIED_COMPANION', target_id=src['target_id'],
                           certificate_metadata=metadata, metadata_gaps=list(cert['gaps']), reason_code=block['reason'])
            _companion_require(seen == blocks.keys() == by_host[hid].keys())
            status[hid] = 'VERIFIED_COMPANION'
        _companion_require(not missing and set(cert_collections) <= set(m['expected_host_ids']) and
                           set(by_host) <= set(m['expected_host_ids']))
        return status
    except run_store.StoreError as exc:
        if exc.code == 'ASSET_INDEX_SIZE_LIMIT':
            raise
        raise run_store.StoreError('INVALID_ASSET_INDEX_COMPANION') from None
    except (KeyError, TypeError, ValueError, AttributeError, IndexError, OverflowError, RecursionError):
        raise run_store.StoreError('INVALID_ASSET_INDEX_COMPANION') from None


def _certificate_metadata(certs, occurrences, budget):
    """Summarize actual retained public metadata without first-value wins."""
    for occurrence in occurrences.values():
        if 'detail_state' not in occurrence:
            budget.charge(3)
            occurrence.update(detail_state='DETAIL_NOT_RETAINED', certificate_metadata=None, metadata_gaps=[])
    for g in certs.values():
        ids = sorted(g['recorded_occurrence_ids'])
        verified = [oid for oid in ids if occurrences[oid]['detail_state'] == 'VERIFIED_COMPANION']
        budget.charge(4 + len(verified))
        g.update(verified_occurrence_ids=verified, verified_occurrence_count=len(verified),
                 detail_state=('VERIFIED_COMPANION' if verified and len(verified) == len(ids) else
                               'PARTIAL_COMPANION' if verified else 'DETAIL_NOT_RETAINED'))
        fields = {}
        for field in _METADATA_FIELDS:
            values = {oid: occurrences[oid]['certificate_metadata'][field] for oid in verified
                      if occurrences[oid]['certificate_metadata'][field] is not None}
            distinct = set(values.values())
            budget.charge(3 + len(values) + sum((len(_serial(v)) + 65) // 66 for v in distinct))
            fields[field] = dict(value=next(iter(distinct)) if len(distinct) == 1 else None,
                state='CONFLICT' if len(distinct) > 1 else 'UNKNOWN' if not distinct else
                      'RECORDED' if len(values) == len(ids) else 'PARTIAL', occurrence_ids=sorted(values))
        gaps = sorted({gap for oid in verified for gap in occurrences[oid]['metadata_gaps']})
        budget.charge(3 + len(gaps))
        g['metadata_fields'] = fields; g['metadata_gaps'] = gaps
        for k in ('not_before', 'not_after', 'issuer', 'subject'):
            g[k] = fields[k]['value']
        before, after = fields['not_before'], fields['not_after']
        pairs = sorted(set(before['occurrence_ids']) & set(after['occurrence_ids']))
        budget.charge(len(pairs))
        g['validity_state'] = ('CONFLICT' if 'VALIDITY_CONFLICT' in gaps or 'CONFLICT' in (before['state'], after['state']) else
            'UNKNOWN' if before['state'] == after['state'] == 'UNKNOWN' else
            'RECORDED' if before['state'] == after['state'] == 'RECORDED' else 'PARTIAL')
        # A shared interval is not a pair of independently aggregated ends.
        g['validity_occurrence_ids'] = pairs if g['validity_state'] != 'CONFLICT' else []
        if not g['validity_occurrence_ids'] and g['not_before'] is not None and g['not_after'] is not None:
            g['not_before'] = g['not_after'] = None
        g['signature_metadata_state'] = ('CONFLICT' if 'SIGNATURE_CONFLICT' in gaps or
            any(fields[k]['state'] == 'CONFLICT' for k in ('signature_inner', 'signature_outer')) else
            'RECORDED' if all(fields[k]['state'] == 'RECORDED' for k in ('signature_inner', 'signature_outer')) else
            'UNKNOWN' if all(fields[k]['state'] == 'UNKNOWN' for k in ('signature_inner', 'signature_outer')) else 'PARTIAL')
        if verified:
            g['public_key_bits'] = fields['public_key_bits']['value']
            g['public_key_bits_state'] = fields['public_key_bits']['state']


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
    """Project recorded sets and verified C1 details without re-evaluation or I/O."""
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
    companion_status = _certificate_companions(published, occurrences, budget)
    _certificate_metadata(certs, occurrences, budget)
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
    verified = sorted(oid for oid, r in occurrences.items() if r['detail_state'] == 'VERIFIED_COMPANION')
    budget.charge(len(verified))
    result['certificates']['verified_occurrence_ids'] = verified
    result['certificates']['counts']['verified_occurrence_ids'] = len(verified)
    for g in result['certificates']['groups']:
        g['counts']['verified_occurrence_ids'] = g['verified_occurrence_count']
    for row in result['coverage']:
        if row['slot'] == 'system_certs' and row['host_id'] in companion_status:
            row['detail_slot_state'] = companion_status[row['host_id']]
    _bounded_bytes(result)
    return result


def render_asset_indexes(published):
    """Return (projection, two fixed preview page buffers), with no writes."""
    return _render_asset_indexes(published)


def _render_asset_indexes(published, *, portal_v5=False, page_limit=None, total_limit=None):
    """Fixed private renderer; V5 changes HTML only, not the verified projection."""
    _require(type(portal_v5) is bool)
    result = project_asset_indexes(published)
    if portal_v5:
        for row in result['coverage']:
            hid = _id(row['host_id'], 'h-')
            _require(hid in result['hosts'] and result['hosts'][hid]['host_id'] == hid)
    pages = {}
    remaining = total_limit
    try:
        env = Environment(loader=FileSystemLoader(str(_TEMPLATES)), autoescape=True,
                          undefined=StrictUndefined, keep_trailing_newline=True)
        for name in ('certificates', 'services'):
            cap = min(_MAX_HTML, page_limit) if page_limit is not None else _MAX_HTML
            if remaining is not None:
                cap = min(cap, remaining)
            out = bytearray()
            for chunk in env.get_template(name + '.html.j2').generate(
                    p=result, index=result[name], portal_v5=portal_v5):
                raw = chunk.encode('utf-8')
                _require(len(raw) <= cap - len(out), 'ASSET_INDEX_SIZE_LIMIT')
                out.extend(raw)
            pages[name + '.html'] = bytes(out)
            if remaining is not None:
                remaining -= len(out)
    except (OSError, TemplateError, UnicodeError):
        raise run_store.StoreError('ASSET_INDEX_RENDER_ERROR') from None
    return result, pages
