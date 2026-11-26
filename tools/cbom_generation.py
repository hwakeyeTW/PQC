"""B1/B2 read-only per-host CycloneDX 1.6 generation from verified Store data.

No path, raw document or caller-constructed PublishedRun is a public input.
This is a discovery projection, not an installed-software inventory, a PQC
verdict, or authorization to publish. Certificate/key projection is opt-in.
"""
from collections import defaultdict
import hashlib
import json
import re

from tools import assessment, cbom_validation, evidence, run_store

try:
    from tools import portal_indexes
except ImportError:
    portal_indexes = None

MAX_BYTES = cbom_validation.MAX_INPUT
MAX_MEMBERSHIPS = evidence.MAX_BYTES // 66
VERSION = 1
_USABLE = frozenset(('COLLECTED', 'PARTIAL'))
_DEFERRED = frozenset(('certificate', 'public-key', 'public_key'))
_KEX_AGREEMENT = frozenset(('tls-x25519', 'tls-secp256r1', 'tls-secp384r1',
    'ssh-curve25519-sha256', 'ssh-ecdh-sha2-nistp256', 'ssh-diffie-hellman-group14-sha256'))
_LIBRARY_NAMES = frozenset(('openssl', 'openssl-libs', 'openssl-cli', 'openssl-linked-library', 'OpenSSL'))
_SAFE_VERSION = re.compile(r'[0-9]{1,9}(?:\.[0-9]{1,9}){0,5}[a-z]?\Z')
_CFF_CLASSES = frozenset(('UNKNOWN', 'LEGACY_PQC_REVIEW', 'SYMMETRIC_REVIEW',
    'CLASSICAL_PUBLIC_KEY_MIGRATION', 'PQC_OR_HYBRID_INVENTORY'))
_TLS_VERSIONS = {'TLSv1': '1.0', 'TLSv1.0': '1.0', 'TLSv1.1': '1.1',
                 'TLSv1.2': '1.2', 'TLSv1.3': '1.3'}


class CBOMGenerationError(ValueError):
    """Fixed safe reason only, never a path, exception or input value."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _require(ok, code='CBOM_SOURCE_INVALID'):
    if not ok:
        raise CBOMGenerationError(code)


def _serial(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False)


def _bytes(value, limit=MAX_BYTES):
    cbom_validation._bound_tree(value)
    raw = bytearray()
    for chunk in json.JSONEncoder(ensure_ascii=True, sort_keys=True, separators=(',', ':'),
                                  allow_nan=False).iterencode(value):
        _require(len(chunk) <= limit - len(raw), 'CBOM_SIZE_LIMIT')
        raw.extend(chunk.encode('ascii'))
    return bytes(raw)


def _id(prefix, identity):
    return prefix + '-' + hashlib.sha256(_serial(identity).encode('ascii')).hexdigest()


def _properties(**values):
    return [{'name': 'pqc:b1:' + k, 'value': v} for k, v in sorted(values.items()) if v is not None]


def _version(value):
    if type(value) is not str or not _SAFE_VERSION.fullmatch(value):
        return None
    # A dotted version can also encode an IPv4 address. Conservatively omit
    # any four consecutive decimal octets, including zero padding, a suffix
    # or surrounding numeric segments. This is a narrow display rule only;
    # the recorded taxonomy/Portal identity remains unchanged.
    parts = [int(part) for part in value.rstrip('abcdefghijklmnopqrstuvwxyz').split('.')]
    if any(all(part <= 255 for part in parts[i:i + 4]) for i in range(len(parts) - 3)):
        return None
    return value


def _version_state(value, displayed):
    return 'MISSING' if value is None else 'RECORDED' if displayed is not None else 'UNSAFE_OMITTED'


def _verified_taxonomy(published):
    # Only the already verified, saved rules qualify canonical display names.
    # Never consult current rules on disk, classify an observed name, or
    # change a recorded family/primitive. Runs without saved rules use IDs.
    raw = published.artifacts.get('assessment_rules.json')
    if raw is None:
        raw = published.artifacts.get('producer_rules.json')
    if raw is None:
        return None
    rules = assessment.load_rules(raw)
    aliases, ids = assessment._compile(rules)
    return aliases, ids, rules['taxonomy_version']


def _algorithm_tuple(row):
    return tuple(row[k] for k in ('algorithm_id', 'taxonomy_version', 'primitive', 'family'))


def _primitive(group, verified):
    if not verified or group['classification'] != 'CANONICAL':
        return 'unknown'
    if group['primitive'] in ('KEM', 'SIGNATURE'):
        return {'KEM': 'kem', 'SIGNATURE': 'signature'}[group['primitive']]
    if group['primitive'] == 'KEX' and group['algorithm_id'] in _KEX_AGREEMENT:
        return 'key-agree'
    return 'unknown'


class _Projection:
    def __init__(self, published, host_id, *, include_certificates=False):
        self.include_certificates = include_certificates
        self.pub = published
        m, doc = published.manifest, published.document
        self.hid, self.rid = host_id, m['run_id']
        _require(m['publication_state'] == 'PUBLISHED' and self.rid == doc['run']['run_id']
                 and host_id in m['expected_host_ids'], 'CBOM_HOST_NOT_FOUND')
        self.host = next(h for h in m['hosts'] if h['host_id'] == host_id)
        self.rows = {r['evidence_id']: r for r in doc['evidence'] if r['host_id'] == host_id}
        self.assets = {a['asset_id']: a for a in doc['assets'] if a['host_id'] == host_id}
        self.collections = {c['collection_id']: c for c in doc['collections'] if c['host_id'] == host_id}
        self.claims = {c['claim_id']: c for c in (published.assessed or doc)['claims']
                       if c['subject']['host_id'] == host_id}
        self.cost = 0
        self.charge(4 * len(self.rows) + 3 * len(self.assets) + 2 * len(self.collections) + len(self.claims))
        self.index = portal_indexes.project_crypto_indexes(published)
        self.taxonomy = _verified_taxonomy(published)
        self.asset_claims = defaultdict(list)
        self.evidence_claims = defaultdict(list)
        for cid, claim in self.claims.items():
            aid = claim['subject'].get('asset_id')
            if aid is not None:
                self.charge(); self.asset_claims[aid].append(cid)
            for eid in claim['evidence_ids']:
                self.charge(); self.evidence_claims[eid].append(cid)
        self.components, self.services, self.nodes = {}, {}, {}
        self.algorithms = {}
        self.edges, self.dependencies = [], defaultdict(set)
        self.omitted = []
        self.covered = set()

    def charge(self, n=1):
        self.cost += n
        _require(self.cost <= MAX_MEMBERSHIPS, 'CBOM_MEMBERSHIP_LIMIT')

    def ref(self, kind, identity):
        return _id('cbom', [self.rid, self.hid, kind, identity])

    def provenance(self, ref, kind, eids, *, aids=(), cids=(), group=None, **state):
        eids, aids, cids = sorted(set(eids)), set(aids), sorted(set(cids))
        self.charge(8 + 4 * len(eids) + len(aids) + len(cids))
        _require(ref not in self.nodes and all(eid in self.rows for eid in eids)
                 and all(aid in self.assets for aid in aids) and all(cid in self.claims for cid in cids))
        rows = [self.rows[eid] for eid in eids]
        aids.update(r['asset_id'] for r in rows if r['asset_id'] is not None)
        _require(aids <= self.assets.keys())
        self.nodes[ref] = {'kind': kind, 'host_id': self.hid, 'asset_ids': sorted(aids),
                           'collection_ids': sorted({r['collection_id'] for r in rows}),
                           'evidence_ids': eids, 'claim_ids': cids,
                           'source_kinds': sorted({r['source']['source_kind'] for r in rows}),
                           'portal_group_id': group, **state}
        self.covered.update(eids)

    def omit(self, reason, eids=(), aids=(), *, group=None):
        eids, aids = sorted(set(eids)), sorted(set(aids))
        self.charge(3 + len(eids) + len(aids))
        self.omitted.append({'reason': reason, 'evidence_ids': eids, 'asset_ids': aids,
                             'portal_group_id': group})

    def members(self, group):
        eids = [eid for eid in group['evidence_ids'] if eid in self.rows]
        aids = [aid for aid in group['asset_ids'] if aid in self.assets]
        cids = [cid for cid in group['claim_ids'] if cid in self.claims]
        self.charge(len(eids) + len(aids) + len(cids))
        return eids, aids, cids

    def algorithm_nodes(self):
        for g in self.index['algorithms']['groups']:
            eids, aids, cids = self.members(g)
            identity = _algorithm_tuple(g)
            # Claims may add pivot membership after grouping. Only an actual
            # algorithm observation, not a claim-only host, seeds a node.
            seeds = [eid for eid in eids if self.rows[eid]['algorithm'] is not None
                     and _algorithm_tuple(self.rows[eid]['algorithm']) == identity
                     and portal_indexes._key('alg', [g['classification'], list(identity),
                         None if g['classification'] == 'CANONICAL' else eid]) == g['id']]
            if not seeds:
                if eids or cids:
                    self.omit('NO_ALGORITHM_OBSERVATION', eids, aids, group=g['id'])
                continue
            verified = (self.taxonomy is not None and g['classification'] == 'CANONICAL'
                        and all(assessment._known(self.rows[eid]['algorithm'], *self.taxonomy) is not None
                                for eid in seeds))
            version = _version(g['taxonomy_version'])
            version_state = _version_state(g['taxonomy_version'], version)
            # A saved taxonomy ID is a validated slug. Never use observed_name.
            name = g['algorithm_id'] if verified else g['id']
            ref = self.ref('algorithm', g['id'])
            primitive = _primitive(g, verified)
            self.components[ref] = {'type': 'cryptographic-asset', 'name': name, 'bom-ref': ref,
                'cryptoProperties': {'assetType': 'algorithm', 'algorithmProperties': {'primitive': primitive}},
                'properties': _properties(classification=g['classification'], family=g['family'],
                    primitive=g['primitive'], taxonomy_version=version,
                    taxonomy_version_state=version_state, portal_group=g['id'])}
            self.provenance(ref, 'ALGORITHM', eids, aids=aids, cids=cids, group=g['id'],
                classification=g['classification'], family=g['family'], primitive=g['primitive'],
                taxonomy_version=version, taxonomy_version_state=version_state,
                algorithm_id=g['algorithm_id'] if verified else None,
                taxonomy_version_sha256=None if g['taxonomy_version'] is None else hashlib.sha256(
                    g['taxonomy_version'].encode('ascii')).hexdigest(),
                taxonomy_id_state='VERIFIED_SAVED_TAXONOMY' if verified else 'OPAQUE_RECORDED_ID',
                seed_evidence_ids=sorted(seeds))
            if g['classification'] in ('LEGACY', 'CONFLICT', 'UNKNOWN'):
                self.omit('ALGORITHM_' + g['classification'], seeds, group=g['id'])
            for eid in seeds:
                _require(eid not in self.algorithms)
                self.algorithms[eid] = (ref, verified)

    def library_nodes(self):
        for g in self.index['libraries']['groups']:
            eids, aids, cids = self.members(g)
            if not eids:
                continue
            kind = g['kind']
            if kind in ('PACKAGE', 'RPM_PACKAGE') and g['presence'] != 'PRESENT':
                self.omit('PACKAGE_ABSENT' if g['presence'] == 'ABSENT' else 'PACKAGE_PRESENCE_UNKNOWN',
                          eids, aids, group=g['id'])
                continue
            # Do not allow claim-added pivot rows to seed a library on
            # another host or upgrade an unavailable acquisition.
            if kind == 'LIBRARY_ASSET':
                owners = [aid for aid in aids if portal_indexes._key(
                    'lib', ['LIBRARY_ASSET', self.hid, aid]) == g['id']
                    and self.assets[aid]['asset_kind'] in portal_indexes._LIBRARY_KINDS]
                _require(len(owners) <= 1)
                seeds = [eid for aid in owners for eid in self.assets[aid]['evidence_ids']
                         if eid in self.rows]
                ref = owners[0] if owners else self.ref('library', g['id'])
            else:
                seeds = []
                for eid in eids:
                    row = self.rows[eid]; c = self.collections[row['collection_id']]
                    d = row['data']
                    if kind in ('PACKAGE', 'RPM_PACKAGE'):
                        matches = (row['evidence_kind'] == 'PACKAGE_INVENTORY' and d['present'] is True)
                    else:
                        matches = portal_indexes._metadata_kind(row, c) == kind
                    if matches and d['name'] == g['name'] and d['version'] == g['version']:
                        seeds.append(eid)
                ref = self.ref('library', g['id'])
            usable_seeds = [eid for eid in seeds if
                            self.collections[self.rows[eid]['collection_id']]['collection_state'] in _USABLE]
            if not usable_seeds:
                self.omit('ACQUISITION_UNAVAILABLE', eids, aids, group=g['id'])
                continue
            # Group membership is a provenance pivot, not qualification of
            # metadata. In particular, runtime evidence on a library asset
            # cannot authorize fields from a failed ASSET_METADATA row.
            metadata_seeds = [eid for eid in usable_seeds if kind != 'LIBRARY_ASSET'
                              or self.rows[eid]['evidence_kind'] == 'ASSET_METADATA']
            metadata_state = g['metadata_state']
            raw_name = raw_version = None
            if metadata_state != 'CONFLICT':
                if metadata_seeds:
                    # The existing group has no conflict, so qualified
                    # same-host metadata must agree. Never choose a winner.
                    values = {(self.rows[eid]['data']['name'], self.rows[eid]['data']['version'])
                              for eid in metadata_seeds}
                    _require(len(values) == 1)
                    raw_name, raw_version = next(iter(values))
                elif kind == 'LIBRARY_ASSET' and any(self.rows[eid]['evidence_kind'] == 'ASSET_METADATA'
                                                       for eid in seeds):
                    metadata_state = 'METADATA_UNAVAILABLE'
                else:
                    metadata_state = 'MISSING_METADATA'
            # Retain the original Portal conflict even if only one of its
            # rows is usable. Do not expose raw metadata or identity keys.
            name = raw_name if raw_name in _LIBRARY_NAMES else g['id']
            ctype = 'application' if kind in ('OPENSSL_CLI', 'LEGACY_RUNTIME_METADATA') else 'library'
            version = _version(raw_version)
            version_state = ('CONFLICT' if metadata_state == 'CONFLICT' else
                             'UNAVAILABLE' if metadata_state == 'METADATA_UNAVAILABLE' else
                             _version_state(raw_version, version))
            self.charge(len(metadata_seeds) + (len(metadata_seeds) if name == raw_name else 0)
                        + (len(metadata_seeds) if version is not None else 0))
            metadata_ids = sorted(metadata_seeds)
            self.components[ref] = {'type': ctype, 'name': name, 'bom-ref': ref,
                'properties': _properties(recorded_kind=kind, presence=g['presence'],
                    metadata_state=metadata_state, version_state=version_state, portal_group=g['id'])}
            if version is not None:
                self.components[ref]['version'] = version
            self.provenance(ref, kind, eids, aids=aids, cids=cids, group=g['id'],
                            presence=g['presence'], metadata_state=metadata_state,
                            portal_metadata_state=g['metadata_state'], version_state=version_state,
                            seed_evidence_ids=sorted(seeds), metadata_evidence_ids=metadata_ids,
                            name_evidence_ids=metadata_ids if name == raw_name else [],
                            version_evidence_ids=metadata_ids if version is not None else [])
            if metadata_state in ('CONFLICT', 'MISSING_METADATA', 'METADATA_UNAVAILABLE'):
                self.omit('LIBRARY_' + metadata_state, eids, aids, group=g['id'])

    def service_nodes(self):
        for aid, asset in self.assets.items():
            if asset['asset_kind'] != 'service':
                continue
            self.services[aid] = {'name': aid, 'bom-ref': aid}
            self.provenance(aid, 'SERVICE', asset['evidence_ids'], aids=[aid],
                            cids=self.asset_claims.get(aid, ()))

    def edge(self, origin, target, kind, eid):
        self.charge(4)
        _require(origin in self.nodes and target in self.nodes and origin != target and eid in self.rows)
        self.edges.append({'from': origin, 'to': target, 'kind': kind, 'evidence_id': eid})

    def protocol_nodes(self):
        groups = defaultdict(list)
        for eid, row in self.rows.items():
            c = self.collections[row['collection_id']]
            if row['evidence_kind'] == 'AUTHORIZED_NEGOTIATION' and row['source']['source_kind'] != 'LEGACY_IMPORT':
                d = row['data']; ctx = d['conditions']
                aid = ctx['service_asset_id']
                _require(ctx['host_id'] == self.hid and row['asset_id'] == aid and aid in self.services)
                key = ('AUTHORIZED_CONTEXT', aid, ctx['protocol'].lower(), None,
                       ctx['endpoint_ref'], ctx['context_ref'], ctx['authorization_ref'])
            elif (row['evidence_kind'] == 'LEGACY_OBSERVATION' and row['source']['source_kind'] == 'LEGACY_IMPORT'
                  and row['source'] == c['source'] and c['collector_id'] == 'legacy-import'
                  and c['scope_key'] == 'tls-services' and row['data']['field'] == 'tls-protocol'
                  and type(row['data']['value']) is str and row['data']['value'] in _TLS_VERSIONS
                  and (row['asset_id'] is None or (row['asset_id'] in self.services
                       and self.assets[row['asset_id']]['identity_scope'] == 'RUN_SCOPED'))
                  and c['collection_state'] in _USABLE):
                key = ('HISTORICAL_ONLY', row['asset_id'], 'tls', _TLS_VERSIONS[row['data']['value']])
            else:
                continue
            self.charge(2)
            groups[key].append(eid)
        for key, eids in sorted(groups.items(), key=lambda x: _serial(x[0])):
            kind, aid, protocol, version = key[:4]
            ref = self.ref('protocol', key)
            details = {'type': protocol}
            if version is not None:
                details['version'] = version
            cids = set()
            for eid in eids:
                for cid in self.evidence_claims.get(eid, ()):
                    self.charge(); cids.add(cid)
            self.provenance(ref, 'PROTOCOL', eids, aids=[] if aid is None else [aid], cids=cids,
                            protocol=protocol, recorded_context=kind)
            related = set()
            for eid in eids:
                row = self.rows[eid]
                if (kind != 'AUTHORIZED_CONTEXT' or row['data']['outcome'] != 'NEGOTIATED'
                        or self.collections[row['collection_id']]['collection_state'] not in _USABLE):
                    self.omit('PROTOCOL_RELATION_NOT_PROVEN', [eid])
                    continue
                # The verified negotiation has an exact service and protocol.
                # This is not proof of an implementing library or observed use.
                self.dependencies[aid].add(ref)
                self.edge(aid, ref, 'SERVICE_PROTOCOL_NEGOTIATED', eid)
                algorithm = self.algorithms.get(eid)
                if algorithm is not None and algorithm[1]:
                    related.add(algorithm[0])
                    self.edge(ref, algorithm[0], 'PROTOCOL_ALGORITHM_NEGOTIATED', eid)
                else:
                    self.omit('PROTOCOL_ALGORITHM_UNVERIFIED', [eid])
            if related:
                details['cryptoRefArray'] = sorted(related)
            self.components[ref] = {'type': 'cryptographic-asset', 'name': ref, 'bom-ref': ref,
                'cryptoProperties': {'assetType': 'protocol', 'protocolProperties': details},
                'properties': _properties(recorded_context=kind)}

    def _usable(self, eid):
        return self.collections[self.rows[eid]['collection_id']]['collection_state'] in _USABLE

    def _certificate_field(self, occurrences, field, *, role=None):
        # C2 has already verified the fixed companion and its exact role joins.
        # Never select values or support IDs from the batch-wide group summary.
        self.charge(3 + len(occurrences))
        values = {oid: o['certificate_metadata'][field] for oid, o in occurrences.items()
                  if o['detail_state'] == 'VERIFIED_COMPANION'
                  and (role is None or role in o['role_evidence_ids'])
                  and o['certificate_metadata'][field] is not None}
        distinct = set(values.values())
        state = ('CONFLICT' if len(distinct) > 1 else 'UNKNOWN' if not distinct else
                 'RECORDED' if len(values) == len(occurrences) else 'PARTIAL')
        return (next(iter(distinct)) if len(distinct) == 1 else None,
                {'state': state, 'occurrence_ids': sorted(values)})

    def _certificate_role(self, ids, primitive, conflict=False):
        ids = sorted(set(ids))
        self.charge(3 + len(ids))
        algorithms = [self.rows[eid]['algorithm'] for eid in ids]
        _require(all(a is not None for a in algorithms))
        identities = {(*_algorithm_tuple(a), a['observed_name'] if a['algorithm_id'] is None else None)
                      for a in algorithms}
        if conflict or len(identities) > 1:
            state, ref = 'CONFLICT', None
        elif not ids or any(a['primitive'] != primitive or a['algorithm_id'] is None for a in algorithms):
            state, ref = 'UNKNOWN', None
        else:
            # Reuse the actual B1 algorithm seed, never resolve by name or
            # group membership alone. PUBLIC_KEY remains the recorded typed
            # primitive; the official algorithm subtype may be "unknown".
            targets = [self.algorithms.get(eid) for eid in ids]
            refs = {t[0] for t in targets if t is not None and t[1]}
            if len(refs) == 1 and all(t is not None and t[1] for t in targets):
                ref = next(iter(refs))
                _require(self.nodes[ref]['primitive'] == primitive
                         and self.components[ref]['cryptoProperties']['assetType'] == 'algorithm')
                if primitive == 'SIGNATURE':
                    _require(self.components[ref]['cryptoProperties']['algorithmProperties']['primitive'] == 'signature')
                state = 'VERIFIED_ALGORITHM'
            else:
                state, ref = 'UNVERIFIED', None
        return {'state': state, 'evidence_ids': ids, 'algorithm_ref': ref}

    def certificate_nodes(self):
        from tools import portal_asset_indexes
        index = portal_asset_indexes.project_asset_indexes(self.pub)
        _require(index['run_id'] == self.rid and self.hid in index['hosts'])
        seen = set()
        for g in index['certificates']['groups']:
            eids, aids, cids = self.members(g)
            if not aids:
                continue
            _require(all(self.assets[aid]['asset_kind'] == 'certificate' for aid in aids)
                     and not seen.intersection(aids))
            seen.update(aids)
            aid_set, eid_set = set(aids), set(eids)
            occurrences, proofs, role_ids = {}, {}, defaultdict(set)
            for oid in g['recorded_occurrence_ids']:
                o = index['occurrences'][oid]
                if o['host_id'] != self.hid:
                    continue
                roles = o['role_evidence_ids']
                _require(o['id'] == oid and o['asset_id'] in aid_set
                         and o['collection_id'] in self.collections
                         and set(roles.values()) == set(o['evidence_ids']) <= eid_set
                         and 'certificate' in roles and set(roles) <= {'certificate', 'public-key', 'signature'}
                         and all(self.rows[eid]['asset_id'] == o['asset_id']
                                 and self.rows[eid]['collection_id'] == o['collection_id']
                                 and self._usable(eid) for eid in roles.values()))
                self.charge(9 + 3 * len(roles))
                occurrences[oid] = o
                # Closed allowlist: no DN, path, vhost, target, raw block or key bytes.
                proofs[oid] = {'asset_id': o['asset_id'], 'collection_id': o['collection_id'],
                    'detail_sha256': o['detail_sha256'], 'detail_state': o['detail_state'],
                    'role_evidence_ids': dict(roles)}
                for role, eid in roles.items():
                    role_ids[role].add(eid)
            if g['kind'] == 'RECORDED_FINGERPRINT':
                _require(bool(occurrences) and all(o['fingerprint'] == g['fingerprint']
                                                  for o in occurrences.values()))
                seeds = sorted(role_ids['certificate'])
                fingerprint = g['fingerprint']
                _require(type(fingerprint) is str and re.fullmatch(r'[0-9a-f]{64}', fingerprint))
            else:
                # Legacy/unverified identity stays opaque. A failed metadata
                # row or claim membership alone cannot qualify an asset.
                seeds = [eid for eid in eids if self.rows[eid]['asset_id'] in aid_set
                         and self.rows[eid]['evidence_kind'] == 'ASSET_METADATA' and self._usable(eid)]
                fingerprint = None
                if g['kind'] == 'LEGACY_RUN_SCOPED' and seeds:
                    for role in ('public-key', 'signature'):
                        for eid in g[role.replace('-', '_')]['evidence_ids']:
                            if (eid in eid_set and self.rows[eid]['asset_id'] in aid_set and self._usable(eid)
                                    and self.rows[eid]['source']['source_kind'] == 'LEGACY_IMPORT'):
                                self.charge(); role_ids[role].add(eid)
            if not seeds:
                self.omit('CERTIFICATE_ACQUISITION_UNAVAILABLE', eids, aids, group=g['id'])
                continue
            verified = sorted(oid for oid, o in occurrences.items() if o['detail_state'] == 'VERIFIED_COMPANION')
            gaps = sorted({gap for oid in verified for gap in occurrences[oid]['metadata_gaps']})
            self.charge(len(seeds) + len(verified) + len(gaps))
            fields, values = {}, {}
            for field in ('not_before', 'not_after', 'signature_inner', 'signature_outer',
                          'public_key_algorithm', 'public_key_bits'):
                values[field], fields[field] = self._certificate_field(occurrences, field,
                    role='public-key' if field == 'public_key_bits' else None)
            before, after = fields['not_before'], fields['not_after']
            pairs = sorted(set(before['occurrence_ids']) & set(after['occurrence_ids']))
            validity = ('CONFLICT' if 'VALIDITY_CONFLICT' in gaps or 'CONFLICT' in (before['state'], after['state'])
                        else 'RECORDED' if before['state'] == after['state'] == 'RECORDED'
                        else 'UNKNOWN' if before['state'] == after['state'] == 'UNKNOWN' else 'PARTIAL')
            if validity == 'CONFLICT':
                pairs = []
            self.charge(len(pairs))
            details = {}
            if validity != 'CONFLICT' and (pairs or values['not_before'] is None or values['not_after'] is None):
                for field, prop in (('not_before', 'notValidBefore'), ('not_after', 'notValidAfter')):
                    if values[field] is not None:
                        details[prop] = values[field]
            if validity != 'RECORDED':
                self.omit('CERTIFICATE_VALIDITY_' + validity, seeds, aids, group=g['id'])
            signature_conflict = ('SIGNATURE_CONFLICT' in gaps or
                                  any(fields[k]['state'] == 'CONFLICT' for k in ('signature_inner', 'signature_outer')))
            sig = self._certificate_role(role_ids['signature'], 'SIGNATURE', signature_conflict)
            key = self._certificate_role(role_ids['public-key'], 'PUBLIC_KEY',
                                         fields['public_key_algorithm']['state'] == 'CONFLICT')
            ref = self.ref('certificate', g['id'])
            self.provenance(ref, 'CERTIFICATE', eids, aids=aids, cids=cids, group=g['id'],
                identity_basis=g['kind'], certificate_fingerprint_sha256=fingerprint,
                seed_evidence_ids=sorted(seeds), recorded_occurrence_ids=sorted(occurrences),
                verified_occurrence_ids=verified, occurrences=proofs, metadata_gaps=gaps,
                field_support=fields, validity_state=validity, validity_occurrence_ids=pairs,
                signature_role=sig, public_key_role=key, distinguished_names_state='OMITTED')
            if sig['algorithm_ref'] is not None:
                details['signatureAlgorithmRef'] = sig['algorithm_ref']
                for eid in sig['evidence_ids']:
                    self.edge(ref, sig['algorithm_ref'], 'CERTIFICATE_SIGNATURE_ALGORITHM', eid)
            else:
                self.omit('CERTIFICATE_SIGNATURE_' + sig['state'], sig['evidence_ids'], aids, group=g['id'])
            if key['evidence_ids']:
                key_ref = self.ref('certificate-subject-public-key', g['id'])
                material = {'type': 'public-key'}
                # Only same-occurrence verified metadata and an actual key
                # role may qualify size. No independently verified key hash.
                size = values['public_key_bits'] if key['state'] != 'CONFLICT' else None
                if size is not None:
                    material['size'] = size
                self.charge(len(fields['public_key_bits']['occurrence_ids']) + len(key['evidence_ids']))
                self.provenance(key_ref, 'PUBLIC_KEY', key['evidence_ids'], group=g['id'],
                    identity_basis='CERTIFICATE_BOUND_SUBJECT_KEY', certificate_ref=ref,
                    key_fingerprint_sha256=None, algorithm_state=key['state'],
                    algorithm_evidence_ids=key['evidence_ids'], size_state=(
                        'CONFLICT' if key['state'] == 'CONFLICT' else fields['public_key_bits']['state']),
                    size_occurrence_ids=fields['public_key_bits']['occurrence_ids'] if size is not None else [])
                if key['algorithm_ref'] is not None:
                    details['subjectPublicKeyRef'] = key_ref
                    material['algorithmRef'] = key['algorithm_ref']
                    for eid in key['evidence_ids']:
                        self.edge(ref, key_ref, 'CERTIFICATE_SUBJECT_PUBLIC_KEY', eid)
                        self.edge(key_ref, key['algorithm_ref'], 'PUBLIC_KEY_ALGORITHM', eid)
                self.components[key_ref] = {'type': 'cryptographic-asset', 'name': key_ref, 'bom-ref': key_ref,
                    'cryptoProperties': {'assetType': 'related-crypto-material', 'relatedCryptoMaterialProperties': material},
                    'properties': _properties(identity_basis='CERTIFICATE_BOUND_SUBJECT_KEY')}
            if key['algorithm_ref'] is None:
                self.omit('CERTIFICATE_PUBLIC_KEY_' + key['state'], key['evidence_ids'], aids, group=g['id'])
            self.components[ref] = {'type': 'cryptographic-asset', 'name': ref, 'bom-ref': ref,
                'cryptoProperties': {'assetType': 'certificate', 'certificateProperties': details},
                'properties': _properties(identity_basis=g['kind'], validity_state=validity, portal_group=g['id'])}
        _require(seen == {aid for aid, a in self.assets.items() if a['asset_kind'] == 'certificate'})
        self.standalone_keys()
        # Keep the original coverage and expose only fixed, same-host C2
        # coverage fields, including required detail missing/not required.
        self.certificate_coverage = []
        for row in index['coverage']:
            if row['host_id'] == self.hid and row['slot'] in ('system_certs', 'nginx_certs'):
                _require(all(cid in self.collections for cid in row['collection_ids']))
                self.charge(8 + len(row['collection_ids']))
                self.certificate_coverage.append({k: row[k] for k in ('slot', 'requested', 'state', 'basis',
                    'slot_state', 'detail_slot_state', 'collection_ids')})

    def standalone_keys(self):
        from tools import ssh_posture
        # The original #17 typed metadata is intentionally not a classified
        # signature/public-key algorithm or proof of a configured host key.
        names = {'ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384',
                 'ecdsa-sha2-nistp521', 'ssh-rsa', 'ssh-dss'}
        # R's S1 Store admits short synthetic collector IDs only. Recognize
        # that explicit fixture contract separately from a #17 producer row.
        # Never accept the short alias as native acquisition evidence.
        synthetic_s1 = (self.pub.manifest['run_kind'] == 'SYNTHETIC'
                        and self.pub.manifest['batch_contract'] == run_store.S1_BATCH_CONTRACT)
        for aid, a in self.assets.items():
            if a['asset_kind'] not in ('public_key', 'public-key'):
                continue
            seeds = []
            identity = a['identity_key']
            if a['asset_kind'] == 'public_key' and re.fullmatch(r'sha256-[0-9a-f]{64}', identity):
                for eid in a['evidence_ids']:
                    r = self.rows[eid]; c = self.collections[r['collection_id']]; alg = r['algorithm']
                    if (self._usable(eid) and r['source'] == c['source']
                            and c['source']['source_kind'] in ('SYNTHETIC', 'NATIVE_COLLECTOR')
                            and c['collector_id'] == c['source']['producer_id']
                            and (c['collector_id'] == ssh_posture.PRODUCER or
                                 (synthetic_s1 and c['source']['source_kind'] == 'SYNTHETIC'
                                  and c['collector_id'] == 'ssh_host_keys'))
                            and c['collector_version'] == c['source']['producer_version'] == ssh_posture.VERSION
                            and c['scope_key'] == 'ssh-keys' and r['evidence_kind'] == 'ASSET_METADATA'
                            and r['data'] == {'name': identity, 'version': None}
                            and re.fullmatch(r'public-[0-9a-f]{64}', r['observation_key'])
                            and alg is not None and alg['algorithm_id'] is None
                            and alg['primitive'] == alg['family'] == 'UNKNOWN' and alg['observed_name'] in names):
                        self.charge(); seeds.append(eid)
            if not seeds:
                self.omit('STANDALONE_PUBLIC_KEY_UNAVAILABLE', a['evidence_ids'], [aid])
                continue
            state = ('CONFLICT' if len({self.rows[eid]['algorithm']['observed_name'] for eid in seeds}) > 1
                     else 'UNKNOWN')
            basis = ('SYNTHETIC_S1_RECORDED_PUBLIC_KEY_FINGERPRINT' if all(
                self.collections[self.rows[eid]['collection_id']]['collector_id'] == 'ssh_host_keys'
                for eid in seeds) else 'SSH_RECORDED_PUBLIC_KEY_FINGERPRINT')
            ref = self.ref('standalone-public-key', aid)
            self.provenance(ref, 'PUBLIC_KEY', a['evidence_ids'], aids=[aid], cids=self.asset_claims.get(aid, ()),
                identity_basis=basis, key_fingerprint_sha256=identity[7:],
                seed_evidence_ids=sorted(seeds), algorithm_state=state, algorithm_evidence_ids=[],
                size_state='UNKNOWN', size_occurrence_ids=[])
            self.components[ref] = {'type': 'cryptographic-asset', 'name': ref, 'bom-ref': ref,
                'cryptoProperties': {'assetType': 'related-crypto-material',
                    'relatedCryptoMaterialProperties': {'type': 'public-key'}},
                'properties': _properties(identity_basis=basis)}
            self.omit('STANDALONE_PUBLIC_KEY_ALGORITHM_' + state, seeds, [aid])

    def cff_consistency(self, raw, observations, claims):
        # Actual Store.open already verified the saved pair. Compare the
        # shared IDs/recorded classification again, without reclassification.
        pair = run_store._loads(raw, run_store.MAX_CFF)
        entries = [x for x in pair['per_host'] if x['host_id'] == self.hid]
        _require(len(entries) == 1, 'CBOM_CFF_MISMATCH')
        comp = entries[0]['companion']
        if self.pub.manifest['run_kind'] == 'LEGACY_IMPORT':
            _require({x['collection_id'] for x in comp['collections']} == self.collections.keys()
                     and {x['asset_id'] for x in comp['assets']} == self.assets.keys()
                     and {x['evidence_id'] for x in comp['evidence']} == observations.keys()
                     and {x['claim_id'] for x in comp['claims']} == claims.keys(), 'CBOM_CFF_MISMATCH')
            for x in comp['evidence']:
                eid = x['evidence_id']; original = self.rows[eid]['algorithm']; recorded = x['algorithm']
                _require((original is None) == (recorded is None), 'CBOM_CFF_MISMATCH')
                if original is not None:
                    _require(_algorithm_tuple(original) == _algorithm_tuple(recorded)
                             and recorded['migration_classification'] in _CFF_CLASSES, 'CBOM_CFF_MISMATCH')
                    observations[eid]['saved_migration_classification'] = recorded['migration_classification']
            for x in comp['claims']:
                c = claims[x['claim_id']]
                _require(c['level'] == x['level'] and c['assessment_state'] == x['assessment_state']
                         and c['evidence_ids'] == sorted(x['evidence_ids']), 'CBOM_CFF_MISMATCH')
        # Both existing pair formats contain the actual saved findings.
        expected = {f['finding_id']: f for f in self.pub.assessed['findings']
                    if f['subject']['host_id'] == self.hid}
        _require({f['finding_id'] for f in comp['findings']} == expected.keys(), 'CBOM_CFF_MISMATCH')
        for f in comp['findings']:
            actual = expected[f['finding_id']]
            _require(all(f[k] == actual[k] for k in ('assessment_state', 'claim_ids', 'evidence_ids')),
                     'CBOM_CFF_MISMATCH')

    def finish(self):
        self.provenance(self.hid, 'HOST', [])
        self.nodes[self.hid]['source_kinds'] = [self.pub.manifest['source']['source_kind']]
        self.algorithm_nodes(); self.library_nodes(); self.service_nodes(); self.protocol_nodes()
        for r in self.index['relations']:
            refs = [eid for eid in r['evidence_ids'] if eid in self.rows]
            if refs:
                self.omit('PIVOT_NOT_DEPENDENCY', refs)
        deferred = []
        if self.include_certificates:
            self.certificate_nodes()
        else:
            deferred = sorted(aid for aid, a in self.assets.items() if a['asset_kind'] in _DEFERRED)
            for aid in deferred:
                self.omit('DEFERRED_B2', self.assets[aid]['evidence_ids'], [aid])
        for aid, a in self.assets.items():
            if a['asset_kind'] not in _DEFERRED and aid not in self.nodes and not any(
                    eid in self.covered for eid in a['evidence_ids']):
                self.omit('ASSET_NOT_PROJECTED', a['evidence_ids'], [aid])
        remaining = sorted(self.rows.keys() - self.covered)
        if remaining:
            self.omit('EVIDENCE_NOT_PROJECTED', remaining)
        observations = {}
        for eid, row in sorted(self.rows.items()):
            c = self.collections[row['collection_id']]
            level, state = portal_indexes._observation(row, c)
            if row['source']['source_kind'] == 'LEGACY_IMPORT' and level in ('L4', 'L5'):
                level, state = None, None
                self.omit('LEGACY_USAGE_NOT_PROVEN', [eid])
            a = row['algorithm']
            version = None if a is None else _version(a['taxonomy_version'])
            observations[eid] = {'collection_id': row['collection_id'], 'asset_id': row['asset_id'],
                'source_kind': row['source']['source_kind'], 'evidence_kind': row['evidence_kind'],
                'collection_state': c['collection_state'], 'level': level, 'observation_state': state,
                'observed_at': row['observed_at'], 'algorithm': None if a is None else {
                    'family': a['family'], 'primitive': a['primitive'], 'taxonomy_version': version,
                    'taxonomy_version_state': _version_state(a['taxonomy_version'], version),
                    'taxonomy_version_sha256': None if a['taxonomy_version'] is None else
                        hashlib.sha256(a['taxonomy_version'].encode('ascii')).hexdigest()}}
        claims = {}
        for cid, c in sorted(self.claims.items()):
            self.charge(len(c['evidence_ids']) + 3)
            _require(all(eid in self.rows for eid in c['evidence_ids']))
            claims[cid] = {'level': c['level'], 'assessment_state': c['assessment_state'],
                           'evidence_ids': sorted(c['evidence_ids']), 'asset_id': c['subject'].get('asset_id')}
        m = self.pub.manifest
        # Store.open already replays the saved CFF pair against the exact
        # assessed Evidence, rule bytes, host/finding/claim/evidence IDs and
        # classification. Bind its verified artifact hash; never regenerate it.
        cff = self.pub.artifacts.get('cff_projection.json')
        if cff is not None:
            _require(self.pub.assessed is not None)
            self.cff_consistency(cff, observations, claims)
        terminal = self.host['terminal']
        coverage = {'run_state': m['run_state'], 'host_state': self.host['host_state'],
            'attempted': self.host['attempted'], 'recovery': m['recovery'],
            'collections': {cid: c['collection_state'] for cid, c in sorted(self.collections.items())},
            'collector_outcomes': [] if terminal is None else [
                {'collector_id': c['collector_id'], 'state': c['state'], 'requested': c['requested']}
                for c in terminal['collectors']],
            'missing_artifact_count': len(m['missing_artifacts']),
            'missing_artifact_reasons': sorted({a['reason_code'] for a in m['missing_artifacts']}),
            'assessment_saved': self.pub.assessed is not None,
            'cff_state': 'VERIFIED_SAVED_PAIR' if cff is not None else 'NOT_AVAILABLE',
            'cff_sha256': None if cff is None else hashlib.sha256(cff).hexdigest(),
            'certificate_key_scope': 'DEFERRED_B2', 'deferred_asset_ids': deferred,
            'evidence_count': len(self.rows), 'projected_evidence_count': len(self.covered)}
        if self.include_certificates:
            coverage['certificate_key_scope'] = 'B2_CERTIFICATE_KEY'
            coverage['certificate_collections'] = self.certificate_coverage
        bom = {'$schema': cbom_validation.ROOT_URI, 'bomFormat': 'CycloneDX', 'specVersion': '1.6',
               'version': 1, 'metadata': {'timestamp': m['recorded_at'], 'component': {
                   'type': 'device', 'name': self.hid, 'bom-ref': self.hid,
                   'properties': _properties(host_state=self.host['host_state'], run_state=m['run_state'],
                       scope='B2_CERTIFICATE_KEY' if self.include_certificates else 'B1_CORE_DEFERRED_B2',
                       source_kind=m['source']['source_kind'])}},
               'components': [self.components[r] for r in sorted(self.components)],
               'services': [self.services[r] for r in sorted(self.services)],
               'dependencies': [{'ref': r, 'dependsOn': sorted(targets)}
                                for r, targets in sorted(self.dependencies.items())]}
        provenance = {'version': VERSION, 'run_id': self.rid, 'host_id': self.hid,
            'evidence_schema_version': m['evidence_schema_version'], 'source_kind': m['source']['source_kind'],
            'evidence_sha256': hashlib.sha256(self.pub.artifacts['evidence.json']).hexdigest(),
            'coverage': coverage, 'nodes': self.nodes, 'observations': observations, 'claims': claims,
            'relationships': sorted(self.edges, key=_serial), 'omitted': sorted(self.omitted, key=_serial)}
        return bom, provenance


def build_cbom_bytes(store, run_id, host_id, *, include_certificates=False):
    """Return validated canonical BOM and provenance bytes, or a fixed error.

    The caller owns an already opened, trusted RunStore. Never accept a path,
    dict, NamedTuple, URI or a subclass overriding open as a trust witness.
    Reopen only the selected published run via its original verification API.
    The explicit bool opts into B2; the default is the unchanged B1 result.
    """
    _require(type(include_certificates) is bool and type(store) is run_store.RunStore and type(run_id) is str
             and re.fullmatch(run_store.RID, run_id) is not None and type(host_id) is str
             and re.fullmatch(r'h-[0-9a-f]{64}', host_id) is not None, 'CBOM_INPUT_TYPE')
    _require(portal_indexes is not None, 'CBOM_DEPENDENCY_UNAVAILABLE')
    code = None
    try:
        published = run_store.RunStore.open(store, run_id)
        _require(host_id in published.manifest['expected_host_ids'], 'CBOM_HOST_NOT_FOUND')
        bom, provenance = _Projection(published, host_id, include_certificates=include_certificates).finish()
        raw = _bytes(bom, MAX_BYTES)
        provenance['bom_sha256'] = hashlib.sha256(raw).hexdigest()
        sidecar = _bytes(provenance, MAX_BYTES - len(raw))
        result = cbom_validation.validate_cbom_bytes(raw)
        _require(result.schema_status == result.reference_status == 'PASS', 'CBOM_VALIDATION_FAILED')
        return raw, sidecar
    except CBOMGenerationError:
        raise
    except cbom_validation.CBOMValidationError as exc:
        code = exc.code
    except ImportError:
        code = 'CBOM_DEPENDENCY_UNAVAILABLE'
    except (run_store.StoreError, assessment.AssessmentError, evidence.EvidenceError,
            ValueError, TypeError, KeyError, OverflowError, RecursionError):
        code = 'CBOM_SOURCE_INVALID'
    raise CBOMGenerationError(code)


def build_cbom(store, run_id, host_id, *, include_certificates=False):
    """Return independent JSON trees of the same verified canonical bytes."""
    raw, sidecar = build_cbom_bytes(store, run_id, host_id, include_certificates=include_certificates)
    return json.loads(raw), json.loads(sidecar)
