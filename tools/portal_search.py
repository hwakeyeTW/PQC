"""Private SEARCH-A render buffer for a verified, pinned Store.open chain.

Use the same unmodified publication and its already computed crypto, asset
and summary projections. This is not a public reader or an authenticator of
caller-constructed PublishedRun objects. No I/O except the fixed template,
no re-assessment, new classification, acquisition or publication.
"""
from collections import defaultdict
from datetime import datetime, timezone
import json
from pathlib import Path
import re

from jinja2 import Environment, FileSystemLoader, StrictUndefined, TemplateError

from tools import cert_assets, evidence, export_summary, portal_asset_indexes, portal_indexes, run_store
from tools import portal_generation_c

_TEMPLATES = Path(__file__).resolve().parents[1] / 'templates' / 'portal'
_MAX_ROWS = 20_000
_MAX_MEMBERSHIPS = portal_indexes._MAX_MEMBERSHIPS
_CATEGORIES = ('hosts', 'algorithms', 'libraries', 'certificates', 'services', 'findings', 'coverage')
_PREFIX = {'algorithms': 'alg-', 'libraries': 'lib-', 'certificates': 'cert-', 'services': 'svc-'}
_SOURCE_FIELDS = ('source_kind', 'producer_id', 'producer_version', 'origin_ref', 'input_sha256')
_UNKNOWN = 'UNKNOWN'


def _require(ok, code='PORTAL_PAYLOAD_INVALID'):
    run_store.require(ok, code)


def _id(value, prefix):
    _require(type(value) is str and re.fullmatch(re.escape(prefix) + r'[0-9a-f]{64}', value))
    return value


def _value(value):
    # Never stringify a nested or caller-supplied object into HTML.
    _require(value is None or type(value) in (str, bool, int))
    _require(type(value) is not str or evidence._plain(value))
    if value is None:
        return 'Unknown / not recorded'
    return str(value)


def _json(value):
    return json.dumps(value, ensure_ascii=True, separators=(',', ':'), allow_nan=False)


def _source(source):
    _require(type(source) is dict and set(source) == set(_SOURCE_FIELDS))
    _require(all(source[k] is None or type(source[k]) is str for k in _SOURCE_FIELDS))
    return tuple(_value(source[k]) for k in _SOURCE_FIELDS)


def _day(value):
    if value is None:
        return None
    _require(type(value) is str and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', value))
    dt = datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    return dt.date().isoformat()


class _Budget:
    def __init__(self):
        self.used = 0

    def charge(self, count=1):
        _require(type(count) is int and 0 <= count <= _MAX_MEMBERSHIPS - self.used,
                 'PORTAL_PAYLOAD_SIZE_LIMIT')
        self.used += count

    def refs(self, values, registry):
        _require(type(values) is list)
        self.charge(len(values))
        _require(all(type(v) is str and v in registry for v in values))
        _require(values == sorted(set(values)))
        return values


class _Rows:
    def __init__(self):
        self.tables = {name: [] for name in _CATEGORIES}
        self.count = 0
        self.keys = set()

    def reserve(self, name, key):
        # Before constructing each result row, including repeated membership.
        _require(self.count < _MAX_ROWS, 'PORTAL_PAYLOAD_SIZE_LIMIT')
        _require((name, key) not in self.keys)
        self.keys.add((name, key)); self.count += 1

    def append(self, name, row):
        self.tables[name].append(row)


def _registry(rows, key, prefix, budget):
    _require(type(rows) is list)
    budget.charge(len(rows))
    result = {}
    for row in rows:
        _require(type(row) is dict)
        ref = _id(row[key], prefix)
        _require(ref not in result)
        result[ref] = row
    return result


def _owner(row):
    return row['subject']['host_id'] if 'subject' in row else row['host_id']


def _href(hid, ref=None):
    _id(hid, 'h-')
    return hid + '.html#' + (hid if ref is None else ref)


def _fields(row, names):
    return [(name.replace('_', ' '), _value(row[name])) for name in names]


class _Search:
    def __init__(self, published, crypto, assets, summary):
        _require(type(published) is run_store.PublishedRun)
        m, doc, saved, _ = published
        rid = run_store._rid(m['run_id']); ids = m['expected_host_ids']
        _require(m['manifest_version'] == run_store.VERSION and m['publication_state'] == 'PUBLISHED'
                 and m['batch_contract'] in (None, run_store.S1_BATCH_CONTRACT,
                     run_store.NATIVE_BATCH_CONTRACT, run_store.PRODUCER_V2_BATCH_CONTRACT)
                 and rid == doc['run']['run_id'] == crypto['run_id'] == assets['run_id'] == summary['run']['run_id']
                 and type(ids) is list and 0 < len(ids) <= 1000 and ids == sorted(set(ids))
                 and ids == doc['run']['expected_host_ids'] == summary['expected_host_ids']
                 and m['source'] == doc['run']['source'] == summary['run']['source']
                 and all(type(p) is dict and p['assessed'] is (saved is not None)
                         and type(p['projection_version']) is int and p['projection_version'] == 1
                         for p in (crypto, assets, summary)))
        if saved is not None:
            _require(saved['run'] == doc['run'] and all(saved[k] == doc[k]
                     for k in ('hosts', 'collections', 'assets', 'evidence')))
        for k in ('run_kind', 'run_state', 'reason_code', 'recovery', 'evidence_schema_version',
                  'rule_version', 'rules_sha256', 'batch_contract'):
            _require(summary['run'][k] == m[k])
        self.m, self.doc, self.saved = m, doc, saved
        self.rid, self.ids = rid, ids
        self.cert_details = {a['host_id']: a for a in m['artifacts']
            if a['kind'] == 'detail' and a['slot'] == 'certificate-assets-v1'}
        self.crypto, self.assets, self.summary = crypto, assets, summary
        self.rows = _Rows()
        self.budget = _Budget()
        self.hosts = _registry(m['hosts'], 'host_id', 'h-', self.budget)
        _require(sorted(self.hosts) == ids)
        self.collections = _registry(doc['collections'], 'collection_id', 'c-', self.budget)
        self.evidence = _registry(doc['evidence'], 'evidence_id', 'e-', self.budget)
        self.asset_rows = _registry(doc['assets'], 'asset_id', 'a-', self.budget)
        self.claims = _registry([] if saved is None else saved['claims'], 'claim_id', 'cl-', self.budget)
        self.findings = _registry([] if saved is None else saved['findings'], 'finding_id', 'f-', self.budget)
        self.budget = _Budget()
        self.os = defaultdict(set)
        for eid, row in self.evidence.items():
            c = self.collections[row['collection_id']]
            _require(row['host_id'] in self.hosts and row['host_id'] == c['host_id'])
            if row['evidence_kind'] == 'PLATFORM_INFO' and c['collection_state'] in ('COLLECTED', 'PARTIAL'):
                d = row['data']
                self.budget.charge()
                self.os[row['host_id']].add((d['os_family'], d.get('distribution'), d['os_version'], eid))
        self._validate_summary()
        self.unresolved = {}

    def _check_table(self, p, kind, actual, key, fields, *, exact=False):
        table = p[kind]
        if kind in ('claims', 'findings') and p is self.summary and self.saved is None:
            _require(table is None and not actual)
            return
        _require(type(table) is dict)
        self.budget.charge(len(table))
        if exact:
            _require(table.keys() == actual.keys())
        for ref, row in table.items():
            _require(ref in actual and type(row) is dict and row[key] == ref)
            raw = actual[ref]; hid = ref if kind == 'hosts' else _owner(raw)
            _require(hid in self.hosts and row['href'] == _href(hid, ref)
                     and all(row[f] == raw[f] for f in fields))
            if kind in ('collections', 'assets', 'claims', 'findings') and (p is self.summary or kind == 'claims'):
                refs = self.budget.refs(row['evidence_ids'], self.evidence)
                _require(refs == sorted(raw['evidence_ids']))
            if kind == 'findings':
                _require(self.budget.refs(row['claim_ids'], self.claims) == sorted(raw['claim_ids']))

    def _validate_summary(self):
        s = self.summary
        self._check_table(s, 'hosts', self.hosts, 'host_id',
            ('target_id', 'host_state', 'reason_code', 'attempted', 'attempt_status', 'dispatch_intent'), exact=True)
        self._check_table(s, 'collections', self.collections, 'collection_id',
            ('host_id', 'collector_id', 'collector_version', 'collection_state', 'reason_code', 'source', 'observed_at'), exact=True)
        self._check_table(s, 'assets', self.asset_rows, 'asset_id', ('host_id', 'asset_kind', 'identity_scope'), exact=True)
        self._check_table(s, 'evidence', self.evidence, 'evidence_id',
            ('host_id', 'asset_id', 'collection_id', 'evidence_kind', 'source'), exact=True)
        self._check_table(s, 'claims', self.claims, 'claim_id',
            ('subject', 'level', 'assessment_state', 'reason_code', 'rule_id', 'rule_version'), exact=True)
        self._check_table(s, 'findings', self.findings, 'finding_id',
            ('subject', 'assessment_state', 'reason_code', 'rule_id', 'rule_version', 'condition_key'), exact=True)
        for aid, row in s['assets'].items():
            _require(self.budget.refs(row['collection_ids'], self.collections) ==
                     sorted({self.evidence[eid]['collection_id'] for eid in row['evidence_ids']}))

    def _projection_tables(self, p):
        self.budget = _Budget()
        self._check_table(p, 'hosts', self.hosts, 'host_id', ('target_id', 'host_state'))
        self._check_table(p, 'assets', self.asset_rows, 'asset_id', ('host_id', 'asset_kind', 'identity_scope'))
        self._check_table(p, 'evidence', self.evidence, 'evidence_id',
            ('host_id', 'asset_id', 'collection_id', 'evidence_kind', 'source', 'algorithm', 'observed_at'))
        self._check_table(p, 'claims', self.claims, 'claim_id',
            ('subject', 'level', 'assessment_state', 'reason_code', 'rule_id', 'rule_version'))
        for eid, r in p['evidence'].items():
            raw = self.evidence[eid]; c = self.collections[raw['collection_id']]
            level, state = portal_indexes._observation(raw, c)
            if p is self.assets and raw['source']['source_kind'] == 'LEGACY_IMPORT' and level in ('L4', 'L5'):
                level, state = None, None
            _require((r['level'], r['observation_state']) == (level, state)
                     and r['collector_id'] == c['collector_id'] and r['scope_key'] == c['scope_key']
                     and r['collection_state'] == c['collection_state'] and r['reason_code'] == c['reason_code'])

    def _row(self, category, key, hid, name, state, *, fields=(), version=None,
             pairs=(), refs=(), sources=(), links=(), interval=None, os_fields=()):
        _require(hid in self.hosts and type(key) is str and (version is None or type(version) is str))
        pairs = sorted(set(pairs))
        _require(all(basis in ('observation', 'claim') and level in evidence.LEVELS
                     and type(state) is str and ref in (self.evidence if basis == 'observation' else self.claims)
                     and _owner((self.evidence if basis == 'observation' else self.claims)[ref]) == hid
                     for basis, level, state, ref in pairs))
        # Link targets are synthesized solely from already checked IDs and
        # constant pages; no caller href is ever interpolated.
        refs = sorted(set(refs)); links = list(links)
        for ref in refs:
            table = (self.evidence if ref in self.evidence else self.claims if ref in self.claims else
                     self.collections if ref in self.collections else self.asset_rows)
            _require(ref in table and _owner(table[ref]) == hid)
            links.append((ref, _href(hid, ref)))
        self.rows.append(category, dict(key=key, host=hid, target=self.hosts[hid]['target_id'],
            host_href=_href(hid), name=_value(name), state=_value(state), version=version,
            fields=[('Host state', self.hosts[hid]['host_state'])] + [(label, _value(value)) for label, value in fields], pairs=pairs, typed=_json([p[:3] for p in pairs]),
            sources=sorted(set(sources)), links=links, ref_count=len(refs),
            interval=interval or (None, None), os_fields=os_fields))

    def host_rows(self):
        _require(len(self.ids) <= _MAX_ROWS - self.rows.count, 'PORTAL_PAYLOAD_SIZE_LIMIT')
        for hid in self.ids:
            self.rows.reserve('hosts', hid)
            h = self.hosts[hid]
            # Ignore missing components rather than inventing an OS. Preserve
            # all conflicting observations and keep independent values explicit.
            entries = sorted(self.os[hid], key=lambda x: x[-1]); parts = []
            for i in range(3):
                vals = {x[i] for x in entries if x[i] is not None}
                parts.append(next(iter(vals)) if len(vals) == 1 else 'CONFLICT' if vals else _UNKNOWN)
            refs = [x[-1] for x in entries]
            fields = _fields(h, ('reason_code', 'attempt_status', 'attempted')) + [
                ('OS family', parts[0]), ('Distribution', parts[1]), ('OS version', parts[2]),
                ('Inventory group', 'Not recorded')]
            for family, distribution, version, eid in entries:
                fields.append(('Recorded OS observation', ' / '.join(_value(x) for x in (family, distribution, version))))
            self._row('hosts', hid, hid, h['target_id'], h['host_state'], fields=fields,
                version=parts[2], refs=refs, sources=[_source(self.evidence[eid]['source']) for eid in refs]
                or [_source(self.m['source'])], links=[('Host list', 'hosts.html#' + hid)], os_fields=parts)

    def _group_members(self, p, name, g):
        gid = _id(g['id'], _PREFIX[name]); b = self.budget
        _require(g['backlink'] == name + '.html#' + gid)
        members = {k: b.refs(g[k + '_ids'], p[k + 's'] if k != 'evidence' else p['evidence'])
                   for k in ('host', 'asset', 'evidence', 'claim')}
        hosts, assets, es, cs = (members[k] for k in ('host', 'asset', 'evidence', 'claim'))
        _require(len(hosts) <= _MAX_ROWS - self.rows.count, 'PORTAL_PAYLOAD_SIZE_LIMIT')
        by_host = {hid: {'assets': [], 'evidence': [], 'claims': [], 'pairs': []} for hid in hosts}
        # Check explicit exact membership before adding rows; no host x ref join.
        b.charge(len(hosts) + len(assets) + len(es) + len(cs))
        for aid in assets:
            by_host[_owner(self.asset_rows[aid])]['assets'].append(aid)
        aset = set(assets); actual_assets = set()
        for eid in es:
            row = self.evidence[eid]; part = by_host[row['host_id']]
            _require(row['asset_id'] is None or row['asset_id'] in aset)
            if row['asset_id'] is not None: actual_assets.add(row['asset_id'])
            part['evidence'].append(eid)
        eset = set(es)
        for cid in cs:
            row = self.claims[cid]; subject = row['subject']; b.charge(len(row['evidence_ids']))
            _require(subject['asset_id'] is None or subject['asset_id'] in aset)
            if subject['asset_id'] is not None: actual_assets.add(subject['asset_id'])
            _require(all(eid in eset for eid in row['evidence_ids']))
            by_host[subject['host_id']]['claims'].append(cid)
        if name in ('algorithms', 'libraries'):
            _require(actual_assets == aset and all(part['evidence'] or part['claims'] for part in by_host.values()))
        else:
            _require(all(part['assets'] for part in by_host.values()))
        # Exact typed observation / claim refs; preserve the two namespaces.
        expected = {level: {'observations': defaultdict(list), 'claims': defaultdict(list)} for level in evidence.LEVELS}
        for eid in es:
            r = p['evidence'][eid]; level, state = r['level'], r['observation_state']
            if level is not None and (name != 'libraries' or level not in ('L4', 'L5')):
                expected[level]['observations'][state].append(eid)
                by_host[r['host_id']]['pairs'].append(('observation', level, state, eid))
        for cid in cs:
            r = self.claims[cid]; level, state = r['level'], r['assessment_state']
            _require(name != 'libraries' or level not in ('L4', 'L5'))
            expected[level]['claims'][state].append(cid)
            by_host[r['subject']['host_id']]['pairs'].append(('claim', level, state, cid))
        _require(type(g['levels']) is dict and set(g['levels']) == set(evidence.LEVELS))
        for level, kinds in expected.items():
            for kind, refs in kinds.items():
                _require(g['levels'][level][kind] == dict(refs) and
                         g['levels'][level][kind[:-1] + '_counts'] == {k: len(v) for k, v in refs.items()})
        for k, refs in members.items():
            _require(type(g['counts'][k + '_ids']) is int and g['counts'][k + '_ids'] == len(refs))
        return gid, members, by_host

    def _check_group_id(self, name, g, members):
        gid = g['id']; es, aids = members['evidence'], members['asset']
        if name == 'algorithms':
            status = g['classification']; _require(status in ('CANONICAL', 'UNKNOWN', 'CONFLICT', 'LEGACY'))
            canonical = [g[k] for k in ('algorithm_id', 'taxonomy_version', 'primitive', 'family')]
            # A claim may add other refs to the group; require its actual seed.
            seeds = {eid for eid in es if self.evidence[eid]['algorithm'] is not None and
                     [self.evidence[eid]['algorithm'][k] for k in ('algorithm_id', 'taxonomy_version', 'primitive', 'family')] == canonical
                     and gid == portal_indexes._key('alg', [status, canonical, None if status == 'CANONICAL' else eid])}
            _require(bool(seeds))
            claimed = set()
            for cid in members['claim']:
                refs = self.claims[cid]['evidence_ids']; self.budget.charge(len(refs))
                _require(any(eid in seeds for eid in refs))
                claimed.update(refs)
            _require(set(es) <= seeds | claimed)
        elif name == 'libraries':
            fields = {k: g[k] for k in ('kind', 'name', 'version', 'release', 'architecture', 'epoch', 'presence', 'metadata_state')}
            if g['kind'] == 'LIBRARY_ASSET':
                # Empty, unreferenced groups have no member rows. The original
                # group may still exist; no host is fabricated to display it.
                _require(not aids and not members['host'] or any(gid == portal_indexes._key('lib',
                    ['LIBRARY_ASSET', self.asset_rows[aid]['host_id'], aid]) for aid in aids))
            elif g['metadata_state'] == 'CONFLICT':
                _require(any(gid == portal_indexes._key('lib', [fields, eid]) for eid in es))
            else:
                _require(gid == portal_indexes._key('lib', [fields, None]))
        else:
            _require(bool(aids))
            for aid in aids:
                a = self.asset_rows[aid]
                _require(a['asset_kind'] == ('certificate' if name == 'certificates' else 'service'))
                if name == 'services':
                    identity = [self.rid, a['host_id'], aid]
                elif g['kind'] == 'RECORDED_FINGERPRINT':
                    _require(g['fingerprint'] == a['identity_key'])
                    identity = [g['kind'], g['source_kind'], g['fingerprint']]
                else:
                    _require(g['kind'] in ('LEGACY_RUN_SCOPED', 'UNVERIFIED_IDENTITY') and g['fingerprint'] is None)
                    identity = [g['kind'], self.rid, a['host_id'], aid]
                _require(gid == portal_indexes._key(_PREFIX[name][:-1], identity))
            self.budget.charge(sum(len(self.asset_rows[aid]['evidence_ids']) for aid in aids))
            _require(set(es) == {eid for aid in aids for eid in self.asset_rows[aid]['evidence_ids']})

    def _certificate_occurrences(self, group, members):
        occ = self.assets['occurrences']; result = defaultdict(list)
        refs = self.budget.refs(group['recorded_occurrence_ids'], occ)
        verified = self.budget.refs(group['verified_occurrence_ids'], occ)
        self.budget.refs(group['validity_occurrence_ids'], occ)
        es, aids = set(members['evidence']), set(members['asset'])
        actual_verified = []
        for oid in refs:
            o = occ[oid]; hid, aid, cid = o['host_id'], o['asset_id'], o['collection_id']
            _require(o['id'] == _id(oid, 'occ-') and aid in aids and hid == self.asset_rows[aid]['host_id']
                     and cid in self.collections and self.collections[cid]['host_id'] == hid
                     and group['kind'] == 'RECORDED_FINGERPRINT' and o['fingerprint'] == group['fingerprint']
                     and o['source']['source_kind'] == group['source_kind']
                     and oid == portal_indexes._key('occ', [hid, cid, aid, o['source_id'], o['block_index'], o['detail_sha256']]))
            eids = self.budget.refs(o['evidence_ids'], self.evidence)
            roles = o['role_evidence_ids']
            _require(type(roles) is dict and set(roles) <= {'certificate', 'public-key', 'signature'}
                     and 'certificate' in roles and sorted(roles.values()) == eids and set(eids) <= es)
            for role, eid in roles.items():
                row = self.evidence[eid]
                _require((row['host_id'], row['asset_id'], row['collection_id']) == (hid, aid, cid)
                         and row['observation_key'] == o['source_id'] + '-' + str(o['block_index']) + '-' + role
                         and row['raw_sha256'] == o['detail_sha256'] and row['evidence_ref'] == o['detail_ref'] == 'cert-' + o['detail_sha256']
                         and row['source'] == o['source'] and row['observed_at'] == o['observed_at']
                         and portal_asset_indexes._role_algorithm(row, role))
            _require(o['detail_state'] in ('VERIFIED_COMPANION', 'DETAIL_NOT_RETAINED')
                     and o['root'] == self.collections[cid]['scope_key']
                     and type(o['block_index']) is int and 1 <= o['block_index'] <= cert_assets.MAX_BLOCKS
                     and _id(o['source_id'], 'src-') == o['source_id'])
            meta = o['certificate_metadata']
            if o['detail_state'] == 'VERIFIED_COMPANION':
                _require(type(meta) is dict and set(meta) == set(portal_asset_indexes._METADATA_FIELDS)
                         and type(o['metadata_gaps']) is list)
                # The original verified companion supplied these paired public
                # fields. No re-read or attempt to recover missing bytes.
                _day(meta['not_before']); _day(meta['not_after'])
                # Bind retained metadata to the already verified Evidence
                # occurrence digest, without opening or replaying its slot.
                # The original digest binds the source format (PEM or DER).
                entry = self.cert_details[hid]
                cert = dict(meta, fingerprint=o['fingerprint'], gaps=o['metadata_gaps'])
                cert_assets.validate_certificate(cert)
                record = {k: o[k] for k in ('host_id','source','observed_at','collection_id',
                          'asset_id','root','source_id','target_id','block_index','fingerprint','evidence_ids')}
                record['run_id'] = self.rid
                block = dict(rc=0, reason=o['reason_code'], certificate=cert)
                _require(self.m['batch_contract'] == run_store.PRODUCER_V2_BATCH_CONTRACT
                         and entry['path'] == 'details/' + hid + '/certificate-assets-v1.json'
                         and o['reason_code'] == ('METADATA_GAP' if cert['gaps'] else 'OK')
                         and _id(o['target_id'], 'src-') == o['target_id']
                         and any(cert_assets.digest(dict(record=record, block=block, format=fmt))
                                 == o['detail_sha256'] for fmt in ('PEM', 'DER')))
                actual_verified.append(oid)
            else:
                _require(meta is None and hid not in self.cert_details and o['target_id'] is None
                         and o['reason_code'] == 'DETAIL_NOT_RETAINED' and not o['metadata_gaps'])
            result[hid].append(o)
        _require(actual_verified == verified)
        _require(type(group['verified_occurrence_count']) is int and group['verified_occurrence_count'] == len(verified))
        _require(group['detail_state'] == ('VERIFIED_COMPANION' if verified and len(verified) == len(refs)
                     else 'PARTIAL_COMPANION' if verified else 'DETAIL_NOT_RETAINED'))
        _require(type(group['metadata_fields']) is dict and set(group['metadata_fields']) == set(portal_asset_indexes._METADATA_FIELDS))
        for field in portal_asset_indexes._METADATA_FIELDS:
            values = {oid: occ[oid]['certificate_metadata'][field] for oid in verified
                      if occ[oid]['certificate_metadata'][field] is not None}
            self.budget.charge(len(values) + 1)
            distinct = set(values.values())
            state = ('CONFLICT' if len(distinct) > 1 else 'UNKNOWN' if not distinct else
                     'RECORDED' if len(values) == len(refs) else 'PARTIAL')
            _require(group['metadata_fields'][field] == dict(value=next(iter(distinct)) if len(distinct) == 1 else None,
                     state=state, occurrence_ids=sorted(values)))
        # Verify the saved group-level pairing against occurrence membership;
        # do not use a group interval as the interval for every member host.
        pairs = [oid for oid in verified if occ[oid]['certificate_metadata']['not_before'] is not None
                 and occ[oid]['certificate_metadata']['not_after'] is not None]
        _require(group['validity_state'] == self._host_validity([occ[oid] for oid in refs])[0]
                 and group['validity_occurrence_ids'] == ([] if group['validity_state'] == 'CONFLICT' else pairs))
        return result

    @staticmethod
    def _host_validity(occurrences):
        known = [o['certificate_metadata'] for o in occurrences if o['detail_state'] == 'VERIFIED_COMPANION']
        before = {m['not_before'] for m in known if m['not_before'] is not None}
        after = {m['not_after'] for m in known if m['not_after'] is not None}
        pairs = {(m['not_before'], m['not_after']) for m in known
                 if m['not_before'] is not None and m['not_after'] is not None}
        if len(before) > 1 or len(after) > 1 or any('VALIDITY_CONFLICT' in o['metadata_gaps'] for o in occurrences):
            return 'CONFLICT', None
        if not before and not after:
            return 'UNKNOWN', None
        full = len(known) == len(occurrences) and all(m['not_before'] is not None and m['not_after'] is not None for m in known)
        return ('RECORDED' if full else 'PARTIAL'), (next(iter(pairs)) if len(pairs) == 1 else None)

    def groups(self, p, names):
        self._projection_tables(p)
        for name in names:
            # The original registry budgets apply independently to the two
            # projections. Bound every member expansion before appending.
            index = p[name]; groups = index['groups']; _require(type(groups) is list)
            self.budget.charge(len(groups)); seen = set(); totals = {k: set() for k in ('host', 'asset', 'evidence', 'claim')}
            seen_occ, seen_assets = set(), set()
            for g in groups:
                gid, members, partitions = self._group_members(p, name, g)
                _require(gid not in seen); seen.add(gid)
                self._check_group_id(name, g, members)
                for k, refs in members.items(): totals[k].update(refs)
                occurrences = self._certificate_occurrences(g, members) if name == 'certificates' else {}
                if name in ('certificates', 'services'):
                    _require(not seen_assets.intersection(members['asset'])); seen_assets.update(members['asset'])
                if name == 'certificates':
                    ids = g['recorded_occurrence_ids']; _require(not seen_occ.intersection(ids)); seen_occ.update(ids)
                roles_by_host = defaultdict(list)
                if name == 'certificates':
                    eids = set(members['evidence'])
                    expected_roles = {'public_key': set(), 'signature': set()}
                    for local in occurrences.values():
                        for occurrence in local:
                            for role, eid in occurrence['role_evidence_ids'].items():
                                if role != 'certificate':
                                    expected_roles[role.replace('-', '_')].add(eid)
                    for eid in eids:
                        r = self.evidence[eid]; c = self.collections[r['collection_id']]
                        if (r['evidence_kind'] == 'LEGACY_OBSERVATION' and r['source'] == c['source']
                                and portal_asset_indexes._legacy_scope(c, portal_asset_indexes._LEGACY_CERT_SCOPES)):
                            role = portal_asset_indexes._LEGACY_ROLES.get(r['data']['field'])
                            if (role and type(r['data']['value']) is str and portal_asset_indexes._role_algorithm(r, role)
                                    and r['algorithm']['observed_name'] == r['data']['value']):
                                expected_roles[role.replace('-', '_')].add(eid)
                    for role in ('public_key', 'signature'):
                        role_refs = self.budget.refs(g[role]['evidence_ids'], self.evidence)
                        _require(set(role_refs) == expected_roles[role])
                        for eid in role_refs:
                            r = self.evidence[eid]; alg = r['algorithm']; _require(alg is not None)
                            roles_by_host[r['host_id']].append((role.replace('_', ' '),
                                _value(alg['observed_name']) + ' / ' + _value(alg['algorithm_id'])))
                endpoints = defaultdict(list); historical = defaultdict(list)
                if name == 'services':
                    eids = set(members['evidence']); ep_seen = set()
                    for ep in g['endpoints']:
                        self.budget.charge(); eid = ep['evidence_id']; _require(eid in eids and eid not in ep_seen); ep_seen.add(eid)
                        raw = self.evidence[eid]; data = raw['data']; ctx = data['conditions']
                        _require(raw['evidence_kind'] == 'AUTHORIZED_NEGOTIATION' and raw['source']['source_kind'] != 'LEGACY_IMPORT'
                                 and ctx['host_id'] == raw['host_id'] and ctx['service_asset_id'] == raw['asset_id']
                                 and ep == dict(evidence_id=eid, endpoint_ref=ctx['endpoint_ref'], protocol=ctx['protocol'],
                                     context_ref=ctx['context_ref'], authorization_ref=ctx['authorization_ref'], outcome=data['outcome'],
                                     collection_state=self.collections[raw['collection_id']]['collection_state']))
                        endpoints[raw['host_id']].append(ep)
                    _require(ep_seen == {eid for eid in eids if self.evidence[eid]['evidence_kind'] == 'AUTHORIZED_NEGOTIATION'
                                         and self.evidence[eid]['source']['source_kind'] != 'LEGACY_IMPORT'})
                    legacy = self.budget.refs(g['legacy_evidence_ids'], self.evidence)
                    _require(set(legacy) == {eid for eid in eids if portal_asset_indexes._legacy_tls(
                        self.evidence[eid], self.collections[self.evidence[eid]['collection_id']])
                        and self.asset_rows[self.evidence[eid]['asset_id']]['identity_scope'] == 'RUN_SCOPED'})
                    ports = {self.evidence[eid]['data']['value'] for eid in legacy
                             if self.evidence[eid]['data']['field'] == 'legacy-tls-port'}
                    _require(g['legacy_port'] == (next(iter(ports)) if len(ports) == 1 else None)
                             and g['endpoint_state'] == ('RECORDED_CONTEXT' if ep_seen else 'HISTORICAL_ONLY' if len(ports) == 1
                                 else 'CONFLICT' if len(ports) > 1 else 'UNKNOWN')
                             and g['kind'] == ('LEGACY_SERVICE' if legacy else 'SERVICE_ASSET')
                             and g['certificate_binding_state'] == 'UNKNOWN' and g['certificate_group_ids'] == [])
                    for eid in legacy:
                        r = self.evidence[eid]; _require(r['evidence_kind'] == 'LEGACY_OBSERVATION')
                        historical[r['host_id']].append(('Historical ' + _value(r['data']['field']), _value(r['data']['value'])))
                for hid, part in sorted(partitions.items()):
                    key = gid + ':' + hid; self.rows.reserve(name, key)
                    refs = part['assets'] + part['evidence'] + part['claims']; self.budget.charge(len(refs))
                    links = [('Group ' + gid, name + '.html#' + gid)]
                    fields = [('Group ID', gid)]; version = None; interval = None
                    if name == 'algorithms':
                        state = g['classification']; title = g['algorithm_id']
                        fields += _fields(g, ('classification', 'algorithm_id', 'family', 'primitive', 'taxonomy_version'))
                        observed = sorted({self.evidence[eid]['algorithm']['observed_name'] for eid in part['evidence']
                            if self.evidence[eid]['algorithm'] is not None and self.evidence[eid]['algorithm']['observed_name'] is not None})
                        fields += [('Observed name', x) for x in observed]
                        title = title or (observed[0] if len(observed) == 1 else None); version = g['taxonomy_version']
                    elif name == 'libraries':
                        state, title, version = g['metadata_state'], g['name'], g['version']
                        fields += _fields(g, ('kind', 'name', 'version', 'release', 'architecture', 'epoch', 'presence', 'metadata_state'))
                    elif name == 'certificates':
                        title = g['fingerprint']; local = occurrences.get(hid, [])
                        state, interval = self._host_validity(local)
                        fields += _fields(g, ('kind', 'fingerprint', 'source_kind'))
                        fields += [('Host validity', state), ('Group validity (all members)', _value(g['validity_state'])),
                                   ('Group detail state (all members)', g['detail_state']),
                                   ('Paired not before (host)', _value(interval[0] if interval else None)),
                                   ('Paired not after (host)', _value(interval[1] if interval else None))]
                        fields += roles_by_host[hid]
                        fields += [('Group metadata ' + field + ' state (all members)', g['metadata_fields'][field]['state'])
                                   for field in portal_asset_indexes._METADATA_FIELDS]
                        for o in local:
                            links.append(('Occurrence ' + o['id'], 'certificates.html#' + o['id']))
                            fields += _fields(o, ('source_id', 'target_id', 'block_index', 'detail_state', 'reason_code'))
                            if o['certificate_metadata'] is not None:
                                fields += _fields(o['certificate_metadata'], portal_asset_indexes._METADATA_FIELDS)
                                fields += [('Metadata gap', _value(x)) for x in o['metadata_gaps']]
                        if not local: fields.append(('Occurrence', 'No recorded occurrence'))
                    else:
                        title, state = g['kind'], g['endpoint_state']
                        fields += _fields(g, ('kind', 'endpoint_state', 'legacy_port', 'certificate_binding_state'))
                        for ep in endpoints[hid]: fields += _fields(ep, ('endpoint_ref', 'protocol', 'outcome', 'collection_state'))
                        fields += historical[hid]
                    self._row(name, key, hid, title, state, fields=fields, version=version,
                        pairs=part['pairs'], refs=refs, links=links, interval=interval,
                        sources=[_source(self.evidence[eid]['source']) for eid in part['evidence']])
            unresolved = index.get('unresolved_claim_ids', [])
            self.budget.refs(unresolved, p['claims'])
            _require(not totals['claim'].intersection(unresolved))
            self.unresolved[name] = len(unresolved)
            for cid in unresolved:
                cl = self.claims[cid]; sub = cl['subject']; totals['claim'].add(cid); totals['host'].add(sub['host_id'])
                if sub['asset_id'] is not None: totals['asset'].add(sub['asset_id'])
                self.budget.charge(len(cl['evidence_ids'])); totals['evidence'].update(cl['evidence_ids'])
            for k, refs in totals.items():
                field = k + '_ids'; table = p[k + 's'] if k != 'evidence' else p['evidence']
                _require(self.budget.refs(index[field], table) == sorted(refs) and index['counts'][field] == len(refs))
            _require(index['counts']['groups'] == len(seen))
            if name in ('algorithms', 'libraries'):
                _require(index['counts']['unresolved_claims'] == len(unresolved))
            if name in ('certificates', 'services'):
                _require(seen_assets == {aid for aid, a in self.asset_rows.items()
                    if a['asset_kind'] == ('certificate' if name == 'certificates' else 'service')})
            if name == 'certificates':
                _require(seen_occ == self.assets['occurrences'].keys())

    def finding_rows(self):
        _require(len(self.findings) <= _MAX_ROWS - self.rows.count, 'PORTAL_PAYLOAD_SIZE_LIMIT')
        for fid, f in sorted(self.findings.items()):
            self.rows.reserve('findings', fid)
            hid = f['subject']['host_id']; self.budget.charge(len(f['claim_ids']) + len(f['evidence_ids']) + 1)
            refs = f['claim_ids'] + f['evidence_ids']
            if f['subject']['asset_id'] is not None: refs = refs + [f['subject']['asset_id']]
            pairs = [('claim', self.claims[cid]['level'], self.claims[cid]['assessment_state'], cid) for cid in f['claim_ids']]
            self._row('findings', fid, hid, f['rule_id'], f['assessment_state'],
                fields=_fields(f, ('rule_id', 'rule_version', 'reason_code', 'condition_key')) +
                       _fields(f['subject'], ('asset_id', 'algorithm_id')),
                version=f['rule_version'], pairs=pairs, refs=refs,
                sources=[_source(self.evidence[eid]['source']) for eid in f['evidence_ids']],
                links=[('Finding ' + fid, 'findings.html#' + fid), (fid, _href(hid, fid))])

    def coverage_rows(self):
        s = self.summary; flags = self.m['flags']; _require(s['flags_known'] is (flags is not None))
        rows = s['collector_rows']; _require(type(rows) is list)
        expected = set()
        _require((len(rows) if flags is not None else len(self.collections)) <= _MAX_ROWS - self.rows.count,
                 'PORTAL_PAYLOAD_SIZE_LIMIT')
        if flags is not None:
            _require(len(rows) == len(self.ids) * len(run_store.COLLECTORS))
            for hid in self.ids:
                h = self.hosts[hid]
                for collector in sorted(run_store.COLLECTORS):
                    expected.add((hid, collector))
            by_host = {hid: {} if self.hosts[hid]['terminal'] is None else {
                run_store.NATIVE_COLLECTORS.get(r['collector_id'], r['collector_id']): r
                for r in self.hosts[hid]['terminal']['collectors']} for hid in self.ids}
            for row in rows:
                hid, collector = row['host_id'], row['collector_id']; _require((hid, collector) in expected)
                expected.remove((hid, collector)); h = self.hosts[hid]; terminal = by_host[hid].get(collector)
                requested = flags[hid][collector]
                _require(type(requested) is bool and row['requested'] is requested and row['terminal_present'] is (terminal is not None)
                         and row['attempt_status'] == export_summary._collector_attempt(h, requested, terminal))
                for field in ('state', 'reason_code', 'rc', 'collection_ids'):
                    _require(row[field] == (None if terminal is None else terminal[field]))
                refs = row['collection_ids'] or []; self.budget.refs(refs, self.collections)
                key = hid + ':' + collector; self.rows.reserve('coverage', key)
                fields = _fields(row, ('requested', 'terminal_present', 'attempt_status', 'reason_code', 'rc'))
                fields += [('Collection state', self.collections[cid]['collection_state']) for cid in refs]
                self._row('coverage', key, hid, collector, row['state'], fields=fields, refs=refs,
                          sources=[_source(self.collections[cid]['source']) for cid in refs],
                          links=[('Collector coverage', 'coverage.html#collector-results')])
            _require(not expected)
        else:
            _require(not rows)
            for cid, c in sorted(self.collections.items()):
                hid = c['host_id']; self.rows.reserve('coverage', cid)
                self._row('coverage', cid, hid, c['collector_id'], c['collection_state'],
                    fields=_fields(c, ('scope_key', 'reason_code', 'collector_version')) +
                    [('Requested / terminal / attempt', 'Unknown / not recorded')],
                    refs=[cid], sources=[_source(c['source'])],
                    links=[('Recorded collections', 'coverage.html#recorded-collections')])

    def finish(self):
        self.host_rows()
        self.groups(self.crypto, ('algorithms', 'libraries'))
        self.groups(self.assets, ('certificates', 'services'))
        self.budget = _Budget(); self.finding_rows(); self.coverage_rows()
        tables = []
        for name, rows in self.rows.tables.items():
            rows.sort(key=lambda r: r['key'])
            tables.append(dict(name=name, rows=rows, total=len(rows),
                host_count=len({r['host'] for r in rows}), states=sorted({r['state'] for r in rows}),
                unresolved=self.unresolved.get(name, 0)))
        return tables


def _byte_limit(page_limit, html_limit, bundle_limit):
    _require(all(type(x) is int and x >= 0 for x in (page_limit, html_limit, bundle_limit)))
    return min(page_limit, html_limit, bundle_limit, portal_generation_c._MAX_HTML,
               portal_generation_c._MAX_HTML_TOTAL, portal_generation_c._MAX_BUNDLE)


def _stream(chunks, limit):
    data = bytearray()
    for chunk in chunks:
        raw = chunk.encode('utf-8')
        _require(len(raw) <= limit - len(data), 'PORTAL_PAYLOAD_SIZE_LIMIT')
        data.extend(raw)
    return bytes(data)


def _render_search_page(published, crypto, assets, summary, *, page_limit, html_limit, bundle_limit):
    """Render one private search.html within trusted remaining byte budgets.

    SEARCH-B owns charging the complete generation/receipt and activating it.
    No partial buffer is returned on a failure. No public path or flag exists.
    """
    try:
        limit = _byte_limit(page_limit, html_limit, bundle_limit)
        _require(limit > 0, 'PORTAL_PAYLOAD_SIZE_LIMIT')
        search = _Search(published, crypto, assets, summary)
        tables = search.finish()
        template = Environment(loader=FileSystemLoader(str(_TEMPLATES)), autoescape=True,
                               undefined=StrictUndefined).get_template('search.html.j2')
        return _stream(template.generate(run_id=search.rid, tables=tables, ids=search.ids,
            hosts=search.hosts, assessed=published.assessed is not None,
            flags_known=summary['flags_known'], source=_source(search.m['source'])), limit)
    except run_store.StoreError as exc:
        if exc.code == 'PORTAL_PAYLOAD_SIZE_LIMIT':
            raise
    except (evidence.EvidenceError, TemplateError, KeyError, TypeError, ValueError, AttributeError, IndexError,
            OSError, OverflowError, RecursionError):
        pass
    raise run_store.StoreError('PORTAL_PAYLOAD_INVALID') from None
