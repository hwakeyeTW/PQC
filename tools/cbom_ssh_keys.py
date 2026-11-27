"""Private SK-A projection of standalone SSH public keys from replayed V3.

The caller must own an untouched snapshot returned by actual RunStore V3
replay. PublishedRun and hashes alone are not authentication. This module
has no public entry point, path input, I/O, or BOM/Portal integration.
"""
from typing import NamedTuple

from tools import evidence, run_store as store, run_store_v2 as v2
from tools import run_store_v3 as v3, scan_collectors as bridge, ssh_posture as ssh


_SLOT = v3.PRODUCER_SLOTS[bridge.SSH]
_USABLE = frozenset(('COLLECTED', 'PARTIAL'))
_BASIS = 'VERIFIED_SSH_STANDALONE_KEY'
_USABLE_HOSTS = frozenset(('COMPLETE', 'PARTIAL'))


class _ProjectionError(ValueError):
    """Fixed diagnostics; never echo caller data or source exceptions."""


class _Key(NamedTuple):
    run_id: str
    host_id: str
    asset_id: str
    identity_basis: str
    fingerprint_sha256: str
    key_type: str
    bits: int
    evidence_ids: tuple[str, ...]
    collection_ids: tuple[str, ...]


class _Omission(NamedTuple):
    reason: str
    evidence_ids: tuple[str, ...] = ()
    collection_ids: tuple[str, ...] = ()
    asset_ids: tuple[str, ...] = ()


class _Projection(NamedTuple):
    run_id: str
    host_id: str
    recovery: bool
    host_state: str
    attempt_status: str
    collection_state: str | None
    keys: tuple[_Key, ...]
    omissions: tuple[_Omission, ...]


def _require(ok, code='INVALID_V3_KEY_PROOF'):
    if not ok:
        raise _ProjectionError(code)


def _entries(published):
    """Check the closed manifest inventory, not paths on a filesystem."""
    m = published.manifest
    required = v3._required(m)
    _require(m['requirements'] == dict(assessment=True, cff=True, details=required))
    slots = {(x['host_id'], x['slot']) for x in required}
    rows = m['artifacts']
    _require(type(rows) is list and 0 < len(rows) <= 66 and type(published.artifacts) is dict)
    index, total = {}, 0
    for entry in rows:
        store._keys(entry, store.ENTRY_KEYS)
        parts, cap = v3._slot(entry['kind'], entry['host_id'], entry['slot'])
        path = '/'.join(parts)
        _require(entry['path'] == path and path not in index and entry['required'] is True)
        if entry['kind'] == 'detail':
            _require((entry['host_id'], entry['slot']) in slots and entry['format_version'] == store.VERSION)
        raw = published.artifacts[path]
        _require(type(raw) is bytes and type(entry['size']) is int and 0 < len(raw) == entry['size'] <= cap
                 and store._match(entry['sha256'], store.HEX))
        index[path] = entry
        total += len(raw)
        _require(total <= v3.CORE_BYTES)
    _require(index.keys() == published.artifacts.keys())
    missing = m['missing_artifacts']
    _require(type(missing) is list and len(missing) <= 64)
    missing_paths = {}
    for item in missing:
        store._keys(item, 'path reason_code')
        _require(item['path'] not in missing_paths and item['path'] not in index)
        missing_paths[item['path']] = item['reason_code']
    expected_missing = ({v3.FILES[k][0]: ('BATCH_MANIFEST_UNAVAILABLE' if k == 'batch'
                        else 'REQUIRED_ARTIFACT_MISSING') for k in ('batch', 'assessed', 'rules', 'cff')}
                        if m['recovery'] else {})
    hosts = {h['host_id']: h for h in m['hosts']}
    for hid, slot in slots:
        path = '/'.join(v3._slot('detail', hid, slot)[0])
        if path not in index:
            _require(hosts[hid]['host_state'] != 'COMPLETE')
            expected_missing[path] = 'REQUIRED_DETAIL_MISSING'
    _require(missing_paths == expected_missing)
    core = {'evidence': '1.1.0', v2.RULES_KIND: m['producer_rules_version']}
    if not m['recovery']:
        core.update(batch=store.VERSION, assessed='1.1.0', rules=m['producer_rules_version'], cff=store.VERSION)
    _require({e['kind'] for e in index.values() if e['kind'] != 'detail'} == set(core))
    for kind, version in core.items():
        entry = index['/'.join(v3._slot(kind)[0])]
        _require(entry['format_version'] == version and
                 all(entry[k] == [] for k in ('collection_ids', 'asset_ids', 'evidence_ids')))
    # Verify the retained raw Evidence bytes against their manifest entry.
    # Do not reparse/recanonicalize the complete V3 fleet for each host.
    _read(published, index, 'evidence')
    return index


def _read(published, entries, kind, host=None, slot=None):
    parts, _ = v3._slot(kind, host, slot)
    path = '/'.join(parts)
    entry = entries[path]
    raw = published.artifacts[path]
    _require(store._digest(raw) == entry['sha256'])
    if kind == 'detail':
        value = v3._parse_detail(host, slot, raw)['value']
    else:
        value = raw
    return entry, value


def _fragment(published, hid):
    """Index one host once; never pass the entire V3 document to a V1 cap."""
    m, doc = published.manifest, published.document
    run = doc['run']
    _require(doc['schema_version'] == '1.1.0' and not doc['claims'] and not doc['findings'])
    _require(all(run[k] == m[k] for k in ('run_id', 'source', 'started_at', 'finished_at',
                                         'recorded_at', 'run_state', 'expected_host_ids')))
    _require(run['coverage_reason'] == m['reason_code'])
    _require(type(m['hosts']) is list and 1 <= len(m['hosts']) <= 10 and type(doc['hosts']) is list)
    ids = [h['host_id'] for h in m['hosts']]
    _require(ids == sorted(set(ids)) == m['expected_host_ids'] and
             ids == sorted(h['host_id'] for h in doc['hosts']) and set(m['flags']) == set(ids))
    _require(hid in ids, 'UNKNOWN_EXPECTED_HOST')
    h = next(h for h in m['hosts'] if h['host_id'] == hid)
    store._keys(h, v3.HOST_KEYS)
    original = next(h for h in doc['hosts'] if h['host_id'] == hid)
    _require(original == bridge.host_record(m['run_id'], h['target_id'], h['host_state'], h['reason_code']))
    _require(all(h[k] == original[k] for k in original))
    flags = m['flags'][hid]
    _require(type(flags) is dict and flags.keys() == set(store.COLLECTORS) and
             all(type(x) is bool for x in flags.values()) and not flags['nginx_certs'] and not flags['tls_services'])
    _require(h['host_state'] in store.HOST_STATES and type(h['dispatch_intent']) is bool)
    attempt = store._attempt(m, original, h['attempted'], h['dispatch_intent'])
    _require(all(h[k] == v for k, v in attempt.items()))
    _require(h['dispatch_intent'] == (h['dispatch_intent_at'] is not None))
    if h['terminal'] is None:
        _require(m['recovery'] is True and h['checkpoint_recorded_at'] is None and h['attempted'] is not True)
    else:
        _require(type(h['attempted']) is bool and h['checkpoint_recorded_at'] is not None)
        v3._terminal(m, original, h['terminal'], h['attempted'])
        v3._order(h['dispatch_intent_at'] or m['reserved_at'], h['checkpoint_recorded_at'], m['recorded_at'])
    fragment = {**doc, 'run': {**run, 'expected_host_ids': [hid], 'run_state': store._run_state([original])},
                'hosts': [original]}
    for registry in ('collections', 'assets', 'evidence'):
        rows = doc[registry]
        _require(type(rows) is list and len(rows) <= 200000)
        fragment[registry] = [r for r in rows if r['host_id'] == hid]
    return h, fragment


def _refs(entry, fragment, cids):
    expected = v2._refs(fragment, fragment['hosts'][0]['host_id'], cids)
    _require(all(entry[k] == value for k, value in expected.items()))
    store._refs(fragment, fragment['hosts'][0]['host_id'], entry)


def _proof(published, entries, host, fragment):
    """Bind the retained mandatory slot to its actual wire and raw rows.

    Store already replayed all producers. Additional pairing is limited to
    this host and the original frozen rules; never regenerate a fleet or
    re-assess keys. No hash or generic metadata is a substitute for replay.
    """
    m = published.manifest
    hid, rid = host['host_id'], m['run_id']
    hp = '/'.join(v3._slot('detail', hid, v3.HANDOFF)[0])
    sp = '/'.join(v3._slot('detail', hid, _SLOT)[0])
    collections = fragment['collections']
    ssh_ids = {c['collection_id'] for c in collections if c['collector_id'] == bridge.SSH}
    if hp not in entries:
        _require(sp not in entries and not any(fragment[k] for k in ('collections', 'assets', 'evidence')))
        return None
    _require(host['attempted'] is True and host['terminal'] is not None)
    handoff_entry, handoff = _read(published, entries, 'detail', hid, v3.HANDOFF)
    _refs(handoff_entry, fragment, {c['collection_id'] for c in collections})
    bridge.shape(handoff, ('handoff_version', 'run_id', 'target_id', 'connection', 'records'))
    _require(type(handoff['records']) is list and len(handoff['records']) <= len(bridge.PRODUCERS))
    _require(type(handoff['handoff_version']) is int and handoff['handoff_version'] == bridge.WIRE_VERSION
             and handoff['run_id'] == rid and handoff['target_id'] == host['target_id'])
    ssh_rows = [r for r in handoff['records'] if r['producer_id'] == bridge.SSH]
    _require(len(ssh_rows) <= 1)
    if sp not in entries:
        _require(not ssh_ids and (not ssh_rows or ssh_rows[0]['snapshot'] is None))
        return None
    _require(len(ssh_rows) == 1 and handoff['connection'] == 'CONNECTED')
    row = ssh_rows[0]
    bridge.shape(row, ('producer_id', 'observed_at', 'reason_code', 'rc', 'cleanup_confirmed', 'snapshot'))
    snapshot = row['snapshot']
    _require(type(snapshot) is dict and row['cleanup_confirmed'] is True)
    if snapshot['platform_status'] == 'UNVERIFIED':
        _require(row['reason_code'] == 'COMMAND_OK' and type(row['rc']) is int and row['rc'] == 0)
    else:
        _require(row['reason_code'] == 'PLATFORM_GAP' and row['rc'] is None)
    v3._order(host['dispatch_intent_at'], row['observed_at'], host['checkpoint_recorded_at'], m['recorded_at'])
    entry, detail = _read(published, entries, 'detail', hid, _SLOT)
    _refs(entry, fragment, ssh_ids)
    _require(detail['run_id'] == rid and detail['host_id'] == hid and detail['observed_at'] == row['observed_at']
             and detail['source'] == bridge._source(bridge.SSH, snapshot))
    _require(detail['flags'] == {f: v2.flags(m, hid)[f] for f in ssh.FLAGS})
    # Match the complete typed snapshot, including non-key/config rows.
    # The original paired validator below checks exact order, grammar, IDs,
    # detail digest, source, backrefs, and the original collection states.
    slots = detail['records']
    _require(type(slots) is list and 8 <= len(slots) <= 9 and
             len({r['slot'] for r in slots}) == len(slots))
    reconstructed = {k: detail[k] for k in ('flags', 'platform_status', 'context_refs')}
    reconstructed['slots'] = {r['slot']: {**{k: r[k] for k in ('state', 'reason', 'rc', 'gaps')},
                                          'rows': [o['row'] for o in r['observations']]} for r in slots}
    _require(reconstructed == snapshot)
    re, rules_raw = _read(published, entries, v2.RULES_KIND)
    _require(re['format_version'] == m['producer_rules_version'] and
             re['sha256'] == m['producer_rules_sha256'] and
             all(re[k] == [] for k in ('collection_ids', 'asset_ids', 'evidence_ids')))
    rules = v2.load_rules(m, rules_raw)
    ssh.validate_details(fragment, detail, rules)
    keys = next(r for r in slots if r['slot'] == 'keys')
    terminal_keys = next(r for r in host['terminal']['collectors'] if r['collector_id'] == bridge.KEYS)
    key_collection = next(c for c in collections if c['collection_id'] == keys['collection_id'])
    _require(terminal_keys == bridge._aggregate(bridge.KEYS, m['flags'][hid]['ssh_host_keys'],
                                                [key_collection], row))
    return keys


def _project(published, hid):
    _require(type(published) is store.PublishedRun and type(published.manifest) is dict,
             'UNVERIFIED_V3_SNAPSHOT')
    m = published.manifest
    _require(m.get('manifest_version') == v3.VERSION and m.get('batch_contract') == v3.CONTRACT and
             m.get('capacity_profile') == v3.CAPACITY_PROFILE and m.get('publication_state') == 'PUBLISHED' and
             m.get('run_kind') == 'SYNTHETIC' and m.get('evidence_schema_version') == '1.1.0' and
             m.get('source') == v2.SOURCE, 'UNVERIFIED_V3_SNAPSHOT')
    store._keys(m, v3.MANIFEST_KEYS)
    store._rid(m['run_id']); store._id(hid)
    _require(type(m['recovery']) is bool)
    if m['recovery']:
        _require(m['finished_at'] is None and m['recovered_at'] == m['recorded_at'])
    else:
        _require(m['recovered_at'] is None and m['finished_at'] is not None)
    host, fragment = _fragment(published, hid)
    entries = _entries(published)
    record = _proof(published, entries, host, fragment)
    state = record['state'] if record is not None else None
    cid = (record['collection_id'],) if record is not None else ()
    rid = m['run_id']

    def result(keys=(), omissions=()):
        return _Projection(rid, hid, m['recovery'], host['host_state'], host['attempt_status'], state,
                           tuple(keys), tuple(omissions))

    def omit(reason):
        observations = record['observations'] if record is not None else ()
        return result(omissions=(_Omission(reason,
            tuple(sorted(o['evidence_id'] for o in observations)), cid,
            tuple(sorted({o['asset_id'] for o in observations if o['asset_id'] is not None}))),))

    if host['attempt_status'] == 'UNKNOWN':
        return omit('OUTCOME_UNKNOWN')
    if not m['flags'][hid]['ssh_host_keys']:
        return omit('KEYS_DISABLED')
    if host['attempt_status'] == 'NOT_ATTEMPTED':
        return omit('NOT_ATTEMPTED')
    if host['host_state'] not in _USABLE_HOSTS:
        blocked = omit('HOST_NOT_USABLE')
        if record is None:
            return blocked._replace(omissions=blocked.omissions + (_Omission('PROOF_NOT_RETAINED'),))
        return blocked
    if record is None:
        return omit('PROOF_NOT_RETAINED')
    if state not in _USABLE:
        return omit('KEY_COLLECTION_UNAVAILABLE')
    observations = record['observations']
    _require(len(observations) <= 32)
    assets = {r['asset_id']: r for r in fragment['assets']}
    grouped, omissions = {}, []
    for observation in observations:
        row = observation['row']
        if row['grammar'] != 'KNOWN':
            _require(row['grammar'] == 'UNKNOWN_TYPE' and observation['asset_id'] is None)
            omissions.append(_Omission('UNKNOWN_KEY_TYPE', (observation['evidence_id'],), cid))
            continue
        aid = observation['asset_id']
        identity = 'sha256-' + row['fingerprint_sha256']
        _require(aid == evidence.asset_id(hid, 'public_key', identity, run_id=rid))
        asset = assets[aid]
        _require(asset['asset_kind'] == 'public_key' and asset['identity_scope'] == 'RUN_SCOPED' and
                 asset['identity_key'] == identity)
        metadata = (row['fingerprint_sha256'], row['key_type'], row['bits'])
        old, ids = grouped.setdefault(aid, (metadata, set()))
        _require(old == metadata and observation['evidence_id'] not in ids)
        ids.add(observation['evidence_id'])
    keys = []
    for aid, (metadata, ids) in sorted(grouped.items()):
        _require(sorted(ids) == sorted(assets[aid]['evidence_ids']))
        keys.append(_Key(rid, hid, aid, _BASIS, *metadata, tuple(sorted(ids)), cid))
    if state == 'PARTIAL':
        omissions.append(_Omission('KEY_COLLECTION_PARTIAL', collection_ids=cid))
    if not observations:
        omissions.append(_Omission('NO_KEYS_OBSERVED', collection_ids=cid))
    return result(keys, sorted(omissions))


def _project_verified_v3_keys(published, host_id):
    """Return closed, deterministic, host-local descriptors and omissions.

    Only for the trusted replay caller chain, under its snapshot ownership.
    No public admission, caller-supplied proof, or fallback to generic assets.
    """
    try:
        return _project(published, host_id)
    except _ProjectionError:
        raise
    except (ValueError, KeyError, TypeError, AttributeError, IndexError, StopIteration,
            OverflowError, RecursionError):
        raise _ProjectionError('INVALID_V3_KEY_PROOF') from None
