"""C1: closed certificate-first V2 Store binding. No transport or discovery.

Only trusted, completed anonymous bridge handoffs are accepted. The original
bridge, Evidence, certificate and assessment validators own their semantics.
This module does not introduce a second producer or a second Store.
"""
from tools import assessment, evidence, run_store as m

CONTRACT = m.PRODUCER_V2_BATCH_CONTRACT
RULES_KIND = m._PRODUCER_RULES_KIND
RULES_FILE = m._PRODUCER_RULES_FILE
FROZEN_FILE = m._PRODUCER_RULES_FROZEN
MAX_RULES = m._MAX_PRODUCER_RULES
HANDOFF = 'producer-handoff-v2'
PLATFORM = 'platform-v2'
CERTIFICATE = 'certificate-assets-v1'
SLOTS = {HANDOFF: 1024 * 1024, PLATFORM: 1024 * 1024, CERTIFICATE: 2 * 1024 * 1024}
SCOPE_FIELDS = m._PRODUCER_SCOPE_FIELDS
SOURCE = {'source_kind': 'SYNTHETIC', 'producer_id': 'pqc-producer-bridge',
          'producer_version': '1.0.0', 'origin_ref': 'i1a-synthetic', 'input_sha256': None}


def enabled(s):
    return s.get('batch_contract') == CONTRACT


def rules_metadata(raw):
    m.require(type(raw) is bytes and 0 < len(raw) <= MAX_RULES, 'PRODUCER_RULES_LIMIT')
    rules = assessment.load_rules(raw)
    return {'producer_rules_sha256': m._digest(raw), 'producer_rules_version': rules['rule_version']}


def load_rules(s, raw):
    m.require(type(raw) is bytes and 0 < len(raw) <= MAX_RULES, 'PRODUCER_RULES_LIMIT')
    m.require(m._digest(raw) == s['producer_rules_sha256'], 'PRODUCER_RULES_MISMATCH')
    rules = assessment.load_rules(raw)
    m.require(rules['rule_version'] == s['producer_rules_version'], 'PRODUCER_RULES_MISMATCH')
    return rules


def read_frozen(fd, device, s):
    m.require(enabled(s), 'BATCH_CONTRACT')
    try:
        raw = m._read(fd, FROZEN_FILE, device, MAX_RULES)
    except FileNotFoundError:
        raise m.StoreError('PRODUCER_RULES_MISSING') from None
    load_rules(s, raw)
    return raw


def required_slots(s):
    return [{'host_id': h['host_id'], 'slot': slot}
            for h in s['hosts'] if s['flags'][h['host_id']]['system_certs']
            for slot in sorted(SLOTS)]


def scope(s):
    m.require(s['run_kind'] == 'SYNTHETIC' and s['evidence_schema_version'] == '1.1.0'
              and s['source'] == SOURCE, 'UNVERIFIED_PRODUCER_FORMAT')
    m.require(s['started_at'] is not None and
              evidence._timestamp_key(s['started_at']) <= evidence._timestamp_key(s['recorded_at']),
              'PRODUCER_TIME_MISMATCH')
    m.require(all(h['identity_scope'] == 'RUN_SCOPED' and h['inventory_authority_id'] is None
                  and h['identity_key'] == h['target_id'] for h in s['hosts']), 'HOST_IDENTITY')
    m.require(all(not any(v for k, v in flags.items() if k != 'system_certs')
                  for flags in s['flags'].values()), 'PROFILE_FLAGS')
    m.require(not s['requirements']['cff'], 'UNVERIFIED_PRODUCER_FORMAT')
    m.require({(x['host_id'], x['slot']) for x in s['requirements']['details']} ==
              {(x['host_id'], x['slot']) for x in required_slots(s)}, 'INVALID_DETAIL_REQUIREMENT')
    m.require(m._match(s['producer_rules_sha256'], m.HEX) and
              m._match(s['producer_rules_version'], m.SLUG), 'PRODUCER_RULES_MISMATCH')


def flags(s, hid):
    return {long: s['flags'][hid][short] for long, short in m.NATIVE_COLLECTORS.items()}


def terminal(s, doc, h, row, attempted):
    """Reuse the original V2 single-host validators, including frozen flags."""
    from tools import scan_collectors as bridge
    api = m._native_api()
    m._keys(row, 'target_id host_state attempted reason_code collectors platform')
    ff = flags(s, h['host_id'])
    m.require(type(row['collectors']) is list and len(row['collectors']) == len(api._COLLECTORS),
              'INVALID_TERMINAL_MANIFEST')
    m.require(api._valid_v2_outcome(row['platform'], bridge.PLATFORM, any(ff.values()), 10)
              and all(api._valid_v2_outcome(c, f, ff[f], 3 if f == bridge.CERT_FLAG else 0)
                      for c, f in zip(row['collectors'], api._COLLECTORS))
              and api._valid_host(api._v2_base_row(row), h['target_id'], ff),
              'INVALID_TERMINAL_MANIFEST')
    m.require(row['attempted'] is attempted and row['host_state'] == h['host_state']
              and row['reason_code'] == h['reason_code'], 'BATCH_HOST_STATE')
    coll = {c['collection_id']: c for c in doc['collections'] if c['host_id'] == h['host_id']}
    scopes = {bridge.PLATFORM: set(bridge._partition(bridge.PLATFORM, None)),
              bridge.CERT: set(bridge.cert_assets.ROOTS)}
    used = set()
    for outcome, producer in ((row['platform'], bridge.PLATFORM),
                              (next(c for c in row['collectors'] if c['collector_id'] == bridge.CERT_FLAG),
                               bridge.CERT)):
        ids = set(outcome['collection_ids'])
        m.require(ids <= coll.keys() and not used & ids, 'FOREIGN_REF')
        m.require(all(coll[x]['collector_id'] == producer and coll[x]['scope_key'] in scopes[producer]
                      for x in ids), 'FOREIGN_COLLECTOR')
        m.require(not ids or (outcome['requested'] and attempted is True and
                             len(ids) == len(scopes[producer]) and
                             {coll[x]['scope_key'] for x in ids} == scopes[producer]),
                  'PRODUCER_REFERENCE_MISMATCH')
        used.update(ids)
    m.require(used == coll.keys(), 'BATCH_COVERAGE')
    return row


def batch(s, doc, value, rc, attempts):
    api = m._native_api()
    try:
        api.validate_producer_manifest(value, rc)
    except (api.Denied, KeyError, TypeError, ValueError):
        raise m.StoreError('INVALID_TERMINAL_MANIFEST') from None
    index = {h['target_id']: h for h in doc['hosts']}
    m.require(value['target_ids'] == sorted(index) and value['target_count'] == len(index), 'BATCH_TARGETS')
    m.require(m._same(value['limits'], s['limits']) and value['profile'] == s['profile'], 'BATCH_SCOPE')
    for row in value['hosts']:
        h = index[row['target_id']]
        att = attempts[h['host_id']]
        m.require(m._same(row, att['terminal']), 'TERMINAL_MISMATCH')
        terminal(s, doc, h, row, att['attempted'])
    m.require(value['run_state'] == doc['run']['run_state'], 'BATCH_RUN_STATE')
    m.require('coverage_reason' not in doc['run'] or doc['run']['coverage_reason'] == value['reason_code'],
              'BATCH_RUN_REASON')
    return value


def detail_bytes(slot, value):
    from tools import cert_assets, scan_collectors as bridge
    m._enum(slot, SLOTS)
    # Bound the exact value before invoking the original serializer. This also
    # preserves the Store's private-field, depth and node limits.
    m._json_bytes(value, SLOTS[slot])
    try:
        raw = cert_assets.canonical(value) if slot == CERTIFICATE else bridge.wire_bytes(value)
        if slot == HANDOFF:
            bridge.read_wire(raw)
    except (bridge.BridgeError, ValueError, TypeError, RecursionError, OverflowError):
        raise m.StoreError('INVALID_PRODUCER_DETAIL') from None
    m.require(0 < len(raw) <= SLOTS[slot], 'ARTIFACT_SIZE')
    return raw


def parse_detail(host, slot, raw):
    m._id(host); m._enum(slot, SLOTS)
    value = m._loads(raw, SLOTS[slot])
    m.require(detail_bytes(slot, value) == raw, 'NONCANONICAL_PRODUCER_DETAIL')
    return {'host_id': host, 'slot': slot, 'value': value}


def _no_handoff(s, h, row):
    """The original ledger's zero-projection terminals, not positive evidence."""
    from tools import scan_collectors as bridge
    api = m._native_api()
    ff = flags(s, h['host_id']); active = any(ff.values())
    reason = row['reason_code']; attempted = row['attempted']
    if not attempted:
        m.require(active or reason == 'NO_EXECUTABLE_COLLECTORS', 'INVALID_TERMINAL_MANIFEST')
        expected = api._blank(h['target_id'], ff, reason)
        gap = 'DISABLED' if not active else reason if reason in api._OUTCOMES['NOT_SCANNED'] else 'STOPPED'
        expected['platform'] = api._outcome(bridge.PLATFORM, active, 'NOT_SCANNED', gap)
    elif reason in ('CONNECTION_FAILED', 'CONNECTION_TIMEOUT'):
        state = 'UNREACHABLE' if reason == 'CONNECTION_FAILED' else 'ERROR'
        expected = api._host(h['target_id'], True,
                             [api._outcome(f, True, state, reason) if ff[f] else
                              api._outcome(f, False, 'NOT_SCANNED', 'DISABLED') for f in api._COLLECTORS], reason)
        expected['platform'] = api._outcome(bridge.PLATFORM, True, state, reason)
    else:
        m.require(reason in api._FATAL, 'PRODUCER_HANDOFF_MISSING')
        expected = api._blank(h['target_id'], ff, reason, True)
        expected['platform'] = api._outcome(bridge.PLATFORM, True, 'ERROR', 'OUTCOME_UNKNOWN')
    m.require(m._same(row, expected), 'PRODUCER_HANDOFF_MISSING')


def _refs(doc, hid, ids):
    rows = [r for r in doc['evidence'] if r['host_id'] == hid and r['collection_id'] in ids]
    return {'collection_ids': sorted(ids), 'asset_ids': sorted({r['asset_id'] for r in rows if r['asset_id'] is not None}),
            'evidence_ids': sorted(r['evidence_id'] for r in rows)}


def verify_host(s, doc, h, row, details, rules):
    """Reproduce the original projection from the retained closed wire object.

    The one-host view is only a binding view for the original validator;
    the full V2 terminal manifest is separately validated by batch().
    """
    from tools import cert_assets, scan_collectors as bridge
    api = m._native_api(); hid = h['host_id']; target = h['target_id']
    m.require(type(details) is list and len(details) <= len(SLOTS), 'SLOT_LIMIT')
    values = {}; encoded = {}
    allowed = {x['slot'] for x in s['requirements']['details'] if x['host_id'] == hid}
    for d in details:
        m._keys(d, 'host_id slot value')
        m.require(d['host_id'] == hid and type(d['slot']) is str and d['slot'] in allowed
                  and d['slot'] not in values, 'INVALID_SLOT')
        values[d['slot']] = d['value']; encoded[d['slot']] = detail_bytes(d['slot'], d['value'])
    fragment = m.host_fragment(doc, hid)
    if row is None:
        m.require(not values and not any(fragment[k] for k in ('collections', 'assets', 'evidence')),
                  'MISSING_TERMINAL_CHECKPOINT')
        return {}
    if HANDOFF not in values:
        m.require(not values and not any(fragment[k] for k in ('collections', 'assets', 'evidence')),
                  'PRODUCER_HANDOFF_MISSING')
        _no_handoff(s, h, row)
        return {}
    m.require(row['attempted'] is True and any(flags(s, hid).values()), 'ATTEMPT_STATE')
    try:
        envelope = bridge.read_wire(encoded[HANDOFF])
        p = bridge.normalize_handoff(envelope, s['run_id'], target, flags(s, hid), s['started_at'], rules)
        m.require(all(evidence._timestamp_key(s['started_at']) <= evidence._timestamp_key(r['observed_at'])
                      <= evidence._timestamp_key(s['recorded_at']) for r in envelope['records']),
                  'PRODUCER_TIME_MISMATCH')
        # The original host classifier excludes Platform from the eight flags.
        expected = api._host(target, True, [p.outcomes[f] for f in api._COLLECTORS], p.special)
        expected['platform'] = p.outcomes[bridge.PLATFORM]
        # The original ledger can conservatively downgrade a provisional result
        # on worker failure, never promote a failed/fatal result to success.
        downgrade = row['reason_code'] in ('CONTROLLER_CLEANUP_UNCONFIRMED', 'CONTROLLER_WORKER_FAILED',
                                            'CONTROLLER_TIMEOUT', 'OUTCOME_UNKNOWN',
                                            'INVALID_NATIVE_RESULT', 'INTERRUPTED')
        if p.special == 'REMOTE_CLEANUP_UNCONFIRMED':
            downgrade = row['reason_code'] == 'CONTROLLER_CLEANUP_UNCONFIRMED'
        m.require(m._same(row, expected) or (downgrade and row['host_state'] == 'ERROR'),
                  'PRODUCER_OUTCOME_MISMATCH')
        companions = {}
        for producer, slot in ((bridge.PLATFORM, PLATFORM), (bridge.CERT, CERTIFICATE)):
            if slot in values:
                companions[producer] = values[slot]
        # Strict canonical byte equality also distinguishes bool from int and
        # binds order, the original companion, and every hash/occurrence.
        m.require(set(companions) == set(p.companions), 'PRODUCER_DETAIL_MISMATCH')
        for producer, slot in ((bridge.PLATFORM, PLATFORM), (bridge.CERT, CERTIFICATE)):
            if producer in companions:
                m.require(encoded[slot] == detail_bytes(slot, p.companions[producer]), 'PRODUCER_DETAIL_MISMATCH')
        bridge.validate_bindings({'target_ids': [target], 'hosts': [row],
                                  'run_state': fragment['run']['run_state']},
                                 fragment, {target: companions}, {target: p})
        if CERTIFICATE in values:
            cert_assets.validate_cert_details(fragment, values[CERTIFICATE], rules)
    except m.StoreError:
        raise
    except (bridge.BridgeError, evidence.EvidenceError, assessment.AssessmentError,
            ValueError, TypeError, KeyError, IndexError, RecursionError, OverflowError):
        raise m.StoreError('INVALID_PRODUCER_BINDING') from None
    pids = set(row['platform']['collection_ids'])
    cids = set(next(c for c in row['collectors'] if c['collector_id'] == bridge.CERT_FLAG)['collection_ids'])
    m.require(bool(pids) == (PLATFORM in values) and bool(cids) == (CERTIFICATE in values),
              'PRODUCER_DETAIL_MISMATCH')
    refs = {HANDOFF: _refs(fragment, hid, pids | cids)}
    if PLATFORM in values:
        refs[PLATFORM] = _refs(fragment, hid, pids)
    if CERTIFICATE in values:
        refs[CERTIFICATE] = _refs(fragment, hid, cids)
    for value in refs.values():
        m._refs(fragment, hid, value)
    return refs


def check_stage(fd, device, entries):
    """An incomplete prepared stage may contain a subset, never hidden slots."""
    core = {row['path'] for key, row in entries.items() if key[0] != 'detail'}
    expected = {}
    for kind, host, slot in entries:
        if kind == 'detail':
            expected.setdefault(host, set()).add(slot + '.json')
    names = set(m._entries(fd, m.MAX_SLOTS))
    m.require(names <= core | {'details'}, 'UNINDEXED_ARTIFACT')
    if 'details' in names:
        with m._directory(fd, ('details',), device) as d:
            hosts = set(m._entries(d, 10))
            m.require(hosts <= expected.keys(), 'UNINDEXED_ARTIFACT')
            for host in hosts:
                with m._directory(d, (host,), device) as h:
                    m.require(set(m._entries(h, len(SLOTS))) <= expected[host], 'UNINDEXED_ARTIFACT')
