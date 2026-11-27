"""Private B04 V3 Store policy. The existing RunStore owns locks and pinned I/O.

No acquisition/dispatch, automatic version selector, arbitrary capacity or path inputs.
The only authoritative inputs are the frozen reservation, canonical typed
handoffs and final terminal checkpoints. Recompute derived artifacts on read.
"""
from collections import Counter
from datetime import datetime, timezone
from functools import wraps
import json
import math
import os
import re
import secrets
import stat
from types import MappingProxyType
from typing import NamedTuple

from tools import assessment, cff, evidence, run_store as m, run_store_v2 as v2
from tools import scan_collectors as bridge

VERSION = '1.1.0'
CONTRACT = 'B04_PRODUCER_V3'
CAPACITY_PROFILE = 'B04_V3_CAPACITY_R2'
MIB = 1024 * 1024
RAW_BYTES = 64 * MIB
ASSESSED_BYTES = 96 * MIB
CFF_BYTES = 128 * MIB
CHECKPOINT_BYTES = 40 * MIB
CHECKPOINT_TOTAL = 400 * MIB
CORE_BYTES = 256 * MIB
MANIFEST_BYTES = 16 * MIB
HANDOFF = 'producer-handoff-v2'
SLOTS = MappingProxyType({HANDOFF: MIB, 'platform-v2': MIB,
    'certificate-assets-v1': 2*MIB, 'openssl-runtime-v2': MIB,
    'crypto-policy-v2': MIB, 'ssh-posture-v2': 2*MIB})
PRODUCER_SLOTS = MappingProxyType({bridge.PLATFORM: 'platform-v2',
    bridge.OPENSSL: 'openssl-runtime-v2', bridge.POLICY: 'crypto-policy-v2',
    bridge.SSH: 'ssh-posture-v2', bridge.CERT: 'certificate-assets-v1'})
FILES = MappingProxyType({**m.FILES, 'evidence': ('evidence.json', RAW_BYTES),
    'assessed': ('assessed_evidence.json', ASSESSED_BYTES),
    'cff': ('cff_projection.json', CFF_BYTES),
    v2.RULES_KIND: (v2.RULES_FILE, v2.MAX_RULES)})
STAGES = ('RAW_EVIDENCE', 'ASSESSED_EVIDENCE', 'CFF', 'CORE')
SCOPE_KEYS = ('run_id run_kind evidence_schema_version source started_at reserved_at '
              'hosts limits profile flags requirements batch_contract capacity_profile '
              + m._PRODUCER_SCOPE_FIELDS)
MANIFEST_KEYS = (m.MANIFEST_KEYS + ' capacity_profile reserved_at recovered_at '
                 + m._PRODUCER_SCOPE_FIELDS)
HOST_KEYS = ('host_id target_id identity_scope inventory_authority_id identity_key '
             'host_state reason_code attempted dispatch_intent attempt_status terminal '
             'dispatch_intent_at checkpoint_recorded_at')
CHECKPOINT_KEYS = 'checkpoint_version document attempted terminal details checkpoint_recorded_at'
JOURNAL_KEYS = 'journal_version scope intents intent_times blocked_capacity_stage'


class CapacityError(m.StoreError):
    def __init__(self, stage):
        m._enum(stage, STAGES)
        self.stage = stage
        super().__init__('V3_CAPACITY_LIMIT')


def _budget(size, limit, stage):
    if size > limit:
        raise CapacityError(stage)


def _checkpoint_budget(total, size):
    m.require(type(size) is int and 0 < size <= CHECKPOINT_BYTES, 'ARTIFACT_SIZE')
    m.require(total + size <= CHECKPOINT_TOTAL, 'CHECKPOINT_SIZE_LIMIT')
    return total + size


def _clock():
    return datetime.now(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def _time(value):
    evidence.STAMP.check(value, '$store.time')
    return evidence._timestamp_key(value)


def _order(*values):
    keys = [_time(v) for v in values]
    m.require(keys == sorted(keys), 'PRODUCER_TIME_MISMATCH')


def _flags(s, hid):
    return v2.flags(s, hid)


def _required(s):
    slots = []
    for h in s['hosts']:
        hid = h['host_id']; producers = bridge.requested(_flags(s, hid))
        for slot in sorted([HANDOFF, *(PRODUCER_SLOTS[p] for p in producers)] if producers else []):
            slots.append({'host_id': hid, 'slot': slot})
    return slots


def _scope(s):
    m._keys(s, SCOPE_KEYS)
    m.require(s['batch_contract'] == CONTRACT and s['capacity_profile'] == CAPACITY_PROFILE
              and s['run_kind'] == 'SYNTHETIC' and s['evidence_schema_version'] == '1.1.0'
              and s['source'] == v2.SOURCE, 'BATCH_CONTRACT')
    m._rid(s['run_id']); _order(s['started_at'], s['reserved_at'])
    hs = s['hosts']; m.require(type(hs) is list and 1 <= len(hs) <= 10, 'HOST_LIMIT')
    targets = []
    for h in hs:
        m._keys(h, 'host_id target_id identity_scope inventory_authority_id identity_key host_state reason_code')
        target = h['target_id']; api = m._native_api()
        m.require(type(target) is str and bridge.TARGET.fullmatch(target) and
                  api._scope.HOST.fullmatch(target) and target.lower() not in api._scope.RESERVED
                  and not api._scope.loopback(target), 'INVALID_TARGET')
        m.require(h == bridge.host_record(s['run_id'], target, 'NOT_ATTEMPTED', 'NOT_ATTEMPTED'), 'HOST_IDENTITY')
        targets.append(target)
    ids = m._ids([h['host_id'] for h in hs], limit=10)
    m.require(len(set(targets)) == len(hs) and [h['host_id'] for h in hs] == sorted(ids), 'HOST_MANIFEST')
    lim = s['limits']; m._keys(lim, 'max_hosts forks serial ssh_timeout_s command_timeout_s')
    m._int(lim['max_hosts'], len(hs), 10); m._int(lim['forks'], 1, 2)
    m._int(lim['serial'], 2, 2); m._int(lim['ssh_timeout_s'], 15, 15); m._int(lim['command_timeout_s'], 30, 30)
    m._enum(s['profile'], ('baseline', 'extended'))
    m.require(type(s['flags']) is dict and set(s['flags']) == ids, 'PROFILE_FLAGS')
    for flags in s['flags'].values():
        m.require(type(flags) is dict and set(flags) == set(m.COLLECTORS) and
                  all(type(v) is bool for v in flags.values()) and not flags['nginx_certs']
                  and not flags['tls_services'], 'PROFILE_FLAGS')
    m.require(s['requirements'] == {'assessment': True, 'cff': True, 'details': _required(s)}
              and s['requirements']['assessment'] is True and s['requirements']['cff'] is True,
              'INVALID_DETAIL_REQUIREMENT')
    m.require(m._match(s['producer_rules_sha256'], m.HEX) and
              m._match(s['producer_rules_version'], m.SLUG), 'PRODUCER_RULES_MISMATCH')
    return s


def _journal(j, rid):
    m._keys(j, JOURNAL_KEYS)
    m.require(j['journal_version'] == VERSION, 'UNSUPPORTED_JOURNAL_VERSION')
    s = _scope(j['scope']); m.require(s['run_id'] == rid, 'MANIFEST_IDENTITY')
    ids = m._ids(j['intents'], limit=10)
    m.require(j['intents'] == sorted(ids) and type(j['intent_times']) is dict and
              set(j['intent_times']) == ids and ids <= {h['host_id'] for h in s['hosts']}, 'FOREIGN_REF')
    for hid, stamp in j['intent_times'].items():
        m.require(any(s['flags'][hid].values()), 'NO_EXECUTABLE_COLLECTORS')
        _order(s['reserved_at'], stamp)
    m.require(j['blocked_capacity_stage'] is None or j['blocked_capacity_stage'] in STAGES,
              'INVALID_CAPACITY_STAGE')
    return j


def _read_journal(fd, device, rid):
    return _journal(m._unseal(m._read(fd, 'journal.json', device, MANIFEST_BYTES), MANIFEST_BYTES), rid)


def _rules(fd, device, s):
    raw = m._read(fd, v2.FROZEN_FILE, device, v2.MAX_RULES)
    return raw, v2.load_rules(s, raw)


def begin(store, *, run_id, expected_hosts, requested_flags, limits, profile,
          producer_rules_raw, started_at=None):
    store._check(); m._rid(run_id)
    meta = v2.rules_metadata(producer_rules_raw)
    # The trusted writer samples reservation time itself. The caller may
    # supply the actual prior start, never a predicted completion time.
    reserved = _clock()
    started = reserved if started_at is None else started_at
    _order(started, reserved)
    m.require(type(expected_hosts) is list and 1 <= len(expected_hosts) <= 10, 'HOST_LIMIT')
    hosts = m._new_hosts(run_id, expected_hosts)
    m.require(type(requested_flags) is dict and set(requested_flags) == {h['target_id'] for h in hosts}, 'PROFILE_FLAGS')
    flags = {}
    for h in hosts:
        f = requested_flags[h['target_id']]
        m.require(type(f) is dict and set(f) == set(m.NATIVE_COLLECTORS) and
                  all(type(x) is bool for x in f.values()), 'PROFILE_FLAGS')
        flags[h['host_id']] = {short: f[long] for long, short in m.NATIVE_COLLECTORS.items()}
    s = dict(run_id=run_id, run_kind='SYNTHETIC', evidence_schema_version='1.1.0',
             source=dict(v2.SOURCE), started_at=started, reserved_at=reserved,
             hosts=hosts, limits=limits, profile=profile, flags=flags,
             batch_contract=CONTRACT, capacity_profile=CAPACITY_PROFILE, **meta)
    try:
        s['requirements'] = {'assessment': True, 'cff': True, 'details': _required(s)}
    except bridge.BridgeError:
        raise m.StoreError('PROFILE_FLAGS') from None
    s = _scope(m._loads(m._json_bytes(s)))
    j = _journal(dict(journal_version=VERSION, scope=s, intents=[], intent_times={},
                      blocked_capacity_stage=None), run_id)
    # Same pinned root reservation, local FS, exclusive lock, atomic writes
    # and durability primitives as RunStore.begin. No separate storage root.
    root_lock = m._lock_file(store._fd, '.reservation.lock', store._device, create=True)
    fd = lock = None
    try:
        m._flock(root_lock, wait=True)
        m.require(not any(x.casefold() == run_id.casefold() for x in m._entries(store._fd, m.MAX_ROOT_ENTRIES)), 'RUN_ID_COLLISION')
        try:
            fd = m._mkdir(store._fd, run_id, store._device)
        except FileExistsError:
            raise m.StoreError('RUN_ID_COLLISION') from None
        lock = m._lock_file(fd, '.writer.lock', store._device, create=True); m._flock(lock)
        with m._directory(fd, ('checkpoints',), store._device, create=True): pass
        m._write(fd, v2.FROZEN_FILE, producer_rules_raw, store._device)
        m._write(fd, 'journal.json', m._seal(j, MANIFEST_BYTES), store._device)
        writer = Writer(fd, lock, store._device, j)
        fd = lock = None
        return writer
    finally:
        if lock is not None: os.close(lock)
        if fd is not None: os.close(fd)
        os.close(root_lock)


# Bounded secret walk for the already validated R2-P model/projection. Do
# not reserialize large derivatives through the old generic 4M-node guard.
def _private_data(value, stage):
    limit = {'RAW_EVIDENCE': RAW_BYTES, 'ASSESSED_EVIDENCE': ASSESSED_BYTES,
             'CFF': 8000000}[stage]
    nodes = 0
    def visit(v, depth):
        nonlocal nodes
        nodes += 1; _budget(nodes, limit, stage)
        m.require(depth <= 64, 'JSON_LIMIT')
        if type(v) is dict:
            for k, x in v.items():
                m.require(type(k) is str and len(k) <= 512, 'INVALID_TYPE')
                m.require(re.sub('[^a-z0-9]', '', k.lower()) not in m.SECRET_KEYS, 'FORBIDDEN_FIELD')
                visit(x, depth + 1)
        elif type(v) is list:
            for x in v: visit(x, depth + 1)
        elif type(v) is str:
            m.require(len(v) <= 4096 and not re.search(r'-----BEGIN [^-\r\n]*PRIVATE KEY-----', v, re.I), 'FORBIDDEN_FIELD')
        elif type(v) is int:
            m.require(abs(v) <= 9007199254740991, 'INVALID_INTEGER')
        elif type(v) is float:
            m.require(math.isfinite(v), 'INVALID_TYPE')
        else:
            m.require(v is None or type(v) is bool, 'INVALID_TYPE')
    visit(value, 1)


def _raw(document):
    raw = evidence._canonical_v3_raw(document)
    _private_data(document, 'RAW_EVIDENCE')
    return raw


def _slot(kind, host=None, slot=None):
    if kind == 'detail':
        m._id(host); m._enum(slot, SLOTS)
        return ('details', host, slot + '.json'), SLOTS[slot]
    m.require(type(kind) is str and kind in FILES and kind != 'legacy' and host is None and slot is None, 'INVALID_SLOT')
    name, cap = FILES[kind]
    return (name,), cap


def _detail_bytes(slot, value):
    m._enum(slot, SLOTS)
    m._json_bytes(value, SLOTS[slot])
    try:
        if slot == PRODUCER_SLOTS[bridge.CERT]:
            raw = bridge.cert_assets.canonical(value)
        elif slot == PRODUCER_SLOTS[bridge.SSH]:
            raw = bridge.ssh_posture.canonical(value)
        else:
            raw = bridge.wire_bytes(value)
        if slot == HANDOFF: bridge.read_wire(raw)
    except (ValueError, TypeError, RecursionError, OverflowError):
        raise m.StoreError('INVALID_PRODUCER_DETAIL') from None
    m.require(0 < len(raw) <= SLOTS[slot], 'ARTIFACT_SIZE')
    return raw


def _parse_detail(hid, slot, raw):
    m._id(hid); m._enum(slot, SLOTS)
    value = m._loads(raw, SLOTS[slot])
    m.require(_detail_bytes(slot, value) == raw, 'NONCANONICAL_PRODUCER_DETAIL')
    return dict(host_id=hid, slot=slot, value=value)


def _terminal(s, h, row, attempted):
    api = m._native_api(); ff = _flags(s, h['host_id'])
    m._keys(row, 'target_id host_state attempted reason_code collectors platform')
    caps = {bridge.PACKAGES: 2, bridge.SSL: 261, bridge.POLICY_FLAG: 9,
            bridge.SSHD: 8, bridge.KEYS: 1, bridge.CERT_FLAG: 3, bridge.NGINX: 0, bridge.TLS: 0}
    m.require(type(row['collectors']) is list and len(row['collectors']) == len(api._COLLECTORS) and
              api._valid_v2_outcome(row['platform'], bridge.PLATFORM, any(ff.values()), 10) and
              all(api._valid_v2_outcome(c, f, ff[f], caps[f]) for c, f in zip(row['collectors'], api._COLLECTORS)),
              'INVALID_TERMINAL_MANIFEST')
    m.require(api._valid_host(api._v2_base_row(row), h['target_id'], ff) and
              row['attempted'] is attempted and row['host_state'] == h['host_state'] and
              row['reason_code'] == h['reason_code'], 'BATCH_HOST_STATE')
    ids = [i for c in [row['platform'], *row['collectors']] for i in c['collection_ids']]
    m.require(len(ids) == len(set(ids)) <= bridge.MAX_REFS, 'PRODUCER_REFERENCE_LIMIT')
    # Validate the original conditional predecessor/fatal rules even before
    # a full terminal manifest exists. This is a shape-only validation view,
    # never a persisted run, replacement terminal or digest.
    stopped = row['reason_code'] if row['reason_code'] in api._FATAL else (
        'OUTCOME_UNKNOWN' if row['reason_code'] == 'STOPPED' else None)
    state, reason, rc = api._run_state([row], stopped)
    try:
        api.validate_producer_manifest(dict(batch_manifest_version=2, target_ids=[h['target_id']],
            target_count=1, limits=s['limits'], profile=s['profile'], run_state=state,
            reason_code=reason, hosts=[row]), rc)
    except (api.Denied, ValueError, KeyError, TypeError):
        raise m.StoreError('INVALID_TERMINAL_MANIFEST') from None
    return row


def _batch(s, rows, raw, rc):
    api = m._native_api(); value = m._loads(raw, MANIFEST_BYTES)
    try:
        api.validate_producer_manifest(value, rc)
    except (api.Denied, KeyError, TypeError, ValueError):
        raise m.StoreError('INVALID_TERMINAL_MANIFEST') from None
    targets = sorted(h['target_id'] for h in s['hosts'])
    m.require(value['target_ids'] == targets and value['target_count'] == len(targets) and
              value['limits'] == s['limits'] and value['profile'] == s['profile'], 'BATCH_SCOPE')
    m.require(all(m._same(r, rows[r['target_id']]) for r in value['hosts']), 'TERMINAL_MISMATCH')
    return value


def _fragment(s, doc, hid, intent, checkpoint_time):
    run = doc['run']; h = doc['hosts'][0]
    frozen = next(x for x in s['hosts'] if x['host_id'] == hid)
    m.require(doc['schema_version'] == '1.1.0' and len(doc['hosts']) == 1 and h['host_id'] == hid and
              m._host_identity(h) == m._host_identity(frozen) and run['expected_host_ids'] == [hid] and
              all(run[k] == s[k] for k in ('run_id', 'started_at', 'source')) and not doc['claims'] and not doc['findings'],
              'EVIDENCE_SCOPE')
    m.require(run['run_state'] == m._run_state([h]), 'RUN_STATE')
    _order(s['reserved_at'], run['recorded_at'], checkpoint_time)
    if intent is not None: _order(intent, run['recorded_at'])
    finish = run['finished_at']
    if finish is not None: _order(intent or s['reserved_at'], finish, run['recorded_at'])
    for k in ('collections', 'evidence'):
        for row in doc[k]:
            if row['observed_at'] is not None:
                m.require(intent is not None and finish is not None, 'PRODUCER_TIME_MISMATCH')
                _order(intent, row['observed_at'], finish)
    return h


class _Checkpoint(NamedTuple):
    document: dict
    attempt: dict
    details: tuple
    projection: object
    refs: dict
    timestamp: str
    seal_sha: str


def _verify_checkpoint(j, body, hid, rules, seal_sha):
    m._keys(body, CHECKPOINT_KEYS)
    m.require(body['checkpoint_version'] == VERSION, 'UNSUPPORTED_CHECKPOINT_VERSION')
    s = j['scope']; doc = body['document']; canonical = _raw(doc)
    m.require(m._json_bytes(doc, 32*MIB) == canonical, 'NONCANONICAL_EVIDENCE')
    m.require(len(doc['hosts']) == 1, 'HOST_MANIFEST')
    intent = j['intent_times'].get(hid); stamp = body['checkpoint_recorded_at']
    h = _fragment(s, doc, hid, intent, stamp)
    attempted, row = body['attempted'], body['terminal']; m._bool(attempted)
    att = m._attempt(s, h, attempted, intent is not None)
    _terminal(s, h, row, attempted); att.update(terminal=row, dispatch_intent_at=intent,
                                               checkpoint_recorded_at=stamp)
    details = body['details']; m.require(type(details) is list and len(details) <= len(SLOTS), 'SLOT_LIMIT')
    allowed = {d['slot'] for d in s['requirements']['details'] if d['host_id'] == hid}
    values = {}; encoded = {}; total = 0
    for detail in details:
        m._keys(detail, 'host_id slot value')
        slot = detail['slot']; m.require(detail['host_id'] == hid and type(slot) is str and slot in allowed
                                       and slot not in values, 'INVALID_SLOT')
        raw = _detail_bytes(slot, detail['value']); total += len(raw)
        m.require(total <= 8*MIB, 'ARTIFACT_SIZE')
        encoded[slot] = raw; values[slot] = detail['value']
    m.require(h['host_state'] != 'COMPLETE' or set(values) == allowed, 'REQUIRED_DETAIL_MISSING')
    if HANDOFF not in values:
        m.require(not values and not any(doc[k] for k in ('collections', 'assets', 'evidence')), 'PRODUCER_HANDOFF_MISSING')
        v2._no_handoff(s, h, row)
        return _Checkpoint(doc, att, (), None, {}, stamp, seal_sha)
    m.require(attempted and intent is not None, 'ATTEMPT_STATE')
    ff = _flags(s, hid); api = m._native_api()
    try:
        envelope = bridge.read_wire(encoded[HANDOFF])
        for record in envelope['records']:
            m.require(doc['run']['finished_at'] is not None, 'PRODUCER_TIME_MISMATCH')
            _order(intent, record['observed_at'], doc['run']['finished_at'])
        p = bridge.normalize_handoff(envelope, s['run_id'], h['target_id'], ff, s['started_at'], rules,
            staged_openssl=any(ff[f] for f in (bridge.PACKAGES, bridge.SSL)),
            staged_policy=ff[bridge.POLICY_FLAG], staged_ssh=any(ff[f] for f in (bridge.SSHD, bridge.KEYS)),
            staged_cert=ff[bridge.CERT_FLAG])
        expected = api._host(h['target_id'], True, [p.outcomes[f] for f in api._COLLECTORS], p.special)
        expected['platform'] = p.outcomes[bridge.PLATFORM]
        # Exact lifecycle downgrade allowed by the original worker_failed;
        # its final outcome is not reclassified as a successful projection.
        downgrade = row['reason_code'] in ('CONTROLLER_CLEANUP_UNCONFIRMED', 'CONTROLLER_WORKER_FAILED',
            'CONTROLLER_TIMEOUT', 'OUTCOME_UNKNOWN', 'INVALID_NATIVE_RESULT', 'INTERRUPTED')
        if p.special == 'REMOTE_CLEANUP_UNCONFIRMED':
            downgrade = row['reason_code'] == 'CONTROLLER_CLEANUP_UNCONFIRMED'
        m.require(m._same(row, expected) or (downgrade and row['host_state'] == 'ERROR'), 'PRODUCER_OUTCOME_MISMATCH')
        companions = {producer: values[slot] for producer, slot in PRODUCER_SLOTS.items() if slot in values}
        m.require(set(companions) == set(p.companions) and set(values) == {HANDOFF, *(PRODUCER_SLOTS[k] for k in p.companions)}, 'PRODUCER_DETAIL_MISMATCH')
        for producer, companion in p.companions.items():
            slot = PRODUCER_SLOTS[producer]
            m.require(encoded[slot] == _detail_bytes(slot, companion), 'PRODUCER_DETAIL_MISMATCH')
        bridge.validate_bindings({'target_ids': [h['target_id']], 'hosts': [row],
            'run_state': doc['run']['run_state']}, doc, {h['target_id']: companions}, {h['target_id']: p})
        # normalize_handoff already runs the original SSH and Cert paired
        # validators. Exact companion equality above binds those results.
    except m.StoreError:
        raise
    except (ValueError, KeyError, TypeError, IndexError, RecursionError, OverflowError):
        raise m.StoreError('INVALID_PRODUCER_BINDING') from None
    by_producer = {producer: set() for producer in p.companions}
    for c in doc['collections']:
        m.require(c['collector_id'] in by_producer, 'FOREIGN_COLLECTOR')
        by_producer[c['collector_id']].add(c['collection_id'])
    refs = {HANDOFF: v2._refs(doc, hid, set().union(*by_producer.values()))}
    for producer, ids in by_producer.items():
        refs[PRODUCER_SLOTS[producer]] = v2._refs(doc, hid, ids)
    for value in refs.values(): m._refs(doc, hid, value)
    return _Checkpoint(doc, att, tuple(sorted(encoded.items())), p, refs, stamp, seal_sha)


def _operation(fn):
    @wraps(fn)
    def run(self, *args, **kwargs):
        try:
            return fn(self, *args, **kwargs)
        except (CapacityError, evidence.V3CapacityError) as exc:
            self._capacity_failure(exc.stage)
            raise CapacityError(exc.stage) from None
        except (bridge.BridgeError, KeyError, TypeError, IndexError, OverflowError, RecursionError):
            self._poisoned = True
            raise m.StoreError('INVALID_STORE_DATA') from None
        except BaseException:
            self._poisoned = True
            raise
    return m._public(run)


class Writer(m.RunWriter):
    def __init__(self, fd, lock, device, journal, *, recovery_guard=None):
        super().__init__(fd, lock, device, journal)
        self._cache = {}  # only validated, same-byte committed checkpoints
        # Only the explicitly locked recovery entry supplies this guard.
        self._recovery_guard = recovery_guard
        self._recovery_checkpoints = None

    def _guard_recovery(self):
        if self._recovery_guard is not None:
            self._recovery_guard()
            m.require(not m._exists(self._fd, 'run_manifest.json'), 'ALREADY_PUBLISHED')

    def _persist(self, parent, name, raw, *, guard=None, **kwargs):
        if self._recovery_guard is not None:
            check = self._guard_recovery if guard is None else guard
            check()
            kwargs['before_publish'] = check
        m._write(parent, name, raw, self._device, **kwargs)


    def close(self):
        self._cache.clear()
        super().close()

    def _check(self, *, mutable=True):
        m.require(self._fd is not None and not self._poisoned, 'WRITER_CLOSED_OR_FAILED')
        m._check_dir(self._fd, self._device)
        self._guard_recovery()
        m.require(not m._exists(self._fd, 'run_manifest.json'), 'ALREADY_PUBLISHED')
        if mutable:
            m.require(not m._exists(self._fd, 'prepared.json'), 'PUBLICATION_PREPARED')
            m.require(self._j['blocked_capacity_stage'] is None, 'WRITER_CLOSED_OR_FAILED')
        actual = _read_journal(self._fd, self._device, self.run_id)
        m.require(m._same(actual, self._j), 'FROZEN_SCOPE_MISMATCH')
        _rules(self._fd, self._device, self._j['scope'])

    def _set_journal(self, j):
        _journal(j, self.run_id)
        self._persist(self._fd, 'journal.json', m._seal(j, MANIFEST_BYTES), replace_journal=True)
        self._j = j

    def _capacity_failure(self, stage):
        # Do not overwrite a prepared plan or a published marker. A failed
        # journal fsync is not represented as a durable blocked stage.
        self._poisoned = True
        if self._fd is not None and not m._exists(self._fd, 'prepared.json') and not m._exists(self._fd, 'run_manifest.json'):
            actual = _read_journal(self._fd, self._device, self.run_id)
            m.require(m._same(actual, self._j), 'FROZEN_SCOPE_MISMATCH')
            self._set_journal({**self._j, 'blocked_capacity_stage': stage})

    def _latest(self, checkpoints=()):
        return max([self._j['scope']['reserved_at'], *self._j['intent_times'].values(),
                    *(c.timestamp for c in checkpoints)], key=_time)

    @_operation
    def dispatch_intent(self, host_id):
        self._check(); self._host(host_id)
        m.require(any(self._j['scope']['flags'][host_id].values()), 'NO_EXECUTABLE_COLLECTORS')
        m.require(host_id not in self._j['intents'], 'DUPLICATE_INTENT')
        with m._directory(self._fd, ('checkpoints',), self._device) as d:
            m.require(not m._exists(d, host_id + '.json'), 'TERMINAL_EXISTS')
        now = _clock(); _order(self._latest(self._cache.values()), now)
        j = {**self._j, 'intents': sorted([*self._j['intents'], host_id]),
             'intent_times': {**self._j['intent_times'], host_id: now}}
        self._set_journal(j)

    @_operation
    def record_host(self, fragment, *, attempted, terminal, details=None):
        self._check(); s = self._j['scope']
        raw = _raw(fragment); doc = evidence._parse_v3_raw(raw)
        m.require(len(doc['hosts']) == 1, 'HOST_MANIFEST')
        hid = doc['hosts'][0]['host_id']; self._host(hid)
        values = {} if details is None else details
        m.require(type(values) is dict and len(values) <= len(SLOTS), 'SLOT_LIMIT')
        parsed = []
        for slot, data in values.items(): parsed.append(_parse_detail(hid, slot, data))
        now = _clock(); _order(self._latest(self._cache.values()), now)
        body = dict(checkpoint_version=VERSION, document=doc, attempted=attempted,
                    terminal=terminal, details=sorted(parsed, key=lambda d: d['slot']), checkpoint_recorded_at=now)
        # Own independent copies: caller mutation after return cannot change
        # the in-process witness or the bytes subsequently used by finalize.
        sealed = m._seal(body, CHECKPOINT_BYTES)
        body = m._unseal(sealed, CHECKPOINT_BYTES)
        _, rules = _rules(self._fd, self._device, s)
        validated = _verify_checkpoint(self._j, body, hid, rules, m._digest(sealed))
        with m._directory(self._fd, ('checkpoints',), self._device) as d:
            name = hid + '.json'; m.require(not m._exists(d, name), 'TERMINAL_EXISTS')
            allowed = {h['host_id'] + '.json' for h in s['hosts']}
            total = _checkpoint_budget(0, len(sealed))
            for n in m._entries(d, 3000):
                if re.fullmatch(r'\.tmp-[0-9a-f]{32}', n): continue
                m.require(n in allowed, 'FOREIGN_CHECKPOINT')
                f = m._open_file(d, n, self._device)
                try: size = m._stat_file(f, self._device).st_size
                finally: os.close(f)
                total = _checkpoint_budget(total, size)
            m._write(d, name, sealed, self._device)
        self._cache[hid] = validated

    def _checkpoints(self):
        s = self._j['scope']; allowed = {h['host_id'] for h in s['hosts']}
        _, rules = _rules(self._fd, self._device, s)
        total = 0; found = {}
        with m._directory(self._fd, ('checkpoints',), self._device) as d:
            for name in m._entries(d, 3000):
                if re.fullmatch(r'\.tmp-[0-9a-f]{32}', name):
                    m._check_file_stat(os.stat(name, dir_fd=d, follow_symlinks=False), self._device)
                    continue
                hid = name[:-5]; m.require(name.endswith('.json') and hid in allowed, 'FOREIGN_CHECKPOINT')
                # Check per-file and cumulative budgets before reading.
                f = m._open_file(d, name, self._device)
                try: size = m._stat_file(f, self._device).st_size
                finally: os.close(f)
                total = _checkpoint_budget(total, size)
                raw = m._read(d, name, self._device, CHECKPOINT_BYTES, size)
                sha = m._digest(raw); old = self._cache.get(hid)
                if old is not None:
                    m.require(old.seal_sha == sha, 'CHECKPOINT_MISMATCH'); found[hid] = old
                else:
                    body = m._unseal(raw, CHECKPOINT_BYTES)
                    found[hid] = _verify_checkpoint(self._j, body, hid, rules, sha)
        m.require(set(self._cache) <= set(found), 'MISSING_TERMINAL_CHECKPOINT')
        if self._recovery_guard is not None:
            hashes = {hid: cp.seal_sha for hid, cp in found.items()}
            if self._recovery_checkpoints is not None:
                m.require(hashes == self._recovery_checkpoints, 'CHECKPOINT_MISMATCH')
            self._recovery_checkpoints = hashes
            self._cache.update(found)
        return found

    @_operation
    def finalize(self, *, batch_raw, batch_rc, finished_at=None):
        self._check(); checkpoints = self._checkpoints()
        recorded = _clock(); finished = recorded if finished_at is None else finished_at
        _order(self._latest(checkpoints.values()), recorded)
        result = self._derive(checkpoints, recovery=False, recorded=recorded, finished=finished,
                              batch_raw=batch_raw, batch_rc=batch_rc)
        return self._prepare(result)

    @_operation
    def _recover_unprepared(self):
        self._check(mutable=False); m.require(not m._exists(self._fd, 'prepared.json'), 'PUBLICATION_PREPARED')
        # Reject a foreign/unsafe root namespace before deriving or staging
        # anything. Unprepared recovery cannot adopt existing core slots.
        _check_index(self._fd, self._device, {}, None, final_only=False)
        checkpoints = self._checkpoints(); now = _clock(); _order(self._latest(checkpoints.values()), now)
        result = self._derive(checkpoints, recovery=True, recorded=now, finished=None,
                              batch_raw=None, batch_rc=None)
        return self._prepare(result)

    def _derive(self, checkpoints, *, recovery, recorded, finished, batch_raw, batch_rc):
        s = self._j['scope']; rules_raw, rules = _rules(self._fd, self._device, s)
        _order(self._latest(checkpoints.values()), recorded)
        m.require(recovery or len(checkpoints) == len(s['hosts']), 'MISSING_TERMINAL_CHECKPOINT')
        hosts = []; rows = []; terminals = {}; projections = {}; companions = {}; wire_total = 0
        for h in s['hosts']:
            hid = h['host_id']; target = h['target_id']; intent = self._j['intent_times'].get(hid)
            if hid in checkpoints:
                cp = checkpoints[hid]; host = cp.document['hosts'][0]; att = cp.attempt
                terminals[target] = att['terminal']
                if finished is not None and cp.document['run']['finished_at'] is not None:
                    _order(cp.document['run']['finished_at'], finished)
                if cp.projection is not None:
                    projections[target] = cp.projection; companions[target] = cp.projection.companions
                wire_total += sum(len(raw) for slot, raw in cp.details if slot == HANDOFF)
                m.require(wire_total <= 10*bridge.MAX_WIRE, 'HANDOFF_SIZE_LIMIT')
            else:
                host = ({**h, 'host_state': 'ERROR', 'reason_code': 'OUTCOME_UNKNOWN'} if intent is not None else h)
                att = {**m._attempt(s, host, None if intent is not None else False, intent is not None),
                       'terminal': None, 'dispatch_intent_at': intent, 'checkpoint_recorded_at': None}
            hosts.append(host); rows.append({**host, **att})
        if recovery:
            m.require(finished is None and batch_raw is None and batch_rc is None, 'RECOVERY_STATE')
            state, reason = m._run_state(hosts, interrupted=True), 'RECOVERY_INCOMPLETE'; batch = None
        else:
            m.require(finished is not None, 'PRODUCER_TIME_MISMATCH'); _order(s['reserved_at'], finished, recorded)
            for intent_time in self._j['intent_times'].values(): _order(intent_time, finished)
            batch = _batch(s, terminals, batch_raw, batch_rc); state, reason = batch['run_state'], batch['reason_code']
        document = bridge.document(s['run_id'], s['started_at'], hosts, state, finished)
        document['run'].update(recorded_at=recorded, coverage_reason=reason)
        # Exact row byte accounting before extending each registry. Every
        # fragment is already canonical; sorting does not change byte count.
        def size(v):
            return len(json.dumps(v, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8'))
        raw_size = size(document)
        for cp in checkpoints.values():
            for registry in ('collections', 'assets', 'evidence'):
                source = cp.document[registry]; dest = document[registry]
                _budget(len(dest) + len(source), 200000, 'RAW_EVIDENCE')
                raw_size += sum(size(row) for row in source) + max(0, len(source) - (0 if dest else 1))
                _budget(raw_size, RAW_BYTES, 'RAW_EVIDENCE'); dest.extend(source)
        raw = _raw(document); m.require(len(raw) == raw_size, 'NONCANONICAL_EVIDENCE')
        document = evidence._parse_v3_raw(raw)
        # Full aggregate binder uses the same row/companion/terminal semantics
        # as the old binder. Unknown recovery hosts have no invented terminal.
        if not recovery:
            try:
                bridge._validate_v3_bindings(batch, document, companions, projections)
            except evidence.V3CapacityError:
                raise
            except (ValueError, KeyError, TypeError):
                raise m.StoreError('INVALID_PRODUCER_BINDING') from None
        payloads = {}; entries = []; total = 0
        def add(kind, value, *, host=None, slot=None, refs=None, version=m.VERSION):
            nonlocal total
            parts, cap = _slot(kind, host, slot)
            m.require(type(value) is bytes and 0 < len(value) <= cap, 'ARTIFACT_SIZE')
            _budget(total + len(value), CORE_BYTES, 'CORE'); total += len(value)
            path = '/'.join(parts); m.require(path not in payloads, 'DUPLICATE_SLOT')
            payloads[path] = value
            entries.append(dict(kind=kind, format_version=version, host_id=host, slot=slot,
                path=path, size=len(value), sha256=m._digest(value), required=True,
                **{k: [] if refs is None else refs[k] for k in ('collection_ids', 'asset_ids', 'evidence_ids')}))
        add('evidence', raw, version='1.1.0'); add(v2.RULES_KIND, rules_raw, version=s['producer_rules_version'])
        present = set()
        for hid, cp in checkpoints.items():
            for slot, raw in cp.details:
                add('detail', raw, host=hid, slot=slot, refs=cp.refs[slot]); present.add((hid, slot))
        assessed = None; rules_sha = rule_version = None; batch_hash = None; missing = []
        if not recovery:
            add('batch', batch_raw); batch_hash = m._digest(m._json_bytes(batch))
            assessed = assessment._evaluate_v3_raw(document, rules)
            assessed_raw = evidence._canonical_v3_assessed(assessed); _private_data(assessed, 'ASSESSED_EVIDENCE')
            add('assessed', assessed_raw, version='1.1.0'); add('rules', rules_raw, version=s['producer_rules_version'])
            projection = cff._project_v3_assessed(assessed, rules)
            m.require(projection['evidence_document_sha256'] == m._digest(assessed_raw) and
                      [p['host_id'] for p in projection['per_host']] == sorted(h['host_id'] for h in hosts), 'CFF_PROJECTION_MISMATCH')
            cff_raw = cff._v3_wrapper_bytes(projection); _private_data(projection, 'CFF'); add('cff', cff_raw)
            rule_version = s['producer_rules_version']; rules_sha = m._digest(rules_raw)
        else:
            missing = [dict(path=FILES[k][0], reason_code='BATCH_MANIFEST_UNAVAILABLE' if k == 'batch'
                            else 'REQUIRED_ARTIFACT_MISSING') for k in ('batch', 'assessed', 'rules', 'cff')]
        for req in s['requirements']['details']:
            key = (req['host_id'], req['slot'])
            if key not in present:
                m.require(next(h for h in hosts if h['host_id'] == key[0])['host_state'] != 'COMPLETE', 'REQUIRED_DETAIL_MISSING')
                missing.append(dict(path='/'.join(_slot('detail', *key)[0]), reason_code='REQUIRED_DETAIL_MISSING'))
        counts = Counter(h['host_state'] for h in hosts)
        manifest = {k: s[k] for k in ('run_id', 'run_kind', 'source', 'started_at', 'reserved_at', 'limits', 'profile',
            'flags', 'requirements', 'evidence_schema_version', 'batch_contract', 'capacity_profile', *m._PRODUCER_SCOPE_FIELDS.split())}
        manifest.update(manifest_version=VERSION, publication_state='PUBLISHED', run_state=state,
            reason_code=reason, recovery=recovery, finished_at=finished, recorded_at=recorded,
            recovered_at=recorded if recovery else None, expected_host_ids=sorted(h['host_id'] for h in hosts),
            hosts=rows, counts={'total': len(hosts), **{k: counts[k] for k in m.HOST_STATES}},
            rule_version=rule_version, rules_sha256=rules_sha, batch_rc=batch_rc,
            batch_canonical_sha256=batch_hash, batch_missing_reason='BATCH_MANIFEST_UNAVAILABLE' if recovery else None,
            artifacts=sorted(entries, key=lambda x: x['path']), missing_artifacts=sorted(missing, key=lambda x: x['path']))
        m._json_bytes(manifest, MANIFEST_BYTES)
        return m.PublishedRun(manifest, document, assessed, payloads)

    def _prepare(self, result):
        # The RunStore's no-replace transaction: stage complete core, then
        # durable immutable plan, then move slots, then publish last marker.
        self._check(mutable=False)
        m.require(not m._exists(self._fd, 'prepared.json') and
                  not any(m._exists(self._fd, name) for name, _ in FILES.values()) and
                  not m._exists(self._fd, 'details'), 'UNPREPARED_CORE_ARTIFACT')
        if self._recovery_guard is not None:
            _check_index(self._fd, self._device, {}, None, final_only=False)
        stages = [n for n in m._entries(self._fd, m.MAX_SLOTS) if n.startswith('.stage-')]
        m.require(len(stages) < m.MAX_STAGES, 'RECOVERY_STAGE_LIMIT')
        self._guard_recovery()
        stage = '.stage-' + secrets.token_hex(16); fd = m._mkdir(self._fd, stage, self._device)
        try:
            def guard_stage():
                self._guard_recovery()
                _recheck_directory(self._fd, stage, fd, self._device)
            prepared = dict(prepared_version=VERSION, stage=stage, manifest=result.manifest)
            sealed = m._seal(prepared, MANIFEST_BYTES)
            for entry in result.manifest['artifacts']:
                parts, _ = _slot(entry['kind'], entry['host_id'], entry['slot'])
                if self._recovery_guard is not None:
                    guard_stage()
                with m._directory(fd, parts[:-1], self._device, create=True) as d:
                    self._persist(d, parts[-1], result.artifacts[entry['path']], guard=guard_stage)
            self._persist(self._fd, 'prepared.json', sealed, guard=guard_stage)
            return self._resume(verified=result)
        finally:
            os.close(fd)

    def _plan(self):
        p = m._unseal(m._read(self._fd, 'prepared.json', self._device, MANIFEST_BYTES), MANIFEST_BYTES)
        m._keys(p, 'prepared_version stage manifest')
        m.require(p['prepared_version'] == VERSION and m._match(p['stage'], r'\.stage-[0-9a-f]{32}'), 'INVALID_STAGE')
        _manifest(p['manifest'], self._j)
        return p

    def _replay(self, manifest, stage, verified=None):
        entries = _manifest(manifest, self._j)
        _check_index(self._fd, self._device, entries, stage, final_only=stage is None)
        def read(entry):
            parts, cap = _slot(entry['kind'], entry['host_id'], entry['slot'])
            final = m._has_at(self._fd, parts, self._device)
            staged = stage is not None and m._has_at(stage, parts, self._device)
            m.require(final != staged, 'INCOMPLETE_PREPARED_ARTIFACT')
            with m._directory(self._fd if final else stage, parts[:-1], self._device) as fd:
                raw = m._read(fd, parts[-1], self._device, cap, entry['size'])
            m.require(m._digest(raw) == entry['sha256'], 'ARTIFACT_HASH'); return raw
        if verified is None:
            batch = entries.get('batch_manifest.json')
            verified = self._derive(self._checkpoints(), recovery=manifest['recovery'], recorded=manifest['recorded_at'],
                finished=manifest['finished_at'], batch_raw=None if batch is None else read(batch), batch_rc=manifest['batch_rc'])
        m.require(m._same(verified.manifest, manifest), 'MANIFEST_MISMATCH')
        for path, entry in entries.items():
            m.require(read(entry) == verified.artifacts[path], 'ARTIFACT_CHANGED')
        return verified

    @_operation
    def _resume(self, verified=None):
        self._check(mutable=False)
        p = self._plan(); manifest = p['manifest']
        with m._directory(self._fd, (p['stage'],), self._device) as stage:
            def guard_stage():
                self._guard_recovery()
                _recheck_directory(self._fd, p['stage'], stage, self._device)
            result = self._replay(manifest, stage, verified)
            for entry in manifest['artifacts']:
                parts, _ = _slot(entry['kind'], entry['host_id'], entry['slot'])
                if self._recovery_guard is not None:
                    guard_stage()
                with m._directory(stage, parts[:-1], self._device) as src:
                    with m._directory(self._fd, parts[:-1], self._device, create=True) as dest:
                        if not m._has_at(self._fd, parts, self._device):
                            if self._recovery_guard is not None:
                                guard_stage()
                            m._rename_noreplace(src, parts[-1], dest, parts[-1])
                        m._sync(dest); m._sync(src)
            marker = m._json_bytes(manifest, MANIFEST_BYTES)
            if self._recovery_guard is None:
                self._replay(manifest, None, result)
                m._write(self._fd, 'run_manifest.json', marker, self._device)
            else:
                def before_marker():
                    # The marker temp is durable but not yet published. Verify
                    # frozen inputs and the exact final core again, without
                    # deriving another assessment/CFF or rewriting a terminal.
                    guard_stage()
                    self._check(mutable=False)
                    m.require(m._same(self._plan(), p), 'MANIFEST_MISMATCH')
                    self._checkpoints()
                    self._replay(manifest, None, result)
                    _check_published_stage(self._fd, self._device, manifest, self._j, stage)
                    guard_stage()
                guard_stage()
                m._write(self._fd, 'run_manifest.json', marker, self._device,
                         before_publish=before_marker)
            return result


def _manifest(manifest, j):
    m._keys(manifest, MANIFEST_KEYS); s = j['scope']
    m.require(manifest['manifest_version'] == VERSION and manifest['publication_state'] == 'PUBLISHED', 'UNSUPPORTED_MANIFEST_VERSION')
    for k in SCOPE_KEYS.split():
        if k != 'hosts': m.require(m._same(manifest[k], s[k]), 'FROZEN_SCOPE_MISMATCH')
    m._bool(manifest['recovery']); _order(s['reserved_at'], manifest['recorded_at'])
    if manifest['recovery']:
        m.require(manifest['recovered_at'] == manifest['recorded_at'] and manifest['finished_at'] is None, 'RECOVERY_STATE')
    else:
        m.require(manifest['recovered_at'] is None and manifest['finished_at'] is not None and
                  j['blocked_capacity_stage'] is None, 'RECOVERY_STATE')
        _order(s['started_at'], manifest['finished_at'], manifest['recorded_at'])
    m.require(type(manifest['hosts']) is list and len(manifest['hosts']) == len(s['hosts']), 'HOST_MANIFEST')
    expected = {h['host_id']: h for h in s['hosts']}; seen = set()
    for h in manifest['hosts']:
        m._keys(h, HOST_KEYS); hid = m._id(h['host_id'])
        m.require(hid in expected and hid not in seen and m._host_identity(h) == m._host_identity(expected[hid]), 'HOST_MANIFEST'); seen.add(hid)
        m.require(h['dispatch_intent_at'] == j['intent_times'].get(hid), 'FROZEN_SCOPE_MISMATCH')
        if h['checkpoint_recorded_at'] is not None: _order(h['dispatch_intent_at'] or s['reserved_at'], h['checkpoint_recorded_at'], manifest['recorded_at'])
    m.require(manifest['expected_host_ids'] == sorted(seen), 'HOST_MANIFEST')
    m.require(type(manifest['artifacts']) is list and 0 < len(manifest['artifacts']) <= 66, 'SLOT_LIMIT')
    entries = {}; total = 0
    for row in manifest['artifacts']:
        m._keys(row, m.ENTRY_KEYS); parts, cap = _slot(row['kind'], row['host_id'], row['slot'])
        path = '/'.join(parts)
        m.require(row['path'] == path and path not in entries, 'INVALID_SLOT_PATH')
        if row['kind'] == 'detail': m.require(row['host_id'] in expected, 'FOREIGN_HOST')
        m._int(row['size'], 1, cap); m._bool(row['required']); m.require(m._match(row['sha256'], m.HEX), 'ARTIFACT_HASH')
        total += row['size']; _budget(total, CORE_BYTES, 'CORE'); entries[path] = row
    return entries


def _check_index(fd, device, entries, stage, *, final_only):
    # Strict actual artifact inventory. Orphan stages/temporary names from
    # interrupted writes remain private and bounded, never become indexed.
    core = {p for p in entries if '/' not in p}; details = {}
    for p, e in entries.items():
        if e['kind'] == 'detail': details.setdefault(e['host_id'], set()).add(e['slot'] + '.json')
    def check(d, staged):
        names = set(m._entries(d, m.MAX_SLOTS))
        if not staged:
            stage_names = {n for n in names if re.fullmatch(r'\.stage-[0-9a-f]{32}', n)}
            m.require(len(stage_names) <= m.MAX_STAGES, 'RECOVERY_STAGE_LIMIT')
            temps = {n for n in names if re.fullmatch(r'\.tmp-[0-9a-f]{32}', n)}
            # Orphan stages remain bounded and are not traversed or adopted.
            # Their fixed names do not excuse unsafe directory/file metadata.
            for name in stage_names:
                info = os.stat(name, dir_fd=d, follow_symlinks=False)
                m.require(stat.S_ISDIR(info.st_mode) and info.st_dev == device and
                          info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
                          'UNSAFE_DIRECTORY')
            for name in temps:
                m._check_file_stat(os.stat(name, dir_fd=d, follow_symlinks=False), device)
            names -= stage_names | temps
            names -= {'journal.json', v2.FROZEN_FILE, 'prepared.json', 'run_manifest.json', '.writer.lock', 'checkpoints'}
        m.require(names <= core | ({'details'} if details else set()), 'UNINDEXED_ARTIFACT')
        if 'details' in names:
            with m._directory(d, ('details',), device) as dd:
                hosts = set(m._entries(dd, 10)); m.require(hosts <= set(details), 'UNINDEXED_ARTIFACT')
                for hid in hosts:
                    with m._directory(dd, (hid,), device) as hd:
                        actual = set(m._entries(hd, len(SLOTS))); m.require(actual <= details[hid], 'UNINDEXED_ARTIFACT')
                        if final_only and not staged: m.require(actual == details[hid], 'MISSING_ARTIFACT')
                if final_only and not staged: m.require(hosts == set(details), 'MISSING_ARTIFACT')
        elif final_only and not staged:
            m.require(not details, 'MISSING_ARTIFACT')
    check(fd, False)
    if stage is not None: check(stage, True)


def _recheck_directory(parent, name, fd, device):
    actual = m._check_dir(fd, device)
    try:
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        raise m.StoreError('RUN_IDENTITY_CHANGED') from None
    m.require(stat.S_ISDIR(named.st_mode) and actual.st_nlink > 0 and
              (named.st_dev, named.st_ino) == (actual.st_dev, actual.st_ino),
              'RUN_IDENTITY_CHANGED')


def _check_published_stage(fd, device, manifest, journal, stage):
    _check_index(fd, device, _manifest(manifest, journal), stage, final_only=True)
    # Current stage cannot retain any indexed core file after publication.
    # Empty generated directories may remain.
    for entry in manifest['artifacts']:
        parts, _ = _slot(entry['kind'], entry['host_id'], entry['slot'])
        m.require(not m._has_at(stage, parts, device), 'DUPLICATE_ARTIFACT')


def open_run(store, run_id):
    with store._locked_v3_run(run_id, shared=True) as (fd, lock, recheck):
        m.require(m._exists(fd, 'run_manifest.json'), 'INCOMPLETE_RUN')
        try:
            j = _read_journal(fd, store._device, run_id)
            raw = m._read(fd, 'run_manifest.json', store._device, MANIFEST_BYTES); manifest = m._loads(raw, MANIFEST_BYTES)
            m.require(m._json_bytes(manifest, MANIFEST_BYTES) == raw, 'NONCANONICAL_MANIFEST')
            with Writer(os.dup(fd), os.dup(lock), store._device, j) as reader:
                plan = reader._plan()
                m.require(m._same(plan['manifest'], manifest), 'MANIFEST_MISMATCH')
                with m._directory(fd, (plan['stage'],), store._device) as stage:
                    _check_published_stage(fd, store._device, manifest, j, stage)
                    result = reader._replay(manifest, None)
                    _recheck_directory(fd, plan['stage'], stage, store._device)
                    _check_published_stage(fd, store._device, manifest, j, stage)
                    m.require(m._same(_read_journal(fd, store._device, run_id), j) and
                              m._same(reader._plan(), plan) and
                              m._read(fd, 'run_manifest.json', store._device, MANIFEST_BYTES) == raw,
                              'MANIFEST_MISMATCH')
                    recheck()
                    return result
        except evidence.V3CapacityError as exc:
            raise CapacityError(exc.stage) from None
        except FileNotFoundError:
            raise m.StoreError('MISSING_ARTIFACT') from None
        except (bridge.BridgeError, KeyError, TypeError, IndexError, OverflowError, RecursionError):
            raise m.StoreError('INVALID_STORE_DATA') from None


def recover(store, run_id):
    with store._locked_v3_run(run_id, shared=False) as (fd, lock, recheck):
        m.require(not m._exists(fd, 'run_manifest.json'), 'ALREADY_PUBLISHED')
        try:
            j = _read_journal(fd, store._device, run_id)
            with Writer(os.dup(fd), os.dup(lock), store._device, j, recovery_guard=recheck) as writer:
                return writer._resume() if m._exists(fd, 'prepared.json') else writer._recover_unprepared()
        except FileNotFoundError:
            raise m.StoreError('INCOMPLETE_RUN') from None
        except (bridge.BridgeError, KeyError, TypeError, IndexError, OverflowError, RecursionError):
            raise m.StoreError('INVALID_STORE_DATA') from None


def manifest_schema_v3():
    """Closed V3 wire shape; runtime checks all cross-record/byte semantics."""
    schema = m.manifest_schema(); schema['$id'] = 'urn:pqc:run-manifest:1.1.0'
    schema['title'] = 'PQC private five-producer V3 Run Store manifest'
    schema.pop('allOf')
    fields, defs = schema['properties'], schema['$defs']
    def const(v): return {'const': v}
    def nullable(v): return {'anyOf': [v, {'type': 'null'}]}
    def ref(v): return {'$ref': '#/$defs/' + v}
    def add(obj, **values): obj['properties'].update(values); obj['required'].extend(values)
    timestamp = fields['recorded_at']; sha = defs['artifact']['properties']['sha256']; version = defs['artifact']['properties']['format_version']
    fields.update(manifest_version=const(VERSION), run_kind=const('SYNTHETIC'), source=const(dict(v2.SOURCE)),
                  evidence_schema_version=const('1.1.0'), batch_contract=const(CONTRACT), started_at=timestamp,
                  limits=ref('limits'), profile={'enum': ['baseline', 'extended']}, flags=fields['flags']['anyOf'][0])
    add(schema, capacity_profile=const(CAPACITY_PROFILE), reserved_at=timestamp, recovered_at=nullable(timestamp),
        producer_rules_sha256=sha, producer_rules_version=version)
    for key in ('hosts', 'expected_host_ids'): fields[key]['maxItems'] = 10
    for value in defs['collector_flags']['properties']:
        if value in ('nginx_certs', 'tls_services'): defs['collector_flags']['properties'][value] = const(False)
    counts = fields['counts']['properties']
    for k in counts: counts[k] = {'type': 'integer', 'minimum': 0, 'maximum': 10}
    host = defs['host']; host['properties'].update(identity_scope=const('RUN_SCOPED'), inventory_authority_id=const(None),
        target_id=host['properties']['target_id']['anyOf'][0], identity_key=host['properties']['identity_key']['anyOf'][0],
        dispatch_intent={'type': 'boolean'}, attempt_status={'enum': ['ATTEMPTED', 'NOT_ATTEMPTED', 'UNKNOWN']}, terminal=nullable(ref('v3_terminal')))
    add(host, dispatch_intent_at=nullable(timestamp), checkpoint_recorded_at=nullable(timestamp))
    # Extend the existing terminal schema with the real long flag names and
    # producer-specific caps, rather than changing the V1 schema helper.
    from copy import deepcopy
    outcome = deepcopy(defs['native_collector_outcome']); outcome['properties']['collection_ids']['maxItems'] = 261
    caps = {bridge.PACKAGES: 2, bridge.SSL: 261, bridge.POLICY_FLAG: 9, bridge.SSHD: 8,
            bridge.KEYS: 1, bridge.CERT_FLAG: 3, bridge.NGINX: 0, bridge.TLS: 0}
    outcome['allOf'] = [{'if': {'properties': {'collector_id': const(flag)}},
                        'then': {'properties': {'collection_ids': {'maxItems': cap}}}} for flag, cap in caps.items()]
    platform_outcome = deepcopy(defs['native_collector_outcome']); platform_outcome['properties']['collector_id'] = const(bridge.PLATFORM)
    platform_outcome['properties']['collection_ids']['maxItems'] = 10
    terminal = deepcopy(defs['native_terminal']); terminal['properties']['collectors']['items'] = ref('v3_outcome')
    add(terminal, platform=ref('v3_platform_outcome'))
    defs.update(v3_outcome=outcome, v3_platform_outcome=platform_outcome, v3_terminal=terminal)
    defs['detail_requirement']['properties']['slot'] = {'enum': list(SLOTS)}
    req = defs['requirements']['properties']; req.update(assessment=const(True), cff=const(True)); req['details']['maxItems'] = 60
    path = {'type': 'string', 'pattern': '^(?:' + '|'.join(re.escape(n) for k, (n, _) in FILES.items() if k != 'legacy') +
            r'|details/h-[0-9a-f]{64}/(?:' + '|'.join(SLOTS) + r')\.json)$(?![\s\S])', 'maxLength': 150}
    artifact = defs['artifact']; artifact['properties'].update(kind={'enum': [k for k in FILES if k != 'legacy'] + ['detail']},
        slot=nullable({'enum': list(SLOTS)}), path=path, required=const(True))
    artifact['allOf'] = [{'if': {'properties': {'kind': const(k)}}, 'then': {'properties': {
        'size': {'maximum': cap}, 'host_id': const(None), 'slot': const(None), 'path': const(name)}}}
        for k, (name, cap) in FILES.items() if k != 'legacy']
    artifact['allOf'].append({'if': {'properties': {'kind': const('detail')}}, 'then': {'properties': {
        'host_id': defs['host']['properties']['host_id'], 'slot': {'enum': list(SLOTS)}}}})
    artifact['allOf'].extend({'if': {'properties': {'slot': const(slot)}}, 'then': {'properties': {'size': {'maximum': cap}}}}
                             for slot, cap in SLOTS.items())
    defs['missing']['properties']['path'] = path; fields['artifacts']['maxItems'] = 66; fields['missing_artifacts']['maxItems'] = 64
    schema['allOf'] = [{'if': {'properties': {'recovery': const(False)}}, 'then': {'properties': {
        'finished_at': timestamp, 'recovered_at': const(None), 'rule_version': version, 'rules_sha256': sha,
        'batch_rc': {'type': 'integer', 'enum': [0, 5, 6, 7]}, 'batch_canonical_sha256': sha,
        'batch_missing_reason': const(None), 'hosts': {'items': {'properties': {'terminal': ref('v3_terminal'),
            'checkpoint_recorded_at': timestamp, 'attempted': {'type': 'boolean'}}}}}}, 'else': {'properties': {
        'finished_at': const(None), 'recovered_at': timestamp, 'rule_version': const(None), 'rules_sha256': const(None),
        'batch_rc': const(None), 'batch_canonical_sha256': const(None), 'batch_missing_reason': const('BATCH_MANIFEST_UNAVAILABLE')}}}]
    return schema
