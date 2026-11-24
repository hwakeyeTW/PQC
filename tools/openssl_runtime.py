"""Issue #15 internal OpenSSL adapter. No acquisition, dispatch or I/O here."""
import hashlib
import json
import re
from copy import deepcopy

from tools import assessment, evidence

PRODUCER = 'pqc-openssl-runtime'
VERSION = '1.0.0'
PACKAGES = ('rpm-openssl', 'rpm-openssl-libs')
CONTEXTS = {'kem': 'KEM_CAPABILITY', 'signature': 'SIGNATURE', 'tls-groups': 'TLS_KEX'}
SLOTS = (*PACKAGES, 'version', 'providers', *CONTEXTS)
FLAGS = ('pqc_collect_packages', 'pqc_collect_openssl')
TOKEN = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}\Z', re.ASCII)
VER = re.compile(r'[0-9][A-Za-z0-9_.+-]{0,63}\Z', re.ASCII)
ARCH = re.compile(r'[a-z0-9][a-z0-9_-]{0,63}\Z', re.ASCII)
OID = re.compile(r'[0-9]+(?:\.[0-9]+)+\Z', re.ASCII)
STATES = {
    'COLLECTED': {'OK', 'PACKAGE_ABSENT'},
    'PARTIAL': {'FORMAT_GAP'},
    'UNKNOWN': {'TOOL_UNAVAILABLE', 'UNSUPPORTED_FLAG', 'NO_OUTPUT', 'UNRECOGNIZED_OUTPUT', 'PLATFORM_UNRESOLVED'},
    'ERROR': {'OUTPUT_LIMIT', 'ROW_LIMIT', 'INCOMPLETE_OUTPUT', 'INVALID_ENCODING', 'COMMAND_FAILED',
              'TIMEOUT', 'OUTER_DEADLINE', 'HELPER_ERROR', 'CLEANUP_UNCONFIRMED', 'EXECUTION_ERROR'},
    'PERMISSION_DENIED': {'PERMISSION_DENIED'},
    'NOT_SCANNED': {'DISABLED_BY_USER'},
    'NOT_APPLICABLE': {'PLATFORM_OUT_OF_SCOPE'},
}


def require(condition):
    if not condition:
        raise ValueError('INVALID_OPENSSL_SNAPSHOT')


def shape(obj, keys):
    return type(obj) is dict and obj.keys() == set(keys)


def token(value, pattern=TOKEN):
    return type(value) is str and pattern.fullmatch(value) is not None


def serial(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'))


def key(prefix, value):
    return prefix + '-' + hashlib.sha256(serial(value).encode('ascii')).hexdigest()


def validate_snapshot(snapshot):
    """Reject unbounded, contradictory, extra-field or duplicate projections."""
    require(shape(snapshot, ('flags', 'platform_status', 'slots')))
    flags, status, slots = snapshot['flags'], snapshot['platform_status'], snapshot['slots']
    require(shape(flags, FLAGS) and all(type(v) is bool for v in flags.values()))
    require(type(status) is str and status in ('UNVERIFIED', 'UNKNOWN', 'OUT_OF_SCOPE'))
    require(shape(slots, SLOTS))
    for slot in SLOTS:
        row = slots[slot]
        require(shape(row, ('state', 'reason', 'rc', 'rows')))
        state, reason, rc, rows = (row[k] for k in ('state', 'reason', 'rc', 'rows'))
        require(type(state) is str and state in STATES and type(reason) is str and reason in STATES[state])
        require(rc is None or (type(rc) is int and -255 <= rc <= 255))
        enabled = flags[FLAGS[0 if slot in PACKAGES else 1]]
        if not enabled:
            require((state, reason, rc) == ('NOT_SCANNED', 'DISABLED_BY_USER', None))
        elif status == 'OUT_OF_SCOPE':
            require((state, reason, rc) == ('NOT_APPLICABLE', 'PLATFORM_OUT_OF_SCOPE', None))
        elif status == 'UNKNOWN':
            require((state, reason, rc) == ('UNKNOWN', 'PLATFORM_UNRESOLVED', None))
        else:
            require(state not in ('NOT_SCANNED', 'NOT_APPLICABLE') and reason != 'PLATFORM_UNRESOLVED')
        good = state in ('COLLECTED', 'PARTIAL')
        require(type(rows) is list and len(rows) <= (32 if slot in PACKAGES else 256))
        require(bool(rows) == good)
        if good:
            require(rc == (1 if reason == 'PACKAGE_ABSENT' else 0))
        if reason == 'PACKAGE_ABSENT':
            require(slot in PACKAGES and rows == [[slot[4:], None, None, None]])
        if reason in ('TOOL_UNAVAILABLE', 'OUTER_DEADLINE', 'HELPER_ERROR'):
            require(rc is None)
        if reason in ('NO_OUTPUT', 'UNRECOGNIZED_OUTPUT'):
            require(rc == 0)
        names = set()
        for item in rows:
            require(type(item) is list)
            if slot in PACKAGES:
                require(len(item) == 4 and item[0] == slot[4:])
                if reason != 'PACKAGE_ABSENT':
                    require(token(item[1]) and token(item[2]) and token(item[3], ARCH))
            elif slot == 'version':
                require(len(rows) == 1 and len(item) == 2 and state == 'COLLECTED')
                require(token(item[0], VER) and (item[1] is None or token(item[1], VER)))
            elif slot == 'providers':
                require(len(item) == 3 and token(item[0]) and item[0] not in names)
                require(item[1] is None or token(item[1], VER))
                require(item[2] is None or type(item[2]) is str and item[2] in ('active', 'inactive'))
                require(state == 'PARTIAL' or None not in item)
                names.add(item[0])
            else:
                require(len(item) == 2 and (item[0] is None if slot == 'tls-groups' else token(item[0])))
                require(type(item[1]) is list and 1 <= len(item[1]) <= (1 if slot == 'tls-groups' else 32))
                require(all(token(x) for x in item[1]) and len(set(item[1])) == len(item[1]))
        require(len({serial(x) for x in rows}) == len(rows))
        # A conservative ceiling for the typed projection (JSON adds framing).
        require(sum(len(serial(x)) for x in rows) <= 32768)


def classify_rows(slot, rows, rules):
    """Keep provider/context distinct; never resolve contradictory aliases by order."""
    candidates = []
    alias_ids = {}
    for provider, aliases in rows:
        names = sorted(x for x in aliases if not OID.fullmatch(x))
        algs = [assessment.classify_algorithm(x, CONTEXTS[slot], rules) for x in names]
        ids = {a['algorithm_id'] for a in algs if a['algorithm_id'] is not None}
        for name in names:
            alias_ids.setdefault((provider, name.lower()), set()).update(ids)
        candidates.append((provider, names, algs, ids))
    selected = {}
    gap = False
    for provider, names, algs, ids in candidates:
        all_ids = set(ids)
        for name in names:
            all_ids.update(alias_ids[provider, name.lower()])
        if not names or len(all_ids) > 1:
            gap = True
            continue
        if not ids and all_ids:
            # An unclassified alias overlaps another implementation's known name.
            # Do not promote it by inference.
            gap = True
            continue
        known = [a for a in algs if a['algorithm_id'] is not None]
        alg = (known or algs)[0]
        identity = alg['algorithm_id'] or sorted(x.lower() for x in names)
        capability = key('openssl-' + slot, [slot, provider, identity])
        value = (alg, provider, names)
        if capability not in selected or serial(value) < serial(selected[capability]):
            selected[capability] = value
    return selected, gap


def normalize_openssl(document, host_id, snapshot, source, observed_at, rules):
    """Append normalized evidence to existing 1.1.0 document; return (copy, diagnostics).

    The trusted caller supplies host/run identity, source, time, flags and OL9
    eligibility. No I/O, schema migration, asset, claim or readiness synthesis.
    """
    evidence.validate_document(document)
    require(document['schema_version'] == '1.1.0')
    require(any(h['host_id'] == host_id for h in document['hosts']))
    require(type(source) is dict and source.get('producer_id') == PRODUCER and
            source.get('producer_version') == VERSION and source.get('source_kind') != 'LEGACY_IMPORT')
    require(type(observed_at) is str)
    assessment.validate_rules(rules)
    validate_snapshot(snapshot)
    doc = deepcopy(document)
    diagnostics = []
    rid = doc['run']['run_id']

    def emit(scope, slot, state, reason, rc, records, observed=None):
        cid = evidence.collection_id(rid, host_id, PRODUCER, scope)
        if state == 'NOT_APPLICABLE':
            records.append(('summary', 'COLLECTION_SUMMARY', {'scope': scope, 'attempted': False,
                            'coverage': 'UNKNOWN', 'observation_count': None, 'applicable': False}, None))
        elif state in ('COLLECTED', 'PARTIAL'):
            count = len(records) if observed is None else observed
            records.append(('summary', 'COLLECTION_SUMMARY', {'scope': scope, 'attempted': True,
                            'coverage': 'COMPLETE' if state == 'COLLECTED' else 'PARTIAL',
                            'observation_count': count, 'applicable': True}, None))
        eids = []
        for obs, kind, data, alg in records:
            eid = evidence.evidence_id(rid, host_id, cid, obs)
            eids.append(eid)
            doc['evidence'].append(dict(evidence_id=eid, host_id=host_id, collection_id=cid,
                asset_id=None, observation_key=obs, evidence_kind=kind, algorithm=alg,
                source=deepcopy(source), observed_at=observed_at, data=data))
        doc['collections'].append(dict(collection_id=cid, host_id=host_id, collector_id=PRODUCER,
            collector_version=VERSION, scope_key=scope, collection_state=state, reason_code=reason,
            source=deepcopy(source), observed_at=observed_at, evidence_ids=eids))
        diag = dict(collection_id=cid, slot=slot, state=state, reason=reason, rc=rc)
        diagnostics.append(diag)
        return diag

    for slot in SLOTS:
        item = snapshot['slots'][slot]
        state, reason, rc, rows = (item[k] for k in ('state', 'reason', 'rc', 'rows'))
        scope = 'openssl-' + slot
        records = []
        detail = []
        if slot in PACKAGES:
            for name, ver, rel, arch in sorted(rows, key=serial):
                data = dict(name=name, version=ver, release=rel, architecture=arch, present=ver is not None)
                records.append((key('rpm', [name, ver, rel, arch]), 'PACKAGE_INVENTORY', data, None))
        elif slot == 'version' and rows:
            ver, lib = rows[0]
            records.append(('cli-version', 'ASSET_METADATA', dict(name='openssl-cli', version=ver), None))
            if lib is not None:
                records.append(('library-version', 'ASSET_METADATA', dict(name='openssl-linked-library', version=lib), None))
        elif slot in CONTEXTS and rows:
            selected, gap = classify_rows(slot, rows, rules)
            if gap:
                state, reason = ('PARTIAL' if selected else 'UNKNOWN'), 'ALIAS_UNRESOLVED'
            for capability, (alg, provider, aliases) in sorted(selected.items()):
                records.append((capability, 'RUNTIME_CAPABILITY', dict(capability=capability, supported=True), alg))
                detail.append(dict(observation_key=capability, provider=provider, aliases=aliases))
        diag = emit(scope, slot, state, reason, rc, records,
                    observed=len(rows) if slot == 'providers' else None)
        if detail:
            diag['observations'] = detail
        if slot == 'providers':
            for name, ver, status in sorted(rows, key=serial):
                provider_scope = key('openssl-provider', name)
                provider_records = [('metadata', 'ASSET_METADATA', dict(name=name, version=ver), None)]
                if status is not None:
                    cap = key('openssl-provider-loaded', name)
                    provider_records.append((cap, 'RUNTIME_CAPABILITY', dict(capability=cap,
                                             supported=True if status == 'active' else None), None))
                provider_state = 'COLLECTED' if ver is not None and status is not None else 'PARTIAL'
                provider_diag = emit(provider_scope, slot, provider_state,
                    'OK' if provider_state == 'COLLECTED' else 'PROVIDER_METADATA_GAP', rc, provider_records)
                provider_diag['provider'] = name
                provider_diag['status'] = status
    evidence.validate_document(doc)
    return doc, diagnostics
