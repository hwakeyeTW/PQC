"""Pure SSH posture adapter and paired Evidence 1.1.0 detail validation.

The caller owns authorization, host identity, trusted inputs, timestamps and
transport. Shared typed effective results support synthetic G/T development;
actual T positives remain disabled until native safety/equivalence is proven.
No command, file read, dispatch or generated verdict here.
"""
import copy
import hashlib
import json
import re

from tools import assessment, evidence as ev

PRODUCER = 'pqc-ssh-posture'
VERSION = '1.0.0'
DETAIL_FORMAT = 'pqc-ssh-posture-details'
FLAGS = ('pqc_collect_sshd', 'pqc_collect_ssh_host_keys')
CLIENTS = ('client-kex', 'client-cipher', 'client-key', 'client-sig', 'client-mac')
CONTEXTS = {'client-kex': 'SSH_KEX', 'client-cipher': 'SSH_CIPHER', 'client-sig': 'SIGNATURE'}
BASE_SLOTS = (*CLIENTS, 'config', 'keys')
TOKEN = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.+@-]{0,127}\Z', re.ASCII)
PATTERN = re.compile(r'[A-Za-z0-9*?][A-Za-z0-9_.+@*?-]{0,127}\Z', re.ASCII)
HEX = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
SETTINGS = {'kexalgorithms', 'ciphers', 'macs', 'hostkeyalgorithms', 'pubkeyacceptedalgorithms',
            'pubkeyacceptedkeytypes', 'hostbasedacceptedalgorithms', 'hostbasedacceptedkeytypes',
            'casignaturealgorithms', 'gssapikexalgorithms'}
# Paired with the code-only gate in the remote helper; neither is caller-controlled.
NATIVE_T_QUALIFIED = False
EFFECTIVE_REQUIRED = {'kexalgorithms', 'ciphers', 'macs', 'hostkeyalgorithms',
                      'pubkeyacceptedalgorithms', 'hostbasedacceptedalgorithms', 'casignaturealgorithms'}
EFFECTIVE_SETTINGS = EFFECTIVE_REQUIRED | {'gssapikexalgorithms'}
EFFECTIVE_CONTEXTS = {'kexalgorithms': 'SSH_KEX', 'ciphers': 'SSH_CIPHER',
                      'casignaturealgorithms': 'SIGNATURE'}
CONFIG_GAPS = {'SOURCE_MISSING', 'SOURCE_PERMISSION', 'SOURCE_UNSAFE', 'FORMAT_GAP',
               'INCLUDE_REJECTED', 'INCLUDE_REPEATED', 'INCLUDE_EMPTY', 'MATCH_UNRESOLVED',
               'NATIVE_DEPENDENCY', 'HOSTKEY_PATH_REJECTED'}
KEY_GAPS = {'SOURCE_MISSING', 'SOURCE_PERMISSION', 'SOURCE_UNSAFE', 'KEY_INVALID', 'KEY_TYPE_UNKNOWN'}
TOOL_REASONS = {'TOOL_UNAVAILABLE', 'TOOL_UNSAFE_PATH', 'TOOL_NOT_EXECUTABLE'}
COMMON_FAILURES = TOOL_REASONS | {'PERMISSION_DENIED', 'EXECUTION_ERROR', 'OUTER_DEADLINE', 'HELPER_ERROR'}
CLIENT_FAILURES = COMMON_FAILURES | {'UNSUPPORTED_QUERY', 'NO_OUTPUT', 'UNRECOGNIZED_OUTPUT',
    'COMMAND_FAILED', 'OUTPUT_LIMIT', 'ROW_LIMIT', 'TIMEOUT', 'CLEANUP_FAILED', 'INCOMPLETE_OUTPUT', 'INVALID_ENCODING'}
NATIVE_FAILURES = COMMON_FAILURES | {'NATIVE_SAFETY_UNPROVEN', 'NATIVE_SOURCE_REJECTED',
    'NATIVE_CONTEXT_REJECTED', 'SOURCE_PERMISSION', 'NO_OUTPUT', 'UNRECOGNIZED_OUTPUT',
    'COMMAND_FAILED', 'OUTPUT_LIMIT', 'ROW_LIMIT', 'TIMEOUT', 'CLEANUP_FAILED', 'INCOMPLETE_OUTPUT',
    'INVALID_ENCODING', 'INPUT_LIMIT', 'SOURCE_LIMIT', 'DIRECTORY_LIMIT', 'SOURCE_DRIFT'}
FILE_FAILURES = COMMON_FAILURES | {'SOURCE_PERMISSION', 'SOURCE_MISSING', 'SOURCE_UNSAFE', 'INPUT_LIMIT',
    'SOURCE_LIMIT', 'DIRECTORY_LIMIT', 'SOURCE_DRIFT', 'ROW_LIMIT', 'TIMEOUT', 'OUTPUT_LIMIT'}
REASONS = {
    'COLLECTED': {'OK'}, 'PARTIAL': {'FORMAT_GAP', 'CONFIG_GAP', 'KEY_GAP'},
    'UNKNOWN': TOOL_REASONS | {'PLATFORM_UNRESOLVED', 'NATIVE_SAFETY_UNPROVEN', 'KEY_FLAG_REQUIRED',
        'UNSUPPORTED_QUERY', 'NO_OUTPUT', 'UNRECOGNIZED_OUTPUT', 'SOURCE_MISSING', 'SOURCE_UNSAFE', 'KEY_INVALID',
        'NATIVE_SOURCE_REJECTED', 'NATIVE_CONTEXT_REJECTED'},
    'ERROR': {'COMMAND_FAILED', 'OUTPUT_LIMIT', 'ROW_LIMIT', 'TIMEOUT', 'CLEANUP_FAILED', 'EXECUTION_ERROR',
        'INCOMPLETE_OUTPUT', 'INVALID_ENCODING', 'INPUT_LIMIT', 'SOURCE_LIMIT', 'DIRECTORY_LIMIT',
        'SOURCE_DRIFT', 'OUTER_DEADLINE', 'HELPER_ERROR'},
    'PERMISSION_DENIED': {'PERMISSION_DENIED', 'SOURCE_PERMISSION'},
    'NOT_SCANNED': {'DISABLED_BY_USER'}, 'NOT_APPLICABLE': {'PLATFORM_OUT_OF_SCOPE'},
}


def require(ok, code='SSH_INPUT'):
    if not ok:
        raise ev.EvidenceError(code, '$ssh')


def mapping(value, keys):
    require(type(value) is dict and value.keys() == set(keys))
    return value


def matches(value, pattern):
    return type(value) is str and bool(pattern.fullmatch(value))


def integer(value, lo, hi):
    return type(value) is int and lo <= value <= hi


def ref(value, prefix):
    return type(value) is str and value.startswith(prefix + '-') and matches(value[len(prefix) + 1:], HEX)


def context(value):
    return (type(value) is str and value == 'global-default') or ref(value, 'ctx')


def canonical(value):
    try:
        return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')
    except (TypeError, ValueError, RecursionError):
        raise ev.EvidenceError('SSH_SERIALIZATION', '$ssh') from None


def digest(prefix, parts):
    return prefix + '-' + hashlib.sha256(canonical(parts)).hexdigest()


def validate_config(rows, gaps):
    require(1 <= len(rows) <= 512 and type(rows[0]) is dict and rows[0].get('kind') == 'SOURCE')
    sources, lines, stack, includes = {}, {}, [], set()
    current = 'global-default'
    required_gaps = set()
    common = {'kind', 'order', 'source_ref', 'line', 'context_ref'}
    shapes = {'SOURCE': {'source_kind', 'parent_ref', 'include_line', 'depth'},
              'MATCH': {'match_kind'}, 'INCLUDE': {'outcome'},
              'DIRECTIVE': {'setting', 'operator', 'values'},
              'KEY_REFERENCE': {'key_source_ref'}, 'HAZARD': {'hazard'}}
    for index, row in enumerate(rows):
        require(type(row) is dict and type(row.get('kind')) is str and row['kind'] in shapes)
        kind = row['kind']
        mapping(row, common | shapes[kind])
        src, line, ctx = row['source_ref'], row['line'], row['context_ref']
        require(integer(row['order'], index, index) and ref(src, 'src') and integer(line, 0, 16384) and context(ctx))
        if kind == 'SOURCE':
            require(line == 0 and src not in sources and len(sources) < 32 and ctx == current)
            parent, depth, inc = row['parent_ref'], row['depth'], row['include_line']
            require(integer(depth, 0, 4))
            if index == 0:
                require(parent is None and inc is None and depth == 0 and row['source_kind'] == 'MAIN' and
                        src == digest('src', ['ssh-config-v1', ['etc', 'ssh'], 'sshd_config']))
            else:
                require(ref(parent, 'src') and parent in stack and integer(inc, 1, 16384) and
                        (parent, inc) in includes and lines[parent] == inc and
                        row['source_kind'] in ('DROPIN', 'POLICY_BACKEND') and depth == sources[parent] + 1)
                stack = stack[:stack.index(parent) + 1]
                if row['source_kind'] == 'POLICY_BACKEND':
                    require(src == digest('src', ['ssh-config-v1', ['etc', 'crypto-policies', 'back-ends'],
                                                  'opensshserver.config']))
            sources[src], lines[src] = depth, 0
            stack.append(src)
            continue
        require(src in stack and line > lines[src])
        stack = stack[:stack.index(src) + 1]
        lines[src] = line
        if kind == 'MATCH':
            require(row['match_kind'] in ('ALL', 'CONDITIONAL') and ctx == digest('ctx', [src, line]))
            current = ctx
            if row['match_kind'] == 'CONDITIONAL':
                required_gaps.add('MATCH_UNRESOLVED')
        else:
            require(ctx == current)
            if kind == 'INCLUDE':
                require(row['outcome'] in ('ALLOWLISTED', 'REJECTED'))
                if row['outcome'] == 'ALLOWLISTED':
                    includes.add((src, line))
                else:
                    required_gaps.add('INCLUDE_REJECTED')
            elif kind == 'DIRECTIVE':
                require(type(row['setting']) is str and row['setting'] in SETTINGS and
                        row['operator'] in ('EXACT', '+', '-', '^'))
                names = row['values']
                require(type(names) is list and 1 <= len(names) <= 256 and
                        all(matches(n, PATTERN) for n in names) and len(set(names)) == len(names))
            elif kind == 'KEY_REFERENCE':
                require(ref(row['key_source_ref'], 'key'))
            elif kind == 'HAZARD':
                require(row['hazard'] in ('HOSTKEY_PATH_REJECTED', 'NATIVE_DEPENDENCY'))
                required_gaps.add(row['hazard'])
    require(required_gaps <= set(gaps))


def validate_keys(rows, gaps):
    require(len(rows) <= 32)
    seen, fingerprints = set(), {}
    fixed = {'ssh-ed25519': 256, 'ecdsa-sha2-nistp256': 256, 'ecdsa-sha2-nistp384': 384,
             'ecdsa-sha2-nistp521': 521}
    for row in rows:
        mapping(row, {'source_ref', 'key_type', 'bits', 'fingerprint_sha256', 'grammar'})
        name, bits, fp, src, grammar = (row[k] for k in ('key_type', 'bits', 'fingerprint_sha256', 'source_ref', 'grammar'))
        require(ref(src, 'key') and src not in seen and matches(name, TOKEN) and
                name.startswith(('ssh-', 'ecdsa-', 'sk-')) and 'private' not in name.lower() and matches(fp, HEX))
        seen.add(src)
        if name in fixed or name in ('ssh-rsa', 'ssh-dss'):
            require(grammar == 'KNOWN' and integer(bits, 1, 16384) and (name not in fixed or bits == fixed[name]))
        else:
            require(grammar == 'UNKNOWN_TYPE' and bits is None and 'KEY_TYPE_UNKNOWN' in gaps)
        key = (name, bits, grammar)
        require(fp not in fingerprints or fingerprints[fp] == key, 'SSH_FINGERPRINT_CONFLICT')
        fingerprints[fp] = key
    require([r['source_ref'] for r in rows] == sorted(seen))


def validate_effective(rows):
    require(1 <= len(rows) <= 256)
    pairs, modes, settings = set(), set(), []
    for row in rows:
        mapping(row, {'mode', 'setting', 'token'})
        mode, setting, token = (row[k] for k in ('mode', 'setting', 'token'))
        require(type(mode) is str and mode in ('G', 'T') and type(setting) is str and
                setting in EFFECTIVE_SETTINGS and matches(token, TOKEN) and token.lower() != 'none')
        require((setting, token) not in pairs)
        pairs.add((setting, token))
        modes.add(mode)
        settings.append(setting)
    require(len(modes) == 1 and settings == sorted(settings) and EFFECTIVE_REQUIRED <= set(settings))
    require(sum(len(row['token']) + 1 for row in rows) <= 16384)
    return next(iter(modes))


def slots(snapshot):
    return (*BASE_SLOTS, *(f'native-{i}' for i in range(len(snapshot['context_refs']))))


def validate_snapshot(s):
    mapping(s, {'flags', 'platform_status', 'context_refs', 'slots'})
    flags = mapping(s['flags'], FLAGS)
    require(all(type(x) is bool for x in flags.values()) and s['platform_status'] in ('UNVERIFIED', 'UNKNOWN', 'OUT_OF_SCOPE'))
    contexts = s['context_refs']
    require(type(contexts) is list and 1 <= len(contexts) <= 2 and all(context(x) for x in contexts) and
            len(set(contexts)) == len(contexts))
    mapping(s['slots'], slots(s))
    native_modes = set()
    for slot in slots(s):
        r = mapping(s['slots'][slot], {'state', 'reason', 'rc', 'rows', 'gaps'})
        state, reason, rc, rows, gaps = (r[k] for k in ('state', 'reason', 'rc', 'rows', 'gaps'))
        require(type(state) is str and state in REASONS and type(reason) is str and reason in REASONS[state])
        require(rc is None or integer(rc, -255, 255))
        require(type(rows) is list and len(rows) <= 512 and type(gaps) is list and len(gaps) <= 16 and
                all(type(x) is str for x in gaps) and gaps == sorted(set(gaps)))
        flag = flags[FLAGS[1] if slot == 'keys' else FLAGS[0]]
        forced = (('NOT_SCANNED', 'DISABLED_BY_USER') if not flag else
                  ('NOT_APPLICABLE', 'PLATFORM_OUT_OF_SCOPE') if s['platform_status'] == 'OUT_OF_SCOPE' else
                  ('UNKNOWN', 'PLATFORM_UNRESOLVED') if s['platform_status'] == 'UNKNOWN' else
                  ('UNKNOWN', 'KEY_FLAG_REQUIRED') if slot.startswith('native-') and not flags[FLAGS[1]] else None)
        if forced:
            require((state, reason) == forced and rc is None and not rows and not gaps)
            continue
        require(state not in ('NOT_SCANNED', 'NOT_APPLICABLE') and reason not in ('PLATFORM_UNRESOLVED', 'KEY_FLAG_REQUIRED'))
        usable = state in ('COLLECTED', 'PARTIAL')
        if not usable:
            require(not rows and not gaps)
        else:
            require(bool(rows) or (state == 'COLLECTED' and slot == 'keys'))
            require(bool(gaps) == (state == 'PARTIAL'))
        if slot in CLIENTS:
            if usable:
                require(rc == 0 and len(rows) <= 256 and all(matches(x, TOKEN) for x in rows) and
                        rows == sorted(set(rows)) and sum(len(x) + 1 for x in rows) <= 16384 and
                        (state == 'COLLECTED' or (reason == 'FORMAT_GAP' and gaps == ['FORMAT_GAP'])))
            else:
                require(reason in CLIENT_FAILURES)
                if reason in TOOL_REASONS:
                    require(rc is None)
                elif reason == 'UNSUPPORTED_QUERY':
                    require(rc is not None and rc != 0)
                elif reason in ('NO_OUTPUT', 'UNRECOGNIZED_OUTPUT'):
                    require(rc == 0)
        elif slot.startswith('native-'):
            if usable:
                require(state == 'COLLECTED' and rc == 0 and not gaps)
                native_modes.add(validate_effective(rows))
            else:
                require(reason in NATIVE_FAILURES)
                if reason in TOOL_REASONS | {'NATIVE_SAFETY_UNPROVEN', 'NATIVE_CONTEXT_REJECTED',
                                            'NATIVE_SOURCE_REJECTED', 'SOURCE_PERMISSION'}:
                    require(rc is None)
                elif reason in ('NO_OUTPUT', 'UNRECOGNIZED_OUTPUT'):
                    require(rc == 0)
        else:
            require(rc is None)
            if slot == 'config' and usable:
                require(set(gaps) <= CONFIG_GAPS and (state == 'COLLECTED' or reason == 'CONFIG_GAP'))
                validate_config(rows, gaps)
            elif slot == 'keys' and usable:
                require(set(gaps) <= KEY_GAPS and (state == 'COLLECTED' or reason == 'KEY_GAP'))
                validate_keys(rows, gaps)
            elif not usable:
                require(reason in FILE_FAILURES | ({'UNRECOGNIZED_OUTPUT'} if slot == 'config' else {'KEY_INVALID'}))
        require(len(canonical(r)) <= 262144, 'SSH_PROJECTION_LIMIT')
    require(len(native_modes) <= 1, 'SSH_NATIVE_MODE_MISMATCH')


def unknown_algorithm(name, rules):
    # SSH key and MAC are not certificate public keys, signature or cipher contexts.
    return dict(algorithm_id=None, family='UNKNOWN', primitive='UNKNOWN', observed_name=name,
                taxonomy_version=rules['taxonomy_version'])


def _project(rid, host, snapshot, source, observed_at, rules):
    validate_snapshot(snapshot)
    assessment.validate_rules(rules)
    mapping(source, {'source_kind', 'producer_id', 'producer_version', 'origin_ref', 'input_sha256'})
    require(source['source_kind'] in ('SYNTHETIC', 'NATIVE_COLLECTOR') and source['producer_id'] == PRODUCER and
            source['producer_version'] == VERSION)
    ev.SOURCE.check(source, '$ssh.source')
    for slot in slots(snapshot):
        if slot.startswith('native-') and snapshot['slots'][slot]['rows']:
            mode = snapshot['slots'][slot]['rows'][0]['mode']
            require(source['source_kind'] == 'SYNTHETIC' or
                    (mode == 'T' and NATIVE_T_QUALIFIED), 'SSH_NATIVE_SOURCE_UNQUALIFIED')
    ev.STAMP.check(observed_at, '$ssh.observed_at')
    hid = host['host_id']
    stable = host['identity_scope'] == 'STABLE'
    collections, evidence, records, assets, key_refs = [], [], [], {}, {}
    for slot in slots(snapshot):
        r = snapshot['slots'][slot]
        state, reason = r['state'], r['reason']
        scope = 'ssh-' + slot
        if slot.startswith('native-'):
            # A context identity must not be conflated with a different invocation order.
            ctx = snapshot['context_refs'][int(slot[-1])]
            scope = 'ssh-native-' + digest('ctx', [ctx])
        else:
            ctx = None
        cid = ev.collection_id(rid, hid, PRODUCER, scope)
        c = dict(collection_id=cid, host_id=hid, collector_id=PRODUCER, collector_version=VERSION,
                 scope_key=scope, collection_state=state, reason_code=reason, source=copy.deepcopy(source),
                 observed_at=None if state == 'NOT_SCANNED' else observed_at, evidence_ids=[])
        collections.append(c)
        obs = []

        def add(key, kind, data, algorithm=None, aid=None):
            eid = ev.evidence_id(rid, hid, cid, key)
            evidence.append(dict(evidence_id=eid, host_id=hid, collection_id=cid, asset_id=aid,
                observation_key=key, evidence_kind=kind, source=copy.deepcopy(source), observed_at=observed_at,
                data=data, algorithm=algorithm))
            c['evidence_ids'].append(eid)
            if aid is not None:
                assets[aid]['evidence_ids'].append(eid)
            return eid

        count = 0
        for row in r['rows']:
            aid = None
            related = []
            if slot in CLIENTS:
                alg = assessment.classify_algorithm(row, CONTEXTS[slot], rules) if slot in CONTEXTS else unknown_algorithm(row, rules)
                eid = add(digest('token', [slot, row]), 'RUNTIME_CAPABILITY',
                          dict(capability='ssh-' + slot, supported=True), alg)
                count += 1
            elif slot == 'config':
                label = (row['source_ref'] if row['kind'] == 'SOURCE' else row['setting'] if row['kind'] == 'DIRECTIVE'
                         else row['key_source_ref'] if row['kind'] == 'KEY_REFERENCE' else
                         row['context_ref'] if row['kind'] == 'MATCH' else row['kind'].lower())
                eid = add(digest('decl', [row['source_ref'], row['line'], row['kind']]),
                          'ASSET_METADATA', dict(name=label, version=None))
                if row['kind'] == 'KEY_REFERENCE':
                    key_refs.setdefault(row['key_source_ref'], []).append(eid)
                count += 1
            elif slot.startswith('native-'):
                # The mode is part of the observation identity and mandatory detail.
                setting, token = row['setting'], row['token']
                alg = (assessment.classify_algorithm(token, EFFECTIVE_CONTEXTS[setting], rules)
                       if setting in EFFECTIVE_CONTEXTS else unknown_algorithm(token, rules))
                eid = add(digest('effective', [ctx, row['mode'], setting, token]),
                          'EFFECTIVE_CONFIGURATION', dict(setting=setting, effective_value=token, allowed=True), alg)
                count += 1
            else:  # validated keys slot
                identity = 'sha256-' + row['fingerprint_sha256']
                if row['grammar'] == 'KNOWN':
                    aid = ev.asset_id(hid, 'public_key', identity, run_id=None if stable else rid)
                    assets.setdefault(aid, dict(asset_id=aid, host_id=hid, asset_kind='public_key',
                        identity_scope='STABLE' if stable else 'RUN_SCOPED', identity_key=identity, evidence_ids=[]))
                    related = sorted(key_refs.get(row['source_ref'], []))
                    count += 1
                eid = add(digest('public', [row['source_ref'], identity]), 'ASSET_METADATA',
                          dict(name=identity, version=None), unknown_algorithm(row['key_type'], rules), aid)
            obs.append(dict(evidence_id=eid, asset_id=aid, evidence_ref=digest('ref', [rid, hid, cid, eid]),
                            row=copy.deepcopy(row), config_evidence_ids=related))
        if state in ('COLLECTED', 'PARTIAL'):
            add('summary', 'COLLECTION_SUMMARY', dict(scope=scope, attempted=True, applicable=True,
                coverage='COMPLETE' if state == 'COLLECTED' else 'PARTIAL', observation_count=count))
        elif state == 'NOT_APPLICABLE':
            add('summary', 'COLLECTION_SUMMARY', dict(scope=scope, attempted=False, applicable=False,
                coverage='UNKNOWN', observation_count=None))
        records.append(dict(run_id=rid, host_id=hid, collection_id=cid, slot=slot, context_ref=ctx,
            state=state, reason=reason, rc=r['rc'], gaps=list(r['gaps']), evidence_ids=list(c['evidence_ids']),
            evidence_ref=digest('ref', [rid, hid, cid, c['evidence_ids']]), observations=obs))
    details = dict(detail_format=DETAIL_FORMAT, detail_version=VERSION, run_id=rid, host_id=hid,
                   source=copy.deepcopy(source), observed_at=observed_at, flags=dict(snapshot['flags']),
                   platform_status=snapshot['platform_status'], context_refs=list(snapshot['context_refs']), records=records)
    data = canonical(details)
    require(len(data) <= 2097152, 'SSH_DETAIL_LIMIT')
    details['detail_sha256'] = hashlib.sha256(data).hexdigest()
    return collections, list(assets.values()), evidence, details


def normalize_ssh(document, host_id, snapshot, source, observed_at, rules):
    """Return a new integrated Evidence document and mandatory private companion."""
    ev.validate_document(document)
    require(document['schema_version'] == '1.1.0', 'SCHEMA_VERSION')
    host = next((h for h in document['hosts'] if h['host_id'] == host_id), None)
    require(host is not None, 'SSH_HOST')
    c, a, e, d = _project(document['run']['run_id'], host, snapshot, source, observed_at, rules)
    result = {**document, 'collections': document['collections'] + c,
              'assets': document['assets'] + a, 'evidence': document['evidence'] + e}
    # Existing identical asset/collection IDs are a conflict until an explicit merger owns backrefs.
    ev.validate_document(result)
    validate_details(result, d, rules)
    return result, d


def validate_details(document, details, rules):
    """Reconstruct and cross-check the closed companion against actual Evidence.

    A hash alone is insufficient: the typed projection, all IDs, records,
    contexts and relationships must be exactly reproducible. No claim is inferred
    from companion data or an invented service asset.
    """
    ev.validate_document(document)
    require(document['schema_version'] == '1.1.0', 'SCHEMA_VERSION')
    mapping(details, {'detail_format', 'detail_version', 'run_id', 'host_id', 'source', 'observed_at',
                      'flags', 'platform_status', 'context_refs', 'records', 'detail_sha256'})
    require(details['detail_format'] == DETAIL_FORMAT and details['detail_version'] == VERSION and
            details['run_id'] == document['run']['run_id'] and matches(details['detail_sha256'], HEX))
    host = next((h for h in document['hosts'] if h['host_id'] == details['host_id']), None)
    require(host is not None, 'SSH_HOST')
    records = details['records']
    require(type(records) is list and 8 <= len(records) <= 9)
    snapshot = {k: details[k] for k in ('flags', 'platform_status', 'context_refs')}
    snapshot['slots'] = {}
    for record in records:
        mapping(record, {'run_id', 'host_id', 'collection_id', 'slot', 'context_ref', 'state', 'reason', 'rc',
                         'gaps', 'evidence_ids', 'evidence_ref', 'observations'})
        slot = record['slot']
        require(type(slot) is str and slot in (*BASE_SLOTS, 'native-0', 'native-1') and slot not in snapshot['slots'])
        observations = record['observations']
        require(type(observations) is list and len(observations) <= 512)
        for item in observations:
            mapping(item, {'evidence_id', 'asset_id', 'evidence_ref', 'row', 'config_evidence_ids'})
            require(ref(item['evidence_id'], 'e') and (item['asset_id'] is None or ref(item['asset_id'], 'a')) and
                    ref(item['evidence_ref'], 'ref') and type(item['config_evidence_ids']) is list and
                    len(item['config_evidence_ids']) <= 512 and all(ref(x, 'e') for x in item['config_evidence_ids']) and
                    (slot == 'keys' or not item['config_evidence_ids']))
        require(record['run_id'] == details['run_id'] and record['host_id'] == details['host_id'] and
                (record['context_ref'] is None or context(record['context_ref'])) and
                ref(record['collection_id'], 'c') and ref(record['evidence_ref'], 'ref') and
                type(record['evidence_ids']) is list and len(record['evidence_ids']) <= 513 and
                all(ref(x, 'e') for x in record['evidence_ids']))
        snapshot['slots'][slot] = {k: record[k] for k in ('state', 'reason', 'rc', 'gaps')} | {
            'rows': [x['row'] for x in observations]}
    c, a, e, expected = _project(document['run']['run_id'], host, snapshot, details['source'], details['observed_at'], rules)
    detail_wire = canonical(details)
    require(len(detail_wire) <= 2097300 and detail_wire == canonical(expected), 'SSH_DETAIL_MISMATCH')
    by_cid = {row['collection_id'] for row in c}
    by_aid = {row['asset_id'] for row in a}
    def ordered(rows, key):
        return [{k: sorted(v) if k == 'evidence_ids' else v for k, v in row.items()}
                for row in sorted(rows, key=lambda r: r[key])]

    def same(x, y, key):
        return canonical(ordered(x, key)) == canonical(ordered(y, key))
    actual_c = [row for row in document['collections'] if row['host_id'] == host['host_id'] and row['collector_id'] == PRODUCER]
    actual_e = [row for row in document['evidence'] if row['collection_id'] in by_cid]
    actual_a = [row for row in document['assets'] if row['asset_id'] in by_aid]
    require(same(c, actual_c, 'collection_id') and same(e, actual_e, 'evidence_id') and
            same(a, actual_a, 'asset_id'), 'SSH_EVIDENCE_MISMATCH')
    return None
