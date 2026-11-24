"""PQC M1-02: offline taxonomy and direct-evidence assessments, V1.0.0.

Inputs are validated Evidence documents and trusted, versioned rule data.
No discovery, network, command execution, file loading or readiness score.
"""
from collections import defaultdict
import hashlib
import json
import re
import unicodedata

from tools import evidence

VERSION = '1.0.0'
MAX_RULE_BYTES = 64 * 1024
CONTEXTS = {'KEM_CAPABILITY': 'KEM', 'TLS_KEX': 'KEX', 'SSH_KEX': 'KEX',
            'CERT_PUBLIC_KEY': 'PUBLIC_KEY', 'SIGNATURE': 'SIGNATURE',
            'SYMMETRIC_CIPHER': 'SYMMETRIC', 'TLS_CIPHER': 'SYMMETRIC',
            'SSH_CIPHER': 'SYMMETRIC'}
# Context and direct observation semantics are not user-defined expressions.
LEVELS = {
    'L1': ('pqc-l1-installed', 'PACKAGE_INVENTORY', 'present', 'name', True, False),
    'L2': ('pqc-l2-supported', 'RUNTIME_CAPABILITY', 'supported', 'capability', True, False),
    'L3': ('pqc-l3-configured', 'EFFECTIVE_CONFIGURATION', 'allowed', 'setting', True, False),
    'L4': ('pqc-l4-negotiable', 'AUTHORIZED_NEGOTIATION', 'outcome', None, 'NEGOTIATED', 'REJECTED'),
    'L5': ('pqc-l5-observed', 'OBSERVED_USAGE', 'outcome', None, 'OBSERVED', 'CONTRADICTED'),
}
KIND_LEVEL = {v[1]: k for k, v in LEVELS.items()}
COVERAGE_RULE = 'pqc-coverage'
REASONS = {'positive': 'DIRECT_POSITIVE', 'negative': 'DIRECT_NEGATIVE',
           'unknown': 'NO_DIRECT_EVIDENCE', 'conflict': 'CONFLICTING_EVIDENCE',
           'partial': 'INCOMPLETE_EVIDENCE', 'na': 'EXPLICIT_NOT_APPLICABLE',
           'acquisition': 'ACQUISITION_UNAVAILABLE', 'coverage_gap': 'INCOMPLETE_COLLECTION',
           'unclassified': 'UNCLASSIFIED_ALGORITHM'}
USABLE = ('COLLECTED', 'PARTIAL')
NA_USABLE = (*USABLE, 'NOT_APPLICABLE')
ALIAS = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.+@-]{0,127}\Z')
SLUG = re.compile(r'[a-z0-9][a-z0-9-]{0,127}\Z')


class AssessmentError(ValueError):
    """A fixed reason code, never raw rule/evidence contents or filenames."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def require(condition, code='INVALID_RULES'):
    if not condition:
        raise AssessmentError(code)


def _pairs(pairs):
    result = {}
    for k, v in pairs:
        require(k not in result, 'DUPLICATE_RULE_KEY')
        result[k] = v
    return result


def _reject_number(_):
    raise AssessmentError('INVALID_RULES')


def _shape(value, keys):
    require(type(value) is dict and value.keys() == set(keys))


def _bounded_rules(value):
    # In-memory callers have the same bounded, plain-data contract as bytes.
    nodes = 0
    def visit(v, depth):
        nonlocal nodes
        nodes += 1
        require(depth <= 12 and nodes <= 16000, 'RULES_LIMIT')
        if type(v) is dict:
            for k, item in v.items():
                require(type(k) is str and ALIAS.fullmatch(k) is not None)
                visit(item, depth + 1)
        elif type(v) is list:
            require(len(v) <= 256, 'RULES_LIMIT')
            for item in v:
                visit(item, depth + 1)
        else:
            require(type(v) is str and ALIAS.fullmatch(v) is not None)
    visit(value, 1)
    require(len(json.dumps(value, separators=(',', ':')).encode('ascii')) <= MAX_RULE_BYTES,
            'RULES_LIMIT')


def _compile(rules):
    _bounded_rules(rules)
    _shape(rules, ('taxonomy_version', 'rule_version', 'algorithms', 'rules', 'reason_codes'))
    require(rules['taxonomy_version'] == VERSION and rules['rule_version'] == VERSION,
            'UNSUPPORTED_RULE_VERSION')
    expected = {level: {'rule_id': r[0], 'evidence_kind': r[1], 'field': r[2]}
                for level, r in LEVELS.items()}
    expected['coverage'] = {'rule_id': COVERAGE_RULE}
    require(rules['rules'] == expected and rules['reason_codes'] == REASONS)
    require(type(rules['algorithms']) is list and 0 < len(rules['algorithms']) <= 256)
    aliases, ids = {}, {}
    for row in rules['algorithms']:
        _shape(row, ('algorithm_id', 'family', 'primitive', 'context', 'provenance', 'aliases'))
        aid, family, primitive, context, origin = (row[k] for k in
            ('algorithm_id', 'family', 'primitive', 'context', 'provenance'))
        require(all(type(x) is str for x in (aid, family, primitive, context, origin)))
        require(SLUG.fullmatch(aid) is not None and aid not in ids, 'DUPLICATE_OR_INVALID_ALGORITHM_ID')
        require(context in CONTEXTS and CONTEXTS[context] == primitive)
        if origin == 'CLASSICAL':
            require(family == 'CLASSICAL' and primitive != 'KEM')
        elif origin == 'PROTOCOL':
            require(family == 'HYBRID' and primitive == 'KEX')
        elif origin == 'LEGACY_KYBER':
            require((family, primitive) in (('PQC', 'KEM'), ('HYBRID', 'KEX')))
        elif origin == 'FIPS_203':
            require((family, primitive) == ('PQC', 'KEM'))
        elif origin in ('FIPS_204', 'FIPS_205', 'LEGACY_DILITHIUM', 'LEGACY_SPHINCS_PLUS'):
            require(family == 'PQC' and primitive in ('SIGNATURE', 'PUBLIC_KEY'))
        else:
            raise AssessmentError('INVALID_RULES')
        require(type(row['aliases']) is list and 0 < len(row['aliases']) <= 32)
        ids[aid] = row
        for name in row['aliases']:
            require(type(name) is str and ALIAS.fullmatch(name) is not None)
            key = context, name.lower()
            require(key not in aliases, 'ALIAS_COLLISION')
            aliases[key] = row
    return aliases, ids


def validate_rules(rules):
    """Check the closed V1 rules mapping, including alias collisions."""
    _compile(rules)


def load_rules(raw):
    """Parse bytes already acquired from the fixed trusted rules file.

    Only JSON-compatible YAML is accepted. YAML tags, anchors, merge keys,
    implicit values, templates and arbitrary objects are intentionally absent.
    """
    require(type(raw) is bytes)
    require(len(raw) <= MAX_RULE_BYTES, 'RULES_LIMIT')
    try:
        rules = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs,
                           parse_constant=_reject_number, parse_int=_reject_number,
                           parse_float=_reject_number)
    except AssessmentError:
        raise
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        raise AssessmentError('INVALID_RULES') from None
    validate_rules(rules)
    return rules


def _safe_name(name):
    return (name is None or type(name) is str and 0 < len(name) <= 512
            and not any(unicodedata.category(c) in ('Cc', 'Cf', 'Cs') for c in name)
            and not any(x in name for x in ('{{', '{%', '{#')))


def classify_algorithm(name, context, rules):
    """Return exactly the Evidence V1 algorithm record, never a verdict.

    Caller supplies the observation context, not an inferred protocol or role.
    ASCII case-insensitive exact aliases only; no trim or punctuation rewrite.
    """
    aliases, _ = _compile(rules)
    require(type(context) is str and context in CONTEXTS, 'INVALID_OBSERVATION_CONTEXT')
    require(_safe_name(name), 'INVALID_ALGORITHM_INPUT')
    row = aliases.get((context, name.lower())) if name is not None and ALIAS.fullmatch(name) else None
    return {'algorithm_id': row['algorithm_id'] if row else None,
            'family': row['family'] if row else 'UNKNOWN',
            'primitive': row['primitive'] if row else 'UNKNOWN',
            'observed_name': name, 'taxonomy_version': rules['taxonomy_version']}


def _known(algorithm, aliases, ids, version):
    if algorithm is None:
        return None
    # Evidence shape is validated first; the standalone migration helper also
    # rejects malformed algorithm records conservatively.
    if type(algorithm) is not dict or algorithm.keys() != {
            'algorithm_id', 'family', 'primitive', 'observed_name', 'taxonomy_version'}:
        return None
    aid, name = algorithm['algorithm_id'], algorithm['observed_name']
    if type(aid) is not str or type(name) is not str or not ALIAS.fullmatch(name):
        return None
    row = ids.get(aid)
    if (row is not None and algorithm['taxonomy_version'] == version
            and algorithm['family'] == row['family'] and algorithm['primitive'] == row['primitive']
            and aliases.get((row['context'], name.lower())) is row):
        return row
    return None


def migration_classification(algorithm, rules):
    """Inventory category, not a security finding or a statement of breakage."""
    aliases, ids = _compile(rules)
    row = _known(algorithm, aliases, ids, rules['taxonomy_version'])
    if row is None:
        return 'UNKNOWN'
    if row['provenance'].startswith('LEGACY_'):
        return 'LEGACY_PQC_REVIEW'
    if row['primitive'] == 'SYMMETRIC':
        return 'SYMMETRIC_REVIEW'
    if row['family'] == 'CLASSICAL':
        return 'CLASSICAL_PUBLIC_KEY_MIGRATION'
    return 'PQC_OR_HYBRID_INVENTORY'


def _token(prefix, parts):
    raw = json.dumps(parts, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')
    return prefix + '-' + hashlib.sha256(raw).hexdigest()


def _subject_key(row):
    algorithm = row['algorithm']
    # Null algorithm and an explicitly unclassified observation are different
    # facts, even though Evidence represents both subjects with a null ID.
    aid = algorithm['algorithm_id'] if algorithm else None
    qualifier = ('unqualified' if algorithm is None else 'algorithm' if aid is not None
                 else _token('unclassified', algorithm))
    return (row['host_id'], row['asset_id'], aid, qualifier)


def _subject(key):
    return dict(zip(('host_id', 'asset_id', 'algorithm_id'), key[:3]))


def _direct_polarity(row, level, collection, known):
    if collection['collection_state'] not in USABLE:
        return None
    alg = row['algorithm']
    if alg is not None and known is None:
        return None
    if level in ('L4', 'L5'):
        if known is None or row['observed_at'] is None:
            return None
        if level == 'L4':
            protocol = row['data']['conditions']['protocol']
            if known['context'] not in (protocol + '_KEX', protocol + '_CIPHER', 'SIGNATURE'):
                return None
    _, _, field, _, yes, no = LEVELS[level]
    value = row['data'][field]
    return 'PASS' if value == yes else 'FAIL' if value == no else None


def _applicability(rows, collections, known):
    negative, positive = [], []
    for row in rows:
        if (row['evidence_kind'] != 'COLLECTION_SUMMARY' or
                row['algorithm'] is not None and known[row['evidence_id']] is None):
            continue
        state = collections[row['collection_id']]['collection_state']
        value = row['data']['applicable']
        if value is False and state in NA_USABLE:
            negative.append(row)
        elif value is True and state in USABLE:
            positive.append(row)
    return negative, positive


def _refs(rows):
    return sorted({r['evidence_id'] for r in rows})


def _claim(run_id, subject, level, rule, key, conditions, state, reason, rows, version):
    return {'claim_id': evidence.claim_id(run_id, subject, level, rule, key, conditions),
            'subject': subject, 'claim_key': key, 'level': level, 'rule_id': rule,
            'rule_version': version, 'assessment_state': state, 'reason_code': reason,
            'evidence_ids': _refs(rows), 'conditions': conditions}


def _finding(subject, rule, key, state, reason, rows, version, claims=()):
    return {'finding_id': evidence.finding_id(subject, rule, key), 'subject': subject,
            'condition_key': key, 'rule_id': rule, 'rule_version': version,
            'assessment_state': state, 'reason_code': reason, 'evidence_ids': _refs(rows),
            'claim_ids': sorted(c['claim_id'] for c in claims)}


def _decide(rows, level, collections, known, applicability, reasons):
    polarities = [_direct_polarity(r, level, collections[r['collection_id']],
                                   known[r['evidence_id']]) for r in rows]
    decisive = {p for p in polarities if p is not None}
    na, applicable = applicability
    # Do not choose a latest winner across different observations/times of the
    # same fact. Explicit contrary applicability is also a conflict.
    if decisive:
        if len(decisive) > 1 or na:
            return 'PARTIAL', reasons['conflict'], rows + na + applicable
        if None in polarities:
            return 'PARTIAL', reasons['partial'], rows
        state = next(iter(decisive))
        return state, reasons['positive' if state == 'PASS' else 'negative'], rows
    if any(r['algorithm'] is not None and known[r['evidence_id']] is None for r in rows):
        return 'UNKNOWN', reasons['unclassified'], rows
    if na and applicable:
        return 'UNKNOWN', reasons['conflict'], rows + na + applicable
    # Scope applicability cannot be borrowed from a different observation
    # time. Unknown timestamps are not proof of equal acquisition times.
    na_times = {r['observed_at'] for r in na if r['observed_at'] is not None}
    if na and all(r['observed_at'] in na_times for r in rows):
        times = {r['observed_at'] for r in rows}
        return 'NOT_APPLICABLE', reasons['na'], [r for r in na if r['observed_at'] in times]
    if all(collections[r['collection_id']]['collection_state'] not in USABLE for r in rows):
        return 'UNKNOWN', reasons['acquisition'], rows
    return 'UNKNOWN', reasons['unknown'], rows


def _coverage_nontrivial(row):
    # Only the minimum proof needed for a coverage gap; never a verdict from
    # metadata or version. Use the same typed observations as Evidence V1.
    kind, d = row['evidence_kind'], row['data']
    if kind == 'PLATFORM_INFO':
        # 1.1.0 status is derived; the original 1.0.0 fields still count.
        return any(v is not None for k, v in d.items() if k != 'platform_status')
    if kind == 'TOOL_AVAILABILITY':
        # A known result is coverage only, including a proven absence.
        return d['available'] is not None
    if kind == 'ASSET_METADATA':
        return any(v is not None for v in d.values())
    if kind == 'COLLECTION_SUMMARY':
        return d['applicable'] is True and d['attempted'] is True and d['coverage'] != 'UNKNOWN'
    if kind in KIND_LEVEL:
        level = KIND_LEVEL[kind]
        _, _, field, _, yes, no = LEVELS[level]
        return d[field] in (yes, no) or level == 'L3' and d['effective_value'] is not None
    return False


def _coverage(collection, rows, key, collections, known, reasons, version):
    subject = _subject(key)
    state = collection['collection_state']
    condition = _token('coverage', [collection['collector_id'], collection['scope_key'], key[3]])
    na, applicable = _applicability(rows, collections, known)
    actual = [r for r in rows if _coverage_nontrivial(r)] if state in USABLE else []
    if state == 'NOT_SCANNED':
        result, reason, refs = 'NOT_SCANNED', collection['reason_code'], []
    elif na and (applicable or actual):
        result, reason, refs = 'UNKNOWN', reasons['conflict'], rows
    elif na:
        result, reason, refs = 'NOT_APPLICABLE', reasons['na'], na
    elif state == 'PARTIAL' and actual:
        result, reason, refs = 'PARTIAL', reasons['coverage_gap'], actual
    elif state == 'COLLECTED' and rows and all(r['evidence_kind'] in KIND_LEVEL for r in rows):
        # Direct claims already describe this exact subject's observations.
        return None
    else:
        result = 'UNKNOWN'
        reason = reasons['unknown'] if state in USABLE else reasons['acquisition']
        refs = rows
    return _finding(subject, COVERAGE_RULE, condition, result, reason, refs, version)


def _ordered_record(row):
    return {k: sorted(v) if k in ('evidence_ids', 'claim_ids') else v for k, v in row.items()}


def _merge_results(existing, generated, id_key, owned):
    """Idempotence only for exact same results; no silent stale replacement."""
    fresh = {row[id_key]: row for row in generated}
    require(len(fresh) == len(generated), 'ASSESSMENT_CONFLICT')
    for row in existing:
        rid = row[id_key]
        if rid in fresh:
            require(_ordered_record(row) == _ordered_record(fresh[rid]), 'ASSESSMENT_CONFLICT')
        else:
            require(row['rule_id'] not in owned, 'ASSESSMENT_CONFLICT')
            fresh[rid] = row
    return list(fresh.values())


def evaluate_document(document, rules):
    """Return a new canonical Evidence V1 document with claims and findings.

    Only existing observations/scope and explicit applicability are evaluated.
    Missing facts/conditions are unknown, not manufactured identities.
    Existing results owned by this ruleset must exactly match recomputation;
    unrelated valid results remain. Re-evaluate original evidence for changes.
    """
    aliases, ids = _compile(rules)
    evidence.validate_document(document)
    version, reasons = rules['rule_version'], rules['reason_codes']
    collections = {c['collection_id']: c for c in document['collections']}
    by_scope, by_collection, groups, known = defaultdict(list), defaultdict(list), defaultdict(list), {}
    for row in document['evidence']:
        subject_key = _subject_key(row)
        collection = collections[row['collection_id']]
        scope = collection['scope_key']
        by_collection[(row['collection_id'], subject_key)].append(row)
        known[row['evidence_id']] = _known(row['algorithm'], aliases, ids, rules['taxonomy_version'])
        kind = row['evidence_kind']
        if kind == 'COLLECTION_SUMMARY':
            by_scope[(subject_key, scope)].append(row)
        if kind in KIND_LEVEL:
            level = KIND_LEVEL[kind]
            fact_field = LEVELS[level][3]
            fact = row['data'][fact_field] if fact_field else None
            conditions = row['data'].get('conditions') if level in ('L4', 'L5') else None
            # Exact literal context, not an inferred time window or endpoint.
            context = json.dumps(conditions, sort_keys=True, separators=(',', ':'))
            groups[(subject_key, scope, level, fact, context)].append(row)
    claims, findings = [], []
    for (key, scope, level, fact, context), rows in groups.items():
        subject, conditions = _subject(key), json.loads(context)
        rule = rules['rules'][level]['rule_id']
        claim_key = _token('fact', [scope, fact, key[3]])
        state, reason, refs = _decide(rows, level, collections, known,
            _applicability(by_scope[(key, scope)], collections, known), reasons)
        cl = _claim(document['run']['run_id'], subject, level, rule, claim_key, conditions,
                    state, reason, refs, version)
        claims.append(cl)
        findings.append(_finding(subject, rule, _token('fact-condition', [claim_key, conditions]),
                                 state, reason, [], version, [cl]))
    # Group coverage without inventing an asset or algorithm for missing data.
    indexed_collections = set()
    for (cid, key), rows in by_collection.items():
        indexed_collections.add(cid)
        f = _coverage(collections[cid], rows, key, collections, known, reasons, version)
        if f is not None:
            findings.append(f)
    for cid, collection in collections.items():
        if cid not in indexed_collections:
            findings.append(_coverage(collection, [], (collection['host_id'], None, None, 'unqualified'),
                                      collections, known, reasons, version))
    hosts_with_collections = {c['host_id'] for c in collections.values()}
    for host in document['hosts']:
        if host['host_id'] not in hosts_with_collections:
            state = 'NOT_SCANNED' if host['host_state'] == 'NOT_ATTEMPTED' else 'UNKNOWN'
            reason = 'NOT_ATTEMPTED' if state == 'NOT_SCANNED' else reasons['unknown']
            findings.append(_finding(_subject((host['host_id'], None, None)), COVERAGE_RULE,
                                     'no-collection', state, reason, [], version))
    owned = {r['rule_id'] for r in rules['rules'].values()}
    result = {**document,
              'claims': _merge_results(document['claims'], claims, 'claim_id', owned),
              'findings': _merge_results(document['findings'], findings, 'finding_id', owned)}
    # canonical_bytes validates the full result and the exact #10 ID/ref contract.
    return json.loads(evidence.canonical_bytes(result))
