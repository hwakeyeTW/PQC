"""PQC M1-04: offline, Evidence-authoritative CFF projection.

The local wire contract is not an upstream certification. The companion and
canonical assessed Evidence are required alongside each lossy CFF envelope.
No file loading, network, remediation, legacy evaluator or clock access.
"""
from collections import Counter, defaultdict
import hashlib
import json
import math
import re
import unicodedata

from tools import assessment, evidence

VERSION = '1.0.0'
PROFILE_ID = 'pqc_evidence_v1'
PROFILE_NAME = 'PQC Evidence Facts and Coverage'
STATUSES = ('pass', 'fail', 'error', 'not_applicable', 'not_checked')
SCORE_SEMANTICS = 'FACT_STATUS_RATIO_NOT_READINESS'
SEVERITY_SEMANTICS = 'COMPAT_PLACEHOLDER_NOT_RISK_RATING'
DISRUPTION_SEMANTICS = 'COMPAT_PLACEHOLDER_NO_REMEDIATION'
IMPACT_SEMANTICS = 'NOT_ASSESSED'
MAX_BYTES = 32 * 1024 * 1024
MAX_HOSTS = 1000
MAX_ROWS = 20000
ERROR_STATES = frozenset(('ERROR', 'PERMISSION_DENIED', 'UNREACHABLE'))
HOST_ERRORS = frozenset(('ERROR', 'UNREACHABLE'))
SAFE_LABEL = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,511}\Z')


class ProjectionError(ValueError):
    """Fixed code only; no caller data or variable keys in diagnostics."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _require(ok, code='PROJECTION_INCONSISTENT'):
    if not ok:
        raise ProjectionError(code)


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _literal_hash(value):
    return _digest(json.dumps(value, ensure_ascii=False, sort_keys=True,
                              separators=(',', ':'), allow_nan=False).encode('utf-8'))


def _token(prefix, values):
    return prefix + '-' + _literal_hash(values)


def _label(value):
    # Evidence permits more literal characters than this presentation subset.
    # Never render a path, command, template or arbitrary free-text value.
    return value if type(value) is str and SAFE_LABEL.fullmatch(value) else None


def _bounded_json(value):
    """Bound the wire bytes; accept only ordinary JSON data, not object hooks."""
    nodes = 0
    def plain_text(v):
        return (type(v) is str and len(v) <= 512 and
                not any(unicodedata.category(c) in ('Cc', 'Cf', 'Cs') for c in v))

    def visit(v, depth):
        nonlocal nodes
        nodes += 1
        _require(depth <= 64 and nodes <= 2000000, 'PROJECTION_LIMIT')
        t = type(v)
        if t is dict:
            for k, item in v.items():
                _require(plain_text(k), 'PROJECTION_TYPE')
                visit(item, depth + 1)
        elif t is list:
            _require(len(v) <= MAX_ROWS, 'PROJECTION_LIMIT')
            for item in v:
                visit(item, depth + 1)
        elif t is str:
            _require(plain_text(v), 'PROJECTION_TYPE')
        elif t is int:
            _require(0 <= v <= 9007199254740991, 'PROJECTION_TYPE')
        elif t is float:
            _require(math.isfinite(v), 'PROJECTION_TYPE')
        else:
            _require(v is None or t is bool, 'PROJECTION_TYPE')
    visit(value, 1)
    out = bytearray()
    encoder = json.JSONEncoder(ensure_ascii=False, sort_keys=True,
                               separators=(',', ':'), allow_nan=False)
    for chunk in encoder.iterencode(value):
        raw = chunk.encode('utf-8')
        _require(len(out) + len(raw) <= MAX_BYTES, 'PROJECTION_LIMIT')
        out.extend(raw)
    return bytes(out)


def _limits(document):
    _require(len(document['hosts']) <= MAX_HOSTS and
             all(len(document[k]) <= MAX_ROWS for k in evidence.REGISTRIES),
             'PROJECTION_LIMIT')


def _subject(s):
    return {k: s.get(k) for k in ('host_id', 'asset_id', 'algorithm_id')}


def _pick(row, *keys):
    # Inputs are validated and the assessed document is a private JSON copy.
    return {k: row[k] for k in keys}


def _key_fields(value, key):
    # Logical keys may contain sensitive free text even when lexically valid.
    # Preserve the exact association by full hash and ID, not the raw key.
    return {key + '_sha256': _literal_hash(value)}


def _algorithm(row, rules, cache):
    if row is None:
        return None
    key = tuple(row[k] for k in ('algorithm_id', 'family', 'primitive',
                                 'observed_name', 'taxonomy_version'))
    if key not in cache:
        cache[key] = assessment.migration_classification(row, rules)
    return {**_pick(row, 'algorithm_id', 'family', 'primitive', 'taxonomy_version'),
            'observed_name_sha256': None if row['observed_name'] is None else
            _literal_hash(row['observed_name']), 'migration_classification': cache[key]}


def _evidence_row(row, rules, cache):
    # Never copy arbitrary data, observation_key or raw algorithm text. Keep
    # typed context and provenance references and point to the canonical source.
    kind = row['evidence_kind']
    conditions = row['data']['conditions'] if kind in (
        'AUTHORIZED_NEGOTIATION', 'OBSERVED_USAGE') else None
    return {**_pick(row, 'evidence_id', 'host_id', 'collection_id', 'asset_id',
                    'evidence_kind', 'source', 'observed_at'),
            'evidence_ref': row.get('evidence_ref'), 'raw_sha256': row.get('raw_sha256'),
            'algorithm': _algorithm(row['algorithm'], rules, cache), 'conditions': conditions}


def _collection_row(row):
    return {**_pick(row, 'collection_id', 'host_id', 'collector_id', 'collector_version',
                    'collection_state', 'reason_code', 'source', 'observed_at', 'evidence_ids'),
            **_key_fields(row['scope_key'], 'scope_key')}


def _asset_row(row):
    return _pick(row, 'asset_id', 'host_id', 'asset_kind', 'identity_scope', 'evidence_ids')


def _claim_row(row):
    return {**_pick(row, 'claim_id', 'level', 'rule_id', 'rule_version',
                    'assessment_state', 'reason_code', 'evidence_ids', 'conditions'),
            'subject': _subject(row['subject']), **_key_fields(row['claim_key'], 'claim_key')}


def _owned_rule_levels(rules):
    return {row['rule_id']: key for key, row in rules['rules'].items()}


def _empty_coverage_ids(host, collections):
    """Match only the exact empty-collection coverage identity from #11.

    This duplicates the documented coverage-key derivation, not assessment.
    Nonempty collections use explicit evidence/claim refs instead. No host-wide
    inference, substring search, or borrowing from an unrelated collection.
    """
    subject = {'host_id': host, 'asset_id': None, 'algorithm_id': None}
    result = defaultdict(list)
    for c in collections:
        if not c['evidence_ids']:
            condition = _token('coverage', [c['collector_id'], c['scope_key'], 'unqualified'])
            fid = evidence.finding_id(subject, assessment.COVERAGE_RULE, condition)
            result[fid].append(c['collection_id'])
    return result


def _finding_links(finding, claim_index, evidence_index, empty_coverage, owned):
    refs = set(finding['evidence_ids'])
    for cid in finding['claim_ids']:
        refs.update(claim_index[cid]['evidence_ids'])
    collections = {evidence_index[eid]['collection_id'] for eid in refs}
    if not refs and owned and finding['rule_id'] == assessment.COVERAGE_RULE:
        candidates = empty_coverage.get(finding['finding_id'], [])
        if len(candidates) == 1:
            collections.add(candidates[0])
    return sorted(refs), sorted(collections)


def _status(finding, owned, collection_ids, collection_index, host, has_collections):
    state = finding['assessment_state']
    if not owned:
        return 'not_checked', 'UNOWNED_RULE', [], None
    if state in ('PASS', 'FAIL'):
        return state.lower(), 'DECISIVE_FACT', [], None
    if state == 'NOT_APPLICABLE':
        return 'not_applicable', 'EXPLICIT_NOT_APPLICABLE', [], None
    if state == 'UNKNOWN':
        errors = [cid for cid in collection_ids
                  if collection_index[cid]['collection_state'] in ERROR_STATES]
        if errors:
            return 'error', 'REFERENCED_ACQUISITION_ERROR', errors, None
        # The one host-only coverage finding, only when no collection exists.
        # An ERROR on a host does not make its other scopes errors.
        sub = {'host_id': host['host_id'], 'asset_id': None, 'algorithm_id': None}
        if (not has_collections and host['host_state'] in HOST_ERRORS and
                finding['rule_id'] == assessment.COVERAGE_RULE and
                finding['finding_id'] == evidence.finding_id(sub, assessment.COVERAGE_RULE,
                                                              'no-collection')):
            return 'error', 'HOST_ACQUISITION_ERROR', [], host['host_state']
    return 'not_checked', 'NON_DECISIVE', [], None


def _finding_row(finding, owned_levels, indexes, empty_coverage, host, has_collections):
    owned = finding['rule_id'] in owned_levels
    refs, cids = _finding_links(finding, indexes['claims'], indexes['evidence'], empty_coverage, owned)
    status, reason, errors, host_error = _status(finding, owned, cids, indexes['collections'],
                                                 host, has_collections)
    return {**_pick(finding, 'finding_id', 'rule_id', 'rule_version', 'assessment_state',
                    'reason_code', 'claim_ids', 'evidence_ids'),
            'subject': _subject(finding['subject']),
            **_key_fields(finding['condition_key'], 'condition_key'),
            'cff_rule_id': finding['finding_id'], 'owned': owned,
            'cff_status': status, 'mapping_reason': reason,
            'score_included': status in ('pass', 'fail'),
            'linked_evidence_ids': refs, 'collection_ids': cids,
            'error_collection_ids': errors, 'error_host_state': host_error}


def _cff_finding(row, display_host, owned_levels):
    level = owned_levels.get(row['rule_id'])
    title = ('Evidence fact ' + level if level in evidence.LEVELS else
             'Evidence coverage' if level == 'coverage' else 'External finding (not assessed)')
    actual = row['assessment_state'] if row['owned'] else 'Not assessed by this ruleset'
    expected = 'See companion evidence'
    return {'rule_id': row['cff_rule_id'], 'host': display_host, 'title': title,
            'status': row['cff_status'], 'severity': 'low', 'category': 'Cryptographic Evidence',
            'description': 'Fact status only; not a PQC readiness or risk rating.',
            'check_text': 'See the linked assessed Evidence and companion.',
            'fix_text': 'No remediation is provided.',
            'evidence': {'actual_value': actual, 'expected_value': expected,
                         'message': row['mapping_reason'], 'scanner_rule_id': row['rule_id']},
            'remediation': {'role': '', 'available': False, 'disruption': 'low'},
            'stig_id': '', 'cis_id': '', 'cce_id': '', 'cci_id': '',
            'actual_value': actual, 'expected_value': expected, 'scanner': 'custom',
            'disruption': 'low', 'aap_impact': 'caution',
            'aap_impact_reason': 'Impact not assessed; compatibility placeholder.'}


def _summary(rows):
    count = Counter(f['status'] for f in rows)
    _require(set(count).issubset(STATUSES))
    result = {'total': len(rows), **{k: count[k] for k in STATUSES}}
    denom = count['pass'] + count['fail']
    result['compliance_score'] = round(count['pass'] / denom * 100, 1) if denom else 0.0
    return result


def _score(summary):
    denom = summary['pass'] + summary['fail']
    return {'score_semantics': SCORE_SEMANTICS, 'numerator': summary['pass'],
            'denominator': denom, 'excluded': summary['total'] - denom,
            'score_available': denom > 0}


def _metadata(run, host, display_host):
    return {'scan_id': _token('pqc-evidence', [run['run_id'], host['host_id']]),
            'profile_id': PROFILE_ID, 'profile_name': PROFILE_NAME, 'framework': 'CUSTOM',
            'scanner': {'name': 'custom', 'version': VERSION, 'tier': 1},
            'timestamp': run['finished_at'] or run['recorded_at'], 'host': display_host,
            'certification': {'status': 'uncertified', 'authority': ''}}


def _run_row(run):
    return {**_pick(run, 'run_id', 'run_state', 'recorded_at', 'started_at', 'finished_at', 'source'),
            'scope_reason': run.get('scope_reason'), 'coverage_reason': run.get('coverage_reason'),
            'timestamp_kind': 'RUN_FINISHED_AT' if run['finished_at'] is not None else 'RUN_RECORDED_AT',
            'expected_host_count': len(run['expected_host_ids'])}


def _host_row(host, display_host):
    return {**_pick(host, 'host_id', 'host_state', 'reason_code', 'identity_scope'),
            'target_id': _label(host['target_id']), 'display_host': display_host,
            'expected': True}


def _group(assessed):
    groups = {h['host_id']: {k: [] for k in evidence.REGISTRIES if k != 'hosts'}
              for h in assessed['hosts']}
    for registry in evidence.REGISTRIES:
        if registry == 'hosts':
            continue
        for row in assessed[registry]:
            hid = row['subject']['host_id'] if registry in ('claims', 'findings') else row['host_id']
            groups[hid][registry].append(row)
    return groups


def _verify_host(entry, host, group, assessed, digest, owned_levels):
    """Check the generated bijection, association, versions and count algebra.

    Public validate_projection additionally replays the full deterministic
    projection; this local check is independent of wire-schema validation.
    """
    cff, comp = entry['cff'], entry['companion']
    run = assessed['run']
    _require(entry['host_id'] == host['host_id'] == comp['host']['host_id'] and
             comp['host']['expected'] is True and comp['run']['run_id'] == run['run_id'] and
             comp['evidence_schema_version'] == assessed['schema_version'] and
             comp['evidence_document_sha256'] == digest and comp['version'] == cff['version'] == VERSION)
    _require(comp['run']['expected_host_count'] == len(run['expected_host_ids']) and
             cff['scan_metadata'] == _metadata(run, host, comp['host']['display_host']))
    for name in ('collections', 'assets', 'evidence', 'claims', 'findings'):
        key = evidence.REGISTRIES[name]
        _require([x[key] for x in comp[name]] == [x[key] for x in group[name]])
    _require([x['rule_id'] for x in cff['findings']] == [x['finding_id'] for x in group['findings']])
    ci = {x['collection_id']: x for x in group['collections']}
    ei = {x['evidence_id']: x for x in group['evidence']}
    ai = {x['asset_id']: x for x in group['assets']}
    cli = {x['claim_id']: x for x in group['claims']}
    empty = _empty_coverage_ids(host['host_id'], group['collections'])
    for c in comp['collections']:
        original = ci[c['collection_id']]
        _require(c['host_id'] == host['host_id'] and c['collection_state'] == original['collection_state'] and
                 c['reason_code'] == original['reason_code'] and c['source'] == original['source'] and
                 c['evidence_ids'] == original['evidence_ids'] and
                 all(eid in ei and ei[eid]['collection_id'] == c['collection_id'] for eid in c['evidence_ids']))
    for e in comp['evidence']:
        original = ei[e['evidence_id']]
        _require(e['host_id'] == host['host_id'] and e['collection_id'] in ci and
                 (e['asset_id'] is None or e['asset_id'] in ai) and
                 e['source'] == original['source'] and e['evidence_kind'] == original['evidence_kind'])
    for a in comp['assets']:
        _require(a == _asset_row(ai[a['asset_id']]) and a['host_id'] == host['host_id'] and
                 all(eid in ei and ei[eid]['asset_id'] == a['asset_id'] for eid in a['evidence_ids']))
    for cl in comp['claims']:
        original = cli[cl['claim_id']]
        _require(cl == _claim_row(original) and cl['subject']['host_id'] == host['host_id'] and
                 (cl['subject']['asset_id'] is None or cl['subject']['asset_id'] in ai) and
                 all(eid in ei and ei[eid]['asset_id'] == cl['subject']['asset_id'] and
                     (cl['subject']['algorithm_id'] is None or
                      (ei[eid]['algorithm'] is not None and
                       ei[eid]['algorithm']['algorithm_id'] == cl['subject']['algorithm_id']))
                     for eid in cl['evidence_ids']))
    for original, row, wire in zip(group['findings'], comp['findings'], cff['findings']):
        owned = original['rule_id'] in owned_levels
        refs, cids = _finding_links(original, cli, ei, empty, owned)
        status, reason, errors, host_error = _status(original, owned, cids, ci, host, bool(ci))
        _require(row['subject'] == _subject(original['subject']) and row['owned'] is owned and
                 row['rule_id'] == original['rule_id'] and row['rule_version'] == original['rule_version'] and
                 row['assessment_state'] == original['assessment_state'] and row['reason_code'] == original['reason_code'] and
                 row['claim_ids'] == original['claim_ids'] and row['evidence_ids'] == original['evidence_ids'] and
                 row['linked_evidence_ids'] == refs and row['collection_ids'] == cids and
                 row['error_collection_ids'] == errors and row['error_host_state'] == host_error and
                 row['mapping_reason'] == reason and row['cff_status'] == wire['status'] == status and
                 row['score_included'] is (status in ('pass', 'fail')) and
                 wire['evidence']['scanner_rule_id'] == original['rule_id'] and wire['host'] == comp['host']['display_host'])
    _require(cff['summary'] == _summary(cff['findings']) and comp['score'] == _score(cff['summary']) and
             sum(cff['summary'][k] for k in STATUSES) == cff['summary']['total'])


def project_cff(document, rules):
    """Return a bounded deterministic projection; never mutate the inputs.

    Revalidate and recompute #11-owned results. Stale/forged owned findings
    raise the original assessment error; foreign findings are retained but
    excluded. Save the canonical assessed Evidence separately with this pair.
    """
    evidence.validate_document(document)
    _limits(document)
    assessed = assessment.evaluate_document(document, rules)
    _limits(assessed)
    digest = _digest(evidence.canonical_bytes(assessed))
    run = assessed['run']
    owned_levels = _owned_rule_levels(rules)
    groups = _group(assessed)
    cache = {}
    result = {'projection_version': VERSION, 'per_host': [], 'evidence_document_sha256': digest}
    budget = 0
    for host in assessed['hosts']:
        hid = host['host_id']
        group = groups[hid]
        display = _label(host['target_id']) or hid
        indexes = {k: {r[evidence.REGISTRIES[k]]: r for r in group[k]}
                   for k in ('claims', 'collections', 'evidence')}
        empty = _empty_coverage_ids(hid, group['collections'])
        rows = [_finding_row(f, owned_levels, indexes, empty, host, bool(group['collections']))
                for f in group['findings']]
        wire = [_cff_finding(f, display, owned_levels) for f in rows]
        summary = _summary(wire)
        comp = {'version': VERSION, 'evidence_schema_version': assessed['schema_version'],
                'evidence_document_sha256': digest, 'run': _run_row(run),
                'host': _host_row(host, display), 'rule_version': rules['rule_version'],
                'taxonomy_version': rules['taxonomy_version'], 'score': _score(summary),
                'severity_semantics': SEVERITY_SEMANTICS, 'disruption_semantics': DISRUPTION_SEMANTICS,
                'aap_impact_semantics': IMPACT_SEMANTICS,
                'collections': [_collection_row(c) for c in group['collections']],
                'assets': [_asset_row(a) for a in group['assets']],
                'evidence': [_evidence_row(e, rules, cache) for e in group['evidence']],
                'claims': [_claim_row(c) for c in group['claims']], 'findings': rows}
        entry = {'host_id': hid, 'cff': {'version': VERSION, 'scan_metadata': _metadata(run, host, display),
                                        'findings': wire, 'summary': summary}, 'companion': comp}
        _verify_host(entry, host, group, assessed, digest, owned_levels)
        budget += len(_bounded_json(entry))
        _require(budget <= MAX_BYTES, 'PROJECTION_LIMIT')
        result['per_host'].append(entry)
    _require([h['host_id'] for h in result['per_host']] == sorted(run['expected_host_ids']))
    _bounded_json(result)
    # The wire payload has no reference to any caller-owned mutable object.
    # The evaluated input is already a fresh canonical JSON copy.
    return result


def validate_projection(projection, document, rules):
    """Validate a stored pair against the original (or assessed) Evidence.

    Exact deterministic replay checks shape, association, hash, versions,
    placeholders, reference/ID bijection and score semantics. JSON object key
    order is immaterial; array order and numeric/boolean representation are not.
    This is a local contract, not an external CFF schema resolver.
    """
    actual = _bounded_json(projection)
    expected = _bounded_json(project_cff(document, rules))
    _require(actual == expected, 'PROJECTION_MISMATCH')


def canonical_projection_bytes(projection, document, rules):
    """Return canonical UTF-8 wire bytes only after exact semantic validation."""
    validate_projection(projection, document, rules)
    return _bounded_json(projection)
