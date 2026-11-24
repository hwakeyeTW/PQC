"""PQC M1-03: bounded, controller-only Legacy JSON -> Evidence 1.0.0.

The caller owns raw bytes, provenance, trusted rules and private storage.
Format selection attests a known producer shape, not authenticity of a report.
No input-directed I/O, execution, migration of schema or readiness verdicts.
"""
from collections import Counter
from datetime import datetime
import hashlib
import json
import math
import re
from typing import NamedTuple
import unicodedata

from tools import assessment, evidence

VERSION = '1.0.0'
FORMATS = ('legacy-per-host', 'legacy-fleet', 'legacy-ol-run-summary')
COLLECTOR = 'legacy-import'
MAX_BYTES = 32 * 1024 * 1024
MAX_DEPTH = 64
MAX_HOSTS = 1000
MAX_ROWS = 1024
MAX_EVIDENCE = 20000
MAX_ASSETS = 20000
MAX_CLASSIFICATIONS = 4096
MAX_NODES = 1000000
SCOPES = ('report-metadata', 'platform', 'packages', 'openssl-version', 'tls-groups',
          'system-certificates', 'nginx-certificates', 'ssh-host-keys', 'tls-services',
          'crypto-policy', 'sshd-config')
HOST_FIELDS = frozenset(('host', 'collected_at', 'os_distribution', 'os_version',
    'openssl_packages', 'openssl_version', 'openssl_version_rc', 'openssl_tls1_3_groups',
    'openssl_tls1_3_groups_rc', 'crypto_policy', 'ssh_host_keys', 'system_certificates',
    'tls_services', 'nginx_present', 'nginx_certificates', 'sshd_crypto_lines',
    'sshd_crypto_lines_commented'))
FLEET_FIELDS = frozenset(('generated_at', 'total_hosts', 'hosts'))
SUMMARY_FIELDS = frozenset(('run_id', 'selected_hosts', 'successful_hosts', 'hosts_without_report',
                            'selected_count', 'completed_count', 'generated_at', 'reports'))
TOKEN = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.+@-]{0,127}\Z')
REF = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')
SOURCE_VERSION = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}\Z')
RUN_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z')
HOST = re.compile(r'[A-Za-z0-9_:][A-Za-z0-9_.:@+-]{0,511}\Z')
STAMP = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?(?:Z|\+00:00)\Z')
OS_VERSION = re.compile(r'(?:0|[1-9][0-9]{0,15})(?:\.(?:0|[1-9][0-9]{0,15})){0,2}\Z')
OPENSSL_VERSION = re.compile(r'OpenSSL ([0-9]+\.[0-9]+\.[0-9]+[a-z]?(?:[-+][A-Za-z0-9.]+)?)(?: [0-9]{1,2} [A-Za-z]{3} [0-9]{4})?(?: \(Library: OpenSSL [0-9]+\.[0-9]+\.[0-9]+[a-z]?(?:[-+][A-Za-z0-9.]+)?(?: [0-9]{1,2} [A-Za-z]{3} [0-9]{4})?\))?\Z')
TEMP_KEY = re.compile(r'([A-Za-z0-9][A-Za-z0-9_.+@-]{0,127})(?:, [1-9][0-9]{0,7} bits)?\Z')
PLACEHOLDERS = frozenset(('unknown', 'none', 'null', 'undefined', 'n/a', 'na', 'disabled',
                          'unavailable', 'error', 'timeout', 'truncated', 'default', 'warning',
                          'failed', 'failure', 'unsupported'))
SECRET_KEYS = frozenset(('password', 'passwd', 'passphrase', 'privatekey', 'privatekeydata',
    'privatekeyfile', 'pem', 'credential', 'credentials', 'token', 'apikey', 'accesstoken',
    'refreshtoken', 'secret', 'secrets', 'hostvars', 'rawhostvars', 'ansiblepassword',
    'ansiblesshpass', 'ansiblesshprivatekeyfile', 'ansiblebecomepassword', 'authorization',
    'sshprivatekey', 'inventory', 'inventorydata', 'groupvars'))


class LegacyImportError(ValueError):
    """Only fixed reason codes; no input values, keys, paths or raw exceptions."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)


class ImportResult(NamedTuple):
    document: dict
    provenance: dict
    diagnostics: dict


def require(condition, code):
    if not condition:
        raise LegacyImportError(code)


def _pairs(items):
    result = {}
    for k, v in items:
        require(k not in result, 'DUPLICATE_KEY')
        result[k] = v
    return result


def _integer(value):
    require(len(value.lstrip('-')) <= 16, 'INTEGER_LIMIT')
    n = int(value)
    require(abs(n) <= 9007199254740991, 'INTEGER_LIMIT')
    return n


def _finite(value):
    n = float(value)
    require(math.isfinite(n), 'NONFINITE')
    return n


def _nonfinite(_):
    raise LegacyImportError('NONFINITE')


def _parse(raw):
    require(type(raw) is bytes, 'INPUT_TYPE')
    require(len(raw) <= MAX_BYTES, 'SIZE_LIMIT')
    # Bound JSON nesting before decoding, including escaped quotes.
    depth, quoted, escaped, delimiters = 0, False, False, 0
    for b in raw:
        if quoted:
            if escaped:
                escaped = False
            elif b == 92:
                escaped = True
            elif b == 34:
                quoted = False
        elif b == 34:
            quoted = True
        elif b in (91, 123):
            delimiters += 1
            require(delimiters <= MAX_NODES, 'NODE_LIMIT')
            depth += 1
            require(depth <= MAX_DEPTH, 'DEPTH_LIMIT')
        elif b in (93, 125):
            depth -= 1
        elif b == 44:
            delimiters += 1
            require(delimiters <= MAX_NODES, 'NODE_LIMIT')
    try:
        root = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs,
                          parse_int=_integer, parse_float=_finite, parse_constant=_nonfinite)
    except LegacyImportError:
        raise
    except (UnicodeError, ValueError, RecursionError, OverflowError):
        raise LegacyImportError('INVALID_JSON') from None
    # Unknown fields are not semantically consumed, but the whole input has
    # bounded plain JSON and rejects explicit secret/PEM payloads.
    stack, nodes = [(root, 1)], 0
    while stack:
        v, d = stack.pop()
        nodes += 1
        require(nodes <= MAX_NODES, 'NODE_LIMIT')
        require(d <= MAX_DEPTH, 'DEPTH_LIMIT')
        if type(v) is dict:
            for key, item in v.items():
                _guard_text(key)
                require(re.sub('[^a-z0-9]', '', key.lower()) not in SECRET_KEYS,
                        'SENSITIVE_INPUT')
                stack.append((item, d + 1))
        elif type(v) is list:
            stack.extend((item, d + 1) for item in v)
        elif type(v) is str:
            _guard_text(v)
    require(type(root) is dict, 'FORMAT_SHAPE')
    return root


def _guard_text(value):
    require(not any(unicodedata.category(c) == 'Cs' or c == '\x00' for c in value),
            'INVALID_STRING')
    require('-----BEGIN ' not in value.upper(), 'SENSITIVE_INPUT')


def _matches(value, pattern):
    return type(value) is str and pattern.fullmatch(value) is not None


def _safe(value, pattern=TOKEN):
    return _matches(value, pattern) and value.lower() not in PLACEHOLDERS


def _stamp(value):
    if type(value) is not str or not STAMP.fullmatch(value):
        return None
    try:
        datetime.fromisoformat(value[:19])
    except ValueError:
        return None
    return value


def _hash(parts):
    return hashlib.sha256(json.dumps(parts, ensure_ascii=False, sort_keys=True,
                                     separators=(',', ':'), allow_nan=False).encode('utf-8')).hexdigest()


def _host(value, rid):
    require(_safe(value, HOST), 'HOST_IDENTITY')
    try:
        evidence.host_id(None, value, run_id=rid, identity_key=value)
    except evidence.EvidenceError:
        raise LegacyImportError('HOST_IDENTITY') from None
    return value


def _host_list(value, rid):
    require(type(value) is list, 'MANIFEST_SHAPE')
    require(len(value) <= MAX_HOSTS, 'HOST_LIMIT')
    names = [_host(x, rid) for x in value]
    require(len(set(names)) == len(names), 'DUPLICATE_HOST')
    return set(names)


def _count(value, expected):
    require(type(value) is int and value >= 0 and value == expected, 'MANIFEST_COUNT')


def _unknown(mapping, allowed, diagnostics):
    n = len(mapping.keys() - allowed)
    if n:
        diagnostics['UNKNOWN_FIELD'] += n


def _reports(root, format_id, rid, diagnostics):
    """Validate known wrapper/manifest before constructing any output rows."""
    if format_id == 'legacy-per-host':
        require(not root.keys() & (FLEET_FIELDS | SUMMARY_FIELDS), 'FORMAT_SHAPE')
        rows, selected, missing = [root], None, set()
    elif format_id == 'legacy-fleet':
        require(not root.keys() & (HOST_FIELDS | (SUMMARY_FIELDS - {'generated_at'})), 'FORMAT_SHAPE')
        require(type(root.get('hosts')) is list, 'FORMAT_SHAPE')
        rows, selected, missing = root['hosts'], None, set()
        _count(root.get('total_hosts'), len(rows))
        _unknown(root, FLEET_FIELDS, diagnostics)
    else:
        require(not root.keys() & (HOST_FIELDS | (FLEET_FIELDS - {'generated_at'})), 'FORMAT_SHAPE')
        require(type(root.get('reports')) is list and _matches(root.get('run_id'), REF), 'FORMAT_SHAPE')
        rows = root['reports']
        selected = _host_list(root.get('selected_hosts'), rid)
        successful = _host_list(root.get('successful_hosts'), rid)
        missing = _host_list(root.get('hosts_without_report'), rid)
        require(not successful & missing and successful | missing == selected, 'MANIFEST_PARTITION')
        _count(root.get('selected_count'), len(selected))
        _count(root.get('completed_count'), len(successful))
        _unknown(root, SUMMARY_FIELDS, diagnostics)
    require(len(rows) <= MAX_HOSTS, 'HOST_LIMIT')
    reports = {}
    for row in rows:
        require(type(row) is dict and not row.keys() & (FLEET_FIELDS | SUMMARY_FIELDS), 'FORMAT_SHAPE')
        name = _host(row.get('host'), rid)
        require(name not in reports, 'DUPLICATE_HOST')
        reports[name] = row
        _unknown(row, HOST_FIELDS, diagnostics)
    if selected is not None:
        require(set(reports) == successful, 'MANIFEST_REPORTS')
    else:
        selected = set(reports)
    return reports, selected, missing


def _disabled(manifest, digest, rid, reports):
    if manifest is None:
        return {}
    require(type(manifest) is dict and manifest.keys() == {'input_sha256', 'run_id', 'disabled'},
            'DISABLED_MANIFEST')
    require(type(manifest['input_sha256']) is str and manifest['input_sha256'] == digest and
            type(manifest['run_id']) is str and manifest['run_id'] == rid, 'DISABLED_BINDING')
    entries = manifest['disabled']
    require(type(entries) is list and len(entries) <= MAX_HOSTS * len(SCOPES), 'DISABLED_MANIFEST')
    result = {}
    for row in entries:
        require(type(row) is dict and row.keys() == {'host', 'collector_id', 'scope_key', 'reason_code'} and
                all(type(v) is str for v in row.values()), 'DISABLED_MANIFEST')
        key = row['host'], row['scope_key']
        require(row['host'] in reports and row['collector_id'] == COLLECTOR and
                row['scope_key'] in SCOPES and row['reason_code'] in ('DISABLED_BY_USER', 'DISABLED_BY_PROFILE'),
                'DISABLED_SCOPE')
        require(key not in result, 'DISABLED_DUPLICATE')
        result[key] = row['reason_code']
    return result


class _Builder:
    def __init__(self, rid, source, rules, diagnostics):
        self.rid, self.source, self.rules, self.diagnostics = rid, source, rules, diagnostics
        self.hosts, self.collections, self.assets, self.rows = [], [], [], []
        self.algorithms = {}

    def gap(self, code):
        self.diagnostics[code] += 1

    def algorithm(self, name, context):
        key = name, context
        if key not in self.algorithms:
            require(len(self.algorithms) < MAX_CLASSIFICATIONS, 'ALGORITHM_LIMIT')
            self.algorithms[key] = assessment.classify_algorithm(name, context, self.rules)
        return dict(self.algorithms[key])

    def scope(self, hid, scope):
        c = {'collection_id': evidence.collection_id(self.rid, hid, COLLECTOR, scope),
             'host_id': hid, 'collector_id': COLLECTOR, 'collector_version': VERSION,
             'scope_key': scope, 'collection_state': 'UNKNOWN', 'reason_code': 'LEGACY_MISSING_OR_DEFAULT',
             'source': dict(self.source), 'observed_at': None, 'evidence_ids': []}
        self.collections.append(c)
        return _Scope(self, c)


class _Scope:
    def __init__(self, builder, collection):
        self.b, self.c = builder, collection
        self.actual = False
        self.activity = False
        self.seen = {}
        self.before_gaps = builder.diagnostics.copy()

    def unique(self, identity, row):
        digest = _hash(row)
        if identity in self.seen:
            require(self.seen[identity] == digest, 'IDENTITY_CONFLICT')
            self.b.gap('DUPLICATE_ROW')
            return False
        self.seen[identity] = digest
        return True

    def asset(self, kind, literal):
        require(len(self.b.assets) < MAX_ASSETS, 'ASSET_LIMIT')
        key = 'legacy-' + _hash([kind, self.c['scope_key'], literal])
        a = {'asset_id': evidence.asset_id(self.c['host_id'], kind, key, run_id=self.b.rid),
             'host_id': self.c['host_id'], 'asset_kind': kind, 'identity_scope': 'RUN_SCOPED',
             'identity_key': key, 'evidence_ids': []}
        self.b.assets.append(a)
        return a

    def add(self, field, kind, data, asset=None, algorithm=None, actual=False, identity=None):
        require(len(self.b.rows) < MAX_EVIDENCE, 'EVIDENCE_LIMIT')
        key = 'legacy-' + _hash([self.c['scope_key'], asset['identity_key'] if asset else None,
                                field, identity])
        eid = evidence.evidence_id(self.b.rid, self.c['host_id'], self.c['collection_id'], key)
        row = {'evidence_id': eid, 'host_id': self.c['host_id'], 'collection_id': self.c['collection_id'],
               'asset_id': asset['asset_id'] if asset else None, 'observation_key': key,
               'evidence_kind': kind, 'source': dict(self.b.source), 'observed_at': None,
               'data': data, 'algorithm': algorithm}
        self.c['evidence_ids'].append(eid)
        if asset:
            asset['evidence_ids'].append(eid)
        self.b.rows.append(row)
        self.activity = True
        self.actual |= actual

    def legacy(self, field, value, asset=None, algorithm=None, identity=None):
        self.add(field, 'LEGACY_OBSERVATION', {'field': field, 'value': value},
                 asset, algorithm, identity=identity)

    def finish(self, disabled):
        if disabled:
            require(not self.activity and not self.c['evidence_ids'], 'DISABLED_CONFLICT')
            self.c.update(collection_state='NOT_SCANNED', reason_code=disabled)
        else:
            gaps = self.b.diagnostics - self.before_gaps
            malformed = any(k.startswith('MALFORMED_') for k in gaps)
            unverified = any(k.startswith('UNVERIFIED_') for k in gaps)
            if self.actual:
                self.c.update(collection_state='PARTIAL', reason_code=
                              'LEGACY_PARTIAL_MALFORMED' if malformed else 'LEGACY_COVERAGE_UNKNOWN')
            elif malformed:
                self.c['reason_code'] = 'LEGACY_MALFORMED'
            elif self.activity or unverified:
                self.c['reason_code'] = 'LEGACY_UNVERIFIED'
            else:
                self.b.gap('MISSING_OR_DEFAULT_SCOPE')
        return self.actual


def _optional_token(scope, value):
    if _safe(value):
        return value
    if value is not None and value != '' and not (type(value) is str and value.lower() in PLACEHOLDERS):
        scope.b.gap('MALFORMED_FIELD')
    return None


def _report_time(scope, report):
    value = _stamp(report.get('collected_at'))
    if value:
        # This is the producer's report timestamp, not an observation time.
        scope.legacy('original-collected-at', value)
    elif report.get('collected_at') is not None:
        scope.b.gap('MALFORMED_TIMESTAMP')


def _platform(scope, report):
    version = report.get('os_version')
    if type(version) is str and OS_VERSION.fullmatch(version):
        scope.add('os-version', 'PLATFORM_INFO', {'os_family': None, 'os_version': version}, actual=True)
    elif version is not None:
        scope.b.gap('MALFORMED_FIELD')
    distribution = report.get('os_distribution')
    # Distribution is not os_family; preserve only known literal aliases.
    names = {'OracleLinux': 'oracle-linux', 'Oracle Linux': 'oracle-linux', 'RedHat': 'rhel',
             'Rocky': 'rocky', 'AlmaLinux': 'almalinux', 'Debian': 'debian', 'Ubuntu': 'ubuntu'}
    if type(distribution) is str and distribution in names:
        scope.legacy('os-distribution', names[distribution])
    elif distribution is not None:
        scope.b.gap('UNVERIFIED_DISTRIBUTION')


def _packages(scope, report):
    mapping = report.get('openssl_packages')
    if mapping is None:
        return
    if type(mapping) is not dict:
        scope.b.gap('MALFORMED_FIELD')
        return
    require(len(mapping) <= MAX_ROWS, 'ROW_LIMIT')
    count = 0
    for name, rows in mapping.items():
        if type(rows) is list:
            count += len(rows)
            require(count <= MAX_ROWS, 'ROW_LIMIT')
        if not _safe(name) or type(rows) is not list:
            scope.b.gap('MALFORMED_FIELD')
            continue
        for row in rows:
            if type(row) is not dict:
                scope.b.gap('MALFORMED_ROW')
                continue
            _unknown(row, {'name', 'version', 'release', 'arch', 'epoch', 'source'}, scope.b.diagnostics)
            require('name' not in row or row['name'] == name, 'IDENTITY_CONFLICT')
            if row.get('source') not in (None, 'rpm'):
                scope.b.gap('UNVERIFIED_PACKAGE_SOURCE')
                continue
            version = _optional_token(scope, row.get('version'))
            if version is None:
                scope.b.gap('MALFORMED_ROW')
                continue
            release = _optional_token(scope, row.get('release'))
            arch = _optional_token(scope, row.get('arch'))
            epoch = row.get('epoch')
            if epoch is not None and (type(epoch) is not int or epoch < 0):
                scope.b.gap('MALFORMED_FIELD')
                epoch = None
            literal = [name, version, release, arch, epoch]
            if not scope.unique(_hash(literal), row):
                continue
            asset = scope.asset('package', literal)
            scope.add('installed-package', 'PACKAGE_INVENTORY', {'name': name, 'version': version,
                      'present': True}, asset, actual=True)
            for field, value in (('rpm-release', release), ('rpm-architecture', arch), ('rpm-epoch', epoch)):
                if value is not None:
                    scope.legacy(field, value, asset)


def _version(scope, report):
    rc, value = report.get('openssl_version_rc'), report.get('openssl_version')
    match = OPENSSL_VERSION.fullmatch(value) if type(value) is str and len(value) <= 512 else None
    if type(rc) is int and rc == 0 and match and _safe(match.group(1)):
        scope.add('openssl-version', 'ASSET_METADATA', {'name': 'OpenSSL', 'version': match.group(1)}, actual=True)
    elif value not in (None, '') or (rc is not None and (type(rc) is not int or rc != -1)):
        scope.legacy('openssl-version-result', 'UNVERIFIED')
        scope.b.gap('UNVERIFIED_VERSION')


def _group_tokens(value):
    if type(value) is not str or not value:
        return None
    require(len(value) <= MAX_ROWS * 132, 'ROW_LIMIT')
    text = value.strip('\r\n')
    # Confirmed legacy output is colon-separated; also accept one token per
    # line. Do not cherry-pick a token from malformed/truncated mixed output.
    if '\n' in text or '\r' in text:
        if ':' in text:
            return None
        parts = text.replace('\r\n', '\n').split('\n')
    else:
        parts = text.split(':')
    require(len(parts) <= MAX_ROWS, 'ROW_LIMIT')
    return parts if parts and all(_safe(p) for p in parts) else None


def _groups(scope, report):
    value, rc = report.get('openssl_tls1_3_groups'), report.get('openssl_tls1_3_groups_rc')
    tokens = _group_tokens(value)
    if tokens is None:
        if value not in (None, '') or (rc is not None and (type(rc) is not int or rc != -1)):
            scope.legacy('tls-group-result', 'UNVERIFIED_OUTPUT')
            scope.b.gap('UNVERIFIED_GROUP_OUTPUT')
        return
    verified = type(rc) is int and rc == 0
    if not verified:
        scope.b.gap('UNVERIFIED_GROUP_OUTPUT')
    for name, count in sorted(Counter(tokens).items()):
        if count > 1:
            scope.b.diagnostics['DUPLICATE_ROW'] += count - 1
        alg = scope.b.algorithm(name, 'TLS_KEX')
        if verified and alg['algorithm_id'] is not None:
            scope.add('tls-group', 'RUNTIME_CAPABILITY', {'capability': 'openssl-tls13-group',
                      'supported': True}, algorithm=alg, actual=True, identity=name)
        else:
            scope.legacy('tls-group', name, algorithm=alg, identity=name)


def _rows(scope, report, field):
    value = report.get(field)
    if value is None:
        return ()
    if type(value) is not list:
        scope.b.gap('MALFORMED_FIELD')
        return ()
    require(len(value) <= MAX_ROWS, 'ROW_LIMIT')
    return value


def _path(value):
    # A source path is opaque identity only; no filesystem normalization.
    return (type(value) is str and 0 < len(value) <= 1024 and bool(value.strip()) and
            value.lower() not in PLACEHOLDERS and value not in ('.', '..') and
            not any(unicodedata.category(c) in ('Cc', 'Cf', 'Cs') for c in value) and
            not any(x in value for x in ('{{', '{%', '{#', '<', '>', '://')) and
            not re.match(r'(?i)^(?:file|data|ssh|smb|http|https|ftp):', value))


def _asset_rows(scope, report, field, kind, key_field, signature_fields, allowed):
    for row in _rows(scope, report, field):
        if type(row) is not dict:
            scope.b.gap('MALFORMED_ROW')
            continue
        _unknown(row, allowed, scope.b.diagnostics)
        path = row.get('path')
        if not _path(path) or (kind == 'public-key' and not path.endswith('.pub')):
            scope.b.gap('MALFORMED_IDENTITY')
            continue
        if not scope.unique(path, row):
            continue
        observations = []
        for name, context in signature_fields:
            value = _optional_token(scope, row.get(name))
            if value is not None:
                observations.append((name.replace('_', '-'), value, scope.b.algorithm(value, context)))
        size = row.get(key_field)
        if type(size) is str and re.fullmatch(r'[1-9][0-9]{0,7}', size):
            size = int(size)
        if type(size) is not int or not 0 < size <= 100000000:
            if size not in (None, 0, '') or type(size) is bool:
                scope.b.gap('MALFORMED_FIELD')
            size = None
        # Only actual parsed non-placeholder data, not a pathname or empty
        # producer defaults, supports a metadata acquisition witness.
        if not observations and size is None:
            scope.b.gap('MALFORMED_ROW')
            continue
        asset = scope.asset(kind, path)
        scope.add('asset-metadata', 'ASSET_METADATA', {'name': scope.c['scope_key'], 'version': None},
                  asset, actual=True)
        for name, value, alg in observations:
            scope.legacy(name, value, asset, alg)
        if size is not None:
            scope.legacy('public-key-bits', size, asset)
        # subject/issuer/path/fingerprint, dates and legacy risk are not echoed.
        # The original report remains accessible via the caller's digest/ref.


def _system_certificates(scope, report):
    _asset_rows(scope, report, 'system_certificates', 'certificate', 'public_key_size',
        (('public_key_algorithm', 'CERT_PUBLIC_KEY'), ('signature_algorithm', 'SIGNATURE')),
        {'path', 'subject', 'issuer', 'expires', 'signature_algorithm', 'public_key_algorithm',
         'public_key_size', 'risk'})


def _nginx_certificates(scope, report):
    _asset_rows(scope, report, 'nginx_certificates', 'certificate', 'public_key_size',
        (('public_key_type', 'CERT_PUBLIC_KEY'), ('signature_algorithm', 'SIGNATURE')),
        {'path', 'subject', 'issuer', 'not_after', 'not_before', 'signature_algorithm',
         'public_key_type', 'public_key_size'})
    # A true availability flag is still only a legacy observation; default
    # false is not a reliable proof of execution or absence.
    if report.get('nginx_present') is True:
        scope.legacy('nginx-present', True)
    elif report.get('nginx_present') is not None and type(report['nginx_present']) is not bool:
        scope.b.gap('MALFORMED_FIELD')


def _ssh_keys(scope, report):
    _asset_rows(scope, report, 'ssh_host_keys', 'public-key', 'bits',
        (('algorithm', 'CERT_PUBLIC_KEY'),), {'path', 'bits', 'fingerprint', 'algorithm', 'risk'})


def _tls(scope, report):
    for row in _rows(scope, report, 'tls_services'):
        if type(row) is not dict:
            scope.b.gap('MALFORMED_ROW')
            continue
        _unknown(row, {'port', 'protocol', 'cipher', 'key_exchange', 'key_exchange_risk',
                       'peer_signature', 'server_signature'}, scope.b.diagnostics)
        port = row.get('port')
        if type(port) is not int or not 1 <= port <= 65535:
            scope.b.gap('MALFORMED_IDENTITY')
            continue
        if not scope.unique(port, row):
            continue
        asset = scope.asset('service', str(port))
        scope.legacy('legacy-tls-port', port, asset)
        protocol = _optional_token(scope, row.get('protocol'))
        if protocol:
            scope.legacy('tls-protocol', protocol, asset)
        for name, context in (('key_exchange', 'TLS_KEX'), ('cipher', 'TLS_CIPHER'),
                              ('peer_signature', 'SIGNATURE'), ('server_signature', 'SIGNATURE')):
            raw = row.get(name)
            if name == 'key_exchange' and type(raw) is str and len(raw) <= 160:
                match = TEMP_KEY.fullmatch(raw)
                raw = match.group(1) if match else raw
            value = _optional_token(scope, raw)
            if value is not None:
                scope.legacy(name.replace('_', '-'), value, asset, scope.b.algorithm(value, context))
        # Legacy probes lack reliable rc, authorization and context. No L4
        # assertion or service acquisition witness follows from these rows.


def _policy(scope, report):
    value = report.get('crypto_policy')
    if type(value) is dict:
        _unknown(value, {'profile', 'fips_enabled', 'fips_output', 'local_overrides'}, scope.b.diagnostics)
        if value:
            scope.legacy('crypto-policy-result', 'LEGACY_UNVERIFIED')
    elif value is not None:
        scope.b.gap('MALFORMED_FIELD')


def _sshd(scope, report):
    for field in ('sshd_crypto_lines', 'sshd_crypto_lines_commented'):
        rows = _rows(scope, report, field)
        if rows:
            scope.legacy(field.replace('_', '-') + '-count', len(rows))
            if any(type(x) is not str for x in rows):
                scope.b.gap('MALFORMED_ROW')


_MAPPERS = (_report_time, _platform, _packages, _version, _groups, _system_certificates,
            _nginx_certificates, _ssh_keys, _tls, _policy, _sshd)


def import_legacy(raw, *, format_id, run_id, recorded_at, origin_ref, rules,
                  source_version=None, disabled_manifest=None):
    """Normalize a known legacy dialect, returning document/provenance/gaps.

    The explicit selector and optional disabled manifest/source_version are
    trusted caller inputs, not fields of the report. No automatic detection.
    """
    require(type(format_id) is str and format_id in FORMATS, 'UNSUPPORTED_FORMAT')
    require(_matches(run_id, RUN_ID) and _stamp(recorded_at) is not None and _matches(origin_ref, REF) and
            (source_version is None or _safe(source_version, SOURCE_VERSION)), 'CALLER_METADATA')
    assessment.validate_rules(rules)
    root = _parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    diagnostics = Counter()
    reports, selected, missing = _reports(root, format_id, run_id, diagnostics)
    disabled = _disabled(disabled_manifest, digest, run_id, reports)
    source = {'source_kind': 'LEGACY_IMPORT', 'producer_id': format_id, 'producer_version': source_version,
              'origin_ref': origin_ref, 'input_sha256': digest}
    generated = _stamp(root.get('generated_at')) if format_id != 'legacy-per-host' else None
    if format_id != 'legacy-per-host' and root.get('generated_at') is not None and generated is None:
        diagnostics['MALFORMED_TIMESTAMP'] += 1
    provenance = {'format_id': format_id, 'source_version': source_version, 'origin_ref': origin_ref,
                  'input_sha256': digest, 'original_run_id': root['run_id'] if format_id == FORMATS[2] else None,
                  'original_generated_at': generated}
    b = _Builder(run_id, source, rules, diagnostics)
    for name in sorted(selected):
        hid = evidence.host_id(None, name, run_id=run_id, identity_key=name)
        host = {'host_id': hid, 'target_id': name, 'identity_scope': 'RUN_SCOPED', 'identity_key': name,
                'inventory_authority_id': None, 'host_state': 'ERROR', 'reason_code': 'LEGACY_NO_EVIDENCE'}
        b.hosts.append(host)
        if name in missing:
            host['reason_code'] = 'LEGACY_REPORT_MISSING'
            for scope_key in SCOPES:
                b.scope(hid, scope_key).c['reason_code'] = 'LEGACY_REPORT_MISSING'
            b.gap('LEGACY_REPORT_MISSING')
            continue
        actual = False
        for scope_key, mapper in zip(SCOPES, _MAPPERS):
            scope = b.scope(hid, scope_key)
            mapper(scope, reports[name])
            actual |= scope.finish(disabled.get((name, scope_key)))
        if actual:
            host.update(host_state='PARTIAL', reason_code='LEGACY_COVERAGE_UNKNOWN')
    partial = any(h['host_state'] == 'PARTIAL' for h in b.hosts)
    doc = {'schema_version': '1.0.0', 'run': {'run_id': run_id, 'recorded_at': recorded_at,
           'started_at': None, 'finished_at': None, 'source': source,
           'run_state': 'PARTIAL' if partial else 'ERROR', 'expected_host_ids': [h['host_id'] for h in b.hosts],
           'scope_reason': 'LEGACY_SELECTED_MANIFEST' if format_id == FORMATS[2] else 'LEGACY_SCOPE_UNKNOWN',
           'coverage_reason': 'LEGACY_COVERAGE_UNKNOWN' if partial else 'LEGACY_NO_EVIDENCE'},
           'hosts': b.hosts, 'collections': b.collections, 'assets': b.assets, 'evidence': b.rows,
           'claims': [], 'findings': []}
    try:
        canonical = evidence.canonical_bytes(doc)
    except evidence.EvidenceError as exc:
        raise LegacyImportError('NORMALIZED_' + exc.code) from None
    require(len(canonical) <= MAX_BYTES, 'SIZE_LIMIT')
    normalized = json.loads(canonical)
    del canonical
    # An empty claims/findings registry can fit while the assessed document
    # exceeds Evidence's byte bound. The fixed evaluator already validates and
    # canonicalizes its complete result. Use it once, with the exact caller
    # rules, and discard the assessed result: import remains normalization.
    # Work is bounded by the existing host/scope and evidence limits. With
    # these import-only kinds (no COLLECTION_SUMMARY), each observation can
    # yield at most one claim, one linked finding and one coverage finding;
    # empty scopes add at most one each. No retries or result truncation.
    try:
        assessment.evaluate_document(normalized, rules)
    except evidence.EvidenceError as exc:
        if exc.code == 'SIZE_LIMIT':
            raise LegacyImportError('REASSESSMENT_SIZE_LIMIT') from None
        raise  # unexpected evaluator/validator failures are not capacity errors
    return ImportResult(normalized, provenance, dict(sorted(diagnostics.items())))
