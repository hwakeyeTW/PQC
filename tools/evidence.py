"""PQC Evidence 1.0.0 / 1.1.0: offline model and deterministic identity helpers.

No file, network, command, schema resolver or assessment-engine dependency.
The small field declarations below describe this model only (not an arbitrary
JSON Schema interpreter). The shipped schema is generated from them.
"""
import hashlib
import json
import math
import re
import unicodedata
from datetime import datetime
from typing import NamedTuple

SCHEMA_VERSION = "1.0.0"  # Stable default for existing producers.
LATEST_SCHEMA_VERSION = "1.1.0"
MAX_BYTES = 32 * 1024 * 1024
MAX_DEPTH = 64
MAX_COMPONENT = 512
PREFIXES = {"host": "h-", "asset": "a-", "collection": "c-",
            "evidence": "e-", "claim": "cl-", "finding": "f-"}
NOT_SCANNED_REASONS = frozenset({
    "DISABLED_BY_USER", "DISABLED_BY_PROFILE", "PLAN_ONLY", "AWAITING_COLLECTOR",
    "ADAPTER_NOT_AVAILABLE", "ACTIVE_NOT_AVAILABLE_V2_0", "NOT_ATTEMPTED",
})
ASSESSMENTS = ("PASS", "FAIL", "PARTIAL", "UNKNOWN", "NOT_SCANNED", "NOT_APPLICABLE")
ACQUISITIONS = ("COLLECTED", "PARTIAL", "UNKNOWN", "NOT_SCANNED", "NOT_APPLICABLE",
                "PERMISSION_DENIED", "ERROR", "UNREACHABLE")
LEVELS = ("L1", "L2", "L3", "L4", "L5")
RUN_STATES = ("PLANNED", "COMPLETE", "PARTIAL", "ERROR")
HOST_STATES = ("COMPLETE", "PARTIAL", "ERROR", "UNREACHABLE", "NOT_ATTEMPTED")
REGISTRIES = {"hosts": "host_id", "collections": "collection_id", "assets": "asset_id",
              "evidence": "evidence_id", "claims": "claim_id", "findings": "finding_id"}


class EvidenceError(ValueError):
    """Stable code and model location; never interpolates input values or keys."""
    def __init__(self, code, location="$?"):
        self.code, self.location = code, location
        super().__init__(f"{code} at {location}")


def _require(condition, code, location):
    if not condition:
        raise EvidenceError(code, location)


def _plain(s):
    return not any(unicodedata.category(c) in ("Cc", "Cf", "Cs") for c in s)


_PATH_PREFIX = r"^(?:[A-Za-z]:|[Ff][Ii][Ll][Ee]:|[Hh][Tt][Tt][Pp][Ss]?:|[Ff][Tt][Pp]:|[Ss][Ss][Hh]:|[Ss][Mm][Bb]:|[Dd][Aa][Tt][Aa]:)"


def _key(s):
    return ("/" not in s and "\\" not in s and s not in (".", "..")
            and bool(s.strip()) and re.match(_PATH_PREFIX, s) is None)


def _json_guard(value, depth=1):
    """Bound nesting before encoding, even for cyclic non-JSON input."""
    _require(depth <= MAX_DEPTH, "DEPTH_LIMIT", "$")
    t = type(value)
    if t is dict:
        for k, v in value.items():
            _require(type(k) is str, "TYPE", "$")
            _require(len(k) <= MAX_BYTES and _plain(k), "STRING", "$")
            _json_guard(v, depth + 1)
    elif t is list:
        for v in value:
            _json_guard(v, depth + 1)
    elif t is str:
        _require(len(value) <= MAX_BYTES, "SIZE_LIMIT", "$")
        _require(_plain(value), "STRING", "$")
    elif t is float:
        _require(math.isfinite(value), "NONFINITE", "$")
    elif t is int:
        _require(value.bit_length() <= 256, "INTEGER_LIMIT", "$")
    else:
        _require(value is None or t is bool, "TYPE", "$")


def _encode(value):
    encoder = json.JSONEncoder(ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                               allow_nan=False)
    output = bytearray()
    for chunk in encoder.iterencode(value):
        part = chunk.encode("utf-8")
        _require(len(output) + len(part) <= MAX_BYTES, "SIZE_LIMIT", "$")
        output.extend(part)
    return bytes(output)


def _nesting(raw):
    # Scan the JSON bytes, ignoring delimiters inside quoted/escaped strings.
    depth, quoted, escaped = 0, False, False
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
            depth += 1
            _require(depth <= MAX_DEPTH, "DEPTH_LIMIT", "$")
        elif b in (93, 125):
            depth -= 1


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "DUPLICATE_KEY", "$")
        result[key] = value
    return result


def _int(text):
    _require(len(text.lstrip("-")) <= 77, "INTEGER_LIMIT", "$")
    return int(text)


def _nonfinite(_):
    raise EvidenceError("NONFINITE", "$")


def parse_evidence_bytes(raw: bytes):
    """Parse strict UTF-8 JSON, validate it, and return a fresh document."""
    _require(type(raw) is bytes, "TYPE", "$")
    _require(len(raw) <= MAX_BYTES, "SIZE_LIMIT", "$")
    _nesting(raw)
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                         parse_constant=_nonfinite, parse_int=_int)
    except EvidenceError:
        raise
    except (UnicodeError, ValueError, RecursionError, OverflowError):
        raise EvidenceError("INVALID_JSON", "$") from None
    validate_document(doc)
    return doc


# Model-specific closed field declarations, with parallel standard schema shape.
class _Field(NamedTuple):
    check: object
    schema: dict


_DEFS = {}
_NO_CONTROL = r"^[^\x00-\x1f\x7f-\x9f]+$(?![\s\S])"
_SLUG = r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}"
_TS = r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?(?:Z|\+00:00)"


def _timestamp_key(s):
    base = datetime(int(s[:4]), int(s[5:7]), int(s[8:10]),
                    int(s[11:13]), int(s[14:16]), int(s[17:19]))
    frac = re.match(r"\.(\d+)", s[19:])
    return base, int(frac.group(1).ljust(9, "0")) if frac else 0


def _string(limit=MAX_COMPONENT, pattern=None, logical=False, timestamp=False):
    schema = {"type": "string", "minLength": 1, "maxLength": limit,
              "pattern": _NO_CONTROL}
    if pattern:
        schema["pattern"] = "^(?:" + pattern + r")$(?![\s\S])"
    if logical:
        schema["allOf"] = [{"not": {"pattern": r"[/\\]"}},
                           {"not": {"enum": [".", ".."]}}, {"pattern": r"\S"},
                           {"not": {"pattern": _PATH_PREFIX}}]
    if timestamp:
        schema["format"] = "date-time"

    def check(value, p):
        _require(type(value) is str, "TYPE", p)
        _require(0 < len(value) <= limit and _plain(value), "STRING", p)
        if pattern:
            _require(re.fullmatch(pattern, value) is not None, "FORMAT", p)
        if logical:
            _require(_key(value), "LOGICAL_KEY", p)
        if timestamp:
            try:
                _timestamp_key(value)
            except ValueError:
                raise EvidenceError("TIMESTAMP", p) from None
    return _Field(check, schema)


def _enum(*values):
    def check(value, p):
        _require(type(value) is str, "TYPE", p)
        _require(value in values, "ENUM", p)
    return _Field(check, {"type": "string", "enum": list(values)})


def _nullable(field):
    def check(value, p):
        if value is not None:
            field.check(value, p)
    return _Field(check, {"anyOf": [field.schema, {"type": "null"}]})


def _boolean():
    def check(value, p):
        _require(type(value) is bool, "TYPE", p)
    return _Field(check, {"type": "boolean"})


def _count():
    def check(value, p):
        _require(type(value) is int, "TYPE", p)
        _require(0 <= value <= 9007199254740991, "RANGE", p)
    return _Field(check, {"type": "integer", "minimum": 0, "maximum": 9007199254740991})


def _legacy_scalar():
    integer = {"type": "integer", "minimum": -9007199254740991, "maximum": 9007199254740991}
    def check(value, p):
        if value is None or type(value) is bool:
            return
        if type(value) is int:
            _require(abs(value) <= 9007199254740991, "RANGE", p)
            return
        TEXT.check(value, p)
    return _Field(check, {"anyOf": [TEXT.schema, integer, {"type": "boolean"}, {"type": "null"}]})


def _array(field, unique=False):
    def check(value, p):
        _require(type(value) is list, "TYPE", p)
        for i, item in enumerate(value):
            field.check(item, f"{p}[{i}]")
        if unique:  # only scalar reference sets use this option
            _require(len(set(value)) == len(value), "DUPLICATE_MEMBER", p)
    schema = {"type": "array", "items": field.schema}
    if unique:
        schema["uniqueItems"] = True
    return _Field(check, schema)


def _record(name, fields, optional=None, *, defs=None):
    optional = optional or {}
    all_fields = {**fields, **optional}
    schema = {"type": "object", "additionalProperties": False,
              "required": list(fields), "properties": {k: v.schema for k, v in all_fields.items()}}
    (_DEFS if defs is None else defs)[name] = schema

    def check(value, p):
        _require(type(value) is dict, "TYPE", p)
        _require(not (value.keys() - all_fields.keys()), "UNKNOWN_FIELD", p)
        for k, field in all_fields.items():
            if k not in value:
                _require(k not in fields, "MISSING_FIELD", f"{p}.{k}")
            else:
                field.check(value[k], f"{p}.{k}")
    return _Field(check, {"$ref": "#/$defs/" + name})


def _variant(name, variants, nullable=False, *, defs=None):
    # The caller selects the exact variant using the model discriminator.
    # Variant object shapes can overlap; the enclosing conditional selects the type.
    schema = {"anyOf": [x.schema for x in variants.values()] + ([{"type": "null"}] if nullable else [])}
    (_DEFS if defs is None else defs)[name] = schema
    def check(value, p):
        if nullable and value is None:
            return
        _require(type(value) is dict, "TYPE", p)
    return _Field(check, {"$ref": "#/$defs/" + name})


TEXT = _string()
KEY = _string(logical=True)
SLUG = _string(128, _SLUG)
REF = SLUG  # opaque tokens, never URL/path or percent escapes
VERSION = _string(128, r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}")
REASON = _string(96, r"[A-Z][A-Z0-9_]{0,95}")
STAMP = _string(40, _TS, timestamp=True)
RUN_ID = _string(64, r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
SHA = _string(64, r"[0-9a-f]{64}")
IDS = {k: _string(len(prefix) + 64, prefix + r"[0-9a-f]{64}") for k, prefix in PREFIXES.items()}
SCOPE = _enum("STABLE", "RUN_SCOPED")
SOURCE = _record("source", {"source_kind": _enum("NATIVE_COLLECTOR", "LEGACY_IMPORT", "SYNTHETIC"),
                            "producer_id": SLUG, "producer_version": _nullable(VERSION),
                            "origin_ref": REF, "input_sha256": _nullable(SHA)})
ALGORITHM = _record("algorithm", {"algorithm_id": _nullable(SLUG),
    "family": _enum("CLASSICAL", "PQC", "HYBRID", "UNKNOWN"),
    "primitive": _enum("KEM", "KEX", "SIGNATURE", "PUBLIC_KEY", "SYMMETRIC", "UNKNOWN"),
    "observed_name": _nullable(TEXT), "taxonomy_version": _nullable(VERSION)})
SUBJECT = _record("subject", {"host_id": IDS["host"]},
                  {"asset_id": _nullable(IDS["asset"]), "algorithm_id": _nullable(SLUG)})
RUN = _record("run", {"run_id": RUN_ID, "run_state": _enum(*RUN_STATES), "recorded_at": STAMP,
    "started_at": _nullable(STAMP), "finished_at": _nullable(STAMP), "source": SOURCE,
    "expected_host_ids": _array(IDS["host"], True)}, {"scope_reason": REASON, "coverage_reason": REASON})
HOST = _record("host", {"host_id": IDS["host"], "target_id": _nullable(KEY),
    "identity_scope": SCOPE, "host_state": _enum(*HOST_STATES), "reason_code": REASON,
    "inventory_authority_id": _nullable(REF), "identity_key": _nullable(KEY)})
COLLECTION = _record("collection", {"collection_id": IDS["collection"], "host_id": IDS["host"],
    "collector_id": SLUG, "collector_version": _nullable(VERSION), "scope_key": KEY,
    "collection_state": _enum(*ACQUISITIONS), "reason_code": REASON, "source": SOURCE,
    "observed_at": _nullable(STAMP), "evidence_ids": _array(IDS["evidence"], True)})
ASSET = _record("asset", {"asset_id": IDS["asset"], "host_id": IDS["host"],
    "asset_kind": _string(64, r"[a-z][a-z0-9_-]{0,63}"), "identity_scope": SCOPE,
    "identity_key": KEY, "evidence_ids": _array(IDS["evidence"], True)})
NEG_FIELDS = {"host_id": IDS["host"], "service_asset_id": IDS["asset"], "endpoint_ref": REF,
              "protocol": _enum("TLS", "SSH"), "context_ref": REF, "authorization_ref": REF}
USE_FIELDS = {"host_id": IDS["host"], "service_asset_id": IDS["asset"], "business_source_ref": REF,
              "method": _enum("APPLICATION_TELEMETRY", "PASSIVE_SESSION_OBSERVATION", "SERVICE_AUDIT_RECORD"),
              "started_at": STAMP, "finished_at": STAMP}
NEG = _record("negotiation_conditions", NEG_FIELDS)
USE = _record("usage_conditions", USE_FIELDS)
_PACKAGE_FIELDS = {"name": TEXT, "version": _nullable(TEXT), "present": _nullable(_boolean())}
DATA = {
    "PLATFORM_INFO": _record("platform_data", {"os_family": _nullable(TEXT), "os_version": _nullable(TEXT)}),
    "PACKAGE_INVENTORY": _record("package_data", _PACKAGE_FIELDS),
    "RUNTIME_CAPABILITY": _record("runtime_data", {"capability": SLUG, "supported": _nullable(_boolean())}),
    "EFFECTIVE_CONFIGURATION": _record("configuration_data", {"setting": SLUG, "effective_value": _nullable(TEXT),
                                                                  "allowed": _nullable(_boolean())}),
    "AUTHORIZED_NEGOTIATION": _record("negotiation_data", {"conditions": NEG,
        "outcome": _enum("NEGOTIATED", "REJECTED", "UNKNOWN", "ERROR", "TIMEOUT")}),
    "OBSERVED_USAGE": _record("usage_data", {"conditions": USE, "outcome": _enum("OBSERVED", "CONTRADICTED", "UNKNOWN")}),
    "ASSET_METADATA": _record("asset_data", {"name": _nullable(TEXT), "version": _nullable(TEXT)}),
    "COLLECTION_SUMMARY": _record("summary_data", {"scope": KEY, "attempted": _nullable(_boolean()),
        "coverage": _enum("COMPLETE", "PARTIAL", "UNKNOWN"), "observation_count": _nullable(_count()),
        "applicable": _nullable(_boolean())}),
    "LEGACY_OBSERVATION": _record("legacy_data", {"field": SLUG, "value": _legacy_scalar()}),
}


def _evidence_shape(data, *, defs=None):
    return _record("evidence", {"evidence_id": IDS["evidence"], "host_id": IDS["host"],
        "collection_id": IDS["collection"], "asset_id": _nullable(IDS["asset"]), "observation_key": KEY,
        "evidence_kind": _enum(*data), "source": SOURCE, "observed_at": _nullable(STAMP),
        "data": _variant("evidence_data", data, defs=defs), "algorithm": _nullable(ALGORITHM)},
        {"evidence_ref": _nullable(REF), "raw_sha256": _nullable(SHA)}, defs=defs)


EVIDENCE = _evidence_shape(DATA)
CLAIM = _record("claim", {"claim_id": IDS["claim"], "subject": SUBJECT, "claim_key": KEY,
    "level": _enum(*LEVELS), "assessment_state": _enum(*ASSESSMENTS), "rule_id": SLUG,
    "rule_version": VERSION, "reason_code": REASON, "evidence_ids": _array(IDS["evidence"], True),
    "conditions": _variant("claim_conditions", {"L4": NEG, "L5": USE}, True)})
FINDING = _record("finding", {"finding_id": IDS["finding"], "subject": SUBJECT,
    "condition_key": KEY, "rule_id": SLUG, "rule_version": VERSION,
    "assessment_state": _enum(*ASSESSMENTS), "reason_code": REASON,
    "claim_ids": _array(IDS["claim"], True), "evidence_ids": _array(IDS["evidence"], True)})


def _document_shape(version, evidence, *, defs=None):
    return _record("document", {"schema_version": _enum(version), "run": RUN,
        "hosts": _array(HOST), "collections": _array(COLLECTION), "assets": _array(ASSET),
        "evidence": _array(evidence), "claims": _array(CLAIM), "findings": _array(FINDING)}, defs=defs)


DOCUMENT = _document_shape(SCHEMA_VERSION, EVIDENCE)

# Standard schema conditionals are emitted from the model discriminators.
def _conditional(field, value, properties):
    return {"if": {"properties": {field: {"const": value}}, "required": [field]},
            "then": {"properties": properties}}


_DEFS["evidence"]["allOf"] = [_conditional("evidence_kind", kind, {"data": shape.schema})
                              for kind, shape in DATA.items()]
_DEFS["claim"]["allOf"] = [_conditional("level", level, {"conditions": (
    NEG.schema if level == "L4" else USE.schema if level == "L5" else {"type": "null"})})
    for level in LEVELS]
_DEFS["host"]["allOf"] = [
    _conditional("identity_scope", "STABLE", {"target_id": KEY.schema,
                 "inventory_authority_id": REF.schema, "identity_key": {"type": "null"}}),
    _conditional("identity_scope", "RUN_SCOPED", {"inventory_authority_id": {"type": "null"},
                                                  "identity_key": KEY.schema}),
]


# Build the second version once. Shared definitions are read-only by convention;
# replace the changed definitions in a separate mapping, never switch global state.
_DEFS_11 = dict(_DEFS)
_NORMALIZED_SLUG = _string(64, r"[a-z0-9][a-z0-9_-]{0,63}")
_DECIMAL_COMPONENT = r"(?:0|[1-9][0-9]{0,15})"
_OS_VERSION = _string(50, _DECIMAL_COMPONENT + r"(?:\." + _DECIMAL_COMPONENT + r"){0,2}")
_METADATA_KINDS = ("PLATFORM_INFO", "TOOL_AVAILABILITY")
_TOOL_IDS = ("rpm", "openssl", "ssh", "sshd", "ssh-keygen", "update-crypto-policies", "timeout")
_DATA_11 = {
    **DATA,
    "PLATFORM_INFO": _record("platform_data", {
        "os_family": _nullable(_NORMALIZED_SLUG), "os_version": _nullable(_OS_VERSION),
        "distribution": _nullable(_NORMALIZED_SLUG), "major": _nullable(_count()),
        "minor": _nullable(_count()), "patch": _nullable(_count()),
        "architecture": _nullable(_NORMALIZED_SLUG),
        "platform_status": _enum("UNVERIFIED", "OUT_OF_SCOPE", "UNKNOWN"),
    }, defs=_DEFS_11),
    "PACKAGE_INVENTORY": _record("package_data", _PACKAGE_FIELDS, {
        "release": _nullable(VERSION), "architecture": _nullable(_NORMALIZED_SLUG),
    }, defs=_DEFS_11),
    "TOOL_AVAILABILITY": _record("tool_availability_data", {
        "tool_id": _enum(*_TOOL_IDS), "lookup_scope": _enum("SYSTEM_EXECUTABLE_PATHS"),
        "available": _nullable(_boolean()),
    }, defs=_DEFS_11),
}
_EVIDENCE_11 = _evidence_shape(_DATA_11, defs=_DEFS_11)
_DOCUMENT_11 = _document_shape(LATEST_SCHEMA_VERSION, _EVIDENCE_11, defs=_DEFS_11)
_DEFS_11["evidence"]["allOf"] = [
    _conditional("evidence_kind", kind, {"data": shape.schema, **(
        {"asset_id": {"type": "null"}, "algorithm": {"type": "null"}}
        if kind in _METADATA_KINDS else {})})
    for kind, shape in _DATA_11.items()
]
_DEFS_11["package_data"]["allOf"] = [{
    "if": {"anyOf": [{"required": [key], "properties": {key: {"not": {"type": "null"}}}}
                     for key in ("release", "architecture")]},
    "then": {"properties": {"present": {"const": True}}},
}]
_MODELS = {
    SCHEMA_VERSION: (DOCUMENT, DATA, _DEFS),
    LATEST_SCHEMA_VERSION: (_DOCUMENT_11, _DATA_11, _DEFS_11),
}


def _model(schema_version):
    _require(type(schema_version) is str and schema_version in _MODELS,
             "SCHEMA_VERSION", "$.schema_version")
    return _MODELS[schema_version]


def model_schema(schema_version=SCHEMA_VERSION):
    """Return an independent local schema snapshot; default remains 1.0.0."""
    document, _, defs = _model(schema_version)
    return json.loads(json.dumps({"$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:pqc:evidence:" + schema_version, **document.schema, "$defs": defs}))


# ID-V1: no path, order index, timestamp or connection-address substitution.
def derive_id(kind, components):
    """SHA-256 of [pqc-id-v1, kind, ...] in canonical UTF-8 JSON.

    Components are nonempty bounded literal strings or explicit null tags for
    optional subject parts. Null is not a valid standalone identity.
    """
    _require(type(kind) is str and kind in PREFIXES, "ID_KIND", "$id")
    _require(type(components) in (list, tuple) and 0 < len(components) <= 32,
             "ID_COMPONENTS", "$id")
    _require(any(x is not None for x in components), "ID_COMPONENTS", "$id")
    for i, item in enumerate(components):
        if item is not None:
            KEY.check(item, f"$id[{i}]")
    raw = json.dumps(["pqc-id-v1", kind, *components], ensure_ascii=False,
                     separators=(",", ":"), allow_nan=False).encode("utf-8")
    return PREFIXES[kind] + hashlib.sha256(raw).hexdigest()


def host_id(inventory_authority_id, target_id, *, run_id=None, identity_key=None):
    if inventory_authority_id is not None:
        REF.check(inventory_authority_id, "$id.authority")
        KEY.check(target_id, "$id.target")
        _require(identity_key is None, "IDENTITY_SCOPE", "$id")
        return derive_id("host", ["STABLE", inventory_authority_id, target_id])
    RUN_ID.check(run_id, "$id.run")
    KEY.check(identity_key, "$id.identity_key")
    if target_id is not None:
        KEY.check(target_id, "$id.target")
    return derive_id("host", ["RUN_SCOPED", run_id, identity_key])


def asset_id(host, kind, identity_key, *, run_id=None):
    IDS["host"].check(host, "$id.host")
    _string(64, r"[a-z][a-z0-9_-]{0,63}").check(kind, "$id.kind")
    KEY.check(identity_key, "$id.identity_key")
    if run_id is not None:
        RUN_ID.check(run_id, "$id.run")
    return derive_id("asset", ["STABLE", host, kind, identity_key] if run_id is None else
                     ["RUN_SCOPED", run_id, host, kind, identity_key])


def collection_id(run_id, host, collector, scope_key):
    RUN_ID.check(run_id, "$id.run")
    IDS["host"].check(host, "$id.host")
    SLUG.check(collector, "$id.collector")
    KEY.check(scope_key, "$id.scope")
    return derive_id("collection", [run_id, host, collector, scope_key])


def evidence_id(run_id, host, collection, observation_key):
    RUN_ID.check(run_id, "$id.run")
    IDS["host"].check(host, "$id.host")
    IDS["collection"].check(collection, "$id.collection")
    KEY.check(observation_key, "$id.observation")
    return derive_id("evidence", [run_id, host, collection, observation_key])


def _subject_parts(subject):
    SUBJECT.check(subject, "$id.subject")
    return [subject["host_id"], subject.get("asset_id"), subject.get("algorithm_id")]


def _conditions_parts(level, conditions, p):
    if level == "L4":
        NEG.check(conditions, p)
        return [conditions[k] for k in NEG_FIELDS]
    if level == "L5":
        USE.check(conditions, p)
        _require(_timestamp_key(conditions["started_at"]) <= _timestamp_key(conditions["finished_at"]),
                 "TIME_ORDER", p)
        return [conditions[k] for k in USE_FIELDS]
    _require(conditions is None, "CONDITIONS", p)
    return []


def claim_id(run_id, subject, level, rule_id, claim_key, conditions=None):
    RUN_ID.check(run_id, "$id.run")
    _enum(*LEVELS).check(level, "$id.level")
    SLUG.check(rule_id, "$id.rule")
    KEY.check(claim_key, "$id.claim_key")
    return derive_id("claim", [run_id, *_subject_parts(subject), level, rule_id, claim_key,
                               *_conditions_parts(level, conditions, "$id.conditions")])


def finding_id(subject, rule_id, condition_key):
    SLUG.check(rule_id, "$id.rule")
    KEY.check(condition_key, "$id.condition_key")
    return derive_id("finding", [*_subject_parts(subject), rule_id, condition_key])


# Cross-record semantics. All error locations use fixed field names/indices.
def _index(doc, registry):
    result = {}
    field = REGISTRIES[registry]
    for i, row in enumerate(doc[registry]):
        _require(row[field] not in result, "DUPLICATE_ID", f"$.{registry}[{i}].{field}")
        result[row[field]] = row
    return result


def _lookup(index, key, p):
    _require(key in index, "DANGLING_REF", p)
    return index[key]


def _id_matches(actual, expected, p):
    _require(actual == expected, "ID_MISMATCH", p)


def _source_matches(source, run_source, p):
    _require((source["source_kind"] == "SYNTHETIC") == (run_source["source_kind"] == "SYNTHETIC"),
             "SYNTHETIC_MIX", p)


def _observed(row, run_source, p, acquired=True):
    _source_matches(row["source"], run_source, p + ".source")
    if acquired and row["source"]["source_kind"] != "LEGACY_IMPORT":
        _require(row["observed_at"] is not None, "OBSERVED_AT_REQUIRED", p + ".observed_at")


def _nontrivial(e):
    kind, d = e["evidence_kind"], e["data"]
    if kind == "PACKAGE_INVENTORY":
        return d["present"] is not None
    if kind == "RUNTIME_CAPABILITY":
        return d["supported"] is not None
    if kind == "EFFECTIVE_CONFIGURATION":
        return d["allowed"] is not None or d["effective_value"] is not None
    if kind == "AUTHORIZED_NEGOTIATION":
        return d["outcome"] in ("NEGOTIATED", "REJECTED")
    if kind == "OBSERVED_USAGE":
        return d["outcome"] in ("OBSERVED", "CONTRADICTED")
    if kind == "COLLECTION_SUMMARY":
        return (d["applicable"] is False or (d["attempted"] is True and
                d["coverage"] != "UNKNOWN" and d["observation_count"] is not None))
    if kind == "PLATFORM_INFO":
        # Status is derived metadata, not an acquired observation by itself.
        return any(v is not None for k, v in d.items() if k != "platform_status")
    if kind == "TOOL_AVAILABILITY":
        return d["available"] is not None
    if kind == "ASSET_METADATA":
        return any(v is not None for v in d.values())
    return False  # unclassified legacy metadata is not a direct assertion


def _verdict_observation(e):
    kind, d = e["evidence_kind"], e["data"]
    if kind == "EFFECTIVE_CONFIGURATION":
        return d["allowed"] is not None
    return kind in ("PACKAGE_INVENTORY", "RUNTIME_CAPABILITY", "AUTHORIZED_NEGOTIATION",
                    "OBSERVED_USAGE") and _nontrivial(e)


def _known_collection(e):
    if e["evidence_kind"] != "COLLECTION_SUMMARY":
        return _nontrivial(e)
    d = e["data"]
    return (d["attempted"] is True and d["applicable"] is True and
            d["coverage"] == "COMPLETE" and d["observation_count"] is not None)


def _applicability(e):
    return e["evidence_kind"] == "COLLECTION_SUMMARY" and e["data"]["applicable"] is False


def _subject_check(subject, hosts, assets, p):
    _lookup(hosts, subject["host_id"], p + ".host_id")
    if subject.get("asset_id") is not None:
        asset = _lookup(assets, subject["asset_id"], p + ".asset_id")
        _require(asset["host_id"] == subject["host_id"], "CROSS_HOST", p + ".asset_id")


def _subject_evidence(subject, row, p):
    _require(row["host_id"] == subject["host_id"], "CROSS_HOST", p)
    _require(row["asset_id"] == subject.get("asset_id"), "UNRELATED_ASSET", p)
    if subject.get("algorithm_id") is not None:
        _require(row["algorithm"] is not None and row["algorithm"]["algorithm_id"] == subject["algorithm_id"],
                 "UNRELATED_ALGORITHM", p)


def _context_check(context, subject, assets, p):
    _require(context["host_id"] == subject["host_id"], "CROSS_HOST", p)
    _require(context["service_asset_id"] == subject.get("asset_id"), "UNRELATED_ASSET", p)
    service = _lookup(assets, context["service_asset_id"], p)
    _require(service["host_id"] == context["host_id"] and service["asset_kind"] == "service",
             "SERVICE_REQUIRED", p)


def _state_reason(state, reason, p):
    if state == "NOT_SCANNED":
        _require(reason in NOT_SCANNED_REASONS, "NOT_SCANNED_REASON", p)
    if state in ("PARTIAL", "NOT_APPLICABLE"):
        _require(reason not in ("OK", "SUCCESS", "COLLECTED", "PASS", "FAIL"), "GAP_REASON", p)


def _usable(row, collections):
    return collections[row["collection_id"]]["collection_state"] in ("COLLECTED", "PARTIAL")


def _na_usable(row, collections):
    return collections[row["collection_id"]]["collection_state"] in ("COLLECTED", "PARTIAL", "NOT_APPLICABLE") and _applicability(row)


def _supports_claim(claim, row, collections):
    if not _usable(row, collections):
        return False
    kind, d = row["evidence_kind"], row["data"]
    positive = claim["assessment_state"] == "PASS"
    level = claim["level"]
    if level == "L1":
        return kind == "PACKAGE_INVENTORY" and d["present"] is positive
    if level == "L2":
        return kind == "RUNTIME_CAPABILITY" and d["supported"] is positive
    if level == "L3":
        return kind == "EFFECTIVE_CONFIGURATION" and d["allowed"] is positive
    if (row["observed_at"] is None or row["algorithm"] is None or
            row["algorithm"]["primitive"] == "UNKNOWN" or claim["subject"].get("algorithm_id") is None):
        return False
    if level == "L4":
        return (kind == "AUTHORIZED_NEGOTIATION" and d["conditions"] == claim["conditions"] and
                d["outcome"] == ("NEGOTIATED" if positive else "REJECTED"))
    return (kind == "OBSERVED_USAGE" and d["conditions"] == claim["conditions"] and
            d["outcome"] == ("OBSERVED" if positive else "CONTRADICTED"))


def _platform_status(data):
    distribution, family = data["distribution"], data["os_family"]
    major, minor = data["major"], data["minor"]
    if distribution is None:
        return "UNKNOWN"
    if distribution != "oracle-linux":
        return "OUT_OF_SCOPE"
    if family not in (None, "redhat") or major is None:
        return "UNKNOWN"
    if major != 9:
        return "OUT_OF_SCOPE"
    return "UNVERIFIED" if minor is not None else "UNKNOWN"


def _validate_extended_data(row, p):
    kind, data = row["evidence_kind"], row["data"]
    if kind in _METADATA_KINDS:
        _require(row["asset_id"] is None and row["algorithm"] is None,
                 "METADATA_ASSOCIATION", p)
    if kind == "PLATFORM_INFO":
        major, minor, patch = (data[k] for k in ("major", "minor", "patch"))
        _require((minor is None or major is not None) and (patch is None or minor is not None),
                 "PLATFORM_VERSION", p + ".data")
        expected = ".".join(str(v) for v in (major, minor, patch) if v is not None) or None
        _require(data["os_version"] == expected, "PLATFORM_VERSION", p + ".data.os_version")
        _require(data["platform_status"] == _platform_status(data),
                 "PLATFORM_STATUS", p + ".data.platform_status")
    if kind == "PACKAGE_INVENTORY" and any(data.get(k) is not None for k in ("release", "architecture")):
        _require(data["present"] is True, "PACKAGE_PRESENCE", p + ".data.present")


def validate_document(document):
    """Validate shape and semantic invariants without mutation; return None."""
    _json_guard(document)
    _encode(document)  # enforce the same byte budget for in-memory callers
    version = document.get("schema_version", SCHEMA_VERSION) if type(document) is dict else SCHEMA_VERSION
    shape, data_shapes, _ = _model(version)
    shape.check(document, "$")
    run = document["run"]
    rid, run_source = run["run_id"], run["source"]
    if run["started_at"] is not None and run["finished_at"] is not None:
        _require(_timestamp_key(run["started_at"]) <= _timestamp_key(run["finished_at"]), "TIME_ORDER", "$.run")
    hosts, collections, assets, evidence, claims, findings = (_index(document, k) for k in REGISTRIES)
    collection_refs = {k: set(c["evidence_ids"]) for k, c in collections.items()}
    asset_refs = {k: set(a["evidence_ids"]) for k, a in assets.items()}
    _require(set(run["expected_host_ids"]) == hosts.keys(), "HOST_MANIFEST", "$.run.expected_host_ids")
    if run["run_state"] == "COMPLETE":
        _require(bool(hosts) and all(h["host_state"] == "COMPLETE" for h in hosts.values()), "RUN_STATE", "$.run")
    if run["run_state"] == "PLANNED":
        _require(all(h["host_state"] == "NOT_ATTEMPTED" for h in hosts.values()), "RUN_STATE", "$.run")
    for i, h in enumerate(document["hosts"]):
        p = f"$.hosts[{i}]"
        stable = h["identity_scope"] == "STABLE"
        _require((stable and h["inventory_authority_id"] is not None and h["target_id"] is not None and h["identity_key"] is None) or
                 (not stable and h["inventory_authority_id"] is None and h["identity_key"] is not None), "IDENTITY_SCOPE", p)
        _id_matches(h["host_id"], host_id(h["inventory_authority_id"], h["target_id"], run_id=rid,
                                         identity_key=h["identity_key"]), p + ".host_id")
    for i, a in enumerate(document["assets"]):
        p = f"$.assets[{i}]"
        h = _lookup(hosts, a["host_id"], p + ".host_id")
        stable = a["identity_scope"] == "STABLE"
        _require(not stable or (h["identity_scope"] == "STABLE" and a["asset_kind"] != "unknown"), "IDENTITY_SCOPE", p)
        _id_matches(a["asset_id"], asset_id(a["host_id"], a["asset_kind"], a["identity_key"],
                                           run_id=None if stable else rid), p + ".asset_id")
        _require(bool(a["evidence_ids"]), "ASSET_EVIDENCE_REQUIRED", p)
        for ref in a["evidence_ids"]:
            e = _lookup(evidence, ref, p + ".evidence_ids")
            _require(e["host_id"] == a["host_id"], "CROSS_HOST", p)
            _require(e["asset_id"] == a["asset_id"], "UNRELATED_ASSET", p)
    for i, c in enumerate(document["collections"]):
        p = f"$.collections[{i}]"
        h = _lookup(hosts, c["host_id"], p + ".host_id")
        state = c["collection_state"]
        _id_matches(c["collection_id"], collection_id(rid, c["host_id"], c["collector_id"], c["scope_key"]), p + ".collection_id")
        _observed(c, run_source, p, acquired=state in ("COLLECTED", "PARTIAL", "NOT_APPLICABLE"))
        if c["source"]["source_kind"] != "LEGACY_IMPORT":
            _require(c["collector_id"] == c["source"]["producer_id"] and
                     c["collector_version"] == c["source"]["producer_version"], "COLLECTOR_SOURCE", p)
            if state in ("COLLECTED", "PARTIAL", "NOT_APPLICABLE"):
                _require(c["collector_version"] is not None, "COLLECTOR_SOURCE", p)
        _state_reason(state, c["reason_code"], p + ".reason_code")
        if h["host_state"] == "NOT_ATTEMPTED":
            _require(state == "NOT_SCANNED", "HOST_STATE", p)
        if h["host_state"] == "UNREACHABLE":
            _require(state in ("UNREACHABLE", "NOT_SCANNED", "UNKNOWN"), "HOST_STATE", p)
        rows = [_lookup(evidence, ref, p + ".evidence_ids") for ref in c["evidence_ids"]]
        for e in rows:
            _require(e["host_id"] == c["host_id"], "CROSS_HOST", p)
            _require(e["collection_id"] == c["collection_id"], "COLLECTION_BACKREF", p)
        if state == "NOT_SCANNED":
            _require(not rows, "UNATTEMPTED_EVIDENCE", p)
        # Data variants are checked below before reading their typed values.
    for i, e in enumerate(document["evidence"]):
        p = f"$.evidence[{i}]"
        data_shapes[e["evidence_kind"]].check(e["data"], p + ".data")
        if version == LATEST_SCHEMA_VERSION:
            _validate_extended_data(e, p)
        _lookup(hosts, e["host_id"], p + ".host_id")
        c = _lookup(collections, e["collection_id"], p + ".collection_id")
        _require(c["host_id"] == e["host_id"], "CROSS_HOST", p)
        _require(e["evidence_id"] in collection_refs[c["collection_id"]], "COLLECTION_BACKREF", p)
        _id_matches(e["evidence_id"], evidence_id(rid, e["host_id"], e["collection_id"], e["observation_key"]), p + ".evidence_id")
        _observed(e, run_source, p)
        _require(all(e["source"][k] == c["source"][k] for k in ("source_kind", "producer_id", "producer_version")),
                 "EVIDENCE_SOURCE", p + ".source")
        if e["asset_id"] is not None:
            a = _lookup(assets, e["asset_id"], p + ".asset_id")
            _require(a["host_id"] == e["host_id"], "CROSS_HOST", p)
            _require(e["evidence_id"] in asset_refs[a["asset_id"]], "ASSET_BACKREF", p)
        if e["evidence_kind"] in ("AUTHORIZED_NEGOTIATION", "OBSERVED_USAGE"):
            level = "L4" if e["evidence_kind"] == "AUTHORIZED_NEGOTIATION" else "L5"
            context = e["data"]["conditions"]
            _conditions_parts(level, context, p + ".data.conditions")
            _context_check(context, e, assets, p + ".data.conditions")
            if _nontrivial(e):
                _require(e["observed_at"] is not None and e["algorithm"] is not None and
                         e["algorithm"]["algorithm_id"] is not None and e["algorithm"]["primitive"] != "UNKNOWN",
                         "ACTUAL_ALGORITHM_REQUIRED", p)
                if level == "L5":
                    # Actual usage must already have occurred when documented.
                    # Observation may be inside the interval or retrospective.
                    observed = _timestamp_key(e["observed_at"])
                    recorded = _timestamp_key(run["recorded_at"])
                    _require(_timestamp_key(context["started_at"]) <= observed <= recorded and
                             _timestamp_key(context["finished_at"]) <= recorded,
                             "USAGE_TIME_ORDER", p + ".data.conditions")
        if e["evidence_kind"] == "COLLECTION_SUMMARY":
            d = e["data"]
            # V1 has no scope hierarchy: every summary describes its parent scope.
            _require(d["scope"] == c["scope_key"], "SCOPE_MISMATCH", p + ".data.scope")
            if d["coverage"] != "UNKNOWN":
                _require(d["attempted"] is True and d["applicable"] is True and d["observation_count"] is not None,
                         "COVERAGE_EVIDENCE", p)
            if d["applicable"] is False:
                _require(d["coverage"] == "UNKNOWN" and d["observation_count"] is None, "APPLICABILITY", p)
    for i, c in enumerate(document["collections"]):
        p = f"$.collections[{i}]"
        rows = [evidence[ref] for ref in c["evidence_ids"]]
        state = c["collection_state"]
        if state == "COLLECTED":
            _require(any(_known_collection(e) for e in rows), "COLLECTION_EVIDENCE_REQUIRED", p)
        elif state == "PARTIAL":
            _require(any(_nontrivial(e) and not _applicability(e) for e in rows), "PARTIAL_EVIDENCE_REQUIRED", p)
        elif state == "NOT_APPLICABLE":
            _require(any(_applicability(e) for e in rows), "APPLICABILITY_EVIDENCE_REQUIRED", p)
    for i, a in enumerate(document["assets"]):
        if a["identity_scope"] == "STABLE":
            _require(any(_usable(evidence[ref], collections) and _nontrivial(evidence[ref])
                         for ref in a["evidence_ids"]), "STABLE_ASSET_EVIDENCE", f"$.assets[{i}]")
    for i, cl in enumerate(document["claims"]):
        p = f"$.claims[{i}]"
        subject, level, state = cl["subject"], cl["level"], cl["assessment_state"]
        _subject_check(subject, hosts, assets, p + ".subject")
        _conditions_parts(level, cl["conditions"], p + ".conditions")
        if level in ("L4", "L5"):
            _context_check(cl["conditions"], subject, assets, p + ".conditions")
        _id_matches(cl["claim_id"], claim_id(rid, subject, level, cl["rule_id"], cl["claim_key"], cl["conditions"]), p + ".claim_id")
        _state_reason(state, cl["reason_code"], p + ".reason_code")
        rows = [_lookup(evidence, ref, p + ".evidence_ids") for ref in cl["evidence_ids"]]
        for e in rows:
            _subject_evidence(subject, e, p + ".evidence_ids")
        if state in ("PASS", "FAIL"):
            _require(any(_supports_claim(cl, e, collections) for e in rows), "CLAIM_EVIDENCE_REQUIRED", p)
            opposite = {**cl, "assessment_state": "FAIL" if state == "PASS" else "PASS"}
            _require(not any(_supports_claim(opposite, e, collections) for e in rows), "CONFLICTING_EVIDENCE", p)
        elif state == "PARTIAL":
            _require(any(_usable(e, collections) and _nontrivial(e) and not _applicability(e) for e in rows), "PARTIAL_EVIDENCE_REQUIRED", p)
        elif state == "NOT_APPLICABLE":
            _require(any(_na_usable(e, collections) for e in rows), "APPLICABILITY_EVIDENCE_REQUIRED", p)
        elif state == "NOT_SCANNED":
            _require(not rows, "UNATTEMPTED_EVIDENCE", p)
    for i, f in enumerate(document["findings"]):
        p = f"$.findings[{i}]"
        subject, state = f["subject"], f["assessment_state"]
        _subject_check(subject, hosts, assets, p + ".subject")
        _id_matches(f["finding_id"], finding_id(subject, f["rule_id"], f["condition_key"]), p + ".finding_id")
        _state_reason(state, f["reason_code"], p + ".reason_code")
        links = [_lookup(claims, ref, p + ".claim_ids") for ref in f["claim_ids"]]
        rows = [_lookup(evidence, ref, p + ".evidence_ids") for ref in f["evidence_ids"]]
        for cl in links:
            _require(_subject_parts(cl["subject"]) == _subject_parts(subject), "UNRELATED_SUBJECT", p)
            _require((cl["rule_id"], cl["rule_version"]) == (f["rule_id"], f["rule_version"]), "UNRELATED_RULE", p)
        for e in rows:
            _subject_evidence(subject, e, p + ".evidence_ids")
        matching = any(cl["assessment_state"] == state for cl in links)
        if state in ("PASS", "FAIL"):
            # A rule evaluator (#11) must supply the verdict. #10 only checks
            # that a relevant actual observation or matching claim exists.
            _require(matching or any(_usable(e, collections) and _verdict_observation(e)
                                     for e in rows), "FINDING_EVIDENCE_REQUIRED", p)
        elif state == "PARTIAL":
            _require(matching or any(_usable(e, collections) and _nontrivial(e) and
                                     not _applicability(e) for e in rows), "PARTIAL_EVIDENCE_REQUIRED", p)
        elif state == "NOT_APPLICABLE":
            _require(matching or any(_na_usable(e, collections) for e in rows), "APPLICABILITY_EVIDENCE_REQUIRED", p)
        elif state == "NOT_SCANNED":
            _require(not rows and all(cl["assessment_state"] == state for cl in links), "UNATTEMPTED_EVIDENCE", p)


def canonical_bytes(document):
    """Validate then sort registry/set fields; no I/O or mutation of input."""
    validate_document(document)
    clone = {**document, "run": {**document["run"],
                                 "expected_host_ids": sorted(document["run"]["expected_host_ids"])}}
    for registry, key in REGISTRIES.items():
        rows = []
        for row in sorted(document[registry], key=lambda r: r[key]):
            rows.append({k: sorted(v) if k in ("evidence_ids", "claim_ids") else v for k, v in row.items()})
        clone[registry] = rows
    return _encode(clone)
