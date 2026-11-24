"""Pure Controller normalization for #16, not runtime policy or dispatch proof."""
import hashlib
import json
import re

from tools import assessment, evidence as ev, platform

COLLECTOR = "pqc-crypto-policy"
COLLECTOR_VERSION = "1.0.0"

# BEGIN SHARED POLICY GRAMMAR (also embedded in the fixed acquisition helper)
FILE_LIMIT = 16 * 1024
TOTAL_LIMIT = 64 * 1024
MAX_VALUES = 64
MAX_ENTRIES = 32
BACKENDS = ("openssh", "opensshserver", "openssl", "opensslcnf")
SCOPES = ("profile-config", "profile-show", "kernel-fips", "current-policy",
          *("backend-" + k for k in BACKENDS), "local-overrides")
PROFILE = re.compile(r"[A-Z0-9][A-Z0-9_-]{0,31}(?::[A-Z0-9][A-Z0-9_-]{0,31}){0,3}", re.ASCII)
TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,95}", re.ASCII)
# '+' can be an operator. Never interpret cipher aliases, globbing or exclusions.
POLICY_FIELDS = {"cipher": "cipher", "group": "group", "sign": "sign",
                 "key_exchange": "key-exchange", "protocol": "protocol"}
SSH_FIELDS = {"ciphers": "ciphers", "kexalgorithms": "kex-algorithms",
              "hostkeyalgorithms": "host-key-algorithms", "pubkeyacceptedalgorithms": "pubkey-accepted-algorithms"}
SSL_FIELDS = {"cipherstring": "cipher-string", "ciphersuites": "cipher-suites",
              "minprotocol": "min-protocol"}
PROTOCOLS = frozenset(("TLSv1", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3", "DTLSv1", "DTLSv1.2"))


def result(state, reason, values=(), *, rc=None, overrides=()):
    return dict(state=state, reason=reason, rc=rc, values=list(values), overrides=list(overrides))


def fields_for(scope):
    if scope == "current-policy":
        return frozenset(POLICY_FIELDS.values())
    if scope in ("backend-openssh", "backend-opensshserver"):
        return frozenset(SSH_FIELDS.values())
    if scope in ("backend-openssl", "backend-opensslcnf"):
        return frozenset(SSL_FIELDS.values())
    return frozenset()


def valid_token(field, value):
    if type(value) is not str or not TOKEN.fullmatch(value):
        return False
    if field == "min-protocol":
        return value in PROTOCOLS
    if field == "cipher-suites":
        return re.fullmatch(r"TLS_[A-Z0-9_]+", value, re.ASCII) is not None
    if field == "cipher-string":
        # Only explicit suite spellings, not OpenSSL selector expressions.
        return re.fullmatch(r"(?:TLS_[A-Z0-9_]+|[A-Z0-9]+(?:-[A-Z0-9]+){2,})", value, re.ASCII) is not None
    return True


def parse_source(scope, raw, *, rc=None):
    """Parse a single bounded fixed source; never return raw text or paths."""
    if scope not in SCOPES[:-1] or type(raw) is not bytes:
        return result("ERROR", "MALFORMED_OUTPUT", rc=rc)
    if len(raw) > FILE_LIMIT:
        return result("ERROR", "OUTPUT_LIMIT", rc=rc)
    if scope == "profile-show" and (type(rc) is not int or rc != 0):
        return result("ERROR", "COMMAND_FAILED", rc=rc)
    if scope != "profile-show" and rc is not None:
        return result("ERROR", "MALFORMED_OUTPUT")
    try:
        text = raw.decode("ascii")
    except UnicodeError:
        return result("UNKNOWN", "UNSUPPORTED_SYNTAX", rc=rc)
    if any(ord(c) < 32 and c not in "\n\t" or ord(c) == 127 for c in text):
        return result("UNKNOWN", "UNSUPPORTED_SYNTAX", rc=rc)
    if scope in ("profile-config", "profile-show"):
        # Only a single exact token, optionally terminated by one LF.
        if scope == "profile-config":
            lines = [line.strip(" \t") for line in text.split("\n")
                     if line.strip(" \t") and not line.lstrip(" \t").startswith("#")]
            token = lines[0] if len(lines) == 1 else ""
        else:
            token = text.removesuffix("\n")
        if PROFILE.fullmatch(token):
            return result("COLLECTED", "OK", [["profile", token]], rc=rc)
        return result("UNKNOWN", "AMBIGUOUS_PROFILE", rc=rc)
    if scope == "kernel-fips":
        if text in ("0", "0\n", "1", "1\n"):
            return result("COLLECTED", "OK", [["fips-enabled", text[0] == "1"]])
        return result("UNKNOWN", "AMBIGUOUS_FIPS")
    # A field is usable only as an entire literal statement. An unsupported or
    # contradictory occurrence invalidates that field, not unrelated fields.
    known, blocked, gap = {}, set(), False
    for line in text.split("\n"):
        line = line.strip(" \t")
        if not line or line.startswith(("#", ";")):
            continue
        if scope == "current-policy":
            key, sep, body = line.partition("=")
            field = POLICY_FIELDS.get(key.strip(" \t"))
            tokens = body.split() if sep else []
        elif scope in ("backend-openssh", "backend-opensshserver"):
            match = re.fullmatch(r"([A-Za-z]+)[ \t]+(.+)", line)
            field = SSH_FIELDS.get(match[1].lower()) if match else SSH_FIELDS.get(line.lower())
            tokens = match[2].split(",") if match else []
        else:
            key, sep, body = line.partition("=")
            field = SSL_FIELDS.get(key.strip(" \t").lower())
            tokens = body.strip(" \t").split(":") if sep else []
        if field is None:
            gap = True
            continue
        if (not tokens or len(tokens) > MAX_VALUES or any(not valid_token(field, v) for v in tokens)
                or len(set(tokens)) != len(tokens) or field in blocked
                or (field == "min-protocol" and len(tokens) != 1)
                or (field in known and known[field] != tokens)):
            known.pop(field, None)
            blocked.add(field)
            gap = True
            continue
        known[field] = tokens
    values = [[field, v] for field in sorted(known) for v in known[field]]
    if len(values) > MAX_VALUES:
        return result("UNKNOWN", "VALUE_LIMIT")
    if not values:
        return result("UNKNOWN", "UNSUPPORTED_SYNTAX" if gap else "NO_DATA")
    return result("PARTIAL" if gap else "COLLECTED", "INCOMPLETE_SYNTAX" if gap else "OK", values)
# END SHARED POLICY GRAMMAR


_STATE_REASONS = {
    "COLLECTED": {"OK"},
    "PARTIAL": {"INCOMPLETE_SYNTAX", "INCOMPLETE_OVERRIDES", "PROFILE_CONFLICT"},
    "UNKNOWN": {"SOURCE_ABSENT", "UNSAFE_SOURCE", "UNSUPPORTED_SYNTAX", "AMBIGUOUS_PROFILE",
                "AMBIGUOUS_FIPS", "NO_DATA", "VALUE_LIMIT", "TOOL_UNAVAILABLE", "PLATFORM_UNKNOWN"},
    "ERROR": {"COMMAND_FAILED", "MALFORMED_OUTPUT", "OUTPUT_LIMIT", "TOTAL_LIMIT", "ENTRY_LIMIT",
              "TIMEOUT", "CLEANUP_FAILED", "SOURCE_CHANGED", "READ_ERROR"},
    "PERMISSION_DENIED": {"PERMISSION_DENIED"},
    "NOT_SCANNED": {"DISABLED_BY_USER", "DISABLED_BY_PROFILE", "NOT_ATTEMPTED", "ADAPTER_NOT_AVAILABLE",
                    "PLATFORM_OUT_OF_SCOPE", "PLATFORM_UNKNOWN", "TIMEOUT_TOOL_UNAVAILABLE",
                    "SHOW_TOOL_UNAVAILABLE", "PROFILE_NOT_VALIDATED"},
}


def _require(ok, code="POLICY_INPUT"):
    if not ok:
        raise ev.EvidenceError(code, "$crypto_policy")


def _record(value, keys):
    _require(type(value) is dict and value.keys() == set(keys))


def _validate_slot(scope, row, *, nested=False):
    _record(row, ("state", "reason", "rc", "values", "overrides"))
    state, reason, rc, values, overrides = (row[k] for k in ("state", "reason", "rc", "values", "overrides"))
    _require(type(state) is str and state in _STATE_REASONS and type(reason) is str and reason in _STATE_REASONS[state])
    _require(rc is None or (type(rc) is int and -255 <= rc <= 255))
    _require(scope == "profile-show" or rc is None or
             (state in ("ERROR", "UNKNOWN", "PERMISSION_DENIED") and not nested))
    if scope == "profile-show":
        _require(state not in ("COLLECTED", "PARTIAL") or rc == 0)
        _require(rc in (None, 0) or state in ("ERROR", "PERMISSION_DENIED", "UNKNOWN"))
        _require(state != "NOT_SCANNED" or rc is None)
    _require(type(values) is list and len(values) <= MAX_VALUES and type(overrides) is list and len(overrides) <= MAX_ENTRIES)
    _require(bool(values) == (state in ("COLLECTED", "PARTIAL")))
    if state == "PARTIAL":
        _require(reason == ("INCOMPLETE_OVERRIDES" if scope == "local-overrides" else "INCOMPLETE_SYNTAX")
                 and (scope == "local-overrides" or bool(fields_for(scope))))
    _require(state != "NOT_SCANNED" or rc is None)
    _require(scope == "local-overrides" or not overrides)
    seen = set()
    for pair in values:
        _require(type(pair) is list and len(pair) == 2 and type(pair[0]) is str)
        field, value = pair
        if scope in ("profile-config", "profile-show"):
            _require(field == "profile" and type(value) is str and PROFILE.fullmatch(value) and len(values) == 1)
        elif scope == "kernel-fips":
            _require(field == "fips-enabled" and type(value) is bool and len(values) == 1)
        elif scope == "local-overrides":
            _require(field == "entry-count" and type(value) is int and 0 <= value <= MAX_ENTRIES and len(values) == 1)
        else:
            _require(field in fields_for(scope) and valid_token(field, value))
        _require((field, value) not in seen, "DUPLICATE_POLICY_VALUE")
        seen.add((field, value))
    _require(sum(1 for field, _ in values if field == "min-protocol") <= 1)
    if scope == "local-overrides":
        _require(not overrides or values and len(overrides) <= values[0][1])
        ids = set()
        total = 0
        for item in overrides:
            _record(item, ("override_id", "backend", "result"))
            oid, backend = item["override_id"], item["backend"]
            _require(type(oid) is str and re.fullmatch(r"ov-[0-9a-f]{64}", oid) and oid not in ids)
            _require(type(backend) is str and backend in BACKENDS)
            ids.add(oid)
            _validate_slot("backend-" + backend, item["result"], nested=True)
            _require(item["result"]["state"] != "NOT_SCANNED")
            total += len(item["result"]["values"])
        _require(total <= MAX_VALUES)
        if state == "COLLECTED":
            _require(len(overrides) == values[0][1] and all(o["result"]["state"] == "COLLECTED" for o in overrides))
    _require(not nested or not overrides)


def normalize_snapshot(snapshot):
    """Validate only the closed path-free projection; do not mutate it."""
    _record(snapshot, SCOPES)
    for scope in SCOPES:
        _validate_slot(scope, snapshot[scope])
    config, show = (snapshot[k] for k in ("profile-config", "profile-show"))
    config_value = config["values"][0][1] if config["values"] else None
    show_value = show["values"][0][1] if show["values"] else None
    conflict = config_value is not None and show_value is not None and config_value != show_value
    slots = dict(snapshot)
    if conflict:
        for key in ("profile-config", "profile-show"):
            slots[key] = {**slots[key], "state": "PARTIAL", "reason": "PROFILE_CONFLICT"}
    consistency = "CONFLICT" if conflict else "MATCH" if config_value is not None and config_value == show_value else "UNVERIFIED"
    fips = slots["kernel-fips"]["values"]
    return slots, dict(declared_profile=config_value, shown_profile=show_value,
                       profile_consistency=consistency, kernel_fips_enabled=fips[0][1] if fips else None)


def _context(scope, field):
    if scope == "current-policy":
        return {"cipher": "SYMMETRIC_CIPHER", "sign": "SIGNATURE"}.get(field)
    if scope in ("backend-openssh", "backend-opensshserver"):
        return {"ciphers": "SSH_CIPHER", "kex-algorithms": "SSH_KEX",
                "pubkey-accepted-algorithms": "SIGNATURE"}.get(field)
    if scope in ("backend-openssl", "backend-opensslcnf") and field in ("cipher-string", "cipher-suites"):
        return "TLS_CIPHER"
    return None


def build_crypto_policy_evidence(document, host_id, *, source, observed_at, snapshot, rules, platform_snapshot, requested):
    """Return new 1.1.0 rows, metadata and companion diagnostics only.

    Trusted caller supplies the fixed host, profile request, #14 projection,
    source/time and approved #11 rules. No authorization is inferred here.
    """
    ev.validate_document(document)
    _require(document["schema_version"] == "1.1.0", "SCHEMA_VERSION")
    _require(any(h["host_id"] == host_id for h in document["hosts"]), "POLICY_HOST")
    _record(source, ("source_kind", "producer_id", "producer_version", "origin_ref", "input_sha256"))
    _require(source["producer_id"] == COLLECTOR and source["producer_version"] == COLLECTOR_VERSION
             and source["source_kind"] in ("SYNTHETIC", "NATIVE_COLLECTOR") and type(observed_at) is str)
    _require(type(requested) is bool)
    assessment.validate_rules(rules)
    _record(platform_snapshot, ("facts_state", "facts", "tools", "rpms"))
    _require(platform_snapshot["facts_state"] in ("OK", "UNKNOWN", "ERROR", "PERMISSION_DENIED", "UNREACHABLE"))
    _require(platform_snapshot["facts_state"] == "OK" or platform_snapshot["facts"] == {})
    facts, _ = platform.normalize_platform(platform_snapshot["facts"], source_kind=source["source_kind"])
    tools = platform.normalize_tools(platform_snapshot["tools"])
    slots, metadata = normalize_snapshot(snapshot)
    eligible = requested and platform_snapshot["facts_state"] == "OK" and facts["platform_status"] == "UNVERIFIED" and tools["timeout"][2]["available"] is True
    if not eligible:
        _require(all(s["state"] == "NOT_SCANNED" for s in slots.values()), "POLICY_OUTSIDE_SCOPE")
    if tools["update-crypto-policies"][2]["available"] is not True:
        _require(slots["profile-show"]["state"] == "NOT_SCANNED", "POLICY_TOOL_UNAVAILABLE")
    collections, evidence, diagnostics = [], [], []
    rid = document["run"]["run_id"]
    for scope in SCOPES:
        row = slots[scope]
        cid = ev.collection_id(rid, host_id, COLLECTOR, scope)
        reason = row["reason"]
        if row["state"] == "NOT_SCANNED" and reason not in ev.NOT_SCANNED_REASONS:
            reason = "ADAPTER_NOT_AVAILABLE" if reason.endswith("TOOL_UNAVAILABLE") else "NOT_ATTEMPTED"
        c = dict(collection_id=cid, host_id=host_id, collector_id=COLLECTOR, collector_version=COLLECTOR_VERSION,
                 scope_key=scope, collection_state=row["state"], reason_code=reason, source=dict(source),
                 observed_at=None if row["state"] == "NOT_SCANNED" else observed_at, evidence_ids=[])
        collections.append(c)
        diagnostics.append(dict(collection_id=cid, scope=scope, state=row["state"], reason=row["reason"], rc=row["rc"],
                                overrides=[dict(override_id=o["override_id"], backend=o["backend"], state=o["result"]["state"],
                                                reason=o["result"]["reason"]) for o in row["overrides"]]))

        def add(key, kind, data, algorithm=None):
            eid = ev.evidence_id(rid, host_id, cid, key)
            evidence.append(dict(evidence_id=eid, host_id=host_id, collection_id=cid, asset_id=None,
                                 observation_key=key, evidence_kind=kind, source=dict(source), observed_at=observed_at,
                                 data=data, algorithm=algorithm))
            c["evidence_ids"].append(eid)

        def observe(field, value, backend_scope=scope, override=None):
            setting = (scope + "-" + field if override is None else
                       "override-" + override[3:] + "-" + backend_scope.removeprefix("backend-") + "-" + field)
            raw = json.dumps([setting, value], separators=(",", ":"), ensure_ascii=True).encode("ascii")
            key = "v-" + hashlib.sha256(raw).hexdigest()
            context = _context(backend_scope, field)
            algorithm = assessment.classify_algorithm(value, context, rules) if context else None
            scalar = ("enabled" if value else "disabled") if field == "fips-enabled" else json.dumps(value) if type(value) in (bool, int) else value
            add(key, "EFFECTIVE_CONFIGURATION", dict(setting=setting, effective_value=scalar, allowed=None), algorithm)

        for field, value in row["values"]:
            observe(field, value)
        for item in row["overrides"]:
            backend_scope, oid = "backend-" + item["backend"], item["override_id"]
            observe("presence", True, backend_scope, oid)
            for field, value in item["result"]["values"]:
                observe(field, value, backend_scope, oid)
        if row["state"] in ("COLLECTED", "PARTIAL"):
            add("summary", "COLLECTION_SUMMARY", dict(scope=scope, attempted=True, applicable=True,
                coverage="COMPLETE" if row["state"] == "COLLECTED" else "PARTIAL", observation_count=len(c["evidence_ids"])))
    ev.validate_document({**document, "collections": document["collections"] + collections,
                          "evidence": document["evidence"] + evidence})
    return dict(schema_version="1.1.0", metadata=metadata, collections=collections, evidence=evidence, diagnostics=diagnostics)
