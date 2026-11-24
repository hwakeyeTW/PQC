"""Pure controller adapter for the internal #14 platform collector (SCOPE-R1).

The caller owns authorization, transport, timestamps and run finalization.
Only the bounded projection documented in platform-support.md is accepted.
"""
import hashlib
import json
import re

from tools import evidence as ev

COLLECTOR = "pqc-platform"
COLLECTOR_VERSION = "1.0.0"
TOOL_SLOTS = {"rpm": 1, "openssl": 1, "ssh": 1, "sshd": 1, "ssh-keygen": 1,
              "update-crypto-policies": 2, "timeout": 1}
PACKAGES = ("oraclelinux-release", "oraclelinux-release-el9")
FACT_NAMES = ("distribution", "os_family", "distribution_version",
              "distribution_major_version", "architecture")
_FACT_KEYS = frozenset(FACT_NAMES + tuple("ansible_" + k for k in FACT_NAMES))
_DIST = {"oraclelinux": "oracle-linux", "oracle linux": "oracle-linux", "oracle-linux": "oracle-linux",
         "redhat": "rhel", "red hat enterprise linux": "rhel", "rhel": "rhel",
         "rocky": "rocky", "rocky linux": "rocky", "almalinux": "almalinux", "alma linux": "almalinux",
         "centos": "centos", "centos stream": "centos", "fedora": "fedora", "debian": "debian",
         "ubuntu": "ubuntu", "sles": "sles", "suse": "suse", "opensuse": "opensuse"}
_OS_ID = {"ol": "oracle-linux", "rhel": "rhel", "rocky": "rocky", "almalinux": "almalinux",
          "centos": "centos", "fedora": "fedora", "debian": "debian", "ubuntu": "ubuntu",
          "sles": "sles", "opensuse": "opensuse"}
_SLUG = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}", re.ASCII)
_DECIMAL = re.compile(r"(?:0|[1-9][0-9]{0,15})", re.ASCII)
_VERSION = re.compile(r"(?:0|[1-9][0-9]{0,15})(?:\.(?:0|[1-9][0-9]{0,15})){0,2}", re.ASCII)
_RPM_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+~^-]{0,127}", re.ASCII)
_RPM_RELEASE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}", re.ASCII)
_SAFE_INT = 9007199254740991
_FAILURE_STATES = ("UNKNOWN", "ERROR", "PERMISSION_DENIED", "UNREACHABLE")
_RPM_REASONS = {
    "ERROR": {"COMMAND_FAILED", "MALFORMED_OUTPUT", "OUTPUT_LIMIT", "TIMEOUT", "CLEANUP_FAILED"},
    "UNKNOWN": {"NO_DATA", "TOOL_UNAVAILABLE"},
    "PERMISSION_DENIED": {"PERMISSION_DENIED"},
    "PARTIAL": {"INCOMPLETE_RPM_ROWS"},
    "COLLECTED": {"OK"}, "ABSENT": {"PACKAGE_ABSENT"},
}


def _require(ok, code="PLATFORM_INPUT"):
    if not ok:
        raise ev.EvidenceError(code, "$platform")


def _mapping(value, allowed, required=()):
    _require(type(value) is dict and value.keys() <= set(allowed) and set(required) <= value.keys())
    return value


def _slug(value):
    if type(value) is str and len(value) <= 64 and value.isascii():
        normalized = value.lower()
        if _SLUG.fullmatch(normalized):
            return normalized
    return None


def _alias(value, aliases):
    return aliases.get(value.lower()) if type(value) is str and len(value) <= 128 and value.isascii() else None


def _version(value):
    if type(value) is str and len(value) <= 50 and _VERSION.fullmatch(value):
        parts = tuple(map(int, value.split(".")))
        if all(v <= _SAFE_INT for v in parts):
            return parts
    return None


def _major(value):
    if type(value) is int and 0 <= value <= _SAFE_INT:
        return value
    if type(value) is str and _DECIMAL.fullmatch(value) and int(value) <= _SAFE_INT:
        return int(value)
    return None


def normalize_platform(facts, *, source_kind):
    """Accept only named fact scalars; return typed data and constant gap codes."""
    _require(source_kind in ("NATIVE_COLLECTOR", "SYNTHETIC"))
    _mapping(facts, _FACT_KEYS | {"ansible_facts", "os_release_id"})
    nested = _mapping(facts.get("ansible_facts", {}), _FACT_KEYS)
    values = {k: [] for k in FACT_NAMES}
    for mapping in (facts, nested):
        for key in _FACT_KEYS & mapping.keys():
            value = mapping[key]
            _require(value is None or type(value) in (str, int, bool))
            _require(type(value) is not str or len(value) <= 128)
            values[key.removeprefix("ansible_")].append(value)
    os_id = facts.get("os_release_id")
    _require(os_id is None or (type(os_id) is str and len(os_id) <= 128))
    gaps = set()

    def choose(raw, convert, label, missing=True):
        present = [v for v in raw if v is not None]
        known = [convert(v) for v in present]
        if not present:
            if missing:
                gaps.add(label + "_MISSING")
            return None
        if any(v is None for v in known) or len(set(known)) != 1:
            gaps.add(label + "_UNRESOLVED")
            return None
        return known[0]

    dist_sources = [_alias(v, _DIST) for v in values["distribution"] if v is not None]
    if os_id is not None:
        dist_sources.append(_alias(os_id, _OS_ID))
    if not dist_sources or None in dist_sources or len(set(dist_sources)) != 1:
        distribution = None
        gaps.add("DISTRIBUTION_UNRESOLVED" if dist_sources else "DISTRIBUTION_MISSING")
    else:
        distribution = dist_sources[0]
    family = choose(values["os_family"], _slug, "FAMILY")
    architecture = choose(values["architecture"], _slug, "ARCHITECTURE")
    parts = choose(values["distribution_version"], _version, "VERSION", missing=False)
    major_fact = choose(values["distribution_major_version"], _major, "MAJOR", missing=False)
    if ("VERSION_UNRESOLVED" in gaps or "MAJOR_UNRESOLVED" in gaps or
            (parts is not None and major_fact is not None and parts[0] != major_fact)):
        parts = None
        gaps.add("VERSION_UNRESOLVED")
    elif parts is None and major_fact is not None:
        parts = (major_fact,)
    if parts is None or len(parts) < 2:
        gaps.add("VERSION_INCOMPLETE")
    major, minor, patch = ((parts or ()) + (None, None, None))[:3]
    # Conflicting family aliases are not equivalent to a genuinely absent family.
    if distribution == "oracle-linux" and "FAMILY_UNRESOLVED" in gaps:
        distribution = None
    if distribution is None:
        status = "UNKNOWN"
    elif distribution != "oracle-linux":
        status = "OUT_OF_SCOPE"
    elif family not in (None, "redhat") or major is None:
        status = "UNKNOWN"
        gaps.add("PLATFORM_UNRESOLVED")
    elif major != 9:
        status = "OUT_OF_SCOPE"
    elif minor is None:
        status = "UNKNOWN"
    else:
        status = "UNVERIFIED"
    data = dict(os_family=family, os_version=".".join(map(str, parts)) if parts else None,
                distribution=distribution, major=major, minor=minor, patch=patch,
                architecture=architecture, platform_status=status)
    return data, sorted(gaps)


def normalize_tools(observations):
    """Reduce exact slot-indexed, path-free stat projections, never raw stat."""
    _mapping(observations, TOOL_SLOTS, TOOL_SLOTS)
    output = {}
    for tool, slots in TOOL_SLOTS.items():
        rows = observations[tool]
        _require(type(rows) is list and len(rows) == slots)
        results, gaps = [], []
        for row in rows:
            _mapping(row, {"state", "exists", "isreg", "islnk", "executable"}, {"state"})
            state = row["state"]
            _require(state in ("OK", *_FAILURE_STATES))
            flags = [row.get(k) for k in ("exists", "isreg", "islnk", "executable")]
            _require(all(v is None or type(v) is bool for v in flags))
            exists, regular, link, executable = flags
            if state != "OK":
                _require(all(v is None for v in flags))
                results.append(None)
                gaps.append(state)
            elif exists is False and all(v is None for v in flags[1:]):
                results.append(False)
            elif exists is True and link is False and regular is False:
                results.append(False)
            elif exists is True and link is False and regular is True and type(executable) is bool:
                results.append(executable)
            else:
                results.append(None)
                gaps.append("UNKNOWN")
        available = True if True in results else False if all(v is False for v in results) else None
        if available is not None:
            state, reason = ("PARTIAL", "INCOMPLETE_TOOL_LOOKUP") if gaps else ("COLLECTED", "OK")
        else:
            state = next((s for s in ("PERMISSION_DENIED", "ERROR", "UNREACHABLE") if s in gaps), "UNKNOWN")
            reason = "TOOL_LOOKUP_" + state
        output[tool] = (state, reason, dict(tool_id=tool, lookup_scope="SYSTEM_EXECUTABLE_PATHS", available=available))
    return output


def _rpm_rows(name, rows):
    _require(type(rows) is list and len(rows) <= 32, "RPM_ROWS")
    good = set()
    size = 0
    for row in rows:
        _require(type(row) is list and len(row) == 4 and all(type(v) is str and len(v) <= 128 for v in row), "RPM_ROWS")
        _require(row[0] == name and _RPM_VERSION.fullmatch(row[1]) and _RPM_RELEASE.fullmatch(row[2]) and
                 _SLUG.fullmatch(row[3]), "RPM_ROWS")
        size += sum(len(v) for v in row) + 4
        _require(size <= 16384 and tuple(row) not in good, "RPM_ROWS")
        good.add(tuple(row))
    return sorted(good)


def normalize_rpm(name, result):
    """Validate the bounded wrapper's typed result; no raw command input."""
    _require(name in PACKAGES)
    _mapping(result, {"state", "reason", "rows"}, {"state", "reason", "rows"})
    state, reason = result["state"], result["reason"]
    _require(type(state) is str and state in _RPM_REASONS and type(reason) is str and reason in _RPM_REASONS[state], "RPM_RESULT")
    rows = _rpm_rows(name, result["rows"])
    _require(bool(rows) == (state in ("COLLECTED", "PARTIAL")), "RPM_RESULT")
    if state == "ABSENT":
        return "COLLECTED", reason, [dict(name=name, version=None, release=None, architecture=None, present=False)]
    return state, reason, [dict(name=n, version=v, release=r, architecture=a, present=True) for n, v, r, a in rows]


def build_platform_evidence(document, host_id, *, source, observed_at, snapshot):
    """Return new rows and status after validating the integrated 1.1.0 document.

    No mutation, time generation, claim evaluation or dispatch authorization.
    """
    ev.validate_document(document)
    _require(document["schema_version"] == "1.1.0", "SCHEMA_VERSION")
    _require(any(h["host_id"] == host_id for h in document["hosts"]), "PLATFORM_HOST")
    _mapping(source, {"source_kind", "producer_id", "producer_version", "origin_ref", "input_sha256"},
             {"source_kind", "producer_id", "producer_version", "origin_ref", "input_sha256"})
    _require(source["producer_id"] == COLLECTOR and source["producer_version"] == COLLECTOR_VERSION and
             source["source_kind"] in ("NATIVE_COLLECTOR", "SYNTHETIC") and type(observed_at) is str)
    _mapping(snapshot, {"facts", "facts_state", "tools", "rpms"}, {"facts", "facts_state", "tools", "rpms"})
    state = snapshot["facts_state"]
    _require(state in ("OK", *_FAILURE_STATES))
    _require(state == "OK" or snapshot["facts"] == {})
    data, gaps = normalize_platform(snapshot["facts"], source_kind=source["source_kind"])
    tools = normalize_tools(snapshot["tools"])
    rpms = _mapping(snapshot["rpms"], PACKAGES)
    rid = document["run"]["run_id"]
    collections, evidence = [], []

    def emit(scope, state, reason, kind, observations):
        cid = ev.collection_id(rid, host_id, COLLECTOR, scope)
        c = dict(collection_id=cid, host_id=host_id, collector_id=COLLECTOR, collector_version=COLLECTOR_VERSION,
                 scope_key=scope, collection_state=state, reason_code=reason, source=dict(source),
                 observed_at=None if state == "NOT_SCANNED" else observed_at, evidence_ids=[])
        collections.append(c)

        def add(key, kind, value):
            eid = ev.evidence_id(rid, host_id, cid, key)
            evidence.append(dict(evidence_id=eid, host_id=host_id, collection_id=cid, asset_id=None,
                                 observation_key=key, evidence_kind=kind, source=dict(source),
                                 observed_at=observed_at, data=dict(value), algorithm=None))
            c["evidence_ids"].append(eid)
        for value in observations:
            if kind == "PACKAGE_INVENTORY":
                parts = [value.get(k) for k in ("name", "version", "release", "architecture")]
                key = "r-" + hashlib.sha256(json.dumps(parts, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
            else:
                key = "observation"
            add(key, kind, value)
        if state in ("COLLECTED", "PARTIAL"):
            add("summary", "COLLECTION_SUMMARY", dict(scope=scope, attempted=True, applicable=True,
                coverage="COMPLETE" if state == "COLLECTED" else "PARTIAL", observation_count=len(observations)))

    if state == "OK":
        known = any(v is not None for k, v in data.items() if k != "platform_status")
        state = ("PARTIAL" if gaps else "COLLECTED") if known else "UNKNOWN"
        emit("platform-info", state, "INCOMPLETE_PLATFORM" if gaps else "OK", "PLATFORM_INFO", [data])
    else:
        emit("platform-info", state, "FACTS_" + state, "PLATFORM_INFO", [])
    for tool, (state, reason, value) in tools.items():
        emit("tool-" + tool, state, reason, "TOOL_AVAILABILITY", [value])
    # Eligibility follows the typed platform status; unknown family alone is not a contradiction.
    eligible = (snapshot["facts_state"] == "OK" and data["platform_status"] == "UNVERIFIED" and
                all(tools[k][2]["available"] is True for k in ("rpm", "timeout")))
    _require(eligible or not rpms, "RPM_OUTSIDE_SCOPE")
    for name in PACKAGES:
        if name not in rpms:
            emit("release-rpm-" + name, "NOT_SCANNED", "NOT_ATTEMPTED", "PACKAGE_INVENTORY", [])
        else:
            state, reason, values = normalize_rpm(name, rpms[name])
            emit("release-rpm-" + name, state, reason, "PACKAGE_INVENTORY", values)
    ev.validate_document({**document, "collections": document["collections"] + collections,
                          "evidence": document["evidence"] + evidence})
    return dict(schema_version="1.1.0", platform_status=data["platform_status"],
                gap_reasons=gaps, collections=collections, evidence=evidence)
