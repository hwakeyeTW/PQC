"""E01-E05: entirely synthetic evidence; no inventory, probe or report I/O."""
import builtins
import copy
import io
import json
import socket
import subprocess
from pathlib import Path

import pytest

from tools import evidence as ev

TS = "2026-01-01T00:00:00Z"
END = "2026-01-01T00:01:00Z"
RID = "synthetic-1"
ROOT = Path(__file__).resolve().parents[2]


def source(producer="fixture", kind="SYNTHETIC", version="1.0"):
    return dict(source_kind=kind, producer_id=producer, producer_version=version,
                origin_ref="fixture-origin", input_sha256=None)


def host(doc, target="Host-A.example.invalid", authority="fixture-authority", key=None,
         state="COMPLETE"):
    hid = ev.host_id(authority, target, run_id=doc["run"]["run_id"], identity_key=key)
    doc["hosts"].append(dict(host_id=hid, target_id=target,
        identity_scope="STABLE" if authority else "RUN_SCOPED", inventory_authority_id=authority,
        identity_key=key, host_state=state, reason_code="PLAN_ONLY" if state == "NOT_ATTEMPTED" else "FIXTURE"))
    doc["run"]["expected_host_ids"].append(hid)
    return hid


def document(state="COMPLETE", host_state="COMPLETE", kind="SYNTHETIC", rid=RID):
    d = dict(schema_version="1.0.0", run=dict(run_id=rid, run_state=state, recorded_at=END,
        started_at=None, finished_at=None, source=source(kind=kind), expected_host_ids=[]),
        hosts=[], collections=[], assets=[], evidence=[], claims=[], findings=[])
    host(d, state=host_state)
    return d


def collector(d, h=None, state="COLLECTED", reason="FIXTURE", scope="all", producer="fixture", version="1.0"):
    h = h or d["hosts"][0]["host_id"]
    kind = d["run"]["source"]["source_kind"]
    c = dict(collection_id=ev.collection_id(d["run"]["run_id"], h, producer, scope), host_id=h,
             collector_id=producer, collector_version=version, scope_key=scope, collection_state=state,
             reason_code=reason, source=source(producer, kind, version),
             observed_at=None if state == "NOT_SCANNED" or kind == "LEGACY_IMPORT" else TS, evidence_ids=[])
    d["collections"].append(c)
    return c


def asset(d, c, kind="package", key="fixture-package", stable=True):
    aid = ev.asset_id(c["host_id"], kind, key, run_id=None if stable else d["run"]["run_id"])
    a = dict(asset_id=aid, host_id=c["host_id"], asset_kind=kind, identity_scope="STABLE" if stable else "RUN_SCOPED",
             identity_key=key, evidence_ids=[])
    d["assets"].append(a)
    return a


def algorithm(family="PQC", primitive="KEX", aid="fixture-algorithm"):
    return dict(algorithm_id=aid, family=family, primitive=primitive, observed_name="fixture-name", taxonomy_version=None)


def observation(d, c, kind, data, a=None, alg=None, key="observation"):
    eid = ev.evidence_id(d["run"]["run_id"], c["host_id"], c["collection_id"], key)
    e = dict(evidence_id=eid, host_id=c["host_id"], collection_id=c["collection_id"],
             asset_id=a["asset_id"] if a else None, observation_key=key, evidence_kind=kind,
             source=copy.deepcopy(c["source"]), observed_at=c["observed_at"], data=data, algorithm=alg)
    d["evidence"].append(e)
    c["evidence_ids"].append(eid)
    if a:
        a["evidence_ids"].append(eid)
    return e


def claim(d, c, a=None, alg=None, refs=(), level="L1", state="PASS", conditions=None, key="claim", reason="FIXTURE"):
    s = dict(host_id=c["host_id"], asset_id=a["asset_id"] if a else None, algorithm_id=alg)
    row = dict(claim_id=ev.claim_id(d["run"]["run_id"], s, level, "fixture-rule", key, conditions),
               subject=s, claim_key=key, level=level, assessment_state=state, rule_id="fixture-rule",
               rule_version="1.0", reason_code=reason, evidence_ids=list(refs), conditions=conditions)
    d["claims"].append(row)
    return row


def finding(d, cl, state=None, refs=(), claims=True):
    row = dict(finding_id=ev.finding_id(cl["subject"], cl["rule_id"], "fixture-condition"),
        subject=copy.deepcopy(cl["subject"]), condition_key="fixture-condition", rule_id=cl["rule_id"],
        rule_version=cl["rule_version"], assessment_state=state or cl["assessment_state"], reason_code="FIXTURE",
        evidence_ids=list(refs), claim_ids=[cl["claim_id"]] if claims else [])
    d["findings"].append(row)
    return row


def installed(present=True, state="PASS"):
    d = document()
    c = collector(d)
    a = asset(d, c)
    e = observation(d, c, "PACKAGE_INVENTORY", dict(name="fixture-package", version="1.0", present=present), a)
    cl = claim(d, c, a, refs=[e["evidence_id"]], state=state)
    finding(d, cl)
    return d


def summary(d, c, *, count=0, coverage="COMPLETE", attempted=True, applicable=True):
    return observation(d, c, "COLLECTION_SUMMARY", dict(scope=c["scope_key"], attempted=attempted,
        coverage=coverage, observation_count=count, applicable=applicable))


def negotiated(level="L4", state="PASS", outcome=None):
    d = document()
    c = collector(d)
    a = asset(d, c, "service", "fixture-service")
    ctx = dict(host_id=c["host_id"], service_asset_id=a["asset_id"])
    if level == "L4":
        ctx.update(endpoint_ref="fixture-endpoint", protocol="TLS", context_ref="fixture-context",
                   authorization_ref="fixture-authorization")
        kind = "AUTHORIZED_NEGOTIATION"
        outcome = outcome or ("NEGOTIATED" if state == "PASS" else "REJECTED")
    else:
        ctx.update(business_source_ref="fixture-business", method="PASSIVE_SESSION_OBSERVATION",
                   started_at=TS, finished_at=END)
        kind = "OBSERVED_USAGE"
        outcome = outcome or ("OBSERVED" if state == "PASS" else "CONTRADICTED")
    e = observation(d, c, kind, dict(conditions=copy.deepcopy(ctx), outcome=outcome), a, algorithm())
    claim(d, c, a, "fixture-algorithm", [e["evidence_id"]], level, state, ctx)
    return d


def rejected(d, code=None):
    with pytest.raises(ev.EvidenceError) as caught:
        ev.validate_document(d)
    if code:
        assert caught.value.code == code
    assert "DUMMY_SECRET_SENTINEL" not in str(caught.value)


def edit(d, path, value):
    row = d
    for p in path[:-1]:
        row = row[p]
    row[path[-1]] = value
    return d


# E01: same structural matrix is run against the standard schema (E05).
@pytest.fixture(scope="module")
def standard():
    js = pytest.importorskip("jsonschema", reason="optional standard schema cross-check")
    schema = json.loads((ROOT / "schemas/evidence.schema.json").read_text(encoding="utf-8"))
    js.Draft202012Validator.check_schema(schema)
    assert schema == ev.model_schema()
    return js.Draft202012Validator(schema, format_checker=js.FormatChecker())


SHAPE_CASES = [
    (("schema_version",), "2.0.0"), (("run", "run_id"), "../fixture"),
    (("run", "run_id"), "fixture\n"), (("run", "run_state"), "PASS"),
    (("run", "recorded_at"), "2026-02-30T00:00:00Z"),
    (("run", "recorded_at"), "2026-01-01T00:00:00+08:00"),
    (("run", "source", "origin_ref"), "https://example.invalid/fixture"),
    (("run", "source", "origin_ref"), "file:fixture"),
    (("run", "source", "input_sha256"), "not-a-hash"),
    (("hosts", 0, "target_id"), False), (("hosts", 0, "identity_scope"), "UNKNOWN"),
    (("hosts", 0, "DUMMY_SECRET_SENTINEL"), "DUMMY_SECRET_SENTINEL"),
    (("collections", 0, "collection_state"), "PASS"),
    (("collections", 0, "reason_code"), ""),
    (("evidence", 0, "evidence_kind"), "RAW_COMMAND"),
    (("evidence", 0, "data", "present"), 1),
    (("evidence", 0, "data", "version"), 7),
    (("evidence", 0, "data", "private_key"), "DUMMY_SECRET_SENTINEL"),
    (("evidence", 0, "evidence_ref"), "../fixture"),
    (("claims", 0, "assessment_state"), "PERMISSION_DENIED"),
    (("claims", 0, "rule_version"), None),
    (("claims", 0, "conditions"), {}),
    (("findings", 0, "claim_ids"), "not-an-array"),
]


@pytest.mark.parametrize("path,value", SHAPE_CASES)
def test_e01_shape_invalid(path, value):
    rejected(edit(installed(), path, value))


@pytest.mark.parametrize("path,value", SHAPE_CASES)
def test_e05_schema_parity_invalid(standard, path, value):
    assert not standard.is_valid(edit(installed(), path, value))


@pytest.mark.parametrize("field", ["schema_version", "run", "hosts", "collections", "assets", "evidence", "claims", "findings"])
def test_e01_required(field):
    d = installed()
    del d[field]
    rejected(d, "MISSING_FIELD")


@pytest.mark.parametrize("field", ["schema_version", "run", "hosts", "collections", "assets", "evidence", "claims", "findings"])
def test_e05_schema_required(standard, field):
    d = installed()
    del d[field]
    assert not standard.is_valid(d)


@pytest.mark.parametrize("raw,code", [(b'{"DUMMY_SECRET_SENTINEL":1,"DUMMY_SECRET_SENTINEL":2}', "DUPLICATE_KEY"),
    (b'{"a":NaN}', "NONFINITE"), (b'{"a":Infinity}', "NONFINITE"), (b'{"a":-Infinity}', "NONFINITE"),
    (b'{"a":1e999}', "NONFINITE"), (b'\xff', "INVALID_JSON"), (b'\xef\xbb\xbf{}', "INVALID_JSON"),
    (b'{"a":"\\ud800"}', "STRING"), (b'{"a":' + b'9'*100 + b'}', "INTEGER_LIMIT"),
    (b'['*65+b']'*65, "DEPTH_LIMIT"), (b'{"a":}', "INVALID_JSON")])
def test_e01_strict_json(raw, code):
    with pytest.raises(ev.EvidenceError) as e:
        ev.parse_evidence_bytes(raw)
    assert e.value.code == code
    assert "DUMMY_SECRET_SENTINEL" not in str(e.value)


def test_e01_size_and_depth(monkeypatch):
    with pytest.raises(ev.EvidenceError, match="SIZE_LIMIT"):
        ev.parse_evidence_bytes(b' ' * (ev.MAX_BYTES + 1))
    cycle = []
    cycle.append(cycle)
    rejected(cycle, "DEPTH_LIMIT")
    d = installed()
    monkeypatch.setattr(ev, "MAX_BYTES", 64)
    rejected(d, "SIZE_LIMIT")


@pytest.mark.parametrize("v", [True, -1, 1.0, "0"])
def test_e01_count_type(v):
    d = document()
    summary(d, collector(d), count=v)
    rejected(d)


@pytest.mark.parametrize("v", [True, -1, "0"])
def test_e05_count_schema(standard, v):
    d = document()
    summary(d, collector(d), count=v)
    assert not standard.is_valid(d)


def test_e02_identity():
    h = ev.host_id("fixture-authority", "Host-A.example.invalid")
    assert h == ev.host_id("fixture-authority", "Host-A.example.invalid", run_id="another")
    assert h != ev.host_id("fixture-authority", "host-a.example.invalid")
    assert h != ev.host_id("other-authority", "Host-A.example.invalid")
    assert h != ev.host_id("fixture-authority", " Host-A.example.invalid")
    assert ev.derive_id("host", ["ab", "c"]) != ev.derive_id("host", ["a", "bc"])
    assert ev.derive_id("host", ["a", None]) != ev.derive_id("host", ["a", "null"])
    assert ev.host_id(None, None, run_id="a", identity_key="legacy") != ev.host_id(None, None, run_id="b", identity_key="legacy")
    assert ev.asset_id(h, "package", "fixture") == ev.asset_id(h, "package", "fixture")
    assert ev.asset_id(h, "package", "fixture", run_id="a") != ev.asset_id(h, "package", "fixture", run_id="b")
    assert len(h) == 66
    for v in (True, 1, "", "a\n", "../fixture", "a/b", "x"*513):
        with pytest.raises(ev.EvidenceError):
            ev.derive_id("host", [v])


def test_e02_fixed_hash_vector():
    import hashlib
    raw = b'["pqc-id-v1","host","STABLE","fixture-authority","Host-A.example.invalid"]'
    assert ev.host_id("fixture-authority", "Host-A.example.invalid") == "h-" + hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize("registry", list(ev.REGISTRIES))
def test_e02_duplicate_registry(registry):
    d = installed()
    d[registry].append(copy.deepcopy(d[registry][0]))
    rejected(d, "DUPLICATE_ID")


@pytest.mark.parametrize("registry,field", [("collections", "evidence_ids"), ("assets", "evidence_ids"),
    ("claims", "evidence_ids"), ("findings", "claim_ids")])
def test_e02_duplicate_member(registry, field):
    d = installed()
    d[registry][0][field] *= 2
    rejected(d, "DUPLICATE_MEMBER")


def test_e02_manifest_and_missing_host():
    d = installed()
    host(d, "Host-B.example.invalid", state="NOT_ATTEMPTED")
    rejected(d, "RUN_STATE")
    d["run"]["run_state"] = "PARTIAL"
    ev.validate_document(d)
    d["hosts"].pop()
    rejected(d, "HOST_MANIFEST")


def test_e02_dangling_and_backrefs():
    d = installed()
    d["claims"][0]["evidence_ids"] = ["e-" + "0"*64]
    rejected(d, "DANGLING_REF")
    d = installed()
    d["collections"][0]["evidence_ids"] = []
    rejected(d, "COLLECTION_BACKREF")
    d = installed()
    d["assets"][0]["evidence_ids"] = []
    rejected(d, "ASSET_EVIDENCE_REQUIRED")


def test_e02_cross_host_and_wrong_id():
    d = installed()
    h = host(d, "Host-B.example.invalid")
    d["evidence"][0]["host_id"] = h
    rejected(d, "CROSS_HOST")
    d = installed()
    d["hosts"][0]["target_id"] = "Host-B.example.invalid"
    rejected(d, "ID_MISMATCH")


@pytest.mark.parametrize("state,host_state,reason", [("NOT_SCANNED", "NOT_ATTEMPTED", "PLAN_ONLY"),
    ("NOT_SCANNED", "COMPLETE", "DISABLED_BY_USER"), ("NOT_SCANNED", "COMPLETE", "DISABLED_BY_PROFILE"),
    ("NOT_SCANNED", "COMPLETE", "AWAITING_COLLECTOR"), ("PERMISSION_DENIED", "PARTIAL", "DENIED"),
    ("ERROR", "ERROR", "COMMAND_FAILED"), ("UNREACHABLE", "UNREACHABLE", "SSH_FAILED"),
    ("UNKNOWN", "PARTIAL", "MISSING_LEGACY_FIELD")])
def test_e03_acquisition_not_verdict(state, host_state, reason):
    d = document("PARTIAL", host_state)
    c = collector(d, state=state, reason=reason)
    ev.validate_document(d)
    assert d["claims"] == d["findings"] == []
    for verdict in ("PASS", "FAIL"):
        claim(d, c, state=verdict)
        rejected(d, "CLAIM_EVIDENCE_REQUIRED")
        d["claims"].clear()


def test_e03_planned():
    d = document("PLANNED", "NOT_ATTEMPTED")
    c = collector(d, state="NOT_SCANNED", reason="PLAN_ONLY", version=None)
    claim(d, c, state="NOT_SCANNED", reason="PLAN_ONLY")
    ev.validate_document(d)
    c["collection_state"] = "UNREACHABLE"
    rejected(d, "HOST_STATE")


def test_e03_empty_and_partial():
    d = document()
    c = collector(d)
    rejected(d, "COLLECTION_EVIDENCE_REQUIRED")
    e = summary(d, c)
    ev.validate_document(d)
    assert not d["claims"] and not d["assets"]
    e["data"].update(coverage="UNKNOWN", observation_count=None)
    rejected(d, "COLLECTION_EVIDENCE_REQUIRED")
    c["collection_state"] = "UNKNOWN"
    ev.validate_document(d)
    c.update(collection_state="PARTIAL", reason_code="INCOMPLETE_SCOPE")
    rejected(d, "PARTIAL_EVIDENCE_REQUIRED")
    e["data"].update(coverage="PARTIAL", observation_count=0)
    ev.validate_document(d)
    cl = claim(d, c, refs=[e["evidence_id"]], state="PARTIAL", reason="INCOMPLETE_SCOPE")
    ev.validate_document(d)
    cl["evidence_ids"] = []
    rejected(d, "PARTIAL_EVIDENCE_REQUIRED")


def test_e03_not_applicable():
    d = document()
    c = collector(d, state="NOT_APPLICABLE", reason="OUTSIDE_APPLICABILITY")
    rejected(d, "APPLICABILITY_EVIDENCE_REQUIRED")
    e = summary(d, c, count=None, coverage="UNKNOWN", attempted=False, applicable=False)
    cl = claim(d, c, refs=[e["evidence_id"]], state="NOT_APPLICABLE", reason="OUTSIDE_APPLICABILITY")
    finding(d, cl)
    ev.validate_document(d)
    cl["evidence_ids"] = []
    rejected(d, "APPLICABILITY_EVIDENCE_REQUIRED")


@pytest.mark.parametrize("level,kind,data", [("L2", "RUNTIME_CAPABILITY", {"capability": "fixture", "supported": True}),
    ("L3", "EFFECTIVE_CONFIGURATION", {"setting": "fixture", "effective_value": "fixture", "allowed": True})])
def test_e04_independent_l2_l3(level, kind, data):
    d = document()
    c = collector(d)
    e = observation(d, c, kind, data)
    claim(d, c, level=level, refs=[e["evidence_id"]])
    ev.validate_document(d)
    assert [cl["level"] for cl in d["claims"]] == [level]


@pytest.mark.parametrize("family", ["CLASSICAL", "PQC", "HYBRID", "UNKNOWN"])
@pytest.mark.parametrize("primitive", ["KEM", "KEX", "SIGNATURE", "PUBLIC_KEY", "SYMMETRIC", "UNKNOWN"])
def test_e04_algorithm_dimensions(family, primitive):
    d = installed()
    d["evidence"][0]["algorithm"] = algorithm(family, primitive)
    ev.validate_document(d)
    assert len(d["claims"]) == 1 and d["claims"][0]["level"] == "L1"


@pytest.mark.parametrize("level", ["L4", "L5"])
@pytest.mark.parametrize("state", ["PASS", "FAIL"])
def test_e04_actual_context(level, state):
    ev.validate_document(negotiated(level, state))


def test_e04_l1_not_l2():
    d = installed()
    cl = d["claims"][0]
    cl["level"] = "L2"
    cl["claim_id"] = ev.claim_id(RID, cl["subject"], "L2", cl["rule_id"], cl["claim_key"])
    rejected(d, "CLAIM_EVIDENCE_REQUIRED")


def test_e04_context_algorithm_source_negatives():
    d = negotiated()
    d["claims"][0]["conditions"] = None
    rejected(d)
    d = negotiated()
    d["claims"][0]["conditions"]["endpoint_ref"] = "other-endpoint"
    cl = d["claims"][0]
    cl["claim_id"] = ev.claim_id(RID, cl["subject"], cl["level"], cl["rule_id"], cl["claim_key"], cl["conditions"])
    rejected(d, "CLAIM_EVIDENCE_REQUIRED")
    d = negotiated()
    d["evidence"][0]["algorithm"]["algorithm_id"] = "other-algorithm"
    rejected(d, "UNRELATED_ALGORITHM")
    d = negotiated()
    d["evidence"][0]["algorithm"]["primitive"] = "UNKNOWN"
    rejected(d, "ACTUAL_ALGORITHM_REQUIRED")
    d = negotiated()
    d["evidence"][0]["source"]["producer_id"] = "other-producer"
    rejected(d, "EVIDENCE_SOURCE")
    d = negotiated()
    d["evidence"][0]["observed_at"] = None
    rejected(d, "OBSERVED_AT_REQUIRED")


def test_e04_probe_is_not_usage():
    d = negotiated()
    cl = d["claims"].pop()
    ctx = dict(host_id=cl["subject"]["host_id"], service_asset_id=cl["subject"]["asset_id"],
               business_source_ref="fixture-business", method="PASSIVE_SESSION_OBSERVATION", started_at=TS, finished_at=END)
    claim(d, d["collections"][0], d["assets"][0], "fixture-algorithm", cl["evidence_ids"], "L5", conditions=ctx)
    rejected(d, "CLAIM_EVIDENCE_REQUIRED")
    d = negotiated("L5")
    d["evidence"][0]["data"]["conditions"]["method"] = "PROBE"
    rejected(d, "ENUM")
    d = negotiated("L5")
    d["evidence"][0]["data"]["conditions"]["finished_at"] = "2025-01-01T00:00:00Z"
    rejected(d, "TIME_ORDER")


@pytest.mark.parametrize("outcome", ["TIMEOUT", "ERROR", "UNKNOWN"])
def test_e04_no_negotiation_verdict_from_failure(outcome):
    d = negotiated("L4", "FAIL", outcome)
    c = d["collections"][0]
    c["collection_state"] = "ERROR"
    # The service identity is now only a run-local one; retain a separate known
    # observation to establish the stable service without the failed probe.
    good = collector(d, scope="metadata")
    observation(d, good, "ASSET_METADATA", dict(name="fixture-service", version=None), d["assets"][0], key="metadata")
    rejected(d, "CLAIM_EVIDENCE_REQUIRED")


def test_e04_unrelated_asset_rule_and_failure():
    d = installed()
    c = d["collections"][0]
    a = asset(d, c, key="other-package")
    e = observation(d, c, "PACKAGE_INVENTORY", dict(name="other-package", version=None, present=True), a, key="other")
    d["claims"][0]["evidence_ids"] = [e["evidence_id"]]
    rejected(d, "UNRELATED_ASSET")
    d = installed()
    d["findings"][0]["rule_version"] = "2.0"
    rejected(d, "UNRELATED_RULE")
    d = installed()
    d["collections"][0]["collection_state"] = "PERMISSION_DENIED"
    rejected(d, "STABLE_ASSET_EVIDENCE")
    d = installed()
    d["evidence"][0]["data"]["present"] = False
    rejected(d, "CLAIM_EVIDENCE_REQUIRED")


def test_e04_conflicting_observations():
    d = installed()
    e = observation(d, d["collections"][0], "PACKAGE_INVENTORY", dict(name="fixture-package", version=None, present=False), d["assets"][0], key="other")
    d["claims"][0]["evidence_ids"].append(e["evidence_id"])
    rejected(d, "CONFLICTING_EVIDENCE")


def test_e04_finding_not_metadata():
    d = document()
    c = collector(d)
    e = observation(d, c, "PLATFORM_INFO", dict(os_family="fixture", os_version="9.9"))
    cl = claim(d, c, state="UNKNOWN")
    finding(d, cl, state="PASS", refs=[e["evidence_id"]], claims=False)
    rejected(d, "FINDING_EVIDENCE_REQUIRED")


def test_e05_legacy_unknown_and_types():
    d = document("PARTIAL", "PARTIAL", "LEGACY_IMPORT")
    d["hosts"].clear()
    d["run"]["expected_host_ids"].clear()
    host(d, None, None, "legacy-local", "PARTIAL")
    c = collector(d, state="UNKNOWN", reason="MISSING_SOURCE", version=None)
    d["run"]["source"]["producer_version"] = None
    for k, v in enumerate(("12", 12, None, False)):
        observation(d, c, "LEGACY_OBSERVATION", dict(field="legacy-count", value=v), key=f"fixture-key-{k}")
    claim(d, c, state="UNKNOWN", refs=c["evidence_ids"])
    parsed = ev.parse_evidence_bytes(ev.canonical_bytes(d))
    assert {type(e["data"]["value"]) for e in parsed["evidence"]} == {str, int, type(None), bool}
    assert all(e["observed_at"] is None and e["source"]["input_sha256"] is None for e in parsed["evidence"])
    assert parsed["claims"][0]["assessment_state"] == "UNKNOWN"


def test_e05_no_io_and_canonical(monkeypatch):
    d = installed()
    other = host(d, "Host-B.example.invalid")
    c = collector(d, other, scope="secondary")
    summary(d, c)
    snapshot = copy.deepcopy(d)
    def forbidden(*a, **kw):
        raise AssertionError("unexpected external I/O")
    with monkeypatch.context() as m:
        for module, attr in [(builtins, "open"), (io, "open"), (socket, "socket"), (socket, "create_connection"), (subprocess, "Popen")]:
            m.setattr(module, attr, forbidden)
        raw = ev.canonical_bytes(d)
        assert raw == ev.canonical_bytes(ev.parse_evidence_bytes(raw))
        assert d == snapshot
        d["run"]["expected_host_ids"].reverse()
        for k in ev.REGISTRIES:
            d[k].reverse()
        assert ev.canonical_bytes(d) == raw


@pytest.mark.parametrize("factory", [installed, lambda: installed(False, "FAIL"), negotiated,
    lambda: negotiated("L4", "FAIL"), lambda: negotiated("L5"), lambda: negotiated("L5", "FAIL"),
    lambda: document("PLANNED", "NOT_ATTEMPTED")])
def test_e05_standard_valid(standard, factory):
    d = factory()
    ev.validate_document(d)
    standard.validate(d)


def test_e05_schema_refs_and_conditionals(standard):
    def walk(x):
        if isinstance(x, dict):
            for k, v in x.items():
                if k == "$ref":
                    assert v.startswith("#/$defs/")
                else:
                    walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
    walk(standard.schema)
    d = negotiated()
    d["claims"][0]["conditions"] = None
    assert not standard.is_valid(d)
    d = installed()
    d["evidence"][0]["data"] = {"capability": "fixture", "supported": True}
    assert not standard.is_valid(d)
    d = document()
    summary(d, collector(d))
    standard.validate(d)
    ev.validate_document(d)


@pytest.mark.parametrize("key", ["file:fixture", "C:fixture", "https:fixture", "../fixture"])
def test_e02_path_like_id_components(key):
    with pytest.raises(ev.EvidenceError):
        ev.derive_id("host", [key])


def test_e02_cross_run_finding_identity():
    a = installed()
    b = document(rid="synthetic-2")
    c = collector(b)
    subject = a["claims"][0]["subject"]
    assert subject["host_id"] == c["host_id"]
    assert ev.finding_id(subject, "fixture-rule", "fixture-condition") == a["findings"][0]["finding_id"]
    assert ev.claim_id("synthetic-2", subject, "L1", "fixture-rule", "claim") != a["claims"][0]["claim_id"]
    h1 = ev.host_id(None, None, run_id="synthetic-1", identity_key="legacy")
    h2 = ev.host_id(None, None, run_id="synthetic-2", identity_key="legacy")
    assert ev.finding_id({"host_id": h1}, "fixture-rule", "fixture-condition") != ev.finding_id({"host_id": h2}, "fixture-rule", "fixture-condition")


def test_e04_failure_observation_cannot_support_claim():
    d = document()
    c = collector(d, state="ERROR", reason="COMMAND_FAILED")
    e = observation(d, c, "RUNTIME_CAPABILITY", dict(capability="fixture", supported=False))
    claim(d, c, refs=[e["evidence_id"]], level="L2", state="FAIL")
    rejected(d, "CLAIM_EVIDENCE_REQUIRED")


def test_e05_synthetic_cannot_be_mixed_with_native():
    d = installed()
    d["run"]["source"]["source_kind"] = "NATIVE_COLLECTOR"
    rejected(d, "SYNTHETIC_MIX")


# R1 C01: scope equality is semantic; shape alone cannot establish association.
@pytest.mark.parametrize("state", ["COLLECTED", "NOT_APPLICABLE"])
@pytest.mark.parametrize("scope", ["scope-b", "Scope-a", "scope-a-child"])
def test_c01_summary_scope_mismatch(standard, state, scope):
    d = document()
    c = collector(d, scope="scope-a", state=state)
    if state == "NOT_APPLICABLE":
        e = summary(d, c, count=None, coverage="UNKNOWN", attempted=False, applicable=False)
        cl = claim(d, c, refs=[e["evidence_id"]], state=state, reason="OUTSIDE_APPLICABILITY")
        finding(d, cl, refs=[e["evidence_id"]])
    else:
        e = summary(d, c)
    e["data"]["scope"] = scope
    standard.validate(d)  # shape valid, same host/collector and intact ID/backrefs
    rejected(d, "SCOPE_MISMATCH")


def test_c01_same_scope_segmented_coverage(standard):
    d = document()
    a = collector(d, scope="scope-a")
    b = collector(d, scope="scope-b", state="NOT_APPLICABLE", reason="OUTSIDE_APPLICABILITY")
    c = collector(d, scope="scope-c", state="PARTIAL", reason="INCOMPLETE_SCOPE")
    zero = summary(d, a)
    na = summary(d, b, count=None, coverage="UNKNOWN", attempted=False, applicable=False)
    part = summary(d, c, count=7, coverage="PARTIAL")
    cl = claim(d, b, refs=[na["evidence_id"]], state="NOT_APPLICABLE", reason="OUTSIDE_APPLICABILITY")
    finding(d, cl, refs=[na["evidence_id"]], claims=False)
    claim(d, c, refs=[part["evidence_id"]], state="PARTIAL", key="partial", reason="INCOMPLETE_SCOPE")
    standard.validate(d)
    ev.validate_document(d)
    assert zero["data"]["observation_count"] == 0
    assert len(c["evidence_ids"]) == 1 and part["data"]["observation_count"] == 7
    assert len({a["collection_id"], b["collection_id"], c["collection_id"]}) == 3
    part["data"]["scope"] = a["scope_key"]
    rejected(d, "SCOPE_MISMATCH")


def usage_times(state, start, finish, observed, recorded):
    d = negotiated("L5", state)
    cl, e = d["claims"][0], d["evidence"][0]
    cl["conditions"].update(started_at=start, finished_at=finish)
    e["data"]["conditions"] = copy.deepcopy(cl["conditions"])
    cl["claim_id"] = ev.claim_id(RID, cl["subject"], "L5", cl["rule_id"], cl["claim_key"], cl["conditions"])
    e["observed_at"] = observed
    d["run"]["recorded_at"] = recorded
    return d


# R1 C02: the original CE02a/b plus independent time boundaries.
@pytest.mark.parametrize("state", ["PASS", "FAIL"])
@pytest.mark.parametrize("start,finish,observed,recorded", [
    ("2026-02-01T00:00:00Z", "2026-02-01T00:01:00Z", TS, END),
    ("2026-01-01T00:00:00.000000001Z", END, TS, END),
    (TS, END, "2026-01-01T00:01:00.000000001Z", END),
    (TS, "2026-01-01T00:01:00.000000001Z", TS, END),
], ids=["future-interval", "before-start", "record-before-observation", "record-before-end"])
def test_c02_usage_time_mismatch(standard, state, start, finish, observed, recorded):
    d = usage_times(state, start, finish, observed, recorded)
    standard.validate(d)
    rejected(d, "USAGE_TIME_ORDER")
    # Direct finding support must not bypass the same actual-evidence check.
    cl = d["claims"].pop()
    finding(d, cl, refs=cl["evidence_ids"], claims=False)
    rejected(d, "USAGE_TIME_ORDER")


@pytest.mark.parametrize("state", ["PASS", "FAIL"])
@pytest.mark.parametrize("observed,recorded", [
    (TS, END),
    ("2026-01-01T00:00:30Z", END),
    (END, END),
    ("2026-01-02T00:00:00Z", "2026-01-03T00:00:00Z"),
    ("2026-01-01T00:01:00.000000001+00:00", "2026-01-01T00:01:00.000000001Z"),
], ids=["start", "within", "end", "retrospective", "exact-nanosecond-offset"])
def test_c02_usage_time_consistent(standard, state, observed, recorded):
    d = usage_times(state, TS, END, observed, recorded)
    standard.validate(d)
    ev.validate_document(d)
    assert ev.parse_evidence_bytes(ev.canonical_bytes(d))["claims"][0]["assessment_state"] == state


# #14 S1 / A01-A03. The complete 1.0.0 suite above is retained verbatim.
def document_11():
    d = document()
    d["schema_version"] = "1.1.0"
    return d


def platform_data(**changes):
    return dict(os_family="redhat", os_version="9.10", distribution="oracle-linux",
                major=9, minor=10, patch=None, architecture="x86_64",
                platform_status="UNVERIFIED") | changes


def tool_data(available=True, tool_id="openssl"):
    return dict(tool_id=tool_id, lookup_scope="SYSTEM_EXECUTABLE_PATHS", available=available)


def metadata_document(kind, data, state="COLLECTED"):
    d = document_11()
    scope = "platform-info" if kind == "PLATFORM_INFO" else "tool-" + data.get("tool_id", "openssl")
    c = collector(d, state=state, scope=scope, producer="pqc-platform", version="1.0.0")
    observation(d, c, kind, data)
    return d


@pytest.fixture(scope="module")
def standard_11():
    js = pytest.importorskip("jsonschema", reason="optional standard schema cross-check")
    schema = json.loads((ROOT / "schemas/evidence-1.1.0.schema.json").read_bytes())
    js.Draft202012Validator.check_schema(schema)
    assert schema == ev.model_schema("1.1.0")
    return js.Draft202012Validator(schema, format_checker=js.FormatChecker())


def test_a01_schema_versions_and_immutable_snapshot():
    import hashlib
    assert ev.SCHEMA_VERSION == "1.0.0" and ev.LATEST_SCHEMA_VERSION == "1.1.0"
    original = (ROOT / "schemas/evidence.schema.json").read_bytes()
    assert hashlib.sha256(original).hexdigest() == "14ba66e6daca7cdf8fda36927e20de2b96d86745e2bee2ea2d8e1736af099e30"
    assert (json.dumps(ev.model_schema(), ensure_ascii=False, indent=2) + "\n").encode() == original
    assert ev.model_schema() == ev.model_schema("1.0.0")
    new = ev.model_schema("1.1.0")
    assert new["$id"] == "urn:pqc:evidence:1.1.0"
    assert (json.dumps(new, ensure_ascii=False, indent=2) + "\n").encode() == (
        ROOT / "schemas/evidence-1.1.0.schema.json").read_bytes()
    for version in ("1.0.0", "1.1.0"):
        def check_refs(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if key == "$ref":
                        assert item.startswith("#/$defs/")
                    else:
                        check_refs(item)
            elif isinstance(value, list):
                for item in value:
                    check_refs(item)
        check_refs(ev.model_schema(version))
    new["$defs"]["source"]["required"].clear()
    assert ev.model_schema("1.1.0")["$defs"]["source"]["required"]
    assert ev.model_schema() == json.loads(original)


@pytest.mark.parametrize("version", ["1.1", "1.0.1", "1.2.0", "1.1.0 ", None, True, 1, [], {}])
def test_a01_unknown_version(version):
    with pytest.raises(ev.EvidenceError, match="SCHEMA_VERSION"):
        ev.model_schema(version)
    d = document()
    d["schema_version"] = version
    rejected(d, "SCHEMA_VERSION")
    with pytest.raises(ev.EvidenceError, match="SCHEMA_VERSION"):
        ev.parse_evidence_bytes(json.dumps(d).encode())


def test_a01_version_isolation():
    old = document()
    observation(old, collector(old), "PLATFORM_INFO", dict(os_family="fixture", os_version="9.9-synthetic"))
    ev.validate_document(old)
    old["schema_version"] = "1.1.0"
    rejected(old)
    for kind, data in [("PLATFORM_INFO", platform_data()), ("TOOL_AVAILABILITY", tool_data())]:
        d = metadata_document(kind, data)
        ev.validate_document(d)
        d["schema_version"] = "1.0.0"
        rejected(d)
    d = installed()
    d["evidence"][0]["data"]["release"] = None
    rejected(d, "UNKNOWN_FIELD")
    d["schema_version"] = "1.1.0"
    ev.validate_document(d)


@pytest.mark.parametrize("field", list(platform_data()))
def test_a01_platform_required(field):
    data = platform_data()
    del data[field]
    rejected(metadata_document("PLATFORM_INFO", data), "MISSING_FIELD")


@pytest.mark.parametrize("field", list(tool_data()))
def test_a01_tool_required(field):
    data = tool_data()
    del data[field]
    rejected(metadata_document("TOOL_AVAILABILITY", data), "MISSING_FIELD")


@pytest.mark.parametrize("kind,data", [
    ("PLATFORM_INFO", platform_data(raw="DUMMY_SECRET_SENTINEL")),
    ("TOOL_AVAILABILITY", dict(tool_data(), path="/synthetic/path")),
    ("TOOL_AVAILABILITY", tool_data(1)),
    ("TOOL_AVAILABILITY", tool_data("false")),
    ("TOOL_AVAILABILITY", tool_data(True, "unapproved-tool")),
    ("TOOL_AVAILABILITY", dict(tool_data(), lookup_scope="PATH")),
    ("UNKNOWN_KIND", {}), ("PLATFORM_INFO", []),
])
def test_a01_closed_new_shapes(kind, data):
    rejected(metadata_document(kind, data))


@pytest.mark.parametrize("changes", [
    dict(minor=7, os_version="9.7"), dict(minor=8, os_version="9.8"),
    dict(minor=9, os_version="9.9"), {}, dict(patch=2, os_version="9.10.2"),
    dict(minor=0, os_version="9.0"), dict(os_family=None),
    dict(major=8, os_version="8.10", platform_status="OUT_OF_SCOPE"),
    dict(major=10, os_version="10.10", platform_status="OUT_OF_SCOPE"),
    dict(distribution="rhel", platform_status="OUT_OF_SCOPE"),
    dict(distribution="debian", os_family="debian", platform_status="OUT_OF_SCOPE"),
    dict(distribution=None, platform_status="UNKNOWN"),
    dict(os_family="debian", platform_status="UNKNOWN"),
    dict(minor=None, os_version="9", platform_status="UNKNOWN"),
    dict(major=None, minor=None, os_version=None, platform_status="UNKNOWN"),
])
def test_a02_platform_status(changes):
    d = metadata_document("PLATFORM_INFO", platform_data(**changes))
    ev.validate_document(d)
    assert ev.parse_evidence_bytes(ev.canonical_bytes(d)) == d
    assert not d["claims"] and not d["findings"]


@pytest.mark.parametrize("changes", [
    dict(os_version="09.10"), dict(os_version="9.010"), dict(os_version="9.10.0.1"),
    dict(os_version="9.10-foo"), dict(os_version="9.10\n"), dict(os_version="9.1"),
    dict(os_version=None), dict(major=None), dict(minor=None, patch=1),
    dict(minor=True), dict(minor=10.0), dict(minor=-1), dict(minor=9007199254740992),
    dict(distribution="OracleLinux"), dict(os_family=""), dict(architecture="x"*65),
    dict(architecture="/synthetic/path"), dict(platform_status="SUPPORTED"),
    dict(platform_status="OUT_OF_SCOPE"), dict(distribution="rhel"),
    dict(os_family="debian"), dict(distribution=None),
])
def test_a02_invalid_platform(changes):
    rejected(metadata_document("PLATFORM_INFO", platform_data(**changes)))


@pytest.mark.parametrize("kind,data", [
    ("PLATFORM_INFO", platform_data(os_family=None, os_version=None, distribution=None,
                                   major=None, minor=None, patch=None, architecture=None,
                                   platform_status="UNKNOWN")),
    ("TOOL_AVAILABILITY", tool_data(None)),
])
def test_a02_unknown_observation_not_acquired(kind, data):
    d = metadata_document(kind, data, "UNKNOWN")
    ev.validate_document(d)
    c = d["collections"][0]
    c["collection_state"] = "COLLECTED"
    rejected(d, "COLLECTION_EVIDENCE_REQUIRED")
    c.update(collection_state="PARTIAL", reason_code="INCOMPLETE_SCOPE")
    rejected(d, "PARTIAL_EVIDENCE_REQUIRED")


@pytest.mark.parametrize("tool_id", ["rpm", "openssl", "ssh", "sshd", "ssh-keygen", "update-crypto-policies", "timeout"])
@pytest.mark.parametrize("available", [True, False])
def test_a02_tool_known_availability(tool_id, available):
    d = metadata_document("TOOL_AVAILABILITY", tool_data(available, tool_id))
    ev.validate_document(d)
    assert d["evidence"][0]["data"]["available"] is available
    assert not d["claims"] and not d["findings"]


@pytest.mark.parametrize("present,changes,valid", [
    (True, {}, True), (True, dict(release="0.1", architecture="x86_64"), True),
    (False, dict(release=None, architecture=None), True), (None, {}, True),
    (False, dict(release="0.1"), False), (None, dict(architecture="x86_64"), False),
    (True, dict(release="/synthetic/path"), False), (True, dict(architecture="X86_64"), False),
    (True, dict(release=1), False), (True, dict(extra="DUMMY_SECRET_SENTINEL"), False),
])
def test_a02_package_extension(present, changes, valid):
    d = document_11()
    c = collector(d, state="UNKNOWN" if present is None else "COLLECTED")
    data = dict(name="oraclelinux-release", version="9.9", present=present) | changes
    e = observation(d, c, "PACKAGE_INVENTORY", data)
    if valid:
        if present is not None:
            claim(d, c, refs=[e["evidence_id"]], state="PASS" if present else "FAIL")
        ev.validate_document(d)
        assert ev.parse_evidence_bytes(ev.canonical_bytes(d))["evidence"][0]["data"] == data
    else:
        rejected(d)


@pytest.mark.parametrize("kind,data", [("PLATFORM_INFO", platform_data()), ("TOOL_AVAILABILITY", tool_data(False))])
def test_a02_metadata_association(kind, data):
    d = metadata_document(kind, data)
    e = d["evidence"][0]
    e["algorithm"] = algorithm()
    rejected(d, "METADATA_ASSOCIATION")
    e["algorithm"] = None
    a = asset(d, d["collections"][0], "platform", "fixture-platform")
    e["asset_id"] = a["asset_id"]
    a["evidence_ids"].append(e["evidence_id"])
    rejected(d, "METADATA_ASSOCIATION")


@pytest.mark.parametrize("kind,data", [("PLATFORM_INFO", platform_data()), ("TOOL_AVAILABILITY", tool_data(True)),
                                        ("TOOL_AVAILABILITY", tool_data(False))])
@pytest.mark.parametrize("state", ["PASS", "FAIL"])
def test_a02_metadata_not_readiness(kind, data, state):
    d = metadata_document(kind, data)
    c, e = d["collections"][0], d["evidence"][0]
    for level in ("L1", "L2", "L3"):
        cl = claim(d, c, refs=[e["evidence_id"]], level=level, state=state)
        rejected(d, "CLAIM_EVIDENCE_REQUIRED")
        d["claims"].clear()
    finding(d, cl, refs=[e["evidence_id"]], claims=False)
    rejected(d, "FINDING_EVIDENCE_REQUIRED")
    for level in ("L4", "L5"):
        actual = negotiated(level, state)
        actual["schema_version"] = "1.1.0"
        c = collector(actual, scope="metadata")
        e = observation(actual, c, kind, copy.deepcopy(data))
        actual["claims"][0]["evidence_ids"] = [e["evidence_id"]]
        rejected(actual, "UNRELATED_ASSET")


@pytest.mark.parametrize("field,value,code", [
    ("observed_at", None, "OBSERVED_AT_REQUIRED"),
    ("source", source(producer="other-producer"), "EVIDENCE_SOURCE"),
    ("collection_id", "c-"+"0"*64, "COLLECTION_BACKREF"),
    ("observation_key", "other-observation", "ID_MISMATCH"),
])
def test_a02_new_row_association_errors(field, value, code):
    d = metadata_document("TOOL_AVAILABILITY", tool_data())
    d["evidence"][0][field] = value
    rejected(d, code)


def test_a02_11_retains_scope_and_time_semantics():
    d = metadata_document("PLATFORM_INFO", platform_data())
    other = host(d, "Host-B.example.invalid")
    d["evidence"][0]["host_id"] = other
    rejected(d, "CROSS_HOST")
    d = metadata_document("PLATFORM_INFO", platform_data())
    e = summary(d, collector(d, scope="fixture-summary"), count=1)
    e["data"]["scope"] = "other-scope"
    rejected(d, "SCOPE_MISMATCH")
    d = usage_times("PASS", TS, END, "2026-01-01T00:01:00.000000001Z", END)
    d["schema_version"] = "1.1.0"
    rejected(d, "USAGE_TIME_ORDER")


def test_a01_standard_11_parity(standard, standard_11):
    for d in (metadata_document("PLATFORM_INFO", platform_data()),
              metadata_document("TOOL_AVAILABILITY", tool_data()),
              metadata_document("TOOL_AVAILABILITY", tool_data(None), "UNKNOWN")):
        ev.validate_document(d)
        standard_11.validate(d)
        assert not standard.is_valid(d)
    for factory in (installed, negotiated, lambda: negotiated("L5")):
        old = factory()
        standard.validate(old)
        assert not standard_11.is_valid(old)
        new = copy.deepcopy(old)
        new["schema_version"] = "1.1.0"
        standard_11.validate(new)
        ev.validate_document(new)
    for data in (platform_data(architecture="X86_64"), platform_data(os_version="09.9"),
                 platform_data(platform_status="SUPPORTED"), platform_data(major=True)):
        d = metadata_document("PLATFORM_INFO", data)
        rejected(d)
        assert not standard_11.is_valid(d)
    d = metadata_document("PLATFORM_INFO", platform_data())
    d["evidence"][0]["algorithm"] = algorithm()
    assert not standard_11.is_valid(d)
    d = installed(False, "FAIL")
    d["schema_version"] = "1.1.0"
    d["evidence"][0]["data"]["release"] = "0.1"
    assert not standard_11.is_valid(d)
    rejected(d, "PACKAGE_PRESENCE")
    d = metadata_document("PLATFORM_INFO", platform_data(os_version="9.1"))
    standard_11.validate(d)  # semantic consistency is checked by Python
    rejected(d, "PLATFORM_VERSION")


def test_a03_document_examples_and_old_canonical_bytes():
    import hashlib
    import re
    blocks = re.findall(r"```json\n(.*?)\n```", (ROOT / "docs/specifications/evidence-model.md").read_text(encoding="utf-8"), re.S)
    assert len(blocks) == 3
    hashes = ("5e4d44a8ab8ba304f17523a1c27c1ecd5e33f783eb91c7ea480aeb3dd4bb5cd2",
              "687664d30fba2dc9c62082590a0d437ccd3d120a840a28a195a6d855842d2bdc")
    for block, expected in zip(blocks[:2], hashes):
        d = ev.parse_evidence_bytes(block.encode())
        assert d["schema_version"] == "1.0.0"
        assert hashlib.sha256(ev.canonical_bytes(d)).hexdigest() == expected
    d = document_11()
    data = json.loads(blocks[2])
    for kind, scope in [("PLATFORM_INFO", "platform-info"), ("PACKAGE_INVENTORY", "release-rpm-oraclelinux-release"),
                        ("TOOL_AVAILABILITY", "tool-openssl")]:
        c = collector(d, scope=scope, producer="pqc-platform", version="1.0.0")
        observation(d, c, kind, data[kind])
    snapshot = copy.deepcopy(d)
    raw = ev.canonical_bytes(d)
    assert d == snapshot and ev.canonical_bytes(ev.parse_evidence_bytes(raw)) == raw
    assert ev.parse_evidence_bytes(raw)["schema_version"] == "1.1.0"


@pytest.mark.parametrize("version", ["1.0.0", "1.1.0"])
def test_a03_offline_roundtrip_and_version_isolation(monkeypatch, version):
    d = installed()
    d["schema_version"] = version
    if version == "1.1.0":
        d["evidence"][0]["data"].update(release="0.1", architecture="x86_64")
        c = collector(d, scope="platform-info")
        observation(d, c, "PLATFORM_INFO", platform_data())
    snapshot = copy.deepcopy(d)
    def forbidden(*a, **kw):
        raise AssertionError("unexpected external I/O")
    with monkeypatch.context() as m:
        for module, attr in [(builtins, "open"), (io, "open"), (socket, "socket"),
                             (socket, "create_connection"), (subprocess, "Popen")]:
            m.setattr(module, attr, forbidden)
        assert ev.validate_document(d) is None
        ev.model_schema(version)
        raw = ev.canonical_bytes(d)
        parsed = ev.parse_evidence_bytes(raw)
        assert parsed["schema_version"] == version
        assert ev.canonical_bytes(parsed) == raw and d == snapshot
        assert set(parsed["run"]["expected_host_ids"]) == set(d["run"]["expected_host_ids"])
        for registry, field in ev.REGISTRIES.items():
            assert {r[field] for r in parsed[registry]} == {r[field] for r in d[registry]}


def test_a02_distinct_release_rpm_observations():
    import hashlib
    d = document_11()
    c = collector(d, scope="release-rpm-oraclelinux-release", producer="pqc-platform", version="1.0.0")
    for release in ("0.1", "0.2"):
        data = dict(name="oraclelinux-release", version="9.9", release=release, architecture="x86_64", present=True)
        components = [data[k] for k in ("name", "version", "release", "architecture")]
        key = "r-" + hashlib.sha256(json.dumps(components, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
        row = observation(d, c, "PACKAGE_INVENTORY", data, key=key)
        assert row["asset_id"] is None and row["algorithm"] is None
        assert row["evidence_id"] == ev.evidence_id(RID, c["host_id"], c["collection_id"], key)
    ev.validate_document(d)
    assert len(set(c["evidence_ids"])) == 2
    raw = ev.canonical_bytes(d)
    d["evidence"].reverse()
    c["evidence_ids"].reverse()
    assert ev.canonical_bytes(d) == raw
