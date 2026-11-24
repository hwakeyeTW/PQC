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
    return observation(d, c, "COLLECTION_SUMMARY", dict(scope="all", attempted=attempted,
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
