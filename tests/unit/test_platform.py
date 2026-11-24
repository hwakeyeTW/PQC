"""B01-B03: synthetic facts, bounded RPM reader and Evidence integration."""
import builtins
import copy
import hashlib
import io
import json
from pathlib import Path
import socket
import subprocess
import sys
import time

import pytest
import yaml

from tools import evidence as ev
from tools import platform as pq

ROOT = Path(__file__).resolve().parents[2]
ROLE = ROOT / "roles/pqc_platform_crypto/tasks/platform.yml"
MIRROR = ROOT / "ansible_collections/security/compliance_pqc_readiness/roles/pqc_platform_crypto/tasks/platform.yml"
TS = "2026-01-01T00:00:00Z"
HID = ev.host_id("fixture-authority", "fixture-host.example.invalid")
SOURCE = dict(source_kind="SYNTHETIC", producer_id="pqc-platform", producer_version="1.0.0",
              origin_ref="fixture-platform", input_sha256=None)
NAME = "oraclelinux-release"


def facts(**changes):
    return dict(distribution="OracleLinux", os_family="RedHat", distribution_version="9.10",
                distribution_major_version="9", architecture="x86_64") | changes


def norm(data):
    return pq.normalize_platform(data, source_kind="SYNTHETIC")


def stat(executable=True):
    return dict(state="OK", exists=True, isreg=True, islnk=False, executable=executable)


def tools():
    return {k: [stat() for _ in range(n)] for k, n in pq.TOOL_SLOTS.items()}


def snapshot(**changes):
    return dict(facts=facts(), facts_state="OK", tools=tools(), rpms={}) | changes


def document(state="COMPLETE", host_state="COMPLETE", kind="SYNTHETIC"):
    return dict(schema_version="1.1.0", run=dict(run_id="fixture-run", run_state=state, recorded_at=TS,
        started_at=None, finished_at=None, source=SOURCE | {"source_kind": kind}, expected_host_ids=[HID]),
        hosts=[dict(host_id=HID, target_id="fixture-host.example.invalid", identity_scope="STABLE",
                    host_state=host_state, reason_code="FIXTURE", inventory_authority_id="fixture-authority", identity_key=None)],
        collections=[], assets=[], evidence=[], claims=[], findings=[])


def build(s, d=None, **context):
    if d is None:
        d = document()
    return pq.build_platform_evidence(d, HID, **(dict(source=SOURCE, observed_at=TS, snapshot=s) | context))


def integrated(d, p):
    return {**d, "collections": d["collections"] + p["collections"], "evidence": d["evidence"] + p["evidence"]}


def rpm_result(state="COLLECTED", reason="OK", rows=None):
    return dict(state=state, reason=reason, rows=[[NAME, "9.10", "0.1", "x86_64"]] if rows is None else rows)


@pytest.mark.parametrize("version,expected", [("9.7", (9, 7, None)), ("9.8", (9, 8, None)),
    ("9.9", (9, 9, None)), ("9.10", (9, 10, None)), ("9.0", (9, 0, None)),
    ("9.10.2", (9, 10, 2)), ("9.9007199254740991", (9, 9007199254740991, None))])
def test_b01_numeric_versions(version, expected):
    data, gaps = norm(facts(distribution_version=version))
    assert tuple(data[k] for k in ("major", "minor", "patch")) == expected
    assert data["os_version"] == version and data["platform_status"] == "UNVERIFIED" and not gaps


@pytest.mark.parametrize("dist", ["OracleLinux", "Oracle Linux", "oracle-linux", "ORACLELINUX"])
def test_b01_exact_aliases(dist):
    data, gaps = norm(facts(distribution=dist))
    assert data["distribution"] == "oracle-linux" and data["platform_status"] == "UNVERIFIED" and not gaps


@pytest.mark.parametrize("dist,family,status", [("RedHat", "RedHat", "OUT_OF_SCOPE"),
    ("Rocky", "RedHat", "OUT_OF_SCOPE"), ("AlmaLinux", "RedHat", "OUT_OF_SCOPE"),
    ("Debian", "Debian", "OUT_OF_SCOPE"), ("UnknownOracleLinux", "RedHat", "UNKNOWN"),
    (None, "RedHat", "UNKNOWN"), ("OracleLinux", "Debian", "UNKNOWN")])
def test_b01_distinct_distributions(dist, family, status):
    data, _ = norm(facts(distribution=dist, os_family=family))
    assert data["platform_status"] == status
    assert (data["distribution"] == "oracle-linux") == (dist == "OracleLinux")


@pytest.mark.parametrize("version,major,status", [("8.10", "8", "OUT_OF_SCOPE"), ("10.1", "10", "OUT_OF_SCOPE"),
    ("9", "9", "UNKNOWN"), (None, 9, "UNKNOWN"), ("9.10", None, "UNVERIFIED")])
def test_b01_partial_version_and_major(version, major, status):
    data, _ = norm(facts(distribution_version=version, distribution_major_version=major))
    assert data["platform_status"] == status
    assert data["major"] == (int(major) if major is not None else 9)


@pytest.mark.parametrize("version,major", [("9.10", "8"), ("9.01", "9"), ("09.10", "9"),
    ("9.10-foo", "9"), ("9.10.1.2", "9"), ("9.9007199254740992", "9"),
    ("9.10", True), ("9.10", "09"), (9, "9"), ("9.10\n", "9")])
def test_b01_bad_version_no_guess(version, major):
    data, gaps = norm(facts(distribution_version=version, distribution_major_version=major))
    assert data["platform_status"] == "UNKNOWN" and "VERSION_UNRESOLVED" in gaps
    assert all(data[k] is None for k in ("os_version", "major", "minor", "patch"))
    assert data["architecture"] == "x86_64" and data["distribution"] == "oracle-linux"


def test_b01_namespaced_legacy_conflicts():
    raw = facts()
    legacy = {"ansible_" + k: v for k, v in raw.items()}
    assert norm(raw) == norm(legacy) == norm({"ansible_facts": raw}) == norm({"ansible_facts": legacy})
    data, gaps = norm({**raw, "os_release_id": "ol"})
    assert data["distribution"] == "oracle-linux" and not gaps
    data, _ = norm({**raw, "os_release_id": "rhel"})
    assert data["distribution"] is None and data["platform_status"] == "UNKNOWN"
    data, _ = norm({**raw, "ansible_facts": {"distribution_version": "9.9"}})
    assert data["os_version"] is None and data["platform_status"] == "UNKNOWN"
    data, _ = norm({**raw, "ansible_os_family": "Debian"})
    assert data["platform_status"] == "UNKNOWN" and data["architecture"] == "x86_64"
    data, _ = norm({"os_release_id": "ol", "distribution_version": "9.10"})
    assert data["distribution"] == "oracle-linux" and data["platform_status"] == "UNVERIFIED"


def test_b01_missing_facts_partial():
    data, gaps = norm({})
    assert all(v is None for k, v in data.items() if k != "platform_status")
    assert data["platform_status"] == "UNKNOWN" and gaps
    p = build(snapshot(facts=facts(architecture=None)))
    c = next(c for c in p["collections"] if c["scope_key"] == "platform-info")
    assert c["collection_state"] == "PARTIAL" and p["platform_status"] == "UNVERIFIED"
    p = build(snapshot(facts={}))
    assert p["collections"][0]["collection_state"] == "UNKNOWN"


@pytest.mark.parametrize("bad", [{"ansible_env": {"SECRET": "DUMMY_SECRET_SENTINEL"}},
    {"ansible_facts": {"ansible_ssh_private_key_file": "DUMMY_SECRET_SENTINEL"}},
    {"architecture": ["x86_64"]}, {"distribution": "x"*129}, {"ansible_facts": None}])
def test_b01_reject_raw_or_unbounded_facts(bad):
    with pytest.raises(ev.EvidenceError) as e:
        norm(bad)
    assert "DUMMY_SECRET_SENTINEL" not in str(e.value)


@pytest.mark.parametrize("row,available,state", [(stat(), True, "COLLECTED"), (stat(False), False, "COLLECTED"),
    (dict(state="OK", exists=False), False, "COLLECTED"),
    (dict(state="OK", exists=True, isreg=False, islnk=False), False, "COLLECTED"),
    (dict(state="OK", exists=True, isreg=False, islnk=True, executable=True), None, "UNKNOWN"),
    (dict(state="OK", exists=True, isreg=True, islnk=False), None, "UNKNOWN"),
    (dict(state="PERMISSION_DENIED"), None, "PERMISSION_DENIED"),
    (dict(state="ERROR"), None, "ERROR"), (dict(state="UNKNOWN"), None, "UNKNOWN")])
def test_b02_tool_candidates(row, available, state):
    t = tools(); t["openssl"] = [row]
    result = pq.normalize_tools(t)["openssl"]
    assert result[0] == state and result[2]["available"] is available


def test_b02_multiple_tool_paths():
    t = tools(); t["update-crypto-policies"] = [stat(), {"state": "ERROR"}]
    result = pq.normalize_tools(t)["update-crypto-policies"]
    assert result[0] == "PARTIAL" and result[2]["available"] is True
    t["update-crypto-policies"][0] = stat(False)
    result = pq.normalize_tools(t)["update-crypto-policies"]
    assert result[0] == "ERROR" and result[2]["available"] is None
    t["update-crypto-policies"][1] = {"state": "OK", "exists": False}
    assert pq.normalize_tools(t)["update-crypto-policies"][2]["available"] is False


@pytest.mark.parametrize("bad", [{"state": "OK", "exists": 1}, {"state": "ERROR", "exists": True},
    {"state": "OK", "path": "/synthetic/private"}, {"state": "OK", "checksum": "secret"}])
def test_b02_reject_raw_stat(bad):
    t = tools(); t["rpm"] = [bad]
    with pytest.raises(ev.EvidenceError):
        pq.normalize_tools(t)


@pytest.fixture(scope="module")
def helper():
    tasks = yaml.safe_load(ROLE.read_text())
    task, = [t for t in tasks if "ansible.builtin.command" in t]
    argv = task["ansible.builtin.command"]["argv"]
    assert argv[:8] == ["/usr/bin/timeout", "--signal=TERM", "--kill-after=2s", "27s",
                        "/usr/bin/python3", "-I", "-B", "-c"]
    namespace = {"__name__": "synthetic_test"}
    exec(compile(argv[8], "<fixed-rpm-helper>", "exec"), namespace)
    return namespace


def line(release="0.1", name=NAME, arch="x86_64"):
    return ("\t".join([name, "9.10", release, arch]) + "\n").encode()


@pytest.mark.parametrize("rc,out,err,state,reason,count", [
    (0, line(), b"", "COLLECTED", "OK", 1),
    (0, line()+line("0.2"), b"", "COLLECTED", "OK", 2),
    (0, line()*2, b"", "PARTIAL", "INCOMPLETE_RPM_ROWS", 1),
    (0, line()+b"invalid\n", b"", "PARTIAL", "INCOMPLETE_RPM_ROWS", 1),
    (0, line(name="unapproved"), b"", "ERROR", "MALFORMED_OUTPUT", 0),
    (0, line(arch="../fixture"), b"", "ERROR", "MALFORMED_OUTPUT", 0),
    (0, line(release="x"*129), b"", "ERROR", "MALFORMED_OUTPUT", 0),
    (0, line()[:-1], b"", "ERROR", "MALFORMED_OUTPUT", 0),
    (0, b"\xff\n", b"", "ERROR", "MALFORMED_OUTPUT", 0),
    (0, b"", b"", "UNKNOWN", "NO_DATA", 0),
    (1, b"package oraclelinux-release is not installed\n", b"", "ABSENT", "PACKAGE_ABSENT", 0),
    (1, b"", b"package oraclelinux-release is not installed\n", "ABSENT", "PACKAGE_ABSENT", 0),
    (1, b"package oraclelinux-release is not installed\n", b"lock failed", "ERROR", "COMMAND_FAILED", 0),
    (2, b"package oraclelinux-release is not installed\n", b"", "ERROR", "COMMAND_FAILED", 0),
    (1, b"", b"Permission denied", "PERMISSION_DENIED", "PERMISSION_DENIED", 0),
    (1, b"", b"database locked", "ERROR", "COMMAND_FAILED", 0),
    (0, line(), b"warning", "ERROR", "COMMAND_FAILED", 0),
    (0, line()*33, b"", "ERROR", "OUTPUT_LIMIT", 0),
    (0, b"x"*16385, b"", "ERROR", "OUTPUT_LIMIT", 0),
    (0, b"x"*8192, b"x"*8193, "ERROR", "OUTPUT_LIMIT", 0),
], ids=["one", "two", "duplicate", "partial", "foreign-name", "bad-arch", "long-release", "truncated", "non-ascii", "empty", "absent-stdout", "absent-stderr", "mixed-absence", "wrong-rc", "permission", "lock", "warning", "row-cap", "byte-cap", "combined-cap"])
def test_b02_rpm_result_parser(helper, rc, out, err, state, reason, count):
    result = helper["parse"](NAME, rc, out, err)
    assert result["state"] == state and result["reason"] == reason and len(result["rows"]) == count
    normalized = pq.normalize_rpm(NAME, json.loads(json.dumps(result)))
    assert normalized[0] == ("COLLECTED" if state == "ABSENT" else state)
    if state == "ABSENT":
        assert normalized[2] == [dict(name=NAME, version=None, release=None, architecture=None, present=False)]


@pytest.mark.parametrize("script", ["import os; os.write(1,b'x'*1000000)", "import os; os.write(2,b'x'*1000000)",
                                   "import os; os.write(1,b'x'*8192); os.write(2,b'x'*8193)"])
def test_b02_actual_bounded_reader(helper, script):
    started = time.monotonic()
    got = helper["capture"]([sys.executable, "-I", "-B", "-c", script])
    assert got == dict(state="ERROR", reason="OUTPUT_LIMIT", rows=[])
    assert time.monotonic() - started < 5


def test_b02_actual_reader_normal_and_missing(helper):
    result = helper["capture"]([sys.executable, "-I", "-B", "-c", "import os; os.write(1,b'abc'); os.write(2,b'def')"])
    assert result == (0, b"abc", b"def")
    result = helper["capture"](["/synthetic/nonexistent-fixture-executable"])
    assert result == dict(state="UNKNOWN", reason="TOOL_UNAVAILABLE", rows=[])


def test_b02_actual_reader_timeout(helper, monkeypatch):
    # Speed up only the test clock; run and reap a real disposable process.
    from types import SimpleNamespace
    clock = iter([0.0, 22.95, 24.0])
    monkeypatch.setitem(helper, "time", SimpleNamespace(monotonic=lambda: next(clock), sleep=time.sleep))
    got = helper["capture"]([sys.executable, "-I", "-B", "-c", "import time; time.sleep(60)"])
    assert got == dict(state="ERROR", reason="TIMEOUT", rows=[])


@pytest.mark.parametrize("result", [rpm_result(rows=[["other", "9", "1", "x86_64"]]),
    rpm_result(rows=[[NAME, "9", "1", "x86_64"]]*2), rpm_result(rows=[[NAME, "9", "1", "x86_64"]]*33),
    rpm_result(state="ABSENT", reason="PACKAGE_ABSENT"), rpm_result(state="ERROR", reason="TIMEOUT"),
    rpm_result(state="COLLECTED", rows=[]), rpm_result(rows=[] ) | {"raw": "DUMMY_SECRET_SENTINEL"}])
def test_b02_reject_forged_rpm_projection(result):
    with pytest.raises(ev.EvidenceError) as e:
        pq.normalize_rpm(NAME, result)
    assert "DUMMY_SECRET_SENTINEL" not in str(e.value)


@pytest.mark.parametrize("change", [dict(distribution="RedHat"), dict(distribution_version="8.1", distribution_major_version="8"),
                                   dict(distribution_version="9", architecture=None), dict(os_family="Debian")])
def test_b02_rpm_outside_scope(change):
    s = snapshot(facts=facts(**change), rpms={NAME: rpm_result()})
    with pytest.raises(ev.EvidenceError, match="RPM_OUTSIDE_SCOPE"):
        build(s)
    s["rpms"] = {}
    p = build(s)
    assert all(c["collection_state"] == "NOT_SCANNED" and not c["evidence_ids"]
               for c in p["collections"] if c["scope_key"].startswith("release-rpm-"))


def test_b02_missing_tool_blocks_rpm():
    t = tools(); t["rpm"] = [stat(False)]
    with pytest.raises(ev.EvidenceError, match="RPM_OUTSIDE_SCOPE"):
        build(snapshot(tools=t, rpms={NAME: rpm_result()}))


@pytest.mark.parametrize("state,reason", [("ERROR", "TIMEOUT"), ("ERROR", "OUTPUT_LIMIT"),
    ("UNKNOWN", "TOOL_UNAVAILABLE"), ("PERMISSION_DENIED", "PERMISSION_DENIED"),
    ("ERROR", "COMMAND_FAILED"), ("UNKNOWN", "NO_DATA")])
def test_b03_failure_coverage(state, reason):
    p = build(snapshot(rpms={NAME: rpm_result(state, reason, [])}))
    c = next(c for c in p["collections"] if c["scope_key"] == "release-rpm-" + NAME)
    assert c["collection_state"] == state and c["reason_code"] == reason and not c["evidence_ids"]


def test_b03_evidence_scope_identity_summary_and_roundtrip():
    s = snapshot(rpms={NAME: rpm_result(rows=[[NAME,"9.10","0.1","x86_64"], [NAME,"9.10","0.2","x86_64"]]),
                       pq.PACKAGES[1]: rpm_result("ABSENT", "PACKAGE_ABSENT", [])})
    d = document(); before = copy.deepcopy((d, s, SOURCE))
    p = build(s, d)
    assert (d, s, SOURCE) == before and p["schema_version"] == "1.1.0"
    full = integrated(d, p); ev.validate_document(full)
    assert len(p["collections"]) == 10 and not full["claims"] and not full["findings"] and not full["assets"]
    byid = {c["collection_id"]: c for c in p["collections"]}
    for e in p["evidence"]:
        c = byid[e["collection_id"]]
        assert e["asset_id"] is None and e["algorithm"] is None and e["observed_at"] == TS
        assert e["source"] == c["source"] == SOURCE and e["host_id"] == HID
        assert e["evidence_id"] in c["evidence_ids"]
        assert c["collection_id"] == ev.collection_id("fixture-run", HID, pq.COLLECTOR, c["scope_key"])
        assert e["evidence_id"] == ev.evidence_id("fixture-run", HID, c["collection_id"], e["observation_key"])
        if e["evidence_kind"] == "COLLECTION_SUMMARY":
            assert e["data"]["scope"] == c["scope_key"] and e["data"]["observation_count"] == len(c["evidence_ids"])-1
        if e["evidence_kind"] == "PACKAGE_INVENTORY":
            parts = [e["data"][k] for k in ("name", "version", "release", "architecture")]
            assert e["observation_key"] == "r-" + hashlib.sha256(json.dumps(parts, separators=(",", ":")).encode()).hexdigest()
    raw = ev.canonical_bytes(full)
    s["rpms"][NAME]["rows"].reverse()
    assert ev.canonical_bytes(integrated(d, build(s, d))) == raw
    assert ev.canonical_bytes(ev.parse_evidence_bytes(raw)) == raw


def test_b03_partial_and_unknown_coverage():
    t = tools(); t["openssl"] = [{"state": "PERMISSION_DENIED"}]
    s = snapshot(facts=facts(architecture=None), tools=t, rpms={NAME: rpm_result("PARTIAL", "INCOMPLETE_RPM_ROWS")})
    p = build(s)
    c = {c["scope_key"]: c for c in p["collections"]}
    assert c["platform-info"]["collection_state"] == "PARTIAL"
    assert c["tool-openssl"]["collection_state"] == "PERMISSION_DENIED"
    assert c["release-rpm-"+NAME]["collection_state"] == "PARTIAL"
    assert c["release-rpm-"+pq.PACKAGES[1]]["observed_at"] is None
    e = next(e for e in p["evidence"] if e["evidence_kind"] == "TOOL_AVAILABILITY" and e["data"]["tool_id"] == "openssl")
    assert e["data"]["available"] is None
    assert not any(e["evidence_kind"] == "COLLECTION_SUMMARY" and e["collection_id"] == c["tool-openssl"]["collection_id"] for e in p["evidence"])


def test_b03_no_io_no_mutation_and_context(monkeypatch):
    s = snapshot(); d = document(); before = copy.deepcopy((d,s,SOURCE))
    def forbidden(*a, **kw):
        raise AssertionError("unexpected I/O")
    with monkeypatch.context() as m:
        for mod, name in [(builtins,"open"), (io,"open"), (socket,"socket"), (socket,"create_connection"), (subprocess,"Popen")]:
            m.setattr(mod, name, forbidden)
        p = build(s, d)
        ev.canonical_bytes(integrated(d,p))
        assert (d,s,SOURCE) == before
    with pytest.raises(ev.EvidenceError):
        build(s, document(kind="NATIVE_COLLECTOR"))
    with pytest.raises(ev.EvidenceError):
        build(s, source=SOURCE | {"producer_id":"other"})
    with pytest.raises(ev.EvidenceError):
        build(s, observed_at=None)
    with pytest.raises(ev.EvidenceError):
        build(s, document("PLANNED", "NOT_ATTEMPTED"))
    with pytest.raises(ev.EvidenceError):
        build(s, document() | {"schema_version":"1.0.0"})


def test_b03_metadata_cannot_support_readiness():
    d = document(); p = build(snapshot()); full = integrated(d,p)
    e = next(e for e in p["evidence"] if e["evidence_kind"] == "TOOL_AVAILABILITY")
    subject = dict(host_id=HID)
    for level in ("L1", "L2", "L3"):
        for state in ("PASS", "FAIL"):
            cl = dict(claim_id=ev.claim_id("fixture-run",subject,level,"fixture-rule","fixture-claim"),
                      subject=subject, level=level, claim_key="fixture-claim", assessment_state=state,
                      rule_id="fixture-rule", rule_version="1", reason_code="FIXTURE", conditions=None,
                      evidence_ids=[e["evidence_id"]])
            with pytest.raises(ev.EvidenceError, match="CLAIM_EVIDENCE_REQUIRED"):
                ev.validate_document(full | {"claims":[cl]})


def test_b02_role_contract_and_mirror():
    assert ROLE.read_bytes() == MIRROR.read_bytes()
    assert ROLE.stat().st_mode & 0o777 == MIRROR.stat().st_mode & 0o777 == 0o644
    tasks = yaml.safe_load(ROLE.read_text())
    assert all(t.get("no_log") is True for t in tasks)
    assert all(not t.get("become", False) for t in tasks)
    assert {k for t in tasks for k in t if k.startswith("ansible.builtin.")} == {
        "ansible.builtin.setup", "ansible.builtin.stat", "ansible.builtin.command", "ansible.builtin.set_fact"}
    setup, stat_task = tasks[:2]
    assert setup["ansible.builtin.setup"]["gather_subset"] == ["!all","!min","distribution","os_family","architecture"]
    assert setup["ansible.builtin.setup"]["filter"] == ["ansible_"+k for k in pq.FACT_NAMES]
    assert stat_task["ansible.builtin.stat"] == dict(path="{{ item.path }}", follow=False, get_checksum=False, get_mime=False, get_attributes=False)
    assert [(x["id"],x["path"]) for x in stat_task["loop"]] == [
        ("rpm","/usr/bin/rpm"),("openssl","/usr/bin/openssl"),("ssh","/usr/bin/ssh"),("sshd","/usr/sbin/sshd"),
        ("ssh-keygen","/usr/bin/ssh-keygen"),("update-crypto-policies","/usr/bin/update-crypto-policies"),
        ("update-crypto-policies","/usr/sbin/update-crypto-policies"),("timeout","/usr/bin/timeout")]
    command, = [t for t in tasks if "ansible.builtin.command" in t]
    assert command["loop"] == list(pq.PACKAGES) and command["environment"] == {"LC_ALL":"C"}
    assert command["changed_when"] is False and len(command["when"]) >= 8
    assert not (ROLE.parent / "main.yml").exists() and not (MIRROR.parent / "main.yml").exists()


def test_b02_known_ol_with_missing_family_remains_candidate():
    p = build(snapshot(facts=facts(os_family=None), rpms={NAME: rpm_result()}))
    assert p["platform_status"] == "UNVERIFIED"
    assert p["collections"][0]["collection_state"] == "PARTIAL"
    assert next(c for c in p["collections"] if c["scope_key"] == "release-rpm-"+NAME)["collection_state"] == "COLLECTED"


def test_b03_native_context_and_duplicate_scope():
    d = document("PARTIAL", "PARTIAL", kind="NATIVE_COLLECTOR")
    source = SOURCE | {"source_kind": "NATIVE_COLLECTOR"}
    s = snapshot(facts={}, facts_state="PERMISSION_DENIED")
    result = build(s, d, source=source)
    full = integrated(d, result)
    ev.validate_document(full)
    assert result["platform_status"] == "UNKNOWN"
    assert result["collections"][0]["collection_state"] == "PERMISSION_DENIED"
    assert not result["collections"][0]["evidence_ids"]
    assert all(c["source"] == source for c in result["collections"])
    with pytest.raises(ev.EvidenceError, match="DUPLICATE_ID"):
        build(s, full, source=source)
    with pytest.raises(ev.EvidenceError, match="PLATFORM_HOST"):
        pq.build_platform_evidence(d, ev.host_id("fixture-authority", "other.example.invalid"),
                                   source=source, observed_at=TS, snapshot=s)
