"""P01-P03 synthetic data and actual fixed helper tests; no host policy reads."""
import builtins
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time

import pytest
import yaml

from tools import assessment, crypto_policy as cp, evidence as ev, platform

ROOT = Path(__file__).resolve().parents[2]
ROLE = ROOT / "roles/pqc_platform_crypto/tasks/crypto_policy.yml"
CANONICAL = ROOT / "ansible_collections/security/compliance_pqc_readiness/roles/pqc_platform_crypto/tasks/crypto_policy.yml"
TS = "2026-01-01T00:00:00Z"


@pytest.fixture(scope="module")
def rules():
    return assessment.load_rules((ROOT / "config/assessment_rules.yml").read_bytes())


@pytest.fixture(scope="module")
def role():
    return yaml.safe_load(ROLE.read_text(encoding="utf-8"))[0]


@pytest.fixture(scope="module")
def helper_source(role):
    task = next(t for t in role["block"] if "ansible.builtin.command" in t)
    return task["ansible.builtin.command"]["argv"][8]


@pytest.fixture
def helper(helper_source):
    ns = {"__name__": "_synthetic_policy_helper"}
    exec(compile(helper_source, "<fixed-policy-helper>", "exec"), ns)
    return ns


def result(state="NOT_SCANNED", reason="NOT_ATTEMPTED", **kw):
    return cp.result(state, reason, **kw)


def snapshot(**slots):
    return {k: slots.get(k, result()) for k in cp.SCOPES}


def source(producer="pqc-crypto-policy", kind="SYNTHETIC"):
    return dict(source_kind=kind, producer_id=producer, producer_version="1.0.0",
                origin_ref="fixture-policy", input_sha256=None)


def document(state="COMPLETE", version="1.1.0"):
    hid = ev.host_id("fixture-authority", "host-a.example.invalid")
    return dict(schema_version=version,
                run=dict(run_id="fixture-run", run_state="PLANNED" if state == "NOT_ATTEMPTED" else "COMPLETE",
                         recorded_at=TS, started_at=None, finished_at=None,
                         source=source("fixture"), expected_host_ids=[hid]),
                hosts=[dict(host_id=hid, target_id="host-a.example.invalid", identity_scope="STABLE",
                            inventory_authority_id="fixture-authority", identity_key=None,
                            host_state=state, reason_code="FIXTURE")],
                collections=[], assets=[], evidence=[], claims=[], findings=[])


def available():
    return dict(state="OK", exists=True, isreg=True, islnk=False, executable=True)


def platform_snapshot(**facts):
    return dict(facts_state="OK", facts=dict(distribution="OracleLinux", os_family="RedHat",
                distribution_version="9.10", distribution_major_version="9", architecture="x86_64") | facts,
                tools={k: [available() for _ in range(n)] for k, n in platform.TOOL_SLOTS.items()}, rpms={})


def build(d, s, rules, **kw):
    params = dict(source=source(), observed_at=TS, snapshot=s, rules=rules,
                  platform_snapshot=platform_snapshot(), requested=True) | kw
    return cp.build_crypto_policy_evidence(d, d["hosts"][0]["host_id"], **params)


def integrated(d, rows):
    return {**d, "collections": d["collections"] + rows["collections"], "evidence": d["evidence"] + rows["evidence"]}


def parse(scope, raw, rc=None):
    return cp.parse_source(scope, raw, rc=rc)


@pytest.mark.parametrize("raw,expected", [(b"DEFAULT\n", "DEFAULT"), (b"FIPS", "FIPS"),
    (b"DEFAULT:SHA1\n", "DEFAULT:SHA1"), (b"# fixture\n\nFUTURE\n", "FUTURE")])
def test_p02_profile_config(raw, expected):
    row = parse("profile-config", raw)
    assert row["state"] == "COLLECTED" and row["values"] == [["profile", expected]]


@pytest.mark.parametrize("raw", [b"", b"DEFAULT\nFIPS\n", b"FIPS enabled\n", b"not enabled\n",
    b"DEFAULT;COMMAND", b"DEFAULT:$VAR", b"DEFAULT:SHA1:ADDITIONAL:MODULE:EXCESS",
    b"DEFAULT\x00", b"\xff", b"DEFAULT\r\n", b"../DEFAULT", b"{{secret}}"])
def test_p02_ambiguous_profiles(raw):
    for scope, rc in [("profile-config", None), ("profile-show", 0)]:
        row = parse(scope, raw, rc)
        assert row["state"] == "UNKNOWN" and row["values"] == []


@pytest.mark.parametrize("rc", [1, 7, 124, -9, None, True])
def test_p02_show_rc_not_success(rc):
    row = parse("profile-show", b"FIPS\n", rc)
    assert row["state"] == "ERROR" and not row["values"]


@pytest.mark.parametrize("raw,expected", [(b"0", False), (b"0\n", False), (b"1", True), (b"1\n", True),
    (b"", None), (b"not enabled\n", None), (b"FIPS", None), (b"01\n", None), (b"1\n\n", None),
    (b" 1", None), (b"1\r\n", None), (b"true", None), (b"1 0", None)])
def test_p02_kernel_exact(raw, expected):
    row = parse("kernel-fips", raw)
    assert (row["values"][0][1] if row["values"] else None) is expected
    assert row["state"] == ("UNKNOWN" if expected is None else "COLLECTED")


@pytest.mark.parametrize("scope,raw,values", [
    ("current-policy", b"cipher = AES-128-GCM AES-256-GCM\nsign = ML-DSA-65\ngroup = X25519\nkey_exchange = ECDHE\nprotocol = TLS1.2\n",
     [["cipher", "AES-128-GCM"], ["cipher", "AES-256-GCM"], ["group", "X25519"], ["key-exchange", "ECDHE"], ["protocol", "TLS1.2"], ["sign", "ML-DSA-65"]]),
    ("backend-openssh", b"Ciphers aes128-ctr,aes256-ctr\nKexAlgorithms mlkem768x25519-sha256,curve25519-sha256\n",
     [["ciphers", "aes128-ctr"], ["ciphers", "aes256-ctr"], ["kex-algorithms", "mlkem768x25519-sha256"], ["kex-algorithms", "curve25519-sha256"]]),
    ("backend-opensshserver", b"HostKeyAlgorithms ssh-rsa\nPubkeyAcceptedAlgorithms RSA-SHA256\n",
     [["host-key-algorithms", "ssh-rsa"], ["pubkey-accepted-algorithms", "RSA-SHA256"]]),
    ("backend-openssl", b"CipherString = ECDHE-RSA-AES256-GCM-SHA384\nMinProtocol = TLSv1.2\n",
     [["cipher-string", "ECDHE-RSA-AES256-GCM-SHA384"], ["min-protocol", "TLSv1.2"]]),
    ("backend-opensslcnf", b"Ciphersuites=TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384\n",
     [["cipher-suites", "TLS_AES_128_GCM_SHA256"], ["cipher-suites", "TLS_AES_256_GCM_SHA384"]]),
])
def test_p02_literal_grammar(scope, raw, values):
    row = parse(scope, raw)
    assert row["state"] == "COLLECTED" and row["values"] == values


@pytest.mark.parametrize("raw", [b"KexAlgorithms +curve25519-sha256", b"KexAlgorithms -curve25519-sha256",
    b"KexAlgorithms curve*", b"KexAlgorithms ${VAR}", b"KexAlgorithms a,b,a", b"KexAlgorithms a,,b",
    b"Include /private/DUMMY_SECRET_SENTINEL", b"CRYPTO_POLICY='-oCiphers=aes128-ctr'", b"KexAlgorithms a b",
    b"KexAlgorithms a\nKexAlgorithms b", b"KexAlgorithms a\nKexAlgorithms +b\nKexAlgorithms a"])
def test_p02_ssh_no_complex_expansion(raw):
    row = parse("backend-opensshserver", raw)
    assert row["state"] == "UNKNOWN" and not row["values"]
    assert "DUMMY_SECRET_SENTINEL" not in json.dumps(row)


@pytest.mark.parametrize("raw", [b"CipherString = DEFAULT", b"CipherString = HIGH:!aNULL",
    b"CipherString = AESGCM", b"CipherString = ECDHE+AESGCM", b"CipherString = @SECLEVEL=2",
    b"Ciphersuites=TLS_AES_128_GCM_SHA256:!TLS_AES_256_GCM_SHA384", b"MinProtocol = TLSv1.2:TLSv1.3"])
def test_p02_ssl_complex_not_literal(raw):
    assert parse("backend-openssl", raw)["state"] == "UNKNOWN"


def test_p02_partial_keeps_only_uncontradicted_values():
    row = parse("backend-openssh", b"Ciphers aes128-ctr\nInclude /private/secret\nKexAlgorithms a\nKexAlgorithms b\n")
    assert row["state"] == "PARTIAL" and row["values"] == [["ciphers", "aes128-ctr"]]
    assert "/private/secret" not in json.dumps(row)
    assert parse("current-policy", b"cipher = AES\nunknown = DUMMY_SECRET_SENTINEL\n")["values"] == [["cipher", "AES"]]


def test_p02_caps():
    assert parse("current-policy", b"x" * (cp.FILE_LIMIT + 1))["reason"] == "OUTPUT_LIMIT"
    assert parse("current-policy", b"cipher = " + b" ".join(f"a{i}".encode() for i in range(65)))["state"] == "UNKNOWN"


def test_p03_end_to_end_policy_fips_conflict(rules):
    d = document()
    s = snapshot(**{"profile-config": parse("profile-config", b"FIPS\n"),
                    "profile-show": parse("profile-show", b"DEFAULT\n", 0),
                    "kernel-fips": parse("kernel-fips", b"0\n"),
                    "current-policy": parse("current-policy", b"cipher = AES\nsign = ML-DSA-65\ngroup = X25519\n"),
                    "backend-openssh": parse("backend-openssh", b"KexAlgorithms mlkem768x25519-sha256\nCiphers aes128-ctr\n"),
                    "backend-opensslcnf": parse("backend-opensslcnf", b"Ciphersuites = TLS_AES_128_GCM_SHA256\n"),
                    "local-overrides": result("COLLECTED", "OK", values=[["entry-count", 0]])})
    before = copy.deepcopy((d, s, rules))
    out = build(d, s, rules)
    assert (d, s, rules) == before
    assert out["metadata"] == dict(declared_profile="FIPS", shown_profile="DEFAULT", profile_consistency="CONFLICT", kernel_fips_enabled=False)
    assert len(out["collections"]) == 9 and len(out["diagnostics"]) == 9
    byscope = {c["scope_key"]: c for c in out["collections"]}
    assert all(byscope[k]["collection_state"] == "PARTIAL" and byscope[k]["reason_code"] == "PROFILE_CONFLICT" for k in ("profile-config", "profile-show"))
    rows = [e for e in out["evidence"] if e["evidence_kind"] == "EFFECTIVE_CONFIGURATION"]
    assert all(e["data"]["allowed"] is None and e["asset_id"] is None for e in rows)
    fips = next(e for e in rows if e["data"]["setting"] == "kernel-fips-fips-enabled")
    assert fips["data"]["effective_value"] == "disabled" and fips["algorithm"] is None
    assert any(e["algorithm"] and e["algorithm"]["algorithm_id"] == "ssh-mlkem768x25519-sha256" for e in rows)
    assert any(e["algorithm"] and e["algorithm"]["algorithm_id"] == "ml-dsa-65-signature" for e in rows)
    assert next(e for e in rows if e["data"]["setting"] == "current-policy-group")["algorithm"] is None
    for c in out["collections"]:
        linked = [e for e in out["evidence"] if e["collection_id"] == c["collection_id"]]
        assert set(c["evidence_ids"]) == {e["evidence_id"] for e in linked}
        for e in linked:
            assert e["evidence_id"] == ev.evidence_id(d["run"]["run_id"], c["host_id"], c["collection_id"], e["observation_key"])
            if e["evidence_kind"] == "COLLECTION_SUMMARY":
                assert e["data"]["scope"] == c["scope_key"] and e["data"]["observation_count"] == len(linked) - 1
    complete = integrated(d, out)
    raw = ev.canonical_bytes(complete)
    assert ev.canonical_bytes(ev.parse_evidence_bytes(raw)) == raw
    evaluated = assessment.evaluate_document(ev.parse_evidence_bytes(raw), rules)
    assert evaluated["schema_version"] == "1.1.0" and evaluated["claims"]
    assert all(c["assessment_state"] == "UNKNOWN" and c["level"] == "L3" for c in evaluated["claims"])
    assert all(f["assessment_state"] not in ("PASS", "FAIL") for f in evaluated["findings"])
    assert ev.canonical_bytes(assessment.evaluate_document(evaluated, rules)) == ev.canonical_bytes(evaluated)
    assert ev.canonical_bytes(integrated(d, build(d, s, rules))) == raw


@pytest.mark.parametrize("reason,state,rc", [("SOURCE_ABSENT", "UNKNOWN", None), ("UNSAFE_SOURCE", "UNKNOWN", None),
    ("PERMISSION_DENIED", "PERMISSION_DENIED", None), ("TIMEOUT", "ERROR", 124),
    ("OUTPUT_LIMIT", "ERROR", -9), ("COMMAND_FAILED", "ERROR", 7)])
def test_p03_failure_coverage(reason, state, rc, rules):
    d = document()
    out = build(d, snapshot(**{"profile-show": result(state, reason, rc=rc)}), rules)
    c = next(c for c in out["collections"] if c["scope_key"] == "profile-show")
    diag = next(c for c in out["diagnostics"] if c["scope"] == "profile-show")
    assert c["collection_state"] == state and not c["evidence_ids"] and diag["rc"] == rc
    x = assessment.evaluate_document(integrated(d, out), rules)
    assert not x["claims"] and all(f["assessment_state"] in ("UNKNOWN", "NOT_SCANNED") for f in x["findings"])


@pytest.mark.parametrize("facts", [{"distribution": "RedHat"}, {"distribution_version": "8.9", "distribution_major_version": "8"},
    {"distribution_version": "9.10", "distribution_major_version": "8"}, {"distribution_version": "9"},
    {"distribution_version": "9.9007199254740992"}, {"os_family": "Debian"}])
def test_p03_wrong_platform_rejects_acquired_rows(facts, rules):
    d = document()
    with pytest.raises(ev.EvidenceError, match="POLICY_OUTSIDE_SCOPE"):
        build(d, snapshot(**{"kernel-fips": parse("kernel-fips", b"1")}), rules, platform_snapshot=platform_snapshot(**facts))
    out = build(d, snapshot(), rules, platform_snapshot=platform_snapshot(**facts))
    assert all(c["collection_state"] == "NOT_SCANNED" for c in out["collections"])


@pytest.mark.parametrize("version", ["9.7", "9.8", "9.9", "9.10", "9.42.1"])
def test_p03_numeric_ol_versions(version, rules):
    out = build(document(), snapshot(**{"kernel-fips": parse("kernel-fips", b"1")}), rules,
                platform_snapshot=platform_snapshot(distribution_version=version))
    assert out["metadata"]["kernel_fips_enabled"] is True


def test_p03_flag_and_tool_gates(rules):
    d = document()
    s = snapshot(**{"profile-show": parse("profile-show", b"FIPS", 0)})
    with pytest.raises(ev.EvidenceError, match="POLICY_OUTSIDE_SCOPE"):
        build(d, s, rules, requested=False)
    p = platform_snapshot()
    p["tools"]["timeout"] = [dict(state="OK", exists=False, isreg=None, islnk=None, executable=None)]
    with pytest.raises(ev.EvidenceError, match="POLICY_OUTSIDE_SCOPE"):
        build(d, s, rules, platform_snapshot=p)
    p = platform_snapshot()
    p["tools"]["update-crypto-policies"] = [dict(state="UNKNOWN"), dict(state="UNKNOWN")]
    with pytest.raises(ev.EvidenceError, match="POLICY_TOOL_UNAVAILABLE"):
        build(d, s, rules, platform_snapshot=p)
    out = build(d, {k: result("NOT_SCANNED", "DISABLED_BY_USER") for k in cp.SCOPES}, rules, requested=False)
    assert not out["evidence"] and all(c["reason_code"] == "DISABLED_BY_USER" for c in out["collections"])


@pytest.mark.parametrize("change", ["foreign-scope", "raw", "rc", "bool", "duplicate", "bad-state", "bad-field", "bad-token", "bad-override", "partial-empty", "multiple-min", "invalid-profile-partial"])
def test_p03_closed_projection(change, rules):
    s = snapshot(**{"backend-openssl": parse("backend-openssl", b"MinProtocol=TLSv1.2\n"),
                    "profile-show": parse("profile-show", b"FIPS", 0)})
    row = s["backend-openssl"]
    if change == "foreign-scope": s["foreign"] = result()
    if change == "raw": row["raw"] = "DUMMY_SECRET_SENTINEL"
    if change == "rc": s["profile-show"]["rc"] = 7
    if change == "bool": s["profile-show"]["rc"] = False
    if change == "duplicate": row["values"] *= 2
    if change == "bad-state": row["state"] = "FAIL"
    if change == "bad-field": row["values"] = [["foreign", "foo"]]
    if change == "bad-token": row["values"] = [["min-protocol", "DUMMY_SECRET_SENTINEL"]]
    if change == "bad-override": row["overrides"] = [{}]
    if change == "partial-empty": row.update(state="PARTIAL", reason="INCOMPLETE_SYNTAX", values=[])
    if change == "multiple-min": row["values"].append(["min-protocol", "TLSv1.3"])
    if change == "invalid-profile-partial": s["profile-show"].update(state="PARTIAL", reason="PROFILE_CONFLICT")
    with pytest.raises(ev.EvidenceError) as caught:
        build(document(), s, rules)
    assert "DUMMY_SECRET_SENTINEL" not in str(caught.value)


def test_p03_identity_and_no_io(rules, monkeypatch):
    d = document(); s = snapshot(**{"kernel-fips": parse("kernel-fips", b"1")})
    with pytest.raises(ev.EvidenceError, match="SCHEMA_VERSION"):
        build(document(version="1.0.0"), s, rules)
    with pytest.raises(ev.EvidenceError, match="POLICY_HOST"):
        cp.build_crypto_policy_evidence(d, "h-" + "0" * 64, source=source(), observed_at=TS,
                                        snapshot=s, rules=rules, platform_snapshot=platform_snapshot(), requested=True)
    with pytest.raises(ev.EvidenceError):
        build(d, s, rules, source=source("other"))
    with pytest.raises(ev.EvidenceError):
        build(d, s, rules, observed_at="invalid")
    with pytest.raises(ev.EvidenceError):
        build(document(state="NOT_ATTEMPTED"), s, rules)
    def forbidden(*args, **kw):
        raise AssertionError("unexpected I/O")
    with monkeypatch.context() as m:
        for mod, attr in [(builtins, "open"), (io, "open"), (socket, "socket"), (subprocess, "Popen"), (os, "open")]:
            m.setattr(mod, attr, forbidden)
        out = build(d, s, rules)
        ev.validate_document(integrated(d, out))
        assessment.evaluate_document(integrated(d, out), rules)
        with pytest.raises(ev.EvidenceError, match="DUPLICATE_ID"):
            build(integrated(d, out), s, rules)


@pytest.fixture
def tree(tmp_path, helper):
    root = tmp_path / "root"
    root.mkdir(mode=0o755)
    if os.getuid() != 0:
        # Only fixture ownership is adapted for ordinary non-root developers.
        # The production main has no configurable trust owner or root.
        helper["trusted"] = lambda st: st.st_uid == os.getuid() and not st.st_mode & 0o022
    def write(path, raw):
        p = root / path.lstrip("/")
        p.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        p.write_bytes(raw); p.chmod(0o644)
        return p
    write("/etc/crypto-policies/config", b"# fixture\nDEFAULT\n")
    write("/etc/crypto-policies/state/CURRENT.pol", b"cipher = AES\n")
    write("/proc/sys/crypto/fips_enabled", b"0\n")
    write("/etc/crypto-policies/back-ends/openssh.config", b"Ciphers aes128-ctr\n")
    (root / "etc/crypto-policies/local.d").mkdir(mode=0o755)
    for directory in (root, *(p for p in root.rglob("*") if p.is_dir())):
        directory.chmod(0o755)
    fd = os.open(root, os.O_PATH | os.O_DIRECTORY)
    try:
        yield root, write, fd
    finally:
        os.close(fd)


def reader(helper, tree, deadline=2):
    return helper["Reader"](tree[2], time.monotonic() + deadline)


def test_p01_actual_fixed_reader_and_known_absence(helper, tree, rules):
    root, write, fd = tree
    before = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}
    rows = reader(helper, tree).collect()
    assert rows["profile-config"]["values"] == [["profile", "DEFAULT"]]
    assert rows["kernel-fips"]["values"] == [["fips-enabled", False]]
    assert rows["backend-openssl"]["reason"] == "SOURCE_ABSENT"
    assert rows["local-overrides"]["values"] == [["entry-count", 0]]
    out = build(document(), snapshot(**rows), rules)
    assert out["metadata"]["kernel_fips_enabled"] is False
    assert {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()} == before


@pytest.mark.parametrize("target,valid", [("/usr/share/crypto-policies/DEFAULT/openssh.config", True),
    ("../../../usr/share/crypto-policies/DEFAULT/openssh.config", True),
    ("/private/secret", False), ("/usr/share/crypto-policies/DEFAULT/openssl.config", False),
    ("/usr/share/crypto-policies/OTHER/openssh.config", False),
    ("/usr/share/crypto-policies/DEFAULT/../DEFAULT/openssh.config", False), ("openssh.config", False)])
def test_p01_actual_symlink_boundary(helper, tree, target, valid):
    root, write, fd = tree
    write("/usr/share/crypto-policies/DEFAULT/openssh.config", b"KexAlgorithms curve25519-sha256\n")
    write("/private/secret", b"DUMMY_SECRET_SENTINEL")
    link = root / "etc/crypto-policies/back-ends/openssh.config"; link.unlink(); link.symlink_to(target)
    # Production link ownership is checked separately; actual run is uid 0.
    row = reader(helper, tree).slot("backend-openssh")
    assert row["state"] == ("COLLECTED" if valid and os.getuid() == 0 else "UNKNOWN")
    if not valid: assert row["reason"] == "UNSAFE_SOURCE"
    assert "DUMMY_SECRET_SENTINEL" not in json.dumps(row)


@pytest.mark.parametrize("kind", ["fifo", "directory", "hardlink", "writable", "parent-link", "oversize"])
def test_p01_actual_unsafe_files(helper, tree, kind):
    root, write, fd = tree
    p = root / "etc/crypto-policies/config"; p.unlink()
    if kind == "fifo": os.mkfifo(p)
    elif kind == "directory": p.mkdir()
    elif kind == "hardlink": os.link(write("/private/secret", b"DUMMY_SECRET_SENTINEL"), p)
    elif kind == "writable": p.write_bytes(b"DEFAULT"); p.chmod(0o666)
    elif kind == "parent-link":
        parent = p.parent; parent.rename(root / "other-policy"); parent.symlink_to(root / "other-policy", target_is_directory=True)
    else: p.write_bytes(b"x" * (cp.FILE_LIMIT + 1))
    row = reader(helper, tree).slot("profile-config")
    assert row["state"] in ("ERROR", "UNKNOWN") and not row["values"]
    assert row["reason"] == ("OUTPUT_LIMIT" if kind == "oversize" else "UNSAFE_SOURCE")


def test_p01_actual_override_bounds_and_identity(helper, tree, rules):
    root, write, fd = tree
    write("/etc/crypto-policies/local.d/openssh-fixture.txt", b"KexAlgorithms mlkem768x25519-sha256\n")
    write("/etc/crypto-policies/local.d/unknown-DUMMY_SECRET_SENTINEL.txt", b"DUMMY_SECRET_SENTINEL")
    write("/etc/crypto-policies/local.d/openssl-fixture.txt", b"CipherString = DEFAULT\n")
    row = reader(helper, tree).overrides()
    assert row["state"] == "PARTIAL" and row["values"] == [["entry-count", 3]] and len(row["overrides"]) == 2
    assert "DUMMY_SECRET_SENTINEL" not in json.dumps(row) and "fixture.txt" not in json.dumps(row)
    out = build(document(), snapshot(**{"local-overrides": row}), rules)
    assert any(e["data"].get("effective_value") == "true" for e in out["evidence"])
    for i in range(30): write(f"/etc/crypto-policies/local.d/unknown-{i}", b"x")
    row = reader(helper, tree).overrides()
    assert row["reason"] == "ENTRY_LIMIT" and not row["values"] and not row["overrides"]


def test_p01_actual_total_read_budget(helper, tree):
    for name in cp.BACKENDS:
        tree[1](f"/etc/crypto-policies/back-ends/{name}.config", b"#" + b"x" * (cp.FILE_LIMIT - 1))
    r = reader(helper, tree)
    rows = r.collect()
    assert 0 <= r.remaining < cp.FILE_LIMIT
    assert any(x["reason"] == "TOTAL_LIMIT" for x in rows.values())


def test_p01_actual_permission_denial(helper, tree):
    root, write, fd = tree
    p = root / "etc/crypto-policies/config"; p.chmod(0)
    if os.getuid() != 0:
        assert reader(helper, tree).slot("profile-config")["state"] == "PERMISSION_DENIED"
        return
    # Privilege drop only in the child, never sudo or real filesystem access.
    rd, wr = os.pipe(); pid = os.fork()
    if pid == 0:
        try:
            os.close(rd); os.setgroups([]); os.setgid(65534); os.setuid(65534)
            os.write(wr, json.dumps(reader(helper, tree).slot("profile-config")).encode())
        finally:
            os._exit(0)
    os.close(wr)
    try: raw = os.read(rd, 4096)
    finally: os.close(rd); os.waitpid(pid, 0)
    assert json.loads(raw)["state"] == "PERMISSION_DENIED"


def test_p01_actual_reader_deadline(helper, tree):
    r = reader(helper, tree, deadline=0.01)
    time.sleep(0.02)
    assert r.slot("profile-config")["reason"] == "TIMEOUT"


@pytest.mark.parametrize("script,expected", [("print('DEFAULT')", "OK"), ("print('FIPS');raise SystemExit(7)", "COMMAND_FAILED"),
    ("import sys; print('FIPS'); print('unexpected',file=sys.stderr)", "AMBIGUOUS_PROFILE"),
    ("print('x'*20000)", "OUTPUT_LIMIT"), ("import sys;sys.stderr.write('x'*20000)", "OUTPUT_LIMIT"),
    ("import sys;print('x'*9000);sys.stderr.write('x'*9000)", "OUTPUT_LIMIT")])
def test_p01_actual_bounded_show(helper, script, expected):
    row = helper["capture"]([sys.executable, "-I", "-B", "-c", script], time.monotonic() + 3)
    assert row["reason"] == expected
    if expected == "OK": assert row["rc"] == 0 and row["values"] == [["profile", "DEFAULT"]]
    else: assert not row["values"]
    if expected == "COMMAND_FAILED": assert row["rc"] == 7


def test_p01_actual_show_timeout_and_reap(helper):
    start = time.monotonic()
    row = helper["capture"]([sys.executable, "-I", "-B", "-c", "import time;time.sleep(5)"], start + .2)
    assert row["reason"] == "TIMEOUT" and row["rc"] == -signal.SIGKILL and time.monotonic() - start < 2


def test_p01_actual_residual_group_cleanup(helper, tmp_path):
    late = tmp_path / "late"
    script = "import os,time\np=os.fork()\nif p==0:\n os.close(1);os.close(2);time.sleep(.5);open(" + repr(str(late)) + ",'w').write('late');os._exit(0)\nprint('DEFAULT')"
    row = helper["capture"]([sys.executable, "-I", "-B", "-c", script], time.monotonic() + 2)
    assert row["reason"] == "CLEANUP_FAILED" and row["rc"] == 0 and not row["values"]
    time.sleep(.55)
    assert not late.exists()


def test_p01_mirror_and_fixed_helper(role, helper_source):
    assert ROLE.read_bytes() == CANONICAL.read_bytes() and ROLE.stat().st_mode & 0o777 == CANONICAL.stat().st_mode & 0o777 == 0o644
    grammar = (ROOT / "tools/crypto_policy.py").read_text().split("# BEGIN SHARED POLICY GRAMMAR (also embedded in the fixed acquisition helper)\n")[1].split("# END SHARED POLICY GRAMMAR")[0]
    assert helper_source.split("# BEGIN SHARED POLICY GRAMMAR\n")[1].split("# END SHARED POLICY GRAMMAR")[0] == grammar
    task = next(t for t in role["block"] if "ansible.builtin.command" in t)
    assert task["ansible.builtin.command"]["argv"][:8] == ["/usr/bin/timeout", "--signal=TERM", "--kill-after=2s", "27s", "/usr/bin/python3", "-I", "-B", "-c"]
    assert task["loop"] == ["reader", "show-bin", "show-sbin"] and task["ansible.builtin.command"]["argv"][-1] == "{{ item }}"
    assert task["ansible.builtin.command"]["expand_argument_vars"] is False and role["no_log"] is True and role["become"] is False
