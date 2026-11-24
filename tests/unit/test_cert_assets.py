"""X01-X03 actual OpenSSL and fixed reader tests, private synthetic inputs."""
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import time

import pytest
import yaml

from tools import assessment, cert_assets as ca, evidence as ev, platform

ROOT = Path(__file__).resolve().parents[2]
ROLE = ROOT / "roles/pqc_platform_crypto/tasks/cert_assets.yml"
MIRROR = ROOT / "ansible_collections/security/compliance_pqc_readiness/roles/pqc_platform_crypto/tasks/cert_assets.yml"
TS = "2026-01-01T00:00:00Z"
SLOT = ca.ROOTS[0]


@pytest.fixture(scope="module")
def role():
    return yaml.safe_load(ROLE.read_text())[0]


@pytest.fixture
def helper(role):
    ns = {"__name__": "_synthetic_certificate_helper"}
    exec(compile(role["block"][4]["ansible.builtin.command"]["argv"][8], "<fixed-helper>", "exec"), ns)
    # Non-root developer fixtures may be owned only by the test user. Production
    # main has no such option. Root tests exercise the exact production rule.
    if os.geteuid() != 0:
        ns["trusted"] = lambda st: st.st_uid == os.geteuid() and not st.st_mode & 0o022
    return ns


@pytest.fixture(scope="module")
def certs(tmp_path_factory):
    p = tmp_path_factory.mktemp("public-cert-fixture")
    os.chmod(p, 0o700)
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "OPENSSL_CONF": "/dev/null", "HOME": str(p)}
    def cli(*args, data=None):
        return subprocess.run(["/usr/bin/openssl", *args], input=data, cwd=p, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=True).stdout
    old = os.umask(0o077)
    try:
        cli("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem",
            "-days", "2", "-subj", "/CN=fixture-ca.example.invalid/O=Fixture")
        cli("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
            "-keyout", "leaf.key", "-out", "leaf.csr", "-subj", "/CN=fixture-leaf.example.invalid")
        cli("x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-set_serial", "2",
            "-days", "1", "-out", "leaf.pem")
        cli("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
            "-keyout", "unsafe.key", "-out", "unsafe.pem", "-days", "1", "-subj", "/CN={{FIXTURE_SENTINEL}}")
        result = {}
        for name in ("ca", "leaf", "unsafe"):
            pem = (p / (name + ".pem")).read_bytes()
            der = cli("x509", "-inform", "PEM", "-outform", "DER", data=pem)
            fp = cli("x509", "-inform", "DER", "-noout", "-sha256", "-fingerprint", data=der)
            assert fp.decode().strip().split("=", 1)[1].replace(":", "").lower() == hashlib.sha256(der).hexdigest()
            result[name] = (pem, der, hashlib.sha256(der).hexdigest())
        return result
    finally:
        os.umask(old)
        for f in list(p.glob("*.key")) + list(p.glob("*.csr")):
            f.unlink()


@pytest.fixture(scope="module")
def rules():
    return assessment.load_rules((ROOT / "config/assessment_rules.yml").read_bytes())


def tree(h, tmp):
    p = tmp / "synthetic-root"
    p.mkdir(mode=0o755)
    for root in h["ROOTS"].values():
        (p / root.lstrip("/")).mkdir(parents=True, mode=0o755)
    return p


def loc(h, p, slot=SLOT):
    return p / h["ROOTS"][slot].lstrip("/")


def reader(h, p, **limits):
    fd = os.open(p, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        r = h["Reader"](fd, time.monotonic() + 23)
        for k, v in limits.items():
            setattr(r, k, v)
        snap = r.collect()
        ca.validate_snapshot(snap)
        return snap, r
    finally:
        os.close(fd)


def cert_rows(snap, slot=SLOT):
    return [b["certificate"] for s in snap[slot]["sources"] for b in s["blocks"] if b["certificate"]]


def src(h, snap, name, slot=SLOT):
    sid = h["source_id"](h["ROOTS"][slot] + "/" + name)
    return next(s for s in snap[slot]["sources"] if s["source_id"] == sid)


def source(producer=ca.COLLECTOR):
    return dict(source_kind="SYNTHETIC", producer_id=producer, producer_version="1.0.0",
                origin_ref="fixture-certificates", input_sha256=None)


def doc(run="fixture-run", target="fixture-a.example.invalid", stable=True):
    hid = ev.host_id("fixture-authority", target) if stable else ev.host_id(None, target, run_id=run, identity_key="fixture-local")
    return dict(schema_version="1.1.0", run=dict(run_id=run, run_state="COMPLETE", recorded_at=TS,
                started_at=None, finished_at=None, source=source("fixture"), expected_host_ids=[hid]),
                hosts=[dict(host_id=hid, target_id=target, identity_scope="STABLE" if stable else "RUN_SCOPED",
                    host_state="COMPLETE", reason_code="FIXTURE", inventory_authority_id="fixture-authority" if stable else None,
                    identity_key=None if stable else "fixture-local")], collections=[], assets=[], evidence=[], claims=[], findings=[])


def platform_snapshot(**facts):
    yes = dict(state="OK", exists=True, isreg=True, islnk=False, executable=True)
    return dict(facts_state="OK", facts=dict(distribution="OracleLinux", os_family="RedHat", architecture="x86_64",
                distribution_version="9.10", distribution_major_version="9") | facts,
                tools={k: [dict(yes) for _ in range(n)] for k, n in platform.TOOL_SLOTS.items()}, rpms={})


def build(d, snap, rules, **kw):
    params = dict(source=source(), observed_at=TS, snapshot=snap, rules=rules, requested=True,
                platform_snapshot=platform_snapshot(), system_python_available=True) | kw
    return ca.build_cert_assets(d, d["hosts"][0]["host_id"], **params)


def merged(d, result):
    return {**d, **{k: d[k] + result[k] for k in ("collections", "assets", "evidence")}}


def test_role_and_mirror(role):
    assert ROLE.read_bytes() == MIRROR.read_bytes()
    assert stat.S_IMODE(ROLE.stat().st_mode) == stat.S_IMODE(MIRROR.stat().st_mode) == 0o644
    assert role["no_log"] is True and role["become"] is False
    argv = role["block"][4]["ansible.builtin.command"]["argv"]
    assert argv[:8] == ["/usr/bin/timeout", "--signal=TERM", "--kill-after=2s", "27s", "/usr/bin/python3", "-I", "-B", "-c"]
    assert len(argv) == 9 and "def main():" in argv[8]
    assert role["block"][1]["ansible.builtin.stat"]["path"] == "/usr/bin/python3"


@pytest.mark.parametrize("name,algorithm,bits", [("ca", "rsaEncryption", 2048), ("leaf", "id-ecPublicKey", 256)])
def test_actual_der_metadata(helper, certs, name, algorithm, bits):
    b = helper["parse"](certs[name][1], time.monotonic() + 5)
    assert b["rc"] == 0 and b["reason"] == "OK"
    c = b["certificate"]
    assert c["fingerprint"] == certs[name][2] and c["public_key_algorithm"] == algorithm and c["public_key_bits"] == bits
    assert c["signature_inner"] == c["signature_outer"] == "sha256WithRSAEncryption"
    assert "fixture-ca.example.invalid" in c["issuer"] and ca.valid_stamp(c["not_before"]) and ca.valid_stamp(c["not_after"])
    ca.validate_certificate(c)


def test_unsafe_dn_is_not_returned(helper, certs):
    b = helper["parse"](certs["unsafe"][1], time.monotonic() + 5)
    assert b["certificate"]["subject"] is None and b["reason"] == "METADATA_GAP"
    assert "FIXTURE_SENTINEL" not in json.dumps(b)


def test_pem_der_bundle_alias(helper, certs, tmp_path):
    p = tree(helper, tmp_path); q = loc(helper, p)
    (q / "a.pem").write_bytes(certs["ca"][0]); (q / "a.der").write_bytes(certs["ca"][1])
    (q / "both.crt").write_bytes(b"# synthetic bundle\r\n" + certs["ca"][0].replace(b"\n", b"\r\n") + certs["leaf"][0])
    (q / "z-alias.pem").symlink_to("a.pem")
    actual = helper["parse"]; calls = []
    def tracked(data, deadline):
        calls.append(len(data)); return actual(data, deadline)
    helper["parse"] = tracked
    snap, r = reader(helper, p)
    assert len(cert_rows(snap)) == 5 and len(calls) == 4 and r.blocks == 5
    assert ca.root_status(snap[SLOT]) == ("COLLECTED", "OK", 5)
    a, b = src(helper, snap, "a.pem"), src(helper, snap, "z-alias.pem")
    assert a["source_id"] != b["source_id"] and a["target_id"] == b["target_id"]
    assert {c["fingerprint"] for c in cert_rows(snap)} == {certs["ca"][2], certs["leaf"][2]}
    assert ca.root_status(snap[ca.ROOTS[1]]) == ("COLLECTED", "OK", 0)


def test_invalid_middle_and_private_sentinel(helper, certs, tmp_path):
    p = tree(helper, tmp_path); q = loc(helper, p)
    bad = b"-----BEGIN CERTIFICATE-----\n%%%\n-----END CERTIFICATE-----\n"
    private = b"-----BEGIN PRIVATE KEY-----\nSYNTHETIC_PRIVATE_SENTINEL\n-----END PRIVATE KEY-----\n"
    (q / "middle.pem").write_bytes(certs["ca"][0] + bad + certs["leaf"][0])
    (q / "mixed.pem").write_bytes(certs["leaf"][0] + private + certs["ca"][0])
    (q / "only.pem").write_bytes(private)
    snap, _ = reader(helper, p)
    assert len(cert_rows(snap)) == 3 and ca.root_status(snap[SLOT])[0] == "PARTIAL"
    assert [b["reason"] for b in src(helper, snap, "middle.pem")["blocks"]] == ["OK", "INVALID_PEM", "OK"]
    assert src(helper, snap, "mixed.pem")["gaps"] == ["NON_PUBLIC_BLOCK"]
    assert not src(helper, snap, "only.pem")["blocks"] and "SYNTHETIC_PRIVATE_SENTINEL" not in json.dumps(snap)


@pytest.mark.parametrize("data", [b"", b"not a certificate", b"-----BEGIN OPENSSH PRIVATE KEY-----\nBAD\n",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nBAD\n", b"-----BEGIN TRUSTED CERTIFICATE-----\nBAD\n",
    b"-----BEGIN CERTIFICATE-----\nAAAA\n", b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END OTHER-----\n"])
def test_unrecognized_never_complete(helper, tmp_path, data):
    p = tree(helper, tmp_path); (loc(helper, p) / "x.pem").write_bytes(data)
    snap, _ = reader(helper, p)
    assert ca.root_status(snap[SLOT])[0] != "COLLECTED" and not cert_rows(snap)


@pytest.mark.parametrize("kind", ["trailing", "truncated", "two-der", "pkcs8-like", "indefinite"])
def test_der_envelope_rejects_before_cli(helper, certs, tmp_path, kind):
    der = certs["ca"][1]
    samples = {"trailing": der + b"X", "truncated": der[:-1], "two-der": der + der,
        "pkcs8-like": b"\x30\x0d\x02\x01\x00\x30\x03\x06\x01\x01\x04\x03ABC", "indefinite": b"\x30\x80\x00\x00"}
    p = tree(helper, tmp_path); (loc(helper, p) / "bad.der").write_bytes(samples[kind])
    def forbidden(*_): raise AssertionError("Non-certificate reached OpenSSL")
    helper["capture"] = forbidden
    snap, r = reader(helper, p)
    assert not cert_rows(snap) and r.blocks == 1 and src(helper, snap, "bad.der")["blocks"][0]["reason"] == "INVALID_DER"
    if kind == "pkcs8-like": assert r.bytes < len(samples[kind])


def test_fixed_bundle_and_root_alias(helper, certs, tmp_path):
    p = tree(helper, tmp_path); q = loc(helper, p)
    bundle = p / "etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"
    bundle.parent.mkdir(parents=True); bundle.write_bytes(certs["ca"][0] + certs["leaf"][0])
    (q / "ca-bundle.crt").symlink_to("/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem")
    other = loc(helper, p, ca.ROOTS[2]); other.rmdir(); other.symlink_to(helper["ROOTS"][SLOT])
    snap, _ = reader(helper, p)
    assert len(cert_rows(snap)) == len(cert_rows(snap, ca.ROOTS[2])) == 2
    assert snap[SLOT]["root_target_id"] == snap[ca.ROOTS[2]]["root_target_id"]
    a, b = snap[SLOT]["sources"][0], snap[ca.ROOTS[2]]["sources"][0]
    assert a["source_id"] != b["source_id"] and a["target_id"] == b["target_id"]


def test_unsafe_links_special_files_private_dirs(helper, certs, tmp_path):
    p = tree(helper, tmp_path); q = loc(helper, p)
    outside = p / "outside.pem"; outside.write_bytes(certs["ca"][0])
    for name, target in [("escape.pem", "/outside.pem"), ("loop.pem", "loop.pem"), ("a.pem", "b.pem"),
                         ("b.pem", "a.pem"), ("key.pem", "/etc/pki/tls/private/secret.key")]:
        (q / name).symlink_to(target)
    os.mkfifo(q / "fifo.pem"); os.link(outside, q / "hardlink.pem")
    (q / "private").mkdir(); (q / "private/hidden.pem").write_bytes(certs["ca"][0])
    (q / "dirlink").symlink_to("/etc/pki/ca-trust/source/anchors")
    (q / "bad.key.pem").write_bytes(certs["ca"][0])
    snap, r = reader(helper, p)
    assert not cert_rows(snap) and r.bytes == 0
    assert all(s["gaps"] == ["UNSAFE_SOURCE"] for s in snap[SLOT]["sources"])
    assert {"DIRECTORY_LINK", "UNSAFE_SOURCE"} <= set(snap[SLOT]["gaps"])


def test_link_hop_limit(helper, certs, tmp_path):
    p = tree(helper, tmp_path); q = loc(helper, p)
    for i in range(5): (q / f"{i}.pem").symlink_to(f"{i+1}.pem")
    (q / "5.pem").write_bytes(certs["ca"][0]); snap, _ = reader(helper, p)
    assert src(helper, snap, "0.pem")["gaps"] == ["UNSAFE_SOURCE"]
    assert src(helper, snap, "1.pem")["blocks"][0]["certificate"]


def test_real_missing_permission(helper, tmp_path, certs):
    p = tree(helper, tmp_path); loc(helper, p, ca.ROOTS[1]).rmdir()
    f = loc(helper, p) / "denied.pem"; f.write_bytes(certs["ca"][0]); f.chmod(0)
    fd = os.open(p, os.O_PATH | os.O_DIRECTORY)
    try:
        if os.geteuid() == 0:
            rd, wr = os.pipe(); pid = os.fork()
            if pid == 0:
                os.close(rd)
                try:
                    os.setgroups([]); os.setgid(65534); os.setuid(65534)
                    os.write(wr, json.dumps(helper["Reader"](fd, time.monotonic() + 5).collect()).encode())
                    os._exit(0)
                except BaseException: os._exit(1)
            os.close(wr)
            with os.fdopen(rd, "rb") as pipe: raw = pipe.read(16384)
            assert os.waitpid(pid, 0)[1] == 0; snap = json.loads(raw)
        else: snap = helper["Reader"](fd, time.monotonic() + 5).collect()
    finally:
        os.close(fd); f.chmod(0o644)
    ca.validate_snapshot(snap)
    assert ca.root_status(snap[SLOT])[0] == "PERMISSION_DENIED"
    assert ca.root_status(snap[ca.ROOTS[1]])[0] == "UNKNOWN"


def test_source_drift_keeps_counts_not_metadata(helper, certs, tmp_path):
    p = tree(helper, tmp_path); f = loc(helper, p) / "drift.pem"; f.write_bytes(certs["ca"][0])
    actual = helper["parse"]
    def change(data, deadline):
        result = actual(data, deadline); f.write_bytes(certs["leaf"][0]); return result
    helper["parse"] = change; snap, _ = reader(helper, p)
    s = src(helper, snap, "drift.pem")
    assert s["gaps"] == ["SOURCE_CHANGED"] and len(s["blocks"]) == 1
    assert s["blocks"][0]["rc"] == 0 and not cert_rows(snap)


def test_depth_entry_candidate_caps(helper, tmp_path):
    p = tree(helper, tmp_path); q = loc(helper, p)
    (q / "a/b/c/d").mkdir(parents=True); (q / "a/b/c/d/no.pem").write_bytes(b"never read")
    for i in range(129): (q / f"c{i:03}.pem").write_bytes(b"invalid")
    snap, r = reader(helper, p)
    assert r.sources == 128 and "LIMIT_REACHED" in snap[SLOT]["gaps"]
    for i in range(400): (q / f"z{i:03}.txt").touch()
    snap, r = reader(helper, p)
    assert r.entries == 512 and r.sources <= 128 and "LIMIT_REACHED" in snap[SLOT]["gaps"]
    for f in list(q.glob("c*.pem")) + list(q.glob("z*.txt")): f.unlink()
    snap, _ = reader(helper, p); assert "DEPTH_LIMIT" in snap[SLOT]["gaps"]


def test_file_aggregate_block_limits(helper, certs, tmp_path):
    p = tree(helper, tmp_path); q = loc(helper, p)
    with (q / "huge.pem").open("wb") as f: f.truncate(helper["MAX_FILE"] + 1)
    snap, r = reader(helper, p)
    assert r.bytes == 0 and src(helper, snap, "huge.pem")["gaps"] == ["LIMIT_REACHED"]
    (q / "huge.pem").unlink(); (q / "bundle.pem").write_bytes(certs["ca"][0] + certs["leaf"][0])
    snap, r = reader(helper, p, bytes=helper["MAX_INPUT"] - 1)
    assert r.bytes == helper["MAX_INPUT"] - 1 and not cert_rows(snap)
    snap, r = reader(helper, p, blocks=helper["MAX_BLOCKS"] - 1)
    assert r.blocks == helper["MAX_BLOCKS"] and len(cert_rows(snap)) == 1
    assert "LIMIT_REACHED" in src(helper, snap, "bundle.pem")["gaps"] and ca.root_status(snap[SLOT])[0] == "PARTIAL"


def test_projection_limit(helper, certs, tmp_path):
    p = tree(helper, tmp_path); (loc(helper, p) / "one.pem").write_bytes(certs["ca"][0])
    snap, _ = reader(helper, p, projected=192 * 1024); s = src(helper, snap, "one.pem")
    assert len(s["blocks"]) == 1 and s["blocks"][0]["reason"] == "PROJECTION_LIMIT" and not cert_rows(snap)


@pytest.mark.parametrize("program,error", [("import time;time.sleep(2)", "TIMEOUT"),
    ("import os;os.write(1,b'x'*16385)", "OUTPUT_LIMIT"), ("import os;os.write(2,b'x'*16385)", "OUTPUT_LIMIT"),
    ("import os;os.write(1,b'x'*9000);os.write(2,b'x'*9000)", "OUTPUT_LIMIT")])
def test_actual_child_capture(helper, program, error):
    start = time.monotonic()
    rc, raw, why = helper["capture"](["/usr/bin/python3", "-I", "-B", "-c", program], b"", start + .25)
    assert why == error and raw is None and type(rc) is int and time.monotonic() - start < 2


def test_actual_residual_child_cleanup(helper, tmp_path):
    sentinel = tmp_path / "late"
    program = "import os,time;pid=os.fork();\nif pid: os._exit(0)\nos.close(0);os.close(1);os.close(2);time.sleep(.5);open(" + repr(str(sentinel)) + ",'w').close()"
    rc, raw, why = helper["capture"](["/usr/bin/python3", "-I", "-B", "-c", program], b"", time.monotonic() + 1)
    assert rc == 0 and raw is None and why == "CLEANUP_FAILED"
    time.sleep(.6); assert not sentinel.exists()


@pytest.fixture
def observed(helper, certs, tmp_path):
    p = tree(helper, tmp_path); q = loc(helper, p)
    (q / "chain.pem").write_bytes(certs["ca"][0] + certs["leaf"][0]); (q / "duplicate.der").write_bytes(certs["leaf"][1])
    (loc(helper, p, ca.ROOTS[1]) / "same.pem").write_bytes(certs["leaf"][0]); (q / "invalid.cer").write_bytes(b"invalid")
    return reader(helper, p)[0]


def test_end_to_end_evidence_details(observed, certs, rules):
    d = doc(); before = copy.deepcopy((d, observed, rules)); result = build(d, observed, rules); actual = merged(d, result)
    assert len(result["assets"]) == 2 and len(result["details"]["occurrences"]) == 4
    assert {a["identity_key"] for a in result["assets"]} == {certs["ca"][2], certs["leaf"][2]}
    leaf = next(a for a in result["assets"] if a["identity_key"] == certs["leaf"][2]); rows = [e for e in result["evidence"] if e["asset_id"] == leaf["asset_id"]]
    assert len(rows) == 9 and {e["algorithm"]["algorithm_id"] for e in rows if e["algorithm"]} == {"ec-public-key", "rsa-sha256-signature"}
    assert len({e["collection_id"] for e in rows}) == 2 and all(e["data"]["version"] is None for e in rows)
    assert result == build(d, observed, rules) and (d, observed, rules) == before
    evaluated = assessment.evaluate_document(ev.parse_evidence_bytes(ev.canonical_bytes(actual)), rules)
    assert not evaluated["claims"] and all(f["assessment_state"] not in ("PASS", "FAIL") for f in evaluated["findings"])
    ca.validate_cert_details(ev.parse_evidence_bytes(ev.canonical_bytes(evaluated)), result["details"], rules)
    assert [c["collection_state"] for c in result["collections"]] == ["PARTIAL", "COLLECTED", "COLLECTED"]


@pytest.mark.parametrize("stable", [True, False])
def test_distinct_hosts_and_identity(observed, rules, stable):
    a, b = doc(stable=stable), doc(run="fixture-run-b", target="fixture-b.example.invalid", stable=stable)
    x, y = build(a, observed, rules), build(b, observed, rules)
    assert {s["identity_key"] for s in x["assets"]} == {s["identity_key"] for s in y["assets"]}
    assert not {s["asset_id"] for s in x["assets"]} & {s["asset_id"] for s in y["assets"]}
    assert all(s["identity_scope"] == ("STABLE" if stable else "RUN_SCOPED") for s in x["assets"])


@pytest.mark.parametrize("change", ["hash", "missing", "duplicate", "cross-host", "asset", "evidence", "root", "root-missing", "fingerprint", "count", "path", "bool", "extra"])
def test_companion_tampering(observed, rules, change):
    d = doc(); result = build(d, observed, rules); actual, details = merged(d, result), copy.deepcopy(result["details"]); first = details["occurrences"][0]
    if change == "hash": first["detail_sha256"] = "0" * 64
    elif change == "missing": details["occurrences"].pop()
    elif change == "duplicate": details["occurrences"].append(copy.deepcopy(first))
    elif change == "cross-host": first["host_id"] = ev.host_id("fixture-authority", "foreign")
    elif change == "asset": first["asset_id"] = next(x["asset_id"] for x in result["assets"] if x["asset_id"] != first["asset_id"])
    elif change == "evidence": first["evidence_ids"] = [result["collections"][0]["evidence_ids"][0]]
    elif change == "root": first["root"] = ca.ROOTS[2]
    elif change == "root-missing": details["roots"].pop()
    elif change == "fingerprint": first["fingerprint"] = "1" * 64
    elif change == "count": details["snapshot"][SLOT]["entries"] += 1
    elif change == "path": first["source_id"] = "/etc/pki/tls/certs/fixture.pem"
    elif change == "bool": first["block_index"] = True
    else: first["extra"] = "fixture"
    with pytest.raises(ev.EvidenceError): ca.validate_cert_details(actual, details, rules)


@pytest.mark.parametrize("change", ["duplicate", "conflict", "rc", "target", "cap", "empty", "gap"])
def test_closed_snapshot_negative(observed, rules, change):
    s = copy.deepcopy(observed); valid = next(x for x in s[SLOT]["sources"] if x["blocks"] and x["blocks"][0]["certificate"])
    if change == "duplicate": s[SLOT]["sources"].append(copy.deepcopy(valid)); s[SLOT]["entries"] += 1
    elif change == "conflict": next(c for c in cert_rows(s) if c["public_key_algorithm"] == "id-ecPublicKey")["public_key_bits"] = 257
    elif change == "rc": valid["blocks"][0]["rc"] = 7
    elif change == "target": valid["target_id"] = None
    elif change == "cap": s[SLOT]["entries"] = 513
    elif change == "empty": s[ca.ROOTS[2]]["root_target_id"] = None
    else: valid["gaps"] = ["arbitrary raw error"]
    with pytest.raises(ev.EvidenceError): build(doc(), s, rules)


@pytest.mark.parametrize("params", [dict(requested=False), dict(system_python_available=False),
    dict(platform_snapshot=platform_snapshot(distribution="RedHat")), dict(platform_snapshot=platform_snapshot(distribution_version="9"))])
def test_positive_requires_scope(observed, rules, params):
    with pytest.raises(ev.EvidenceError): build(doc(), observed, rules, **params)


def test_disabled_missing_scope(helper, rules):
    s = {k: helper["empty"](False, "DISABLED_BY_USER", None) for k in ca.ROOTS}
    result = build(doc(), s, rules, requested=False, system_python_available=False)
    assert not result["assets"] and not result["evidence"] and all(c["collection_state"] == "NOT_SCANNED" for c in result["collections"])
    s = {k: helper["empty"](False, "TOOL_UNAVAILABLE", None) for k in ca.ROOTS}
    result = build(doc(), s, rules, system_python_available=False)
    assert all(c["collection_state"] == "UNKNOWN" for c in result["collections"]) and not result["evidence"]


def test_private_header_stops_before_body(helper, tmp_path):
    p = tree(helper, tmp_path)
    (loc(helper, p) / "private.pem").write_bytes(b"-----BEGIN PRIVATE KEY-----\n" + b"S" * 100000)
    def forbidden(*_): raise AssertionError("Private block reached parser")
    helper["parse"] = forbidden
    snap, r = reader(helper, p)
    assert r.bytes <= 4097 and src(helper, snap, "private.pem")["gaps"] == ["NON_PUBLIC_BLOCK"]


def test_target_conflict_rejected(observed, rules):
    s = copy.deepcopy(observed)
    chain = next(x for x in s[SLOT]["sources"] if len(x["blocks"]) == 2)
    duplicate = next(x for x in s[SLOT]["sources"] if x["format"] == "DER")
    duplicate["target_id"] = chain["target_id"]
    with pytest.raises(ev.EvidenceError, match="CERT_TARGET_CONFLICT"):
        build(doc(), s, rules)


def test_actual_capture_exact_cap(helper):
    rc, raw, error = helper["capture"](["/usr/bin/python3", "-I", "-B", "-c", "import os;os.write(1,b'x'*16384)"], b"", time.monotonic() + 1)
    assert rc == 0 and error is None and len(raw) == 16384


def test_actual_deadline_no_reads(helper, tmp_path):
    p = tree(helper, tmp_path)
    fd = os.open(p, os.O_PATH | os.O_DIRECTORY)
    try:
        r = helper["Reader"](fd, time.monotonic() - 1)
        snap = r.collect()
        assert r.bytes == r.entries == 0 and all(ca.root_status(x)[0] == "ERROR" and x["gaps"] == ["TIMEOUT"] for x in snap.values())
    finally:
        os.close(fd)


def test_actual_inner_outer_signature_disagreement(helper, certs):
    der = certs["ca"][1]
    oid = bytes.fromhex("06092a864886f70d01010b")
    assert der.count(oid) == 2
    at = der.rfind(oid) + len(oid) - 1
    changed = der[:at] + b"\x0c" + der[at + 1:]
    b = helper["parse"](changed, time.monotonic() + 5)
    # OpenSSL is the parser, not a trust/verification operation. A rejection
    # is safe; if accepted, both separately observed algorithms must survive.
    if b["certificate"] is None:
        assert b["reason"] != "OK"
    else:
        c = b["certificate"]
        assert c["fingerprint"] == hashlib.sha256(changed).hexdigest()
        assert c["signature_inner"] != c["signature_outer"] and "SIGNATURE_CONFLICT" in c["gaps"]
        ca.validate_certificate(c)


def test_unknown_and_conflicting_algorithms_not_readiness(observed, rules):
    s = copy.deepcopy(observed)
    for root in ca.ROOTS:
        for c in cert_rows(s, root):
            c["public_key_algorithm"] = "Fixture-Unknown-Algorithm"
            c["signature_outer"] = "Fixture-Unknown-Signature"
            c["gaps"] = ca.metadata_gaps(c)
        for row in s[root]["sources"]:
            for block in row["blocks"]:
                if block["certificate"]:
                    block["reason"] = "METADATA_GAP"
    d = doc(); out = build(d, s, rules)
    annotations = [e["algorithm"] for e in out["evidence"] if e["algorithm"]]
    assert annotations and all(a["family"] == "UNKNOWN" and a["algorithm_id"] is None for a in annotations)
    evaluated = assessment.evaluate_document(merged(d, out), rules)
    assert not evaluated["claims"] and not any(f["assessment_state"] in ("PASS", "FAIL") for f in evaluated["findings"])
    ca.validate_cert_details(evaluated, out["details"], rules)
