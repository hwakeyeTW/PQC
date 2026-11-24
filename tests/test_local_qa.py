"""Synthetic controls only; never fetch a repository or execute a real playbook."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "tools/run_local_qa.py"
SPEC = importlib.util.spec_from_file_location("pqc_local_qa", SCRIPT)
qa = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(qa)


def put(root, path, raw, mode=0o644):
    p = root / path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(raw); p.chmod(mode)
    return p


def git(root, *args, data=None):
    env = {"PATH": "/usr/bin:/bin", "HOME": str(root.parent), "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull, "GIT_NO_LAZY_FETCH": "1",
           "GIT_AUTHOR_NAME": "Dummy", "GIT_AUTHOR_EMAIL": "dummy@example.invalid",
           "GIT_COMMITTER_NAME": "Dummy", "GIT_COMMITTER_EMAIL": "dummy@example.invalid"}
    return subprocess.run(["git", "--no-lazy-fetch", *args], cwd=root, env=env, input=data,
                          capture_output=True, check=True, timeout=30).stdout


def make_git(root, sources):
    root.mkdir(mode=0o700); root.chmod(0o700)
    git(root, "init", "-q", "--template=", "--object-format=sha1", "-b", "projection")
    index = b""
    for name, (raw, mode) in sorted(sources.items()):
        put(root, name, raw, int(mode, 8) & 0o777)
        h = git(root, "hash-object", "-w", "--stdin", data=raw).decode().strip()
        index += f"{mode} {h}\t{name}\0".encode()
    git(root, "update-index", "-z", "--index-info", data=index)
    tree = git(root, "write-tree").decode().strip()
    commit = git(root, "commit-tree", tree, data=b"Synthetic source only\n").decode().strip()
    git(root, "update-ref", "refs/heads/projection", commit)
    return tree, commit


def native_rows(root, tree):
    rows = []
    for line in git(root, "ls-tree", "-r", "-t", "-l", "-z", tree).split(b"\0"):
        if not line: continue
        meta, path = line.decode().split("\t", 1)
        mode, kind, h, size = meta.split()
        row = {"path": path, "mode": mode, "type": kind, "sha": h}
        if kind == "blob": row["size"] = int(size)
        rows.append(row)
    return rows


def build(tmp, baseline=False, overlap=False):
    paths = qa.REQUIRED | {"README.md", "roles/example/tasks/main.yml", "plugins/modules/example.py",
                          qa.COLL + "/roles/example/tasks/main.yml", qa.COLL + "/plugins/modules/example.py",
                          qa.COLL + "/tests/unit/test_example.py"}
    if baseline: paths |= qa.BASELINE
    sources = {p: (f"dummy {p}\n".encode(), "100644") for p in paths}
    sources[qa.RUNNER] = (SCRIPT.read_bytes(), "100644")
    sources[qa.COLL + "/roles/example/tasks/main.yml"] = sources["roles/example/tasks/main.yml"]
    sources[qa.COLL + "/plugins/modules/example.py"] = sources["plugins/modules/example.py"]
    sources[".gitignore"] = (b"*.ignored\n", "100644")
    sources["reports/.gitignore"] = (b"*\n!/.gitignore\n", "100644")
    excluded = {"reports.tar.xz": (b"DUMMY ONLY", "100644"), "inventory/hosts.yml": (b"DUMMY INVENTORY", "100644")}
    if overlap: excluded["reports.tar.xz"] = sources["README.md"]
    origin, root, scratch = tmp / "origin", tmp / "source", tmp / "runtime"
    native_tree, native_commit = make_git(origin, {**sources, **excluded})
    tree, commit = make_git(root, sources)
    rows = native_rows(origin, native_tree)
    pins = sorted({r["sha"] for r in rows if r["type"] == "blob" and r["path"] in sources})
    denied = sorted({r["sha"] for r in rows if r["type"] == "blob" and r["path"] in excluded})
    manifest = {"version": 1, "repository": qa.REPO, "repo_id": qa.REPO_ID, "truncated": False, "kind": "head",
                "commit": native_commit, "tree": native_tree, "base": "1" * 40, "head": native_commit, "parents": ["1" * 40],
                "entries": rows, "allowed_paths": sorted(sources), "excluded_oids": denied,
                "projection": {"tree": tree, "commit": commit},
                "provenance": {"method": "metadata-first-per-oid", "reference": "SYNTHETIC-FIXTURE", "excluded_acquired": False, "acquired_oids": pins}}
    manifest_path = put(tmp, "manifest.json", json.dumps(manifest).encode(), 0o600)
    scratch.mkdir(mode=0o700)
    for name in ("home", "xdg-config", "xdg-cache", "tmp", "docker-config"):
        (scratch / name).mkdir(mode=0o700)
    env = qa.clean_env(scratch, Path(sys.executable).parent)
    env["ANSIBLE_COLLECTIONS_PATH"] = f"{root}:{tmp / 'deps'}"
    return root, scratch, manifest_path, manifest, env


@pytest.fixture
def source(tmp_path):
    return build(tmp_path)


def guard(source, baseline=False):
    root, _, path, _, env = source
    return qa.SourceGuard(root, path, qa.sha256(path.read_bytes()), baseline, env)


def test_actual_projection_and_native_tree(source):
    root, _, path, m, _ = source
    g = guard(source)
    assert g.manifest["tree"] == m["tree"] and g.manifest["projection"]["tree"] != m["tree"]
    assert not (root / "reports.tar.xz").exists() and not (root / "inventory").exists()
    for oid in m["excluded_oids"]:
        assert not (root / ".git/objects" / oid[:2] / oid[2:]).exists()
    g.check()
    assert qa.sha256(path.read_bytes()) == g.digest


@pytest.mark.parametrize("case", ["repo", "truncated", "tree", "directory", "missing_row", "bad_mode", "symlink", "gitlink",
    "duplicate", "case_alias", "traversal", "absolute", "dotgit", "size", "allowed", "excluded", "receipt", "provenance", "parents", "projection"])
def test_manifest_rejects_invalid_metadata(source, case):
    m = copy.deepcopy(source[3])
    rows = m["entries"]; leaf = next(r for r in rows if r["path"] == "README.md")
    if case == "repo": m["repo_id"] = 1
    elif case == "truncated": m["truncated"] = True
    elif case == "tree": m["tree"] = "0" * 40
    elif case == "directory": next(r for r in rows if r["type"] == "tree")["sha"] = "0" * 40
    elif case == "missing_row": rows.remove(leaf)
    elif case == "bad_mode": leaf["mode"] = "100600"
    elif case == "symlink": leaf["mode"] = "120000"
    elif case == "gitlink": leaf.update(mode="160000", type="commit")
    elif case == "duplicate": rows.append(copy.deepcopy(leaf))
    elif case == "case_alias": rows.append({**leaf, "path": "readme.md"})
    elif case == "traversal": leaf["path"] = "../README.md"
    elif case == "absolute": leaf["path"] = "/README.md"
    elif case == "dotgit": leaf["path"] = ".git/README.md"
    elif case == "size": leaf["size"] = -1
    elif case == "allowed": m["allowed_paths"].remove("README.md")
    elif case == "excluded": m["excluded_oids"] = []
    elif case == "receipt": m["provenance"]["acquired_oids"] = []
    elif case == "provenance": m["provenance"]["excluded_acquired"] = True
    elif case == "parents": m["kind"] = "integration"
    elif case == "projection": m["projection"]["tree"] = "0" * 40
    with pytest.raises(qa.Blocked): qa.validate_manifest(m)


def test_real_excluded_oid_overlap(tmp_path, monkeypatch):
    fixture = build(tmp_path, overlap=True)
    original = qa.regular
    seen = []
    def monitored(path, *args):
        seen.append(path)
        assert path == fixture[2], "source opened before metadata preflight"
        return original(path, *args)
    monkeypatch.setattr(qa, "regular", monitored)
    with pytest.raises(qa.Blocked, match="OID overlap"): guard(fixture)
    assert seen == [fixture[2]]


def test_manifest_digest_and_duplicate_json(source):
    root, _, path, _, env = source
    with pytest.raises(qa.Blocked, match="digest"): qa.SourceGuard(root, path, "0" * 64, False, env)
    with pytest.raises(qa.Blocked, match="duplicate"): qa.json_object(b'{"version":1,"version":2}')


def test_baseline_intake_explicit(tmp_path):
    fixture = build(tmp_path, baseline=True)
    with pytest.raises(qa.Blocked, match="baseline-intake"): guard(fixture)
    guard(fixture, baseline=True)


def test_missing_baseline_intake(source):
    with pytest.raises(qa.Blocked, match="baseline-intake"): guard(source, baseline=True)


@pytest.mark.parametrize("path", ["reports.tar.xz", "inventory/hosts.yml", "roles/demo/secrets/x", "tools/new.py",
    "tests/private.json", qa.COLL + "/tests/output/logs/dummy", qa.COLL + "/tests/Output/logs/dummy", ".github/workflows/collection-tests.yml"])
def test_deny_policy(path):
    assert not qa.approved(path)


@pytest.mark.parametrize("case", ["extra", "ignored", "empty_dir", "missing", "content", "mode", "symlink", "hardlink", "parent_symlink",
    "git_config", "alternate", "promisor", "hook", "git_object", "index", "intent", "manifest"])
def test_guard_drift(source, tmp_path, case, monkeypatch):
    root, _, manifest_path, _, _ = source
    g = guard(source)
    external = put(tmp_path, "outside/dummy.txt", b"DUMMY OUTSIDE")
    file = root / "README.md"
    if case == "extra": put(root, "reports/untracked.json", b"dummy")
    elif case == "ignored": put(root, "a.ignored", b"dummy")
    elif case == "empty_dir": (root / "unexpected").mkdir()
    elif case == "missing": file.unlink()
    elif case == "content": file.write_bytes(b"different")
    elif case == "mode": file.chmod(0o755)
    elif case == "symlink": file.unlink(); file.symlink_to(external)
    elif case == "hardlink": file.unlink(); os.link(external, file)
    elif case == "parent_symlink":
        import shutil
        shutil.rmtree(root / "roles"); (root / "roles").symlink_to(external.parent, target_is_directory=True)
    elif case == "git_config": git(root, "config", "include.path", str(external))
    elif case == "alternate": put(root, ".git/objects/info/alternates", str(external.parent).encode())
    elif case == "promisor": put(root, ".git/objects/pack/pack-dummy.promisor", b"dummy")
    elif case == "hook": put(root, ".git/hooks/pre-commit", b"dummy", 0o755)
    elif case == "git_object": git(root, "hash-object", "-w", "--stdin", data=b"unapproved dummy object")
    elif case == "index": git(root, "update-index", "--force-remove", "README.md")
    elif case == "intent": git(root, "rm", "--cached", "README.md"); git(root, "add", "-N", "README.md")
    elif case == "manifest": manifest_path.write_bytes(b"{}")
    original = qa.regular
    def monitored(path, *args):
        assert external.parent not in path.parents and path != external
        assert not path.name.endswith(".promisor") and path.name != "alternates"
        return original(path, *args)
    monkeypatch.setattr(qa, "regular", monitored)
    with pytest.raises((qa.Blocked, OSError)): g.check()


def test_guard_initial_unexpected_git_config(source):
    root = source[0]
    git(root, "config", "remote.origin.url", "https://example.invalid/dummy")
    with pytest.raises(qa.Blocked, match="config"): guard(source)


def test_environment_and_boundary_latch(source, monkeypatch):
    root, scratch, _, _, env = source
    g = guard(source)
    monkeypatch.setenv("GIT_TRACE", str(scratch / "trace")); monkeypatch.setenv("PYTEST_ADDOPTS", "--collect-only")
    monkeypatch.setenv("ANSIBLE_CONFIG", "DUMMY_UNTRUSTED")
    report = {"checks": {}}
    run = qa.LaneRun(root, scratch, env, g, "legacy-217", time.monotonic()+60, report)
    entry, _ = run.run("positive", [sys.executable, "-c", "import os; assert 'GIT_TRACE' not in os.environ and 'PYTEST_ADDOPTS' not in os.environ and 'ANSIBLE_CONFIG' not in os.environ"], root, 10)
    assert entry["status"] == "PASS" and entry["rc"] == 0
    entry, _ = run.run("ordinary-failure", [sys.executable, "-c", "raise SystemExit(7)"], root, 10)
    assert entry["status"] == "FAIL" and entry["rc"] == 7
    with pytest.raises(qa.Blocked):
        run.run("mutation", [sys.executable, "-c", "from pathlib import Path; Path('new.ignored').touch(); raise SystemExit(9)"], root, 10)
    assert report["checks"]["mutation"]["rc"] == 9 and report["checks"]["mutation"]["command_status"] == "FAIL"
    marker = scratch / "must-not-run"
    with pytest.raises(qa.Blocked):
        run.run("later", [sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"], root, 10)
    assert not marker.exists()


@pytest.mark.parametrize("case", ["missing", "timeout", "budget"])
def test_real_process_blocked(source, case):
    root, _, _, _, env = source
    argv, timeout = {"missing": (["/nonexistent/pqc-tool"], 5), "timeout": ([sys.executable, "-c", "import time; time.sleep(30)"], .1),
                     "budget": ([sys.executable, "-c", "raise SystemExit(0)"], 0)}[case]
    result, _ = qa.process(argv, root, env, timeout)
    assert result["status"] == "BLOCKED" and result["rc"] != 0


def xml_suite(cases, tests=1, **kwargs):
    attr = {"tests": str(tests), "failures": "0", "errors": "0", "skipped": "0", **kwargs}
    return "<testsuite " + " ".join(f'{k}="{v}"' for k, v in attr.items()) + ">" + cases + "</testsuite>"


CASE = '<testcase classname="dummy" name="one"/>'


@pytest.mark.parametrize("xml", [xml_suite(CASE), '<testsuites tests="1">' + xml_suite(CASE) + '</testsuites>',
    xml_suite('<testcase name="one"><properties><property name="k" value="v"/></properties><system-out>dummy</system-out></testcase>')])
def test_valid_junit(tmp_path, xml):
    result = qa.junit(put(tmp_path, "result.xml", xml.encode()))
    assert result["tests"] == 1 and not result["nonpass"]


@pytest.mark.parametrize("xml", [xml_suite(CASE, tests=2), '<testsuites>'+xml_suite(CASE, tests=2)+xml_suite(CASE, tests=0)+'</testsuites>',
    '<testsuites>'+xml_suite('', tests=1)+CASE+'</testsuites>', '<testsuites>'+xml_suite('', tests=-1)+xml_suite(CASE, tests=2)+'</testsuites>',
    xml_suite('', tests=0), '<testsuites/>', '<broken', '<testsuite tests="1">'+CASE+'</testsuite>',
    xml_suite(CASE+CASE, tests=2), '<testsuites>'+xml_suite(CASE)+xml_suite(CASE)+'</testsuites>',
    xml_suite('<testcase/>'), xml_suite('<testcase name="one"><testcase name="nested"/></testcase>'),
    xml_suite('<testcase name="one"><failure/><error/></testcase>', failures="1", errors="1"),
    xml_suite(CASE, skipped="-1"), xml_suite(CASE, failures="1"), xml_suite(CASE, errors="+0"),
    '<testsuites tests="2">'+xml_suite(CASE)+'</testsuites>', xml_suite("unexpected"+CASE), xml_suite(CASE+"tail"),
    xml_suite('<testcase name="one"><properties><property><testcase name="nested"/></property></properties></testcase>'),
    '<!DOCTYPE x [<!ENTITY a "dummy">]>'+xml_suite(CASE), '<?xml version="1.0" encoding="UTF-16"?>'+xml_suite(CASE)])
def test_invalid_junit(tmp_path, xml):
    import xml.etree.ElementTree as ET
    with pytest.raises((qa.Blocked, ET.ParseError)): qa.junit(put(tmp_path, "result.xml", xml.encode()))


def test_non_utf8_junit(tmp_path):
    with pytest.raises(UnicodeError): qa.junit(put(tmp_path, "result.xml", b"\xff" + xml_suite(CASE).encode()))


@pytest.mark.parametrize("source_text,rc,status", [("def test_ok(): assert True\n", 0, "PASS"), ("def test_bad(): assert False\n", 1, "FAIL"),
    ("import pytest\n@pytest.mark.skip\ndef test_skip(): pass\n", 0, "FAIL"), ("# empty\n", 5, "FAIL"),
    ("import pytest\ndef test_ok(): pass\n@pytest.mark.skip\ndef test_skip(): pass\n", 0, "FAIL")])
def test_actual_pytest_gate(source, source_text, rc, status):
    root, scratch, _, _, env = source
    test = put(scratch, "test_dummy.py", source_text.encode()); result = scratch / "test.xml"
    run = qa.LaneRun(root, scratch, env, guard(source), "legacy-217", time.monotonic()+60, {"checks": {}})
    entry, _ = run.run("pytest", [sys.executable, "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider", "-c", os.devnull, "--rootdir", str(scratch), "--confcutdir", str(scratch), "--junitxml", str(result), str(test)], scratch, 30, xml=result)
    assert entry["rc"] == rc and entry["status"] == status


@pytest.mark.parametrize("lane", list(qa.LANES))
@pytest.mark.parametrize("baseline", [False, True])
def test_required_commands(lane, baseline, tmp_path):
    steps = qa.plan(lane, baseline, tmp_path / "src", tmp_path / "scratch", "python", lambda s: s)
    names = [s[0] for s in steps]
    assert len(names) == len(set(names))
    assert set(names) == {"collection-unit", "syntax-1", "syntax-2", "syntax-3", "sanity", "data-handling", "mirror-check", "mirrors", "local-qa"} | ({"lint"} if lane == "maintained-221" else set()) | ({"baseline-intake"} if baseline else set())
    assert [s[1][-1] for s in steps if s[0].startswith("syntax-")] == list(qa.SYNTAX)
    assert all("--syntax-check" in s[1] for s in steps if s[0].startswith("syntax-"))
    assert not any(set(s[1]) & {"install", "fetch", "checkout", "--skip-test", "--fix"} for s in steps)


def test_locale_and_private_environment(source, monkeypatch):
    root, scratch, _, _, _ = source
    for key in ("HOME", "GIT_CONFIG_GLOBAL", "PYTHONUTF8", "HTTP_PROXY", "ANSIBLE_CONFIG"):
        monkeypatch.setenv(key, "DUMMY")
    env = qa.clean_env(scratch, Path(sys.executable).parent)
    assert env["HOME"] == str(scratch / "home") and env["GIT_CONFIG_GLOBAL"] == os.devnull
    assert all(k not in env for k in ("PYTHONUTF8", "HTTP_PROXY", "ANSIBLE_CONFIG"))
    assert qa.locale_utf8(env, sys.executable)


def test_cli_wrong_lane_records_blocked(source, tmp_path):
    root, _, manifest_path, _, _ = source
    deps = tmp_path / "deps"; deps.mkdir(mode=0o700)
    out = tmp_path / "evidence"
    lane = next(name for name, p in qa.LANES.items() if p[0] != platform.python_version())
    cmd = [sys.executable, "-I", "-B", str(SCRIPT), "--lane", lane, "--source-root", str(root),
           "--source-manifest", str(manifest_path), "--manifest-sha256", qa.sha256(manifest_path.read_bytes()),
           "--collections-root", str(deps), "--evidence-dir", str(out), "--runtime-reference", "SYNTHETIC"]
    p = subprocess.run(cmd, capture_output=True, timeout=60)
    assert p.returncode == 2 and p.stdout == b"BLOCKED\n"
    result = json.loads((out / "results.json").read_text())
    assert result["overall"] == "BLOCKED" and result["checks"]["source-preflight"]["status"] == "PASS"
    assert result["checks"]["collection-unit"]["status"] == "NOT_TESTED"
    assert "wrong lane Python" in result["blocked"]
    assert (out / "results.json").stat().st_mode & 0o777 == 0o600 and out.stat().st_mode & 0o777 == 0o700
    assert sorted(p.name for p in out.iterdir()) == ["results.json"]
    assert str(root) not in (out / "results.json").read_text()
    p = subprocess.run(cmd, capture_output=True, timeout=60)
    assert p.returncode == 2  # Existing evidence cannot be overwritten.


@pytest.mark.parametrize("case", ["good", "category", "extension", "executable", "symlink"])
def test_sanity_output(source, case):
    root, scratch, _, _, _ = source
    g = guard(source); output = root / qa.COLL / "tests/output"
    if case == "good":
        put(output, "logs/dummy.log", b"dummy", 0o600)
        qa.move_sanity_results(root, scratch)
        assert not output.exists(); g.check()
        assert (scratch / "sanity-output/logs/dummy.log").is_file()
        return
    if case == "category": put(output, "other/dummy.txt", b"dummy")
    elif case == "extension": put(output, "logs/dummy.py", b"dummy")
    elif case == "executable": put(output, "logs/dummy.txt", b"dummy", 0o755)
    else:
        (output / "logs").mkdir(parents=True); (output / "logs/dummy.txt").symlink_to(SCRIPT)
    with pytest.raises(qa.Blocked): qa.move_sanity_results(root, scratch)


@pytest.mark.parametrize("raw,legacy,canonical,ok", [
    (b"PASS pairs=1\n", {"roles/a"}, {"roles/a"}, True),
    (b"PASS pairs=0\n", {"roles/a"}, {"roles/a"}, False),
    (b"PASS pairs=1\n", {"roles/a"}, {"roles/b"}, False),
    (b"FAIL pairs=1\n", {"roles/a"}, {"roles/a"}, False),
    (b"PASS pairs=0\n", set(), set(), False),
])
def test_mirror_pair_oracle(raw, legacy, canonical, ok):
    if ok:
        assert qa.mirror_result(raw, legacy, canonical)["pairs"] == 1
    else:
        with pytest.raises(qa.Blocked): qa.mirror_result(raw, legacy, canonical)
