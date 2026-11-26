"""Synthetic-only controls for the exact workflow bootstrap and helper."""
import base64
import copy
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import textwrap
import time

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/collection-tests.yml"
HELPER = ROOT / "tools/ci_bootstrap.py"
SPEC = importlib.util.spec_from_file_location("pqc_ci_bootstrap_test", HELPER)
ci = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ci)


def inline_namespace():
    text = WORKFLOW.read_text(encoding="utf-8")
    script = text.split("python3 -I -B - <<'PY'\n", 1)[1].split("\n          PY\n", 1)[0]
    code = textwrap.dedent(script) + "\n"
    namespace = {"__name__": "pqc_inline_test"}
    exec(compile(code, str(WORKFLOW), "exec"), namespace)
    return code, namespace


def git(root, *args, data=None):
    env = {"PATH": os.environ.get("PATH", os.defpath), "HOME": str(root.parent), "LC_ALL": "C",
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
           "GIT_CONFIG_SYSTEM": os.devnull, "GIT_NO_LAZY_FETCH": "1"}
    return subprocess.run(["git", "--no-lazy-fetch", "-c", "core.hooksPath=/dev/null", *args],
                          cwd=root, env=env, input=data, capture_output=True, check=True, timeout=30).stdout


def put(root, path, data, mode=0o644):
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    target.chmod(mode)
    return target


def metadata(origin):
    tree = git(origin, "write-tree").decode().strip()
    entries = []
    for item in git(origin, "ls-tree", "-r", "-t", "-l", "-z", tree).split(b"\0"):
        if not item:
            continue
        info, path = item.decode().split("\t", 1)
        mode, kind, sha, size = info.split()
        row = {"path": path, "mode": mode, "type": kind, "sha": sha}
        if kind == "blob":
            row["size"] = int(size)
        entries.append(row)
    return {"sha": tree, "truncated": False, "tree": entries}


class FakeResponse:
    def __init__(self, obj, status=200, headers=None, raw=None):
        self.status = status
        self.raw = json.dumps(obj).encode() if raw is None else raw
        self.headers = {"Content-Type": "application/json; charset=utf-8",
                        "Content-Length": str(len(self.raw)), "X-RateLimit-Remaining": "999"}
        self.headers.update(headers or {})

    def getheader(self, name, default=None):
        return self.headers.get(name, default)

    def read(self, limit):
        return self.raw[:limit]


class FakeApiTransport:
    """Intercept actual HTTPSConnection request method of the inline bootstrap."""
    def __init__(self, responses):
        self.responses = responses
        self.requests = []
        self.hosts = []
        self.timeouts = []

    def connection(self, host, port, timeout, context):
        assert host == ci.HOST and port == 443 and context.check_hostname
        self.hosts.append(host)
        self.timeouts.append(timeout)
        transport = self

        class Connection:
            def request(self, method, path, headers):
                assert method == "GET"
                assert headers["Authorization"] == "Bearer SYNTHETIC_ONLY"
                assert headers["Accept-Encoding"] == "identity"
                assert path.startswith("/repos/" + ci.REPO)
                self.path = path
                transport.requests.append(path)

            def getresponse(self):
                assert self.path in transport.responses, "unexpected endpoint (no fallback allowed)"
                result = transport.responses[self.path]
                if isinstance(result, Exception):
                    raise result
                return result

            def close(self):
                pass
        return Connection()

    def blobs(self):
        return [p.rsplit("/", 1)[1] for p in self.requests if "/git/blobs/" in p]


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    origin = tmp_path / "dummy-origin"
    origin.mkdir()
    git(origin, "init", "-q", "--template=", "--object-format=sha1")
    required = set(ci.REQUIRED) | {"roles/example/tasks/main.yml", "plugins/modules/example.py",
                 ci.COLLECTION + "/roles/example/tasks/main.yml", ci.COLLECTION + "/plugins/modules/example.py",
                 ci.COLLECTION + "/tests/unit/test_example.py", "tools/executable.py", "tests/dummy.py"}
    files = {path: ("dummy public source " + path + "\n").encode() for path in required}
    files[ci.HELPER] = HELPER.read_bytes()
    files[ci.WORKFLOW] = WORKFLOW.read_bytes()
    files[".gitignore"] = b"*.ignored\n"
    files["reports/.gitignore"] = b"*\n!/.gitignore\n"
    files["roles/example/tasks/main.yml"] = files[ci.COLLECTION + "/roles/example/tasks/main.yml"]
    files.update({"reports.tar.xz": b"DUMMY EXCLUDED ARCHIVE", "inventory/hosts.yml": b"DUMMY EXCLUDED INVENTORY",
                  "inventory/group_vars/all.yml": b"DUMMY EXCLUDED GROUP VARS", "tools/secrets/dummy.txt": b"DUMMY EXCLUDED SECRET",
                  "install.yml": b"DUMMY EXCLUDED DEPLOYMENT"})
    for path, data in files.items():
        put(origin, path, data, 0o755 if path == "tools/executable.py" else 0o644)
    git(origin, "add", "-f", "--all")  # Only this synthetic origin.
    tree = metadata(origin)
    repo = {"id": ci.REPO_ID, "full_name": ci.REPO, "private": False}
    base, head, tested = "1" * 40, "2" * 40, "3" * 40
    event = {"repository": repo, "action": "synchronize", "number": 48,
             "pull_request": {"base": {"repo": repo, "ref": "main", "sha": base},
                              "head": {"sha": head}, "merge_commit_sha": tested}}
    workspace, runner = tmp_path / "workspace", tmp_path / "runner"
    workspace.mkdir(); runner.mkdir()
    event_path = tmp_path / "event.json"
    env_path = tmp_path / "github-env"
    env_path.touch()
    event_path.write_text(json.dumps(event))
    env = {"GITHUB_REPOSITORY": ci.REPO, "GITHUB_REPOSITORY_ID": str(ci.REPO_ID),
           "GITHUB_API_URL": "https://" + ci.HOST, "GITHUB_SHA": tested,
           "GITHUB_EVENT_NAME": "pull_request", "GITHUB_REF": "refs/pull/48/merge",
           "GITHUB_WORKSPACE": str(workspace), "RUNNER_TEMP": str(runner),
           "GITHUB_EVENT_PATH": str(event_path), "GITHUB_ENV": str(env_path), "PQC_CI_TOKEN": "SYNTHETIC_ONLY"}
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    prefix = "/repos/" + ci.REPO
    responses = {prefix: FakeResponse(repo), prefix + "/git/commits/" + tested:
                 FakeResponse({"sha": tested, "tree": {"sha": tree["sha"]}, "parents": [{"sha": base}, {"sha": head}]}),
                 prefix + "/git/trees/" + tree["sha"] + "?recursive=1": FakeResponse(tree)}
    for row in tree["tree"]:
        if row["type"] == "blob":
            raw = files[row["path"]]
            responses[prefix + "/git/blobs/" + row["sha"]] = FakeResponse(
                {"sha": row["sha"], "size": len(raw), "encoding": "base64", "content": base64.b64encode(raw).decode()})
    transport = FakeApiTransport(responses)
    monkeypatch.setattr(http.client, "HTTPSConnection", transport.connection)
    return {"origin": origin, "files": files, "tree": tree, "event": event, "env": env,
            "workspace": workspace, "runner": runner, "prefix": prefix, "responses": responses,
            "transport": transport, "env_path": env_path, "event_path": event_path}


def tree_key(f):
    return f["prefix"] + "/git/trees/" + f["tree"]["sha"] + "?recursive=1"


def commit_key(f):
    return f["prefix"] + "/git/commits/" + f["env"]["GITHUB_SHA"]


def blob_key(f, path):
    sha = next(r["sha"] for r in f["tree"]["tree"] if r["path"] == path)
    return f["prefix"] + "/git/blobs/" + sha


def run_inline(f):
    _, ns = inline_namespace()
    ns["inline_main"]()
    exports = dict(l.split("=", 1) for l in f["env_path"].read_text().splitlines())
    scratch = Path(exports["CI_ROOT"])
    manifest = json.loads((scratch / "manifest.json").read_text())
    snapshot = json.loads((scratch / "projection.json").read_text())
    return scratch, manifest, snapshot, exports


def replace_tree(f, tree):
    old = tree_key(f)
    del f["responses"][old]
    f["tree"] = tree
    f["responses"][tree_key(f)] = FakeResponse(tree)
    commit = json.loads(f["responses"][commit_key(f)].raw)
    commit["tree"]["sha"] = tree["sha"]
    f["responses"][commit_key(f)] = FakeResponse(commit)


def test_inline_prefix_and_workflow_contract():
    code, ns = inline_namespace()
    common = code.split("# END INLINE COMMON\n", 1)[0] + "# END INLINE COMMON\n"
    assert HELPER.read_text().startswith(common)
    assert hashlib.sha256(common.encode()).hexdigest() == ns["COMMON_SHA256"]
    text = WORKFLOW.read_text()
    assert "actions/checkout@" not in text and "git fetch" not in text and "git clone" not in text
    assert "tarball" not in text and "zipball" not in text
    assert "pull_request_target" not in text and "continue-on-error" not in text and "|| true" not in text
    assert text.count("PQC_CI_TOKEN: ${{ github.token }}") == 1
    assert text.count("--syntax-check playbooks/") == 2
    assert "--syntax-check ansible_collections/security/compliance_pqc_readiness/playbooks/pqc_pipeline.yml" in text
    assert "--sanity --" in text and "ansible-lint --offline playbooks/ roles/" in text
    assert "tests/test_ci_bootstrap.py" in text and 'max-parallel: 1' in text
    for lane in ("legacy-217", "legacy-218", "maintained-221"):
        assert f"lane: {lane}" in text


def test_exact_inline_success(fixture, monkeypatch):
    f = fixture
    trace = f["runner"] / "trace-marker"
    monkeypatch.setenv("GIT_TRACE", str(trace))
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.fsmonitor")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "synthetic-not-executable")
    scratch, manifest, snapshot, exports = run_inline(f)
    allowed = {r["sha"] for r in manifest["allowed"]}
    assert f["transport"].requests[:3] == [f["prefix"], commit_key(f), tree_key(f)]
    assert f["transport"].requests[3] == blob_key(f, ci.HELPER)
    assert len(f["transport"].blobs()) == len(set(f["transport"].blobs())) == len(allowed)
    assert set(f["transport"].blobs()) == allowed and not allowed.intersection(manifest["excluded_oids"])
    assert all(0 < t <= ci.REQUEST_SECONDS for t in f["transport"].timeouts)
    assert not trace.exists() and "PQC_CI_TOKEN" not in os.environ and "SYNTHETIC_ONLY" not in f["env_path"].read_text()
    assert not (f["workspace"] / "reports.tar.xz").exists() and not (f["workspace"] / "inventory").exists()
    ci.verify_files(f["workspace"], manifest)
    env = ci.isolated_env(scratch, os.environ["PATH"])
    subset = ci.verify_git(f["workspace"], env, manifest, snapshot)
    assert subset == {r["path"][len(ci.COLLECTION)+1:] for r in manifest["allowed"] if r["path"].startswith(ci.COLLECTION + "/")}
    assert snapshot["commit"] != f["env"]["GITHUB_SHA"]
    assert git(f["workspace"], "rev-list", "--count", "HEAD") == b"1\n"
    assert exports["CI_GUARD_SHA256"] == hashlib.sha256(HELPER.read_bytes()).hexdigest()


def test_push_event(fixture, monkeypatch):
    f = fixture
    event = {"repository": f["event"]["repository"], "ref": "refs/heads/main", "after": f["env"]["GITHUB_SHA"],
             "before": "1"*40, "deleted": False}
    f["event_path"].write_text(json.dumps(event))
    monkeypatch.setenv("GITHUB_EVENT_NAME", "push"); monkeypatch.setenv("GITHUB_REF", "refs/heads/main")
    _, manifest, _, _ = run_inline(f)
    assert manifest["event"] == "push" and manifest["head"] == event["after"]


@pytest.mark.parametrize("case", ["truncated", "wrong_tree", "duplicate", "case_collision", "traversal", "absolute",
    "dotgit", "backslash", "symlink", "gitlink", "unknown_type", "bad_mode", "ancestor", "invalid_size", "corrupt_oid",
    "omitted_leaf", "wrong_directory_hash", "blob_budget", "total_budget", "missing_anchor"])
def test_metadata_rejected_before_any_blob(fixture, case):
    f = fixture; t = copy.deepcopy(f["tree"]); rows = t["tree"]
    leaf = next(r for r in rows if r["path"] == "README.md")
    if case == "truncated": t["truncated"] = True
    elif case == "wrong_tree": t["sha"] = "0"*40
    elif case == "duplicate": rows.append(copy.deepcopy(leaf))
    elif case == "case_collision": rows.append({**leaf, "path": "readme.md"})
    elif case in {"traversal", "absolute", "dotgit", "backslash"}:
        leaf["path"] = {"traversal": "../README.md", "absolute": "/README.md", "dotgit": "tools/.Git/file", "backslash": "tools\\bad.py"}[case]
    elif case == "symlink": leaf["mode"] = "120000"
    elif case == "gitlink": leaf.update(mode="160000", type="commit")
    elif case == "unknown_type": leaf["type"] = "other"
    elif case == "bad_mode": leaf["mode"] = "100600"
    elif case == "ancestor": rows.append({**leaf, "path": "README.md/child"})
    elif case == "invalid_size": leaf["size"] = -1
    elif case == "corrupt_oid": leaf["sha"] = "not-an-oid"
    elif case == "omitted_leaf": rows.remove(leaf)
    elif case == "wrong_directory_hash": next(r for r in rows if r["type"] == "tree")["sha"] = "0"*40
    elif case == "blob_budget": leaf["size"] = ci.MAX_BLOB + 1
    elif case == "total_budget":
        for r in rows:
            if r["type"] == "blob" and ci.allowed(r["path"]): r["size"] = ci.MAX_BLOB
    elif case == "missing_anchor":
        git(f["origin"], "rm", "-f", "--", "ansible.cfg")
        replace_tree(f, metadata(f["origin"]))
    if case != "missing_anchor": f["responses"][tree_key(f)] = FakeResponse(t)
    with pytest.raises((RuntimeError, KeyError, ValueError)):
        run_inline(f)
    assert f["transport"].blobs() == []


def test_private_oid_overlap_zero_blob_requests(fixture):
    f = fixture
    put(f["origin"], "README.md", f["files"]["reports.tar.xz"])
    git(f["origin"], "add", "--", "README.md")
    replace_tree(f, metadata(f["origin"]))
    with pytest.raises(RuntimeError, match="OID overlap"):
        run_inline(f)
    assert not f["transport"].blobs()


@pytest.mark.parametrize("case", ["wrong_repo", "wrong_tested", "wrong_parents", "wrong_event", "wrong_ref", "rate", "redirect",
                                      "http_403", "http_429", "network", "bad_json", "duplicate_json", "content_type", "response_length"])
def test_identity_transport_fail_closed(fixture, monkeypatch, case):
    f = fixture; k = commit_key(f)
    if case == "wrong_repo": f["responses"][f["prefix"]] = FakeResponse({**f["event"]["repository"], "id": 42})
    elif case in {"wrong_tested", "wrong_parents"}:
        obj = json.loads(f["responses"][k].raw)
        if case == "wrong_tested": obj["sha"] = "4"*40
        else: obj["parents"].reverse()
        f["responses"][k] = FakeResponse(obj)
    elif case == "wrong_event": monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request_target")
    elif case == "wrong_ref": monkeypatch.setenv("GITHUB_REF", "refs/pull/1/merge")
    elif case == "rate": f["responses"][tree_key(f)] = FakeResponse(f["tree"], headers={"X-RateLimit-Remaining": "1"})
    elif case in {"redirect", "http_403", "http_429"}:
        f["responses"][k] = FakeResponse({}, status={"redirect":302,"http_403":403,"http_429":429}[case], headers={"Location":"https://example.invalid/archive"})
    elif case == "network": f["responses"][k] = OSError("synthetic network failure")
    elif case == "bad_json": f["responses"][k] = FakeResponse({}, raw=b"not-json")
    elif case == "duplicate_json": f["responses"][k] = FakeResponse({}, raw=b'{"sha":"a","sha":"b"}')
    elif case == "content_type": f["responses"][k] = FakeResponse({}, headers={"Content-Type":"application/octet-stream"})
    elif case == "response_length": f["responses"][k] = FakeResponse({}, headers={"Content-Length":str(ci.MAX_RESPONSE+1)})
    with pytest.raises((RuntimeError, KeyError, ValueError)):
        run_inline(f)
    assert not f["transport"].blobs() and len(f["transport"].requests) <= 3


@pytest.mark.parametrize("case", ["hash", "size", "base64", "wrong_sha", "encoding", "redirect", "network", "http_500"])
def test_blob_failure_no_fallback_or_materialization(fixture, case):
    f = fixture; k = blob_key(f, "README.md")
    obj = json.loads(f["responses"][k].raw)
    if case == "hash": obj["content"] = base64.b64encode(b"X"*obj["size"]).decode()
    elif case == "size": obj["size"] += 1
    elif case == "base64": obj["content"] = "!!!"
    elif case == "wrong_sha": obj["sha"] = "5"*40
    elif case == "encoding": obj["encoding"] = "utf-8"
    if case == "redirect": f["responses"][k] = FakeResponse({}, status=302)
    elif case == "network": f["responses"][k] = OSError("synthetic")
    elif case == "http_500": f["responses"][k] = FakeResponse({}, status=500)
    else: f["responses"][k] = FakeResponse(obj)
    with pytest.raises(RuntimeError): run_inline(f)
    assert set(p.name for p in f["workspace"].iterdir()) == {".git"}
    allowed = {r["sha"] for r in f["tree"]["tree"] if r["type"] == "blob" and ci.allowed(r["path"])}
    assert set(f["transport"].blobs()) <= allowed and len(f["transport"].blobs()) == len(set(f["transport"].blobs()))


@pytest.mark.parametrize("case", ["no_git", "init_failure", "nonempty_workspace", "workspace_symlink"])
def test_git_preflight_blocks_all_requests(fixture, monkeypatch, case):
    f = fixture
    if case == "no_git": monkeypatch.setenv("PATH", str(f["runner"] / "no-bin"))
    elif case == "init_failure":
        bin_dir = f["runner"] / "bin"; bin_dir.mkdir()
        put(bin_dir, "git", b'#!/bin/sh\ncase "$*" in *--version*) exit 0;; *) exit 23;; esac\n', 0o755)
        monkeypatch.setenv("PATH", str(bin_dir))
    elif case == "nonempty_workspace": put(f["workspace"], "unexpected", b"dummy")
    else:
        f["workspace"].rmdir(); f["workspace"].symlink_to(f["origin"], target_is_directory=True)
    with pytest.raises((RuntimeError, OSError)): run_inline(f)
    assert f["transport"].requests == []


def test_filter_loss_original_counterexample(tmp_path):
    # Reproduce R1 only against an independent synthetic file:// origin.
    origin = tmp_path / "dummy"; origin.mkdir()
    git(origin, "init", "-q", "--template=")
    put(origin, "README.md", b"public dummy")
    put(origin, "reports.tar.xz", b"excluded dummy")
    git(origin, "add", "--all")
    git(origin, "-c", "user.name=Dummy", "-c", "user.email=dummy@example.invalid", "commit", "-qm", "dummy")
    sha = git(origin, "rev-parse", "HEAD:reports.tar.xz").decode().strip()
    git(origin, "config", "uploadpack.allowFilter", "true")
    git(origin, "-c", "protocol.version=2", "ls-remote", origin.as_uri(), "HEAD")
    git(origin, "config", "uploadpack.allowFilter", "false")
    target = tmp_path / "client"; target.mkdir()
    git(target, "init", "-q", "--template=")
    git(target, "-c", "protocol.version=2", "fetch", "--filter=blob:none", "--depth=1", origin.as_uri(), "HEAD")
    assert git(target, "cat-file", "-t", sha) == b"blob\n"
    # New exact inline uses neither this command nor a checkout action.
    assert "git fetch" not in WORKFLOW.read_text() and "actions/checkout@" not in WORKFLOW.read_text()


@pytest.fixture
def projection(fixture, monkeypatch):
    f = fixture
    scratch, manifest, snapshot, exports = run_inline(f)
    for name, value in exports.items(): monkeypatch.setenv(name, value)
    for name, value in {"CI_CORE":"2.19.11", "CI_PYTHON":"3.13.5", "CI_PYTHON_MINOR":"3.13", "CI_PYTEST":"9.0.2",
                        "CI_LINT":"", "CI_REQUIREMENTS": str(f["workspace"] / "collections/requirements-ci.yml")}.items():
        monkeypatch.setenv(name, value)
    return f["workspace"], scratch, manifest, snapshot


@pytest.mark.parametrize("case", ["extra_report", "ignored", "collection_extra", "modified", "missing", "mode", "parent_symlink",
                                      "leaf_symlink", "hardlink", "extra_dir", "index_drift", "config_injection", "hook", "alternate", "object"])
def test_guard_rejects_drift_before_tool(projection, tmp_path, case, monkeypatch):
    root, scratch, manifest, snapshot = projection
    outside = tmp_path / "external"; outside.mkdir()
    sentinel = put(outside, "marker", b"synthetic external untouched")
    before = sentinel.stat().st_mtime_ns
    if case == "extra_report": put(root, "reports/untracked.json", b"dummy")
    elif case == "ignored": put(root, "unexpected.ignored", b"dummy")
    elif case == "collection_extra": put(root, ci.COLLECTION + "/tests/unit/untracked_dummy.py", b"dummy")
    elif case == "modified": (root / "README.md").write_bytes(b"changed")
    elif case == "missing": (root / "README.md").unlink()
    elif case == "mode": (root / "README.md").chmod(0o755)
    elif case == "parent_symlink": shutil.rmtree(root / "roles"); (root / "roles").symlink_to(outside, target_is_directory=True)
    elif case == "leaf_symlink": (root / "README.md").unlink(); (root / "README.md").symlink_to(sentinel)
    elif case == "hardlink": (root / "README.md").unlink(); os.link(sentinel, root / "README.md")
    elif case == "extra_dir": (root / "extra").mkdir()
    elif case == "index_drift": git(root, "update-index", "--force-remove", "README.md")
    elif case == "config_injection": git(root, "config", "core.fsmonitor", str(sentinel))
    elif case == "hook": put(root, ".git/hooks/pre-commit", b"dummy", 0o755)
    elif case == "alternate": put(root, ".git/objects/info/alternates", str(outside).encode())
    elif case == "object": git(root, "hash-object", "-w", "--stdin", data=b"dummy unexpected object")
    marker = scratch / "tool-ran"
    command = [sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"]
    # Track attempted reads, not the external marker contents.
    read = ci.read_regular
    def monitored(path, size=None):
        assert outside not in path.parents and path != sentinel
        return read(path, size)
    monkeypatch.setattr(ci, "read_regular", monitored)
    with pytest.raises(ci.BoundaryError): ci.guarded_run(root, scratch, "guard", root, command)
    assert not marker.exists() and (scratch / "boundary-failed").exists()
    assert sentinel.stat().st_mtime_ns == before
    with pytest.raises(ci.BoundaryError): ci.guarded_run(root, scratch, "later", root, command)
    assert not marker.exists()


def test_guard_command_failure_retained_and_boundary_latch(projection):
    root, scratch, _, _ = projection
    assert ci.guarded_run(root, scratch, "failed command", root, [sys.executable, "-c", "raise SystemExit(7)"]) == 7
    assert not (scratch / "boundary-failed").exists()
    assert ci.guarded_run(root, scratch, "next command", root, [sys.executable, "-c", "pass"]) == 0
    with pytest.raises(ci.BoundaryError):
        ci.guarded_run(root, scratch, "writes unexpected", root,
                       [sys.executable, "-c", "from pathlib import Path; Path('extra.ignored').touch()"])
    assert (scratch / "boundary-failed").exists()


def test_git_and_command_environment_isolation(projection, monkeypatch):
    root, scratch, _, _ = projection
    trace = scratch / "trace"; hook = scratch / "hook-ran"
    script = put(scratch, "monitor", f'#!/bin/sh\ntouch "{hook}"\n'.encode(), 0o755)
    monkeypatch.setenv("GIT_TRACE", str(trace)); monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.fsmonitor"); monkeypatch.setenv("GIT_CONFIG_VALUE_0", str(script))
    monkeypatch.setenv("ANSIBLE_CONFIG", "untrusted"); monkeypatch.setenv("PQC_CI_TOKEN", "synthetic-not-inherited")
    command = [sys.executable, "-c", "import os,subprocess; assert 'GIT_TRACE' not in os.environ; assert 'GIT_CONFIG_COUNT' not in os.environ; assert 'PQC_CI_TOKEN' not in os.environ; assert os.environ['ANSIBLE_CONFIG'].endswith('/ansible.cfg'); subprocess.run(['git','status','--porcelain'],check=True)"]
    assert ci.guarded_run(root, scratch, "isolated", root, command) == 0
    assert not trace.exists() and not hook.exists()


@pytest.mark.parametrize("case", ["good", "unexpected_category", "executable", "executable_text", "symlink"])
def test_sanity_output_boundary(projection, case):
    root, scratch, manifest, snapshot = projection
    output = root / ci.SANITY_OUTPUT
    if case == "good":
        put(output, "junit/sanity.xml", b"synthetic")
        put(output, "logs/sanity.log", b"synthetic")
        ci.isolate_sanity_output(root, scratch)
        assert not output.exists() and (scratch / "sanity-results/junit/sanity.xml").is_file()
        ci.verify_files(root, manifest)
    elif case == "unexpected_category": put(output, "unknown/file.txt", b"dummy")
    elif case == "executable": put(output, "logs/payload.py", b"dummy")
    elif case == "executable_text": put(output, "logs/payload.txt", b"dummy", 0o755)
    else:
        (output / "logs").mkdir(parents=True); (output / "logs/out.txt").symlink_to(scratch / "guard.py")
    if case != "good":
        with pytest.raises(ci.BoundaryError): ci.isolate_sanity_output(root, scratch)


def suite(tests, cases, **attrs):
    values = {"tests": str(tests), "failures": "0", "errors": "0", "skipped": "0", **attrs}
    return '<testsuite ' + ' '.join(f'{k}="{v}"' for k,v in values.items()) + '>' + cases + '</testsuite>'


CASE = '<testcase name="dummy"/>'


@pytest.mark.parametrize("xml", [
    suite(1, CASE), '<testsuites>'+suite(1, CASE)+suite(1, CASE)+'</testsuites>',
    suite(1, '<testcase name="dummy"><properties><property name="k" value="v"/></properties><system-out>synthetic</system-out></testcase>'),
])
def test_junit_valid(tmp_path, xml):
    path = put(tmp_path, "unit.xml", xml.encode())
    assert ci.verify_junit(path) >= 1


@pytest.mark.parametrize("xml", [
    '<testsuites>'+suite(2, CASE)+suite(0, CASE)+'</testsuites>', # Original false PASS 1
    '<testsuites>'+suite(1, '')+CASE+'</testsuites>', # Original false PASS 2
    '<testsuites>'+suite(-1, '')+suite(2, CASE)+'</testsuites>', # Original false PASS 3
    '<testsuites tests="3">'+suite(1, CASE)+'</testsuites>',
    suite(0, ''), '<testsuites/>', '<testsuite tests="1">'+CASE+'</testsuite>', '<broken',
    suite(2, CASE), suite(1, '<testcase name="x"><failure/></testcase>'),
    suite(1, '<testcase name="x"><skipped/></testcase>'), suite(1, '<testcase name="x"><error/></testcase>'),
    suite(1, CASE, failures="1"), suite(1, CASE, skipped="-1"), suite(1, CASE, errors="+0"),
    suite(1, '<testcase name="x"><testcase name="nested"/></testcase>'), suite(1, suite(1, CASE)),
    suite(1, '<testcase name="x"><properties><property><testcase name="nested"/></property></properties></testcase>'),
    '<!DOCTYPE x [<!ENTITY a "dummy">]>'+suite(1, CASE),
    suite(1, '<testcase/>'),
    suite(1, "unexpected text" + CASE),
    suite(1, CASE + "unexpected tail"),
])
def test_junit_invalid(tmp_path, xml):
    path = put(tmp_path, "unit.xml", xml.encode())
    with pytest.raises(ci.BoundaryError): ci.verify_junit(path)


@pytest.mark.parametrize("label,source,rc,gate", [
    ("pass", "def test_ok(): assert True\n", 0, True),
    ("fail", "def test_bad(): assert False\n", 1, False),
    ("skip", "import pytest\n@pytest.mark.skip\ndef test_skip(): pass\n", 0, False),
    ("mixed", "import pytest\ndef test_ok(): pass\n@pytest.mark.skip\ndef test_skip(): pass\n", 0, False),
    ("empty", "# no tests\n", 5, False),
])
def test_real_pytest_junit(tmp_path, label, source, rc, gate):
    path = put(tmp_path, "test_synthetic.py", source.encode())
    xml = tmp_path / "unit.xml"
    env = {**os.environ, "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1", "PYTHONDONTWRITEBYTECODE": "1"}
    env.pop("PYTEST_ADDOPTS", None)
    proc = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--junitxml", str(xml), str(path)],
                          cwd=tmp_path, env=env, capture_output=True, timeout=60)
    assert proc.returncode == rc
    if gate: assert ci.verify_junit(xml) == 1
    else:
        with pytest.raises(ci.BoundaryError): ci.verify_junit(xml)


@pytest.mark.parametrize("outer", ["C", "C.UTF-8"])
def test_utf8_locale_isolated(tmp_path, monkeypatch, outer):
    monkeypatch.setenv("LC_ALL", outer); monkeypatch.setenv("PYTHONUTF8", "1")
    env = ci.isolated_env(tmp_path, os.environ["PATH"])
    assert env["LC_ALL"] == "C" and "PYTHONUTF8" not in env
    assert not ci.locale_works(env, "C") and not ci.locale_works(env, "POSIX")
    chosen = ci.select_locale(env)
    assert ci.locale_works(env, chosen)


def test_locale_missing_fails(tmp_path, monkeypatch):
    env = ci.isolated_env(tmp_path, str(tmp_path / "no-tools"))
    monkeypatch.setattr(ci, "locale_works", lambda env, name: False)
    with pytest.raises(ci.BoundaryError, match="no usable UTF-8 locale"):
        ci.select_locale(env)


def test_junit_non_utf8(tmp_path):
    path = put(tmp_path, "unit.xml", b"\xff" + suite(1, CASE).encode())
    with pytest.raises(ci.BoundaryError): ci.verify_junit(path)
