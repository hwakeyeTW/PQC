"""Synthetic Git fixtures for the mirror contract (Issue #4, M01-M12)."""
from contextlib import contextmanager
import ctypes
import importlib.util
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "check_mirrors.py"
C = "ansible_collections/security/compliance_pqc_readiness/"
ANCHORS = [f"roles/{r}/tasks/main.yml" for r in (
    "crypto_posture_snapshot", "remediate_certificates", "remediate_crypto_policy",
    "remediate_nginx_tls", "remediate_sshd", "vault_deploy", "vault_issue_cert",
    "vault_pki_setup",
)] + ["plugins/modules/normalize_pqc.py", "plugins/modules/generate_cbom.py"]
EXTRA = "roles/crypto_posture_snapshot/templates/sample.j2"
FILE = ANCHORS[0]
SPEC = importlib.util.spec_from_file_location("check_mirrors", SCRIPT)
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)


def git(root, *args, data=None):
    p = subprocess.run(["git", *args], cwd=root, input=data,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    return p.stdout


def put(root, path, data=b"synthetic\n"):
    f = root / path
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_bytes(data)
    return f


def pair(root, path, data=b"synthetic\n"):
    put(root, path, data)
    put(root, C + path, data)


def cli(root, *args, cwd=None, script=SCRIPT, use_root=True):
    command = [sys.executable, str(script)]
    if use_root:
        command += ["--repo-root", str(root)]
    return subprocess.run(command + list(args), cwd=cwd or root,
                          capture_output=True, text=True, check=False)


def expect(root, rc, *reasons):
    p = cli(root)
    assert p.returncode == rc, (p.stdout, p.stderr)
    for reason in reasons:
        assert reason in p.stdout
    assert p.stderr == ""
    assert p.stdout.splitlines()[-1].startswith(("PASS", "FAIL", "ERROR")[rc] + " pairs=")
    return p.stdout


@pytest.fixture
def repo(tmp_path, monkeypatch):
    # Isolate inherited Git repository/config/excludes settings from real data.
    for key in tuple(os.environ):
        if key.startswith("GIT_"):
            monkeypatch.delenv(key, raising=False)
    home = tmp_path / "home"
    home.mkdir()
    for key in ("HOME", "USERPROFILE", "XDG_CONFIG_HOME"):
        monkeypatch.setenv(key, str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(home / "gitconfig"))
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q")
    git(root, "config", "user.name", "Synthetic")
    git(root, "config", "user.email", "synthetic@example.invalid")
    git(root, "config", "core.autocrlf", "false")
    git(root, "config", "core.filemode", "false")
    for path in ANCHORS + [EXTRA]:
        pair(root, path)
    git(root, "add", "--", "roles", "plugins", "ansible_collections")
    git(root, "commit", "-qm", "synthetic baseline")
    return root


def test_m01_paired_tree(repo):
    assert expect(repo, 0) == "PASS pairs=11\n"


@pytest.mark.parametrize("prefix", ["", C])
def test_m02_staged_content_drift(repo, prefix):
    put(repo, prefix + FILE, b"different\n")  # same byte length
    git(repo, "add", "--", prefix + FILE)
    expect(repo, 1, "INDEX_CONTENT_MISMATCH", FILE, "WORKTREE_CONTENT_MISMATCH")


@pytest.mark.parametrize("prefix,reason", [("", "MISSING_CANONICAL"), (C, "MISSING_MIRROR")])
def test_m03_single_side_add(repo, prefix, reason):
    path = prefix + "plugins/modules/new.py"
    put(repo, path)
    git(repo, "add", "--", path)
    expect(repo, 1, reason, "plugins/modules/new.py")


@pytest.mark.parametrize("prefix,reason", [("", "MISSING_MIRROR"), (C, "MISSING_CANONICAL")])
def test_m03_remove_role(repo, prefix, reason):
    git(repo, "rm", "-qr", "--", prefix + "roles/crypto_posture_snapshot")
    expect(repo, 1, reason, "MISSING_ANCHOR", FILE)


def test_m04_rename_same_basename(repo):
    dest = "roles/crypto_posture_snapshot/other/sample.j2"
    (repo / dest).parent.mkdir()
    git(repo, "mv", "--", EXTRA, dest)
    expect(repo, 1, "MISSING_CANONICAL", "MISSING_MIRROR", dest, EXTRA)


def test_m04_new_role_and_nested_plugin(repo):
    pair(repo, "roles/new_role/tasks/main.yml")
    pair(repo, "plugins/module_utils/deep/example.py")
    git(repo, "add", "--", "roles", "plugins", "ansible_collections")
    assert expect(repo, 0) == "PASS pairs=13\n"


def test_m05_index_modes(repo):
    git(repo, "update-index", "--chmod=+x", "--", FILE)
    expect(repo, 1, "MODE_MISMATCH", FILE)
    git(repo, "update-index", "--chmod=+x", "--", C + FILE)
    expect(repo, 0)


@pytest.mark.parametrize("mode", ["120000", "160000"])
def test_m05_unsupported_index_type_on_both_sides(repo, mode):
    oid = git(repo, "rev-parse", "HEAD" if mode == "160000" else "HEAD:" + FILE).decode().strip()
    for prefix in ("", C):
        git(repo, "update-index", "--cacheinfo", f"{mode},{oid},{prefix + FILE}")
    expect(repo, 1, "UNSUPPORTED_TYPE", FILE)


@pytest.mark.parametrize("data", [b"different\n", b"synthetic\r\n"])
def test_m06_unstaged_bytes(repo, data):
    put(repo, FILE, data)
    out = expect(repo, 1, "WORKTREE_CONTENT_MISMATCH", FILE)
    assert "INDEX_CONTENT_MISMATCH" not in out


def test_m06_missing_checkout_file(repo):
    (repo / (C + FILE)).unlink()
    expect(repo, 1, "MISSING_PATH", C + FILE)


@pytest.mark.parametrize("parent", [False, True])
def test_m06_redirected_path(repo, tmp_path, monkeypatch, parent):
    target = tmp_path / "external"
    target.mkdir()
    put(target, "main.yml", b"outside-private-sentinel")
    path = repo / FILE
    if parent:
        path = path.parent
        shutil.rmtree(path)
    else:
        path.unlink()
    try:
        path.symlink_to(target if parent else target / "main.yml", target_is_directory=parent)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation unavailable on this platform")
    out = expect(repo, 1, "UNSUPPORTED_TYPE", FILE)
    assert "outside-private-sentinel" not in out
    # Directly establish rejection before a byte read, not merely redacted output.
    def forbidden_read(*args):
        pytest.fail("redirected file must not be read")
    monkeypatch.setattr(checker.os, "read", forbidden_read)
    with pytest.raises(checker.Violation, match="UNSUPPORTED_TYPE"):
        checker.digest(repo, FILE)


def test_m07_index_drift_even_with_equal_checkout(repo):
    put(repo, FILE, b"different\n")
    git(repo, "add", "--", FILE)
    put(repo, C + FILE, b"different\n")
    out = expect(repo, 1, "INDEX_CONTENT_MISMATCH")
    assert "WORKTREE_CONTENT_MISMATCH" not in out


def test_m07_equal_unstaged_changes_are_not_staged_evidence(repo):
    pair(repo, FILE, b"different\n")
    expect(repo, 0)
    assert git(repo, "diff", "--cached", "--name-only") == b""
    assert git(repo, "diff", "--name-only")


@pytest.mark.parametrize("both", [False, True])
def test_m08_untracked_source(repo, both):
    path = "plugins/modules/new.py"
    put(repo, path)
    if both:
        put(repo, C + path)
    expect(repo, 1, "UNTRACKED_SOURCE", path)
    if both:
        git(repo, "add", "--", path, C + path)
        expect(repo, 0)


def test_m08_ignored_cache_and_outside_domain(repo):
    put(repo, ".gitignore", b"__pycache__/\n")
    put(repo, "plugins/modules/__pycache__/ignored.pyc")
    for path in ("reports/example.json", "inventory/synthetic.yml", "tools/new.py", "secret/token"):
        put(repo, path, b"outside-private-sentinel")
    expect(repo, 0)


def test_m09_both_anchor_missing(repo):
    git(repo, "rm", "-q", "--", FILE, C + FILE)
    expect(repo, 1, "MISSING_ANCHOR", FILE, C + FILE)


def test_m09_empty_domain(repo):
    git(repo, "rm", "-qr", "--", "roles", "plugins", "ansible_collections")
    out = expect(repo, 1, "MISSING_ANCHOR")
    assert out.endswith("FAIL pairs=0\n")


def test_m09_empty_mirror(repo):
    git(repo, "rm", "-qr", "--", "roles", "plugins")
    expect(repo, 1, "MISSING_ANCHOR", "MISSING_MIRROR")


def test_m10_invalid_root(repo, tmp_path):
    for path in (tmp_path, repo / "roles", tmp_path / "missing-private-sentinel"):
        p = cli(path, cwd=repo)
        assert p.returncode == 2 and "ERROR" in p.stdout
        assert str(path) not in p.stdout + p.stderr


def test_m10_git_missing(repo, monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(tmp_path))
    expect(repo, 2, "GIT_ERROR")


def test_m10_unmerged_stage(repo):
    oid = git(repo, "rev-parse", "HEAD:" + FILE).strip()
    git(repo, "update-index", "--force-remove", "--", FILE)
    git(repo, "update-index", "--index-info", data=b"100644 " + oid + b" 1\t" + FILE.encode() + b"\n")
    expect(repo, 2, "UNMERGED_STAGE")


@pytest.mark.parametrize("raw", [b"bad\0", b"no-nul", b"\0", b"100644 bad 0\troles/a\0",
                                 b"100644 " + b"a" * 40 + b" 0\troles/../outside\0"])
def test_m10_invalid_git_output(raw):
    with pytest.raises(checker.CheckError, match="INVALID_GIT_OUTPUT"):
        checker.index_entries(raw)


def test_m10_permission_error_has_priority(repo, monkeypatch, capsys):
    put(repo, FILE, b"different\n")
    git(repo, "add", "--", FILE)
    original = checker.digest
    def denied(root, path):
        if path == FILE:
            raise PermissionError("private-absolute-sentinel")
        return original(root, path)
    monkeypatch.setattr(checker, "digest", denied)
    assert checker.main(["--repo-root", str(repo)]) == 2
    out = capsys.readouterr().out
    assert "IO_ERROR" in out and "INDEX_CONTENT_MISMATCH" in out
    assert "private-absolute-sentinel" not in out
    assert out.endswith("ERROR pairs=11\n")


def test_m11_unicode_spaces_and_cwd(repo, tmp_path):
    path = "roles/crypto_posture_snapshot/templates/\u6e2c\u8a66 name.j2"
    pair(repo, path)
    git(repo, "add", "--", path, C + path)
    assert cli(repo, cwd=tmp_path).stdout == "PASS pairs=12\n"
    local_script = put(repo, "tools/check_mirrors.py", SCRIPT.read_bytes())
    p = cli(repo, cwd=tmp_path, script=local_script, use_root=False)
    assert p.returncode == 0 and p.stdout == "PASS pairs=12\n"
    put(repo, path, b"different\n")
    out = expect(repo, 1, "WORKTREE_CONTENT_MISMATCH", "\\u6e2c\\u8a66 name.j2")
    assert out == expect(repo, 1)


@pytest.mark.skipif(os.name == "nt", reason="Windows disallows control characters in names")
def test_m11_control_character_escaped(repo):
    path = "plugins/modules/line\nwith\ttab.py"
    pair(repo, path)
    git(repo, "add", "--", path, C + path)
    expect(repo, 0)
    put(repo, path, b"different\n")
    out = expect(repo, 1, "line\\nwith\\ttab.py")
    assert len(out.splitlines()) == 2


def test_m11_help_and_invalid_cli(repo):
    assert cli(repo, "--help").returncode == 0
    p = cli(repo, "--private-sentinel")
    assert p.returncode == 2 and "INVALID_CLI" in p.stderr
    assert "private-sentinel" not in p.stdout + p.stderr


def test_m11_linked_worktree(repo, tmp_path):
    other = tmp_path / "linked"
    git(repo, "worktree", "add", "--detach", str(other), "HEAD")
    expect(other, 0)


def test_m12_read_only_and_redaction(repo, monkeypatch):
    put(repo, FILE, b"inside-private-sentinel")
    put(repo, "reports/raw.json", b"outside-private-sentinel")
    put(repo, "inventory/hosts.yml", b"outside-private-sentinel")
    before_index = (repo / ".git/index").read_bytes()
    before_head = git(repo, "rev-parse", "HEAD")
    before_config = (repo / ".git/config").read_bytes()
    def snapshot():
        return {p.relative_to(repo): p.read_bytes() for p in repo.rglob("*")
                if p.is_file() and ".git" not in p.relative_to(repo).parts}
    before_files = snapshot()
    out = expect(repo, 1, "WORKTREE_CONTENT_MISMATCH")
    assert "private-sentinel" not in out and str(repo) not in out
    assert (repo / ".git/index").read_bytes() == before_index
    assert (repo / ".git/config").read_bytes() == before_config
    assert git(repo, "rev-parse", "HEAD") == before_head
    assert snapshot() == before_files
    original = checker.digest
    seen = []
    def bounded(root, path):
        seen.append(path)
        assert path in [prefix + p for prefix in ("", C) for p in ANCHORS + [EXTRA]]
        return original(root, path)
    monkeypatch.setattr(checker, "digest", bounded)
    assert checker.main(["--repo-root", str(repo)]) == 1
    assert len(seen) == 22


def test_m12_alternate_index_not_used(repo, monkeypatch, tmp_path):
    monkeypatch.setenv("GIT_INDEX_FILE", str(tmp_path / "nonexistent-index"))
    expect(repo, 0)
    assert not (tmp_path / "nonexistent-index").exists()


# Review R1 regressions: actual Git index mutations only in synthetic repos.
@pytest.mark.parametrize("kind,rc,reason", [
    ("missing", 2, "MISSING_INDEX_OBJECT"),
    ("commit", 1, "UNSUPPORTED_INDEX_OBJECT"),
    ("tree", 1, "UNSUPPORTED_INDEX_OBJECT"),
])
@pytest.mark.parametrize("prefixes", [("",), (C,), ("", C)])
def test_r1_01_regular_index_object_type(repo, kind, rc, reason, prefixes):
    if kind == "missing":
        oid = git(repo, "hash-object", "--stdin", data=b"missing-index-object-sentinel").decode().strip()
        p = subprocess.run(["git", "cat-file", "-e", oid], cwd=repo, capture_output=True)
        assert p.returncode != 0
    else:
        oid = git(repo, "rev-parse", "HEAD" if kind == "commit" else "HEAD^{tree}").decode().strip()
        assert git(repo, "cat-file", "-t", oid).strip() == kind.encode()
    for prefix in prefixes:
        git(repo, "update-index", "--cacheinfo", f"100644,{oid},{prefix + FILE}")
    out = expect(repo, rc, reason)
    for prefix in prefixes:
        assert f'{"ERROR" if rc == 2 else "FAIL"} {reason} "{prefix + FILE}"' in out.splitlines()


def test_r1_01_unpaired_missing_object_is_error(repo):
    path = "plugins/modules/unpaired.py"
    oid = git(repo, "hash-object", "--stdin", data=b"unpaired-missing-sentinel").decode().strip()
    put(repo, path)
    git(repo, "update-index", "--add", "--cacheinfo", f"100644,{oid},{path}")
    out = expect(repo, 2, "MISSING_INDEX_OBJECT", "MISSING_CANONICAL")
    assert f'ERROR MISSING_INDEX_OBJECT "{path}"' in out.splitlines()


def test_r1_01_valid_staged_empty_blob(repo):
    path = "plugins/modules/empty.py"
    pair(repo, path, b"")
    git(repo, "add", "--", path, C + path)
    oid = git(repo, "rev-parse", ":" + path).strip().decode()
    assert git(repo, "cat-file", "-t", oid) == b"blob\n"
    assert expect(repo, 0) == "PASS pairs=12\n"


@pytest.mark.parametrize("data", [b"", b"synthetic intent\n"])
@pytest.mark.parametrize("prefixes", [("",), (C,), ("", C)])
def test_r1_02_intent_to_add_requires_real_stage(repo, data, prefixes):
    path = "plugins/modules/intent.py"
    for prefix in prefixes:
        put(repo, prefix + path, data)
    git(repo, "add", "-N", "--", *(prefix + path for prefix in prefixes))
    assert git(repo, "diff", "--cached", "--ita-invisible-in-index", "--name-only") == b""
    out = expect(repo, 1, "INTENT_TO_ADD")
    for prefix in prefixes:
        assert f'FAIL INTENT_TO_ADD "{prefix + path}"' in out.splitlines()
    pair(repo, path, data)
    git(repo, "add", "--", path, C + path)
    assert expect(repo, 0) == "PASS pairs=12\n"


def test_r1_02_intent_after_removing_committed_empty_pair(repo):
    path = "plugins/modules/committed_empty.py"
    pair(repo, path, b"")
    git(repo, "add", "--", path, C + path)
    git(repo, "commit", "-qm", "synthetic empty pair")
    git(repo, "rm", "--cached", "--", path, C + path)
    git(repo, "add", "-N", "--", path, C + path)
    expect(repo, 1, "INTENT_TO_ADD", path, C + path)
    git(repo, "add", "--", path, C + path)
    expect(repo, 0)


@pytest.mark.parametrize("prefix", ["", C])
def test_r1_03_case_variant_not_hidden(repo, prefix):
    tracked = repo / (prefix + "plugins/modules/normalize_pqc.py")
    path = prefix + "plugins/modules/normalize_PQC.py"
    if (repo / path).exists():
        pytest.skip("case-insensitive filesystem cannot represent this counterexample")
    git(repo, "config", "core.ignorecase", "true")
    expect(repo, 0)
    variant = put(repo, path)
    assert not tracked.samefile(variant)
    p = subprocess.run(["git", "check-ignore", "--no-index", "--", path],
                       cwd=repo, capture_output=True)
    assert p.returncode == 1
    assert f'FAIL UNTRACKED_SOURCE "{path}"' in expect(repo, 1, "UNTRACKED_SOURCE").splitlines()
    # Exact-case ignore rule still works; configuration must not be changed.
    put(repo, ".gitignore", b"normalize_PQC.py\n")
    expect(repo, 0)
    assert git(repo, "config", "--local", "core.ignorecase") == b"true\n"


def test_r1_03_standard_ignore_sources(repo):
    home = Path(os.environ["HOME"])
    put(home, ".gitconfig", b"[core]\n\texcludesFile = ~/standard-excludes\n")
    put(home, "standard-excludes", b"global-cache.pyc\n")
    put(repo, ".git/info/exclude", b"local-cache.pyc\n")
    put(repo, ".gitignore", b"root-cache.pyc\n")
    for prefix in ("", C):
        for name in ("global-cache.pyc", "local-cache.pyc", "root-cache.pyc"):
            put(repo, prefix + "plugins/modules/" + name)
    expect(repo, 0)
    put(repo, "plugins/modules/not-ignored.py")
    expect(repo, 1, "UNTRACKED_SOURCE", "not-ignored.py")


def all_files(root):
    return {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}


def marker_hook(tmp_path):
    hook = put(tmp_path, "fsmonitor-hook", b"#!/bin/sh\n: > \"$0.marker\"\nprintf 'synthetic-token\\000'\n")
    hook.chmod(0o700)
    return hook, Path(str(hook) + ".marker")


def test_r1_04_fsmonitor_and_traces_are_disabled(repo, tmp_path, monkeypatch):
    hook, marker = marker_hook(tmp_path)
    git(repo, "config", "core.fsmonitor", str(hook))
    trace_paths = []
    for name in ("GIT_TRACE", "GIT_TRACE_SETUP", "GIT_TRACE_PACK_ACCESS",
                 "GIT_TRACE2", "GIT_TRACE2_EVENT", "GIT_TRACE2_PERF"):
        path = tmp_path / name
        trace_paths.append(path)
        monkeypatch.setenv(name, str(path))
    assert not marker.exists() and all(not p.exists() for p in trace_paths)
    before = all_files(repo)
    expect(repo, 0)
    assert not marker.exists() and all(not p.exists() for p in trace_paths)
    assert all_files(repo) == before


def test_r1_04_file_config_trace2_disabled(repo, tmp_path):
    home = Path(os.environ["HOME"])
    paths = [tmp_path / name for name in ("normal-trace", "event-trace", "perf-trace")]
    put(home, ".gitconfig", ("[trace2]\n" + "".join(
        f'\t{key} = "{path.as_posix()}"\n'
        for key, path in zip(("normalTarget", "eventTarget", "perfTarget"), paths)
    )).encode())
    before = all_files(repo), all_files(home)
    expect(repo, 0)
    assert all(not p.exists() for p in paths)
    assert (all_files(repo), all_files(home)) == before


@pytest.mark.parametrize("injection", ["count", "parameters", "config-files", "redirect"])
def test_r1_04_inherited_git_config_and_redirects_ignored(repo, tmp_path, monkeypatch, injection):
    hook, marker = marker_hook(tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    poison = put(tmp_path, "poison-config", (
        f'[core]\n\tfsmonitor = "{hook.as_posix()}"\n\tworktree = "{other.as_posix()}"\n'
    ).encode())
    if injection == "count":
        values = {"core.fsmonitor": str(hook), "core.worktree": str(other), "core.ignorecase": "true"}
        monkeypatch.setenv("GIT_CONFIG_COUNT", str(len(values)))
        for i, (key, value) in enumerate(values.items()):
            monkeypatch.setenv(f"GIT_CONFIG_KEY_{i}", key)
            monkeypatch.setenv(f"GIT_CONFIG_VALUE_{i}", value)
    elif injection == "parameters":
        monkeypatch.setenv("GIT_CONFIG_PARAMETERS", f"'core.fsmonitor={hook}' 'core.worktree={other}'")
    elif injection == "config-files":
        for key in ("GIT_CONFIG", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM"):
            monkeypatch.setenv(key, str(poison))
    else:
        for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE",
                    "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_NAMESPACE"):
            monkeypatch.setenv(key, str(other))
    before = all_files(repo)
    expect(repo, 0)
    assert not marker.exists()
    assert not list(other.iterdir())
    assert all_files(repo) == before


def test_r1_04_injected_ignorecase_cannot_hide_source(repo, monkeypatch):
    path = "plugins/modules/normalize_PQC.py"
    if (repo / path).exists():
        pytest.skip("case-insensitive filesystem cannot represent this counterexample")
    put(repo, path)
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.ignorecase")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "true")
    monkeypatch.setenv("GIT_CONFIG_PARAMETERS", "'core.ignorecase=true'")
    expect(repo, 1, "UNTRACKED_SOURCE", path)


def test_r1_05_nested_repository_is_untracked_source(repo):
    path = "plugins/embedded"
    embedded = repo / path
    embedded.mkdir()
    git(embedded, "init", "-q")
    put(embedded, "inner.py", b"nested-private-sentinel")
    assert (path + "/").encode() + b"\0" in git(
        repo, "ls-files", "--others", "--exclude-standard", "-z", "--", "plugins")
    out = expect(repo, 1, "UNTRACKED_SOURCE", path)
    assert f'FAIL UNTRACKED_SOURCE "{path}"' in out.splitlines()
    assert "inner.py" not in out and "nested-private-sentinel" not in out


@pytest.mark.parametrize("raw", [b"plugins/embedded//", b"plugins/../outside/", b"/plugins/embedded/"])
def test_r1_05_malformed_directory_record_rejected(raw):
    with pytest.raises(checker.CheckError, match="INVALID_GIT_OUTPUT"):
        checker.split_path(raw, allow_directory=True)


def test_r1_05_directory_record_not_valid_index_path():
    with pytest.raises(checker.CheckError, match="INVALID_GIT_OUTPUT"):
        checker.index_entries(b"100644 " + b"a" * 40 + b" 0\tplugins/embedded/\0")


# Review R2 regression: observe the excluded synthetic file itself, not stdout.
@contextmanager
def watch_orderfile(path):
    """Linux open/access oracle with a fresh watch for each command."""
    if not sys.platform.startswith("linux"):
        pytest.skip("NOT_TESTED: Linux inotify access oracle unavailable")
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        init = libc.inotify_init1
        add_watch = libc.inotify_add_watch
    except AttributeError:
        pytest.fail("BLOCKED: inotify access oracle unavailable")
    init.argtypes = [ctypes.c_int]
    init.restype = ctypes.c_int
    add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
    add_watch.restype = ctypes.c_int
    fd = init(os.O_NONBLOCK | os.O_CLOEXEC)
    assert fd >= 0, "BLOCKED: inotify init failed"
    try:
        # IN_ACCESS | IN_OPEN | IN_DELETE_SELF | IN_MOVE_SELF; reject lost watches
        # and queue overflow rather than treating missing events as a pass.
        wd = add_watch(fd, os.fsencode(path), 0xC21)
        assert wd >= 0, "BLOCKED: inotify watch failed"

        def events():
            masks = []
            header = struct.Struct("iIII")
            while True:
                try:
                    raw = os.read(fd, 65536)
                except BlockingIOError:
                    break
                assert raw, "inotify returned an empty event buffer"
                offset = 0
                while offset < len(raw):
                    assert len(raw) - offset >= header.size
                    watch, mask, _, size = header.unpack_from(raw, offset)
                    offset += header.size + size
                    assert offset <= len(raw)
                    assert watch == wd and not mask & 0xEC00, "inotify watch lost/overflow"
                    assert mask in (0x20, 0x1), "unexpected inotify event"
                    masks.append(mask)
            return masks

        yield events
    finally:
        os.close(fd)


def configure_orderfile(repo, scope, path):
    if scope == "local":
        git(repo, "config", "--local", "diff.orderFile", path)
    else:
        # The checker discards GIT_CONFIG_GLOBAL and uses normal HOME discovery.
        put(Path(os.environ["HOME"]), ".gitconfig",
            f"[diff]\n\torderFile = {path}\n".encode())


def orderfile_fixture(repo, scope):
    relative = "reports/synthetic-order.txt"
    order = put(repo, relative, b"# orderfile-private-sentinel\nroles/*\nplugins/*\n")
    configure_orderfile(repo, scope, relative)
    return order


def checked_without_orderfile_access(repo, order, rc, *reasons):
    home = Path(os.environ["HOME"])
    before = all_files(repo), all_files(home)
    with watch_orderfile(order) as events:
        out = expect(repo, rc, *reasons)
        observed = events()
    assert not observed, f"excluded order file accessed: {observed}"
    assert "orderfile-private-sentinel" not in out and str(order) not in out
    assert (all_files(repo), all_files(home)) == before
    return out


@pytest.mark.parametrize("scope", ["local", "user"])
def test_r2_01_orderfile_no_access(repo, scope):
    order = orderfile_fixture(repo, scope)
    empty = checker.git(repo, "hash-object", "-t", "tree", "--stdin").strip().decode()
    # Positive control: each original R2 command really opens and reads the
    # excluded dummy file. The explicit override must return the same paths.
    common = ("diff", "--cached", "--name-only", "-z", "--no-renames",
              "--no-ext-diff", "--no-textconv", "--no-relative", "--ignore-submodules=none")
    for option in ("--ita-visible-in-index", "--ita-invisible-in-index"):
        args = (option, empty, "--", *checker.PATHS)
        with watch_orderfile(order) as events:
            original = checker.git(repo, *common, *args)
            assert events() == [0x20, 0x1]
        with watch_orderfile(order) as events:
            corrected = checker.git(repo, *common, "-O" + os.devnull, *args)
            assert events() == []
        assert set(checker.records(original)) == set(checker.records(corrected))
        assert len(checker.records(corrected)) == 22
    assert checked_without_orderfile_access(repo, order, 0) == "PASS pairs=11\n"


@pytest.mark.parametrize("scope", ["local", "user"])
def test_r2_01_missing_orderfile_does_not_break_check(repo, scope):
    relative = "reports/missing-order-file"
    configure_orderfile(repo, scope, relative)
    home = Path(os.environ["HOME"])
    before = all_files(repo), all_files(home)
    assert expect(repo, 0) == "PASS pairs=11\n"
    assert not (repo / relative).exists()
    assert (all_files(repo), all_files(home)) == before


@pytest.mark.parametrize("data", [b"", b"synthetic intent\n"], ids=["empty", "nonempty"])
@pytest.mark.parametrize("prefixes", [("",), (C,), ("", C)], ids=["legacy", "canonical", "both"])
def test_r2_01_orderfile_preserves_ita_and_real_stage(repo, data, prefixes):
    order = orderfile_fixture(repo, "local")
    path = "plugins/modules/ordered-intent.py"
    for prefix in prefixes:
        put(repo, prefix + path, data)
    git(repo, "add", "-N", "--", *(prefix + path for prefix in prefixes))
    out = checked_without_orderfile_access(repo, order, 1, "INTENT_TO_ADD")
    assert {line for line in out.splitlines() if line.startswith("FAIL INTENT_TO_ADD ")} == {
        f'FAIL INTENT_TO_ADD "{prefix + path}"' for prefix in prefixes}
    if len(prefixes) == 1:
        assert ("MISSING_CANONICAL" if prefixes == ("",) else "MISSING_MIRROR") in out
    pair(repo, path, data)
    git(repo, "add", "--", path, C + path)
    assert checked_without_orderfile_access(repo, order, 0) == "PASS pairs=12\n"


def test_r2_01_orderfile_linked_worktree_and_ignores(repo, tmp_path):
    other = tmp_path / "linked"
    git(repo, "worktree", "add", "--detach", str(other), "HEAD")
    order = orderfile_fixture(other, "local")
    home = Path(os.environ["HOME"])
    put(home, ".gitconfig", b"[core]\n\texcludesFile = ~/standard-excludes\n")
    put(home, "standard-excludes", b"global-cache.pyc\n")
    put(repo, ".git/info/exclude", b"local-cache.pyc\n")
    put(other, ".gitignore", b"root-cache.pyc\n")
    for prefix in ("", C):
        for name in ("global-cache.pyc", "local-cache.pyc", "root-cache.pyc"):
            put(other, prefix + "plugins/modules/" + name)
    before = all_files(repo)
    assert checked_without_orderfile_access(other, order, 0) == "PASS pairs=11\n"
    put(other, "plugins/modules/not-ignored.py")
    checked_without_orderfile_access(other, order, 1, "UNTRACKED_SOURCE", "not-ignored.py")
    assert all_files(repo) == before
