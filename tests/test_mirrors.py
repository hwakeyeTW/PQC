"""Synthetic Git fixtures for the mirror contract (Issue #4, M01-M12)."""
import importlib.util
import os
from pathlib import Path
import shutil
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
