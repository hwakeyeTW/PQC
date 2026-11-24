"""Synthetic-only regression tests for PQC-M0-01 data boundaries."""

import configparser
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import uuid

import pytest


ROOT = Path(__file__).resolve().parents[1]
POLICY_FILES = (".gitignore", "reports/.gitignore")

# D01-D04: paths only; files contain no real report or environment data.
IGNORED = (
    "reports/host.json", "reports/host.html", "reports/host.pdf",
    "reports/fleet.csv", "reports/host.cbom.json", "reports/scan.log",
    "reports/README", "reports/.hidden", "reports/.cache/data",
    "reports/run-id/hosts/host-a/index.html", "reports/run-id/assets/site.js",
    "reports/run-id/assets/site.css", "reports/run_catalog.json",
    "reports/run-id/evidence/archive.zip", "reports/run-id/.gitignore",
    "report.zip", "report.7z", "report.tar", "report.tar.gz", "report.tgz",
    "report.tar.xz", "report.txz", "report.tar.bz2", "report.tbz2",
    "reports.tar.xz", "scan.log", ".ansible/tmp/module", "logs/scan.log",
    "tmp/file", ".pytest_cache/v/cache/nodeids", ".venv/bin/python",
    "__pycache__/module.pyc", "plugins/__pycache__/module.pyc",
    "module.pyc", "module.pyo", "module.pyd", "nested/scan.retry",
    ".local/private/data", "inventory/local/hosts.yml",
    "inventory/local/host_vars/host-a.yml", "inventory/local/group_vars/all.yml",
    "secrets/key", ".env", ".env.local", ".vault_pass", ".vault_pass.txt",
    "vault-password", "vault-password.txt",
)

# D05: filenames/extensions alone must not conceal legitimate source/fixtures.
PUBLIC = (
    "docs/example.md", "docs/example.html", "docs/example.json",
    "inventory/hosts.yml", "inventory/group_vars/pqc_targets/vault.yml",
    "tests/fixtures/sample.json", "tests/fixtures/sample.html",
    "tests/fixtures/sample.csv", "tests/fixtures/sample.pem",
    "tests/fixtures/sample.zip", "tests/fixtures/sample.pdf",
    "tests/fixtures/sample.tar.xz", "tests/fixtures/sample.yaml",
    "schemas/evidence.schema.json", "roles/example/templates/report.html.j2",
    "plugins/modules/example.py", "tests/fixtures/reports/index.html",
)


def clean_env(home):
    home.mkdir(parents=True, exist_ok=True)
    return {
        "PATH": os.environ.get("PATH", os.defpath),
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home / "config"),
        "LC_ALL": "C",
    }


def put(root, path, data):
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(data, encoding="utf-8")


@pytest.fixture
def isolated_git(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    env = clean_env(tmp_path / "home")
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
               GIT_CONFIG_SYSTEM=os.devnull)

    def git(*args, expected=0):
        result = subprocess.run(
            ["git", "-c", "core.excludesFile=" + os.devnull, *args],
            cwd=repo, env=env, capture_output=True, text=True, timeout=30,
        )
        # Do not print file contents or sentinel arguments on failures.
        assert result.returncode == expected, (
            f"git {args[0]}: expected {expected}, got {result.returncode}"
        )
        return result.stdout

    git("init", "-q", "--template=")
    for path in POLICY_FILES:
        target = repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / path, target)
    return repo, git


def paths(output):
    return set(output.split("\0")) - {""}


@pytest.mark.parametrize("path", IGNORED)
def test_ignored_paths(isolated_git, path):
    repo, git = isolated_git
    put(repo, path, "synthetic\n")
    git("check-ignore", "--no-index", "--", path, expected=0)
    git("check-ignore", "-v", "--no-index", "--", path, expected=0)


@pytest.mark.parametrize("path", PUBLIC + POLICY_FILES)
def test_versionable_paths(isolated_git, path):
    repo, git = isolated_git
    if path not in POLICY_FILES:
        put(repo, path, "synthetic\n")
    # Verbose mode also reports negated patterns; use non-verbose exit status.
    git("check-ignore", "--no-index", "--", path, expected=1)


def test_normal_staging_excludes_sentinels(isolated_git):
    repo, git = isolated_git
    sentinel = "PQC_SYNTHETIC_" + uuid.uuid4().hex
    for path in IGNORED:
        put(repo, path, sentinel + "\n")
    for path in PUBLIC:
        put(repo, path, "reviewed synthetic placeholder\n")
    git("add", "-A")  # Only the isolated synthetic repo.
    assert paths(git("ls-files", "-z")) == set(PUBLIC + POLICY_FILES)
    assert paths(git("diff", "--cached", "--name-only", "-z")) == set(
        PUBLIC + POLICY_FILES
    )
    assert git("grep", "--cached", "-l", "-F", "-z", "-e", sentinel, "--",
               expected=1) == ""


def test_ignore_does_not_protect_tracked_or_forced_files(isolated_git):
    repo, git = isolated_git
    tracked = "reports/previously-tracked.html"
    forced = "secrets/force-added.txt"
    # Simulate a previously tracked report from before the ignore policy.
    (repo / "reports/.gitignore").unlink()
    put(repo, tracked, "old synthetic placeholder\n")
    git("add", "--", tracked)
    git("-c", "user.name=Synthetic", "-c", "user.email=test@example.invalid",
        "commit", "-qm", "Synthetic tracked-file baseline")
    shutil.copyfile(ROOT / "reports/.gitignore", repo / "reports/.gitignore")

    sentinel = "PQC_SYNTHETIC_" + uuid.uuid4().hex
    put(repo, tracked, sentinel + "\n")
    put(repo, forced, sentinel + "\n")
    for path in (tracked, forced):
        git("check-ignore", "--no-index", "--", path, expected=0)
    git("check-ignore", "--", tracked, expected=1)
    git("add", "-A")  # Only the isolated synthetic repo.
    git("add", "-f", "--", forced)  # Negative example, not project policy.

    # These paths violate the policy even though Git permits them. Inspect
    # paths, not sentinel contents, to detect both forms of bypass.
    staged = paths(git("diff", "--cached", "--name-only", "-z"))
    assert staged - set(POLICY_FILES) == {tracked, forced}
    hits = paths(git("grep", "--cached", "-l", "-F", "-z", "-e", sentinel, "--"))
    assert hits == {tracked, forced}


def test_repo_config_has_no_host_key_override():
    config = configparser.ConfigParser(interpolation=None)
    config.read_string((ROOT / "ansible.cfg").read_text(encoding="utf-8"))
    assert "host_key_checking" not in config["defaults"]


def utf8_locale_available(env, name):
    # Probe in a child, not by changing the pytest process's locale. Disable
    # Python UTF-8 mode so a C/ASCII locale cannot appear to be UTF-8.
    probe = subprocess.run(
        [sys.executable, "-I", "-X", "utf8=0", "-c", """
import codecs
import locale
try:
    locale.setlocale(locale.LC_ALL, "")
    encoding = codecs.lookup(locale.nl_langinfo(locale.CODESET)).name
except (locale.Error, LookupError):
    raise SystemExit(1)
raise SystemExit(0 if encoding == "utf-8" else 1)
"""],
        env={**env, "LC_ALL": name}, capture_output=True, timeout=30,
    )
    assert probe.returncode in (0, 1), "UTF-8 locale probe failed"
    return probe.returncode == 0


def select_utf8_locale(env):
    preferred = ("C.UTF-8", "C.utf8")
    for name in preferred:
        if utf8_locale_available(env, name):
            return name
    # Other POSIX controllers may have a different installed UTF-8 locale.
    executable = shutil.which("locale", path=env["PATH"])
    if executable is not None:
        result = subprocess.run(
            [executable, "-a"], env=env, capture_output=True,
            encoding="utf-8", timeout=30,
        )
        assert result.returncode == 0, "locale enumeration failed"
        for name in sorted(set(result.stdout.splitlines()) - set(preferred)):
            if utf8_locale_available(env, name):
                return name
    pytest.fail("BLOCKED: no usable UTF-8 locale for Ansible subprocess")


def ansible_env(home, config, override=None):
    env = clean_env(home)
    env["LC_ALL"] = select_utf8_locale(env)
    env["ANSIBLE_CONFIG"] = str(config)
    if override is not None:
        env["ANSIBLE_HOST_KEY_CHECKING"] = override
    return env


@pytest.mark.parametrize("outer_locale", ["C", "C.UTF-8"])
def test_ansible_env_isolated(tmp_path, monkeypatch, outer_locale):
    # Deliberately contaminate only the parent with synthetic values.
    for key, value in {
        "LC_ALL": outer_locale, "LANG": "C", "LC_CTYPE": "C",
        "HOME": str(tmp_path / "outer-home"),
        "XDG_CONFIG_HOME": str(tmp_path / "outer-config"),
        "ANSIBLE_CONFIG": str(tmp_path / "outer.cfg"),
        "ANSIBLE_HOST_KEY_CHECKING": "False",
        "ANSIBLE_INVENTORY": str(tmp_path / "outer-inventory"),
        "ANSIBLE_COLLECTIONS_PATH": str(tmp_path / "outer-collections"),
        "PYTHONUTF8": "1", "PYTHONPATH": str(tmp_path / "outer-python"),
    }.items():
        monkeypatch.setenv(key, value)
    home = tmp_path / "home"
    config = tmp_path / "candidate.cfg"
    shutil.copyfile(ROOT / "ansible.cfg", config)
    git_env = clean_env(home)
    env = ansible_env(home, config)
    assert git_env == {
        "PATH": os.environ.get("PATH", os.defpath),
        "HOME": str(home), "XDG_CONFIG_HOME": str(home / "config"),
        "LC_ALL": "C",
    }
    assert env == {**git_env, "LC_ALL": env["LC_ALL"],
                   "ANSIBLE_CONFIG": str(config)}
    assert utf8_locale_available(env, env["LC_ALL"])
    assert home.is_dir()
    assert ansible_env(home, config, "True") == {
        **env, "ANSIBLE_HOST_KEY_CHECKING": "True",
    }


@pytest.mark.parametrize("name", ["C", "POSIX", "pqc_invalid_locale"])
def test_utf8_locale_rejects_non_utf8_or_missing(tmp_path, name):
    assert not utf8_locale_available(clean_env(tmp_path / "home"), name)


def test_utf8_locale_unavailable_fails(tmp_path, monkeypatch):
    # Exercise the no-locale branch synthetically; no Ansible output is mocked.
    env = clean_env(tmp_path / "home")
    env["PATH"] = str(tmp_path / "empty-bin")
    monkeypatch.setattr(sys.modules[__name__], "utf8_locale_available",
                        lambda env, name: False)
    with pytest.raises(pytest.fail.Exception, match="no usable UTF-8 locale"):
        select_utf8_locale(env)


def host_key_checking(tmp_path, config, override=None):
    executable = shutil.which("ansible-config")
    if executable is None:
        pytest.skip("NOT_TESTED: ansible-config is unavailable")
    env = ansible_env(tmp_path / "home", config, override)
    result = subprocess.run(
        [executable, "dump"], cwd=tmp_path, env=env, capture_output=True,
        encoding="utf-8", timeout=30,
    )
    assert result.returncode == 0, "isolated ansible-config dump failed"
    matches = re.findall(
        r"^HOST_KEY_CHECKING\(([^\n]*)\) = (True|False)$",
        result.stdout, re.MULTILINE,
    )
    assert len(matches) == 1, "expected exactly one HOST_KEY_CHECKING setting"
    return matches[0]


def test_ansible_clean_default(tmp_path):
    config = tmp_path / "ansible.cfg"
    shutil.copyfile(ROOT / "ansible.cfg", config)
    assert host_key_checking(tmp_path, config) == ("default", "True")


def test_ansible_env_override(tmp_path):
    config = tmp_path / "ansible.cfg"
    shutil.copyfile(ROOT / "ansible.cfg", config)
    assert host_key_checking(tmp_path, config, "False") == (
        "env: ANSIBLE_HOST_KEY_CHECKING", "False"
    )


def test_ansible_external_config_precedence(tmp_path):
    config = tmp_path / "external.cfg"
    put(tmp_path, config.name, "[defaults]\nhost_key_checking = False\n")
    assert host_key_checking(tmp_path, config) == (str(config), "False")
    assert host_key_checking(tmp_path, config, "True") == (
        "env: ANSIBLE_HOST_KEY_CHECKING", "True"
    )
