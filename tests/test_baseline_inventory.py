"""Issue #3 synthetic inventory contract; no play execution or remote access."""
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/inventory_synthetic.py"
MODE = "PQC_SYNTHETIC_INVENTORY_MODE"
HOSTS = tuple(f"host-{letter}.example.invalid" for letter in "abcd")


@pytest.fixture
def isolated(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    config = tmp_path / "config"
    cache = tmp_path / "cache"
    config.mkdir()
    cache.mkdir()
    env = {
        "PATH": os.environ.get("PATH", os.defpath),
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(config),
        "XDG_CACHE_HOME": str(cache),
        "LC_ALL": "C.UTF-8",
        "LANG": "C.UTF-8",
        "PYTHONUTF8": "1",
        "PYTHONIOENCODING": "utf-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "ANSIBLE_CONFIG": str(ROOT / "ansible.cfg"),
        "ANSIBLE_LOCAL_TEMP": str(tmp_path / "ansible-tmp"),
        "ANSIBLE_INVENTORY_ENABLED": "script",
        "ANSIBLE_COLLECTIONS_PATH": os.pathsep.join((str(ROOT), str(ROOT / "collections"))),
        "ANSIBLE_COLLECTIONS_SCAN_SYS_PATH": "false",
    }
    return tmp_path, env


def run(isolated, command, mode=None, timeout=5):
    cwd, env = isolated
    env = env.copy()
    if mode is not None:
        env[MODE] = mode
    return subprocess.run(command, cwd=cwd, env=env, capture_output=True,
                          timeout=timeout, check=False)


def cli(isolated, *args, mode=None):
    return run(isolated, [sys.executable, str(FIXTURE), *args], mode)


def json_object(proc):
    assert proc.returncode == 0, proc.stderr.decode("utf-8", errors="replace")
    value = json.loads(proc.stdout.decode("utf-8"))
    assert type(value) is dict
    return value


def members(data, group, ancestors=()):
    assert group not in ancestors, "unexpected inventory cycle"
    entry = data.get(group, {})
    result = set(entry.get("hosts", []))
    for child in entry.get("children", []):
        result.update(members(data, child, ancestors + (group,)))
    return result


def check_topology(data):
    assert set(data["pqc_targets"]["children"]) == {"fixture_a", "fixture_b"}
    assert set(data["fixture_a"]["hosts"]) == set(HOSTS[:2])
    assert set(data["fixture_b"]["hosts"]) == set(HOSTS[1:3])
    assert members(data, "pqc_targets") == set(HOSTS[:3])
    assert members(data, "fixture_outside") == {HOSTS[3]}
    assert members(data, "all") == set(HOSTS)


def check_hostvars(data, merged):
    assert set(data) == set(HOSTS)
    for index, host in enumerate(HOSTS):
        values = data[host]
        assert values["ansible_host"] == f"192.0.2.{10 + index}"
        assert values["ansible_user"] == "synthetic"
        assert values["ansible_port"] == 2222
        assert values["ansible_connection"] == "local"
        assert values["ansible_ssh_common_args"] == "-o ProxyJump=jump.example.invalid"
    assert data[HOSTS[1]]["fixture_precedence"] == "host"
    if merged:
        for host in (HOSTS[0], HOSTS[2]):
            assert data[host]["fixture_precedence"] == "group"
        assert data[HOSTS[1]]["fixture_a_flag"] is True
        assert data[HOSTS[1]]["fixture_b_flag"] is True
        for host in HOSTS[:3]:
            assert data[host]["fixture_target"] is True
        assert data[HOSTS[3]]["fixture_target"] is False
        assert "fixture_precedence" not in data[HOSTS[3]]


@pytest.mark.parametrize("mode", [None, "inline", "lookup"])
def test_cli_complete_modes(isolated, mode):
    proc = cli(isolated, "--list", mode=mode)
    data = json_object(proc)
    assert proc.stderr == b""
    assert proc.stdout == cli(isolated, "--list", mode=mode).stdout
    check_topology(data)
    if mode == "lookup":
        assert "_meta" not in data
        check_hostvars({host: json_object(cli(isolated, "--host", host, mode=mode))
                        for host in HOSTS}, merged=False)
    else:
        check_hostvars(data["_meta"]["hostvars"], merged=False)
        for host in HOSTS:
            assert json_object(cli(isolated, "--host", host, mode=mode)) == data["_meta"]["hostvars"][host]


@pytest.mark.parametrize("mode", ["inline", "lookup", "empty"])
def test_cli_unknown_host(isolated, mode):
    assert json_object(cli(isolated, "--host", "unknown.example.invalid", mode=mode)) == {}


def test_cli_empty(isolated):
    data = json_object(cli(isolated, "--list", mode="empty"))
    assert data["_meta"]["hostvars"] == {}
    assert members(data, "all") == members(data, "pqc_targets") == set()
    assert json_object(cli(isolated, "--host", HOSTS[1], mode="empty")) == {}


@pytest.mark.parametrize("args", [[], ["--host"], ["--host", ""], ["--host", "--list"],
                                  ["--list", "extra"], ["--unknown-private-sentinel"]])
def test_cli_invalid_args(isolated, args):
    proc = cli(isolated, *args)
    assert proc.returncode == 2
    assert proc.stdout == b""
    assert proc.stderr == b"ERROR INVALID_FIXTURE_ARGS\n"


@pytest.mark.parametrize("mode", ["", "invalid-private-sentinel"])
def test_cli_invalid_mode(isolated, mode):
    proc = cli(isolated, "--list", mode=mode)
    assert proc.returncode == 2
    assert proc.stdout == b""
    assert proc.stderr == b"ERROR INVALID_FIXTURE_MODE\n"


def test_cli_executable_and_read_only(isolated):
    before = FIXTURE.read_bytes(), stat.S_IMODE(FIXTURE.stat().st_mode)
    assert before[1] == 0o755
    assert before[0].startswith(b"#!/usr/bin/env python3\n")
    proc = run(isolated, [str(FIXTURE), "--list"], "inline")
    assert json_object(proc) == json_object(cli(isolated, "--list", mode="inline"))
    assert (FIXTURE.read_bytes(), stat.S_IMODE(FIXTURE.stat().st_mode)) == before


def ansible_inventory(isolated, *args, mode):
    cwd, env = isolated
    binary = shutil.which("ansible-inventory", path=env["PATH"])
    # Required integration cases fail closed when the tool is absent; no mock or skip.
    assert binary is not None, "BLOCKED: required ansible-inventory not installed"
    assert (ROOT / "ansible.cfg").is_file(), "BLOCKED: candidate config unavailable"
    before = FIXTURE.read_bytes(), stat.S_IMODE(FIXTURE.stat().st_mode)
    proc = run(isolated, [binary, "-i", str(FIXTURE), "--playbook-dir", str(cwd), *args],
               mode, timeout=30)
    data = json_object(proc)
    assert (FIXTURE.read_bytes(), stat.S_IMODE(FIXTURE.stat().st_mode)) == before
    return data


@pytest.mark.parametrize("mode", ["inline", "lookup"])
def test_ansible_inventory_effective(isolated, mode):
    data = ansible_inventory(isolated, "--list", mode=mode)
    check_topology(data)
    check_hostvars(data["_meta"]["hostvars"], merged=True)


def test_ansible_inventory_modes_equivalent(isolated):
    inline = ansible_inventory(isolated, "--list", mode="inline")
    lookup = ansible_inventory(isolated, "--list", mode="lookup")
    assert inline == lookup


@pytest.mark.parametrize("mode", ["inline", "lookup"])
def test_ansible_inventory_host(isolated, mode):
    data = ansible_inventory(isolated, "--host", HOSTS[1], mode=mode)
    assert data == ansible_inventory(isolated, "--list", mode=mode)["_meta"]["hostvars"][HOSTS[1]]
    assert data["fixture_precedence"] == "host"
    assert data["fixture_a_flag"] is True and data["fixture_b_flag"] is True


def test_ansible_inventory_empty(isolated):
    data = ansible_inventory(isolated, "--list", mode="empty")
    assert data.get("_meta", {}).get("hostvars", {}) == {}
    assert members(data, "all") == members(data, "pqc_targets") == set()
