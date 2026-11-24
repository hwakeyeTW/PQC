"""Issue #3 synthetic inventory contract; no play execution or remote access."""
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/inventory_synthetic.py"
MODE = "PQC_SYNTHETIC_INVENTORY_MODE"
HOSTS = tuple(f"host-{letter}.example.invalid" for letter in "abcd")


def isolated_environment(tmp_path):
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
        "ANSIBLE_INVENTORY_ANY_UNPARSED_IS_FAILED": "true",
        "ANSIBLE_INVENTORY_UNPARSED_FAILED": "true",
        "ANSIBLE_COLLECTIONS_PATH": os.pathsep.join((str(ROOT), str(ROOT / "collections"))),
        "ANSIBLE_COLLECTIONS_SCAN_SYS_PATH": "false",
    }
    return tmp_path, env


@pytest.fixture
def isolated(tmp_path):
    return isolated_environment(tmp_path)


def run(isolated, command, mode=None, timeout=5):
    cwd, env = isolated
    env = env.copy()
    if mode is not None:
        env[MODE] = mode
    return subprocess.run(command, cwd=cwd, env=env, capture_output=True,
                          timeout=timeout, check=False)


def cli(isolated, *args, mode=None):
    return run(isolated, [sys.executable, str(FIXTURE), *args], mode)


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        assert key not in value, "duplicate JSON key"
        value[key] = item
    return value


def reject_json_constant(token):
    raise ValueError("nonstandard JSON constant: " + token)


def json_object(proc):
    assert proc.returncode == 0, proc.stderr.decode("utf-8", errors="replace")
    value = json.loads(proc.stdout.decode("utf-8"), object_pairs_hook=unique_object,
                       parse_constant=reject_json_constant)
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


def require_binary(isolated, name):
    binary = shutil.which(name, path=isolated[1]["PATH"])
    # Required integration cases fail closed when the tool is absent; no mock or skip.
    assert binary is not None, f"BLOCKED: required {name} not installed"
    assert (ROOT / "ansible.cfg").is_file(), "BLOCKED: candidate config unavailable"
    return binary


# Bounded diagnostic families from ansible-core v2.18.3 and v2.19.11
# inventory/script.py. Matching a family is not a runtime version/support claim.
PROFILE_FAILURE = "unable to get json decoder for inventory script result."
VALUE_FAILURE = "value could not be parsed as json."
DECODE_FAILURE = "inventory script result could not be parsed as json."
EXIT_FAILURE = "inventory script returned non-zero exit code "
OLD_JSON_FAILURE = "failed to parse executable inventory script results from "


def inventory_json_object(proc):
    data = json_object(proc)
    stderr = proc.stderr.decode("utf-8", errors="replace")
    normalized = " ".join(stderr.lower().split())
    # The v2.18.3 inventory manager may warn and serialize an empty inventory
    # if fatal controls are ineffective. Reject those diagnostics even at rc=0.
    # Do not suppress stderr or reject unrelated warnings about an empty source.
    parse_failures = (
        "failed to parse", "unable to parse", "no inventory was parsed",
        "failed to load inventory plugin", "no inventory plugins available",
        PROFILE_FAILURE, DECODE_FAILURE, EXIT_FAILURE,
    )
    assert not (any(phrase in normalized for phrase in parse_failures)
                or ("inventory script" in normalized and "had an execution error" in normalized)), (
        "inventory source parse failure: " + stderr)
    return data


def string_list(value):
    assert type(value) is list, "group hosts/children must be lists"
    assert all(type(item) is str and item for item in value), "invalid host/group name"
    assert len(value) == len(set(value)), "duplicate host/group in entry"
    return set(value)


def validate_effective_inventory(data, mode):
    """Fixture-specific --list oracle, not a general production inventory schema."""
    assert type(data) is dict
    assert "_meta" in data and type(data["_meta"]) is dict, "missing/invalid _meta"
    meta = data["_meta"]
    assert "hostvars" in meta and type(meta["hostvars"]) is dict, "missing/invalid hostvars"
    expected_hosts = set() if mode == "empty" else set(HOSTS)
    assert set(meta["hostvars"]) == expected_hosts, "unexpected hostvars host set"
    assert all(type(values) is dict for values in meta["hostvars"].values())

    if mode == "empty":
        edges = {"all": {"pqc_targets", "ungrouped"},
                 "pqc_targets": set(), "ungrouped": set()}
        # v2.18.3 JSON formatting removes empty group entries and empty keys;
        # its built-in all -> ungrouped edge remains. An omitted empty target
        # group/reference is also allowed, but no arbitrary group or host is.
        required_entries = {"all"}
        required_root_children = {"ungrouped"}
        omittable = {"pqc_targets", "ungrouped"}
    else:
        edges = {"all": {"pqc_targets", "fixture_outside", "ungrouped"},
                 "pqc_targets": {"fixture_a", "fixture_b"},
                 "fixture_a": set(), "fixture_b": set(),
                 "fixture_outside": set(), "ungrouped": set()}
        required_entries = set(edges) - {"ungrouped"}
        required_root_children = edges["all"]
        omittable = {"ungrouped"}

    groups = {name: entry for name, entry in data.items() if name != "_meta"}
    assert required_entries <= set(groups) <= set(edges), "missing/unexpected inventory group"
    children = {}
    all_hosts = set()
    for name, entry in groups.items():
        assert type(entry) is dict, "invalid inventory group entry"
        assert set(entry) <= {"hosts", "children", "vars"}, "unexpected group field"
        hosts = string_list(entry.get("hosts", []))
        refs = string_list(entry.get("children", []))
        assert type(entry.get("vars", {})) is dict, "invalid group vars"
        assert refs <= edges[name], "unexpected group reference or cycle"
        assert refs <= set(groups) | omittable, "missing nonempty group reference"
        assert hosts <= expected_hosts, "unexpected inventory host"
        if name in ("all", "ungrouped"):
            assert not hosts, "unexpected root or ungrouped host"
        children[name] = refs
        all_hosts.update(hosts)

    assert required_root_children <= children["all"], "missing required root child"
    if mode != "empty":
        assert children["pqc_targets"] == edges["pqc_targets"]
    # Traverse from all without silently accepting unattached groups or cycles.
    def reachable(name, ancestors=()):
        assert name not in ancestors, "inventory cycle"
        found = {name}
        for child in children.get(name, set()):
            found.update(reachable(child, ancestors + (name,)))
        return found

    assert set(groups) <= reachable("all"), "unlinked inventory group"
    assert all_hosts == expected_hosts, "unexpected global host union"
    assert members(data, "all") == expected_hosts
    if mode == "empty":
        assert members(data, "pqc_targets") == set()
    return data


def effective_inventory_object(proc, mode):
    return validate_effective_inventory(inventory_json_object(proc), mode)


def inventory_process(isolated, provider, *args, mode):
    cwd, _ = isolated
    binary = require_binary(isolated, "ansible-inventory")
    return run(isolated, [binary, "-i", str(provider), "--playbook-dir", str(cwd), *args],
               mode, timeout=30)


def ansible_inventory(isolated, *args, mode):
    before = FIXTURE.read_bytes(), stat.S_IMODE(FIXTURE.stat().st_mode)
    proc = inventory_process(isolated, FIXTURE, *args, mode=mode)
    data = (effective_inventory_object(proc, mode) if args == ("--list",)
            else inventory_json_object(proc))
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
    assert data["_meta"]["hostvars"] == {}
    assert members(data, "all") == members(data, "pqc_targets") == set()


# R1 oracle regressions: controlled CompletedProcess records, not native runs.
def synthetic_response(data, stderr=b"", rc=0):
    return subprocess.CompletedProcess(["synthetic-oracle-only"], rc,
                                       json.dumps(data).encode("utf-8"), stderr)


def empty_response():
    return {"_meta": {"hostvars": {}}, "all": {"children": ["ungrouped", "pqc_targets"]}}


@pytest.mark.parametrize("form", ["omitted-entries", "omitted-target", "explicit-empty-entries"])
def test_r1_oracle_legal_empty(form):
    data = empty_response()
    if form == "omitted-target":
        data["all"]["children"] = ["ungrouped"]
    elif form == "explicit-empty-entries":
        data.update(pqc_targets={"hosts": []}, ungrouped={})
    proc = synthetic_response(data, b"[WARNING]: synthetic unrelated warning\n")
    assert effective_inventory_object(proc, "empty") == data


@pytest.mark.parametrize("diagnostic", [
    b"[WARNING]: No inventory was parsed, only implicit localhost is available\n",
    b"[WARNING]: Unable to parse synthetic as an inventory source\n",
    b"[WARNING]: * Failed to\nparse synthetic with script plugin: synthetic error\n",
    b"[WARNING]: Failed to load inventory plugin, skipping script\n",
])
def test_r1_oracle_parse_warning_rc0(diagnostic):
    with pytest.raises(AssertionError, match="inventory source parse failure"):
        effective_inventory_object(synthetic_response(empty_response(), diagnostic), "empty")


@pytest.mark.parametrize("data", [
    {},
    {"all": {"children": ["ungrouped"]}},
    {"_meta": [], "all": {"children": ["ungrouped"]}},
    {"_meta": {}, "all": {"children": ["ungrouped"]}},
    {"_meta": {"hostvars": []}, "all": {"children": ["ungrouped"]}},
    {"_meta": {"hostvars": {"host-a.example.invalid": {}}}, "all": {"children": ["ungrouped"]}},
    {"_meta": {"hostvars": {}}},
    {**empty_response(), "orphan": {"hosts": ["host-extra.example.invalid"]}},
    {**empty_response(), "ungrouped": {"hosts": ["localhost"]}},
    {**empty_response(), "pqc_targets": {"hosts": "host-a.example.invalid"}},
    {**empty_response(), "pqc_targets": {"hosts": [1]}},
    {**empty_response(), "pqc_targets": []},
    {**empty_response(), "pqc_targets": {"children": "ungrouped"}},
    {**empty_response(), "pqc_targets": {"children": ["all"]}},
    {**empty_response(), "pqc_targets": {"vars": []}},
    {**empty_response(), "all": {"children": ["ungrouped", "orphan"]}},
    {**empty_response(), "all": {"children": ["ungrouped", "ungrouped"]}},
    {**empty_response(), "all": {"children": ["ungrouped"]}, "pqc_targets": {}},
], ids=["missing-shape", "missing-meta", "meta-type", "missing-hostvars", "hostvars-type",
        "nonempty-hostvars", "missing-all", "orphan-host", "implicit-localhost",
        "hosts-type", "host-name-type", "group-type", "children-type", "cycle",
        "vars-type", "unexpected-reference", "duplicate-reference", "unlinked-empty"])
def test_r1_oracle_rejects_invalid_empty(data):
    with pytest.raises(AssertionError):
        effective_inventory_object(synthetic_response(data), "empty")


def test_r1_oracle_duplicate_json_key():
    proc = subprocess.CompletedProcess(["synthetic-oracle-only"], 0,
        b'{"_meta":{"hostvars":{}},"all":{"children":["ungrouped"]},"all":{}}', b"")
    with pytest.raises(AssertionError, match="duplicate JSON key"):
        effective_inventory_object(proc, "empty")


def test_r1_oracle_nonzero():
    with pytest.raises(AssertionError):
        effective_inventory_object(synthetic_response(empty_response(), rc=2), "empty")


def test_r1_oracle_missing_tool(tmp_path):
    empty_path = tmp_path / "no-tools"
    empty_path.mkdir()
    with pytest.raises(AssertionError, match="BLOCKED: required ansible-inventory"):
        require_binary((tmp_path, {"PATH": str(empty_path)}), "ansible-inventory")


def test_r1_oracle_isolates_fatal_controls(tmp_path, monkeypatch):
    for name in ("ANSIBLE_INVENTORY_ANY_UNPARSED_IS_FAILED", "ANSIBLE_INVENTORY_UNPARSED_FAILED"):
        monkeypatch.setenv(name, "false")
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.example.invalid:8080")
    monkeypatch.setenv("ANSIBLE_INVENTORY_ENABLED", "yaml")
    _, env = isolated_environment(tmp_path)
    assert env["ANSIBLE_INVENTORY_ANY_UNPARSED_IS_FAILED"] == "true"
    assert env["ANSIBLE_INVENTORY_UNPARSED_FAILED"] == "true"
    assert env["ANSIBLE_INVENTORY_ENABLED"] == "script"
    assert env["ANSIBLE_CONFIG"] == str(ROOT / "ansible.cfg")
    assert "HTTP_PROXY" not in env


# Native negative tests: require real binaries and actual nonzero parser rc.
# The temporary executable providers contain only synthetic data and never run plays.
def test_ansible_inventory_fatal_controls(isolated):
    binary = require_binary(isolated, "ansible-config")
    proc = run(isolated, [binary, "dump", "--only-changed"], timeout=30)
    assert proc.returncode == 0, proc.stderr.decode("utf-8", errors="replace")
    output = proc.stdout.decode("utf-8")
    for setting in ("INVENTORY_ANY_UNPARSED_IS_FAILED", "INVENTORY_UNPARSED_IS_FAILED"):
        assert re.search(rf"^{setting}(?:\([^\n]*\))?\s*=\s*True\s*$", output, re.MULTILINE), (
            f"effective fatal control not enabled: {setting}")


def assert_failed_provider(proc, provider, case):
    """Native negative-case oracle; accept only the source-proven cause families."""
    stderr = proc.stderr.decode("utf-8", errors="replace")
    normalized = " ".join(stderr.split())
    lower = normalized.lower()
    path = re.escape(" ".join(str(provider).split()))
    assert proc.returncode != 0, "native parser accepted failed synthetic provider"
    # Both managers append this fatal diagnostic for the explicit inventory source.
    # Require its exact path (not just the filename or a substring of another path).
    assert re.search(r"(?i:completely failed to parse inventory source) " + path
                     + r"(?=\s|$)", normalized), stderr
    old_json = re.search(r"(?i:" + OLD_JSON_FAILURE + r")" + path + r":", normalized)
    old_exit = re.search(r"(?i:inventory script) \(" + path
                         + r"\) (?i:had an execution error):", normalized)
    profile_json = PROFILE_FAILURE in lower and VALUE_FAILURE in lower
    decode_json = DECODE_FAILURE in lower
    has_json_cause = any(phrase in lower for phrase in
                         (OLD_JSON_FAILURE, PROFILE_FAILURE, DECODE_FAILURE))
    has_exit_cause = EXIT_FAILURE in lower or ("inventory script" in lower
                                               and "had an execution error" in lower)
    if case == "malformed-json":
        assert not has_exit_cause and (old_json or profile_json or decode_json), stderr
    else:
        assert case == "nonzero-provider", "unknown synthetic failure case"
        assert not has_json_cause, stderr
        assert re.search(r"\bsynthetic_provider_failure\b", lower), stderr
        if EXIT_FAILURE in lower:
            # 2.19.11 emits a numeric exit code; 7. is not 70. or any other code.
            # Exception-chain display may repeat the same message.
            exits = re.findall(re.escape(EXIT_FAILURE) + r"([+-]?\d+)\.(?=\s|$)", lower)
            assert len(exits) == lower.count(EXIT_FAILURE) and set(exits) == {"7"}, stderr
        else:
            # 2.18.3 does not report a numeric provider rc. The native caller
            # independently proves this exact disposable script returns 7.
            assert old_exit, stderr


@pytest.mark.parametrize("case,source", [
    ("malformed-json", "print('not-json')\n"),
    ("nonzero-provider", "import sys\nprint('SYNTHETIC_PROVIDER_FAILURE', file=sys.stderr)\nsys.exit(7)\n"),
], ids=["malformed-json", "nonzero-provider"])
def test_ansible_inventory_rejects_failed_provider(isolated, case, source):
    cwd, _ = isolated
    require_binary(isolated, "ansible-inventory")
    provider = cwd / f"{case}.py"
    provider.write_text("#!/usr/bin/env python3\n" + source, encoding="utf-8")
    provider.chmod(0o700)
    if case == "nonzero-provider":
        direct = run(isolated, [str(provider), "--list"], "empty")
        assert direct.returncode == 7 and direct.stdout == b""
        assert direct.stderr == b"SYNTHETIC_PROVIDER_FAILURE\n"
    proc = inventory_process(isolated, provider, "--list", mode="empty")
    assert_failed_provider(proc, provider, case)


# Source-derived, controlled subprocess records, not native Ansible stderr.
OLD_MALFORMED = "failed to parse executable inventory script results from {provider}: invalid JSON"
OLD_NONZERO = "Inventory script ({provider}) had an execution error: SYNTHETIC_PROVIDER_FAILURE"
NEW_PROFILE = "Unable to get JSON decoder for inventory script result.\nValue could not be parsed as JSON."
NEW_DECODE = "Inventory script result could not be parsed as JSON."
NEW_NONZERO = "Inventory script returned non-zero exit code 7.\nStandard error from inventory script:\nSYNTHETIC_PROVIDER_FAILURE"


def synthetic_failure(case, detail, rc=1, fatal="{provider}"):
    provider = Path("/synthetic") / f"{case}.py"
    stderr = detail.format(provider=provider)
    if fatal is not None:
        stderr += "\n[ERROR]: Completely failed to parse inventory source " + fatal.format(provider=provider)
    proc = synthetic_response(empty_response(), stderr.encode("utf-8"), rc)
    return proc, provider, case


@pytest.mark.parametrize("case,detail", [
    ("malformed-json", OLD_MALFORMED),
    ("nonzero-provider", OLD_NONZERO),
    ("malformed-json", NEW_PROFILE),
    ("malformed-json", NEW_DECODE),
    ("nonzero-provider", NEW_NONZERO),
], ids=["v218-malformed", "v218-nonzero", "v219-profile", "v219-decode", "v219-nonzero"])
def test_r2_oracle_accepts_failed_provider(case, detail):
    assert_failed_provider(*synthetic_failure(case, detail))


@pytest.mark.parametrize("case,detail,rc,fatal", [
    ("malformed-json", NEW_PROFILE, 0, "{provider}"),
    ("malformed-json", NEW_PROFILE, 1, None),
    ("malformed-json", NEW_PROFILE, 1, "{provider}.other"),
    ("malformed-json", OLD_MALFORMED.replace("{provider}", "/synthetic/other.py"), 1, "{provider}"),
    ("malformed-json", OLD_NONZERO, 1, "{provider}"),
    ("nonzero-provider", NEW_PROFILE, 1, "{provider}"),
    ("nonzero-provider", NEW_NONZERO.replace("SYNTHETIC_PROVIDER_FAILURE", "other stderr"), 1, "{provider}"),
    ("nonzero-provider", NEW_NONZERO.replace("code 7.", "code 70."), 1, "{provider}"),
    ("malformed-json", "Unable to get JSON decoder for inventory script result.", 1, "{provider}"),
], ids=["rc-zero", "missing-fatal", "foreign-fatal-source", "foreign-old-cause",
        "nonzero-not-json", "json-not-nonzero", "missing-sentinel", "exit-70", "incomplete-profile"])
def test_r2_oracle_rejects_wrong_failure(case, detail, rc, fatal):
    with pytest.raises(AssertionError):
        assert_failed_provider(*synthetic_failure(case, detail, rc, fatal))
    if detail == NEW_NONZERO.replace("code 7.", "code 70."):
        for other in (NEW_NONZERO.replace("code 7.", "code 8."),
                      NEW_NONZERO + "\nInventory script returned non-zero exit code 70."):
            with pytest.raises(AssertionError):
                assert_failed_provider(*synthetic_failure(case, other))


def test_r2_oracle_rejects_unrelated_failure():
    for case in ("malformed-json", "nonzero-provider"):
        for detail in ("required ansible-inventory not installed", "Permission denied",
                       "invalid configuration", "Failed to load inventory plugin",
                       "SYNTHETIC_PROVIDER_FAILURE", "JSON error"):
            with pytest.raises(AssertionError):
                assert_failed_provider(*synthetic_failure(case, detail))


def test_r2_oracle_rejects_new_parse_warning_rc0():
    for detail in (NEW_PROFILE, NEW_DECODE, NEW_NONZERO):
        proc = synthetic_response(empty_response(), detail.encode("utf-8"))
        with pytest.raises(AssertionError, match="inventory source parse failure"):
            effective_inventory_object(proc, "empty")


@pytest.mark.parametrize("token", ["NaN", "Infinity", "-Infinity"])
def test_r2_oracle_rejects_nonstandard_json(token):
    raw = ('{"_meta":{"hostvars":{}},"all":{"children":["ungrouped"],'
           '"vars":{"value":' + token + '}}}').encode("utf-8")
    proc = subprocess.CompletedProcess(["synthetic-oracle-only"], 0, raw, b"")
    with pytest.raises(ValueError, match="nonstandard JSON constant"):
        effective_inventory_object(proc, "empty")


def test_r2_oracle_accepts_standard_json():
    data = empty_response()
    data["all"]["vars"] = {"values": [None, True, 0, -1, 1.5, "NaN", "Infinity", "-Infinity"]}
    proc = synthetic_response(data, b"[WARNING]: unrelated JSON note\n")
    assert effective_inventory_object(proc, "empty") == data
