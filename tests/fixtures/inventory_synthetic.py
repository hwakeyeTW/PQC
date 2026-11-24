#!/usr/bin/env python3
"""Deterministic synthetic inventory provider, never a production inventory."""
import json
import os
import sys

MODE_ENV = "PQC_SYNTHETIC_INVENTORY_MODE"
HOSTS = tuple(f"host-{letter}.example.invalid" for letter in "abcd")


def hostvars():
    return {
        host: {
            "ansible_connection": "local",
            "ansible_host": f"192.0.2.{10 + index}",
            "ansible_user": "synthetic",
            "ansible_port": 2222,
            "ansible_ssh_common_args": "-o ProxyJump=jump.example.invalid",
            **({"fixture_precedence": "host"} if index == 1 else {}),
        }
        for index, host in enumerate(HOSTS)
    }


def inventory(mode):
    if mode == "empty":
        return {
            "all": {"children": ["pqc_targets", "ungrouped"]},
            "pqc_targets": {"hosts": []},
            "ungrouped": {"hosts": []},
            "_meta": {"hostvars": {}},
        }
    result = {
        "all": {"children": ["pqc_targets", "fixture_outside", "ungrouped"]},
        "pqc_targets": {
            "children": ["fixture_a", "fixture_b"],
            "vars": {"fixture_precedence": "group", "fixture_target": True},
        },
        "fixture_a": {"hosts": list(HOSTS[:2]), "vars": {"fixture_a_flag": True}},
        "fixture_b": {"hosts": list(HOSTS[1:3]), "vars": {"fixture_b_flag": True}},
        "fixture_outside": {"hosts": [HOSTS[3]], "vars": {"fixture_target": False}},
        "ungrouped": {"hosts": []},
    }
    if mode == "inline":
        result["_meta"] = {"hostvars": hostvars()}
    return result


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    mode = os.environ.get(MODE_ENV, "inline")
    if mode not in ("inline", "lookup", "empty"):
        print("ERROR INVALID_FIXTURE_MODE", file=sys.stderr)
        return 2
    if args == ["--list"]:
        result = inventory(mode)
    elif len(args) == 2 and args[0] == "--host" and args[1] and not args[1].startswith("-"):
        result = {} if mode == "empty" else hostvars().get(args[1], {})
    else:
        print("ERROR INVALID_FIXTURE_ARGS", file=sys.stderr)
        return 2
    # One JSON object, deterministic ordering and UTF-8 bytes; no external lookup.
    sys.stdout.buffer.write((json.dumps(result, sort_keys=True) + "\n").encode("utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
