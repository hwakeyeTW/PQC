#!/usr/bin/env python3
"""Read-only parity check for the Collection and standalone Git mirrors."""
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

COLLECTION = "ansible_collections/security/compliance_pqc_readiness/"
DOMAINS = ("roles", "plugins")
PATHS = DOMAINS + tuple(COLLECTION + d for d in DOMAINS)
ANCHORS = tuple(
    f"roles/{role}/tasks/main.yml"
    for role in (
        "crypto_posture_snapshot", "remediate_certificates",
        "remediate_crypto_policy", "remediate_nginx_tls", "remediate_sshd",
        "vault_deploy", "vault_issue_cert", "vault_pki_setup",
    )
) + ("plugins/modules/normalize_pqc.py", "plugins/modules/generate_cbom.py")
REGULAR = {b"100644", b"100755"}


class CheckError(Exception):
    """Inspection could not be completed reliably."""


class Violation(Exception):
    """A path violates the mirror contract."""


def git(root, *args, data=b""):
    # Ignore caller Git config injection, alternate repositories/objects, tracing,
    # and other Git-specific environment controls. Keep ordinary HOME/XDG config
    # discovery so standard repo/user ignore rules still apply.
    env = {key: value for key, value in os.environ.items()
           if not key.upper().startswith("GIT_")}
    env.update(GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0",
               GIT_NO_LAZY_FETCH="1", GIT_ALLOW_PROTOCOL="",
               GIT_TRACE="0", GIT_TRACE2="0", GIT_TRACE2_EVENT="0",
               GIT_TRACE2_PERF="0")
    # Command-line config overrides repository/user config without writing it.
    # --no-lazy-fetch must be supported; older Git fails closed before inspection.
    command = ["git", "--no-pager", "--no-replace-objects", "--no-lazy-fetch",
               "--literal-pathspecs", "-c", "core.fsmonitor=false",
               "-c", "core.ignorecase=false", "-c", "core.untrackedCache=false",
               *args]
    try:
        result = subprocess.run(command, cwd=root, env=env, input=data,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                check=False)
    except OSError:
        raise CheckError("GIT_ERROR") from None
    if result.returncode or result.stderr:
        # Do not echo Git diagnostics: they can contain local paths/configuration.
        raise CheckError("GIT_ERROR")
    return result.stdout


def validate_root(root):
    try:
        root = root.resolve(strict=True)
        if not root.is_dir():
            raise CheckError("INVALID_ROOT")
        if git(root, "rev-parse", "--is-inside-work-tree") != b"true\n":
            raise CheckError("INVALID_ROOT")
        top = git(root, "rev-parse", "--show-toplevel")
        if not top.endswith(b"\n") or b"\0" in top:
            raise CheckError("INVALID_ROOT")
        if Path(os.fsdecode(top[:-1])).resolve(strict=True) != root:
            raise CheckError("INVALID_ROOT")
    except (OSError, ValueError, RuntimeError):
        raise CheckError("INVALID_ROOT") from None
    return root


def records(data):
    if not data:
        return []
    if not data.endswith(b"\0") or b"\0\0" in data:
        raise CheckError("INVALID_GIT_OUTPUT")
    return data[:-1].split(b"\0")


def split_path(raw, allow_directory=False):
    # Git may report an untracked embedded repository as a directory record.
    # Only the untracked listing permits a single trailing slash.
    if allow_directory and raw.endswith(b"/"):
        raw = raw[:-1]
    path = os.fsdecode(raw)
    parts = path.split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise CheckError("INVALID_GIT_OUTPUT")
    if os.name == "nt" and any("\\" in p or ":" in p or p.endswith((".", " "))
                               for p in parts):
        raise CheckError("INVALID_GIT_OUTPUT")
    canonical = path.startswith(COLLECTION)
    relative = path[len(COLLECTION):] if canonical else path
    if not any(relative == d or relative.startswith(d + "/") for d in DOMAINS):
        raise CheckError("INVALID_GIT_OUTPUT")
    return canonical, relative


def index_entries(data):
    sides = ({}, {})  # legacy, canonical
    for record in records(data):
        fields, sep, raw = record.partition(b"\t")
        match = re.fullmatch(rb"([0-7]{6}) ([0-9a-f]{40}|[0-9a-f]{64}) ([0-3])", fields)
        if not sep or not match:
            raise CheckError("INVALID_GIT_OUTPUT")
        mode, oid, stage = match.groups()
        if stage != b"0":
            raise CheckError("UNMERGED_STAGE")
        side, relative = split_path(raw)
        if relative in sides[side]:
            raise CheckError("INVALID_GIT_OUTPUT")
        sides[side][relative] = (mode, oid)
    return sides


def verify_objects(root, entries, result):
    """Query only regular index OIDs, without reading object contents or fetching."""
    by_oid = {}
    for path, (mode, oid) in entries.items():
        if mode in REGULAR:
            by_oid.setdefault(oid, []).append(path)
    if not by_oid:
        return
    oids = sorted(by_oid)
    data = b"".join(oid + b"\n" for oid in oids)
    output = git(root, "cat-file", "--batch-check=%(objectname) %(objecttype)", data=data)
    if not output.endswith(b"\n"):
        raise CheckError("INVALID_GIT_OUTPUT")
    lines = output[:-1].split(b"\n")
    if len(lines) != len(oids):
        raise CheckError("INVALID_GIT_OUTPUT")
    for oid, line in zip(oids, lines):
        name, sep, kind = line.partition(b" ")
        if not sep or name != oid or kind not in (b"blob", b"tree", b"commit", b"tag", b"missing"):
            raise CheckError("INVALID_GIT_OUTPUT")
        for path in by_oid[oid]:
            if kind == b"missing":
                result.errors.add((path, "MISSING_INDEX_OBJECT"))
            elif kind != b"blob":
                result.failures.add((path, "UNSUPPORTED_INDEX_OBJECT"))


def staged_paths(root, entries):
    """Identify ITA without confusing it with a genuinely staged empty blob."""
    # Git's empty tree is virtual; hash-object without -w never writes it.
    empty = git(root, "hash-object", "-t", "tree", "--stdin")
    if not re.fullmatch(rb"(?:[0-9a-f]{40}|[0-9a-f]{64})\n", empty):
        raise CheckError("INVALID_GIT_OUTPUT")
    common = ("diff", "--cached", "--name-only", "-z", "--no-renames",
              "--no-ext-diff", "--no-textconv", "--no-relative", "--ignore-submodules=none")
    def listing(option):
        paths = set()
        for raw in records(git(root, *common, option, empty[:-1].decode("ascii"), "--", *PATHS)):
            side, relative = split_path(raw)
            path = (COLLECTION if side else "") + relative
            if path in paths:
                raise CheckError("INVALID_GIT_OUTPUT")
            paths.add(path)
        return paths
    visible = listing("--ita-visible-in-index")
    staged = listing("--ita-invisible-in-index")
    # With an empty baseline every index path must be visible; reject unexpected
    # output rather than guessing intent flags or silently accepting missing rows.
    if visible != set(entries) or not staged <= visible:
        raise CheckError("INVALID_GIT_OUTPUT")
    return staged


def require_type(info, directory):
    # Windows junctions and other reparse points are unsupported, too.
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    if (getattr(info, "st_file_attributes", 0) & reparse or
            not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))):
        raise Violation("UNSUPPORTED_TYPE")


def digest(root, relative):
    """Hash regular file bytes only; reject redirected path components."""
    parts = relative.split("/")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    h = hashlib.sha256()
    try:
        with ExitStack() as stack:
            if os.open in os.supports_dir_fd and hasattr(os, "O_NOFOLLOW"):
                # Hold directory descriptors and forbid symlink following on open.
                dflags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                parent = os.open(root, dflags)
                stack.callback(os.close, parent)
                for part in parts[:-1]:
                    require_type(os.stat(part, dir_fd=parent, follow_symlinks=False), True)
                    parent = os.open(part, dflags, dir_fd=parent)
                    stack.callback(os.close, parent)
                require_type(os.stat(parts[-1], dir_fd=parent, follow_symlinks=False), False)
                fd = os.open(parts[-1], flags | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            else:
                # On platforms without dir_fd, inspect every component before open.
                path = root
                for i, part in enumerate(parts):
                    path = path / part
                    require_type(path.lstat(), i < len(parts) - 1)
                fd = os.open(path, flags | getattr(os, "O_NOFOLLOW", 0))
            stack.callback(os.close, fd)
            require_type(os.fstat(fd), False)
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                h.update(chunk)
    except FileNotFoundError:
        raise Violation("MISSING_PATH") from None
    return h.digest()


class Result:
    def __init__(self):
        self.pairs = 0
        self.failures = set()
        self.errors = set()

    def report(self):
        for level, items in (("ERROR", self.errors), ("FAIL", self.failures)):
            for path, reason in sorted(items):
                # JSON escaping keeps control characters and unusual names on one line.
                print(f"{level} {reason} {json.dumps(path, ensure_ascii=True)}")
        rc = 2 if self.errors else 1 if self.failures else 0
        print(f"{('PASS', 'FAIL', 'ERROR')[rc]} pairs={self.pairs}")
        return rc


def inspect(root, result):
    root = validate_root(root)
    legacy, canonical = index_entries(git(root, "ls-files", "--stage", "-z", "--", *PATHS))
    result.pairs = len(legacy.keys() & canonical.keys())
    entries = {**legacy, **{COLLECTION + path: entry for path, entry in canonical.items()}}
    verify_objects(root, entries, result)
    for path in entries.keys() - staged_paths(root, entries):
        result.failures.add((path, "INTENT_TO_ADD"))
    for side, prefix in ((legacy, ""), (canonical, COLLECTION)):
        for anchor in ANCHORS:
            if anchor not in side:
                result.failures.add((prefix + anchor, "MISSING_ANCHOR"))
        for path, (mode, _) in side.items():
            if mode not in REGULAR:
                result.failures.add((prefix + path, "UNSUPPORTED_TYPE"))
    for path in sorted(legacy.keys() | canonical.keys()):
        if path not in legacy:
            result.failures.add((path, "MISSING_MIRROR"))
            continue
        if path not in canonical:
            result.failures.add((path, "MISSING_CANONICAL"))
            continue
        lm, lo = legacy[path]
        cm, co = canonical[path]
        if lo != co:
            result.failures.add((path, "INDEX_CONTENT_MISMATCH"))
        if lm != cm:
            result.failures.add((path, "MODE_MISMATCH"))
        if lm not in REGULAR or cm not in REGULAR:
            continue
        hashes = []
        for full in (path, COLLECTION + path):
            try:
                hashes.append(digest(root, full))
            except Violation as exc:
                result.failures.add((full, str(exc)))
            except OSError:
                result.errors.add((full, "IO_ERROR"))
        if len(hashes) == 2 and hashes[0] != hashes[1]:
            result.failures.add((path, "WORKTREE_CONTENT_MISMATCH"))
    for raw in records(git(root, "ls-files", "--others", "--exclude-standard", "-z", "--", *PATHS)):
        side, relative = split_path(raw, allow_directory=True)
        result.failures.add(((COLLECTION if side else "") + relative, "UNTRACKED_SOURCE"))


class Parser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's default error echoes invalid arguments (possibly private data).
        self.exit(2, "ERROR INVALID_CLI\nERROR pairs=0\n")


def main(argv=None):
    parser = Parser(prog="check_mirrors.py", description=__doc__, allow_abbrev=False)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1],
                        help="Git worktree root (default: script's repository)")
    args = parser.parse_args(argv)
    result = Result()
    try:
        inspect(args.repo_root, result)
    except CheckError as exc:
        result.errors.add((".", str(exc)))
    except (OSError, ValueError):
        result.errors.add((".", "IO_ERROR"))
    return result.report()


if __name__ == "__main__":
    sys.exit(main())
