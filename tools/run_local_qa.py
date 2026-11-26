#!/usr/bin/env python3
"""Manual, source-only QA gate. No source acquisition or dependency installation."""
import argparse
import configparser
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

REPO = "hwakeyeTW/PQC"
REPO_ID = 1469533358
COLL = "ansible_collections/security/compliance_pqc_readiness"
RUNNER = "tools/run_local_qa.py"
LANES = {
    "legacy-217": ("3.11.15", "2.17.14", "9.0.2", None, "legacy"),
    "legacy-218": ("3.11.15", "2.18.15", "9.0.2", None, "legacy"),
    "maintained-221": ("3.12.14", "2.21.5", "9.0.2", "26.8.0", "maintained"),
}
COLLECTION_PINS = {
    "legacy": dict(zip(("community.crypto", "ansible.posix", "community.general", "community.hashi_vault"),
                       ("2.26.0", "1.6.2", "10.7.0", "6.2.0"))),
    "maintained": dict(zip(("community.crypto", "ansible.posix", "community.general", "community.hashi_vault"),
                           ("3.0.5", "2.1.0", "12.0.0", "7.0.0"))),
}
SYNTAX = ("playbooks/crypto_posture_snapshot.yml", "playbooks/pqc_pipeline.yml",
          COLL + "/playbooks/pqc_pipeline.yml")
BASELINE = {"tests/test_baseline_inventory.py", "tests/fixtures/inventory_synthetic.py",
            "tests/fixtures/scan_ol9.anonymized.yml"}
EXACT = {".gitignore", "README.md", "ansible.cfg", "reports/.gitignore",
         "collections/requirements-ci.yml", "collections/requirements-ci-legacy.yml",
         "tools/check_mirrors.py", RUNNER, "tests/test_data_handling.py",
         "tests/test_mirrors.py", "tests/test_local_qa.py", "docs/development/qa.md"} | BASELINE
PREFIXES = ("roles/", "plugins/", "playbooks/", COLL + "/", "docs/development/")
REQUIRED = (EXACT - BASELINE - {"README.md"}) | set(SYNTAX) | {COLL + "/galaxy.yml", COLL + "/meta/runtime.yml"}
DOMAINS = ("roles/", "plugins/", COLL + "/roles/", COLL + "/plugins/", COLL + "/tests/unit/")
MAX_FILE, MAX_TOTAL = 2 * 1024**2, 16 * 1024**2
MAX_META, MAX_OUTPUT = 4 * 1024**2, 8 * 1024**2


class Blocked(RuntimeError):
    """Missing prerequisite or violated data boundary; never a pass."""


def require(ok, reason):
    if not ok:
        raise Blocked(reason)


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def git_hash(kind, raw):
    return hashlib.sha1(f"{kind} {len(raw)}\0".encode() + raw).hexdigest()


def oid(s):
    require(isinstance(s, str) and re.fullmatch(r"[0-9a-f]{40}", s), "invalid Git OID")
    return s


def json_object(raw):
    def unique(pairs):
        obj = {}
        for k, v in pairs:
            require(k not in obj, "duplicate JSON key")
            obj[k] = v
        return obj
    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                      parse_constant=lambda _: require(False, "invalid JSON constant"))


def safe_path(s):
    require(isinstance(s, str) and len(s) <= 512, "unsafe path")
    for p in s.split("/"):
        require(re.fullmatch(r"[A-Za-z0-9._-]{1,160}", p) and p not in {".", ".."} and
                p.lower() != ".git" and not p.endswith(".") and
                not re.fullmatch(r"(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])", p.split(".")[0]), "unsafe path")
    return s


def approved(path):
    if path == "reports/.gitignore":
        return True
    parts = path.lower().split("/")
    denied = {"inventory", "reports", "secrets", "logs", ".local", ".ansible", ".env", "__pycache__",
              ".venv", ".pytest_cache", ".gitmodules", ".gitattributes", "tmp", "host_vars", "group_vars"}
    if (any(p in denied or p.startswith((".env.", ".vault_pass", "vault-password")) for p in parts)
            or parts[-1].endswith((".zip", ".7z", ".tar", ".tar.gz", ".tgz", ".tar.xz", ".txz", ".tar.bz2",
                                  ".tbz2", ".pyc", ".pyo", ".retry", ".log", ".pem", ".key"))
            or path.lower().startswith((COLL + "/tests/output/").lower())):
        return False
    return path in EXACT or path.startswith(PREFIXES)


def tree_hashes(leaves, directories=()):
    children = {"": {}}
    for path in list(leaves) + list(directories):
        parts = path.split("/")
        for i in range(1, len(parts)):
            parent = "/".join(parts[:i-1]); current = "/".join(parts[:i])
            children.setdefault(current, {})
            children[parent][parts[i-1]] = ("40000", current)
    for path in directories:
        parent, _, name = path.rpartition("/")
        children.setdefault(path, {})
        children[parent][name] = ("40000", path)
    for path, row in leaves.items():
        parent, _, name = path.rpartition("/")
        require(name not in children[parent], "tree/leaf conflict")
        children[parent][name] = (row["mode"], row["sha"])
    hashes = {}
    def visit(path):
        data = b""
        for name, (mode, target) in sorted(children[path].items(), key=lambda item: item[0] + ("/" if item[1][0] == "40000" else "")):
            data += (mode + " " + name).encode() + b"\0" + bytes.fromhex(visit(target) if mode == "40000" else target)
        hashes[path] = git_hash("tree", data)
        return hashes[path]
    visit("")
    return hashes


def validate_manifest(m, baseline=False):
    """Validate complete metadata, not a claim that the original acquisition was safe."""
    require(isinstance(m, dict), "manifest object required")
    require(type(m.get("repo_id")) is int and m["repo_id"] == REPO_ID and m.get("repository") == REPO
            and m.get("version") == 1 and m.get("truncated") is False, "manifest identity/version")
    tested, base, head = (oid(m[k]) for k in ("commit", "base", "head"))
    parents = [oid(p) for p in m["parents"]]
    require(1 <= len(parents) <= 2 and len(set(parents)) == len(parents) and tested not in parents, "invalid parents")
    require((m.get("kind") == "head" and tested == head) or
            (m.get("kind") == "integration" and parents == [base, head] and tested not in parents), "tested source identity")
    provenance = m["provenance"]
    require(provenance.get("method") == "metadata-first-per-oid" and provenance.get("excluded_acquired") is False
            and isinstance(provenance.get("reference"), str) and re.fullmatch(r"[A-Za-z0-9._:/#-]{1,200}", provenance["reference"]),
            "external acquisition evidence required")
    rows = m["entries"]
    require(isinstance(rows, list) and 0 < len(rows) <= 10000, "invalid manifest size")
    entries, folded, leaves, dirs = {}, set(), {}, {}
    for row in rows:
        p = safe_path(row["path"]); h = oid(row["sha"])
        require(p.casefold() not in folded, "duplicate or case-aliased path")
        folded.add(p.casefold()); entries[p] = row
        if row["type"] == "tree" and row["mode"] == "040000":
            dirs[p] = h
        else:
            require(row["type"] == "blob" and row["mode"] in {"100644", "100755"}
                    and type(row.get("size")) is int and row["size"] >= 0, "unsupported source type/mode/size")
            leaves[p] = row
    require(all(not p.rpartition("/")[0] or p.rpartition("/")[0] in dirs for p in entries), "missing directory metadata")
    actual = tree_hashes(leaves, dirs)
    require(actual == {**dirs, "": oid(m["tree"])}, "native tree mismatch")
    require(not any(p.lower().startswith(".github/workflows/") for p in leaves), "automatic workflow in tested source")
    selected = {p: row for p, row in leaves.items() if approved(p)}
    require(sorted(selected) == m["allowed_paths"], "approved path set mismatch")
    require(REQUIRED <= selected.keys() and all(any(p.startswith(d) for p in selected) for d in DOMAINS), "required source missing")
    require((baseline and BASELINE <= selected.keys()) or (not baseline and not BASELINE.intersection(selected)),
            "explicit baseline-intake mode or fixtures missing")
    pins = {}
    for row in selected.values():
        h, size = row["sha"], row["size"]
        require(size <= MAX_FILE and pins.get(h, size) == size, "source size conflict")
        pins[h] = size
    excluded = {row["sha"] for p, row in leaves.items() if p not in selected}
    require(not excluded.intersection(pins) and sorted(excluded) == m["excluded_oids"], "excluded OID overlap or mismatch")
    require(sorted(pins) == provenance["acquired_oids"] and len(pins) <= 200 and sum(r["size"] for r in selected.values()) <= MAX_TOTAL,
            "acquisition evidence/budget mismatch")
    projection = tree_hashes(selected)
    require(projection[""] == oid(m["projection"]["tree"]), "projection tree mismatch")
    commit = oid(m["projection"]["commit"])
    require(commit not in {tested, base, head} and commit not in excluded, "synthetic commit identity mismatch")
    objects = set(pins) | set(projection.values()) | {commit}
    require(not objects.intersection(excluded), "projection/excluded object collision")
    return selected, objects


def directory(path):
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts, "unsafe directory path")
    for node in reversed((path, *path.parents)):
        require(stat.S_ISDIR(node.lstat().st_mode), "non-directory or redirected ancestor")
    return path


def regular(path, limit=MAX_META):
    directory(path.parent)
    s = path.lstat()
    require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and s.st_size <= limit, "unsafe file type/size")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as f:
        require((os.fstat(f.fileno()).st_ino, os.fstat(f.fileno()).st_dev) == (s.st_ino, s.st_dev), "file identity drift")
        raw = f.read(limit + 1)
    require(len(raw) == s.st_size and len(raw) <= limit, "file size drift")
    return raw


def disjoint(*paths):
    for i, a in enumerate(paths):
        for b in paths[i+1:]:
            require(a != b and a not in b.parents and b not in a.parents, "overlapping source/runtime/evidence paths")


def fs_snapshot(root, selected):
    dirs = {str(q) for p in selected for q in Path(p).parents if str(q) != "."}
    seen = set()
    for parent, folders, files in os.walk(directory(root), followlinks=False):
        parent = Path(parent)
        for name in folders[:]:
            p = parent / name; rel = p.relative_to(root).as_posix()
            if rel == ".git":
                directory(p); folders.remove(name); continue
            require(rel in dirs, "unexpected source directory")
            directory(p)
        for name in files:
            p = parent / name; rel = p.relative_to(root).as_posix()
            require(rel in selected, "unexpected source file")
            row = selected[rel]
            raw = regular(p, MAX_FILE)
            require(len(raw) == row["size"] and git_hash("blob", raw) == row["sha"]
                    and stat.S_IMODE(p.lstat().st_mode) == int(row["mode"], 8) & 0o777
                    and not raw.startswith(b"version https://git-lfs.github.com/spec/"), "source content/mode drift")
            seen.add(rel)
    require(seen == set(selected), "source file missing")


def git_snapshot(root, objects):
    gitdir = directory(root / ".git")
    fixed = {"HEAD", "config", "index", "description", "refs/heads/projection", "logs/HEAD", "logs/refs/heads/projection"}
    required = {"HEAD", "config", "index", "refs/heads/projection"}
    object_paths = {"objects/" + x[:2] + "/" + x[2:] for x in objects}
    possible = fixed | object_paths
    dirs = {str(q) for p in possible for q in Path(p).parents if str(q) != "."} | {"hooks", "info", "objects/info", "objects/pack", "refs/tags"}
    files = {}
    # Reject unknown paths, including remotes, alternates, promisor packs, config
    # includes, and hooks, before invoking Git or opening unexpected objects.
    for parent, folders, names in os.walk(gitdir, followlinks=False):
        for name in folders:
            p = Path(parent) / name
            require(p.relative_to(gitdir).as_posix() in dirs, "unexpected Git directory")
            directory(p)
        for name in names:
            p = Path(parent) / name; rel = p.relative_to(gitdir).as_posix()
            require(rel in possible, "unexpected Git metadata/object")
            files[rel] = (stat.S_IMODE(p.lstat().st_mode), sha256(regular(p, MAX_META)))
    require(required | object_paths <= files.keys(), "missing projection metadata/object")
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.read_string(regular(gitdir / "config").decode("ascii"))
    require(parser.sections() == ["core"] and not parser.defaults(), "unsafe Git config section")
    core = dict(parser["core"])
    require(set(core) == {"repositoryformatversion", "filemode", "bare", "logallrefupdates"} and
            core["repositoryformatversion"] == "0" and core["bare"] == "false" and
            core["filemode"] in {"true", "false"} and core["logallrefupdates"] in {"true", "false"}, "unsafe Git config")
    require(regular(gitdir / "HEAD") == b"ref: refs/heads/projection\n", "unexpected projection ref")
    return files


def clean_env(scratch, bin_dir):
    return {"PATH": str(bin_dir) + ":/usr/bin:/bin", "HOME": str(scratch / "home"),
            "XDG_CONFIG_HOME": str(scratch / "xdg-config"), "XDG_CACHE_HOME": str(scratch / "xdg-cache"),
            "TMPDIR": str(scratch / "tmp"), "LANG": "C", "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull, "GIT_ATTR_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_LAZY_FETCH": "1", "GIT_ALLOW_PROTOCOL": "",
            "GIT_TERMINAL_PROMPT": "0", "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1", "PIP_CONFIG_FILE": os.devnull, "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "DOCKER_CONFIG": str(scratch / "docker-config")}


def git(root, env, *args, deadline=None):
    remaining = 30 if deadline is None else min(30, deadline - time.monotonic())
    require(remaining > 0, "lane time budget exhausted")
    exe = shutil.which("git", path="/usr/bin:/bin")
    require(exe is not None, "Git unavailable")
    p = subprocess.run([exe, "--no-lazy-fetch", "--no-replace-objects", "--no-pager", "-c", "core.hooksPath=/dev/null",
                        "-c", "core.fsmonitor=false", *args], cwd=root, env=env, capture_output=True, timeout=remaining)
    require(p.returncode == 0 and len(p.stdout) <= MAX_META, "projection Git inspection failed")
    return p.stdout


class SourceGuard:
    def __init__(self, root, manifest_path, digest, baseline, env, deadline=None):
        self.deadline = deadline
        self.root, self.path, self.digest, self.env = root, manifest_path, digest, env
        raw = regular(manifest_path)
        require(sha256(raw) == digest, "manifest digest mismatch")
        self.manifest = json_object(raw)
        self.selected, self.objects = validate_manifest(self.manifest, baseline)
        self.snapshot = None
        self.check()
        self.git("fsck", "--strict", "--no-reflogs")
        self.check()

    def git(self, *args):
        return git(self.root, self.env, *args, deadline=self.deadline)

    def check(self):
        require(sha256(regular(self.path)) == self.digest, "manifest drift")
        fs_snapshot(self.root, self.selected)
        snapshot = git_snapshot(self.root, self.objects)
        require(self.snapshot is None or self.snapshot == snapshot, "projection Git metadata drift")
        self.snapshot = snapshot
        expected = self.manifest["projection"]
        require(self.git("rev-parse", "HEAD").strip().decode() == expected["commit"] and
                self.git("rev-parse", "HEAD^{tree}").strip().decode() == expected["tree"] and
                self.git("rev-list", "--parents", "HEAD").decode().split() == [expected["commit"]],
                "projection commit/tree/history mismatch")
        rows = {}
        for item in self.git("ls-files", "--stage", "-z").split(b"\0"):
            if item:
                meta, path = item.decode("ascii").split("\t", 1)
                mode, h, stage = meta.split()
                require(stage == "0" and path not in rows, "invalid projection index")
                rows[path] = (mode, h)
        require(rows == {p: (r["mode"], r["sha"]) for p, r in self.selected.items()}, "projection index mismatch")
        empty = git_hash("tree", b"")
        staged = self.git("diff", "--cached", "--name-only", "-z", "--ita-invisible-in-index",
                     "--no-renames", "--no-ext-diff", "--no-textconv", "-O" + os.devnull, empty, "--")
        require(set(staged.decode().split("\0")) - {""} == set(rows), "projection ITA/index mismatch")


def locale_utf8(env, python, deadline=None):
    probe = "import codecs,locale,sys; locale.setlocale(locale.LC_ALL,''); sys.exit(not (codecs.lookup(locale.nl_langinfo(locale.CODESET)).name == 'utf-8' and codecs.lookup(sys.getfilesystemencoding()).name == 'utf-8'))"
    def remaining():
        value = 15 if deadline is None else min(15, deadline - time.monotonic())
        require(value > 0, "lane time budget exhausted")
        return value
    def works(name):
        p = subprocess.run([python, "-I", "-B", "-X", "utf8=0", "-c", probe], env={**env, "LC_ALL": name, "LANG": name}, capture_output=True, timeout=remaining())
        return p.returncode == 0
    preferred = ("C.UTF-8", "C.utf8")
    for name in preferred:
        if works(name): return name
    exe = shutil.which("locale", path="/usr/bin:/bin")
    if exe:
        p = subprocess.run([exe, "-a"], env=env, capture_output=True, timeout=remaining())
        require(p.returncode == 0 and len(p.stdout) <= 65536, "locale enumeration failed")
        for name in sorted(set(p.stdout.decode("ascii").splitlines()) - set(preferred))[:64]:
            if re.fullmatch(r"[A-Za-z0-9_.@-]+", name) and works(name): return name
    raise Blocked("usable UTF-8 locale unavailable")


def junit(path):
    raw = regular(path, MAX_OUTPUT)
    text = raw.decode("utf-8")
    require("\0" not in text and "<!DOCTYPE" not in text.upper() and "<!ENTITY" not in text.upper(), "unsafe JUnit XML")
    encoding = re.match(r"\s*<\?xml[^?]*encoding\s*=\s*['\"]([^'\"]+)['\"]", text, re.I)
    require(not encoding or encoding[1].lower() in {"utf-8", "utf8"}, "non-UTF8 JUnit declaration")
    root = ET.fromstring(text)
    require(root.tag in {"testsuite", "testsuites"}, "invalid JUnit root")
    suites = [root] if root.tag == "testsuite" else list(root)
    require(suites and all(s.tag == "testsuite" for s in suites), "invalid JUnit suites")
    counts = dict(tests=0, failures=0, errors=0, skipped=0)
    identities, nonpass = set(), []
    def count(node, k):
        s = node.get(k)
        require(isinstance(s, str) and re.fullmatch(r"[0-9]{1,9}", s), "invalid JUnit count")
        return int(s)
    def structure(node, tags):
        require(not (node.text or "").strip() and all(c.tag in tags and not (c.tail or "").strip() for c in node), "invalid JUnit structure")
        for child in node:
            if child.tag == "properties":
                require(not (child.text or "").strip() and all(p.tag == "property" and not list(p) and not (p.tail or "").strip() for p in child), "invalid JUnit properties")
            elif child.tag in {"system-out", "system-err", "failure", "error", "skipped"}:
                require(not list(child), "nested JUnit status/output")
    for s in suites:
        structure(s, {"testcase", "properties", "system-out", "system-err"})
        actual = dict(tests=0, failures=0, errors=0, skipped=0)
        for case in s.findall("testcase"):
            structure(case, {"properties", "system-out", "system-err", "failure", "error", "skipped"})
            key = (case.get("classname", ""), case.get("name", ""))
            require(key[1] and key not in identities, "duplicate/unnamed JUnit case")
            identities.add(key); actual["tests"] += 1
            statuses = [c.tag for c in case if c.tag in {"failure", "error", "skipped"}]
            require(len(statuses) <= 1, "ambiguous JUnit status")
            if statuses:
                k = {"failure": "failures", "error": "errors", "skipped": "skipped"}[statuses[0]]
                actual[k] += 1
                # Keep only bounded source-case identities, not exception text or output.
                name = ".".join(key)
                if len(nonpass) < 50 and re.fullmatch(r"[A-Za-z0-9_./\[\](), -]{1,200}", name):
                    nonpass.append({"case": name, "status": statuses[0]})
        require(all(count(s, k) == v for k, v in actual.items()), "JUnit suite count mismatch")
        for k, v in actual.items(): counts[k] += v
    if root.tag == "testsuites":
        structure(root, {"testsuite"})
        require(all(k not in root.attrib or count(root, k) == v for k, v in counts.items()), "JUnit aggregate mismatch")
    require(counts["tests"] > 0, "empty JUnit report")
    return {**counts, "nonpass": nonpass}


def utc():
    return datetime.now(timezone.utc).isoformat()


def process(argv, cwd, env, timeout):
    """Real argv invocation, bounded output/time; do not keep raw logs."""
    result = {"start": utc(), "rc": None, "status": "BLOCKED"}
    started = time.monotonic(); output = b""
    try:
        if timeout <= 0:
            result["reason"] = "lane time budget exhausted"
            return result, output
        with tempfile.TemporaryFile(dir=env["TMPDIR"]) as f:
            p = subprocess.Popen(argv, cwd=cwd, env=env, stdout=f, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                while p.poll() is None:
                    if time.monotonic() - started >= timeout or os.fstat(f.fileno()).st_size > MAX_OUTPUT:
                        result["reason"] = "command timeout/output budget"
                        os.killpg(p.pid, signal.SIGKILL)
                        break
                    time.sleep(.05)
            finally:
                if p.poll() is None:
                    os.killpg(p.pid, signal.SIGKILL)
                result["rc"] = p.wait(timeout=10)
            f.seek(0); output = f.read(MAX_OUTPUT + 1)
            if len(output) > MAX_OUTPUT:
                result["reason"] = "command output budget"
            elif time.monotonic() - started > timeout:
                result["reason"] = "command timeout"
            if "reason" not in result:
                result["status"] = "PASS" if result["rc"] == 0 else "FAIL"
    except (OSError, subprocess.SubprocessError):
        result["reason"] = "command unavailable or execution error"
    finally:
        result["end"] = utc(); result["duration_s"] = round(time.monotonic() - started, 3)
    return result, output


def plan(lane, baseline, root, scratch, python, executable):
    _, _, _, lint, _ = LANES[lane]
    steps = []
    def add(name, argv, cwd=root, timeout=120, report=None):
        steps.append((name, argv, cwd, timeout, report))
    def suite(name, path):
        report = scratch / (name + ".xml")
        add(name, [python, "-B", "-m", "pytest", "-q", "-rs", "-p", "no:cacheprovider",
                   "-c", os.devnull, "--rootdir", str(root), "--confcutdir", str(root), "--basetemp", str(scratch / (name + "-tmp")),
                   "--junitxml", str(report), path], report=report)
    suite("collection-unit", COLL + "/tests/unit/")
    for i, path in enumerate(SYNTAX, 1):
        add("syntax-" + str(i), [executable("ansible-playbook"), "-i", str(scratch / "inventory.ini"), "--syntax-check", path], timeout=60)
    add("sanity", [executable("ansible-test"), "sanity", "--docker", "--python", ".".join(LANES[lane][0].split(".")[:2]), "plugins/"], root / COLL, 900)
    if lint:
        add("lint", [executable("ansible-lint"), "--offline", "playbooks/", "roles/"], root / COLL, 300)
    suite("data-handling", "tests/test_data_handling.py")
    add("mirror-check", [python, "-B", "tools/check_mirrors.py"])
    suite("mirrors", "tests/test_mirrors.py")
    suite("local-qa", "tests/test_local_qa.py")
    if baseline: suite("baseline-intake", "tests/test_baseline_inventory.py")
    return steps


def mirror_result(raw, legacy, canonical):
    m = re.fullmatch(rb"PASS pairs=([0-9]+)\n", raw)
    require(m and legacy == canonical and legacy and int(m[1]) == len(legacy), "mirror pair oracle mismatch")
    return {"pairs": int(m[1]), "scope": "Q14-source-projection", "original_full_checkout": "NOT_TESTED"}


def move_sanity_results(root, scratch):
    out = root / COLL / "tests/output"
    if not os.path.lexists(out): return
    directory(out); total = count = 0
    for parent, dirs, files in os.walk(out, followlinks=False):
        for name in dirs + files:
            p = Path(parent) / name; rel = p.relative_to(out)
            safe_path(rel.as_posix()); st = p.lstat(); count += 1
            require(count <= 10000 and rel.parts[0] in {"bot", "coverage", "data", "junit", "logs", "reports", ".tmp"}, "unexpected sanity output")
            if stat.S_ISDIR(st.st_mode): directory(p)
            else:
                total += st.st_size
                require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and not st.st_mode & 0o111 and total <= MAX_TOTAL
                        and p.suffix.lower() in {".xml", ".json", ".txt", ".log", ".out", ".err"}, "unsafe sanity output")
    out.rename(scratch / "sanity-output")


# These probes run in the prepared interpreter, never install anything. Keep
# third-party imports out of the standard-library orchestration process.
RUNTIME_PROBE = '''import json, sys
from importlib.metadata import distributions
from ansible import constants as c
from packaging.specifiers import SpecifierSet
from pathlib import Path
import yaml
root, deps, inv, core, manifest = sys.argv[1:]
installed = {}
for path in (Path(deps) / 'ansible_collections').glob('*/*/MANIFEST.json'):
    info = json.loads(path.read_text())['collection_info']
    key = info['namespace'] + '.' + info['name']
    if key in installed:
        raise SystemExit(1)
    runtime = yaml.safe_load((path.parent / 'meta/runtime.yml').read_text())
    if core not in SpecifierSet(runtime['requires_ansible']):
        raise SystemExit(1)
    installed[key] = info['version']
requested = {x['name']: x['version'] for x in yaml.safe_load(Path(manifest).read_text())['collections']}
assert c.COLLECTIONS_PATHS == [root, deps] and not c.COLLECTIONS_SCAN_SYS_PATH
assert c.DEFAULT_ROLES_PATH == [root + '/roles'] and c.DEFAULT_MODULE_PATH == [root + '/plugins/modules']
assert c.DEFAULT_HOST_LIST == [inv]
print(json.dumps({'packages': sorted((x.metadata['Name'], x.version) for x in distributions()), 'collections': installed, 'requested': requested}))'''
PROVIDER_PROBE = '''import json
from ansible_test._internal.data import data_context
ctx = data_context()
print(json.dumps({'provider': type(ctx.source_provider).__name__, 'root': ctx.content.root, 'paths': sorted(ctx.content.all_files()), 'layouts': sorted(x.root for x in ctx.create_collection_layouts())}))'''


class LaneRun:
    def __init__(self, root, scratch, env, guard, lane, deadline, report):
        self.root, self.scratch, self.env, self.guard = root, scratch, env, guard
        self.lane, self.deadline, self.report = lane, deadline, report
        self.failed_boundary = False

    def run(self, name, argv, cwd, limit, xml=None, sanity=False, extra=None):
        require(not self.failed_boundary, "previous source boundary failure")
        require(cwd in {self.root, self.root / COLL, self.scratch}, "unexpected command working directory")
        entry = self.report["checks"].setdefault(name, {"status": "NOT_TESTED"})
        # Record the executed argv with local path aliases; no environment or raw stdout.
        def alias(s):
            for path, label in ((self.scratch, "<scratch>"), (self.root, "<source>"),
                                (Path(sys.prefix), "<venv>"), (Path(self.env["ANSIBLE_COLLECTIONS_PATH"].split(":", 1)[-1]), "<deps>")):
                s = s.replace(str(path), label)
            return s
        entry.update(argv=[alias(str(x)) for x in argv], cwd=alias(str(cwd)), timeout_s=min(limit, max(0, self.deadline - time.monotonic())))
        try:
            require(time.monotonic() < self.deadline, "lane time budget exhausted")
            self.guard.check()
            result, output = process(argv, cwd, self.env, min(limit, self.deadline - time.monotonic()))
            entry.update(result)
            if sanity: move_sanity_results(self.root, self.scratch)
            self.guard.check()
        except (Blocked, OSError, ValueError, subprocess.SubprocessError) as exc:
            entry["command_status"] = entry["status"]
            entry.update(status="BLOCKED", reason=str(exc) if isinstance(exc, Blocked) else "source boundary inspection failed")
            self.failed_boundary = True
            raise Blocked("source boundary stopped lane") from exc
        if xml is not None:
            try:
                entry["junit"] = junit(xml)
                if any(entry["junit"][k] for k in ("failures", "errors", "skipped")) and entry["status"] == "PASS":
                    entry.update(status="FAIL", reason="required test did not pass")
            except (Blocked, OSError, ValueError, ET.ParseError):
                if entry["status"] == "PASS": entry.update(status="FAIL", reason="missing/invalid/empty JUnit")
                else: entry["junit_status"] = "INVALID_OR_MISSING"
        if entry["status"] != "PASS":
            # Limited known diagnostic identifiers, never raw lines or stack traces.
            entry["diagnostic_codes"] = sorted(set(re.findall(r"\b(?:name|yaml|fqcn|schema|var-naming|no-changed-when)\[[A-Za-z0-9_-]+\]", output.decode("utf-8", "replace"))))[:50]
        if extra and entry["status"] == "PASS":
            try:
                extra(output)
            except (Blocked, OSError, ValueError, KeyError, TypeError):
                entry.update(status="BLOCKED", reason="runtime oracle mismatch")
        return entry, output


def runtime(run, deps, python, executable):
    py, core, pytest_version, lint, group = LANES[run.lane]
    require(platform.python_version() == py and sys.prefix != sys.base_prefix, "wrong lane Python or no isolated venv")
    venv = directory(Path(sys.prefix))
    cfg = regular(venv / "pyvenv.cfg").decode("utf-8").lower().splitlines()
    require(sum(line.strip() == "include-system-site-packages = false" for line in cfg) == 1, "venv includes system packages")
    required_tools = ["ansible", "ansible-config", "ansible-doc", "ansible-inventory", "ansible-playbook", "ansible-test", "ansible-galaxy"]
    if lint: required_tools.append("ansible-lint")
    for name in required_tools:
        script = Path(executable(name))
        require(script.is_file() and os.access(script, os.X_OK), "required lane tool unavailable: " + name)
        shebang = regular(script, MAX_FILE).split(b"\n", 1)[0]
        require(shebang.startswith(b"#!" + os.fsencode(venv / "bin/python")) and
                re.fullmatch(rb"#!.+/bin/python(?:[0-9.]+)?", shebang), "tool outside prepared interpreter: " + name)
    require(shutil.which("docker", path=run.env["PATH"]) is not None, "Docker unavailable")
    # A dependency root must contain exactly the four approved collections.
    coll_root = directory(deps / "ansible_collections")
    found = set()
    for ns in coll_root.iterdir():
        directory(ns)
        for child in ns.iterdir():
            directory(child); found.add(ns.name + "." + child.name)
            regular(child / "MANIFEST.json"); regular(child / "meta/runtime.yml")
    require(found == set(COLLECTION_PINS[group]), "unexpected/missing dependency collection")
    manifest = run.root / ("collections/requirements-ci-legacy.yml" if group == "legacy" else "collections/requirements-ci.yml")
    def installed(raw):
        data = json_object(raw)
        packages = {}
        for name, version in data["packages"]:
            require(re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", name) and re.fullmatch(r"[A-Za-z0-9_.+!-]{1,100}", version), "unsafe dependency metadata")
            key = re.sub(r"[-_.]+", "-", name).lower()
            require(key not in packages, "duplicate distribution")
            packages[key] = version
        pins = {"ansible-core": core, "pytest": pytest_version}
        if lint: pins["ansible-lint"] = lint
        require(all(packages.get(k) == v for k, v in pins.items()) and data["collections"] == data["requested"] == COLLECTION_PINS[group], "runtime pin mismatch")
        run.report["versions"] = {"python": py, "packages": packages, "collections": data["collections"]}
    def inventory(raw):
        data = json_object(raw)
        require(set(data) <= {"all", "pqc_targets", "ungrouped", "_meta"} and data.get("pqc_targets", {}).get("hosts") == ["localhost"] and
                data.get("_meta", {}).get("hostvars") == {"localhost": {"ansible_connection": "local"}}, "synthetic inventory mismatch")
    def modules(raw):
        paths = dict(line.split(None, 1) for line in raw.decode().splitlines() if line.strip())
        for module in ("normalize_pqc", "generate_cbom"):
            require(paths.get("security.compliance_pqc_readiness." + module) == str(run.root / COLL / "plugins/modules" / (module + ".py")), "module loader mismatch")
    def config(raw):
        require(("config file = " + str(run.root / "ansible.cfg")).encode() in raw and ("ansible [core " + core + "]").encode() in raw, "configuration or Ansible core mismatch")
    def docker_version(raw):
        require(bool(re.fullmatch(rb"[A-Za-z0-9_.+-]+\s*", raw)), "Docker server version unavailable")
        run.report["docker_server"] = raw.decode().strip()
    def git_version(raw):
        require(bool(re.fullmatch(rb"git version [A-Za-z0-9_.+-]+\s*", raw)), "Git version unavailable")
        run.report["git_version"] = raw.decode().strip()
    checks = [
        ("git-version", [shutil.which("git", path="/usr/bin:/bin"), "--version"], git_version),
        ("pip-check", [python, "-I", "-B", "-m", "pip", "check"], None),
        ("runtime-pins", [python, "-I", "-B", "-c", RUNTIME_PROBE, str(run.root), str(deps), str(run.scratch / "inventory.ini"), core, str(manifest)], installed),
        ("config-origin", [executable("ansible"), "--version"], config),
        ("config-dump", [executable("ansible-config"), "dump", "--only-changed"], None),
        ("inventory", [executable("ansible-inventory"), "-i", str(run.scratch / "inventory.ini"), "--list"], inventory),
        ("loader", [executable("ansible-doc"), "-t", "module", "-F", "security.compliance_pqc_readiness"], modules),
        ("docker", [shutil.which("docker", path=run.env["PATH"]), "version", "--format", "{{.Server.Version}}"], docker_version),
    ]
    for name, argv, oracle in checks:
        entry, _ = run.run(name, argv, run.root, 60, extra=oracle)
        require(entry["status"] == "PASS", "runtime prerequisite failed: " + name)


def execute(args, scratch, report, deadline):
    root, deps = args.source_root, args.collections_root
    venv = Path(sys.prefix)
    for name in ("home", "xdg-config", "xdg-cache", "tmp", "docker-config", "ansible-home", "ansible-tmp", "lint-cache"):
        (scratch / name).mkdir(mode=0o700)
    python = sys.executable
    def executable(name): return str(venv / "bin" / name)
    git_env = clean_env(scratch, venv / "bin")
    require(sys.platform.startswith("linux") and sys.flags.isolated and sys.dont_write_bytecode, "Linux and python -I -B required")
    require(stat.S_IMODE(root.lstat().st_mode) == 0o700, "source root must be private (0700)")
    guard = SourceGuard(root, args.source_manifest, args.manifest_sha256, args.with_baseline_intake, git_env, deadline=deadline)
    m = guard.manifest
    require(git_hash("blob", regular(Path(__file__).absolute(), MAX_FILE)) == guard.selected[RUNNER]["sha"], "runner bytes differ from tested source")
    report["source"] = {k: m[k] for k in ("repository", "repo_id", "kind", "commit", "tree", "base", "head", "parents", "projection")}
    report["source"].update(manifest_sha256=args.manifest_sha256, provenance=m["provenance"]["reference"],
                            allowed_count=len(guard.selected), excluded_oid_count=len(m["excluded_oids"]))
    report["checks"]["source-preflight"] = {"status": "PASS"}
    (scratch / "inventory.ini").write_text("[pqc_targets]\nlocalhost ansible_connection=local\n", encoding="utf-8")
    env = {**git_env, "LC_ALL": locale_utf8(git_env, python, deadline), "ANSIBLE_CONFIG": str(root / "ansible.cfg"),
           "ANSIBLE_INVENTORY": str(scratch / "inventory.ini"), "ANSIBLE_COLLECTIONS_PATH": f"{root}:{deps}",
           "ANSIBLE_COLLECTIONS_SCAN_SYS_PATH": "False", "ANSIBLE_COLLECTIONS_ON_ANSIBLE_VERSION_MISMATCH": "error",
           "ANSIBLE_ROLES_PATH": str(root / "roles"), "ANSIBLE_LIBRARY": str(root / "plugins/modules"),
           "ANSIBLE_HOME": str(scratch / "ansible-home"), "ANSIBLE_LOCAL_TEMP": str(scratch / "ansible-tmp"),
           "ANSIBLE_LINT_CACHE_DIR": str(scratch / "lint-cache"), "ANSIBLE_NOCOLOR": "1"}
    env["LANG"] = env["LC_ALL"]; report["locale"] = env["LC_ALL"]
    run = LaneRun(root, scratch, env, guard, args.lane, deadline, report)
    runtime(run, deps, python, executable)
    report["checks"]["runtime-preflight"] = {"status": "PASS"}
    for name, argv, cwd, limit, xml in plan(args.lane, args.with_baseline_intake, root, scratch, python, executable):
        if name == "sanity":
            def provider(raw):
                data = json_object(raw)
                paths = {p[len(COLL)+1:] for p in guard.selected if p.startswith(COLL + "/")}
                require(data == {"provider": "GitSource", "root": str(root / COLL), "paths": sorted(paths), "layouts": [str(root / COLL)]}, "sanity payload source mismatch")
            entry, _ = run.run("sanity-source", [python, "-I", "-B", "-c", PROVIDER_PROBE], cwd, 60, extra=provider)
            require(entry["status"] == "PASS", "sanity payload preflight blocked")
        if name == "mirror-check":
            legacy = {p for p in guard.selected if p.startswith(("roles/", "plugins/"))}
            canonical = {p[len(COLL)+1:] for p in guard.selected if p.startswith((COLL + "/roles/", COLL + "/plugins/"))}
            def mirror(raw):
                report["mirror"] = mirror_result(raw, legacy, canonical)
            run.run(name, argv, cwd, limit, extra=mirror)
        else:
            run.run(name, argv, cwd, limit, xml=xml, sanity=name == "sanity")
    guard.check()
    report["checks"]["source-final"] = {"status": "PASS"}


def main(argv=None):
    class Parser(argparse.ArgumentParser):
        def error(self, message):
            self.exit(2, "BLOCKED: invalid CLI\n")
    parser = Parser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--lane", required=True, choices=LANES)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--source-manifest", required=True, type=Path)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--collections-root", required=True, type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--runtime-reference", required=True, help="Approved isolated preparation record identifier")
    parser.add_argument("--with-baseline-intake", action="store_true")
    args = parser.parse_args(argv)
    os.umask(0o077)
    start = time.monotonic()
    try:
        require(re.fullmatch(r"[0-9a-f]{64}", args.manifest_sha256) and re.fullmatch(r"[A-Za-z0-9._:/#-]{1,200}", args.runtime_reference), "invalid evidence reference/digest")
        root, deps, out = args.source_root, args.collections_root, args.evidence_dir
        directory(root); directory(deps); directory(out.parent); directory(args.source_manifest.parent)
        disjoint(root, deps, out, Path(sys.prefix), args.source_manifest)
        require(":" not in str(root) and ":" not in str(deps), "ambiguous collection path")
        out.mkdir(mode=0o700)  # No overwrite or reuse of evidence directories.
        out.chmod(0o700)
    except (Blocked, OSError, ValueError):
        print("BLOCKED: unsafe or unavailable input/output locations", file=sys.stderr)
        return 2
    names = [x[0] for x in plan(args.lane, args.with_baseline_intake, root, out, sys.executable, lambda x: x)]
    names = ["source-preflight", "runtime-preflight", "git-version", "pip-check", "runtime-pins", "config-origin", "config-dump", "inventory", "loader", "docker", "sanity-source", *names, "source-final"]
    report = {"version": 1, "lane": args.lane, "runtime_reference": args.runtime_reference, "start": utc(),
              "with_baseline_intake": args.with_baseline_intake, "actual_python": platform.python_version(),
              "checks": {name: {"status": "NOT_TESTED"} for name in names}}
    try:
        with tempfile.TemporaryDirectory(dir=out, prefix="scratch-") as tmp:
            Path(tmp).chmod(0o700)
            execute(args, Path(tmp), report, start + 1800)
    except (Blocked, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, configparser.Error, ET.ParseError, AttributeError, RecursionError, KeyboardInterrupt) as exc:
        report["blocked"] = str(exc) if isinstance(exc, Blocked) else type(exc).__name__
    states = [v["status"] for v in report["checks"].values()]
    report["overall"] = "BLOCKED" if report.get("blocked") or any(s in {"BLOCKED", "NOT_TESTED"} for s in states) else "FAIL" if "FAIL" in states else "PASS"
    report.update(end=utc(), duration_s=round(time.monotonic() - start, 3))
    with (out / "results.json").open("x", encoding="utf-8") as f:
        json.dump(report, f, indent=2, sort_keys=True); f.write("\n")
    print(report["overall"])
    return {"PASS": 0, "FAIL": 1, "BLOCKED": 2}[report["overall"]]


if __name__ == "__main__":
    raise SystemExit(main())
