"""Metadata-first CI acquisition; only public, verified source is projected.

The prefix through END INLINE COMMON is copied verbatim into the workflow.
The inline caller uses it before any candidate Python is executed.
"""
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import stat
import subprocess
import sys
import tempfile
import time

REPO = "hwakeyeTW/PQC"
REPO_ID = 1469533358
HOST = "api.github.com"
COLLECTION = "ansible_collections/security/compliance_pqc_readiness"
HELPER = "tools/ci_bootstrap.py"
WORKFLOW = ".github/workflows/collection-tests.yml"
MAX_BLOBS, MAX_REQUESTS = 200, 220
MAX_BLOB, MAX_TOTAL = 2 * 1024**2, 16 * 1024**2
MAX_RESPONSE = 4 * 1024**2
MAX_SECONDS, REQUEST_SECONDS = 480, 20
EXACT = frozenset({WORKFLOW, ".gitignore", "README.md", "ansible.cfg",
                   "reports/.gitignore", "collections/requirements-ci-legacy.yml",
                   "collections/requirements-ci.yml"})
PREFIXES = ("roles/", "plugins/", "playbooks/", COLLECTION + "/", "tools/",
            "tests/", "schema/", "schemas/", "docs/development/")
REQUIRED = EXACT | {"docs/development/qa.md", HELPER, "tests/test_ci_bootstrap.py",
                    "playbooks/crypto_posture_snapshot.yml", "playbooks/pqc_pipeline.yml",
                    COLLECTION + "/playbooks/pqc_pipeline.yml", COLLECTION + "/galaxy.yml",
                    COLLECTION + "/meta/runtime.yml"}
DOMAINS = ("roles/", "plugins/", COLLECTION + "/roles/",
           COLLECTION + "/plugins/", COLLECTION + "/tests/unit/")


class BoundaryError(RuntimeError):
    """Sanitized, fail-closed boundary error."""


def require(condition, message):
    if not condition:
        raise BoundaryError(message)


def oid(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value), "invalid Git OID")
    return value


def git_hash(kind, data):
    return hashlib.sha1(f"{kind} {len(data)}\0".encode() + data).hexdigest()


def unique_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON member")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _: require(False, "invalid JSON constant"))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise BoundaryError("invalid JSON response") from exc


def repo_identity(obj):
    require(type(obj.get("id")) is int and obj["id"] == REPO_ID and
            obj.get("full_name") == REPO and obj.get("private") is False,
            "repository identity mismatch")


def event_identity(env, event):
    require(env.get("GITHUB_REPOSITORY") == REPO and
            env.get("GITHUB_REPOSITORY_ID") == str(REPO_ID) and
            env.get("GITHUB_API_URL") == "https://" + HOST, "runner identity mismatch")
    repo_identity(event["repository"])
    tested = oid(env["GITHUB_SHA"])
    name = env["GITHUB_EVENT_NAME"]
    if name == "pull_request":
        pr = event["pull_request"]
        repo_identity(pr["base"]["repo"])
        require(pr["base"]["ref"] == "main" and pr.get("merge_commit_sha") == tested and
                event.get("action") in {"opened", "synchronize", "reopened"} and
                type(event.get("number")) is int and event["number"] > 0 and
                env.get("GITHUB_REF") == f"refs/pull/{event['number']}/merge", "PR event mismatch")
        base, head = oid(pr["base"]["sha"]), oid(pr["head"]["sha"])
        require(base != head and tested not in {base, head}, "PR requires tested merge commit")
    elif name == "push":
        require(event.get("ref") == env.get("GITHUB_REF") == "refs/heads/main" and
                event.get("after") == tested and event.get("deleted") is False,
                "push event mismatch")
        base, head = oid(event["before"]), tested
    else:
        raise BoundaryError("unsupported event")
    return {"repo": REPO, "repo_id": REPO_ID, "event": name, "tested": tested,
            "base": base, "head": head}


def safe_path(path):
    # Intentionally narrow portable ASCII namespace, including hidden files.
    require(isinstance(path, str) and len(path) <= 512, "unsafe path")
    for part in path.split("/"):
        require(re.fullmatch(r"[A-Za-z0-9._-]{1,160}", part) and
                part not in {".", ".."} and part.casefold() != ".git" and
                not part.endswith(".") and
                part.split(".")[0].upper() not in {"CON", "PRN", "AUX", "NUL",
                    *[f"COM{i}" for i in range(1, 10)], *[f"LPT{i}" for i in range(1, 10)]},
                "unsafe path component")
    return path


def allowed(path):
    if path == "reports/.gitignore":
        return True
    if path.casefold().startswith((COLLECTION + "/tests/output/").casefold()):
        return False
    parts = path.casefold().split("/")
    deny = {"reports", "inventory", ".local", "secrets", ".ansible", "logs", "tmp",
            ".venv", ".pytest_cache", "__pycache__", ".gitmodules", ".gitattributes"}
    if (any(p in deny or p == ".env" or p.startswith((".env.", ".vault_pass", "vault-password"))
            for p in parts) or parts[-1].endswith((".retry", ".pyc", ".pyo", ".pyd", ".log"))
            or parts[-1].endswith((".tar", ".tar.gz", ".tgz", ".tar.xz", ".txz",
                                   ".tar.bz2", ".tbz2", ".zip", ".7z"))):
        return False
    return path in EXACT or path.startswith(PREFIXES)


def tree_manifest(identity, tree_oid, response):
    """Verify every directory's Git tree object from complete recursive metadata."""
    require(response.get("sha") == oid(tree_oid) and response.get("truncated") is False,
            "wrong or truncated recursive tree")
    rows = response.get("tree")
    require(isinstance(rows, list) and 0 < len(rows) <= 10000, "invalid tree size")
    entries, folded = {}, set()
    for row in rows:
        path = safe_path(row["path"])
        require(path.casefold() not in folded, "duplicate or case-ambiguous path")
        folded.add(path.casefold())
        kind, mode, sha = row["type"], row["mode"], oid(row["sha"])
        require((kind == "tree" and mode == "040000") or
                (kind == "blob" and mode in {"100644", "100755"}), "unsupported type or mode")
        size = row.get("size")
        require(kind == "tree" or (type(size) is int and size >= 0), "invalid blob size")
        entries[path] = {"path": path, "mode": mode, "type": kind, "sha": sha, "size": size}
    children = {"": []}
    for path, row in entries.items():
        parent, _, name = path.rpartition("/")
        require(not parent or (parent in entries and entries[parent]["type"] == "tree"),
                "missing directory or ancestor conflict")
        children.setdefault(parent, []).append((name, row))
        if row["type"] == "tree":
            children.setdefault(path, [])
    for path, items in children.items():
        data = b"".join((r["mode"].lstrip("0") + " " + name).encode() + b"\0" + bytes.fromhex(r["sha"])
                        for name, r in sorted(items, key=lambda x: x[0] + ("/" if x[1]["type"] == "tree" else "")))
        require(git_hash("tree", data) == (entries[path]["sha"] if path else tree_oid),
                "recursive tree identity mismatch")
    leaves = [row for row in entries.values() if row["type"] == "blob"]
    selected = sorted((r for r in leaves if allowed(r["path"])), key=lambda r: r["path"])
    paths = {r["path"] for r in selected}
    require(REQUIRED <= paths and all(any(p.startswith(d) for p in paths) for d in DOMAINS),
            "required source missing")
    approved = {}
    for row in selected:
        sha, size = row["sha"], row["size"]
        require(size <= MAX_BLOB and approved.get(sha, size) == size, "blob size budget or conflict")
        approved[sha] = size
    excluded = {r["sha"] for r in leaves if r["path"] not in paths}
    require(not excluded.intersection(approved), "allowed/excluded OID overlap")
    require(len(approved) <= MAX_BLOBS and sum(r["size"] for r in selected) <= MAX_TOTAL,
            "source acquisition budget exceeded")
    return {**identity, "tree": tree_oid, "allowed": selected, "excluded_oids": sorted(excluded)}


class Api:
    """Bounded, exact-endpoint HTTPS GET. No redirect, proxy, retry or archive API."""
    def __init__(self, token):
        require(isinstance(token, str) and bool(token), "missing scoped read token")
        self.token, self.deadline = token, time.monotonic() + MAX_SECONDS
        self.requests, self.remaining = 0, None
        self.approved, self.fetched = None, set()

    def get(self, kind, sha=None):
        prefix = "/repos/" + REPO
        if kind == "repo":
            require(sha is None, "invalid repository endpoint")
            path = prefix
        elif kind == "commit":
            path = prefix + "/git/commits/" + oid(sha)
        elif kind == "tree":
            path = prefix + "/git/trees/" + oid(sha) + "?recursive=1"
        elif kind == "blob":
            require(self.approved is not None and sha in self.approved and sha not in self.fetched,
                    "unapproved or duplicate blob request")
            self.fetched.add(sha)
            path = prefix + "/git/blobs/" + oid(sha)
        else:
            raise BoundaryError("unsupported API endpoint")
        require(self.requests < MAX_REQUESTS and (self.remaining is None or self.remaining > 0),
                "API request budget exhausted")
        remaining_time = self.deadline - time.monotonic()
        require(remaining_time > 0, "acquisition deadline exceeded")
        self.requests += 1
        conn = http.client.HTTPSConnection(HOST, 443, timeout=min(REQUEST_SECONDS, remaining_time),
                                           context=ssl.create_default_context())
        try:
            conn.request("GET", path, headers={"Accept": "application/vnd.github+json",
                         "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "PQC-CI-bootstrap",
                         "Authorization": "Bearer " + self.token, "Accept-Encoding": "identity"})
            response = conn.getresponse()
            require(response.status == 200, "API non-200 response (no retry or redirect)")
            require(response.getheader("Content-Type", "").split(";")[0].strip() == "application/json" and
                    response.getheader("Content-Encoding", "identity") == "identity", "unexpected API response type")
            rate = response.getheader("X-RateLimit-Remaining", "")
            require(re.fullmatch(r"[0-9]+", rate), "rate limit metadata missing")
            self.remaining = int(rate)
            length = response.getheader("Content-Length")
            require(length is None or (re.fullmatch(r"[0-9]+", length) and int(length) <= MAX_RESPONSE),
                    "response length budget exceeded")
            raw = response.read(MAX_RESPONSE + 1)
            require(len(raw) <= MAX_RESPONSE and (length is None or len(raw) == int(length)) and
                    time.monotonic() < self.deadline, "response budget or length mismatch")
            result = unique_json(raw)
            require(isinstance(result, dict), "API object expected")
            return result
        except (OSError, http.client.HTTPException) as exc:
            raise BoundaryError("API transport failed") from exc
        finally:
            conn.close()

    def authorize(self, manifest):
        require(self.approved is None and not self.fetched, "API already authorized")
        pins = {r["sha"]: r["size"] for r in manifest["allowed"]}
        require(not set(pins).intersection(manifest["excluded_oids"]) and len(pins) <= MAX_BLOBS and
                self.requests + len(pins) <= MAX_REQUESTS and self.remaining is not None and
                self.remaining >= len(pins), "insufficient safe acquisition budget")
        self.approved = pins

    def blob(self, sha):
        data = self.get("blob", sha)
        size = self.approved[sha]
        require(data.get("sha") == sha and type(data.get("size")) is int and data["size"] == size and
                data.get("encoding") == "base64" and isinstance(data.get("content"), str), "blob metadata mismatch")
        try:
            raw = base64.b64decode(data["content"].replace("\n", ""), validate=True)
        except ValueError as exc:
            raise BoundaryError("invalid blob base64") from exc
        require(len(raw) == size and git_hash("blob", raw) == sha, "blob size or hash mismatch")
        require(not raw.startswith(b"version https://git-lfs.github.com/spec/"), "LFS pointer forbidden")
        return raw


def acquire_manifest(api, env, event):
    identity = event_identity(env, event)
    repo_identity(api.get("repo"))
    commit = api.get("commit", identity["tested"])
    require(commit.get("sha") == identity["tested"], "tested commit mismatch")
    parents = [oid(p["sha"]) for p in commit["parents"]]
    if identity["event"] == "pull_request":
        require(parents == [identity["base"], identity["head"]], "merge parents mismatch")
    tree_oid = oid(commit["tree"]["sha"])
    manifest = tree_manifest({**identity, "parents": parents}, tree_oid, api.get("tree", tree_oid))
    api.authorize(manifest)
    return manifest


def directory(path):
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts, "unsafe directory path")
    for node in reversed((path, *path.parents)):
        st = node.lstat()
        require(stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode), "non-directory ancestor")
    return path


def isolated_env(scratch, path=None):
    return {"PATH": path or os.defpath, "HOME": str(scratch / "home"),
            "XDG_CONFIG_HOME": str(scratch / "xdg-config"), "XDG_CACHE_HOME": str(scratch / "xdg-cache"),
            "TMPDIR": str(scratch / "tmp"), "LC_ALL": "C", "LANG": "C",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull, "GIT_ATTR_NOSYSTEM": "1",
            "GIT_NO_LAZY_FETCH": "1", "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0",
            "GIT_LFS_SKIP_SMUDGE": "1", "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1"}


def git_call(root, env, *args, data=None):
    git = shutil.which("git", path=env["PATH"])
    require(git is not None, "Git unavailable")
    # Never inherit GIT_* or configure hooks, remotes, filters or alternates.
    proc = subprocess.run([git, "--no-lazy-fetch", "-c", "core.hooksPath=/dev/null", *args],
                          cwd=root, env=env, input=data, capture_output=True, timeout=30)
    require(proc.returncode == 0, "isolated Git command failed")
    return proc.stdout


def prepare(root, scratch, env):
    directory(root)
    directory(scratch)
    require(root != scratch and root not in scratch.parents and scratch not in root.parents,
            "scratch/workspace overlap")
    require(not any(root.iterdir()), "workspace not empty")
    require(not any(scratch.iterdir()), "scratch not empty")
    for name in ("home", "xdg-config", "xdg-cache", "tmp"):
        (scratch / name).mkdir(mode=0o700)
    clean = isolated_env(scratch, env.get("PATH"))
    git_call(root, clean, "--version")
    git_call(root, clean, "init", "-q", "--template=", "--object-format=sha1", "-b", "projection")
    return clean


# END INLINE COMMON


def write_regular(path, data, mode=0o600):
    directory(path.parent)
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                           mode), "wb") as stream:
        stream.write(data)
        os.fchmod(stream.fileno(), mode)


def read_regular(path, size=None):
    directory(path.parent)
    st = path.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1, "non-regular or linked file")
    require(st.st_size <= MAX_TOTAL, "file size budget exceeded")
    if size is not None:
        require(st.st_size == size, "source size drift")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
        actual = os.fstat(stream.fileno())
        require((actual.st_dev, actual.st_ino) == (st.st_dev, st.st_ino), "file identity drift")
        return stream.read()


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode() + b"\n"


def expected_dirs(paths):
    return {str(parent) for name in paths for parent in Path(name).parents if str(parent) != "."}


def verify_files(root, manifest):
    """Check all physical source entries before any tool consumes the projection."""
    directory(root)
    files = {r["path"]: r for r in manifest["allowed"]}
    dirs = expected_dirs(files)
    seen = set()

    def visit(folder, prefix=""):
        directory(folder)
        with os.scandir(folder) as entries:
            for item in entries:
                path = prefix + item.name
                if path == ".git":
                    require(item.is_dir(follow_symlinks=False), "invalid Git directory")
                    continue
                if path in dirs:
                    require(item.is_dir(follow_symlinks=False), "source ancestor redirected")
                    visit(Path(item.path), path + "/")
                else:
                    require(path in files and item.is_file(follow_symlinks=False), "unexpected or non-regular source entry")
                    row = files[path]
                    actual = item.stat(follow_symlinks=False)
                    require(stat.S_IMODE(actual.st_mode) == int(row["mode"], 8) & 0o777,
                            "source mode drift")
                    require(git_hash("blob", read_regular(Path(item.path), row["size"])) == row["sha"],
                            "source blob drift")
                    seen.add(path)
    visit(root)
    require(seen == set(files), "source missing")


def git_metadata_snapshot(root, expected=None):
    """Read only projection-owned Git metadata, never a linked object or index."""
    gitdir = directory(root / ".git")
    files, dirs, paths = {}, set(), {}
    for parent, children, names in os.walk(gitdir, followlinks=False):
        directory(Path(parent))
        for name in children:
            path = Path(parent) / name
            directory(path)
            dirs.add(str(path.relative_to(gitdir)))
        for name in names:
            path = Path(parent) / name
            st = path.lstat()
            require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_size <= MAX_TOTAL,
                    "unsafe Git metadata")
            paths[str(path.relative_to(gitdir))] = path
    if expected is not None:
        require(set(paths) == set(expected["files"]) and sorted(dirs) == expected["dirs"],
                "unexpected Git metadata path")
    for name, path in paths.items():
        files[name] = hashlib.sha256(read_regular(path)).hexdigest()
    return {"files": files, "dirs": sorted(dirs)}


def projection_index(root, env):
    entries = {}
    for record in git_call(root, env, "ls-files", "--stage", "-z").split(b"\0"):
        if record:
            meta, path = record.decode("ascii").split("\t", 1)
            mode, sha, stage = meta.split()
            require(stage == "0" and path not in entries, "invalid index stage")
            entries[path] = (mode, sha)
    return entries


def verify_git(root, env, manifest, snapshot):
    # Compare the *entire* metadata namespace before invoking Git. Do not let
    # a modified config, hook, alternate, index, ref or object redirect Git.
    actual_meta = git_metadata_snapshot(root, snapshot["git_metadata"])
    require(actual_meta == snapshot["git_metadata"], "Git metadata drift")
    expected = {r["path"]: (r["mode"], r["sha"]) for r in manifest["allowed"]}
    require(projection_index(root, env) == expected, "projection index mismatch")
    require(git_call(root, env, "rev-parse", "HEAD").decode().strip() == snapshot["commit"], "projection HEAD drift")
    require(git_call(root, env, "rev-parse", "HEAD^{tree}").decode().strip() == snapshot["tree"], "projection tree drift")
    require(not git_call(root, env, "remote").strip(), "remote forbidden")
    # All excluded OIDs must remain absent, without lazy fetch.
    excluded = manifest["excluded_oids"]
    if excluded:
        output = git_call(root, env, "cat-file", "--batch-check=%(objectname) %(objecttype)",
                          data=("\n".join(excluded) + "\n").encode()).decode().splitlines()
        require(output == [sha + " missing" for sha in excluded], "excluded object present")
    # The same native Git listing used by the pinned ansible-test GitSource.
    coll = root / COLLECTION
    listed = git_call(coll, env, "ls-files", "--cached", "--others", "--exclude-standard", "-z")
    deleted = git_call(coll, env, "ls-files", "--deleted", "-z")
    subset = {p[len(COLLECTION) + 1:] for p in expected if p.startswith(COLLECTION + "/")}
    require(set(listed.decode().split("\0")) - {""} == subset and not deleted,
            "Collection source provider listing mismatch")
    return subset


def materialize(api, manifest, root, scratch, env, helper_bytes):
    """Called only after inline metadata preflight and helper hash verification."""
    require(api.approved == {r["sha"]: r["size"] for r in manifest["allowed"]}, "manifest authorization drift")
    helper_oid = next(r["sha"] for r in manifest["allowed"] if r["path"] == HELPER)
    require(git_hash("blob", helper_bytes) == helper_oid and api.fetched == {helper_oid}, "helper bootstrap mismatch")
    objects = {helper_oid: helper_bytes}
    for sha in sorted(api.approved):
        if sha != helper_oid:
            objects[sha] = api.blob(sha)
    require(api.fetched == set(api.approved), "incomplete acquisition")
    require(set(p.name for p in root.iterdir()) == {".git"}, "workspace changed during acquisition")
    for row in manifest["allowed"]:
        path = root / row["path"]
        # Every parent is created/checked before an exclusive non-following write.
        for parent in reversed(path.parents):
            if parent == root or root in parent.parents:
                if not os.path.lexists(parent):
                    parent.mkdir(mode=0o700)
                directory(parent)
        write_regular(path, objects[row["sha"]], int(row["mode"], 8) & 0o777)
    verify_files(root, manifest)
    # Write raw objects and exact index entries: no git add/filter/ignore behavior.
    for sha, data in objects.items():
        require(git_call(root, env, "hash-object", "-w", "--stdin", data=data).decode().strip() == sha,
                "projection object hash mismatch")
    index_data = b"".join(f"{r['mode']} {r['sha']}\t{r['path']}\0".encode() for r in manifest["allowed"])
    git_call(root, env, "update-index", "-z", "--index-info", data=index_data)
    tree = git_call(root, env, "write-tree").decode().strip()
    commit_env = {**env, "GIT_AUTHOR_NAME": "PQC synthetic projection", "GIT_AUTHOR_EMAIL": "ci@example.invalid",
                  "GIT_COMMITTER_NAME": "PQC synthetic projection", "GIT_COMMITTER_EMAIL": "ci@example.invalid",
                  "GIT_AUTHOR_DATE": "2000-01-01T00:00:00Z", "GIT_COMMITTER_DATE": "2000-01-01T00:00:00Z"}
    commit = git_call(root, commit_env, "commit-tree", tree, data=b"Synthetic source-only projection\n").decode().strip()
    git_call(root, env, "update-ref", "refs/heads/projection", commit)
    snapshot = {"tree": tree, "commit": commit, "git_metadata": git_metadata_snapshot(root)}
    verify_git(root, env, manifest, snapshot)
    write_regular(scratch / "manifest.json", canonical(manifest))
    write_regular(scratch / "projection.json", canonical(snapshot))
    write_regular(scratch / "guard.py", helper_bytes)
    print(f"repository={REPO_ID} event={manifest['event']} tested={manifest['tested']} "
          f"base={manifest['base']} head={manifest['head']} native_tree={manifest['tree']}")
    print(f"manifest_sha256={hashlib.sha256(canonical(manifest)).hexdigest()} "
          f"projection_tree={tree} synthetic_commit={commit} "
          f"sources={len(manifest['allowed'])} unique_blobs={len(objects)} requests={api.requests}")


def locale_works(env, name):
    probe = """import codecs, locale, sys
try:
    locale.setlocale(locale.LC_ALL, '')
    enc = locale.getlocale()[1]
    valid = bool(enc) and codecs.lookup(enc).name == 'utf-8' and codecs.lookup(sys.getfilesystemencoding()).name == 'utf-8'
except (locale.Error, LookupError):
    valid = False
raise SystemExit(0 if valid else 1)
"""
    result = subprocess.run([sys.executable, "-I", "-B", "-X", "utf8=0", "-c", probe],
                            env={**env, "LC_ALL": name, "LANG": name}, capture_output=True, timeout=20)
    require(result.returncode in {0, 1}, "locale probe failed")
    return result.returncode == 0


def select_locale(env):
    preferred = ("C.UTF-8", "C.utf8")
    for name in preferred:
        if locale_works(env, name):
            return name
    exe = shutil.which("locale", path=env["PATH"])
    if exe:
        result = subprocess.run([exe, "-a"], env=env, capture_output=True, encoding="ascii", timeout=20)
        require(result.returncode == 0, "locale enumeration failed")
        for name in sorted(set(result.stdout.splitlines()) - set(preferred)):
            if re.fullmatch(r"[A-Za-z0-9_.@-]+", name) and locale_works(env, name):
                return name
    raise BoundaryError("BLOCKED: no usable UTF-8 locale")


def verify_junit(path):
    import xml.etree.ElementTree as ET
    # pytest xunit1/xunit2 use direct suites/cases; allow ordinary properties
    # and captured output, not arbitrary XML or status markers.
    raw = read_regular(Path(path))
    # pytest produces UTF-8 XML. Reject other encodings and entity declarations.
    try:
        text = raw.decode("utf-8")
    except UnicodeError as exc:
        raise BoundaryError("invalid JUnit UTF-8") from exc
    require(len(raw) <= MAX_TOTAL and "\0" not in text and "<!DOCTYPE" not in text.upper() and "<!ENTITY" not in text.upper(),
            "invalid or oversized JUnit XML")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise BoundaryError("invalid JUnit XML") from exc
    require(root.tag in {"testsuite", "testsuites"}, "invalid JUnit root")
    suites = [root] if root.tag == "testsuite" else list(root)
    require(suites and all(s.tag == "testsuite" for s in suites), "invalid suite placement")
    total = 0
    def count(node, key):
        value = node.get(key)
        require(isinstance(value, str) and re.fullmatch(r"[0-9]{1,9}", value), "invalid JUnit count")
        return int(value)
    def decorations(node, permitted):
        require(not (node.text or "").strip() and all(not (child.tail or "").strip() for child in node),
                "invalid JUnit structural text")
        require(all(child.tag in permitted for child in node), "invalid JUnit child")
        for child in node:
            if child.tag == "properties":
                require(all(p.tag == "property" and not list(p) for p in child), "invalid JUnit properties")
            elif child.tag in {"system-out", "system-err"}:
                require(not list(child), "invalid JUnit output")
    for suite in suites:
        decorations(suite, {"testcase", "properties", "system-out", "system-err"})
        cases = suite.findall("testcase")
        require(count(suite, "tests") == len(cases) and all(count(suite, k) == 0 for k in
                ("failures", "errors", "skipped")), "suite counts or status invalid")
        for case in cases:
            require(bool(case.get("name")), "unnamed testcase")
            decorations(case, {"properties", "system-out", "system-err"})
        total += len(cases)
    if root.tag == "testsuites":
        require(not (root.text or "").strip() and all(not (child.tail or "").strip() for child in root),
                "invalid JUnit root text")
        for key, expected in (("tests", total), ("failures", 0), ("errors", 0), ("skipped", 0)):
            if key in root.attrib:
                require(count(root, key) == expected, "aggregate count mismatch")
    require(total > 0, "empty JUnit report")
    print(f"JUnit verified: {total} cases passed, no failures/errors/skips")
    return total


# Only this exact ansible-test output area may appear after the sanity command.
# Source is never allowed there. Validate types/names without following or reading
# unexpected content; move the validated output out before the final strict guard.
SANITY_OUTPUT = COLLECTION + "/tests/output"
SANITY_DIRS = {"bot", "coverage", "data", "junit", "logs", "reports", ".tmp"}


def isolate_sanity_output(root, scratch):
    output = root / SANITY_OUTPUT
    if not os.path.lexists(output):
        return
    directory(output)
    count = total_size = 0
    for parent, dirs, files in os.walk(output, followlinks=False):
        directory(Path(parent))
        for name in dirs + files:
            path = Path(parent) / name
            relative = path.relative_to(output)
            require(relative.parts[0] in SANITY_DIRS, "unexpected sanity result category")
            safe_path(str(relative))
            st = path.lstat()
            count += 1
            require(count <= 10000 and (stat.S_ISDIR(st.st_mode) or
                    (stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_size <= MAX_TOTAL)),
                    "unsafe sanity result entry")
            if stat.S_ISREG(st.st_mode):
                total_size += st.st_size
                require(total_size <= MAX_TOTAL and not (st.st_mode & 0o111) and
                        path.suffix.lower() in {".xml", ".json", ".txt", ".log", ".out", ".err"},
                        "unexpected sanity result type, mode or size")
    dest = scratch / "sanity-results"
    require(not os.path.lexists(dest), "sanity result destination exists")
    output.rename(dest)


def load_state(root, scratch):
    directory(root)
    directory(scratch)
    manifest_bytes = read_regular(scratch / "manifest.json")
    snapshot_bytes = read_regular(scratch / "projection.json")
    require(hashlib.sha256(manifest_bytes).hexdigest() == os.environ["CI_MANIFEST_SHA256"] and
            hashlib.sha256(snapshot_bytes).hexdigest() == os.environ["CI_PROJECTION_SHA256"], "checkpoint identity drift")
    manifest, snapshot = unique_json(manifest_bytes), unique_json(snapshot_bytes)
    require(manifest["repo"] == REPO and manifest["repo_id"] == REPO_ID and
            manifest["tested"] == os.environ["GITHUB_SHA"], "manifest identity drift")
    env = isolated_env(scratch, os.environ.get("PATH"))
    return manifest, snapshot, env


def guarded_run(root, scratch, label, cwd, command, junit=None, sanity=False):
    """On an isolation failure, latch a fail-closed stop for every later step."""
    marker = scratch / "boundary-failed"
    try:
        require(not os.path.lexists(marker), "previous data boundary failure")
        manifest, snapshot, git_env = load_state(root, scratch)
        verify_files(root, manifest)
        subset = verify_git(root, git_env, manifest, snapshot)
        env = {**git_env, "LC_ALL": select_locale(git_env)}
        env["LANG"] = env["LC_ALL"]
        env.update({"PIP_CONFIG_FILE": os.devnull, "PIP_DISABLE_PIP_VERSION_CHECK": "1",
                    "PIP_NO_CACHE_DIR": "1", "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
                    "ANSIBLE_CONFIG": str(root / "ansible.cfg"),
                    "ANSIBLE_INVENTORY": str(scratch / "inventory.ini"),
                    "ANSIBLE_COLLECTIONS_PATH": f"{root}:{scratch / 'collections'}",
                    "ANSIBLE_COLLECTIONS_SCAN_SYS_PATH": "False",
                    "ANSIBLE_COLLECTIONS_ON_ANSIBLE_VERSION_MISMATCH": "error",
                    "ANSIBLE_ROLES_PATH": str(root / "roles"),
                    "ANSIBLE_LIBRARY": str(root / "plugins/modules"),
                    "ANSIBLE_LOCAL_TEMP": str(scratch / "ansible-tmp"),
                    "ANSIBLE_HOME": str(scratch / "ansible-home"),
                    "ANSIBLE_LINT_CACHE_DIR": str(scratch / "lint-cache"),
                    "CI_ROOT": str(scratch), "CI_COLLECTION": COLLECTION,
                    "CI_COLLECTIONS": str(scratch / "collections"),
                    "SYNTHETIC_INVENTORY": str(scratch / "inventory.ini")})
        for name in ("CI_CORE", "CI_PYTHON", "CI_PYTHON_MINOR", "CI_PYTEST", "CI_LINT", "CI_REQUIREMENTS"):
            env[name] = os.environ[name]
        directory(cwd)
        require(cwd in {root, root / COLLECTION, scratch}, "unexpected command cwd")
        if sanity:
            # Exercise the installed pinned provider/layout before Docker.
            # No tarball/repository download; only the local provider's listing.
            probe = """import json
from ansible_test._internal.data import data_context
ctx = data_context()
print(json.dumps({'provider': type(ctx.source_provider).__name__, 'paths': sorted(ctx.content.all_files()), 'layouts': sorted(x.root for x in ctx.create_collection_layouts()), 'root': ctx.content.root}))
"""
            result = subprocess.run([sys.executable, "-B", "-c", probe], cwd=cwd, env=env,
                                    capture_output=True, timeout=60)
            require(result.returncode == 0, "installed ansible-test provider probe failed")
            actual = unique_json(result.stdout)
            require(actual["provider"] == "GitSource" and actual["root"] == str(cwd) and
                    actual["layouts"] == [str(cwd)] and set(actual["paths"]) == subset,
                    "installed ansible-test payload source mismatch")
            print(f"ansible-test provider/payload source subset verified: {len(subset)} files")
            verify_files(root, manifest)
            verify_git(root, git_env, manifest, snapshot)
        proc = subprocess.run(command, cwd=cwd, env=env)
        print(f"{label}: command rc={proc.returncode}", flush=True)
        if sanity:
            isolate_sanity_output(root, scratch)
        verify_files(root, manifest)
        verify_git(root, git_env, manifest, snapshot)
    except (BoundaryError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        if not os.path.lexists(marker):
            write_regular(marker, b"boundary failed\n")
        raise BoundaryError("data boundary blocked: " + (str(exc) if isinstance(exc, BoundaryError) else type(exc).__name__)) from exc
    if proc.returncode:
        return proc.returncode if proc.returncode > 0 else 1
    if junit:
        require(junit.parent == scratch and junit.name in {"bootstrap.xml", "collection-unit.xml"},
                "unexpected JUnit destination")
        verify_junit(junit)
    return 0


def install_dependencies():
    from importlib.metadata import version
    import platform
    root = Path.cwd()
    scratch = Path(os.environ["CI_ROOT"])
    pins = {"ansible-core": os.environ["CI_CORE"], "pytest": os.environ["CI_PYTEST"]}
    if os.environ["CI_LINT"]:
        pins["ansible-lint"] = os.environ["CI_LINT"]
    require(platform.python_version() == os.environ["CI_PYTHON"], "wrong Python version")
    packages = [f"{name}=={pin}" for name, pin in pins.items()]
    pip = [sys.executable, "-m", "pip"]
    subprocess.run(pip + ["install", "--index-url", "https://pypi.org/simple", *packages], check=True)
    subprocess.run(pip + ["check"], check=True)
    subprocess.run(pip + ["freeze"], check=True)
    deps = scratch / "collections"
    manifest_path = Path(os.environ["CI_REQUIREMENTS"])
    require(manifest_path in {root / "collections/requirements-ci-legacy.yml", root / "collections/requirements-ci.yml"},
            "unexpected dependency manifest")
    subprocess.run(["ansible-galaxy", "collection", "install", "-r", str(manifest_path), "-p", str(deps),
                    "--server", "https://galaxy.ansible.com/"], check=True)
    # Import only after installing pinned packages, in a fresh interpreter.
    subprocess.run([sys.executable, "-I", "-B", __file__, "installed"], check=True)


def verify_installed():
    from importlib.metadata import version
    import platform
    from packaging.specifiers import SpecifierSet
    import yaml
    from ansible import constants as C
    root = Path.cwd()
    deps = Path(os.environ["CI_COLLECTIONS"])
    pins = {"ansible-core": os.environ["CI_CORE"], "pytest": os.environ["CI_PYTEST"]}
    if os.environ["CI_LINT"]:
        pins["ansible-lint"] = os.environ["CI_LINT"]
    require(platform.python_version() == os.environ["CI_PYTHON"], "wrong Python")
    for name, pin in pins.items():
        require(version(name) == pin, f"wrong version: {name}")
    requirements = yaml.safe_load(Path(os.environ["CI_REQUIREMENTS"]).read_text())["collections"]
    expected = {r["name"]: r["version"] for r in requirements}
    installed = {}
    for manifest in (deps / "ansible_collections").glob("*/*/MANIFEST.json"):
        info = json.loads(manifest.read_text())["collection_info"]
        name = info["namespace"] + "." + info["name"]
        require(name not in installed, "duplicate collection")
        installed[name] = info["version"]
        runtime = yaml.safe_load((manifest.parent / "meta/runtime.yml").read_text())
        require(pins["ansible-core"] in SpecifierSet(runtime["requires_ansible"]), f"incompatible collection: {name}")
        print(f"Galaxy: {name} {info['version']} dependencies={info.get('dependencies', {})}")
    require(installed == expected, "installed collections differ from CI pins")
    require(C.COLLECTIONS_PATHS == [str(root), str(deps)] and not C.COLLECTIONS_SCAN_SYS_PATH,
            "wrong collection search path")
    require(C.DEFAULT_ROLES_PATH == [str(root / "roles")] and C.DEFAULT_MODULE_PATH == [str(root / "plugins/modules")],
            "wrong role or module path")
    require(C.DEFAULT_HOST_LIST == [os.environ["SYNTHETIC_INVENTORY"]], "wrong inventory")
    text = subprocess.check_output(["ansible", "--version"], text=True)
    require(f"config file = {root / 'ansible.cfg'}" in text, "wrong config file")
    print(text.strip())
    collection = "security.compliance_pqc_readiness"
    files = subprocess.check_output(["ansible-doc", "-t", "module", "-F", collection], text=True)
    found = dict(line.split(None, 1) for line in files.splitlines() if line.strip())
    for module in ("normalize_pqc", "generate_cbom"):
        expected_path = root / COLLECTION / "plugins/modules" / (module + ".py")
        require(Path(found.get(collection + "." + module, "")).resolve() == expected_path,
                "candidate module loader mismatch")
    print("candidate config, inventory and collection loader verified")


def ansible_controls():
    root = Path(os.environ["CI_ROOT"]) / "oracle"
    root.mkdir(mode=0o700)
    good, bad = root / "good.yml", root / "bad.yml"
    good.write_text("---\n- name: Synthetic play\n  hosts: pqc_targets\n  gather_facts: false\n"
                    "  tasks:\n    - name: Display synthetic text\n      ansible.builtin.debug:\n        msg: synthetic\n")
    bad.write_text("---\n- hosts: [\n")
    cmd = ["ansible-playbook", "-i", os.environ["SYNTHETIC_INVENTORY"], "--syntax-check"]
    subprocess.run(cmd + [str(good)], check=True, cwd=root)
    rc = subprocess.run(cmd + [str(bad)], cwd=root).returncode
    require(rc > 0, "invalid YAML did not produce a normal nonzero exit")
    print(f"synthetic invalid YAML: syntax rc={rc}")
    if os.environ["CI_LINT"]:
        unnamed = root / "unnamed.yml"
        unnamed.write_text("---\n- hosts: pqc_targets\n  gather_facts: false\n"
                           "  tasks:\n    - ansible.builtin.debug:\n        msg: synthetic\n")
        subprocess.run(["ansible-lint", "--offline", str(good)], check=True, cwd=root)
        result = subprocess.run(["ansible-lint", "--offline", str(unnamed)], cwd=root,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        print(result.stdout)
        require(result.returncode > 0 and "name[" in result.stdout, "expected lint naming violation not observed")
        print(f"synthetic naming violation: lint rc={result.returncode}")


def sanity_command():
    subprocess.run(["docker", "version", "--format", "{{.Server.Version}}"], check=True)
    subprocess.run(["ansible-test", "sanity", "--docker", "--python", os.environ["CI_PYTHON_MINOR"], "plugins/"], check=True)


def cli():
    import argparse
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="action", required=True)
    for action in ("install", "installed", "controls", "sanity"):
        sub.add_parser(action)
    junit = sub.add_parser("junit")
    junit.add_argument("path", type=Path)
    for name in ("verify", "locale", "run"):
        p = sub.add_parser(name)
        p.add_argument("--root", required=True, type=Path)
        p.add_argument("--scratch", required=True, type=Path)
        if name == "run":
            p.add_argument("--label", required=True)
            p.add_argument("--cwd", choices=("root", "collection", "scratch"), default="root")
            p.add_argument("--junit", type=Path)
            p.add_argument("--sanity", action="store_true")
            p.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.action in {"install", "installed", "controls", "sanity"}:
        {"install": install_dependencies, "installed": verify_installed,
         "controls": ansible_controls, "sanity": sanity_command}[args.action]()
    elif args.action == "junit":
        verify_junit(args.path)
    else:
        root, scratch = args.root, args.scratch
        if args.action == "run":
            command = args.command[1:] if args.command[:1] == ["--"] else args.command
            require(command, "missing command")
            cwd = {"root": root, "collection": root / COLLECTION, "scratch": scratch}[args.cwd]
            return guarded_run(root, scratch, args.label, cwd, command, args.junit, args.sanity)
        manifest, snapshot, env = load_state(root, scratch)
        require(not os.path.lexists(scratch / "boundary-failed"), "previous data boundary failure")
        verify_files(root, manifest)
        verify_git(root, env, manifest, snapshot)
        if args.action == "locale":
            print(select_locale(env))
        else:
            print("verified source projection and Git metadata")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(cli())
    except subprocess.CalledProcessError as exc:
        print(f"required command failed: rc={exc.returncode}", file=sys.stderr)
        raise SystemExit(exc.returncode if exc.returncode > 0 else 1)
    except (BoundaryError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print(str(exc) if isinstance(exc, BoundaryError) else type(exc).__name__, file=sys.stderr)
        raise SystemExit(1)
