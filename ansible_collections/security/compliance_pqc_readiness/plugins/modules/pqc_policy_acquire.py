"""Private fixed Crypto Policy acquisition stages (I1b CP1).

Acquisition only: no target authorization, policy change, runtime-consumption
claim, or public scan dispatch. The trusted native caller owns the scope.
"""
import hashlib
import json
import os
import posixpath
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
import zipimport
from contextlib import contextmanager

from ansible.module_utils.basic import AnsibleModule

STAGES = ('reader', 'show-bin', 'show-sbin')
STAGE_SECONDS = 30
INNER_SECONDS = 23
PAYLOAD_BYTES = 64 * 1024
RECEIPT_BYTES = 66 * 1024
WRAPPER_BYTES = 128 * 1024
ROOT_DIRECTORY = '/'
_TRUSTED_UID = 0
_MODULE_NAMES = ('ansible.legacy.pqc_policy_acquire', 'ansible.modules.pqc_policy_acquire',
                 'ansible_collections.security.compliance_pqc_readiness.plugins.modules.pqc_policy_acquire')
_CHILD = ('import importlib,sys; sys.path.insert(0,sys.argv[1]); '
          'importlib.import_module(sys.argv[2])._child(sys.argv[3])')
_REASONS = {
    'COMMAND_OK', 'INVALID_COMMAND_CONTRACT', 'PROCESS_CONTROL_UNAVAILABLE',
    'COMMAND_START_FAILED', 'COMMAND_FAILED', 'COMMAND_TIMEOUT', 'COMMAND_OUTPUT_LIMIT',
    'COMMAND_IO_FAILED', 'RESIDUAL_PROCESS', 'INTERRUPTED', 'REMOTE_CLEANUP_UNCONFIRMED',
}

# BEGIN SHARED POLICY GRAMMAR (also embedded in the fixed acquisition helper)
FILE_LIMIT = 16 * 1024
TOTAL_LIMIT = 64 * 1024
MAX_VALUES = 64
MAX_ENTRIES = 32
BACKENDS = ("openssh", "opensshserver", "openssl", "opensslcnf")
SCOPES = ("profile-config", "profile-show", "kernel-fips", "current-policy",
          *("backend-" + k for k in BACKENDS), "local-overrides")
PROFILE = re.compile(r"[A-Z0-9][A-Z0-9_-]{0,31}(?::[A-Z0-9][A-Z0-9_-]{0,31}){0,3}", re.ASCII)
TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,95}", re.ASCII)
# '+' can be an operator. Never interpret cipher aliases, globbing or exclusions.
POLICY_FIELDS = {"cipher": "cipher", "group": "group", "sign": "sign",
                 "key_exchange": "key-exchange", "protocol": "protocol"}
SSH_FIELDS = {"ciphers": "ciphers", "kexalgorithms": "kex-algorithms",
              "hostkeyalgorithms": "host-key-algorithms", "pubkeyacceptedalgorithms": "pubkey-accepted-algorithms"}
SSL_FIELDS = {"cipherstring": "cipher-string", "ciphersuites": "cipher-suites",
              "minprotocol": "min-protocol"}
PROTOCOLS = frozenset(("TLSv1", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3", "DTLSv1", "DTLSv1.2"))


def result(state, reason, values=(), *, rc=None, overrides=()):
    return dict(state=state, reason=reason, rc=rc, values=list(values), overrides=list(overrides))


def fields_for(scope):
    if scope == "current-policy":
        return frozenset(POLICY_FIELDS.values())
    if scope in ("backend-openssh", "backend-opensshserver"):
        return frozenset(SSH_FIELDS.values())
    if scope in ("backend-openssl", "backend-opensslcnf"):
        return frozenset(SSL_FIELDS.values())
    return frozenset()


def valid_token(field, value):
    if type(value) is not str or not TOKEN.fullmatch(value):
        return False
    if field == "min-protocol":
        return value in PROTOCOLS
    if field == "cipher-suites":
        return re.fullmatch(r"TLS_[A-Z0-9_]+", value, re.ASCII) is not None
    if field == "cipher-string":
        # Only explicit suite spellings, not OpenSSL selector expressions.
        return re.fullmatch(r"(?:TLS_[A-Z0-9_]+|[A-Z0-9]+(?:-[A-Z0-9]+){2,})", value, re.ASCII) is not None
    return True


def parse_source(scope, raw, *, rc=None):
    """Parse a single bounded fixed source; never return raw text or paths."""
    if scope not in SCOPES[:-1] or type(raw) is not bytes:
        return result("ERROR", "MALFORMED_OUTPUT", rc=rc)
    if len(raw) > FILE_LIMIT:
        return result("ERROR", "OUTPUT_LIMIT", rc=rc)
    if scope == "profile-show" and (type(rc) is not int or rc != 0):
        return result("ERROR", "COMMAND_FAILED", rc=rc)
    if scope != "profile-show" and rc is not None:
        return result("ERROR", "MALFORMED_OUTPUT")
    try:
        text = raw.decode("ascii")
    except UnicodeError:
        return result("UNKNOWN", "UNSUPPORTED_SYNTAX", rc=rc)
    if any(ord(c) < 32 and c not in "\n\t" or ord(c) == 127 for c in text):
        return result("UNKNOWN", "UNSUPPORTED_SYNTAX", rc=rc)
    if scope in ("profile-config", "profile-show"):
        # Only a single exact token, optionally terminated by one LF.
        if scope == "profile-config":
            lines = [line.strip(" \t") for line in text.split("\n")
                     if line.strip(" \t") and not line.lstrip(" \t").startswith("#")]
            token = lines[0] if len(lines) == 1 else ""
        else:
            token = text.removesuffix("\n")
        if PROFILE.fullmatch(token):
            return result("COLLECTED", "OK", [["profile", token]], rc=rc)
        return result("UNKNOWN", "AMBIGUOUS_PROFILE", rc=rc)
    if scope == "kernel-fips":
        if text in ("0", "0\n", "1", "1\n"):
            return result("COLLECTED", "OK", [["fips-enabled", text[0] == "1"]])
        return result("UNKNOWN", "AMBIGUOUS_FIPS")
    # A field is usable only as an entire literal statement. An unsupported or
    # contradictory occurrence invalidates that field, not unrelated fields.
    known, blocked, gap = {}, set(), False
    for line in text.split("\n"):
        line = line.strip(" \t")
        if not line or line.startswith(("#", ";")):
            continue
        if scope == "current-policy":
            key, sep, body = line.partition("=")
            field = POLICY_FIELDS.get(key.strip(" \t"))
            tokens = body.split() if sep else []
        elif scope in ("backend-openssh", "backend-opensshserver"):
            match = re.fullmatch(r"([A-Za-z]+)[ \t]+(.+)", line)
            field = SSH_FIELDS.get(match[1].lower()) if match else SSH_FIELDS.get(line.lower())
            tokens = match[2].split(",") if match else []
        else:
            key, sep, body = line.partition("=")
            field = SSL_FIELDS.get(key.strip(" \t").lower())
            tokens = body.strip(" \t").split(":") if sep else []
        if field is None:
            gap = True
            continue
        if (not tokens or len(tokens) > MAX_VALUES or any(not valid_token(field, v) for v in tokens)
                or len(set(tokens)) != len(tokens) or field in blocked
                or (field == "min-protocol" and len(tokens) != 1)
                or (field in known and known[field] != tokens)):
            known.pop(field, None)
            blocked.add(field)
            gap = True
            continue
        known[field] = tokens
    values = [[field, v] for field in sorted(known) for v in known[field]]
    if len(values) > MAX_VALUES:
        return result("UNKNOWN", "VALUE_LIMIT")
    if not values:
        return result("UNKNOWN", "UNSUPPORTED_SYNTAX" if gap else "NO_DATA")
    return result("PARTIAL" if gap else "COLLECTED", "INCOMPLETE_SYNTAX" if gap else "OK", values)
# END SHARED POLICY GRAMMAR


_STATE_REASONS = {
    "COLLECTED": {"OK"},
    "PARTIAL": {"INCOMPLETE_SYNTAX", "INCOMPLETE_OVERRIDES", "PROFILE_CONFLICT"},
    "UNKNOWN": {"SOURCE_ABSENT", "UNSAFE_SOURCE", "UNSUPPORTED_SYNTAX", "AMBIGUOUS_PROFILE",
                "AMBIGUOUS_FIPS", "NO_DATA", "VALUE_LIMIT", "TOOL_UNAVAILABLE", "PLATFORM_UNKNOWN"},
    "ERROR": {"COMMAND_FAILED", "MALFORMED_OUTPUT", "OUTPUT_LIMIT", "TOTAL_LIMIT", "ENTRY_LIMIT",
              "TIMEOUT", "CLEANUP_FAILED", "SOURCE_CHANGED", "READ_ERROR"},
    "PERMISSION_DENIED": {"PERMISSION_DENIED"},
    "NOT_SCANNED": {"DISABLED_BY_USER", "DISABLED_BY_PROFILE", "NOT_ATTEMPTED", "ADAPTER_NOT_AVAILABLE",
                    "PLATFORM_OUT_OF_SCOPE", "PLATFORM_UNKNOWN", "TIMEOUT_TOOL_UNAVAILABLE",
                    "SHOW_TOOL_UNAVAILABLE", "PROFILE_NOT_VALIDATED"},
}


def _require(ok, code="POLICY_INPUT"):
    if not ok:
        raise ValueError(code)


def _record(value, keys):
    _require(type(value) is dict and value.keys() == set(keys))


def _validate_slot(scope, row, *, nested=False):
    _record(row, ("state", "reason", "rc", "values", "overrides"))
    state, reason, rc, values, overrides = (row[k] for k in ("state", "reason", "rc", "values", "overrides"))
    _require(type(state) is str and state in _STATE_REASONS and type(reason) is str and reason in _STATE_REASONS[state])
    _require(rc is None or (type(rc) is int and -255 <= rc <= 255))
    _require(scope == "profile-show" or rc is None or
             (state in ("ERROR", "UNKNOWN", "PERMISSION_DENIED") and not nested))
    if scope == "profile-show":
        _require(state not in ("COLLECTED", "PARTIAL") or rc == 0)
        _require(rc in (None, 0) or state in ("ERROR", "PERMISSION_DENIED", "UNKNOWN"))
        _require(state != "NOT_SCANNED" or rc is None)
    _require(type(values) is list and len(values) <= MAX_VALUES and type(overrides) is list and len(overrides) <= MAX_ENTRIES)
    _require(bool(values) == (state in ("COLLECTED", "PARTIAL")))
    if state == "PARTIAL":
        _require(reason == ("INCOMPLETE_OVERRIDES" if scope == "local-overrides" else "INCOMPLETE_SYNTAX")
                 and (scope == "local-overrides" or bool(fields_for(scope))))
    _require(state != "NOT_SCANNED" or rc is None)
    _require(scope == "local-overrides" or not overrides)
    seen = set()
    for pair in values:
        _require(type(pair) is list and len(pair) == 2 and type(pair[0]) is str)
        field, value = pair
        if scope in ("profile-config", "profile-show"):
            _require(field == "profile" and type(value) is str and PROFILE.fullmatch(value) and len(values) == 1)
        elif scope == "kernel-fips":
            _require(field == "fips-enabled" and type(value) is bool and len(values) == 1)
        elif scope == "local-overrides":
            _require(field == "entry-count" and type(value) is int and 0 <= value <= MAX_ENTRIES and len(values) == 1)
        else:
            _require(field in fields_for(scope) and valid_token(field, value))
        _require((field, value) not in seen, "DUPLICATE_POLICY_VALUE")
        seen.add((field, value))
    _require(sum(1 for field, _ in values if field == "min-protocol") <= 1)
    if scope == "local-overrides":
        _require(not overrides or values and len(overrides) <= values[0][1])
        ids = set()
        total = 0
        for item in overrides:
            _record(item, ("override_id", "backend", "result"))
            oid, backend = item["override_id"], item["backend"]
            _require(type(oid) is str and re.fullmatch(r"ov-[0-9a-f]{64}", oid) and oid not in ids)
            _require(type(backend) is str and backend in BACKENDS)
            ids.add(oid)
            _validate_slot("backend-" + backend, item["result"], nested=True)
            _require(item["result"]["state"] != "NOT_SCANNED")
            total += len(item["result"]["values"])
        _require(total <= MAX_VALUES)
        if state == "COLLECTED":
            _require(len(overrides) == values[0][1] and all(o["result"]["state"] == "COLLECTED" for o in overrides))
    _require(not nested or not overrides)

FILE_SCOPES = tuple(s for s in SCOPES if s not in ("profile-show", "local-overrides"))
READER_SCOPES = (*FILE_SCOPES, 'local-overrides')
PATHS = {"profile-config": "/etc/crypto-policies/config",
         "current-policy": "/etc/crypto-policies/state/CURRENT.pol",
         "kernel-fips": "/proc/sys/crypto/fips_enabled",
         **{"backend-" + b: "/etc/crypto-policies/back-ends/" + b + ".config" for b in BACKENDS}}
LOCAL_DIR = "/etc/crypto-policies/local.d"
SHOW_PATHS = {"show-bin": "/usr/bin/update-crypto-policies", "show-sbin": "/usr/sbin/update-crypto-policies"}
LINK_PROFILES = ("DEFAULT", "FUTURE", "LEGACY", "FIPS")
OVERRIDE = re.compile(r"(opensshserver|openssh|opensslcnf|openssl)(?:-[A-Za-z0-9][A-Za-z0-9_.-]{0,63})?\.txt", re.ASCII)


class Fault(Exception):
    def __init__(self, state, reason):
        self.state, self.reason = state, reason
        super().__init__(reason)


def failure(exc):
    if isinstance(exc, Fault):
        return result(exc.state, exc.reason)
    if isinstance(exc, PermissionError):
        return result("PERMISSION_DENIED", "PERMISSION_DENIED")
    if isinstance(exc, FileNotFoundError):
        return result("UNKNOWN", "SOURCE_ABSENT")
    if isinstance(exc, OSError) and exc.errno in (20, 40):
        return result("UNKNOWN", "UNSAFE_SOURCE")
    return result("ERROR", "READ_ERROR")


def unsafe():
    raise Fault("UNKNOWN", "UNSAFE_SOURCE")


def trusted(st):
    return st.st_uid == _TRUSTED_UID and not st.st_mode & 0o022


def identity(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_size,
            st.st_mtime_ns, st.st_ctime_ns, st.st_nlink)


class Reader:
    """Fixed #16 sources, with pinned file and directory/link identity proof.

    root_fd is an internal descriptor, never an input to the native module.
    """
    def __init__(self, root_fd, deadline):
        self.root = root_fd
        self.deadline = deadline
        self.remaining = TOTAL_LIMIT
        if not trusted(os.fstat(root_fd)) or not stat.S_ISDIR(os.fstat(root_fd).st_mode):
            unsafe()

    def tick(self):
        if time.monotonic() >= self.deadline:
            raise Fault("ERROR", "TIMEOUT")

    def total_limit(self):
        raise Fault("ERROR", "TOTAL_LIMIT")

    @contextmanager
    def directory(self, path, *, listing=False, trail=None):
        parts = path.strip("/").split("/") if path != "/" else []
        if len(parts) > 12 or any(not p or p in (".", "..") for p in parts):
            unsafe()
        fd = os.dup(self.root)
        try:
            st = os.fstat(fd)
            if not stat.S_ISDIR(st.st_mode) or not trusted(st):
                unsafe()
            if trail is not None:
                trail.append(identity(st))
            for index, part in enumerate(parts):
                self.tick()
                flags = os.O_RDONLY if listing and index == len(parts) - 1 else os.O_PATH
                new = os.open(part, flags | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                os.close(fd)
                fd = new
                st = os.fstat(fd)
                if not stat.S_ISDIR(st.st_mode) or not trusted(st):
                    unsafe()
                if trail is not None:
                    trail.append(identity(st))
            yield fd
        finally:
            os.close(fd)

    def link_target(self, path, target, allowed):
        if not target.isascii() or not 0 < len(target) <= 512:
            unsafe()
        parts = target.split("/")
        if target.startswith("/"):
            parts = parts[1:]
        else:
            while parts and parts[0] == "..":
                parts.pop(0)
        if any(p in ("", ".", "..") for p in parts):
            unsafe()
        resolved = posixpath.normpath(posixpath.join(posixpath.dirname(path), target))
        if resolved not in allowed:
            unsafe()
        return resolved

    @contextmanager
    def pinned(self, path, allowed, *, local_fd=None):
        seen, trail = set(), []
        for _ in range(5):
            self.tick()
            if path in seen or path not in allowed:
                unsafe()
            seen.add(path)
            parent, name = posixpath.split(path)
            if local_fd is None:
                with self.directory(parent, trail=trail) as fd:
                    entry = os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            else:
                trail.append(identity(os.fstat(local_fd)))
                entry = os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=local_fd)
            try:
                st = os.fstat(entry)
                trail.append((path, identity(st)))
                if stat.S_ISLNK(st.st_mode):
                    if local_fd is not None or len(allowed) == 1 or st.st_uid != _TRUSTED_UID or st.st_nlink != 1:
                        unsafe()
                    target = os.readlink("", dir_fd=entry)
                    trail.append(target)
                    path = self.link_target(path, target, allowed)
                    continue
                if not stat.S_ISREG(st.st_mode) or not trusted(st) or st.st_nlink != 1:
                    unsafe()
                yield entry, st, tuple(trail)
                return
            finally:
                os.close(entry)
        unsafe()

    def recheck(self, path, allowed, trail, *, local_fd=None):
        try:
            with self.pinned(path, allowed, local_fd=local_fd) as (_, _, current):
                if current != trail:
                    raise Fault("ERROR", "SOURCE_CHANGED")
        except (Fault, OSError) as exc:
            if isinstance(exc, Fault) and exc.reason == 'TIMEOUT':
                raise
            raise Fault("ERROR", "SOURCE_CHANGED") from None

    def read(self, path, allowed, *, local_fd=None):
        self.tick()
        with self.pinned(path, allowed, local_fd=local_fd) as (pinned, st, trail):
            if st.st_size > FILE_LIMIT:
                raise Fault("ERROR", "OUTPUT_LIMIT")
            if st.st_size > self.remaining:
                self.total_limit()
            # Only open a previously validated regular file, not a FIFO/device.
            fd = os.open("/proc/self/fd/" + str(pinned), os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
            try:
                if identity(os.fstat(fd)) != identity(st):
                    raise Fault("ERROR", "SOURCE_CHANGED")
                data = bytearray()
                while True:
                    self.tick()
                    room = min(FILE_LIMIT - len(data), self.remaining)
                    if room <= 0:
                        if st.st_size > 0 and st.st_size == len(data) and path != PATHS["kernel-fips"]:
                            break
                        if self.remaining == 0:
                            self.total_limit()
                        raise Fault("ERROR", "OUTPUT_LIMIT")
                    part = os.read(fd, min(4096, room))
                    self.remaining -= len(part)
                    if not part:
                        break
                    data.extend(part)
                self.tick()
                if identity(os.fstat(fd)) != identity(st):
                    raise Fault("ERROR", "SOURCE_CHANGED")
                self.recheck(path, allowed, trail, local_fd=local_fd)
                return bytes(data)
            finally:
                os.close(fd)

    def slot(self, scope):
        path = PATHS[scope]
        allowed = {path}
        if scope.startswith("backend-"):
            name = posixpath.basename(path)
            allowed.update("/usr/share/crypto-policies/" + profile + "/" + name for profile in LINK_PROFILES)
        try:
            return parse_source(scope, self.read(path, allowed))
        except (Fault, OSError) as exc:
            if isinstance(exc, Fault) and exc.reason in ('TOTAL_LIMIT', 'TIMEOUT'):
                raise
            return failure(exc)

    def overrides(self):
        try:
            trail = []
            with self.directory(LOCAL_DIR, listing=True, trail=trail) as fd:
                before = os.fstat(fd)
                names = []
                with os.scandir(fd) as entries:
                    for entry in entries:
                        self.tick()
                        if len(names) == MAX_ENTRIES:
                            raise Fault("ERROR", "ENTRY_LIMIT")
                        names.append(entry.name)
                rows, gap, total = [], False, 0
                for name in sorted(names):
                    self.tick()
                    match = OVERRIDE.fullmatch(name)
                    if not match:
                        gap = True
                        continue
                    backend = match[1]
                    path = LOCAL_DIR + "/" + name
                    try:
                        row = parse_source("backend-" + backend, self.read(path, {path}, local_fd=fd))
                    except (Fault, OSError) as exc:
                        if isinstance(exc, Fault) and exc.reason in ('TOTAL_LIMIT', 'TIMEOUT'):
                            raise
                        row = failure(exc)
                    if total + len(row["values"]) > MAX_VALUES:
                        row = result("UNKNOWN", "VALUE_LIMIT")
                    total += len(row["values"])
                    gap |= row["state"] != "COLLECTED"
                    rows.append(dict(override_id="ov-" + hashlib.sha256(name.encode("ascii")).hexdigest(),
                                     backend=backend, result=row))
                self.tick()
                if identity(os.fstat(fd)) != identity(before):
                    raise Fault("ERROR", "SOURCE_CHANGED")
                after = []
                try:
                    with self.directory(LOCAL_DIR, listing=True, trail=after) as other:
                        if trail != after or identity(os.fstat(other)) != identity(before):
                            raise Fault("ERROR", "SOURCE_CHANGED")
                except OSError:
                    raise Fault("ERROR", "SOURCE_CHANGED") from None
                return result("PARTIAL" if gap else "COLLECTED", "INCOMPLETE_OVERRIDES" if gap else "OK",
                              [["entry-count", len(names)]], overrides=rows)
        except (Fault, OSError) as exc:
            if isinstance(exc, Fault) and exc.reason in ('TOTAL_LIMIT', 'TIMEOUT'):
                raise
            return failure(exc)

    def collect(self):
        rows = {scope: self.slot(scope) for scope in FILE_SCOPES}
        rows["local-overrides"] = self.overrides()
        return rows


def _capture_show(argv, deadline):
    """One fixed --show child; never detach from the outer owned PGID."""
    work_end = deadline - min(1.0, INNER_SECONDS / 2)
    proc = None
    buffers = [bytearray(), bytearray()]
    reason = None
    try:
        if time.monotonic() >= work_end:
            return result('ERROR', 'TIMEOUT')
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, shell=False, close_fds=True, cwd=ROOT_DIRECTORY,
                                env={'PATH': '/usr/bin:/usr/sbin:/bin', 'LC_ALL': 'C', 'LANG': 'C',
                                     'PYTHONDONTWRITEBYTECODE': '1'})
        with selectors.DefaultSelector() as sel:
            for i, pipe in enumerate((proc.stdout, proc.stderr)):
                sel.register(pipe, selectors.EVENT_READ, i)
            while sel.get_map() or proc.poll() is None:
                left = work_end - time.monotonic()
                if left <= 0:
                    reason = 'TIMEOUT'
                    break
                if not sel.get_map():
                    time.sleep(min(0.02, left))
                    continue
                for key, _ in sel.select(min(left, 0.05)):
                    room = FILE_LIMIT - sum(map(len, buffers))
                    data = os.read(key.fd, min(4096, room + 1))
                    if len(data) > room:
                        reason = 'OUTPUT_LIMIT'
                        break
                    if data:
                        buffers[key.data].extend(data)
                    else:
                        sel.unregister(key.fileobj)
                if reason:
                    break
            if reason is None and time.monotonic() >= work_end:
                reason = 'TIMEOUT'
    except PermissionError:
        if proc is None:
            return result('PERMISSION_DENIED', 'PERMISSION_DENIED')
        reason = 'COMMAND_FAILED'
    except FileNotFoundError:
        if proc is None:
            return result('UNKNOWN', 'TOOL_UNAVAILABLE')
        reason = 'COMMAND_FAILED'
    except Fault as exc:
        reason = exc.reason
    except (OSError, ValueError, subprocess.SubprocessError):
        reason = 'COMMAND_FAILED'
    finally:
        if proc is not None:
            try:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=max(0, deadline - time.monotonic()))
            except (OSError, subprocess.TimeoutExpired, Fault):
                reason = 'CLEANUP_FAILED'
            finally:
                proc.stdout.close()
                proc.stderr.close()
    if proc is None:
        return result('ERROR', reason or 'COMMAND_FAILED')
    rc = proc.returncode
    if rc is None:
        return result('ERROR', 'CLEANUP_FAILED')
    if reason:
        return result('ERROR', reason, rc=rc)
    if time.monotonic() >= deadline:
        return result('ERROR', 'TIMEOUT', rc=rc)
    if rc != 0:
        if rc == 126 and bytes(buffers[1]) in (b'Permission denied\n', b'Permission denied'):
            return result('PERMISSION_DENIED', 'PERMISSION_DENIED', rc=rc)
        return result('ERROR', 'COMMAND_FAILED', rc=rc)
    if buffers[1]:
        return result('UNKNOWN', 'AMBIGUOUS_PROFILE', rc=rc)
    return parse_source('profile-show', bytes(buffers[0]), rc=rc)


def _show(reader, stage):
    path = SHOW_PATHS[stage]
    try:
        with reader.pinned(path, {path}) as (fd, before, trail):
            real = os.path.join(ROOT_DIRECTORY, path.lstrip('/'))
            if not os.access('/proc/self/fd/' + str(fd), os.X_OK, effective_ids=True):
                return result('UNKNOWN', 'TOOL_UNAVAILABLE')
            reader.recheck(path, {path}, trail)
            if identity(os.lstat(real)) != identity(before):
                return result('ERROR', 'SOURCE_CHANGED')
            row = _capture_show([real, '--show'], reader.deadline)
            # Never turn an unconfirmed cleanup into an ordinary drift gap.
            if row['reason'] == 'CLEANUP_FAILED':
                return row
            try:
                reader.recheck(path, {path}, trail)
                if identity(os.lstat(real)) != identity(before):
                    raise Fault('ERROR', 'SOURCE_CHANGED')
            except (Fault, OSError):
                if row['reason'] == 'TIMEOUT':
                    return row
                return result('ERROR', 'SOURCE_CHANGED', rc=row['rc'])
            return row
    except FileNotFoundError:
        return result('UNKNOWN', 'TOOL_UNAVAILABLE')
    except (Fault, OSError) as exc:
        return failure(exc)


def _stage(stage):
    _require(type(stage) is str and stage in STAGES)
    return stage


def _scopes(stage):
    return READER_SCOPES if _stage(stage) == 'reader' else ('profile-show',)


def _gap(stage, row):
    return {scope: dict(row) for scope in _scopes(stage)}


def _timeout_fault(_signum, _frame):
    raise Fault('ERROR', 'TIMEOUT')


def _acquire(stage):
    _stage(stage)
    deadline = time.monotonic() + INNER_SECONDS
    signal.signal(signal.SIGALRM, _timeout_fault)
    signal.setitimer(signal.ITIMER_REAL, INNER_SECONDS)
    try:
        root = os.open(ROOT_DIRECTORY, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            reader = Reader(root, deadline)
            rows = reader.collect() if stage == 'reader' else {'profile-show': _show(reader, stage)}
            if stage == 'reader':
                reader.tick()
            return rows
        finally:
            os.close(root)
    except (Fault, OSError) as exc:
        return _gap(stage, failure(exc))
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


def _json_bytes(value):
    return json.dumps(value, ensure_ascii=True, separators=(',', ':'), sort_keys=True, allow_nan=False).encode('ascii')


def _decode(raw):
    def unique(pairs):
        value = dict(pairs)
        _require(len(value) == len(pairs))
        return value

    def reject(_):
        raise ValueError('INVALID_STAGE_RECEIPT')

    _require(type(raw) is bytes and len(raw) <= PAYLOAD_BYTES + 1 and raw.endswith(b'\n'))
    value = json.loads(raw.decode('ascii'), object_pairs_hook=unique, parse_constant=reject, parse_float=reject)
    _require(_json_bytes(value) + b'\n' == raw)
    return value


def _slot_payload(stage, payload):
    _record(payload, _scopes(stage))
    for scope in _scopes(stage):
        row = payload[scope]
        _validate_slot(scope, row)
        _require(row['state'] != 'NOT_SCANNED')
        if stage == 'reader':
            _require(row['rc'] is None)
            if scope == 'local-overrides':
                _require(all(o['result']['rc'] is None for o in row['overrides']))
        elif row['state'] == 'COLLECTED' or row['reason'] == 'AMBIGUOUS_PROFILE':
            _require(type(row['rc']) is int and row['rc'] == 0)
    if stage == 'reader' and any(row['reason'] == 'TOTAL_LIMIT' or
            any(o['result']['reason'] == 'TOTAL_LIMIT' for o in row['overrides']) for row in payload.values()):
        _require(payload == _gap(stage, result('ERROR', 'TOTAL_LIMIT')))


def _receipt(stage, reason, rc, clean, payload):
    return dict(format=1, stage=stage, reason_code=reason, rc=rc, cleanup_confirmed=clean, payload=payload)


def _fits(receipt):
    frame = dict(changed=False, receipt=receipt, invocation={'module_args': {'stage': receipt['stage']}})
    return len(_json_bytes(receipt)) <= RECEIPT_BYTES and len(json.dumps(frame, ensure_ascii=True)) + 1 <= WRAPPER_BYTES


def validate_receipt(receipt, stage):
    """Closed CP1 receipt, not host identity or permission to dispatch CP2."""
    _stage(stage)
    _record(receipt, ('format', 'stage', 'reason_code', 'rc', 'cleanup_confirmed', 'payload'))
    _require(type(receipt['format']) is int and receipt['format'] == 1 and receipt['stage'] == stage)
    reason, rc, clean, payload = (receipt[k] for k in ('reason_code', 'rc', 'cleanup_confirmed', 'payload'))
    _require(type(reason) is str and reason in _REASONS and (rc is None or type(rc) is int and -255 <= rc <= 255)
             and type(clean) is bool)
    _require(clean == (reason not in ('PROCESS_CONTROL_UNAVAILABLE', 'REMOTE_CLEANUP_UNCONFIRMED')))
    if reason == 'COMMAND_OK':
        _require(type(rc) is int and rc == 0 and clean)
        _slot_payload(stage, payload)
        _require(len(_json_bytes(payload)) <= PAYLOAD_BYTES)
    else:
        _require(payload is None)
        if reason in ('INVALID_COMMAND_CONTRACT', 'PROCESS_CONTROL_UNAVAILABLE', 'COMMAND_START_FAILED'):
            _require(rc is None)
        if reason == 'COMMAND_FAILED':
            _require(type(rc) is int and rc != 0)
        if reason in ('COMMAND_TIMEOUT', 'COMMAND_OUTPUT_LIMIT', 'COMMAND_IO_FAILED', 'RESIDUAL_PROCESS'):
            _require(type(rc) is int)
    _require(_fits(receipt))
    return receipt


def _payload_archive():
    spec = __spec__
    _require(spec is not None and spec.name in _MODULE_NAMES and isinstance(spec.loader, zipimport.zipimporter))
    archive = spec.loader.archive
    _require(os.path.isabs(archive) and spec.origin == archive + '/' + spec.name.replace('.', '/') + '.py')
    parent = os.lstat(os.path.dirname(archive))
    entry = os.lstat(archive)
    _require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid() and parent.st_mode & 0o077 == 0)
    _require(stat.S_ISREG(entry.st_mode) and entry.st_uid == os.geteuid() and entry.st_nlink == 1 and entry.st_mode & 0o022 == 0)
    return archive


def _bounded_runner(archive):
    if __spec__.name == _MODULE_NAMES[-1]:
        from ansible_collections.security.compliance_pqc_readiness.plugins.module_utils import pqc_bounded_execution as helper
    else:
        from ansible.module_utils import pqc_bounded_execution as helper
    loader = getattr(getattr(helper, '__spec__', None), 'loader', None)
    _require(isinstance(loader, zipimport.zipimporter) and loader.archive == archive)
    return helper.run_policy_bounded


def _child_argv(stage):
    archive = _payload_archive()
    _require(os.path.isabs(sys.executable))
    return [sys.executable, '-I', '-S', '-B', '-c', _CHILD, archive, __spec__.name, _stage(stage)]


def _from_result(stage, outcome):
    payload = None
    if outcome.reason_code == 'COMMAND_OK':
        _require(outcome.stderr == b'' and outcome.cleanup_confirmed is True)
        payload = _decode(outcome.stdout)
    else:
        _require(outcome.stdout == outcome.stderr == b'')
    return validate_receipt(_receipt(stage, outcome.reason_code, outcome.rc, outcome.cleanup_confirmed, payload), stage)


def _run_stage(stage):
    argv = _child_argv(stage)
    return _from_result(stage, _bounded_runner(argv[6])(argv, timeout_s=STAGE_SECONDS))


def _typed_payload(stage, payload):
    _slot_payload(stage, payload)
    if len(_json_bytes(payload)) > PAYLOAD_BYTES or not _fits(_receipt(stage, 'COMMAND_OK', 0, True, payload)):
        row = result('ERROR', 'TOTAL_LIMIT') if stage == 'reader' else result('ERROR', 'OUTPUT_LIMIT', rc=payload['profile-show']['rc'])
        payload = _gap(stage, row)
    validate_receipt(_receipt(stage, 'COMMAND_OK', 0, True, payload), stage)
    return payload


def _child(stage):
    _stage(stage)
    _payload_archive()
    _require(sys.platform == 'linux' and sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode)
    raw = _json_bytes(_typed_payload(stage, _acquire(stage))) + b'\n'
    _require(len(raw) <= PAYLOAD_BYTES + 1)
    sys.stdout.buffer.write(raw)


def main():
    module = AnsibleModule(argument_spec={'stage': dict(type='str', required=True, choices=list(STAGES))},
                           supports_check_mode=True, no_log=True)
    try:
        receipt = _run_stage(_stage(module.params['stage']))
    except (ImportError, OSError, ValueError, TypeError, AttributeError, KeyError, RecursionError):
        module.fail_json(changed=False, msg='POLICY_STAGE_CONTRACT_FAILED')
    module.exit_json(changed=False, receipt=receipt)


if __name__ == '__main__':
    main()
