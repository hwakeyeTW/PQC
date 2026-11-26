"""Fixed, passive native certificate acquisition (Cert S1, #57).

The Reader, framing and metadata parser are ported from the reviewed #18
cert_assets.yml helper. Only the dedicated isolated acquisition child uses
these functions. The caller still owns authorization and platform eligibility.
"""
import base64
import ctypes
import hashlib
import json
import os
import posixpath as path
import re
import selectors
import signal
import stat
import subprocess
import sys
import threading
import time
import zipimport
from contextlib import contextmanager
from datetime import datetime

from ansible.module_utils.basic import AnsibleModule

ROOTS = {"system-tls-certs": "/etc/pki/tls/certs",
         "system-ca-anchors": "/etc/pki/ca-trust/source/anchors",
         "system-ssl-certs": "/etc/ssl/certs"}
BUNDLES = {"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
           "/etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt"}
MAX_ENTRIES, MAX_SOURCES, MAX_BLOCKS = 512, 128, 256
MAX_FILE, MAX_INPUT, MAX_DER = 1048576, 8388608, 65536
MAX_OUTPUT, MAX_PROJECTION = 16384, 192 * 1024
METADATA_BUDGET = 128 * 1024
WORK_SECONDS, ALARM_SECONDS, STAGE_SECONDS = 23, 25, 29
PARSE_SECONDS, CLEANUP_SECONDS = 3.5, 1.0
ROOT_DIRECTORY = '/'
_TRUSTED_UID = 0
_SYSTEM_PYTHON = '/usr/bin/python3'
_OPENSSL = '/usr/bin/openssl'
_cleanup_uncertain = False
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}\Z")
TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+@-]{0,127}\Z")
CERT_FIELDS = ("fingerprint", "public_key_algorithm", "public_key_bits", "signature_inner",
               "signature_outer", "issuer", "subject", "not_before", "not_after", "gaps")
BEGIN, END = b"-----BEGIN CERTIFICATE-----", b"-----END CERTIFICATE-----"


class Fault(Exception):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


def fail(reason):
    raise Fault(reason)


def reason(exc):
    if isinstance(exc, Fault):
        return exc.reason
    if isinstance(exc, PermissionError):
        return "PERMISSION_DENIED"
    if isinstance(exc, FileNotFoundError):
        return "SOURCE_ABSENT"
    return "UNSAFE_SOURCE" if isinstance(exc, OSError) and exc.errno in (20, 40) else "READ_ERROR"


def trusted(st):
    return st.st_uid == _TRUSTED_UID and not st.st_mode & 0o022


def identity(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_size,
            st.st_mtime_ns, st.st_ctime_ns, st.st_nlink)


def safe_name(name):
    return (bool(NAME.fullmatch(name)) and ".key." not in name.lower()
            and name.lower() not in ("private", "private-keys", "private_keys", "privatekey", "private_key", "keys", "key", "secrets"))


def candidate(name):
    return name.lower().endswith((".pem", ".crt", ".cer", ".der"))


def allowed_file(p):
    if p in BUNDLES:
        return True
    for root in ROOTS.values():
        if p.startswith(root + "/"):
            parts = p[len(root) + 1:].split("/")
            if 1 <= len(parts) <= 4 and all(safe_name(x) for x in parts) and candidate(parts[-1]):
                return True
    return False


def source_id(p):
    return "src-" + hashlib.sha256(p.encode("ascii")).hexdigest()


def target_path(p, target):
    if not target.isascii() or not 0 < len(target) <= 512:
        fail("UNSAFE_SOURCE")
    parts = target.split("/")
    if target.startswith("/"):
        parts = parts[1:]
    else:
        while parts and parts[0] == "..":
            parts.pop(0)
    # Do not collapse arbitrary intermediate symlink/.. pairs.
    if not parts or any(not safe_name(x) for x in parts):
        fail("UNSAFE_SOURCE")
    return path.normpath(path.join(path.dirname(p), target))


def empty(attempted=True, gap=None, rc=0):
    return dict(attempted=attempted, rc=rc, entries=0, directories=0, skipped=0, root_target_id=None,
                gaps=[gap] if gap else [], sources=[])


def block_error(reason, rc=None):
    return dict(rc=rc, reason=reason, certificate=None)


def tlv(read, offset, end):
    # Only definite, minimally encoded, low-tag-length framing. Never decode
    # private key values. OpenSSL owns actual X.509/ASN.1 semantic parsing.
    if offset + 2 > end:
        fail("INVALID_DER")
    head = read(offset, 2)
    if len(head) != 2 or head[0] & 31 == 31:
        fail("INVALID_DER")
    tag, size = head
    start = offset + 2
    if size & 128:
        n = size & 127
        if not 1 <= n <= 3 or start + n > end:
            fail("INVALID_DER")
        raw = read(start, n)
        size = int.from_bytes(raw, "big")
        if len(raw) != n or raw[0] == 0 or size < 128:
            fail("INVALID_DER")
        start += n
    if start + size > end:
        fail("INVALID_DER")
    return tag, start, start + size


def expect(read, offset, end, tag):
    t, a, b = tlv(read, offset, end)
    if t != tag:
        fail("INVALID_DER")
    return a, b


def algorithm_envelope(read, start, end):
    a, b = expect(read, start, end, 6)
    if a == b:
        fail("INVALID_DER")
    if b < end:
        _, _, b = tlv(read, b, end)
    if b != end:
        fail("INVALID_DER")


def certificate_envelope(read, size):
    if not 0 < size <= MAX_DER:
        fail("LIMIT_REACHED")
    a, end = expect(read, 0, size, 48)
    if end != size:
        fail("INVALID_DER")
    tbs, tbs_end = expect(read, a, end, 48)
    alg, alg_end = expect(read, tbs_end, end, 48)
    algorithm_envelope(read, alg, alg_end)
    bit, bit_end = expect(read, alg_end, end, 3)
    if bit_end != end or bit_end - bit < 2:
        fail("INVALID_DER")
    if tbs >= tbs_end:
        fail("INVALID_DER")
    if read(tbs, 1) == b"\xa0":
        v, tbs = expect(read, tbs, tbs_end, 160)
        _, v_end = expect(read, v, tbs, 2)
        if v_end != tbs:
            fail("INVALID_DER")
    serial, pos = expect(read, tbs, tbs_end, 2)
    if serial == pos:
        fail("INVALID_DER")
    inner, pos = expect(read, pos, tbs_end, 48)
    algorithm_envelope(read, inner, pos)
    for _ in range(3):  # issuer, validity, subject
        _, pos = expect(read, pos, tbs_end, 48)
    spki, pos = expect(read, pos, tbs_end, 48)
    a, b = expect(read, spki, pos, 48)
    algorithm_envelope(read, a, b)
    a, b = expect(read, b, pos, 3)
    if b != pos or b - a < 2:
        fail("INVALID_DER")
    previous = 0
    while pos < tbs_end:
        tag, _, pos = tlv(read, pos, tbs_end)
        if tag not in (129, 130, 163) or tag <= previous:
            fail("INVALID_DER")
        previous = tag


class ToolFailure(Exception):
    """Closed fixed-tool failure; never returned as a successful snapshot."""


def _trusted_executable(filename, *, alias):
    # The installed interpreter alias may be a symlink; openssl must not be.
    try:
        for parent in ('/', '/usr', '/usr/bin'):
            st = os.stat(parent, follow_symlinks=False)
            if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
                return False
        link = os.lstat(filename)
        if link.st_uid != 0 or (not alias and not stat.S_ISREG(link.st_mode)):
            return False
        if not stat.S_ISLNK(link.st_mode) and link.st_mode & 0o022:
            return False
        st = os.stat(filename)
        return (stat.S_ISREG(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022
                and bool(st.st_mode & 0o111) and os.access(filename, os.X_OK))
    except OSError:
        return False


def _process_control():
    if (sys.platform != 'linux' or threading.current_thread() is not threading.main_thread()
            or threading.active_count() != 1 or os.getpid() != os.getpgrp()):
        return False
    libc = ctypes.CDLL(None, use_errno=True)
    return libc.prctl(36, 1, 0, 0, 0) == 0


def _adopted_children():
    # Linux's per-thread child list, not a traversal of unrelated processes.
    # This dedicated single-threaded subreaper owns all listed child PIDs.
    with open('/proc/self/task/%d/children' % os.getpid(), 'rb') as stream:
        raw = stream.read(16385)
    if len(raw) > 16384:
        fail('CLEANUP_FAILED')
    children = [int(token) for token in raw.split()]
    if any(pid <= 1 or pid == os.getpid() for pid in children):
        fail('CLEANUP_FAILED')
    return children


def reap(proc, terminate):
    """Bounded direct/adopted-child reaping, never signal our own group.

    The trusted installed x509 command must remain in our outer group. A
    residual child is a fatal contract failure even if subsequently reaped.
    ECHILD after the direct child is reaped confirms no adopted children.
    The unchanged outer runner separately confirms group absence.
    """
    end = time.monotonic() + CLEANUP_SECONDS
    residual = False
    group_term_sent = False
    try:
        while time.monotonic() < end:
            if proc.poll() is None:
                if terminate:
                    proc.kill()
                time.sleep(min(0.01, max(0, end - time.monotonic())))
                continue
            try:
                pid, _ = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                return not residual
            residual = True
            if pid:
                continue
            try:
                children = _adopted_children()
            except (Fault, OSError, ValueError):
                # The optional Linux children file is not available in every
                # kernel/runtime. No scan of unrelated /proc entries. With
                # our own TERM blocked during cleanup, signal only our
                # dedicated group once, then continue bounded waitpid/reap.
                # A stubborn child remains fatal and the outer runner KILLs
                # the same group. The pending self-TERM cannot yield success:
                # residue is sticky fatal before the signal is sent.
                global _cleanup_uncertain
                _cleanup_uncertain = True
                if not group_term_sent:
                    if (os.getpid() != os.getpgrp() or
                            signal.SIGTERM not in signal.pthread_sigmask(signal.SIG_BLOCK, set())):
                        return False
                    os.killpg(os.getpgrp(), signal.SIGTERM)
                    group_term_sent = True
                children = []
            for child in children:
                try:
                    # No PID is reaped by another thread or signal handler.
                    if os.getpgid(child) != os.getpgrp():
                        return False
                    os.kill(child, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            time.sleep(min(0.01, max(0, end - time.monotonic())))
    except (Fault, OSError, ValueError):
        pass
    return False


def capture(argv, data, deadline):
    # Private test seam; production parse() always selects fixed x509 argv.
    # Bounded simultaneous stdin/stdout/stderr, direct and same-group cleanup.
    libc = ctypes.CDLL(None, use_errno=True)
    global _cleanup_uncertain
    if _cleanup_uncertain or not _process_control():
        _cleanup_uncertain = True
        return None, None, "CLEANUP_FAILED"
    parent = os.getpid()
    blocked = {signal.SIGTERM, signal.SIGINT, signal.SIGALRM}
    mask = signal.pthread_sigmask(signal.SIG_BLOCK, blocked)
    proc, error, clean = None, None, False
    buffers = [bytearray(), bytearray()]
    sent = 0
    def child_setup():
        if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent:
            os._exit(126)
        signal.pthread_sigmask(signal.SIG_SETMASK, mask)
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=False, preexec_fn=child_setup, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C",
            "LANG": "C", "OPENSSL_CONF": "/dev/null", "HOME": "/nonexistent"})
        signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        with selectors.DefaultSelector() as sel:
            for i, pipe in enumerate((proc.stdout, proc.stderr)):
                os.set_blocking(pipe.fileno(), False)
                sel.register(pipe, selectors.EVENT_READ, i)
            os.set_blocking(proc.stdin.fileno(), False)
            if data:
                sel.register(proc.stdin, selectors.EVENT_WRITE, 2)
            else:
                proc.stdin.close()
            while sel.get_map():
                left = deadline - time.monotonic()
                if left <= 0:
                    fail("TIMEOUT")
                for key, _ in sel.select(left):
                    if key.data == 2:
                        try:
                            sent += os.write(key.fd, data[sent:sent + 4096])
                        except BrokenPipeError:
                            fail("COMMAND_FAILED")
                        except BlockingIOError:
                            continue
                        if sent == len(data):
                            sel.unregister(key.fileobj)
                            proc.stdin.close()
                    else:
                        room = MAX_OUTPUT - sum(map(len, buffers))
                        try:
                            chunk = os.read(key.fd, min(4096, room + 1))
                        except BlockingIOError:
                            continue
                        if len(chunk) > room:
                            fail("OUTPUT_LIMIT")
                        if chunk:
                            buffers[key.data].extend(chunk)
                        else:
                            sel.unregister(key.fileobj)
            try:
                proc.wait(timeout=max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                fail("TIMEOUT")
        if time.monotonic() > deadline:
            fail("TIMEOUT")
    except Fault as exc:
        error = exc.reason
    except FileNotFoundError:
        raise ToolFailure()
    except PermissionError:
        error = "PERMISSION_DENIED"
    except (OSError, ValueError, subprocess.SubprocessError):
        error = "COMMAND_FAILED"
    finally:
        signal.pthread_sigmask(signal.SIG_BLOCK, blocked)
        try:
            if proc is not None:
                clean = reap(proc, error is not None)
                if not clean:
                    _cleanup_uncertain = True
                for pipe in (proc.stdin, proc.stdout, proc.stderr):
                    pipe.close()
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)
    rc = proc.returncode if proc is not None else None
    if proc is not None and not clean:
        return rc, None, "CLEANUP_FAILED"
    if error or rc != 0 or sent != len(data):
        return rc, None, ("AMBIGUOUS_OUTPUT" if rc == 0 and error not in ("TIMEOUT", "OUTPUT_LIMIT") else error or "COMMAND_FAILED")
    if buffers[1]:
        return rc, None, "AMBIGUOUS_OUTPUT"
    return rc, bytes(buffers[0]), None


def safe_dn(value):
    return (type(value) is str and 0 < len(value) <= 512 and value.isascii() and all(32 <= ord(c) < 127 for c in value)
            and not any(s in value.upper() for s in ("{" * 2, "{" + "%", "{" + "#", "-----BEGIN", "PRIVATE KEY"))
            and re.search(r"\\(?:0[0-9a-fA-F]|1[0-9a-fA-F]|7[fF])", value) is None)


def metadata_gaps(cert):
    gaps = [k.upper() + "_UNKNOWN" for k in CERT_FIELDS[1:-1] if cert[k] is None]
    if cert["signature_inner"] is not None and cert["signature_outer"] is not None:
        if cert["signature_inner"] != cert["signature_outer"]:
            gaps.append("SIGNATURE_CONFLICT")
    if cert["not_before"] and cert["not_after"] and cert["not_before"] > cert["not_after"]:
        gaps.append("VALIDITY_CONFLICT")
    return sorted(gaps)


def parse(der, deadline):
    try:
        certificate_envelope(lambda p, n: der[p:p + n], len(der))
    except Fault as exc:
        return block_error(exc.reason)
    if not _trusted_executable(_OPENSSL, alias=False):
        raise ToolFailure()
    argv = [_OPENSSL, "x509", "-inform", "DER", "-noout", "-sha256", "-fingerprint",
            "-subject", "-issuer", "-dates", "-nameopt", "RFC2253", "-text"]
    rc, raw, error = capture(argv, der, min(deadline, time.monotonic() + PARSE_SECONDS))
    if error:
        return block_error(error, rc)
    try:
        text = raw.decode("ascii")
    except UnicodeError:
        return block_error("AMBIGUOUS_OUTPUT", rc)
    summary, sep, body = text.partition("\nCertificate:\n")
    if not sep or not body.startswith("    Data:\n"):
        return block_error("AMBIGUOUS_OUTPUT", rc)
    prefix, sep, spki = body.partition("        Subject Public Key Info:\n")
    if not sep:
        return block_error("AMBIGUOUS_OUTPUT", rc)
    def unique(pattern, segment=summary):
        matches = re.findall(pattern, segment, re.MULTILINE)
        return matches[0] if len(matches) == 1 else None
    fingerprint = unique(r"^(?:SHA256|sha256) Fingerprint=([0-9A-F]{2}(?::[0-9A-F]{2}){31})$")
    if fingerprint is None:
        return block_error("AMBIGUOUS_OUTPUT", rc)
    fp = fingerprint.replace(":", "").lower()
    if fp != hashlib.sha256(der).hexdigest():
        return block_error("FINGERPRINT_MISMATCH", rc)
    def token(pattern, segment):
        value = unique(pattern, segment)
        return value if value and TOKEN.fullmatch(value) else None
    def dn(label):
        value = unique(r"^" + label + r"=([^\r\n]*)$")
        return value if value and safe_dn(value) else None
    def stamp(label):
        value = unique(r"^" + label + r"=([A-Z][a-z]{2} +[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2} [0-9]{4} GMT)$")
        try:
            if value:
                dt = datetime.strptime(value, "%b %d %H:%M:%S %Y GMT")
                return dt.isoformat(timespec="seconds") + "Z"
            return None
        except ValueError:
            return None
    key_header = "\n".join(spki.split("\n", 2)[:2])
    bits = unique(r"^ {16}Public-Key: \(([1-9][0-9]{0,6}) bit\)$", key_header)
    bits = int(bits) if bits and int(bits) <= 1048576 else None
    cert = dict(fingerprint=fp, public_key_algorithm=token(r"^ {12}Public Key Algorithm: ([^\r\n]+)$", key_header),
                public_key_bits=bits, signature_inner=token(r"^ {8}Signature Algorithm: ([^\r\n]+)$", prefix),
                signature_outer=token(r"^ {4}Signature Algorithm: ([^\r\n]+)$", spki),
                issuer=dn("issuer"), subject=dn("subject"), not_before=stamp("notBefore"), not_after=stamp("notAfter"))
    cert["gaps"] = metadata_gaps(cert)
    return dict(rc=0, reason="METADATA_GAP" if cert["gaps"] else "OK", certificate=cert)


class Reader:
    # Tests may supply an already opened private synthetic root FD. main()
    # always opens '/' itself; no root/path/command arguments or fallback.
    def __init__(self, root, deadline):
        self.root, self.deadline = root, deadline
        self.entries = self.sources = self.blocks = self.bytes = self.file_bytes = self.projected = 0
        self.cache, self.target_seen = {}, {}
        self.cleanup_failed = False
        if not trusted(os.fstat(root)) or not stat.S_ISDIR(os.fstat(root).st_mode):
            fail("UNSAFE_SOURCE")

    def abort_cleanup(self):
        # Sticky fatal: descriptor unwinding must not mask cleanup failure.
        self.cleanup_failed = True
        fail("CLEANUP_FAILED")

    def acquisition_reason(self, exc):
        if self.cleanup_failed or reason(exc) == "CLEANUP_FAILED":
            self.abort_cleanup()
        return reason(exc)

    def parse_block(self, der):
        try:
            row = parse(der, self.deadline)
        except Fault as exc:
            if exc.reason == "CLEANUP_FAILED":
                self.abort_cleanup()
            raise
        if row["reason"] == "CLEANUP_FAILED":
            self.abort_cleanup()
        return row

    def tick(self):
        if self.cleanup_failed:
            self.abort_cleanup()
        if time.monotonic() >= self.deadline:
            fail("TIMEOUT")

    @contextmanager
    def directory(self, p, listing=False):
        parts = p.strip("/").split("/") if p != "/" else []
        if len(parts) > 12 or any(not safe_name(x) for x in parts):
            fail("UNSAFE_SOURCE")
        fd = os.dup(self.root)
        try:
            for i, part in enumerate(parts):
                self.tick()
                flags = os.O_RDONLY if listing and i == len(parts) - 1 else os.O_PATH
                new = os.open(part, flags | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                os.close(fd)
                fd = new
                if not trusted(os.fstat(fd)):
                    fail("UNSAFE_SOURCE")
            yield fd
        finally:
            os.close(fd)

    @contextmanager
    def pin(self, p, root=False):
        seen = set()
        for _ in range(5):
            self.tick()
            if p in seen or (p not in ROOTS.values() if root else not allowed_file(p)):
                fail("UNSAFE_SOURCE")
            seen.add(p)
            with self.directory(path.dirname(p)) as fd:
                entry = os.open(path.basename(p), os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            try:
                st = os.fstat(entry)
                if stat.S_ISLNK(st.st_mode):
                    if st.st_uid != _TRUSTED_UID:
                        fail("UNSAFE_SOURCE")
                    p = target_path(p, os.readlink("", dir_fd=entry))
                    continue
                if not trusted(st) or (not stat.S_ISDIR(st.st_mode) if root else not stat.S_ISREG(st.st_mode) or st.st_nlink != 1):
                    fail("UNSAFE_SOURCE")
                yield entry, st, p
                return
            finally:
                os.close(entry)
        fail("UNSAFE_SOURCE")

    def read_at(self, fd, offset, size):
        self.tick()
        if size > MAX_INPUT - self.bytes or size > MAX_FILE - self.file_bytes:
            fail("LIMIT_REACHED")
        data = os.pread(fd, size, offset)
        self.bytes += len(data)
        self.file_bytes += len(data)
        if len(data) != size:
            fail("SOURCE_CHANGED")
        return data

    def lines(self, fd, size):
        buf = b""
        for off in range(0, size, 4096):
            buf += self.read_at(fd, off, min(4096, size - off))
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if len(line) > 8192:
                    fail("UNKNOWN_FORMAT")
                yield line.removesuffix(b"\r")
            if len(buf) > 8192:
                fail("UNKNOWN_FORMAT")
        if buf:
            yield buf

    def take_block(self):
        if self.blocks >= MAX_BLOCKS:
            fail("LIMIT_REACHED")
        self.blocks += 1

    def pem(self, fd, size, src):
        payload = None
        invalid = None
        for line in self.lines(fd, size):
            self.tick()
            if line == BEGIN:
                if payload is not None:
                    src["blocks"].append(block_error("INVALID_PEM"))
                payload = None
                self.take_block()
                payload, invalid = bytearray(), None
            elif line.startswith(b"-----BEGIN") or (line.startswith(b"-----END") and line != END):
                if payload is not None:
                    src["blocks"].append(block_error("INVALID_PEM"))
                    payload = None
                src["gaps"].append("UNSUPPORTED_TRUSTED_CERTIFICATE" if line == b"-----BEGIN TRUSTED CERTIFICATE-----" else "NON_PUBLIC_BLOCK")
                break  # Never decode or hash a non-certificate body.
            elif line == END:
                if payload is None:
                    src["gaps"].append("INVALID_PEM")
                    continue
                try:
                    if invalid or not payload:
                        fail(invalid or "INVALID_PEM")
                    der = base64.b64decode(payload, validate=True)
                    if base64.b64encode(der) != payload:
                        fail("INVALID_PEM")
                    row = self.parse_block(der)
                except Fault as exc:
                    if exc.reason == "CLEANUP_FAILED":
                        raise
                    row = block_error(exc.reason)
                except ValueError:
                    row = block_error("INVALID_PEM")
                src["blocks"].append(row)
                payload = None
            elif payload is not None:
                if len(payload) + len(line) > 4 * ((MAX_DER + 2) // 3):
                    invalid = "LIMIT_REACHED"
                elif not re.fullmatch(rb"[A-Za-z0-9+/=]+", line) and invalid is None:
                    invalid = "INVALID_PEM"
                if not invalid:
                    payload.extend(line)
            elif line.strip() and not line.startswith(b"#"):
                src["gaps"].append("UNKNOWN_FORMAT")
                break
        if payload is not None:
            src["blocks"].append(block_error("INVALID_PEM"))
        if not src["blocks"] and not src["gaps"]:
            src["gaps"].append("UNKNOWN_FORMAT")

    def read_source(self, p, original):
        src = dict(source_id=source_id(original), target_id=None, format="UNKNOWN", gaps=[], blocks=[])
        self.file_bytes = 0
        before_blocks = self.blocks
        try:
            with self.pin(p) as (pin, st, target):
                src["target_id"] = source_id(target)
                if st.st_size > MAX_FILE or st.st_size > MAX_INPUT - self.bytes:
                    fail("LIMIT_REACHED")
                key = (target, identity(st))
                if target in self.target_seen and self.target_seen[target] != key[1]:
                    fail("SOURCE_CHANGED")
                self.target_seen[target] = key[1]
                # Cache only normalized public metadata. Count every occurrence.
                if key in self.cache:
                    cached = self.cache[key]
                    if self.blocks + len(cached["blocks"]) > MAX_BLOCKS:
                        fail("LIMIT_REACHED")
                    self.blocks += len(cached["blocks"])
                    src.update(format=cached["format"], gaps=list(cached["gaps"]), blocks=list(cached["blocks"]))
                else:
                    fd = os.open("/proc/self/fd/" + str(pin), os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
                    try:
                        if identity(os.fstat(fd)) != identity(st):
                            fail("SOURCE_CHANGED")
                        if st.st_size and self.read_at(fd, 0, 1) == b"\x30":
                            src["format"] = "DER"
                            self.take_block()
                            try:
                                certificate_envelope(lambda p, n: self.read_at(fd, p, n), st.st_size)
                                row = self.parse_block(self.read_at(fd, 0, st.st_size))
                            except Fault as exc:
                                if exc.reason not in ("INVALID_DER", "LIMIT_REACHED"):
                                    raise
                                row = block_error(exc.reason)
                            src["blocks"].append(row)
                        else:
                            src["format"] = "PEM"
                            try:
                                self.pem(fd, st.st_size, src)
                            except Fault as exc:
                                if exc.reason not in ("LIMIT_REACHED", "UNKNOWN_FORMAT"):
                                    raise
                                src["gaps"].append(exc.reason)
                        if identity(os.fstat(fd)) != identity(st):
                            fail("SOURCE_CHANGED")
                    finally:
                        os.close(fd)
                with self.pin(p) as (_, after, target_after):
                    if target_after != target or identity(after) != identity(st):
                        fail("SOURCE_CHANGED")
                while len(src["blocks"]) < self.blocks - before_blocks:
                    src["blocks"].append(block_error("INVALID_PEM"))
                src["gaps"] = sorted(set(src["gaps"]))
                if any(b["reason"] == "CLEANUP_FAILED" for b in src["blocks"]):
                    self.abort_cleanup()
                # Cache only complete source traversal (no limit/timeout/invalid
                # read); no raw bytes, no digest of mixed or private content.
                if not src["gaps"] and all(b["certificate"] for b in src["blocks"]):
                    self.cache[key] = dict(format=src["format"], gaps=[], blocks=list(src["blocks"]))
        except (Fault, OSError) as exc:
            why = self.acquisition_reason(exc)
            # A read error or drift discards the entire source, not a stale winner.
            # Retain identified-block counts and actual rc, not rejected metadata.
            old = src["blocks"]
            src.update(gaps=[why], blocks=[block_error(why, old[i]["rc"] if i < len(old) else None)
                                           for i in range(self.blocks - before_blocks)])
        return src

    def walk(self, root, resolved, rel, row):
        p = path.join(resolved, *rel)
        with self.directory(p, listing=True) as fd:
            before = os.fstat(fd)
            names = []
            if self.entries >= MAX_ENTRIES:
                row["gaps"].append("LIMIT_REACHED")
                return
            with os.scandir(fd) as scan:
                for entry in scan:
                    self.tick()
                    self.entries += 1
                    row["entries"] += 1
                    names.append(entry.name)
                    if self.entries == MAX_ENTRIES:
                        row["gaps"].append("LIMIT_REACHED")
                        break
            for name in sorted(names):
                self.tick()
                if not safe_name(name):
                    row["skipped"] += 1
                    row["gaps"].append("UNSAFE_SOURCE")
                    continue
                try:
                    st = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    if stat.S_ISDIR(st.st_mode):
                        if len(rel) >= 3:
                            row["skipped"] += 1
                            row["gaps"].append("DEPTH_LIMIT")
                        else:
                            row["directories"] += 1
                            self.walk(root, resolved, (*rel, name), row)
                    elif candidate(name):
                        if self.sources >= MAX_SOURCES:
                            row["skipped"] += 1
                            row["gaps"].append("LIMIT_REACHED")
                            continue
                        self.sources += 1
                        src = self.read_source(path.join(p, name), path.join(root, *rel, name))
                        n = len(json.dumps(src, ensure_ascii=True, separators=(",", ":")))
                        if self.projected + n > METADATA_BUDGET:
                            src["gaps"] = sorted(set(src["gaps"]) | {"PROJECTION_LIMIT"})
                            src["blocks"] = [block_error("PROJECTION_LIMIT", b["rc"])
                                             if b["certificate"] is not None else b for b in src["blocks"]]
                        else:
                            self.projected += n
                        row["sources"].append(src)
                    else:
                        row["skipped"] += 1
                        if stat.S_ISLNK(st.st_mode):
                            row["gaps"].append("DIRECTORY_LINK")
                except (Fault, OSError) as exc:
                    why = self.acquisition_reason(exc)
                    if why in ("SOURCE_CHANGED", "TIMEOUT"):
                        raise
                    row["gaps"].append(why)
            if identity(os.fstat(fd)) != identity(before):
                fail("SOURCE_CHANGED")
            with self.directory(p) as after:
                if identity(os.fstat(after)) != identity(before):
                    fail("SOURCE_CHANGED")

    def collect(self):
        rows = {}
        for slot, root in ROOTS.items():
            row = empty()
            try:
                self.tick()
                with self.pin(root, root=True) as (_, st, resolved):
                    row["root_target_id"] = source_id(resolved)
                    self.walk(root, resolved, (), row)
                    with self.pin(root, root=True) as (_, after, target):
                        if target != resolved or identity(st) != identity(after):
                            fail("SOURCE_CHANGED")
            except (Fault, OSError) as exc:
                why = self.acquisition_reason(exc)
                if why == "SOURCE_CHANGED":
                    for src in row["sources"]:
                        src.update(gaps=[why], blocks=[block_error(why, b["rc"]) for b in src["blocks"]])
                    row["root_target_id"] = None
                row["gaps"].append(why)
            row["gaps"] = sorted(set(row["gaps"]))
            row["sources"].sort(key=lambda s: s["source_id"])
            rows[slot] = row
        return rows


# Closed remote validation, ported from tools/cert_assets.py (#18).
SHA = re.compile(r"[0-9a-f]{64}\Z")
SOURCE_ID = re.compile(r"src-[0-9a-f]{64}\Z")
STAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
SKIP = {"DISABLED_BY_USER", "DISABLED_BY_PROFILE", "NOT_ATTEMPTED", "PROFILE_NOT_VALIDATED",
        "PLATFORM_OUT_OF_SCOPE", "PLATFORM_UNKNOWN", "TOOL_UNAVAILABLE"}
GAPS = {"LIMIT_REACHED", "TIMEOUT", "READ_ERROR", "PERMISSION_DENIED", "UNSAFE_SOURCE",
        "SOURCE_CHANGED", "SOURCE_ABSENT", "DIRECTORY_LINK", "DEPTH_LIMIT", "NON_PUBLIC_BLOCK",
        "UNKNOWN_FORMAT", "INVALID_PEM", "UNSUPPORTED_TRUSTED_CERTIFICATE", "COMMAND_FAILED", "CLEANUP_FAILED", "PROJECTION_LIMIT"}
BLOCK_ERRORS = {"INVALID_PEM", "INVALID_DER", "LIMIT_REACHED", "COMMAND_FAILED", "TIMEOUT",
                "OUTPUT_LIMIT", "CLEANUP_FAILED", "FINGERPRINT_MISMATCH", "AMBIGUOUS_OUTPUT",
                "PERMISSION_DENIED", "TOOL_UNAVAILABLE", "SOURCE_CHANGED", "READ_ERROR", "UNSAFE_SOURCE",
                "SOURCE_ABSENT", "UNKNOWN_FORMAT", "PROJECTION_LIMIT"}
ROOT_TARGET_IDS = {source_id(p) for p in ROOTS.values()}


def require(ok, code="CERT_INPUT"):
    if not ok:
        raise ValueError(code)


def shape(value, keys):
    require(type(value) is dict and value.keys() == set(keys))


def integer(value, low, high):
    return type(value) is int and low <= value <= high


def match(pattern, value):
    return type(value) is str and pattern.fullmatch(value) is not None


def canonical(value):
    try:
        return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                          allow_nan=False).encode("ascii")
    except (ValueError, TypeError, RecursionError, OverflowError):
        raise ValueError("CERT_INPUT") from None


def valid_stamp(value):
    if not match(STAMP, value):
        return False
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
        return True
    except ValueError:
        return False


def validate_certificate(cert):
    shape(cert, CERT_FIELDS)
    require(match(SHA, cert["fingerprint"]))
    for k in ("public_key_algorithm", "signature_inner", "signature_outer"):
        require(cert[k] is None or match(TOKEN, cert[k]))
    require(cert["public_key_bits"] is None or integer(cert["public_key_bits"], 1, 1048576))
    for k in ("issuer", "subject"):
        require(cert[k] is None or safe_dn(cert[k]))
    for k in ("not_before", "not_after"):
        require(cert[k] is None or valid_stamp(cert[k]))
    require(cert["gaps"] == metadata_gaps(cert), "CERT_METADATA_GAPS")


def gap_list(value, allowed):
    require(type(value) is list and len(value) <= len(allowed))
    require(all(type(x) is str and x in allowed for x in value))
    require(value == sorted(set(value)))


def validate_snapshot(snapshot):
    shape(snapshot, ROOTS)
    # Validate closed shapes before canonical encoding; no arbitrary nested data.
    ids, fingerprints, target_blocks = set(), {}, {}
    entries = sources = blocks = 0
    for root in ROOTS:
        row = snapshot[root]
        shape(row, ("attempted", "rc", "entries", "directories", "skipped", "root_target_id", "gaps", "sources"))
        require(type(row["attempted"]) is bool and (row["rc"] is None or integer(row["rc"], -255, 255)))
        require(integer(row["entries"], 0, MAX_ENTRIES) and integer(row["skipped"], 0, row["entries"]) and integer(row["directories"], 0, row["entries"]))
        require(row["root_target_id"] is None or (match(SOURCE_ID, row["root_target_id"]) and row["root_target_id"] in ROOT_TARGET_IDS))
        entries += row["entries"]
        require(type(row["sources"]) is list and len(row["sources"]) <= MAX_SOURCES)
        sources += len(row["sources"])
        accounted = len(row["sources"]) + row["skipped"] + row["directories"]
        require(accounted <= row["entries"] and (row["gaps"] or accounted == row["entries"]))
        gap_list(row["gaps"], GAPS if row["attempted"] else SKIP)
        require("CLEANUP_FAILED" not in row["gaps"])
        if not row["attempted"]:
            require(row["root_target_id"] is None and row["rc"] is None and row["entries"] == row["skipped"] == row["directories"] == 0 and not row["sources"]
                    and len(row["gaps"]) == 1)
        elif row["rc"] != 0:
            require(row["root_target_id"] is None and not row["sources"] and row["entries"] == row["skipped"] == row["directories"] == 0
                    and row["gaps"] in (["COMMAND_FAILED"], ["TIMEOUT"], ["CLEANUP_FAILED"]))
        if row["attempted"] and row["rc"] == 0 and not row["gaps"]:
            require(row["root_target_id"] is not None)
        for src in row["sources"]:
            shape(src, ("source_id", "target_id", "format", "gaps", "blocks"))
            require(match(SOURCE_ID, src["source_id"]) and src["source_id"] not in ids)
            ids.add(src["source_id"])
            require(src["target_id"] is None or match(SOURCE_ID, src["target_id"]))
            require(src["format"] in ("PEM", "DER", "UNKNOWN"))
            gap_list(src["gaps"], GAPS)
            require("CLEANUP_FAILED" not in src["gaps"])
            require(type(src["blocks"]) is list and len(src["blocks"]) <= MAX_BLOCKS)
            blocks += len(src["blocks"])
            require(src["blocks"] or src["gaps"])
            require(src["format"] != "UNKNOWN" or not src["blocks"])
            require(src["format"] != "DER" or len(src["blocks"]) <= 1)
            for index, block in enumerate(src["blocks"], 1):
                shape(block, ("rc", "reason", "certificate"))
                rc, reason, cert = block["rc"], block["reason"], block["certificate"]
                require(rc is None or integer(rc, -255, 255))
                if cert is None:
                    require(type(reason) is str and reason in BLOCK_ERRORS and reason != "CLEANUP_FAILED")
                    require(rc != 0 or reason in ("FINGERPRINT_MISMATCH", "AMBIGUOUS_OUTPUT", "OUTPUT_LIMIT", "TIMEOUT", "CLEANUP_FAILED", "SOURCE_CHANGED", "READ_ERROR", "UNSAFE_SOURCE", "SOURCE_ABSENT", "PROJECTION_LIMIT", "UNKNOWN_FORMAT", "PERMISSION_DENIED", "LIMIT_REACHED"))
                else:
                    validate_certificate(cert)
                    require(rc == 0 and reason == ("METADATA_GAP" if cert["gaps"] else "OK"))
                    require(src["target_id"] is not None)
                    fp = cert["fingerprint"]
                    require(fp not in fingerprints or fingerprints[fp] == cert, "CERT_FINGERPRINT_CONFLICT")
                    fingerprints[fp] = cert
                    target_key = (src["target_id"], index)
                    require(target_key not in target_blocks or target_blocks[target_key] == fp, "CERT_TARGET_CONFLICT")
                    target_blocks[target_key] = fp
        require([s["source_id"] for s in row["sources"]] == sorted(s["source_id"] for s in row["sources"]))
    require(entries <= MAX_ENTRIES and sources <= MAX_SOURCES and blocks <= MAX_BLOCKS, "CERT_LIMIT")
    require(len(canonical(snapshot)) <= MAX_PROJECTION, "CERT_LIMIT")


STAGES = ('system',)
CHILD_BYTES = MAX_PROJECTION + 1
_MODULE_NAMES = ('ansible.legacy.pqc_cert_acquire', 'ansible.modules.pqc_cert_acquire',
                 'ansible_collections.security.compliance_pqc_readiness.plugins.modules.pqc_cert_acquire')
_CHILD = ('import importlib,sys; sys.path.insert(0,sys.argv[1]); '
          'importlib.import_module(sys.argv[2])._child(sys.argv[3])')
_REASONS = {
    'COMMAND_OK', 'TOOL_UNAVAILABLE', 'INVALID_COMMAND_CONTRACT', 'PROCESS_CONTROL_UNAVAILABLE',
    'COMMAND_START_FAILED', 'COMMAND_FAILED', 'COMMAND_TIMEOUT', 'COMMAND_OUTPUT_LIMIT',
    'COMMAND_IO_FAILED', 'RESIDUAL_PROCESS', 'INTERRUPTED', 'REMOTE_CLEANUP_UNCONFIRMED',
}


def _stage(stage):
    require(type(stage) is str and stage in STAGES)
    return stage


def _error_roots(reason):
    return {name: empty(gap=reason) for name in ROOTS}


def _python_unavailable():
    return dict(system_python_available=False,
                roots={name: empty(False, 'TOOL_UNAVAILABLE', None) for name in ROOTS})


def _validate_payload(payload, *, available=True):
    shape(payload, ('system_python_available', 'roots'))
    require(payload['system_python_available'] is available)
    validate_snapshot(payload['roots'])
    if available:
        require(all(row['attempted'] is True for row in payload['roots'].values()))
    else:
        require(payload == _python_unavailable())
    require(len(canonical(payload)) <= MAX_PROJECTION)


def _typed_payload(roots):
    payload = dict(system_python_available=True, roots=roots)
    if len(canonical(payload)) > MAX_PROJECTION:
        payload = dict(system_python_available=True, roots=_error_roots('PROJECTION_LIMIT'))
    _validate_payload(payload)
    return payload


def _decode(raw):
    def unique(pairs):
        value = dict(pairs)
        require(len(value) == len(pairs))
        return value

    def reject(_):
        raise ValueError('CERT_STAGE_CONTRACT_FAILED')

    def bounded_int(value):
        require(len(value) <= 8)
        return int(value)

    require(type(raw) is bytes and len(raw) <= CHILD_BYTES and raw.endswith(b'\n'))
    value = json.loads(raw.decode('ascii'), object_pairs_hook=unique, parse_constant=reject,
                       parse_float=reject, parse_int=bounded_int)
    _validate_payload(value)
    require(canonical(value) + b'\n' == raw)
    return value


def _receipt(stage, reason, rc, clean, payload):
    return dict(format=1, stage=stage, reason_code=reason, rc=rc, cleanup_confirmed=clean, payload=payload)


def _wrapper_size(receipt):
    frame = dict(changed=False, receipt=receipt, invocation={'module_args': {'stage': receipt['stage']}})
    return len(json.dumps(frame, ensure_ascii=True, allow_nan=False).encode('ascii')) + 2


RECEIPT_BYTES = MAX_PROJECTION + len(canonical(_receipt('system', 'COMMAND_OK', 0, True, None))) - 4
WRAPPER_BYTES = 2 * MAX_PROJECTION + _wrapper_size(_receipt('system', 'COMMAND_OK', 0, True, None)) - 4
assert (CHILD_BYTES, RECEIPT_BYTES, WRAPPER_BYTES) == (196609, 196707, 393411)


def validate_receipt(receipt, stage):
    _stage(stage)
    shape(receipt, ('format', 'stage', 'reason_code', 'rc', 'cleanup_confirmed', 'payload'))
    require(type(receipt['format']) is int and receipt['format'] == 1 and receipt['stage'] == stage)
    why, rc, clean, payload = (receipt[k] for k in ('reason_code', 'rc', 'cleanup_confirmed', 'payload'))
    require(type(why) is str and why in _REASONS and (rc is None or integer(rc, -255, 255)))
    require(type(clean) is bool and clean == (why not in ('PROCESS_CONTROL_UNAVAILABLE', 'REMOTE_CLEANUP_UNCONFIRMED')))
    if why == 'COMMAND_OK':
        require(type(rc) is int and rc == 0 and clean)
        _validate_payload(payload)
    elif why == 'TOOL_UNAVAILABLE':
        require(rc is None and clean)
        _validate_payload(payload, available=False)
    else:
        require(payload is None)
        if why in ('INVALID_COMMAND_CONTRACT', 'PROCESS_CONTROL_UNAVAILABLE', 'COMMAND_START_FAILED'):
            require(rc is None)
        if why == 'COMMAND_FAILED':
            require(type(rc) is int and rc != 0 and rc != 70)
        if why in ('COMMAND_TIMEOUT', 'COMMAND_OUTPUT_LIMIT', 'COMMAND_IO_FAILED', 'RESIDUAL_PROCESS'):
            require(type(rc) is int)
    require(len(canonical(receipt)) <= RECEIPT_BYTES and _wrapper_size(receipt) <= WRAPPER_BYTES)
    return receipt


def _payload_archive():
    spec = __spec__
    require(spec is not None and spec.name in _MODULE_NAMES and isinstance(spec.loader, zipimport.zipimporter))
    archive = spec.loader.archive
    require(os.path.isabs(archive) and spec.origin == archive + '/' + spec.name.replace('.', '/') + '.py')
    parent = os.lstat(os.path.dirname(archive))
    entry = os.lstat(archive)
    require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid() and parent.st_mode & 0o077 == 0)
    require(stat.S_ISREG(entry.st_mode) and entry.st_uid == os.geteuid() and entry.st_nlink == 1 and entry.st_mode & 0o022 == 0)
    return archive


def _bounded_runner(archive):
    if __spec__.name == _MODULE_NAMES[-1]:
        from ansible_collections.security.compliance_pqc_readiness.plugins.module_utils import pqc_bounded_execution as helper
    else:
        from ansible.module_utils import pqc_bounded_execution as helper
    loader = getattr(getattr(helper, '__spec__', None), 'loader', None)
    require(isinstance(loader, zipimport.zipimporter) and loader.archive == archive)
    return helper._run_bounded


def _child_argv(stage):
    archive = _payload_archive()
    return [_SYSTEM_PYTHON, '-I', '-S', '-B', '-c', _CHILD, archive, __spec__.name, _stage(stage)]


def _from_result(stage, outcome):
    payload = None
    why, rc, clean = outcome.reason_code, outcome.rc, outcome.cleanup_confirmed
    if why == 'COMMAND_OK':
        require(outcome.stderr == b'' and clean is True and rc == 0)
        payload = _decode(outcome.stdout)
    else:
        require(outcome.stdout == outcome.stderr == b'')
        if rc == 70:
            why, clean = 'REMOTE_CLEANUP_UNCONFIRMED', False
        elif why == 'COMMAND_FAILED' and rc == 124:
            why = 'COMMAND_TIMEOUT'
    return validate_receipt(_receipt(stage, why, rc, clean, payload), stage)


def _run_stage(stage):
    _stage(stage)
    argv = _child_argv(stage)
    if not _trusted_executable(_SYSTEM_PYTHON, alias=True):
        return validate_receipt(_receipt(stage, 'TOOL_UNAVAILABLE', None, True, _python_unavailable()), stage)
    if not _trusted_executable(_OPENSSL, alias=False):
        return validate_receipt(_receipt(stage, 'COMMAND_START_FAILED', None, True, None), stage)
    return _from_result(stage, _bounded_runner(argv[6])(argv, STAGE_SECONDS, CHILD_BYTES))


def _interrupt(_signum, _frame):
    fail('CLEANUP_FAILED' if _cleanup_uncertain else 'TIMEOUT')


def _acquire(deadline):
    # No paths are supplied by module arguments. Synthetic tests may replace
    # the private root constant or call Reader with an already-open root FD.
    if not _trusted_executable(_OPENSSL, alias=False):
        raise ToolFailure()
    reader = None
    try:
        fd = os.open(ROOT_DIRECTORY, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            reader = Reader(fd, deadline)
            rows = reader.collect()
        finally:
            os.close(fd)
    except (Fault, OSError) as exc:
        if _cleanup_uncertain or (reader is not None and reader.cleanup_failed) or reason(exc) == 'CLEANUP_FAILED':
            fail('CLEANUP_FAILED')
        rows = _error_roots(reason(exc))
    return rows


def _child(stage):
    _stage(stage)
    _payload_archive()
    require(sys.platform == 'linux' and sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode)
    if not _process_control():
        raise SystemExit(70)
    try:
        if (not _trusted_executable(_SYSTEM_PYTHON, alias=True)
                or not os.path.samestat(os.stat(_SYSTEM_PYTHON), os.stat('/proc/self/exe'))):
            raise ToolFailure()
    except (OSError, ToolFailure):
        raise SystemExit(71) from None
    deadline = time.monotonic() + WORK_SECONDS
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM):
        signal.signal(sig, _interrupt)
    signal.setitimer(signal.ITIMER_REAL, ALARM_SECONDS)
    try:
        payload = _typed_payload(_acquire(deadline))
        if _cleanup_uncertain:
            fail('CLEANUP_FAILED')
        raw = canonical(payload) + b'\n'
        require(len(raw) <= CHILD_BYTES)
        if time.monotonic() >= deadline:
            fail('TIMEOUT')
        sys.stdout.buffer.write(raw)
        sys.stdout.buffer.flush()
    except Fault as exc:
        raise SystemExit(70 if _cleanup_uncertain or exc.reason == 'CLEANUP_FAILED' else 124 if exc.reason == 'TIMEOUT' else 71) from None
    except (ToolFailure, OSError, ValueError, TypeError, KeyError, RecursionError):
        raise SystemExit(70 if _cleanup_uncertain else 71) from None
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


def main():
    module = AnsibleModule(argument_spec={'stage': dict(type='str', required=True, choices=list(STAGES))},
                           supports_check_mode=True, no_log=True)
    try:
        receipt = _run_stage(_stage(module.params['stage']))
    except (ImportError, OSError, ValueError, TypeError, AttributeError, KeyError, RecursionError):
        module.fail_json(changed=False, msg='CERT_STAGE_CONTRACT_FAILED')
    module.exit_json(changed=False, receipt=receipt)


if __name__ == '__main__':
    main()
