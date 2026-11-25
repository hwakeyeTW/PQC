"""Private Linux runner for fixed, trusted passive adapter commands.

Not an Ansible module, CLI, arbitrary-command service or security sandbox.
Call in the foreground of a dedicated, single-threaded remote worker. The
trusted installed program must not daemonize, detach or move process groups.
No controller/transport heartbeat is needed to enforce the local deadline.
"""
import ctypes
import os
import selectors
import signal
import subprocess
import sys
import threading
import time
from typing import NamedTuple

COMMAND_SECONDS = 30
OUTPUT_BYTES = 16 * 1024


class CommandResult(NamedTuple):
    reason_code: str
    rc: int | None
    stdout: bytes
    stderr: bytes
    cleanup_confirmed: bool


class _Stop(Exception):
    pass


def _exists(pgid):
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False


def _reap(proc):
    # Popen owns the direct child's wait status. Only after its exit may we
    # reap adopted, same-group descendants of this dedicated worker.
    if proc.poll() is None:
        return
    while True:
        try:
            pid, _ = os.waitpid(-proc.pid, os.WNOHANG)
        except ChildProcessError:
            return
        if not pid:
            return


def _clean(proc, deadline):
    """Use TERM then KILL; success requires reaped leader and absent group."""
    try:
        _reap(proc)
        if not _exists(proc.pid) and proc.returncode is not None:
            return True
        term_end = min(deadline, time.monotonic() + 0.25)
        for sig, end in ((signal.SIGTERM, term_end), (signal.SIGKILL, deadline)):
            try:
                os.killpg(proc.pid, sig)
            except ProcessLookupError:
                pass
            while True:
                _reap(proc)
                if proc.returncode is not None and not _exists(proc.pid):
                    return True
                if time.monotonic() >= end:
                    break
                time.sleep(min(0.01, max(0, end - time.monotonic())))
    except OSError:
        pass
    return False


def run_bounded(argv, *, timeout_s=COMMAND_SECONDS):
    """Return a bounded local outcome; only COMMAND_OK has usable bytes.

    argv is supplied by trusted adapter code, not Inventory, report or CLI.
    A lower timeout may narrow (never enlarge) a fixed adapter's budget.
    The combined stdout/stderr cap is a failure threshold, not truncation.
    """
    try:
        argv_bytes = (sum(len(x.encode('utf-8')) + 1 for x in argv)
                      if type(argv) in (list, tuple) and len(argv) <= 32
                      and all(type(x) is str for x in argv) else 8193)
    except (AttributeError, UnicodeError):
        argv_bytes = 8193
    if (type(argv) not in (list, tuple) or not 1 <= len(argv) <= 32
            or any(type(x) is not str or '\x00' in x for x in argv)
            or not os.path.isabs(argv[0])
            or argv_bytes > 8192
            or type(timeout_s) not in (int, float) or not 0.5 <= timeout_s <= COMMAND_SECONDS):
        return CommandResult('INVALID_COMMAND_CONTRACT', None, b'', b'', True)
    if (sys.platform != 'linux' or threading.current_thread() is not threading.main_thread()
            or threading.active_count() != 1):
        return CommandResult('PROCESS_CONTROL_UNAVAILABLE', None, b'', b'', False)
    libc = ctypes.CDLL(None, use_errno=True)
    old = ctypes.c_int()
    if libc.prctl(37, ctypes.byref(old), 0, 0, 0) or libc.prctl(36, 1, 0, 0, 0):
        return CommandResult('PROCESS_CONTROL_UNAVAILABLE', None, b'', b'', False)
    deadline = time.monotonic() + timeout_s
    work_end = deadline - min(1.0, timeout_s / 2)
    stopped = False
    handlers = {}
    proc = None
    reason, confirmed = 'COMMAND_START_FAILED', True
    buffers = [bytearray(), bytearray()]

    def interrupt(signum, frame):
        nonlocal stopped
        stopped = True

    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            handlers[sig] = signal.signal(sig, interrupt)
        if stopped:
            raise _Stop('INTERRUPTED')
        proc = subprocess.Popen(tuple(argv), stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C.UTF-8'},
                                shell=False, close_fds=True, start_new_session=True)
        with selectors.DefaultSelector() as sel:
            for i, stream in enumerate((proc.stdout, proc.stderr)):
                sel.register(stream, selectors.EVENT_READ, i)
            while sel.get_map() or proc.poll() is None:
                if stopped:
                    raise _Stop('INTERRUPTED')
                left = work_end - time.monotonic()
                if left <= 0:
                    raise _Stop('COMMAND_TIMEOUT')
                if not sel.get_map():
                    time.sleep(min(0.02, left))
                    continue
                for key, _ in sel.select(min(left, 0.05)):
                    remaining = OUTPUT_BYTES - sum(map(len, buffers))
                    data = os.read(key.fd, min(4096, remaining + 1))
                    if not data:
                        sel.unregister(key.fileobj)
                        continue
                    if len(data) > remaining:
                        raise _Stop('COMMAND_OUTPUT_LIMIT')
                    buffers[key.data].extend(data)
        _reap(proc)
        if _exists(proc.pid):
            raise _Stop('RESIDUAL_PROCESS')
        if time.monotonic() >= work_end:
            raise _Stop('COMMAND_TIMEOUT')
        reason = 'COMMAND_OK' if proc.returncode == 0 else 'COMMAND_FAILED'
    except _Stop as exc:
        reason = exc.args[0]
    except (OSError, ValueError, subprocess.SubprocessError):
        reason = 'COMMAND_START_FAILED' if proc is None else 'COMMAND_IO_FAILED'
    finally:
        try:
            if proc is not None:
                confirmed = _clean(proc, deadline)
                proc.stdout.close()
                proc.stderr.close()
        finally:
            if libc.prctl(36, old.value, 0, 0, 0):
                confirmed = False
            for sig, previous in handlers.items():
                signal.signal(sig, previous)
    if not confirmed:
        reason = 'REMOTE_CLEANUP_UNCONFIRMED'
    elif stopped:
        reason = 'INTERRUPTED'
    elif reason == 'COMMAND_OK' and time.monotonic() > deadline:
        reason = 'COMMAND_TIMEOUT'
    rc = proc.returncode if proc is not None else None
    return CommandResult(reason, rc, bytes(buffers[0]) if reason == 'COMMAND_OK' else b'',
                         bytes(buffers[1]) if reason == 'COMMAND_OK' else b'', confirmed)
