"""C3b private synthetic native worker-to-V3 Store bridge.

One trusted, exclusive Controller, one original Context and one pinned Store.
No public selector, transport, arbitrary adapter or path authority. Forked
workers receive only the existing acquisition boundary, not a Store handle.
"""
import contextlib
import errno
import os
import re
import signal
import stat
import time
from typing import NamedTuple

from tools import assessment, batch_execution as batch, run_store as m
from tools import run_store_v3 as v3, scan_collectors as bridge

_PERSIST_SECONDS = 1200


class _Result(NamedTuple):
    batch_rc: int
    batch_manifest: dict
    published: m.PublishedRun
    late_interrupted: bool


class _WorkflowError(Exception):
    """Fixed private disposition; no paths, raw exceptions or diagnostics."""
    def __init__(self, stage, reason, *, store_code=None, capacity_stage=None,
                 batch_rc=None, publication_unconfirmed=False):
        super().__init__(reason)
        self.stage, self.reason = stage, reason
        self.store_code, self.capacity_stage = store_code, capacity_stage
        self.batch_rc = batch_rc
        self.publication_unconfirmed = publication_unconfirmed


def _identity(st):
    return st.st_dev, st.st_ino, stat.S_IFMT(st.st_mode)


def _close_inherited(fds):
    # No unlock (flock is shared across fork), no writer.close, no fd sweep.
    # Verify all expected identities before closing any. Fail before TaskExecutor.
    for fd, identity in fds:
        if _identity(os.fstat(fd)) != identity:
            raise RuntimeError('STORE_FD_IDENTITY')
    for fd, identity in fds:
        os.close(fd)
        try:
            os.fstat(fd)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise
        else:
            raise RuntimeError('STORE_FD_CLOSE_UNCONFIRMED')


class _Control:
    def __init__(self, ctx, store, session, rules_raw):
        self.ctx, self.store, self.session, self.rules_raw = ctx, store, session, rules_raw
        self.pid = os.getpid()
        self.writer = None
        self.failure = None
        self.storage_active = self.reserving = False
        self.frozen = self.late_interrupted = self.finalize_started = False
        self.batch_rc = self.finished_at = self.persistence_end = None
        self.ids = {}
        self.owned_fds = None

    def mark_failure(self, stage, reason, exc=None):
        if self.failure is None:
            code = exc.code if isinstance(exc, m.StoreError) else None
            if type(code) is not str or not re.fullmatch(r'[A-Z][A-Z0-9_]{0,95}', code):
                code = None
            capacity = exc.stage if isinstance(exc, v3.CapacityError) else None
            self.failure = _WorkflowError(stage, reason, store_code=code,
                capacity_stage=capacity, batch_rc=self.batch_rc,
                publication_unconfirmed=self.finalize_started)
        return self.failure

    def reject(self, stage, reason, exc=None):
        raise self.mark_failure(stage, reason, exc) from None

    def check_registry(self, registry, ledger):
        types = {bridge.PLATFORM: bridge._PlatformStageAdapter,
                 bridge.OPENSSL: bridge._OpenSSLStageAdapter,
                 bridge.POLICY: bridge._PolicyStageAdapter,
                 bridge.SSH: bridge._SSHStageAdapter,
                 bridge.CERT: bridge._CertStageAdapter}
        batch.require(all(type(registry[p]) is types[p]
                          for names in ledger.eligible.values() for p in names),
                      3, 'INVALID_ADAPTER_REGISTRY')

    def reserve(self, ledger):
        ctx = self.ctx
        batch.require(os.getpid() == self.pid and self.writer is None and not self.frozen,
                      3, 'NATIVE_CONTEXT_UNVERIFIED')
        self.ids = {n: bridge.host_record(self.session.run_id, n)['host_id'] for n in ctx._targets}
        self.storage_active = self.reserving = True
        try:
            self.writer = self.store._begin_v3(run_id=self.session.run_id,
                expected_hosts=[dict(target_id=n, inventory_authority_id=None, identity_key=n)
                                for n in ctx._targets],
                requested_flags=ledger.flags, limits=dict(max_hosts=ctx._request['max_hosts'],
                    forks=ctx._request['forks'], serial=2, ssh_timeout_s=15, command_timeout_s=30),
                profile=ctx._request['profile'], producer_rules_raw=self.rules_raw,
                started_at=self.session.started_at)
            m.require(type(self.writer) is v3.Writer, 'INVALID_STORE_DATA')
            self.owned_fds = self._fds()
        except batch._Deadline:
            self.reject('RESERVATION', 'STORAGE_DEADLINE')
        except Exception as exc:
            self.reject('RESERVATION', 'RESERVATION_FAILED', exc)
        finally:
            self.storage_active = self.reserving = False

    def _fds(self):
        m.require(os.getpid() == self.pid and type(self.writer) is v3.Writer
                  and not self.frozen and self.writer._device == self.store._device,
                  'INVALID_STORE_DATA')
        root, run, lock = self.store._fd, self.writer._fd, self.writer._lock
        m.require(all(type(fd) is int and fd > 2 for fd in (root, run, lock))
                  and len({root, run, lock}) == 3, 'INVALID_STORE_DATA')
        device = self.store._device
        identities = (_identity(m._check_dir(root, device)),
                      _identity(m._check_dir(run, device)),
                      _identity(m._stat_file(lock, device)))
        m.require(len(set(identities)) == 3 and
                  _identity(os.stat(self.writer.run_id, dir_fd=root, follow_symlinks=False)) == identities[1]
                  and _identity(os.stat('.writer.lock', dir_fd=run, follow_symlinks=False)) == identities[2],
                  'INVALID_STORE_DATA')
        # Exclusive Controller contract: reject aliases and extra descriptors
        # under this pinned root. The caller must not hold another Store.
        # This is an ownership check, never a generic descriptor close list.
        fds = tuple(zip((root, run, lock), identities))
        root_path = os.readlink(f'/proc/self/fd/{root}')
        prefix = root_path.rstrip('/') + '/'
        for entry in os.listdir('/proc/self/fd'):
            fd = int(entry)
            if fd in (root, run, lock):
                continue
            try:
                alias = _identity(os.fstat(fd))
                location = os.readlink(f'/proc/self/fd/{fd}')
            except OSError as exc:
                if exc.errno in (errno.EBADF, errno.ENOENT):
                    continue
                raise
            m.require(alias not in identities and not location.startswith(prefix), 'INVALID_STORE_DATA')
        return fds

    def check_worker(self, worker, host, task):
        from ansible.executor.process.worker import WorkerProcess
        from ansible.utils.multiprocessing import context
        if not (os.getpid() == self.pid and type(worker) is WorkerProcess
                and context.get_start_method() == 'fork' and worker._start_method == 'fork'
                and worker._host is host and worker._task is task and worker.pid is None
                and host.name in self.ids and task.no_log is True):
            self.reject('DISPATCH', 'WORKER_IDENTITY_UNVERIFIED')

    def intent(self, name, end):
        if self.failure is not None:
            raise self.failure
        self.storage_active = True
        try:
            self.writer.dispatch_intent(self.ids[name])
            if time.monotonic() >= end or signal.getitimer(signal.ITIMER_REAL)[0] <= 0:
                self.reject('DISPATCH_INTENT', 'STORAGE_DEADLINE')
        except _WorkflowError:
            raise
        except batch._Deadline:
            self.reject('DISPATCH_INTENT', 'STORAGE_DEADLINE')
        except Exception as exc:
            self.reject('DISPATCH_INTENT', 'INTENT_FAILED', exc)
        finally:
            self.storage_active = False

    @contextlib.contextmanager
    def isolate_child(self, worker):
        from ansible.executor.process.worker import WorkerProcess
        try:
            fds = self._fds()
            m.require(fds == self.owned_fds, 'INVALID_STORE_DATA')
        except Exception as exc:
            self.reject('DISPATCH', 'STORE_FD_IDENTITY', exc)
        original = WorkerProcess.run
        parent = self.pid

        def isolated(child):
            # The closure contains only fixed fd identities and native run,
            # never the control, Store, writer, path or persistence callable.
            try:
                if os.getpid() == parent or child is not worker:
                    raise RuntimeError('WORKER_IDENTITY_UNVERIFIED')
                _close_inherited(fds)
            except BaseException:
                os._exit(1)
            return original(child)

        WorkerProcess.run = isolated
        try:
            yield
        finally:
            WorkerProcess.run = original

    def freeze(self, rc):
        self.batch_rc = rc
        if self.failure is not None:
            if self.failure.reason != 'START_UNCONFIRMED':
                self.failure.batch_rc = rc
            raise self.failure
        if self.writer is None:
            self.reject('RESERVATION', 'RESERVATION_NOT_CONFIRMED')
        self.finished_at = bridge.stamp()
        self.persistence_end = time.monotonic() + _PERSIST_SECONDS
        self.frozen = True

    def boundary(self, stage):
        if time.monotonic() >= self.persistence_end:
            self.reject(stage, 'STORAGE_DEADLINE')
        if self.late_interrupted:
            self.reject(stage, 'PERSISTENCE_CANCELLED')

    def persist(self, manifest, ledger):
        stage = 'CHECKPOINT'
        try:
            self.boundary(stage)
            with batch._deadline(self.persistence_end - time.monotonic()):
                for row in manifest['hosts']:
                    self.boundary(stage)
                    name = row['target_id']
                    host = bridge.host_record(self.session.run_id, name,
                                              row['host_state'], row['reason_code'])
                    fragment = bridge.document(self.session.run_id, self.session.started_at,
                        [host], m._run_state([host]), self.finished_at if row['attempted'] else None)
                    details = {}
                    projection = ledger.projections.get(name)
                    if projection is not None:
                        for k in ('collections', 'assets', 'evidence'):
                            fragment[k] = projection.document[k]
                        details = {v3.HANDOFF: ledger.wires[name], **{
                            v3.PRODUCER_SLOTS[p]: v3._detail_bytes(v3.PRODUCER_SLOTS[p], value)
                            for p, value in projection.companions.items()}}
                    fragment['run']['recorded_at'] = bridge.stamp()
                    self.boundary(stage)
                    self.writer.record_host(fragment, attempted=row['attempted'], terminal=row,
                                            details=details)
                stage = 'FINALIZE'
                raw = m._json_bytes(manifest, v3.MANIFEST_BYTES)
                # Admit the single atomic finalize at this boundary. Signals
                # thereafter only latch; never change the frozen acquisition.
                mask = signal.pthread_sigmask(signal.SIG_BLOCK, (signal.SIGINT, signal.SIGTERM))
                try:
                    if {signal.SIGINT, signal.SIGTERM} & signal.sigpending():
                        self.late_interrupted = True
                    self.boundary(stage)
                    self.finalize_started = True
                finally:
                    signal.pthread_sigmask(signal.SIG_SETMASK, mask)
                result = self.writer.finalize(batch_raw=raw, batch_rc=self.batch_rc,
                                              finished_at=self.finished_at)
                m.require(type(result) is m.PublishedRun and result.manifest['publication_state'] == 'PUBLISHED'
                          and result.manifest['run_id'] == self.session.run_id
                          and result.manifest['batch_rc'] == self.batch_rc, 'MANIFEST_MISMATCH')
                if time.monotonic() >= self.persistence_end:
                    self.reject(stage, 'STORAGE_DEADLINE')
        except _WorkflowError:
            raise
        except batch._Deadline:
            self.reject(stage, 'STORAGE_DEADLINE')
        except Exception as exc:
            self.reject(stage, 'PUBLICATION_FAILED' if self.finalize_started else 'CHECKPOINT_FAILED', exc)
        finally:
            if self.failure is not None:
                self.writer._poisoned = True
        return _Result(self.batch_rc, manifest, result, self.late_interrupted)


def _execute_scan_workflow(ctx, store, producer_rules_raw):
    """Private only; caller owns the root Store, this invocation owns its writer."""
    batch.require(type(ctx) is batch._Context and not ctx._batch_used and type(store) is m.RunStore,
                  3, 'NATIVE_CONTEXT_UNVERIFIED')
    try:
        store._check()
        rules = assessment.load_rules(producer_rules_raw)
    except (m.StoreError, assessment.AssessmentError, OSError) as exc:
        raise _WorkflowError('RESERVATION', 'INVALID_WORKFLOW_INPUT',
                             store_code=exc.code if isinstance(exc, m.StoreError) else None) from None
    session = batch._ProducerSession(rules)
    session.retain_wire = True
    control = _Control(ctx, store, session, producer_rules_raw)
    try:
        try:
            result = batch._execute_batch(ctx, session, workflow=control)
        except batch.Denied:
            if control.writer is None:
                raise
            control.reject('TERMINAL', 'TERMINAL_UNCONFIRMED')
        except _WorkflowError:
            raise
        except Exception as exc:
            control.reject('TERMINAL', 'TERMINAL_UNCONFIRMED', exc)
    finally:
        try:
            if not session.close():
                control.reject('CLEANUP', 'CONTROLLER_CLEANUP_UNCONFIRMED')
        finally:
            try:
                if control.writer is not None:
                    if control.failure is not None:
                        control.writer._poisoned = True
                    try:
                        control.writer.close()
                    except Exception as exc:
                        control.reject('CLEANUP', 'STORE_CLOSE_UNCONFIRMED', exc)
            finally:
                for sig, previous in session.handlers.items():
                    signal.signal(sig, previous)
    return result._replace(late_interrupted=control.late_interrupted)
