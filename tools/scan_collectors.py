"""I1a private, synthetic-only producer bridge. No acquisition entry point.

The native executor owns authorization, worker lifetime and deadlines. This
module owns typed, bounded receipts and exact projections of the five existing
Controller normalizers. Real acquisition and persistent storage are separate.
"""
import copy
import hashlib
import json
import os
import re
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import NamedTuple
from types import MappingProxyType

from tools import assessment, cert_assets, crypto_policy, evidence, openssl_runtime, platform, ssh_posture

PLATFORM = platform.COLLECTOR
OPENSSL = openssl_runtime.PRODUCER
POLICY = crypto_policy.COLLECTOR
SSH = ssh_posture.PRODUCER
CERT = cert_assets.COLLECTOR
PRODUCERS = (PLATFORM, OPENSSL, POLICY, SSH, CERT)
PACKAGES, SSL = openssl_runtime.FLAGS
SSHD, KEYS = ssh_posture.FLAGS
POLICY_FLAG = 'pqc_collect_crypto_policy'
CERT_FLAG = 'pqc_collect_system_certs'
NGINX, TLS = 'pqc_collect_nginx_certs', 'pqc_collect_tls_services'
FLAGS = tuple(sorted((PACKAGES, SSL, POLICY_FLAG, SSHD, KEYS, CERT_FLAG, NGINX, TLS)))
PRODUCER_FLAGS = MappingProxyType({PLATFORM: (), OPENSSL: (PACKAGES, SSL),
                                  POLICY: (POLICY_FLAG,), SSH: (SSHD, KEYS), CERT: (CERT_FLAG,)})
VERSIONS = MappingProxyType({PLATFORM: platform.COLLECTOR_VERSION, OPENSSL: openssl_runtime.VERSION,
                            POLICY: crypto_policy.COLLECTOR_VERSION, SSH: ssh_posture.VERSION,
                            CERT: cert_assets.VERSION})
MAX_WIRE = 1024 * 1024
MAX_HOSTS = 10
MAX_REFS = 294
MAX_PROVIDERS = 256
WIRE_VERSION = 1
SHA = re.compile(r'[0-9a-f]{64}\Z')
TARGET = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,254}\Z')
RUN = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z')
CONNECTIONS = frozenset(('CONNECTED', 'CONNECTION_FAILED', 'CONNECTION_TIMEOUT',
                         'REMOTE_CLEANUP_UNCONFIRMED', 'INVALID_ADAPTER_RESULT'))
FAILURES = frozenset(('COMMAND_FAILED', 'COMMAND_TIMEOUT', 'COMMAND_OUTPUT_LIMIT',
                      'COMMAND_START_FAILED', 'COMMAND_IO_FAILED', 'RESIDUAL_PROCESS',
                      'REMOTE_CLEANUP_UNCONFIRMED', 'INVALID_ADAPTER_RESULT',
                      'PROCESS_CONTROL_UNAVAILABLE', 'INVALID_COMMAND_CONTRACT',
                      'GUARD_REJECTED', 'CONTROLLER_TIMEOUT', 'INTERRUPTED'))
FATAL = frozenset(('REMOTE_CLEANUP_UNCONFIRMED', 'INVALID_ADAPTER_RESULT',
                   'PROCESS_CONTROL_UNAVAILABLE', 'INVALID_COMMAND_CONTRACT',
                   'GUARD_REJECTED', 'CONTROLLER_TIMEOUT', 'INTERRUPTED'))
UNCERTAIN = frozenset(('CLEANUP_FAILED', 'CLEANUP_UNCONFIRMED', 'OUTER_DEADLINE',
                       'HELPER_ERROR', 'EXECUTION_ERROR'))
GOOD = frozenset(('COLLECTED', 'PARTIAL', 'NOT_APPLICABLE'))


class BridgeError(ValueError):
    """Only constant non-sensitive diagnostics, never raw adapter data."""


def require(ok, reason='INVALID_PRODUCER_PROJECTION'):
    if not ok:
        raise BridgeError(reason)


def shape(obj, keys):
    require(type(obj) is dict and obj.keys() == set(keys))


def stamp():
    return datetime.now(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def requested(flags):
    shape(flags, FLAGS)
    require(all(type(v) is bool for v in flags.values()))
    require(not flags[NGINX] and not flags[TLS], 'UNSUPPORTED_PRODUCER')
    return ((PLATFORM,) + tuple(p for p in PRODUCERS[1:] if any(flags[f] for f in PRODUCER_FLAGS[p]))) if any(flags.values()) else ()


def _producer_adapters():
    # Deliberately empty. Only trusted test code substitutes synthetic adapters.
    # No payload, CLI, hostvar or serialized plan can register an adapter.
    return {}


# I1b P2/O2/CP2: fixed private stage bridges. Not a live transport or a public driver
# registry. A prepare callback may only package the bound fixed P1 stage;
# the returned launcher must consume its one-use native launch gate before
# dispatch. It owns independent stage completion and cleanup evidence.
_PLATFORM_STAGES = ('metadata', *('release-rpm-' + name for name in platform.PACKAGES))
_OPENSSL_STAGES = openssl_runtime.SLOTS
_POLICY_STAGES = ('reader', 'show-bin', 'show-sbin')
_POLICY_READER_SCOPES = tuple(s for s in crypto_policy.SCOPES if s != 'profile-show')
_POLICY_PAYLOAD_BYTES = 64 * 1024
_POLICY_RECEIPT_BYTES = 66 * 1024
_POLICY_FRAME_BYTES = 128 * 1024
_SSH_STAGES = ('config', 'keys')
_SSH_SLOT_BYTES = 262144
_SSH_CHILD_BYTES = 262145
_SSH_RECEIPT_BYTES = 262243
_SSH_FRAME_BYTES = 524483
_SSH_STRUCTURE_RESERVE = 16384
_SSH_STAGED_PAYLOAD_BUDGET = 819200
_SSH_STAGED_WIRE_BUDGET = _SSH_STAGED_PAYLOAD_BUDGET + _SSH_STRUCTURE_RESERVE
_SSH_ORDINARY_FAILURES = MappingProxyType({
    'COMMAND_OUTPUT_LIMIT': 'OUTPUT_LIMIT', 'COMMAND_TIMEOUT': 'TIMEOUT',
    'COMMAND_START_FAILED': 'EXECUTION_ERROR', 'COMMAND_FAILED': 'EXECUTION_ERROR',
    'COMMAND_IO_FAILED': 'EXECUTION_ERROR', 'RESIDUAL_PROCESS': 'EXECUTION_ERROR',
})
_STAGE_FRAME_BYTES = 32 * 1024
_STAGE_RECEIPT_BYTES = 16 * 1024
_STAGE_RPM_FAILURES = MappingProxyType({
    'COMMAND_TIMEOUT': 'TIMEOUT', 'COMMAND_OUTPUT_LIMIT': 'OUTPUT_LIMIT',
    'COMMAND_START_FAILED': 'COMMAND_FAILED', 'COMMAND_FAILED': 'COMMAND_FAILED',
    'COMMAND_IO_FAILED': 'COMMAND_FAILED', 'RESIDUAL_PROCESS': 'COMMAND_FAILED',
})


class _StageBinding(NamedTuple):
    run_id: str
    target_id: str
    task_uuid: str
    stage: str
    ordinal: int


class _OpenSSLStageBinding(NamedTuple):
    run_id: str
    target_id: str
    task_uuid: str
    producer_id: str
    stage: str
    ordinal: int


class _PolicyStageBinding(NamedTuple):
    run_id: str
    target_id: str
    task_uuid: str
    producer_id: str
    stage: str
    ordinal: int


class _SSHStageBinding(NamedTuple):
    run_id: str
    target_id: str
    task_uuid: str
    producer_id: str
    stage: str
    ordinal: int


class _StageCompletion(NamedTuple):
    # The binding is the actual controller-issued object, not fields taken
    # from remote output. clean is the trusted driver's independent lifecycle
    # receipt, never copied from an unchecked frame. started=False requires
    # proof that no stage process was launched.
    binding: _StageBinding | _OpenSSLStageBinding | _PolicyStageBinding | _SSHStageBinding
    stdout: bytes
    stderr: bytes
    wrapper_rc: int | None
    started: bool
    clean: bool


class _StageFailure(BridgeError):
    def __init__(self, reason, rc=None, clean=False):
        super().__init__(reason)
        self.reason, self.rc, self.clean = reason, rc, clean

    def value(self):
        return dict(reason_code=self.reason, rc=self.rc,
                    cleanup_confirmed=self.clean, snapshot=None)


def _bound_stage_validator():
    # Lazy import: normal offline consumers do not need Ansible installed.
    # Use only the canonical fixed product module, never an injected path or
    # an alternative validator in a test-only packaged copy.
    from ansible_collections.security.compliance_pqc_readiness.plugins.modules import pqc_platform_acquire
    expected = (Path(__file__).resolve().parents[1] / 'ansible_collections/security/'
                'compliance_pqc_readiness/plugins/modules/pqc_platform_acquire.py')
    require(Path(pqc_platform_acquire.__file__).resolve() == expected
            and pqc_platform_acquire.STAGES == _PLATFORM_STAGES
            and pqc_platform_acquire.OUTPUT_BYTES == _STAGE_RECEIPT_BYTES,
            'INVALID_STAGE_VALIDATOR')
    return pqc_platform_acquire.validate_receipt


def _bound_openssl_stage_validator():
    from ansible_collections.security.compliance_pqc_readiness.plugins.modules import pqc_openssl_acquire
    expected = (Path(__file__).resolve().parents[1] / 'ansible_collections/security/'
                'compliance_pqc_readiness/plugins/modules/pqc_openssl_acquire.py')
    require(Path(pqc_openssl_acquire.__file__).resolve() == expected
            and pqc_openssl_acquire.STAGES == _OPENSSL_STAGES
            and pqc_openssl_acquire.OUTPUT_BYTES == _STAGE_RECEIPT_BYTES
            and pqc_openssl_acquire.WRAPPER_BYTES == _STAGE_FRAME_BYTES,
            'INVALID_STAGE_VALIDATOR')
    return pqc_openssl_acquire.validate_receipt


def _bound_policy_stage_validator():
    # Offline Store/import callers never need to load Ansible.
    from ansible_collections.security.compliance_pqc_readiness.plugins.modules import pqc_policy_acquire
    expected = (Path(__file__).resolve().parents[1] / 'ansible_collections/security/'
                'compliance_pqc_readiness/plugins/modules/pqc_policy_acquire.py')
    require(Path(pqc_policy_acquire.__file__).resolve() == expected
            and pqc_policy_acquire.STAGES == _POLICY_STAGES
            and pqc_policy_acquire.PAYLOAD_BYTES == _POLICY_PAYLOAD_BYTES
            and pqc_policy_acquire.RECEIPT_BYTES == _POLICY_RECEIPT_BYTES
            and pqc_policy_acquire.WRAPPER_BYTES == _POLICY_FRAME_BYTES,
            'INVALID_STAGE_VALIDATOR')
    return pqc_policy_acquire.validate_receipt


def _bound_ssh_stage_validator():
    # Only the canonical S1 module can validate the fixed acquisition frame.
    from ansible_collections.security.compliance_pqc_readiness.plugins.modules import pqc_ssh_acquire
    expected = (Path(__file__).resolve().parents[1] / 'ansible_collections/security/'
                'compliance_pqc_readiness/plugins/modules/pqc_ssh_acquire.py')
    require(Path(pqc_ssh_acquire.__file__).resolve() == expected
            and pqc_ssh_acquire.STAGES == _SSH_STAGES
            and pqc_ssh_acquire.SLOT_BYTES == _SSH_SLOT_BYTES
            and pqc_ssh_acquire.CHILD_BYTES == _SSH_CHILD_BYTES
            and pqc_ssh_acquire.RECEIPT_BYTES == _SSH_RECEIPT_BYTES
            and pqc_ssh_acquire.WRAPPER_BYTES == _SSH_FRAME_BYTES
            and pqc_ssh_acquire.WIRE_BYTES == MAX_WIRE
            and pqc_ssh_acquire.NATIVE_Q_QUALIFIED is False
            and pqc_ssh_acquire.NATIVE_T_QUALIFIED is False
            and ssh_posture.NATIVE_Q_QUALIFIED is False
            and ssh_posture.NATIVE_T_QUALIFIED is False,
            'INVALID_STAGE_VALIDATOR')
    return pqc_ssh_acquire.validate_receipt


def _ssh_plan(flags, snapshot):
    require(all(type(flags[f]) is bool for f in (SSHD, KEYS)))
    if _platform_status(snapshot) != 'UNVERIFIED':
        return ()
    return tuple((i, stage) for i, (stage, flag) in enumerate(zip(_SSH_STAGES, (SSHD, KEYS)))
                 if flags[flag])


def _ssh_slot(state, reason):
    return dict(state=state, reason=reason, rc=None, rows=[], gaps=[])


def _ssh_fixed_gap(flags, slot, halted=False):
    # Only for an eligible platform. Disabled and native key-flag conditions
    # have priority over a host-local halt, exactly as in #17's validator.
    if not flags[KEYS if slot == 'keys' else SSHD]:
        return _ssh_slot('NOT_SCANNED', 'DISABLED_BY_USER')
    if slot == 'native-0' and not flags[KEYS]:
        return _ssh_slot('UNKNOWN', 'KEY_FLAG_REQUIRED')
    if halted:
        return _ssh_slot('UNKNOWN', 'ACQUISITION_STOPPED')
    if slot not in _SSH_STAGES:
        return _ssh_slot('UNKNOWN', 'NATIVE_SAFETY_UNPROVEN')
    return None


def _ssh_host_stop(snapshot):
    # Called only on a closed staged snapshot revalidated by the trusted
    # worker/parent. No generic uncertainty is downgraded to a host-local stop.
    return any(snapshot['slots'][s]['reason'] in ('TIMEOUT', 'EXECUTION_ERROR') for s in _SSH_STAGES)


def _validate_staged_ssh(snapshot, flags, platform_snapshot):
    require(platform_snapshot is not None and any(flags[f] for f in (SSHD, KEYS)))
    ssh_posture.validate_snapshot(snapshot)
    status = _platform_status(platform_snapshot)
    if status != 'UNVERIFIED':
        require(snapshot == _gap_snapshot(SSH, flags, status))
        return
    require(snapshot['flags'] == {f: flags[f] for f in (SSHD, KEYS)}
            and snapshot['platform_status'] == status and snapshot['context_refs'] == ['global-default'])
    validator = _bound_ssh_stage_validator()
    halted = False
    for slot in (*ssh_posture.BASE_SLOTS, 'native-0'):
        value = snapshot['slots'][slot]
        gap = _ssh_fixed_gap(flags, slot, halted)
        if gap is not None:
            require(value == gap)
        else:
            # Revalidate the S1 payload grammar as well as the original whole
            # snapshot grammar. This reconstructed receipt is schema checking,
            # not a cleanup or launch witness. The caller owns that authority.
            validator(dict(format=1, stage=slot, reason_code='COMMAND_OK', rc=0,
                           cleanup_confirmed=True, payload=value), slot)
            halted = value['reason'] in ('TIMEOUT', 'EXECUTION_ERROR')


def _openssl_plan(flags):
    require(all(type(flags[f]) is bool for f in (PACKAGES, SSL)))
    return tuple((i, stage) for i, stage in enumerate(_OPENSSL_STAGES)
                 if flags[PACKAGES if stage in openssl_runtime.PACKAGES else SSL])


def _policy_plan(flags, snapshot):
    """Derive an exact plan from validated same-host P1 data, never paths."""
    require(type(flags[POLICY_FLAG]) is bool)
    if not flags[POLICY_FLAG]:
        return ()
    tools = platform.normalize_tools(snapshot['tools'])
    if (_platform_status(snapshot) != 'UNVERIFIED'
            or tools['timeout'][2]['available'] is not True):
        return ()
    for i, row in enumerate(snapshot['tools']['update-crypto-policies'], 1):
        if (row['state'] == 'OK' and row.get('exists') is True
                and row.get('isreg') is True and row.get('islnk') is False
                and row.get('executable') is True):
            return ((0, 'reader'), (i, _POLICY_STAGES[i]))
    return ((0, 'reader'),)


def _policy_timeout_gap():
    return {scope: crypto_policy.result('NOT_SCANNED', 'TIMEOUT_TOOL_UNAVAILABLE')
            for scope in crypto_policy.SCOPES}


def _validate_staged_policy(snapshot, flags, platform_snapshot):
    """Pure revalidation of the closed projection and its fixed plan."""
    require(flags[POLICY_FLAG] is True and platform_snapshot is not None)
    crypto_policy.normalize_snapshot(snapshot)
    plan = _policy_plan(flags, platform_snapshot)
    status = _platform_status(platform_snapshot)
    if status != 'UNVERIFIED':
        require(snapshot == _gap_snapshot(POLICY, flags, status))
    elif not plan:
        require(snapshot == _policy_timeout_gap())
    else:
        reader = {scope: snapshot[scope] for scope in _POLICY_READER_SCOPES}
        require(all(row['state'] != 'NOT_SCANNED' and row['rc'] is None
                    and all(item['result']['rc'] is None for item in row['overrides'])
                    for row in reader.values()))
        if any(row['reason'] == 'TOTAL_LIMIT' or
               any(item['result']['reason'] == 'TOTAL_LIMIT' for item in row['overrides'])
               for row in reader.values()):
            require(reader == {scope: crypto_policy.result('ERROR', 'TOTAL_LIMIT')
                               for scope in _POLICY_READER_SCOPES})
        show = snapshot['profile-show']
        if len(plan) == 1:
            require(show == crypto_policy.result('NOT_SCANNED', 'SHOW_TOOL_UNAVAILABLE'))
        else:
            require(show['state'] != 'NOT_SCANNED')
            if show['reason'] == 'AMBIGUOUS_PROFILE':
                require(show['rc'] == 0 and type(show['rc']) is int)
    require(not _uncertain(snapshot))


def _stage_receipt(completion, binding):
    # Do not accept a target-provided cleanup bit, a replay/foreign binding,
    # or process exit alone as an independent completion/cleanup receipt.
    if (type(completion) is not _StageCompletion or completion.binding is not binding
            or completion.clean is not True or type(completion.started) is not bool):
        raise _StageFailure('REMOTE_CLEANUP_UNCONFIRMED')
    try:
        out, err, rc = completion.stdout, completion.stderr, completion.wrapper_rc
        if type(binding) is _SSHStageBinding:
            require(binding.producer_id == SSH and type(binding.ordinal) is int
                    and 0 <= binding.ordinal < len(_SSH_STAGES)
                    and binding.stage == _SSH_STAGES[binding.ordinal])
            frame_bytes = _SSH_FRAME_BYTES
        elif type(binding) is _PolicyStageBinding:
            require(binding.producer_id == POLICY and type(binding.ordinal) is int
                    and 0 <= binding.ordinal < len(_POLICY_STAGES)
                    and binding.stage == _POLICY_STAGES[binding.ordinal])
            frame_bytes = _POLICY_FRAME_BYTES
        else:
            require(type(binding) in (_StageBinding, _OpenSSLStageBinding))
            frame_bytes = _STAGE_FRAME_BYTES
        require(type(out) is bytes and type(err) is bytes
                and len(out) + len(err) <= frame_bytes)
        if not completion.started:
            require(rc is None and not out and not err)
            raise _StageFailure('COMMAND_START_FAILED', clean=True)
        require(type(rc) is int and rc == 0 and not err and bool(out))
        frame = json.loads(out.decode('ascii'), object_pairs_hook=_pairs,
                           parse_constant=_bad_number, parse_float=_bad_number)
        shape(frame, ('changed', 'invocation', 'receipt'))
        require(frame['changed'] is False and frame['invocation'] == {
            'module_args': {'stage': binding.stage}})
        if type(binding) is _StageBinding:
            validator = _bound_stage_validator()
        elif type(binding) is _PolicyStageBinding:
            validator = _bound_policy_stage_validator()
        elif type(binding) is _SSHStageBinding:
            validator = _bound_ssh_stage_validator()
        else:
            require(type(binding) is _OpenSSLStageBinding and binding.producer_id == OPENSSL
                    and type(binding.ordinal) is int and 0 <= binding.ordinal < len(_OPENSSL_STAGES)
                    and binding.stage == _OPENSSL_STAGES[binding.ordinal])
            validator = _bound_openssl_stage_validator()
        receipt = validator(frame['receipt'], binding.stage)
        if not receipt['cleanup_confirmed']:
            raise _StageFailure('REMOTE_CLEANUP_UNCONFIRMED', receipt['rc'])
        if (type(binding) is _PolicyStageBinding and receipt['payload'] is not None
                and _uncertain(receipt['payload'])):
            # A clean outer supervisor cannot certify an uncertain inner
            # --show cleanup. Retain pending and deny further dispatch.
            raise _StageFailure('REMOTE_CLEANUP_UNCONFIRMED', receipt['rc'])
        return receipt
    except _StageFailure:
        raise
    except Exception:
        # The independently verified, *same binding* completion is clean,
        # but invalid data cannot acquire evidence or authorize another stage.
        raise _StageFailure('INVALID_ADAPTER_RESULT', clean=True) from None


def _rpm_eligible(snapshot):
    facts, _ = platform.normalize_platform(snapshot['facts'], source_kind='SYNTHETIC')
    tools = platform.normalize_tools(snapshot['tools'])
    return (snapshot['facts_state'] == 'OK' and facts['platform_status'] == 'UNVERIFIED'
            and all(tools[k][2]['available'] is True for k in ('rpm', 'timeout')))


class _PlatformStageAdapter:
    """Explicit internal type; legacy synthetic callables retain their path."""
    def __init__(self, prepare):
        require(callable(prepare), 'INVALID_STAGE_DRIVER')
        self.prepare = prepare

    def collect(self, run_id, target, task_uuid, invoke, validate):
        snapshot = None
        for ordinal, stage in enumerate(_PLATFORM_STAGES):
            binding = _StageBinding(run_id, target, task_uuid, stage, ordinal)
            try:
                receipt = invoke(self.prepare, binding)
                reason, rc = receipt['reason_code'], receipt['rc']
                if reason != 'COMMAND_OK':
                    raise _StageFailure(reason, rc, receipt['cleanup_confirmed'])
            except _StageFailure as exc:
                if (ordinal == 0 or not exc.clean
                        or exc.reason not in _STAGE_RPM_FAILURES):
                    return exc.value()
                # Only an ordinary confirmed failure of an eligible RPM stage
                # may become a typed error gap and allow the next stage.
                value = dict(state='ERROR', reason=_STAGE_RPM_FAILURES[exc.reason], rows=[])
            else:
                value = receipt['payload']
            if ordinal == 0:
                snapshot = {**copy.deepcopy(value), 'rpms': {}}
                if not validate(_rpm_eligible, snapshot):
                    break
            else:
                package = platform.PACKAGES[ordinal - 1]
                validate(platform.normalize_rpm, package, value)
                snapshot['rpms'][package] = copy.deepcopy(value)
        return dict(reason_code='COMMAND_OK', rc=0, cleanup_confirmed=True, snapshot=snapshot)


class _OpenSSLStageAdapter:
    """Fixed O1 stages; only the native session supplies its validated Platform proof."""
    def __init__(self, prepare):
        require(callable(prepare), 'INVALID_STAGE_DRIVER')
        self.prepare = prepare

    def collect(self, run_id, target, task_uuid, flags, platform_snapshot, invoke, validate):
        # The session additionally requires the proof's actual staged-worker
        # identity. A value supplied by a legacy callable cannot authorize O2.
        require(validate(_platform_status, platform_snapshot) == 'UNVERIFIED')
        frozen = {f: flags[f] for f in openssl_runtime.FLAGS}
        plan = _openssl_plan(frozen)
        require(bool(plan))
        enabled = {stage for _, stage in plan}
        slots = {stage: dict(state='NOT_SCANNED', reason='DISABLED_BY_USER', rc=None, rows=[])
                 for stage in _OPENSSL_STAGES if stage not in enabled}
        for ordinal, stage in plan:
            binding = _OpenSSLStageBinding(run_id, target, task_uuid, OPENSSL, stage, ordinal)
            try:
                receipt = invoke(self.prepare, binding)
                if receipt['reason_code'] != 'COMMAND_OK':
                    raise _StageFailure(receipt['reason_code'], receipt['rc'], receipt['cleanup_confirmed'])
            except _StageFailure as exc:
                if not exc.clean or exc.reason not in _STAGE_RPM_FAILURES:
                    return exc.value()
                # An outer failure has no trustworthy inner command rc. A
                # named absence is possible only in a validated inner payload.
                value = dict(state='ERROR', reason=_STAGE_RPM_FAILURES[exc.reason], rc=None, rows=[])
            else:
                value = receipt['payload']
                if _uncertain(value):
                    # Cleanup itself was confirmed, but the acquisition is
                    # uncertain. Discard this producer's incomplete snapshot.
                    return _StageFailure('INVALID_ADAPTER_RESULT', receipt['rc'], True).value()
            slots[stage] = copy.deepcopy(value)
        snapshot = dict(flags=frozen, platform_status='UNVERIFIED',
                        slots={stage: slots[stage] for stage in _OPENSSL_STAGES})
        validate(openssl_runtime.validate_snapshot, snapshot)
        return dict(reason_code='COMMAND_OK', rc=0, cleanup_confirmed=True, snapshot=snapshot)


class _PolicyStageAdapter:
    """Fixed CP1 stages; authorization and the ordinal gate belong to the worker."""
    def __init__(self, prepare):
        require(callable(prepare), 'INVALID_STAGE_DRIVER')
        self.prepare = prepare

    def collect(self, run_id, target, task_uuid, flags, platform_snapshot, invoke, validate):
        require(flags[POLICY_FLAG] is True)
        plan = validate(_policy_plan, flags, platform_snapshot)
        status = validate(_platform_status, platform_snapshot)
        if status != 'UNVERIFIED':
            return dict(reason_code='PLATFORM_GAP', rc=None, cleanup_confirmed=True,
                        snapshot=_gap_snapshot(POLICY, flags, status))
        if not plan:
            # COMMAND_OK denotes a complete internal projection, not a
            # launched native command. All nine scopes explicitly remain gaps.
            return dict(reason_code='COMMAND_OK', rc=0, cleanup_confirmed=True,
                        snapshot=_policy_timeout_gap())
        slots = {}
        if len(plan) == 1:
            slots['profile-show'] = crypto_policy.result('NOT_SCANNED', 'SHOW_TOOL_UNAVAILABLE')
        for ordinal, stage in plan:
            binding = _PolicyStageBinding(run_id, target, task_uuid, POLICY, stage, ordinal)
            scopes = _POLICY_READER_SCOPES if stage == 'reader' else ('profile-show',)
            try:
                receipt = invoke(self.prepare, binding)
                if receipt['reason_code'] != 'COMMAND_OK':
                    raise _StageFailure(receipt['reason_code'], receipt['rc'], receipt['cleanup_confirmed'])
            except _StageFailure as exc:
                if exc.clean is not True or exc.reason not in _STAGE_RPM_FAILURES:
                    return exc.value()
                # The outer helper rc is not an observed inner --show rc.
                rows = {scope: crypto_policy.result('ERROR', _STAGE_RPM_FAILURES[exc.reason])
                        for scope in scopes}
            else:
                rows = receipt['payload']
                if _uncertain(rows):
                    return _StageFailure('INVALID_ADAPTER_RESULT', receipt['rc'], True).value()
            shape(rows, scopes)
            require(not slots.keys() & rows.keys())
            slots.update(copy.deepcopy(rows))
        snapshot = {scope: slots[scope] for scope in crypto_policy.SCOPES}
        return dict(reason_code='COMMAND_OK', rc=0, cleanup_confirmed=True, snapshot=snapshot)


class _SSHStageAdapter:
    """Private S1 config/keys only; the native worker owns plan and gate."""
    def __init__(self, prepare):
        require(callable(prepare), 'INVALID_STAGE_DRIVER')
        self.prepare = prepare

    def collect(self, run_id, target, task_uuid, flags, platform_snapshot, invoke, validate):
        require(any(flags[f] for f in (SSHD, KEYS)))
        plan = validate(_ssh_plan, flags, platform_snapshot)
        status = validate(_platform_status, platform_snapshot)
        if status != 'UNVERIFIED':
            return dict(reason_code='PLATFORM_GAP', rc=None, cleanup_confirmed=True,
                        snapshot=_gap_snapshot(SSH, flags, status))
        slots = {}
        halted = False
        for slot in (*ssh_posture.BASE_SLOTS, 'native-0'):
            gap = _ssh_fixed_gap(flags, slot, halted)
            if gap is not None:
                slots[slot] = gap
                continue
            ordinal = _SSH_STAGES.index(slot)
            require((ordinal, slot) in plan)
            binding = _SSHStageBinding(run_id, target, task_uuid, SSH, slot, ordinal)
            try:
                receipt = invoke(self.prepare, binding)
                if receipt['reason_code'] != 'COMMAND_OK':
                    raise _StageFailure(receipt['reason_code'], receipt['rc'], receipt['cleanup_confirmed'])
            except _StageFailure as exc:
                if exc.clean is not True or exc.reason not in _SSH_ORDINARY_FAILURES:
                    return exc.value()
                value = _ssh_slot('ERROR', _SSH_ORDINARY_FAILURES[exc.reason])
            else:
                value = receipt['payload']
            slots[slot] = copy.deepcopy(value)
            halted = value['reason'] in ('TIMEOUT', 'EXECUTION_ERROR')
        snapshot = dict(flags={f: flags[f] for f in (SSHD, KEYS)}, platform_status=status,
                        context_refs=['global-default'], slots=slots)
        return dict(reason_code='COMMAND_OK', rc=0, cleanup_confirmed=True, snapshot=snapshot)


def _json_guard(value):
    # Bound work before encoding/parsing producer fields. No arbitrary objects,
    # bytes, raw diagnostics, control characters, templates or private PEM.
    stack = [(value, 0)]
    nodes = 0
    while stack:
        obj, depth = stack.pop()
        nodes += 1
        require(nodes <= MAX_WIRE and depth <= 64, 'HANDOFF_SIZE_LIMIT')
        if type(obj) is dict:
            require(len(obj) <= MAX_WIRE and all(type(k) is str for k in obj))
            stack.extend((x, depth + 1) for k, v in obj.items() for x in (k, v))
        elif type(obj) is list:
            require(len(obj) <= MAX_WIRE, 'HANDOFF_SIZE_LIMIT')
            stack.extend((x, depth + 1) for x in obj)
        elif type(obj) is str:
            require(len(obj) <= MAX_WIRE and obj.isascii() and all(32 <= ord(c) < 127 for c in obj)
                    and not any(s in obj.upper() for s in ('-----BEGIN', 'PRIVATE KEY', '{{', '{%', '{#')))
        else:
            require(obj is None or type(obj) is bool or type(obj) is int and abs(obj) <= 9007199254740991)


def wire_bytes(value):
    _json_guard(value)
    parts = bytearray()
    encoder = json.JSONEncoder(ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False)
    for part in encoder.iterencode(value):
        raw = part.encode('ascii')
        require(len(parts) + len(raw) <= MAX_WIRE, 'HANDOFF_SIZE_LIMIT')
        parts.extend(raw)
    return bytes(parts)


def _pairs(items):
    result = {}
    for k, v in items:
        require(k not in result, 'INVALID_HANDOFF_JSON')
        result[k] = v
    return result


def _bad_number(value):
    raise BridgeError('INVALID_HANDOFF_JSON')


def read_wire(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_WIRE, 'HANDOFF_SIZE_LIMIT')
    try:
        value = json.loads(raw.decode('ascii'), object_pairs_hook=_pairs,
                           parse_constant=_bad_number, parse_float=_bad_number)
        require(wire_bytes(value) == raw, 'INVALID_HANDOFF_JSON')
    except (UnicodeError, ValueError, TypeError, RecursionError, OverflowError):
        raise BridgeError('INVALID_HANDOFF_JSON') from None
    return value


def valid_receipt(value, target):
    return (type(value) is dict and value.keys() == {'handoff_version', 'run_id', 'target_id',
                                                     'byte_count', 'sha256', 'complete'}
            and type(value['handoff_version']) is int and value['handoff_version'] == WIRE_VERSION
            and type(value['run_id']) is str and RUN.fullmatch(value['run_id']) is not None
            and value['target_id'] == target and type(value['target_id']) is str
            and type(value['byte_count']) is int and 0 < value['byte_count'] <= MAX_WIRE
            and type(value['sha256']) is str and SHA.fullmatch(value['sha256']) is not None
            and value['complete'] is True)


class Handoff:
    """Private single-use, fixed-slot, fork-inherited descriptors. No path input.

    Same-UID trusted Controller/worker code is the trust boundary, not a sandbox.
    Files are never publication artifacts or reopened from an adapter path.
    """
    def __init__(self, run_id, targets):
        require(type(run_id) is str and RUN.fullmatch(run_id) and type(targets) in (list, tuple)
                and 0 < len(targets) <= MAX_HOSTS and len(set(targets)) == len(targets)
                and all(type(n) is str and TARGET.fullmatch(n) for n in targets), 'INVALID_HANDOFF_IDENTITY')
        self.run_id = run_id
        self.path = None
        self.dirfd = None
        self.directory = None
        self.slots = {}
        self.consumed = set()
        self.total = 0
        try:
            self.path = tempfile.mkdtemp(prefix='pqc-i1a-')
            # Only the just-created directory is adjusted, never an existing root.
            os.chmod(self.path, 0o700)
            self.directory = os.stat(self.path, follow_symlinks=False)
            self.dirfd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            self._directory()
            for i, target in enumerate(targets):
                name = 'slot-%02d.json' % i
                fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=self.dirfd)
                # Track the descriptor before the first potentially failing stat.
                self.slots[target] = (name, fd, None)
                self.slots[target] = (name, fd, os.fstat(fd))
                os.fchmod(fd, 0o600)
                self._file(target, size=0)
        except BaseException as exc:
            if not self.close() and isinstance(exc, Exception):
                raise BridgeError('CONTROLLER_CLEANUP_UNCONFIRMED') from None
            raise

    def _directory(self):
        current = os.fstat(self.dirfd)
        path = os.stat(self.path, follow_symlinks=False)
        require(stat.S_ISDIR(current.st_mode) and stat.S_IMODE(current.st_mode) == 0o700
                and current.st_uid == os.geteuid()
                and (current.st_dev, current.st_ino) == (self.directory.st_dev, self.directory.st_ino)
                == (path.st_dev, path.st_ino), 'UNSAFE_HANDOFF')

    def _file(self, target, size=None):
        self._directory()
        require(target in self.slots, 'INVALID_HANDOFF_IDENTITY')
        name, fd, original = self.slots[target]
        now = os.fstat(fd)
        path = os.stat(name, dir_fd=self.dirfd, follow_symlinks=False)
        require(stat.S_ISREG(now.st_mode) and stat.S_IMODE(now.st_mode) == 0o600
                and now.st_uid == os.geteuid() and now.st_nlink == 1
                and (now.st_dev, now.st_ino) == (original.st_dev, original.st_ino) == (path.st_dev, path.st_ino)
                and now.st_dev == self.directory.st_dev and 0 <= now.st_size <= MAX_WIRE
                and (size is None or now.st_size == size), 'UNSAFE_HANDOFF')
        return fd, now

    def write(self, target, envelope):
        require(envelope['run_id'] == self.run_id and envelope['target_id'] == target, 'INVALID_HANDOFF_IDENTITY')
        raw = wire_bytes(envelope)
        fd, _ = self._file(target, size=0)
        offset = 0
        while offset < len(raw):
            n = os.pwrite(fd, raw[offset:], offset)
            require(n > 0, 'HANDOFF_WRITE_FAILED')
            offset += n
        self._file(target, size=len(raw))
        return dict(handoff_version=WIRE_VERSION, run_id=self.run_id, target_id=target,
                    byte_count=len(raw), sha256=hashlib.sha256(raw).hexdigest(), complete=True)

    def read(self, target, receipt):
        require(valid_receipt(receipt, target) and receipt['run_id'] == self.run_id
                and target not in self.consumed, 'INVALID_HANDOFF_RECEIPT')
        size = receipt['byte_count']
        fd, before = self._file(target, size=size)
        data = bytearray()
        while len(data) < size:
            chunk = os.pread(fd, min(65536, size - len(data)), len(data))
            require(bool(chunk), 'HANDOFF_READ_FAILED')
            data.extend(chunk)
        require(os.pread(fd, 1, size) == b'', 'HANDOFF_READ_FAILED')
        _, after = self._file(target, size=size)
        require((before.st_mtime_ns, before.st_ctime_ns) == (after.st_mtime_ns, after.st_ctime_ns)
                and hashlib.sha256(data).hexdigest() == receipt['sha256'], 'HANDOFF_HASH_MISMATCH')
        require(self.total + size <= MAX_HOSTS * MAX_WIRE, 'HANDOFF_SIZE_LIMIT')
        value = read_wire(bytes(data))
        require(type(value) is dict and value.get('target_id') == target and value.get('run_id') == self.run_id,
                'INVALID_HANDOFF_IDENTITY')
        self.consumed.add(target)
        self.total += size
        return value

    def close(self):
        """Remove only known entries; release descriptors even on interruption."""
        clean = True
        try:
            if self.dirfd is not None:
                for target, (name, fd, original) in list(self.slots.items()):
                    try:
                        current = os.stat(name, dir_fd=self.dirfd, follow_symlinks=False)
                        if original is None:
                            original = os.fstat(fd)
                        if (current.st_dev, current.st_ino) == (original.st_dev, original.st_ino):
                            if (current.st_nlink != 1 or current.st_uid != os.geteuid() or
                                    not stat.S_ISREG(current.st_mode) or stat.S_IMODE(current.st_mode) != 0o600):
                                clean = False
                            os.unlink(name, dir_fd=self.dirfd)
                        else:
                            clean = False
                    except OSError:
                        clean = False
                    finally:
                        self.slots.pop(target, None)
                        try:
                            os.close(fd)
                        except OSError:
                            clean = False
                try:
                    self._directory()
                    os.rmdir(self.path)
                except (OSError, BridgeError):
                    clean = False
            elif self.path is not None:
                try:
                    os.rmdir(self.path)
                except OSError:
                    clean = False
        finally:
            # If a local cleanup deadline interrupts unlink/rmdir, do not
            # claim the directory is clean. Release remaining owned FDs.
            for _, fd, _ in self.slots.values():
                try:
                    os.close(fd)
                except OSError:
                    clean = False
            self.slots.clear()
            if self.dirfd is not None:
                try:
                    os.close(self.dirfd)
                except OSError:
                    clean = False
                self.dirfd = None
            self.path = None
        return clean


def host_record(run_id, target, state='ERROR', reason='NO_VALID_RESULT'):
    return dict(host_id=evidence.host_id(None, target, run_id=run_id, identity_key=target),
                target_id=target, identity_scope='RUN_SCOPED', host_state=state, reason_code=reason,
                inventory_authority_id=None, identity_key=target)


def document(run_id, started_at, hosts, state='PARTIAL', finished_at=None):
    return dict(schema_version='1.1.0', run=dict(run_id=run_id, run_state=state,
        recorded_at=finished_at or started_at, started_at=started_at, finished_at=finished_at,
        source=dict(source_kind='SYNTHETIC', producer_id='pqc-producer-bridge', producer_version='1.0.0',
                    origin_ref='i1a-synthetic', input_sha256=None),
        expected_host_ids=sorted(h['host_id'] for h in hosts)), hosts=hosts,
        collections=[], assets=[], evidence=[], claims=[], findings=[])


def _source(producer, snapshot):
    return dict(source_kind='SYNTHETIC', producer_id=producer, producer_version=VERSIONS[producer],
                origin_ref='i1a-synthetic', input_sha256=hashlib.sha256(wire_bytes(snapshot)).hexdigest())


def _append(doc, rows):
    return {**doc, **{k: doc[k] + rows.get(k, []) for k in ('collections', 'assets', 'evidence')}}


def _platform_status(snapshot):
    facts, _ = platform.normalize_platform(snapshot['facts'], source_kind='SYNTHETIC')
    return facts['platform_status'] if snapshot['facts_state'] == 'OK' else 'UNKNOWN'


def _gap_snapshot(producer, flags, status):
    """Only for an actual validated non-eligible platform, never acquired data."""
    require(status in ('UNKNOWN', 'OUT_OF_SCOPE'))
    if producer in (OPENSSL, SSH):
        module = openssl_runtime if producer == OPENSSL else ssh_posture
        scoped_flags = {f: flags[f] for f in module.FLAGS}
        slots = {}
        names = module.SLOTS if producer == OPENSSL else (*module.BASE_SLOTS, 'native-0')
        for slot in names:
            f = (PACKAGES if slot in openssl_runtime.PACKAGES else SSL) if producer == OPENSSL else (KEYS if slot == 'keys' else SSHD)
            state, reason = (('NOT_SCANNED', 'DISABLED_BY_USER') if not flags[f] else
                             ('NOT_APPLICABLE', 'PLATFORM_OUT_OF_SCOPE') if status == 'OUT_OF_SCOPE' else
                             ('UNKNOWN', 'PLATFORM_UNRESOLVED'))
            slots[slot] = dict(state=state, reason=reason, rc=None, rows=[])
            if producer == SSH:
                slots[slot]['gaps'] = []
        value = dict(flags=scoped_flags, platform_status=status, slots=slots)
        if producer == SSH:
            value['context_refs'] = ['global-default']
        return value
    if producer == POLICY:
        return {s: crypto_policy.result('NOT_SCANNED', 'PLATFORM_OUT_OF_SCOPE' if status == 'OUT_OF_SCOPE'
                                       else 'PLATFORM_UNKNOWN') for s in crypto_policy.SCOPES}
    require(producer == CERT)
    return dict(system_python_available=False, roots={s: dict(attempted=False, rc=None, entries=0,
        directories=0, skipped=0, root_target_id=None, gaps=['PLATFORM_OUT_OF_SCOPE' if status == 'OUT_OF_SCOPE'
                                                          else 'PLATFORM_UNKNOWN'], sources=[]) for s in cert_assets.ROOTS})


def _uncertain(value):
    if type(value) is dict:
        if value.get('reason') in UNCERTAIN or any(x in UNCERTAIN for x in value.get('gaps', ())):
            return True
        return any(_uncertain(x) for x in value.values())
    if type(value) is list:
        return any(_uncertain(x) for x in value)
    return False


def precheck(producer, snapshot, flags, platform_snapshot, run_id, target, observed_at):
    """Closed producer validators before any snapshot is written to disk."""
    _json_guard(snapshot)
    if producer == PLATFORM:
        h = host_record(run_id, target)
        platform.build_platform_evidence(document(run_id, observed_at, [h]), h['host_id'],
            source=_source(producer, snapshot), observed_at=observed_at, snapshot=snapshot)
        return
    status = _platform_status(platform_snapshot)
    if producer in (OPENSSL, SSH):
        module = openssl_runtime if producer == OPENSSL else ssh_posture
        module.validate_snapshot(snapshot)
        require(snapshot['flags'] == {f: flags[f] for f in module.FLAGS}
                and snapshot['platform_status'] == status, 'PRODUCER_SCOPE_MISMATCH')
    elif producer == POLICY:
        crypto_policy.normalize_snapshot(snapshot)
        require(flags[POLICY_FLAG])
    elif producer == CERT:
        shape(snapshot, ('system_python_available', 'roots'))
        require(type(snapshot['system_python_available']) is bool and flags[CERT_FLAG])
        cert_assets.validate_snapshot(snapshot['roots'])
    else:
        raise BridgeError('INVALID_PRODUCER')


def record(producer, value, flags, platform_snapshot, run_id, target, *, gap=False,
           staged_openssl=False, staged_policy=False, staged_ssh=False):
    """Validate one trusted adapter return and bind its observed time."""
    require(type(staged_openssl) is bool and (not staged_openssl or producer == OPENSSL)
            and type(staged_policy) is bool and (not staged_policy or producer == POLICY)
            and type(staged_ssh) is bool and (not staged_ssh or producer == SSH))
    if staged_ssh:
        require(platform_snapshot is not None and any(flags[f] for f in (SSHD, KEYS)))
    if staged_policy:
        require(platform_snapshot is not None and flags[POLICY_FLAG] is True)
    if staged_openssl and not gap:
        require(platform_snapshot is not None and _platform_status(platform_snapshot) == 'UNVERIFIED')
    shape(value, ('reason_code', 'rc', 'cleanup_confirmed', 'snapshot'))
    now = stamp()
    reason, rc, clean, snapshot = (value[k] for k in ('reason_code', 'rc', 'cleanup_confirmed', 'snapshot'))
    require(type(reason) is str and type(clean) is bool and
            (rc is None or type(rc) is int and -255 <= rc <= 255))
    if reason == 'COMMAND_OK' or gap:
        require(clean and type(snapshot) is dict and (reason, rc) == (('PLATFORM_GAP', None) if gap else ('COMMAND_OK', 0)))
        require(not staged_openssl or not _uncertain(snapshot))
        if staged_policy:
            require(gap == (_platform_status(platform_snapshot) != 'UNVERIFIED'))
            _validate_staged_policy(snapshot, flags, platform_snapshot)
        if staged_ssh:
            require(gap == (_platform_status(platform_snapshot) != 'UNVERIFIED'))
            _validate_staged_ssh(snapshot, flags, platform_snapshot)
        precheck(producer, snapshot, flags, platform_snapshot, run_id, target, now)
    else:
        require(reason in FAILURES and snapshot is None and (reason != 'COMMAND_FAILED' or rc is not None and rc != 0)
                and (reason not in ('GUARD_REJECTED', 'CONTROLLER_TIMEOUT', 'INTERRUPTED')
                     or producer == PLATFORM or (staged_openssl and producer == OPENSSL)
                     or (staged_policy and producer == POLICY) or (staged_ssh and producer == SSH))
                and (clean or reason == 'REMOTE_CLEANUP_UNCONFIRMED')
                and (reason != 'REMOTE_CLEANUP_UNCONFIRMED' or not clean))
        require(not (staged_policy or staged_ssh) or reason in FATAL)
    return dict(producer_id=producer, observed_at=now, **copy.deepcopy(value))


def failed_record(producer, reason, rc=None, cleanup=False):
    return dict(producer_id=producer, observed_at=stamp(), reason_code=reason, rc=rc,
                cleanup_confirmed=cleanup, snapshot=None)


def record_stop(row, *, staged_ssh=False):
    if row['reason_code'] in FATAL:
        return row['reason_code']
    if row['snapshot'] is not None and _uncertain(row['snapshot']):
        # Only the exact staged SSH grammar, already checked at record/parent
        # boundaries, admits a confirmed EXECUTION_ERROR as a local halt.
        if not (staged_ssh and row['producer_id'] == SSH and row['cleanup_confirmed'] is True
                and _ssh_host_stop(row['snapshot'])):
            return 'REMOTE_CLEANUP_UNCONFIRMED'
    return None


def _host_local_stop(row, *, staged_ssh=False):
    return (staged_ssh and row['producer_id'] == SSH and row['cleanup_confirmed'] is True
            and row['snapshot'] is not None and _ssh_host_stop(row['snapshot']))


def _partition(producer, snapshot):
    """Exact producer+scope table, including only validated dynamic rows."""
    if producer == PLATFORM:
        return {s: PLATFORM for s in ('platform-info', *('tool-' + t for t in platform.TOOL_SLOTS),
                                      *('release-rpm-' + p for p in platform.PACKAGES))}
    if producer == OPENSSL:
        openssl_runtime.validate_snapshot(snapshot)
        p = snapshot['slots']['providers']['rows']
        require(len(p) <= MAX_PROVIDERS)
        return {**{'openssl-' + s: PACKAGES if s in openssl_runtime.PACKAGES else SSL for s in openssl_runtime.SLOTS},
                **{openssl_runtime.key('openssl-provider', r[0]): SSL for r in p}}
    if producer == POLICY:
        return {s: POLICY_FLAG for s in crypto_policy.SCOPES}
    if producer == SSH:
        ssh_posture.validate_snapshot(snapshot)
        return {**{'ssh-' + s: KEYS if s == 'keys' else SSHD for s in ssh_posture.BASE_SLOTS},
                **{'ssh-native-' + ssh_posture.digest('ctx', [c]): SSHD for c in snapshot['context_refs']}}
    require(producer == CERT)
    return {s: CERT_FLAG for s in cert_assets.ROOTS}


def _normalize(doc, host, producer, snapshot, source, observed_at, rules, flags, platform_snapshot):
    hid = host['host_id']
    if producer == PLATFORM:
        value = platform.build_platform_evidence(doc, hid, source=source, observed_at=observed_at, snapshot=snapshot)
        return _append(doc, value), {k: value[k] for k in ('platform_status', 'gap_reasons')}
    if producer == OPENSSL:
        return openssl_runtime.normalize_openssl(doc, hid, snapshot, source, observed_at, rules)
    if producer == POLICY:
        value = crypto_policy.build_crypto_policy_evidence(doc, hid, source=source, observed_at=observed_at,
                    snapshot=snapshot, rules=rules, platform_snapshot=platform_snapshot, requested=flags[POLICY_FLAG])
        return _append(doc, value), {k: value[k] for k in ('metadata', 'diagnostics')}
    if producer == SSH:
        return ssh_posture.normalize_ssh(doc, hid, snapshot, source, observed_at, rules)
    require(producer == CERT)
    value = cert_assets.build_cert_assets(doc, hid, source=source, observed_at=observed_at, snapshot=snapshot['roots'],
                    rules=rules, requested=flags[CERT_FLAG], platform_snapshot=platform_snapshot,
                    system_python_available=snapshot['system_python_available'])
    return _append(doc, value), value['details']


def _bind(doc, producer, host, snapshot, source, observed_at, detail):
    partition = _partition(producer, snapshot)
    rows = [c for c in doc['collections'] if c['collector_id'] == producer and c['host_id'] == host['host_id']]
    expected = {evidence.collection_id(doc['run']['run_id'], host['host_id'], producer, scope): scope for scope in partition}
    require(len(rows) == len(expected) and {c['collection_id']: c['scope_key'] for c in rows} == expected,
            'PRODUCER_SCOPE_MISMATCH')
    by_id = {c['collection_id']: c for c in rows}
    for c in rows:
        require(c['source'] == source and c['collector_version'] == VERSIONS[producer]
                and c['observed_at'] in (observed_at, None) and
                (c['observed_at'] == observed_at or c['collection_state'] == 'NOT_SCANNED'), 'PRODUCER_SOURCE_MISMATCH')
    for e in doc['evidence']:
        if e['collection_id'] in by_id:
            require(e['source'] == source and e['observed_at'] == observed_at, 'PRODUCER_SOURCE_MISMATCH')
    if producer == OPENSSL:
        require(len(detail) == len(expected) and {d['collection_id'] for d in detail} == set(expected), 'PRODUCER_DETAIL_MISMATCH')
        dynamic = {openssl_runtime.key('openssl-provider', r[0]): (r[0], r[2]) for r in snapshot['slots']['providers']['rows']}
        for d in detail:
            c = by_id[d['collection_id']]
            scope = c['scope_key']
            require((d['state'], d['reason']) == (c['collection_state'], c['reason_code']))
            if scope in dynamic:
                require(d['slot'] == 'providers' and (d['provider'], d['status']) == dynamic[scope],
                        'PRODUCER_DETAIL_MISMATCH')
            else:
                require(scope == 'openssl-' + d['slot'] and d['slot'] in openssl_runtime.SLOTS and 'provider' not in d)
            require(d['rc'] == snapshot['slots'][d['slot']]['rc'])
    elif producer == POLICY:
        ds = detail['diagnostics']
        require(len(ds) == len(expected) and {d['collection_id']: d['scope'] for d in ds} == expected,
                'PRODUCER_DETAIL_MISMATCH')
        require(all(d['state'] == by_id[d['collection_id']]['collection_state'] for d in ds))
    # SSH/cert mandatory paired validators already run in their normalizers.
    return {flag: [c for c in rows if partition[c['scope_key']] == flag]
            for flag in set(partition.values())}


def outcome(flag, enabled, state, reason, rc=None, ids=()):
    return dict(collector_id=flag, requested=enabled, state=state, reason_code=reason, rc=rc,
                collection_ids=sorted(ids))


def _aggregate(flag, enabled, rows, acquisition):
    ids = [c['collection_id'] for c in rows]
    states = [c['collection_state'] for c in rows]
    if not enabled:
        require(all(s == 'NOT_SCANNED' for s in states))
        return outcome(flag, False, 'NOT_SCANNED', 'DISABLED', ids=ids)
    if not rows:
        return outcome(flag, True, 'ERROR', acquisition['reason_code'], acquisition['rc'])
    if all(s in ('COLLECTED', 'NOT_APPLICABLE') for s in states):
        return outcome(flag, True, 'COLLECTED' if 'COLLECTED' in states else 'NOT_APPLICABLE',
                       'COLLECTED' if 'COLLECTED' in states else 'NOT_APPLICABLE',
                       0 if 'COLLECTED' in states else None, ids)
    if any(s in GOOD for s in states):
        return outcome(flag, True, 'PARTIAL', 'INCOMPLETE_COLLECTION', acquisition['rc'], ids)
    if all(s == 'NOT_SCANNED' for s in states):
        return outcome(flag, True, 'NOT_SCANNED', 'ADAPTER_NOT_AVAILABLE', ids=ids)
    if all(s == 'PERMISSION_DENIED' for s in states):
        return outcome(flag, True, 'PERMISSION_DENIED', 'PERMISSION_DENIED', ids=ids)
    if 'ERROR' in states:
        return outcome(flag, True, 'ERROR', 'COLLECTION_ERROR', ids=ids)
    return outcome(flag, True, 'UNKNOWN', 'UNKNOWN_RESULT', ids=ids)


class HostProjection:
    """Private validated projection, not a serialized authorization token."""
    def __init__(self, doc, outcomes, companions, p, special):
        self.document = doc
        self.outcomes = outcomes
        self.companions = companions
        self.provider_count = p
        self.special = special


def normalize_handoff(envelope, run_id, target, flags, started_at, rules, *,
                      staged_openssl=False, staged_policy=False, staged_ssh=False):
    """Bind actual typed snapshots to one frozen target, in fixed producer order.

    The optional private context comes only from the trusted staged session,
    never the handoff itself. The legacy synthetic contract is unchanged.
    """
    require(type(staged_openssl) is bool and type(staged_policy) is bool and type(staged_ssh) is bool)
    require(not staged_policy or flags[POLICY_FLAG] is True)
    require(not staged_ssh or (any(flags[f] for f in (SSHD, KEYS))
            and (staged_openssl or not any(flags[f] for f in (PACKAGES, SSL)))
            and (staged_policy or not flags[POLICY_FLAG])))
    shape(envelope, ('handoff_version', 'run_id', 'target_id', 'connection', 'records'))
    require(type(envelope['handoff_version']) is int and envelope['handoff_version'] == WIRE_VERSION
            and envelope['run_id'] == run_id and envelope['target_id'] == target)
    connection, records = envelope['connection'], envelope['records']
    required = requested(flags)
    require(bool(required) and connection in CONNECTIONS and type(records) is list and len(records) <= len(required))
    assessment.validate_rules(rules)
    host = host_record(run_id, target)
    doc = document(run_id, started_at, [host])
    outcomes = {f: outcome(f, flags[f], 'NOT_SCANNED', 'STOPPED' if flags[f] else 'DISABLED') for f in FLAGS}
    outcomes[PLATFORM] = outcome(PLATFORM, True, 'NOT_SCANNED', 'STOPPED')
    companions = {}
    p = 0
    if connection != 'CONNECTED':
        require(not records)
        state = 'UNREACHABLE' if connection == 'CONNECTION_FAILED' else 'ERROR'
        for f in (PLATFORM, *FLAGS):
            if outcomes[f]['requested']:
                outcomes[f] = outcome(f, True, state, connection)
        return HostProjection(doc, outcomes, companions, p, connection)
    require(bool(records))
    platform_snapshot = None
    special = None
    stopped = False
    previous_time = evidence._timestamp_key(started_at)
    now = evidence._timestamp_key(stamp())
    for index, row in enumerate(records):
        shape(row, ('producer_id', 'observed_at', 'reason_code', 'rc', 'cleanup_confirmed', 'snapshot'))
        producer, observed_at = row['producer_id'], row['observed_at']
        require(not stopped and producer == required[index], 'PRODUCER_ORDER_MISMATCH')
        evidence.STAMP.check(observed_at, '$handoff.observed_at')
        observed = evidence._timestamp_key(observed_at)
        require(previous_time <= observed <= now, 'PRODUCER_TIME_MISMATCH')
        previous_time = observed
        reason, rc, clean, snapshot = (row[k] for k in ('reason_code', 'rc', 'cleanup_confirmed', 'snapshot'))
        require(type(reason) is str and type(clean) is bool and (rc is None or type(rc) is int and -255 <= rc <= 255))
        fset = (PLATFORM,) if producer == PLATFORM else PRODUCER_FLAGS[producer]
        if staged_policy and producer == POLICY:
            require(platform_snapshot is not None and flags[POLICY_FLAG] is True)
        if snapshot is not None:
            require(clean and type(snapshot) is dict)
            if reason == 'PLATFORM_GAP':
                require(producer != PLATFORM and rc is None and _platform_status(platform_snapshot) != 'UNVERIFIED'
                        and snapshot == _gap_snapshot(producer, flags, _platform_status(platform_snapshot)))
            else:
                require(reason == 'COMMAND_OK' and rc == 0 and (producer == PLATFORM or _platform_status(platform_snapshot) == 'UNVERIFIED'))
            require(not (staged_openssl and producer == OPENSSL and _uncertain(snapshot)))
            if staged_policy and producer == POLICY:
                _validate_staged_policy(snapshot, flags, platform_snapshot)
            if staged_ssh and producer == SSH:
                _validate_staged_ssh(snapshot, flags, platform_snapshot)
            precheck(producer, snapshot, flags, platform_snapshot, run_id, target, observed_at)
            source = _source(producer, snapshot)
            doc, detail = _normalize(doc, host, producer, snapshot, source, observed_at, rules, flags, platform_snapshot)
            by_flag = _bind(doc, producer, host, snapshot, source, observed_at, detail)
            companions[producer] = detail
            if producer == PLATFORM:
                platform_snapshot = snapshot
            if producer == OPENSSL:
                p = len(snapshot['slots']['providers']['rows'])
            for f in fset:
                outcomes[f] = _aggregate(f, f == PLATFORM or flags[f], by_flag[f], row)
        else:
            if staged_openssl and producer == OPENSSL:
                require(platform_snapshot is not None and _platform_status(platform_snapshot) == 'UNVERIFIED')
            if (staged_policy and producer == POLICY) or (staged_ssh and producer == SSH):
                require(platform_snapshot is not None and reason in FATAL)
            require(reason in FAILURES and (clean or reason == 'REMOTE_CLEANUP_UNCONFIRMED')
                    and (reason not in ('GUARD_REJECTED', 'CONTROLLER_TIMEOUT', 'INTERRUPTED')
                     or producer == PLATFORM or (staged_openssl and producer == OPENSSL)
                     or (staged_policy and producer == POLICY) or (staged_ssh and producer == SSH))
                    and (reason != 'REMOTE_CLEANUP_UNCONFIRMED' or not clean)
                    and (reason != 'COMMAND_FAILED' or rc is not None and rc != 0))
            for f in fset:
                if f == PLATFORM or flags[f]:
                    outcomes[f] = outcome(f, True, 'ERROR', reason, rc)
            if producer == PLATFORM:
                stopped = True
        special = record_stop(row, staged_ssh=staged_ssh)
        stopped = stopped or special is not None or _host_local_stop(row, staged_ssh=staged_ssh)
    require(stopped or len(records) == len(required), 'MISSING_PRODUCER_RESULT')
    refs = [cid for r in outcomes.values() for cid in r['collection_ids']]
    require(len(refs) == len(set(refs)) == len(doc['collections']) and set(refs) == {c['collection_id'] for c in doc['collections']})
    caps = {PLATFORM: 10, PACKAGES: 2, SSL: 5 + p, POLICY_FLAG: 9, SSHD: 8, KEYS: 1, CERT_FLAG: 3, NGINX: 0, TLS: 0}
    require(len(refs) <= 38 + p and all(len(outcomes[f]['collection_ids']) <= cap for f, cap in caps.items()), 'PRODUCER_REFERENCE_LIMIT')
    evidence.validate_document(doc)
    return HostProjection(doc, outcomes, companions, p, special)


def validate_bindings(manifest, doc, companions, projections):
    """Exact association with previously validated outputs, not shape-only proof.

    Projections are trusted private in-process objects, never supplied by a
    serialized manifest. The final document/companions must preserve their rows.
    """
    evidence.validate_document(doc)
    require(doc['schema_version'] == '1.1.0' and doc['run']['run_state'] == manifest['run_state']
            and not doc['claims'] and not doc['findings'])
    rid = doc['run']['run_id']
    hosts = {h['target_id']: h for h in doc['hosts']}
    require(len(hosts) == len(doc['hosts']) == len(manifest['target_ids'])
            and set(hosts) == set(manifest['target_ids']) and set(companions) == set(projections)
            and set(projections) <= set(hosts))
    expected_rows = {k: [] for k in ('collections', 'assets', 'evidence')}
    for row in manifest['hosts']:
        n = row['target_id']
        require(hosts[n] == host_record(rid, n, row['host_state'], row['reason_code']))
        actual_outcomes = {r['collector_id']: r for r in [row['platform'], *row['collectors']]}
        actual = {k: v['collection_ids'] for k, v in actual_outcomes.items()}
        if n not in projections:
            require(not any(actual.values()), 'PRODUCER_REFERENCE_MISMATCH')
            continue
        p = projections[n]
        require(actual == {k: r['collection_ids'] for k, r in p.outcomes.items()}
                and companions[n] == p.companions and p.document['run']['run_id'] == rid
                and p.document['hosts'][0]['target_id'] == n, 'PRODUCER_REFERENCE_MISMATCH')
        # Preserve full trusted outcomes, except the original lifecycle rule
        # downgrading provisional UNREACHABLE when cleanup/reap is unconfirmed.
        for flag, expected in p.outcomes.items():
            current = actual_outcomes[flag]
            if (row['host_state'] == 'ERROR' and expected['state'] == 'UNREACHABLE'
                    and row['reason_code'] in ('CONTROLLER_CLEANUP_UNCONFIRMED', 'CONTROLLER_WORKER_FAILED',
                                               'CONTROLLER_TIMEOUT', 'OUTCOME_UNKNOWN', 'INVALID_NATIVE_RESULT',
                                               'INTERRUPTED')):
                expected = outcome(flag, True, 'ERROR', 'OUTCOME_UNKNOWN')
            require(current == expected, 'PRODUCER_OUTCOME_MISMATCH')
        require(len(actual[SSL]) <= 5 + p.provider_count
                and sum(len(v) for v in actual.values()) <= 38 + p.provider_count, 'PRODUCER_REFERENCE_LIMIT')
        for k in expected_rows:
            expected_rows[k].extend(p.document[k])
    for k, expected in expected_rows.items():
        key = {'collections': 'collection_id', 'assets': 'asset_id', 'evidence': 'evidence_id'}[k]
        def canonical_rows(rows):
            return sorted(({field: sorted(value) if field == 'evidence_ids' else value
                            for field, value in row.items()} for row in rows), key=lambda x: x[key])
        require(canonical_rows(doc[k]) == canonical_rows(expected), 'PRODUCER_EVIDENCE_MISMATCH')
    return None
