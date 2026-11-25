# Private native execution context and bounded batch (M0-07 S1/S2)

Issue #8 / proposal 7137701807 / dispatch 7138019670. This slice supplies an
internal controller context and a guarded native SSH command-construction
boundary. It is **not a live scanner or production release**. The reviewed S1 layer has
no command-line entry, production adapter, collector registry, report,
remote command runner or task scheduler. The existing launcher and its
12-field plan-only contract, fixed profile resolver, policy and rejecting
playbook stubs are unchanged. The S1 terminal boundary always rejects with
`LIVE_NOT_AVAILABLE`; a test-only instrument may observe the guarded boundary.

## Context and input boundary

The trusted internal caller selects the approved executable Inventory script
and supplies the same normalized request shape produced by `pqc_scan.py`.
The request is revalidated against the original scope parser, including
literal host/group selection, deduplication, limits and collector flags.
Public plan JSON, invented target lists, extra-vars and Active are not an
execution grant. There is no new supported invocation or user-configurable
adapter. All-disabled remains a valid passive decision, not scan success.

The exclusive worker uses the native InventoryManager, DataLoader and
VariableManager. It requires script-only/fatal parse settings to be in
place before importing Ansible, memory fact cache, trusted fixed plugins,
no extra-vars and no SSH agent in the S1 worker. The native script plugin's
command boundary is replaced only during the single inventory load with the
existing bounded command primitive: aggregate 30-second provider deadline,
32 MiB stdout budget and per-command bounded stderr, strict JSON and fixed
error reasons. Native `--host` fallback is allowed only once per host after
`--list`. The same native inventory/variable objects are retained. The
provider must be trusted not to detach; same-group child cleanup is checked.

The native graph is projected only into literal groups/hosts and relevant
flag/reserved fields; native effective variables retain precedence. The
original `resolve_targets` and `profile_plan` establish the fixed scope and
per-host decisions. Full hostvars, credentials, raw diagnostics, SSH options,
addresses and file paths must not be serialized or exposed to callers. The
private context stores only internal objects and returns no public grant.

## Native binding and guard

This candidate uses private Ansible APIs pinned to the development runtime
2.19.11. It constructs fixed native Play/Task objects, resolves a PlayContext,
and calls the native TaskExecutor option resolver on a built-in SSH
connection. No arbitrary play/task/role/collector can come from Inventory
or the request; no facts, delegation, local connection or become is allowed.
The fixed raw-task witness is never executed on a managed host in S1. Native
connection plugin `_build_command` constructs the actual SSH argv, and the
same connection object's `exec_command` enters the guarded `_run` boundary.
Preflight checks the whole target set before any boundary can be reached.
At the boundary, the native graph/flags/decisions, provider identity,
connection argv and effective SSH proof must agree with preflight. Any
missing proof, unexpected host or change is denied; S1's terminal stop does
not call the original native `_run`.

The initial compatible configuration subset is deliberately narrow: native
SSH only, trusted `/usr/bin/ssh` (or the same executable found via PATH),
explicit existing absolute `-F` configuration with a restricted literal
syntax, host-key checking enabled, bounded ConnectTimeout, BatchMode,
no persistent multiplexing, local commands, ProxyCommand, forwarding,
implicit Include/Match, password payload, inline private key, or unsafe
transport overrides. Literal ProxyJump intent and explicit identity paths
are supported candidates. The tool does not edit user/system configuration,
replace legitimate ProxyJump, install SSH or silently relax options. An
unsupported configuration is rejected with a fixed reason. This is not a
claim that every legitimate existing SSH configuration is supported. In
particular the Ansible default multiplexing options and implicit OpenSSH
config loading are not accepted in this candidate. The exact effective
OpenSSH configuration is intended to be checked using bounded native
`ssh -G` for the destination and jump hosts; without that native evidence
preflight must remain closed.

For the allowed explicit `-F` subset, the bounded validated raw bytes and
fingerprint are bound to a fresh private snapshot for each effective-config
proof. A worker-created 0700 directory and exclusive 0600 regular file under
the fixed trusted `/tmp` root hold the exact bytes (no re-rendering). No
Inventory, CLI or environment setting selects this snapshot path. Only the assessment's `-F` value is substituted, for the
destination and every ProxyJump consumer; the original native argv/path and
fingerprint remain in the connection binding. The existing absolute-path
and restricted syntax checks exclude Include, Match exec and relative
identity/known-hosts paths, so no new config-relative semantics are introduced.
At the native boundary, a changed original argv or fingerprint is denied
before re-evaluation. The source is checked before consumers and at completion.
Persistent source drift denies the proof; even if a transient edit is restored, a child
can read only the validated snapshot, never the edited original pathname.
Snapshots are removed before proof return, including on rejection, exception
and bounded-command timeout; creation or reported cleanup failure denies the
proof. This assumes the original trusted controller worker/UID and system
paths, not hostile code with its privileges or cleanup after SIGKILL.
The S1 layer alone does not assert a 15-second complete
handshake/chain deadline or 30-second remote command termination. S2 below
implements and exercises those bounds on the restricted synthetic path. It also cannot guarantee DNS aliases are never local,
configuration files cannot be changed by the trusted controller administrator,
or arbitrary plugins/provider code cannot bypass the trust boundary.

## Development verification and current limitation

Use the approved isolated R1 development runtime, no network, test-only
synthetic inventory, no real SSH or production credentials:

```
python -I -B -m pytest -q -rs -p no:cacheprovider tests/integration/test_batch_context.py
python -m py_compile tools/batch_execution.py tests/integration/test_batch_context.py
```

The focused tests include inline/lookup native context, native group/host
vars, change-on-second-load trap, literal scope and profile precedence,
provider error/duplicate/output/timeout/residual process rejection, forged
request, native option rejection, actual fake SSH subprocess positive
control and a test-only instrumented native `_run` boundary. The latter
substitutes only the unavailable OpenSSH effective-config proof; it is not
a proof of actual OpenSSH option consumption. A separate required test must
exercise real `ssh -G` on the synthetic configuration and then the guarded
native boundary. If OpenSSH is absent, the test confirms fail-closed and
records NOT_TESTED; this is an S1-02 HOLD, not a successful S1 acceptance.
The validated-snapshot cases use actual bounded synthetic child file reads
at each destination/jump consumer, test permanent and transient edits and
verify byte-for-byte input, mode, unchanged argv options/order, cleanup and
fail-closed behavior. The native guard case retains the actual Ansible
context/argv and terminal `_run` stop while substituting synthetic `-G`
records and the fixed-binary availability check in the test only. These
cases do not replace the required real OpenSSH effective-config proof.
The existing plan-only CLI gets one directly relevant synthetic check; no
historical full-suite rerun is required. Any release/production validation
remains Issue #28. Owner-approved restricted development (A/B/C, 7143603231)
and fixed-N S1 R2 PASS allow the separately dispatched S2 work (7148366223).
They do not close the original real SSH proof or compatibility gap.

## S2 private execution API (B04-B06)

The supported internal integration seam is deliberately small:

```python
# Existing trusted, normalized S1 request; never a serialized READY plan.
ctx = _Context(approved_inventory_script, normalized_request)
rc, manifest = execute_batch(ctx)
validate_terminal_manifest(manifest, rc)  # returns None or raises Denied
```

A context is single-use for execution. The caller must be the exclusive
trusted Linux controller worker, not an arbitrary thread or external JSON
consumer. Reuse the original InventoryManager, DataLoader and VariableManager;
never reload the inventory or derive targets from a callback. The target
set, request, flags, resolver decision and source identity are rechecked.
Preflight Denied(2/3/4) is a rejection, not a successful or partial run.
The fixed `_passive_adapters()` registry is empty in the shipped S2 core;
`_restricted_connection()` always rejects live execution. With no eligible
adapter, the invocation returns rc 6, all hosts NOT_ATTEMPTED, and
NO_EXECUTABLE_COLLECTORS. No environment, Inventory, CLI or manifest field
can register a callable, choose an arbitrary command, or authorize SSH.
The public plan-only launcher and both playbook rejection stubs are unchanged.

The isolated tests replace those two private functions with fixed synthetic
implementations, and substitute the unavailable real OpenSSH proof with a
synthetic proof. This does not create a production adapter, a real transport
or a supported override. There is no attempt to turn S1's fixed stop into
an SSH authorization. S1 `_boundary()` and `_stop_s1()` are retained. The
actual native argv consumer is guarded again before the restricted witness
can enter the private adapter bridge. The original SSH `_run` is never
called. An invalid connection/task/host, altered argv, source, flags or
proof rejects the dispatch. There is no localhost transport fallback.

### Native scheduling and resource contract

The private fixed-task driver uses core 2.19.11 TaskQueueManager and the
actual StrategyBase `_queue_task`, native WorkerProcess and TaskExecutor,
with a fixed raw witness `:` and the built-in SSH command constructor.
It does not run a general PlaybookExecutor, arbitrary playbook or strategy
result thread. The driver owns the bounded waves and closed native result
queue. Each wave has at most `min(forks, 2)` selected eligible targets;
workers are joined/reaped before the next wave. Frozen manifest targets
include every expected host, even if no adapter is eligible for it. The
native task/variable resolution and guards do not use a second Inventory.
The worker's connection guard checks the consumed task and instance as
well as the actual command argv; the only successful restricted witness
returns a typed host result from the synthetic adapter bridge.

- At most 10 targets, forks 1 or 2, serial 2. Provider cap: 30 s, original
  bounded S1 output and cleanup. The initial native projection (including
  no-adapter/all-disabled cases) and whole-context preflight each have a
  30 s cap. Parent guard, task variable construction, native scheduler
  setup and queueing each use a bounded phase capped by the remaining
  aggregate and outstanding worker deadlines. Actual child guard: 30 s.
  Before-dispatch projection/preflight expiry is a Denied(3) rejection;
  caught cancellation produces rc 7 without inventing a host attempt.
- One restricted connection phase per attempted host, 15 s aggregate,
  not 15 s per stage or jump. A timeout reported by a trusted synthetic
  connection with confirmed cleanup is CONNECTION_TIMEOUT; a controller
  deadline without that receipt is REMOTE_CLEANUP_UNCONFIRMED.
- Each eligible passive collector is called at most once (no retries).
  Command deadline 30 s, including remote-side termination grace. The
  trusted adapter must use the bounded runner; controller return is
  additionally limited to 31 s. A missing return is not remote proof.
- Per-worker budget is `30 + 15 + 31 * eligible_slots + 2 + 5` seconds.
  The absolute invocation budget is anchored before initial projection:
  60 s plus the sum over eligible hosts of `60 + worker_budget`, plus 5 s.
  Each scheduler phase and poll is also constrained by the earliest
  outstanding worker deadline. A callback never cancels that deadline;
  the exit grace is at most 2 s and cannot extend it. The deliberately
  conservative aggregate sum is independent of observed parallelism.
  Local TERM/KILL/join is bounded to 2 s per cleanup attempt; a final
  cleanup attempt may follow an uncertain receipt. Owned queue/lockfile
  closure is separately bounded. Native fork receipt publication is a
  narrow trusted critical section: cancel/expiry is latched until the
  receipt can be recorded, then no more work is dispatched. These are
  engineering limits for the trusted runtime, not hard real-time OS
  guarantees or proof of remote termination.
- Native worker result IPC is closed and limited to 3500 bytes per
  message, including the target/task identity. Only the fixed typed result
  may cross it; arbitrary callback diagnostics, prompts, raw stdout/stderr,
  hostvars and task objects are not serialized as batch results. Queue
  input is checked again on receipt. Foreign, duplicate, out-of-order,
  malformed, missing or inconsistent results stop new dispatch. A valid
  callback is provisional until normal exit, join/reap and absence of
  residual process groups are observed within its limits. One lifecycle
  check drains callbacks and checks worker exits, grace and deadlines
  before new dispatch, after guard/vars and at the actual native fork
  boundary, and while waiting. Already observable faults prevent further
  forks. Native queue errors after a real fork retain ownership and the
  actual attempted host; a queue failure before fork is not an attempt.
- SIGINT/SIGTERM stop new dispatch and trigger bounded controller cleanup.
  Install cancellation before the first projection; restore signal
  handlers, timer, mask and subreaper state on exit. Do not replace an
  externally installed interval timer.
  Major guard, unknown remote cleanup, invalid result and controller
  worker/deadline/cleanup faults also stop new dispatch. Ordinary confirmed
  per-host collection or connection failure does not stop remaining hosts.
  No claim is made that killing the controller or its transport terminates
  a remote command.

### Independent remote-side primitive

`pqc_bounded_execution.run_bounded(argv, *, timeout_s=30)` is a private
module_utils helper, not a module or public command service. Its canonical
Collection and standalone mirror are identical. A trusted adapter uses
fixed installed absolute argv, no shell, no Inventory-derived command,
no daemon/detach, no privilege elevation. The runner is foreground,
dedicated, Linux, single-threaded main process. It rejects malformed argv,
more than 32 arguments or 8192 encoded bytes, non-finite/unapproved budgets,
and limits narrowed by trusted code only (0.5 to 30 seconds).

It measures its own monotonic deadline without a heartbeat; a child starts
in its own process group with minimal environment and no input. A selector
reads combined stdout/stderr at a hard 16 KiB total limit (overflow fails,
never returns truncated success). Reserve up to one second within the
budget for TERM, a maximum 0.25 s TERM grace, KILL, and direct/adopted
same-group descendant reap. A Linux subreaper verifies leader exit and
absence of the group. Residual descendants after leader exit fail even
if rc was zero. A cleanup failure returns REMOTE_CLEANUP_UNCONFIRMED,
`cleanup_confirmed=False`; no output is accepted as success. Only
COMMAND_OK has usable stdout/stderr, and its rc must be zero. The returned
`CommandResult` has `reason_code`, `rc`, `stdout`, `stderr`,
`cleanup_confirmed`. The trusted collector converts that receipt to a
closed typed result, not raw data in the terminal manifest. There is no
retry, install, modification or general-purpose sandbox. A malicious
program that detaches/moves groups, a killed worker, inaccessible OS or
machine failure is not proven safe by this primitive. Actual SSH chain,
remote worker survivability and termination on OL must still qualify
before any real transport/adapter becomes available.

### Terminal manifest v1

A successful preflight yields a single in-process `(rc, manifest)` result;
the fixed top-level keys are exactly:

| Key | Contract |
| --- | --- |
| batch_manifest_version | integer 1 |
| target_ids | sorted unique literal selected names (1..10) |
| target_count | exact length of target_ids |
| limits | max_hosts, forks, serial=2, ssh_timeout_s=15, command_timeout_s=30 |
| profile | baseline or extended |
| run_state | COMPLETE, PARTIAL, ERROR |
| reason_code | fixed run outcome or stop reason |
| hosts | one terminal row per target in target_ids order |

Each host has exactly `target_id`, `host_state`, `attempted`, `reason_code`,
`collectors`. The eight collector rows are sorted by fixed legacy flag ID;
each has exactly `collector_id`, `requested`, `state`, `reason_code`, `rc`,
`collection_ids`. `requested` is the frozen effective Boolean, not a
claim of execution. rc is null or a bounded signed process result; collection
references are sorted distinct `c-` + 64 lower-case hex, at most 8 per slot
and 16 per host, globally nonduplicate and subject to the message bound.
The synthetic adapters have empty references. Store/Evidence integration
must verify actual source documents and refs; this shape validator alone
cannot establish authenticity or scan authorization.

Host COMPLETE requires all requested slots to be COLLECTED or evidenced
NOT_APPLICABLE. A valid acquisition plus a gap is PARTIAL. Attempted without
valid acquisition is ERROR, and unconfirmed cleanup overrides partial data
and remains ERROR. Only a confirmed connection failure yields UNREACHABLE.
No dispatch is NOT_ATTEMPTED. Disabled slots are NOT_SCANNED/DISABLED;
requested unavailable/stopped slots remain NOT_SCANNED with a fixed gap.
There is no active TLS dispatch. Native result association uses the exact
started host and task UUID. A started worker with no acceptable terminal
result is ERROR/OUTCOME_UNKNOWN (or a more specific fixed stop reason),
never inferred UNREACHABLE or COMPLETE. If a worker reports then exits
abnormally, validated slot observations may be retained but not its
provisional successful host state. In particular, a provisional connection
failure becomes an attempted ERROR with the controller fault reason if
normal worker exit or cleanup is unconfirmed. Its requested UNREACHABLE
rows become ERROR/OUTCOME_UNKNOWN with null rc and no references; disabled
rows and genuine other observations retain their typed semantics. No raw
collector data, stderr, transport
addresses, credentials or exceptions are part of this manifest.

| rc | Result |
| --- | --- |
| 0 | Normal completion, nonempty and all hosts COMPLETE |
| 5 | PARTIAL (one or more COMPLETE/PARTIAL hosts, not complete) |
| 6 | ERROR, no COMPLETE/PARTIAL host (including zero dispatch) |
| 7 | Caught SIGINT/SIGTERM, priority over 5/6; never run COMPLETE |

All summaries derive from actual terminal rows. The validator recomputes
run state/rc and checks the closed shape, flags, counts and unique refs.
A stop reason is independent of host coverage. This is a synthetic batch
result contract, not Evidence, scan readiness, report storage, a recovery
journal, a release QA verdict or an alternative live entry point. #9 S2
and #57 I1 may consume the actual API only after the required Planner/Owner
integration decision; no storage or producer integration is implemented.

### Focused S2 verification and limits

```
python -I -B -m pytest -q -rs -p no:cacheprovider tests/integration/test_batch_context.py tests/integration/test_batch.py
```

The original S1 test file is unchanged. New tests exercise the actual
native worker queue, short/FQCN loader and syntax/isolated execution, observed
fork overlap and waves, 10/11 host limit, confirmed synthetic connection
failure, all-disabled/unavailable adapters, callback/worker failures, caught
signals, and a separate remote surrogate whose command survives transport
loss until its own 30-second deadline and reaps child/grandchild processes.
The R1 lifecycle regressions retain all original tests and exercise native
fork barriers, abnormal exit with/without a callback, callback followed by
an earlier individual deadline or exit grace, initial native projection
timeout/cancellation with or without eligible adapters, scheduler setup
and partial-start failure, timer/handler restoration, and uncertain cleanup
of a connection-failure callback. Faults are injected only in trusted
synthetic tests, including reported cleanup uncertainty after actual safe
reaping. The two-stage connection surrogate exercises the full 15-second budget.
Both are synthetic proof, not real OpenSSH qualification. Actual fixed-path
`ssh -G` evidence and implicit/Include/multiplexing compatibility remain
HOLD; real SSH transport and live execution remain hard closed. Actual
Controller/OL9.7-9.9, legitimate native SSH/ProxyJump, remote lifetime,
performance and offline deployment are required release QA (#28).
