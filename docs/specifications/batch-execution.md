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

### B compatibility candidate (Draft PR #70, R2 review pending)

The B candidate retains native SSH only, trusted `/usr/bin/ssh` (or the
same executable found via PATH), the private Ansible context and the hard
transport stop. It validates the raw option vectors and native control-path
options before the actual builder, binds them separately from the consumed
argv, and makes a private per-Connection normalization to
`ControlMaster=no`, `ControlPersist=no`, `ControlPath=none`. Normalization
precedes `_build_command` on the retained connection and actual native
worker; raw drift is denied even when normalized argv would be unchanged.
The temporary private connection options are restored after the builder.
This does not inspect, connect to, remove or create a mux socket or directory
or change the operator's Ansible/SSH configuration.

An explicit absolute `-F` keeps its native root-selection semantics. The
candidate closure reads only bounded regular files using directory-relative
no-follow opens, validates literal nonexecuting syntax before native
parsing, and fingerprints file identity and bytes, ordered Include edges,
absence and glob enumeration. Limits are 32 regular files, depth 8,
256 KiB aggregate and 64 KiB per file. The local conservative implementation
also bounds expansions to 32 and enumerated directory entries to 256;
accepted literal ControlPersist durations, including compound literals
validated against the native parser, are at most seven days. The latter
are provisional conservative implementation choices, not broader
compatibility guarantees. Safe absolute Include paths and relative Include
source roots are restricted; lexical globs are evaluated in verified C-like
locale, and `Match final all` is the only admitted Match form. Unknown
syntax, arbitrary links, unsafe owners/modes, commands and host-key
downgrades remain denied. No source bytes or native output enter the
terminal manifest.

Each proof uses a new 0700 private `/tmp` directory and exclusive 0600
regular files. The simple explicit source remains byte-exact; the closed
Include graph uses private filenames preserving order and source scope.
The implicit composition uses ordered user then system sources. The
qualified-client synthetic source-selection oracle retains native first-set
precedence, Include roots and Match final reparse semantics. A no-mux prelude applies to every
snapshot consumer when needed. Bounded `ssh -G` checks destination and
successive literal ProxyJump children with the same snapshot, including
child port/user and remaining jump prefix. Every consumer checks the
original closure fingerprint, and the proof checks it again before return.
Restored transient changes cannot change the private consumer bytes and
now also deny on changed source identity. Creation, drift or reported
cleanup failure denies; this retains the existing trusted UID assumptions.
The per-consumer timeout is at most five seconds and remaining guard time.

Implicit source qualification uses private, explicit client-source
contracts. The development contract is the exact Debian amd64
`openssh-client` package `1:10.0p1-7+deb13u4` (package SHA-256
`8fff343654f86c3b3266f94cd338c7b4da2e386da029327815118ea00bce03b9`;
original signed-package evidence in Issue #8, comment 7140990021).
The 1,047,584-byte ELF has SHA-256
`af3b04ec5653755032fc18ad02445e4e51170e75d8bac4265647d423caa9a83e`.
The same package supplies `/etc/ssh/ssh_config`, `ssh(1)` and
`ssh_config(5)`. Its shipped manuals identify the passwd-home user
configuration, the system configuration and first-set order; the shipped
configuration is part of that package evidence. This is a build identity
contract, not a version-string or OS-minor-version inference. The fixed
client must pass owner/mode, no-follow identity, exact-size and digest
checks; the qualified build, binary identity and native passwd-home
source selection enter the closure fingerprint. Unknown or changed
clients fail closed (`SSH_IMPLICIT_ROOT_UNQUALIFIED`). There is no product
binary or root override.

For Oracle Linux 9, the installed-package contract uses the trusted local
OS/admin and RPM database rather than a per-release ELF allowlist. Oracle's
client configuration documentation identifies the system and per-user
configuration entries. Oracle ELSA-2026-13381 (8.7p1) and ELSA-2026-19219
(9.9p1) identify the official package families; Oracle Linux 9 documents
RPM 4.16 with SQLite. This is not an inference from the managed host OS or
an assertion that every Oracle package has been independently verified.
The controller's fixed `/etc/os-release` (regular or stock link to
`/usr/lib/os-release`) must identify `ol` major 9. The fixed `/usr/bin/ssh`
and `/usr/bin/rpm`, standard system `rpmrc` and macros, and `/var/lib/rpm`
SQLite database and known sidecars must have trusted ownership, no-follow
identity and non-writable-by-other-users modes. A fixed, sanitized, bounded
`rpm -qf` query of `/usr/bin/ssh` uses the fixed DB path, explicit system
macro inputs, SQLite backend and no plugins; no verify scripts, package
inventory dump, installation, network, user macro or caller-controlled
path is used. The query returns one package's typed file metadata, not
contents of its other files. Exactly one `openssh-clients` package must
match Oracle America, the 8.7p1 or 9.9p1 version family, EL9 release,
controller architecture, valid epoch and matching `openssh` source RPM.
The package must record the system config and exactly one SSH binary,
whose size and SHA-256/384/512 file digest must match the selected bytes.
Executable reads are bounded to 16 MiB, OS identity to 16 KiB, system
macro input files to 256 KiB each; query output is bounded to 64 KiB per
stream and at most 256 file rows. One query has at most five seconds
within the existing remaining guard, reserving cleanup time. The actual
OS, tool, DB/sidecar and binary identities and validated package metadata
enter the original closure fingerprint. A destination/jump proof reuses
only the metadata for the same freshly rechecked state; each new proof
and dispatch qualifies afresh, without a TTL or per-hop RPM process.
Unknown, changed, unsupported or ambiguous state fails closed. The local
RPM database is trusted OS inventory, not independent package-signature
attestation. Actual installed OL9 binary, RPM/DB and complete stock
configuration qualification remain formal-environment NOT_TESTED.
Public source references:
- https://linux.oracle.com/errata/ELSA-2026-13381.html
- https://linux.oracle.com/errata/ELSA-2026-19219.html
- https://docs.oracle.com/en/operating-systems/oracle-linux/openssh/openssh-ModifyingOpenSSHServerConfigurationFiles.html

Only the OS-managed SSH and crypto-policy roots (`/etc/ssh`,
`/etc/crypto-policies`, `/usr/share/crypto-policies`) may supply a
qualified file symlink. Production traversals require root-owned,
non-group/world-writable directories and final regular files; links
require trusted owner, single link and pinned parent, and include their
identity and literal target in the graph. Crypto-policy link targets
are restricted to client `openssh.config` and `openssh.txt` names.
Absolute targets or unambiguous relative targets with leading parent
components must remain in the same closed set of managed roots. Directory
symlinks, cycles, dangling or foreign targets, unsafe owner/mode and
secret-name paths are rejected before any native parser. Link traversal
is bounded to eight hops and 32 total link traversals per closure without
increasing the existing Include expansion, bytes, files or guard limits.
The native consumer receives the validated regular-file bytes in the
same private snapshot, not the original link. Link and target identity
or byte drift invalidates the proof, including retarget-and-restore.

Stock configuration qualification admits `SendEnv` solely as a syntax
and effective-pattern proof. The same validator checks the entire closure,
raw option groups and actual consumed `-o` argv. Literal names are LANG,
LANGUAGE, LC_ALL, LC_CTYPE, LC_NUMERIC, LC_TIME, LC_COLLATE, LC_MONETARY,
LC_MESSAGES, LC_PAPER, LC_NAME, LC_ADDRESS, LC_TELEPHONE, LC_MEASUREMENT,
LC_IDENTIFICATION, COLORTERM, NO_COLOR and XMODIFIERS, plus exactly the
LC_* pattern. The same allowed names/patterns may have a leading `-`
for native removal semantics. Preserve order, duplicates, Host/Include
and Match final behavior; do not expand patterns or consult local values.
At most 32 tokens per directive, 128 per expanded closure and 128 across
consumed option groups; unknown names/wildcards, interpolation, assignment,
SetEnv and malformed syntax remain denied. `HashKnownHosts` admits only
native yes/no. Both settings are included in the actual destination and
jump effective proof and raw/source drift detection. The `-G` proof child
has a fixed minimal environment, does not inherit the caller's environment,
does not send any variables and does not read or write known_hosts contents.
HashKnownHosts does not authorize a host-key policy downgrade or any write.
Unapproved `GSSAPIAuthentication` is rejected for all values and keyword
case variants, including in `-o`, Includes and inactive Host blocks; it is
not ignored or normalized to `no`. Configurations containing it, including
otherwise valid stock configurations, remain outside the admitted syntax.
The two prior same-package stock defects are covered by real `-G` comparison
with the validated snapshot. The OL9 engineering route is tested using
synthetic typed RPM metadata through a real bounded local process and the
approved actual native client; this does not claim an OL9 ELF/RPM execution
or full stock configuration coverage. The fixed product client entry and
actual Controller configuration remain NOT_TESTED pending release QA.

Arbitrary symlinks, unsafe Includes, Match exec, external commands,
forwarding, unknown directives and unsupported syntax remain denied.
No adapter/live grant is added. A future real transport must consume the
same private closure while its files remain alive, prove a safe exact
minimal environment for the destination and every jump (the LC_* pattern
is not an arbitrary environment transmission grant), and validate
known_hosts/host-key verification and write side effects independently.
This candidate still cleans up before returning proof and retains
`LIVE_NOT_AVAILABLE`. Engineering delivery is not independent review,
formal OL support or release acceptance.

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
The B tests additionally exercise native parser field equivalence (except mux),
ordered closure, caps and denials, retained connection and native synthetic
worker consumption, and raw-option drift. The source-qualification tests
exercise the real digest/identity resolver with the approved native ELF,
unknown/changed builds, passwd-home selection, absent-root and late
binary drift; managed-link fixtures exercise the same bounded resolver
with controlled owner and roots, including native worker consumers and
retarget/target drift. A private verified client path is a test-only seam,
not a product fixed-path proof. The two identified SendEnv/HashKnownHosts
stock defects are resolved at the engineering level. The B candidate is
pending R2 review; complete official OL9 stock configurations, the installed
client path and actual Controller qualification remain NOT_TESTED.
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
integration decision. No storage is implemented in this module. The
separately approved I1a private producer-aware path is described below;
it does not change the V1 contract.

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
Both are synthetic proof, not real SSH transport qualification. The B
candidate has controlled-source native parser/builder evidence and the two
identified stock directive corrections; R2 review remains pending. Complete
official OL9 stock configuration, installed-path and actual Controller
qualification remain NOT_TESTED.
Actual fixed-path `ssh -G` and real SSH transport remain unqualified; live
execution remains hard closed. Actual
Controller/OL9.7-9.9, legitimate native SSH/ProxyJump, remote lifetime,
performance and offline deployment are required release QA (#28).


## I1a private Producer-aware V2 (R2)

The separate `execute_producer_batch(ctx, rules)` entry point uses the
same frozen context and native scheduler/guard/worker lifecycle. The real
producer registry and real transport remain closed. It returns
`(rc, manifest, bundle)` for the restricted synthetic path only. The V1
`execute_batch(ctx)` path and its V1 validator/8-per-slot/16-per-host
reference limits remain unchanged; V1 never consumes a V2 receipt.

See [collector integration](collector-integration.md) for the closed V2
outcomes, exact producer-scope/Evidence association, R2 5+P/38+P capacity,
and private typed-handoff contract. The native IPC is still at most 3500
bytes per message; it carries a small length/hash/identity receipt rather
than collection references or typed projection bytes. The private
0700/0600 per-host slot has a hard 1 MiB cap and ten hosts have a hard 10 MiB
aggregate cap. The original 16 KiB raw command output limit is independent.
No raw output, arbitrary paths, snapshot, or assessment is added to IPC.

Only confirmed normal worker reap and validated receipts establish a safe
terminal. Duplicate receipts invalidate that host terminal while preserving
validated observations, and stop subsequent dispatch; a malformed receipt
never becomes Evidence. The V2 close/final normalization phases remain
bounded, including caught interrupt handling. Platform prerequisite is
separate from the eight flags and is not counted as requested-scan success.
V2 is not a public CLI, a V1 fallback or a persistent store interface.
The restricted Platform P2 extension is below; other I1b/I2 work and
formal compatibility/security/release qualification remain separate,
with no live opening.


### I1b Platform P2: bounded stage execution

The fixed private Platform stage type extends only the restricted V2
native worker path (#7169477310, #7169696850). The original native raw
COMMAND witness still intercepts `_run` exactly once and never invokes
original SSH. No public driver, path, host, argv, command, timeout or
transport selector; no new requested flag. V1, its manifest validator and
old single-call synthetic producers keep their original budgets and
reference limits. Both real registries are empty and
`_restricted_connection` remains a hard deny. See [collector integration](collector-integration.md) for exact order, gating and bound receipt shape.

Before every fixed stage, use the same actual native host/task UUID,
no-log/no-become context, frozen Inventory projection/source identity,
preflight native bindings and effective SSH proof, and recheck the actual
consumed connection/raw argv. Packaging and these checks share one guard
budget; after the bounded synthetic connection witness, recheck immediately
before the one-use launch gate. Do not call a second raw witness, reload
Inventory, change SSH settings, enable mux, or run original SSH `_run`.
Any observed identity/guard drift denies subsequent launch.

Fixed seconds: G=30 guard (including packaging), S=15 connection,
C=30 independent target command (including cleanup), return=1,
worker exit grace=2. Each stage has at most G+S+C+1=76 seconds. Three
stages plus one cumulative 30-second Platform validation allowance give
258 seconds for the explicit staged Platform producer, not for an
individual command. Metadata operations share one P1 stage deadline;
inner RPM27s and independent outer30s stay unchanged. All other producer
budgets, including the legacy single-call Platform, remain 31 seconds.
The host budget remains G+S+sum(producer budgets)+grace+5; at all five
producers the staged maximum is 434 seconds. The absolute invocation
budget remains 2G+sum(2G+host budget)+5 (5005 seconds for ten such hosts).
These are conservative scheduling bounds, not elapsed-time guarantees;
the existing bounded teardown/final validation is separate.

Per-stage and cumulative validation deadlines take the minimum of their
own fixed end, host and producer end, invocation end and current wave
limit. A launch must have room for the complete independent 30s plus 1s
return. The private shared-memory wave lease has bounded lock acquisition,
controller-owned stop and per-active-worker deadline slots and a pending
stage marker. It is not external configuration or a new persistent wire.
Controller synchronizes the earliest outstanding worker and exit grace,
including immediately after a validated receipt, before further receipt
normalization. Active worker slots only decrease until confirmed normal
exit; removing a confirmed peer never extends an already started phase
or command deadline. A worker checks the current lease before every
stage and at its one-use launch gate, then checks completion before the
original command end. The controller enforces the earliest outstanding
limit even while a peer is blocked in a stage. Insufficient time denies
launch rather than granting a new interval. The existing fork barrier,
active phase shortening, external/nested timer rejection, SIGINT/SIGTERM
priority, RC5/6/7 and signal restoration remain. A stop does not authorize
late normalization or a subsequent successful terminal.

P1 `start_new_session` creates a separate target command group; a normal
Controller WorkerProcess exit or `_stop_workers` cannot certify its cleanup.
The trusted local engineering launcher uses actual native AnsiballZ
packaging and an independent supervisor in a separate session with P1's
unchanged bounded helper. On consumer loss, controller cancellation or
peer stop, do not kill the only target cleanup supervisor. The pending
marker is cleared only on independently verified matching completion and
cleanup; a missing, foreign or uncertain completion remains fatal, even
when the Controller group has exited. The controller does not wait for a
late receipt to turn that host into success. Tests independently reap all
owned local supervisors and verify descendant group disappearance, including
shortened test-only timeout, actual WorkerProcess loss, caught interrupt
and peer fatal stop. Local surrogate cleanup is not proof of real remote
SSH transport or crash/power-loss cleanup. Real transport and formal
Controller/OL9.x safety, performance and offline qualification remain
closed/NOT_TESTED (#8/#17/#28).
