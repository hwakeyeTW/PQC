# I1a — private producer-aware bridge (R2)

Scope: #57 I1a, approved R1 and capacity correction R2 (#7155598677,
#7155636533). This is an internal Controller-only synthetic integration,
not an acquisition adapter, public scan CLI, storage format, live grant or
release qualification. The real registry is empty and the original SSH
transport is never called. The I1b Platform P2 restricted extension is
described below; other I1b acquisition and I2 have separate acceptance work.

## Entry points and frozen context

The caller owns an exclusive trusted Linux Controller process and the
existing validated native `_Context`, constructed from the approved
Inventory script and normalized request. The original V1
`execute_batch(ctx) -> (rc, manifest)` and `validate_terminal_manifest`
remain V1-only; neither consumes the V2 envelope. I1a exposes a private
`execute_producer_batch(ctx, rules) -> (rc, manifest, bundle)`, where rules
are a trusted in-process copy of the existing #11 rules. No adapter,
transport, scratch path, task, argv, host list, P value, raw evidence or
registry is taken from serialized input. Context use is single-shot.

The fixed producer order is `pqc-platform`, `pqc-openssl-runtime`,
`pqc-crypto-policy`, `pqc-ssh-posture`, `pqc-cert-assets`. The platform
prerequisite is not a ninth user-selectable flag. Only producers needed by
the original eight flags are eligible; platform is first for a host with
an eligible request. The required registry for the entire frozen batch
must be available before preflight/connection. Missing required adapter,
Active or requested unsupported nginx/TLS is a rejection, not a fallback
or zero-scan success. All-disabled produces no dispatch, even for platform.
`_producer_adapters()` is deliberately empty; positive tests substitute
trusted fixed synthetic code only. Existing `_restricted_connection`
remains the hard real-transport stop.

Platform facts/tools/release RPMs are normalized first. A validated
out-of-scope or unknown platform causes the relevant existing producer gap
projections, without invoking subsequent acquisition surrogates. A failed
platform receipt cannot authorize later producers. The original per-producer
closed snapshot validators, flags, platform status, Q/T safety gates,
timestamps, data limits and reasons apply. Real per-tool acquisition
eligibility and the bounded per-command acquisition of a production adapter
are I1b responsibilities. The fixed Platform P2 stage bridge below is
restricted to trusted synthetic execution; a synthetic result is not
evidence of actual managed execution or OL support.

## Typed handoff and lifecycle

A trusted test adapter returns only `{reason_code, rc, cleanup_confirmed,
snapshot}` for a fixed producer. Snapshot is its existing closed typed
projection; cert uses `{system_python_available, roots}`. No arbitrary raw
output or task output is retained. The worker records an actual UTC
observation time, validates the projection against the original producer
validator and records a constant failure if the projection or execution
receipt is invalid. The parent revalidates the projection and performs the
actual normalization; times must be within this run's start/current-time
interval and nondecreasing in producer order. Source is `SYNTHETIC`, fixed
producer ID/version/origin, and SHA-256 of canonical typed snapshot bytes.
No managed host or official provider/transport claim is inferred.

`handoff_version=1` envelope has exactly `run_id`, `target_id`, `connection`,
`records` and the version. Each record has `producer_id`, `observed_at`,
`reason_code`, `rc`, `cleanup_confirmed`, `snapshot`. Order is the exact
eligible sequence, with omissions permitted only following an explicit
stop; a connection failure has no producer records. The parent derives P
and all refs only after receipt and typed validation. JSON is closed,
canonical ASCII, bounded in bytes/depth/nodes; duplicate keys, unexpected
fields, malformed strings, PEM/template/control data, invalid numbers,
missing/foreign identities and excess data are rejected. This is not a
general DLP guarantee: allowed logical metadata can still be sensitive.
Treat snapshots, companions and reports as private.

One Controller-owned private 0700 directory in trusted local scratch is
created per invocation; each eligible frozen target has one generated
0600 regular slot with an exclusively opened, no-follow FD. Only the
trusted worker uses its assigned inherited FD. Directory and file identity,
owner, exact mode, nlink=1, size and stable identity are checked; no payload
selects a path. Only the known entries are removed; a replaced path or
unconfirmed cleanup is an error, not a recursive delete. The worker writes
at most 1 MiB of canonical typed bytes per host (10 hosts, 10 MiB aggregate).
A fixed small receipt contains `handoff_version`, `run_id`, `target_id`,
`byte_count`, `sha256`, `complete`. The existing exact native task/host
wrapper and 3500-byte IPC bound remain. Neither a list of collection IDs nor
normalized/assessed documents are sent through this IPC. The Controller
verifies length, hash, slot identity, canonical bytes and exact expected
run/target, and consumes a receipt once. A malformed, duplicate, foreign,
partial or oversized result is rejected. No truncation. Cleanup is bounded
and known slots/FDs are released; uncertainty stops further dispatch or
precludes successful terminal publication. The scratch is not a persistent
journal or an isolation sandbox against a malicious same-UID process or
administrator. Crash/power loss and untrusted filesystems are not qualified.

The same native TaskQueueManager/WorkerProcess/TaskExecutor/argv witness,
validated context, per-dispatch guard, two-worker maximum, fork barrier,
absolute scheduling budget, callback/normal-reap separation, and bounded
TERM/KILL/join remain. For I1a, one bounded synthetic surrogate per eligible
producer uses the existing 30s command deadline plus 1s return cap; the
existing 15s connection cap and 16 KiB combined raw command output cap are
not expanded. This does not allow wrapping a whole real producer in a
single command budget: I1b must establish each actual command's deadline,
acquisition projection and cleanup. Platform P2 has the separate fixed
stage budget described below; it is not a whole-producer command timeout.
Controller typed normalization and
final verification run under a guard interval; the existing earliest
worker/phase deadline is not extended during callback validation. The
final typed normalization/assessment is separately bounded. Caught
SIGINT/SIGTERM retains priority (rc7) including the final evaluation;
ordinary confirmed failure may continue other hosts, severe faults stop
new dispatch, normal worker exit must be confirmed, and known validated
observations may be retained without promoting an uncertain terminal.

## V2 outcome / exact reference contract

Manifest version 2 retains V1's top-level fields and exact expected host
rows, limits, requested flags, host/run-state and rc derivation. Each host
has the additional `platform` outcome with the same closed outcome fields
and the fixed collector ID `pqc-platform`. The eight original flag outcomes
remain in canonical order. Platform is excluded from requested-scan
success. An outcome describes collection coverage, not readiness: rc0/5/6/7
keep the original semantics. Disabled flags are NOT_SCANNED and can retain
actual disabled collection references from a producer that was called for
its other flag. V2's aggregate `ERROR/COLLECTION_ERROR` with null rc
expresses a typed collection error without inventing a command rc. No
unreachable or successful terminal is inferred from a missing callback.

`validate_producer_manifest(manifest, rc)` checks closed shape, fixed
maximums, rc/state, counts and no duplicate refs across hosts. It is not
proof of origin or complete binding. `scan_collectors.normalize_handoff`
creates a private `HostProjection`; the parent calls `validate_bindings`
with actual validated projections and final Evidence/companions. The latter
checks exact outcome/collection IDs, host, scope, provenance, evidence and
asset rows, and companions against those projections. The only lifecycle
adjustment allowed is downgrade of a provisional UNREACHABLE on unconfirmed
worker exit/cleanup. No caller-supplied projection is an authorization token.

| Outcome | Exact producer scope construction | Max refs |
| --- | --- | ---: |
| platform | platform-info, seven tool scopes, two release RPM scopes | 10 |
| packages | two fixed OpenSSL RPM slots | 2 |
| openssl | five fixed runtime slots plus each validated provider scope | 5+P |
| crypto_policy | nine fixed policy scopes | 9 |
| sshd | five clients, config, actual validated native contexts | 8 |
| ssh_host_keys | fixed SSH public-key scope | 1 |
| system_certs | three fixed certificate roots | 3 |
| nginx/tls | unavailable, never acquired | 0 |

P is the number of actual unique exact names in the providers rows accepted
by the unchanged OpenSSL `validate_snapshot`; P is 0..256. For each row,
use the existing `key('openssl-provider', name)` and existing
`evidence.collection_id(run_id, host_id, producer, scope)`. Include the
metadata-gap PARTIAL rows and their diagnostic/evidence relationships. No
case folding, prefix-only mapping, arbitrary hash-like ID, guessed P,
reference truncation, scope merge or stable-ID replacement. Check the exact
set generated by the actual normalizer, not just the upper bound. Each
host has at most 38+P refs (294 max); total for ten hosts is at most 2940.
No host borrows another host's quota. V1 remains 8 refs/flag and 16/host.

The returned bundle has `document`, `assessed`, `companions`, and
`handoff_metrics`. The normalized Evidence is actual schema 1.1.0, with
run-scoped host identity where no authoritative stable inventory identity
is supplied; all expected hosts appear even when not attempted. Source,
asset, collection, evidence and companion IDs are from existing producer
APIs; the #10 validator/canonical roundtrip and #11 evaluator are invoked,
including original SSH and certificate paired validators. `companions`
are per-target maps of actual typed producer results (platform status/gaps,
OpenSSL diagnostics, policy metadata/diagnostics, SSH and cert details).
The normalized document has empty claims/findings; assessment is separate.
`handoff_metrics` is diagnostic byte counts for accepted receipts, not
identity proof or a persistent store contract. Keep the bundle private.
The existing Evidence 32 MiB and producer detail limits remain; on an
actual limit failure deny the result, retain previously valid observations
when the contract permits, do not enlarge limits or drop rows. I1a does
not prove all valid actual acquisition combinations fit the wire,
document, or runtime budgets. Report a concrete legal capacity conflict
before changing any contract. I2 owns persistent v2 store/detail/CFF
binding; no Run Store file is changed here.

## Engineering verification

Run the directly related `tests/integration/test_scan_collectors.py` with
an approved, isolated Ansible 2.19.11 runtime and synthetic Inventory, plus
named V1 regressions for the touched scheduler/queue/guard paths. The tests
exercise the five real normalization APIs, P=0/1/2/256, exact per-host
partitions, false/missing/foreign/duplicate refs, platform gating, native
256-provider receipt and complete companion data, actual local bounded
surrogates, overlapping workers, failure/interrupt/cleanup and handoff
filesystem negatives. The original V1 tests and helper/mirror are not
modified. These are engineering tests; actual fixed-path OpenSSH,
SSH/ProxyJump, OL9.x and official remote acquisition/cleanup, controller
qualification and #28 release QA remain pending. No live execution is
available.


## I1b Platform P2: fixed staged native bridge (restricted)

Approved #57 specification #7169477310 and dispatch #7169696850; P1
module, mirrors, helper and original normalizer are unchanged. This is
not a public module/driver registration API, SSH transport implementation,
Platform support declaration, or new wire/persistence contract. Only an
explicit private `_PlatformStageAdapter` for `pqc-platform` selects this
path. Both real registries stay empty; the old single-call synthetic
Platform and other producers retain their original path. Required producer
availability is checked for the entire frozen batch before connection.

The guarded native WorkerProcess owns the following exact order:

1. `metadata` (the original five facts and eight stat observations).
2. `release-rpm-oraclelinux-release`.
3. `release-rpm-oraclelinux-release-el9`.

The private trusted driver prepares only the bound fixed P1 stage and
consumes a one-use launch gate immediately before dispatch. The Controller
binding contains its actual run ID, frozen target, native TaskExecutor task
UUID, stage and ordinal. The completion must return that same binding
object, a separately trusted launch/completion/cleanup receipt, exact
integer wrapper rc and bounded bytes. It cannot select its own identity or
command from a report, plan, host variable, CLI or environment. This is
not a remote signature or an authorization token. The original fixed raw
SSH witness remains one-use and the original SSH `_run` is never called.
Per-stage guard and deadline rules are in [batch execution](batch-execution.md).

The private JSON frame cap is 32 KiB combined stdout/stderr, including
Ansible wrapper overhead. Read/return must be bounded; reject truncation,
extra data, unexpected frame fields, nonzero wrapper rc, stderr, duplicate
keys, invalid numbers, wrong invocation, missing/foreign/replayed/late
binding and malformed or contradictory receipt. The lazy fixed canonical
P1 `validate_receipt` checks the seven-key format 1 receipt, including its
16 KiB typed cap, outer rc, cleanup, payload and inner RPM rc. P1's own
16 KiB combined command output, 32 RPM rows and independent bounded group
cleanup are unchanged. Neither wrapper bytes nor raw diagnostics enter
Evidence, handoff or the native queue. A remote receipt's cleanup bit, a
Controller worker exit, or wrapper exit alone is not independent proof.
Only a trusted matching completion with confirmed cleanup may yield
`INVALID_ADAPTER_RESULT`; uncertainty remains `REMOTE_CLEANUP_UNCONFIRMED`.
Confirmed failure before launch may be `COMMAND_START_FAILED` with null rc.

After a valid metadata `COMMAND_OK` / rc0 / confirmed cleanup, reuse
`normalize_platform(..., source_kind='SYNTHETIC')` and `normalize_tools`.
Both release queries require `facts_state=OK`, numeric OL 9.x status
`UNVERIFIED`, and positive rpm and timeout capabilities. 9.10 is not a
special case or a `SUPPORTED` declaration. Otherwise preserve valid
metadata, do not dispatch either RPM, and pass `rpms={}` (both release
scopes become `NOT_SCANNED/NOT_ATTEMPTED`). Missing RPM capability does
not by itself suppress other eligible producers on an UNVERIFIED platform.
UNKNOWN/OUT_OF_SCOPE retains the original later-producer gap behavior.

A confirmed ordinary metadata failure produces a failed Platform record,
no invented ten-scope snapshot, and no later acquisition for that host.
A confirmed ordinary RPM outer failure becomes only a narrow typed error
with no rows (`TIMEOUT`, `OUTPUT_LIMIT`, or `COMMAND_FAILED`); the next
eligible fixed stage may proceed. Valid inner results retain the original
`normalize_rpm` states/reasons. In particular exact P1 absence with inner
rc1 is not inferred from outer rc0. Interrupt, invalid command contract,
process-control failure, guard/identity drift, invalid binding/receipt,
controller deadline and uncertain cleanup are fatal. No subsequent stage
or producer runs on that host; after the Controller observes a fatal stop,
no new host is dispatched. Already in-flight peers are stopped/cleaned
under the existing bounds; this is not instantaneous cross-process revoke.
No partial Platform snapshot is manufactured from a fatal sequence.

The existing four-key producer result and snapshot
`{facts_state,facts,tools,rpms}` feed original record/precheck, handoff v1,
actual normalizer, exact ten Platform scopes, Evidence 1.1.0 validation
and assessment. Wrapper `COMMAND_OK`/rc0 denotes a safely assembled
snapshot, not success of every RPM query. P2 keeps actual stage rc/inner rc
for trusted validation/engineering evidence only, not additional persistent
fields. The Platform-specific fatal ERROR reasons `GUARD_REJECTED`,
`CONTROLLER_TIMEOUT`, `INTERRUPTED` keep the original host/run RC5/6/7
semantics; unattempted hosts retain their existing NOT_SCANNED reasons.
A pre-launch deadline may yield a validated empty failure envelope, never
successful collection references. Parent retains previously validated
observations without upgrading an unsafe worker terminal. No schema,
Run Store, other collector or original P1/helper change is made.

Focused `test_p2_platform_*` tests in `tests/integration/test_scan_collectors.py`
exercise actual `execute_producer_batch` / native WorkerProcess, short and
FQCN packaging, original P1 helper and validator, local Debian metadata and
private synthetic OL inputs/RPM surrogate, exact scopes/bindings/assessment,
ordinary/fatal failures, both-worker deadlines, observed stop, signal and
independently reaped target groups. Synthetic copies replace only fixed
fact/stat input, RPM literal and necessary shorter test-only stage deadline;
no system RPM or real managed host is queried. These are restricted
engineering results. The real registry/transport, #8/#17 qualification,
actual Controller and OL9.7--9.9, installed tools, SSH/ProxyJump/host-key,
permissions, load, before/after state, remote lifetime and offline release
QA remain NOT_TESTED under #28. Other I1b adapters and I2 remain separate.


### I1b O2 — restricted fixed OpenSSL native bridge

O2 is a private staged adapter, not a registered public collector or a live
transport. The existing Platform staged adapter and the legacy callable
contract remain separate. A staged OpenSSL adapter requires the same native
worker's completed, validated Platform snapshot and independently clean
stage lifecycle; combining staged OpenSSL with a legacy Platform callable
is refused before connection. The numeric OL9 gate is unchanged. An
UNKNOWN or OUT_OF_SCOPE Platform produces the original typed gap snapshot,
with no O1 launch. Frozen flags select only the canonical indices 0–1
(RPM packages) and/or 2–6 (version, providers, KEM, signature, TLS groups).
No requested OpenSSL family means no OpenSSL dispatch.

Every O2 stage binds the original run, target, task UUID, fixed producer,
stage and canonical ordinal. A completion must retain the actual issued
binding object and independent lifecycle proof. The wrapper is a closed
32 KiB combined frame, with changed=false and exact stage invocation;
the canonical O1 validator applies its separate 16 KiB typed limit.
The wrapper exit status, outer supervisor receipt rc and inner slot rc
have different meanings. Only a validated COMMAND_OK outer receipt can
supply an inner payload. Confirmed outer TIMEOUT/OUTPUT_LIMIT/ordinary
command failures become the original ERROR slot with null inner rc and
empty rows. No inferred absence, truncated positive evidence, or persisted
second rc is introduced. Valid ordinary inner gaps preserve actual inner
rc and allow the next enabled stage. An uncertain inner reason (including
EXECUTION_ERROR), invalid receipt, foreign/replayed binding, unconfirmed
cleanup, guard rejection, controller timeout or interruption stops the
producer. Confirmed cleanup with invalid acquisition is distinct from
unconfirmed cleanup.

The existing seven-slot Snapshot, precheck, normalizer, exact source,
collection/detail references and Evidence 1.1.0 assessment are unchanged.
Only the trusted staged session can admit the OpenSSL-specific fatal
record extension. No partially completed seven-slot snapshot is promoted
on fatal failure: previous finalized producer observations are retained
when a valid host envelope is available; subsequent producers remain
undispatched. Loss of the host's handoff cannot authenticate earlier
in-memory snapshots. The existing 7 basic scopes, at most 256 provider
scopes, MAX_REFS, MAX_WIRE and MAX_HOSTS remain unchanged; L1/L2
observations do not assert L3/L4/L5. Both registries remain empty.



### I1b CP2 — restricted fixed Crypto Policy native bridge

The private Policy adapter accepts only the actual same-worker P1 snapshot
object after validated, independently clean completion. The fixed order is
Platform, selected OpenSSL, Policy, SSH, Cert. Selected O2 on an eligible
CP2 host must complete through its staged lifecycle (including legal clean
ordinary failure); no generic Platform or mixed generic OpenSSL substitute
can authorize acquisition. Neither public registry nor live transport is
enabled. Existing offline Store/import callers do not load Ansible to
normalize a legacy envelope.

The worker and adapter independently derive the same fixed ordinal plan
from frozen requested Policy flag, validated Platform facts and ordered
tool observations. UNKNOWN or OUT_OF_SCOPE retains the existing nine
typed platform gap scopes without native dispatch. An otherwise eligible
OL9.x with no positively proven timeout capability has nine
NOT_SCANNED/TIMEOUT_TOOL_UNAVAILABLE slots and no dispatch. For a positive
eligible platform/timeout, reader is ordinal 0. Only the exact positive
ordered tool slot (state OK, exists, regular, non-link, executable all
proved) may choose show-bin ordinal 1, otherwise show-sbin ordinal 2.
Bin has priority; never infer a path from aggregate availability. If no
slot proves availability, profile-show remains
NOT_SCANNED/SHOW_TOOL_UNAVAILABLE. At most two stages, no retry or fallback,
even if CP1 later discovers that the selected file is absent or unsafe.
CP1 independently validates its trusted file and fixed path contract.

Each CP2 binding carries run, target, task UUID, fixed Policy producer,
stage and canonical ordinal. An exact issued binding object, one-use
native begin gate and independent started/cleanup witness are required.
The combined stdout+stderr wrapper frame is at most 128 KiB for Policy
bindings only. The lazy canonical CP1 validator at the actual collection
module path checks exact stages and 66 KiB receipt / 64 KiB payload limits;
P1/O2 keep 32 KiB frame / 16 KiB receipt limits. Wrapper keys, changed
false, exact invocation stage, wrapper rc0, empty stderr and strict ASCII
JSON (no duplicate keys, floats or non-finite constants) remain closed.
The native worker's elapsed deadlines and independent cleanup proof are
not inferred from a remote cleanup bit, process exit alone or an exception.

Merge exactly the eight reader scopes and one show scope. Confirmed
ordinary outer failures become narrow typed scope ERROR gaps with null
inner rc, and may permit the remaining fixed stage only under the original
lease. Actual show payload retains its inner rc. Reader TOTAL_LIMIT is
an eight-scope all-gap; no truncated partial success. An empty plan is an
internal complete gap projection, not successful command execution.
Unconfirmed cleanup, uncertain inner cleanup, foreign/replayed completion,
invalid stage/frame, guard/transport/deadline failure or interruption stops
the current producer without a partial Policy snapshot; completed earlier
observations are retained only if a valid host envelope is available.
Later producers do not run. A worker's loss cannot prove earlier data or
cleanup.

The original nine-scope Policy snapshot, crypto_policy.normalize_snapshot
and build_crypto_policy_evidence, original profile conflict/FIPS semantics,
assessment and exact companion/collection bindings are reused. FIPS is
not PQC readiness. Private staged_policy context is supplied only by the
trusted session/ledger, never a serialized field, and defaults to false.
No change to the default C1 or legacy callable normalization contract,
handoff v1, manifest v2, Policy nine refs, 294 maximum refs, 1 MiB wire or
ten-host limit. No change to CP1 module/helper or mirrors.

Focused test_cp2_* cases cover actual short/FQCN packaging, P1 and O2
ordering, reader/show gating, oversized-for-P1 but legal-for-CP2 reader,
original builder and assessment, malformed/foreign receipts, failures and
worker cleanup/earliest lease. They must be executed against fixed source
and actual approved native runtime before engineering acceptance. Actual
Controller, OL9.7/9.8/9.9, installed tools, remote lifetime, load and
Before-After/offline release QA remain NOT_TESTED under #28.
