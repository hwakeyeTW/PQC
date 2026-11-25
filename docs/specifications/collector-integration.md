# I1a — private producer-aware bridge (R2)

Scope: #57 I1a, approved R1 and capacity correction R2 (#7155598677,
#7155636533). This is an internal Controller-only synthetic integration,
not an acquisition adapter, public scan CLI, storage format, live grant or
release qualification. The real registry is empty and the original SSH
transport is never called. I1b and I2 have separate acceptance work.

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
are I1b responsibilities; a synthetic result is not evidence of actual
managed execution or OL support.

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
acquisition projection and cleanup. Controller typed normalization and
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
