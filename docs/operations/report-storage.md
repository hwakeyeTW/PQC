# Private Controller run store (M0-08 S2)

This is the internal Python API and local run-manifest 1.0.0 contract
for issue #9. It is not a scan entry point, an Inventory adapter, a remote
writer, a catalog, or a report-rendering API. No call authorizes dispatch.
Plan-only and the existing live-rejection stubs remain unchanged. Issue #8
is integrated for restricted development at 1216f76df9913bc0e557523c88de99e1485d24c0.
S2 binds its actual B04 terminal API for trusted synthetic batches only.
This is not a production transport qualification or live dispatch grant.

## Owner-approved storage root

Use a dedicated existing absolute directory, outside the checkout if
possible, owned by the effective Controller UID and mode `0700`. Inside a
checkout only use the Owner-approved ignored `reports/` location. Do not
supply a path from Inventory, a report, or a host. The API does not create,
repair, chmod or chown an existing root. The operator must arrange a suitable
private root using the normal local administration procedure.

Linux local POSIX writer is the initial scope. The store walks path components
with directory descriptors and `O_NOFOLLOW`, refuses traversal and unsafe
ancestors, checks ownership, device and exact permission bits, and accepts
only known local filesystem types (ext family, XFS, Btrfs, tmpfs, overlay).
Root-owned sticky ancestors such as `/tmp` are permitted. tmpfs and overlay
are useful for engineering, not a production durability qualification. A
filesystem type check cannot establish mount provenance; the Owner must
approve the actual local filesystem and its locking/rename/fsync semantics.
NFS and Windows writers are unsupported. No fallback to a less safe storage
primitive is provided. The threat boundary trusts the Controller UID and
local administrator; it is not a sandbox against malicious same-UID or root
processes, replacement of trusted code, or hostile mount administration.

New directories use `0700` and new regular files use `0600`, even with a
permissive or restrictive umask. Only newly exclusively created objects may
have their mode set. Existing files must be regular, same-device, owned by
the effective UID, `0600`, and have a single hard link. File identity is
checked across open. Symlinks, hard links, devices and unsafe modes/owners
are rejected. Never repair a corrupt run by modifying core files or locks.

## API and frozen identity

Import `RunStore`, `StoreError`, `host_fragment` from `tools.run_store`.
The caller uses the fixed installed Evidence and Assessment modules, not
modules or rules loaded from a path embedded in input. Use context managers;
all writer methods must be called serially by the trusted caller. The store
has no CLI. The primary methods are:

```python
with RunStore(approved_root) as store:
    with store.begin(run_id=chosen_id, run_kind="SYNTHETIC",
                     evidence_schema_version="1.1.0", source=source,
                     recorded_at=recorded_at, started_at=started_at,
                     expected_hosts=expected_hosts, limits=limits,
                     profile="baseline", requested_flags=flags) as writer:
        # Synthetic caller already holds a frozen, authorized scope.
        scope = writer.scope
        # For a host whose simulated dispatch is about to occur:
        writer.dispatch_intent(host_id)
        # Only after receiving a validated terminal result:
        writer.record_host(host_fragment(document, host_id),
                           attempted=True, terminal=terminal_row)
        # Repeat for every expected host, including NOT_ATTEMPTED.
        result = writer.finalize(document, batch_raw=batch_bytes, batch_rc=0)
    # Reader is opened after closing the exclusive writer.
    verified = store.open(result.manifest["run_id"])
```

The names in the example are caller variables, not an authorization or a
runnable scan example. The caller must stop new dispatch on any persistence
failure, and must not retry a failed writer as though persistence succeeded.
`PublishedRun` contains `manifest`, `document`, `assessed` (or `None`), and
`artifacts` (fixed relative path to validated bytes). `scope` is a copy.
`StoreError.code` is a fixed reason, not input values or a sensitive path.

`begin` freezes source, timestamps, IDs, schema version, profile, limits,
requested flags and required artifacts before it returns. `source` is the
closed Evidence source record. All times are actual trusted caller values;
`started_at` can be null. Generated run IDs alone use the UTC clock and
128 random bits (`YYYYMMDDTHHMMSSZ-<32 hex>`). Explicit IDs use the existing
ASCII grammar, length 1..64, additionally excluding Windows device names.
A bounded root reservation flock serializes case-insensitive collision
checks and exclusive mkdir. Explicit collisions fail, generated collisions
retry at most eight times. Existing files, directories (including empty or
incomplete runs), and links are never reused. A failed reservation can leave
a reserved directory; do not delete it or retry using the same ID. Root
entry enumeration is bounded at 100000 and reservation lock wait at 5 s.

Each `expected_hosts` row has exactly `target_id`,
`inventory_authority_id`, `identity_key`. The Evidence host ID helper
computes STABLE IDs only with a trusted explicit authority and exact literal
target; otherwise a run-scoped identity is used. Identity strings are
restricted further to a safe ASCII literal subset (up to 512 characters);
no name or address becomes a path. Legacy requires RUN_SCOPED. Native-like
runs require distinct non-null targets, at most ten hosts and the exact
limits `max_hosts` (1..10), `forks` (1..2), `serial: 2`, `ssh_timeout_s: 15`,
`command_timeout_s: 30`. Profile is baseline or extended. `requested_flags`
keys are the literal targets, each with the eight boolean collector suffixes
packages, openssl, sshd, ssh_host_keys, system_certs, crypto_policy,
nginx_certs, tls_services; TLS is false and baseline nginx is false.
These are recorded inputs, not dispatch grants. Legacy permits up to 1000
hosts and null limits/profile/flags. Run kinds NATIVE_SCAN, LEGACY_IMPORT and
SYNTHETIC require the corresponding Evidence source kind NATIVE_COLLECTOR,
LEGACY_IMPORT or SYNTHETIC. Synthetic cannot be promoted to real evidence.

## Intent, terminal records and publication

`dispatch_intent(host_id)` makes the journal intent durable before a caller
can start dispatch. It does not dispatch or assert attempted. Duplicate,
foreign, disabled and legacy intents are rejected. `record_host` requires a
validated single-host Evidence envelope, frozen metadata and identity, no
claims/findings, and at most one immutable checkpoint per host. Use
`host_fragment` to split a validated unassessed document. The caller records
actual terminal data, not an inference from files or logs.

The explicitly identified S1 fixture and native B04 v1 contracts use terminal rows with exactly `target_id`,
`host_state`, `attempted`, `reason_code`, `collectors`. The eight collector
rows have `collector_id`, `requested`, `state`, `reason_code`, `rc`,
`collection_ids`. They match frozen flags and partition the same host's
Evidence collections; their coverage states must agree with those records.
`rc` is an actual bounded integer (-255..255) or null. A disabled or
unattempted collector has no invented result. A confirmed UNREACHABLE host
requires CONNECTION_FAILED. Native-like attempted is boolean; intent alone
cannot prove it. Legacy has null attempted and no terminal or batch record.

`finalize(document, *, batch_raw=None, batch_rc=None, assessed=None,
rules_raw=None, cff=None)` validates the full unassessed Evidence, exact
expected host set and all immutable terminal checkpoints. It compares every
observation, identity and source with the checkpoints. The native-like
`batch_raw` is the original UTF-8 JSON bytes of the closed synthetic record:
`batch_manifest_version` (1), sorted `target_ids`, `target_count`, `limits`,
`profile`, `run_state`, `reason_code`, sorted `hosts` (terminal rows).
The manifest preserves both raw artifact SHA and canonical batch SHA,
plus the actual rc supplied by the trusted caller. It labels this contract
`B04_S1_CONTRACT_ONLY` for the historical short-ID fixture; it is not an
assertion that #8 was executed. The `B04_NATIVE_V1` path is selected explicitly
at begin, not inferred from payload shape, and uses the actual #8 validator.
It preserves original run reason/state/rc even when all hosts completed before
an abnormal stop, or a fatal ERROR host retained earlier valid observations.
Normal rc 0/5/6 requires COMPLETE/PARTIAL/ERROR respectively; rc 7 is a
caught interruption with reason INTERRUPTED and non-COMPLETE state.
INTERRUPTED is valid only with rc 7; contradictory rc/state/reason inputs
are rejected, not rewritten, during publication, reading and recovery. A historical S1 fixture run
is COMPLETE only for a nonempty all-COMPLETE host set without interruption,
PARTIAL when any host provides valid coverage but the run is incomplete,
otherwise ERROR. No report existence is used as a success oracle.

The writer holds a per-run exclusive flock until close; readers take a shared
lock, and recovery requires the exclusive lock. A live writer cannot be
recovered or read as complete. No PID guess or lock-file deletion is used.
The sealed journal stores frozen scope and intent. A private temporary file,
file fsync, atomic replace and directory fsync update only that journal.
Host checkpoints are sealed and immutable. Their hashes detect corruption,
not authenticate data against an attacker who can rewrite the private root.

Publication uses a private staging directory on the same filesystem. Every
artifact is fully validated, written and synced, with fixed names, sizes and
SHA256. An immutable sealed `prepared.json` records the validated index and
staging directory before any promotion. `renameat2(RENAME_NOREPLACE)` moves
files atomically without clobbering; both directories are synced. The writer
re-reads the complete final index and publishes `run_manifest.json` last,
using the same non-overwriting operation and directory fsync. No file or
manifest is replaced by a retry. A successful publish is a storage result,
not a claim that the scan succeeded. `PUBLISHED` and `run_state` are distinct.

`store.open(run_id)` validates the marker, the exact index, fixed paths,
permissions, actual sizes/hashes, Evidence, assessment pairing, and derived
manifest semantics. It rejects absent/unknown/corrupt data; a directory,
index.html, temp file, or incomplete journal is not a published run. A
reader must not interpret a fixed error as a successful or empty run.

## Explicit failure recovery

After the writer has closed or exited, the trusted operator may call
`store.recover(run_id)`. There is no automatic re-dispatch, reconnection or
cleanup of external workers. Existing manifest markers, even corrupt ones,
block recovery. A valid prepared transaction resumes the already-validated
proposal, rechecks checkpoints and artifacts and completes the same atomic
publication, syncing directories even for previously promoted files. It
may preserve COMPLETE only if that exact proposal was prepared before the
failure. A corrupt/missing checkpoint or prepared artifact is rejected.

Without prepare, recovery reconstructs the full expected host registry from
validated checkpoints. An intent without a terminal outcome becomes ERROR /
OUTCOME_UNKNOWN / attempted null; no intent becomes NOT_ATTEMPTED. Missing
legacy outcomes are ERROR / LEGACY_OUTCOME_UNKNOWN, never a native connection
failure. Preserved host outcomes retain their real terminal rows. No valid
coverage means ERROR; some coverage means PARTIAL. Recovery is never a new
normal batch, does not invent batch bytes/rc/finished_at, and records missing
required artifacts explicitly. No remote termination is inferred. A crash
before creation of a valid journal remains incomplete and is not guessed
from arbitrary files. The filesystem may have private staging remnants;
the store does not delete them or reuse reserved IDs. At most four staging
attempts are accepted. A failure after rename but before successful fsync
is not a guarantee of durable success; an already existing marker cannot be
overwritten. Recovery is not a promise of surviving every power-loss case.

## Artifacts and manifest 1.0.0

The local draft 2020-12 schema is `schemas/run-manifest-1.0.0.schema.json`,
logical ID `urn:pqc:run-manifest:1.0.0`, with local references only. Schema
shape is not a replacement for the actual store's cross-field, path, hash
and Evidence checks. The manifest records expected IDs and full host rows,
counts, run/coverage/attempt states, source and time, limits/profile/flags,
requirements, schema/rule version and hash, batch contract/rc/hash, indexed
artifacts and missing artifacts. Counts and paths are derived; caller-supplied
summary or arbitrary attachment names are not accepted.

| Fixed relative path | Purpose | Individual cap |
|---|---|---:|
| evidence.json | Actual canonical Evidence 1.0.0 or 1.1.0 | 32 MiB |
| assessed_evidence.json | Actual canonical evaluation | 32 MiB |
| assessment_rules.json | Exact supplied rules bytes (existing JSON-form rules) | 64 KiB |
| batch_manifest.json | Original selected B04 terminal bytes | 16 MiB |
| cff_projection.json | S1 synthetic CFF + companion pair | 128 MiB |
| legacy_provenance.json | Closed original-source provenance | 1 MiB |
| details/<host_id>/<slot>.json | S1 synthetic typed detail | 1 MiB |
| run_manifest.json | Last immutable commit marker | 16 MiB |

Every index entry includes kind, format_version, host_id/slot or null, path,
size, sha256, required, collection_ids, asset_ids and evidence_ids. Paths
must equal the fixed mapping; no caller path resolver. Core payloads are
bounded to 256 MiB and 8192 slots. Evidence's original size/depth rules still
apply. Store JSON also bounds depth to 64, structural/node count to four
million and text fields to 4096 characters; journal/prepare/manifest are
bounded to 16 MiB, individual checkpoints to 40 MiB, aggregate checkpoints
to 256 MiB. Existing limits are conservative, not a storage quota or a
Controller memory/time guarantee. Checkpoints, staging and failed attempts
can consume additional private disk space. Capacity failure is an explicit
error, not a truncated result.

`requirements` defaults to `{assessment: false, cff: false, details: []}`.
CFF requires assessment. Detail requirements are exact `{host_id, slot}`
rows (use an explicit run ID for run-scoped IDs). Slots are platform,
openssl-runtime, crypto-policy, ssh-posture, certificate-inventory and
service-inventory. Assessment and raw rules are all-or-nothing; the fixed
actual evaluator recomputes canonical bytes and rejects mismatches. CFF
and typed detail are **SYNTHETIC only in S1**. Unknown producer formats or
versions fail closed. Required detail cannot be missing from a COMPLETE
host, even within a PARTIAL run. Publication, reading and recovery enforce
this same per-host requirement. A COMPLETE run cannot omit any required
artifact; a partial/error run records permitted missing paths and fixed reasons.

The closed synthetic detail envelope contains `format_version: "1.0.0"`,
`format: "S1_TYPED_FIXTURE"`, `run_id`, `host_id`, `slot`, `collection_ids`,
`asset_ids`, `evidence_ids`, and `records` (1..1024). Each record contains
`record_kind` (DIAGNOSTIC/ASSET/CONFIGURATION), `evidence_id`, `state`,
`reason_code`, `rc`. All references, kinds and collection states must agree
with the corresponding actual Evidence; free-form raw payload is disallowed.

The closed synthetic projection has `format: "S1_CFF_PAIR"`,
`projection_version: "1.0.0"`, `evidence_document_sha256`, and `per_host`.
Each host has `host_id`, `cff` (version, findings with full rule_id/status,
summary) and `companion` (same Evidence SHA, findings with original
finding_id, assessment_state, reason_code, claim_ids, evidence_ids, and
`score_semantics: "FACT_STATUS_RATIO_NOT_READINESS"`). Summary contains
pass/fail/error/not_applicable/not_checked/total/denominator/score_available;
only pass+fail count in the denominator. Bijection and references are
checked against actual assessed Evidence. UNKNOWN can be not_checked or
error in the fixture; this does not define a new production CFF evaluator.
These fixture contracts prove paired storage mechanics, not #13 or the
individual Collector wire contracts. Actual producer-specific typed
validation and required slots will be bound by the authorized integration
work, not by accepting opaque attachments or loading validators dynamically.

For legacy, `begin` requires the exact original `legacy_raw` bytes and
`legacy_provenance`: `format_version`, `source` (same frozen source),
`original_run_id` (only for legacy-ol-run-summary), `original_generated_at`
(actual UTC timestamp or null), `diagnostics` (at most 128 unique reason/count
rows). Source producer is one of legacy-per-host, legacy-fleet,
legacy-ol-run-summary; actual original SHA256 must match. The original
report is retained separately by the Owner; the store does not copy it.
Every legacy collection/evidence source must bind the same original digest.
Missing hosts remain present; no native batch/attempt facts are manufactured.
This is the S1 common provenance contract, not a direct import of #12 code.
Existing legacy reports and normalization interfaces remain unchanged.

## Verification and handoff

Run the focused unit file with the existing Python/pytest installation:

```sh
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -I -B -m pytest -q -rs \
  -p no:cacheprovider tests/unit/test_run_store.py
```

Tests exercise actual local filesystem operations, independent processes,
mode/owner/path/lock collisions, no-replace publication, abrupt exit and
recovery, strict schema and actual Evidence/Assessment validation. Only
synthetic fixtures are used. S1 does not require or restore Ansible. No
public network, remote scan, actual Inventory, original production report,
raw command output, secret attachments or arbitrary attachment paths are
needed. Closed records and rejection of recognizable sensitive keys/PEM
are not general DLP or source authentication.

## Native v1 restricted integration

Use `batch_contract="B04_NATIVE_V1"` with `run_kind="SYNTHETIC"`, Evidence
1.1.0, and all eight actual `pqc_collect_*` boolean keys per target. Mapping
is exactly the eight fixed suffixes listed above (including `tls_services`,
which remains disabled). The journal freezes short-ID flags and the explicit
contract marker. The raw terminal and each host checkpoint preserve the long
IDs. Actual `batch_execution.validate_terminal_manifest` validates run/rc and
its native host validator checks terminal rows against frozen flags. The store
also checks every referenced collection, host, short fixture collector and
scope key, actual Evidence coverage and immutable checkpoints. It does not
infer COLLECTED from empty refs or convert a fatal ERROR into PARTIAL.
Unknown contracts, versions, mismatched refs and unsupported producers are
rejected; there is no native-to-fixture fallback. Historical fixture calls
use short flags; new historical NATIVE_SCAN fixture calls must explicitly
select `B04_S1_CONTRACT_ONLY`. This compatibility marker is not a real scan.
Reader and recovery retain the selected contract. A recovered run without a
terminal batch has null batch rc/hash and BATCH_MANIFEST_UNAVAILABLE, never a
fabricated native terminal result. Existing legacy and S1 journals remain
readable under their original contract.

The trusted test orchestrator freezes the scope before execute_batch, persists
intent before native queueing, validates separately acquired synthetic
Evidence, and records the actual returned terminal rows. This does not implement
production per-dispatch orchestration or register live collectors. Real #57
producer IDs, scope-specific mapping and typed detail/CFF integration remain
unqualified; the native path accepts only the fixed synthetic short-ID scope.
Run store does not authorize any host connection. S2 review and Owner-approved
merge are required before #9 DEV_COMPLETE.
Production native/legacy/CFF/collector wiring, reader/catalog/Portal,
actual Controller/OL, approved local filesystem durability and power loss,
permissions/load and integrated release/offline QA remain for the authorized
later work and #28. This local engineering test is not formal support for
any production storage system.
