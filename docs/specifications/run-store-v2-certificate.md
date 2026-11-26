# I2 C1 - certificate-first private V2 Run Store

Status: restricted offline engineering contract. This does not qualify native
transport, a live producer registry, managed hosts, or report publication.

## Explicit selection and trust boundary

The existing `RunStore` API retains its legacy, S1 and `B04_NATIVE_V1`
contracts and the original manifest schema. C1 is selected only by
`batch_contract="B04_PRODUCER_V2"`, `run_kind="SYNTHETIC"`, Evidence 1.1.0,
and an explicit run ID. The caller supplies the original completed anonymous
bridge run, original start/recorded/finish times, and exact trusted rules
bytes (`producer_rules_raw`, at most 64 KiB). This is not a public scan API.
Only the eight existing long flag names are accepted; for each host only
`pqc_collect_system_certs` may be true, or all eight may be false. Platform
is a prerequisite, not a ninth flag. The original target/profile/host limits,
identity rules and private storage constraints apply. Every host must be
RUN_SCOPED with identity_key equal to target_id and no inventory authority.
The run source is the exact original synthetic bridge source (`pqc-producer-bridge`,
`1.0.0`, `i1a-synthetic`, null input hash). V2 dependencies load only on explicit
selection; old minimal installations do not require the new helper.

The caller has already obtained and validated the original closed typed
handoff; it is not an arbitrary JSON import. The C1 test fixtures retain
this original wire object directly. The existing executor does not yet return
that raw handoff to a persistent Store caller. C3 owns the actual acquisition
and time integration. No code here dispatches a worker or contacts a host.

## Frozen rules and exact binding

`begin` validates the original rule bytes with `assessment.load_rules`,
freezes SHA-256 and rule version in the sealed scope, and durably creates
`producer_rules.frozen.json` before the initial journal is returned. On
intent, checkpoint, finalize, recovery and open, the original exact bytes,
validated rule version and SHA-256 must match. Publication indexes the same
bytes as required `producer-rules` / `producer_rules.json`, format_version
being the original rule version and all reference arrays empty. It is not
an assessment result. Optional assessed Evidence and assessment rules must
be paired, use those exact rule bytes, and pass original assessment replay.
Without assessment, rule_version and rules_sha256 remain null. CFF is denied.

For each host use original `scan_collectors.wire_bytes` / `read_wire` and
`normalize_handoff` with the frozen run, target, long flags, start and rules.
The original Platform and certificate normalizers, `validate_bindings`,
Evidence model and `cert_assets.validate_cert_details` prove the exact
collection, asset, observation, outcome and companion association. The
original V2 terminal validators bind the Platform and all eight collector
rows to frozen flags; normal finalize and open also use the original complete
batch validator with its actual RC. Host binding views are not new batches.
The original Platform ten scopes and certificate three roots retain their
long collector identities. C1 never aliases them to short flag names.
All retained observation timestamps must lie within start and recorded_at;
completed checkpoint and final finish times equal recorded_at. Original
normalizer current-time validation remains in effect. No time is rewritten.

## API and fixed slots

The trusted caller calls `begin` with the arguments above, original
`source`, `expected_hosts`, `started_at`, `recorded_at`, `limits`, `profile`,
and `requested_flags` keyed by target. `requirements` may be omitted to
select the three required slots per requested certificate host; if supplied,
its `details` must equal exactly that set, with cff=false. For every host
with an actual attempted result, persist `dispatch_intent(host_id)` before
its terminal checkpoint. In this slice this records the completed synthetic
fixture, not proof of a real dispatch. `record_host` receives the original
canonical one-host Evidence fragment, exact V2 terminal and a closed list
of `{host_id, slot, value}` wrappers. The wrappers exist only in checkpoints.
The values are the actual original objects and are published without wrapping:

| Slot | Original value | Max serialized bytes | References |
|---|---|---:|---|
| producer-handoff-v2 | Closed version-1 handoff, original wire bytes | 1048576 | Both producers' exact union |
| platform-v2 | Original Platform status/gap summary, original wire bytes | 1048576 | Platform only |
| certificate-assets-v1 | Original #18 details, canonical ASCII bytes | 2097152 | Certificate roots only |

Paths are fixed `details/<validated host_id>/<slot>.json`, format_version
1.0.0, required=true. Exact collection, asset and evidence ID sets are
derived from the validated producer rows. The handoff is typed path-free
snapshot data, not PEM/DER/private key, raw command output, or debug data.
The original source/block IDs and dates, issuer, subject and other validated
public certificate fields are preserved, not inferred. There is no positive
certificate completion without all required companions. If a valid projection
exists, its handoff and every produced companion are mandatory, including
partial/gap projections. No handoff means no observed rows or companions;
only original zero-projection stopped/disabled/connection/worker outcomes
are permitted. Missing slots on incomplete hosts are reported explicitly.

`finalize(document, batch_raw=original_bytes, batch_rc=actual_rc, ...)`
validates all checkpoints and the complete original V2 terminal manifest.
`open` returns the existing `PublishedRun(manifest, document, assessed,
artifacts)` shape and revalidates the frozen scope, checkpoint association,
exact raw rule/slot bytes, original producer bindings and derived manifest.
The marker remains manifest_version 1.0.0, with explicit batch_contract
`B04_PRODUCER_V2` and two V2-only producer_rules fields. The historical
JSON schema describes only historical contracts; it is deliberately unchanged.
The V2 reader validates the conditional closed keys and fixed entries itself.
The old reader/schema must reject this marker, not interpret it as V1/S1.

## Recovery, safety and bounds

Use the existing FD-pinned local POSIX Store, private 0700 directories,
0600 singly-linked owned regular files, no-follow, original device checks,
sealed journal, immutable checkpoints, locks, fsync, staging and no-replace
publication marker. Prepared recovery revalidates all retained materials and
checkpoints and resumes the same plan. Unprepared recovery never creates a
fake terminal/batch, leaves recorded_at unchanged, sets finished_at null,
and reports RECOVERY_INCOMPLETE, unknown intents and unattempted hosts with
no invented observations. Missing frozen rules, wrong bytes, mismatched
required slots or unindexed artifacts fail closed. There is no repair or
redispatch. The caller must use the approved private root.

The only expanded detail cap is the new certificate slot. Old generic
MAX_DETAIL stays 1 MiB, MAX_CHECKPOINT 40 MiB, MAX_EVIDENCE 32 MiB,
MAX_CORE 256 MiB, MAX_SLOTS 8192; original bridge wire, ten-host, 294-ref,
certificate snapshot/block limits stay unchanged. No padding is used to
make a certificate companion exceed the old limit. The focused tests
conservatively bound the original closed C1 details from MAX_PROJECTION,
MAX_BLOCKS, three root records and at most three IDs per occurrence. The
bound is below 1 MiB; the 2 MiB explicit slot cap does not increase producer
capacity. Actual multi-host/multi-block details are tested through Store.
Over-cap material is refused, never truncated.

## Deferred work

C2 must consume the actual verified Store result for #22 dates and occurrence
navigation and prove the real render path. Catalog/Portal/CSV/CBOM are not
connected to this V2 marker by C1. C3 owns native handoff/time integration.
Do not interpret synthetic Store tests as actual native transport or formal
Controller/Oracle Linux, filesystem durability/load or browser acceptance.
