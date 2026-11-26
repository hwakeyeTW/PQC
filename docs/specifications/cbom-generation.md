# Evidence-based CBOM generation core (M5-08 B1)

Contract: Issue #26, approved AC-B1-1 through AC-B1-3 (7178753285,
7178897845). This is an internal, offline, Controller-side generation
core. It does not scan, reassess, publish, modify Store, or replace the
upstream legacy CBOM generator. Certificate/public-key nodes, dates,
certificate signature/public-key references and their verified asset
relationships are **DEFERRED_B2**. Portal downloads, immutable generations,
receipts and catalog integration are C, not B1.

## Public input and result

```python
from tools.cbom_generation import build_cbom, build_cbom_bytes
from tools.run_store import RunStore

# The caller has already selected an approved private Store root and exact
# published run/expected host identities. B1 itself takes no paths or URIs.
with RunStore(approved_root) as store:
    bom_bytes, provenance_bytes = build_cbom_bytes(store, run_id, host_id)
    bom, provenance = build_cbom(store, run_id, host_id)
```

The actual `RunStore.open` is invoked internally for each call, under its
original lock, pinned root, artifact and journal verification. Do not pass a
caller-constructed `PublishedRun`, raw report, subclass overriding `open`,
URL or path as a trust witness. This deliberately uses a Store and run ID
rather than exposing the suggested PublishedRun-only signature. The run ID
and host ID must be valid fixed identifiers, the host must belong to the
verified expected-host set, and only verified published data are used. The
existing Store may replay a saved assessment/CFF pair or a V2 handoff as
part of its own verification. B1 does not run a new assessment, substitute
current policy, or regenerate CFF. If a saved CFF pair exists, shared actual
IDs, finding/claim references and recorded algorithm classification are
checked against the same host; the verified CFF hash is retained. The legacy
pair's saved migration classification is copied only from its exact matching
algorithm record. Synthetic S1 CFF has only the original limited finding
contract. No CFF or assessed result is invented for C1 or other runs.

The result is the exact CycloneDX 1.6 JSON and a separate closed, in-memory
JSON provenance object (version 1). `build_cbom` returns independent decoded
objects of the same validated bytes. No new Store slot, path, file, report
receipt, transport registration or CLI is defined. Errors raise
`CBOMGenerationError` with a constant code; no raw error instance, data or
path is returned. The original validator must actually return both schema
and reference integrity PASS before either result is returned. Missing
pinned official schemas, engine or format dependencies are failures, not a
fallback to simplified validation. Generation is not authorization to
publish, a complete inventory or release acceptance.

## Graph, identity and provenance

* The fixed official `$schema` is the original A root URI. The generic host
  device uses its exact host ID; the timestamp is the saved `recorded_at`.
  No UUID, time, random token or input iteration order is used for identity.
  Actual service/library asset nodes use their local asset IDs. Other nodes
  use `cbom-` plus SHA-256 of compact canonical JSON containing the run ID,
  host ID, fixed node kind and its typed group/context identity. A metadata
  group is not a unique installed asset. Run-scoped identity is not claimed
  stable across unrelated runs.
* Algorithms and library groups reuse the original read-only #21
  `project_crypto_indexes` grouping, exact host-filtered membership and
  saved claim references. Claim-only membership cannot create a new
  algorithm or an unavailable library seed. Unknown, conflicting and legacy
  algorithm observations remain separately grouped by the original index.
  Family, primitive, taxonomy identity/state and typed acquisition status
  remain separate; a validated alias/identity in the already saved taxonomy
  qualifies a canonical algorithm name. Without saved rules or a matching
  record, the display is opaque. Only verified KEM/signature and explicit
  known classical key-agreement IDs map to the corresponding official
  primitive. Hybrid KEX, generic public key, symmetric and insufficiently
  proven primitives use `unknown`. No implied key size, mode, curve, FIPS,
  security level, use or readiness. Negative/unavailable observation states
  do not mean installed, configured, negotiated or in business use.
* Library asset, package and runtime metadata membership follow #21. Only
  a positive package presence with usable source is included as a package
  component; absence/unknown and failed metadata have explicit omission
  records. Explicit library/CLI/provider/linked-library observations are
  typed metadata, not proof of a library used by a service. Conflicting
  metadata has no selected winner, including a conflict recorded by #21
  between usable and unavailable rows. The original group ID and all pivot
  references are retained; the B1 metadata state is independently qualified.
  Library asset fields require their own same-host, same-asset ASSET_METADATA
  rows from COLLECTED/PARTIAL collections. A usable runtime row may retain
  the asset node, but cannot authorize failed or unknown metadata; such
  metadata produces an opaque name, omitted version, METADATA_UNAVAILABLE
  state and LIBRARY_METADATA_UNAVAILABLE omission. Package/runtime metadata
  groups still require their matching usable seed rows. Provenance retains
  portal_metadata_state, qualified metadata_evidence_ids and separate
  name_evidence_ids/version_evidence_ids for emitted fields; pivot/seed IDs
  alone do not prove a version. Only a small fixed OpenSSL name allowlist
  and narrow numeric version spellings are exposed. Any four consecutive
  decimal octets (0-255), including zero padding, suffixes and longer dotted
  strings, are conservatively omitted even if a legitimate version is
  ambiguous. Other names use opaque group IDs; unsafe versions are omitted
  with UNSAFE_OMITTED state. An unknown version is not a positive presence
  assertion.
* A service node requires an actual service asset. A protocol node requires
  an original same-host validated negotiation context, or a fixed legacy
  `tls-services` scope with a recognized typed `tls-protocol` observation.
  Protocol identities distinguish exact bound contexts without emitting the
  endpoint, context or authorization literals. A confirmed positive usable
  nonlegacy negotiation supports only a service-to-protocol edge for that
  context, and a protocol `cryptoRefArray` to the actually evidenced,
  verified canonical algorithm. These are service/protocol associations,
  not an assertion of a software implementation dependency or business use.
  Rejected/failed/unknown or historical protocol evidence does not establish
  these edges. Observed-use claims alone do not supply a protocol. Shared
  EIDs, library/algorithm pivots and host membership are not dependency
  proofs. No host-to-all or library-to-all graph, cipher-suite invention or
  external ref is emitted. All edges have exact same-host evidence IDs.
* Provenance binds the BOM SHA-256, verified Evidence SHA-256, run and host
  IDs, evidence schema, source kind, node definitions, Portal group IDs,
  asset/collection/evidence/claim IDs, seed IDs, recorded acquisition and
  assessment states, actual relationships and explicit omissions. Saved
  CFF classification is distinct from #21 grouping classification. Raw
  targets, endpoints, source origin refs, paths, hostvars, raw input values,
  arbitrary names, debug text, key material and external URLs are not copied.
  Unqualified taxonomy version strings, including ambiguous dotted octets,
  are represented by hash and omitted display version. The same version
  filter and explicit taxonomy_version_state apply to algorithm properties,
  node provenance and observation provenance without changing the original
  taxonomy identity or classification. No untrusted free-text label is
  promoted to a name.
  Missing or conflicted metadata and unproven relationships have fixed
  reason codes. Both BOM metadata and the sidecar distinguish the host/run
  state and B1-only scope. The sidecar retains attempted/recovery state,
  collection outcomes, missing artifact counts/reasons, actual evidence
  coverage and deferred certificate/key asset IDs. An empty unreachable or
  not-attempted host can produce a valid minimal BOM, never a scan PASS.

Both results use deterministic compact ASCII JSON with sorted keys, sorted
node IDs, explicit sets and fixed ordering. The combined host output is
bounded by the original A 32 MiB limit; each JSON tree is subject to the
original depth-64 preflight and bounded serialization. Construction charges
memberships at the original #21 `evidence.MAX_BYTES // 66` scale before
return; exceedance fails the whole host. The original A validator reads only
the pinned CycloneDX root/SPDX/JSF bytes and uses Draft7Validator with the
closed offline registry, format checker and product reference integrity
profile. No external retrieval is permitted by B1.

## Verification and remaining boundaries

Focused integration covers actual synthetic multi-host S1 publication,
actual C1 V2 fixture and original legacy Store/CFF pairing, canonical bytes,
actual #21 memberships and saved classification, missing/unavailable input,
corrupted Store, unsafe labels, cap, foreign reference and schema failures,
engine/format/schema absence, no writes and offline network traps. Each
successful fixture output is also consumed by the actual A validation API.
No mock substitutes for the official schema engine or actual Store.open.
A directly related official-validator regression is run without changing
original tests. The legacy per-host CLI compatibility work remains B2/C;
the original importer CLI is not executed by the minimal legacy Store test.
B2 certificate/public-key roles, C publication, actual production Controller
and OL9.7-9.9, Windows/Linux file:// and operational load/scale acceptance
remain NOT_TESTED or out of scope for #27/#28. No Ansible runtime is needed.
