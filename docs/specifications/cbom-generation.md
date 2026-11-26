# Evidence-based CBOM generation core (M5-08 B1/B2)

Contract: Issue #26, approved AC-B1-1 through AC-B1-3 (7178753285,
7178897845). This is an internal, offline, Controller-side generation
core. It does not scan, reassess, publish, modify Store, or replace the
upstream legacy CBOM generator. Certificate/public-key nodes, dates,
certificate signature/public-key references and their verified asset
relationships are **DEFERRED_B2** in the unchanged default B1 mode. B2 is
explicit opt-in per approved AC-B2-1 through AC-B2-3 (7181942477,
7182100614). Portal downloads, immutable generations, receipts, legacy CLI
compatibility and catalog integration are C, not B1/B2.

## Public input and result

```python
from tools.cbom_generation import build_cbom, build_cbom_bytes
from tools.run_store import RunStore

# The caller has already selected an approved private Store root and exact
# published run/expected host identities. B1 itself takes no paths or URIs.
with RunStore(approved_root) as store:
    bom_bytes, provenance_bytes = build_cbom_bytes(store, run_id, host_id)
    bom, provenance = build_cbom(store, run_id, host_id)
    # Explicit B2 in-memory projection, never an implicit change to B1.
    b2_bom, b2_provenance = build_cbom(store, run_id, host_id, include_certificates=True)
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

## B2 opt-in certificate and public-key projection

Both APIs accept the keyword-only exact bool `include_certificates=False`.
False (including omission of the keyword) preserves the B1 wire shape, scope
and deferred-asset semantics. True adds B2 and reports `B2_CERTIFICATE_KEY`
in coverage and the BOM scope property. Non-bool values fail closed.

* Reuse C2 `project_asset_indexes` on the very same verified publication;
  no alternate companion parser, new source read, classification or
  assessment. Only actual local asset and occurrence membership qualifies
  the node. A C2 recorded-fingerprint group yields one certificate per host
  and run, regardless of repeated sources or positions. A legacy/unverified
  certificate requires its own usable ASSET_METADATA seed and has an opaque
  group identity, no guessed fingerprint. Unavailable acquisition is an
  explicit omission. A certificate's recorded fingerprint is only a
  certificate fingerprint, never an SPKI or independent key identifier.
* The certificate is a `cryptographic-asset` with `assetType=certificate`.
  A subject key is `assetType=related-crypto-material`, `type=public-key`,
  and is created only from actual same-host public-key role evidence. Its
  identity basis is `CERTIFICATE_BOUND_SUBJECT_KEY`; its independent key
  fingerprint is null. It is not merged with a standalone key on the basis
  of name, size, fingerprint of a certificate, or host co-location.
  The original #17 `public_key` asset and matching `ssh-keys` ASSET_METADATA
  may qualify an independent SSH recorded public-key fingerprint only with
  its own usable collection, original producer/version and typed identity
  and observation grammar. The fixed R Store's V2 contract is cert-only;
  its S1 synthetic short `ssh_host_keys` source may represent the same
  legal typed #17 asset/metadata only under the explicit SYNTHETIC S1
  contract, with separate `SYNTHETIC_S1_RECORDED_PUBLIC_KEY_FINGERPRINT`
  identity basis. This is a synthetic positive control, not native #17
  Store integration or proof of a configured host key. Unknown/unqualified
  standalone assets are omitted; the #17 unknown algorithm remains unknown.
  No standalone size or algorithmRef is inferred from a key label.
* `signatureAlgorithmRef` uses the actual signature-role EID mapped to an
  already built and verified signature algorithm node. `subjectPublicKeyRef`
  and the key's `algorithmRef` use the actual same-host public-key role EIDs
  and corresponding verified typed algorithm, not another role or an alias
  guessed from the certificate text. Unknown/unverified/conflicted roles
  omit the references, with fixed reasons and role IDs. A recorded unknown
  public-key role may retain an opaque certificate-bound key node without
  algorithm or certificate reference. Legacy evidence does not promote a
  relation to verified. All emitted edges carry their exact role EIDs;
  no new service binding, dependencies, trust, CA chain, negotiation, or
  readiness/assessment claims are inferred.
* Only local `VERIFIED_COMPANION` occurrences qualify dates and size, and
  size also needs a public-key role in that same occurrence. A single known
  date may be retained as partial; both dates require shared occurrence
  support. Disjoint ends, reversed intervals and conflicts never produce a
  fabricated interval. Signature inner/outer conflict omits signature refs;
  conflicting key role omits size/ref. Never use the batch-wide C2 aggregated
  field value to fill a host's gap. Local field_support records state and
  exact qualifying occurrence IDs; validity_state, validity_occurrence_ids,
  metadata gaps and role states are independent. The sidecar retains local
  group/asset/evidence/collection/claim IDs and occurrence proof records
  (detail hash, detail state and role EIDs), including recorded but not
  retained detail. Certificate collection coverage includes the original
  C2 host-local requested/state/basis/slot/detail state, e.g. NOT_REQUIRED
  and REQUIRED_DETAIL_MISSING. No raw issuer/subject DN, target, path,
  endpoint, source position text, raw key value, private bytes or unverified
  lifetime/trust data are copied. The B1 safety filters remain unchanged.
* New memberships and field/role/occurrence support are charged against the
  same budget; combined canonical bytes/depth and official A validation are
  unchanged. No success is returned for an invalid reference, exceeded cap,
  invalid Store/companion or missing required official validation material.

## Verification and remaining boundaries

Focused integration covers actual synthetic multi-host S1 publication,
actual C1 V2 fixture and original legacy Store/CFF pairing, canonical bytes,
actual #21 memberships and saved classification, missing/unavailable input,
corrupted Store, unsafe labels, cap, foreign reference and schema failures,
engine/format/schema absence, no writes and offline network traps. Each
successful fixture output is also consumed by the actual A validation API.
No mock substitutes for the official schema engine or actual Store.open.
A directly related official-validator regression is run without changing
original tests. B2 focused tests reuse fixed C1/C2 actual Store fixtures (including the
multi-host same-fingerprint and multi-occurrence case), S1 and legacy Store
fixtures, explicit default/opt-in mode, actual role references, host-local
verified dates/bits and gaps, conflicts, disjoint ends, typed SSH synthetic
metadata, tampering, deterministic read-only output and combined caps. The
original A schema and typed reference validator also rejects corrupted
B2 output. C publication/legacy CLI compatibility remains separate;
the original importer CLI is not executed by the minimal legacy Store test.
Native #17 producer-to-Store integration is not available under the fixed R
certificate-only V2 contract. Actual production Controller and OL9.7-9.9,
Windows/Linux file:// and operational load/scale acceptance remain
NOT_TESTED or out of scope for #27/#28. No Ansible runtime is needed.
