# Certificate CSV B (V2.0, offline preview)

`tools.export_summary.render_certificate_csv(store, run_id) -> bytes` accepts
only an actual `RunStore` (exact type) and its legal run ID. It calls `open`
then the existing C2 `project_asset_indexes` once; it does not accept paths,
URI, caller-constructed PublishedRun, or caller-supplied companion data.
Store integrity failures propagate. No publication, new generation, download
link, scan, assessment, certificate parsing or additional artifact read occurs.
The buffer is the proposed fixed `certificates.csv`, not a new Store artifact.
The A `render_summary_exports` API and its two HTML/three export buffers are
unchanged. Portal publication C is a separate work package.

## Rows and columns

Version B1 uses the exact ordered `_CERTIFICATE_COLUMNS` tuple. Every record
has `run_id`, `row_kind` and `assessed`. Order: GROUP by group ID, OCCURRENCE
by occurrence ID, COVERAGE by host ID then slot. Each is emitted exactly once;
no Cartesian expansion of repeated sources, assets, claims or evidence.

- GROUP: C2 ID/kind, fingerprint/source kind, the original six counts and
  membership sets (`host_ids`, `asset_ids`, `evidence_ids`, `claim_ids`,
  `recorded_occurrence_ids`, `verified_occurrence_ids`), asset identity scopes,
  role states/EIDs, bit value/state and original bit EIDs, metadata gaps and
  service/algorithm membership and shared-evidence links. `issuer`, `subject`,
  `not_before`, `not_after`, `validity_state`, `validity_occurrence_ids`, and
  `signature_metadata_state` are the existing C2 group values. Eight
  `metadata_<field>`, `metadata_<field>_state`,
  `metadata_<field>_occurrence_ids` triples expose the original field-specific
  value/state/support. The fields are public_key_algorithm, public_key_bits,
  signature_inner, signature_outer, issuer, subject, not_before, not_after.
  The independent date field values are NOT a paired validity interval;
  consult the group dates, state and actual supporting occurrences. Conflict
  does not select a first value. Legacy bits/roles are kept separate from
  companion metadata. Unassessed claim counts are C2 recorded counts, not a
  zero-risk result (`assessed=FALSE`).
- OCCURRENCE: original occurrence ID and group membership, exact host/asset/
  collection IDs and asset identity scope, root, source/opaque target IDs,
  block, fingerprint, detail state/ref/hash, observation timestamp, source
  kind/producer/version/origin/input hash, evidence and role IDs, reason,
  exact retained `metadata_<field>` values and `metadata_gaps`. The group-only
  state/support/count columns remain blank; occurrence gaps are the original
  per-block states. No path/vhost, endpoint or deployment relation is inferred
  from a fingerprint or opaque target ID. Unretained positions stay unretained.
- COVERAGE: each expected host has exactly one `nginx_certs` and one
  `system_certs` row, including no-asset/zero-occurrence, disabled, missing,
  unreachable, recovery and legacy runs. C2 requested/state/reason/rc/basis,
  terminal retention, slot/detail states and collection IDs/states are kept;
  host state and reason are independent. No coverage gap becomes absence or
  security/PQC PASS. Group and occurrence fields are blank here.

No unclassified source payload, raw snapshot, PEM/DER, private key, raw
report, target hostname, filesystem path, or arbitrary endpoint is exported.
IDs and existing typed provenance are not additional authorization to publish
internal data. Use only the Owner-approved private offline report environment.

## Encoding, safety and limits

UTF-8 with BOM, `csv.QUOTE_ALL`, CRLF; all scalar text passes through the
existing `_csv_text` formula/control protection. JSON list/map cells use
compact sorted-key ASCII JSON, preserving the exact C2 typed memberships and
values without an ambiguous delimiter; decode JSON after CSV parsing. Empty
cell means not applicable or unknown (use the corresponding state); `[]` and
`{}` are actual empty sets/maps. Booleans are TRUE/FALSE or blank for null.
Only the explicit nonnegative integer columns (counts, block_index, public
key bits and metadata_public_key_bits) use `_csv_number`. Terminal rc is a
bounded exact integer -255..255 or blank, with negative values protected by the
same apostrophe formula escape as A. A prefixed apostrophe on formula-like
text is a display safety marker; original control/format characters are
escaped as in A. This is not a lossless raw certificate export. JSON cells are
machine-readable, not executable expressions. No spreadsheet evaluation or
re-import is part of this API.

C2 retains its own projection membership/byte bounds. The export recharges
rows and JSON members using the existing summary budget, streams bounded
JSON cells and rejects over-budget output before returning any bytes. BOM,
header, UTF-8/quote expansion and record separators count toward the 16 MiB
single CSV and 32 MiB aggregate cap. B returns only one CSV, so both caps
apply to that buffer; C must check the aggregate of all published CSVs when
publication is authorized. The original A aggregate contract is unchanged.
Output is deterministic for the same validated run; no files are created or
changed by this preview. Actual Controller/OL, full-capacity and Windows/Linux
file:// acceptance remain release QA (#28), not engineering certification.
