# Legacy JSON import (V2.0 development API)

`tools/import_legacy.py` is a pure Controller-side adapter. It accepts already
acquired bytes from a known legacy producer and trusted caller metadata, not a
file name, URL, directory, archive, Ansible inventory or remote host. It does
not run the old producer. There is no new CLI, live dispatch, report store or
network dependency. The caller must retain original bytes and manage private
storage; use the #2 data handling policy (directories 0700, files 0600). Never
commit or transmit real report data, identities, diagnostics or derived reports
to the public repository. IDs and SHA-256 are not anonymization.

## L01: Explicit formats and caller contract

Select one of these fixed, case-sensitive format IDs. Selection is the caller's
attestation that the input came from the identified producer; it is not a
signature or proof that a historical report was authentic or complete.

| Selector | Confirmed producer at base `22082a4b33409e3e77b20565204918e2aa992f03` | Required structural fields |
| --- | --- | --- |
| `legacy-per-host` | `roles/crypto_posture_snapshot/tasks/report.yml` (`3bd674f1a5783954b1a4b4d5ef815dcbcd2cec83`); OL-enriched per-host records have optional `os_distribution`, `os_version` | `host` |
| `legacy-fleet` | `playbooks/crypto_posture_snapshot.yml` (`0accc261e02174a4fe6619b3b66daf94e700caf0`) | `total_hosts`, `hosts` (array of per-host objects); optional `generated_at` |
| `legacy-ol-run-summary` | Static anonymized producer `tests/fixtures/scan_ol9.anonymized.yml` (`e306a7967853dc37a9c87ce81cad568589484e33`) | `run_id`, `selected_hosts`, `successful_hosts`, `hosts_without_report`, `selected_count`, `completed_count`, `reports`; optional `generated_at` |

These are source-specific adapters, not generic JSON Schema importers. There
is no auto-detection, mixed wrapper, HTML/PDF/CBOM/CFF reverse conversion or
support claim for unconfirmed legacy formats. A report's flags, risk fields,
version claims and producer defaults do not authorize or prove acquisition.
`tests/fixtures/legacy_report.json` is an artificial three-format test bundle;
its enclosing object is not an accepted product dialect.

### API

```python
from tools import assessment, evidence, import_legacy

# The trusted caller supplies legacy_bytes and fixed_rules_bytes. No I/O here.
rules = assessment.load_rules(fixed_rules_bytes)
result = import_legacy.import_legacy(
    legacy_bytes,
    format_id="legacy-per-host",
    run_id="import-fixture-01",
    recorded_at="2026-01-03T00:00:00Z",
    origin_ref="private-fixture-ref",
    rules=rules,
    source_version=None,
    disabled_manifest=None,
)
normalized = evidence.canonical_bytes(result.document)
reevaluated = assessment.evaluate_document(result.document, rules)
assessment_bytes = evidence.canonical_bytes(reevaluated)
```

`ImportResult` contains three fresh plain-data members: `document` (valid,
canonical-order Evidence 1.0.0, empty `claims`/`findings`); `provenance` (format,
source version, origin ref, raw input SHA-256, original summary run ID and
original aggregate generation time when valid); and `diagnostics` (sorted
constant reason-code counts). Persist provenance and diagnostics alongside the
normalized document if the original aggregate metadata must remain available.
The original valid per-host `collected_at` is retained in a typed legacy
observation in `report-metadata`. The `run.recorded_at` is the explicit new
caller time; old `run_id` never substitutes for the new run ID. The legacy
producer's `collected_at` is a report/gather-facts timestamp, not a per-row
observation time; `generated_at` is aggregate generation time. Neither proves
an observation interval. Therefore all imported `observed_at`, and the run's
`started_at` and `finished_at`, are null. Invalid times are gaps; no wall clock
or invented observation time is used. Timestamp strings must use the existing
UTC `Z`/`+00:00`, at most nine fractional digits and valid calendar date/time.

The source on run, collections and evidence is `LEGACY_IMPORT`, with the exact
selector as producer ID, SHA-256 of the supplied bytes, opaque origin reference
and optional independently verified producer version (default null). The
selector and adapter version are not the legacy producer's software version.
Source version in an untrusted report is ignored. The adapter does not modify
rules, inputs or existing Evidence files. Retaining the raw bytes is the
caller's responsibility. A successful import also preflights the complete
assessment with the exact supplied rules using the real #11 evaluator (which
validates and canonicalizes its result). The temporary assessed document is
not returned or stored: the normalized Evidence still has empty claims and
findings and is sufficient for offline reassessment with those same rules,
without opening original reports or contacting hosts. A different future
ruleset is not covered by this capacity guarantee.

### Bounds and failure contract

- Strict UTF-8 JSON, no duplicate object keys, invalid encoding, nonfinite
  numbers (including overflowing float), surrogate or NUL strings. Integers
  are limited to the interoperable safe range. JSON boolean is not an integer.
  Maximum raw input and canonical Evidence output 32 MiB, nesting depth 64
  (including leaf depth), at most 1,000,000 structural delimiters/nodes,
  1,000 hosts, 1,024 rows per host per asset/algorithm group (package map
  entries and aggregate package rows bounded separately), 20,000 evidence
  rows and 20,000 assets, and 4,096 distinct algorithm/context classifications
  per import. Excess rejects the whole input, not a truncated result.
- The 32 MiB Evidence bound applies independently to the complete assessed
  document, not just the normalized bytes. One bounded real reassessment is
  required before returning an import. An assessor `SIZE_LIMIT` is reported
  as `LegacyImportError('REASSESSMENT_SIZE_LIMIT')`; nothing is returned and
  no rows, hosts, claims or findings are truncated. Unexpected assessment or
  validation failures propagate rather than being mislabeled as capacity
  errors. No second evaluator, retries, rules modification or new dependency.
  With at most 20,000 observations and 11 scopes per host, the fixed #11
  evaluator can generate at most 20,000 claims and 51,000 findings (one
  direct claim and its finding per observation, one coverage finding per
  observation or empty scope). The importer emits no COLLECTION_SUMMARY,
  so there is no cross-product of applicability references. The existing
  input/registry/string/depth and streaming 32 MiB encoder bounds therefore
  also bound preflight work and temporary output; no additional unbounded
  input or external work is accepted. This is a deterministic resource bound,
  not a wall-clock or process-RSS guarantee across Controllers.
- New run ID, origin ref and optional version satisfy the existing Evidence
  lexical forms. A host must be a non-placeholder, exact ASCII literal alias
  (letters/digits/underscore/dot/hyphen/colon/@/+ within the existing logical
  identity restriction, at most 512 characters); no trimming, filename, array
  index, connection-address substitution or case folding. Explicitly named
  IPv4/IPv6 aliases are not inferred from other fields. Unsupported host
  identity or inconsistent manifest is a whole-item error.
- Known optional malformed leaves, defaults and missing fields become scoped
  gaps. Unknown keys are counted, not copied or used as extra semantics.
  `UNKNOWN_FIELD` does not contain the key name. Nontrivial scopes with a
  malformed leaf use `LEGACY_PARTIAL_MALFORMED`; malformed scopes without a
  witness use `LEGACY_MALFORMED`. Missing/default scopes and unverified
  observations use separate reason codes. Errors are `LegacyImportError`
  with fixed codes only; a failing existing rule validator uses its fixed
  `AssessmentError` code. A normalized Evidence error is wrapped with a
  fixed `NORMALIZED_` code. No partial document or raw exception is returned.
- Explicit secret-bearing keys (including private key, PEM, password, token,
  credentials and raw hostvars variants) and PEM begin markers anywhere in
  the JSON are rejected. Unknown nested fields, raw command/sshd lines, FIPS
  output, certificate subject/issuer, raw fingerprint and risk values are
  never copied to output. Valid source certificate/public key paths are
  only used as exact opaque hash inputs; URL/template/XML-like paths are
  rejected as malformed identities; no path canonicalization or access.
  Algorithm names and other selected metadata use bounded literal grammars.
  This is a controlled import boundary, not a general DLP or authentication
  engine: even valid literal host, package or algorithm names may be private.

## L02: Manifest, stable IDs and coverage

The original fleet's `total_hosts` must be an exact nonnegative JSON integer
matching its array length. It represents reports present, not an independently
known expected inventory. Per-host and original fleet use
`run.scope_reason=LEGACY_SCOPE_UNKNOWN` and retain only the literally named
hosts. The OL summary has three unique lists with the successful/missing
sets disjoint and their union exactly the selected set. Counts must be exact,
reported hosts equal the successful set, and all selected hosts are preserved
with `LEGACY_SELECTED_MANIFEST`. Missing reports use host `ERROR` and every
fixed scope `UNKNOWN`, reason `LEGACY_REPORT_MISSING`; no inferred unreachable
or not-attempted state. Empty valid fleet/summary imports yield `ERROR`, not a
successful zero-host scan.

Host identity is ID-V1 `RUN_SCOPED` with exact target and identity key; no
invented inventory authority. All assets are `RUN_SCOPED`. Asset identity key
is `legacy-` plus the full SHA-256 of canonical JSON
`[asset kind, source scope, validated literal source identity]`. For installed
packages the identity is name/version/release/architecture/epoch; for
certificates and public SSH keys it is the exact source path (SSH keys require
`.pub`); for legacy TLS port records it is the exact validated decimal port.
Same path in two certificate scopes or two hosts is not the same asset.
Distinct paths with the same basename remain distinct. No persistent
certificate fingerprint or cross-run identity is asserted. Observation keys
are full SHA-256 tokens over scope, asset identity, field and optional literal
observation identity; no array index, timestamp or original run ID. Use the
existing `collection_id`, `evidence_id`, `host_id`, `asset_id` helpers.

Duplicate equal rows for the same validated identity are deduplicated and
counted. If a distinct raw row shares the same identity (including optional
field differences), reject `IDENTITY_CONFLICT` rather than pick a winner.
Exact repeated group tokens are counted/deduplicated; equivalent aliases are
separate literal observations of the same catalog fact. Reordering rows
preserves IDs, but the raw SHA-256 changes with different input bytes. Same
bytes, run ID, trusted metadata/manifest and rules produce identical
canonical output. Different run IDs isolate hosts, assets and evidence.

Fixed collector `legacy-import`, adapter version `1.0.0`; scopes:
`report-metadata`, `platform`, `packages`, `openssl-version`, `tls-groups`,
`system-certificates`, `nginx-certificates`, `ssh-host-keys`, `tls-services`,
`crypto-policy`, `sshd-config`. A nontrivial typed observation supports
`PARTIAL`, never full historical coverage. Legacy observations alone cannot
support acquired coverage. No synthetic collection summary or evidence from
empty lists/default false is emitted. Hosts with a nontrivial acquisition
are `PARTIAL`; otherwise `ERROR` (import evidence coverage, not a diagnosis
of the host). A run is `PARTIAL` if any host is partial, otherwise `ERROR`.
The legacy success list only proves report presence.

Only an independently verified, trusted caller's disabled manifest can mark
an exact scope `NOT_SCANNED`. Example (the caller computes the full digest
from actual raw bytes):

```python
disabled_manifest = {
    "input_sha256": hashlib.sha256(legacy_bytes).hexdigest(),
    "run_id": "import-fixture-01",
    "disabled": [{
        "host": "host-a.example.invalid",
        "collector_id": "legacy-import",
        "scope_key": "tls-services",
        "reason_code": "DISABLED_BY_PROFILE",
    }],
}
```

The digest, new run ID, present report's exact host, fixed collector and exact
scope must match. Only `DISABLED_BY_USER` or `DISABLED_BY_PROFILE` is accepted;
no wildcard, duplicates or flags embedded in raw reports. Any actual or
retained non-default legacy observation for that scope conflicts and rejects
rather than silently discard it. Disabled scopes carry zero evidence; a
missing-report host remains `ERROR`/`UNKNOWN` even with a manifest. No
unverified absence is upgraded to `NOT_SCANNED`.

## L03: Typed mapping and limits of historical evidence

| Source field | Evidence and evaluation boundary |
| --- | --- |
| `os_distribution`, `os_version` | A known distribution alias is a separate legacy observation, never `os_family`; canonical decimal version if known is `PLATFORM_INFO` with null family. No OL support inference. |
| `openssl_packages` | Valid named package-map rows with explicit version, source RPM or unspecified, `present=true` `PACKAGE_INVENTORY`; release, architecture and nonnegative epoch are separate legacy scalars. L1 only for that package. Empty/absent rows do not mean not installed. |
| `openssl_version` + rc | Exact integer rc=0 and bounded recognizable `OpenSSL` version output -> `ASSET_METADATA`, never L2. Missing/failed/invalid -> unknown legacy diagnostic. |
| `openssl_tls1_3_groups` + rc | Exact integer rc=0 and all tokens in a bounded, complete colon-separated or one-token-per-line listing; recognized exact `TLS_KEX` catalog tokens become `RUNTIME_CAPABILITY supported=true` for `openssl-tls13-group`. No pure KEM context inferred from a group name. Unknown token, missing/nonzero rc or malformed/truncated-looking output remains legacy/unknown; absent groups never become false. No detection guarantee for silent truncation or false source attestation. |
| System certificate / nginx certificate | Separate scopes and hashed literal paths. Actual non-placeholder public-key/signature metadata or positive parsed key size supports `ASSET_METADATA`; algorithm fields remain typed legacy observations with distinct `CERT_PUBLIC_KEY` and `SIGNATURE` annotations. No assertion of deployment or live use. |
| `ssh_host_keys` | Public-key context only, bounded size/algorithm, distinct public source path; KEM is not a host key. No service or negotiation claim. |
| `tls_services` | Valid exact port gives a run-scoped legacy service identity; protocol, cipher (`TLS_CIPHER`), key exchange (`TLS_KEX`), peer and server signature (`SIGNATURE`) remain separate legacy observations. Recognizable `Server Temp Key` form `NAME, N bits` is parsed by a full anchored grammar. No trustworthy rc/authorization/full negotiation context, so no L4 or service coverage witness. |
| Policy/FIPS, sshd lines, old risk, nginx flag | Raw policy/FIPS/sshd/risk contents never become effective configuration or usage. Bounded fixed diagnostic observations or line counts; nginx true only legacy, default false no fact. No decisive L3-L5. |

Algorithm annotations use the actual shipped #11 exact classifier, including
Hybrid `X25519MLKEM768` as `HYBRID/KEX`, independent public-key/signature
contexts and distinct legacy algorithms. Unknown aliases stay UNKNOWN. No
substring migration or readiness classification from old risk. The trusted
caller can apply the same catalog's migration classification to annotations.
OpenSSL group tokens are not KEM capabilities; version text cannot prove an
algorithm, and neither certificate presence nor a port's historical probe
proves real business use. No direct readiness verdict is produced by this
adapter. Existing evaluator and validator decide what observations support.

Output is deliberately Evidence 1.0.0, not a guessed 1.1.0 migration; the
integrated dual-version validator retains its original API and original
1.0.0 shape. No changes to #10/#11/#14 or existing producer/normalizer.

## Focused engineering verification and release boundary

```sh
python3 -m py_compile tools/import_legacy.py tests/unit/test_import_legacy.py
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python3 -I -B -m pytest -q -rs -p no:cacheprovider tests/unit/test_import_legacy.py
```

Tests use artificial producer fixtures and the existing Evidence and
Assessment APIs (including existing development `jsonschema`, not a new
runtime dependency). They cover exact manifests, duplicate/malformed/default
and malicious input, caps, disabled binding/conflicts, typed scope semantics,
no input-directed I/O, IDs/determinism, and real `validate_document`,
`evaluate_document`, `canonical_bytes`, `parse_evidence_bytes` and standard
1.0.0 schema checks. R1 capacity regression uses the real APIs with the
1,000-host/10-package-version CE01 negative case and an 800-host near-limit
positive case, checks full reassessment/roundtrip and exact preserved counts,
and verifies that non-capacity failures are not suppressed. No Ansible runtime
is required. Only the four approved new paths are part of this work package.

The API is an offline development component; actual historical reports,
Controller/Oracle Linux 9.7/9.8/9.9, product store/Portal and complete offline
release deployment/regression remain NOT_TESTED and are assigned to #28 and
applicable downstream work packages. Real Active L4/L5 validation remains
separately authorized #36-38. No release or readiness acceptance follows
from synthetic tests, and the old scanning entry points are unchanged.
