# Evidence-based CFF projection, V1.0.0

Work package PQC-M1-04 (#13), approved C01-C03. This is the V2.0
controller-side **local compatibility contract**, not an external CFF
certification or a service-readiness verdict. Evidence and its independently
recomputed assessment remain authoritative.

## 1. Scope and unchanged legacy interface

The fixed legacy module in
`ansible_collections/security/compliance_pqc_readiness/plugins/modules/normalize_pqc.py`
and its root mirror `plugins/modules/normalize_pqc.py` are unchanged. Both
have Git Blob `f2f994676be4eebb04e0174b962aeec66da6940e` at the approved base
`22082a4b33409e3e77b20565204918e2aa992f03`. The original named test file,
`ansible_collections/security/compliance_pqc_readiness/tests/unit/plugins/modules/test_normalize_pqc.py`,
remains Blob `868fb434ed60da65e581aab3ce1bca108cf67591`.

Its existing short-name and FQCN calls, `crypto_report` required dictionary,
`profile_id`, `profile_name`, `output_file`, `scan_id`,
`certification_status`, `certification_authority`, `supports_check_mode`, and
returned `changed`, `findings`, `summary`, `scan_metadata`, `output_file`
are not changed. The old JSON file envelope is `version`, `scan_metadata`,
`findings`, `summary`. Historical module behavior, including its old
assessment and score semantics, is preserved strictly for compatibility.
In particular, its substring and version heuristics, empty-report failures,
public-key/signature OR test and old error-inclusive score are not new
Evidence semantics. Do not use that module, the old readiness percentage,
or the old Backstage publishing playbook as the V2.0 evaluation/report path.

The new `tools/cff.py` is a separate pure Python API. It does not call the
legacy module, run commands, import Ansible, load files/rules, modify hosts,
produce remedies, access a clock, fetch schemas, or send anything to
Backstage. A trusted Controller caller supplies a validated data object and
trusted fixed assessment rules. No new runtime dependencies are needed.

There is no independently fixed authoritative upstream CFF schema in the
approved sources. The new local schema `schemas/cff-projection-1.0.0.schema.json`
(`urn:pqc:cff-projection:1.0.0`, draft 2020-12) is based on the legacy producer's
RETURN/main and named fixtures, plus the mandatory new companion. It is not
an upstream specification or a third-party consumer certification.

## 2. API and Evidence authority (C01)

```python
from tools import assessment, cff, evidence

# The trusted caller has already acquired these two inputs as bytes.
document = evidence.parse_evidence_bytes(evidence_bytes)
rules = assessment.load_rules(trusted_rules_bytes)
projection = cff.project_cff(document, rules)
assessed = assessment.evaluate_document(document, rules)
assessed_bytes = evidence.canonical_bytes(assessed)
wire_bytes = cff.canonical_projection_bytes(projection, assessed, rules)
# Persist assessed_bytes and wire_bytes together through the approved private
# store when that later work package provides it. This API never writes them.
```

- The exact Evidence 1.0.0 or 1.1.0 document is accepted by the fixed Evidence
  validator. Unknown versions, invalid references and contradictory scope
  are rejected by that validator. The projector does not upgrade/downgrade.
- The existing `assessment.evaluate_document` recomputes the current trusted
  rules' owned results. Already present owned results must match exactly;
  a stale/forged result raises the original `ASSESSMENT_CONFLICT`, even if
  its shape and IDs are valid. Other valid rule results are retained and
  explicitly excluded, never interpreted as owned verdicts.
- The projector uses the actual canonical assessed bytes (including all
  valid external results) to compute `evidence_document_sha256`. It never
  hashes an arbitrary report string or unassessed input instead. Caller
  inputs and the supplied rules are not mutated. The evaluated copy is
  separate from the inputs. The same logical input/rules yield identical
  projection bytes despite registry/ref-set ordering.
- L1 Installed, L2 Supported, L3 Configured, L4 Negotiable, L5 Observed in
  Use stay independent. Direct fact PASS/FAIL is not service readiness.
  No new finding is inferred from a crypto report, package version, old
  risk string, policy name or algorithm name. Certificate public-key and
  signature observations keep their distinct typed algorithms, source
  IDs and subjects. Migration classification is delegated to the exact
  existing #11 classifier, not a second taxonomy. The original annotation
  fields are retained even if that classifier returns UNKNOWN; this is not
  a validation of the annotation. Classical migration is not a statement
  that a key has already been broken. A PQC KEM L2 does not prove L3-L5 or
  a service KEX; cipher/signature/public-key/KEX observations are distinct.
  FIPS stays an independent fact, not a PQC verdict.

`project_cff(document, rules)` returns this closed wrapper (ellipses are
explanatory, not literal JSON):

```text
{
  projection_version: "1.0.0",
  evidence_document_sha256: <full SHA-256 of canonical assessed Evidence>,
  per_host: [ { host_id: <Evidence host ID>, cff: {...}, companion: {...} } ]
}
```

Every expected host appears exactly once, in ascending host ID order.
This includes ERROR, UNREACHABLE, NOT_ATTEMPTED and hosts with no collected
facts; an empty expected manifest produces an empty `per_host`, not an
invented host. IDs, not display names, join data across views. Each `cff`
object is the four-key legacy wire envelope. Each `companion` is mandatory.
A bare CFF envelope is lossy and cannot be advertised as a complete new
report. Store/report consumers must preserve the canonical assessed Evidence
and the full projection together, and validate their association. Later
#9/store/Portal work owns persistence and final report integration.

### Metadata and identity

The new fixed `profile_id=pqc_evidence_v1` and profile name `PQC Evidence
Facts and Coverage` distinguish this output from `pqc_readiness_v1`. The
legacy-format `framework=CUSTOM`, `scanner={name: custom, version: 1.0.0,
tier: 1}` are retained as wire metadata. Certification is always
`{status: uncertified, authority: ""}`. It is not a copied self-assertion.

`scan_id` is `pqc-evidence-` plus the full SHA-256 of the canonical JSON
array `[run_id, host_id]` (UTF-8, no whitespace, no shortened hash). The
metadata timestamp is the original validated `run.finished_at` if non-null,
otherwise `run.recorded_at`; companion `run.timestamp_kind` distinguishes
`RUN_FINISHED_AT` and `RUN_RECORDED_AT`. It is not per-observation time;
legacy null observation times remain null. Display the literal `target_id`
only if it is a bounded ASCII token `[A-Za-z0-9][A-Za-z0-9_.-]{0,511}`;
otherwise use `host_id` (including a null target). Do not use a display
label to construct a path, invent identity, or merge two hosts.

Each CFF finding uses the complete original `finding_id` as its unique
`rule_id`; `evidence.scanner_rule_id` preserves the original assessment
rule ID. One rule with multiple assets, scopes or actual conditions may
produce multiple findings. One output row per original finding is required;
no collapsing by rule name or host label.

## 3. Status and count mapping (C02)

| Recomputed original assessment | CFF status | In denominator |
| --- | --- | --- |
| Owned PASS | pass | Yes |
| Owned FAIL | fail | Yes |
| Owned NOT_APPLICABLE | not_applicable | No |
| Owned NOT_SCANNED | not_checked | No |
| Owned PARTIAL | not_checked | No |
| Owned UNKNOWN, explicit relevant acquisition failure | error | No |
| Owned UNKNOWN, otherwise | not_checked | No |
| Unowned (any original state) | not_checked | No |

An UNKNOWN becomes `error` only on explicit acquisition ERROR,
PERMISSION_DENIED or UNREACHABLE connected to that exact finding. Resolve
its own `evidence_ids` and its own linked claims' `evidence_ids`; their parent
collections are its explicit associations. If any such parent has a listed
failure, include its exact collection ID in `error_collection_ids`. For an
owned empty-collection coverage finding with no refs, reproduce only #11's
coverage identity (`coverage-` + full SHA-256 of canonical JSON
`[collector_id, scope_key, "unqualified"]`, then the original `finding_id`
helper with the exact host/null asset/null algorithm subject) and require a
unique match. This derives a link, not another assessment. An owned exact
host-only `no-collection` coverage finding may reflect an explicit host
ERROR/UNREACHABLE only when the host has no collection at all; its
`error_host_state` records that host state. A host's error does not spread
to unrelated collections or other subjects. Unowned findings never inherit
these owned coverage identities. No timeout, legacy default, missing tool,
string substring or guessed condition is mapped to a fact FAIL. A PARTIAL
remains not_checked even if linked observations include a failure.

All five CFF status counters partition `summary.total`. The compatibility
numeric `summary.compliance_score` is `round(pass / (pass + fail) * 100, 1)`
when the denominator is nonzero; a zero denominator emits `0.0` solely as a
wire sentinel. Companion `score` has these fields:

- `score_semantics`: `FACT_STATUS_RATIO_NOT_READINESS`
- `numerator`: number of pass findings
- `denominator`: pass + fail (owned, decisive facts only)
- `excluded`: total - denominator
- `score_available`: true iff denominator is nonzero

For example, one pass, one fail, one error, one not_applicable and three
not_checked findings yield total 7, denominator 2, excluded 5 and score
50.0. All-error, all-unknown, and all-disabled hosts have zero denominator;
0.0 is not evidence of failure. 100.0 is not proof of PQC safety or complete
coverage. The future Portal must not present a PQC readiness/safety
percentage. Display the independent fact states and acquisition coverage.

### CFF finding fields

The legacy required finding fields are present: rule_id, host, title,
status, severity, category, description, check_text, fix_text, evidence,
remediation, stig_id, cis_id, cce_id, cci_id, actual_value, expected_value,
scanner, disruption, aap_impact, aap_impact_reason. Category is fixed to
`Cryptographic Evidence`; title denotes only the owned level, coverage,
or external finding. `evidence.actual_value` is the original owned state
(or a fixed not-assessed explanation for unowned); `expected_value` is a
fixed reference to companion Evidence; `message` is the bounded mapping
reason. Top-level actual/expected duplicate the evidence fields for legacy
consumers. No raw observation text is copied to these fields.

Severity `low` is a compatibility placeholder, not a risk classification;
`disruption=low` is not a claim of remediation impact. The companion fixes
`severity_semantics=COMPAT_PLACEHOLDER_NOT_RISK_RATING` and
`disruption_semantics=COMPAT_PLACEHOLDER_NO_REMEDIATION`.
`aap_impact=caution` means unassessed; `aap_impact_semantics=NOT_ASSESSED`.
Remediation is `{role: "", available: false, disruption: low}` with a
fixed no-remediation message. STIG/CIS/CCE/CCI IDs are empty, not invented.
No execution instructions or commands appear. These choices deliberately
avoid reusing legacy remediation/severity/impact heuristics.

## 4. Mandatory companion and local validation (C03)

The companion is a closed, versioned per-host projection containing:

| Field/group | Content |
| --- | --- |
| version, evidence_schema_version, evidence_document_sha256 | Exact local version, original Evidence version, same global hash |
| run | Run ID/state, original run timestamps, source, scope/coverage reasons, timestamp kind, expected host count |
| host | Host ID, expected=true, original host state/reason/identity scope, safe literal target or null, display label |
| rule_version, taxonomy_version | Current trusted #11 rule/catalog versions |
| score, placeholder semantics | Counts, availability, meaning as above |
| collections | Original host/collector/version/state/reason/source/observed_at, exact collection and evidence IDs, full scope key hash |
| assets | Original asset IDs, host, kind, identity scope and evidence IDs |
| evidence | Original evidence ID, collection/host/asset, kind, source, observation time, optional logical evidence ref/raw SHA, typed algorithm annotation and migration classification, actual L4/L5 conditions |
| claims | Original claim ID, subject, level, rule ID/version, assessment state/reason, evidence IDs and exact typed conditions, claim key hash |
| findings | Original finding ID/subject/rule/version/state/reason/claim IDs/direct evidence IDs, condition key hash, CFF rule/status, owned flag, mapping reason, score inclusion, resolved evidence and collection IDs, explicit error IDs/state |

Free-text Evidence values (including raw path, command, legacy payload,
observation key, identity key and observed algorithm name) are never copied
into the projection. Literal scope/claim/condition keys are represented by
full SHA-256 of their canonical JSON strings, even if they look like tokens;
observed algorithm names have a nullable full hash instead of raw text.
Exact source refs, typed conditions, algorithm IDs and the defined safe
host presentation token are retained for the necessary joins. This is
not a DLP/redaction or provenance-authentication engine. Opaque identifiers,
hashes and otherwise well-formed host labels can still disclose private
information. The canonical Evidence and the projection must remain in the
Owner-approved private store. No production report or derived output goes
into a public repository or service. Consumers must also safely escape
values for the actual HTML/CSV rendering context.

The shipped local schema closes every object and defines bounded IDs,
refs, version/condition variants, five CFF status values, bounded counts
and score, and constant certification/remediation placeholders. `$ref`
values are only local `#/$defs/` references. Schema shape alone cannot
prove ownership, record identity, hash, manifest or count algebra.

The pure projector checks host/finding bijections, association with actual
collections/claims/evidence/assets, mapping/reasons, version/hash binding,
metadata and count algebra. `validate_projection(projection, document,
rules)` recomputes the full canonical projection from the same original or
assessed document and trusted rules, then requires exact canonical JSON
bytes, rejecting wrong hash, altered references, score, states, placeholders,
unknown fields, or missing/duplicate records. `canonical_projection_bytes`
uses the same semantic validation; no arbitrary schema resolver or file
access is invoked. JSON object-key order is immaterial; registry arrays are
in canonical order, numeric/boolean representations are not conflated.
Errors from Evidence and Assessment retain their stable codes; local
projection errors use fixed codes without payload echo.

Bounded representation: maximum 1,000 hosts and 20,000 rows per Evidence
registry (including assessed rows), 20,000 array entries, 32 MiB output
bytes, depth 64, 2,000,000 JSON nodes and 512-character output strings.
Validate original Evidence limits first and reject any projection overflow
as `PROJECTION_LIMIT`, without partial output or truncation. The explicit
limits are conservative and may require a later approved revision for
large fleets. Inputs must be plain JSON-shaped objects and trusted rules,
not arbitrary Python objects. No new configuration or runtime dependency.

## 5. Focused verification and integration limits

```sh
python3 -m py_compile tools/cff.py tests/unit/test_cff.py
python3 -m json.tool schemas/cff-projection-1.0.0.schema.json
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python3 -I -B -m pytest -q -rs -p no:cacheprovider tests/unit/test_cff.py
```

The new synthetic suite uses both original Evidence schema versions,
actual Evidence validator/ID/canonical APIs and actual assessment engine.
It tests all independent levels and states, mixed/error/zero-denominator
counts, forged owned results, external exclusion, host and scope isolation,
conditions, certificate public-key/signature separation, migration and FIPS,
full hash/ref joins, determinism, tampering, resource bounds, and no I/O.
When the already available `jsonschema` tool is present, test the closed
local draft 2020-12 schema plus both Evidence snapshots with its actual
validator; without it, the semantic and fixed consumer-shape assertions
remain runnable and the dedicated external-validator tests are NOT_TESTED.
Tests use only synthetic data; the projector itself does not depend on
jsonschema, Ansible, or an external service.

The original named `test_normalize_pqc.py` remains byte-identical. Under
ansible-core 2.19.11 its legacy test helper's `_ANSIBLE_PROFILE='json'`
is not a recognized serialization profile, so the unadapted suite may
fail before reaching the module. A private test-only compatibility harness
can adapt only that argument helper to the installed Ansible's actual
`legacy` profile (the default for this unchanged legacy module), leaving
the original argument JSON, module, and all assertions intact. Record raw
and adapted results separately. Do not change the legacy test or module
as part of this projection. The focused old/new comparison uses the actual
ready/vulnerable/empty legacy fixtures and a synthetic nginx key/signature
OR counterexample, and separately typed synthetic Evidence in both versions;
there is no dependency on the #12 importer or real reports. Old structural
compatibility is not new decision equivalence.

Actual Controller/Oracle Linux 9.7/9.8/9.9, full consumer/Portal/store
integration, real legacy import integration, external CFF/Backstage
certification and complete offline release regression remain NOT_TESTED
for the appropriate later work packages/#28. No real host probing, privilege
changes or live dispatch are authorized. Development test PASS is not
independent Review, formal release QA, or Owner merge/release approval.
