# Algorithm taxonomy and direct-evidence assessment V1.0.0

Contract: PQC-M1-02 / Issue #11 / A01-A03. Evidence schema 1.0.0 and
ID-V1 remain unchanged. This is a pure Controller library, not a collector,
scanner, authorization mechanism, risk score, or release acceptance test.

## Trusted policy and API

The shipped `config/assessment_rules.yml` is the fixed, version-controlled
policy for this release. Both `taxonomy_version` and `rule_version` are
`1.0.0`, separate from the Evidence schema and collector versions. The
approved installation and caller must select the fixed file from the trusted
repository; evidence cannot select a policy, file, URL, import or command.
The caller supplies bytes already obtained from this approved source (no
file-reading API or CLI in the library). The file uses the JSON-compatible
subset of YAML, intentionally not general YAML. Strict UTF-8 JSON, maximum
64 KiB, duplicate keys rejected at every depth, closed mappings, maximum
12 levels / 16,000 value nodes, 256 array entries, 32 aliases per row,
128-character ASCII policy tokens. Non-string scalar values, tags, aliases,
anchors, merge keys, templates, nonfinite values, unknown fields, unsupported
versions/context/primitive/family/provenance and duplicate IDs or aliases
are errors. No regex or executable rule expression is accepted from data.
Fixed level-to-evidence/field mappings and reason codes are checked against
V1 semantics. The policy is trusted source, not a signature or a mechanism
for accepting arbitrary externally supplied taxonomy. Any change to rule
or taxonomy semantics requires an approved version/identity decision.

```python
from pathlib import Path
from tools.assessment import load_rules, classify_algorithm, evaluate_document
from tools.assessment import migration_classification
from tools.evidence import parse_evidence_bytes, canonical_bytes

# In a trusted installation, fix root to the approved repository root.
# raw_evidence is privately acquired by the caller; never uploaded to a repo.
rules = load_rules((root / 'config/assessment_rules.yml').read_bytes())
algorithm = classify_algorithm('X25519MLKEM768', 'TLS_KEX', rules)
category = migration_classification(algorithm, rules)
document = parse_evidence_bytes(raw_evidence)
result = evaluate_document(document, rules)
output = canonical_bytes(result)
```

`validate_rules(mapping)` checks the same shape/semantics and returns None.
`classify_algorithm` takes an explicit observation context supplied by the
producer; its output is exactly the five Evidence algorithm fields, not a
readiness result. `migration_classification` returns an inventory category
only. `evaluate_document` requires a valid Evidence V1 document, returns a
new canonical document, and validates the complete result using the original
public `validate_document` / `canonical_bytes` / ID helpers. It performs no
I/O, subprocesses, probes, configuration changes, installation, dynamic code
loading from data, or clock-dependent decisions. `AssessmentError.code` is a
fixed code; Evidence validation errors retain the original fixed locations.
Inputs and the supplied rule mapping are not mutated. Existing evidence
values are retained, not silently redacted or reclassified. Private normalized
scalars can still contain sensitive information; this library is not DLP.

## A01: exact aliases, observation context, and migration classification

The policy enumerates the complete initial catalog. Alias comparison is ASCII
case-insensitive exact equality within the explicitly selected context. No
whitespace trimming, punctuation rewriting, Unicode normalization, substring,
algorithm-name guesses, arbitrary OID inference or version inference. Unlisted
names (including generic parameter-unspecified PQC names) become UNKNOWN with
null algorithm_id; safe observed_name remains unchanged. A missing/invalid
context is an error. An observed name must be null or bounded, normalized
non-control text (maximum 512 characters, no template delimiters). The context
is not inferred from the name. Contexts and examples:

| Context | Exact example | Algorithm ID | Family / primitive |
|---|---|---|---|
| KEM_CAPABILITY | MLKEM768, ML-KEM-768 | ml-kem-768 | PQC / KEM |
| KEM_CAPABILITY | Kyber768 | legacy-kyber-768 | PQC / KEM |
| TLS_KEX | X25519MLKEM768 | tls-x25519-mlkem768 | HYBRID / KEX |
| TLS_KEX | X25519Kyber768Draft00 | tls-x25519-kyber768-draft00 | HYBRID / KEX |
| SSH_KEX | mlkem768x25519-sha256 | ssh-mlkem768x25519-sha256 | HYBRID / KEX |
| SSH_KEX | sntrup761x25519-sha512@openssh.com | ssh-sntrup761x25519-sha512 | HYBRID / KEX |
| SIGNATURE | ML-DSA-65 | ml-dsa-65-signature | PQC / SIGNATURE |
| CERT_PUBLIC_KEY | ML-DSA-65 | ml-dsa-65-public-key | PQC / PUBLIC_KEY |
| SIGNATURE | SLH-DSA-SHA2-128s | slh-dsa-sha2-128s-signature | PQC / SIGNATURE |
| CERT_PUBLIC_KEY | RSA | rsa-public-key | CLASSICAL / PUBLIC_KEY |
| SIGNATURE | RSA | rsa-signature | CLASSICAL / SIGNATURE |
| SIGNATURE | ECDSA | ecdsa-signature | CLASSICAL / SIGNATURE |
| SYMMETRIC_CIPHER | AES | aes | CLASSICAL / SYMMETRIC |
| TLS_CIPHER | TLS_AES_128_GCM_SHA256 | tls-aes-128-gcm-sha256 | CLASSICAL / SYMMETRIC |
| SSH_CIPHER | aes128-ctr | ssh-aes128-ctr | CLASSICAL / SYMMETRIC |

A catalog row has a distinct slug, family, primitive, context, aliases and
provenance. Generic RSA/EC/ECDSA/AES names classify the stated family/use only,
not an inferred key size, hash, padding, parameter or security level. Standard
ML-KEM/ML-DSA/SLH-DSA parameter identifiers and legacy Kyber/Dilithium/SPHINCS+
identifiers are distinct; protocol hybrid groups have their own IDs and do
not collapse into pure KEM IDs. The FIPS_203/204/205 provenance labels identify
algorithm standards, not validation of a module or operating mode. The catalog
is bounded, not exhaustive. Unknown algorithms remain unknown; a collector
can extend only via an approved taxonomy update. TLS cipher suites, TLS/SSH
KEX groups, certificate keys and signatures are separate contexts. For example,
X25519MLKEM768 in KEM_CAPABILITY, MLKEM768 in TLS_KEX and TLS_AES_128_GCM_SHA256
in TLS_KEX are all UNKNOWN, not a substring match. No FIPS policy or software
version is a taxonomy alias or proof of readiness.

Migration categories: CLASSICAL_PUBLIC_KEY_MIGRATION for classical KEX/public
key/signature, SYMMETRIC_REVIEW for symmetric ciphers, LEGACY_PQC_REVIEW for
explicit legacy provenance, PQC_OR_HYBRID_INVENTORY for other classified
PQC/hybrid entries, UNKNOWN otherwise. These are inventory labels, not claims
of present breakage, FIPS compliance, sufficient key strength, security
percentages or automatically generated remediation instructions.

## A02: independent direct evidence and conservative coverage

Only the typed, explicit observations below can prove a fact. The parent's
acquisition state must be COLLECTED or PARTIAL. A PARTIAL collection may
provide direct proof of one exact fact; it never proves complete coverage.
Neither a package version nor any other level implies a different level.

| Level / fixed rule ID | Evidence kind / decisive field | PASS / FAIL |
|---|---|---|
| L1 / pqc-l1-installed | PACKAGE_INVENTORY / present | true / false |
| L2 / pqc-l2-supported | RUNTIME_CAPABILITY / supported | true / false |
| L3 / pqc-l3-configured | EFFECTIVE_CONFIGURATION / allowed | true / false |
| L4 / pqc-l4-negotiable | AUTHORIZED_NEGOTIATION / outcome | NEGOTIATED / REJECTED |
| L5 / pqc-l5-observed | OBSERVED_USAGE / outcome | OBSERVED / CONTRADICTED |

L1-L3 statements concern the exact named package/capability/setting and
subject, not a broader service or fleet. A null algorithm can support an
unqualified L1-L3 fact, including an explicit FIPS setting, but never an
algorithm-specific result. If an algorithm record is supplied, the evaluator
checks its ID, family, primitive, observed alias and taxonomy version against
the catalog. An unknown/inconsistent annotation cannot support a decisive
algorithm claim. Evidence V1 does not store a separate general observation
context field: producers must use the explicit classifier correctly; the
adapter verifies the recorded tuple, and for L4 also the protocol context.
L4 requires the original validated service/host/conditions, observed time,
known algorithm and actual outcome. TLS or SSH KEX/cipher observations must
match the corresponding protocol context; explicit signature negotiations
may concern the signature only. A raw KEM capability or certificate public
key does not establish an L4 negotiation. L5 requires a known algorithm and
actual typed usage observation with the original V1 method, service,
business source and valid time interval. The original Evidence validator
checks precise UTC ordering, including the recorded-at boundary. Negotiation
alone never creates a usage claim. Synthetic observations are not live proof.

Direct groups use exact host_id, asset_id (including null), algorithm_id,
literal collection scope_key, level, exact package name/capability/setting,
and full literal L4/L5 conditions. Unqualified and explicitly unclassified
observations are separate; distinct unclassified annotations with null ID
are not merged. Different scope/subject/fact/context cannot lend proof.
For repeated observations of the same fact and exact context within a run,
contrary direct outcomes yield PARTIAL (CONFLICTING_EVIDENCE); no arbitrary
latest-wins or timestamp substitution for identity. A mix of decisive and
incomplete observations gives PARTIAL (INCOMPLETE_EVIDENCE). A single
unambiguous usable direct fact gives PASS/FAIL with DIRECT_POSITIVE or
DIRECT_NEGATIVE. Observation time is retained through evidence references;
L1-L3 legacy timestamps may remain null, without asserting a current-time
observation. No cross-run evidence is used. Null boolean, ERROR/TIMEOUT/
UNKNOWN outcome, missing tool, denied access, unavailable host, and other
acquisition failures never manufacture a direct FAIL. Missing facts are
UNKNOWN, with no fabricated claim for an unspecified subject or an L4/L5
condition that does not exist in the input.

Coverage uses separate `pqc-coverage` findings, scoped to the collection
collector/scope and exact observed subject. No readiness PASS is created
from a successful empty inventory, metadata, or an applicability summary.
An explicitly NOT_SCANNED collection yields NOT_SCANNED with its original
validated reason, no evidence references. A host with no collection yields
UNKNOWN, or NOT_SCANNED if explicitly NOT_ATTEMPTED. Failed/unknown acquisition
yields UNKNOWN (ACQUISITION_UNAVAILABLE); a partial collection with relevant
nontrivial evidence yields PARTIAL (INCOMPLETE_COLLECTION). Otherwise a
coverage-only result is UNKNOWN (NO_DIRECT_EVIDENCE). For successful
collections containing only direct observations, the direct claims already
describe the available facts; no additional coverage finding is necessary.
Absence of a claim is not PASS/FAIL or proof of non-applicability.

NOT_APPLICABLE requires an explicit applicable=false COLLECTION_SUMMARY,
usable applicability acquisition, exact same scope and subject, and a
consistent known annotation when algorithm is specified. For a direct claim,
applicability must match the literal known observation times of the group's
rows; unknown or different timestamps do not lend N/A proof. Contrary usable
applicability or direct observations are treated conservatively as conflicts,
not discarded. The summary describes its own scope, not an inferred parent or
child scope. There are no blanket host-wide N/A or disabled algorithm claims.

## A03: identity, offline reevaluation, and compatibility

A direct claim uses `claim_id` from ID-V1 with the exact subject, level,
rule_id, fact key and original conditions. The fact key is a SHA-256 token
of a canonical JSON tuple of the literal scope, fact and subject qualifier;
it is not the timestamp, input position or a path. Each finding uses the
original `finding_id` helper and a token of the fact key and context, linked
to its exact claim. Coverage findings use the original subject and a token
of the collection's logical collector/scope and qualifier. Generated keys
are bounded opaque tokens, not a copy of names or raw values. References
point only to actual source IDs or generated same-rule claims. Hashes and
IDs are not anonymization. The versions of the rule and its catalog are
bound by the shipped trusted configuration; algorithm evidence retains
its own taxonomy_version, claims/findings retain rule_version. No new
Evidence fields are introduced.

Canonical output sorts registry arrays and reference sets using the original
validator. Reordering input registry/reference sets does not change the
canonical assessment. Existing valid results of other rules are preserved.
A pre-existing result of this ruleset must exactly match recomputation
(reference-set order excepted); conflicting IDs, stale owned results and
version conflicts raise ASSESSMENT_CONFLICT, never silently replace data.
For changed evidence or approved rules, evaluate the original unassessed
Evidence document and retain the previous evaluated document separately.
No upgrade/downgrade of Evidence schema, taxonomy or rule version is guessed.
The V1 contract accepts only Evidence 1.0.0; future 1.1.0 integration requires
its own approved compatibility contract. Output size is subject to the
original Evidence model's bound; no truncation or partial verdict is returned.

## R4 tests and remaining work

```sh
python3 -m py_compile tools/assessment.py tests/unit/test_assessment.py
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python3 -m pytest -q -rs -p no:cacheprovider tests/unit/test_assessment.py
```

Only synthetic data and the unchanged Evidence public API are used. Tests
cover positive/negative exact aliases, collision and malformed rules,
all five levels, scope/subject/algorithm/time and acquisition boundaries,
strict output/ID/reference validation, idempotence, conflicts, and no I/O.
The engine does not modify existing normalize_pqc, generate_cbom, CFF,
HTML, legacy importer, or any collector. Actual producer normalization,
legacy import (#12), CFF (#13), CBOM (#26), Portal and release integration
remain their assigned work packages. Real negotiation/usage, real Controller
and Oracle Linux 9.7/9.8/9.9, actual data and offline release verification
remain NOT_TESTED / RELEASE_QA_PENDING (#28, later Active #36-38). No
formal release or readiness claim follows from synthetic test success.
