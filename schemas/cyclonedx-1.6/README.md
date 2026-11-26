# Pinned CycloneDX 1.6 schemas (#26 A)

These are unmodified upstream release files, not generated schemas. Source:
[CycloneDX/specification release 1.6](https://github.com/CycloneDX/specification/releases/tag/1.6),
commit `55343ba19dee1785acf1ce9191540d5fd7b590db`, tree
`67cf9fdf15cd985f0981e1f81259a233ad657f29`. The upstream `LICENSE` is
included unchanged (Apache-2.0); embedded attribution is retained.

| Upstream path | Bytes | Git blob SHA-1 | Raw SHA-256 |
| --- | ---: | --- | --- |
| `schema/bom-1.6.schema.json` | 252625 | `d52d4631b42c3c6370bc545e369611327ff6e1c8` | `3e92dddbc30cf7f6a02b80f0942b1a4cfd4fb1c26f1dfc4310afa9d613cafb93` |
| `schema/spdx.schema.json` | 14269 | `d081ef979232166476cb25eb4e33edb1f6ba83da` | `baa9d3bd1ed57b6751b0887edead6b5063ff53ff7429cf85d476c6c94af0166e` |
| `schema/jsf-0.82.schema.json` | 8058 | `f46bfb1e52731ad1280123ff3e2bd29bd18d4bc2` | `8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae` |
| `LICENSE` | 11341 | `0808751c23d827d483dc3673d6e3f49514e49d1f` | `6c29f22a4a7385285c6f579ec9f33c5e989f00739d6b257243a0b082ec9447ae` |

All three schemas declare `http://json-schema.org/draft-07/schema#`. Their
canonical IDs are `http://cyclonedx.org/schema/` followed by the exact local
schema name. The root's only nonfragment references are `spdx.schema.json`
and `jsf-0.82.schema.json#/definitions/signature`; both dependencies have no
external references. The standard Draft7 meta-schema is supplied locally by
jsonschema, not downloaded. The URIs are identifiers, never retrieval URLs.

## Controller-only dependency and execution boundary

Use Python jsonschema 4.x with the `registry=` API, referencing Registry and
Resource, and the four registered format checks `uri`, `iri-reference`,
`idn-email`, `date-time`. In particular the official JSF `oneOf` requires URI
format checking to distinguish named algorithms from proprietary URI values.
Missing APIs/format checks fail closed. The development environment inventory
is Python 3.13.5, jsonschema 4.26.0, referencing 0.37.0,
jsonschema-specifications 2025.9.1, attrs 26.1.0, rpds-py 2026.5.1;
format-checker providers rfc3986-validator 0.1.1, rfc3339-validator 0.1.4,
rfc3987-syntax 1.1.0, lark 1.3.1, six 1.17.0. These are observed development
versions, not an Oracle Linux controller qualification or deployment lock.
Referencing on Python <3.13 additionally declares typing-extensions. Install
and pin a verified compatible dependency closure only during an authorized
controller deployment, from local material or the approved existing PyPI
proxy. No runtime installation, download, network fallback, target dependency,
new service, or Ansible runtime restore is required by this module.

The trusted installed source tree contains the fixed schema directory; the
POSIX controller opens fixed directory/file descriptors with no symlink
following, bounds file reads by their pinned sizes, and checks SHA-256 and
canonical IDs on every validation. No instance may choose a file or resolver.
The offline registry registers only the three above URIs and denies retrieval
of anything else. The Windows/Linux browser acceptance is separate from
controller-side Python execution.

## API

```python
from tools.cbom_validation import validate_cbom, validate_cbom_bytes, CBOMValidationError

result = validate_cbom({"bomFormat": "CycloneDX", "specVersion": "1.6"})
assert result.schema_status == result.reference_status == "PASS"
```

`validate_cbom_bytes` accepts bytes (strict UTF-8, duplicate-free JSON), not a
path. `validate_cbom` accepts a builtin JSON object tree that is not modified
concurrently; it does not mutate the input. Raw input and compact ASCII JSON
size are bounded to 32 MiB each; containers count toward a depth of 64. Cycles,
non-JSON types, lone surrogates, NaN/Infinity, wrong format/version, and an
explicit `$schema` other than the exact canonical 1.6 root ID are rejected.
The validator returns `ValidationResult` only for both checks passing. On
failure it raises `CBOMValidationError` with a fixed `code`, `schema_status`
and `reference_status`. Input/version/installation failures leave both checks
NOT_TESTED; invalid official schema instances have schema FAIL and references
NOT_TESTED; product-reference failures have schema PASS and references FAIL
or UNSUPPORTED. Error messages never include the input value, URL, path, or
underlying schema-validation exception. Missing, changed or inaccessible
pinned files fail closed; there is no mutable schema fallback.

## Closed V2.0 product reference profile

After official schema validation, collect actual local definitions globally;
only then check typed relation slots. A `bom-ref` is an opaque local identity,
not a locator. Control/whitespace-bearing identifiers, external BOM-Link
(`urn:cdx:`) and URL-looking identities/relations are unsupported. Ordinary
metadata URLs/endpoints/external references and ref-like property names,
identifier strings and signature fields are not local relations or fetched.

Definitions: `metadata.component`, root `components`, recursively nested
`components`, root `services`, recursively nested `services`, modern
`metadata.tools.components/services` (old tool arrays have no definitions),
organization/manufacturer/supplier/provider/contact/authors/address
`bom-ref`, and `licenses[].license.bom-ref` or license-expression `bom-ref`.
Every actual definition shares the same namespace. Organizational/License
IDs cannot serve as dependency or cryptographic asset endpoints. Missing
optional `bom-ref` is not fabricated, and an unresolved reference is invalid.

| Relation slot | Permitted existing target |
| --- | --- |
| `dependencies[].ref`, `dependsOn[]`, `provides[]` | Component or service (including crypto components); one dependency row per owner, no self-reference |
| `cryptoProperties.certificateProperties.signatureAlgorithmRef` | Cryptographic asset, assetType algorithm, primitive signature |
| `cryptoProperties.certificateProperties.subjectPublicKeyRef` | Cryptographic asset, related-crypto-material, type public-key |
| `cryptoProperties.relatedCryptoMaterialProperties.algorithmRef` | Algorithm asset |
| `cryptoProperties.relatedCryptoMaterialProperties.securedBy.algorithmRef` | Algorithm asset |
| `cryptoProperties.protocolProperties.cipherSuites[].algorithms[]` | Algorithm asset |
| `cryptoProperties.protocolProperties.ikev2TransformTypes.{encr,prf,integ,ke,auth}[]` | Algorithm asset |
| `cryptoProperties.protocolProperties.cryptoRefArray[]` | Cryptographic asset |

Crypto components require a typed `assetType`; property blocks may be absent
but must not contradict it. Noncrypto components cannot claim cryptoProperties.
No self-reference is accepted in a relation. A public-key or signature edge
requires the explicit target type; no label, opaque ID or co-location inference.
No reference is created by validation. `provides` does not mean in-use.

The supported root keys are `$schema`, `bomFormat`, `specVersion`, `serialNumber`,
`version`, `metadata`, `components`, `services`, `dependencies`,
`externalReferences`, `properties`, `signature`. The module enumerates the
allowed metadata/component/service keys, including ordinary scalar metadata,
properties, hashes, licenses, tags, signatures and external references. Other
schema-valid models (compositions, vulnerabilities, annotations, formulation,
declarations, definitions, component pedigree/evidence/modelCard/data/
releaseNotes, service data/releaseNotes, commercial licensing details) are
explicitly UNSUPPORTED, even when empty, rather than claiming comprehensive
reference integrity. Raw crypto material `value` is outside this discovery
profile. Any additional field or model needs an explicit later contract.
The JSF structure is schema-checked; this is not signature authentication.

This is A only: no CBOM generation, evidence/asset mapping, claim assessment,
legacy module changes, Report Root writes or Portal links. Schema validity
and local reference integrity do not establish L1-L5 or evidence authenticity.
B/C require separate authorization. Formal controller/offline deployment and
browser acceptance remain #27/#28.
