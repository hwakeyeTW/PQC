# System certificate assets V1.0.0 (X01-X03)

Issue #18, approved proposal 7138843849 and dispatch 7138946352. This is an
internal `pqc_platform_crypto` Role adapter (`tasks_from: cert_assets`) and a
pure Controller projection. It is not a live entry point, trust validator,
service discovery, certificate verification, key discovery, or remediation.
The existing legacy Role, schemas, assessment policy and launcher remain
unchanged. The trusted caller owns the fixed native context, authorization,
`pqc_profile_decision`, `pqc_platform_snapshot`, time and storage. No arbitrary
Inventory/extra-vars overrides are part of this contract. The #7 exact bool
`system_certs` request and VALIDATED decision, #14 consistent identifiable OL9
with known minor, and positive fixed openssl/timeout slots are prerequisites.
A fixed metadata-only `/usr/bin/python3` stat follows the trusted installed
interpreter alias and requires an executable regular root-owned target without
group/other write permissions. Disabled/denied/noneligible cases perform no
stat or acquisition; missing interpreter performs no reader invocation. The
Role has `become: false`, `no_log: true`, non-cacheable facts, no remote service
connection, and only the fixed command. It requires a trusted system runtime,
not protection against root or arbitrary modified executables/environment.

## X01: fixed bounded acquisition

| Root scope | Fixed root |
| --- | --- |
| system-tls-certs | `/etc/pki/tls/certs` |
| system-ca-anchors | `/etc/pki/ca-trust/source/anchors` |
| system-ssl-certs | `/etc/ssl/certs` |

Only `.pem`, `.crt`, `.cer`, `.der` (case-insensitive) are candidates. Root
aliases may resolve only to another exact listed root. File symlinks may
resolve to an eligible regular candidate under these roots, or exactly
`/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem` and
`/etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt`. Other directory
symlinks are not descended; unrecognized non-candidate links record a gap.
Names are bounded ASCII `[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}`, excluding private
key/secret directory names and `.key.` components. No dot traversal, arbitrary
Include, application/Nginx path, home directory, private key directory, network
or trust-store modification. A relative symlink may have initial parent
components, never a collapsed intermediate symlink/`..` sequence. Every
normalized target is checked independently against the fixed allowlist; four
link hops maximum, no cycles. Directory traversal uses no-follow FDs, trusted
root-owned non-group/other-writable components; file entries are pinned with
`O_PATH`, checked regular, trusted and single-link before opening through
`/proc/self/fd` with nonblocking read. Reject special files, unexpected hardlinks,
permissions, unsafe names/targets or identity drift. Check file and directory
identities before/after reading and re-pin; same target identity changes across
occurrences are rejected. These checks address ordinary drift, not malicious
root, mount manipulation, or an OS kernel outside the trusted boundary.

Host-wide depth 3 (root=0), 512 directory entries, 128 candidates, 256 recognized
certificate blocks including failed/repeated occurrences; each source up to
1 MiB actual input, aggregate input 8 MiB including framing reads; DER up to
64 KiB. Enumerate only the bounded available names and sort that set. If the
entry cap is reached, the selection may depend on filesystem enumeration and
is explicitly incomplete; it is not an exhaustive or stable first-N claim.
No unbounded sort/read/retry. Projection max 256 KiB; a conservative 192 KiB
source-detail budget reserves space for constant failure rows, with final cap
check. Discarded metadata retains identified block counts/rc when available.
Missing root, permission, unsafe link, unknown format, depth/entry/byte/block/
projection limits, timeout and drift are distinct constant gaps. Skip counts
include non-candidates; completed traversal accounts for all seen entries.

The fixed command is `/usr/bin/timeout --signal=TERM --kill-after=2s 27s
/usr/bin/python3 -I -B -c <literal helper>` (argv, no shell/argument expansion).
The helper opens `/` itself. It has no root/command/path argument. Work deadline
23 s, alarm 25 s, outer 27+2 s; each fixed x509 child has <=3.5 s I/O/wait plus
<=1 s same-group cleanup, combined stdout/stderr <=16 KiB. Bounded nonblocking
stdin/out/err via selector; parent death signal, subreaper, child process group
kill/reap on timeout/output failure/residue. Cleanup uncertainty stops the
collector with a constant gap, not success. Kernel uninterruptible operations,
escaped processes, transport disconnect/remote cleanup and total dispatch budget
remain #8/actual QA; no claim of proven remote termination. The child environment
is fixed PATH, C locale, `OPENSSL_CONF=/dev/null`, nonexistent HOME; this is
isolated public certificate parsing, not evidence about the service's OpenSSL
configuration or FIPS/provider consumption. No network/OCSP/AIA or update.

## X02: public certificate observations

PEM framing uses bounded 4 KiB reads and exact CERTIFICATE delimiters; LF/CRLF,
blank lines and comment lines outside certificates are allowed. Every identified
block is counted, including malformed/interrupted blocks. Decode only an
explicit CERTIFICATE body's canonical base64; reject malformed/oversized body.
Stop at unknown/non-certificate headers/content, retain independently acquired
public certs with a gap. TRUSTED CERTIFICATE/aux is explicitly unsupported;
never parse its body as an ordinary certificate. A small bounded read-ahead may
contain bytes after a rejected header, but no private body is decoded, hashed,
retained, returned or sent to OpenSSL. DER starts with definite bounded single
X.509-shaped envelope (TBS sequence, algorithm identifiers, SPKI and signature
bit string; exact outer length, no trailing/indefinite/concatenated input).
The framing checker inspects tags/lengths, not general ASN.1 values/private keys.
A mislabeled CERTIFICATE body must be decoded to check its envelope; noncert
payload never reaches x509 or fingerprint computation. No key loader.

Fixed `/usr/bin/openssl x509 -inform DER -noout -sha256 -fingerprint -subject
-issuer -dates -nameopt RFC2253 -text` with controlled certificate stdin. Actual
rc0, bounded output, no stderr and exact SHA256 fingerprint are necessary;
verify fingerprint equals SHA256 of the complete supplied DER. If re-encoding
or unexpected output disagrees, reject rather than identify by PEM or bundle
hash. Extract only known summary lines and named public-key/signature fields;
no raw dump, raw DER/PEM/SPKI, extensions/SAN or private material leaves helper.
Public-key type/size and inner/outer signatures are independent. Conflicting
signatures have an explicit gap and no arbitrarily selected signature annotation.
DNs are RFC2253 ASCII data <=512 chars; reject controls, escaped controls,
template delimiters and private-material markers, do not truncate. UTC validity
dates are exact parsed GMT timestamps or null; contradictions explicit. No
claim of expiry at observation, trust, valid signature, deployment or PQC level.

Each root/source/target reference is an opaque `src-` plus SHA256 of the exact
validated absolute source path or resolved target path (ASCII). A UI may label
`<root-id> / source-<first 12 hex>`; the full digest is identity, not a local
path or URI. Literal filenames are intentionally not retained; an opaque
source reference cannot reconstruct the original pathname. Alias and resolved
target references are distinct; cache only normalized complete source results
for unchanged target identity, count every occurrence. Same fingerprint must
have identical normalized metadata within host; contradictory same-target block
fingerprints reject. No cross-host identity merging. The stable certificate
asset identity key is the full verified DER fingerprint if host stable,
otherwise run-scoped. No separate SPKI identity or scattered public-key asset
is invented; public key metadata is retained inside the certificate detail.

## X03: typed snapshot, evidence and mandatory companion

Role returns `pqc_cert_assets_snapshot` and boolean
`pqc_cert_assets_python_available`. Snapshot is exactly a mapping of the three
root IDs. Each root has `attempted` bool, `rc` int -255..255 or null (helper
outer status), `entries`, `directories`, `skipped` nonnegative bounded counts,
`root_target_id` fixed known root digest or null, sorted unique constant `gaps`,
`sources` sorted by source ID. Each source has exactly
`source_id`, nullable `target_id`, `format` PEM/DER/UNKNOWN, sorted unique
constant `gaps`, ordered `blocks`. A block has `rc` (actual x509 rc or null if
not invoked), constant `reason`, nullable `certificate`. The certificate has
exact `fingerprint` (64 lowercase hex), nullable `public_key_algorithm` (safe
128-char token), `public_key_bits` (integer 1..1048576 or null),
`signature_inner`, `signature_outer` (same token shape or null), `issuer`,
`subject` (safe DN/null), `not_before`, `not_after` (UTC seconds or null), sorted
exact metadata `gaps` derived from missing values/conflicting signature/dates.
No extras, arbitrary reasons or raw input. The block list accounts for recognized
blocks; count successful certificates by non-null certificate, failures by
null, and source gaps describe unexamined/unrecognized content. Root counts
include skipped/failed/repeated entries; caps are global. Snapshot canonical
ASCII JSON <=256 KiB. Missing/disabled/unattempted scopes have no sources or
invented root target. Malformed helper stdout is rejected without raw output.

Controller API:

```python
from tools.cert_assets import build_cert_assets, validate_cert_details
from tools.evidence import canonical_bytes, parse_evidence_bytes

# All caller inputs are already trusted/acquired privately.
result = build_cert_assets(document, host_id, source=source,
    observed_at=observed_at, snapshot=snapshot, rules=rules,
    requested=requested, platform_snapshot=platform_snapshot,
    system_python_available=system_python_available)
combined = {**document, **{k: document[k] + result[k]
    for k in ('collections', 'assets', 'evidence')}}
encoded = canonical_bytes(combined)
validate_cert_details(parse_evidence_bytes(encoded), result['details'], rules)
```

Existing valid Evidence 1.1.0 document, existing host, caller source/time,
fixed producer `pqc-cert-assets/1.0.0`, native/synthetic kind, exact trusted
origin_ref and optional real input_sha256. No self-selected clock, run/host
state, claim/finding or I/O. Three collection scopes; each public occurrence
has ASSET_METADATA(name=full fingerprint, version=null) and separate #11
CERT_PUBLIC_KEY and SIGNATURE classifications when context/name is known;
unknown names remain unknown. No L1-L5 observation/claim. Same-host asset
backrefs contain all occurrence rows; duplicate IDs/metadata conflict reject.
For a collector already present in a document, do not append duplicate rows;
caller must resolve integration, not overwrite identities. A complete root
summary counts successful occurrences, not distinct certs or evidence rows;
zero only after an actual complete empty traversal. PARTIAL requires genuine
certificate evidence and gap. Without cert evidence, denied/unknown/error
remain separate. Disabled produces NOT_SCANNED and zero evidence. No blanket N/A.

`details` is **mandatory paired private data**, not debug output. Canonical
serialization is ASCII JSON, sorted keys, compact separators, no NaN, <=2 MiB.
Exact top keys: `detail_format=pqc-certificate-details`,
`detail_version=1.0.0`, `run_id`, `host_id`, `source`, `observed_at`, `snapshot`,
`roots` (three root records), `occurrences` (<=256). Each root record has common
run/host/source/time, root ID, collection_id, sorted evidence_ids and
`detail_sha256=SHA256(canonical({record: record_without_hash, result: root_row}))`.
Each successful occurrence record has common fields, root, collection_id,
source_id, target_id, 1-based block_index, fingerprint, asset_id, sorted
unique evidence_ids; SHA256 of canonical `{record: record_without_hash_ref,
block: exact_block, format: source_format}` supplies `detail_sha256` and
`detail_ref=cert-<hash>`. Every occurrence evidence row has that opaque
`evidence_ref` and `raw_sha256` of the canonical **detail** bytes, not raw DER.
Root summaries and failure details are paired via root records. Reader uses
`validate_cert_details(document, details, rules)` to recompute exact IDs,
hashes, typed observations, classifications and all references with strict
type equality; reject missing/extra/duplicate/tampered/cross-host/asset/scope
records. No arbitrary paths, parser or commands selected by details. Hashes
bind data, not authenticity; trusted acquisition and #9 private atomic manifest
must protect the pair. #9, #20/#22/#26 must preserve both and rebuild offline.

Engineering checks use actual existing OpenSSL with synthetic generated public
certs, ephemeral private test keys removed, exact helper on synthetic FD roots,
actual original Evidence/Assessment, native short/FQCN loader/no-acquisition
and synthetic literal-root positive harness. No actual managed host or system
trust-store reads. Actual Controller, OL9.7/9.8/9.9, representative bundle
completeness, filesystem layout, privileges/load, transport, integrated offline
report storage/Portal remain NOT_TESTED for #8/#9/#28. No formal support claim.
