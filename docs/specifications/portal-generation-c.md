# Portal Generation C-A: verified payload assembler

C-A implements the internal, in-memory part of the shared C generation
contract for issues #22, #23 and #26. It is not a publication API, a receipt,
a new Store version, a catalog entry, or activation of portal-v5. C-B and
C-C own navigation, publication, receipt and admission in later slices.

## Verified call chain and compatibility

The future renderer/catalog caller must supply the **unmodified result of
its pinned actual Store.open call** to the private `_assemble_payload` helper
in `tools/portal_generation_c.py`. A NamedTuple is not an authentication
mechanism. Neither this helper nor the private shared projection helpers
are public input APIs, and none accepts a path, URI, raw report, or caller
claim of authority. No new Store subclass, trust marker or open override is
introduced. Do not expose these helpers as a public or CLI entry point.

Existing `render_certificate_csv` and `build_cbom_bytes` retain their exact
RunStore type, actual open, run/host input checks and errors. The latter
retains default B1 and explicit boolean B2 selection. A summary preview
retains its existing verified-publication contract. The shared serializers
and original C2, A, B and B2 semantics are not copied or reinterpreted.
A artifact-slot verification uses the actual V2 producer contract when
present, so the existing C1 detail slots and producer rules are accepted
without relaxing V1 validation or changing already successful A bytes.

## Fixed payload

`_Payload` contains the run ID, a name-sorted mapping of immutable byte
buffers and a name-sorted tuple of name/size/SHA256 records. There are nine
fixed batch-level entries and two entries per expected host:

- certificates.html, services.html, findings.html, coverage.html;
- asset_indexes.json, scan_summary.json;
- summary.csv, algorithms.csv, certificates.csv;
- h-<64 lowercase hex>.cbom.json and h-<64 lowercase hex>.cbom.provenance.json.

All are preview bytes; relative links are not yet a complete site. The
expected hosts include unreachable, not-attempted and zero-evidence hosts.
The verified manifest determines run/host identity and coverage. Missing
or empty evidence is not proof of absence, a complete inventory or success.
Each BOM is explicit B2, uses the existing pinned CycloneDX 1.6 validator
(schema and typed references), and retains its paired provenance/hash.
Unproved standalone public keys and fingerprints remain omitted with their
original B2 reason codes and evidence references; full standalone support
remains OPEN. Only proven certificate-bound subject keys can be emitted.
No new acquisition, classification, assessment or certificate parsing is
performed. No raw certificate, key material or diagnostic dump is added.

C2 performs its original crypto pivot validation once. One additional shared
crypto projection feeds A and every CBOM. The private batch inputs partition
registry and membership references by host, preserve the original global
identity and metadata qualification, and reuse verified taxonomy, CFF and
artifact digests. They do not replicate a full document or re-run a batch
projection or Store.open for each host. Each individual BOM still undergoes
actual validation. All projection membership and output limits remain.

## Capacity and error boundary

Byte limits count the actual UTF-8/CSV/BOM buffers, not row estimates:

| Payload category | Individual limit | Aggregate limit |
| --- | ---: | ---: |
| HTML | 16 MiB | 128 MiB |
| Asset and summary JSON | 32 MiB each | bundle limit |
| CSV | 16 MiB | 32 MiB |
| CBOM and provenance pair | 32 MiB per host | 256 MiB |
| C-A payload | | 512 MiB |

The original 1000 expected host bound remains. The shared CBOM membership
partition also charges retained registry and membership references against
256 MiB / 66 entries; per-host and original projection limits still apply.
New CSV and per-host pair serialization uses the remaining applicable byte
budgets. CSV quoting, BOM, CRLF and formula/control protections are unchanged.
No partial mapping escapes an error. Capacity failures raise the fixed
StoreError `PORTAL_PAYLOAD_SIZE_LIMIT`; invalid projection, validation or
source failures raise `PORTAL_PAYLOAD_INVALID` without raw diagnostics.
These are internal errors; old public preview errors are unchanged.

The 512 MiB final generation budget must also account for the later index,
CSS and receipt. The final 128 MiB HTML aggregate, 32 MiB crypto JSON,
1 MiB v5 receipt and unchanged 4 GiB / 1000-row catalog admission limit are
C-B/C-C responsibilities, not additional outputs or features of C-A.
No report files are written or published. Formal environment and maximum
capacity/load acceptance remains in release QA #28.
