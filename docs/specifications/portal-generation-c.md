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

## C-B1: private four-page V5 mode

C-B1a integrated the Certificate and Service pages; C-B1b integrates the
Findings and Coverage pages. The private `_assemble_payload(published, *,
portal_v5=False)` parameter accepts an exact boolean only. The original
public previews and the omitted/False mode retain their successful bytes,
fixed errors and signatures. The True mode changes only the four fixed HTML
buffers and their size/hash records; in particular, the C-B1a V5 asset
pages are byte-identical across C-B1b. The file set, projection JSON, CSV,
per-host B2 CBOM/provenance pairs and membership limits are unchanged.

The fixed relative run-section navigation is Hosts, Algorithms, Libraries,
Certificates, Services, Findings and Coverage. Existing breadcrumbs,
styles, skip links, section IDs and evidence/asset/claim references remain.
Each saved finding links to the Coverage row for its own validated subject
host. The expected host IDs and registry must agree, and Coverage renders
one row for every expected ID. No new finding or inferred binding is created.
Unknown and missing data, absent assessments and saved empty findings retain
their original meaning. Required missing artifact paths remain status text,
not downloadable links. The templates remain fixed, strictly undefined and
autoescaped; no extra projection, evaluation, Store.open or preview render
is introduced.

In True mode the two asset pages first consume their actual HTML and bundle
bytes. The summary renderer consumes the actual summary JSON and two CSV
export sizes from the remaining bundle budget, then streams each of its two
HTML pages against the minimum of the original page limit, the private page
cap and remaining HTML/bundle bytes. Each completed page reduces both
remaining budgets. The original final `_Buffers` checks still apply to
all files; no partial payload is returned. These caps are private, bounded
caller inputs, not new configuration or public authority.

Focused tests retain the fixed Q-to-R historical two-page oracle, using
independently hash-checked old assemblers, asset and summary renderers and
templates. They additionally check R-to-candidate summary-only differences,
all four V5 changes relative to default, actual Store inputs, saved finding
ownership, coverage anchors, safe markup and capacity boundaries, plus the
original actual per-host official schema and typed reference validators.

C-B1 is only the internal page integration. C-B2 still owns the actual C1
V2 run/host/crypto Renderer: its producer-rules label and three `_slot()`
call sites, complete navigation, downloads and reverse links. C-C owns
publication, receipt, catalog admission and CLI integration. No portal-v5
activation, new publication API, Store change or complete standalone key
support is provided here. Formal browser, capacity and deployment acceptance
remains in #28.

## C-B2a: private complete render buffers

The B1 entry point and its default, explicit false and true payloads remain
unchanged. `_assemble_v5_render_payload` is an additional **private** entry
for the same unmodified verified publication. It does not open Store again.
The B1 work path retains its one asset projection, two crypto projections
(including C2 membership validation), one summary projection and the actual
per-host B2 schema/reference validation. The same second crypto projection
feeds the two core crypto pages, crypto JSON and explicit backlinks; there
is no third crypto projection or new assessment.

Only the private V5 renderer derives the Producer V2 slot grammar from the
verified manifest. The run and host views link only present verified slots,
with detail ownership confined to its expected host; producer rules are
batch-wide and have their own label, saved version and SHA-256. Required
missing artifacts stay status text. The private signature branch pins the
closed slot directory chain and file identity, checks the verified bytes,
and includes the manifest and journal signatures. It is not a new public
trust witness or a publication lock/recheck protocol.

The fixed result contains run ID, root index and CSS buffers, sorted nested
file mapping and sorted size/SHA-256 entries. Root entry names are `index.html`
and `portal.css`; nested entry names have the fixed `portal-v5/` prefix. The
nested mapping uses basenames only: the original 9+2*h B1 files plus
`hosts.html`, `algorithms.html`, `libraries.html`, `crypto_indexes.json` and
one `h-<64 lowercase hex>.html` for each expected host (13+3*h nested files,
15+3*h total). The original B1 bytes remain exact. The root index targets
these actual buffers, not a V4 generation. No marker, receipt, catalog,
write or publication is produced. History remains an external prerequisite.
The unchanged host/crypto templates retain existing links and anchors;
reverse/download pivots and seven-section navigation are B2b responsibilities.

After charging the B1 actual bytes, the bounded canonical crypto JSON and
CSS read (256 KiB maximum) consume the remaining bundle budget. The crypto
pages and root/host pages stream UTF-8 against the minimum of page, remaining
HTML and remaining bundle limits before extending each output buffer. Each
page charges actual bytes, including root index. The final fixed set and
category/total checks remain; no partial result, truncation or raw diagnostic
escapes. Original 16/128 MiB HTML, 32 MiB each JSON, 16/32 MiB CSV,
32/256 MiB CBOM pair, 512 MiB total and 1000 expected host limits are unchanged.
Old public rendering, CSS, receipts, errors and publication are not extended
to Producer V2 or V5 by this private branch. C-C owns formal marker/receipt,
lock/recheck, catalog admission and atomic publication. Formal environment,
full capacity and browser acceptance remain #28.

## C-B2b-1 private navigation and verified downloads

Only `_assemble_v5_render_payload(published, navigation=True)` opts in to
this intermediate private view. The flag must be an exact bool. Omission or
False keeps all C-B2a buffers and error contracts; public V1 through V4 and
B1 payload modes are unchanged. Root, Hosts and Host Detail share the seven
fixed Run sections (Hosts, Algorithms, Libraries, Certificates, Services,
Findings, Coverage); existing breadcrumbs, History entrance, local anchors,
host previous/next, and explicit crypto backlinks remain. The current Hosts
section stays linkable. Crypto-page navigation and reverse pivots remain
C-B2b-2; publication, receipt and catalog admission remain C-C.

Metadata is derived from the same bounded actual B1/B2 buffers, not paths or
external metadata. Each expected host's strict BOM/provenance pair is checked
against its fixed name, host ID, run ID, actual BOM SHA-256 and the existing
batch Evidence SHA-256. Host state and B2 coverage remain bound; the original
schema and typed-reference validator is not rerun. The sixth batch-wide
export is the actual canonical crypto JSON buffer. Each row records the fixed
name, run ID, host owner (none for batch-wide), size and SHA-256. The root
lists all six batch exports and all expected-host pairs; a host page lists
only its pair and the same six explicitly batch-wide exports. Missing core
artifacts remain text only; generated downloads are not published artifacts,
and empty/unattempted BOMs do not imply complete inventory. No new files,
public mode, Store.open, projection, raw log, secret or receipt is introduced.

Private metadata is bounded by the existing host count; one host pair is
decoded at a time. All original buffer membership, per-category and aggregate
limits remain, with new HTML charged before each UTF-8 chunk extension.
Fixed invalid/size-limit errors return no partial result. Focused engineering
uses real Store publications, an independent fixed M byte oracle, actual
links/fragments/metadata, pair binding faults and exact/+1 streaming caps.
Formal file://, full-load and production environment QA remain #28.

## C-B2b-2 private reverse pivots and crypto navigation

The exact bool `reverse_pivots=True` requires the complete private V5 buffer
path with `navigation=True`. Omitting it or passing False retains the fixed
F modes, bytes and errors. Algorithms and Libraries share the seven Run
sections, preserving existing breadcrumbs, anchors and cross-index links.
Only those two pages and host pages with new recorded backlinks may change.
Root, Hosts, the B1 asset/summary pages, CSS, JSON, CSV and CBOM/provenance
pairs retain their bytes. No new files, publication marker or receipt exist.

The assembler reuses the actual crypto, asset and summary projections and
verified publication. A private render-only inverted index checks their
run/host/record identity, ownership and explicit membership. Certificate and
service pivots use exact shared evidence IDs, consistent with C2 algorithm
links; library pivots independently use shared evidence IDs. Occurrence
pivots require the matching recorded role evidence, not all occurrences of
that fingerprint. Saved Finding pivots use explicit claim/evidence references
or an exact subject asset ID. Collection pivots identify the member evidence
and its recorded collection. Host coverage is host coverage, not a group
coverage verdict. Host collection and Finding rows link back to precisely
those crypto groups; existing B1 host/evidence/claim links provide the return
path. Unresolved or missing references do not imply a match, use or readiness.
Neither same host, same name, same fingerprint nor transitive relations imply
membership. No additional assessment, Store open or CBOM validation occurs.

The render-only index charges input memberships, candidate visits, accepted
references, edges and backlinks before retaining them, under the existing
32 MiB / 66 membership limit. Rows are deterministic and deduplicated; no
caller-selected URLs, raw diagnostics or new serialized fields are retained.
The original HTML/bundle limits apply before each encoded chunk extension.
Invalid or oversized private assembly returns the fixed invalid/size-limit
error, never partial output. Focused tests use actual synthetic Store runs,
fixed F and prior M/K oracles, precise reverse href/fragment checks, recorded
occurrence subsets, binding defects and exact/+1 capacity boundaries. Formal
browser, filesystem, target OS and full-load acceptance remain #28; C-C still
owns activation and publication.
