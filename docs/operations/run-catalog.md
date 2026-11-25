# Run Catalog and history navigation (V2.0)

The catalog is an offline snapshot of direct children of an existing,
Owner-approved private report root. It does not launch scans, recover runs,
re-assess evidence, or generate/refresh individual run pages. An unavailable
portal does not change the verified run outcome.

## Operations

From the trusted repository, on the Controller using the existing Python and
Jinja2 environment:

```sh
python -m tools.run_catalog --report-root /approved/private/reports
python -m tools.run_catalog --report-root /approved/private/reports --check
python -m tools.run_catalog --report-root /approved/private/reports --recover
```

The root must already exist as a private local Linux directory (0700, owned by
the effective user, with safe ancestors), under the same Run Store filesystem
contract. No automatic creation/permission repair of the root, network access,
Ansible dispatch or additional dependency installation. The default command
rebuilds from a bounded enumeration snapshot; `--check` is read-only and checks
only the published catalog pair and its immutable snapshot, not run freshness.
`--recover` explicitly rebuilds after a proven catalog publication interruption.
The two flags are mutually exclusive. Exit 0 means publication or consistency
verified (not scan/readiness PASS); exit 1 is a fixed failure reason, including
busy/recovery/durability failure; exit 2 denotes invalid arguments.

Open `reports/index.html` locally. The table works with JavaScript disabled; no
server, external styles, fonts, network or local JSON fetch. Move or archive and
extract the **whole** report root, including `catalog.generations`, preserving
private permissions for further Controller operations. Existing Portal v1/v2/v3/v4
pages are not changed by a catalog rebuild.

## Opt-in Portal v3 history navigation

The catalog links to every verified available batch dashboard. To add return
links for a specific run, first publish a coherent catalog, then explicitly
render that run with history enabled:

```sh
python -m tools.run_catalog --report-root /approved/private/reports
python -m tools.render_portal --report-root /approved/private/reports --run-id RID --with-history
# For an existing exact v1 or v2 portal, explicitly authorize replacement:
python -m tools.render_portal --report-root /approved/private/reports --run-id RID --refresh-portal --with-history
python -m tools.run_catalog --report-root /approved/private/reports
python -m tools.run_catalog --report-root /approved/private/reports --check
```

Use only the applicable render command. Replace RID with the approved run ID;
the run need not already be listed in the catalog. There is no automatic
refresh of all historical runs, and no scan, SSH or reassessment. Without
`--with-history`, a new portal remains v2; `--refresh-portal` alone allows
only the original v1-to-v2 upgrade (or an exact existing portal no-op).
`--with-history` alone does not replace an existing v1/v2 index. An exact v3
portal is verified without rewriting it, for all four flag combinations,
even when the current catalog is missing or inconsistent. That no-op does not
prove the history link currently opens; use the explicit catalog operations
above to restore the entrance. The renderer never creates or recovers a
catalog automatically. CLI exit 0 (`PORTAL_RENDERED`) means derived publication
or no-op verification, 1 a fixed failure reason, 2 invalid arguments.

Portal v3 uses the stable run `index.html` and fixed `portal-v3/hosts.html`,
`portal-v3/<host-id>.html` and `portal-v3/portal_receipt.json` (format 3).
History breadcrumbs link to the stable root `index.html`: `../index.html` from
the batch, `../../index.html` from nested pages. Batch/host-list/host links,
anchors and verified artifact references remain relative; the whole root
can be moved with both v2/v3 generations and the catalog snapshots intact.
CBOM is not provided by this slice. Old v1/v2 pages are still accessible from
the catalog; a retained v2 host page can return to the newly upgraded batch.
The v3 history link does not bind a catalog generation hash. Rebuilding the
catalog after the explicit upgrade records `portal-v3` in its new snapshot;
previous coherent snapshots remain valid historical records, not freshness
proofs.

The new v3 publication holds a shared `.catalog.lock` from coherent catalog
validation through the stable run index switch. The lock order is catalog
then run; a run-only probe is released before acquiring the catalog lock.
Ordinary v1/v2 rendering and exact v3 no-ops do not require a catalog lock.
New v3 generation checks the pinned root/lock and coherent stable slots again
before the index switch. Run Store authority, frozen scope and the original
core-byte rechecks remain in force. Only exact old v1/v2 index/CSS (and the
complete v2 generation for a v2 upgrade) may be replaced by the opted-in
v3 index. Old v2 pages/receipt, CSS and immutable core files are retained;
the old stable index is not separately archived. A v3 marker is a routing
hint, never proof of a generation. All expected pages and the deterministic
receipt must match exactly. Existing unknown/corrupt/unsafe output is refused,
not repaired. The same per-page, total HTML, CSS and receipt caps apply.

The renderer writes missing exact v3 pages no-replace, seals the receipt after
the complete page set, syncs and publishes the stable index last. A known
exact partial generation can be resumed; a present receipt requires a complete
matching set. A failure before the stable switch leaves the old entry intact;
a failed sync after a switch is `DURABILITY_UNCONFIRMED`, not success or
rollback. Retry verifies the exact visible version and reconfirms durability.
Do not remove unknown staging or change permissions to force a retry.

## Opt-in Portal v4 crypto indexes

A v4 portal includes history navigation and the evidence-backed Algorithms and
Libraries indexes. The default for a new run remains v2; `--with-history`
without the new flag still selects v3. First explicitly publish a coherent
catalog, then render only the approved RID:

```sh
python -m tools.run_catalog --report-root /approved/private/reports
# Fresh run with no stable portal index:
python -m tools.render_portal --report-root /approved/private/reports --run-id RID --with-crypto-indexes
# Existing exact v1, v2 or v3 portal (explicit replacement):
python -m tools.render_portal --report-root /approved/private/reports --run-id RID --refresh-portal --with-crypto-indexes
python -m tools.run_catalog --report-root /approved/private/reports
python -m tools.run_catalog --report-root /approved/private/reports --check
```

Use only the applicable render command. `--with-crypto-indexes` itself includes
history; also specifying `--with-history` is valid. The equivalent API is
`render_run(root, rid, with_crypto_indexes=True)`, with `refresh_portal=True`
required to replace a proven old index. All three flags are keyword-only
Booleans. CLI abbreviations are rejected. Without refresh, existing v1/v2/v3
cannot be overwritten by v4. Exact existing v4 is verified without rewriting
or downgrading under every combination of the three flags, even if the current
catalog is missing or inconsistent. That no-op does not establish a working
history link; use the explicit catalog operations to restore it. No automatic
catalog rebuild/recovery, scan, or reassessment occurs.

The fixed `portal-v4/` directory contains `hosts.html`, every expected
`<host-id>.html`, `algorithms.html`, `libraries.html`, `crypto_indexes.json`,
and `portal_receipt.json`. The stable run entry remains `index.html`. Format 4
receipt binds the manifest, index and CSS SHA-256 and the sorted fixed derived
file names/sizes/hashes (including the JSON). The JSON is the exact bounded
canonical projection used by the two index pages, not separately computed
statistics. Each group links to its recorded host, asset, evidence and saved
claim anchors; backlinks are the reverse of those explicit memberships.
Unresolved saved claims stay unresolved and point to the unresolved section.
Counts are unique-set cardinalities, not readiness scores; package presence,
CLI or provider metadata never establishes service library use. The two
reviewed index templates and projection rules are unchanged.

The v4 batch and host pages link to the two index pages and JSON via fixed
same-generation relative paths. History/Batch/Hosts/peer and evidence links
work offline with the complete report root retained. Prior generations are
not amended; their stable batch link can return to the upgraded index. Do not
copy just one page or mix generations. Catalog refresh records `portal-v4`
only after exact proof of the currently referenced stable entry; old coherent
catalog snapshots remain valid, not fresh. No browser script, external
resources, or JSON fetch is needed.

The same catalog-first shared lock and pinned root / run locking order as v3
apply to a new or upgraded v4. The Store must validate the published core and
frozen scope; the old index/CSS and its referenced v2/v3 generation must be
exact before an upgrade. The v4 writer verifies the fixed slot set and
file/directory identities and content again before the stable switch. Missing
exact staging files can be resumed no-replace; a present receipt requires the
complete exact set. Unknown, corrupt, or unsafe slots are refused, not repaired.
The receipt is sealed after all derived files and the stable index is switched
last, with fsync. A failure after the switch is not success or rollback; retry
verifies the visible exact generation and its durability. Old v2/v3 files,
CSS, manifest, journal and immutable core bytes remain unchanged.

The per-HTML-page cap is 16 MiB and the combined HTML cap (including the stable
index and both index pages) is 128 MiB. The only fixed non-HTML generation
slot, `crypto_indexes.json`, has a separate 32 MiB cap and is excluded from the
HTML aggregate; CSS is capped at 256 KiB and the receipt at 256 KiB. Each
admitted derived file, including this JSON, counts once toward the existing
4 GiB catalog admission limit. Generated or actual proven capacity excess is
fatal for the whole catalog rebuild/recover; ordinary corruption stays an
invalid unlinked row. No output truncation or implicit downgrade. Actual
filesystem/power-loss/load and Windows/Linux file-browser acceptance remain
release QA; an engineering relative-link check is not browser certification.

## Interpretation

`run_catalog.json` is canonical catalog version 1 / render format 1, with
SHA-256 generation of the canonical payload excluding `generation`, summary,
fixed diagnostics and ordered rows (validated recorded time descending, then
literal run ID; unknown times last). Only a successful actual `RunStore.open`
provides run kind, source, recovery flag, outcome, dates, host counts, missing
artifact count and manifest hash. No host names, Inventory, raw evidence,
absolute paths or source references are included. Unknown fields are null, not
zero or a guessed failed scan.

| Publication | Interpretation |
| --- | --- |
| PUBLISHED | Verified immutable publication; COMPLETE, PARTIAL or ERROR preserved. |
| UNPUBLISHED_OR_INCOMPLETE | Safe direct candidate without a published marker. |
| INVALID | Unsafe/casefold collision or unverified marker, lock or core. |
| BUSY | Could not obtain the run's shared lock. Outcome unknown. |

The separate `portal_status` is AVAILABLE (exact verified v1, v2, v3 or v4),
NOT_GENERATED (no derived slots), INVALID (incomplete, unsafe, unknown or
inconsistent derived output), or NOT_VERIFIED (publication not verified).
Only AVAILABLE has a relative `run_id/index.html` link. Only the version
referenced by the stable run index is verified; unreferenced v2/v3/v4 retained
or staging directories are not opened. A v2/v3/v4 index needs the complete
expected generation and matching receipt/manifest/CSS bytes. V4 also verifies
the exact canonical crypto index JSON with its separate cap.
The catalog schema, version, render format and immutable snapshot contract
are unchanged. There is no historical trend or security/readiness score.

Case-insensitive duplicate IDs are all rejected; reserved/temporary/non-ID
entries are counted rather than interpreted or printed. No recursive discovery
or archive reading. Fixed catalog/store infrastructure names are not candidates.
The root enumeration cap is 100,000 direct entries; maximum 1,000 legal candidates
and 4 GiB cumulative admitted indexed core, marker/journal and derived bytes
(including admitted bytes for invalid candidates). This is an admission limit,
not actual I/O or a performance SLA. Per-run Store/Portal limits still apply.
A proven capacity excess (safe fixed-file size, structurally admitted indexed
size/count/aggregate, or the fixed renderer's generated byte limit) stops the
whole rebuild, including `--recover`, with `CATALOG_CAPACITY` or the existing
root/output limit reason. Oversized files are not read. Indexed core admission
is charged once; safe stat checks do not charge those bytes again. No new
generation or stable replacement is made on a capacity failure.

Ordinary Run corruption is different: a within-limit size mismatch, wrong
hash, malformed declaration, missing or extra slot, unsafe inode, or invalid
page is not by itself capacity evidence. The affected row remains unverified
or has an invalid portal with no link; other valid runs can still be included
and a new catalog published. Unknown or unsafe names are not examined to infer
capacity. The Store remains the publication authority; diagnostic admission
never makes a rejected manifest valid. A coherent old catalog can still pass
`--check` after a refused rebuild (consistency, not freshness). These rules do
not permit overwriting foreign/corrupt catalog output or bypassing locks.

Limit failure does not publish a truncated index. JSON and HTML each have a
16 MiB cap, receipt 256 KiB. A new run finishing after enumeration is visible
on a later rebuild; the catalog is not a globally atomic live inventory or a
retention ledger for runs removed externally.

## Publication and interruption

The private `.catalog.lock` serializes catalog writers; checks use a shared
lock, with bounded five-second acquisition. Catalog lock precedes one shared
per-run lock at a time. `catalog.generations/<generation>/` contains an immutable
closed set: `run_catalog.json`, `index.html.snapshot` (verification copy, not a
navigation page), `catalog_receipt.json`. Each file is private 0600. A complete
private stage is fsynced and published no-replace; existing generations must
exactly match. Stable `run_catalog.json` is switched first, `index.html` last.
The HTML always links to its own immutable generation JSON, never the potentially
cross-generation stable JSON. This is not a multi-file atomic rename.

A complete same-generation rebuild does not replace either stable inode or
modify its timestamp. An interruption between stable switches may leave two
legitimate different generations. The old HTML remains readable with its own
snapshot. `--check` reports `CATALOG_RECOVERY_REQUIRED`; the normal build refuses
an incomplete/mixed pair. `--recover` requires every present stable slot to be
proven by the exact canonical snapshot/receipt/HTML, then rescans and completes
in the same order. A proven single remaining slot can also be recovered.
Unknown, corrupt, foreign, unsafe files or mismatching snapshots are never
silently overwritten, even with recovery; leave them for the Owner to inspect.
An fsync failure returns `DURABILITY_UNCONFIRMED`, not success; reopen and verify,
then explicitly recover if needed. Visible consistency alone is not power-loss
durability. No automatic rollback, deletion of old runs, snapshots or abandoned
stages, or chmod of an existing output. Keep private root access restricted to
trusted cooperating writers; hostile same-UID modifications are outside that
contract.

## Verification boundary

The focused engineering tests use actual synthetic Run Store/legacy import and
Portal v1/v2/v3 output, fixed pre-change v1/v2 hash oracles, exact HTML/JSON,
local locks, fault injection and relocation. Official Controller/local filesystem/power-loss/load qualification,
Windows/Linux `file://` browser and network-zero verification remain #27/#28
release QA. Do not use engineering fixture success as formal release acceptance.
