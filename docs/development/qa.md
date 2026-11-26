# Isolated local QA gate (PQC-M0-04 R2)

Issue #5 R2 supersedes the Actions-specific Phase A/B proposal. The inherited
Collection Tests workflow is removed **in this candidate**, not by changing
repository settings. The historical PR #48 is not a source or a gate for this
work. Until this candidate is merged, main still has its previous workflow.
Neither a Draft PR nor zero Actions runs proves that automatic execution is
safe. Verify the actual workflow/event/path set before publishing any PR.

This is a manual engineering gate for a disposable Linux/WSL QA environment,
not a deployment tool, scan entry point, sandbox for hostile programs, or
production Controller installation procedure. The runner has no repository
acquisition, token handling, installer, workflow or container management API.
Independent Review, QA and Owner acceptance remain separate. Do not execute
play tasks, check-mode scans, remediation, Vault, SSH or real Inventory scripts.

## 1. Fixed matrix and preparation

| Lane | Python | ansible-core | pytest | ansible-lint | QA manifest |
|---|---|---|---|---|---|
| legacy-217 | 3.11.15 | 2.17.14 | 9.0.2 | not required | requirements-ci-legacy.yml |
| legacy-218 | 3.11.15 | 2.18.15 | 9.0.2 | not required | requirements-ci-legacy.yml |
| maintained-221 | 3.12.14 | 2.21.5 | 9.0.2 | 26.8.0 | requirements-ci.yml |

The two historical `requirements-ci*.yml` filenames/bytes are QA-only.
Legacy pins: community.crypto 2.26.0, ansible.posix 1.6.2, community.general
10.7.0, community.hashi_vault 6.2.0. Maintained pins: 3.0.5, 2.1.0, 12.0.0,
7.0.0 respectively. The legacy core lines are EOL compatibility regressions.
These pins are **requirements, not evidence that any lane is installed or
works**. They are not a complete transitive lock and do not establish Oracle
Linux or Controller support. Preserve the deployment requirements unchanged.

Use a dedicated disposable QA VM/WSL instance, with no production files,
credentials, SSH agent, shared production Docker daemon, database, mounts or
real Inventory. Review system Git configuration (the #4 checker intentionally
preserves normal ignore semantics) and executable/dependency provenance.
Restrict network access at the environment boundary to separately approved
public development sources if necessary; source checks are not an OS sandbox.
Do not run concurrent candidate mutations or other lanes in the same workspace.
Prepare one venv with the exact Python patch version, system site-packages
excluded, in a short absolute path with ordinary pip entry-point shebangs.
Keep venv, approved Collection dependencies, source, manifest and evidence
separate. Restrict private scratch directories to 0700 and evidence to 0600.

Manual preparation, in the approved QA environment only (example for 2.17):

```sh
umask 077
/path/to/python3.11.15 -m venv /qa/venv217
/qa/venv217/bin/python -m pip install --no-index --find-links /approved/wheels \
  'ansible-core==2.17.14' 'pytest==9.0.2'
/qa/venv217/bin/python -m pip check
```

For 2.18 use its exact core pin; for maintained use exact Python 3.12.14,
core 2.21.5 and `ansible-lint==26.8.0`. If separately approved for development,
use official PyPI instead of the approved local wheel source. Install all
approved Collections and their dependency closure into an isolated Collection
root using the corresponding verified QA requirements manifest. For example,
when the approved Galaxy preparation route is available:

```sh
/qa/venv217/bin/ansible-galaxy collection install \
  -r /qa/source/collections/requirements-ci-legacy.yml -p /qa/deps217
```

For offline preparation, use the already approved local Collection tarballs
and complete dependency closure, with offline installation support verified
for the chosen tool. Never use a network fallback to silently complete an
incomplete local package set. Record artifact source, versions, dependencies,
requires_ansible and preparation commands/results. The runner checks actual
Python, package versions, pip consistency, all four Collection versions and
requires_ansible, and actual candidate-first configuration/module resolution.
Unexpected or missing dependencies, unsupported versions and unavailable
images are BLOCKED; do not reduce the matrix or change pins without approval.
Prepare the native ansible-test Docker images and their dependencies in the
isolated environment. Record exact image identities and approved development
network scope before execution; Docker may contact external services if the
required image/dependencies are absent. Deny unapproved egress outside the
runner. No automatic installation/image preparation is provided by the runner.
The QA environment is not the formal offline runtime of Issue #1.

## 2. Source preparation is a separate, reviewed operation

For Head N and, when required, actual integration I, first obtain complete
non-truncated native Git tree **metadata** for the fixed commit, including
ordered parents. Confirm Repository ID 1469533358, `hwakeyeTW/PQC`, base/head
and actual merge identity. Do not infer I from a stale PR field. Recompute
all Git directory tree IDs; check the complete path/type/mode/OID list and
validate the exact source scope before any content acquisition. The manifest
must list all leaves/directories, even exclusions (metadata only).

For this gate use a disposable, source-only local Git projection. The current
policy allows root roles/plugins/playbooks, the named Collection tree,
`docs/development/`, explicit QA files, root `.gitignore`, `README.md`,
`ansible.cfg`, and `reports/.gitignore`; the three explicit #3 paths are
allowed only with the baseline-intake mode. See `approved()` and `REQUIRED`
for the precise policy. Review every selected path, not just a prefix. Refuse
unapproved material within an otherwise allowed directory. Exclude all native
workflows, the historical report archive, real Inventory/host/group vars,
report payloads, deployment setup, secrets, caches, archives, LFS and other
unapproved data. The gate requires a source with no workflow. Unknown or
unsupported native modes (symlink/gitlink included), path/case conflicts,
missing required domains or overlapping allowed/excluded OIDs block acquisition.

Only obtain the unique approved regular blob OIDs through the separately
approved metadata-first acquisition procedure. Verify exact Git blob SHA-1,
size and mode against the native manifest before using any file. Preserve the
actual request/receipt list, complete native tree metadata and reviewer
approval locally. The archive and excluded Inventory are **metadata-only**.
Never clone/fetch a full repository/history, use an archive download or rely
on a partial-clone/sparse fallback. Absence after acquisition is not proof
that data was never acquired. The runner cannot establish past acquisition
safety from a self-attestation: independently verify the receipts and the
manifest digest before invoking it. A missing trustworthy receipt is BLOCKED.

Prepare the exact approved files under a new 0700 directory without symlinks,
hardlinks or filter conversion; set regular file modes to 0644/0755. Build a
local SHA-1 Git projection from those same bytes, not the native history.
Use `git init -q --template= --object-format=sha1 -b projection`, with clean
HOME/XDG, no system/global Git config, no remote, no alternates or promisor,
no hooks, no filters and no lazy fetch. For each distinct approved blob, use
`git hash-object -w --stdin` on the verified local bytes and check its result.
Use a verified NUL-delimited `index-info` file **outside the source** with
records `mode SP oid TAB relative-path NUL`; run `git update-index -z
--index-info` with those records on stdin (not blind `git add`). Run
`git write-tree`, `git commit-tree <tree>` with a synthetic author/committer,
no parent and an innocuous message, then `git update-ref refs/heads/projection
<synthetic-commit>`. Keep only the exact loose objects, minimal generated
core config/index/ref/log metadata; no packing or shared index. `git fsck
--strict --no-reflogs` must succeed. Record both the native and synthetic
commit/tree separately; the synthetic commit is not a GitHub commit.

### Manifest format, version 1

UTF-8 JSON object (no duplicate keys), external to the source. Use the exact
native identities, not the illustrative field values below. `entries` is
**all** recursive native entries, with every directory and leaf, not just the
allowed subset. A directory has mode `040000`, type `tree`, path and SHA;
a blob has mode `100644` or `100755`, type `blob`, path, size and SHA.

| Field | Required value |
|---|---|
| `version`, `repository`, `repo_id`, `truncated` | `1`, `hwakeyeTW/PQC`, `1469533358`, `false` |
| `kind` | `head` or `integration` |
| `commit`, `tree`, `base`, `head` | native 40-hex OIDs; for head, commit=head |
| `parents` | actual ordered native parent OIDs; for integration `[base, head]` |
| `entries` | full native recursive tree records described above |
| `allowed_paths` | sorted exact allowed blob paths, independently approved |
| `excluded_oids` | sorted unique excluded leaf OIDs (no content) |
| `projection` | object `{"commit": "...", "tree": "..."}` of synthetic Git projection |
| `provenance` | object with `method: "metadata-first-per-oid"`, `reference` (safe external receipt identifier), `excluded_acquired: false`, `acquired_oids` (sorted exact unique approved blob OIDs) |

The raw manifest SHA256 is provided separately as `--manifest-sha256` from
the reviewed acquisition receipt. The runner rechecks the digest, reconstructs
the native and projection tree hashes, verifies required source, the exact
file bytes/modes, index, single synthetic commit, loose object namespace,
minimal Git config and no remote/alternates/promisor. It refuses extra
ignored/untracked entries and verifies before and after every command. A
boundary failure stops later tools even when an earlier command returned 0.
Limits: at most 10,000 tree entries, 200 unique selected blobs, 2 MiB per source
file, 16 MiB total materialized source, 4 MiB manifest. These are QA bounds,
not claims of protection from an attacker racing the filesystem or arbitrary
untrusted code. Independently enforce the disposable environment and source
provenance before running reviewed candidate code. Do not point it at a normal
full checkout with private data or existing production Git objects.

## 3. Invocation and necessary checks

Invoke from the prepared venv with an exact, reviewed runner copy; `-I -B`
prevents Python user-site/PYTHONPATH influence and bytecode writes. Each path
must be absolute, with no symlink ancestors and no overlapping source,
manifest, venv, dependency or evidence locations. The evidence directory
must not exist. Use a safe identifier for the approved preparation record.

```sh
/qa/venv217/bin/python -I -B /qa/source/tools/run_local_qa.py \
  --lane legacy-217 --source-root /qa/source \
  --source-manifest /qa/manifests/head.json \
  --manifest-sha256 "$REVIEWED_MANIFEST_SHA256" \
  --collections-root /qa/deps217 --evidence-dir /qa/results/head-217 \
  --runtime-reference QA-PREP-217-R1
```

One lane per invocation; run sequentially, never more than three lanes.
A complete lane has a 30-minute budget including guarded execution; individual
pytest checks have 120 s, syntax 60 s, sanity up to 900 s and lint up to 300 s,
always bounded by the remaining lane budget. Preparation is separate. Perform
at most one full run per lane plus bounded defect localization with explicit
reason and coverage; no infinite retries. Missing prerequisites are nonzero.
The runner verifies UTF-8 locale/filesystem capability and uses a fresh HOME,
XDG/temp/Ansible home, clean Git C locale and candidate-first explicit
Ansible paths. The synthetic inventory is exactly `[pqc_targets]` with
`localhost ansible_connection=local`; no real Inventory or task execution.

All lanes run (JF is a private external JUnit path, INV the synthetic inventory):

```sh
python -B -m pytest -q -rs -p no:cacheprovider --junitxml="$JF" ansible_collections/security/compliance_pqc_readiness/tests/unit/
ansible-playbook -i "$INV" --syntax-check playbooks/crypto_posture_snapshot.yml
ansible-playbook -i "$INV" --syntax-check playbooks/pqc_pipeline.yml
ansible-playbook -i "$INV" --syntax-check ansible_collections/security/compliance_pqc_readiness/playbooks/pqc_pipeline.yml
# From the Collection directory, with the lane Python minor version:
ansible-test sanity --docker --python "$PYTHON_MINOR" plugins/
# Maintained lane only, from the Collection directory:
ansible-lint --offline playbooks/ roles/
# From the projection root, with a separate JF and basetemp for every suite:
python -B -m pytest -q -rs -p no:cacheprovider --junitxml="$JF" tests/test_data_handling.py
python -B tools/check_mirrors.py
python -B -m pytest -q -rs -p no:cacheprovider --junitxml="$JF" tests/test_mirrors.py
python -B -m pytest -q -rs -p no:cacheprovider --junitxml="$JF" tests/test_local_qa.py
```

These are explanatory commands; use the runner for the full environment,
per-command isolation, exact argv, external basetemp, explicit empty pytest
configuration and source-root/confcutdir, loader and evidence controls.
The actual installed ansible-test source provider/layout listing is checked
before Docker sanity against the exact Collection subset. Native sanity
output under `tests/output` is accepted only in the declared result categories
and regular non-executable bounded XML/JSON/text/log files, then moved to
private scratch before the final strict source check. Unknown output/cache
locations block the lane; do not relax the guard just to obtain green tests.
Sanity uses its actual native tool and Docker. No Python/lint/sanity fallback,
`--fix`, skipped required checks, warning-list overrides or fabricated results.

For the fixed #3 candidate or its subsequent integration, explicitly add
`--with-baseline-intake`. The manifest must contain `tests/test_baseline_inventory.py`,
`tests/fixtures/inventory_synthetic.py` and `tests/fixtures/scan_ol9.anonymized.yml`.
The runner then adds the necessary baseline-intake pytest suite. Missing
paths or a source containing those paths without explicit mode block; there
is no existence-based implicit skip. A later approved slice makes this a
normal required gate after #3 integration. #5 itself does not import #3's
unmerged bytes. All other work packages retain their focused gates.

## 4. Actual negative controls and evidence

`tests/test_local_qa.py` exercises real synthetic Git projection/index and
actual pytest subprocesses, malformed/empty/duplicate/skipped JUnit, missing
command, timeout, wrong lane, path/mode/byte/object/manifest drift, excluded
OID overlap before source access, clean environment and boundary stop. Run it
in an isolated test directory, not with actual excluded data. A synthetic
control pass is not a native Collection/Ansible/lane pass. For Q10, independent
QA also records actual tool controls on separate disposable synthetic input:

- Use the same prepared Ansible and synthetic inventory. A valid dummy debug
  playbook must pass `--syntax-check`; a file containing `- hosts: [` must
  return an actual nonzero syntax error. Do not execute either playbook.
- Maintained lint: `ansible-lint --offline` on a valid named dummy playbook,
  then on a play without a required name; check the actual naming violation
  and nonzero rc, not simply a missing executable.
- In a separate tiny synthetic collection, verify native `ansible-test sanity
  --docker --python <minor> --test compile plugins/` with a valid dummy Python
  file, then a deliberately invalid Python file and verify the compile failure.
  Use the same approved image/development scope. This targeted negative
  oracle does not replace the required full plugin sanity command.
- Exercise actual #4 checker drift in a synthetic mirror repository and the
  existing #4 focused suite; do not mutate the fixed product projection.
- Check actual tool availability/version and positive control first. Record
  fixed environment, commands, exit codes and sanitized reason identifiers;
  missing tools or images block their native controls, never count as success.

Results are local `results.json` (0600, parent 0700), containing native and
projection identity, manifest digest, preparation reference, actual versions,
lane, command argv with local path aliases, start/end/duration, raw return code,
per-check states, actual mirror pair count and JUnit counts. Required pytest suites must have nonempty
unique cases and zero failures, errors or skips. Validate UTF-8 XML, exact
per-suite counts, structure and optional aggregate totals, no DTD/entity or
nested/orphan cases. Preserve failed command rc even if a post-boundary guard
blocks further work. Only bounded safe case/rule identifiers are recorded; raw
logs, environment, JUnit, source and transient output are not retained/uploaded
by the runner. Keep any separately approved diagnostic records private and
sanitized; a failure not explained by summary needs independent bounded
local investigation, not a blind retry. Do not reuse or overwrite evidence.
Exit 0 = all required checks PASS; 1 = check FAIL (no unresolved prerequisite);
2 = BLOCKED, including missing/invalid inputs, runtime or boundary failure,
time budget, cancellation or necessary NOT_TESTED. A blocked lane may also
contain explicit failed check results. Preserve both. No result is not PASS.

## 5. Acceptance mapping and handoff

| Gate | Required independent evidence |
|---|---|
| Q01 | Native Repo/main/Head/Test Merge/Tree/Blob, six paths (1 delete + 5 add), no other changes; old PR48 unchanged |
| Q02 | All three actual pinned runtimes, preparation/closure and actual loader |
| Q03 | Manual fixed invocation, no workflow, full required check list and bounded results |
| Q04 | Independently approved acquisition receipts, complete metadata, no excluded bytes, local source/manifest guard and environment boundary |
| Q05 | Actual clean environment, UTF-8, configuration/loader/synthetic inventory |
| Q06 | Nonempty Collection unit, zero required failures/errors/skips on all lanes |
| Q07 | Three real syntax-only results on all lanes |
| Q08 | Real native plugin sanity on all lanes, actual Docker |
| Q09 | Real maintained offline lint |
| Q10 | Positive/negative controls and actual tool failures, no false pass |
| Q11 | All #2 required tests including Ansible cases on all lanes |
| Q12 | Actual complete local run evidence, fixed Head/integration, all required checks |
| Q13 | This runbook and actual environment/limit/command reproducibility |
| Q14 | The limited equivalent below and all #4 focused tests on all lanes |
| Q15 | All necessary results, fixed integrated candidate, independent Review/QA and Owner acceptance |

For Q14 only, Owner's R2 equivalence permits an exact native-metadata-derived
projection with the complete four mirror domains, checker, root ignores,
raw Git bytes/OIDs/modes and actual index/worktree. At the current baseline
there are 138 mirrored leaves/69 pairs (not a permanent hardcoded number).
Run the actual checker for its exit code and pair count; run actual focused
mirror tests and synthetic drift negatives. Metadata parity alone is not
sufficient. Record original full upstream checkout as NOT_TESTED when using
projection. This does not reopen #4 M01 or create a general exemption for
future QA. The actual native source must be independently verified before
using this equivalence, not merely a synthetic fixture.

For native integration I, verify actual ordered parents and native Tree. If
Head and I trees are identical, independently confirm exact bytes/identity
and document reuse; if different, repeat the affected checks under the
approved integration plan. Preserve actual failed/blocked/not-tested states.
No required native Actions run is expected under R2; absence of a run is not
local QA evidence. Do not claim an independent PASS from implementer tests.
#5 remains open until all necessary local gates and Owner acceptance are met;
old PR48 closure is separate authorization. Do not bypass #3 B13 or the
V2.0 release offline and OL 9.x actual-environment gates. Formal deployment
and Production remain separately authorized.
