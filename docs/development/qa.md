# PQC CI and QA (M0-04)

Issue #5 Phase A establishes a required-test candidate, not an accepted QA gate.
The R1 correction implements metadata-first selective blob acquisition and a
verified source-only Git projection. Phase B remains a separate work package.

## Release and safety gates

R1 found that Git partial/sparse acquisition can obtain excluded blobs when
filter support changes between sessions, and that the checkout action has a
whole-repository REST fallback. Post-fetch detection is too late. **Neither
that workflow nor its predecessor may be triggered to test these defects.**
Only synthetic negative controls may simulate filter loss and private data.
Do not use, download, open, extract, delete or rewrite the already tracked
`reports.tar.xz`; its content remains UNKNOWN. Exclude the original inventory.

Before publishing this correction, the Owner must confirm that updating the
original branch cannot automatically start the workflow and explicitly authorize
that update. A Draft PR, zero runs or a skip message is not a disabling control.
No settings changes, workflow run/rerun, push, merge or Production access is
implied by the implementation grant. After safe publication, independent
Review R2 and Q04 precheck, then QA's own safety check and explicit Owner run
authorization are required before a real repository run. If any gate fails,
keep Phase A HOLD; preserve actual results and do not bypass a test.

## Matrix and dependency boundary

`Collection Tests` uses hosted Ubuntu 24.04 x64, 30-minute job timeout,
fail-fast disabled and max-parallel 1. Every main push and PR targeting main
triggers the same checks; cancellation, timeout or no run is not PASS.
Stable lane names do not confer permission to merge.

| Job suffix | Python | ansible-core | pytest | ansible-lint | CI manifest |
| --- | --- | --- | --- | --- | --- |
| legacy-217 | 3.11.15 | 2.17.14 | 9.0.2 | not run | requirements-ci-legacy.yml |
| legacy-218 | 3.11.15 | 2.18.15 | 9.0.2 | not run | requirements-ci-legacy.yml |
| maintained-221 | 3.12.14 | 2.21.5 | 9.0.2 | 26.8.0 | requirements-ci.yml |

2.17/2.18 are EOL regression lanes (November 2025/May 2026); 2.21 is the
maintained-minor candidate. None claims OL 9.7/9.8/9.9 or controller support.
#3 inventories the real controller; #28 verifies the release in approved lab
and real environments. Official Python runner assets and pinned release tags
were checked in R1, but installation and compatibility require real lane runs.

| Galaxy collection | Legacy pin / requires_ansible | 2.21 pin / requires_ansible |
| --- | --- | --- |
| community.crypto | 2.26.0 / >=2.9.10 | 3.0.5 / >=2.17.0 |
| ansible.posix | 1.6.2 / >=2.15.0 | 2.1.0 / >=2.15.0 |
| community.general | 10.7.0 / >=2.15.0 | 12.0.0 / >=2.17.0 |
| community.hashi_vault | 6.2.0 / >=2.14.0 | 7.0.0 / >=2.17.0 |

Python direct dependencies and the two CI-only Galaxy manifests are unchanged.
Use a new venv, pip install exact pins, pip check/freeze and
`ansible-galaxy collection install -r ... -p ...`; verify exact installed
versions, dependency metadata and actual candidate loader paths. Metadata and
direct pins alone are not installed compatibility or a transitive/bitwise lock.
Keep existing deployment manifests, Galaxy metadata and controller unchanged.
Vault Collection is for static parsing, not a Vault service or AAP deployment.
The only external action is official setup-python v6.2.0, fixed at
`a309ff8b426b58ec0e2a45f0f869d46889d02405`, exact Python patch, no cache.

## Metadata-first acquisition (Q04)

The inline Python block in the workflow and `tools/ci_bootstrap.py` share an
identical prefix through `# END INLINE COMMON`. The regression suite extracts
the actual block from the workflow, checks prefix equality, and invokes the
actual HTTPS client against intercepted synthetic responses. When changing
common code, update the inline prefix and its SHA-256 together, then rerun the
suite. The inline block is needed because no candidate file may be executed
before the first metadata preflight. No other acquisition implementation is
used by the workflow.

1. Start with a fresh empty workspace and private disposable scratch, no `.git`
   or prior source. Require Git and its no-lazy-fetch option; initialize a local
   empty SHA-1 repository with no templates before any source request. Reject
   symlink/non-directory ancestors, overlapping scratch/workspace or dirty root.
2. Require the fixed public `hwakeyeTW/PQC` repository ID 1469533358, official
   `api.github.com` TLS endpoint, event repository/ref and full tested SHA.
   For PRs require main base, event merge SHA and ordered base/head parents
   of the Git Database commit; for main push record the actual pushed SHA.
   Read the repository/commit and full recursive Git Database tree metadata.
   Trust the official TLS commit-to-tree mapping; independently reconstruct
   every directory's Git tree hash from names, modes and OIDs, including
   excluded entries. Fail on truncated metadata, omissions, duplicate JSON
   members, ambiguous paths, unsafe components or unsupported modes/types.
3. Form the complete allowed and excluded blob sets before any blob GET.
   Deny takes priority over the explicit original source allowlist (root
   roles/plugins/playbooks, specified Collection, tools/tests/schema(s),
   development docs, exact config/policy/CI files). Keep only reports/.gitignore
   in reports. Deny original inventory, archives, secret/private/local/cache
   areas, generated bytecode/logs, Git attribute/module files and sanity output.
   Paths are restricted to portable ASCII components; reject case aliases,
   dot traversal, absolute paths, Git metadata names, reserved device names,
   symlinks, gitlinks or unsupported types. Required anchors, four source
   domains and Collection unit tests must exist. Reject any allowed/excluded
   OID overlap *before* the helper request, even if two paths share bytes.
4. Only use GET `/repos/hwakeyeTW/PQC/git/blobs/<approved SHA>` once per
   approved unique OID. The first blob is the helper; validate Base64, exact
   size, raw Git object hash, and its shared prefix before executing it. It
   uses the same authorized manifest and client/budget to get the remaining
   blobs. Reject LFS pointers. No redirects, proxies, response URL following,
   repository archive requests, upstream Git transport, lazy fetch, full
   download, cache fallback or retries. HTTP status, JSON/type, hash, size,
   identity, deadline and rate errors fail closed. Request cap 220/lane,
   unique blob cap 200/lane, each allowed blob <=2 MiB, materialized sum <=16 MiB,
   each response <=4 MiB, metadata <=10,000 entries, each request <=20 seconds
   socket timeout plus overall 480-second shell timeout. Require rate remaining
   sufficient for the whole approved blob set before first blob. Three lanes
   are sequential within a run; other runs may still share rate limits.
5. Acquire and verify all allowed bytes before writing source files. Create only
   the approved directories/files, exclusively with no-follow leaf creation,
   validate parent/root types, exact bytes and mode. Use raw Git hash-object
   and explicit index entries (not git add with ignore/filter rules). Write a
   local source-only tree and one synthetic root commit. No remote, promisor,
   alternate, upstream history or refs. Record native event/repo/tested
   commit/tree/base/head, manifest SHA256 and synthetic projection tree/commit.
   The synthetic commit is not the GitHub commit and must never be pushed.
6. Save the verified helper, manifest and exact Git metadata snapshot outside
   source. Only export their hashes and private scratch paths, not the job
   read token. The token is scoped to the acquisition step only and removed
   from the subprocess environment. The verified helper's common prefix is
   checked before execution; subsequent steps hash the scratch helper again.

This protects against accidental excluded-object acquisition, malformed or
inconsistent metadata/responses, and source/metadata drift in a disposable
trusted runner. It is not a DLP scanner, an adversarial-code sandbox, or a
claim against an arbitrary malicious GitHub/TLS provider or concurrent
malicious runner process. A workflow itself can execute code: review the
candidate before authorizing it. Do not use arbitrary unreviewed ref content,
real credentials, or a runner containing other users' data.

## Verified projection and tools

Each required command uses the scratch guard, which verifies all physical
source entries (including ignored/untracked entries), parent/leaf types,
regular raw bytes, executable modes, exact tracked index, HEAD/tree and Git
metadata/object namespace before and after execution. Git metadata paths
must match the snapshot before reading expected metadata or calling Git;
unknown files, hardlinks, symlinked directories, alternate/config/index/hook
changes and excluded OIDs fail. No Git config, trace, index, alternates or
hook environment is inherited. Git commands use a deterministic C locale.
Only trusted PATH and a fresh HOME/XDG/temp environment are inherited by the
command wrapper; explicit Ansible config, inventory and Collection/module/role
paths refer to the verified candidate. No system Collection search. The
Ansible/pytest/lint subprocesses use a probed UTF-8 locale, preferring C.UTF-8
or C.utf8; actual locale and filesystem encoding must both be UTF-8 with
Python UTF-8 mode disabled in the probe. No OS locale changes or inherited
locale override. Missing UTF-8 capability is BLOCKED, never a skip.

The only inventory is scratch `inventory.ini` containing `[pqc_targets]` and
`localhost ansible_connection=local`. Ansible tasks, SSH, scanning, active
probes, remediation, external Vault/Backstage calls and production access are
prohibited. #2 is independent: Phase A does not attest its SSH default.

Pytest cache/temporary data and JUnit, venv, Galaxy, HOME/XDG, Ansible and lint
cache/temp live outside source; disable Python bytecode. No source artifacts
are tolerated except the explicitly bounded post-sanity Collection
`tests/output/{bot,coverage,data,junit,logs,reports,.tmp}` result namespace.
Only safe directories and bounded non-executable single-link regular
XML/JSON/text/log/out/err files (total at most 16 MiB) are accepted there, then moved to scratch before strict recheck. No
blanket ignored-directory exception. If an installed tool needs another
legitimate result type or cache location, record its actual red result and
ask Planner for a bounded adjustment; do not allow arbitrary extra source.
Sanity starts with a clean verified projection, verifies Git's actual
`--cached --others --exclude-standard` minus deleted listing, then checks
installed ansible-test GitSource, Collection layout, all_files and only one
Collection in the source root. This is the payload source set used by the
pinned provider; Docker/payload runtime still needs native QA. The tool may
add its own installed Ansible library and synthetic test data, not excluded
repository files. No upload of payload, logs, repository snapshot, report,
full environment/config, token or JUnit artifact. Data boundary failure is
latched; later independent steps cannot execute candidate code. Ordinary
required test failure stays nonzero while independent guarded tests can run.

## Local equivalent verification (Linux/WSL)

Use a disposable machine with Git, exact Python patch/venv, Bash, timeout,
public dependency access and Docker for sanity; never the real controller.
Before any real source acquisition require the safety gates above. For the
current local correction, run only the synthetic helper suite using the fixed
four replacement files and unchanged manifests, not the R1 workflow:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  python -m pytest -q -rs -p no:cacheprovider \
  --basetemp /tmp/pqc-bootstrap-synthetic-tests tests/test_ci_bootstrap.py
```

The synthetic suite invokes the actual inline block, with dummy API responses
built from real local Git trees. It checks event/tree/manifest identities,
zero forbidden requests, helper/response hash and size, unavailable Git,
redirect/limit/network failures, R1 synthetic filter loss, source/index/metadata
and environment contamination, strict JUnit using real pytest and malformed
XML, UTF-8/ASCII and missing locale. No real acquisition or Docker run is
claimed by synthetic tests. Use a new unique basetemp each run.

For a separately authorized native or local fixed-candidate acquisition, use
exact event metadata (repo, tested SHA, main push or PR merge parents), the
same workflow inline block and a fresh workspace. Local fixed blobs may be
supplied through the approved read-only Connector instead of a live token;
apply the same complete tree, allowlist and per-OID oracle. Do not execute any
real acquisition merely to establish Q04. Do not invent event/merge SHAs or
use a moving branch. If a local live API acquisition is explicitly authorized,
provide the approved scoped read credential to the acquisition process only;
never put it in commands, artifacts, config or chat. Set the standard GitHub
event variables and temporary `GITHUB_ENV` file from verified native metadata,
`GITHUB_WORKSPACE` to a new empty directory, `RUNNER_TEMP` outside it. Run the
exact workflow acquisition shell block, using the reviewed fixed workflow
bytes (not a repository archive). The GitHub environment/path export files
are local scratch files; validate their keys, values and hashes before
applying, do not source arbitrary text. After acquisition verify and record
manifest/projection/guard hashes, then use the exact setup/environment block.

For each matrix row export CI_PYTHON, CI_PYTHON_MINOR, CI_CORE, CI_PYTEST,
CI_LINT (empty for legacy), CI_REQUIREMENTS (absolute verified manifest path),
CI_COLLECTION and the verified CI_ROOT, CI_MANIFEST_SHA256,
CI_PROJECTION_SHA256, CI_GUARD_SHA256, GITHUB_SHA/GITHUB_WORKSPACE. Use the
exact Python patch; run the environment block with a scratch GITHUB_PATH,
then explicitly put `$CI_ROOT/venv/bin` first on PATH. Do not inherit Git,
Python, Ansible, credentials or locale variables. For every invocation below,
first check the scratch helper SHA-256, then use the workflow's guarded run
form. Missing tool or unsafe output is a nonzero result.

```bash
set -euo pipefail
printf '%s  %s\n' "$CI_GUARD_SHA256" "$CI_ROOT/guard.py" | sha256sum -c -
python -I -B "$CI_ROOT/guard.py" verify --root "$GITHUB_WORKSPACE" --scratch "$CI_ROOT"
python -I -B "$CI_ROOT/guard.py" locale --root "$GITHUB_WORKSPACE" --scratch "$CI_ROOT"
# Same guard invocation for every required command, e.g. install:
python -I -B "$CI_ROOT/guard.py" run --root "$GITHUB_WORKSPACE" --scratch "$CI_ROOT" --label install -- python -I -B "$CI_ROOT/guard.py" install
```

Execute the exact workflow run blocks for all other checks. They invoke:

| Check | Guarded command / scope |
| --- | --- |
| Bootstrap regression | `python -m pytest -q -rs -p no:cacheprovider --basetemp <scratch> --junitxml=<scratch>/bootstrap.xml tests/test_ci_bootstrap.py` |
| Synthetic syntax and lint controls | `python -I -B <scratch>/guard.py controls` (valid/invalid YAML; maintained lint naming positive/negative) |
| Collection unit | `python -m pytest -q -rs -p no:cacheprovider --basetemp <scratch> --junitxml=<scratch>/collection-unit.xml ansible_collections/security/compliance_pqc_readiness/tests/unit/` |
| Standalone snapshot | `ansible-playbook -i <scratch>/inventory.ini --syntax-check playbooks/crypto_posture_snapshot.yml` |
| Standalone pipeline | `ansible-playbook -i <scratch>/inventory.ini --syntax-check playbooks/pqc_pipeline.yml` |
| Collection pipeline | `ansible-playbook -i <scratch>/inventory.ini --syntax-check ansible_collections/security/compliance_pqc_readiness/playbooks/pqc_pipeline.yml` |
| Sanity (Collection cwd) | guard `--sanity -- python -I -B <scratch>/guard.py sanity` -> Docker version and `ansible-test sanity --docker --python "$CI_PYTHON_MINOR" plugins/` |
| Maintained lint (Collection cwd) | `ansible-lint --offline playbooks/ roles/` |

The guard applies strict per-suite JUnit validation for both required pytest
suites after command rc=0: direct suites and cases, nonnegative exact counts,
nonempty total, zero failures/errors/skips, no isolated or nested cases or
status nodes. Captured stdout and properties must have legitimate structure;
invalid XML fails. Do not use alternate unit runners or ignore errors. Retain
original command rc even if post-check fails; report a boundary failure and
stop candidate tools. Independent commands continue only while isolation is
intact; no shell fallback, auto-fix, skip rules or warning-only conversion.

## Reporting and gates

Record fixed native Repo ID, Base/Head, tested commit and ordered parents,
tree, event, complete allowed manifest SHA256, projection tree/synthetic
commit, exact source verification, API request counts, locale, runner image,
Git/Python/core/pytest/lint, Galaxy metadata and installed versions, pip check
and freeze, actual job/step IDs/conclusions, command rc and test counts.
Separate synthetic evidence, native runner evidence and independent QA.
Record all missing tools, required skips, timeouts and actual baseline red.
Validate workflow YAML and shell/inline Python syntax; actionlint if available.
Independent native tree/Blob/diff evidence verifies the formal candidate;
projection Git diff is *not* a comparison against upstream history. For local
correction publication use the old exact blob SHA, four-path delta and six-path
cumulative scope, candidate SHA256 manifest and fixed candidate bytes. No
repository source snapshot or report uploaded to CI. Do not close #5 or merge
without independent R2 and QA R2, native evidence and Owner acceptance.

Phase B remains PENDING until #2/#4 are accepted and merged and Phase A gate
is satisfied. Integrate `tests/test_data_handling.py`, `tools/check_mirrors.py`
and `tests/test_mirrors.py` as required checks without existence-based skip.
#2 D08/D09/D12 need its own native Ansible evidence; #4 needs its own exact
parity/syntax and independent review. Before Phase B, Planner/Owner must decide
whether a verified source-only projection satisfies #4's complete-checkout
contract or authorize a changed oracle. Phase A cannot turn projection into
complete native checkout QA. Later root tests/schema/entry points join through
authorized work packages; #28 lab and offline browser verification is separate.
