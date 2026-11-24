# PQC CI and QA (M0-04)

Issue #5, Phase A (CI Bootstrap), establishes a required-test candidate for
existing Collection and standalone sources. It does not merge or test the
unpublished #2/#4 branches. Phase B is a separately authorized follow-up.

## Matrix and dependency boundary

The workflow `Collection Tests` uses the following direct pins on GitHub-hosted
`ubuntu-24.04` x64 runners. They are candidate regression environments, not a
claim that these versions work in the owner's controller or Oracle Linux lab.

| Job suffix | Python | ansible-core | pytest | ansible-lint | CI manifest |
| --- | --- | --- | --- | --- | --- |
| legacy-217 | 3.11.15 | 2.17.14 | 9.0.2 | not run | requirements-ci-legacy.yml |
| legacy-218 | 3.11.15 | 2.18.15 | 9.0.2 | not run | requirements-ci-legacy.yml |
| maintained-221 | 3.12.14 | 2.21.5 | 9.0.2 | 26.8.0 | requirements-ci.yml |

2.17 and 2.18 are EOL regression lanes (November 2025 and May 2026);
2.21 is the maintained-minor candidate selected by #5. None of these lanes
implies OL 9.7/9.8/9.9 target support. #3 inventories the actual controller;
#28 separately verifies the release in approved lab/real environments.

| Galaxy collection | Legacy pin / requires_ansible | 2.21 pin / requires_ansible |
| --- | --- | --- |
| community.crypto | 2.26.0 / >=2.9.10 | 3.0.5 / >=2.17.0 |
| ansible.posix | 1.6.2 / >=2.15.0 | 2.1.0 / >=2.15.0 |
| community.general | 10.7.0 / >=2.15.0 | 12.0.0 / >=2.17.0 |
| community.hashi_vault | 6.2.0 / >=2.14.0 | 7.0.0 / >=2.17.0 |

Published Python patch assets are listed in the [official runner manifest](https://github.com/actions/python-versions/blob/main/versions-manifest.json).
Core, pytest and lint pins refer to their exact PyPI releases. Collection pins
refer to the corresponding upstream version tags and `meta/runtime.yml`;
installation from public Galaxy and compatibility must still be demonstrated
by the actual lane. `requires_ansible` metadata alone is not a compatibility
test. The workflow checks exact installed versions, manifest dependencies,
`pip check`, and candidate loader/config paths. A version conflict is a red
result, not permission to remove or silently change a lane. Actual pip freeze,
runner image, and Galaxy versions/dependency resolution belong to run evidence.
Only direct pins are fixed; this is not a transitive or bitwise lock.

Install Python packages in a fresh venv and Collections using
`ansible-galaxy collection install -r ... -p ...`, never pip for Collections.
The two CI-only manifests do not change `collections/requirements.yml`,
`requirements-aap-setup.yml`, Galaxy metadata or the production controller.
`community.hashi_vault` is a pre-existing Collection dependency for static
parsing; this does not install or connect to a Vault service. Do not install
AAP/controller deployment dependencies, add credentials, or run any deployment.

The workflow uses official checkout v6.0.2 (`de0fac2e4500dabe0009e67214ff5f5447ce83dd`)
and setup-python v6.2.0 (`a309ff8b426b58ec0e2a45f0f869d46889d02405`).

## Execution and data boundary

Pushes to main and PRs targeting main trigger every lane, with no path filter.
Stable job names, a 30-minute job timeout, fail-fast disabled and cancellation
of superseded runs do not confer merge authorization. Repository protection
settings are an Owner decision; this change does not configure them.

Use a disposable Linux/WSL environment and public source plus synthetic inputs.
The checkout action's non-cone sparse list uses its implicit `blob:none` filter;
never supply both `filter` and `sparse-checkout`. Check Git support for
`--no-lazy-fetch` and the public remote's protocol-v2 filter capability before
fetching. The workflow verifies HEAD, promisor/filter config, non-cone sparse
index and complete allowed source domains. It checks that excluded paths are
not materialized and queries the excluded archive/inventory object IDs with
lazy fetch explicitly disabled. A present private blob, unsupported filter or
incomplete checkout is a failure; do not fall back to a full clone, archive
fetch, LFS or submodule download. The final boundary check repeats the object
metadata check. The already-tracked `reports.tar.xz` is UNKNOWN and must not
be opened, downloaded, extracted or otherwise processed; ignore rules cannot
protect tracked history. Exclude all original `inventory/` paths.

The workflow uses isolated HOME, Git config, venv, temporary Collection root
and Ansible temp files. Candidate root is searched before CI dependencies;
system collection lookup is disabled. The only inventory is generated under
the temporary directory: group `pqc_targets`, localhost, local connection.
Explicit `ANSIBLE_CONFIG` points to the candidate `ansible.cfg`; #2 is not yet
merged at this bootstrap baseline, so Phase A does not attest the SSH default.
No actual playbook execution, SSH, scan, remediation, Vault/Backstage calls or
production access is allowed. Docker is used only for ansible-test sanity.
Public network access is limited to repository/development dependency sources.
Never upload reports, repository snapshots, full config/environment dumps,
credentials, raw inventory, packet traces or JUnit files as artifacts.

## Repeat a lane in an isolated Linux/WSL environment

Required tools: Git with explicit no-lazy-fetch support, Bash, the exact Python
patch in the table, its venv/pip support, and a usable local Docker daemon for
sanity. Use an approved disposable machine, never the production controller.
Start a clean shell with only the intended tool PATH; do not inherit Ansible,
Git, Python, pip or credential settings. From a new scratch directory, use the
fixed candidate SHA approved by the Planner (not a moving branch):

```bash
set -euo pipefail
umask 077
export CI_ROOT=$(mktemp -d /tmp/pqc-ci.XXXXXX)
export HOME="$CI_ROOT/home" XDG_CONFIG_HOME="$CI_ROOT/xdg-config" XDG_CACHE_HOME="$CI_ROOT/xdg-cache"
mkdir "$HOME" "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME"
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL="$CI_ROOT/gitconfig"
export GIT_TERMINAL_PROMPT=0 GIT_LFS_SKIP_SMUDGE=1
export PYTHONNOUSERSITE=1 PYTHONPATH='' PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
export PIP_CONFIG_FILE=/dev/null PIP_EXTRA_INDEX_URL='' PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
export ANSIBLE_COLLECTIONS_SCAN_SYS_PATH=False ANSIBLE_COLLECTIONS_ON_ANSIBLE_VERSION_MISMATCH=error
export CI_EXPECTED_SHA='<approved full commit SHA>'
[[ "$CI_EXPECTED_SHA" =~ ^[0-9a-f]{40}$ ]]
remote=https://github.com/hwakeyeTW/PQC.git
git --no-lazy-fetch --version
GIT_TRACE_PACKET="$CI_ROOT/protocol.log" git -c protocol.version=2 ls-remote --exit-code "$remote" HEAD >/dev/null
grep -Eq 'fetch=.*[[:space:]]filter([[:space:]]|$)' "$CI_ROOT/protocol.log"
git init -q "$CI_ROOT/repo"
cd "$CI_ROOT/repo"
git remote add origin "$remote"
git -c protocol.version=2 fetch --no-tags --no-recurse-submodules --filter=blob:none --depth=1 origin "$CI_EXPECTED_SHA"
git config core.sparseCheckout true
git config core.sparseCheckoutCone false
mkdir -p .git/info
cat > .git/info/sparse-checkout <<'PATTERNS'
/.github/workflows/collection-tests.yml
/.gitignore
/README.md
/ansible.cfg
/reports/.gitignore
/roles/
/plugins/
/playbooks/
/ansible_collections/security/compliance_pqc_readiness/
/tools/
/tests/
/schema/
/schemas/
/docs/development/
/collections/requirements-ci-legacy.yml
/collections/requirements-ci.yml
PATTERNS
git checkout --detach FETCH_HEAD
export GITHUB_WORKSPACE="$PWD"
export CI_COLLECTION=ansible_collections/security/compliance_pqc_readiness
export GITHUB_ENV="$CI_ROOT/github-env" GITHUB_PATH="$CI_ROOT/github-path"
```

Run the exact `Verify sparse checkout and absent private objects` shell block
from the checked-out workflow. This writes/runs the same metadata guard as CI.
If it fails, stop. Export `GIT_NO_LAZY_FETCH=1` before subsequent commands.
For local tests against #2 or #4, use the separately approved fixed candidate
and the same safety policy; the A-only guard expects its own manifests/qa.md,
so adapt only the temporary allowlist/required inputs under QA authorization,
not the other work package's branch. Record the actual tested SHA and inputs.

Select one row of the matrix. Set `CI_PYTHON`, `CI_PYTHON_MINOR`, `CI_CORE`,
`CI_PYTEST`, `CI_LINT` (empty for legacy), and absolute `CI_REQUIREMENTS` from
that row. For example, with the exact 3.12.14 executable already on PATH:

```bash
export CI_PYTHON=3.12.14 CI_PYTHON_MINOR=3.12 CI_CORE=2.21.5 CI_PYTEST=9.0.2 CI_LINT=26.8.0
export CI_REQUIREMENTS="$PWD/collections/requirements-ci.yml"
export GIT_NO_LAZY_FETCH=1
```

Run the workflow's `Create isolated test environment` shell block verbatim.
It checks the Python patch, creates the venv, writes synthetic inventory and the
JUnit verifier; the GitHub env/path files are only local scratch files here.
Then apply the equivalent exports explicitly (do not source untrusted files):

```bash
export PATH="$CI_ROOT/venv/bin:$PATH"
export CI_COLLECTIONS="$CI_ROOT/collections"
export SYNTHETIC_INVENTORY="$CI_ROOT/inventory.ini" ANSIBLE_INVENTORY="$CI_ROOT/inventory.ini"
export ANSIBLE_CONFIG="$PWD/ansible.cfg"
export ANSIBLE_COLLECTIONS_PATH="$PWD:$CI_COLLECTIONS"
export ANSIBLE_ROLES_PATH="$PWD/roles" ANSIBLE_LIBRARY="$PWD/plugins/modules"
export ANSIBLE_LOCAL_TEMP="$CI_ROOT/ansible-tmp"
```

Run `Install and verify pinned CI dependencies` and `Synthetic failure-oracle
checks` from the workflow without changing them. The former invokes exact
package pins together, `pip check`, `pip freeze`, Galaxy install, installed
manifest and loader verification. The latter runs real pytest pass/fail/skip/
empty cases, syntax-only valid/invalid YAML, and the maintained lane's lint
positive/naming-violation control in temporary files. Expected nonzero results
in negative controls are explicit assertions, never ignored required failures.
Missing tools or a failing positive control cannot satisfy Q10.

From the checkout root, run each required step and retain its actual rc:

```bash
python -m pytest -q -rs --junitxml="$CI_ROOT/collection-unit.xml" "$CI_COLLECTION/tests/unit/"
python "$CI_ROOT/verify-junit.py" "$CI_ROOT/collection-unit.xml"
ansible-playbook -i "$SYNTHETIC_INVENTORY" --syntax-check playbooks/crypto_posture_snapshot.yml
ansible-playbook -i "$SYNTHETIC_INVENTORY" --syntax-check playbooks/pqc_pipeline.yml
ansible-playbook -i "$SYNTHETIC_INVENTORY" --syntax-check ansible_collections/security/compliance_pqc_readiness/playbooks/pqc_pipeline.yml
```

From the Collection root:

```bash
cd "$GITHUB_WORKSPACE/$CI_COLLECTION"
docker version --format '{{.Server.Version}}'
ansible-test sanity --docker --python "$CI_PYTHON_MINOR" plugins/
# Maintained lane only:
ansible-lint --offline playbooks/ roles/
cd "$GITHUB_WORKSPACE"
python3 "$CI_ROOT/verify-checkout.py"
```

Execute the maintained-only lint command only in its intended lane. Run
independent checks even when another required check fails; do not turn a
failure into success, skip a required test, or invoke an alternate runner as
fallback. CI uses separate steps with status-function conditions so a prior
check failure does not hide the remaining evidence. For local QA, record each
command's result separately rather than treating a shell aborted at the first
failure as full coverage. No lint auto-fix, generated ignore list, skip-test,
NODEPS or warning-only conversion is permitted.

Validate workflow YAML/shell and, where available, actionlint. For the candidate
diff, run `git diff --check` and `git diff --cached --check` in a separate
isolated staging repo built from the approved Base/Head text blobs; confirm
all changed paths and bytes against the native PR diff/tree. Do not fetch
excluded blobs or use a full checkout for this purpose. To exercise the
checkout oracle, use a disposable synthetic origin with unique dummy archive
and inventory blobs, then verify both absent objects and the rejected case
where a dummy blob exists without a worktree file. Never use the actual archive
as a negative test. Any extra workflow ref or remote retry needs authorization.

## Reporting and gates

Record Repository ID, fixed PR Base/Head, actual tested SHA (PR runs can use a
merge commit), event, runner image/version, Git/Python/core/pytest/lint and
Galaxy versions, pip freeze/check, actual job/step names, run/job IDs and
conclusions, commands/rc, test collection count and failed/error/skipped
counts. Only sanitized evidence belongs in public issues/PRs/CI logs. Retain
JUnit in the runner temporary area for validation, not as an uploaded artifact.
A nonempty unit suite with rc=0 and no failure/error/skip is required. An empty
suite, required skip, missing runner, failed installation, timeout, cancellation
or no native run is not PASS. A failed lint/sanity/unit/syntax command remains
red; preserve its rule/line/rc and ask the Planner for a separate repair slice.
The current plugin sanity and maintained Collection lint scopes are not claims
about every target Python, role behavior or production safety.

Phase A is complete only with fixed-head native Actions and independent
review/focused QA evidence plus the Owner gate. Until then mark deficiencies
PARTIAL, FAIL, BLOCKED or NOT_TESTED as appropriate, keep #5 open and do not
claim full acceptance. Native CI evidence must be rechecked on head/base drift.

Phase B is PENDING: after #2 and #4 complete their independent gates and Owner
merges, the Planner arranges a new candidate on the actual main. Add all three
required paths (`tests/test_data_handling.py`, `tools/check_mirrors.py`,
`tests/test_mirrors.py`) without existence-based skip/fallback. Each lane must
run both pytest suites with nonempty JUnit/no required skips, plus the real
mirror checker against complete four-domain checkout. #2 needs D08/D09/D12
Ansible evidence; #4 needs fixed-source parity and syntax verification as well
as its own independent review findings resolved. Phase A does not establish
these results. Further root tests/schema/entry points join CI through their
approved work packages. CI does not replace independent QA, Owner acceptance,
or the final #28 lab/offline-browser release checks.
