# Collection source and standalone mirrors

Decision: PQC-M0-03 / Issue #4, detailed plan R1. The Collection is the
canonical implementation; the root layout is a compatibility mirror. This
is a maintenance contract, not removal of the physical duplicates.

## Mapping and compatibility

Canonical prefix: `ansible_collections/security/compliance_pqc_readiness/`.
Legacy prefix: repository root. The initial parity domain is every Git-tracked
leaf under `roles/` and `plugins/` on both sides. Map by complete, case-sensitive
POSIX Git relative path, never basename. Each pair must have the same Git blob
ID, Git mode (100644 or 100755), and worktree bytes. At baseline
`86e1cf08787d99804e6e2d834df82ac2c9b3fc11` there are 69 pairs; this is not a cap.
The eight existing roles' `tasks/main.yml` and `plugins/modules/normalize_pqc.py`
and `plugins/modules/generate_cbom.py` are required anchors on both sides.
Remediation and Vault sources are included only for static parity; never execute
them for this check.

Root `ansible.cfg` sets `roles_path=roles`, `library=plugins/modules`, and
`collections_path=.:collections`. Root `playbooks/crypto_posture_snapshot.yml`
and `playbooks/pqc_pipeline.yml` use short role/module names. Collection
`playbooks/pqc_pipeline.yml` uses `security.compliance_pqc_readiness.*` FQCNs.
Preserve both loader interfaces, parameters and playbook behavior. The two
pipelines differ in behavior; playbooks are not mirrored by this contract.
Docs, tests, metadata and controller tools outside the domain are not mirrored.
No AAP, AWX, Backstage, Vault or new runtime dependency is introduced.

Keeping both copies with one canonical edit direction is small and reversible.
Independent edits risk drift; deleting root or rewriting everything to FQCN
breaks deployments. Symlinks/cross-package wrappers risk Windows, packaging
and loader incompatibility. Shared module_utils, wrappers and packaging changes
need separate planning and compatibility evidence.

## Maintenance procedure

1. Identify the component and approved scope before editing. Edit canonical
   logic once; explicitly copy the corresponding files to root, preserving
   paths and Git modes. Add, delete or rename both sides in the same PR.
   Do not independently patch the mirror or use a blind directory sync.
2. Explicitly stage the approved files. Review both staged copies, mode changes,
   and the complete diff; verify no unrelated paths changed.
3. Run the checker and focused tests below. Repeat against the fixed candidate
   commit/PR head in a clean checkout. Submit evidence for independent review/QA.

All new role/plugin components are mirrored by default. No exceptions currently
exist. Before introducing a genuinely standalone-only or collection-only
component (e.g. #7, #14, #29, #36), Planner must classify it and obtain approval
for a precise component-boundary exception and its checker tests. Never exclude
a whole arbitrary subtree or suppress missing children of an existing pair.
Changing anchors also needs an approved migration. Paired deletion of a non-anchor
can pass parity; feature completeness and scope are separately reviewed.

## Read-only parity CLI

```sh
python3 tools/check_mirrors.py
python3 tools/check_mirrors.py --repo-root /path/to/synthetic-checkout
python3 -m pytest -q tests/test_mirrors.py
git diff --check
git diff --cached --check
```

Requires Python 3 standard library and Git CLI (pytest for tests); no Ansible,
network or synchronization is needed. Default root is relative to the script,
not cwd. Explicit root must be the actual Git worktree root (linked worktrees
are supported). The checker does not change index, refs, config or files.

The Git index (`ls-files --stage -z`) is compared by union of paths, including
blob IDs and index modes. Unsupported types (including symlinks and gitlinks),
unmerged stages, missing files/anchors and mode or content drift fail. Separately
hash actual paired regular files without newline/whitespace normalization;
inspect every relative directory node and reject symlinks/junctions/reparse
points. Git mode is authoritative, not OS permissions. Do not concurrently
mutate the checkout; this is not a filesystem security boundary against an
attacker racing inspection (especially on systems without dir_fd support).

Nonignored untracked source within the domain is a violation, even if present
on both sides. Ignored files (e.g. caches) and domain-external files are not
covered. Do not add broad ignores for executable source. The check is not a
complete loader proof or arbitrary ignored-file injection detector. Equal
unstaged bytes on both sides can pass the checkout comparison; index parity
is independent and does not establish that worktree bytes are staged. CI/QA
must use a clean fixed checkout and inspect the approved staged diff.

Exit 0: PASS, both layers consistent, anchors present and no nonignored
untracked source. Exit 1: FAIL, contract violation. Exit 2: ERROR, unreliable
inspection (invalid root/CLI, Git, parse, unmerged index, I/O or permissions).
ERROR takes precedence over FAIL. Diagnostics contain sorted relative paths
(JSON-escaped) and reason codes, plus a summary with the number of paired index
paths. No file contents, Git stderr, full environment or private absolute paths
are printed. `--help` exits 0. No `--fix`/`--sync`, hooks or automatic mutation.

## Loader verification and handoff

For #4, run syntax-only checks from the candidate root in an isolated HOME,
using its existing configuration and explicit candidate-first collection paths
and a temporary synthetic inventory with `[pqc_targets]` and
`localhost ansible_connection=local`. No real inventory, hosts or task execution.
Verify module resolution with `ansible-doc` where available.

```sh
# SYNTHETIC_INVENTORY points to the temporary synthetic inventory.
ANSIBLE_CONFIG="$PWD/ansible.cfg" ansible-playbook -i "$SYNTHETIC_INVENTORY" --syntax-check playbooks/crypto_posture_snapshot.yml
ANSIBLE_CONFIG="$PWD/ansible.cfg" ansible-playbook -i "$SYNTHETIC_INVENTORY" --syntax-check playbooks/pqc_pipeline.yml
ANSIBLE_CONFIG="$PWD/ansible.cfg" ansible-playbook -i "$SYNTHETIC_INVENTORY" --syntax-check ansible_collections/security/compliance_pqc_readiness/playbooks/pqc_pipeline.yml
```

Record versions, actual exit codes and sanitized evidence. Missing dependencies
or tooling are BLOCKED/NOT_TESTED, not PASS. Syntax is not runtime compatibility.
#3 inventories actual controller versions; #5-B integrates the checker and
focused tests as required CI checks with relevant role/plugin/collection/tools/
tests/docs triggers and clean fixed checkout. No optional skip or ignored failure.
#6/#7/#10 depend on #4; later collectors follow the same mapping and exception
process. #28 handles integrated QA. #4 does not modify workflows or existing
roles, modules, inventory, playbooks or config. Production execution is separate.
