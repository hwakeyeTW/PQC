# Environment and source baseline (PQC-M0-02)

Issue #3, detailed plan R1 and Owner PoC clarification R2. Observed on
2026-11-24 (UTC); this is a versioned intake and implementation record, not a
support matrix, production run, independent review or QA result. See
[compatibility.md](compatibility.md) and [data-handling.md](data-handling.md).

## REPO_SOURCE: fixed public sources

GitHub native metadata and selected public source blobs, observed 2026-11-24.

| Repository | ID | Commit (main) | Tree | Leaves |
|---|---|---|---|---:|
| nmartins0611/PQC-AAP | 1260697926 | `86e1cf08787d99804e6e2d834df82ac2c9b3fc11` | `2b03a8e2b5b2de715ebcb441110fd315e7499360` | 178 |
| hwakeyeTW/PQC | 1469533358 | `95c0d6512c69cadf8b0cd3131d88a043b4885425` | `8285b027f90a3b515cc496e810a746c9bda0bbad` | 180 |

[Upstream tree](https://github.com/nmartins0611/PQC-AAP/tree/86e1cf08787d99804e6e2d834df82ac2c9b3fc11)
/ [fork tree](https://github.com/hwakeyeTW/PQC/tree/95c0d6512c69cadf8b0cd3131d88a043b4885425).
Recursive trees are non-truncated (282 and 286 entries respectively). The fork
has only the #2 five-path delta from upstream: `.gitignore`, `ansible.cfg`,
`reports/.gitignore`, `docs/development/data-handling.md`,
`tests/test_data_handling.py`. #2 is closed/merged; no historical scan_ol9.yml
exists in the base. #4/#5 are separate work packages. The tracked
`reports.tar.xz` has blob `74cb57fab91d1a30f7babeec6cbef9352dba4aba`,
149788 bytes, mode 100644, unchanged from upstream; content/provenance UNKNOWN.
Only its metadata was inspected, never its bytes or real inventory data.

### Loader and dependency declarations (static, not installed versions)

| Source at fixed fork base | Blob SHA-1 | Observed declaration |
|---|---|---|
| `ansible.cfg` | `7d4427ab368af06b61c75f60a149d39e16725f34` | inventory=inventory/hosts.yml; roles_path=roles; collections_path=.:collections; library=plugins/modules; plugins host_list/script/auto/yaml/ini; #2 removed forced host_key_checking=False |
| `collections/requirements.yml` | `803ddd4a5aade5304f0872e96d52604d27ed3e69` | Unpinned community.crypto, ansible.posix, community.general, ansible.controller, community.hashi_vault |
| `collections/requirements-aap-setup.yml` | `920033a2372e314f1c86b27c9aad4acddf40c021` | ansible.controller for AAP setup only |
| Collection `galaxy.yml` | `3dd9a0626a2972554d56d4c7610eda05cef26c19` | security.compliance_pqc_readiness 0.3.0; crypto >=2.0.0, posix >=1.5.0, general >=5.0.0, hashi_vault >=6.0.0 |
| Collection `meta/runtime.yml` | `1e85b01d0f46b6bd927d38b04faddb7470d376c6` | requires_ansible >=2.15.0 |

Collection prefix C = `ansible_collections/security/compliance_pqc_readiness/`.
Root and C roles/plugins each contain 69 tracked leaves, all 69 pairs match
relative paths, modes and blob IDs. This is static metadata, not #4 runtime
parity. Eight roles: crypto_posture_snapshot, remediate_certificates,
remediate_crypto_policy, remediate_nginx_tls, remediate_sshd, vault_deploy,
vault_issue_cert, vault_pki_setup. Modules normalize_pqc.py
(`f2f994676be4eebb04e0174b962aeec66da6940e`) and generate_cbom.py
(`53615fdb9034caf6130267c83ae1f44d92426195`) accept crypto_report and can write
output_file; CFF and CycloneDX 1.6 declarations are not schema validation.
Keep short-name and Collection FQCN interfaces; no AAP, Vault or other
service is required for the planned standalone scan. Do not install all
listed deployment dependencies just because they appear in metadata.

### Existing entry points (REPO_SOURCE, static only)

Paths below are relative to the fixed fork tree; C denotes the prefix above.

| Path | Blob SHA-1 | Targets, loader, inputs and outputs / effects |
|---|---|---|
| playbooks/crypto_posture_snapshot.yml | 0accc261e02174a4fe6619b3b66daf94e700caf0 | pqc_targets; short role; facts/become; crypto report, controller JSON/HTML/PDF/CBOM and fleet when enabled |
| playbooks/pqc_pipeline.yml | 9108fa7791f0ace98a170777e2d6f1bfe3460a9e | pqc_targets; short role/modules; facts/become; CFF findings, optional CBOM |
| C/playbooks/pqc_pipeline.yml | 2b915e35b8b2a406734b9f63edd6e9535cbdebf8 | all with facts/become, then localhost FQCN normalization, conditional Backstage URI ingest and CBOM |
| playbooks/normalize.yml | 559d8c0801c964754c21aa339cd8a567626db9ff | pqc_targets; no facts; requires existing pqc_crypto_report; short module, CFF facts/summary |
| C/playbooks/normalize.yml | cdffb91a88e0004aacb162e5a9695de0419a60f0 | all; no facts; same report input, FQCN CFF |
| playbooks/generate_cbom.yml | f18ac8d390f70b568f055d0cd22a5b899e926102 | pqc_targets; report input; short module, optional output path and CBOM fact |
| playbooks/remediate.yml | 1a65f62428597a11338d16c87d2b3e655e3cb8b7 | all; short roles, facts/become; discovery, Vault access and changes |
| C/playbooks/remediate.yml | 1c036b493d8f68c58a3ffd6e5d60a4eb70837c58 | all; FQCN roles, facts/become; discovery, Vault access and changes |
| playbooks/remediate_certificates.yml | c1bb806f3b259aff9db4bb4d98cb0907473f8de6 | pqc_targets; short role, facts/become, Vault parameters and certificate replacement |
| playbooks/remediate_crypto_policy.yml | 487df0ff8041d90349eecd8d7b815d4beb16593c | pqc_targets; short role, facts/become, changes crypto policy |
| playbooks/remediate_nginx_tls.yml | 36a0a4e324d8580a69e2cfa6fe442f2e74031760 | pqc_targets; short role, facts/become, Vault and nginx changes |
| playbooks/remediate_sshd.yml | e3941ea7197886b549fc1e40f88ff023f6343df6 | pqc_targets; short role, facts/become, sshd changes |
| playbooks/vault_deploy.yml | 47ca0f2a2c3c6d959ca3f7f361cf63d9e8cdf177 | vault_servers; short role, facts/become, deploy/init Vault |
| C/playbooks/vault_deploy.yml | b50b638686288955eba14446204891d638eec81e | vault_servers; FQCN, facts/become, deploy/init Vault |
| playbooks/vault_pki_setup.yml | 6c134beb633d7f70f24119f61d0618622e4581bf | localhost, local connection, facts; short role and Vault parameters, PKI configuration |
| C/playbooks/vault_pki_setup.yml | 0060acdf34641a8b255401ddd2c3801eba904312 | localhost, local connection, facts; FQCN, PKI configuration |
| playbooks/sync_pqc_inventory.yml | 34fa13b77588429f7bd1844845737546747f8f0d | pqc_targets discovery with facts/become; localhost AAP controller inventory/group/host writes |
| setup/configure-aap-project.yml | 199e420bfd3c1be11ec49c1252bef23a6834ca99 | localhost, local connection; AAP API, execution environment/project setup |

All entries are prohibited from actual task execution in #3, even check mode.
Only the original snapshot is eligible for syntax-only verification here.
Role defaults (`a7c53ed24bdcea417d0b2101d35ce986e24448f4`) enable all eight
pqc_collect_* switches (packages, openssl, nginx_certs, sshd, ssh_host_keys,
system_certs, tls_services, crypto_policy), disable pqc_write_local_report,
pqc_write_html_report, pqc_write_pdf_report and pqc_write_cbom. TLS ports
443/8443/636/993/995, timeout 5, are source defaults, not authorized targets.
Role main imports collector tasks and report assembly; tls_probe.yml
(`e0c8ea7bff6c5cfcdc94c7c9b9a2c1154574eb13`) uses ss and openssl s_client
on loopback. Snapshot has full-report debug, 0644 JSON/HTML and flat paths;
fleet includes only defined reports. #7/#8/#9/#17/#18/#36 must address these
risks: this legacy source is not the new passive Baseline. Do not execute
remediation/Vault/AAP/pipeline or infer effective privileges from declarations.

## OWNER_CONTROLLER: provided sanitized / Owner-attested intake

Source: Owner-approved baseline intake-review package, prepared 2026-11-24;
[Planner intake](https://github.com/hwakeyeTW/PQC/issues/3#issuecomment-7124360208).
The version summary refers to a Controller screenshot inspected during intake;
this implementation received the reviewed summary, not the screenshot or a
live Controller. Observed date is the intake date (exact capture time UNKNOWN).
Publication authorized by Owner for reviewed versions/contracts, not original
config, private identifiers, raw inventory or reports.

| Item | Value | Evidence / status |
|---|---|---|
| ansible-core CLI | 2.18.3 | PROVIDED_SANITIZED, listed version |
| CLI runtime Python | 3.12.15 | PROVIDED_SANITIZED |
| PATH python3 CLI | 3.12.15 | PROVIDED_SANITIZED, distinct from runtime |
| Jinja2 | 3.1.5 | PROVIDED_SANITIZED |
| LibYAML | True | PROVIDED_SANITIZED |
| community.crypto | 3.6.0 | installed listing only |
| community.hashi_vault | 7.1.0 | installed listing only; no Vault deployment requirement |
| Controller OS/arch, Git, pytest | UNKNOWN | not in approved summary |
| Other Collection installed versions, all resolved/loaded versions | UNKNOWN | not inferred from declarations or missing screenshot entries |

| Effective setting or boundary | Approved value / origin class | Status |
|---|---|---|
| Config source | system-level configuration / EXTERNAL_CONFIG | attested; actual path REDACTED |
| Inventory source | external DB-backed Python/Shell script; --list / --host / EXTERNAL_CONFIG | Owner-attested interface; provider not invoked; exact path and DB settings private |
| roles_path, collections_path, module library, script plugin effective settings | UNKNOWN | repo defaults are separate, not resolved Controller loader |
| HOST_KEY_CHECKING, DEFAULT_FORKS, DEFAULT_TIMEOUT | UNKNOWN | no effective dump provided; historical CLI forks=2 is not a Controller default |
| SSH/ProxyJump, become, per-host/group vars and overrides | UNKNOWN | private values never published; effective origin classes ENV/CLI/INVENTORY_VAR/EXTERNAL_CONFIG not established |
| Galaxy servers, effective lookup order and dependency versions | UNKNOWN | not inferred from installed listing |

Preserve the existing external provider, DB, inventory, host/group variables,
SSH, ProxyJump, and operational settings. Ansible config defaults, environment,
CLI, play vars, inventory and extra-vars have distinct precedence; no private
per-host override was measured. Unknown host/error behavior of real provider
is not the synthetic fixture oracle. Owner may locally run ansible --version,
python3 --version, ansible-galaxy collection list and ansible-config dump
--only-changed, sharing only approved summaries; this work package does not
invoke those commands on the real Controller or call the real inventory.
OL 9.7/9.8/9.9 are verification targets, not proven support. #14/#28 own lab
acceptance; an observed historical OL 9.8 report is not a lab test.

## ISOLATED_TEST: implementation evidence, 2026-11-24

Selected fixed source reconstruction, not full checkout. Candidate ansible.cfg
bytes were checked against the fixed blob; only authorized fixture/source bytes
and synthetic examples were used. Linux x86_64 Debian 13; Python 3.13.5,
Git 2.47.3, pytest 9.0.2, Jinja2 3.1.6, PyYAML 6.0.3; UTF-8 C.UTF-8 locale
verified. Python 3.12 and Ansible executables are absent. No usable local
Ansible dependency cache or reachable package source was established; no
installation attempted. This differs from actual Controller core 2.18.3 /
Python 3.12.15 / Jinja2 3.1.5. #2 QA core 2.19.11 is not the Controller;
#5's proposed CI versions are not established support. No full inventory or
config dump, remote connection, or existing playbook task execution occurred.

| Verification | Actual result / status |
|---|---|
| Synthetic fixture mode and CLI | 100755; 16 passed, 6 deselected (CLI-only run, 22.42s, rc=0) |
| Full focused pytest | 22 collected: 16 passed, 6 failed, 0 skipped (22.44s, rc=1); each failure is the explicit missing ansible-inventory tool guard, not an executed integration test |
| py_compile (both Python files) | rc=0 |
| Intake YAML/JSON static parse | strict duplicate-key checks passed for two YAML and two JSON samples; no historical execution |
| ansible --version / collection list / config dump --only-changed / loader | BLOCKED: tools absent; no rc fabricated |
| Real script plugin, inline/lookup/host/empty | BLOCKED: tool absent; six required pytest cases fail closed, not skipped |
| Original snapshot syntax-check | BLOCKED: ansible-playbook and necessary resolved dependencies unavailable; no rc |
| Collection pytest tests/unit/ -v | BLOCKED: ansible-core absent; fixed tree contains test_normalize_pqc.py (868fb434ed60da65e581aab3ce1bca108cf67591); suite not run |

Commands for the focused run (from reconstructed root, isolated HOME/XDG,
UTF-8 and explicit candidate config; scratch paths not committed):

```sh
python3 -m pytest -q -rs -p no:cacheprovider tests/test_baseline_inventory.py -k 'not ansible_inventory'
python3 -m pytest -q -rs -p no:cacheprovider tests/test_baseline_inventory.py
python3 -m py_compile tests/fixtures/inventory_synthetic.py tests/test_baseline_inventory.py
```

For a subsequent authorized isolated test environment, use a metadata-first
verified source projection excluding archive and real inventory; no unsafe
clone/sparse fallback. Verify candidate loader paths and actual installed
versions before the following, record rc, counts and sanitized evidence. No
--check, real play tasks, historical script execution or remote access.

```sh
ROOT="$PWD"
FIXTURE="$ROOT/tests/fixtures/inventory_synthetic.py"
# Isolate HOME/XDG, UTF-8 locale, config, collection search paths and temp dirs.
ANSIBLE_CONFIG="$ROOT/ansible.cfg" PQC_SYNTHETIC_INVENTORY_MODE=inline ansible-inventory -i "$FIXTURE" --list
ANSIBLE_CONFIG="$ROOT/ansible.cfg" PQC_SYNTHETIC_INVENTORY_MODE=lookup ansible-inventory -i "$FIXTURE" --list
ANSIBLE_CONFIG="$ROOT/ansible.cfg" PQC_SYNTHETIC_INVENTORY_MODE=inline ansible-inventory -i "$FIXTURE" --host host-b.example.invalid
ANSIBLE_CONFIG="$ROOT/ansible.cfg" PQC_SYNTHETIC_INVENTORY_MODE=empty ansible-inventory -i "$FIXTURE" --list
python3 -m pytest -q -rs -p no:cacheprovider tests/test_baseline_inventory.py
ANSIBLE_CONFIG="$ROOT/ansible.cfg" PQC_SYNTHETIC_INVENTORY_MODE=inline ansible-playbook -i "$FIXTURE" --syntax-check playbooks/crypto_posture_snapshot.yml
(cd "$ROOT/ansible_collections/security/compliance_pqc_readiness" && python3 -m pytest tests/unit/ -v)
```

Budgets: CLI 5s, inventory 30s, syntax 60s, focused/unit each 120s. These are
isolated test bounds, not production scanning limits. Preserve baseline red
results; do not make them green by skipping requirements or changing source.
#5 owns CI integration and safe acquisition. B07/B11 and full B10 are not
complete. #3 remains HOLD pending required tests, independent review/QA,
CI gate and Owner decision; neither intake nor a Draft PR proves readiness.

## Review R1 correction and deployment-source contract (2026-11-24)

Authority: [F-R1-01 review](https://github.com/hwakeyeTW/PQC/pull/49#pullrequestreview-6035267423),
[correction dispatch](https://github.com/hwakeyeTW/PQC/issues/3#issuecomment-7125234125),
[offline source policy R2](https://github.com/hwakeyeTW/PQC/issues/1#issuecomment-7125166664).
The earlier source and test records above remain historical evidence. Fixed
R1 parent is f87ef0ebd83e89dedea888bfd5cac9dbc4c92088 (tree
8d7a0adad607c24ace6f1692a3649f4f8122f3fb); original base B remains
95c0d6512c69cadf8b0cd3131d88a043b4885425. Actual main M is
596c5c7fae7ee0b2d3874a59c25e073cdbb0735d (tree
73f2c4691d814008c7a154b8a721d6e071283578), with #4 merged. B to M adds
three nonoverlapping paths; B to R1 adds five. No rebase or main merge
into this branch. A new native integration test merge and its QA remain
required; the old test merge is not evidence for M.

### Deployment source classes (FORMAL_REQUIREMENT, not tested availability)

| Class | Meaning and observed state |
|---|---|
| INSTALLED | Prefer already installed, compatible dependencies. Owner-attested listing above is installed evidence only; actual resolved versions and loader/closure remain UNKNOWN. |
| APPROVED_PROXY_PACKAGE_SOURCE | During separately authorized deployment only, existing approved Proxy may supply necessary Controller Python dependencies from PyPI and RPMs from official Oracle Linux repositories, if available. Authorization is not reachability or package availability; both NOT_TESTED. |
| LOCAL_COLLECTION_ARTIFACT | Collections must support local offline installation of versioned tarballs and complete necessary transitive Collection dependencies, with trusted source, integrity/checksum manifest and verified loader. Actual local artifacts, closure and offline install are UNKNOWN/NOT_TESTED. No required public Galaxy access. |
| UNAVAILABLE | An identified dependency/source absent or inaccessible in the tested environment; do not substitute an unapproved source. The isolated test environment lacks Ansible; this is not evidence of a missing Owner Controller dependency. |
| UNKNOWN | No sufficient approved evidence about availability, installed or resolved version, source, or actual compatibility. Do not treat declarations as installed or available. |

Approved local wheels/RPMs are optional deployment alternatives, not a
mandatory full bundle on every release. Verify versions, platform, complete
necessary dependencies and trust; preserve TLS/GPG validation. Do not change
Proxy, CA, pip/DNF/repository settings, add mirrors, bypass restrictions,
install/update automatically or modify the Controller/managed hosts. Do not
blindly install development CI, AAP, Vault or optional PDF dependencies.
Prepare local Collection artifacts separately in an approved environment;
verify actual offline flags and dependency order, and do not use --no-deps
to conceal missing dependencies or resolve/fetch from Galaxy. Runtime
(scan, evaluate, import and render) must not use the package Proxy or public
Internet. Existing authorized internal Inventory/DB/SSH/ProxyJump remains
unchanged. See compatibility.md; actual deployment and offline runtime QA
are NOT_TESTED here. OFFLINE-DELIVERY is a separate proposed work package,
not implemented or authorized by this correction.

### B04 remaining necessary effective-setting evidence

No new Owner Controller measurements were supplied in this correction.
Retain PARTIAL/BLOCKED for the following gaps; obtain only approved minimal
local summaries, with effective source/precedence, or an explicit Owner
acceptance decision. Actual paths, credentials and network values stay private.

| Gap (UNKNOWN unless noted) | Downstream impact |
|---|---|
| Effective script plugin/inventory source class | #6 actual provider selection, without invoking the real script |
| Role/collection/library origin, lookup precedence, resolved versions and necessary installed dependency closure | #6/#7 local capability/loader preflight; #14 compatibility |
| HOST_KEY_CHECKING/forks/timeout effective values or REDACTED with origin | #6/#7/#8 trust, execution bounds and failure handling |
| SSH/ProxyJump/become and host/group override presence and origin | #6/#7 preserve authorized internal settings; no privilege assumptions |
| Actual provider unknown-host/error semantics | #6 failure/zero-host classification; synthetic fixture is not proof |

### ISOLATED_TEST: correction evidence

Exact fixed seven-file local projection (five candidate blobs, ansible.cfg
and .gitignore) was recovered and verified by Git hash-object; no complete
checkout, archive bytes or real inventory. Same Debian 13 x86_64, Python
3.13.5, Git 2.47.3, pytest 9.0.2, Jinja2 3.1.6, PyYAML 6.0.3, C.UTF-8.
Python 3.12 and Ansible tools/cache still unavailable; no install, deployment,
Controller access or native inventory/loader/Ansible syntax/unit result.

F-R1-01: old empty oracle accepted rc0 parse-failure warnings, missing
structure {} and an orphan group with an extra host; all three were
reproduced using controlled synthetic subprocess responses, not Ansible.
The new oracle rejects all three and retains valid empty, rejects nonzero
rc and absent binary. Both fatal controls are enabled in isolated test env
only, with targeted parse-warning rejection even at rc0. Static version
basis: ansible-core v2.18.3 config/base.yml (445fd4540a10c2fc92568012538145258bbcb2de),
inventory/manager.py (96df1f46477a436c2d5c6619ebc46d68b5c71d0b),
cli/inventory.py (6a4ee9241f7eed5a386d97db6e2b0491c7cc5487),
inventory/data.py (7282d6fb751ab43b2698d9b8e4f9aa24a52fac9f) and
plugins/inventory/script.py (9b4c316ebdd3aa3e64888ed4006ad41a8b1a8ca7).
These source declarations/formatting rules are not runtime verification.

- Focused collection: 54 unique nodes, all 22 original nodes retained,
  32 new (29 pure oracle regressions, 3 required native checks).
- Full focused pytest: 45 passed, 9 failed, 0 skipped, rc=1, 22.96s.
  Original 16 CLI and all 29 new oracle cases passed. Original six native
  cases and new fatal-config plus two failed-provider cases failed only at
  the explicit missing-tool guard. B07/B10 remain BLOCKED/PARTIAL.
- Both Python files py_compile rc=0. Original two fixture blobs and modes
  unchanged. No historical YAML execution. B11 remains BLOCKED/NOT_TESTED.
- R2 QA must actually check both effective fatal settings with ansible-config,
  legitimate empty and nonempty lists/hosts, inline vs lookup invocation trace,
  and nonzero native parser rc plus diagnostics for disposable malformed JSON
  and nonzero providers. Then run the required full suite, loader, original
  snapshot syntax-only and Collection unit checks in an authorized isolated
  environment. No mock or skip substitutes for the native checks.

This correction is implementation evidence only. B09 delta review, independent
Review R2, Focused QA R2, refreshed integration and required CI are pending;
#3 remains HOLD. No actual package acquisition, install or offline release
verification was performed.
