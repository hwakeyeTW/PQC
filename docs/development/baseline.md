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
