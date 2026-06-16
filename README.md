# PQC-AAP

**Post-Quantum Cryptography readiness** assessment and remediation for RHEL 8/9 hosts, delivered as an Ansible collection installable on the [AAP Compliance Pipelines](https://github.com/cross-logic/aap-compliance-pipelines).

Evaluates PQC readiness across 8 categories — OpenSSL runtime, system certificates, SSH host keys, TLS services, nginx certificates, sshd configuration, and RHEL crypto-policies — producing Common Findings Format (CFF) v1.0.0 JSON for the Backstage compliance plugin and CycloneDX v1.6 Cryptography Bill of Materials (CBOM) for cryptographic asset inventory. Includes automated remediation using HashiCorp Vault as a Certificate Authority.

| Property | Value |
|----------|-------|
| **Framework** | CUSTOM |
| **Scanner** | custom (Tier 1 — native OS tools) |
| **Certification** | uncertified |
| **Platforms** | RHEL 8, RHEL 9 |
| **Remediation** | Automated via HashiCorp Vault CA |

## Project Structure

```
PQC-AAP/
  ansible_collections/security/compliance_pqc_readiness/
    galaxy.yml                    # Collection metadata (v0.3.0)
    meta/compliance-profile.yml   # Compliance pipeline profile identity
    meta/runtime.yml              # Ansible version constraint
    plugins/modules/normalize_pqc.py  # CFF normalizer module
    plugins/modules/generate_cbom.py   # CycloneDX CBOM generator module
    playbooks/
      pqc_pipeline.yml            # Pipeline-compatible (2-play Direct POST)
      normalize.yml               # Standalone normalization utility
      remediate.yml               # Full remediation pipeline via Vault CA
      vault_deploy.yml            # Deploy HashiCorp Vault server
      vault_pki_setup.yml         # Configure PKI CA hierarchy
    roles/
      crypto_posture_snapshot/    # Discovery role (read-only)
      vault_deploy/               # Install and configure Vault
      vault_pki_setup/            # Root + Intermediate CA setup
      vault_issue_cert/           # Issue certificates from Vault PKI
      remediate_certificates/     # Replace non-PQC system certs
      remediate_crypto_policy/    # RHEL crypto-policy PQC update
      remediate_nginx_tls/        # nginx TLS cert + PQC KEX
      remediate_sshd/             # SSH PQC hardening
    tests/unit/                   # pytest unit tests
    LICENSE
  ee/execution-environment.yml    # Execution Environment build definition
  install.yml                     # Register profile + job templates on AAP
  playbooks/                      # Standalone playbooks (non-pipeline use)
    crypto_posture_snapshot.yml   # Full snapshot with HTML/PDF reports
    pqc_pipeline.yml              # Legacy pipeline (event-based)
    normalize.yml                 # Standalone normalize
    generate_cbom.yml             # Standalone CBOM generation
    sync_pqc_inventory.yml        # Sync results to Controller inventory
    vault_deploy.yml              # Deploy Vault (standalone)
    vault_pki_setup.yml           # Configure PKI CA (standalone)
    remediate.yml                 # Full remediation orchestrator
    remediate_certificates.yml    # Certificate-only remediation
    remediate_crypto_policy.yml   # Crypto-policy-only remediation
    remediate_nginx_tls.yml       # nginx-only remediation
    remediate_sshd.yml            # SSH-only remediation
  roles/                          # Standalone roles (mirrors collection)
  plugins/modules/                # Standalone module (same as collection)
  setup/configure-aap-project.yml # AAP project + EE registration
  inventory/hosts.yml             # Sample inventory
  collections/requirements.yml    # Galaxy dependencies
  reports/                        # Generated report output
```

## Installation on AAP Compliance Pipelines

This project is designed as a compliance profile that plugs into the [aap-compliance-pipelines](https://github.com/cross-logic/aap-compliance-pipelines) Backstage plugin.

### 1. Build the Execution Environment

```bash
ansible-builder build -f ee/execution-environment.yml -t compliance-pqc-readiness:latest -v3
```

Push to your container registry:

```bash
podman push compliance-pqc-readiness:latest quay.io/your-org/compliance-pqc-readiness:latest
```

### 2. Register on AAP Controller

```bash
export AAP_HOST=https://controller.example.com
export AAP_API_TOKEN=<your-token>

ansible-playbook install.yml \
  -e organization=Default \
  -e project=compliance-profile-pqc-readiness \
  -e execution_environment=compliance-pqc-readiness \
  -e inventory=compliance-rhel-inventory
```

This creates:
- **Assessment JT**: `compliance-scan-pqc-readiness` (runs `pqc_pipeline.yml`)
- **Remediation JT**: `compliance-remediate-pqc-readiness` (full remediation pipeline)
- **Vault Deploy JT**: `pqc-vault-deploy`
- **Vault PKI Setup JT**: `pqc-vault-pki-setup`
- **Certificate Remediation JT**: `pqc-remediate-certificates`
- **Crypto Policy JT**: `pqc-remediate-crypto-policy`
- **nginx TLS JT**: `pqc-remediate-nginx`
- **SSH Remediation JT**: `pqc-remediate-sshd`

### 3. Register in Backstage

In **Compliance > Settings**, add a new profile:
- Select the assessment JT (`compliance-scan-pqc-readiness`)
- The `compliance-profile.yml` metadata auto-populates profile fields
- Link the remediation JT (`compliance-remediate-pqc-readiness`)

### Pipeline Integration (Direct POST)

The collection's `playbooks/pqc_pipeline.yml` follows the ADR-003 pattern:

1. **Play 1** (on targets): Runs the `crypto_posture_snapshot` role — read-only discovery
2. **Play 2** (on localhost): Normalizes to CFF and POSTs findings to `/api/compliance/findings/ingest`

Extra vars injected by the Backstage plugin at launch:
- `scan_id` — UUID assigned by the backend
- `backstage_api_url` — Backend base URL
- `ingest_token` — Per-scan security token (ADR-010)
- `compliance_profile` — Profile UUID from Settings

## Standalone Usage (without Pipeline)

### Requirements

- Ansible 2.15+
- Collections: `community.crypto`, `ansible.posix`, `community.general`, `community.hashi_vault`
- Python: `hvac>=2.1.0` (for Vault operations)

```bash
ansible-galaxy collection install -r collections/requirements.yml -p collections
```

### Quick Start — Assessment

1. Add hosts under the `pqc_targets` group in `inventory/hosts.yml`
2. Run the snapshot:

```bash
ansible-playbook playbooks/crypto_posture_snapshot.yml
```

3. Generate HTML/PDF reports:

```bash
ansible-playbook playbooks/crypto_posture_snapshot.yml \
  -e pqc_write_html_report=true \
  -e pqc_write_pdf_report=true
```

4. Sync findings to AAP Controller inventory:

```bash
ansible-playbook playbooks/sync_pqc_inventory.yml \
  -e aap_controller_url=https://controller.example.com
```

### Cryptography Bill of Materials (CBOM)

Generate a [CycloneDX v1.6](https://cyclonedx.org/capabilities/cbom/) CBOM per host — a structured inventory of all discovered cryptographic assets (algorithms, certificates, keys, protocols) and their dependency relationships. Conforms to ECMA-424 and aligns with NIST SP 1800-38B cryptographic discovery guidance.

```bash
ansible-playbook playbooks/crypto_posture_snapshot.yml \
  -e pqc_write_cbom=true
```

Per-host CBOM files are written to `reports/cbom/<hostname>.cbom.json`.

To generate a CBOM from an existing `pqc_crypto_report` fact (e.g., from a prior snapshot):

```bash
ansible-playbook playbooks/generate_cbom.yml \
  -e pqc_cbom_output_file=/tmp/cbom-myhost.json
```

When running the pipeline with `pqc_write_cbom=true`, CBOM generation runs alongside CFF normalization:

```bash
ansible-playbook playbooks/pqc_pipeline.yml \
  -e pqc_write_cbom=true
```

Each CBOM maps discovered assets to CycloneDX component types:

| Discovery source | CycloneDX asset type | Components created |
|-----------------|----------------------|-------------------|
| System certificates | `certificate` + `algorithm` + `related-crypto-material` | Certificate, signature algorithm, public key |
| nginx certificates | `certificate` + `algorithm` + `related-crypto-material` | Certificate, signature algorithm, public key |
| SSH host keys | `related-crypto-material` + `algorithm` | Public key, key algorithm |
| TLS services | `protocol` + `algorithm` | TLS protocol with cipher suites, KEX/cipher/signature algorithms |
| sshd configuration | `protocol` + `algorithm` | SSH protocol with configured KEX, ciphers, MACs |
| OpenSSL runtime | `library` + `algorithm` | OpenSSL library, available TLS 1.3 groups |
| RHEL crypto-policy | BOM `properties` | Policy profile, FIPS mode, local overrides |

Algorithms include `nistQuantumSecurityLevel` (0 for classical, 1-5 for PQC) and `classicalSecurityLevel` (bits) for quantum readiness assessment by downstream tooling.

## HashiCorp Vault Setup (Certificate Authority)

The remediation pipeline uses HashiCorp Vault as a PKI Certificate Authority to issue
replacement certificates for non-PQC-compliant assets.

### 1. Deploy Vault

Add your Vault target to the `vault_servers` inventory group, then deploy:

```bash
ansible-playbook playbooks/vault_deploy.yml -l vault_servers
```

This installs Vault from the HashiCorp RPM repo, configures it with TLS 1.3, initializes
with Shamir key shares, and enables audit logging.

**Security**: The init-keys.json file created during initialization contains unseal keys
and the root token. Secure this file immediately — move keys to offline storage and delete
the file from the server.

### 2. Configure PKI CA Hierarchy

```bash
ansible-playbook playbooks/vault_pki_setup.yml \
  -e vault_addr=https://vault.example.com:8200 \
  -e vault_token=<root-token>
```

This creates:
- **Root CA** (`pki` mount) — ECDSA P-384, 10-year TTL
- **Intermediate CA** (`pki_int` mount) — ECDSA P-384, 5-year TTL, signed by Root
- **Certificate roles**: `pqc-server`, `pqc-client`, `pqc-nginx`
- **AppRole** (`pqc-cert-issuer`) for automated issuance from AAP
- **CRL/OCSP** distribution points

Customize allowed domains by overriding `vault_pki_roles`:

```bash
ansible-playbook playbooks/vault_pki_setup.yml \
  -e vault_addr=https://vault:8200 \
  -e vault_token=<token> \
  -e '{"vault_pki_roles": [{"name": "pqc-server", "allowed_domains": ["mycompany.com"], "allow_subdomains": true, "key_type": "ec", "key_bits": 384}]}'
```

### 3. Store Vault Credentials in AAP

After PKI setup, configure AAP to authenticate to Vault:

1. Create a **HashiCorp Vault Secret Lookup** credential type in AAP
2. Set the `role_id` and `secret_id` from the AppRole output
3. Reference the credential in remediation job templates

## Remediation

### Full Remediation Pipeline

Run all remediation stages (scan → certificates → crypto policy → nginx → SSH → validate):

```bash
ansible-playbook playbooks/remediate.yml \
  -e vault_addr=https://vault:8200 \
  -e vault_token=<token>
```

### Selective Remediation via Tags

```bash
# Certificates only
ansible-playbook playbooks/remediate.yml --tags remediate_certificates \
  -e vault_addr=https://vault:8200 -e vault_token=<token>

# Crypto policy only (no Vault needed)
ansible-playbook playbooks/remediate.yml --tags remediate_crypto_policy

# nginx TLS only
ansible-playbook playbooks/remediate.yml --tags remediate_nginx \
  -e vault_addr=https://vault:8200 -e vault_token=<token>

# SSH hardening only (no Vault needed)
ansible-playbook playbooks/remediate.yml --tags remediate_sshd
```

### Standalone Remediation Playbooks

Each remediation domain has its own standalone playbook:

```bash
ansible-playbook playbooks/remediate_certificates.yml \
  -e vault_addr=https://vault:8200 -e vault_token=<token>

ansible-playbook playbooks/remediate_crypto_policy.yml

ansible-playbook playbooks/remediate_nginx_tls.yml \
  -e vault_addr=https://vault:8200 -e vault_token=<token>

ansible-playbook playbooks/remediate_sshd.yml
```

### Dry Run Mode

Assess without making changes:

```bash
ansible-playbook playbooks/remediate.yml \
  -e vault_addr=https://vault:8200 -e vault_token=<token> \
  -e remediate_cert_dry_run=true \
  -e remediate_crypto_dry_run=true \
  -e remediate_nginx_dry_run=true \
  -e remediate_sshd_dry_run=true
```

### What Remediation Does

| Role | Action | Vault Required |
|------|--------|---------------|
| `remediate_certificates` | Scans system cert paths, identifies non-PQC certs (RSA/ECDSA/DSA), issues replacements from Vault Intermediate CA, backs up originals | Yes |
| `remediate_crypto_policy` | Sets RHEL crypto-policy to `FUTURE:PQC`, configures OpenSSL for ML-KEM key exchange, applies local.d overrides | No |
| `remediate_nginx_tls` | Detects nginx SSL sites, re-issues certs from Vault, configures `ssl_ecdh_curve X25519MLKEM768`, enforces TLS 1.3 | Yes |
| `remediate_sshd` | Deploys PQC KEX algorithms (`mlkem768x25519-sha256`, `sntrup761x25519-sha512`), hardens ciphers/MACs, optionally regenerates host keys | No |

## What It Checks

| Category | Rule IDs | Check |
|----------|----------|-------|
| Cryptographic Libraries | `pqc_openssl_mlkem_support`, `pqc_openssl_version` | ML-KEM in TLS 1.3 groups, OpenSSL >= 3.5 |
| Certificates | `pqc_cert_<hash>` | PQC-safe public key algorithm |
| TLS Services | `pqc_nginx_cert_<hash>`, `pqc_tls_service_port_<port>` | PQC KEX on active TLS services |
| SSH Configuration | `pqc_ssh_hostkey_<algo>`, `pqc_sshd_kex_algorithms` | PQC host keys and KEX config |
| System Configuration | `pqc_crypto_policy_profile` | RHEL crypto-policy PQC sub-policy |

## Role Variables

### Discovery (`crypto_posture_snapshot`)

| Variable | Default | Purpose |
|----------|---------|---------|
| `pqc_collect_packages` | `true` | Gather OpenSSL package versions |
| `pqc_collect_openssl` | `true` | OpenSSL version and TLS groups |
| `pqc_collect_nginx_certs` | `true` | Discover and inspect nginx certs |
| `pqc_collect_sshd` | `true` | SSH daemon crypto directives |
| `pqc_collect_ssh_host_keys` | `true` | SSH host key algorithms |
| `pqc_collect_system_certs` | `true` | System certificate scan |
| `pqc_collect_tls_services` | `true` | TLS port probe |
| `pqc_collect_crypto_policy` | `true` | RHEL crypto-policies |
| `pqc_write_local_report` | `false` | Write JSON reports |
| `pqc_write_html_report` | `false` | Generate HTML reports |
| `pqc_write_pdf_report` | `false` | Export PDF (requires weasyprint) |
| `pqc_write_cbom` | `false` | Generate CycloneDX v1.6 CBOM |

### Vault Deploy (`vault_deploy`)

| Variable | Default | Purpose |
|----------|---------|---------|
| `vault_version` | `1.19.0` | Vault package version |
| `vault_listen_address` | `0.0.0.0:8200` | Vault listener bind address |
| `vault_tls_disable` | `false` | Disable TLS on listener |
| `vault_tls_min_version` | `tls13` | Minimum TLS version |
| `vault_storage_backend` | `file` | Storage backend (file or raft) |
| `vault_init_secret_shares` | `5` | Shamir key shares |
| `vault_init_secret_threshold` | `3` | Unseal threshold |
| `vault_enable_audit_file` | `true` | Enable file audit logging |

### Vault PKI (`vault_pki_setup`)

| Variable | Default | Purpose |
|----------|---------|---------|
| `vault_pki_root_common_name` | `PQC Root CA` | Root CA CN |
| `vault_pki_root_key_type` | `ec` | Root CA key type |
| `vault_pki_root_key_bits` | `384` | Root CA key size (P-384) |
| `vault_pki_intermediate_common_name` | `PQC Intermediate CA` | Intermediate CA CN |
| `vault_pki_roles` | (see defaults) | Certificate issuance role definitions |
| `vault_pki_create_approle` | `true` | Create AppRole for automation |
| `vault_pki_approle_name` | `pqc-cert-issuer` | AppRole name |

### Certificate Remediation (`remediate_certificates`)

| Variable | Default | Purpose |
|----------|---------|---------|
| `vault_addr` | `https://127.0.0.1:8200` | Vault API address |
| `vault_cert_pki_path` | `pki_int` | PKI mount to issue from |
| `vault_cert_role` | `pqc-server` | Vault role for issuance |
| `remediate_cert_scan_paths` | `/etc/pki/tls/certs`, etc. | Paths to scan for certs |
| `remediate_cert_dry_run` | `false` | Assess only, no changes |
| `remediate_cert_backup` | `true` | Backup before replacing |

### Crypto Policy Remediation (`remediate_crypto_policy`)

| Variable | Default | Purpose |
|----------|---------|---------|
| `remediate_crypto_policy_base` | `FUTURE` | Base crypto-policy |
| `remediate_crypto_policy_subpolicies` | `[PQC]` | Sub-policy modules |
| `remediate_crypto_openssl_groups` | `x25519_mlkem768:...` | OpenSSL TLS groups |
| `remediate_crypto_dry_run` | `false` | Assess only, no changes |

### nginx TLS Remediation (`remediate_nginx_tls`)

| Variable | Default | Purpose |
|----------|---------|---------|
| `vault_cert_role` | `pqc-nginx` | Vault role for nginx certs |
| `remediate_nginx_ssl_protocols` | `TLSv1.3` | Allowed TLS protocols |
| `remediate_nginx_ssl_ecdh_curve` | `X25519MLKEM768:...` | PQC ECDH curves |
| `remediate_nginx_dry_run` | `false` | Assess only, no changes |

### SSH Remediation (`remediate_sshd`)

| Variable | Default | Purpose |
|----------|---------|---------|
| `remediate_sshd_kex_algorithms` | `mlkem768x25519-sha256`, etc. | PQC KEX algorithms |
| `remediate_sshd_ciphers` | `chacha20-poly1305`, etc. | AEAD ciphers |
| `remediate_sshd_regenerate_host_keys` | `false` | Remove weak keys, regenerate |
| `remediate_sshd_dry_run` | `false` | Assess only, no changes |

## Running Tests

```bash
cd ansible_collections/security/compliance_pqc_readiness
pytest tests/unit/ -v
```

## Discovery Tools Used

All discovery is read-only (`changed=0`):

- `openssl version`, `openssl list -tls-groups -tls1_3`
- `ssh-keygen -l -f`
- `openssl x509 -noout -text`
- `openssl s_client -connect`
- `ss -tlnp`
- `update-crypto-policies --show`
- `fips-mode-setup --check`
- `community.crypto.x509_certificate_info` (nginx certs)

## Maintainer Checks

```bash
ansible-galaxy collection install -r collections/requirements.yml -p collections

# Syntax check all playbooks
ansible-playbook --syntax-check playbooks/crypto_posture_snapshot.yml
ansible-playbook --syntax-check playbooks/vault_deploy.yml
ansible-playbook --syntax-check playbooks/vault_pki_setup.yml
ansible-playbook --syntax-check playbooks/remediate.yml
ansible-playbook --syntax-check playbooks/remediate_certificates.yml
ansible-playbook --syntax-check playbooks/remediate_crypto_policy.yml
ansible-playbook --syntax-check playbooks/remediate_nginx_tls.yml
ansible-playbook --syntax-check playbooks/remediate_sshd.yml
ansible-playbook --syntax-check playbooks/generate_cbom.yml
ansible-playbook --syntax-check install.yml

# Unit tests
cd ansible_collections/security/compliance_pqc_readiness && pytest tests/unit/ -v
```
