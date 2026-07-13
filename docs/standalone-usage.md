# PQC Readiness — Standalone Usage

Run Post-Quantum Cryptography discovery and remediation directly from the CLI or as AAP job templates, without the Backstage compliance pipeline.

## Prerequisites

- Ansible 2.15+ (or ansible-core 2.17+)
- RHEL 8 or RHEL 9 target hosts
- SSH access with privilege escalation (`become: true`)
- Python 3 on targets

Install collection dependencies:

```bash
ansible-galaxy collection install -r collections/requirements.yml -p collections
```

## Inventory Setup

Add your hosts under the `pqc_targets` group in `inventory/hosts.yml`:

```yaml
all:
  children:
    pqc_targets:
      hosts:
        rhel01:
          ansible_host: 192.168.1.201
        rhel02:
          ansible_host: 192.168.1.197
      vars:
        ansible_python_interpreter: /usr/bin/python3
        ansible_user: root
```

Or pass your own inventory file:

```bash
ansible-playbook playbooks/crypto_posture_snapshot.yml -i /path/to/inventory
```

---

## Discovery (Read-Only)

The `crypto_posture_snapshot` playbook scans targets without making any changes.

```bash
ansible-playbook playbooks/crypto_posture_snapshot.yml
```

### What it checks

| Category | What it inspects |
|----------|-----------------|
| OpenSSL runtime | Version, ML-KEM support, TLS 1.3 groups |
| System certificates | Public key algorithms across `/etc/pki` |
| nginx certificates | SSL cert chain algorithms |
| TLS services | Active listening ports, cipher suites, KEX |
| SSH host keys | Key algorithms on disk |
| sshd configuration | KEX, ciphers, MACs directives |
| RHEL crypto-policy | Active policy profile, FIPS mode |

### Output options

| Extra var | Effect |
|-----------|--------|
| `pqc_write_local_report=true` | JSON report per host in `reports/` |
| `pqc_write_html_report=true` | HTML report per host + fleet aggregate |
| `pqc_write_pdf_report=true` | PDF export (requires `weasyprint`) |
| `pqc_write_cbom=true` | CycloneDX v1.6 CBOM per host in `reports/cbom/` |

Example with all reports:

```bash
ansible-playbook playbooks/crypto_posture_snapshot.yml \
  -e pqc_write_local_report=true \
  -e pqc_write_html_report=true \
  -e pqc_write_cbom=true
```

### Narrowing scope

Disable collectors you don't need:

```bash
ansible-playbook playbooks/crypto_posture_snapshot.yml \
  -e pqc_collect_nginx_certs=false \
  -e pqc_collect_tls_services=false
```

All toggles (default `true`): `pqc_collect_packages`, `pqc_collect_openssl`, `pqc_collect_nginx_certs`, `pqc_collect_sshd`, `pqc_collect_ssh_host_keys`, `pqc_collect_system_certs`, `pqc_collect_tls_services`, `pqc_collect_crypto_policy`.

### Targeting specific hosts

```bash
ansible-playbook playbooks/crypto_posture_snapshot.yml -l rhel01
```

---

## Remediation

### Full remediation (all domains)

Requires a running HashiCorp Vault for certificate issuance:

```bash
ansible-playbook playbooks/remediate.yml \
  -e vault_addr=https://vault.example.com:8200 \
  -e vault_token=<token>
```

### Single-domain playbooks

```bash
# Certificates — replace non-PQC certs via Vault CA
ansible-playbook playbooks/remediate_certificates.yml \
  -e vault_addr=https://vault:8200 -e vault_token=<token>

# Crypto policy — set FUTURE:PQC, no Vault needed
ansible-playbook playbooks/remediate_crypto_policy.yml

# nginx TLS — PQC KEX + cert rotation
ansible-playbook playbooks/remediate_nginx_tls.yml \
  -e vault_addr=https://vault:8200 -e vault_token=<token>

# SSH hardening — PQC KEX algorithms, no Vault needed
ansible-playbook playbooks/remediate_sshd.yml
```

### Selective remediation via tags

```bash
ansible-playbook playbooks/remediate.yml --tags remediate_certificates \
  -e vault_addr=https://vault:8200 -e vault_token=<token>

ansible-playbook playbooks/remediate.yml --tags remediate_crypto_policy

ansible-playbook playbooks/remediate.yml --tags remediate_sshd
```

### Dry run (assess only)

```bash
ansible-playbook playbooks/remediate.yml \
  -e vault_addr=https://vault:8200 -e vault_token=<token> \
  -e remediate_cert_dry_run=true \
  -e remediate_crypto_dry_run=true \
  -e remediate_nginx_dry_run=true \
  -e remediate_sshd_dry_run=true
```

---

## AAP Job Templates

Register all job templates on your AAP Controller:

```bash
export AAP_HOST=https://controller.example.com
export AAP_API_TOKEN=<your-token>

ansible-playbook install.yml \
  -e organization=Default \
  -e project=compliance-profile-pqc-readiness \
  -e execution_environment=compliance-pqc-readiness \
  -e inventory=compliance-rhel-inventory
```

This creates the following job templates:

| Job Template | Playbook | Purpose |
|--------------|----------|---------|
| `compliance-scan-pqc-readiness` | `pqc_pipeline.yml` | Discovery + CFF normalization |
| `compliance-remediate-pqc-readiness` | `remediate.yml` | Full remediation pipeline |
| `pqc-vault-deploy` | `vault_deploy.yml` | Deploy Vault server |
| `pqc-vault-pki-setup` | `vault_pki_setup.yml` | Configure CA hierarchy |
| `pqc-remediate-certificates` | `remediate_certificates.yml` | Certificate rotation only |
| `pqc-remediate-crypto-policy` | `remediate_crypto_policy.yml` | Crypto policy only |
| `pqc-remediate-nginx` | `remediate_nginx_tls.yml` | nginx TLS only |
| `pqc-remediate-sshd` | `remediate_sshd.yml` | SSH hardening only |

Launch any template from the CLI with `awx` or the Controller API:

```bash
awx job_templates launch "compliance-scan-pqc-readiness" \
  --extra_vars '{"pqc_write_local_report": true}'
```

---

## CBOM Generation

Generate a CycloneDX v1.6 Cryptography Bill of Materials:

```bash
# During discovery
ansible-playbook playbooks/crypto_posture_snapshot.yml -e pqc_write_cbom=true

# From an existing report fact
ansible-playbook playbooks/generate_cbom.yml \
  -e pqc_cbom_output_file=/tmp/cbom-myhost.json
```

Output: `reports/cbom/<hostname>.cbom.json`

---

## Vault Setup (for Remediation)

Only needed if you plan to run certificate remediation.

```bash
# 1. Deploy Vault
ansible-playbook playbooks/vault_deploy.yml -l vault_servers

# 2. Configure PKI CA hierarchy
ansible-playbook playbooks/vault_pki_setup.yml \
  -e vault_addr=https://vault:8200 \
  -e vault_token=<root-token>
```

---

## Quick Reference

| Task | Command |
|------|---------|
| Discovery scan | `ansible-playbook playbooks/crypto_posture_snapshot.yml` |
| Discovery + reports | `ansible-playbook playbooks/crypto_posture_snapshot.yml -e pqc_write_html_report=true` |
| Discovery + CBOM | `ansible-playbook playbooks/crypto_posture_snapshot.yml -e pqc_write_cbom=true` |
| Full remediation | `ansible-playbook playbooks/remediate.yml -e vault_addr=... -e vault_token=...` |
| SSH hardening only | `ansible-playbook playbooks/remediate_sshd.yml` |
| Crypto policy only | `ansible-playbook playbooks/remediate_crypto_policy.yml` |
| Dry run | `ansible-playbook playbooks/remediate.yml -e remediate_cert_dry_run=true ...` |
| Single host | `ansible-playbook playbooks/crypto_posture_snapshot.yml -l rhel01` |
