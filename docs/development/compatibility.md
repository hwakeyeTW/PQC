# PoC, inventory and legacy report compatibility baseline (PQC-M0-02)

Issue #3 / R1 intake with Owner clarification R2. Source kind
OWNER_SANITIZED_LOCAL / PROVIDED_SANITIZED, reviewed package prepared
2026-11-24; [Planner intake](https://github.com/hwakeyeTW/PQC/issues/3#issuecomment-7124360208)
and [latest Issue #3](https://github.com/hwakeyeTW/PQC/issues/3). Owner
explicitly approved reviewed version summaries, anonymized contracts and
synthetic examples for publication in this work package. See
[baseline.md](baseline.md) for separate repo and Controller evidence.

## Custody and limits

The supplied review ZIP contains a version/contract summary, one historical
YAML, a synthetic scope and two synthetic JSON examples. CRC, strict safe
YAML and JSON parsing (duplicate keys rejected) and sample shape consistency
were checked in isolation. No original inventory, mapping table, screenshot,
original source hash, real report, certificate data or raw scan archive was
received or processed in this implementation. The original evidence remains
private with Owner. Actual legacy shape is the Planner's attested observation
from the prior private intake, not this implementation re-reading raw reports.

`tests/fixtures/scan_ol9.anonymized.yml` is the exact approved historical
copy (10524 bytes; SHA-256
`e5ea8c10973d09e736c12e4fd7e5212b7473946dcbbe269271d120be00079523`).
The intake summary states only the leading comments changed and original and
candidate parsed YAML were equal; this implementation checked candidate bytes
and structure, not the private original. Mode 100644. Three plays, safe parser
only; no Jinja evaluation, inventory execution or Ansible execution. Static
INPUT fixture only; never load as a runtime entry or execute in CI (including
check mode). Retention provides concrete regression reference for migration;
R2 does not require preserving this script as the future product API.
Synthetic samples are hand-built, not anonymized actual records. No actual
host/group identifiers, paths, counts, fingerprints or credentials are included.

## OBSERVED_POC versus FORMAL_REQUIREMENT versus PLANNED_DESIGN

Historical invocation (generic, not authorized to run):
`ansible-playbook -e @scopes/canary.yml --forks 2 ./playbooks/scan_ol9.yml`.
Uses existing config-based external inventory. Actual -i/--limit/tags usage,
separate single-host execution and per-host overrides remain UNKNOWN. The
historical path was playbooks/scan_ol9.yml; it is not a mandatory final path.
The following maps observed PoC behavior to requirements and open decisions.

| OBSERVED_POC | FORMAL_REQUIREMENT | PLANNED_DESIGN / responsible issue |
|---|---|---|
| pqc_run_id required; regex `[A-Za-z0-9][A-Za-z0-9_-]{0,63}`; pqc_scan_hosts and pqc_scan_groups lists, default [] | safe run identity; explicit scope | #6/#9 define final CLI/IDs and migration mapping |
| pqc_max_hosts default 10, historical assertion 1..5000; group expansion/union/dedup, rejects unknown, all, ungrouped, runtime group, unsafe/local names and local connections | bounded approved exact targets; honor --limit, no bypass or unauthorized local target | #6 validate scope and plan-only; no automatic 5000-host approval |
| localhost preflight/add_host, pqc_runtime_targets scan serial=2, localhost summary; historical command forks=2 | preserve existing external inventory and vars; safe execution and terminal coverage | #6/#8 define actual entry path, limit semantics, orchestration and failures; add_host behavior not proven safe |
| become=true and gather_facts before OracleLinux major 9, >=9.7 and <10.0 assertion | explicit privilege authorization; OS family/version and capabilities, lab evidence | #7/#14 guard before unsafe action; range not formal support |
| pqc_collect_packages/openssl/sshd/ssh_host_keys/system_certs/crypto_policy true; pqc_collect_nginx_certs/tls_services false at play level | default passive profile; active validation only on authorization; preserve useful collector semantics | #7 decide flags/mapping, enforce constraints against extra-vars precedence; actual historical run flags unknown |
| Wrapper unconditionally writes per-host JSON, HTML, CBOM; pqc_report_root/pqc_report_dir; first play computes from report_root, later plays recompute from playbook_dir | private output, run isolation, no overwrite, consistent relative paths | #8/#9 clarify path/default/flags, atomic run reservation (stat-then-mkdir not atomic); new Portal need not use old layout |
| mode 0600 files / 0700 dirs; pqc_report_complete after three writes; fleet JSON and conditional aggregate HTML | complete expected host terminal states, private logs, interruption handling | #8/#9 distinguish unreachable/failed/not-attempted; no debug of actual destinations/paths; completion marker is not evidence coverage |

No PoC logic is normative over #1 or future Owner-approved specs. #6/#7
must explicitly preserve, map or migrate useful legacy flags and interfaces;
choose a single implementation path and avoid duplicate entry logic. No
runtime migration or new scan entry is implemented here. Keep actual DB
provider and its --list/--host interface, external config, host vars, SSH and
ProxyJump intact. No AAP/AWX/Backstage/Vault requirement for the planned scan.

Synthetic scope reference (not the original scope, not executed):

```yaml
pqc_run_id: "example-run-001"
pqc_scan_hosts: []
pqc_scan_groups:
  - fixture_a
pqc_max_hosts: 10
```

## Synthetic inventory contract (FORMAL_REQUIREMENT for the fixture)

`tests/fixtures/inventory_synthetic.py` is an executable stdlib fixture only.
It returns exactly one UTF-8 JSON object for --list or --host NAME. Unknown
host returns {}; invalid args/mode exit 2 with a fixed diagnostic. No DB,
network, file lookup, cache or clock. Mode PQC_SYNTHETIC_INVENTORY_MODE defaults
to inline (complete _meta.hostvars); lookup omits _meta and requires actual
script-plugin --host lookups; empty returns no hosts. The raw fixtures are
synthetic and not claims about production provider errors or unknown hosts.

pqc_targets has children fixture_a (a,b) and fixture_b (b,c); fixture_outside
has d; all contains all four; ungrouped is empty. The three distinct targets
are host-a/b/c.example.invalid; host-d.example.invalid is outside. All use
TEST-NET addresses, dummy SSH vars including a ProxyJump placeholder and
ansible_connection=local solely for test safety. Group fixture_precedence is
"group"; b overrides "host" and belongs to both child groups. Actual Ansible
merged hostvars, overlap dedup and empty behavior are required integration
oracles, not proven by raw JSON alone. No tasks may execute. #6 owns actual
scope resolution, limit/overlimit/malformed inventory tests and preflight.

## REPO_SOURCE: upstream report contract (static)

At fixed base `95c0d6512c69cadf8b0cd3131d88a043b4885425`, role
`roles/crypto_posture_snapshot/tasks/report.yml` (blob
`3bd674f1a5783954b1a4b4d5ef815dcbcd2cec83`) assembles host, collected_at,
openssl_packages (default {}), openssl_version and openssl_tls1_3_groups
(default empty strings), corresponding rc fields (default -1), crypto_policy
(default {}), ssh_host_keys, system_certificates, tls_services,
nginx_certificates, sshd_crypto_lines and sshd_crypto_lines_commented
(default []), nginx_present (default false). These are intended defaults,
not observed serialized types. Upstream normalize unit fixtures use integer
rc, bits and size; this does not prove actual serialization. Upstream
snapshot fleet envelope generated_at/total_hosts/hosts includes only defined
reports; total_hosts counts reports, not expected hosts. CFF summary and
legacy risk labels are not new Evidence Model verdicts. Do not infer JSON
from HTML. CBOM module declares CycloneDX 1.6; no schema conformance assumed.

## OWNER_LEGACY: attested observed local report shape

Producer: historical local PoC, exact producer commit/version UNKNOWN;
Planner prior private JSON inspection, intake date 2026-11-24. Provided
sanitized structure only; no actual report bytes in the review package.
Observed formats: per-host JSON and HTML, fleet JSON and aggregate HTML,
per-host CBOM. Observed OS OracleLinux 9.8, not OL lab acceptance. The
prior intake reported consistent fleet counts/sets and embedded per-host
objects matching separate reports; archive entry permissions 0600/0700
were metadata, not actual filesystem enforcement. This is not proof of
complete collection or readiness. No real sample counts/identities published.

| Field path | Observed JSON type | Meaning / limit |
|---|---|---|
| host, collected_at, os_distribution, os_version | string | identity/time/platform as producer reported |
| openssl_version, openssl_tls1_3_groups | string | raw producer output, not negotiation proof |
| openssl_version_rc, openssl_tls1_3_groups_rc | string (decimal) | preserve raw type and RC semantics |
| openssl_packages | object keyed by package; arrays of records | arch/name/release/source/version strings, epoch integer; installation evidence only |
| crypto_policy | object | profile/fips_output strings; fips_enabled bool; local_overrides array |
| ssh_host_keys[] | object | algorithm/bits/fingerprint/path/risk strings; bits can be decimal string |
| system_certificates[] | object | expires/issuer/path/public_key_algorithm/public_key_size/risk/signature_algorithm/subject strings; distinguish key and signature |
| nginx_present | boolean | producer observation, not comprehensive coverage |
| nginx_certificates, tls_services, sshd_crypto_lines, sshd_crypto_lines_commented | array | empty in observed sample; element types not established from empty arrays |
| fleet.run_id, fleet.generated_at | string | local run identity/time |
| fleet.selected_hosts, successful_hosts, hosts_without_report | array | selected/successful/missing sets, no failure-cause inference |
| fleet.selected_count, completed_count | string (decimal) | selected/reported counts, not upstream total_hosts |
| fleet.reports | array | embedded per-host reports |

Missing/null/optional/failed/skipped variants beyond the observed shape are
UNKNOWN. Empty arrays, false booleans, defaults or absent reports cannot by
themselves establish PASS, no assets, NOT_SCANNED or a reason for failure.
#10 defines new evidence states; #12 must recognize both fleet envelopes,
validate counts/sets/embedded IDs, reject duplicates, malformed/negative or
out-of-range values as appropriate to each field, and preserve original
value/type/provenance. RC may have different signed semantics than counts and
sizes; no universal arbitrary int coercion. Legacy risk/score is not a new
verdict. #12 owns final fixtures, schema and adapter. These examples do not
establish the full input acceptance domain.

CBOM attested shape: bomFormat/specVersion/serialNumber strings, version
integer, metadata object, components/dependencies/properties arrays;
component bom-ref/name/type plus optional version/cryptoProperties;
dependency ref/dependsOn. Intake checked unique nonempty refs including
metadata.component and known dependency targets. Full CycloneDX 1.6 schema,
semantic links and asset identity are not verified; #26 owns them. No raw
CBOM or original certificate/host data is published.

## Synthetic legacy examples (approved structure references)

These are the two artificial examples from the approved intake; deliberately
synthetic values, including a missing report in the fleet, are not actual
scan evidence. Retained inside this document, not extra fixture paths.

<!-- synthetic-legacy-per-host -->
```json
{
  "host": "host-a.example.invalid",
  "collected_at": "2000-01-01T00:00:00Z",
  "os_distribution": "OracleLinux",
  "os_version": "9.8",
  "openssl_packages": {
    "openssl": [
      {
        "arch": "x86_64",
        "epoch": 0,
        "name": "openssl",
        "release": "synthetic",
        "source": "synthetic",
        "version": "0.0.0"
      }
    ]
  },
  "openssl_version": "SYNTHETIC VERSION STRING",
  "openssl_version_rc": "0",
  "openssl_tls1_3_groups": "X25519",
  "openssl_tls1_3_groups_rc": "0",
  "crypto_policy": {
    "fips_enabled": false,
    "fips_output": "SYNTHETIC OUTPUT",
    "local_overrides": [],
    "profile": "SYNTHETIC"
  },
  "ssh_host_keys": [
    {
      "algorithm": "ssh-rsa",
      "bits": "2048",
      "fingerprint": "SYNTHETIC-NOT-A-REAL-FINGERPRINT",
      "path": "/example.invalid/fixtures/ssh_host_key.pub",
      "risk": "quantum_vulnerable"
    }
  ],
  "system_certificates": [
    {
      "expires": "Jan  1 00:00:00 2001 GMT",
      "issuer": "CN=Example synthetic issuer",
      "path": "/example.invalid/fixtures/certificate.crt",
      "public_key_algorithm": "rsaEncryption",
      "public_key_size": "2048",
      "risk": "quantum_vulnerable",
      "signature_algorithm": "sha256WithRSAEncryption",
      "subject": "CN=host-a.example.invalid"
    }
  ],
  "tls_services": [],
  "nginx_present": false,
  "nginx_certificates": [],
  "sshd_crypto_lines": [],
  "sshd_crypto_lines_commented": []
}
```

<!-- synthetic-legacy-fleet -->
```json
{
  "run_id": "example-run-001",
  "selected_hosts": [
    "host-a.example.invalid",
    "host-b.example.invalid"
  ],
  "successful_hosts": [
    "host-a.example.invalid"
  ],
  "hosts_without_report": [
    "host-b.example.invalid"
  ],
  "selected_count": "2",
  "completed_count": "1",
  "generated_at": "2000-01-01T00:00:00Z",
  "reports": [
    {
      "host": "host-a.example.invalid",
      "collected_at": "2000-01-01T00:00:00Z",
      "os_distribution": "OracleLinux",
      "os_version": "9.8",
      "openssl_packages": {
        "openssl": [
          {
            "arch": "x86_64",
            "epoch": 0,
            "name": "openssl",
            "release": "synthetic",
            "source": "synthetic",
            "version": "0.0.0"
          }
        ]
      },
      "openssl_version": "SYNTHETIC VERSION STRING",
      "openssl_version_rc": "0",
      "openssl_tls1_3_groups": "X25519",
      "openssl_tls1_3_groups_rc": "0",
      "crypto_policy": {
        "fips_enabled": false,
        "fips_output": "SYNTHETIC OUTPUT",
        "local_overrides": [],
        "profile": "SYNTHETIC"
      },
      "ssh_host_keys": [
        {
          "algorithm": "ssh-rsa",
          "bits": "2048",
          "fingerprint": "SYNTHETIC-NOT-A-REAL-FINGERPRINT",
          "path": "/example.invalid/fixtures/ssh_host_key.pub",
          "risk": "quantum_vulnerable"
        }
      ],
      "system_certificates": [
        {
          "expires": "Jan  1 00:00:00 2001 GMT",
          "issuer": "CN=Example synthetic issuer",
          "path": "/example.invalid/fixtures/certificate.crt",
          "public_key_algorithm": "rsaEncryption",
          "public_key_size": "2048",
          "risk": "quantum_vulnerable",
          "signature_algorithm": "sha256WithRSAEncryption",
          "subject": "CN=host-a.example.invalid"
        }
      ],
      "tls_services": [],
      "nginx_present": false,
      "nginx_certificates": [],
      "sshd_crypto_lines": [],
      "sshd_crypto_lines_commented": []
    }
  ]
}
```

## Handoff and acceptance boundaries

#6/#7 consume inventory/PoC contracts and choose formal entry/flag migration;
#8/#9 implement terminal states, safe private publication and path handling;
#10/#12 use legacy producer shapes without converting unknown to PASS;
#14 validates real platform capabilities; #26 validates CBOM; #19-#27 design
the new offline Portal. #5 owns necessary CI. The source sample and the two
synthetic JSON structures do not substitute for independent QA. Controller
resolved loader and effective settings remain partially unknown; real Ansible
fixture parsing and baseline runtime checks are BLOCKED in this environment.
No product runtime source, Controller setting, production inventory or original
report is changed. Review all staged bytes under #2; owner approval of this
copy is not approval of arbitrary original data. Issue #3 remains HOLD.

## Review R1 correction: fixture-specific effective inventory oracle

FORMAL_REQUIREMENT for #3 tests only: a successful raw process rc is not
proof that inventory parsing succeeded. The isolated Ansible subprocess
enables ANSIBLE_INVENTORY_ANY_UNPARSED_IS_FAILED=true and
ANSIBLE_INVENTORY_UNPARSED_FAILED=true, with explicit candidate config,
script-only plugin, temporary HOME/XDG, UTF-8, bounded timeout and no inherited
caller parse flags or package Proxy variables. Reject targeted parse-failure
diagnostics even at rc0; unrelated warnings need not be fatal. Retain actual
stderr evidence in the isolated test logs; do not suppress warnings or invent
native output. Neither the production configuration nor provider is changed.

For effective --list, require explicit _meta and hostvars objects, expected
hostvars keys, group objects and typed hosts/children (and vars when present).
Validate fixture group names, references, reachability/cycles and the union
of hosts across every group, not only pqc_targets. Zero-host mode requires
empty hostvars and a zero global host union, including ungrouped or unlinked
entries. It rejects {} and unexpected groups/hosts, including implicit
localhost as a target. The ansible-core v2.18.3 JSON formatter removes empty
keys and entries, and the inventory data initializes all -> ungrouped;
therefore known empty group entries may be absent even when referenced.
Bounded synthetic empty variants permit all with ungrouped and optional
pqc_targets, with only consistent empty group entries/references. Native
version-specific output remains to be verified; no claim that every synthetic
variant was emitted by Ansible. Nonempty effective results must preserve the
original topology, overlap and host/group precedence checks. Raw unknown
--host={} is still valid; this is not a production inventory parser/schema.

Native negative checks use disposable synthetic executable providers in temp
storage only, not extra repository files: invalid JSON and nonzero --list
must give an actual nonzero ansible-inventory rc and parse-failure diagnostics.
Actual fatal configuration, legal empty and all required native tests remain
BLOCKED in the correction environment; see baseline.md. QA must verify
inline _meta and lookup per-host fallback invocation trace using a synthetic
wrapper only. No change to either fixture or the historical PoC/Legacy samples.

## FORMAL_REQUIREMENT: offline-first deployment and runtime (R2)

Source: [Owner deployment-source supplement R2](https://github.com/hwakeyeTW/PQC/issues/1#issuecomment-7125166664).
This is a formal product boundary, not OBSERVED_POC behavior. Keep development,
CI, authorized deployment and production runtime separate. Prefer existing
verified compatible dependencies. Necessary Controller Python/RPM dependencies
may be obtained only in a separately approved deployment phase using the
existing approved Proxy to PyPI/official Oracle Linux RPM sources or approved
local artifacts; do not change existing settings or trust. Collections must
support local offline installation with fixed necessary transitive closure,
verified artifact provenance/checksums and actual loader/compatibility checks,
without Galaxy resolution or downloads. Missing packages stop the relevant
approved deployment; no external fallback or automatic installation/update.
Source permission does not prove availability or successful installation.
Full wheels/RPM bundles or new mirror services are not mandatory.

Runtime scan, plan-only, collector, evidence evaluation, legacy import,
report generation, CBOM, Schema validation (including transitive references),
Portal and historical analysis must not depend on public DNS/HTTP(S), public
Internet, external assets, package Proxy, automatic downloads/installs/updates,
external fallback or telemetry. The existence of Proxy configuration does not
authorize runtime use. Preserve existing authorized internal Inventory, DB,
SSH/ProxyJump and explicitly authorized service endpoints; do not overwrite
operational configuration or block legitimate internal traffic. Necessary
Controller capability/loader missing -> preflight BLOCKED; optional managed
host tool missing -> explicit Coverage/Evidence state, never install RPMs
on managed hosts. Baseline/Extended/Active authorization and budgets remain.

PLANNED_DESIGN (not implemented in #3): #6 verifies actual local capabilities
and loader during preflight; #7 enforces profiles/network boundary; #8 retains
terminal states; #19/#26/#27 use local Portal resources/Schema and offline
browser validation; #28 performs separate deployment and zero-public-egress
runtime acceptance. #5 owns development CI and offline regression integration;
OFFLINE-DELIVERY remains proposed/pending approval (no new installer, bundle,
manifest, issue or dependency changes here). #41/#45 retain the same release
boundary. Test permitted deployment sources and local Collection installation
with full dependency closure in an authorized isolated environment; verify
runtime with blocked direct/Proxy public egress and no product-originated
public requests while permitted internal connections still work. Neither the
source capability nor actual offline runtime has been tested in this correction.
