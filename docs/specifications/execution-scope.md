# Execution scope and plan-only preflight (SCOPE-R1)

Issue #6 / PQC-M0-05, approved specification R1 and Owner dispatch
7131072762 / 7131941041, with Issue #7 S3 integration (7133748151 /
7134089219). V2.0 controller-side scope and profile planning contract, not
a live scanner, authorization token, or Oracle Linux support assertion.
See [scan profiles](scan-profiles.md) for the profile decision contract. No existing Inventory, configuration, Collection, standalone
mirror or deployment setting is modified.

## Entry point and migration

Run in the trusted controller environment (existing Python/Ansible/PyYAML).
Select an explicitly approved existing executable dynamic Inventory script.
The required `-i` selects exactly one script, not an inline host list,
directory, multiple sources or shell expression. Relative paths resolve to
an existing regular executable file with a shebang. Spaces are supported
by argv, not shell interpolation. Keep existing Ansible configuration,
DB-backed `--list`/`--host` provider, host/group vars, SSH, ProxyJump and
approved internal authentication unchanged. The caller must trust installed
Ansible executables, configuration/variable plugins and the chosen provider;
this launcher is not a sandbox for hostile controller programs. It does not
discover which scripts are approved for an organization. No public network
access or installation is needed.

```sh
python3 tools/pqc_scan.py -i /approved/inventory-script \
  --scope-file /private/scope.yml --plan-only --forks 2
python3 tools/pqc_scan.py -i /approved/inventory-script \
  -e @/private/scope.yml --plan-only --forks 2
python3 tools/pqc_scan.py -i /approved/inventory-script \
  --host host-a.example.invalid --group fixture_a --plan-only
```

`-e` is only the single `@scope-file` compatibility alias, never forwarded
as Ansible extra-vars. Use a scope file OR CLI selectors. Repeated exact
`--host` and `--group` select their union. Single-use options cannot repeat.
`--forks` defaults to 2 and accepts 1 or 2 (planned limits, not actual remote
execution). `--plan-only` must be explicit; live execution is unavailable.
`--help` is informational, not a plan. Unknown/abbreviated options,
`--limit`/`-l` (including equals forms), arbitrary `-e`/`--extra-vars`, tags,
start-at-task, check, step, connection, become, SSH overrides and other
passthrough options are rejected before Inventory execution. No `add_host`
or alternate target route exists.

`playbooks/scan_ol9.yml` retains the historical path but only imports
`preflight.yml`, a localhost-only static fail task with facts and become
disabled. Direct `ansible-playbook` is not a supported scan invocation.
Even if localhost is excluded or the task is skipped, there are no managed
plays, roles, collectors or dispatch tasks. Arbitrary direct Ansible CLI
options are outside the supported entry point. The historical PoC command
is not unchanged CLI compatibility; migrate to the launcher. Do not run
historical anonymized or original scan/pipeline playbooks for #6 testing.

## Scope file

One UTF-8 YAML/JSON mapping (maximum 256 KiB, depth 16, 8192 nodes). No
duplicate keys, explicit tags, anchors, aliases, merges or template
expressions. Decimal integer and true/false scalar semantics are explicit;
YAML 1.1 yes/no/on/off are not implicit booleans. Unknown or reserved fields
are errors. Synthetic example:

```yaml
pqc_scan_hosts: [host-a.example.invalid]
pqc_scan_groups: [fixture_a]
pqc_max_hosts: 10
pqc_run_id: example_run_1
pqc_scan_profile: baseline
pqc_collect_packages: true
pqc_collect_openssl: "false"
pqc_active_opt_in: false
pqc_active_endpoints: []
```

- `pqc_scan_hosts`, `pqc_scan_groups`: string arrays, default empty; at least
  one selector, only literal case-preserving names.
- `pqc_max_hosts`: integer 1..10, default 10; bool is not an integer.
- `pqc_run_id`: optional ASCII `[A-Za-z0-9][A-Za-z0-9_-]{0,63}`; no storage
  is reserved or created in #6.
- Eight optional legacy booleans: `pqc_collect_packages`,
  `pqc_collect_openssl`, `pqc_collect_sshd`, `pqc_collect_ssh_host_keys`,
  `pqc_collect_system_certs`, `pqc_collect_crypto_policy`,
  `pqc_collect_nginx_certs`, `pqc_collect_tls_services`. Boolean or exact
  case-insensitive true/false strings normalize to bool. Missing is not
  false. Unknown collector keys are rejected.
- `pqc_scan_profile`: optional exact baseline/extended/active; only absence
  selects baseline. No profile name or collector request grants execution.
- `pqc_active_opt_in`: bool or exact case-insensitive true/false string;
  default false. `pqc_active_endpoints`: list, default empty, at most 200
  rows. Passive profiles reject true opt-in or a nonempty list. Active
  requires explicit true opt-in and nonempty valid endpoint intent; the
  launcher still only supports plan-only and never probes. Full validation
  uses the fixed resolver after the target set is known.
- Report paths, `pqc_write_*`, probe controls, internal decision fields and
  all other scope keys are unsupported; never silently broaden permissions.

## Native resolution and safety boundary

Validate CLI and scope before any Inventory tool. Use installed sibling
`ansible-config` and `ansible-inventory` executables from trusted PATH, never
a shell. Preserve environment/config origin (explicit `ANSIBLE_CONFIG`
must exist as a file), except these child-process-only fatal controls:

```
ANSIBLE_INVENTORY_ENABLED=script
ANSIBLE_INVENTORY_ANY_UNPARSED_IS_FAILED=true
ANSIBLE_INVENTORY_UNPARSED_FAILED=true
```

`ansible-config dump --format json` must confirm effective values. Exactly
one `ansible-inventory -i <resolved-script> --list` follows, not `--export`,
a manual provider call or second Inventory load. Native plugin may call
`--host` in lookup mode. Configured sources cannot supplement explicit
`-i`. If script-only/fatal controls conflict with a legitimate environment,
stop for Owner review rather than fallback. Existing approved internal DB
access is permitted; launcher invokes no managed SSH, DNS resolution,
remote facts, service probes or collectors.

Each subprocess has a 30-second deadline including cleanup reserve, 32 MiB
stdout, 1 MiB stderr, closed stdin and separate process group. Linux
child-subreaper reaps adopted same-group descendants; timeout/output limit,
residual process or unconfirmed cleanup fails closed. Trusted tools/providers
must not detach. External containment is necessary for hostile programs,
detached descendants, SIGKILL or host failure. This is a single-invocation,
single-threaded controller, not a general process-isolation framework.
No raw command output is printed or saved by the launcher.

Only rc 0 with acceptable diagnostics and strict effective UTF-8 JSON can
proceed. Duplicate JSON keys, nonfinite numbers, malformed/unknown
structure and identifiable parser/plugin failures are refused. Ordinary
unrelated warnings and the known lookup deprecation are not failures;
ambiguous Inventory-related warnings fail closed. The native parser may
normalize provider output; strict JSON checking applies to the effective
result, not a second raw-provider parse. Provider integrity is a trusted
input prerequisite.

Validate `_meta.hostvars`, `all`, group hosts/children/vars, reachability and
cycles. Hostvars entries must belong to graph members. Native formatter
omits empty group objects while retaining child references, and omits
hostvars entries for hosts with no variables. These represent empty groups
or empty mappings, not invented hosts. Unknown selector is rejected; a
selected empty group alone is `EMPTY_SCOPE`.

Host aliases match ASCII `[A-Za-z0-9][A-Za-z0-9_.-]{0,254}`; group names
may also start with underscore. Case is preserved. No pattern, glob,
range, intersection, negation, unsafe name or untyped fallback. Select
literal existing members, recursively union children, deduplicate and sort.
A host and group of the same name are separate typed selectors. `all`,
`ungrouped` and `pqc_runtime_targets` cannot be selected (including as
selected-group descendants). Reject local/loopback identities, explicit
local connection, loopback/local `ansible_host` or legacy `ansible_ssh_host`,
unspecified addresses and unresolved templated connection values. Do not
resolve DNS to infer host identity; existing IPv6 literals may be supplied
by hostvars using safe aliases. Missing connection is `UNKNOWN`, not an
assumed SSH connection or live authorization. Unknown, unsafe, zero-target
or over-cap scope is refused as a whole.

## Controller contract and stdout

`parse_scope`, `resolve_targets`, `build_plan` are controller helpers.
`build_plan` consumes the same effective Inventory and normalized request;
no exported plan is a live token. Private in-memory result has
`scope_plan_version=1`, `plan_status=READY`, `reason_code=TARGET_PLAN_READY`,
`plan_only=true`, `execution_allowed=false`, `active_dispatch_allowed=false`,
sorted unique `target_ids`, `target_count`,
`limits={max_hosts, forks, serial:2, ssh_timeout_s:15, command_timeout_s:30}`,
optional run_id, separate `run_flags`, per-target `inventory_flags`,
`inventory_flags_source=INVENTORY_EFFECTIVE`, `connection_status`, and
normalized `active_opt_in`. S3 adds `profile_decision_version=1`, `profile`,
`profile_status` and `profile_decisions`; the raw endpoint list is not
retained in the plan. See [scan profiles](scan-profiles.md). Serial and timing values are planned #8 limits,
not executed operations. Inventory flags are projected only from the eight
keys; missing values remain absent. Run-only/reserved decision fields and
unknown collector/write flags in selected effective hostvars fail closed.
No Inventory variable authorizes dispatch. No template evaluation, arbitrary
hostvars or connection values are returned in the plan. Caller must not
retain raw effective Inventory or publish it; use only necessary projection.

CLI emits the original eight fields (version, status, reason, plan-only,
both dispatch booleans, target aliases and count) plus the four S3 profile
fields above. Every host has a closed resolver decision with eight
NOT_SCANNED rows and false dispatch booleans. The separate raw run and
inventory flags, endpoint list, run_id, addresses, credentials, paths,
raw stderr and config are not output. Existing exact-key consumers must
accept the four additive fields. A denial emits no partial plan and only
a constant reason on stderr. Exit codes (help excepted):

| Code | Meaning |
|---|---|
| 0 | READY target plan, profile VALIDATED or Active DEFERRED; never a successful scan |
| 2 | Invalid CLI/scope syntax/fields/limits or run-level profile/endpoint conflict |
| 3 | Tool/config/provider, timeout/output/cleanup, JSON/structure, fixed policy or resolver failure |
| 4 | Unsafe/untrusted source, unknown/empty/over-cap/unsafe scope, foreign endpoint source or effective host conflict |

Keep target aliases private to Owner. Do not upload real stdout, logs,
Inventory, reports or credentials. No report or run directory is generated.
Plan data is not a public evidence schema.

## Downstream handoff and verification

#7 S3 now constructs its request (`profile`, `plan_only`, `run_flags`,
`inventory_flags`, `target_ids`, `active_opt_in`, `active_endpoints`) from
a trusted invocation and applies the existing canonical pure resolver,
first for run-level policy and then once per fixed target. Any denial
rejects the whole plan. It does not launch another Ansible play or reload
the Inventory. #8 must fix the
same native Inventory/Variable context (or proven equivalent snapshot)
with exact identities and effective connection context, revalidate scope/
profile before managed connection and use the expected target manifest
for COMPLETE/PARTIAL/ERROR/UNREACHABLE/NOT_ATTEMPTED, not just successful
reports. A saved plan or second drifted provider is not a safe dispatch
contract. Live remains unavailable until these contracts are implemented
and reviewed. #9 owns private run_id/storage; #10 stable namespace/target_id
to host_id (never substitute address/path for literal identity). No reports,
CBOM, IDs, collectors or actual active service validation here.

R4 focused development checks (trusted isolated synthetic source and
prepared runtime, no production data):

```sh
python3 -m py_compile tools/pqc_scan.py tests/integration/test_scope.py
PQC_SYNTHETIC_INVENTORY_MODE=inline ansible-inventory -i tests/fixtures/inventory_synthetic.py --list
PQC_SYNTHETIC_INVENTORY_MODE=lookup ansible-inventory -i tests/fixtures/inventory_synthetic.py --list
ansible-playbook -i localhost, --syntax-check playbooks/scan_ol9.yml
ansible-playbook -i localhost, --syntax-check playbooks/preflight.yml
python3 -m pytest -q -rs -p no:cacheprovider tests/integration/test_scope.py
```

The suite traces actual native tools and provider invocations, retains
fixture/config bytes and modes, checks literal scope/precedence/flag
projection, input/source/diagnostic/process failures, fixed policy and
per-host decisions, whole-batch profile refusals and tripwire controls for
forbidden execution. Synthetic tests require no actual SSH. Use a
disposable offline environment without production credentials/agent/mounts;
do not impose universal socket denial on the legitimate DB provider.
Actual Controller ansible-core 2.18.3/Python 3.12.15, OL9.7/9.8/9.9, actual
Inventory DB/SSH/ProxyJump/config/permissions, load and integrated offline
release behavior are NOT_TESTED here and belong to #28. Development runtime
is not formal Controller or OL acceptance. Independent review and Owner
merge are separate; no release acceptance is implied.
