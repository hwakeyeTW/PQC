# Scan profiles: controller-side plan contract V1

Issue #7 / PQC-M0-06 S1-S3, approved S3 plan 7133748151 and dispatch
7134089219. This is a preflight plan, not cryptographic evidence, a live
scan, an authorization token, or a supported production release.

## Supported invocation

Use the sole supported entry in [execution scope](execution-scope.md):

```sh
umask 077
python3 tools/pqc_scan.py -i /approved/inventory-script \
  --scope-file /private/scope.yml --plan-only
```

Use an approved executable Inventory script, trusted controller runtime and
unchanged existing configuration. The scope file is local/private. The
single `-e @/private/scope.yml` alias and literal `--host`/`--group` are
supported; CLI selectors without a scope file select the default profile.
Arbitrary extra-vars, limit, tags, start-at-task, check, connection, become
and other passthrough options are not accepted. No `--plan-only` means
`LIVE_NOT_AVAILABLE` for every profile. The old playbook paths remain
controller-only rejection stubs, not alternate supported entry points.

The launcher imports the fixed Collection `resolve_scan_profile.py` source
relative to its own installation and reads fixed `config/scan_profiles.yml`
(maximum 16 KiB of UTF-8 bytes, regular file). It uses the resolver's
existing strict `load_policy` and pure `resolve_scan_profile` functions.
It does not choose a module or policy using cwd, Inventory or user-supplied
paths, execute a second playbook, or fall back to the standalone mirror.
The two S2 `tasks_from: profile` Role adapters remain available to a trusted
controller-only caller (local, facts/become disabled, explicit separated
policy/request). They are not a managed dispatch or alternate scan entry.
The trusted installed sources and controller executables must not be
arbitrarily modified; this is not a sandbox against a controller admin.

## Profiles and legacy flags

Only absence of `pqc_scan_profile` defaults to `baseline`. Exact lowercase
`baseline`, `extended`, `active` are the only accepted selectors. Empty,
null, other values and unsupported fields are errors. The following are
policy **requests**, not an installed capability or approved collector:

| Legacy `pqc_collect_` suffix | Baseline | Extended | Active intent |
|---|---|---|---|
| packages, openssl, sshd, ssh_host_keys, system_certs, crypto_policy | true | true | true |
| nginx_certs | false | true | true |
| tls_services | false | false | true only with explicit TLS endpoint rows |

Eight flags accept bool or exact case-insensitive strings `true`/`false`.
Absence is distinct from false. One native effective Inventory resolution
fixes sorted unique literal targets and per-host effective flags. The
launcher validates run-level input first with an empty inventory flag map,
then each target's own flag map with the same full target list and run
request. Inventory values are never run-level authorization. The existing
resolver decides precedence: explicit run true beyond the profile ceiling
is a conflict even if Inventory says false; run false narrows Inventory
true; Inventory false narrows an otherwise permitted true. An Inventory
true beyond the ceiling is rejected unless explicitly narrowed by run
false. No cross-host borrowing or legacy Role defaults. Legal all-eight
false is VALIDATED with eight NOT_SCANNED rows. Any denied host means the
whole plan is denied. No partial READY result.

Synthetic extended scope file (not a production Inventory):

```yaml
pqc_scan_groups: [fixture_a]
pqc_scan_profile: extended
pqc_collect_packages: false
pqc_collect_openssl: true
pqc_collect_tls_services: false
```

## Active intent only in V2.0

Active needs explicit run-level `pqc_active_opt_in: true` and a nonempty
`pqc_active_endpoints` list, at most 200 rows. The opt-in also accepts exact
case-insensitive true/false strings. For example, with a selected synthetic
host, the following is only an intent plan:

```yaml
pqc_scan_hosts: [host-a.example.invalid]
pqc_scan_profile: active
pqc_active_opt_in: true
pqc_active_endpoints:
  - source_host: host-a.example.invalid
    protocol: tls
    address: endpoint.example.invalid
    port: 443
    sni: endpoint.example.invalid
```

Every row has exactly source_host, protocol, address, port and sni. The
source must be a member of the fixed target set. Protocol is tls or ssh;
port is an integer 1..65535 (not bool). Address is a single IP literal or
valid DNS name, never a URL, range, CIDR or wildcard. SNI is null or a valid
TLS DNS name; SSH requires null. The resolver rejects duplicate canonical
rows and malformed/foreign sources, with no DNS resolution or connection.
Passive profiles refuse true opt-in or any nonempty endpoint list.

For Active, the entire run-level list determines TLS intent. Explicit TLS
flag values in the run or any selected host must agree with that intent;
conflicts are denied. SSH-only intent needs no TLS row and does not request
TLS. The full run list is deliberately passed to each resolver call; a TLS
request on a host with no row is **not** an endpoint grant. Do not infer
which host may connect from requested flags. All valid Active plans are
DEFERRED with `ACTIVE_NOT_AVAILABLE_V2_0`; non-plan execution is rejected.
The 200-row shape bound is not a service budget or permission. Actual
endpoint authorization, resolution, binding and probes belong to #36-38.

## Closed JSON and denial contract

Success emits exactly twelve top-level fields, retaining the eight original
scope fields and adding four profile fields:

| Field | Meaning |
|---|---|
| scope_plan_version | integer 1 |
| plan_status, reason_code | READY, TARGET_PLAN_READY |
| plan_only | true |
| execution_allowed, active_dispatch_allowed | both false |
| target_ids, target_count | exact sorted fixed target names and count |
| profile_decision_version | integer 1 |
| profile | baseline, extended or active |
| profile_status | VALIDATED for passive profiles, DEFERRED for Active |
| profile_decisions | mapping with keys exactly target_ids |

Each profile decision is the original closed V1 resolver result, with its
version, profile, decision, reason_code, plan_only, requested_flags,
per_collector, active_intent_validated, active_dispatch_allowed and
execution_allowed. Eight requested bools and eight unique NOT_SCANNED
rows carry collector ID, request, allowed_by_profile, planned_scope,
request_source and fixed reason_code. Every dispatch boolean stays false;
`active_intent_validated` is true only for accepted Active intent. This is
not collection success, readiness, or a percentage. A missing adapter
remains NOT_SCANNED. No raw endpoints/SNI, connection values, full hostvars,
raw flag maps, arbitrary exceptions or paths are printed. Do not upload
real target aliases or plans to the public repository. An exact-key
consumer of the old eight-field shape must accept these additive fields.

Denials emit no stdout plan and only a fixed stderr reason. Examples:

| Exit | Examples |
|---|---|
| 2 | INVALID_PROFILE, INVALID_ACTIVE_INTENT, ACTIVE_OPT_IN_REQUIRED, ENDPOINT_INVALID, run-level PROFILE_CONFLICT, LIVE_NOT_AVAILABLE |
| 3 | PROFILE_POLICY_ERROR (missing, malformed, oversized, duplicate or drifted policy); PROFILE_RESOLVER_ERROR (fixed loader, exception or malformed/unsafe output); original Inventory tool errors |
| 4 | TARGET_NOT_AUTHORIZED (foreign endpoint source), per-host PROFILE_CONFLICT, INVENTORY_SCOPE_CONFLICT, original scope/target errors |

## Safety and release handoff

One native effective Inventory load, no managed facts/SSH or service probe,
no collectors, no privilege escalation, no report write, no remediation.
Scope, profile and intent are validated in a single controller invocation.
`VALIDATED`, `DEFERRED`, READY, and exit 0 never authorize live execution.
#8 must fix the native connection/Variable context and guard/budget/dispatch
and preserve failure/NOT_ATTEMPTED states; a saved plan or reloaded drifting
provider cannot grant permission. #9 owns private report publication. Formal
Controller, OL9.7/9.8/9.9, actual Inventory/SSH and offline release acceptance
remain #28. No formal platform support is inferred from synthetic tests.
