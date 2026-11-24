# OpenSSL runtime and providers (PQC-M2-02)

Contract: Issue #15, approved proposal 7138470854 and dispatch 7138563071.
This is an internal component only. The public launcher, legacy roles, profile
resolver, Evidence schemas and assessment rules are unchanged. Live operation
remains unavailable until the separately approved execution/dispatch work.

## O01: bounded acquisition

Use `pqc_platform_crypto` (or its collection FQCN),
`tasks_from: openssl_runtime`, only from a trusted caller. It supplies
`pqc_openssl_request` with exactly `flags` (Boolean `pqc_collect_packages`
and `pqc_collect_openssl`) and `platform_status` from the same host's #14
platform proof (`UNVERIFIED` = identified OL9, not supported/QA-certified;
`UNKNOWN` or `OUT_OF_SCOPE` otherwise). Inventory, report data and untrusted
variables must not be used to manufacture this proof or invoke this component.
The future guarded dispatcher is responsible for binding it to the host and
approved profile. This role is not itself that authorization boundary.

| Slot | Fixed query | Scope of evidence |
| --- | --- | --- |
| rpm-openssl | rpm -q openssl (four fixed fields) | Package only |
| rpm-openssl-libs | rpm -q openssl-libs (four fixed fields) | Package only |
| version | openssl version | CLI and linked library metadata |
| providers | openssl list -providers | Observed provider metadata and explicit status |
| kem | openssl list -kem-algorithms | CLI KEM list |
| signature | openssl list -signature-algorithms | CLI signature list |
| tls-groups | openssl list -tls-groups -tls1_3 | CLI TLS 1.3 key-exchange group list |

Disabled families run zero queries. Unresolved/ineligible platforms run none.
Fixed absolute executable paths; regular/executable checks, no alternative
binary or provider loading. The system Python path may resolve its normal
system symlink. No shell, stdin closed, C locale, child environment reduced to
PATH and LC_ALL, trusted system OpenSSL configuration (no injected CONF,
MODULES, property query, HOME or provider override). No active handshake,
private-key access, installation, remediation or escalation. All tasks are
no_log and explicit become:false; output facts are noncacheable.

Each slot runs once at most, with a 23 s monotonic capture deadline, 1 s direct
child reap bound and 27 s GNU timeout plus 2 s kill grace around the helper.
Combined stdout/stderr limit 16 KiB; overflow, incomplete terminal line and
row-limit failures discard the result. The direct child is killed/reaped on
failure; unconfirmed cleanup cannot yield positive evidence. The outer
process group is a second bound, not proof of remote transport termination
or distributed cancellation (#8). RPM permits at most 32 four-field rows;
other lists at most 256, at most 32 aliases per row. The only exact package
absence is rc 1 with the C-locale named absence line on one stream and the
other empty. Other errors are not absence. Unknown flags, empty or ambiguous
output, permission failures and timeouts never create negative capability.

## O02: typed projection and normalization

The role returns `pqc_openssl_snapshot` with flags, platform_status and seven
fixed slots. Each slot has exactly state, reason, rc (integer or null), rows.
Rows are lists: RPM [name, version, release, architecture]; version [CLI,
library-or-null]; provider [identifier, version-or-null, active/inactive/null];
algorithm [provider-or-null, bounded aliases]. Only explicit RPM absence uses
null RPM fields. No raw stdout/stderr, executable paths, hostvars or secrets
in this projection. Outer failure has unknown child rc. Exact current and
legacy recognized version lines are metadata; the FIPS label is not proof
of compliance. Provider blocks need exact identifiers; malformed boundaries,
missing fields and unknown grammar are gaps. Recognized provider-attributed
algorithm rows accept exact names and brace alias lists; known headings are
allowed, ambiguous legacy output remains unknown. TLS groups accept the
fixed query's colon list or explicit group heading, without inferred provider
attribution. Unsupported names/format are not silently converted to a complete
list. A complete empty list has no supported proof in this version.

`tools.openssl_runtime.normalize_openssl(document, host_id, snapshot, source,
observed_at, rules)` returns a new Evidence 1.1.0 document and separate closed
acquisition diagnostics. The caller provides the existing host/run identity,
trusted source/time and fixed rules. Producer is `pqc-openssl-runtime`,
version `1.0.0`. Strict shape/types/state/reason/rc/row bounds and duplicates
are checked before append. The original input is not mutated. Diagnostics
contain collection ID, fixed slot, state, reason, rc and, for recognized
observations, typed provider/aliases/status. They are not Evidence extensions
or public output; eventual report/storage handling belongs to #9.

The existing #11 classifier is applied with KEM_CAPABILITY, SIGNATURE or
TLS_KEX separately. Exact known aliases deduplicate per provider/context;
conflicting aliases and OID-only rows cannot promote a known algorithm.
Unclassified recognizable names remain UNKNOWN in the taxonomy. The hashed
capability/observation identity includes slot, exact provider (or null for
unattributed TLS groups), and classified ID or normalized alias set. Provider
metadata has its own stable scope keyed by exact observed provider identifier.
Explicit active status is a positive observation in that CLI context only;
inactive/unknown or omitted providers do not prove absence or non-support.
An RPM record only establishes that named package's L1 status; metadata does
not imply runtime support. A positive classified runtime record is at most L2
for that exact context, not service readiness, FIPS compliance, negotiation,
configuration or observed usage. No L3/L4/L5 evidence or synthetic claims.

## O03: coverage and compatibility

Each slot and observed provider metadata scope has an independent collection
with ID-V1 and back-references. COLLECTED has real typed observations (or a
count of explicitly observed provider records); PARTIAL has real retained
observations and a fixed gap reason. UNKNOWN/ERROR/PERMISSION_DENIED are not
negative evidence. NOT_SCANNED uses the established DISABLED_BY_USER reason;
NOT_APPLICABLE has an explicit applicability summary. Metadata has null
asset/algorithm; the adapter creates no assets or host/run/claim/finding IDs
other than its own collection and evidence IDs. No 1.0.0 implicit upgrade.
The existing validator validates both input and appended document. Focused
integration exercises canonical_bytes, parse_evidence_bytes and the actual
#11 evaluator; the adapter does not create assessments itself.

## Engineering checks and limits

Focused tests exercise bounded real synthetic children and parser/adapter
fixtures, native short-name and FQCN local tasks_from, flag-gated execution,
canonical mirror equality, and the unchanged validator/rules. Read-only local
OpenSSL smoke is engineering evidence only. Actual OL9.7/9.8/9.9 RPM/provider
behavior, production Controller Python/Ansible, load, offline deployment,
remote cancellation and product/report integration remain #28 release QA.
