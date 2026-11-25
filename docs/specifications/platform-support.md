# Platform collector and normalization (Issue #14 S2)

Contract: [approved R1](https://github.com/hwakeyeTW/PQC/issues/14#issuecomment-7133535002),
Evidence 1.1.0 section 9. S2 is an internal component, not a supported
scanner invocation, authorization mechanism, release acceptance or
PQC readiness result. The existing plan-only entry point remains unchanged.
Only the future trusted #8 caller, after the #7 guard and exact effective
Inventory/connection context validation, can invoke this on authorized
managed hosts. This work adds no role main/defaults, public playbook,
user-controlled path/command, live flag or managed dispatch. It never
requires become, configuration changes, package installation or a service
connection. Do not use an arbitrary ad hoc playbook as a supported entry.

## 1. Native role and bounded handoff

The canonical role is `security.compliance_pqc_readiness.pqc_platform_crypto`,
`tasks_from: platform`; the standalone mirror has identical bytes/mode.
The role registers with `no_log: true`, explicitly disables become on
acquisition tasks, and projects only a transient, non-cacheable
`pqc_platform_snapshot`. It does not publish a report or raw results.
The trusted caller must retain only this projection, not the registered
Ansible results or full hostvars; keep transport/logs private. The five
minimal selected setup facts are distribution, os_family, distribution_version,
distribution_major_version and architecture. Use native `!all,!min` plus
`distribution,os_family,architecture` and the five explicit filters;
no fallback to full setup. Ansible's internal implementation of these
subsets can obtain additional intermediate platform metadata (e.g. its
architecture/platform fact collector); the filter limits the returned
facts, not every internal read by Ansible. No additional custom acquisition
of unrelated fields is performed. Failure or insufficient data is not
replaced by controller facts.

The eight stat calls cover exactly seven tool IDs:

| Tool ID | Fixed system candidates (in slot order) |
|---|---|
| rpm | /usr/bin/rpm |
| openssl | /usr/bin/openssl |
| ssh | /usr/bin/ssh |
| sshd | /usr/sbin/sshd |
| ssh-keygen | /usr/bin/ssh-keygen |
| update-crypto-policies | /usr/bin/update-crypto-policies, /usr/sbin/update-crypto-policies |
| timeout | /usr/bin/timeout |

`stat` disables follow, checksum, MIME and attributes. Only `state`,
`exists`, `isreg`, `islnk`, `executable` (bool/null) are projected in
fixed candidate order. No path, mode, checksum or raw diagnostic is
passed to the adapter. Known executable regular file means true; known
missing/nonregular/nonexecutable means false only when every candidate
is resolved negative. Unknown symlinks, incomplete fields and failures
are unknown; a known positive plus an unresolved candidate is partial.
Permission and other errors remain distinct. These observations concern
the selected paths and current caller, not arbitrary PATH, service
availability or algorithm support. The installed system paths and
executables are trusted infrastructure, not an untrusted executable sandbox.

Only an identifiable Oracle Linux 9 candidate (known minor, consistent
major, no contradictory family) with positively observed rpm and timeout
is eligible for at most one query for each of `oraclelinux-release` and
`oraclelinux-release-el9`. A missing family alone is not a contradictory
family. No query for unknown platform, non-OL or non-9, or unavailable
required tool. No full RPM inventory. The fixed command argv invokes
`/usr/bin/timeout --signal=TERM --kill-after=2s 27s /usr/bin/python3 -I -B -c`
with a literal stdlib helper and one fixed package name. The helper uses
`/usr/bin/rpm -q --queryformat` with exactly NAME, VERSION, RELEASE and ARCH,
no shell, closed stdin, child-only LC_ALL=C. It streams both stdout and
stderr with a combined 16 KiB limit, at most 32 rows, a 23-second internal
monotonic deadline including read and wait, and bounded kill/wait for the
trusted direct RPM child. The fixed GNU timeout provides an outer group
deadline (27s + 2s kill-after, within 30s). If direct cleanup is unconfirmed,
the helper stays inside the outer timeout rather than reporting success.
No output truncation is treated as complete. Missing interpreter, unsupported
timeout or command failure does not trigger fallback. The helper emits only
constant status/reason and bounded typed rows, not raw stdout/stderr. Native
Ansible transport overhead and cleanup of disconnected, detached or
uninterruptible processes are not proven by this local command bound;
#8 must prove the final connection, command lifetime and load boundary
before opening managed execution. No claim of a general process sandbox.

Return codes alone do not prove absence: rc=1 plus the exact sole C-locale
`package <fixed-name> is not installed` diagnostic (including newline in
one stream and empty other stream) is required. Other nonzero or unexpected
stderr gives ERROR, or PERMISSION_DENIED for the known denial diagnostic.
Missing executable gives UNKNOWN, deadline/output-cap give ERROR with
TIMEOUT/OUTPUT_LIMIT reason. Empty rc0 is UNKNOWN. Only complete ASCII
four-column newline-terminated rows with the exact requested name and
bounded scalar formats are accepted. Malformed/duplicate rows within the
bounds produce PARTIAL if valid distinct rows remain, otherwise ERROR.
No rows survive output/row-cap or timeout. Distinct valid versions/releases
are retained. Version uses bounded RPM scalar (letters/digits and `_.+~^-`),
release uses the existing Evidence VERSION scalar, architecture lowercase
ASCII slug; unsupported formats remain gaps, not invented values.

## 2. Pure controller API

Import `from tools import platform` from the repository controller context;
this is not an executable or stdlib platform replacement.

`normalize_platform(facts, *, source_kind)` returns `(data, gap_reasons)`.
Accept only the five named bounded scalar keys (or their `ansible_` aliases,
optionally in `ansible_facts`), and optional trusted top-level `os_release_id`.
No other keys, arbitrary nested data or full facts/hostvars. Native and
synthetic source kinds only. Explicit case-insensitive exact aliases map
OracleLinux / Oracle Linux / oracle-linux or trusted ID `ol` to
`oracle-linux`. RHEL, Rocky, AlmaLinux, Debian and other explicitly
recognized distributions are distinct; unknown aliases are unknown, not
substring-matched. Family/architecture normalize to bounded ASCII slugs.
Conflicting or malformed values yield constant gaps and null for the
unresolved field(s); version/major contradictions null the full version
and tuple. Canonical decimal components are safe integers with no leading
zeros, suffix or skipped component. Missing version may retain a known
major; missing minor is not guessed. Preserve independently known fields.
Conflicting family aliases on an otherwise OL identity suppress the
unverified classification (distribution becomes null because S1 has no
separate conflict field); an explicit incompatible family remains visible
and yields UNKNOWN. A known OL major 9 with known minor and no family
contradiction is UNVERIFIED, including 9.10, never SUPPORTED. Reliable
non-OL/non-9 is OUT_OF_SCOPE, not a PQC FAIL. Missing facts and gaps are
independent of platform classification and actual release support.

`normalize_tools(observations)` requires all seven tool keys and their
exact slot counts. `normalize_rpm(name, result)` accepts only the two
fixed package names and the helper's closed typed result (`state`,
`reason`, `rows`); no raw output or arbitrary command input. It rechecks
row count, size, exact name, scalar bounds and unique tuple, rejects forged
projections, and converts confirmed absence to one present=false
observation. An observed absence is not missing data. A wrapper result
must not be forged from user input. The role and adapter are components
of the trusted caller, not a new authorization token.

Example synthetic snapshot (all remaining tool keys supplied analogously,
including two update-crypto-policies slots):

```python
snapshot = {
    "facts_state": "OK",
    "facts": {"distribution": "OracleLinux", "os_family": "RedHat",
              "distribution_version": "9.10", "distribution_major_version": "9",
              "architecture": "x86_64"},
    "tools": {tool: [{"state": "OK", "exists": True, "isreg": True,
                      "islnk": False, "executable": True} for _ in range(slots)]
              for tool, slots in platform.TOOL_SLOTS.items()},
    "rpms": {"oraclelinux-release": {"state": "COLLECTED", "reason": "OK",
              "rows": [["oraclelinux-release", "9.10", "0.1", "x86_64"]]}}
}
```

`facts_state` is OK or UNKNOWN/ERROR/PERMISSION_DENIED/UNREACHABLE;
non-OK requires an empty facts mapping. Missing RPM entries mean not
attempted, never absent. Actual input timestamps and source kind come
from the trusted caller, not from the example or controller clock.

`build_platform_evidence(document, host_id, *, source, observed_at, snapshot)`
requires an already valid Evidence 1.1.0 document with the existing host,
run and appropriate acquisition state. `source` is the closed Evidence
source for `pqc-platform` version `1.0.0`, with opaque origin_ref and
truthful source_kind/hash; `observed_at` is the caller's actual observation
UTC timestamp. It does not invent host IDs, timestamps, claims or terminal
states. It returns `schema_version`, `platform_status`, `gap_reasons`,
`collections`, `evidence`, without mutation or external I/O. It validates
the proposed integrated document with the unchanged S1 public validator;
caller may append the returned rows and use canonical_bytes. Duplicate
existing scope IDs, source mismatch, invalid time/host, or a non-eligible
RPM result fail closed. No auto-upgrade from Evidence 1.0.0. The caller
owns final run/host state, truthful provenance and any later publication.

Ten scopes per host: platform-info, release-rpm-oraclelinux-release,
release-rpm-oraclelinux-release-el9 and tool-<tool_id>. Use ID-V1 helpers
and fixed observation/summary keys; package observation key is `r-` plus
SHA256 of canonical compact JSON [name,version,release,architecture].
Every observation has null asset/algorithm. Successful and partial scopes
have a summary with identical scope_key and count of their actual
observations (not summary count/registry size). Unknown platform metadata
alone or unknown tool availability does not create a successful summary.
Not-attempted RPM uses NOT_SCANNED/NOT_ATTEMPTED, no observation/timestamp.
Known observations plus gaps are PARTIAL; raw errors are not returned.
No readiness or dispatch inference; release RPMs are not crypto libraries.

## 3. Engineering and release boundary

Focused B01-B03 tests in `tests/unit/test_platform.py` exercise numeric
versions, aliases/conflicts/missing facts, fixed stat projection, bounded
RPM helper parser and reader on disposable synthetic processes, strict
adapter results, IDs/summary/coverage and unchanged Evidence validation.
The temporary harness loads both short and FQCN role names, syntax-checks,
executes the minimal facts/stat tasks locally and validates only the
projected result with synthetic host/source context. No mock producer
switch is shipped. On non-OL localhost both RPM calls must skip.
Exact changed mirror bytes and 100644 mode are tested. These are R4
engineering checks, not formal release QA. Actual controller
core 2.18.3/Python 3.12.15, OL9.7/9.8/9.9, RPM package names/versions,
fixed path usability, native OL query/timeout behavior, #8 transport
termination, Inventory/permissions/load, and integrated offline/report
behavior remain NOT_TESTED for #28 and the applicable later work packages.

## 4. I1b Platform acquisition P1: fixed bounded module stages

Contract: [approved P1 scope](https://github.com/hwakeyeTW/PQC/issues/57#issuecomment-7158400543).
The new internal module `pqc_platform_acquire` (standalone) and
`security.compliance_pqc_readiness.pqc_platform_acquire` (collection) have
identical bytes and mode. This is an additive acquisition implementation;
the original role and pure normalization contracts above remain unchanged.
P1 does not register a scheduler adapter, dispatch a scan, or enable live
transport. A trusted future executor must bind a receipt to the actual
host, task, stage and observation time; use `no_log: true`, no become,
and the existing authorization and transport guards. A receipt or direct
module invocation is not a grant of authority.

| `stage` (only module parameter) | Fixed acquisition |
|---|---|
| `metadata` | Five native distribution/architecture facts and all eight stat candidates in section 1 |
| `release-rpm-oraclelinux-release` | Query exactly `oraclelinux-release` |
| `release-rpm-oraclelinux-release-el9` | Query exactly `oraclelinux-release-el9` |

The Ansible module uses the actual trusted AnsiballZ ZIP loader and fixed
module names, not a caller-supplied script or path. The private ZIP and its
parent must be owned by the executing user; reject links and unsafe access.
The child imports the same bundled module with the actual target Python
interpreter in isolated, no-site, no-bytecode mode. Both the native fact
implementation and `pqc_bounded_execution` must come from that same ZIP.
The target need not have Ansible installed. No fallback to host site-packages,
arbitrary module selection, extra tools, shell or supplied argv is allowed.
The installed interpreter, distribution fact code, system paths and RPM
executable are trusted infrastructure, not an adversarial-code sandbox.

Metadata uses the bundled native DistributionFactCollector and distro
library in file-only mode (optional external command fallbacks disabled).
The Linux architecture expression uses `os.uname().machine`, without the
unrelated DNS, machine-id or hostname projection of the full platform fact
collector. Only the five bounded scalar fields are returned; unavailable or
unsupported facts remain null/UNKNOWN/ERROR/PERMISSION_DENIED, not guesses.
Fixed-path `lstat` and effective-user execute access replace the eight stat
calls, with no symlink target following for the final path component, content
read, checksum, MIME or attributes. A changed stat identity produces UNKNOWN.
The local Debian engineering oracle compares all five fields and eight
projected rows against the native minimal setup/stat tasks. Actual OL and
other Ansible versions still require qualification.

Each invocation uses the existing `run_bounded` helper with an independent
30-second process-group budget including TERM/KILL and reap. The metadata
child shares that single budget across all fact and stat operations. Each RPM
stage launches only the fixed `/usr/bin/rpm -q --queryformat` (NAME, VERSION,
RELEASE, ARCH) and one package under LC_ALL=C, with closed stdin. The nested
RPM process remains in the bounded child's group, never starts a new session,
and has a 27-second capture deadline and a bounded direct-child kill/wait.
Its combined stdout/stderr limit is 16 KiB and row cap is 32; the outer
helper independently caps the combined child output at 16 KiB. Overflow,
timeout and cleanup failure never produce truncated successful observations.
The exact absence, malformed/partial and other RPM result semantics in
section 1 are preserved. No raw RPM output or diagnostic is returned.

The result is `changed: false` and `receipt`, or a fixed module failure.
`receipt` has exactly `format` (integer 1), `stage`, `reason_code` (existing
bounded-helper enum), `rc` (outer actual process status or null),
`cleanup_confirmed` (boolean), `payload`, and `rpm_rc` (actual inner RPM
status or null). Metadata has null `rpm_rc`. Only `COMMAND_OK` with confirmed
cleanup and outer rc 0 may carry a payload: `{facts_state, facts, tools}` for
metadata or `{state, reason, rows}` for a release query. RPM absence still
requires the exact sole not-installed diagnostic and inner rc 1; outer rc 0
alone proves neither presence nor absence. A failed outer command has null
payload and null inner rc. An unknown stage, foreign/invalid typed shape,
contradiction or overflow fails closed. The serialized typed receipt is
bounded to 16 KiB, without raw paths, stderr, credentials or host identity.
`validate_receipt(receipt, stage)` checks this local contract; the trusted
controller must also enforce one receipt per actual bound task and reject
missing, duplicate, late or out-of-order receipts. No unconfirmed cleanup
can be accepted as usable observations.

P2 (not implemented here) must collect metadata first, use the existing
normalizer and eligibility gate in sections 1-2, then dispatch each eligible
release stage separately. It must stop further dispatch if cleanup or
transport is uncertain and preserve NOT_ATTEMPTED for unattempted scopes.
Do not call the release stages for non-OL, non-9, unknown/contradictory
platforms or without positively observed rpm and timeout. No host or
cross-stage scheduling contract is qualified by this P1 module alone.

Focused tests exercise actual standalone/FQCN packaging, native metadata
and stat equivalence, both RPM stages with fixed private surrogate
executables, the unchanged ten-scope normalizer, typed negative receipts,
inner and outer output caps, bounded timeout and same-group descendant
reaping, and a lost result-consumer surrogate. The private fixture copies
may narrow a deadline or substitute a fixed test executable; the production
module exposes no such parameters. These are SYNTHETIC development evidence,
not actual managed OL RPM queries, SSH transport or real transport-loss proof.
Formal qualification and the existing #8/#17 restrictions remain in force.
