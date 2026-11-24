# SSH posture: internal acquisition and Evidence 1.1.0 (S01-S03)

Approved contract: Issue #17, proposal #7138840806 and dispatch #7138943919.
This is an **engineering candidate on HOLD**, not a live entry point. In
particular, S02's safe native `sshd -T` invocation and actual positive control
are NOT_IMPLEMENTED/NOT_TESTED. The SSH client binary is also unavailable in
this development environment. An exit-zero focused suite with these mandatory
skips is not S01/S02 acceptance. Do not merge or authorize live dispatch on the
basis of the other tests. #8 owns before-connect/remote termination, #9 owns
private storage, and #28 owns actual target/controller release verification.

## Internal request and acquisition

Use `pqc_platform_crypto`, `tasks_from: ssh_posture`, by short name or
`security.compliance_pqc_readiness.pqc_platform_crypto`. The trusted caller
supplies `pqc_ssh_request` with exactly `flags`, `platform_status` and optional
`context_refs`. Flags must be exact booleans `pqc_collect_sshd` and
`pqc_collect_ssh_host_keys` from the existing per-host profile decision.
`platform_status` is the same host's trusted #14 `UNVERIFIED` (eligible OL9,
not supported-platform proof), `OUT_OF_SCOPE` or `UNKNOWN`. The role does not
re-authenticate an arbitrary inventory's assertion of eligibility; the caller
must own that binding, without inventory/report overrides of internal facts.

`context_refs` defaults to `["global-default"]`; if supplied, it is a unique
list of one or two opaque references (`global-default` or `ctx-` plus 64
lowercase hex digits). These are reserved context identities, not a completed
`-C` authorization contract. No actual username, address, DNS, group, NSS or
agent context is consumed until S02 is safely implemented.

The role is `become: false`, `no_log: true`, non-cacheable. It emits only
`pqc_ssh_snapshot` with `flags`, `platform_status`, `context_refs`, `slots`.
Each fixed slot is `{state, reason, rc, rows, gaps}`. `rc` is null or an exact
integer in [-255,255] (not a bool); file and blocked native slots have null rc.
`gaps` is a sorted unique array of closed constant reason codes. The snapshot
validator rejects unknown fields, invalid rows, cross-slot reason misuse,
disabled/ineligible results with acquired data and forged native positives.

| Slot | Flag | Scope and bounded source |
|---|---|---|
| `client-kex`, `client-cipher`, `client-key`, `client-sig`, `client-mac` | sshd | fixed `/usr/bin/ssh -Q kex/cipher/key/sig/mac`, respectively |
| `config` | sshd | fixed main, allowlisted Include closure, lexical metadata only |
| `keys` | ssh_host_keys | fixed single-level public-key candidates, not private files |
| `native-0`, optional `native-1` | sshd AND ssh_host_keys | opaque context; **no `sshd` execution in this candidate** |

Disabled flags acquire nothing for that family. Reliable out-of-scope platform
is `NOT_APPLICABLE`; unknown eligibility remains `UNKNOWN`. With sshd enabled
but keys disabled, native slots are `UNKNOWN/KEY_FLAG_REQUIRED`, with zero
native helper calls. With both enabled, the native helper only checks the
fixed `/usr/sbin/sshd` executable and returns a tool gap or
`UNKNOWN/NATIVE_SAFETY_UNPROVEN`. It cannot emit a successful native row.

The outer command uses the fixed system `env -i`, `timeout` and Python
(`-I -B`); the system Python's normal installation symlink is trusted, not a
caller-selectable executable. Fixed env/timeout paths must be regular,
non-link, executable. A client command uses fixed argv, no shell, no endpoint,
closed stdin, and an exact minimal environment (C locale, fixed PATH, dummy
nonexistent HOME, no agent or askpass variables). The helper verifies fixed
client executable regular/non-link/executable status and never falls back to
PATH. Per slot: 23 s internal monotonic deadline, direct child kill/reap up to
1 s; outer GNU timeout 27 s plus 2 s kill grace. Combined raw stdout/stderr
cap 16 KiB, 256 client lines; overflow discards the entire result, not a
truncated success. Unknown flag, absent/unexecutable/unsafe executable,
permission failure, malformed or empty output and nonzero rc retain gaps.
There is no automatic retry. This is direct-child/local process evidence;
remote process group lifetime and the trusted system runtime/connection
boundary are not solved here.

## Static configuration-source reader (not effective settings)

Linux descriptor-anchored, bounded traversal starts at `/`. It opens only
`etc/ssh/sshd_config`, allowlisted `sshd_config.d/*.conf` (exact relative or
absolute approved expression), and the named
`/etc/crypto-policies/back-ends/opensshserver.config`. Includes are expanded in
sorted order of eligible names, with recorded source/parent/line/ordinal and
lexical Match context. Arbitrary paths, quoting, other globs, repeated or
cyclic sources, unsupported syntax, empty or inaccessible Includes are gaps;
no shell or glob evaluation of arbitrary input. Unknown non-crypto lines are
not copied. A Match condition's raw user/group/address predicates are never
returned or evaluated. `Match all` is a distinct lexical context, not proof
of daemon semantics. `+`, `-`, `^`, wildcard lists remain declarations. Known
risky dependency directives are represented only by constant hazards, not
commands or paths. A declared fixed `HostKey` candidate maps only to the
corresponding `.pub` source reference; the private path is never opened.

Directory traversal uses fixed components, directory FDs and `O_NOFOLLOW`.
The allowed regular inode is pinned with Linux `O_PATH|O_NOFOLLOW` before any
read, checked for single link and size, then reopened only through the helper's
own `/proc/self/fd/<n>`; identity is checked before and after the read. Parent
and source identities, size, mode, owner, mtime/ctime/link count are rechecked
after the closure. Reject symlink, hardlink, nonregular, missing, permission
and drift cases; all limit/drift failures discard the entire affected slot.
No real private key, arbitrary HostKey, certificate, authorized-key file or
command is read by this reader. A disguised private-format marker encountered
in a fixed allowed input is rejected; no raw bytes are exported. The trusted
OS mount topology, executable integrity and caller remain prerequisites; this
is not isolation against a compromised privileged host or a claim of complete
OpenSSH parser equivalence.

Bounds: at most 32 distinct source attempts, depth <= 4, <= 256 entries per
listed directory, 16 KiB/file, 64 KiB aggregate, 512 projected records, at most
256 declared tokens/record (128 ASCII characters/token), 23 s internal deadline
plus outer 27+2 s; 256 KiB serialized slot projection cap. A successful
source row is actual source acquisition, not proof that all possible config
syntax is understood or that a running daemon has loaded these values.

Config rows share `kind`, `order` (zero-based contiguous traversal ordinal),
`source_ref`, `line` (0 for SOURCE, otherwise one-based), `context_ref`.
All refs are full SHA-256 opaque IDs. Variant fields are exact:

| kind | Additional fields |
|---|---|
| SOURCE | `source_kind` MAIN/DROPIN/POLICY_BACKEND; nullable `parent_ref`, `include_line`; `depth` 0..4 |
| MATCH | `match_kind` ALL/CONDITIONAL; context ID is derived from source ref and line |
| INCLUDE | `outcome` ALLOWLISTED/REJECTED (not a claim of full expansion) |
| DIRECTIVE | fixed recognized `setting`, `operator` EXACT/+/-/^, `values` unique bounded lexical tokens |
| KEY_REFERENCE | `key_source_ref` (fixed candidate .pub reference, not loaded key) |
| HAZARD | `hazard` NATIVE_DEPENDENCY/HOSTKEY_PATH_REJECTED |

The controller verifies source/Include parent/depth/order and context linkage,
no duplicate source/line observations, correct fixed main/backend references,
and mandatory gaps for conditional Match/rejected Include/hazards. Source refs
are `src-` plus SHA-256 of compact ASCII JSON
`["ssh-config-v1", path_components, basename]`; lexical context refs hash
`[source_ref, line]`. The actual names/predicates/raw config are not part of the
projection. Unknown source syntax is not reinterpreted as an effective value.

## Host public-key scope

Only fixed single-level `ssh_host_<safe token>_key.pub` candidates under
`/etc/ssh` are read, with the same descriptor checks and limits (<=256 directory
entries, <=32 candidates, <=16 KiB/file, <=512 KiB aggregate, 23 s internal +
outer deadline). No ssh-keygen invocation is necessary: the bounded stdlib
parser checks a single OpenSSH public-key line, strict canonical base64, SSH
wire string length and matching first wire type. Known structural layouts are
RSA, DSS, Ed25519 and ECDSA NIST P-256/P-384/P-521. Canonical positive mpints,
field lengths and trailing bytes are checked. This is structural parsing, not
mathematical validation of a point, signature or proof of possession. Comments
and raw key bytes are never returned or saved. A candidate with an unknown
wire layout is an explicitly partial type-envelope observation; its size is
null and it does not become a confirmed public_key asset or count. Certificates,
hardware-backed or other unknown layouts are not guessed. A valid known
layout is a syntactic public-key observation, not a claim of loaded host key.

Rows are exactly `source_ref`, `key_type`, `bits` (integer 1..16384 or null),
`fingerprint_sha256` (lowercase 64-hex SHA-256 of actual decoded wire blob),
`grammar` (`KNOWN`/`UNKNOWN_TYPE`). Source ref is `key-` + SHA-256 of
`["ssh-host-public-source-v1", basename]`. Full fingerprint is independent of
file name and comment. Repeated fingerprint on distinct sources maps to one
host-scoped asset, with distinct evidence refs. Conflicting type/size/grammar
for the same fingerprint, duplicated source ref or invalid row rejects input.
A known key candidate may link to observed config `KEY_REFERENCE` evidence
only by exact corresponding opaque source ref in the same host/run. This
means the configuration declared a corresponding path, not cryptographic
matching to a private key or that a running service loaded it. The count is
known public-key source observations; unique assets are separate. Complete
zero is allowed only after a successful bounded candidate enumeration with no
gaps. Unknown layout or bad input never creates a complete zero assertion.

## S02 hold and required follow-up

A real `sshd -T` may read host private keys, Includes, NSS/DNS, agent data and
other dependencies. This candidate intentionally contains no native eval
launch path and rejects any proposed positive native result at normalization.
It cannot produce `EFFECTIVE_CONFIGURATION allowed=true/false` or L3 claims.
To clear HOLD, implement a verified readonly confined native evaluator with
public-only host key input, exact config closure/Include order/backend and
trusted default plus distinct approved `-C` contexts. Prove actual `sshd -T`
positive outputs for Include and different Match results and demonstrate real
private-key, outside-path, agent, network and external-command restrictions.
Do not assume `-T`, non-root or permission alone supplies those restrictions.
Do not use an actual managed host, real private key or mock-only substitute.
The current approved development Runtime lacks ssh/sshd/ssh-keygen, and
restoring the same archive cannot supply them. A later compatible offline tool
material and independently bounded implementation/verification are needed.

## Mandatory paired Evidence and details (format 1.0.0)

`normalize_ssh(document, host_id, snapshot, source, observed_at, rules)` is pure
and returns `(new_document, details)`; existing Evidence 1.1.0, host, caller
source/time and the fixed #11 rules are required. No implicit version upgrade,
new run/host/time, endpoint, service, claim, finding, dispatch or persistence.
Producer `pqc-ssh-posture`, version `1.0.0`. Source kind NATIVE_COLLECTOR or
SYNTHETIC, with trusted origin_ref/input_sha256; no raw origin path. Existing
colliding asset or collection ID rejects instead of silently changing an
existing asset's backrefs. Future multi-collector asset merging requires an
explicit backref-preserving integration contract.

Each slot has a distinct ID-V1 collection scope. Native scope incorporates a
hash of its opaque context identity; slot order alone is not a context.
Actual recognizable client tokens give `RUNTIME_CAPABILITY supported=true`
within that client-query scope only. `client-kex`, `client-cipher`, `client-sig`
use exact #11 SSH_KEX, SSH_CIPHER and SIGNATURE classification. `client-key`
and `client-mac` have UNKNOWN taxonomy here: no certificate-key, signature,
cipher or KEM substitution. Missing lists never give supported=false. Static
config rows use ASSET_METADATA (observed source/setting name, version null,
asset/algorithm null); never an effective allow/deny. Known key assets use
`asset_kind=public_key`, identity `sha256-<wire digest>`, stable only for a
stable host, otherwise run-scoped per ID-V1. ASSET_METADATA name is this
observed identity, version null, algorithm observation conservatively UNKNOWN
with original key type; key presence is not L1 package, L2 server, L3 allowed,
L4 negotiation or L5 usage. No fabricated service asset. Summary counts apply
to the exact scope. PARTIAL includes actual observations and a named gap;
NOT_SCANNED has no evidence, N/A has explicit applicability evidence.

The required private companion is an exact JSON object (no extras):
`detail_format`=`pqc-ssh-posture-details`, `detail_version`=`1.0.0`, `run_id`,
`host_id`, `source`, `observed_at`, `flags`, `platform_status`, `context_refs`,
`records`, `detail_sha256`. `records` (8 or 9) are in fixed slot order. Each
has `run_id`, `host_id`, `collection_id`, `slot`, nullable `context_ref`,
`state`, `reason`, nullable `rc`, `gaps`, `evidence_ids` (<=513), `evidence_ref`,
`observations` (<=512, slot-specific bounds above). An observation has exact
`evidence_id`, nullable `asset_id`, `evidence_ref`, typed `row` from the slot,
and `config_evidence_ids` (only for known public key, <=512; exact config
links). Summary evidence is included in collection-level IDs. The opaque
refs hash the compact JSON tuple of run, host, collection and evidence ID or
collection's ordered ID list, prefixed `ref-`. These refs are correlation
identities, not external file locators. All IDs must match actual Evidence.

`canonical(details)` is ASCII JSON (`ensure_ascii`, sorted object keys,
compact separators, no NaN); array order is preserved. `detail_sha256` is the
SHA-256 of those bytes with only that field removed. The unhashed body is
limited to 2 MiB; enforce the complete wire bound before loading from storage
(and reject duplicate JSON keys). `validate_details(document, details, rules)`
reconstructs the entire typed projection, identities, assets, evidence and
companion using the same rules. It verifies the hash and exact closed details,
all host/run/collection/evidence/asset associations, coverage and linked
config declarations against the validated document, allowing only the set
ordering canonicalization of Evidence. Recomputed hashes alone cannot repair
mismatched or cross-host evidence. Hashing ensures consistency, not source
authentication; the caller/storage trust boundary still applies. Do not treat
this companion as optional diagnostic text.

#9 must retain paired canonical Evidence+details with private 0600 files/0700
directories, manifest/hash and atomic publication. Portal/exports must rebuild
from the saved pair without reconnecting or guessing relations; formal
persistence and integration are outside this package. The existing legacy
roles/defaults/launcher/stubs/API/schema/taxonomy remain unchanged.
