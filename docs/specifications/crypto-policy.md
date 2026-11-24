# Crypto Policy and kernel FIPS acquisition (PQC-M2-03, R1)

Contract: Issue #16, approved proposal 7138473823. This is an internal V2.0
collector and pure Controller adapter, not a new scan entry point. The existing
legacy crypto_policies.yml, launcher, plan-only guard, profile policy, Evidence
schemas and assessment rules are unchanged. #8 must establish the authorized
native host/connection context before any managed dispatch; #9 and subsequent
integration own private persistence. Do not invoke the internal role as a
replacement for the supported launcher or as authorization to connect.

## P01: bounded acquisition

The trusted caller supplies the existing per-host #7 `pqc_profile_decision`
(including `requested_flags.crypto_policy`) and the #14
`pqc_platform_snapshot`. The latter is the separated five platform facts and
fixed tool-slot metadata, not full hostvars. `decision == VALIDATED` and an
exact true request, recognized Oracle Linux 9.x with a known numeric minor,
consistent major and family (RedHat or unknown), and a positively verified
`timeout` slot are required. Disabled, out-of-scope, ambiguous or insufficient
inputs leave explicit NOT_SCANNED reasons; no command or policy read occurs.
The role is `pqc_platform_crypto`, explicit `tasks_from: crypto_policy`
(short name or `security.compliance_pqc_readiness.pqc_platform_crypto`).
It is non-cacheable, no_log and become:false. It assumes the caller already
holds the approved execution context; role variables are not an access-control
mechanism. The V2.0 public execution gate remains closed.

Nine independent slots:

| Scope | Fixed source |
|---|---|
| profile-config | /etc/crypto-policies/config |
| profile-show | /usr/bin/update-crypto-policies --show, else the proven /usr/sbin slot |
| kernel-fips | /proc/sys/crypto/fips_enabled |
| current-policy | /etc/crypto-policies/state/CURRENT.pol |
| backend-openssh | /etc/crypto-policies/back-ends/openssh.config |
| backend-opensshserver | /etc/crypto-policies/back-ends/opensshserver.config |
| backend-openssl | /etc/crypto-policies/back-ends/openssl.config |
| backend-opensslcnf | /etc/crypto-policies/back-ends/opensslcnf.config |
| local-overrides | /etc/crypto-policies/local.d (one level) |

At most one reader and one show invocation. Show requires a positively proven
#14 tool slot (regular, non-symlink, executable); prefer /usr/bin when both
exist. No PATH search or second try after a failure. A missing show slot does
not suppress otherwise permitted file observations. No --set, fips-mode-setup,
service probes, configuration edits, elevation, installation or restart.

The mirrored role embeds a fixed stdlib Python helper. GNU timeout receives
`--signal=TERM --kill-after=2s 27s`; the helper uses /usr/bin/python3 -I -B,
fixed mode, LC_ALL=C and no shell. Its reader opens only / as its root. The
same helper code is exercised on private synthetic directory FDs in tests;
there is no production option to override the root, paths, commands or limits.
The reader uses Linux directory FDs with no-follow traversal, trusted root-owned
non-group/world-writable directories/files, O_PATH + fstat before readable
FD open via /proc/self/fd, and identity checks before/after read. It refuses
hardlinks, nonregular files, directory symlinks and unsafe targets. Only
explicit backend filename links to the corresponding file under the fixed
DEFAULT/FUTURE/LEGACY/FIPS system policy subtrees are recognized, with at most
four symlink hops; all other links remain UNKNOWN (UNSAFE_SOURCE). Kernel FIPS
is the only accepted fixed pseudo-file. No general symlink following, directory
recursion or Include expansion. Custom system policy trees may require a later
explicitly approved extension, not a fallback to arbitrary paths.

Each file <=16 KiB; aggregate bytes read <=64 KiB; local.d <=32 direct entries.
The reader has a 23s internal deadline/alarm and a 29s outer timeout envelope.
It rejects incomplete or oversize reads rather than interpreting truncation.
Show launches only fixed executable + --show, closed stdin and C locale, with
stdout and stderr combined <=16 KiB, 23s internal deadline and bounded 1.5s
same-group cleanup. Linux subreaping, dedicated process group, parent-death
signal and explicit cleanup check reject surviving same-group descendants;
no retry on cleanup uncertainty. The helper checks the selected executable
identity again after capture. These are local execution bounds under a trusted
OS and installed tools, not proof against a hostile root, arbitrary detached
programs, uninterruptible kernel I/O, or all remote transport failure modes.
#8 must establish those managed execution boundaries. Unavailable prerequisites
or unsafe/drifting files fail closed; no alternate acquisition method.

## P02: normalized observation contract

`pqc_crypto_policy_snapshot` has exactly the nine named slots, each with
`state`, `reason`, `rc`, `values`, `overrides`. `values` is a list of [field,
value] pairs, at most 64 per slot. The override slot has an additional bounded
list of {override_id, backend, result}; each nested result uses the same closed
shape without nested overrides. `rc` is null or a bounded integer; raw stdout,
stderr, raw file text, full hostvars and filenames are never in the projection.
The acquisition helper emits only this typed structure; an invalid helper JSON
response fails the no_log task, and the Controller checks the closed shape and
state/value consistency before forming any Evidence. Acquisition diagnostics
must not be interpreted as authorization or published in the public repo.

Supported grammar is deliberately literal:

- Config: one uppercase ASCII profile token, with at most three colon-separated
  subpolicy tokens; blank and comment lines ignored. Show: one exact token and
  optional single LF, rc=0 with empty stderr. Preserve separate declared/shown
  values. If both known and different, both become PARTIAL/PROFILE_CONFLICT,
  with neither selected as the winner.
- Kernel FIPS: only `0`, `0\n`, `1`, `1\n` map to false/true. Unknown or missing
  content is not false. FIPS profile name and text such as "not enabled" do not
  prove the kernel state, module validation or PQC readiness.
- CURRENT.pol: recognize exact cipher/group/sign/key_exchange/protocol keys and
  bounded whitespace-separated literal tokens. OpenSSH: Ciphers, KexAlgorithms,
  HostKeyAlgorithms, PubkeyAcceptedAlgorithms, comma-separated literals.
  OpenSSL: CipherString, Ciphersuites, MinProtocol; only explicit suite spellings
  and known protocol literals, not selector expansion. No shell, Jinja, variable
  substitution, wildcard, Include or add/remove/prepend operators. A field with
  incompatible/unsupported occurrences is not accepted; other independently
  readable literal fields can be retained as PARTIAL. Nonempty unrecognized
  input and empty data are UNKNOWN, not a complete empty algorithm set.
- local.d: count all direct entries when bounded, recognize only names of the
  form <backend>.txt or <backend>-<bounded-safe-suffix>.txt with an approved
  backend. Read only trusted regular entries; do not follow links. Identify a
  recognized entry by `ov-` + SHA-256 of its ASCII basename (not the basename).
  Keep per-entry presence, backend and its bounded parsed literal observations.
  Unknown names/formats, read failures and unsupported entries make coverage
  partial. Zero entries in a successfully enumerated directory is a known
  observation. An absent directory is UNKNOWN/SOURCE_ABSENT, not an empty one.

COLLECTED requires known values; PARTIAL requires known observations and a gap;
UNKNOWN, PERMISSION_DENIED, ERROR and NOT_SCANNED are separate, no invented
negative algorithm assertions. Source absence has its own reason; no implied
NOT_APPLICABLE. Timeout, output/entry limits, unsafe source, ambiguity and
command failure have explicit fixed reason codes. Exact limits can conservatively
produce UNKNOWN/ERROR when EOF or cleanup cannot be established. The parser's
source block in tools/crypto_policy.py is embedded byte-identically in the role
helper; focused tests compare it as well as both mirror files/modes.

## P03: Controller integration and Evidence 1.1.0

Pure API:

```python
from tools.crypto_policy import build_crypto_policy_evidence

rows = build_crypto_policy_evidence(
    document, host_id, source=source, observed_at=observed_at,
    snapshot=pqc_crypto_policy_snapshot, rules=rules,
    platform_snapshot=pqc_platform_snapshot, requested=requested,
)
```

The caller provides an existing valid 1.1.0 document/host, trusted #11 rules,
boolean request, #14 platform projection, actual timestamp and matching source
(kind SYNTHETIC or NATIVE_COLLECTOR, producer pqc-crypto-policy/1.0.0, opaque
origin_ref, optional input_sha256). It must preserve the host/run lifecycle and
choose the correct source kind. The adapter is offline, performs no I/O or
mutation, and returns new `collections`, `evidence`, `metadata`, `diagnostics`
and schema_version, not a new run. It validates the integrated document with
the original Evidence API and refuses duplicate IDs. All nine scope identities
are stable by ID-V1; observation keys hash the fixed setting and normalized
value. Collection summaries count actually produced observations, excluding the
summary itself. NOT_SCANNED produces no evidence; the companion diagnostic
retains the exact reason when an existing generic NOT_SCANNED reason is needed.
Metadata preserves declared_profile, shown_profile, profile_consistency and
kernel_fips_enabled; nullable values stay unknown. Keep diagnostics (including
per-scope rc, override IDs and reasons) in private caller storage, correlated
by collection_id; do not add unapproved fields to the Evidence schema.

Each known value is a host-scoped EFFECTIVE_CONFIGURATION observation with
`allowed=null` and a fixed slot/field setting (or hashed override identity).
Boolean FIPS false is recorded as the scalar "disabled", not missing data.
Only explicit contexts call the approved classifier: current-policy cipher/sign,
SSH Ciphers/KexAlgorithms/PubkeyAcceptedAlgorithms, TLS cipher suite fields.
Unclassified literal names remain UNKNOWN; generic group/key-exchange and SSH
HostKeyAlgorithms are not guessed into a primitive. No extra assets, service
binding, runtime capability, claims, findings or host/run terminal states are
created by this adapter. A generated/declared setting is not proof of runtime
consumption, even when its algorithm is recognized. #11 evaluation can show
coverage and UNKNOWN L3, never a decisive L3 or PQC verdict from these rows.

## R4 verification and remaining limits

Focused synthetic checks use the existing Evidence and Assessment APIs and
approved rule bytes, exact parser/mirror checks, actual isolated reader file
and link cases, real subprocess timeout/output/cleanup cases, and canonical
round trips. Native localhost harnesses load the exact short/FQCN role and
verify no acquisition for disabled/non-OL/unknown/invalid/missing prerequisites;
positive synthetic execution uses the same helper on a private directory FD
and the exact Ansible result projection. Eligible production role execution,
actual system policy files, actual update-crypto-policies, real Controller and
OL9.7/9.8/9.9, remote transport/termination/load and final report integration
remain NOT_TESTED, subject to #8 and #28. No formal support or release acceptance
is inferred from this internal development slice. No historical full suite.
