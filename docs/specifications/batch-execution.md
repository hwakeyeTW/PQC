# Private native execution context (M0-07 S1)

Issue #8 / proposal 7137701807 / dispatch 7138019670. This slice supplies an
internal controller context and a guarded native SSH command-construction
boundary. It is **not a live scanner, command executor or release**. S1 has
no command-line entry, production adapter, collector registry, report,
remote command runner or task scheduler. The existing launcher and its
12-field plan-only contract, fixed profile resolver, policy and rejecting
playbook stubs are unchanged. The S1 terminal boundary always rejects with
`LIVE_NOT_AVAILABLE`; a test-only instrument may observe the guarded boundary.

## Context and input boundary

The trusted internal caller selects the approved executable Inventory script
and supplies the same normalized request shape produced by `pqc_scan.py`.
The request is revalidated against the original scope parser, including
literal host/group selection, deduplication, limits and collector flags.
Public plan JSON, invented target lists, extra-vars and Active are not an
execution grant. There is no new supported invocation or user-configurable
adapter. All-disabled remains a valid passive decision, not scan success.

The exclusive worker uses the native InventoryManager, DataLoader and
VariableManager. It requires script-only/fatal parse settings to be in
place before importing Ansible, memory fact cache, trusted fixed plugins,
no extra-vars and no SSH agent in the S1 worker. The native script plugin's
command boundary is replaced only during the single inventory load with the
existing bounded command primitive: aggregate 30-second provider deadline,
32 MiB stdout budget and per-command bounded stderr, strict JSON and fixed
error reasons. Native `--host` fallback is allowed only once per host after
`--list`. The same native inventory/variable objects are retained. The
provider must be trusted not to detach; same-group child cleanup is checked.

The native graph is projected only into literal groups/hosts and relevant
flag/reserved fields; native effective variables retain precedence. The
original `resolve_targets` and `profile_plan` establish the fixed scope and
per-host decisions. Full hostvars, credentials, raw diagnostics, SSH options,
addresses and file paths must not be serialized or exposed to callers. The
private context stores only internal objects and returns no public grant.

## Native binding and guard

This candidate uses private Ansible APIs pinned to the development runtime
2.19.11. It constructs fixed native Play/Task objects, resolves a PlayContext,
and calls the native TaskExecutor option resolver on a built-in SSH
connection. No arbitrary play/task/role/collector can come from Inventory
or the request; no facts, delegation, local connection or become is allowed.
The fixed raw-task witness is never executed on a managed host in S1. Native
connection plugin `_build_command` constructs the actual SSH argv, and the
same connection object's `exec_command` enters the guarded `_run` boundary.
Preflight checks the whole target set before any boundary can be reached.
At the boundary, the native graph/flags/decisions, provider identity,
connection argv and effective SSH proof must agree with preflight. Any
missing proof, unexpected host or change is denied; S1's terminal stop does
not call the original native `_run`.

The initial compatible configuration subset is deliberately narrow: native
SSH only, trusted `/usr/bin/ssh` (or the same executable found via PATH),
explicit existing absolute `-F` configuration with a restricted literal
syntax, host-key checking enabled, bounded ConnectTimeout, BatchMode,
no persistent multiplexing, local commands, ProxyCommand, forwarding,
implicit Include/Match, password payload, inline private key, or unsafe
transport overrides. Literal ProxyJump intent and explicit identity paths
are supported candidates. The tool does not edit user/system configuration,
replace legitimate ProxyJump, install SSH or silently relax options. An
unsupported configuration is rejected with a fixed reason. This is not a
claim that every legitimate existing SSH configuration is supported. In
particular the Ansible default multiplexing options and implicit OpenSSH
config loading are not accepted in this candidate. The exact effective
OpenSSH configuration is intended to be checked using bounded native
`ssh -G` for the destination and jump hosts; without that native evidence
preflight must remain closed. The code does not assert a 15-second complete
handshake/chain deadline or 30-second remote command termination; those
are required S2 work. It also cannot guarantee DNS aliases are never local,
configuration files cannot be changed by the trusted controller administrator,
or arbitrary plugins/provider code cannot bypass the trust boundary.

## Development verification and current limitation

Use the approved isolated R1 development runtime, no network, test-only
synthetic inventory, no real SSH or production credentials:

```
python -I -B -m pytest -q -rs -p no:cacheprovider tests/integration/test_batch_context.py
python -m py_compile tools/batch_execution.py tests/integration/test_batch_context.py
```

The focused tests include inline/lookup native context, native group/host
vars, change-on-second-load trap, literal scope and profile precedence,
provider error/duplicate/output/timeout/residual process rejection, forged
request, native option rejection, actual fake SSH subprocess positive
control and a test-only instrumented native `_run` boundary. The latter
substitutes only the unavailable OpenSSH effective-config proof; it is not
a proof of actual OpenSSH option consumption. A separate required test must
exercise real `ssh -G` on the synthetic configuration and then the guarded
native boundary. If OpenSSH is absent, the test confirms fail-closed and
records NOT_TESTED; this is an S1-02 HOLD, not a successful S1 acceptance.
The existing plan-only CLI gets one directly relevant synthetic check; no
historical full-suite rerun is required. Any release/production validation
remains Issue #28. S2 cannot start until the S1 proof gap is closed and the
Planner records a fixed-head independent Review PASS.
