# Public repository data handling

PQC is a public repository. This policy reduces accidental disclosure; it is
not a runtime redaction engine or an automatic secret scanner.

## What may be published

- Source, schemas, templates, documentation, and reviewed synthetic fixtures.
- Sample inventory and configuration containing only placeholders. Use names
  such as `host-a.example.invalid`, RFC 5737 addresses (e.g. `192.0.2.10`),
  and randomly generated dummy sentinels, never actual environment values.
- Anonymized material only after Owner approval and review. Anonymization must
  cover contents, filenames, paths, identifiers, evidence, derived output and
  archive contents. Unknown provenance is not approval to publish.

Do not commit or disclose real hostnames, IP addresses, internal domains,
network topology, Production inventory/host or group variables, database or
connection settings, passwords, tokens, private keys, SSH credentials, raw
certificate details, Production reports or sensitive logs. This prohibition
also applies to public issues, PRs, comments, CI logs and artifacts. Do not
upload private data to external services without explicit authorization.

For #3, receive only an Owner-approved, sanitized copy of the local scan entry
point, inventory interface examples and necessary environment metadata. Never
request or upload the original inventory, database settings, credentials or
raw reports to this repository. Review the copy before staging or publishing;
if provenance or sanitization is uncertain, stop and keep it private.

## Storage boundaries

Prefer an Owner-approved private location outside the checkout. If local data
must be inside the checkout, use the following ignored paths:

| Path | Purpose |
| --- | --- |
| `reports/` | All report files, nested runs, JSON/HTML/PDF/CSV/CBOM, Portal assets, catalog, archives and logs; only `reports/.gitignore` may be tracked. |
| `.local/`, `inventory/local/`, `secrets/` | Private data, inventory and host/group variables, credentials and local parameters. |
| `.ansible/`, `logs/`, `tmp/` | Controller temporary files, cache and logs. |
| `.pytest_cache/`, `.venv/`, `__pycache__/`, `*.py[cod]`, `*.retry` | Local test and runtime artifacts. |
| Root `.env`, `.env.*`, `.vault_pass*`, `vault-password*` | Local environment/password files. |
| Root `*.log`, `*.zip`, `*.7z`, `*.tar`, `*.tar.gz`, `*.tgz`, `*.tar.xz`, `*.txz`, `*.tar.bz2`, `*.tbz2` | Manually packaged output and logs. |

Use a private directory for secrets with arbitrary names and archives with
other names or locations. Do not overwrite tracked sample inventory or other
tracked files with private values. `tests/fixtures/`, `docs/`, source, schemas
and templates remain versionable; that does not make their contents public by
default. Never use a fixture directory to bypass the private-data policy.

The follow-up runtime contract is private reports and logs (default file mode
`0600`, directory mode `0700`), isolated run paths and minimal sanitized logging.
Ignore rules do not enforce these permissions or prevent runtime disclosure.
Existing standalone report debug and `0644` outputs are not fixed by #2.

## Before staging and committing

Inspect local changes, then stage only explicitly approved paths. Do not use
`git add -f` or a blanket `git add -A` in the actual project. The synthetic
regression tests may use these commands only in isolated temporary repos.

```sh
git status --short
git check-ignore -v --no-index -- reports/example-run/index.html
git diff --cached --name-status
git diff --cached --check
git diff --cached
```

Review the actual staged diff locally (including names and contents) against
this policy and the PR's exact allowed paths. Reject added/changed private or
report data, the existing archive, unexpected paths, and questionable content.
If a secret or an uncertain file is discovered, stop the commit and resolve
it in the authorized local environment; never print its value in an issue,
PR or CI log. Do not publish sensitive diffs, full inventory/config dumps or
scan logs. For one path, non-verbose `git check-ignore --no-index -- <path>`
exits 0 if ignored and 1 if not ignored; other codes indicate errors. Use `-v`
separately for diagnostics: it can return 0 for a matched negation pattern,
so its exit status alone is not the ignore oracle.

Git ignore cannot prevent force-add, protect previously tracked files, detect
arbitrary filenames or inspect content. Manual staged review and synthetic
regressions are required. Dummy sentinel tests only demonstrate the isolation
and the limitations of the rules; they do not prove the repository has no
secrets. This policy does not add mandatory Git hooks or DLP dependencies.

## SSH trust and compatibility

The repository-local `ansible.cfg` no longer sets `host_key_checking = False`.
Ansible's built-in default applies in a clean environment; legitimate external
configuration and environment precedence are preserved. This does not claim
that every controller's effective setting is True. Keep existing inventory,
host variables, SSH/ProxyJump and other operational settings unchanged. A
legacy first connection can fail if the host key is unknown: provision keys
through the existing trusted `known_hosts`/host-key verification process.
Do not auto-accept unknown keys, disable verification, or change system/user
settings just to make a scan succeed.

Verify config precedence offline with isolated HOME and explicit
`ANSIBLE_CONFIG`. The synthetic False override is a test only; never use it
to connect to hosts. Never publish the full `ansible-config dump`.

## Existing archive and scope

`reports.tar.xz` is already tracked (baseline blob
`74cb57fab91d1a30f7babeec6cbef9352dba4aba`); upstream contains the same blob.
Its provenance beyond repository metadata, contents and anonymization status
are UNKNOWN. Ignore rules do not untrack it. Do not open, extract, redistribute,
modify, delete or rewrite its history as part of #2. Any remediation or history
change requires a separate Owner decision. The archive is not declared safe.

## Verification and handoff

Run `python3 -m pytest -q tests/test_data_handling.py` from the checkout root.
The tests use synthetic data and isolated Git repositories; Ansible config
checks require an existing `ansible-config`. Report missing tools as
BLOCKED/NOT_TESTED, not PASS. The existing playbook syntax-check must use only
synthetic inventory and available dependencies; it is not a scan.

- #5: make the focused tests and their relevant change triggers required CI.
- #6/#7: verify the new entry point does not force-disable host key checking,
  alter existing inventory/SSH/ProxyJump settings or expose connection secrets.
- #8/#9: implement private batch logs, run isolation, minimal logging and
  `0600`/`0700` output permissions, including removal of unsafe report debug.
- #12/#19-#27: apply the policy to legacy import, Portal and exports; #28 owns
  complete integration and real-environment acceptance under separate approval.

No Production scan, active probe, extra privilege, remediation or actual
inventory change is authorized by #2. Implementation tests do not replace
independent review, focused QA or Owner acceptance.
