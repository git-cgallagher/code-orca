# AGENTS.md: code-orca

Read `~/Code/AGENTS.md` first (workspace rules: branches + PRs, never commit a secret, docs in the same PR).
Public repo; the new-public-repo baseline applies.

## What this is

A YAML-driven Terraform + Ansible orchestrator for use anywhere: a Python package (`src/codeorca`), a
reference project (`examples/reference/`, placeholder values only), and later a container image.
Consumers keep their own `codeorca.yaml`, `workflows/`, `specs/` in their own (usually private) repos:
**no estate-specific data (account IDs, bucket names, secret paths, hostnames) ever lands here.**

## Layout

| Path | What |
|---|---|
| `src/codeorca/models.py` | Pydantic v2 models: the single source of truth for workflow files and the JSON Schema |
| `src/codeorca/config.py` | YAML 1.2 loader (ruamel, pure) |
| `src/codeorca/cli.py` | `codeorca validate`, `codeorca schema export [--check]` |
| `schema/` | exported JSON Schema; CI fails if it differs from the models (`schema export --check`) |
| `src/codeorca/redact/` | redaction pipeline (plan §5.7): `registry.py` (`SecretRegistry`, HMAC placeholders, encodings), `text.py` (`redact_tree`/`redact_text`, key denylist), `terraform.py` (`mask_by_map`, `merge_unknown`, `schema_sensitive_paths`, `mask_by_schema`), `stream.py` (`StreamRedactor`), `gate.py` (`scan_outputs`), `entropy.py` (`entropy_warnings`); residual risk in the package docstring |
| `examples/reference/` | the offline reference project: project config, a provider-free Terraform stack, a localhost playbook, workflows |
| `tests/` | pytest; `tests/negative/` holds workflow files that must fail validation, each for a named reason |
| `tests/redact/` | redaction tests (no terraform/ansible binary needed); `fixtures/` holds a hand-scrubbed plan/state/output JSON, a providers-schema excerpt and two log captures, all with `FIXTURE-SECRET-*` placeholders; regeneration recipe in `conftest.py` |

## Conventions

- **Deny floor in code.** The Terraform `action` enum and the `apply` -> `plan_file` rule live in the
  models. A workflow file can only narrow policy, never widen it. Do not add `destroy`, `import`,
  `state`, `taint` or an auto-approve flag to the enum.
- **Every new model field is validated fail-closed** (`extra='forbid'`), gets a negative test when it
  carries a rule, and the committed schema is regenerated in the same PR (`codeorca schema export schema`).
- **Expressions use `${{ … }}`**, never `{{ … }}`, so Ansible's own templating passes through untouched.
- **Retry policy key is `policy`, not `on`**: PyYAML reads an unquoted `on:` as `True`; the models reject
  YAML 1.1 boolean tokens as keys regardless of loader.
- Actions in workflows are SHA-pinned with a `# vX.Y.Z` comment; workflow-level `permissions: contents: read`;
  `pull_request`, never `pull_request_target`.
- One PR at a time against `main`; merge by hand once every check is green (`gh pr merge --admin`
  satisfies the "external contributor review" ruleset for the owner's own PRs).

## ⚠️ Gotchas (learned during the design research, 2026-11-01)

Terraform (1.14.7):
- `show -json` (plan and state), `output -json`, plan files, the plan's `variables` block and `TF_LOG` all
  hold sensitive values in **plain text**; only sibling flag maps mark them, and the flags do **not**
  follow a secret into a computed attribute (`terraform_data.output` echoed a sensitive input unmarked).
- `init -json` emits non-JSON lines: parse `-json` streams tolerantly.
- Plan JSON `format_version` is 1.2 while the docs say 1.0; the streaming `planned_change` message and
  the plan file use different action vocabularies (`replace` vs `[delete, create]`).
- `plan -detailed-exitcode` exits 2 on success-with-changes; never run it under `set -e` or through a
  pipe that loses the status.
- `state pull` is reading the state file by another name; `.terraform/terraform.tfstate` holds
  `-backend-config` values in plain text; committed tfvars outrank `TF_VAR_*`.
- The apply `-json` stream omitted sensitive output values on 1.14.7 although the docs say otherwise.

Ansible (core 2.21.5):
- No built-in `json` stdout callback (`ANSIBLE_STDOUT_CALLBACK=json` fails to load); an aggregate callback
  cannot intercept the default callback's `[ERROR]: Task failed` line, so a redacting callback must be
  the stdout callback.
- A template string read with `open()` or `DataLoader.get_text_file_contents()` is **untrusted** and comes
  back silently unrendered; wrap it with `ansible.template.trust_as_template()` and run with
  `_ANSIBLE_TEMPLAR_UNTRUSTED_TEMPLATE_BEHAVIOR=error` to catch the omission.
- `Templar.template(..., disable_lookups=True)` is a deprecated no-op; lookups execute during rendering.
- Vault outside the CLI needs `loader.set_vault_secrets()` **and** `VaultSecretsContext.initialize()`.
- `no_log` censors a whole task result; `fail:` messages still leak to stdout; `ANSIBLE_DEBUG=1` bypasses
  `no_log` entirely.
- `VariableManager.get_vars(host=)` outside a play never sees play vars, role defaults or `set_fact`.
- Native templating changes types (`"{{ 8000 + 80 }}"` -> `8080`); `yaml.safe_dump` raises on templated
  results (use `AnsibleDumper` or a JSON round trip); `DataLoader.load(file_name=)` needs an absolute path.
- ansible-runner's `artifacts/<id>/command` records the whole process environment regardless of
  `suppress_env_files`; that is why code-orca drives `ansible-playbook` directly.
- `cloud.terraform.terraform_state` runs `terraform state pull` and dumps every state attribute into
  hostvars; not used.

Container (for the image phase):
- The base image is Debian 13 trixie: Microsoft's legacy `microsoft.asc` key fails under trixie's apt,
  use `packages-microsoft-prod.deb`; .NET deps are `libicu76` + `libssl3t64`.
- PowerShell's `hashes.sha256` is UTF-16LE with BOM and CRLF; `Get-InstalledPSResource` reports nothing
  after a good install (smoke-test with `Invoke-ScriptAnalyzer`); 7.4 and 7.5 end support 2026-11-10.
- `hashicorp/terraform` images ship no LICENSE file; BSL 1.1 wants the license with the binary, so
  install from the GPG-verified release zip.
- OpenTofu images are `COPY --from` sources only (direct use unsupported since 1.10).
- aws-vault's `--ecs-server` cannot serve a container (SDKs refuse non-loopback credential URLs); pass
  `AWS_*` by name on `docker run -e`, never `--env-file` or a value on the argv.

## TODO (phases, from the design plan)

1. Core, read-only: project-file model, DAG runner (sequential), Terraform adapter, policy floor + plan gate,
   redaction pipeline + fixture, plan-spec renderer, `codeorca drift`, `codeorca doctor`.
2. Ansible adapter + redacting stdout callback, inventory/handoff generation, host-spec renderer.
3. Helpers (python/powershell/shell), gate with TTY + resume, apply bound to the plan sha256, backend bootstrap.
4. Container image on `ghcr.io/git-cgallagher/ansible-runtime`.
5. Reference project end to end in CI; consumer guide; v0.1.0.
