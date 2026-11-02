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
| `src/codeorca/cli.py` | `codeorca validate`, `schema export [--check]` (workflow + project schemas), `run` (registers the terraform, ansible and spec-render executors), `drift`, `doctor`, `render`, `summary`, `runs gc`, `lint ansible` (`-p` optional there); every project command takes `-p` |
| `src/codeorca/secrets.py` | run-wide redaction wiring: `build_registry` (HMAC key from `CODEORCA_REDACTION_KEY` in this phase, fail-closed; seeds from `AWS_SECRET_ACCESS_KEY`/`AWS_SESSION_TOKEN` + every stack's `secrets:`/`required_env` values), `seed_inputs` (inputs whose name matches the key denylist), `line_hook` for `Runner(stream=)`, `record_filter` for `Runner(redact=)`, `terraform_stream` (a `StreamRedactor` per channel) for `TerraformRunner(stream=)` |
| `src/codeorca/doctor.py` | `codeorca doctor`: tiny dependency-free version matcher (`exact`, `>=,<`, `7.6.*`, `*`), injectable probes, table / `--json` / `--lock` output |
| `src/codeorca/specs/` | spec rendering: `__init__.py` (`render_spec_yaml`, `write_spec` + `.meta.yaml` sidecar + the post-write gate, `build_header`, `NEVER_RENDERED`), `terraform_plan.py` (`seed_registry`, `build_plan_document`: merge_unknown -> placeholder mask -> schema mask -> value scrub + key denylist on value trees only, provenance from `configuration.*.expressions`, `never_render`) |
| `src/codeorca/specs/ansible_vars.py` | the Ansible host spec's **inventory scope**, run as a subprocess (`python -m codeorca.specs.ansible_vars --inventory … --host … [--roles-path …] [--lookup-denylist] [--key-denylist] [--template] [--extra-vars-file] [--play-hosts] [--resolve-lookup]`): one JSON document on stdout (fd 1 is parked, ansible's own output goes to stderr), `declared`/`resolved`/`source` per var templated key by key, `<secret: declared>` from `meta/argument_specs.yml` or `meta/main.yml`'s `argument_specs` (`no_log`, nested too, OR-ed over every role and entry point), `<skipped: key matches denylist>`, `<vault>` (never decrypted), `<skipped: lookup <fqcn> is a secret source>` (lookup denylist by raw name and FQCN, denylist-named arguments, non-literal plugin names), nested denylist-named leaves masked for templating, argument-spec enrichment, `--template` files rendered like the `template` action with the markers in place (a template whose text calls a denied lookup is a marker), extra vars overlaid on top; provenance derived from the `group_vars`/`host_vars` files `DataLoader.find_vars_files` selects; underscore keys (`_play_hosts`, `_lookup_fqcns`, `_skipped_templates`) for the caller only |
| `src/codeorca/specs/ansible_files.py` | vars files without ansible-core: `load_vars_yaml` (`!vault` -> opaque `VaultValue`, `!unsafe` -> string, other tags plain; a real parse error raises `VarsFileError`), `find_vars_files` (= `DataLoader.find_vars_files`), `role_vars_files` (= `Role._load_role_yaml` for `defaults`/`vars`, `main/` dir included) |
| `src/codeorca/specs/ansible_host.py` | pure side of the host spec: `run_vars_subprocess` (stdout in memory, stderr to a callback, no redaction key in the child), `build_host_document` (registry scrub + key denylist over value trees only), `header_for`, `render_play_scope_playbook` (**play scope**: check-mode play with `import_role` + `when: false` per role, `template` tasks with `ignore_errors` + `copy content: to_nice_json` of an allow list), `marker_vars`, `parse_play_scope_events` over the adapter's JSONL (`not run` for an expected task with no result) |
| `src/codeorca/lint/` | `lint_playbooks(paths, key_denylist, lookup_denylist)` -> `{file, line, rule, level, message}`: `no-hostvars-dump`, `debug-secret-name`, `secret-to-plain-param` (module `no_log` from DOCUMENTATION plus a source scan of `argument_spec`; `resolve_module` injectable), `unknown-module` (info), `redundant-task-no-log` (info) |
| `tests/specs/test_ansible_host*.py`, `tests/lint/`, `tests/fixtures/ansible_host/` | host spec and lint tests; the fixture inventory (2 hosts, templated/int/vaulted/lookup/password-named vars, `roles/app_config` with an argument spec and a template; the vault password is the placeholder `vault-pass.txt`); the subprocess and installed-module tests skip without ansible-core (`pip install -e '.[ansible]'`) |
| `src/codeorca/steps/terraform.py` | the `terraform` executor (`make_executor(registry)`): stack resolution, per-stack flock, non-secret backend config, pre-plan registration of sensitive `var_overrides` / `TF_VAR_*`, `init` (`-lockfile=readonly` under `CI`), `validate`/`plan`/`output`/`test`; `apply` and `migrate_backend` fail with the Phase 3 message; `open_session` + `plan_stack` are what `codeorca drift` reuses |
| `src/codeorca/steps/spec_render.py` | the `spec-render` executor (`terraform_plan` and `ansible` sources; `terraform_state` is not implemented) and `render_run` behind `codeorca render` (plan specs from `plan.json`, host specs from `host-vars.json`, nothing re-run) |
| `src/codeorca/steps/host_spec.py` | `spec-render` with `source.ansible`: the play-scope playbook, its roles' `defaults`/`vars` and `vars_files` read first (vault-aware, fail closed), staged inventory (playbook-adjacent `group_vars`/`host_vars` copied) in the 0700 handoff dir, inventory scope via `run_vars_subprocess` (every roles dir, the producer's kept `extra-vars.json` overlaid on top), play scope via `AnsibleRunner` (only the plays that target the host, `--check --diff`, a random vault password, markers incl. `<vault>` and masked nested trees in a 0600 `-e @` file, secret leaves registered before it runs, output held until clear values are registered), `merge_play_scope` (`scope: inventory`/`play`, `source` = the play-scope source that won), `host-vars.json` (0600) + `write_spec` |
| `tests/specs/`, `tests/steps/`, `tests/cli/`, `tests/integration/` | plan document + YAML writer over the fixtures; executors without a terraform binary; doctor with injected probes; the reference project end to end through the CLI (skipped without `terraform`) |
| `src/codeorca/policy.py` | Terraform deny floor as code (`DENY_FLOOR`, `check_argv`), the `Policy` model (narrow-only, `extra='forbid'`) and the plan gate (`plan_gate` -> `GateVerdict`) |
| `src/codeorca/tfjson.py` | pure parsers for `-json` streams (tolerant of non-JSON lines) and `show -json` plan/state documents: summary, sensitive variables/outputs, prior and previous outputs |
| `src/codeorca/adapters/terraform.py` | `TerraformRunner`: one policy-checked `_run` for init/validate/plan/show/output/providers schema/apply/test; `-detailed-exitcode` 2 preserved; apply bound to the plan's sha256; stream callback is where redaction attaches |
| `tests/terraform/` | deny floor, plan gate, tfjson and runner tests (the live ones skip without `terraform` on PATH) |
| `src/codeorca/ansible_plugins/` | plugins handed to `ansible-playbook` by path: `callback/codeorca_jsonl.py` is the **stdout** callback (one JSON object per line for every event, nothing else; schema in its docstring; imports only stdlib + `ansible`, never `codeorca`) |
| `src/codeorca/adapters/ansible.py` | `AnsibleRunner`: `ansible-playbook` as an argv subprocess with the callback forced in (`ANSIBLE_STDOUT_CALLBACK`/`ANSIBLE_CALLBACK_PLUGINS`), `CODEORCA_REDACTION_KEY` dropped, `HARDENED_ENV` forced (`ANSIBLE_DEBUG=False`, `ANSIBLE_LOG_PATH=/dev/null`, `ANSIBLE_VERBOSITY=0`, `ANSIBLE_KEEP_REMOTE_FILES=False`) plus `ANSIBLE_CALLBACKS_ENABLED=codeorca_jsonl` (`project.ansible.env` may not set any of them), JSONL parsed tolerantly, `(line, channel)` stream callback where redaction attaches, status from the stats (rc 4 is also a parser error), tree kill on timeout; `generate_inventory`, `generate_role_playbook`, `write_handoff` |
| `src/codeorca/steps/ansible.py` | the `ansible` executor (`make_executor(registry)`): playbook or generated `import_role` play (`gather_facts` default true; project `roles`/`collections` as playbook-adjacent symlinks in the handoff dir), 0600 inventory + extra-vars handoff files deleted after the run, `<step dir>/inventory.yml` kept redacted for the host-spec renderer, pre-run registration of denylist-named `extra_vars`/inventory values and of the literal secret leaves of the vars files the play reads (`group_vars`/`host_vars`, playbook `vars`/`vars_files`, role `defaults`/`vars`, argument-spec `no_log`), `events.jsonl` through the stream redactor, `--check --diff` under `--dry-run`, `check_unsupported` policy (stricter of project and step) |
| `tests/steps/test_spec_render_ansible.py`, `tests/integration/test_reference_configure_local.py`, `tests/cli/test_lint_cli.py` | host-spec step (pure helpers without ansible; live runs over the host-spec fixture with and without play scope, and the failing-subprocess path), the reference `configure-local` workflow end to end (determinism, `codeorca render` with ansible patched out, `scan_outputs`), `lint ansible` output and exit codes |
| `tests/ansible/`, `tests/fixtures/ansible/` | callback, adapter and step tests over an offline `connection: local` fixture playbook (ok/changed/skipped/failed/no_log/loop/check-unsupported tasks), a `sleep` playbook for timeouts and a role with `meta/argument_specs.yml`; they need `ansible-playbook` on PATH or next to the test interpreter (`pip install -e '.[dev,ansible]'`) and skip otherwise |
| `tests/fixtures/terraform/` | 1.14.7 captures from the reference stack via `regenerate.py` (plan, replace plan, state, outputs, providers schema, init/apply streams) + hand-made `delete-plan.json` and `init-mixed.jsonl`; the placeholder secret is in them on purpose |
| `src/codeorca/project.py` | Pydantic models for the project file `codeorca.yaml` (`load_project`, `project_json_schema`): s3 backend needs bucket/region/account_id, stack `depends_on` DAG, `max_parallel` must be 1 |
| `src/codeorca/expr.py` | `${{ … }}` expressions: sandboxed Jinja2 + StrictUndefined, `render`/`render_value`/`render_tree`, `evaluate_when` (must be a bool), GHA-style `success()`/`always()`/`failure()`/`cancelled()` |
| `src/codeorca/rundir.py` | `RunDir` (`<state_dir>/<run_id>/{run.json, steps/<id>/, outputs/, handoff/ (0700), specs/}`), run id format, `stack_lock` (flock), `list_runs`, `gc` |
| `src/codeorca/runner.py` | `Runner`: sequential graphlib DAG, status propagation, retry/backoff, timeouts, inputs, outputs from the typed `result`, `finally`, run.json; `StepContext`/`StepResult`/`Executor` |
| `src/codeorca/steps/` | executor registry (`register`/`lookup`/`default_executors`), the `shell` executor (argv only, logs via line sink + stream hook), "not implemented in this phase" placeholders for the other types |
| `tests/core/` | project model, expressions, run directory and runner tests (shell-step workflows on `sys.executable`) |
| `src/codeorca/steps/helpers.py` | the shared `python`/`powershell` helper contract (plan 5.8): `run_helper`, project-root-relative `script:` (symlinks resolved, escape/missing refused), child cwd = project root, step `env:` with `{secret: ssm:/...}` resolved through an injected `resolve_secret` and registered before the child starts (denylist-named literals too; values under 8 chars listed by name in `unprotected_env`), `CODEORCA_*` env names reserved, `CODEORCA_DRY_RUN` set only under `--dry-run`, redaction through the registry whatever `ctx.stream` is; runs through `shell.run_argv` (the shell step's child-process machinery) |
| `src/codeorca/steps/python_step.py`, `src/codeorca/steps/powershell_step.py` | `make_executor(registry, resolve_secret=None)` each: `[sys.executable, -I, script, *args]`; `[pwsh, -NoProfile, -NonInteractive, -File, script, *args]` + `-WhatIf` under `--dry-run` (a script without a script-level `[CmdletBinding(SupportsShouldProcess)]`, textual check `declares_should_process`, is refused there); `lint_powershell(paths, settings=None)` (PSScriptAnalyzer via pwsh, `{file, line, rule, level, message}` findings, one `info` finding when pwsh or the module is missing) and `ansible_pslint_settings()` (ansible-test's `pslint/settings.psd1`). Not registered in `steps/__init__.py` (integration does it) |
| `tests/helpers/`, `tests/fixtures/helpers/` | helper-step tests through a real `Runner` + `SecretRegistry` (`helper_support.py`; `conftest.py` re-exports its fixtures): outputs to a dependent step, secret env vs `scan_outputs`, exit codes, `-I` (a planted `json.py`), dry run, path containment, timeout; pwsh tests (exit 3 through `-File`, `-WhatIf`, refusal, secret env) and PSScriptAnalyzer tests skip without `pwsh` / the module (both on the ubuntu-24.04 runner); fail-closed lint edges use a fake `pwsh` |
| `schema/` | exported JSON Schema; CI fails if it differs from the models (`schema export --check`) |
| `src/codeorca/redact/` | redaction pipeline (plan §5.7): `registry.py` (`SecretRegistry`, HMAC placeholders, encodings), `text.py` (`redact_tree`/`redact_text`, key denylist), `terraform.py` (`mask_by_map`, `merge_unknown`, `schema_sensitive_paths`, `mask_by_schema`), `stream.py` (`StreamRedactor`), `gate.py` (`scan_outputs`), `entropy.py` (`entropy_warnings`); residual risk in the package docstring |
| `examples/reference/` | the offline reference project: project config, a provider-free Terraform stack, `ansible/` (role `app_config` with an argument spec incl. a `no_log` token, playbook-adjacent `group_vars/app.yml` with a denied env lookup, `site.yml`), workflows `plan-only` + `configure-local` (run in CI) and `demo-rollout` (validates only) |
| `tests/` | pytest; `tests/negative/` holds workflow files that must fail validation, each for a named reason |
| `tests/redact/` | redaction tests (no terraform/ansible binary needed); `fixtures/` holds a hand-scrubbed plan/state/output JSON, a providers-schema excerpt and two log captures, all with `FIXTURE-SECRET-*` placeholders; regeneration recipe in `conftest.py` |

## Conventions

- **Deny floor in code.** The Terraform `action` enum and the `apply` -> `plan_file` rule live in the
  models. A workflow file can only narrow policy, never widen it. Do not add `destroy`, `import`,
  `state`, `taint` or an auto-approve flag to the enum. The floor covers the `terraform` step type; helpers
  (`shell` today, `python`/`powershell` later) are trusted code, but the `shell` executor still runs
  `policy.check_argv` over an argv whose program is `terraform`/`tofu`, so `run: [terraform, destroy]` is
  refused too. The adapter drops `TF_CLI_ARGS*` from every child environment (the one other way onto the
  command line).
- **Model rules with a negative test each** (`tests/test_models.py`): duplicate step ids across `steps` and
  `finally`; `needs` on a finally step is refused (finally steps always run last; their status functions
  describe the run); `retry` + `on_failure: continue`; references to unknown or non-ancestor steps; unknown
  keys; `retry.backoff` is a typed `Backoff` (`duration`/`max_duration` as Go durations or seconds, `factor`);
  two `spec-render` steps may not share an `output`; `policy.critical_tag` must be `key=value` (the key is
  compared exactly, the value case-folded).
- **Workflow `vars` are rendered once at run start** over `inputs`/`run`/`project` (never `steps`) and
  `run.json` carries the resolved values.
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

Phase 1 integration (2026-11-01):
- **`prior_state.values.outputs` is not the previous value.** On 1.14.7 it holds the root outputs re-evaluated
  against the *current* configuration and variables (a first plan already lists them; a plan that changes an output
  shows the new value there). The value the state recorded is `output_changes[name].before`
  (`tfjson.previous_outputs`); `prior_outputs` is the fallback for outputs with no change entry.
- **`init -json` and `-migrate-state` are mutually exclusive** on 1.14.7; the `migrate_backend` action (Phase 3) must
  run its init without `-json` (tolerant text parsing) or not at all.
- **The redaction key is `CODEORCA_REDACTION_KEY` in Phase 1** (bytes of its UTF-8; key id `env:<sha256[:8]>` in
  spec headers). There is no SSM wrapper yet, so `redaction.hmac_key` is validated but unused; a project with
  `placeholder: hmac` fails closed when the variable is absent. The key's own text is registered, so it never
  appears in a log either.
- **A sensitive variable's value must be registered before Terraform starts**, and the plan JSON that says which
  variables are sensitive only exists after it ran: the executor reads `sensitive = true` out of the stack's `*.tf`
  / `*.tf.json` files (`#`, `//`, `/* */` comments tolerated) and registers `var_overrides` and **every**
  `TF_VAR_<name>` whose variable is declared sensitive or whose name matches the key denylist first;
  `seed_registry` over the plan JSON (sensitive flags plus denylist-named variables) is the authoritative second
  pass. A value shorter than the registry's `min_length` (8) is never registered: the step result lists it under
  `unprotected_overrides` and a warning, by name only.
- **Terraform's `-json` documents are never streamed, and the human `plan` output is held back.** `show -json`,
  `output -json`, `providers schema`, `version` and `validate` stdout is parsed in memory only (their stderr still
  streams). `plan`'s stdout prints state-held values that nothing can flag before `show -json` ran (a computed
  attribute echoing a secret: `~ output = "<the secret>" -> (known after apply)`), so the step buffers it and
  writes it through the registry only after `seed_registry`, and holds `plan`'s stderr (diagnostics) the same
  way. Proven by the applied-state integration test. Every other command's stderr streams live through the
  redactor, which then knows only the pre-registered values (inputs, `TF_VAR_*` of sensitive or denylist-named
  variables, env tokens): a diagnostic from `init`/`validate`/`output` that quotes an undeclared secret is the
  residual.
- **A `: ` inside an unquoted step `name:` breaks the whole workflow file.** GitHub then fails every run in 0 s
  with "workflow file issue", a required check such as `test` never runs, and the PR is blocked with
  'Required status check "test" is expected'. Quote step names that contain a colon; parse `ci.yml` with
  ruamel before pushing (hit on the Phase 1 PR, 2026-11-01).
- **The shell step's terraform check is a courtesy, not a boundary.** `run: [terraform, destroy]` is refused by
  basename; `env terraform …`, `sh -c`, or a renamed binary are not inspected. Helpers are bounded by the
  credentials they get and by review, not by argv inspection.
- **Go's `encoding/json` escapes `<`, `>`, `&` as `\u003c`, `\u003e`, `\u0026`** in every `-json` document and
  stream; Python's `json.dumps` does not. The registry's encodings include both Go-escaped JSON forms, so a
  password with `&` in it is matched by the stream redactor and seen by the gate.
- **A multi-line registered value also registers each of its lines** (`SecretRegistry.add`): the shell step's
  hook is per line, so a PEM body line printed on its own is still matched; the whole value still collapses to
  one placeholder.
- **`timeout:` on a terraform step is a deadline over the whole session** (init included): on expiry the engine
  gets SIGINT (so it releases the state lock), `interrupt_grace` (10 s) to unwind, then SIGKILL, and the step is
  `errored` with `timeout:` (`retry.policy: error` applies). The adapter does NOT start Terraform in its own
  session: a terminal's Ctrl-C reaches it directly. The shell step's timeout bounds the pipe drain too (a
  background child holding stdout open cannot keep the step alive), and an interrupt kills its process group
  before propagating; the runner finalises `run.json` (status `failed`, the in-flight step `cancelled`) on any
  escape, Ctrl-C included.
- **`terraform test` run blocks default to apply**, Terraform also loads `*.tftest.hcl` / `*.tftest.json` from
  the root module directory, and the `-json` stream never says which mode a run block used: the `test` action
  refuses the whole test unless every run block says `command = plan` explicitly (textual scan with a
  whole-file cross-check; `python-hcl2` would be the real parse).
- **Whatever a child process writes is unredacted**: `CODEORCA_OUTPUT_FILE` is rewritten through the hook
  whenever it exists, before it is parsed and whatever the exit (bad JSON and a timeout included), and unlinked
  before every attempt so a failed attempt's file is never a retry's output; shell `argv.json` goes through the
  hook too; `run.json`/`result.json`/`outputs/*.json` go through `Runner(redact=)`; `plan.json`,
  `tf-outputs.json` and a spec are scanned in memory and only then written (0600 for the run-dir files, atomic
  temp + `os.replace` for a spec, so a gate hit leaves the committed spec untouched). No child ever sees
  `CODEORCA_REDACTION_KEY`. `plan.tfplan` holds the
  sensitive variable values in clear inside a zip; on the reference stack the entries are deflated so the value is not
  byte-visible (observed, not guaranteed: deflate may emit stored blocks), which is why the file is 0600, never copied
  out of the run dir, and `scan_outputs` over the whole run dir is part of the integration test. Nothing else under the
  run dir is written by anyone but the orchestrator.
- **Run ids order by second only**: two runs in one second sort by their random suffix, so `latest` picks by the
  recorded `started` time, and a test must pick a run by its content, not by position.
- **`mask_by_map` says `(sensitive)`; specs want placeholders.** The spec renderer masks map-flagged leaves with the
  registry placeholder (`mask_with_placeholders`) so a diff shows a secret changed; the schema mask and the key
  denylist both leave a leaf that already is a placeholder alone (otherwise every real provider's sensitive
  attribute, map- and schema-flagged by construction, lost its change signal); a sensitive leaf that is also
  unknown stays `(known after apply)` under the map mask (never the HMAC of that constant), and a
  schema-sensitive attribute that is also unknown renders `(sensitive)` (the schema mask wins: fail closed).
- **`never_render.resources` entries are matched exactly first, then as globs**: to `fnmatch`, `[0]` and
  `["prod"]` are character classes, so an indexed address could never match itself. Outputs are exact names.
- **`! grep` under `bash -e` never fails a CI step** (errexit ignores an inverted pipeline, and a multi-line
  `run:` exits with its last command's status). Every leak check is its own fatal `if grep -raq`.
- **An editable install cannot catch a subpackage missing from the wheel**: setuptools finds packages under
  `src/` and CI installs the built wheel into a scratch venv (`--no-cache-dir`: pip happily reuses a cached build
  of the same version) and imports every subpackage from it.

Phase 2 integration (2026-11-01):
- **`codeorca_jsonl` emits a `task_start` event with the same `task` name as the task's `runner` result.** The
  play-scope parser matched by name only, so every task first looked like a result without a diff and was
  reported as an error; `parse_play_scope_events` now ignores the non-result event types.
- **The ansible step's kept inventory has no `group_vars`.** It lives in `<run>/steps/<id>/`, so neither the
  inventory-scope subprocess (`group_vars` next to the inventory) nor a spec play generated in the step dir
  (playbook-adjacent `group_vars`) sees `ansible/group_vars/*`; the host-spec step stages the inventory with a
  **copy** of those trees. (Provenance labels were once `path.resolve().relative_to(inventory_dir)`, so a symlink
  became an absolute path in a committed body; they are lexical now, `os.path.relpath`, so a symlinked shared
  `group_vars/all.yml` keeps a relative label too.) When the inventory has `group_vars` of its own, the playbook's
  are not merged in (residual).
- **The extra-vars handoff is deleted with the play**, so the host spec could not see `app_environment` & co.:
  the ansible step keeps a redacted 0600 `extra-vars.json` next to its inventory copy and the host-spec step
  hands it to the vars subprocess, which overlays it on top of `get_vars` (`source: extra_vars (step <id>)`).
  Merging it into the host's inventory entry (the first design) was wrong: `host_vars` files outrank the host
  entry, real `-e` outranks everything, so the spec showed the `host_vars` value labelled `extra_vars`. Markers
  ride in the play scope's `-e` file, not play `vars`: `-e` outranks role `vars/` and `set_fact`, play vars do not.
- **A plain YAML loader turns one `!vault` entry into "no candidates at all"**: ruamel's safe loader raises on the
  unknown tag, and swallowing that error dropped every key of the file (a denylist-named plain value next to one
  vaulted entry rendered in clear). `specs/ansible_files.py` constructs `!vault` as an opaque `VaultValue`; a file
  that still does not parse fails the step. `add_constructor` has the `add_representer` trap (a classmethod on a
  shared dict): subclass `SafeConstructor` and assign `yaml.Constructor`. Ansible also reads `defaults/main/` and
  `vars/main/` directories, extensionless `group_vars/all` and nested `group_vars/<g>/sub/x.yml`: mirror
  `find_vars_files`, never a fixed list of names.
- **The lookup denylist must see template TEXT and every play-scope source**: markers are keyed by var name, so a
  `lookup()` written in a listed `.j2`, a `vars_files` value or a nested `password:` leaf rendered in clear. The
  vars subprocess scans each template's Jinja code (`{{ }}`/`{% %}` only: prose like "DNS lookup (cached)" is not a
  call) and resolves the play scope's lookup names (`aws_ssm` -> `amazon.aws.aws_ssm`, a fake
  `ansible.builtin.<name>` missed redirects); nested denylist-named leaves are masked before templating.
- **The play scope inherits the consumer's vault config** (`ANSIBLE_VAULT_IDENTITY_LIST`/`_PASSWORD_FILE` or
  `ansible.cfg` `vault_identity_list`): a vaulted role default on the allow list rendered decrypted. Vaulted values
  get a `<vault>` marker through `-e`, and the spec play runs with a random vault password so a missed one fails to
  decrypt. (An empty `ANSIBLE_VAULT_IDENTITY_LIST=` fails every run: "can not be a directory".)
- **A literal secret in a playbook's own `vars:` was copied into the kept `play-scope.yml`** (caught by
  `scan_outputs` in the step test): a play var that gets a marker is now left out of the generated play.
- **Role defaults are invisible to the inventory scope**, so a role template fails there (`AnsibleUndefinedVariable`)
  and only the play scope renders it; the merge lets the play-scope template replace the inventory attempt and
  drops its error. A group var that references a role default has the same problem: keep reference group vars
  resolvable from inventory + extra vars.
- **Dropping `ANSIBLE_DEBUG`/`ANSIBLE_LOG_PATH`/`ANSIBLE_VERBOSITY` from the env protects nothing**: each has an
  `ansible.cfg` twin (`[defaults] debug`/`log_path`/`verbosity`) and ansible-playbook runs from the project root, so
  a consumer's config turned them back on (debug dumped `no_log` module args to stderr). Env beats ini, so the
  adapter **forces** safe values. Empty values do not work: `ANSIBLE_LOG_PATH=` resolves to the cwd ("can not be a
  directory"), `ANSIBLE_CALLBACKS_ENABLED=` fails at start ("A non-empty plugin name is required"),
  `ANSIBLE_VAULT_IDENTITY_LIST=` too; hence `/dev/null` and `callbacks_enabled=codeorca_jsonl` (naming the stdout
  callback there is a no-op). Aggregate callbacks (`ansible.builtin.junit`) see raw results and write files past the
  redactor, so none is allowed.
- **Setting `ANSIBLE_ROLES_PATH`/`ANSIBLE_COLLECTIONS_PATH` replaces Ansible's defaults** (`~/.ansible/...`,
  `/usr/share/ansible/...`) and any `ansible.cfg` `roles_path`/`collections_path`: a project whose `collections/`
  held only `requirements.yml` lost every installed collection role. Generated playbooks (role steps, the play
  scope) get `roles`/`collections` **symlinks** next to them in the handoff dir instead: playbook-adjacent dirs are
  always searched and nothing else changes.
- **`from x import f` defeats `monkeypatch.setattr("x.f", …)`**: `steps/host_spec.py` imports
  `run_vars_subprocess` by name, so a test that must prove no subprocess ran patches `codeorca.steps.host_spec`.
- **Specs render multi-line strings as literal blocks** (`|`, a `SafeRepresenter` subclass in `specs/__init__.py`,
  per the `add_representer` gotcha below), so a rendered template diffs line by line.

Phase 3 helpers (2026-11-02):
- **`ConvertTo-Json -InputObject $array -AsArray` nests the array** (`[[...]]`), and a parser that skipped
  non-object entries reported every script as lint-clean. `-InputObject` alone keeps 0- and 1-element arrays arrays;
  `lint_powershell` turns any unexpected shape into a `pslint-error` finding.
- **pwsh writes ANSI escapes in error records even when stderr is a pipe** (7.6): the helper child env defaults
  `NO_COLOR=1` and the lint command sets `$PSStyle.OutputRendering = 'PlainText'`, or `stderr.log` and step errors
  carry escape codes.
- **pwsh always adds its default module dirs to `PSModulePath`**, so "PSScriptAnalyzer is missing" cannot be
  simulated with a real pwsh on a machine that has the module (the runner image does); the test uses a fake `pwsh`.
- **The `SupportsShouldProcess` check is textual**: comments dropped, only the text before the first `{` is searched
  (the script-level attribute area), `= $false`/`= 0` does not count. A `#` or `{` inside a string in the header
  makes it refuse (fails closed). Without the check, `-WhatIf` on a script that does not declare it fails to bind or
  is ignored while the script makes real changes.
- **`python -I`** keeps the script's own directory and the cwd off `sys.path` (a planted `json.py` is not
  imported) and ignores `PYTHON*`/user site; the interpreter's own site-packages still load.
- PowerShell for local tests: the portable `powershell-7.6.x-osx-arm64.tar.gz` (sha256 from the release's UTF-16LE
  `hashes.sha256`) plus `Save-PSResource PSScriptAnalyzer -Path <dir>` and `PSModulePath=<dir>`; never brew/sudo.

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
- **A process-group kill does not stop a running module.** Every ansible-core worker calls `os.setsid()`
  (`WORKER_SESSION_ISOLATION`, on by default), so the worker, its `AnsiballZ_*.py` and whatever that runs are in
  sessions of their own; `killpg(leader)` kills only `ansible-playbook` and the `sleep` keeps running. The adapter
  lists the leader's descendants with `ps -axo pid=,ppid=` *before* killing and SIGKILLs every pid and group
  (found on the Phase 2 timeout test, 2026-11-01). The runtime image (`python:3.13-slim-trixie`) ships **no `ps`**
  (no procps), so on Linux the tree comes from `/proc/*/stat` (fields after the *last* `)`: `comm` may hold
  parentheses); the leader's group is SIGSTOPped first so it cannot fork mid-kill. Still residual: a detached
  `async` task (reparented to init) and, for `connection: local`, the killed module's `AnsiballZ_*.py` in
  `~/.ansible/tmp` (its arguments verbatim; `no_log` does not scrub the payload).
- **`ansible.builtin.command` in check mode says "Command would have run if not in check mode"**, not "does not
  support check mode" (that wording is `module_utils/basic.py` and the action base class); `script` says "Check
  mode is not supported for this task.", `fetch` "check mode not (yet) supported for this module", and `raw` skips
  with **no message at all**: the callback matches the wordings and treats a check-mode skip with no `msg` and no
  `skip_reason` as unsupported (a `when:` skip always has a reason; a `no_log` skip has lost it, residual).
- **ansible-playbook's exit code is not a bitmask, and 4 means two things**: `ExitCode.PARSER_ERROR` and
  `HOST_UNREACHABLE` are both 4 at 2.21.5, a run with failed *and* unreachable hosts exits 4 (unreachable wins),
  and `RUN_FAILED_BREAK_PLAY` (8) never leaves `PlaybookExecutor`. The status is built from the stats event
  (`AnsibleResult.describe`); no stats event means nothing ran, and the step error carries the stderr tail.
  A rescued failure or an `ignore_unreachable` result is a failed/unreachable event for a host the stats do not
  count: `last_failure` only considers hosts the stats count.
- **`no_log` censors `result.result`, not `TaskResult.exception`**: the exception summary carries the verbatim
  `fail`/`assert` message, so the callback nulls `exception`/`warnings`/`deprecations` for a `no_log` result.
  `loop_control.label` hides the item only in the default callback's display: the raw item still sits in the
  result under `ansible_loop_var`, and `set_stats` data has no `no_log` link at all (the stats event carries keys
  only). `str.splitlines()` splits on U+2028/U+2029/U+0085, so the callback prints with `ensure_ascii`.
- **`ruamel.yaml`'s `add_representer` is a classmethod on a shared dict**: calling it on `yaml.representer` to
  quote strings changed every later dump in the process (the spec renderer's output broke two tests). Subclass
  `SafeRepresenter` and assign `yaml.Representer`.
- **Host spec, learned building it (2026-11-01):** `lookup_loader`/`module_loader` resolve an FQCN
  (`ansible.builtin.env`, `ansible.builtin.copy`) only after `ansible.plugins.loader.init_plugin_loader()`; before
  it, only short names resolve. ansible needs a **writable `HOME`** (`~/.ansible/tmp`) even to template, so a
  child env of `{PATH}` alone fails with "Unable to create local directories". Pass the inventory **file**
  (`inventory/hosts.yml`), not its directory: a directory source makes ansible try to parse every subfolder as an
  inventory (`files/` warns). Group `vars` on inventory `Group` objects are empty for file-based `group_vars`,
  so provenance is derived by loading `group_vars`/`host_vars` ourselves in precedence order. A static
  `ansible.builtin.import_role` with `when: false` exposes the role's defaults and vars to the play while every
  task is skipped (the play-scope spec play's way to see role defaults without running the role). Play `vars`
  outrank inventory vars and role defaults but not role `vars/` or `set_fact`, which is why every marker rides in
  the `-e` file (a value only `set_fact` produces is still the redactor's job).
- **Builtin module DOCUMENTATION almost never carries `no_log`** (at 2.21.5 only `expect` does; `user.password`,
  `uri.url_password`, `copy.content` are `no_log` in the code's `argument_spec` only): the lint reads the docs
  *and* scans the module source (`name=dict(... no_log=True)` at the entry's own level), so a lint that trusted
  the docs alone would flag `user: password:` on every real playbook. `copy.content` **is** `no_log`, which is
  what makes the play-scope vars dump safe in results.

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

1. ~~Core, read-only~~ (done 2026-11-01: project-file model, DAG runner (sequential), Terraform adapter, policy
   floor + plan gate, redaction pipeline + fixture, plan-spec renderer, `codeorca drift`, `codeorca doctor`).
   Left for later phases from Phase 1: the SSM-backed redaction key (Phase 3), `terraform_state` specs
   (`state_specs: true`; the renderer exists, the executor does not call `show_state` yet), the `resource_drift`
   shape is assumed identical to `resource_changes` (plan §10, unverified), `--dry-run` is a no-op for the
   read-only Terraform actions, and `required_env` is checked by the terraform step only.
2. ~~Ansible adapter + redacting stdout callback, inventory/handoff generation, host-spec renderer~~ (done 2026-11-01:
   adapter, callback, step, host spec with play scope, `codeorca lint ansible`, reference `configure-local` in CI).
   Left from Phase 2: `vault_password_file` is not a step field yet; Windows/psrp targets are deferred; a project
   that omits `redaction.lookup_denylist` gets an empty one (env/password lookups run in the host spec); play
   scope scans only roles vendored under a roles dir (not installed collection roles) for markers and argument
   specs, cannot read a templated `vars_files` path (a warning) and does not follow `{% include %}` into other
   templates for the lookup scan; `set_fact` values are the redactor's job; playbook-adjacent `group_vars` are not
   merged with an inventory's own.
3. Helpers (python/powershell/shell), gate with TTY + resume, apply bound to the plan sha256, backend bootstrap.
4. Container image on `ghcr.io/git-cgallagher/ansible-runtime`: the pyproject ranges (`pydantic`, `ruamel.yaml`,
   `jinja2`) must be pinned exactly, with hashes, in `requirements/codeorca.txt` for the image; ranges are for pip users only.
5. Reference project end to end in CI; consumer guide; v0.1.0.
