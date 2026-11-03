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
| `src/codeorca/models.py` | Pydantic v2 models: the single source of truth for workflow files and the JSON Schema (a gate refuses `on_failure: continue` and `retry`, and is not allowed in `finally`) |
| `src/codeorca/config.py` | YAML 1.2 loader (ruamel, pure) |
| `src/codeorca/cli.py` | `codeorca validate`, `schema export [--check]` (workflow + project schemas), `run` (registers the terraform, ansible, spec-render, gate, python and powershell executors; one SSM resolver per run, `make_resolver`, handed to the helpers and the terraform step), `resume <run-id\|latest> (--approve [--field k=v] \| --reject)` (terminal check first, before anything is read; secret inputs via `getpass` from `resume.needed_secret_inputs`, never a flag; `--field` refused for a field named like a secret, which is asked with `getpass` instead; `--approve` prints `describe_gate` and asks for a typed `approve`; `run` records `redaction_key_id`), `drift` (stack secrets through the resolver too), `doctor`, `render`, `summary`, `runs gc`, `lint ansible` (`-p` optional there), `lint powershell <paths> [--ansible-settings]`; every project command takes `-p`; the registry gets `key_fetcher=ssm_key_fetcher(project)`. Nothing here passes `isatty=`/`prompt=` (a test greps the source) |
| `src/codeorca/secrets.py` | run-wide redaction wiring: `build_registry(project, env, *, key_fetcher=None)` (HMAC key: `CODEORCA_REDACTION_KEY` when set, SSM not called; else the SecureString `redaction.hmac_key` through `key_fetcher` = `ssm_key_fetcher(project)`, key id `<ref>@<version>`; else fail closed naming the parameter; seeds from `AWS_SECRET_ACCESS_KEY`/`AWS_SESSION_TOKEN` + every stack's `secrets:`/`required_env` values), `seed_inputs` (inputs whose name matches the key denylist), `line_hook` for `Runner(stream=)`, `record_filter` for `Runner(redact=)`, `terraform_stream` (a `StreamRedactor` per channel) for `TerraformRunner(stream=)` |
| `src/codeorca/providers/` | secret providers (plan 5.9): `ssm.py` (`SSMSecrets(registry, *, session_factory, region, timeout_s)`: `get`/`resolve_secret`/`fetch`, a SecureString or any value fetched as a secret registered before it is returned, per-run in-memory cache, `__reduce__` raises; `fetch_parameter`, `aws_config` (connect/read timeout, `retries={'max_attempts': 2}`), `call_with_deadline` (wall-clock limit on a daemon thread, covers a hung credential provider); errors carry the parameter + error code only); `__init__.py` `make_resolver(project, registry)` (`None` without boto3), `make_secrets`, `declared_secret_refs`, `NO_PROVIDER_MESSAGE`; boto3 is the `aws` extra, imported lazily |
| `src/codeorca/bootstrap/s3.py` | S3 state-backend bootstrap (plan 5.11; `python -m codeorca.bootstrap.s3 --project … [--dry-run] [--output-file]`, `main(argv)`, `bootstrap(project, *, dry_run, session_factory, timeout_s)`): refuses a local backend and a caller outside `backend.account_id`, creates the bucket, refuses an Object Lock default retention before any write, converges public access block / versioning / encryption / TLS-only policy statement (Sid `CodeOrcaDenyInsecureTransport`, merged) / noncurrent-expiry lifecycle rule (merged by ID) / `managed-by=code-orca` tag, writes each stack's `backend.hcl` (`backend_settings`, `render_backend_hcl`); output `{bucket, region, account_id, created, changed, dry_run, backend_files, diff, notes}`; never touches objects |
| `examples/reference/helpers/bootstrap_backend.py`, `examples/reference/workflows/bootstrap-backend.yaml` | the reference bootstrap workflow (a `python` step wrapping `codeorca.bootstrap.s3.main`, its `diff` an output, then a terraform `validate` per stack); validates in CI; a test runs it through the real python step, which refuses the reference project's local backend |
| `tests/providers/`, `tests/bootstrap/` | SSM provider, SSM redaction key and bootstrap tests over moto (`mock_aws` + fake credentials + `AWS_CONFIG_FILE` emptied in an autouse conftest, so a developer's aws-vault profile never engages); never real AWS |
| `src/codeorca/doctor.py` | `codeorca doctor`: tiny dependency-free version matcher (`exact`, `>=,<`, `7.6.*`, `*`), injectable probes, table / `--json` / `--lock` output |
| `src/codeorca/specs/` | spec rendering: `__init__.py` (`render_spec_yaml`, `write_spec` + `.meta.yaml` sidecar + the post-write gate, `build_header`, `NEVER_RENDERED`), `terraform_plan.py` (`seed_registry`, `build_plan_document`: merge_unknown -> placeholder mask -> schema mask -> value scrub + key denylist on value trees only, provenance from `configuration.*.expressions`, `never_render`) |
| `src/codeorca/specs/ansible_vars.py` | the Ansible host spec's **inventory scope**, run as a subprocess (`python -m codeorca.specs.ansible_vars --inventory … --host … [--roles-path …] [--lookup-denylist] [--key-denylist] [--template] [--extra-vars-file] [--play-hosts] [--resolve-lookup]`): one JSON document on stdout (fd 1 is parked, ansible's own output goes to stderr), `declared`/`resolved`/`source` per var templated key by key, `<secret: declared>` from `meta/argument_specs.yml` or `meta/main.yml`'s `argument_specs` (`no_log`, nested too, OR-ed over every role and entry point), `<skipped: key matches denylist>`, `<vault>` (never decrypted), `<skipped: lookup <fqcn> is a secret source>` (lookup denylist by raw name and FQCN, denylist-named arguments, non-literal plugin names), nested denylist-named leaves masked for templating, argument-spec enrichment, `--template` files rendered like the `template` action with the markers in place (a template whose text calls a denied lookup is a marker), extra vars overlaid on top; provenance derived from the `group_vars`/`host_vars` files `DataLoader.find_vars_files` selects; underscore keys (`_play_hosts`, `_lookup_fqcns`, `_skipped_templates`) for the caller only |
| `src/codeorca/specs/ansible_files.py` | vars files without ansible-core: `load_vars_yaml` (`!vault` -> opaque `VaultValue`, `!unsafe` -> string, other tags plain; a real parse error raises `VarsFileError`), `find_vars_files` (= `DataLoader.find_vars_files`), `role_vars_files` (= `Role._load_role_yaml` for `defaults`/`vars`, `main/` dir included) |
| `src/codeorca/specs/ansible_host.py` | pure side of the host spec: `run_vars_subprocess` (stdout in memory, stderr to a callback, no redaction key in the child), `build_host_document` (registry scrub + key denylist over value trees only), `header_for`, `render_play_scope_playbook` (**play scope**: check-mode play with `import_role` + `when: false` per role, `template` tasks with `ignore_errors` + `copy content: to_nice_json` of an allow list), `marker_vars`, `parse_play_scope_events` over the adapter's JSONL (`not run` for an expected task with no result) |
| `src/codeorca/lint/` | `lint_playbooks(paths, key_denylist, lookup_denylist)` -> `{file, line, rule, level, message}`: `no-hostvars-dump`, `debug-secret-name`, `secret-to-plain-param` (module `no_log` from DOCUMENTATION plus a source scan of `argument_spec`; `resolve_module` injectable), `unknown-module` (info), `redundant-task-no-log` (info) |
| `tests/specs/test_ansible_host*.py`, `tests/lint/`, `tests/fixtures/ansible_host/` | host spec and lint tests; the fixture inventory (2 hosts, templated/int/vaulted/lookup/password-named vars, `roles/app_config` with an argument spec and a template; the vault password is the placeholder `vault-pass.txt`); the subprocess and installed-module tests skip without ansible-core (`pip install -e '.[ansible]'`) |
| `src/codeorca/steps/terraform.py` | the `terraform` executor (`make_executor(registry, resolve_secret=None)`): stack resolution, the stack's `secrets:` resolved into the child env only and registered first (`resolve_stack_secrets`; before `required_env` is checked; no resolver -> `NO_PROVIDER_MESSAGE`, `SSMError` -> its value-free message), per-stack flock, non-secret backend config (`backend_config` = `bootstrap.s3.backend_settings` for s3), pre-plan registration of sensitive `var_overrides` / `TF_VAR_*`, `init` (`-lockfile=readonly` under `CI`), `validate`/`plan`/`output`/`test`; `apply` (`apply_step`: `resolve_plan_file` = this run's own plan output for the stack, `find_approval` = an approving gate the step transitively needs whose recorded sha256 matches, `check_approval_age` against `gate.max_age`, `show -json` seeds the registry, applyable/complete check, plan gate again with the gate's `allow_delete_of`, adapter apply, redacted `tf_outputs`, plan file deleted; retries only after a lock error before any change, via `apply-attempt.json`; `--dry-run` = skipped) and `migrate_backend` (`migrate_step`/`migrate_stack`: approving gate, `state list` probe of the target from a temp copy of the stack, then `init -migrate-state -force-copy` without `-json`); `open_session` + `plan_stack` are what `codeorca drift` reuses |
| `src/codeorca/steps/gate.py` | the `gate` executor (`make_executor(registry, *, prompt, isatty, out, getuser, secret_prompt)`): `--dry-run` auto-approves (`approver: dry-run`); on a terminal (stdin AND stdout) prints the redacted message, staged specs and plan files + sha256, asks approve/reject and the typed `fields` (a field named like a secret through `terminal_secret_prompt`, echo off; one too short to register is named in `unprotected_fields` + `warning`), records approver/decision/`decided_at`/`waiting_since`/`plans` (the binding: `{path, sha256, planned_at}`); no terminal: `non_interactive: wait` -> `waiting` (exit 3), `fail` -> failed; `timeout` bounds the prompt, no `on_timeout` approves; helpers `collect_plans`, `plan_binding_problems`, `coerce_fields`, `is_terminal`, `terminal_prompt` |
| `src/codeorca/resume.py` | `needed_secret_inputs(workflow, record)` (what the CLI asks for), `waiting_gate`/`describe_gate` (what `resume --approve` shows), `resume(project, run_dir, decision, *, fields, executors, isatty, secret_inputs, workflow, env, stream, redact, registry, …)` (`isatty` resolved at call time): terminal required (no env var or keyword bypass), refuses non-waiting runs, a changed workflow (`workflow_sha256`), project (`project_sha256`) or redaction key (`redaction_key_id`), a remaining step that references a scrubbed step output (`unreplayable_outputs`, from the runner's `scrubbed_outputs`), on approve a gate or plan older than `gate.max_age` or a changed/missing plan file; re-supplied inputs are checked part by part (`matches_recorded`) and never quoted in a refusal; references to `inputs`/`vars` that are not literal names fail closed (every redacted name is needed); redacted inputs a remaining step needs must be re-supplied (`secret_inputs`); settles the gate, replays completed steps, runs the rest and `finally` once; `ResumeRefused` |
| `tests/gate/`, `tests/apply/` | gate executor + model rules + resume (injected prompt/terminal, counting executors); apply on a fake engine (binding, max_age, plan gate, lock-only retry, dry-run), the reference stack plan -> wait -> resume -> apply with real Terraform, `migrate_backend` over two local backends (`path=`) |
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
| `src/codeorca/runner.py` | `Runner`: sequential graphlib DAG, status propagation (a step its executor cancelled, a gate's `on_timeout: cancel`, cancels the run: exit 1, `executor_cancelled`), retry/backoff, timeouts, inputs, outputs from the typed `result`, `finally` (never at a wait: once, at the real end), run.json (`workflow_sha256`, `project_sha256`, `redaction_key_id` from `Runner(key_id=)`, `resumes`/`resumed_at`/`decision`; per step `scrubbed_outputs`: the outputs the persisted scrub changed; a waiting `finally` step is an error); `Runner.restore` (replay a persisted run) + `settle` (decide a waiting step) for resume; `StepContext` (carries the `workflow`)/`StepResult`/`Executor` |
| `src/codeorca/steps/` | executor registry (`register`/`lookup`/`default_executors`), the `shell` executor (argv only, logs via line sink + stream hook), "not implemented in this phase" placeholders for the other types |
| `tests/core/` | project model, expressions, run directory and runner tests (shell-step workflows on `sys.executable`) |
| `src/codeorca/steps/helpers.py` | the shared `python`/`powershell` helper contract (plan 5.8): `run_helper`, project-root-relative `script:` (symlinks resolved, escape/missing refused), child cwd = project root, step `env:` with `{secret: ssm:/...}` resolved through an injected `resolve_secret` and registered before the child starts (denylist-named literals too; values under 8 chars listed by name in `unprotected_env`), `CODEORCA_*` env names reserved, `CODEORCA_DRY_RUN` set only under `--dry-run`, redaction through the registry whatever `ctx.stream` is; runs through `shell.run_argv` (the shell step's child-process machinery) |
| `src/codeorca/steps/python_step.py`, `src/codeorca/steps/powershell_step.py` | `make_executor(registry, resolve_secret=None)` each: `[sys.executable, -I, script, *args]`; `[pwsh, -NoProfile, -NonInteractive, -File, script, *args]` + `-WhatIf` under `--dry-run` (a script without a script-level `[CmdletBinding(SupportsShouldProcess)]`, textual check `declares_should_process`, is refused there); `lint_powershell(paths, settings=None)` (PSScriptAnalyzer via pwsh, `{file, line, rule, level, message}` findings, one `info` finding when pwsh or the module is missing) and `ansible_pslint_settings()` (ansible-test's `pslint/settings.psd1`). Registered by the CLI (`cli._executors`), not in `steps/__init__.py` |
| `tests/helpers/`, `tests/fixtures/helpers/` | helper-step tests through a real `Runner` + `SecretRegistry` (`helper_support.py`; `conftest.py` re-exports its fixtures): outputs to a dependent step, secret env vs `scan_outputs`, exit codes, `-I` (a planted `json.py`), dry run, path containment, timeout; pwsh tests (exit 3 through `-File`, `-WhatIf`, refusal, secret env) and PSScriptAnalyzer tests skip without `pwsh` / the module (both on the ubuntu-24.04 runner); fail-closed lint edges use a fake `pwsh` |
| `schema/` | exported JSON Schema; CI fails if it differs from the models (`schema export --check`) |
| `src/codeorca/redact/` | redaction pipeline (plan §5.7): `registry.py` (`SecretRegistry`, HMAC placeholders, encodings), `text.py` (`redact_tree`/`redact_text`, key denylist), `terraform.py` (`mask_by_map`, `merge_unknown`, `schema_sensitive_paths`, `mask_by_schema`), `stream.py` (`StreamRedactor`), `gate.py` (`scan_outputs`), `entropy.py` (`entropy_warnings`); residual risk in the package docstring |
| `examples/reference/` | the offline reference project: project config, a provider-free Terraform stack, `ansible/` (role `app_config` with an argument spec incl. a `no_log` token, playbook-adjacent `group_vars/app.yml` with a denied env lookup, `site.yml`), `helpers/` (`check_dns.py`, `Test-AppConfig.ps1`, `summary.py`, `bootstrap_backend.py`), workflows `plan-only` + `configure-local` (run in CI), `demo-rollout` (plan -> spec -> gate -> apply -> configure -> host spec -> python + powershell helpers -> finally summary; CI runs it to the gate and asserts exit 3 + a refused resume; the test resumes it with an injected terminal) and `bootstrap-backend` (validates only) |
| `tests/conftest.py` | suite-wide: AWS profile/role/static-key variables removed, `AWS_CONFIG_FILE`/`AWS_SHARED_CREDENTIALS_FILE` empty, IMDS disabled for every test; `no_boto3_session` makes `boto3.Session` raise and counts attempts (the no-network proof) |
| `tests/cli/test_cli_phase3.py`, `tests/steps/test_stack_secrets.py`, `tests/integration/test_reference_demo_rollout.py` | CLI wiring (executors, resolver closures, key fetcher, no AWS call with the env key, `resume` refusal + no bypass option, `lint powershell`); stack secrets (unit + live `drift`/`run` with a fake resolver); `demo-rollout` wait -> refused CLI resume -> approve (all steps, finally once, plan deleted, no placeholder anywhere) and reject |
| `tests/` | pytest; `tests/negative/` holds workflow files that must fail validation, each for a named reason |
| `tests/redact/` | redaction tests (no terraform/ansible binary needed); `fixtures/` holds a hand-scrubbed plan/state/output JSON, a providers-schema excerpt and two log captures, all with `FIXTURE-SECRET-*` placeholders; regeneration recipe in `conftest.py` |
| `container/Dockerfile` | the runtime image (`docker buildx build -f container/Dockerfile --target runtime .`): `FROM ${BASE_IMAGE}` (ansible-runtime 1.3.0 index digest), a `downloader` stage (curl/gnupg/unzip, never shipped) feeding `terraform` (release zip: VALIDSIG primary fingerprint, one-line `sha256sum -c`, binary + `LICENSE.txt` copied out) and `msrepo` (`packages-microsoft-prod.deb`, bind-mounted into the final stage), a `builder` stage (wheel with hash-pinned setuptools, `--no-build-isolation`), and `runtime` (PowerShell `${PWSH_VERSION}-1.deb`, PSScriptAnalyzer AllUsers, code-orca into the base's site-packages under the base's constraints + `pip check`, no venv; root, tini, `WORKDIR /work`, `CMD codeorca --help`, OCI labels incl. `MIT AND BUSL-1.1 AND GPL-3.0-or-later`, `version=${IMAGE_VERSION}` and `revision=${IMAGE_REVISION}`, whose ARGs are declared after the last RUN). Build args `BASE_IMAGE`, `TF_VERSION`, `PWSH_VERSION`, `PSSA_VERSION` (pins: CI never passes them), `IMAGE_VERSION`, `IMAGE_REVISION` (labels: CI passes them); keep each `ARG X=default` line comment-free (the smoke test parses them) |
| `container/requirements/` | `codeorca.in`/`.txt` (what code-orca needs that the base lacks, hash-pinned; empty today), `build.in`/`.txt` (setuptools for the builder stage), `lock.sh` (pip-compile inside the image on the Dockerfile's literal `FROM … AS pinned-base` line, never the `ARG BASE_IMAGE` default, which names the stage; `BASE_IMAGE` env overrides, must be `@sha256:`-pinned; `--print-base`; tested in `tests/container/`) with `--constraint=/usr/share/ansible-runtime/constraints.txt`), `README.md` |
| `container/tests/smoke.sh` | runs inside the image from a bind-mounted checkout (`docker run --rm -v "$PWD":/work -w /work <image> bash container/tests/smoke.sh`): tini PID 1, terraform/pwsh/PSScriptAnalyzer equal the Dockerfile's ARG defaults, ansible-core and every base pin as installed, `codeorca --version` = pyproject, `pip check`, no curl/gpg/unzip, the TF/PowerShell env, then on a temp COPY of `examples/reference`: `doctor`, `validate`, `plan-only`, `configure-local`, `demo-rollout` exit 3, `resume latest --approve` refused, both lints, no placeholder in specs/run dir; prints one `PASS:` line. Never writes to or runs git in the checkout |
| `.dockerignore` | allow-list build context: `pyproject.toml`, `README.md`, `LICENSE`, `src/`, `container/requirements/` only |
| `.github/workflows/image.yml` | the image pipeline (modelled on ansible-runtime's `build.yml`): `image (amd64)` / `image (arm64)` on native runners build `container/Dockerfile` `--target runtime` with no build-args (the ARG defaults are the pins), run `container/tests/smoke.sh` from the checkout, check the checkout stayed clean, grype (amd64, fixable critical) and, on `main` or a tag only (`PUBLISH`), push by digest; `manifest` makes `:main` (+ `:sha-<short>` on a push) or `:X.Y.Z`/`:X.Y`/`:latest` (`.github/ci/release-check.sh`: strict `vX.Y.Z`, equal to pyproject's version, commit on `origin/main` (both checkouts `fetch-depth: 0`); `:X.Y`/`:latest` only for the highest release of the line / overall; `.github/ci/refuse-overwrite.sh`: an existing `:X.Y.Z` is never re-pointed, only "not found" counts as absent, a re-run with the same digests carbon-copies the existing index), then build provenance + SPDX SBOM attestations on the index. Label build-args `IMAGE_VERSION`/`IMAGE_REVISION` on both build steps. No path filter on `pull_request` (the two image jobs are to become required checks) |
| `.github/ci/` | `release-check.sh` and `refuse-overwrite.sh`, the tag-run checks `image.yml` calls (bash 3.2-safe; tested in `tests/container/` against throwaway git repos and a fake `docker`) |
| `tests/container/` | `lock.sh` against a fake `docker`, the two release scripts, and static checks on the Dockerfile + `image.yml` (label ARG order, identical build-args, release-check wiring) |
| `bin/codeorca` | local launch wrapper (bash 3.2-safe; header lists every mount, env name and exit code): checks `docker` is on PATH and `docker info` answers (else exit 69), then `docker run --rm` of `CODEORCA_IMAGE` (default `code-orca-runtime:latest`) with `$PWD` at `/work`, `-it` only when stdin and stdout are TTYs, AWS/`CODEORCA_*`/`TF_VAR_*` by name only (`compgen -e`; `CODEORCA_IMAGE`/`CODEORCA_DOCKER_SOCKET` not passed), ssh agent, `known_hosts` ro, plugin cache (both skipped without `HOME`), the Docker socket only with `CODEORCA_DOCKER_SOCKET=1`. Only `$PWD` is mounted: an absolute `-p` under it is rewritten to the relative path, a project file outside it is refused (64), and so is a `state_dir`/`specs_dir` that is absolute or leaves it, for the commands that use them. Then, unless the caller is root, Docker is rootless or the container never started (125/126/127), a second container runs `find -P <state top dir> <specs_dir> -uid 0 -exec chown -h` (root-owned files only; never the project root, a symlink or a path leaving the root). Exit code is codeorca's. Never runs aws-vault |
| `tests/wrapper/` | `bin/codeorca` against a fake `docker` (records argv; answers `docker info`, rootless or daemon down on request) and a fake `id` (uid 1001, so the suite also passes as root, inside the image) on PATH: no secret value on any argv, names only, `-it` needs both TTY ends (pty), socket only on `=1`, exit codes propagate (a failed chown never masks one; 64/69/125-127), the `-p` rewrite in every form, paths outside `$PWD` refused, chown targets per `-p` form and never the project root; clean env per test; skipped on Windows |
| `docs/CONTAINER.md` | what the image holds and why, local arm64 build + smoke, `bin/codeorca`, the trigger table, releasing (tag == pyproject version), pulling + `gh attestation verify`, GHCR visibility (manual), bumping the base / Terraform / PowerShell / PSScriptAnalyzer |

## Conventions

- **Deny floor in code.** The Terraform `action` enum and the `apply` -> `plan_file` rule live in the
  models. A workflow file can only narrow policy, never widen it. Do not add `destroy`, `import`,
  `state`, `taint` or an auto-approve flag to the enum. The floor covers the `terraform` step type; helpers
  (`shell`, `python`, `powershell`) are trusted code, but the `shell` executor still runs
  `policy.check_argv` over an argv whose program is `terraform`/`tofu`, so `run: [terraform, destroy]` is
  refused too (a `python`/`powershell` helper's own child processes are not inspected: review bounds them). The adapter drops `TF_CLI_ARGS*` from every child environment (the one other way onto the
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
- **The approval invariant** (plan 5.9, owner decision 2026-11-01): an agent-launched run can reach exit 3 at a
  gate and nothing further. The gate asks only when stdin AND stdout are terminals; `resume` refuses otherwise,
  for either decision, and there is no environment variable or keyword that skips the check (tests assert both;
  `isatty` is injectable for tests only and the CLI must never pass it). An apply runs only a plan file whose
  sha256 an approving gate recorded, within `gate.max_age` (measured from the decision, from when the gate started
  asking or waiting, and from when the plan was made); a dry-run approval never counts in a real run. A resume
  refuses when the workflow, the project (`project_sha256`) or the redaction key (`redaction_key_id`) changed since
  the stop; `resume --approve` shows what the approval binds and the approver types `approve` to confirm. A gate
  may not sit in `finally` or carry `retry`. Gate fields named like secrets are read without echo and never taken
  from `--field`.
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
- **(Superseded in Phase 3: see the Phase 3 gotchas.) The redaction key is `CODEORCA_REDACTION_KEY` in Phase 1** (bytes of its UTF-8; key id `env:<sha256[:8]>` in
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
Phase 3 gate / resume / apply (2026-11-02):
- **`finally` used to run when a run stopped at a gate** (exit 3), so a resumed run would have run it twice; it now
  runs only at the real end (the old waiting test asserted the opposite and was changed with the reason in the
  commit). A run.json from before the change whose finally already ran is not run again on resume.
- **A redacted input cannot be replayed.** `record_filter` key-denylists `inputs`, so `api_token` persists as
  `<redacted:key>` (no placeholder to check a re-supplied value against); an input that is only *registered*
  persists as `<redacted:hmac:…>` and is checked. Resume therefore keeps inputs verbatim (never re-coerces them:
  `<redacted:key>` is not an int) and asks again only for redacted inputs a remaining step (or a var it uses)
  references; a var built from one is rendered again. A step output the persisted scrub changed (the runner names
  it in the step's `scrubbed_outputs`) cannot be replayed either: resume refuses when a remaining step references
  one (an output that was already a placeholder at its source replays as it was).
- **The runner's retry cannot be vetoed by an executor**, and `retry.policy: transient` matches any
  `policy.transient_errors` entry (`Throttling`, `429`), so the apply step keeps `apply-attempt.json` in its step
  dir and refuses attempt 2+ unless attempt 1 failed with `Error acquiring the state lock` before any
  `apply_start`/`apply_progress` message; the lock failure's error text carries that phrase so `transient` fires.
- **A resumed apply runs in a fresh registry**: nothing from the first process is registered, so the apply runs
  `show -json` first and `seed_registry` over it before the apply streams (the plan file carries the variables,
  so no input needs re-supplying for an apply).
- **`terraform state list` with no state exits 1** with "No state file was found!" on stderr (1.14.7); the
  `migrate_backend` probe treats exactly that as empty. A state that exists but lists **no resources** is
  treated as empty too and would be overwritten by `-force-copy` (residual). `init -backend-config=path=…` works
  only when the configuration declares `backend "local" {}` explicitly; `-migrate-state -force-copy` from local
  path A to B copies and leaves A in place.
- **`n` is a YAML 1.1 boolean token**: a gate field (or any key) named `n` fails validation; name it `count`.
Phase 3, SSM provider and backend bootstrap (2026-11-02):
- **botocore timeouts do not bound credential resolution.** `connect_timeout`/`read_timeout` cover the HTTP call
  only; a `credential_process` (aws-vault waiting on a locked keychain) hangs before it. Every code-orca AWS call
  also runs under `providers.ssm.call_with_deadline` (a daemon thread joined with a wall-clock limit, 4x the
  per-call timeout by default); the abandoned thread cannot keep the process alive.
- **`retries={'max_attempts': 2}` means two retries**: botocore normalises it to `total_max_attempts == 3`
  (legacy mode); assert that, not the dict you passed.
- **The redaction key's precedence is deliberate**: `CODEORCA_REDACTION_KEY`, when set, wins and SSM is never
  called (deterministic key id, no credential provider touched in CI or tests); otherwise the SecureString named by
  `redaction.hmac_key` (key id `<ref>@<version>`; a `String` parameter is refused); a failed fetch never falls back
  to anything: it fails closed naming the parameter. `build_registry` only reaches SSM when the caller passes
  `key_fetcher`, so a test that calls it bare stays offline.
- **AWS tests must neutralise the developer's config**, not just set fake keys: `AWS_PROFILE` and `~/.aws/config`
  profiles with `credential_process` (aws-vault) would still engage. The conftests drop the profile/role/container
  variables and point `AWS_CONFIG_FILE`/`AWS_SHARED_CREDENTIALS_FILE` at an empty file under `mock_aws`.
- **`SecretRegistry` has `__slots__`**: an instance's `add` cannot be monkeypatched; subclass it to spy.
- **`${` and `%{` are template sequences in an HCL string**, a backend file included: `render_backend_hcl` escapes
  them (`$${`, `%%{`). `terraform fmt` only accepts `.tf`/`.tfvars`/`.tftest.hcl`: syntax-check a backend file by
  copying it to `.tfvars`.
- **S3 settings to compare field by field** (moto 5 and S3 alike): `get_bucket_versioning` returns `{}` with no
  `Status` on a new bucket; a missing setting is an error code (`NoSuchPublicAccessBlockConfiguration`,
  `ServerSideEncryptionConfigurationNotFoundError`, `NoSuchBucketPolicy`, `NoSuchLifecycleConfiguration`,
  `ObjectLockConfigurationNotFoundError`, `NoSuchTagSet`); a policy's `Statement`/`Action`/`Resource` may be a
  string or a list; `put_bucket_policy`/`put_bucket_lifecycle_configuration`/`put_bucket_tagging` replace the whole
  set, so the bootstrap merges by Sid / rule ID / tag key. A lifecycle rule needs `Filter` (`{"Prefix": ""}`).

Phase 3 integration (2026-11-02):
- **A gate cancelled by `on_timeout: cancel` used to end the run with exit 0**: the runner only counted
  `failed`/`errored` as blocking. A step whose *executor* returned `cancelled` (status `cancelled` with an error;
  `fail_fast` cancellations carry none) now cancels the run: exit 1, `cancelled()` true, unrelated steps cancelled.
- **Once the CLI passes `key_fetcher`, any test that builds a registry without `CODEORCA_REDACTION_KEY` asks real
  SSM** with whatever the shell has (aws-vault hangs on a locked keychain). `tests/conftest.py` neutralises AWS for
  every test; a test that must prove "no AWS call" uses `no_boto3_session`. A default argument
  `isatty=os.isatty` binds at definition time (monkeypatching `os.isatty` then does nothing): `resume()` takes
  `isatty=None` and resolves `os.isatty` at call time, so a CLI test patches `os.isatty` (plus `getpass.getpass`
  and `builtins.input`) and drives the CLI's own resume wiring.
- **A terminal check under pytest must not rely on fd capture** (fd 1 is a pipe only under the default capture):
  with `pytest -s` in a terminal, a refusal test would approve or a run would block on a real prompt. The tests
  that need "no terminal" patch `os.isatty` to return False.
- **`${{ steps.x.outputs.tf.a.value | default(y) }}` still raises when `x` was skipped**: outputs are `None`, `.tf`
  is a StrictUndefined and `.a` on it raises before `default` runs. Default the first level that can be missing:
  `(steps.x.outputs.tf | default(steps.plan.outputs.planned)).a.value` (`planned` = the plan's `prior_outputs`, the
  root outputs re-evaluated by the plan, so a dry run or a no-change run still has the host and bucket).
- **A gate with `when: changed` that is skipped leaves its dependents `omitted`, not `skipped`** (skipped is not a
  met status): a step that should run after "nothing to apply" too needs `always()` plus an explicit status list
  (demo-rollout's `configure`), and must exclude a rejected gate itself.
- **`-WhatIf` reaches every cmdlet in the script** (`$WhatIfPreference`), so `Set-Content $env:CODEORCA_OUTPUT_FILE`
  is silently skipped under `--dry-run` and the step has no output: write the output with
  `[System.IO.File]::WriteAllText` (or `-WhatIf:$false`). PSScriptAnalyzer's `PSShouldProcess` warns when a script
  declares `SupportsShouldProcess` but never calls `$PSCmdlet.ShouldProcess`: guard the script's real change with it.
- **A `finally` shell step running `codeorca summary` depends on PATH and the operator's cwd** (the shell step runs
  in the process cwd, `-p` defaults to `./codeorca.yaml`); the reference uses a `python` helper (cwd = project root,
  the interpreter running code-orca, `python -I` still sees its site-packages and an editable install).
- **A reference workflow's input defaults ARE the placeholders**: the configure-local test asserts its token
  appears in no project file but its own workflow, so a second workflow reusing the same default broke it; each
  reference workflow has its own `FIXTURE-SECRET-*` values (all covered by CI's `FIXTURE-SECRET` grep).
- **`resume --reject` still asks for redacted inputs the remaining steps reference** (they are computed before the
  decision, and `when: always()` steps may still run); type anything for a step that the reject will omit.

Phase 3 review fixes (2026-11-02):
- **A helper's output file is not always UTF-8**: PowerShell 5.1's `Out-File` default (and `-Encoding unicode`)
  is UTF-16LE with a BOM, and a Python helper may write Latin-1. A strict UTF-8 read raised before the scrubbed
  rewrite and left the raw file (with the helper's secret) in the run dir. `shell.decode_output` decodes by BOM, else
  UTF-8 with `surrogateescape`; a rewrite that fails deletes the file; `scan_outputs` also reads files with NUL
  bytes as UTF-16.
- **An interactive gate with no `timeout` can stay open for days**: `decided_at` is "now" when the approver
  finally types, so `gate.max_age` also bounds `waiting_since` (recorded on both paths) and each plan's
  `planned_at` (the plan step's finish time from run.json, in the gate's `plans` binding); a binding without a
  plan time is refused.
- **`decided_at` has second precision**: two gates answered in the same second tie; the tie goes to the gate with
  the most approving gates upstream of it, never to the id that sorts first.
- **Resume pins more than the workflow**: the plan gate's `stateful_types`/`critical_tag`, `gate.max_age` and the
  `migrate_backend` target come from `codeorca.yaml` at resume time, so run.json records `project_sha256`; and
  `redaction_key_id`, so run and resume cannot use different keys (env override vs SSM, or a rotated parameter).
- **botocore resolves credentials in `create_client`, not in `boto3.Session()`**: a `credential_process` (aws-vault)
  runs when the first client is built, with no timeout. Build the clients inside `call_with_deadline`, never just
  the session. The abandoned child cannot be killed (botocore owns the `Popen`): `SSMSecrets` shares one session
  per run and, after the first `SSMTimeout`, fails later fetches at once instead of spawning another child.
- **A gate in `finally` or with `retry` broke the approval contract** (exit 0 with the gate unanswered and the run
  unresumable; a typed reject asked again with a fresh timeout): both are refused by the model.
- **A replaced `backend.hcl` is recorded by digest only** (`{sha256, bytes}` before): a hand-written one can hold
  credentials and the diff lands in output.json, result.json, outputs/ and run.json.
- **An inline `(?i)` flag cannot be embedded mid-pattern** (Python 3.11+ raises "global flags not at the start"):
  reuse a pattern's text with `.removeprefix("(?i)")` and pass `re.IGNORECASE`.
- **CI fails on any skipped test**: terraform, ansible-core, moto, boto3 and pwsh are all installed there, so a
  skip means a broken install. `faulthandler_timeout = 300` names a hung test instead of a silent 30-minute timeout.

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
- **Learned building it (2026-11-03):** the base has **no curl, gpg or unzip** (and no setuptools): downloads
  happen in a `downloader` stage and only their results reach the final stage (`COPY --from`, or a
  `RUN --mount=type=bind,from=…` for the Microsoft repo .deb, so it never lands in a layer). The base already pins
  **every** code-orca dependency (jinja2, pydantic, ruamel.yaml 0.19.1, ansible-core, boto3), so
  `container/requirements/codeorca.txt` has no packages; pip accepts an empty `-r` file, and an install under
  `-c /usr/share/ansible-runtime/constraints.txt` with a pin that disagrees fails `ResolutionImpossible` (tested).
  `--require-hashes` rejects an unhashed local wheel, so the wheel is a separate `pip install --no-deps`. Without a
  hash-pinned setuptools, `pip wheel` build isolation would fetch an unhashed one: the builder uses
  `--no-build-isolation`. `pip-compile` with no source argument compiles `pyproject.toml` into `./requirements.txt`
  (a stray file in the checkout). PSScriptAnalyzer 1.25.0 is ~286 MB, 279 MB of it `compatibility_profiles/` (the
  data the `PSUseCompatible*` rules read): kept, the image is ~1.24 GB (arm64; the base is ~612 MB). A git worktree's
  `.git` is a file pointing at the main checkout's absolute host path, so git inside the container fails on a
  worktree mount (and on Linux a root container sees a runner-owned checkout as "dubious ownership"): the smoke
  test never calls git; the caller checks `git status --porcelain`.
- Dependabot's docker updater reads literal `FROM image:tag@sha256:...` lines only (`docker/file_parser.rb`'s
  `FROM_LINE`): `ARG BASE_IMAGE=...` + `FROM ${BASE_IMAGE}` is invisible to it. A literal pinned stage that the ARG
  default names works (`ARG BASE_IMAGE=pinned-base` BEFORE the first `FROM`, then `FROM <image>@sha256:... AS
  pinned-base`, `FROM ${BASE_IMAGE}`): BuildKit resolves an ARG naming a stage, but a global ARG declared after
  the first `FROM` is blank in later `FROM` lines ("base name should not be blank").
- BuildKit passes every `ARG` in scope to each later `RUN` as an environment variable, so a changed value is a cache
  miss for all of them: an `ARG IMAGE_VERSION` declared at the top of the runtime stage would rebuild the PowerShell,
  PSScriptAnalyzer and pip layers on every release. The label ARGs sit right before `LABEL` (tested: a late ARG
  changes only the label; `tests/container/test_image_pipeline.py` pins the order).
- A `paths:` filter on `pull_request` and a required check do not mix: a skipped workflow leaves the check
  "Expected" and the PR unmergeable. `image.yml` filters only its `push` trigger.
- A container package pushed to GHCR from Actions starts private for a personal account; making it public is a
  UI-only step in the package settings (Chris). Check with an anonymous token + manifest fetch after the first
  push (`docs/CONTAINER.md`), not `docker logout`.
- On Docker Desktop for macOS, files a root container writes into a bind mount already show as the host user, so
  `bin/codeorca`'s chown is a no-op there; it matters on Linux. Under rootless Docker (and Podman) container root IS the caller, and a
  `chown` to the caller's uid inside the container maps to a subordinate uid on the host: the wrapper asks
  `docker info` (`name=rootless`) and skips the chown. It chowns only `-uid 0` files, so a multi-component
  `state_dir` or a shared checkout never has anyone else's files re-owned.
- The wrapper's exit codes must not collide with codeorca's: 2 is `drift`'s "drift found", so wrapper refusals are
  64 and "no Docker" is 69 (sysexits). A daemon that cannot be reached makes `docker run` exit 1, which looks like
  a failed workflow: hence the `docker info` check before the run.
- argparse's `allow_abbrev` is per parser: `add_parser` does not inherit it from the parent's keyword, only through
  the parser CLASS (`add_subparsers` uses `type(parent)`). `cli._Parser` defaults it to False for every subcommand,
  so `--proj` is an error and `bin/codeorca`'s exact `-p`/`--project` match always finds the project codeorca
  uses.

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
3. ~~Helpers (python/powershell/shell), gate with TTY + resume, apply bound to the plan sha256, backend bootstrap~~
   (done 2026-11-02: `gate` + `codeorca resume`, `apply` bound to the approved sha256, `migrate_backend`, `python`/
   `powershell` helpers + `codeorca lint powershell`, SSM secrets + SSM-backed redaction key, S3 bootstrap +
   reference `bootstrap-backend`, `demo-rollout` end to end, CI to the gate). Residuals:
   - **TTY faking**: the gate and `resume` trust `isatty(0)` and `isatty(1)`; anything that hands a process a
     pseudo-terminal (`script`, `expect`, `unbuffer`, a pty library) passes. The invariant holds against agents and
     pipes as launched today, not against a deliberately faked terminal; the operator's own launch is the boundary.
   - **Redaction key across a resume**: refused since the review fixes (run.json `redaction_key_id`); a run.json
     from before them carries none and is not checked.
   - **Abandoned credential_process children**: a hung aws-vault child outlives the deadline (and codeorca) until it
     exits on its own; only one per run, after which SSM fetches fail fast.
   - **Object Lock (plan V15)**: a bucket with Object Lock but no default retention is accepted and believed
     harmless for `.tflock`; unverified.
   - **Real AWS never exercised**: the SSM provider, the SSM redaction key, the bootstrap and an s3 backend init are
     tested against moto only (the reference backend is local); run once against a sandbox account before v0.1.0.
   - **`migrate_backend` limits**: a target state that exists but lists no resources is treated as empty and
     overwritten by `-force-copy`; tested between two local backends only, never into S3.
   - **Ansible steps cannot take SSM secrets**: the `ansible` step has no `stack:` or `env:` field, so
     `stacks.*.secrets` and `{secret: ssm:/...}` reach terraform and the helpers only (a secret for a play goes
     through a helper or a `no_log` extra var today); a model field for it is a design decision, not done here.
   - **`specs/backend.yaml`** (plan 5.11): not rendered; the bootstrap step's `diff` output (run.json/result.json) is
     the record until a `source.backend` spec renderer (model field, schema, kind) exists.
4. ~~Container image~~ done (Phase 4): `container/Dockerfile` on `ansible-runtime` 1.3.0, `bin/codeorca`, the
   `image` workflow. The pyproject ranges are for pip users only; in the image the base's `constraints.txt` fixes
   every version, and anything the base lacks is hash-pinned in `container/requirements/codeorca.txt` (nothing
   today). Residuals: amd64 is verified only in CI; the GHCR package starts private (Chris makes it public in its
   settings); `image (amd64)` and `image (arm64)` join the required checks after their first run; the image is
   about 1.24 GB, 279 MB of it PSScriptAnalyzer's compatibility profiles (kept for the PSUseCompatible* rules).
   Also open: nothing stops a `v*` tag from being CREATED on a non-main commit (both rulesets target
   `~DEFAULT_BRANCH`); `release-check.sh` refuses to publish one, and a tag ruleset restricting `v*` creation is
   Chris's to add.
5. Reference project end to end in CI; consumer guide; v0.1.0.
