# Changelog

## Unreleased

- Phase 4 review fixes: `container/requirements/lock.sh` locks inside the image on the Dockerfile's literal
  `AS pinned-base` line again (it had read `ARG BASE_IMAGE=`, which names the stage since the Dependabot refactor,
  and ran `docker run pinned-base`); a `BASE_IMAGE` override must be digest-pinned; `--print-base`.
  `bin/codeorca`: an absolute `-p` under `$PWD` is rewritten for the container (it failed "not found"), a project file,
  `state_dir` or `specs_dir` outside `$PWD` is refused (exit 64) instead of being written to the container's
  throwaway filesystem; the chown changes only root-owned files, never the project root (`./.codeorca/runs`,
  `specs_dir: .` had chowned the whole tree), and is skipped under rootless Docker and when the container never
  started; a missing `docker` or unreachable daemon exits 69 (it had exited 1, like a failed workflow); `HOME` unset
  no longer aborts. codeorca takes no abbreviated long options (`--proj`), on any subcommand.
  The image's OCI labels: `version` is `X.Y.Z` on a release (it was always `dev`), a new `revision` carries the commit,
  and `licenses` adds `GPL-3.0-or-later` (ansible-core, ansible-lint).
  Releases (`.github/ci/release-check.sh`, `refuse-overwrite.sh`): only a strict `vX.Y.Z` tag on a `main` commit
  publishes (a prerelease tag had published only `:latest`; a branch tag published at all); `:latest` and `:X.Y` move
  only for the highest release (a backport or racing tags had moved them backwards); the overwrite refusal fails on
  any registry error but "not found" (it had failed open), and lets a re-run with the same digests re-attest a
  release whose attestation failed after the tags went out.
  The weekly schedule no longer claims to deliver Debian security updates (it cannot: digest-pinned base, cached
  layers; it re-scans with a fresh grype database). The clean-checkout check includes ignored files.
- Container image (Phase 4): `container/Dockerfile` builds `code-orca-runtime` on ansible-runtime 1.3.0 with
  Terraform 1.14.7 (GPG-verified release zip + its BSL 1.1 license), PowerShell 7.6.9 LTS + PSScriptAnalyzer 1.25.0
  and the code-orca wheel under the base's pins (no venv, `pip check` in the build); `container/tests/smoke.sh`
  checks the pins and runs the reference project end to end inside the image; the reference `runtime:` block lists
  `boto3` (bootstrap-backend) and documents where each pin comes from.
- Container pipeline: `.github/workflows/image.yml` builds, smoke-tests and grype-scans
  `ghcr.io/git-cgallagher/code-orca-runtime` on native amd64 + arm64 runners, publishes `:main`/`:sha-<short>` from
  main and `:X.Y.Z`/`:X.Y`/`:latest` from a `vX.Y.Z` tag matching pyproject's version (never re-tagging a release),
  with build provenance and an SPDX SBOM attested on the index; `bin/codeorca` runs code-orca in the image (secrets
  by name only, `-it` only on a terminal, Docker socket only on request, state/specs chowned back); tests in
  `tests/wrapper/`; Dependabot's docker entry; `docs/CONTAINER.md`.

- Phase 3 review fixes: a helper's non-UTF-8 output file (UTF-16 `Out-File`, Latin-1) is rewritten scrubbed or
  deleted, never left raw, and `scan_outputs` reads UTF-16; `gate.max_age` also bounds when the gate started asking
  (`waiting_since`) and when the plan was made (`planned_at` in the binding); resume refuses a changed project
  (`project_sha256`) or redaction key (`redaction_key_id`), a remaining step that references a scrubbed step output
  (`scrubbed_outputs`), a non-literal `inputs`/`vars` reference without every redacted input, and a re-supplied
  input that differs from the recorded one part by part; a mistyped secret input or field is never quoted; a gate
  in `finally` or with `retry` is refused; a same-second approval tie goes to the downstream gate; gate fields named
  like secrets are read without echo, never taken from `--field`, and a short one is named in a warning;
  `resume --approve` shows the gate's message, specs, plan sha256s and waivers and asks for a typed confirmation;
  the S3 bootstrap records a replaced `backend.hcl` by digest and builds its clients (credential resolution) inside
  the deadline; `SSMSecrets` shares one session per run and fails fast after a hang; stack secrets too short to
  scrub are named in the step result (`unprotected_secrets`); an apply that fails deletes its plan file unless a
  retry may use it, and a stack-flock conflict before Terraform ran may be retried. Tests: the CLI's own resume path,
  the ancestor-gate rule, the adapter's sha256 re-check, re-supplied secrets and fields never in the run dir, no
  dependence on pytest's fd capture, botocore's legacy credential files closed, `faulthandler_timeout`; CI fails on
  any skipped test.

- Phase 3 integration: `codeorca run`/`resume` register the `gate`, `python` and `powershell` executors and hand one
  SSM resolver per run to the helpers and the terraform step (a stack's `secrets:` resolved into the child env only,
  registered first, `drift` included; without boto3 only the step that needs a secret fails); the registry takes the
  SSM-backed redaction key (`CODEORCA_REDACTION_KEY` still wins). New `codeorca resume <run-id|latest>
  (--approve [--field k=v] | --reject)` (terminal required, no bypass; secret inputs asked with `getpass`) and
  `codeorca lint powershell <paths> [--ansible-settings]`. A gate cancelled by `on_timeout: cancel` now fails the
  run (exit 1). The terraform step's s3 backend config is `bootstrap.s3.backend_settings` (adds `kms_key_id`).
  Reference: `demo-rollout` runs end to end (plan, spec, gate, apply, Ansible from the outputs, host spec, python
  and powershell helpers, finally summary); `bootstrap-backend` validates each stack after the helper. CI installs
  the `aws` extra, imports the Phase 3 modules from the wheel, requires the pwsh tests to run, lints the
  PowerShell helpers, runs `demo-rollout` to the gate (exit 3, run.json waiting) and asserts `resume --approve`
  refuses without a terminal; the test job has a 30-minute timeout. Tests never reach AWS (`tests/conftest.py`).
- Helper steps (Phase 3, plan 5.8): `steps/python_step.py` (`python -I`) and `steps/powershell_step.py`
  (`pwsh -NoProfile -NonInteractive -File`, `-WhatIf` under `--dry-run`, scripts without a script-level
  `SupportsShouldProcess` refused there) on the shared contract in `steps/helpers.py` (project-root-relative scripts,
  `{secret: ssm:/...}` env resolved through an injected resolver and registered before the child starts, outputs via
  `CODEORCA_OUTPUT_FILE`), plus `lint_powershell` (PSScriptAnalyzer, optional ansible-test pslint settings). The
  shell step's child-process code moved into `shell.run_argv` unchanged. Registered by the CLI (integration).
- Phase 3 (gate, resume, apply): the `gate` step (dry-run auto-approval; on a terminal: message, staged specs and
  plan sha256s, approve/reject and typed `fields`, approver/decision/timestamp/plan binding recorded; no terminal:
  `wait` -> exit 3 or `fail`; no timeout ever approves), `codeorca.resume.resume` (terminal required with no
  bypass, `gate.max_age`, plan tamper check, changed-workflow check, re-supplied secret inputs, completed steps
  replayed, `finally` once), the runner no longer runs `finally` at a wait (`Runner.restore`/`settle`, run.json
  `workflow_sha256`/`resumes`), Terraform `apply` bound to an approved plan of this run (max_age, plan gate with
  `allow_delete_of`, lock-only retry, redacted `tf_outputs`, plan file deleted, `--dry-run` skips) and
  `migrate_backend` (approving gate, refuses a non-empty target, `init -migrate-state -force-copy`). Models: typed
  `GateField`, gate fields are outputs, no `on_failure: continue` on a gate, no `var_overrides` on apply/migrate.
- Phase 3 (SSM + backend bootstrap): `codeorca.providers` (`SSMSecrets`, `make_resolver`: SSM `ssm:/` references
  registered before they are returned, memory-only cache, time-limited calls incl. a wall-clock deadline, value-free
  errors), the SSM-backed redaction key (`build_registry(..., key_fetcher=ssm_key_fetcher(project))`, key id
  `<ref>@<version>`; `CODEORCA_REDACTION_KEY` still wins when set; a failed fetch fails closed), and
  `codeorca.bootstrap.s3` (`python -m codeorca.bootstrap.s3`): S3 state bucket created and converged idempotently
  (account check, Object Lock default-retention refusal, public access block, versioning, encryption, merged
  TLS-only policy, lifecycle and tags), `backend.hcl` per stack, `--dry-run` diff; reference workflow
  `bootstrap-backend`; new `aws` extra (`boto3`), `moto` in `dev`.
- Phase 2 review fixes (host spec, secrets): a listed template whose own text calls a denied lookup is a
  `<skipped: …>` marker in both scopes; the play scope reads its playbook, its roles' `defaults`/`vars` (every file
  Ansible reads, `main/` dirs included) and its `vars_files` with `!vault` values opaque (`specs/ansible_files.py`;
  a file that does not parse fails the step), hands `<vault>` and masked nested trees through `-e`, registers every
  literal secret leaf before the play, resolves short lookup names to FQCNs through the vars subprocess, and runs
  with a random vault password (a consumer's vault config never decrypts anything there); nested denylist-named
  leaves render as markers in templates; argument specs come from every roles dir, `meta/main.yml`'s
  `argument_specs` counts and `no_log` is OR-ed over roles and entry points.
- Phase 2 review fixes (host spec, correctness): extra vars are overlaid on top of the inventory scope (they no
  longer lose to `host_vars` files, and only their names are labelled `extra_vars`); only plays whose `hosts` match
  the host feed its spec; a play-scope value's `source` names the source that won (`role defaults: <role>`,
  `play vars: …`, `vars_files: …`, `role vars: …`); one failing template no longer stops the others (tasks never
  run are `not run`, and template errors fail the step); a YAML date default no longer crashes the subprocess;
  provenance follows `DataLoader.find_vars_files` and labels are lexical (a symlinked file keeps a relative label);
  inventory-scope templates render like the `template` action (`{% include %}`, `template_*`, `ansible_managed`).
- Phase 2 review fixes (secrets): the Ansible adapter forces `ANSIBLE_DEBUG=False`, `ANSIBLE_LOG_PATH=/dev/null`,
  `ANSIBLE_VERBOSITY=0`, `ANSIBLE_KEEP_REMOTE_FILES=False` and `ANSIBLE_CALLBACKS_ENABLED=codeorca_jsonl` instead of
  dropping names a consumer's `ansible.cfg` could set again (the vars subprocess forces the first three too), and
  `project.ansible.env` refuses those names.
- Phase 2 review fixes (ansible step, secrets): before the play starts the step also registers the literal secret
  leaves of the vars files it will read (an `inventory.path` file, `group_vars`/`host_vars` next to the inventory
  and the playbook, the playbook's `vars`/`vars_files`, its roles' `defaults`/`vars`, argument-spec `no_log` vars),
  so `--dry-run`'s `--diff` no longer prints a denylist-named `group_vars` value into `events.jsonl`.
- Phase 2 review fixes (runtime): the ansible step writes the live inventory and the extra-vars handoff inside the
  `try` that deletes the handoff dir (a failure after the inventory was written left `ansible_password` on disk),
  and handoff JSON is dumped with str keys (a nested `{80: http, https: 443}` raised under `sort_keys`).
- Phase 2 review fixes (role steps): the generated play no longer sets `ANSIBLE_ROLES_PATH`/
  `ANSIBLE_COLLECTIONS_PATH` (which replaced Ansible's defaults and `ansible.cfg` paths); it is written to the
  handoff dir with `roles`/`collections` symlinks next to it, and the play scope does the same. New step field
  `gather_facts` (role steps only, default true, as Ansible's own; refused on a `playbook:` step).
- Phase 2 review fixes (timeouts): the tree kill reads `/proc/*/stat` on Linux (the slim runtime image has no
  `ps`), SIGSTOPs the leader's group and every descendant before the SIGKILL, and the steps remove their
  `ANSIBLE_LOCAL_TEMP`; a playbook that exits just before the deadline gets a 2 s grace for the pipe readers
  instead of being reported as a timeout.
- Phase 2 review fixes (exit status): `AnsibleResult.describe` reads the stats (rc 4 is also ansible-core's
  `PARSER_ERROR`; a run with no stats event is a parser/CLI error and the step error carries the stderr tail),
  `describe_rc` no longer decodes a bitmask, and `last_failure` skips rescued failures and `ignore_unreachable`
  results (the callback marks the latter `ignore_errors`).
- Phase 2 review fixes (callback): a `no_log` result's `exception`/`warnings`/`deprecations` are `null` (the step
  error never falls back to the exception text of a `no_log` failure); an item event's result shows the
  `loop_control.label` in place of the loop variable; the stats event lists `set_stats` keys only; events are
  ASCII-escaped JSON (U+2028/U+0085 no longer split a line); `notify` events carry no task attribution and
  `include` events name the include task; `raw`, `script` and `fetch` count as check-mode-unsupported.
- Phase 2 integration: `codeorca run` registers the `ansible` executor; `spec-render` takes `source.ansible`
  (`codeorca.steps.host_spec`): inventory scope via the vars subprocess, optional play scope as a check-mode play
  through `AnsibleRunner` with markers handed over in a 0600 `-e @` file, a staged inventory that merges the
  producing step's redacted extra vars and copies playbook-adjacent `group_vars`, `scope: inventory`/`play` per
  var, `host-vars.json` for `codeorca render` (which re-renders host specs without running anything). The ansible
  step keeps a redacted `extra-vars.json`; specs render multi-line strings as literal blocks; the play-scope
  parser ignores `task_start` events. Reference project: role `app_config` (argument spec with a `no_log` token),
  `group_vars/app.yml` with a denied lookup, `workflows/configure-local.yaml` (run in CI with its host spec
  checked for the placeholder token). New `codeorca lint ansible <paths…> [-p]`. CI installs `.[dev,ansible]`,
  imports the Phase 2 modules from the wheel and lints the reference playbooks.
- Ansible step (Phase 2): the `codeorca_jsonl` stdout callback (one JSON event per line, no default-callback line
  ever reaches stdout, `no_log` censoring kept, check-mode-unsupported detection), `adapters/ansible.py`
  (`AnsibleRunner`: argv subprocess, hardened child env, tolerant JSONL parsing, stats/failed/unreachable hosts,
  bitmask exit codes, whole-tree kill on timeout; inventory, role-playbook and 0600 handoff generation) and the
  `ansible` executor (playbook or `role:`, handoff files that live only while the play runs, redacted
  `inventory.yml` kept for the host spec, `events.jsonl` through the stream redactor, `--check --diff` under
  `--dry-run`, `check_unsupported` warn/fail/ignore); `pip install 'code-orca[ansible]'` pins ansible-core 2.21.
- Ansible host spec (Phase 2): `specs/ansible_vars.py` (inventory scope as a subprocess: `declared`/`resolved`/
  `source` per var, key-by-key templating, `<secret: declared>` from role argument specs, `<vault>`, key and
  lookup denylists, template rendering with markers in place), `specs/ansible_host.py` (`run_vars_subprocess`,
  `build_host_document`, the check-mode play-scope play generator with `import_role` + `when: false` and
  `marker_vars`, the JSONL events parser) and the playbook lint `codeorca.lint` (`no-hostvars-dump`,
  `debug-secret-name`, `secret-to-plain-param`, `unknown-module`, `redundant-task-no-log`), with a fixture
  inventory under `tests/fixtures/ansible_host/`.
- Phase 1 review fixes (secrets): Terraform's `-json` documents are parsed in memory and never streamed to
  `stdout.log`, and the human `plan` output is written only after the registry was seeded from the plan JSON;
  every `TF_VAR_<name>` whose variable is declared sensitive or denylist-named is registered before Terraform
  starts (`//` and `/* */` comments and `*.tf.json` recognised), and `seed_registry` registers denylist-named
  variables; `registered_overrides` lists only protected names (`unprotected_overrides` + a warning for values too
  short to scrub); `CODEORCA_REDACTION_KEY` is stripped from every child environment; shell `argv.json` is
  redacted; `CODEORCA_OUTPUT_FILE` is rewritten through the hook on every exit path and unlinked per attempt;
  multi-line registered values also match line by line; Go's `\u003c`/`\u003e`/`\u0026` JSON escaping is a
  registry encoding; `plan.json`, `tf-outputs.json` and specs are scanned in memory before anything is written
  (specs atomically, so a gate hit leaves the committed spec intact); `prior_outputs` honours `never_render`
  and the key denylist; the integration test covers an applied stack (drift with a rotated secret, an `output`
  step, a Go-escaped input).
- Phase 1 review fixes (policy): `TF_CLI_ARGS*` dropped from the child environment; `terraform test` refuses any
  run block that is not explicitly `command = plan` (root-dir files and `*.tftest.json` included); a shell step
  whose program is `terraform`/`tofu` goes through the deny floor; `policy.critical_tag` must be `key=value`;
  `complete == false` plans carry a warning (`codeorca drift` shows "incomplete plan").
- Phase 1 review fixes (runtime): `timeout:` works on terraform steps (session deadline, SIGINT then SIGKILL)
  and bounds a shell step's pipe drain; Ctrl-C kills the shell child's process group and the run record is
  finalised on any escape; `retry.backoff` is a typed `Backoff`; an optional input without a default no longer
  crashes `codeorca run` (and a refused run leaves no empty run dir); any exception inside an expression errors
  the step; transient matching sees only the current attempt's stderr; finally step ids are checked and finally
  `needs` refused; `always()`/`failure()`/`cancelled()` inside a string literal no longer count as an override;
  workflow `vars` are rendered once and persisted resolved; two `spec-render` steps may not share an `output`.
- Phase 1 review fixes (renderer): map-flagged sensitive attributes keep their stable placeholder through the
  schema mask; a sensitive+unknown leaf stays `(known after apply)`; `never_render.resources` matches indexed
  addresses exactly; deposed objects carry `deposed`; init failures report the JSON diagnostics; an unsupported
  plan `format_version` is refused; `.meta.yaml` sidecars follow the full file name; `tfjson.state_outputs` no
  longer mistakes an output named `values`/`format_version` for a state document.
- Phase 1 review fixes (CI): the placeholder-secret grep is fatal per pattern (`! grep` was masked under
  `bash -e`), the wheel is built and imported from a scratch venv, step tests run on a tmp copy of the reference
  project, locked-stack and multi-stack drift paths are tested.

- Phase 1 integration: `codeorca run` (real `terraform` and `spec-render` executors, `--input`, `--dry-run`, status
  table), `codeorca drift` (plan every stack without locking, specs refreshed, verdict table with exit 0/2/1),
  `codeorca doctor [--lock|--json]`, `codeorca render <run-id>`, `codeorca summary <run-id>`, `codeorca runs gc`,
  `schema export` now also writes/checks `schema/codeorca-project.schema.json`. Run-wide redaction: one
  `SecretRegistry` per run keyed by `CODEORCA_REDACTION_KEY` (fail-closed for `placeholder: hmac`), seeded from
  env tokens, stack `secrets:`/`required_env`, denylist-named workflow inputs, sensitive `var_overrides` /
  `TF_VAR_*` and the plan JSON; every subprocess line, `run.json`, results, outputs and `CODEORCA_OUTPUT_FILE`
  are scrubbed. The Terraform plan spec (`specs/<stack>/plan.yaml` + `plan.meta.yaml`): deterministic body, header
  with pipeline/engine/git SHA/key id/gate verdict, placeholders stable per value, provenance, `never_render`,
  post-write gate. Reference project: `workflows/plan-only.yaml` runs end to end in CI (terraform 1.14.7), the
  placeholder secret is asserted absent from specs and the run dir; `apply`/`migrate_backend` steps fail with a
  Phase 3 message.
- Terraform adapter, policy and JSON parsing (Phase 1): `policy.py` (deny floor in code, `Policy` narrows only,
  plan gate over `show -json`), `tfjson.py` (tolerant `-json` stream parser, plan summary, sensitivity lookups,
  prior/previous outputs), `adapters/terraform.py` (`TerraformRunner`, every call through one policy-checked
  `_run`, exit 2 preserved, apply refused on a sha256 mismatch), 1.14.7 fixtures captured through the runner.
- Core runtime (Phase 1): project-file model (`codeorca.yaml`, local or s3 backend, stack `depends_on` DAG,
  `max_parallel: 1` enforced), sandboxed `${{ … }}` expressions with GHA-style status functions, the run directory
  (names-only env record, per-stack flock, `list_runs`/`gc`), the sequential DAG runner (needs/when propagation,
  retry with transient regexes, Go-duration timeouts, typed inputs, `finally`, exit codes 0/1/3) and the `shell`
  executor; the reference project now uses a local backend so it validates and runs offline. `for_each`, `cache`,
  gate/resume and parallelism are deliberately not implemented yet.
- Skeleton: workflow models (Pydantic v2, discriminated step types, deny-floor `action` enum, cycle and
  output-reference checks, YAML 1.1 key guard), `codeorca validate`, `codeorca schema export [--check]`,
  the committed JSON Schema, the provider-free reference project, negative test cases, CI.
- Redaction package `codeorca.redact` (plan §5.7): `SecretRegistry` (HMAC placeholders, raw/JSON/URL/base64
  encodings, never pickled or logged), `redact_tree` with a key denylist, Terraform structural masking
  (`mask_by_map`, `merge_unknown`, `schema_sensitive_paths`, `mask_by_schema`), the chunk-safe `StreamRedactor`,
  the `scan_outputs` gate and `entropy_warnings`; offline `FIXTURE-SECRET-*` fixtures and an acceptance test
  proving no fixture secret survives in any encoding.
