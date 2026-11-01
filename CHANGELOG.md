# Changelog

## Unreleased

- Ansible step (Phase 2): the `codeorca_jsonl` stdout callback (one JSON event per line, no default-callback line
  ever reaches stdout, `no_log` censoring kept, check-mode-unsupported detection), `adapters/ansible.py`
  (`AnsibleRunner`: argv subprocess, hardened child env, tolerant JSONL parsing, stats/failed/unreachable hosts,
  bitmask exit codes, whole-tree kill on timeout; inventory, role-playbook and 0600 handoff generation) and the
  `ansible` executor (playbook or `role:`, handoff files that live only while the play runs, redacted
  `inventory.yml` kept for the host spec, `events.jsonl` through the stream redactor, `--check --diff` under
  `--dry-run`, `check_unsupported` warn/fail/ignore); `pip install 'code-orca[ansible]'` pins ansible-core 2.21.
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
