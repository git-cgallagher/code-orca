# Changelog

## Unreleased

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
