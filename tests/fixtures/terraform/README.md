# Terraform fixtures

Captured from `examples/reference/terraform/app` (provider-free, local state, offline) on Terraform 1.14.7
through `TerraformRunner`, by `regenerate.py`. The only secret is the placeholder
`FIXTURE-SECRET-tf-input-001`; it appears in plain text in `plan.json`, `replace-plan.json`, `state.json`
and `outputs.json` **on purpose**: these documents are what Terraform hands the orchestrator before any
redaction, and the tests assert the value is present so nobody mistakes the adapter for a redactor.

| File | Source |
|---|---|
| `init.jsonl` | raw `init -json` stdout + stderr |
| `init-mixed.jsonl` | hand-made: the same capture with plausible non-JSON provider-install and lock-file lines (the provider-free stack emitted none; a provider download does) |
| `plan.json` | `show -json` of the first (create) plan, `environment=dev` |
| `apply.jsonl` | raw `apply -json <plan>` stream (sensitive outputs carry no value on 1.14.7) |
| `state.json` | `show -json` after the apply, through the runner (never the state file) |
| `outputs.json` | `output -json` after the apply |
| `providers_schema.json` | `providers schema -json` (builtin provider only) |
| `replace-plan.json` | `show -json` of a second plan with `environment=prod`: `terraform_data.app` is replaced, `prior_state` present |
| `delete-plan.json` | hand-crafted for the plan gate: delete of `aws_s3_bucket`, replacement of a `critical=true`-tagged resource, a non-stateful replacement, an update |

Regenerate: `.venv/bin/python tests/fixtures/terraform/regenerate.py` (needs `terraform` on PATH).
