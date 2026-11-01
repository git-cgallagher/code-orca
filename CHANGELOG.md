# Changelog

## Unreleased

- Terraform adapter, policy and JSON parsing (Phase 1): `policy.py` (deny floor in code, `Policy` narrows only,
  plan gate over `show -json`), `tfjson.py` (tolerant `-json` stream parser, plan summary, sensitivity lookups,
  prior/previous outputs), `adapters/terraform.py` (`TerraformRunner`, every call through one policy-checked
  `_run`, exit 2 preserved, apply refused on a sha256 mismatch), 1.14.7 fixtures captured through the runner.
- Skeleton: workflow models (Pydantic v2, discriminated step types, deny-floor `action` enum, cycle and
  output-reference checks, YAML 1.1 key guard), `codeorca validate`, `codeorca schema export [--check]`,
  the committed JSON Schema, the provider-free reference project, negative test cases, CI.
