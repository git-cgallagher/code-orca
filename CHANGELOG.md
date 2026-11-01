# Changelog

## Unreleased

- Terraform adapter, policy and JSON parsing (Phase 1): `policy.py` (deny floor in code, `Policy` narrows only,
  plan gate over `show -json`), `tfjson.py` (tolerant `-json` stream parser, plan summary, sensitivity lookups,
  prior/previous outputs), `adapters/terraform.py` (`TerraformRunner`, every call through one policy-checked
  `_run`, exit 2 preserved, apply refused on a sha256 mismatch), 1.14.7 fixtures captured through the runner.
- Skeleton: workflow models (Pydantic v2, discriminated step types, deny-floor `action` enum, cycle and
  output-reference checks, YAML 1.1 key guard), `codeorca validate`, `codeorca schema export [--check]`,
  the committed JSON Schema, the provider-free reference project, negative test cases, CI.
- Redaction package `codeorca.redact` (plan §5.7): `SecretRegistry` (HMAC placeholders, raw/JSON/URL/base64
  encodings, never pickled or logged), `redact_tree` with a key denylist, Terraform structural masking
  (`mask_by_map`, `merge_unknown`, `schema_sensitive_paths`, `mask_by_schema`), the chunk-safe `StreamRedactor`,
  the `scan_outputs` gate and `entropy_warnings`; offline `FIXTURE-SECRET-*` fixtures and an acceptance test
  proving no fixture secret survives in any encoding.
