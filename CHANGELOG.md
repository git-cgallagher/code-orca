# Changelog

## Unreleased

- Core runtime (Phase 1): project-file model (`codeorca.yaml`, local or s3 backend, stack `depends_on` DAG,
  `max_parallel: 1` enforced), sandboxed `${{ … }}` expressions with GHA-style status functions, the run directory
  (names-only env record, per-stack flock, `list_runs`/`gc`), the sequential DAG runner (needs/when propagation,
  retry with transient regexes, Go-duration timeouts, typed inputs, `finally`, exit codes 0/1/3) and the `shell`
  executor; the reference project now uses a local backend so it validates and runs offline. `for_each`, `cache`,
  gate/resume and parallelism are deliberately not implemented yet.
- Skeleton: workflow models (Pydantic v2, discriminated step types, deny-floor `action` enum, cycle and
  output-reference checks, YAML 1.1 key guard), `codeorca validate`, `codeorca schema export [--check]`,
  the committed JSON Schema, the provider-free reference project, negative test cases, CI.
