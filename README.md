# code-orca

A text-only orchestrator that intermingles Terraform and Ansible: YAML workflows (a DAG of typed steps),
every non-destructive Terraform operation, Ansible steps fed from Terraform outputs, **resolved,
redacted configuration specs** rendered from Terraform plan/state JSON and from Ansible's own variable
resolution, and Python or PowerShell helpers where neither tool fits. It ships as one container
holding Terraform, Ansible, Python, PowerShell and itself.

Status: **Phase 1 (core, read-only).** Workflow and project models, the sequential DAG runner, the Terraform
adapter (init/validate/plan/show/output/providers schema/test; apply refused until the gate lands), the policy
floor and plan gate, the redaction pipeline, the Terraform plan-spec renderer and the `run`, `drift`, `doctor`,
`render`, `summary` commands. Ansible, helpers, the approval gate + apply, backend bootstrap and the container
follow (see `AGENTS.md`, TODO).

```bash
pip install -e '.[dev]'
codeorca validate examples/reference/workflows/*.yaml
codeorca schema export schema          # JSON Schema for editors (yaml-language-server modeline in the examples)
```

## Usage (Phase 1)

Every command that touches a project takes `-p/--project codeorca.yaml` (default `./codeorca.yaml`); paths in
the project file (`state_dir`, `specs_dir`, `workflows_dir`, `stacks.*.dir`) resolve against it. The HMAC key
for redaction placeholders comes from the environment variable **`CODEORCA_REDACTION_KEY`** in this phase (the
SSM-backed key named by `redaction.hmac_key` arrives in Phase 3); a project with `placeholder: hmac` refuses to
run without it. The reference project runs offline against a local backend with `terraform` on PATH:

```bash
export CODEORCA_REDACTION_KEY=example-not-secret-local            # any string; its id (not its value) lands in spec headers

codeorca run plan-only -p examples/reference/codeorca.yaml        # plan the app stack, render specs/app/plan.yaml, exit 0
codeorca run plan-only -p examples/reference/codeorca.yaml --input env=prod --dry-run
codeorca summary latest -p examples/reference/codeorca.yaml       # step table + outputs of a run (redacted content only)
codeorca render latest -p examples/reference/codeorca.yaml        # re-render every spec-render step from the run dir
TF_VAR_app_secret=FIXTURE-SECRET-reference-001 \
  codeorca drift -p examples/reference/codeorca.yaml              # plan every stack without locking: 0 clean, 2 drift, 1 error
codeorca doctor -p examples/reference/codeorca.yaml [--lock|--json]   # runtime: vs the environment; exit 1 on any mismatch
codeorca runs gc --keep 20 -p examples/reference/codeorca.yaml
```

- `run <workflow>` takes a file path or a name under `workflows_dir`; `--input k=v` sets a declared input. An
  input whose **name** matches `redaction.key_denylist` (`app_secret`, `api_token`, ...) is registered as a
  secret before anything is written, so it shows as `<redacted:key>` in `run.json` and its value is scrubbed from
  every log and spec. Exit codes: 0 ok, 1 a blocking failure, 3 waiting at a gate (Phase 3).
- The reference stack's `app_secret` variable is sensitive and has **no default**: `plan-only` passes it as a
  workflow input (default `FIXTURE-SECRET-reference-001`, a placeholder CI asserts never leaks) through
  `var_overrides`; `drift` carries no inputs, so it takes the variable from `TF_VAR_app_secret` (the executor
  registers every `TF_VAR_<name>` whose variable is declared sensitive **or** whose name matches
  `redaction.key_denylist` before Terraform starts; a value too short for the registry is listed under
  `unprotected_overrides` in the step result, never scrubbed).
- `drift` writes `<specs_dir>/<stack>/plan.yaml` + `plan.meta.yaml` for every stack in `depends_on` order and
  prints a verdict table. Consumers commit `specs/`; the reference project's are generated and gitignored.
- A spec body is deterministic (sorted keys, no run id, timestamp, duration or plan sha256: those live in the
  `.meta.yaml` sidecar) and headed by `codeorca: {pipeline, kind, workflow, stack, backend_key, engine, git_sha,
  redaction_key, gate}`. Sensitive values appear as `<redacted:hmac:8hex>` (stable per key and value, so a diff
  shows a secret *changed*), `(known after apply)` and `(sensitive)` are Terraform's own markers,
  `<never rendered: stack policy>` marks `never_render` entries and `<redacted:key>` a denylisted key.
- `doctor` compares `runtime:`: `terraform`, `ansible_core` and `collections` are exact pins; `python`, `pwsh` and
  `python_packages` accept `>=3.13,<3.14`, `7.6.*`, `==x` or `*`. `--lock` prints a `runtime:` block of what it
  observed (null for a missing tool).

## Principles (the short list)

- **Secrets never persist.** Terraform's JSON surfaces print sensitive values in clear text; the spec
  renderer redacts structurally (sensitivity maps, provider schema) and by value (a per-run secret
  registry) before anything is written, and a post-render gate fails on any hit.
- **The orchestrator is a policy enforcement point.** Destroy, state surgery, `-target`,
  `-auto-approve` and a bare apply are not expressible in a workflow; an apply consumes a reviewed plan
  file bound to a human approval on a terminal.
- **Config is YAML, validated fail-closed** against Pydantic models that also export the JSON Schema.
- **The execution environment is built elsewhere and verified here** (`codeorca doctor`).
- **Specs are deterministic and committed**, so `git diff specs/` is the change and drift record.

See `AGENTS.md` for conventions and the gotchas this design is built on.
