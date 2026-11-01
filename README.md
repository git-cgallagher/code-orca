# code-orca

A text-only orchestrator that intermingles Terraform and Ansible: YAML workflows (a DAG of typed steps),
every non-destructive Terraform operation, Ansible steps fed from Terraform outputs, **resolved,
redacted configuration specs** rendered from Terraform plan/state JSON and from Ansible's own variable
resolution, and Python or PowerShell helpers where neither tool fits. It ships as one container
holding Terraform, Ansible, Python, PowerShell and itself.

Status: **Phase 0 skeleton.** Workflow models, validation and the JSON Schema exist; the run engine,
Terraform and Ansible adapters, spec renderer, redaction pipeline and container follow in later phases.

```bash
pip install -e '.[dev]'
codeorca validate examples/reference/workflows/demo-rollout.yaml
codeorca schema export schema          # JSON Schema for editors (yaml-language-server modeline in the examples)
```

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
