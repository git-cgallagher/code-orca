# code-orca

A text-only orchestrator that intermingles Terraform and Ansible: YAML workflows (a DAG of typed steps),
every non-destructive Terraform operation, Ansible steps fed from Terraform outputs, **resolved,
redacted configuration specs** rendered from Terraform plan/state JSON and from Ansible's own variable
resolution, and Python or PowerShell helpers where neither tool fits. It ships as one container
holding Terraform, Ansible, Python, PowerShell and itself.

Status: **Phase 3 (gates, apply, helpers, secrets, backend bootstrap).** Phase 1 (core, read-only): workflow and
project models, the sequential DAG runner, the Terraform adapter, the policy floor and plan gate, the redaction
pipeline, the Terraform plan-spec renderer and the `run`, `drift`, `doctor`, `render`, `summary` commands. Phase 2:
the `ansible` step (`ansible-playbook` with a redacting JSONL stdout callback), the Ansible host spec (inventory +
play scope) and `codeorca lint ansible`. Phase 3: the approval `gate` + `codeorca resume`, Terraform `apply` bound
to the approved plan's sha256, `migrate_backend`, the `python`/`powershell` helpers + `codeorca lint powershell`,
SSM secrets and the SSM-backed redaction key, and the S3 state-backend bootstrap. The container image follows (see
`AGENTS.md`, TODO).

```bash
pip install -e '.[dev,ansible,aws]'    # ansible-core 2.21 (Ansible steps) and boto3 (SSM, S3 bootstrap); tests
                                       # needing a missing extra, terraform or pwsh skip
codeorca validate examples/reference/workflows/*.yaml
codeorca schema export schema          # JSON Schema for editors (yaml-language-server modeline in the examples)
```

## Usage (Phase 1)

Every command that touches a project takes `-p/--project codeorca.yaml` (default `./codeorca.yaml`); paths in
the project file (`state_dir`, `specs_dir`, `workflows_dir`, `stacks.*.dir`) resolve against it. The HMAC key
for redaction placeholders is **`CODEORCA_REDACTION_KEY`** when that variable is set (SSM is then never called),
otherwise the SSM SecureString named by `redaction.hmac_key` (needs the `aws` extra and credentials; key id
`<ref>@<version>` in spec headers); a project with `placeholder: hmac` refuses to run when neither resolves. The
reference project runs offline against a local backend with `terraform` on PATH:

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
  every log and spec. Exit codes: 0 ok, 1 a blocking failure, 3 waiting at a gate.
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

## Usage (Phase 2: Ansible)

```bash
export CODEORCA_REDACTION_KEY=example-not-secret-local
codeorca run configure-local -p examples/reference/codeorca.yaml   # configure this host (connection: local), render
                                                                   # specs/app/hosts/app-host.yaml, exit 0
codeorca run configure-local -p examples/reference/codeorca.yaml --dry-run   # the play runs with --check --diff
codeorca render latest -p examples/reference/codeorca.yaml         # re-render the host spec from the run dir only
codeorca lint ansible -p examples/reference/codeorca.yaml examples/reference/ansible
```

An **`ansible` step** runs `playbook:` (project-relative) or `role:` (an FQCN or role name: the orchestrator
generates a one-task `import_role` play, `gather_facts` per the step's field, default true, with the project's
`roles/`/`collections/` linked next to it) against `inventory.inline:` (groups -> `hosts` -> host vars, values may be
`${{ … }}` expressions over Terraform outputs) or `inventory.path:`:

```yaml
- id: configure
  type: ansible
  playbook: ansible/site.yml                 # or: role: example.app.config
  inventory:
    inline: { app: { hosts: { app-host: { ansible_host: "${{ steps.apply_app.outputs.tf.app_host.value }}" } } } }
  extra_vars: { app_environment: "${{ inputs.env }}" }
  tags: [config]                             # also skip_tags, limit, check_unsupported: warn | fail | ignore
```

- `extra_vars` reach the play as a 0600 `-e @file` and the inline inventory as a 0600 YAML file, both under
  `<run>/handoff/<step>/` (0700) and deleted when the play ends; nothing travels on the command line or in the
  environment. A value whose key matches `redaction.key_denylist` (`app_api_token`, `ansible_password`) is
  registered before the play starts, and so is every literal denylist-named (or argument-spec `no_log`) value of
  the vars files the play reads (`group_vars`/`host_vars`, playbook `vars`/`vars_files`, role `defaults`/`vars`). The step keeps redacted copies (`inventory.yml`, `extra-vars.json`) in its
  step dir; its implicit output `inventory_path` names the inventory copy.
- Every line `ansible-playbook` prints goes through the redactor: the in-repo `codeorca_jsonl` stdout callback
  writes one JSON event per line to `events.jsonl`, everything else lands in `stderr.log`. The redaction key is
  dropped from the child environment and `ANSIBLE_DEBUG=False`, `ANSIBLE_LOG_PATH=/dev/null`,
  `ANSIBLE_VERBOSITY=0`, `ANSIBLE_KEEP_REMOTE_FILES=False` and `ANSIBLE_CALLBACKS_ENABLED=codeorca_jsonl` are
  forced (env beats a project `ansible.cfg`), so no aggregate callback (`profile_tasks`, `junit`) runs and
  `ansible.env` may not set any of them.
- Under `--dry-run` the play runs with `--check --diff`; a task Ansible skipped because its module cannot run in
  check mode is reported per `check_unsupported` (the stricter of the project's and the step's value).
- A role variable that carries a secret is declared `no_log: true` in the role's `meta/argument_specs.yml`; the
  host spec then shows `<secret: declared>` and never resolves it.

A **host spec** is a `spec-render` step with `source.ansible`:

```yaml
- id: host_spec
  type: spec-render
  source:
    ansible:
      inventory: "${{ steps.configure.outputs.inventory_path }}"   # or a project-relative inventory file
      host: app-host
      play_scope: { playbook: ansible/site.yml, vars: [app_listen_port, app_config_paths] }   # optional
      templates: [ansible/roles/app_config/templates/app.conf.j2]
  output: specs/app/hosts/app-host.yaml
```

- *Inventory scope*: every inventory variable of the host with `declared` (raw), `resolved` (templated key by
  key, native types: `"{{ 8000 + 80 }}"` -> `8080`), `source` (the `group_vars`/`host_vars` file, the inventory
  entry, or `extra_vars (step <id>)` for values the producing ansible step handed over, which outrank everything
  as `-e` does) and, for role variables, the argument spec's `type`/`description`/`default`/`role`.
  Playbook-adjacent `group_vars`/`host_vars` are read too when the inventory has none of its own.
- *Play scope* (`play_scope`): role defaults and vars, play vars, `vars_files` and the listed templates as the
  play sees them, from a generated check-mode play (`connection: local`, `--check --diff`, role tasks skipped,
  only the plays whose `hosts` target the host, no vault password) over an explicit allow list of variables, never
  `hostvars`. Entries carry `scope: inventory` or `scope: play`, and a play-scope value's `source` names where it
  came from (`role defaults: <role>`, `play vars: <playbook>`, `vars_files: <file>`, `role vars: <role>`). A
  playbook, role vars file or `vars_files` entry that is not YAML fails the step before anything runs; a failing
  template fails the step after the spec (with `errors.play`) is written.
- Markers instead of values: `<secret: declared>` (argument spec `no_log`, from any role), `<skipped: key matches
  denylist>` (a denylist-named var, or a denylist-named key anywhere inside a var's value), `<vault>` (never
  decrypted, in either scope), `<skipped: lookup <fqcn> is a secret source>` (`redaction.lookup_denylist`; the
  lookup never runs, in either scope, and a listed template whose own text calls one is that marker). Rendered
  templates appear as literal blocks with those markers in place.
- The redacted document is kept as `<run>/steps/<id>/host-vars.json`, which is what `codeorca render` re-renders
  from; the body is deterministic (no run id, project-relative paths) and the sidecar carries the run id.

`codeorca lint ansible <paths…> [-p codeorca.yaml]` checks playbooks and role task files (directories are
searched for `*.yml`/`*.yaml`, vars/meta/templates trees skipped) for `debug` of `hostvars`/`vars`, `debug` of a
secret-named variable, and a secret-named variable passed to a module parameter the module does not mark
`no_log`. It prints `file:line rule level message` and exits 1 on any finding above `info`. With `-p` it uses the
project's key and lookup denylists, otherwise the default key denylist.

## Usage (Phase 3: gates, apply, helpers, secrets, backend)

`demo-rollout` is the whole loop on the reference stack, offline: plan -> plan spec -> **gate** -> **apply** ->
Ansible on localhost from the outputs -> host spec -> a python and a powershell helper -> `finally` summary.

```bash
export CODEORCA_REDACTION_KEY=example-not-secret-local
codeorca run demo-rollout -p examples/reference/codeorca.yaml | cat   # no terminal: stops at the gate, exit 3
codeorca resume latest --approve -p examples/reference/codeorca.yaml  # on YOUR terminal: approve, apply, finish
codeorca resume latest --reject -p examples/reference/codeorca.yaml   # or reject: the apply and its dependents are omitted
codeorca run demo-rollout -p examples/reference/codeorca.yaml --dry-run   # gate auto-approved, apply skipped,
                                                                          # Ansible --check, helpers dry-run
codeorca lint powershell examples/reference/helpers [--ansible-settings]
```

**Gate and apply.** A `gate` step prints its message, the specs the run staged and every plan file with its
sha256, then asks `approve`/`reject` and its typed `fields` (`--field k=v` on `resume --approve`). It asks only
when stdin AND stdout are terminals. Without one (an agent, CI, a pipe) `non_interactive: wait` stops the run
(`run.json` status `waiting`, exit 3; `finally` does not run yet) and `non_interactive: fail` fails it.
`codeorca resume <run-id|latest> --approve|--reject` decides the gate **on a terminal only**: there is no flag or
environment variable that bypasses that check, for either decision. Secret inputs the remaining steps need
(recorded redacted) are asked for again on the terminal, not echoed, never taken from the command line. Resume
refuses a changed workflow, a gate older than `gate.max_age` and a plan file that changed or vanished since the gate
recorded it; completed steps are replayed, the rest run, `finally` runs once. A `terraform` `apply` step runs only
a plan file of this run whose sha256 an approving gate it needs recorded, re-checks the plan gate (with the gate's
`allow_delete_of`), deletes the plan file afterwards and retries only a lock-acquisition failure before any change.
`timeout` bounds the prompt; `on_timeout: fail|cancel|warn` never approves, and a cancelled gate fails the run
(exit 1). `--dry-run` auto-approves (recorded as `approver: dry-run`) and an apply then only reports the plan.

```yaml
- id: approve
  type: gate
  needs: [plan_spec]
  message: "Apply the app stack? Review ${{ steps.plan_spec.outputs.path }}"
  non_interactive: wait                       # exit 3 for an agent; resume on a terminal
  fields: { ticket: { type: string, required: true } }
- id: apply_app
  type: terraform
  needs: [approve]
  stack: app
  action: apply
  plan_file: "${{ steps.plan_app.outputs.plan_file }}"
```

**Helpers.** `python` (`[python, -I, script, *args]`, the interpreter running code-orca) and `powershell`
(`pwsh -NoProfile -NonInteractive -File script *args`, `-WhatIf` appended under `--dry-run`, which refuses a script
that does not declare `[CmdletBinding(SupportsShouldProcess)]`). `script:` is relative to the project root (also the
child's cwd) and must stay inside it; the result is the JSON the script writes to `$CODEORCA_OUTPUT_FILE`
(`result.output`), stdout/stderr are redacted logs; `CODEORCA_DRY_RUN=1` under `--dry-run`. `env:` values are
literals or `{secret: ssm:/path}`:

```yaml
- id: dns_check
  type: python
  script: helpers/check_dns.py
  args: ["--name", "localhost"]
  env: { EXAMPLE_API_TOKEN: { secret: "ssm:/example/app/api-token" } }   # SSM -> child env only, redacted
  outputs: { resolved: "${{ result.output.resolved }}" }
```

`codeorca lint powershell <paths…> [--ansible-settings]` runs PSScriptAnalyzer through `pwsh` (with
`--ansible-settings`, ansible-test's pslint rules, so a helper can move into an Ansible collection unchanged) and
exits 1 on any warning or error; missing `pwsh`/PSScriptAnalyzer is one `info` finding.

**SSM secrets.** `ssm:/path` references are fetched inside the process (time-limited, a wall-clock deadline
included, so a hung credential provider cannot hang the run), **registered with the redactor before the value is
returned**, cached in memory only and passed into a child's environment only: helper `env:` entries and a stack's
`secrets: {ENV_NAME: ssm:/path}` (into every terraform command's env for that stack, `drift` included; a name also
in `required_env` is satisfied by it). Without boto3 only a step that needs a secret fails, naming the `aws` extra.
AWS credentials themselves arrive as environment variables passed by name (`aws-vault exec`, SSO, OIDC in CI).

**Backend bootstrap** (s3 backends; plan 5.11). `codeorca run bootstrap-backend` (or
`python -m codeorca.bootstrap.s3 --project codeorca.yaml [--dry-run]`) refuses a caller outside
`backend.account_id`, creates the bucket if absent, converges public access block, versioning, encryption, a
TLS-only policy statement, a noncurrent-version lifecycle rule and a tag (refusing an Object Lock default retention),
writes each stack's `backend.hcl` and reports `{bucket, created, changed, diff, …}`; the workflow then runs
`terraform init` + `validate` per stack. `--dry-run` is the drift check: the diff, nothing written. Adopting a stack
with local state is an explicit `action: migrate_backend` step behind a gate (refused when the target already holds
a state).

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
