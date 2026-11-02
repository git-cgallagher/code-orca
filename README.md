# code-orca

A text-only orchestrator that intermingles Terraform and Ansible: YAML workflows (a DAG of typed steps),
every non-destructive Terraform operation, Ansible steps fed from Terraform outputs, **resolved,
redacted configuration specs** rendered from Terraform plan/state JSON and from Ansible's own variable
resolution, and Python or PowerShell helpers where neither tool fits. It ships as one container
holding Terraform, Ansible, Python, PowerShell and itself.

Status: **Phase 2 (Ansible).** Phase 1 (core, read-only): workflow and project models, the sequential DAG
runner, the Terraform adapter (init/validate/plan/show/output/providers schema/test; apply refused until the gate
lands), the policy floor and plan gate, the redaction pipeline, the Terraform plan-spec renderer and the `run`,
`drift`, `doctor`, `render`, `summary` commands. Phase 2: the `ansible` step (`ansible-playbook` with a redacting
JSONL stdout callback), the Ansible host spec (inventory + play scope) and `codeorca lint ansible`. Helpers, the
approval gate + apply, backend bootstrap and the container follow (see `AGENTS.md`, TODO).

```bash
pip install -e '.[dev,ansible]'        # the ansible extra pins ansible-core 2.21; without it the Ansible tests skip
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
