"""Pydantic v2 models for code-orca workflow files: the single source of truth for validation and the JSON Schema.

Design rules baked in here (see AGENTS.md):
- ``extra='forbid'`` everywhere: an unknown key is an error, never silently ignored.
- Step types are a discriminated union on ``type``.
- The Terraform ``action`` enum is the deny floor: destroy, import, state surgery, -target and -auto-approve
  are not expressible in a ``terraform`` step at all. A helper (``shell`` today, ``python``/``powershell`` later)
  is trusted code and may run any program; the ``shell`` executor still runs ``policy.check_argv`` over an argv
  whose program is ``terraform``/``tofu``, so the literal ``run: [terraform, destroy]`` is refused too.
- ``apply`` requires a ``plan_file``: a bare apply is denied.
- Cross-step output references (``${{ steps.x.outputs.y }}``) must name a declared output of a step this step
  (transitively) needs, so a typo fails at validation instead of at run time under StrictUndefined.
- YAML 1.1 boolean tokens (``on``, ``off``, ``yes``, ``no``) are rejected as keys even though the loader is YAML 1.2.
"""

from __future__ import annotations

import graphlib
import re
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

Duration = Annotated[str, Field(pattern=r"^\d+(ns|us|ms|s|m|h)(\d+(ns|us|ms|s|m|h))*$")]
STEP_REF = re.compile(r"steps\.([A-Za-z_][A-Za-z0-9_]*)\.outputs\.([A-Za-z_][A-Za-z0-9_]*)")
YAML11_BOOL_KEYS = frozenset({"on", "off", "yes", "no", "y", "n", "true", "false"})


class Backoff(BaseModel):
    """``duration * factor ** (attempt - 1)``, capped at ``max_duration``; durations are Go strings or seconds."""

    model_config = ConfigDict(extra="forbid")
    duration: Duration | float = 0.0
    factor: float = 1.0
    max_duration: Duration | float | None = None


class Retry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    limit: int = 0
    policy: Literal["failure", "error", "transient"] = "failure"  # not `on`: YAML 1.1 reads that key as True
    backoff: Backoff = Backoff()


class StepBase(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    needs: list[str] = []
    when: str | None = None
    timeout: Duration | None = None
    retry: Retry = Retry()
    on_failure: Literal["fail", "continue"] = "fail"
    for_each: list[object] | None = None
    outputs: dict[str, str] = {}
    cache: dict | None = None

    @model_validator(mode="after")
    def _no_retry_with_continue(self):
        if self.on_failure == "continue" and self.retry.limit:
            raise ValueError("retry and on_failure: continue cannot be combined")
        return self


class Terraform(StepBase):
    type: Literal["terraform"]
    stack: str
    # Deliberately no destroy / import / state / taint: the deny floor (AGENTS.md).
    action: Literal["plan", "apply", "output", "validate", "test", "migrate_backend"] = "plan"
    plan_file: str | None = None
    var_overrides: dict[str, object] = {}

    @model_validator(mode="after")
    def _apply_needs_plan_file(self):
        if self.action == "apply" and not self.plan_file:
            raise ValueError("apply requires plan_file (a bare apply is denied)")
        return self


class Inventory(BaseModel):
    model_config = ConfigDict(extra="forbid")
    inline: dict[str, object] | None = None
    path: str | None = None

    @model_validator(mode="after")
    def _one_of(self):
        if bool(self.inline) == bool(self.path):
            raise ValueError("inventory needs exactly one of inline or path")
        return self


class Ansible(StepBase):
    type: Literal["ansible"]
    playbook: str | None = None
    role: str | None = None  # FQCN; the orchestrator generates a one-task import_role play
    inventory: Inventory
    extra_vars: dict[str, object] = {}
    tags: list[str] = []
    skip_tags: list[str] = []
    limit: str | None = None
    check_unsupported: Literal["warn", "fail", "ignore"] = "warn"
    # role steps only: the generated play's gather_facts (default true, as Ansible's own); a playbook sets its own
    gather_facts: bool | None = None

    @model_validator(mode="after")
    def _playbook_xor_role(self):
        if bool(self.playbook) == bool(self.role):
            raise ValueError("ansible step needs exactly one of playbook or role")
        if self.playbook and self.gather_facts is not None:
            raise ValueError("gather_facts is for role steps; a playbook sets gather_facts in its own plays")
        return self


class SecretRef(BaseModel):
    model_config = ConfigDict(extra="forbid")
    secret: str = Field(pattern=r"^ssm:/.+")


class Helper(StepBase):
    script: str
    args: list[str] = []
    env: dict[str, str | SecretRef] = {}


class Python(Helper):
    type: Literal["python"]


class PowerShell(Helper):
    type: Literal["powershell"]


class Shell(StepBase):
    type: Literal["shell"]
    run: list[str]  # argv array, never a shell string


class Gate(StepBase):
    type: Literal["gate"]
    message: str
    on_timeout: Literal["fail", "cancel", "warn"] = "fail"
    non_interactive: Literal["wait", "fail"] = "wait"
    allow_delete_of: list[str] = []
    fields: dict[str, dict] = {}


class PlayScope(BaseModel):
    model_config = ConfigDict(extra="forbid")
    playbook: str
    vars: list[str]  # explicit list; never hostvars[...] wholesale


class AnsibleSource(BaseModel):
    model_config = ConfigDict(extra="forbid")
    inventory: str
    host: str
    play_scope: PlayScope | None = None
    templates: list[str] = []


class SpecSource(BaseModel):
    model_config = ConfigDict(extra="forbid")
    terraform_plan: str | None = None
    terraform_state: str | None = None
    ansible: AnsibleSource | None = None

    @model_validator(mode="after")
    def _one_of(self):
        if sum(x is not None for x in (self.terraform_plan, self.terraform_state, self.ansible)) != 1:
            raise ValueError("spec-render source needs exactly one of terraform_plan, terraform_state, ansible")
        return self


class SpecRender(StepBase):
    type: Literal["spec-render"]
    source: SpecSource
    output: str


Step = Annotated[
    Terraform | Ansible | Python | PowerShell | Shell | Gate | SpecRender,
    Field(discriminator="type"),
]

# Outputs every step type exposes without declaring them.
IMPLICIT_OUTPUTS: dict[str, frozenset[str]] = {
    "terraform": frozenset({"stack"}),
    "ansible": frozenset({"inventory_path"}),
    "spec-render": frozenset({"path"}),
    "gate": frozenset({"approved", "approver"}),
    "python": frozenset(),
    "powershell": frozenset(),
    "shell": frozenset(),
}


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["string", "int", "bool", "list", "map"]
    default: object = None
    enum: list[object] | None = None
    required: bool = False


def _walk_strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, bool) or (isinstance(k, str) and k.lower() in YAML11_BOOL_KEYS):
                raise ValueError(f"key {k!r} is a YAML 1.1 boolean token; quote it or rename it")
            yield from _walk_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk_strings(v)


def _ancestors(graph: dict[str, set[str]], sid: str) -> set[str]:
    seen: set[str] = set()
    stack = list(graph.get(sid, ()))
    while stack:
        n = stack.pop()
        if n not in seen:
            seen.add(n)
            stack.extend(graph.get(n, ()))
    return seen


class Workflow(BaseModel):
    model_config = ConfigDict(extra="forbid")
    api: Literal["codeorca/v1"]
    kind: Literal["workflow"]
    name: str
    description: str = ""
    inputs: dict[str, Input] = {}
    vars: dict[str, object] = {}
    fail_fast: bool = True
    steps: list[Step]
    finally_: list[Step] = Field(default=[], alias="finally")

    def graph(self) -> dict[str, set[str]]:
        return {s.id: set(s.needs) for s in self.steps}

    def order(self) -> tuple[str, ...]:
        return tuple(graphlib.TopologicalSorter(self.graph()).static_order())

    @model_validator(mode="after")
    def _dag_and_refs(self):
        ids = [s.id for s in self.steps]
        seen: set[str] = set()
        for sid in [*ids, *(s.id for s in self.finally_)]:
            if sid in seen:
                raise ValueError(f"duplicate step id {sid!r}")
            seen.add(sid)
        graph = self.graph()
        for s in self.steps:
            for n in s.needs:
                if n not in ids:
                    raise ValueError(f"{s.id}: needs unknown step {n}")
        for s in self.finally_:
            if s.needs:
                # finally steps always run after the main graph; their status functions describe the run
                raise ValueError(f"finally step {s.id}: needs is not allowed on a finally step (they always run last)")
        outputs_written: dict[str, str] = {}
        for s in [*self.steps, *self.finally_]:
            if s.type == "spec-render":
                other = outputs_written.setdefault(s.output, s.id)
                if other != s.id:
                    raise ValueError(f"spec-render output {s.output!r} is written by steps {other} and {s.id}")
        try:
            tuple(graphlib.TopologicalSorter(graph).static_order())
        except graphlib.CycleError as e:
            raise ValueError(f"dependency cycle: {e.args[1]}") from None
        declared = {s.id: set(s.outputs) | IMPLICIT_OUTPUTS[s.type] for s in self.steps}
        for s in [*self.steps, *self.finally_]:
            for text in _walk_strings(s.model_dump(by_alias=True, exclude={"outputs"})):
                for sid, out in STEP_REF.findall(text):
                    if sid not in declared:
                        raise ValueError(f"{s.id}: references unknown step {sid}")
                    if out not in declared[sid]:
                        raise ValueError(
                            f"{s.id}: step {sid} declares no output {out!r} (declared: {sorted(declared[sid])})"
                        )
                    if s in self.steps and sid != s.id and sid not in _ancestors(graph, s.id):
                        raise ValueError(
                            f"{s.id}: references {sid}.outputs.{out} but does not (transitively) need {sid}"
                        )
        return self


def workflow_json_schema() -> dict:
    schema = Workflow.model_json_schema(by_alias=True)
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"  # Pydantic omits it; editors want it
    return schema
