"""Pydantic v2 models for the project file ``codeorca.yaml`` (plan section 5.2).

The project file is static configuration: no expressions, no secrets (only ``ssm:/`` references). Every model
is ``extra='forbid'`` so an unknown key fails instead of being ignored.

Rules baked in:
- ``max_parallel`` must be 1: v1 is strictly sequential (plan section 3).
- ``backend.type: s3`` requires ``bucket``, ``region`` and ``account_id``; ``local`` requires nothing.
- ``stacks.*.depends_on`` names must exist and form a DAG (``graphlib``).
- ``stacks.*.secrets`` values are ``ssm:/`` references, never values.
- ``redaction.placeholder: hmac`` requires ``hmac_key``.
"""

from __future__ import annotations

import graphlib
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, model_validator

from codeorca.config import load_yaml
from codeorca.models import Duration
from codeorca.policy import CRITICAL_TAG_PATTERN

SsmRef = Annotated[str, Field(pattern=r"^ssm:/.+")]


class Runtime(BaseModel):
    """The expected execution environment; ``codeorca doctor`` fails closed on any mismatch."""

    model_config = ConfigDict(extra="forbid")
    image: str
    terraform: str  # exact
    ansible_core: str  # exact
    python: str  # range allowed
    pwsh: str  # range allowed
    collections: dict[str, str] = {}  # exact pins
    python_packages: dict[str, str] = {}
    collections_from_file: str | None = None


class Backend(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["s3", "local"]
    account_id: Annotated[str, Field(pattern=r"^\d{12}$")] | None = None
    bucket: str | None = None
    region: str | None = None
    encryption: Annotated[str, Field(pattern=r"^(aes256|kms:.+)$")] = "aes256"
    locking: Literal["lockfile"] = "lockfile"
    noncurrent_version_expiry_days: int = Field(default=90, ge=1)

    @model_validator(mode="after")
    def _s3_fields(self):
        if self.type == "s3":
            missing = [k for k in ("bucket", "region", "account_id") if getattr(self, k) is None]
            if missing:
                raise ValueError(f"backend type s3 requires {', '.join(missing)}")
        return self


class NeverRender(BaseModel):
    """Values dropped before redaction; the name is kept and shown as ``<never rendered: stack policy>``."""

    model_config = ConfigDict(extra="forbid")
    outputs: list[str] = []
    resources: list[str] = []


class Stack(BaseModel):
    model_config = ConfigDict(extra="forbid")
    dir: str
    key: str
    aws_profile: str | None = None
    tfvars_committed: bool = True
    state_specs: bool = False
    never_render: NeverRender = NeverRender()
    plan_lock: bool = False
    depends_on: list[str] = []
    required_env: list[str] = []
    secrets: dict[str, SsmRef] = {}


class Policy(BaseModel):
    """Can only NARROW the code-level deny floor (plan section 5.4)."""

    model_config = ConfigDict(extra="forbid")
    stateful_types: list[str] = []
    critical_tag: str = Field(default="critical=true", pattern=CRITICAL_TAG_PATTERN)  # key exact, value case-folded
    transient_errors: list[str] = []  # regexes matched against a step's error text for ``retry.policy: transient``
    profile_allows: dict[str, dict[str, bool]] = {}


class Redaction(BaseModel):
    model_config = ConfigDict(extra="forbid")
    placeholder: Literal["hmac", "sha256"] = "hmac"
    hmac_key: SsmRef | None = None
    key_denylist: list[str] = []
    lookup_denylist: list[str] = []

    @model_validator(mode="after")
    def _hmac_needs_key(self):
        if self.placeholder == "hmac" and not self.hmac_key:
            raise ValueError("redaction.placeholder hmac requires hmac_key (an ssm:/ reference)")
        return self


class AnsibleConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    env: dict[str, str] = {}
    check_unsupported: Literal["warn", "fail", "ignore"] = "warn"


class GateConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_age: Duration = "24h"


class Project(BaseModel):
    model_config = ConfigDict(extra="forbid")
    api: Literal["codeorca/v1"]
    project: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    runtime: Runtime
    state_dir: str = ".codeorca/runs"
    specs_dir: str = "specs"
    max_parallel: int = 1
    backend: Backend
    stacks: dict[str, Stack] = {}
    policy: Policy = Policy()
    redaction: Redaction  # required: a project states its redaction policy explicitly
    ansible: AnsibleConfig = AnsibleConfig()
    gate: GateConfig = GateConfig()
    workflows_dir: str = "workflows"

    # Directory the project file was loaded from; relative paths (state_dir, stacks.*.dir) resolve against it.
    _root: Path | None = PrivateAttr(default=None)

    @property
    def root(self) -> Path | None:
        return self._root

    @model_validator(mode="after")
    def _rules(self):
        if self.max_parallel != 1:
            raise ValueError("max_parallel must be 1 in v1 (strictly sequential; see the plan, section 3)")
        for name, stack in self.stacks.items():
            for dep in stack.depends_on:
                if dep not in self.stacks:
                    raise ValueError(f"stacks.{name}: depends_on unknown stack {dep!r}")
                if dep == name:
                    raise ValueError(f"stacks.{name}: depends on itself")
        try:
            tuple(graphlib.TopologicalSorter({n: set(s.depends_on) for n, s in self.stacks.items()}).static_order())
        except graphlib.CycleError as e:
            raise ValueError(f"stacks: dependency cycle: {e.args[1]}") from None
        return self

    def stack_order(self) -> tuple[str, ...]:
        """Stack names in ``depends_on`` order (for ``codeorca drift`` and multi-stack workflows)."""
        return tuple(graphlib.TopologicalSorter({n: set(s.depends_on) for n, s in self.stacks.items()}).static_order())


def load_project(path: str | Path) -> Project:
    path = Path(path)
    project = Project.model_validate(load_yaml(path))
    project._root = path.resolve().parent
    return project


def project_json_schema() -> dict:
    schema = Project.model_json_schema(by_alias=True)
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    return schema
