"""Step executors: one callable per step ``type`` (``Executor = (step, StepContext) -> StepResult``).

``register(type, executor)`` / ``lookup(type)`` form a plain process-wide registry; ``default_executors()``
returns the set this phase ships: a real ``shell`` executor and a "not implemented in this phase" placeholder
for every other type (integration replaces those by registering the adapters).
"""

from __future__ import annotations

from codeorca.runner import Executor
from codeorca.steps import not_implemented, shell

_REGISTRY: dict[str, Executor] = {}

STEP_TYPES = ("terraform", "ansible", "python", "powershell", "shell", "gate", "spec-render")


def register(step_type: str, executor: Executor) -> None:
    if step_type not in STEP_TYPES:
        raise ValueError(f"unknown step type {step_type!r}; known: {', '.join(STEP_TYPES)}")
    _REGISTRY[step_type] = executor


def lookup(step_type: str) -> Executor:
    try:
        return _REGISTRY[step_type]
    except KeyError:
        raise KeyError(f"no executor registered for step type {step_type!r}") from None


def registered() -> dict[str, Executor]:
    return dict(_REGISTRY)


def default_executors() -> dict[str, Executor]:
    """The phase-1 set: real ``shell``, placeholders for the rest. Does not touch the registry."""
    executors: dict[str, Executor] = {t: not_implemented.executor_for(t) for t in STEP_TYPES}
    executors["shell"] = shell.run_shell
    return executors


for _type, _executor in default_executors().items():
    _REGISTRY.setdefault(_type, _executor)
