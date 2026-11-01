"""Placeholder executors for step types whose adapters land in later phases (or in the integration step).

Each one raises ``NotImplementedInPhase`` with a clear message; the runner turns that into an ``errored`` step
so a workflow that reaches such a step fails loudly instead of pretending to have run it.
"""

from __future__ import annotations

from codeorca.runner import Executor, NotImplementedInPhase, StepContext, StepResult


def executor_for(step_type: str) -> Executor:
    def _not_implemented(step, ctx: StepContext) -> StepResult:
        raise NotImplementedInPhase(
            f"step {step.id}: type {step_type!r} is not implemented in this phase "
            "(the adapter is registered by the integration step; see AGENTS.md TODO)"
        )

    _not_implemented.__name__ = f"not_implemented_{step_type.replace('-', '_')}"
    return _not_implemented
