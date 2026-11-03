"""The ``python`` helper step (plan section 5.8): ``[sys.executable, "-I", <script>, *args]``.

``-I`` is isolated mode: the script's own directory and the cwd are not put on ``sys.path`` (a ``json.py`` planted
next to a script that reads untrusted files is never imported), and ``PYTHON*`` variables and the user site are
ignored. The interpreter is the one running code-orca, so a helper may import what that environment has installed
(its site-packages), but not what ``PYTHONPATH`` or ``~/.local`` would add. Everything else (script path, env and
secrets, outputs, dry run, timeouts) is the shared contract in ``steps/helpers.py``.
"""

from __future__ import annotations

import sys
from collections.abc import Mapping
from pathlib import Path

from codeorca.redact import SecretRegistry
from codeorca.runner import Executor, StepContext, StepResult
from codeorca.steps.helpers import SecretResolver, run_helper


def build_argv(script: Path, args: list[str], ctx: StepContext, env: Mapping[str, str]) -> list[str]:
    return [sys.executable, "-I", str(script), *args]


def make_executor(registry: SecretRegistry, resolve_secret: SecretResolver | None = None) -> Executor:
    """The ``python`` executor bound to the run's registry and the SSM resolver (``None``: a step with a
    ``{secret: ...}`` env entry fails)."""

    def run_python(step, ctx: StepContext) -> StepResult:
        return run_helper(step, ctx, registry, resolve_secret, build_argv)

    run_python.__name__ = "run_python"
    return run_python
