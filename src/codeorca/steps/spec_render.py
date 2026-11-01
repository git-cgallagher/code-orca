"""The ``spec-render`` step: pure file to file, no subprocess.

``source.terraform_plan`` names the **redacted** plan document a ``terraform`` plan step wrote (``plan.json`` under
its step dir). It is rendered to ``output`` (relative to the project root) with its ``.meta.yaml`` sidecar, and a
copy of both is staged under ``<run_dir>/specs/``. The implicit output ``path`` is the written spec's path.
``terraform_state`` and ``ansible`` sources arrive in later phases.

``codeorca render <run-id>`` re-renders every spec-render step of a run from the run directory with
``render_run``, which is the same function the executor uses.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from codeorca.config import load_workflow
from codeorca.expr import ExpressionError, render_value
from codeorca.project import Project
from codeorca.redact import SecretRegistry
from codeorca.rundir import RunDir
from codeorca.runner import Executor, NotImplementedInPhase, StepContext, StepError, StepResult
from codeorca.specs import META_KEY, SpecGateError, write_spec
from codeorca.specs.terraform_plan import header_for


def make_executor(registry: SecretRegistry) -> Executor:
    def run_spec_render(step, ctx: StepContext) -> StepResult:
        return execute(step, ctx, registry)

    run_spec_render.__name__ = "run_spec_render"
    return run_spec_render


def _read_document(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise StepError(f"spec-render: source {path} does not exist") from None
    except ValueError as e:
        raise StepError(f"spec-render: source {path} is not JSON: {e}") from None
    if not isinstance(document, dict) or document.get("kind") != "terraform_plan":
        raise StepError(f"spec-render: {path} is not a terraform_plan document written by a terraform plan step")
    return document


def render_plan_spec(
    source: Path,
    output: Path,
    run_dir: RunDir,
    registry: SecretRegistry,
    *,
    git_sha: str | None,
    workflow: str | None,
    project: Project | None,
) -> dict[str, Any]:
    """Render one redacted plan document to ``output`` and stage a copy under the run dir's ``specs/``."""
    document = _read_document(source)
    stack_name = str(document.get("stack", ""))
    backend_key = None
    if project is not None and stack_name in project.stacks:
        backend_key = project.stacks[stack_name].key
    header = header_for(document, registry.key_id, git_sha, workflow=workflow, backend_key=backend_key)
    meta = dict(document.get(META_KEY) or {})
    meta.setdefault("run_id", run_dir.run_id)
    try:
        meta["source"] = (
            source.resolve().relative_to(run_dir.path.resolve()).as_posix()
        )  # no workstation path in a committed file
    except ValueError:
        meta["source"] = source.name
    try:
        spec_path, sidecar = write_spec(output, document, header, meta, registry)
    except SpecGateError as e:
        raise StepError(str(e)) from None
    staged_dir = run_dir.specs_dir / stack_name
    staged_dir.mkdir(parents=True, exist_ok=True)
    staged = [shutil.copy2(p, staged_dir / p.name) for p in (spec_path, sidecar)]
    return {
        "path": str(spec_path),
        "source": str(source),
        "meta_path": str(sidecar),
        "staged": [str(p) for p in staged],
        "stack": stack_name,
        "gate": header["gate"],
    }


def _output_path(project: Project | None, output: str) -> Path:
    out = Path(str(output))
    if out.is_absolute():
        return out
    root = project.root if project is not None and project.root is not None else Path.cwd()
    return root / out


def execute(step, ctx: StepContext, registry: SecretRegistry) -> StepResult:
    source = step.source
    if source.terraform_plan is None:
        kind = "terraform_state" if source.terraform_state is not None else "ansible"
        raise NotImplementedInPhase(f"step {step.id}: spec-render source {kind!r} is not implemented in this phase")
    run = ctx.run_dir.read_run() or {}
    result = render_plan_spec(
        Path(str(source.terraform_plan)),
        _output_path(ctx.project, step.output),
        ctx.run_dir,
        registry,
        git_sha=run.get("git_sha"),
        workflow=run.get("workflow"),
        project=ctx.project,
    )
    return StepResult("succeeded", outputs={"path": result["path"]}, result=result)


def render_run(
    project: Project, run_dir: RunDir, registry: SecretRegistry, workflow_file: Path
) -> list[dict[str, Any]]:
    """Re-render every ``spec-render`` step of a finished run from its run directory (``codeorca render``).

    The step's ``source.terraform_plan`` expression is evaluated against the run record (inputs, vars, step
    outputs), exactly as the runner did, so it resolves to the same ``plan.json`` under the run dir.
    """
    run = run_dir.read_run()
    if run is None:
        raise StepError(f"run {run_dir.run_id}: no run.json under {run_dir.path}")
    workflow = load_workflow(workflow_file)
    context = {
        "inputs": run.get("inputs") or {},
        "vars": run.get("vars") or {},
        "steps": {
            sid: {"status": st.get("status"), "outputs": st.get("outputs")}
            for sid, st in (run.get("steps") or {}).items()
        },
        "run": {"id": run_dir.run_id, "status": run.get("status"), "dir": str(run_dir.path), "dry_run": False},
        "project": project.project,
    }
    rendered: list[dict[str, Any]] = []
    for step in workflow.steps:
        if step.type != "spec-render" or step.source.terraform_plan is None:
            continue
        try:
            source = render_value(step.source.terraform_plan, context)
        except ExpressionError as e:
            rendered.append({"step": step.id, "skipped": f"source not resolvable from the run record: {e}"})
            continue
        if not source:
            rendered.append({"step": step.id, "skipped": "the producing step has no plan_json output in this run"})
            continue
        result = render_plan_spec(
            Path(str(source)),
            _output_path(project, step.output),
            run_dir,
            registry,
            git_sha=run.get("git_sha"),
            workflow=run.get("workflow"),
            project=project,
        )
        rendered.append({"step": step.id, **result})
    return rendered
