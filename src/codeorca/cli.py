"""codeorca command line (plan section 5.1).

Phase 1 ships ``validate``, ``schema export``, ``run``, ``drift``, ``doctor``, ``render``, ``summary`` and
``runs gc``. ``resume`` arrives with the gate (Phase 3). Every command that touches a project takes
``-p/--project codeorca.yaml`` (default: ``./codeorca.yaml``); paths in the project file resolve against it.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from collections.abc import Mapping
from contextlib import ExitStack
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from codeorca import __version__
from codeorca.config import load_workflow
from codeorca.models import workflow_json_schema
from codeorca.project import Project, load_project, project_json_schema

EXIT_DRIFT = 2


class CliError(RuntimeError):
    """A user-facing failure: printed to stderr, exit 1, no traceback."""


# ----------------------------------------------------------------------------------------------- helpers


def _project(args: argparse.Namespace) -> Project:
    path = Path(args.project)
    if not path.is_file():
        raise CliError(f"project file {path} not found (use -p/--project)")
    try:
        return load_project(path)
    except ValidationError as e:
        raise CliError(f"{path}: INVALID\n{e}") from None


def _workflow_file(project: Project, name_or_path: str) -> Path:
    candidate = Path(name_or_path)
    if candidate.is_file():
        return candidate
    assert project.root is not None
    by_name = project.root / project.workflows_dir / f"{name_or_path}.yaml"
    if by_name.is_file():
        return by_name
    raise CliError(f"workflow {name_or_path!r}: neither a file nor {by_name}")


def _parse_inputs(pairs: list[str]) -> dict[str, str]:
    inputs: dict[str, str] = {}
    for pair in pairs:
        key, sep, value = pair.partition("=")
        if not sep or not key:
            raise CliError(f"--input expects k=v, got {pair!r}")
        inputs[key] = value
    return inputs


def _table(rows: list[list[str]], header: list[str]) -> str:
    all_rows = [header, *rows]
    widths = [max(len(str(r[i])) for r in all_rows) for i in range(len(header))]
    return "\n".join("  ".join(str(c).ljust(widths[i]) for i, c in enumerate(r)).rstrip() for r in all_rows)


def _registry(project: Project, env: Mapping[str, str]):
    from codeorca.secrets import RedactionKeyMissing, build_registry

    try:
        return build_registry(project, env)
    except RedactionKeyMissing as e:
        raise CliError(str(e)) from None


def _executors(registry) -> dict:
    from codeorca.steps import default_executors
    from codeorca.steps import spec_render as spec_render_step
    from codeorca.steps import terraform as terraform_step

    executors = default_executors()
    executors["terraform"] = terraform_step.make_executor(registry)
    executors["spec-render"] = spec_render_step.make_executor(registry)
    # passed to Runner explicitly, never register()ed process-wide: the executors close over this run's registry
    return executors


def _state_dir(project: Project) -> Path:
    assert project.root is not None
    return project.root / project.state_dir


# ---------------------------------------------------------------------------------------------- commands


def cmd_validate(args: argparse.Namespace) -> int:
    rc = 0
    for path in args.files:
        try:
            wf = load_workflow(path)
        except ValidationError as e:
            print(f"{path}: INVALID\n{e}", file=sys.stderr)
            rc = 1
            continue
        except Exception as e:  # noqa: BLE001 - a CLI reports, it does not crash
            print(f"{path}: ERROR {type(e).__name__}: {e}", file=sys.stderr)
            rc = 1
            continue
        order = " -> ".join(wf.order())
        print(f"{path}: OK {wf.name}: {len(wf.steps)} steps, {len(wf.finally_)} finally; order = {order}")
    return rc


def cmd_schema_export(args: argparse.Namespace) -> int:
    out = Path(args.dir)
    out.mkdir(parents=True, exist_ok=True)
    targets = {
        out / "codeorca-workflow.schema.json": json.dumps(workflow_json_schema(), indent=2) + "\n",
        out / "codeorca-project.schema.json": json.dumps(project_json_schema(), indent=2) + "\n",
    }
    rc = 0
    for target, text in targets.items():
        if args.check:
            if not target.exists() or target.read_text(encoding="utf-8") != text:
                print(f"{target}: out of date; run `codeorca schema export {out}`", file=sys.stderr)
                rc = 1
            else:
                print(f"{target}: up to date")
            continue
        target.write_text(text, encoding="utf-8")
        print(f"wrote {target}")
    return rc


def cmd_run(args: argparse.Namespace) -> int:
    from codeorca.rundir import RunDir
    from codeorca.runner import EXIT_FAILED, InputError, RunError, Runner, resolve_inputs
    from codeorca.secrets import key_denylist, line_hook, record_filter, seed_inputs

    project = _project(args)
    path = _workflow_file(project, args.workflow)
    try:
        workflow = load_workflow(path)
    except ValidationError as e:
        raise CliError(f"{path}: INVALID\n{e}") from None
    env = dict(os.environ)
    registry = _registry(project, env)
    try:
        inputs = resolve_inputs(workflow, _parse_inputs(args.input))
    except InputError as e:
        raise CliError(str(e)) from None
    denylist = key_denylist(project)
    seed_inputs(registry, inputs, denylist)  # before the first persist: run.json carries the inputs
    run_dir = RunDir(_state_dir(project))
    try:
        runner = Runner(
            project,
            workflow,
            inputs,
            run_dir,
            _executors(registry),
            dry_run=args.dry_run,
            env=env,
            stream=line_hook(registry),
            redact=record_filter(registry, denylist),
            cwd=project.root,
        )
    except RunError as e:
        shutil.rmtree(run_dir.path, ignore_errors=True)  # nothing ran and no run.json exists: leave no empty run
        raise CliError(str(e)) from None
    print(f"run {run_dir.run_id}: {workflow.name} ({path}){' [dry-run]' if args.dry_run else ''}")
    try:
        code = runner.run()
    except KeyboardInterrupt:
        print(f"run {run_dir.run_id}: interrupted", file=sys.stderr)
        return EXIT_FAILED
    print(_status_table(runner.record(finished=True), registry))
    print(f"run {run_dir.run_id}: {runner.status} (exit {code}); run dir {run_dir.path}")
    return code


def _status_table(record: Mapping[str, Any], registry=None) -> str:
    rows = []
    for sid, st in (record.get("steps") or {}).items():
        error = st.get("error") or ""
        if registry is not None:
            error = registry.redact(error)
        rows.append([sid, str(st.get("status")), str(st.get("attempts", 0)), error.splitlines()[0] if error else ""])
    return _table(rows, ["step", "status", "attempts", "error"])


def cmd_drift(args: argparse.Namespace) -> int:
    from codeorca.adapters.terraform import TerraformError
    from codeorca.policy import PolicyError
    from codeorca.rundir import RunDir
    from codeorca.runner import StepError, _git_sha
    from codeorca.steps.spec_render import render_plan_spec
    from codeorca.steps.terraform import open_session, plan_stack

    project = _project(args)
    env = dict(os.environ)
    registry = _registry(project, env)
    wanted = list(args.stack) if args.stack else list(project.stack_order())
    unknown = sorted(set(wanted) - set(project.stacks))
    if unknown:
        raise CliError(f"unknown stack(s): {', '.join(unknown)}")
    run_dir = RunDir(_state_dir(project))
    git_sha = _git_sha(project.root)
    assert project.root is not None
    record: dict[str, Any] = {
        "run_id": run_dir.run_id,
        "codeorca": __version__,
        "kind": "drift",
        "project": project.project,
        "git_sha": git_sha,
        "started": datetime.now(UTC).isoformat(timespec="seconds"),
        "stacks": {},
    }
    run_dir.write_run(record)
    rows: list[list[str]] = []
    worst = 0
    for name in wanted:
        step_id = f"drift_{name}"
        step_dir = run_dir.step_dir(step_id)
        verdict, detail, spec = "error", "", ""
        try:
            with ExitStack() as resources:
                session = open_session(project, name, registry, step_dir, env, resources, lock=False)
                try:
                    session.init()
                    outcome = plan_stack(session, lock=False, run_id=run_dir.run_id, step_id=step_id)
                finally:
                    session.record()
            if outcome.exit_code == 1:
                detail = outcome.error or "plan failed"
            else:
                rendered = render_plan_spec(
                    Path(outcome.plan_json),
                    project.root / project.specs_dir / name / "plan.yaml",
                    run_dir,
                    registry,
                    git_sha=git_sha,
                    workflow=None,
                    project=project,
                )
                spec = rendered["path"]
                counts = outcome.result["summary"]["counts"]
                verdict = "drift" if outcome.changed else "clean"
                detail = ", ".join(f"{k} {v}" for k, v in counts.items() if v) or "no changes"
                if not outcome.result["gate"]["passed"]:
                    detail += "; gate blocked"
        except (StepError, TerraformError, PolicyError, OSError, ValueError) as e:
            # engine missing, init/show failure, a credential-looking backend key, a locked stack: a verdict row
            detail = registry.redact(str(e)).splitlines()[0]
        code = {"clean": 0, "drift": EXIT_DRIFT, "error": 1}[verdict]
        worst = 1 if 1 in (worst, code) else max(worst, code)
        record["stacks"][name] = {"verdict": verdict, "detail": detail, "spec": spec}
        run_dir.write_run(record)
        rows.append([name, verdict, detail.splitlines()[0] if detail else "", spec])
    record["finished"] = datetime.now(UTC).isoformat(timespec="seconds")
    record["exit_code"] = worst
    run_dir.write_run(record)
    print(_table(rows, ["stack", "verdict", "detail", "spec"]))
    print(f"drift {run_dir.run_id}: exit {worst} (0 clean, 2 drift, 1 error)")
    return worst


def cmd_doctor(args: argparse.Namespace) -> int:
    from codeorca.doctor import format_lock, format_table, run_checks

    project = _project(args)
    checks, observed = run_checks(project.runtime)
    ok = all(c.ok for c in checks)
    if args.json:
        print(json.dumps({"ok": ok, "checks": [c.as_dict() for c in checks], "observed": observed}, indent=2))
    else:
        print(format_table(checks))
        print("doctor: ok" if ok else "doctor: MISMATCH (exit 1)", file=sys.stderr if not ok else sys.stdout)
    if args.lock:
        print(format_lock(observed), end="")
    return 0 if ok else 1


def cmd_render(args: argparse.Namespace) -> int:
    from codeorca.runner import StepError
    from codeorca.steps.spec_render import render_run

    project = _project(args)
    run_dir = _existing_run(project, args.run_id)
    run = run_dir.read_run() or {}
    env = dict(os.environ)
    registry = _registry(project, env)
    workflow_name = args.workflow or run.get("workflow")
    if not workflow_name:
        raise CliError(f"run {args.run_id}: no workflow recorded; pass --workflow")
    try:
        rendered = render_run(project, run_dir, registry, _workflow_file(project, workflow_name))
    except StepError as e:
        raise CliError(registry.redact(str(e))) from None
    rows = [[r["step"], r.get("path") or "-", r.get("gate") or "-", r.get("skipped") or ""] for r in rendered]
    print(_table(rows, ["step", "spec", "gate", "note"]))
    return 0 if rendered and not any("skipped" in r for r in rendered) else 1


def _existing_run(project: Project, run_id: str):
    from codeorca.rundir import RunDir, list_runs

    state_dir = _state_dir(project)
    if run_id == "latest":
        runs = list_runs(state_dir)
        if not runs:
            raise CliError(f"no runs under {state_dir}")
        # ids order by second only; two runs in one second are told apart by their recorded start time, then by id
        run_id = max(runs, key=lambda r: (_started(state_dir / r / "run.json"), r))
    if not (state_dir / run_id / "run.json").is_file():
        raise CliError(f"run {run_id!r} not found under {state_dir}")
    return RunDir(state_dir, run_id)


def _started(run_json: Path) -> str:
    try:
        return str(json.loads(run_json.read_text(encoding="utf-8")).get("started") or "")
    except (OSError, ValueError):
        return ""


def cmd_summary(args: argparse.Namespace) -> int:
    project = _project(args)
    run_dir = _existing_run(project, args.run_id)
    run = run_dir.read_run() or {}
    if run.get("kind") == "drift":
        rows = [[s, v["verdict"], v["detail"], v["spec"]] for s, v in (run.get("stacks") or {}).items()]
        print(f"drift {run_dir.run_id}: exit {run.get('exit_code')}")
        print(_table(rows, ["stack", "verdict", "detail", "spec"]))
        return 0
    print(
        f"run {run_dir.run_id}: {run.get('workflow')} status={run.get('status')} exit={run.get('exit_code')} "
        f"started={run.get('started')} finished={run.get('finished')} git={run.get('git_sha')}"
    )
    print(_status_table(run))
    outputs = {sid: st.get("outputs") for sid, st in (run.get("steps") or {}).items() if st.get("outputs")}
    if outputs:
        print("outputs:")
        for sid, outs in outputs.items():
            for name, value in outs.items():
                print(f"  {sid}.{name} = {json.dumps(value, sort_keys=True)}")
    return 0


def cmd_runs_gc(args: argparse.Namespace) -> int:
    from codeorca.rundir import gc

    project = _project(args)
    removed = gc(_state_dir(project), args.keep)
    print(f"removed {len(removed)} run(s)" + (": " + ", ".join(removed) if removed else ""))
    return 0


# -------------------------------------------------------------------------------------------------- parser


def _add_project(p: argparse.ArgumentParser) -> None:
    p.add_argument("-p", "--project", default="codeorca.yaml", help="project file (default: ./codeorca.yaml)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="codeorca", description="Terraform + Ansible orchestrator")
    parser.add_argument("--version", action="version", version=f"codeorca {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("validate", help="validate workflow files against the models (no side effects)")
    p.add_argument("files", nargs="+")
    p.set_defaults(func=cmd_validate)

    s = sub.add_parser("schema", help="JSON Schema for editors")
    ssub = s.add_subparsers(dest="schema_command", required=True)
    e = ssub.add_parser("export", help="write schema/codeorca-workflow.schema.json and codeorca-project.schema.json")
    e.add_argument("dir", nargs="?", default="schema")
    e.add_argument("--check", action="store_true", help="fail if a committed schema differs from the models")
    e.set_defaults(func=cmd_schema_export)

    r = sub.add_parser("run", help="run a workflow (a file path or <workflows_dir>/<name>.yaml)")
    r.add_argument("workflow")
    _add_project(r)
    r.add_argument("--input", action="append", default=[], metavar="K=V")
    r.add_argument("--dry-run", action="store_true")
    r.set_defaults(func=cmd_run)

    d = sub.add_parser(
        "drift", help="plan every stack (no lock), refresh specs, verdict table: 0 clean, 2 drift, 1 error"
    )
    _add_project(d)
    d.add_argument("--stack", action="append", default=[], metavar="NAME")
    d.set_defaults(func=cmd_drift)

    doc = sub.add_parser("doctor", help="compare the environment with runtime:; exit 1 on any mismatch")
    _add_project(doc)
    doc.add_argument("--lock", action="store_true", help="print a runtime: block of what was observed")
    doc.add_argument("--json", action="store_true")
    doc.set_defaults(func=cmd_doctor)

    rn = sub.add_parser("render", help="re-render every spec-render step of a run from its run dir")
    rn.add_argument("run_id", help="a run id or 'latest'")
    _add_project(rn)
    rn.add_argument("--workflow", help="workflow file or name (default: the one run.json records)")
    rn.set_defaults(func=cmd_render)

    sm = sub.add_parser("summary", help="status table and outputs of a run")
    sm.add_argument("run_id", help="a run id or 'latest'")
    _add_project(sm)
    sm.set_defaults(func=cmd_summary)

    runs = sub.add_parser("runs", help="run directory housekeeping")
    rsub = runs.add_subparsers(dest="runs_command", required=True)
    g = rsub.add_parser("gc", help="delete all but the newest N runs")
    g.add_argument("--keep", type=int, required=True)
    _add_project(g)
    g.set_defaults(func=cmd_runs_gc)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except CliError as e:
        print(f"codeorca: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
