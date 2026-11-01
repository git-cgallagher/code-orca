"""The DAG runner on tiny workflows of shell steps: propagation, status functions, retry, timeout, inputs,
run-dir contents, exit codes."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from codeorca.models import Workflow
from codeorca.project import load_project
from codeorca.rundir import RunDir
from codeorca.runner import (
    EXIT_FAILED,
    EXIT_OK,
    EXIT_WAITING,
    InputError,
    NotImplementedInPhase,
    RunError,
    Runner,
    StepContext,
    StepResult,
    parse_duration,
    resolve_inputs,
)
from codeorca.steps import default_executors, lookup, register

ROOT = Path(__file__).resolve().parent.parent.parent
PROJECT = load_project(ROOT / "examples" / "reference" / "codeorca.yaml")

PY = sys.executable
OK = [PY, "-c", "pass"]
FAIL = [PY, "-c", "import sys; sys.exit(2)"]


def py(code: str) -> list[str]:
    return [PY, "-c", code]


def emit(outputs: dict) -> list[str]:
    """A step that writes ``outputs`` to $CODEORCA_OUTPUT_FILE."""
    return py(f"import os, json; json.dump({outputs!r}, open(os.environ['CODEORCA_OUTPUT_FILE'], 'w'))")


def shell(id: str, run: list[str], **kw) -> dict:
    return {"id": id, "type": "shell", "run": run, **kw}


def workflow(steps: list[dict], **kw) -> Workflow:
    return Workflow.model_validate({"api": "codeorca/v1", "kind": "workflow", "name": "t", "steps": steps, **kw})


def run(wf: Workflow, tmp_path, inputs=None, **kw) -> tuple[int, Runner]:
    rd = RunDir(tmp_path)
    runner = Runner(PROJECT, wf, inputs or {}, rd, default_executors(), sleep=lambda s: None, **kw)
    return runner.run(), runner


def statuses(runner: Runner) -> dict[str, str | None]:
    return {sid: st["status"] for sid, st in runner.states.items()}


# --- propagation ---------------------------------------------------------------------------------------------


def test_outputs_flow_between_steps_and_exit_ok(tmp_path):
    wf = workflow(
        [
            shell(
                "a",
                emit({"host": "h1", "n": 2}),
                outputs={"host": "${{ result.output.host }}", "n": "${{ result.output.n }}"},
            ),
            shell(
                "b",
                py(
                    "import sys, os; assert sys.argv[1:] == ['h1-x', '2'], sys.argv; "
                    "open(os.environ['CODEORCA_OUTPUT_FILE'], 'w').write('{\"ok\": true}')"
                ),
                needs=["a"],
                outputs={"ok": "${{ result.output.ok }}"},
            ),
        ]
    )
    wf.steps[1].run += ["${{ steps.a.outputs.host }}-x", "${{ steps.a.outputs.n }}"]
    rc, r = run(wf, tmp_path)
    assert rc == EXIT_OK
    assert statuses(r) == {"a": "succeeded", "b": "succeeded"}
    assert r.states["a"]["outputs"] == {"host": "h1", "n": 2}  # native int preserved
    assert r.states["b"]["outputs"] == {"ok": True}
    assert r.run_dir.read_outputs("a") == {"host": "h1", "n": 2}


def test_needs_unmet_omits_dependents_and_fails_run(tmp_path):
    wf = workflow([shell("a", FAIL), shell("b", OK, needs=["a"]), shell("c", OK, needs=["b"])])
    rc, r = run(wf, tmp_path)
    assert rc == EXIT_FAILED
    assert statuses(r) == {"a": "failed", "b": "omitted", "c": "omitted"}
    assert r.states["a"]["error"].endswith("exited 2")
    assert r.states["b"]["outputs"] is None


def test_when_false_skips_and_dependents_are_omitted(tmp_path):
    wf = workflow(
        [
            shell("a", emit({"changed": False}), outputs={"changed": "${{ result.output.changed }}"}),
            shell("b", OK, needs=["a"], when="steps.a.outputs.changed"),
            shell("c", OK, needs=["b"]),
            shell("d", OK, needs=["b"], when="always() and steps.b.status == 'skipped'"),
        ]
    )
    rc, r = run(wf, tmp_path)
    assert rc == EXIT_OK
    assert statuses(r) == {"a": "succeeded", "b": "skipped", "c": "omitted", "d": "succeeded"}


def test_when_on_an_omitted_steps_outputs_is_not_evaluated(tmp_path):
    # approve-style: `when: steps.plan.outputs.changed` with an unmet need must be omitted, not errored
    wf = workflow(
        [
            shell("plan", FAIL, outputs={"changed": "${{ result.exit_code == 2 }}"}),
            shell("spec", OK, needs=["plan"]),
            shell("approve", OK, needs=["spec"], when="steps.plan.outputs.changed"),
        ]
    )
    rc, r = run(wf, tmp_path)
    assert rc == EXIT_FAILED
    assert statuses(r) == {"plan": "failed", "spec": "omitted", "approve": "omitted"}


def test_always_runs_after_a_failure_and_failure_function(tmp_path):
    wf = workflow(
        [
            shell("a", FAIL),
            shell("cleanup", OK, needs=["a"], when="always()"),
            shell("notify", OK, needs=["a"], when="failure()"),
            shell("only_ok", OK, needs=["a"], when="success()"),
        ]
    )
    rc, r = run(wf, tmp_path)
    assert rc == EXIT_FAILED
    assert statuses(r) == {"a": "failed", "cleanup": "succeeded", "notify": "succeeded", "only_ok": "omitted"}


def test_on_failure_continue_lets_dependents_run_and_run_succeeds(tmp_path):
    wf = workflow(
        [
            shell("a", FAIL, on_failure="continue"),
            shell("b", OK, needs=["a"]),
            shell("c", OK, needs=["a"], when="steps.a.status == 'failed'"),
        ]
    )
    rc, r = run(wf, tmp_path)
    assert rc == EXIT_OK
    assert statuses(r) == {"a": "failed", "b": "succeeded", "c": "succeeded"}
    assert r.status == "succeeded"


def test_fail_fast_cancels_unrelated_steps_but_omits_dependents(tmp_path):
    wf = workflow(
        [
            shell("a", FAIL),
            shell("dep", OK, needs=["a"]),
            shell("unrelated", OK),
            shell("always", OK, when="always()"),
        ]
    )
    # ids are scheduled in file order among the ready set; `a` fails first
    rc, r = run(wf, tmp_path)
    assert rc == EXIT_FAILED
    assert statuses(r) == {"a": "failed", "dep": "omitted", "unrelated": "cancelled", "always": "succeeded"}


def test_fail_fast_off_keeps_scheduling(tmp_path):
    wf = workflow([shell("a", FAIL), shell("dep", OK, needs=["a"]), shell("unrelated", OK)], fail_fast=False)
    rc, r = run(wf, tmp_path)
    assert rc == EXIT_FAILED
    assert statuses(r) == {"a": "failed", "dep": "omitted", "unrelated": "succeeded"}


def test_finally_runs_on_failure_with_run_status(tmp_path):
    marker = tmp_path / "status.txt"
    wf = workflow(
        [shell("a", FAIL)],
        **{
            "finally": [
                shell("fin", py(f"import sys; open({str(marker)!r}, 'w').write(sys.argv[1])") + ["${{ run.status }}"])
            ]
        },
    )
    rc, r = run(wf, tmp_path)
    assert rc == EXIT_FAILED
    assert statuses(r) == {"a": "failed", "fin": "succeeded"}
    assert marker.read_text() == "failed"


def test_finally_failure_fails_the_run(tmp_path):
    wf = workflow([shell("a", OK)], **{"finally": [shell("fin", FAIL)]})
    rc, r = run(wf, tmp_path)
    assert rc == EXIT_FAILED
    assert r.status == "failed"


def test_finally_when_can_skip(tmp_path):
    wf = workflow([shell("a", OK)], **{"finally": [shell("fin", OK, when="failure()")]})
    rc, r = run(wf, tmp_path)
    assert rc == EXIT_OK
    assert statuses(r)["fin"] == "skipped"


# --- outputs and expressions -----------------------------------------------------------------------------------


def test_bare_reference_to_skipped_output_errors_default_works(tmp_path):
    wf = workflow(
        [
            shell("a", emit({"v": "x"}), when="1 == 2", outputs={"v": "${{ result.output.v }}"}),
            shell("bare", ["echo", "${{ steps.a.outputs.v }}"], needs=["a"], when="always()"),
            shell(
                "dflt",
                py("import sys; assert sys.argv[1] == 'fallback'") + ["${{ steps.a.outputs.v | default('fallback') }}"],
                needs=["a"],
                when="always()",
            ),
        ],
        fail_fast=False,
    )
    rc, r = run(wf, tmp_path)
    assert rc == EXIT_FAILED
    assert statuses(r) == {"a": "skipped", "bare": "errored", "dflt": "succeeded"}
    assert "has no attribute 'v'" in r.states["bare"]["error"]


def test_output_expression_error_errors_the_producer(tmp_path):
    wf = workflow(
        [
            shell("a", OK, when="1 == 2"),
            shell("b", OK, needs=["a"], when="always()", outputs={"bad": "${{ steps.a.outputs.nope }}"}),
            shell("c", OK, needs=["b"]),
        ]
    )
    rc, r = run(wf, tmp_path)
    assert rc == EXIT_FAILED
    assert statuses(r) == {"a": "skipped", "b": "errored", "c": "omitted"}
    assert r.states["b"]["outputs"] is None


@pytest.mark.parametrize("template", ["${{ range(3) }}", "${{ {'h': steps.z.outputs.y} }}"])
def test_non_json_output_errors_the_producer_and_run_json_is_written(tmp_path, template):
    wf = workflow(
        [
            shell("z", OK, when="1 == 2"),
            shell("a", OK, needs=["z"], when="always()", outputs={"r": template}),
            shell("b", OK, needs=["a"]),
        ]
    )
    rc, r = run(wf, tmp_path)
    assert rc == EXIT_FAILED
    assert statuses(r) == {"z": "skipped", "a": "errored", "b": "omitted"}
    assert "not JSON-serializable" in r.states["a"]["error"]
    assert r.run_dir.read_run()["steps"]["a"]["status"] == "errored"


def test_when_that_is_not_a_bool_errors(tmp_path):
    wf = workflow(
        [
            shell("a", emit({"s": "yes"}), outputs={"s": "${{ result.output.s }}"}),
            shell("b", OK, needs=["a"], when="steps.a.outputs.s"),
        ]
    )
    rc, r = run(wf, tmp_path)
    assert rc == EXIT_FAILED
    assert statuses(r)["b"] == "errored"
    assert "must evaluate to a bool" in r.states["b"]["error"]


def test_ansible_braces_and_vars_pass_through_argv(tmp_path):
    wf = workflow(
        [
            shell(
                "a",
                py("import sys; assert sys.argv[1:] == ['{{ ansible_host }}', 'us-east-1'], sys.argv")
                + ["{{ ansible_host }}", "${{ vars.region }}"],
            )
        ],
        vars={"region": "us-east-1"},
    )
    assert run(wf, tmp_path)[0] == EXIT_OK


# --- retry and timeout ---------------------------------------------------------------------------------------


def test_retry_transient_matches_project_regex(tmp_path):
    counter = tmp_path / "n"
    # first attempt prints a transient error on stderr and fails; later attempts succeed
    code = (
        f"import sys, pathlib; p = pathlib.Path({str(counter)!r}); n = int(p.read_text() or 0) if p.exists() else 0; "
        "p.write_text(str(n + 1)); "
        "sys.exit(0) if n else (print('Error acquiring the state lock', file=sys.stderr), sys.exit(1))"
    )
    wf = workflow(
        [shell("a", py(code), retry={"limit": 2, "policy": "transient", "backoff": {"duration": "1s", "factor": 2}})]
    )
    waits: list[float] = []
    rd = RunDir(tmp_path)
    runner = Runner(PROJECT, wf, {}, rd, default_executors(), sleep=waits.append)
    assert runner.run() == EXIT_OK
    assert runner.states["a"]["attempts"] == 2
    assert waits == [1.0]
    assert rd.read_result("a")["attempts"] == 2


def test_retry_transient_does_not_retry_a_non_matching_error(tmp_path):
    wf = workflow([shell("a", FAIL, retry={"limit": 3, "policy": "transient"})])
    rc, r = run(wf, tmp_path)
    assert rc == EXIT_FAILED
    assert r.states["a"]["attempts"] == 1


def test_retry_failure_policy_retries_any_failure(tmp_path):
    wf = workflow([shell("a", FAIL, retry={"limit": 2, "policy": "failure"})])
    rc, r = run(wf, tmp_path)
    assert rc == EXIT_FAILED
    assert r.states["a"]["attempts"] == 3


def test_timeout_errors_the_step(tmp_path):
    wf = workflow([shell("a", py("import time; time.sleep(30)"), timeout="200ms"), shell("b", OK, needs=["a"])])
    rc, r = run(wf, tmp_path)
    assert rc == EXIT_FAILED
    assert statuses(r) == {"a": "errored", "b": "omitted"}
    assert r.states["a"]["error"].startswith("timeout:")


def test_retry_error_policy_covers_timeouts(tmp_path):
    wf = workflow(
        [shell("a", py("import time; time.sleep(30)"), timeout="100ms", retry={"limit": 1, "policy": "error"})]
    )
    rc, r = run(wf, tmp_path)
    assert rc == EXIT_FAILED
    assert r.states["a"]["attempts"] == 2


@pytest.mark.parametrize(("text", "seconds"), [("1h30m", 5400.0), ("500ms", 0.5), ("2s", 2.0), ("1m1s", 61.0)])
def test_parse_duration(text, seconds):
    assert parse_duration(text) == pytest.approx(seconds)


@pytest.mark.parametrize("text", ["", "10", "5x", "1h 30m"])
def test_parse_duration_rejects(text):
    with pytest.raises(ValueError):
        parse_duration(text)


# --- inputs --------------------------------------------------------------------------------------------------


def inputs_workflow(**inputs) -> Workflow:
    return workflow([shell("a", OK)], inputs=inputs)


def test_inputs_defaults_and_coercion(tmp_path):
    wf = inputs_workflow(
        env={"type": "string", "enum": ["dev", "prod"], "default": "dev"},
        count={"type": "int", "default": 1},
        verbose={"type": "bool", "default": False},
        hosts={"type": "list", "default": []},
        tags={"type": "map"},
    )
    rd = RunDir(tmp_path)
    r = Runner(PROJECT, wf, {"count": "3", "verbose": "true", "hosts": '["a"]'}, rd, default_executors())
    assert r.inputs == {"env": "dev", "count": 3, "verbose": True, "hosts": ["a"], "tags": None}
    assert rd.read_run()["inputs"] == {"env": "dev", "count": 3, "verbose": True, "hosts": ["a"], "tags": None}


@pytest.mark.parametrize(
    ("spec", "given", "message"),
    [
        ({"type": "string", "enum": ["dev", "prod"]}, {"x": "stage"}, "is not one of"),
        ({"type": "string", "required": True}, {}, "is required"),
        ({"type": "int"}, {"x": "three"}, "cannot read 'three' as int"),
        ({"type": "bool"}, {"x": "yes"}, "expected true or false"),
        ({"type": "list"}, {"x": "{}"}, "expected list"),
        ({"type": "string"}, {"y": "1"}, "unknown input"),
    ],
)
def test_inputs_validation_errors(tmp_path, spec, given, message):
    wf = inputs_workflow(x=spec)
    with pytest.raises(InputError, match=message):
        Runner(PROJECT, wf, given, RunDir(tmp_path), default_executors())


def test_inputs_reach_expressions(tmp_path):
    wf = workflow(
        [shell("a", py("import sys; assert sys.argv[1:] == ['prod', '2']") + ["${{ inputs.env }}", "${{ inputs.n }}"])],
        inputs={"env": {"type": "string", "enum": ["dev", "prod"]}, "n": {"type": "int"}},
    )
    assert run(wf, tmp_path, {"env": "prod", "n": 2})[0] == EXIT_OK


# --- run dir contents and run.json ----------------------------------------------------------------------------


def test_run_dir_contents(tmp_path):
    wf = workflow([shell("a", py("import sys; print('to stdout'); print('to stderr', file=sys.stderr)"))])
    rc, r = run(wf, tmp_path, env={"PATH": "/usr/bin:/bin", "FIXTURE_TOKEN": "FIXTURE-SECRET-value"})
    assert rc == EXIT_OK
    sdir = r.run_dir.steps_dir / "a"
    assert json.loads((sdir / "argv.json").read_text()) == wf.steps[0].run
    names = json.loads((sdir / "env-names.json").read_text())
    assert "FIXTURE_TOKEN" in names and "CODEORCA_OUTPUT_FILE" in names and "CODEORCA_STEP_ID" in names
    assert "FIXTURE-SECRET-value" not in (sdir / "env-names.json").read_text()
    assert (sdir / "stdout.log").read_text() == "to stdout\n"
    assert (sdir / "stderr.log").read_text() == "to stderr\n"
    result = json.loads((sdir / "result.json").read_text())
    assert result["exit_code"] == 0 and result["status"] == "succeeded" and result["stdout_path"].endswith("stdout.log")
    record = r.run_dir.read_run()
    assert record["status"] == "succeeded" and record["exit_code"] == 0 and record["finished"]
    assert record["steps"]["a"]["status"] == "succeeded"
    assert record["workflow"] == "t" and record["project"] == "example"


def test_stream_hook_redacts_before_the_log_is_written(tmp_path):
    seen: list[tuple[str, str]] = []

    def hook(name: str, line: str) -> str:
        seen.append((name, line))
        return line.replace("FIXTURE-SECRET-value", "***")

    wf = workflow([shell("a", py("print('token=FIXTURE-SECRET-value')"))])
    rc, r = run(wf, tmp_path, stream=hook)
    assert rc == EXIT_OK
    assert (r.run_dir.steps_dir / "a" / "stdout.log").read_text() == "token=***\n"
    assert seen == [("stdout", "token=FIXTURE-SECRET-value")]


def test_dry_run_sets_env_flag(tmp_path):
    wf = workflow([shell("a", py("import os; assert os.environ['CODEORCA_DRY_RUN'] == '1'"))])
    assert run(wf, tmp_path, dry_run=True)[0] == EXIT_OK
    wf = workflow([shell("a", py("import os; assert 'CODEORCA_DRY_RUN' not in os.environ"))])
    assert run(wf, tmp_path)[0] == EXIT_OK


def test_run_json_is_persisted_after_each_step(tmp_path):
    rd = RunDir(tmp_path)
    probe = py(
        f"import json; d = json.load(open({str(rd.run_json)!r})); assert d['steps']['a']['status'] == 'succeeded', d"
    )
    wf = workflow([shell("a", OK), shell("b", probe, needs=["a"])])
    assert Runner(PROJECT, wf, {}, rd, default_executors()).run() == EXIT_OK


# --- executors, waiting, unsupported features --------------------------------------------------------------------


def test_waiting_executor_stops_scheduling_and_exits_3(tmp_path):
    def gate(step, ctx: StepContext) -> StepResult:
        return StepResult("waiting", result={"message": step.message})

    executors = {**default_executors(), "gate": gate}
    wf = workflow(
        [
            shell("a", OK),
            {"id": "approve", "type": "gate", "needs": ["a"], "message": "ok?"},
            shell("b", OK, needs=["approve"]),
            shell("c", OK, needs=["a"]),  # ready alongside the gate; file order schedules the gate first
        ],
        **{"finally": [shell("fin", OK)]},
    )
    rd = RunDir(tmp_path)
    r = Runner(PROJECT, wf, {}, rd, executors)
    assert r.run() == EXIT_WAITING
    assert statuses(r) == {"a": "succeeded", "approve": "waiting", "b": None, "c": None, "fin": "succeeded"}
    assert rd.read_run()["status"] == "waiting" and rd.read_run()["exit_code"] == 3


def test_executor_exception_errors_the_step(tmp_path):
    def boom(step, ctx):
        raise RuntimeError("adapter crashed")

    wf = workflow([shell("a", OK)])
    rd = RunDir(tmp_path)
    r = Runner(PROJECT, wf, {}, rd, {**default_executors(), "shell": boom})
    assert r.run() == EXIT_FAILED
    assert r.states["a"]["status"] == "errored" and "adapter crashed" in r.states["a"]["error"]


def test_not_implemented_placeholders_error_clearly(tmp_path):
    wf = workflow([{"id": "tf", "type": "terraform", "stack": "app"}])
    rc, r = run(wf, tmp_path)
    assert rc == EXIT_FAILED
    assert r.states["tf"]["status"] == "errored"
    assert "'terraform' is not implemented in this phase" in r.states["tf"]["error"]
    assert lookup("spec-render").__name__ == "not_implemented_spec_render"


def test_register_and_lookup():
    def custom(step, ctx):
        return StepResult("succeeded")

    before = lookup("python")
    register("python", custom)
    assert lookup("python") is custom
    register("python", before)
    with pytest.raises(ValueError, match="unknown step type"):
        register("bash", custom)
    with pytest.raises(KeyError):
        lookup("bash")


@pytest.mark.parametrize("field", [{"for_each": ["x"]}, {"cache": {"sources": ["a"], "status": ["true"]}}])
def test_for_each_and_cache_are_not_implemented(tmp_path, field):
    wf = workflow([shell("a", OK, **field)])
    with pytest.raises(NotImplementedInPhase, match="not implemented in this phase"):
        Runner(PROJECT, wf, {}, RunDir(tmp_path), default_executors())


def test_missing_executor_is_a_run_error(tmp_path):
    wf = workflow([shell("a", OK)])
    with pytest.raises(RunError, match="no executor registered"):
        Runner(PROJECT, wf, {}, RunDir(tmp_path), {})


def test_exit_code_zero_when_every_step_skipped_or_succeeded(tmp_path):
    wf = workflow([shell("a", OK, when="1 == 2"), shell("b", OK, needs=["a"])])
    rc, r = run(wf, tmp_path)
    assert rc == EXIT_OK and statuses(r) == {"a": "skipped", "b": "omitted"}


# --- hardening: resolve twice, vars, unexpected exceptions, interrupts ------------------------------------------


def test_resolve_inputs_is_idempotent_for_an_optional_input_without_default(tmp_path):
    wf = inputs_workflow(note={"type": "string"}, n={"type": "int"})
    once = resolve_inputs(wf, {})
    assert once == {"note": None, "n": None}
    assert resolve_inputs(wf, once) == once  # the CLI resolves, then Runner resolves again
    rc, r = run(wf, tmp_path, once)
    assert rc == EXIT_OK and r.inputs == once


def test_vars_are_rendered_once_from_inputs_and_persisted_resolved(tmp_path):
    wf = workflow(
        [shell("a", py("import sys; assert sys.argv[1] == 'name=prod-app', sys.argv") + ["name=${{ vars.name }}"])],
        inputs={"env": {"type": "string", "default": "prod"}},
        vars={"name": "${{ inputs.env }}-app", "plain": 1},
    )
    rc, r = run(wf, tmp_path)
    assert rc == EXIT_OK
    assert r.vars == {"name": "prod-app", "plain": 1}
    assert r.run_dir.read_run()["vars"] == {"name": "prod-app", "plain": 1}


def test_vars_cannot_reference_steps(tmp_path):
    wf = workflow([shell("a", OK)], vars={"x": "${{ steps.a.status }}"})
    with pytest.raises(RunError, match="vars"):
        Runner(PROJECT, wf, {}, RunDir(tmp_path), default_executors())


@pytest.mark.parametrize(
    "step",
    [
        shell("a", ["echo", "${{ 100 / inputs.count }}"]),
        shell("a", OK, when="100 / inputs.count > 1"),
        shell("a", OK, outputs={"x": "${{ 100 / inputs.count }}"}),
    ],
)
def test_non_jinja_exception_in_an_expression_errors_the_step(tmp_path, step):
    wf = workflow([step], inputs={"count": {"type": "int", "default": 0}})
    rc, r = run(wf, tmp_path)
    assert rc == EXIT_FAILED
    assert r.states["a"]["status"] == "errored" and "ZeroDivisionError" in r.states["a"]["error"]
    assert r.run_dir.read_run()["status"] == "failed"


def test_interrupt_finalises_the_run_record_before_propagating(tmp_path):
    def interrupted(step, ctx):
        raise KeyboardInterrupt

    wf = workflow([shell("a", OK), shell("b", OK, needs=["a"])], **{"finally": [shell("f", OK)]})
    rd = RunDir(tmp_path)
    r = Runner(PROJECT, wf, {}, rd, {**default_executors(), "shell": interrupted})
    with pytest.raises(KeyboardInterrupt):
        r.run()
    record = rd.read_run()
    assert record["status"] == "failed" and record["exit_code"] == EXIT_FAILED and record["finished"]
    assert record["steps"]["a"]["status"] == "cancelled" and "interrupted" in record["steps"]["a"]["error"]
    assert record["steps"]["b"]["status"] == "cancelled" and record["steps"]["f"]["status"] == "cancelled"


def test_override_function_inside_a_string_literal_does_not_evaluate_an_omitted_step(tmp_path):
    wf = workflow(
        [
            shell("a", FAIL),
            shell("b", OK, needs=["a"], outputs={"m": "1"}),
            shell("c", OK, needs=["b"], when="steps.b.outputs.m != 'failure()'"),
        ],
        fail_fast=False,
    )
    rc, r = run(wf, tmp_path)
    assert rc == EXIT_FAILED
    assert statuses(r) == {"a": "failed", "b": "omitted", "c": "omitted"}
