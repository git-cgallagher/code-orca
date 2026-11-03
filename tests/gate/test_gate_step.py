"""The gate executor with an injected prompt and terminal check: approve / reject / re-ask / end of input, typed
fields, dry-run auto-approval, the non-interactive wait (exit 3) and fail, timeouts, and the plan binding."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codeorca.models import Workflow
from codeorca.project import load_project
from codeorca.redact import SecretRegistry
from codeorca.rundir import RunDir
from codeorca.runner import EXIT_FAILED, EXIT_OK, EXIT_WAITING, Runner, StepContext, StepResult
from codeorca.secrets import key_denylist, record_filter
from codeorca.steps import default_executors
from codeorca.steps import gate as gate_step

ROOT = Path(__file__).resolve().parents[2]
PROJECT = load_project(ROOT / "examples" / "reference" / "codeorca.yaml")
KEY = b"example-not-secret-key"


def workflow(steps: list[dict], **kw) -> Workflow:
    return Workflow.model_validate({"api": "codeorca/v1", "kind": "workflow", "name": "t", "steps": steps, **kw})


def scripted(*answers):
    """A prompt that returns ``answers`` in order; an exception instance is raised instead of returned."""
    queue = list(answers)
    asked: list[tuple[str, float | None]] = []

    def prompt(text: str, timeout: float | None) -> str:
        asked.append((text, timeout))
        if not queue:
            raise EOFError
        answer = queue.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return answer

    prompt.asked = asked  # type: ignore[attr-defined]
    return prompt


def recorder(calls: list[str]):
    def run(step, ctx: StepContext) -> StepResult:
        calls.append(step.id)
        return StepResult("succeeded", result={"echo": getattr(step, "run", [])})

    return run


def fake_plan(step, ctx: StepContext) -> StepResult:
    """A terraform-typed stand-in that writes a plan file into its step dir and names it in its result."""
    path = ctx.step_dir / "plan.tfplan"
    path.write_bytes(b"FAKE-PLAN-" + step.id.encode())
    return StepResult("succeeded", result={"files": {"plan_file": str(path)}})


def make_run(
    tmp_path, wf, *, prompt=None, tty=True, dry_run=False, registry=None, calls=None, out=None, redact=None
) -> tuple[int, Runner]:
    registry = registry or SecretRegistry(KEY, "env:test")
    executors = default_executors()
    executors["shell"] = recorder(calls if calls is not None else [])
    executors["terraform"] = fake_plan
    executors["gate"] = gate_step.make_executor(
        registry,
        prompt=prompt or scripted(),
        isatty=lambda fd: tty,
        out=(out.append if out is not None else lambda text: None),
        getuser=lambda: "alice",
    )
    runner = Runner(PROJECT, wf, {}, RunDir(tmp_path / "runs"), executors, dry_run=dry_run, redact=redact)
    return runner.run(), runner


GATED = [
    {"id": "a", "type": "shell", "run": ["true"]},
    {"id": "approve", "type": "gate", "needs": ["a"], "message": "ship it?"},
    {"id": "b", "type": "shell", "needs": ["approve"], "run": ["${{ steps.approve.outputs.approver }}"]},
]


def test_interactive_approve_records_the_approver_and_decision(tmp_path):
    out: list[str] = []
    rc, r = make_run(tmp_path, workflow(GATED), prompt=scripted("approve"), out=out)
    assert rc == EXIT_OK
    assert r.states["approve"]["status"] == "succeeded"
    assert r.states["approve"]["outputs"] == {"approved": True, "approver": "alice"}
    result = r.run_dir.read_result("approve")
    assert result["decision"] == "approve" and result["approver"] == "alice" and result["decided_at"]
    assert result["plans"] == {} and "dry_run" not in result
    assert "gate approve: ship it?" in out[0]


def test_interactive_reject_fails_the_gate_and_omits_dependents(tmp_path):
    calls: list[str] = []
    rc, r = make_run(tmp_path, workflow(GATED), prompt=scripted("Reject"), calls=calls)
    assert rc == EXIT_FAILED
    assert r.states["approve"]["status"] == "failed" and "rejected by alice" in r.states["approve"]["error"]
    assert r.states["b"]["status"] == "omitted" and calls == ["a"]
    assert r.run_dir.read_result("approve")["decision"] == "reject"


def test_anything_but_approve_or_reject_asks_again(tmp_path):
    out: list[str] = []
    prompt = scripted("yes", "ok", "  APPROVE ")
    rc, r = make_run(tmp_path, workflow(GATED), prompt=prompt, out=out)
    assert rc == EXIT_OK and len(prompt.asked) == 3
    assert sum("please type exactly" in line for line in out) == 2


def test_end_of_input_is_a_reject(tmp_path):
    rc, r = make_run(tmp_path, workflow(GATED), prompt=scripted(EOFError()))
    assert rc == EXIT_FAILED
    assert r.states["approve"]["status"] == "failed" and "end of input" in r.states["approve"]["error"]


def test_typed_fields_are_asked_coerced_and_exposed_as_outputs(tmp_path):
    steps = [
        {
            "id": "approve",
            "type": "gate",
            "message": "m",
            "fields": {
                "ticket": {"type": "string", "required": True},
                "count": {"type": "int", "default": 3},
                "urgent": {"type": "bool"},
                "note": {"type": "string"},
            },
        },
        {"id": "b", "type": "shell", "needs": ["approve"], "run": ["${{ steps.approve.outputs.ticket }}"]},
    ]
    out: list[str] = []
    # ticket: empty -> required, asked again; count: "x" -> not an int, asked again, then empty -> default;
    # urgent: "yes" -> True; note: empty and optional -> None
    prompt = scripted("approve", "", "CHG-42", "x", "", "yes", "")
    rc, r = make_run(tmp_path, workflow(steps), prompt=prompt, out=out)
    assert rc == EXIT_OK
    assert r.states["approve"]["outputs"] == {
        "ticket": "CHG-42",
        "count": 3,
        "urgent": True,
        "note": None,
        "approved": True,
        "approver": "alice",
    }
    assert r.run_dir.read_result("approve")["fields"]["ticket"] == "CHG-42"
    assert any("ticket is required" in line for line in out) and any("is not an int" in line for line in out)


def test_a_secret_named_field_is_registered_before_it_is_written(tmp_path):
    registry = SecretRegistry(KEY, "env:test")
    steps = [{"id": "approve", "type": "gate", "message": "m", "fields": {"change_token": {"type": "string"}}}]
    value = "FIXTURE-SECRET-gate-field-001"
    rc, r = make_run(
        tmp_path,
        workflow(steps),
        prompt=scripted("approve", value),
        registry=registry,
        redact=record_filter(registry, key_denylist(PROJECT)),
    )
    assert rc == EXIT_OK
    for path in r.run_dir.path.rglob("*.json"):
        assert value not in path.read_text(encoding="utf-8"), path


def test_dry_run_auto_approves_without_asking_and_says_so(tmp_path):
    prompt = scripted()
    out: list[str] = []
    rc, r = make_run(tmp_path, workflow(GATED), prompt=prompt, tty=False, dry_run=True, out=out)
    assert rc == EXIT_OK and prompt.asked == []
    assert r.states["approve"]["outputs"] == {"approved": True, "approver": "dry-run"}
    result = r.run_dir.read_result("approve")
    assert result["dry_run"] is True and result["approver"] == "dry-run" and "auto-approved" in result["note"]
    assert any("auto-approved (--dry-run)" in line for line in out)


def test_non_interactive_wait_persists_the_run_and_exits_3(tmp_path):
    calls: list[str] = []
    # a plan before the gate, so the binding has something to record
    wf = workflow(
        [
            {"id": "plan", "type": "terraform", "stack": "app"},
            {"id": "a", "type": "shell", "needs": ["plan"], "run": ["true"]},
            {"id": "approve", "type": "gate", "needs": ["a"], "message": "ship it?"},
            {"id": "b", "type": "shell", "needs": ["approve"], "run": ["true"]},
        ],
        **{"finally": [{"id": "fin", "type": "shell", "run": ["true"]}]},
    )
    prompt = scripted()
    rc, r = make_run(tmp_path, wf, prompt=prompt, tty=False, calls=calls)
    assert rc == EXIT_WAITING and prompt.asked == []
    run = r.run_dir.read_run()
    assert run["status"] == "waiting" and run["exit_code"] == 3
    assert run["steps"]["approve"]["status"] == "waiting" and run["steps"]["fin"]["status"] is None
    assert calls == ["a"]  # b waits; finally waits for the real end
    result = r.run_dir.read_result("approve")
    assert result["reason"] == "waiting for approval"
    assert result["resume"] == f"codeorca resume {r.run_dir.run_id} --approve"
    assert result["waiting_since"]
    plan = r.run_dir.step_dir("plan") / "plan.tfplan"
    assert result["plans"] == {
        "plan": {
            "path": str(plan.resolve()),
            "sha256": gate_step.plan_file_sha256(plan),
            "planned_at": run["steps"]["plan"]["finished"],
        }
    }


@pytest.mark.parametrize("tty", [lambda fd: fd == 0, lambda fd: fd == 1, lambda fd: False])
def test_both_stdin_and_stdout_must_be_terminals(tmp_path, tty):
    registry = SecretRegistry(KEY, "env:test")
    executors = {**default_executors(), "shell": recorder([])}
    executors["gate"] = gate_step.make_executor(registry, prompt=scripted("approve"), isatty=tty)
    r = Runner(PROJECT, workflow(GATED), {}, RunDir(tmp_path / "runs"), executors)
    assert r.run() == EXIT_WAITING


def test_isatty_that_raises_counts_as_no_terminal():
    def broken(fd):
        raise ValueError("closed")

    assert gate_step.is_terminal(broken) is False


def test_non_interactive_fail_fails_the_gate(tmp_path):
    steps = [{"id": "approve", "type": "gate", "message": "m", "non_interactive": "fail"}]
    rc, r = make_run(tmp_path, workflow(steps), tty=False)
    assert rc == EXIT_FAILED and "non_interactive: fail" in r.states["approve"]["error"]


@pytest.mark.parametrize(
    ("on_timeout", "status", "rc"), [("fail", "failed", 1), ("cancel", "cancelled", 1), ("warn", "skipped", 0)]
)
def test_timeout_never_approves(tmp_path, on_timeout, status, rc):
    calls: list[str] = []
    steps = [
        {"id": "approve", "type": "gate", "message": "m", "timeout": "5s", "on_timeout": on_timeout},
        {"id": "b", "type": "shell", "needs": ["approve"], "run": ["true"]},
    ]
    prompt = scripted(TimeoutError())
    code, r = make_run(tmp_path, workflow(steps), prompt=prompt, calls=calls)
    assert code == rc and r.states["approve"]["status"] == status
    assert r.states["b"]["status"] == "omitted" and calls == []
    assert prompt.asked[0][1] == pytest.approx(5, abs=1)  # the step timeout bounds the prompt
    assert r.run_dir.read_result("approve")["timed_out"] is True


def test_message_is_redacted_and_specs_and_plans_are_shown(tmp_path):
    registry = SecretRegistry(KEY, "env:test")
    registry.add("FIXTURE-SECRET-message-001")
    wf = workflow(
        [
            {"id": "plan", "type": "terraform", "stack": "app"},
            {
                "id": "approve",
                "type": "gate",
                "needs": ["plan"],
                "message": "token FIXTURE-SECRET-message-001",
                "allow_delete_of": ["aws_s3_bucket.logs"],
            },
        ]
    )
    rundir_specs = tmp_path / "runs"
    out: list[str] = []
    rc, r = make_run(rundir_specs, wf, prompt=scripted("approve"), registry=registry, out=out)
    assert rc == EXIT_OK
    shown = "\n".join(out)
    assert "FIXTURE-SECRET-message-001" not in shown and "<redacted:hmac:" in shown
    assert "plan.tfplan" in shown and "sha256" in shown and "aws_s3_bucket.logs" in shown
    assert r.run_dir.read_result("approve")["allow_delete_of"] == ["aws_s3_bucket.logs"]


def test_staged_specs_are_listed(tmp_path):
    rd = RunDir(tmp_path)
    (rd.specs_dir / "app").mkdir()
    (rd.specs_dir / "app" / "plan.yaml").write_text("x: 1\n", encoding="utf-8")
    assert gate_step.collect_specs(rd) == [str(rd.specs_dir / "app" / "plan.yaml")]


def test_terminal_prompt_reads_one_line_and_raises_eof(monkeypatch, capsys):
    import io

    monkeypatch.setattr("sys.stdin", io.StringIO("approve\n"))
    assert gate_step.terminal_prompt("q: ", None) == "approve"
    with pytest.raises(EOFError):
        gate_step.terminal_prompt("q: ", None)
    assert capsys.readouterr().out == "q: q: "


def test_terminal_prompt_times_out_on_a_silent_pipe(monkeypatch):
    import os

    read_fd, write_fd = os.pipe()
    try:
        with os.fdopen(read_fd, "r") as reader:
            monkeypatch.setattr("sys.stdin", reader)
            with pytest.raises(TimeoutError):
                gate_step.terminal_prompt("", 0.05)
    finally:
        os.close(write_fd)


def test_field_coercion_rules():
    from codeorca.models import GateField

    assert gate_step.coerce_field("n", GateField(type="int"), "7") == 7
    assert gate_step.coerce_field("b", GateField(type="bool"), "No") is False
    with pytest.raises(gate_step.FieldError):
        gate_step.coerce_field("b", GateField(type="bool"), "maybe")
    with pytest.raises(gate_step.FieldError):
        gate_step.coerce_field("n", GateField(type="int"), True)
    specs = {"t": GateField(required=True), "d": GateField(type="int", default=2)}
    with pytest.raises(gate_step.FieldError, match="required"):
        gate_step.coerce_fields(specs, {})
    with pytest.raises(gate_step.FieldError, match="unknown"):
        gate_step.coerce_fields(specs, {"t": "x", "zzz": "1"})
    assert gate_step.coerce_fields(specs, {"t": "x"}) == {"t": "x", "d": 2}


def test_plan_binding_problems_detect_change_and_removal(tmp_path):
    plan = tmp_path / "plan.tfplan"
    plan.write_bytes(b"one")
    binding = {"p": {"path": str(plan), "sha256": gate_step.plan_file_sha256(plan)}}
    assert gate_step.plan_binding_problems(binding) == []
    plan.write_bytes(b"two")
    assert "changed" in gate_step.plan_binding_problems(binding)[0]
    plan.unlink()
    assert "gone" in gate_step.plan_binding_problems(binding)[0]


def test_run_json_carries_no_typed_secret_from_the_prompt(tmp_path):
    # the decision words and field values are the only things typed; neither is a secret here, but the record
    # must stay JSON (no Path objects or datetimes leak into it)
    rc, r = make_run(tmp_path, workflow(GATED), prompt=scripted("approve"))
    json.loads(r.run_dir.run_json.read_text(encoding="utf-8"))


def test_cancelled_gate_fails_the_run_and_cancels_unrelated_work(tmp_path):
    """A gate cancelled by ``on_timeout: cancel`` is not success: run status failed, exit 1; an unrelated step is
    cancelled, a finally step sees ``cancelled()``."""
    calls: list[str] = []
    wf = Workflow.model_validate(
        {
            "api": "codeorca/v1",
            "kind": "workflow",
            "name": "t",
            "steps": [
                {"id": "approve", "type": "gate", "message": "m", "timeout": "5s", "on_timeout": "cancel"},
                {"id": "after", "type": "shell", "needs": ["approve"], "run": ["true"]},
                {"id": "unrelated", "type": "shell", "run": ["true"]},
            ],
            "finally": [{"id": "notify", "type": "shell", "when": "cancelled()", "run": ["true"]}],
        }
    )
    code, r = make_run(tmp_path, wf, prompt=scripted(TimeoutError()), calls=calls)
    assert code == 1 and r.status == "failed"
    assert r.states["approve"]["status"] == "cancelled" and "on_timeout: cancel" in r.states["approve"]["error"]
    assert r.states["after"]["status"] == "omitted"
    assert r.states["unrelated"]["status"] == "cancelled"
    assert r.states["notify"]["status"] == "succeeded"
    assert r.run_dir.read_run()["exit_code"] == 1


def test_a_rejection_is_final_even_where_retry_would_apply():
    """Review finding: retry on a gate re-asked after a typed reject (and restarted the timeout); the model now
    refuses retry on a gate, so a rejection always blocks its dependents."""
    from pydantic import ValidationError

    from codeorca.models import Workflow

    with pytest.raises(ValidationError, match="a gate cannot use retry"):
        Workflow.model_validate(
            {
                "api": "codeorca/v1",
                "kind": "workflow",
                "name": "t",
                "steps": [
                    {"id": "approve", "type": "gate", "message": "m", "retry": {"limit": 1, "policy": "failure"}},
                    {"id": "use", "type": "shell", "needs": ["approve"], "run": ["use"]},
                ],
            }
        )
