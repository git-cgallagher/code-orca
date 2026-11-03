"""``codeorca.resume``: the terminal requirement (no env/flag bypass), refusals (not waiting, stale, tampered plan,
changed workflow, bad fields, missing secret inputs), approve without re-running completed steps, reject, and
``finally`` running exactly once at the real end."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from codeorca.models import Workflow
from codeorca.project import load_project
from codeorca.redact import KEY_PLACEHOLDER, SecretRegistry
from codeorca.resume import TTY_REFUSAL, ResumeRefused, is_redacted, resume
from codeorca.rundir import RunDir
from codeorca.runner import EXIT_FAILED, EXIT_OK, EXIT_WAITING, Runner, StepContext, StepResult
from codeorca.secrets import key_denylist, record_filter, seed_inputs
from codeorca.steps import default_executors
from codeorca.steps import gate as gate_step

ROOT = Path(__file__).resolve().parents[2]
PROJECT = load_project(ROOT / "examples" / "reference" / "codeorca.yaml")
KEY = b"example-not-secret-key"
YES = lambda fd: True  # noqa: E731 - a fake terminal
NO = lambda fd: False  # noqa: E731


def workflow(steps: list[dict], **kw) -> Workflow:
    return Workflow.model_validate({"api": "codeorca/v1", "kind": "workflow", "name": "t", "steps": steps, **kw})


class Calls:
    """Counts executor calls per step id and keeps the rendered argv each shell step saw."""

    def __init__(self):
        self.ids: list[str] = []
        self.argv: dict[str, list] = {}

    def shell(self, step, ctx: StepContext) -> StepResult:
        self.ids.append(step.id)
        self.argv[step.id] = [str(a) for a in step.run]
        return StepResult("succeeded", result={"n": len(self.ids)})


def fake_plan(step, ctx: StepContext) -> StepResult:
    path = ctx.step_dir / "plan.tfplan"
    path.write_bytes(b"FAKE-PLAN-" + step.id.encode())
    return StepResult("succeeded", result={"files": {"plan_file": str(path)}})


def executors(calls: Calls, registry: SecretRegistry, tty=NO) -> dict:
    ex = default_executors()
    ex["shell"] = calls.shell
    ex["terraform"] = fake_plan
    ex["gate"] = gate_step.make_executor(registry, prompt=lambda t, s: "approve", isatty=tty, out=lambda t: None)
    return ex


WF = workflow(
    [
        {"id": "plan", "type": "terraform", "stack": "app"},
        {"id": "a", "type": "shell", "needs": ["plan"], "run": ["a"]},
        {
            "id": "approve",
            "type": "gate",
            "needs": ["a"],
            "message": "ship?",
            "fields": {"ticket": {"type": "string"}, "count": {"type": "int", "default": 1}},
        },
        {"id": "b", "type": "shell", "needs": ["approve"], "run": ["b", "${{ steps.approve.outputs.ticket }}"]},
        {"id": "c", "type": "shell", "needs": ["a"], "run": ["c"]},  # ready alongside the gate, scheduled after it
    ],
    **{"finally": [{"id": "fin", "type": "shell", "run": ["fin", "${{ run.status }}"]}]},
)


def start(tmp_path, wf=WF, inputs=None, registry=None) -> tuple[RunDir, Calls, SecretRegistry]:
    registry = registry or SecretRegistry(KEY, "env:test")
    calls = Calls()
    rd = RunDir(tmp_path / "runs")
    denylist = key_denylist(PROJECT)
    resolved = inputs or {}
    seed_inputs(registry, resolved, denylist)
    runner = Runner(PROJECT, wf, resolved, rd, executors(calls, registry), redact=record_filter(registry, denylist))
    assert runner.run() == EXIT_WAITING
    return rd, calls, registry


def go(rd, calls, registry, decision="approve", wf=WF, **kw):
    kw.setdefault("isatty", YES)
    return resume(
        PROJECT,
        rd,
        decision,
        executors=executors(calls, registry, tty=YES),
        workflow=wf,
        redact=record_filter(registry, key_denylist(PROJECT)),
        registry=registry,
        getuser=lambda: "alice",
        **kw,
    )


# --- the terminal requirement ------------------------------------------------------------------------------------


@pytest.mark.parametrize("tty", [NO, lambda fd: fd == 0, lambda fd: fd == 1])
def test_resume_refuses_without_a_terminal_on_stdin_and_stdout(tmp_path, tty):
    rd, calls, registry = start(tmp_path)
    before = rd.run_json.read_text(encoding="utf-8")
    with pytest.raises(ResumeRefused, match="interactive terminal"):
        go(rd, calls, registry, isatty=tty)
    assert rd.run_json.read_text(encoding="utf-8") == before  # nothing written


@pytest.mark.parametrize("decision", ["approve", "reject"])
def test_no_environment_variable_bypasses_the_terminal_check(tmp_path, monkeypatch, decision):
    rd, calls, registry = start(tmp_path)
    for name in ("CODEORCA_APPROVE", "CODEORCA_FORCE", "CODEORCA_YES", "CODEORCA_NONINTERACTIVE", "CI"):
        monkeypatch.setenv(name, "1")
    with pytest.raises(ResumeRefused) as e:
        resume(PROJECT, rd, decision, executors=executors(calls, registry), workflow=WF, isatty=NO)
    assert str(e.value) == TTY_REFUSAL
    assert rd.read_run()["status"] == "waiting"


@pytest.mark.parametrize("flag", ["force", "yes", "assume_tty", "non_interactive_ok"])
def test_no_keyword_bypasses_the_terminal_check(tmp_path, flag):
    rd, calls, registry = start(tmp_path)
    with pytest.raises(TypeError):
        resume(PROJECT, rd, "approve", executors=executors(calls, registry), workflow=WF, isatty=NO, **{flag: True})
    assert rd.read_run()["status"] == "waiting"


def test_default_isatty_is_the_real_one_and_pytest_has_no_terminal(tmp_path):
    rd, calls, registry = start(tmp_path)
    with pytest.raises(ResumeRefused, match="interactive terminal"):
        resume(PROJECT, rd, "approve", executors=executors(calls, registry), workflow=WF)


# --- refusals ------------------------------------------------------------------------------------------------------


def test_resume_refuses_a_run_that_is_not_waiting(tmp_path):
    rd, calls, registry = start(tmp_path)
    assert go(rd, calls, registry) == EXIT_OK
    with pytest.raises(ResumeRefused, match="'succeeded', not waiting"):
        go(rd, calls, registry)


def _age_gate(rd: RunDir, hours: float) -> None:
    path = rd.steps_dir / "approve" / "result.json"
    result = json.loads(path.read_text(encoding="utf-8"))
    result["waiting_since"] = (datetime.now(UTC) - timedelta(hours=hours)).isoformat(timespec="seconds")
    path.write_text(json.dumps(result), encoding="utf-8")


def test_resume_refuses_a_gate_older_than_max_age(tmp_path):
    rd, calls, registry = start(tmp_path)
    _age_gate(rd, 25)  # the reference project says gate.max_age: 24h
    with pytest.raises(ResumeRefused, match="fresh plan is needed"):
        go(rd, calls, registry)
    assert rd.read_run()["status"] == "waiting"


def test_resume_refuses_a_plan_older_than_max_age(tmp_path):
    rd, calls, registry = start(tmp_path)
    path = rd.steps_dir / "approve" / "result.json"
    result = json.loads(path.read_text(encoding="utf-8"))
    result["plans"]["plan"]["planned_at"] = (datetime.now(UTC) - timedelta(hours=30)).isoformat(timespec="seconds")
    path.write_text(json.dumps(result), encoding="utf-8")
    with pytest.raises(ResumeRefused, match="fresh plan is needed"):
        go(rd, calls, registry)


def test_a_gate_within_max_age_resumes(tmp_path):
    rd, calls, registry = start(tmp_path)
    _age_gate(rd, 23)
    assert go(rd, calls, registry) == EXIT_OK


def test_a_stale_gate_can_still_be_rejected(tmp_path):
    rd, calls, registry = start(tmp_path)
    _age_gate(rd, 48)
    assert go(rd, calls, registry, decision="reject") == EXIT_FAILED


def test_resume_refuses_a_tampered_plan_file(tmp_path):
    rd, calls, registry = start(tmp_path)
    plan = rd.steps_dir / "plan" / "plan.tfplan"
    plan.write_bytes(plan.read_bytes() + b"x")
    with pytest.raises(ResumeRefused, match="changed since the gate recorded it"):
        go(rd, calls, registry)
    plan.unlink()
    with pytest.raises(ResumeRefused, match="is gone"):
        go(rd, calls, registry)


def test_resume_refuses_a_changed_workflow(tmp_path):
    rd, calls, registry = start(tmp_path)
    changed = WF.model_copy(update={"description": "edited after the stop"})
    with pytest.raises(ResumeRefused, match="changed since"):
        go(rd, calls, registry, wf=changed)


def test_resume_refuses_unknown_or_mistyped_fields(tmp_path):
    rd, calls, registry = start(tmp_path)
    with pytest.raises(ResumeRefused, match="unknown field"):
        go(rd, calls, registry, fields={"nope": "1"})
    with pytest.raises(ResumeRefused, match="is not an int"):
        go(rd, calls, registry, fields={"count": "many"})
    with pytest.raises(ResumeRefused, match="--approve only"):
        go(rd, calls, registry, decision="reject", fields={"ticket": "x"})


def test_a_concurrent_resume_is_refused(tmp_path):
    import fcntl

    rd, calls, registry = start(tmp_path)
    with open(rd.path / ".resume.lock", "a+") as held:
        fcntl.flock(held.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(ResumeRefused, match="another process"):
            go(rd, calls, registry)


# --- approve / reject ----------------------------------------------------------------------------------------------


def test_approve_continues_without_rerunning_completed_steps(tmp_path):
    rd, calls, registry = start(tmp_path)
    assert calls.ids == ["a"]
    assert rd.read_run()["steps"]["fin"]["status"] is None  # finally waits for the real end
    rc = go(rd, calls, registry, fields={"ticket": "CHG-7", "count": "5"})
    assert rc == EXIT_OK
    assert calls.ids == ["a", "c", "b", "fin"]  # a once (c was ready with the gate), finally once, at the end
    assert calls.argv["b"] == ["b", "CHG-7"] and calls.argv["fin"] == ["fin", "succeeded"]
    run = rd.read_run()
    assert run["status"] == "succeeded" and run["exit_code"] == 0
    gate = run["steps"]["approve"]
    assert gate["status"] == "succeeded"
    assert gate["outputs"] == {"ticket": "CHG-7", "count": 5, "approved": True, "approver": "alice"}
    result = rd.read_result("approve")
    assert result["decision"] == "approve" and result["approver"] == "alice" and result["fields"]["count"] == 5
    assert "plan" in result["plans"] and result["waiting_since"] and result["decided_at"]
    assert run["decision"] == "approve" and run["resumed_at"] == result["decided_at"]
    assert run["resumes"] == [
        {"gate": "approve", "decision": "approve", "approver": "alice", "resumed_at": result["decided_at"]}
    ]
    assert run["steps"]["a"]["status"] == "succeeded"


def test_reject_omits_dependents_and_runs_finally_once(tmp_path):
    rd, calls, registry = start(tmp_path)
    rc = go(rd, calls, registry, decision="reject")
    assert rc == EXIT_FAILED
    run = rd.read_run()
    assert run["steps"]["approve"]["status"] == "failed" and "rejected by alice" in run["steps"]["approve"]["error"]
    assert run["steps"]["b"]["status"] == "omitted"
    assert run["steps"]["c"]["status"] == "cancelled"  # fail_fast: the rejection stops unrelated work too
    assert calls.ids == ["a", "fin"] and calls.argv["fin"] == ["fin", "failed"]
    assert rd.read_result("approve")["decision"] == "reject" and run["decision"] == "reject"


def test_a_second_gate_after_resume_asks_on_the_terminal(tmp_path):
    wf = workflow(
        [
            {"id": "g1", "type": "gate", "message": "one"},
            {"id": "g2", "type": "gate", "needs": ["g1"], "message": "two"},
            {"id": "b", "type": "shell", "needs": ["g2"], "run": ["b"]},
        ]
    )
    rd, calls, registry = start(tmp_path, wf=wf)
    assert go(rd, calls, registry, wf=wf) == EXIT_OK  # the resume executors answer g2 'approve' on a fake tty
    assert rd.read_run()["steps"]["g2"]["outputs"]["approved"] is True
    assert calls.ids == ["b"]


def test_a_legacy_run_whose_finally_ran_at_the_wait_does_not_run_it_twice(tmp_path):
    rd, calls, registry = start(tmp_path)
    run = rd.read_run()
    run["steps"]["fin"]["status"] = "succeeded"  # a run.json from before finally moved to the real end
    rd.write_run(run)
    assert go(rd, calls, registry) == EXIT_OK
    assert calls.ids.count("fin") == 0


# --- secret inputs -------------------------------------------------------------------------------------------------

SECRET = "FIXTURE-SECRET-resume-input-001"
WF_SECRET = Workflow.model_validate(
    {
        "api": "codeorca/v1",
        "kind": "workflow",
        "name": "s",
        "inputs": {"api_token": {"type": "string", "required": True}, "env": {"type": "string", "default": "dev"}},
        "vars": {"auth": "Bearer ${{ inputs.api_token }}"},
        "steps": [
            {"id": "a", "type": "shell", "run": ["a", "${{ inputs.api_token }}"]},
            {"id": "approve", "type": "gate", "needs": ["a"], "message": "m"},
            {"id": "b", "type": "shell", "needs": ["approve"], "run": ["b", "${{ inputs.api_token }}"]},
        ],
    }
)


def test_redacted_inputs_are_detected():
    assert is_redacted(KEY_PLACEHOLDER) and is_redacted({"x": ["<redacted:hmac:0123abcd>"]})
    assert not is_redacted("dev") and not is_redacted(3)


def test_resume_requires_a_redacted_input_a_remaining_step_uses(tmp_path):
    rd, calls, registry = start(tmp_path, wf=WF_SECRET, inputs={"api_token": SECRET, "env": "dev"})
    assert rd.read_run()["inputs"]["api_token"] == KEY_PLACEHOLDER  # persisted redacted
    fresh = SecretRegistry(KEY, "env:test")  # a resume is a new process: nothing is registered yet
    with pytest.raises(ResumeRefused, match="api_token"):
        go(rd, calls, fresh, wf=WF_SECRET)
    assert go(rd, calls, fresh, wf=WF_SECRET, secret_inputs={"api_token": SECRET}) == EXIT_OK
    assert calls.argv["b"] == ["b", SECRET]  # the real value reached the step
    for path in rd.path.rglob("*.json"):
        assert SECRET not in path.read_text(encoding="utf-8"), path


def test_a_var_built_from_a_secret_input_is_rendered_again(tmp_path):
    wf = WF_SECRET.model_copy(
        update={
            "steps": [
                *WF_SECRET.steps[:2],
                WF_SECRET.steps[2].model_copy(update={"run": ["b", "${{ vars.auth }}"]}),
            ]
        }
    )
    rd, calls, registry = start(tmp_path, wf=wf, inputs={"api_token": SECRET})
    fresh = SecretRegistry(KEY, "env:test")
    with pytest.raises(ResumeRefused, match="api_token"):
        go(rd, calls, fresh, wf=wf)
    assert go(rd, calls, fresh, wf=wf, secret_inputs={"api_token": SECRET}) == EXIT_OK
    assert calls.argv["b"] == ["b", f"Bearer {SECRET}"]


def test_a_redacted_input_nobody_needs_any_more_is_not_asked_for(tmp_path):
    wf = WF_SECRET.model_copy(
        update={"steps": [*WF_SECRET.steps[:2], WF_SECRET.steps[2].model_copy(update={"run": ["b"]})]}
    )
    rd, calls, registry = start(tmp_path, wf=wf, inputs={"api_token": SECRET})
    assert go(rd, calls, SecretRegistry(KEY, "env:test"), wf=wf) == EXIT_OK


def test_secret_inputs_cannot_change_a_clear_input_or_name_an_unknown_one(tmp_path):
    rd, calls, registry = start(tmp_path, wf=WF_SECRET, inputs={"api_token": SECRET, "env": "dev"})
    with pytest.raises(ResumeRefused, match="recorded in clear"):
        go(rd, calls, registry, wf=WF_SECRET, secret_inputs={"api_token": SECRET, "env": "prod"})
    with pytest.raises(ResumeRefused, match="unknown secret input"):
        go(rd, calls, registry, wf=WF_SECRET, secret_inputs={"nope": "x"})


def test_a_resupplied_value_must_match_the_recorded_placeholder(tmp_path):
    # an input whose NAME is harmless but whose value was registered persists as an HMAC placeholder, which a
    # resume can check the re-supplied value against
    wf = Workflow.model_validate(
        {
            "api": "codeorca/v1",
            "kind": "workflow",
            "name": "p",
            "inputs": {"blob": {"type": "string"}},
            "steps": [
                {"id": "approve", "type": "gate", "message": "m"},
                {
                    "id": "b",
                    "type": "shell",
                    "needs": ["approve"],
                    "run": ["${{ inputs.blob }}"],
                    "outputs": {"echo": "seen ${{ inputs.blob }}"},
                },
            ],
        }
    )
    registry = SecretRegistry(KEY, "env:test")
    registry.add(SECRET)
    rd, calls, _ = start(tmp_path, wf=wf, inputs={"blob": SECRET}, registry=registry)
    assert rd.read_run()["inputs"]["blob"].startswith("<redacted:hmac:")
    fresh = SecretRegistry(KEY, "env:test")
    with pytest.raises(ResumeRefused, match="does not match"):
        go(rd, calls, SecretRegistry(KEY, "env:test"), wf=wf, secret_inputs={"blob": "FIXTURE-SECRET-some-other-value"})
    assert go(rd, calls, fresh, wf=wf, secret_inputs={"blob": SECRET}) == EXIT_OK
    assert calls.argv["b"] == [SECRET]
    # the re-supplied value (a name the key denylist does not cover) is registered: nothing under the run dir
    # holds it in clear after the resume (run.json inputs, the step's outputs, its result)
    for path in rd.path.rglob("*"):
        if path.is_file():
            assert SECRET.encode() not in path.read_bytes(), path


@pytest.mark.parametrize(
    ("spec", "typed"),
    [
        ({"type": "list"}, '["FIXTURE-SECRET-token-abcdefgh-0001"'),
        ({"type": "int"}, "FIXTURE-SECRET-token-abcdefgh-0001"),
        ({"type": "string", "enum": ["a", "b"]}, "FIXTURE-SECRET-token-abcdefgh-0001"),
        ({"type": "string", "enum": ["a", "b"]}, "short1"),  # too short to register: the message must not quote it
    ],
    ids=["list", "int", "enum", "short-enum"],
)
def test_a_mistyped_secret_input_is_not_quoted_in_the_refusal(tmp_path, spec, typed):
    """Review finding: coerce_input's InputError quoted the getpass-typed value before it was registered, and the
    CLI printed it in clear."""
    wf = Workflow.model_validate(
        {
            "api": "codeorca/v1",
            "kind": "workflow",
            "name": "p",
            "inputs": {"api_token": spec},
            "steps": [
                {"id": "approve", "type": "gate", "message": "m"},
                {"id": "b", "type": "shell", "needs": ["approve"], "run": ["b", "${{ inputs.api_token | string }}"]},
            ],
        }
    )
    good = {"list": '["x"]', "int": "1", "string": "a"}[spec["type"]]
    rd, calls, _ = start(tmp_path, wf=wf, inputs={"api_token": json.loads(good) if spec["type"] != "string" else good})
    fresh = SecretRegistry(KEY, "env:test")
    with pytest.raises(ResumeRefused) as e:
        go(rd, calls, fresh, wf=wf, secret_inputs={"api_token": typed})
    shown = fresh.redact(str(e.value))  # what the CLI prints
    assert "api_token" in shown and "FIXTURE-SECRET" not in shown and "short1" not in shown


WF_CONN = Workflow.model_validate(
    {
        "api": "codeorca/v1",
        "kind": "workflow",
        "name": "conn",
        "inputs": {"db_password": {"type": "string"}, "conn": {"type": "string"}, "hosts": {"type": "list"}},
        "steps": [
            {"id": "approve", "type": "gate", "message": "m"},
            {
                "id": "use",
                "type": "shell",
                "needs": ["approve"],
                "run": ["use", "${{ inputs.conn }}", "${{ inputs.hosts | join(',') }}"],
            },
        ],
    }
)


@pytest.mark.parametrize(
    "supplied",
    [
        {"conn": "u:WRONG-but-long-enough@evil"},
        {"conn": f"u:{SECRET}@elsewhere"},
        {"conn": f"u:{SECRET}@h", "hosts": '["h1", "other-host"]'},
        {"conn": f"u:{SECRET}@h", "hosts": f'["{SECRET}"]'},
    ],
    ids=["conn-wrong", "conn-literal-changed", "list-wrong", "list-short"],
)
def test_a_partially_redacted_input_must_match_part_by_part(tmp_path, supplied):
    """Review finding: only a value recorded as ONE placeholder was checked; ``u:<redacted:...>@h`` or a list
    input accepted any re-supplied value."""
    inputs = {"db_password": SECRET, "conn": f"u:{SECRET}@h", "hosts": ["h1", SECRET]}
    rd, calls, _ = start(tmp_path, wf=WF_CONN, inputs=inputs)
    recorded = rd.read_run()["inputs"]
    assert recorded["conn"].startswith("u:<redacted:hmac:") and recorded["conn"].endswith("@h")
    full = {"conn": f"u:{SECRET}@h", "hosts": json.dumps(["h1", SECRET])}
    with pytest.raises(ResumeRefused, match="does not match"):
        go(rd, calls, SecretRegistry(KEY, "env:test"), wf=WF_CONN, secret_inputs={**full, **supplied})
    assert rd.read_run()["status"] == "waiting"


def test_a_partially_redacted_input_resupplied_exactly_resumes(tmp_path):
    inputs = {"db_password": SECRET, "conn": f"u:{SECRET}@h", "hosts": ["h1", SECRET]}
    rd, calls, _ = start(tmp_path, wf=WF_CONN, inputs=inputs)
    fresh = SecretRegistry(KEY, "env:test")
    supplied = {"conn": f"u:{SECRET}@h", "hosts": json.dumps(["h1", SECRET])}
    code = go(rd, calls, fresh, wf=WF_CONN, secret_inputs=supplied)
    assert code == EXIT_OK
    assert calls.argv["use"] == ["use", f"u:{SECRET}@h", f"h1,{SECRET}"]


def test_a_waiting_step_in_finally_is_an_error_not_exit_0(tmp_path):
    """Defence behind the model rule: a finally step that returns 'waiting' fails the run."""
    wf = workflow(
        [{"id": "a", "type": "shell", "run": ["a"]}],
        **{"finally": [{"id": "z", "type": "shell", "run": ["z"]}]},
    )
    calls = Calls()
    ex = executors(calls, SecretRegistry(KEY, "env:test"))
    ex["shell"] = lambda step, ctx: StepResult("waiting") if step.id == "z" else calls.shell(step, ctx)
    rd = RunDir(tmp_path / "runs")
    assert Runner(PROJECT, wf, {}, rd, ex).run() == EXIT_FAILED
    record = rd.read_run()
    assert record["status"] == "failed" and record["steps"]["z"]["status"] == "errored"
