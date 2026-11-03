"""The apply action on a fake ``terraform``: the plan file must be this run's, an approving gate must bind its
sha256 within ``gate.max_age``, the plan gate runs again with the gate's ``allow_delete_of``, retries happen only
after a state-lock error, the plan file is deleted after success, ``--dry-run`` applies nothing."""

from __future__ import annotations

import json
import shutil
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from codeorca.models import Workflow
from codeorca.project import Project, load_project
from codeorca.redact import SecretRegistry, scan_outputs
from codeorca.rundir import RunDir
from codeorca.runner import Runner
from codeorca.steps import default_executors
from codeorca.steps import gate as gate_step
from codeorca.steps import terraform as terraform_step

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = ROOT / "examples" / "reference"
SECRET = "FIXTURE-SECRET-apply-output-001"

# stdout/exit per subcommand (FAKE_STDOUT_<sub>/FAKE_EXIT_<sub>); every call is logged to $FAKE_LOG; `plan -out=`
# writes a plan file; the first $FAKE_LOCK_TIMES applies fail with Terraform's lock error.
FAKE_ENGINE = r"""#!/bin/sh
sub=$1
[ "$sub" = providers ] && sub=providers_schema
echo "$sub" >> "$FAKE_LOG"
for a in "$@"; do case "$a" in -out=*) printf 'FAKE-PLAN' > "${a#-out=}";; esac; done
if [ "$sub" = apply ] && [ -n "$FAKE_LOCK_TIMES" ]; then
  n=$(grep -c '^apply$' "$FAKE_LOG")
  if [ "$n" -le "$FAKE_LOCK_TIMES" ]; then
    printf '%s\n' "$FAKE_LOCK_MSG"
    exit 1
  fi
fi
eval "out=\${FAKE_STDOUT_$sub:-\$FAKE_STDOUT}"
eval "code=\${FAKE_EXIT_$sub:-0}"
printf '%s\n' "$out"
exit "$code"
"""

PLAN_DOC = {
    "format_version": "1.2",
    "terraform_version": "1.14.7",
    "complete": True,
    "applyable": True,
    "errored": False,
    "variables": {"environment": {"value": "dev"}},
    "resource_changes": [],
    "configuration": {"root_module": {"variables": {"environment": {}}}},
}
DELETE = {
    "address": "aws_s3_bucket.logs",
    "type": "aws_s3_bucket",
    "change": {"actions": ["delete"], "before": {"bucket": "example-logs"}, "after": None},
}
APPLY_STREAM = "\n".join(
    json.dumps(m)
    for m in (
        {"@level": "info", "@message": "terraform_data.app: Creating...", "type": "apply_start"},
        {"@level": "info", "@message": "Apply complete!", "type": "change_summary"},
    )
)
OUTPUTS = {
    "app_host": {"sensitive": False, "type": "string", "value": "127.0.0.1"},
    "app_token": {"sensitive": True, "type": "string", "value": SECRET},
}


@pytest.fixture
def project(tmp_path: Path) -> Project:
    root = tmp_path / "reference"
    shutil.copytree(REFERENCE, root, ignore=shutil.ignore_patterns(".codeorca", "specs", ".terraform*", "*.tfstate*"))
    return load_project(root / "codeorca.yaml")


@pytest.fixture
def engine(tmp_path: Path) -> dict:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "terraform").write_text(FAKE_ENGINE, encoding="utf-8")
    (bindir / "terraform").chmod(0o700)
    log = tmp_path / "engine.log"
    log.write_text("", encoding="utf-8")
    return {
        "PATH": f"{bindir}:/usr/bin:/bin",
        "FAKE_LOG": str(log),
        "FAKE_STDOUT_init": "{}",
        "FAKE_STDOUT_version": '{"terraform_version": "1.14.7"}',
        "FAKE_STDOUT_plan": "Plan: 1 to add.",
        "FAKE_EXIT_plan": "2",
        "FAKE_STDOUT_show": json.dumps(PLAN_DOC),
        "FAKE_STDOUT_providers_schema": json.dumps({"format_version": "1.0", "provider_schemas": {}}),
        "FAKE_STDOUT_apply": APPLY_STREAM,
        "FAKE_STDOUT_output": json.dumps(OUTPUTS),
        "FAKE_LOCK_MSG": json.dumps(
            {
                "@level": "error",
                "@message": "Error: Error acquiring the state lock",
                "type": "diagnostic",
                "diagnostic": {"severity": "error", "summary": "Error acquiring the state lock", "detail": "held"},
            }
        ),
    }


def calls(engine: dict, sub: str) -> int:
    return Path(engine["FAKE_LOG"]).read_text(encoding="utf-8").split().count(sub)


def workflow(steps: list[dict]) -> Workflow:
    return Workflow.model_validate({"api": "codeorca/v1", "kind": "workflow", "name": "t", "steps": steps})


PLAN = {
    "id": "plan",
    "type": "terraform",
    "stack": "app",
    "action": "plan",
    "outputs": {"f": "${{ result.files.plan_file }}"},
}
GATE = {"id": "approve", "type": "gate", "needs": ["plan"], "message": "apply?"}
APPLY = {
    "id": "apply",
    "type": "terraform",
    "stack": "app",
    "action": "apply",
    "needs": ["approve"],
    "plan_file": "${{ steps.plan.outputs.f }}",
    "outputs": {"tf": "${{ result.tf_outputs }}"},
}


def run(project, wf, engine, *, answer="approve", dry_run=False, registry=None, extra=None) -> Runner:
    registry = registry or SecretRegistry(b"example-not-secret-key", "env:test")
    executors = default_executors()
    executors["terraform"] = terraform_step.make_executor(registry)
    executors["gate"] = gate_step.make_executor(
        registry, prompt=lambda text, t: answer, isatty=lambda fd: True, out=lambda text: None
    )
    executors.update(extra or {})
    rd = RunDir(project.root / project.state_dir)
    runner = Runner(project, wf, {}, rd, executors, dry_run=dry_run, env=engine, sleep=lambda s: None)
    runner.run()
    return runner


def plan_path(r: Runner) -> Path:
    return r.run_dir.steps_dir / "plan" / "plan.tfplan"


def test_apply_after_an_approving_gate_applies_redacts_and_deletes_the_plan(project, engine):
    r = run(project, workflow([PLAN, GATE, APPLY]), engine)
    st = r.states["apply"]
    assert st["status"] == "succeeded", st["error"]
    result = r.run_dir.read_result("apply")
    assert result["applied"] is True and result["exit_code"] == 0 and result["gate"] == "approve"
    assert result["plan_sha256"] == r.run_dir.read_result("approve")["plans"]["plan"]["sha256"]
    assert not plan_path(r).exists() and result["plan_deleted"] is True
    token = st["outputs"]["tf"]["app_token"]
    assert token["sensitive"] is True and token["value"].startswith("<redacted:hmac:")
    assert st["outputs"]["tf"]["app_host"]["value"] == "127.0.0.1"
    assert Path(result["files"]["tf_outputs"]).is_file()
    argv = json.loads((r.run_dir.steps_dir / "apply" / "argv.json").read_text(encoding="utf-8"))
    assert any(a[1] == "apply" and a[-1] == str(plan_path(r).resolve()) for a in argv)
    registry = SecretRegistry(b"example-not-secret-key", "env:test")
    registry.add(SECRET)
    assert scan_outputs(r.run_dir.path, registry) == []


def test_apply_without_a_gate_is_refused(project, engine):
    r = run(project, workflow([PLAN, {**APPLY, "needs": ["plan"]}]), engine)
    assert r.states["apply"]["status"] == "failed"
    assert "needs an approving gate upstream" in r.states["apply"]["error"]
    assert calls(engine, "apply") == 0 and plan_path(r).exists()


def test_a_rejected_gate_never_applies_even_when_apply_is_forced_to_run(project, engine):
    wf = workflow([PLAN, GATE, {**APPLY, "when": "always()"}])
    r = run(project, wf, engine, answer="reject")
    assert r.states["approve"]["status"] == "failed"
    assert r.states["apply"]["status"] == "failed" and "decision 'reject'" in r.states["apply"]["error"]
    assert calls(engine, "apply") == 0


def test_a_plan_file_from_outside_the_run_is_refused(project, engine, tmp_path):
    outside = tmp_path / "elsewhere" / "plan.tfplan"
    outside.parent.mkdir()
    outside.write_bytes(b"FAKE-PLAN")
    r = run(project, workflow([PLAN, GATE, {**APPLY, "plan_file": str(outside)}]), engine)
    assert "outside this run's directory" in r.states["apply"]["error"]
    assert calls(engine, "apply") == 0


def test_a_plan_file_not_produced_by_a_plan_step_is_refused(project, engine):
    stray = {
        "id": "stray",
        "type": "shell",
        "run": [
            sys.executable,
            "-c",
            "import os; open(os.path.join(os.environ['CODEORCA_STEP_DIR'], 'plan.tfplan'), 'w').write('x')",
        ],
    }
    apply = {**APPLY, "needs": ["approve", "stray"], "plan_file": "steps/stray/plan.tfplan"}
    r = run(project, workflow([PLAN, stray, {**GATE, "needs": ["plan", "stray"]}, apply]), engine)
    assert "not produced by a terraform plan step" in r.states["apply"]["error"]


def test_a_plan_file_changed_after_the_approval_is_refused(project, engine):
    tamper = {
        "id": "tamper",
        "type": "shell",
        "needs": ["approve"],
        "run": [sys.executable, "-c", "import sys; open(sys.argv[1], 'ab').write(b'x')", "${{ steps.plan.outputs.f }}"],
    }
    r = run(project, workflow([PLAN, GATE, tamper, {**APPLY, "needs": ["tamper"]}]), engine)
    assert "changed after gate approve approved it" in r.states["apply"]["error"]
    assert calls(engine, "apply") == 0


def test_an_approval_older_than_max_age_is_refused(project, engine, monkeypatch):
    old = (datetime.now(UTC) - timedelta(hours=25)).isoformat(timespec="seconds")
    monkeypatch.setattr(gate_step, "now_utc", lambda: old)
    r = run(project, workflow([PLAN, GATE, APPLY]), engine)
    assert "older than gate.max_age 24h" in r.states["apply"]["error"]
    assert calls(engine, "apply") == 0


def test_a_plan_older_than_max_age_is_refused_even_when_approved_just_now(project, engine, monkeypatch):
    """Review finding: only the decision time was checked, so an interactive prompt (no timeout) left open for
    days approved a days-old plan. The plan step's own finish time is bound by gate.max_age too."""
    from codeorca import runner as runner_mod

    real_now = runner_mod._now
    old = (datetime.now(UTC) - timedelta(days=3)).isoformat(timespec="seconds")
    monkeypatch.setattr(runner_mod, "_now", lambda: old)  # the plan step finishes "3 days ago"

    def answer_now(text, timeout):
        monkeypatch.setattr(runner_mod, "_now", real_now)  # the approver answers today
        return "approve"

    r = run(project, workflow([PLAN, GATE, APPLY]), engine, extra={"gate": _gate(answer_now)})
    assert r.states["plan"]["finished"] == old
    assert r.run_dir.read_result("approve")["plans"]["plan"]["planned_at"] == old
    assert r.states["apply"]["status"] == "failed"
    assert "the plan behind gate approve is older than gate.max_age 24h" in r.states["apply"]["error"]
    assert calls(engine, "apply") == 0


def test_a_gate_that_recorded_no_plan_time_is_refused(project, engine):
    def drop_plan_time(step, ctx):
        result = gate_step.make_executor(
            SecretRegistry(b"example-not-secret-key", "env:test"),
            prompt=lambda text, t: "approve",
            isatty=lambda fd: True,
            out=lambda text: None,
        )(step, ctx)
        for entry in result.result["plans"].values():
            entry.pop("planned_at", None)
        return result

    r = run(project, workflow([PLAN, GATE, APPLY]), engine, extra={"gate": drop_plan_time})
    assert "recorded no time for the plan it approved" in r.states["apply"]["error"]
    assert calls(engine, "apply") == 0


def test_a_tie_in_decision_time_goes_to_the_downstream_gate(project, engine, monkeypatch):
    """Review finding: with both gates decided in the same second, max() picked the alphabetically-first gate, so
    an earlier gate's allow_delete_of governed instead of the final gate's (which waives nothing)."""
    engine["FAKE_STDOUT_show"] = json.dumps({**PLAN_DOC, "resource_changes": [DELETE]})
    first = {
        "id": "a_waive",
        "type": "gate",
        "needs": ["plan"],
        "message": "w",
        "allow_delete_of": ["aws_s3_bucket.logs"],
    }
    final = {"id": "b_final", "type": "gate", "needs": ["a_waive"], "message": "final, no waiver"}
    fixed = datetime.now(UTC).replace(microsecond=0).isoformat()
    monkeypatch.setattr(gate_step, "now_utc", lambda: fixed)  # both decided "in the same second"
    r = run(project, workflow([PLAN, first, final, {**APPLY, "needs": ["b_final"]}]), engine)
    assert r.run_dir.read_result("a_waive")["decided_at"] == r.run_dir.read_result("b_final")["decided_at"]
    assert r.states["apply"]["status"] == "failed" and "plan gate: aws_s3_bucket.logs" in r.states["apply"]["error"]
    assert "gate b_final's allow_delete_of" in r.states["apply"]["error"]
    assert calls(engine, "apply") == 0


def _gate(prompt):
    return gate_step.make_executor(
        SecretRegistry(b"example-not-secret-key", "env:test"), prompt=prompt, isatty=lambda fd: True, out=lambda t: None
    )


def test_the_plan_gate_blocks_a_delete_the_gate_did_not_waive(project, engine):
    engine["FAKE_STDOUT_show"] = json.dumps({**PLAN_DOC, "resource_changes": [DELETE]})
    r = run(project, workflow([PLAN, GATE, APPLY]), engine)
    assert r.states["apply"]["status"] == "failed"
    assert "plan gate: aws_s3_bucket.logs (stateful type aws_s3_bucket)" in r.states["apply"]["error"]
    assert calls(engine, "apply") == 0 and plan_path(r).exists()


def test_allow_delete_of_on_the_approving_gate_waives_it(project, engine):
    engine["FAKE_STDOUT_show"] = json.dumps({**PLAN_DOC, "resource_changes": [DELETE]})
    r = run(project, workflow([PLAN, {**GATE, "allow_delete_of": ["aws_s3_bucket.logs"]}, APPLY]), engine)
    assert r.states["apply"]["status"] == "succeeded", r.states["apply"]["error"]
    assert calls(engine, "apply") == 1


@pytest.mark.parametrize("flag", ["applyable", "errored", "complete"])
def test_an_unapplyable_plan_is_refused(project, engine, flag):
    bad = {"applyable": False, "errored": True, "complete": False}[flag]
    engine["FAKE_STDOUT_show"] = json.dumps({**PLAN_DOC, flag: bad})
    r = run(project, workflow([PLAN, GATE, APPLY]), engine)
    assert r.states["apply"]["status"] == "failed" and "apply refused" in r.states["apply"]["error"]
    assert calls(engine, "apply") == 0


def test_a_lock_error_before_any_change_is_retried(project, engine):
    engine["FAKE_LOCK_TIMES"] = "1"
    apply = {**APPLY, "retry": {"limit": 2, "policy": "transient"}}
    r = run(project, workflow([PLAN, GATE, apply]), engine)
    assert r.states["apply"]["status"] == "succeeded", r.states["apply"]["error"]
    assert r.states["apply"]["attempts"] == 2 and calls(engine, "apply") == 2


def test_any_other_apply_failure_is_never_retried(project, engine):
    engine["FAKE_STDOUT_apply"] = json.dumps(
        {"@level": "error", "@message": "Error: creating thing", "type": "apply_errored"}
    )
    engine["FAKE_EXIT_apply"] = "1"
    apply = {**APPLY, "retry": {"limit": 2, "policy": "failure"}}
    r = run(project, workflow([PLAN, GATE, apply]), engine)
    st = r.states["apply"]
    assert st["status"] == "failed" and calls(engine, "apply") == 1
    assert "retried only after a state-lock error" in st["error"] and "creating thing" in st["error"]
    assert plan_path(r).exists()  # kept on failure (no success, nothing to clean up behind)


def test_dry_run_applies_nothing_and_reports_skipped(project, engine):
    r = run(project, workflow([PLAN, GATE, APPLY]), engine, dry_run=True)
    assert r.states["approve"]["outputs"]["approver"] == "dry-run"
    assert r.states["apply"]["status"] == "skipped"
    result = r.run_dir.read_result("apply")
    assert result["dry_run"] is True and result["applied"] is False
    assert calls(engine, "apply") == 0 and plan_path(r).exists()


def test_a_dry_run_approval_never_counts_in_a_real_run(project, engine):
    r = run(project, workflow([PLAN, GATE, APPLY]), engine)
    gate_result = r.run_dir.read_result("approve")
    gate_result["dry_run"] = True
    (r.run_dir.steps_dir / "approve" / "result.json").write_text(json.dumps(gate_result), encoding="utf-8")
    from codeorca.runner import StepContext

    # replay the apply's precondition against the doctored record
    ctx = StepContext(
        step=r.workflow.steps[2],
        run_dir=r.run_dir,
        step_dir=r.run_dir.step_dir("apply"),
        run_id=r.run_dir.run_id,
        context=r.context(),
        project=project,
        workflow=r.workflow,
    )
    with pytest.raises(terraform_step.Refused, match="auto-approved by --dry-run"):
        terraform_step.find_approval(r.workflow.steps[2], ctx)


def _waiting_run(project, wf, engine) -> RunDir:
    registry = SecretRegistry(b"example-not-secret-key", "env:test")
    executors = default_executors()
    executors["terraform"] = terraform_step.make_executor(registry)
    executors["gate"] = gate_step.make_executor(registry, isatty=lambda fd: False, out=lambda text: None)
    rd = RunDir(project.root / project.state_dir)
    assert Runner(project, wf, {}, rd, executors, env=engine, sleep=lambda s: None).run() == 3
    return rd


def _resume(project, rd, wf, engine):
    from codeorca.resume import resume

    registry = SecretRegistry(b"example-not-secret-key", "env:test")
    executors = default_executors()
    executors["terraform"] = terraform_step.make_executor(registry)
    executors["gate"] = _gate(lambda text, t: "approve")
    return resume(
        project,
        rd,
        "approve",
        executors=executors,
        isatty=lambda fd: True,
        workflow=wf,
        env=engine,
        registry=registry,
        cwd=project.root,
        getuser=lambda: "alice",
    )


@pytest.mark.parametrize(
    ("old", "new"),
    [("aws_s3_bucket", "aws_nothing_here"), ("max_age: 24h", "max_age: 9999h")],
    ids=["stateful_types", "max_age"],
)
def test_resume_refuses_when_the_project_changed_since_the_stop(project, engine, old, new):
    """Review finding: resume pinned the workflow but not codeorca.yaml, so dropping a stateful type (or raising
    gate.max_age) between the exit-3 stop and the human's resume let the approved apply delete a bucket."""
    from codeorca.resume import ResumeRefused

    engine["FAKE_STDOUT_show"] = json.dumps({**PLAN_DOC, "resource_changes": [DELETE]})
    wf = workflow([PLAN, GATE, APPLY])
    rd = _waiting_run(project, wf, engine)
    config = project.root / "codeorca.yaml"
    text = config.read_text(encoding="utf-8")
    assert old in text
    config.write_text(text.replace(old, new), encoding="utf-8")
    with pytest.raises(ResumeRefused, match=r"the project \(codeorca.yaml\) changed"):
        _resume(load_project(config), rd, wf, engine)
    assert rd.read_run()["status"] == "waiting" and calls(engine, "apply") == 0


def test_resume_with_the_same_project_still_runs_the_plan_gate(project, engine):
    engine["FAKE_STDOUT_show"] = json.dumps({**PLAN_DOC, "resource_changes": [DELETE]})
    wf = workflow([PLAN, GATE, APPLY])
    rd = _waiting_run(project, wf, engine)
    _resume(load_project(project.root / "codeorca.yaml"), rd, wf, engine)
    record = rd.read_run()
    assert record["project_sha256"] and record["steps"]["apply"]["status"] == "failed"
    assert calls(engine, "apply") == 0
