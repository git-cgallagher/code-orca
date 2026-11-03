"""The reference ``demo-rollout`` end to end on a temporary copy: the agent-like CLI run stops at the gate (exit 3),
the CLI ``resume`` refuses without a terminal, then a human's approval is simulated by calling ``resume.resume``
directly with an injected terminal and a scripted ``approve`` (the injection lives in the executor factory and the
``isatty`` keyword; the CLI never offers either). The apply runs exactly the plan the gate recorded, Ansible
configures localhost from the outputs, the host spec renders, both helpers run (the PowerShell one is replaced by a
stub reporting ``skipped`` when ``pwsh`` is missing), ``finally`` runs once and no placeholder secret reaches any
file code-orca wrote. A reject omits the apply and everything after it.

Needs ``terraform`` and ``ansible-playbook`` (skipped otherwise). The role's ``app_config_dir`` points at a
temporary directory OUTSIDE the project copy (``app.conf`` holds the token by design). The applied
``terraform/app/terraform.tfstate`` holds the stack's sensitive variable in clear, as every Terraform state does: it is
never read and is excluded from the scan, as is the workflow file whose input defaults ARE the placeholders.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sys
from pathlib import Path

import pytest

from codeorca import cli
from codeorca.config import load_workflow
from codeorca.project import load_project
from codeorca.redact import SecretRegistry, scan_outputs
from codeorca.resume import needed_secret_inputs, resume
from codeorca.rundir import RunDir, list_runs
from codeorca.runner import EXIT_FAILED, EXIT_OK, EXIT_WAITING, StepResult
from codeorca.secrets import build_registry, key_denylist, line_hook, record_filter
from codeorca.steps import gate as gate_step
from codeorca.steps.powershell_step import find_pwsh

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = ROOT / "examples" / "reference"
KEY = "example-not-secret-ci-key"
APP_SECRET = "FIXTURE-SECRET-reference-demo-001"
TOKEN = "FIXTURE-SECRET-reference-demo-token-001"


def ansible_available() -> bool:
    # duplicated from tests/ansible/ansible_support.py: pytest puts only this file's directory on sys.path
    if shutil.which("ansible-playbook"):
        return True
    return (
        importlib.util.find_spec("ansible") is not None and (Path(sys.executable).parent / "ansible-playbook").exists()
    )


pytestmark = [
    pytest.mark.skipif(shutil.which("terraform") is None, reason="terraform not on PATH"),
    pytest.mark.skipif(not ansible_available(), reason="ansible-playbook is not available"),
]


@pytest.fixture
def project(tmp_path: Path, monkeypatch) -> Path:
    root = tmp_path / "reference"
    shutil.copytree(REFERENCE, root, ignore=shutil.ignore_patterns(".codeorca", "specs", ".terraform*", "*.tfstate*"))
    monkeypatch.setenv("CODEORCA_REDACTION_KEY", KEY)
    monkeypatch.delenv("TF_VAR_app_secret", raising=False)
    monkeypatch.delenv("CI", raising=False)
    # no terminal, whatever pytest's capture mode: `pytest -s` in a terminal must not reach a real prompt (the
    # human side injects its own isatty and prompt)
    monkeypatch.setattr("os.isatty", lambda fd: False)
    return root


def first_run(project: Path, config_dir: Path, capsys) -> RunDir:
    """The agent-like run through the CLI: no terminal (os.isatty patched in the fixture), so the gate waits."""
    p = str(project / "codeorca.yaml")
    assert cli.main(["run", "demo-rollout", "-p", p, "--input", f"config_dir={config_dir}"]) == EXIT_WAITING
    out = capsys.readouterr().out
    assert APP_SECRET not in out and TOKEN not in out
    (run_id,) = list_runs(project / ".codeorca" / "runs")
    run_dir = RunDir(project / ".codeorca" / "runs", run_id)
    record = run_dir.read_run()
    assert record["status"] == "waiting" and record["exit_code"] == EXIT_WAITING
    assert record["steps"]["approve"]["status"] == "waiting"
    for later in ("apply_app", "configure", "host_spec", "dns_check", "config_audit", "summary"):
        assert record["steps"][later]["status"] is None, later  # finally does not run at a wait
    assert record["inputs"]["app_secret"] == "<redacted:key>" and record["inputs"]["api_token"] == "<redacted:key>"
    return run_dir


def pwsh_stub(step, ctx) -> StepResult:
    return StepResult("skipped", result={"reason": "pwsh not on PATH (test stub)"})


def resume_as_a_human(project: Path, run_dir: RunDir, decision: str, approver: str = "alice") -> tuple[int, list]:
    """``resume.resume`` as the CLI calls it, plus the two test-only injections: the gate executor's terminal and
    prompt, and ``resume``'s own ``isatty``. A fresh registry, as a new process would have."""
    proj = load_project(project / "codeorca.yaml")
    env = dict(os.environ)
    registry = build_registry(proj, env)
    executors = cli._executors(registry, None)
    executors["gate"] = gate_step.make_executor(registry, isatty=lambda fd: True, prompt=lambda text, t: decision)
    if find_pwsh() is None:
        executors["powershell"] = pwsh_stub
    workflow = load_workflow(project / "workflows" / "demo-rollout.yaml")
    needed = needed_secret_inputs(workflow, run_dir.read_run())
    denylist = key_denylist(proj)
    rc = resume(
        proj,
        run_dir,
        decision,
        executors=executors,
        isatty=lambda fd: True,
        secret_inputs={"api_token": TOKEN} if "api_token" in needed else {},
        workflow=workflow,
        env=env,
        stream=line_hook(registry),
        redact=record_filter(registry, denylist),
        registry=registry,
        cwd=proj.root,
        getuser=lambda: approver,
    )
    return rc, needed


def assert_no_placeholder_secret(project: Path, run_dir: RunDir) -> None:
    check = SecretRegistry(KEY.encode(), "env:test")
    check.add(APP_SECRET)
    check.add(TOKEN)
    assert scan_outputs(run_dir.path, check) == []
    assert scan_outputs(project / "specs", check) == []
    allowed = {project / "workflows" / "demo-rollout.yaml"}  # the input defaults ARE the placeholders
    for path in project.rglob("*"):
        if not path.is_file() or path in allowed:
            continue
        rel = path.relative_to(project).as_posix()
        if rel.startswith("terraform/app/terraform.tfstate") or "/.terraform/" in f"/{rel}":
            continue  # Terraform's own state holds the sensitive variable by design; never read by code-orca
        text = path.read_bytes().decode("utf-8", "replace")
        assert APP_SECRET not in text and TOKEN not in text, rel


def test_wait_refuse_then_approve_applies_configures_and_finishes(project: Path, tmp_path: Path, capsys):
    config_dir = tmp_path / "app-config"
    run_dir = first_run(project, config_dir, capsys)
    plan_file = Path(run_dir.read_run()["steps"]["plan_app"]["outputs"]["plan_file"])
    assert plan_file.is_file()

    # the CLI refuses without a terminal, for either decision, and changes nothing
    p = str(project / "codeorca.yaml")
    for decision in ("--approve", "--reject"):
        assert cli.main(["resume", "latest", decision, "-p", p]) == 1
        assert "needs an interactive terminal" in capsys.readouterr().err
    assert run_dir.read_run()["status"] == "waiting"

    rc, needed = resume_as_a_human(project, run_dir, "approve")
    record = run_dir.read_run()
    statuses = {sid: st["status"] for sid, st in record["steps"].items()}
    assert rc == EXIT_OK, (statuses, {sid: st["error"] for sid, st in record["steps"].items() if st["error"]})
    assert needed == ["api_token"]  # configure uses it; the apply needs nothing (the plan file carries app_secret)
    assert record["status"] == "succeeded" and record["exit_code"] == EXIT_OK
    assert [r["decision"] for r in record["resumes"]] == ["approve"] and record["resumes"][0]["approver"] == "alice"
    assert record["steps"]["plan_app"]["attempts"] == 1  # replayed, not re-planned
    for sid in ("approve", "apply_app", "configure", "host_spec", "dns_check", "summary"):
        assert statuses[sid] == "succeeded", (sid, record["steps"][sid])
    assert statuses["config_audit"] == ("succeeded" if find_pwsh() else "skipped")

    # the apply ran the plan the gate bound, then deleted it
    assert not plan_file.exists()
    apply_result = run_dir.read_result("apply_app")
    assert apply_result["applied"] is True and apply_result["gate"] == "approve" and apply_result["approver"] == "alice"
    tf = record["steps"]["apply_app"]["outputs"]["tf"]
    assert tf["app_host"]["value"] == "127.0.0.1" and tf["app_token"]["value"].startswith("<redacted:hmac:")

    # Ansible configured localhost from the outputs, with the real token (outside the project)
    conf = (config_dir / "app.conf").read_text(encoding="utf-8")
    assert TOKEN in conf and "bucket = example-app-123456789012" in conf
    host_spec = (project / "specs" / "app" / "hosts" / "app-host.yaml").read_text(encoding="utf-8")
    assert "<secret: declared>" in host_spec and "workflow: demo-rollout" in host_spec

    # both helpers
    assert record["steps"]["dns_check"]["outputs"]["resolved"] is True
    if find_pwsh():
        assert record["steps"]["config_audit"]["outputs"]["ok"] is True
        assert (run_dir.step_dir("config_audit") / "audit.txt").is_file()  # ShouldProcess let it through

    # finally ran exactly once, at the real end
    assert record["steps"]["summary"]["attempts"] == 1
    summary_log = (run_dir.step_dir("summary") / "stdout.log").read_text(encoding="utf-8")
    assert summary_log.count(f"run {run_dir.run_id}: demo-rollout") == 1

    assert_no_placeholder_secret(project, run_dir)


def test_reject_omits_the_apply_and_everything_after_it(project: Path, tmp_path: Path, capsys):
    config_dir = tmp_path / "app-config"
    run_dir = first_run(project, config_dir, capsys)
    plan_file = Path(run_dir.read_run()["steps"]["plan_app"]["outputs"]["plan_file"])

    rc, _ = resume_as_a_human(project, run_dir, "reject", approver="bob")
    record = run_dir.read_run()
    statuses = {sid: st["status"] for sid, st in record["steps"].items()}
    assert rc == EXIT_FAILED and record["status"] == "failed"
    assert statuses["approve"] == "failed" and "rejected by bob" in record["steps"]["approve"]["error"]
    for sid in ("apply_app", "configure", "host_spec", "dns_check", "config_audit"):
        assert statuses[sid] == "omitted", (sid, statuses[sid])
    assert statuses["summary"] == "succeeded" and record["steps"]["summary"]["attempts"] == 1
    assert not (config_dir / "app.conf").exists()  # Ansible never ran
    assert not (project / "terraform" / "app" / "terraform.tfstate").exists()  # nothing applied
    assert plan_file.is_file()  # the reviewed plan is left in the run dir (0600), never applied
    assert json.loads((run_dir.path / "run.json").read_text(encoding="utf-8"))["decision"] == "reject"
    assert_no_placeholder_secret(project, run_dir)
