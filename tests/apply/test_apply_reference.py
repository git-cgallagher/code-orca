"""plan -> gate (waiting, exit 3) -> resume --approve (fake terminal) -> apply, against the provider-free reference
stack in a temporary copy, with real Terraform (skipped without ``terraform`` on PATH).

The resume is a fresh registry, as a new process would have: the apply must register the plan's sensitive values
from ``show -json`` before anything streams. The placeholder secret must never reach the run directory."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from codeorca.models import Workflow
from codeorca.project import load_project
from codeorca.redact import SecretRegistry, scan_outputs
from codeorca.resume import resume
from codeorca.rundir import RunDir
from codeorca.runner import EXIT_OK, EXIT_WAITING, Runner
from codeorca.secrets import key_denylist, line_hook, record_filter, seed_inputs
from codeorca.steps import default_executors
from codeorca.steps import gate as gate_step
from codeorca.steps import terraform as terraform_step

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = ROOT / "examples" / "reference"
SECRET = "FIXTURE-SECRET-reference-apply-001"
KEY = b"example-not-secret-ci-key"

pytestmark = pytest.mark.skipif(shutil.which("terraform") is None, reason="terraform not on PATH")

WF = Workflow.model_validate(
    {
        "api": "codeorca/v1",
        "kind": "workflow",
        "name": "apply-reference",
        "inputs": {"app_secret": {"type": "string", "required": True}},
        "steps": [
            {
                "id": "plan_app",
                "type": "terraform",
                "stack": "app",
                "action": "plan",
                "var_overrides": {"environment": "dev", "app_secret": "${{ inputs.app_secret }}"},
                "outputs": {"plan_file": "${{ result.files.plan_file }}"},
            },
            {"id": "approve", "type": "gate", "needs": ["plan_app"], "message": "apply the app stack?"},
            {
                "id": "apply_app",
                "type": "terraform",
                "needs": ["approve"],
                "stack": "app",
                "action": "apply",
                "plan_file": "${{ steps.plan_app.outputs.plan_file }}",
                "outputs": {"tf": "${{ result.tf_outputs }}"},
            },
        ],
    }
)


def executors(registry: SecretRegistry, tty: bool) -> dict:
    ex = default_executors()
    ex["terraform"] = terraform_step.make_executor(registry)
    ex["gate"] = gate_step.make_executor(registry, isatty=lambda fd: tty, prompt=lambda t, s: "approve")
    return ex


def test_plan_wait_resume_apply_end_to_end(tmp_path, monkeypatch):
    root = tmp_path / "reference"
    shutil.copytree(REFERENCE, root, ignore=shutil.ignore_patterns(".codeorca", "specs", ".terraform*", "*.tfstate*"))
    project = load_project(root / "codeorca.yaml")
    env = {k: v for k, v in os.environ.items() if not k.startswith(("TF_", "CODEORCA_")) and k != "CI"}
    denylist = key_denylist(project)

    # 1. the agent-like run: no terminal, so the gate waits
    registry = SecretRegistry(KEY, "env:test")
    inputs = {"app_secret": SECRET}
    seed_inputs(registry, inputs, denylist)
    rd = RunDir(root / project.state_dir)
    runner = Runner(
        project,
        WF,
        inputs,
        rd,
        executors(registry, tty=False),
        env=env,
        stream=line_hook(registry),
        redact=record_filter(registry, denylist),
    )
    assert runner.run() == EXIT_WAITING
    plan = Path(runner.states["plan_app"]["outputs"]["plan_file"])
    assert plan.is_file()
    assert rd.read_run()["steps"]["apply_app"]["status"] is None

    # 2. a human on a terminal approves, in a "new process": a fresh registry, nothing re-supplied (the apply
    # needs no input; the plan file carries the variables)
    fresh = SecretRegistry(KEY, "env:test")
    rc = resume(
        project,
        rd,
        "approve",
        executors=executors(fresh, tty=True),
        isatty=lambda fd: True,
        workflow=WF,
        env=env,
        stream=line_hook(fresh),
        redact=record_filter(fresh, denylist),
        registry=fresh,
        getuser=lambda: "alice",
    )
    run = rd.read_run()
    assert rc == EXIT_OK, run["steps"]["apply_app"]
    assert run["steps"]["plan_app"]["attempts"] == 1  # replayed, not re-planned
    apply = run["steps"]["apply_app"]
    assert apply["status"] == "succeeded"
    assert not plan.exists()  # deleted after the apply
    result = rd.read_result("apply_app")
    assert result["applied"] is True and result["approver"] == "alice" and result["gate"] == "approve"
    token = apply["outputs"]["tf"]["app_token"]
    assert token["sensitive"] is True and token["value"] == fresh.placeholder(SECRET)
    assert apply["outputs"]["tf"]["app_host"]["value"] == "127.0.0.1"
    tf_outputs = json.loads(Path(result["files"]["tf_outputs"]).read_text(encoding="utf-8"))
    assert tf_outputs["app_token"]["value"].startswith("<redacted:hmac:")
    assert (root / "terraform" / "app" / "terraform.tfstate").exists()  # applied (existence only, never read)

    # 3. the placeholder secret is nowhere under the run directory, in any encoding
    check = SecretRegistry(KEY, "env:test")
    check.add(SECRET)
    assert scan_outputs(rd.path, check) == []
