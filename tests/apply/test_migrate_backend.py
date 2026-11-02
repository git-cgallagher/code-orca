"""``migrate_backend`` with real Terraform and two local backends (``path=`` through ``-backend-config``): it needs
an approving gate, refuses a target that already holds a state, and otherwise moves the state with
``init -migrate-state -force-copy``. State files are only checked for existence, never read."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from codeorca.adapters.terraform import TerraformRunner, plan_file_sha256
from codeorca.models import Workflow
from codeorca.project import Stack, load_project
from codeorca.redact import SecretRegistry
from codeorca.rundir import RunDir
from codeorca.runner import Runner
from codeorca.steps import default_executors
from codeorca.steps import gate as gate_step
from codeorca.steps import terraform as terraform_step

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = ROOT / "examples" / "reference"

pytestmark = pytest.mark.skipif(shutil.which("terraform") is None, reason="terraform not on PATH")

STACK_TF = """terraform {
  backend "local" {}
}

resource "terraform_data" "marker" {
  input = "migrate-me"
}
"""

GATE = {"id": "approve", "type": "gate", "message": "migrate the state?"}
MIGRATE = {"id": "migrate", "type": "terraform", "stack": "mig", "action": "migrate_backend", "needs": ["approve"]}


def env() -> dict:
    return {k: v for k, v in os.environ.items() if not k.startswith(("TF_", "CODEORCA_")) and k != "CI"}


def apply_at(stack_dir: Path, state: Path) -> None:
    """init against ``state`` and apply one resource there (the test's own setup, outside the orchestrator)."""
    runner = TerraformRunner(stack_dir, env())
    assert runner.init({"path": str(state)}, reconfigure=True).exit_code == 0
    plan = runner.plan(stack_dir / "setup.tfplan")
    assert plan.exit_code == 2
    assert runner.apply(plan.plan_file, plan_file_sha256(plan.plan_file)).exit_code == 0
    Path(plan.plan_file).unlink()


@pytest.fixture
def setup(tmp_path: Path, monkeypatch):
    root = tmp_path / "reference"
    shutil.copytree(REFERENCE, root, ignore=shutil.ignore_patterns(".codeorca", "specs", ".terraform*", "*.tfstate*"))
    stack_dir = root / "terraform" / "mig"
    stack_dir.mkdir()
    (stack_dir / "main.tf").write_text(STACK_TF, encoding="utf-8")
    project = load_project(root / "codeorca.yaml")
    project.stacks["mig"] = Stack(dir="terraform/mig", key="example/mig/terraform.tfstate")
    source, target = tmp_path / "A" / "mig.tfstate", tmp_path / "B" / "mig.tfstate"
    source.parent.mkdir()
    target.parent.mkdir()
    apply_at(stack_dir, source)
    # the project's backend is `local`, which renders no -backend-config: point the step at path B
    monkeypatch.setattr(terraform_step, "backend_config", lambda project, stack: {"path": str(target)})
    return project, stack_dir, source, target


def run(project, steps: list[dict], *, dry_run=False) -> Runner:
    registry = SecretRegistry(b"example-not-secret-key", "env:test")
    executors = default_executors()
    executors["terraform"] = terraform_step.make_executor(registry)
    executors["gate"] = gate_step.make_executor(
        registry, prompt=lambda t, s: "approve", isatty=lambda fd: True, out=lambda t: None
    )
    wf = Workflow.model_validate({"api": "codeorca/v1", "kind": "workflow", "name": "m", "steps": steps})
    r = Runner(project, wf, {}, RunDir(project.root / project.state_dir), executors, dry_run=dry_run, env=env())
    r.run()
    return r


def test_migrate_backend_moves_the_state_after_an_approval(setup):
    project, stack_dir, source, target = setup
    r = run(project, [GATE, MIGRATE])
    st = r.states["migrate"]
    assert st["status"] == "succeeded", st["error"]
    result = r.run_dir.read_result("migrate")
    assert result["migrated"] is True and result["gate"] == "approve" and result["backend"] == {"path": str(target)}
    assert target.exists() and source.exists()  # copied, the old one left alone
    argv = json.loads((r.run_dir.steps_dir / "migrate" / "argv.json").read_text(encoding="utf-8"))
    migrate = [a for a in argv if "-migrate-state" in a]
    assert len(migrate) == 1 and "-force-copy" in migrate[0] and "-json" not in migrate[0]
    listed = TerraformRunner(stack_dir, env())._run(["state", "list", "-no-color"], stream_stdout=False)
    assert listed.stdout_lines == ["terraform_data.marker"]  # the stack now reads its state from B


def test_migrate_backend_without_a_gate_is_refused(setup):
    project, stack_dir, source, target = setup
    r = run(project, [{**MIGRATE, "needs": []}])
    assert r.states["migrate"]["status"] == "failed"
    assert "needs an approving gate upstream" in r.states["migrate"]["error"]
    assert not target.exists()


def test_migrate_backend_after_a_rejection_is_refused(setup):
    project, stack_dir, source, target = setup
    registry = SecretRegistry(b"example-not-secret-key", "env:test")
    executors = default_executors()
    executors["terraform"] = terraform_step.make_executor(registry)
    executors["gate"] = gate_step.make_executor(
        registry, prompt=lambda t, s: "reject", isatty=lambda fd: True, out=lambda t: None
    )
    wf = Workflow.model_validate(
        {"api": "codeorca/v1", "kind": "workflow", "name": "m", "steps": [GATE, {**MIGRATE, "when": "always()"}]}
    )
    r = Runner(project, wf, {}, RunDir(project.root / project.state_dir), executors, env=env())
    r.run()
    assert "decision 'reject'" in r.states["migrate"]["error"] and not target.exists()


def test_migrate_backend_refuses_a_target_that_already_holds_a_state(setup, tmp_path):
    project, stack_dir, source, target = setup
    other = tmp_path / "other"
    other.mkdir()
    (other / "main.tf").write_text(STACK_TF, encoding="utf-8")
    apply_at(other, target)  # somebody else's state already lives at B
    before = target.stat().st_mtime_ns
    r = run(project, [GATE, MIGRATE])
    st = r.states["migrate"]
    assert st["status"] == "failed"
    assert "already holds a state (1 resources)" in st["error"] and "refusing to overwrite" in st["error"]
    assert target.stat().st_mtime_ns == before  # untouched
    argv = json.loads((r.run_dir.steps_dir / "migrate" / "argv.json").read_text(encoding="utf-8"))
    assert not any("-migrate-state" in a for a in argv)


def test_migrate_backend_under_dry_run_moves_nothing(setup):
    project, stack_dir, source, target = setup
    r = run(project, [GATE, MIGRATE], dry_run=True)
    assert r.states["migrate"]["status"] == "skipped" and not target.exists()


def test_a_local_backend_without_a_target_is_refused(setup, monkeypatch):
    project, stack_dir, source, target = setup
    monkeypatch.setattr(terraform_step, "backend_config", lambda project, stack: {})
    r = run(project, [GATE, MIGRATE])
    assert "renders no backend config to migrate to" in r.states["migrate"]["error"]
