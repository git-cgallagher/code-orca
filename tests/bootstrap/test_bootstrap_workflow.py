"""The reference bootstrap-backend workflow validates, and its wrapper refuses the reference (local) backend."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

from codeorca.config import load_workflow
from codeorca.project import load_project
from codeorca.redact import SecretRegistry
from codeorca.rundir import RunDir
from codeorca.runner import EXIT_FAILED, Runner
from codeorca.steps import default_executors, python_step

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = ROOT / "examples" / "reference"


def test_bootstrap_backend_workflow_validates():
    wf = load_workflow(REFERENCE / "workflows" / "bootstrap-backend.yaml")
    assert wf.name == "bootstrap-backend"
    step, *validates = wf.steps
    assert step.type == "python" and step.script == "helpers/bootstrap_backend.py"
    assert (REFERENCE / step.script).is_file()
    project = load_project(REFERENCE / "codeorca.yaml")
    # one init + validate per stack, in depends_on order, each after the bootstrap
    assert [v.stack for v in validates] == list(project.stack_order())
    assert all(v.type == "terraform" and v.action == "validate" and v.needs == ["bootstrap"] for v in validates)


def test_the_wrapper_runs_through_the_real_python_step(tmp_path):
    """The workflow's bootstrap step through the python executor (``python -I``, cwd = project root): on the
    reference (local) backend the helper refuses, the step fails with that message, the validate steps are omitted
    and nothing is written. No AWS: the refusal comes before any client is built."""
    root = tmp_path / "reference"
    shutil.copytree(REFERENCE, root, ignore=shutil.ignore_patterns(".codeorca", "specs", ".terraform*", "*.tfstate*"))
    project = load_project(root / "codeorca.yaml")
    wf = load_workflow(root / "workflows" / "bootstrap-backend.yaml")
    registry = SecretRegistry(b"example-not-secret", "env:test")
    executors = default_executors()
    executors["python"] = python_step.make_executor(registry, None)
    runner = Runner(project, wf, {}, RunDir(root / project.state_dir), executors, cwd=root)
    assert runner.run() == EXIT_FAILED
    state = runner.states["bootstrap"]
    assert state["status"] == "failed" and "local backend has nothing to bootstrap" in state["error"]
    assert runner.states["validate_app"]["status"] == "omitted"
    assert not (root / "terraform" / "app" / "backend.hcl").exists()


def test_wrapper_refuses_the_reference_local_backend(tmp_path):
    out = tmp_path / "output.json"
    proc = subprocess.run(
        [sys.executable, "-I", str(REFERENCE / "helpers" / "bootstrap_backend.py"), "--output-file", str(out)],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=tmp_path,
    )
    assert proc.returncode == 2
    assert "local backend has nothing to bootstrap" in proc.stderr
    assert not out.exists()
    assert not (REFERENCE / "terraform" / "app" / "backend.hcl").exists()
