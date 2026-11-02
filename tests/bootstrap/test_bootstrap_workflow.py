"""The reference bootstrap-backend workflow validates, and its wrapper refuses the reference (local) backend."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from codeorca.config import load_workflow

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = ROOT / "examples" / "reference"


def test_bootstrap_backend_workflow_validates():
    wf = load_workflow(REFERENCE / "workflows" / "bootstrap-backend.yaml")
    assert wf.name == "bootstrap-backend"
    (step,) = wf.steps
    assert step.type == "python" and step.script == "helpers/bootstrap_backend.py"
    assert (REFERENCE / step.script).is_file()


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
