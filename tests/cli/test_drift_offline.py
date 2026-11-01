"""``codeorca drift`` without a terraform binary: every failure is a verdict row and exit 1, never a traceback."""

from __future__ import annotations

import shutil
from pathlib import Path

from codeorca import cli
from codeorca.steps import lookup

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = ROOT / "examples" / "reference"


def test_missing_engine_is_an_error_row(tmp_path: Path, monkeypatch, capsys):
    root = tmp_path / "reference"
    shutil.copytree(REFERENCE, root, ignore=shutil.ignore_patterns(".codeorca", "specs"))
    monkeypatch.setenv("CODEORCA_REDACTION_KEY", "example-not-secret-key")
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    assert cli.main(["drift", "-p", str(root / "codeorca.yaml")]) == 1
    out = capsys.readouterr().out
    assert "app    error" in out and "not found on PATH" in out
    assert (root / ".codeorca" / "runs").is_dir() and not (root / "specs").exists()


def test_run_registers_the_real_executors(tmp_path: Path, monkeypatch, capsys):
    root = tmp_path / "reference"
    shutil.copytree(REFERENCE, root, ignore=shutil.ignore_patterns(".codeorca", "specs"))
    monkeypatch.setenv("CODEORCA_REDACTION_KEY", "example-not-secret-key")
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    assert cli.main(["run", "plan-only", "-p", str(root / "codeorca.yaml")]) == 1  # no terraform: plan_app errored
    assert lookup("terraform").__name__ == "run_terraform" and lookup("spec-render").__name__ == "run_spec_render"
    assert "not found on PATH" in capsys.readouterr().out
