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


def test_run_uses_the_real_terraform_executor_without_touching_the_global_registry(tmp_path: Path, monkeypatch, capsys):
    root = tmp_path / "reference"
    shutil.copytree(REFERENCE, root, ignore=shutil.ignore_patterns(".codeorca", "specs"))
    monkeypatch.setenv("CODEORCA_REDACTION_KEY", "example-not-secret-key")
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    assert cli.main(["run", "plan-only", "-p", str(root / "codeorca.yaml")]) == 1  # no terraform: plan_app errored
    out = capsys.readouterr().out
    assert "not found on PATH" in out and "not implemented in this phase" not in out  # the real executor ran
    assert lookup("terraform").__name__.startswith("not_implemented")  # the process-wide defaults are untouched
