"""``codeorca run`` without a terraform binary: input resolution through the CLI and what a refused run leaves."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

from codeorca import cli
from codeorca.rundir import list_runs

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = ROOT / "examples" / "reference"


def reference_copy(tmp_path: Path, monkeypatch) -> Path:
    root = tmp_path / "reference"
    shutil.copytree(REFERENCE, root, ignore=shutil.ignore_patterns(".codeorca", "specs"))
    monkeypatch.setenv("CODEORCA_REDACTION_KEY", "example-not-secret-key")
    return root


def write_workflow(root: Path, name: str, inputs: str, step: str) -> None:
    head = f"api: codeorca/v1\nkind: workflow\nname: {name}\n"
    if inputs:
        head += f"inputs:\n{inputs}"
    (root / "workflows" / f"{name}.yaml").write_text(f"{head}steps:\n{step}", encoding="utf-8")


def test_optional_input_without_a_value_runs(tmp_path: Path, monkeypatch, capsys):
    root = reference_copy(tmp_path, monkeypatch)
    write_workflow(
        root,
        "opt",
        "  note: { type: string }\n",
        f"  - id: a\n    type: shell\n    run: [{sys.executable!r}, '-c', 'pass']\n",
    )
    assert cli.main(["run", "opt", "-p", str(root / "codeorca.yaml")]) == 0
    assert "a     succeeded" in capsys.readouterr().out


def test_refused_run_leaves_no_run_directory(tmp_path: Path, monkeypatch, capsys):
    root = reference_copy(tmp_path, monkeypatch)
    write_workflow(root, "fe", "", f"  - id: a\n    type: shell\n    for_each: [1]\n    run: [{sys.executable!r}]\n")
    assert cli.main(["run", "fe", "-p", str(root / "codeorca.yaml")]) == 1
    assert "for_each is not implemented" in capsys.readouterr().err
    assert list_runs(root / ".codeorca" / "runs") == []


def test_run_registers_the_real_executors_but_default_executors_stays_phase1():
    from codeorca.redact import SecretRegistry
    from codeorca.steps import default_executors

    executors = cli._executors(SecretRegistry(b"example-not-secret", "env:test"))
    assert executors["ansible"].__name__ == "run_ansible"
    assert callable(executors["terraform"])
    assert executors["spec-render"].__name__ == "run_spec_render"
    assert default_executors()["ansible"].__name__ != "run_ansible"  # the placeholder, untouched
