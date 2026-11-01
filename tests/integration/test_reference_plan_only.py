"""The reference project end to end through the CLI: plan-only workflow, drift, render, summary, gc.

Needs ``terraform`` on PATH (skipped otherwise). Runs on a temporary copy of the reference project, so nothing
under ``examples/`` changes. The placeholder secret ``FIXTURE-SECRET-reference-001`` is the workflow input's
default; the whole point of the test is that it never reaches a spec, a log or the run directory.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from codeorca import cli
from codeorca.redact import PLACEHOLDER_RE, SecretRegistry, scan_outputs
from codeorca.rundir import list_runs

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = ROOT / "examples" / "reference"
SECRET = "FIXTURE-SECRET-reference-001"
KEY = "example-not-secret-ci-key"
needs_terraform = pytest.mark.skipif(shutil.which("terraform") is None, reason="terraform not on PATH")

pytestmark = needs_terraform


@pytest.fixture
def project(tmp_path: Path, monkeypatch) -> Path:
    root = tmp_path / "reference"
    shutil.copytree(REFERENCE, root, ignore=shutil.ignore_patterns(".codeorca", "specs", ".terraform*", "*.tfstate*"))
    monkeypatch.setenv("CODEORCA_REDACTION_KEY", KEY)
    monkeypatch.delenv("TF_VAR_app_secret", raising=False)
    monkeypatch.delenv("CI", raising=False)
    return root


def registry_with_secret() -> SecretRegistry:
    r = SecretRegistry(KEY.encode(), "env:test")
    r.add(SECRET)
    return r


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def body(spec: Path) -> str:
    """The spec minus its header lines (git_sha differs between a checkout and a temp copy)."""
    return spec.read_text(encoding="utf-8").split("\ndrift:", 1)[1]


def test_plan_only_end_to_end_redacted_deterministic(project: Path, capsys):
    p = str(project / "codeorca.yaml")
    assert cli.main(["run", "plan-only", "-p", p]) == 0
    out = capsys.readouterr().out
    assert "plan_app   succeeded" in out and "plan_spec  succeeded" in out and "show_spec  succeeded" in out
    assert SECRET not in out

    spec = project / "specs" / "app" / "plan.yaml"
    sidecar = project / "specs" / "app" / "plan.meta.yaml"
    assert spec.exists() and sidecar.exists()
    text = read(spec)
    assert "<redacted:hmac:" in text and SECRET not in text
    assert "variables:\n  app_secret:\n    sensitive: true\n  environment:" in text
    assert "rendered: '<never rendered: stack policy>'" in text  # app_token
    assert "gate: pass" in text and "engine: terraform/" in text and "workflow: plan-only" in text
    runs = list_runs(project / ".codeorca" / "runs")
    assert len(runs) == 1
    run_id = runs[0]
    assert run_id not in text and "generated_at" not in text and "plan_sha256" not in text
    meta = read(sidecar)
    assert f"run_id: {run_id}" in meta and "generated_at:" in meta and "plan_sha256:" in meta

    run_dir = project / ".codeorca" / "runs" / run_id
    staged = run_dir / "specs" / "app" / "plan.yaml"
    assert staged.exists() and read(staged) == text
    assert (run_dir / "steps" / "plan_app" / "plan.tfplan").exists()
    assert (run_dir / "steps" / "plan_app" / "plan.json").exists()
    argv = json.loads(read(run_dir / "steps" / "plan_app" / "argv.json"))
    assert [a[1] for a in argv] == ["init", "version", "plan", "show", "providers"]
    assert any("-var-file=" in tok for tok in argv[2])
    assert not any("-lockfile=readonly" in tok for tok in argv[0])
    record = json.loads(read(run_dir / "run.json"))
    assert record["inputs"]["app_secret"] == "<redacted:key>" and record["status"] == "succeeded"
    assert record["steps"]["plan_app"]["outputs"]["changed"] is True
    result = json.loads(read(run_dir / "steps" / "plan_app" / "result.json"))
    assert result["sensitive_variables"] == ["app_secret"] and result["sensitive_outputs"] == ["app_token"]
    assert result["gate"]["passed"] is True and result["registered_overrides"] == ["app_secret"]
    assert "app_token" not in result["prior_outputs"]
    assert read(run_dir / "steps" / "show_spec" / "stdout.log").startswith("spec written to ")

    registry = registry_with_secret()
    assert scan_outputs(run_dir, registry) == []
    assert scan_outputs(project / "specs", registry) == []
    assert not list(project.rglob("*.tfvars.json"))  # the temporary override var file was deleted

    # determinism: a second run yields a byte-identical spec body (header too: same checkout, same key)
    assert cli.main(["run", "plan-only", "-p", p]) == 0
    capsys.readouterr()
    assert read(spec) == text

    # a different secret changes the placeholder, nothing else
    assert cli.main(["run", "plan-only", "-p", p, "--input", "app_secret=FIXTURE-SECRET-reference-002"]) == 0
    capsys.readouterr()
    changed = read(spec)
    assert changed != text and PLACEHOLDER_RE.sub("<ph>", changed) == PLACEHOLDER_RE.sub("<ph>", text)
    assert "FIXTURE-SECRET-reference-002" not in changed


def test_summary_render_and_gc(project: Path, capsys):
    p = str(project / "codeorca.yaml")
    assert cli.main(["run", "plan-only", "-p", p]) == 0
    capsys.readouterr()
    assert cli.main(["summary", "latest", "-p", p]) == 0
    out = capsys.readouterr().out
    assert "plan-only status=succeeded" in out and "plan_spec.path = " in out and SECRET not in out

    spec = project / "specs" / "app" / "plan.yaml"
    before = read(spec)
    shutil.rmtree(project / "specs")
    assert cli.main(["render", "latest", "-p", p]) == 0
    out = capsys.readouterr().out
    assert "plan_spec" in out and "pass" in out
    assert read(spec) == before

    assert cli.main(["run", "plan-only", "-p", p]) == 0
    capsys.readouterr()
    assert len(list_runs(project / ".codeorca" / "runs")) == 2
    assert cli.main(["runs", "gc", "--keep", "1", "-p", p]) == 0
    assert "removed 1 run(s)" in capsys.readouterr().out
    assert len(list_runs(project / ".codeorca" / "runs")) == 1


def test_drift_on_the_fresh_stack_exits_2_and_writes_the_spec(project: Path, capsys, monkeypatch):
    p = str(project / "codeorca.yaml")
    assert cli.main(["drift", "-p", p]) == 1  # app_secret has no default: the plan errors, verdict error
    out = capsys.readouterr().out
    assert "error" in out and SECRET not in out
    monkeypatch.setenv("TF_VAR_app_secret", SECRET)
    monkeypatch.setenv("CI", "true")  # init -lockfile=readonly path
    assert cli.main(["drift", "-p", p]) == 2
    out = capsys.readouterr().out
    assert "app    drift    add 2" in out and SECRET not in out
    spec = project / "specs" / "app" / "plan.yaml"
    text = read(spec)
    assert "<redacted:hmac:" in text and SECRET not in text and "workflow:" not in text
    # two drift runs may share a second, and the id's hex suffix does not order them: pick by recorded exit code
    runs_dir = project / ".codeorca" / "runs"
    run_dir = next(
        runs_dir / r for r in list_runs(runs_dir) if json.loads(read(runs_dir / r / "run.json"))["exit_code"] == 2
    )
    argv = json.loads(read(run_dir / "steps" / "drift_app" / "argv.json"))
    assert "-lockfile=readonly" in argv[0] and "-lock=false" in argv[2]
    assert scan_outputs(run_dir, registry_with_secret()) == []
    assert scan_outputs(project / "specs", registry_with_secret()) == []
    assert cli.main(["summary", "latest", "-p", p]) == 0
    assert "drift" in capsys.readouterr().out
    assert cli.main(["drift", "-p", p, "--stack", "nope"]) == 1


def test_missing_redaction_key_fails_closed(project: Path, monkeypatch, capsys):
    monkeypatch.delenv("CODEORCA_REDACTION_KEY")
    assert cli.main(["run", "plan-only", "-p", str(project / "codeorca.yaml")]) == 1
    assert "CODEORCA_REDACTION_KEY" in capsys.readouterr().err
    assert not (project / ".codeorca").exists()
