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


def test_locked_stack_is_an_error_row(tmp_path: Path, monkeypatch, capsys):
    from codeorca.rundir import stack_lock

    root = tmp_path / "reference"
    shutil.copytree(REFERENCE, root, ignore=shutil.ignore_patterns(".codeorca", "specs"))
    monkeypatch.setenv("CODEORCA_REDACTION_KEY", "example-not-secret-key")
    with stack_lock(root / ".codeorca" / "runs", "app"):
        assert cli.main(["drift", "-p", str(root / "codeorca.yaml")]) == 1
    out = capsys.readouterr().out
    assert "app    error" in out and "stack 'app' is locked" in out


def two_stack_project(tmp_path: Path, monkeypatch) -> Path:
    """The reference copy plus a `network` stack that `app` depends on."""
    root = tmp_path / "reference"
    shutil.copytree(REFERENCE, root, ignore=shutil.ignore_patterns(".codeorca", "specs"))
    (root / "terraform" / "network").mkdir()
    (root / "terraform" / "network" / "main.tf").write_text('output "x" { value = 1 }\n', encoding="utf-8")
    text = (root / "codeorca.yaml").read_text(encoding="utf-8")
    text = text.replace(
        "stacks:\n  app:\n",
        "stacks:\n  network:\n    dir: terraform/network\n    key: example/network/terraform.tfstate\n  app:\n",
    ).replace("    depends_on: []\n", "    depends_on: [network]\n")
    (root / "codeorca.yaml").write_text(text, encoding="utf-8")
    monkeypatch.setenv("CODEORCA_REDACTION_KEY", "example-not-secret-key")
    return root


def fake_sessions(monkeypatch, outcomes: dict[str, tuple[int, bool]]) -> list[str]:
    """Replace open_session/plan_stack (imported inside cmd_drift) with fakes driven by ``outcomes``:
    ``{stack: (exit_code, changed)}``. Returns the list the fakes append each planned stack to."""
    import json

    from codeorca.steps import terraform as tf

    order: list[str] = []

    class Session:
        def __init__(self, name, step_dir):
            self.stack_name, self.step_dir = name, step_dir

        def init(self):
            pass

        def record(self):
            pass

    def open_session(project, name, registry, step_dir, env, stack_ctx, **kw):
        return Session(name, step_dir)

    def plan_stack(session, **kw):
        order.append(session.stack_name)
        code, changed = outcomes[session.stack_name]
        if code == 1:
            return tf.PlanOutcome(1, False, "", "", {}, {}, "plan failed (exit 1): boom")
        counts = {"add": 1 if changed else 0, "change": 0, "remove": 0, "replace": 0}
        document = {
            "kind": "terraform_plan",
            "stack": session.stack_name,
            "engine": {"name": "terraform", "version": "1.14.7"},
            "summary": {"counts": counts, "gate": {"passed": True, "blocked": [], "replacements": []}},
        }
        plan_json = session.step_dir / "plan.json"
        plan_json.write_text(json.dumps(document), encoding="utf-8")
        result = {"summary": document["summary"], "gate": document["summary"]["gate"], "warnings": []}
        return tf.PlanOutcome(code, changed, "", str(plan_json), document, result)

    monkeypatch.setattr(tf, "open_session", open_session)
    monkeypatch.setattr(tf, "plan_stack", plan_stack)
    return order


def test_drift_walks_stacks_in_depends_on_order_and_aggregates_verdicts(tmp_path: Path, monkeypatch, capsys):
    root = two_stack_project(tmp_path, monkeypatch)
    p = str(root / "codeorca.yaml")
    order = fake_sessions(monkeypatch, {"network": (0, False), "app": (2, True)})
    assert cli.main(["drift", "-p", p]) == 2
    out = capsys.readouterr().out.splitlines()
    assert order == ["network", "app"]  # app depends on network, whatever the file order says
    assert out[1].startswith("network  clean") and out[2].startswith("app      drift    add 1")

    order = fake_sessions(monkeypatch, {"network": (1, False), "app": (2, True)})
    assert cli.main(["drift", "-p", p]) == 1  # an error outranks drift, whichever stack produced it
    out = capsys.readouterr().out
    assert "network  error    plan failed (exit 1): boom" in out and "app      drift" in out
    order = fake_sessions(monkeypatch, {"network": (2, True), "app": (1, False)})
    assert cli.main(["drift", "-p", p]) == 1
    capsys.readouterr()
