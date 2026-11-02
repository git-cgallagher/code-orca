"""A stack's ``secrets:`` (``{ENV_NAME: ssm:/path}``): resolved through the run's resolver into the terraform child
env only, registered first; no provider -> ``NO_PROVIDER_MESSAGE``; an ``SSMError`` keeps its value-free message.
The live test drives ``codeorca drift`` and ``codeorca run`` with a fake resolver (no AWS) on the reference stack
(skipped without ``terraform``)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from codeorca import cli
from codeorca.project import Stack
from codeorca.providers import SSMError
from codeorca.redact import SecretRegistry, scan_outputs
from codeorca.runner import StepError
from codeorca.steps.terraform import backend_config, resolve_stack_secrets

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = ROOT / "examples" / "reference"
KEY = "example-not-secret-stack-key"
SECRET = "FIXTURE-SECRET-stack-secret-001"


def stack(**secrets: str) -> Stack:
    return Stack.model_validate({"dir": "terraform/app", "key": "example/app.tfstate", "secrets": secrets})


def test_no_secrets_never_touches_the_resolver():
    def boom(ref):
        raise AssertionError("called")

    assert resolve_stack_secrets("app", stack(), SecretRegistry(b"k" * 8, "t"), boom) == {}
    assert resolve_stack_secrets("app", stack(), SecretRegistry(b"k" * 8, "t"), None) == {}


def test_secrets_are_resolved_and_registered():
    registry = SecretRegistry(b"example-not-secret", "env:test")
    out = resolve_stack_secrets("app", stack(TF_VAR_app_secret="ssm:/example/app/secret"), registry, lambda r: SECRET)
    assert out == {"TF_VAR_app_secret": SECRET}
    assert SECRET not in registry.redact(f"x {SECRET} y")


def test_no_provider_and_provider_errors_are_value_free():
    registry = SecretRegistry(b"example-not-secret", "env:test")
    with pytest.raises(StepError, match=r"pip install 'code-orca\[aws\]'"):
        resolve_stack_secrets("app", stack(X="ssm:/example/x"), registry, None)

    def failing(ref):
        raise SSMError("ssm get_parameter /example/x failed: ParameterNotFound")

    with pytest.raises(StepError, match="secret X: ssm get_parameter /example/x failed: ParameterNotFound"):
        resolve_stack_secrets("app", stack(X="ssm:/example/x"), registry, failing)

    def crashing(ref):
        raise ValueError(SECRET)

    with pytest.raises(StepError) as e:
        resolve_stack_secrets("app", stack(X="ssm:/example/x"), registry, crashing)
    assert SECRET not in str(e.value) and "ValueError" in str(e.value)


def test_s3_backend_config_is_the_bootstrap_settings(tmp_path):
    from codeorca.bootstrap.s3 import backend_settings
    from codeorca.project import load_project

    text = (REFERENCE / "codeorca.yaml").read_text(encoding="utf-8")
    s3 = (
        'backend:\n  type: s3\n  account_id: "123456789012"\n  bucket: example-tfstate-123456789012\n'
        "  region: us-east-1\n  encryption: kms:arn:aws:kms:us-east-1:123456789012:key/example\n"
    )
    assert "backend:\n  type: local" in text
    text = text.replace("backend:\n  type: local", s3 + "#", 1)
    (tmp_path / "codeorca.yaml").write_text(text, encoding="utf-8")
    project = load_project(tmp_path / "codeorca.yaml")
    config = backend_config(project, project.stacks["app"])
    assert config == backend_settings(project, project.stacks["app"])
    assert config["kms_key_id"] == "arn:aws:kms:us-east-1:123456789012:key/example"


@pytest.mark.skipif(shutil.which("terraform") is None, reason="terraform not on PATH")
def test_drift_and_run_take_the_stack_secret_from_the_resolver(tmp_path, monkeypatch, capsys):
    root = tmp_path / "reference"
    shutil.copytree(REFERENCE, root, ignore=shutil.ignore_patterns(".codeorca", "specs", ".terraform*", "*.tfstate*"))
    config = root / "codeorca.yaml"
    text = config.read_text(encoding="utf-8")
    assert "    secrets: {}" in text
    config.write_text(
        text.replace("    secrets: {}", '    secrets: { TF_VAR_app_secret: "ssm:/example/app/secret" }'),
        encoding="utf-8",
    )
    monkeypatch.setenv("CODEORCA_REDACTION_KEY", KEY)
    monkeypatch.delenv("TF_VAR_app_secret", raising=False)
    monkeypatch.delenv("CI", raising=False)
    asked: list[str] = []

    def fake_make_resolver(project, registry, **kw):
        def resolve(ref):
            asked.append(ref)
            registry.add(SECRET)
            return SECRET

        return resolve

    monkeypatch.setattr("codeorca.providers.make_resolver", fake_make_resolver)
    p = str(config)
    # app_secret has no default: without the resolved secret this plan would error (verdict 1)
    assert cli.main(["drift", "-p", p]) == 2
    assert asked == ["ssm:/example/app/secret"]
    (root / "workflows" / "plan-no-input.yaml").write_text(
        "api: codeorca/v1\nkind: workflow\nname: plan-no-input\nsteps:\n"
        "  - id: plan_app\n    type: terraform\n    stack: app\n    action: plan\n",
        encoding="utf-8",
    )
    assert cli.main(["run", "plan-no-input", "-p", p]) == 0
    assert SECRET not in capsys.readouterr().out
    check = SecretRegistry(KEY.encode(), "env:test")
    check.add(SECRET)
    runs = root / ".codeorca" / "runs"
    assert scan_outputs(runs, check) == []
    assert scan_outputs(root / "specs", check) == []
    for names in runs.rglob("env-names.json"):
        assert "TF_VAR_app_secret" in json.loads(names.read_text(encoding="utf-8"))
