"""The terraform and spec-render executors without a terraform binary: stack resolution, the Phase 3 refusals,
pre-plan secret registration, required_env, backend config, the spec-render source gate."""

from __future__ import annotations

from pathlib import Path

import pytest

from codeorca.models import Workflow
from codeorca.project import load_project
from codeorca.redact import SecretRegistry
from codeorca.rundir import RunDir
from codeorca.runner import Runner
from codeorca.steps import default_executors
from codeorca.steps import spec_render as spec_render_step
from codeorca.steps import terraform as terraform_step
from codeorca.steps.terraform import (
    PHASE3_APPLY,
    PHASE3_MIGRATE,
    backend_config,
    check_required_env,
    declared_sensitive_variables,
    register_overrides,
)

ROOT = Path(__file__).resolve().parents[2]
PROJECT = load_project(ROOT / "examples" / "reference" / "codeorca.yaml")
SECRET = "FIXTURE-SECRET-override-001"


def workflow(steps: list[dict], **kw) -> Workflow:
    return Workflow.model_validate({"api": "codeorca/v1", "kind": "workflow", "name": "t", "steps": steps, **kw})


def run(wf: Workflow, tmp_path, registry: SecretRegistry) -> Runner:
    executors = default_executors()
    executors["terraform"] = terraform_step.make_executor(registry)
    executors["spec-render"] = spec_render_step.make_executor(registry)
    runner = Runner(PROJECT, wf, {}, RunDir(tmp_path), executors, env={"PATH": "/nonexistent"}, sleep=lambda s: None)
    runner.run()
    return runner


@pytest.fixture
def registry() -> SecretRegistry:
    return SecretRegistry(b"example-not-secret-key", "env:x")


def test_apply_and_migrate_backend_fail_with_the_phase3_message(tmp_path, registry):
    wf = workflow(
        [
            {"id": "a", "type": "terraform", "stack": "app", "action": "apply", "plan_file": "p.tfplan"},
            {"id": "m", "type": "terraform", "stack": "app", "action": "migrate_backend", "on_failure": "continue"},
        ],
        fail_fast=False,
    )
    r = run(wf, tmp_path, registry)
    assert r.states["a"]["status"] == "failed" and r.states["a"]["error"] == PHASE3_APPLY
    assert r.states["m"]["status"] == "failed" and r.states["m"]["error"] == PHASE3_MIGRATE


def test_unknown_stack_and_missing_engine_are_errored_steps(tmp_path, registry):
    wf = workflow(
        [
            {"id": "u", "type": "terraform", "stack": "nope", "action": "plan", "on_failure": "continue"},
            {"id": "e", "type": "terraform", "stack": "app", "action": "validate"},
        ]
    )
    r = run(wf, tmp_path, registry)
    assert r.states["u"]["status"] == "errored" and "unknown stack 'nope'" in r.states["u"]["error"]
    assert r.states["e"]["status"] == "errored" and "not found on PATH" in r.states["e"]["error"]
    # the session still recorded what it tried
    assert (tmp_path / r.run_dir.run_id / "steps" / "e" / "argv.json").exists()


def test_declared_sensitive_variables_are_read_from_the_tf_files():
    assert declared_sensitive_variables(ROOT / "examples" / "reference" / "terraform" / "app") == {"app_secret"}


def test_register_overrides_before_terraform_runs(registry):
    env = {"TF_VAR_app_secret": SECRET + "-env", "TF_VAR_environment": "dev"}
    names = register_overrides(
        registry,
        {"app_secret": SECRET, "environment": "prod", "db_password": "short"},
        {"app_secret"},
        ("(?i)password",),
        env,
    )
    assert names == ["app_secret", "db_password"]
    assert SECRET not in registry.redact(SECRET) and (SECRET + "-env") not in registry.redact(SECRET + "-env")
    assert registry.redact("prod") == "prod"  # not sensitive, not registered


def test_required_env_is_checked_by_name_only():
    stack = PROJECT.stacks["app"].model_copy(update={"required_env": ["EXAMPLE_TOKEN", "OTHER"]})
    with pytest.raises(Exception, match="required_env not set: EXAMPLE_TOKEN, OTHER"):
        check_required_env(stack, {})
    check_required_env(stack, {"EXAMPLE_TOKEN": "x", "OTHER": "y"})


def test_backend_config_local_is_empty_and_s3_is_non_secret():
    assert backend_config(PROJECT, PROJECT.stacks["app"]) == {}
    s3 = PROJECT.backend.model_copy(
        update={"type": "s3", "bucket": "b", "region": "us-east-1", "account_id": "123456789012"}
    )
    project = PROJECT.model_copy(update={"backend": s3})
    assert backend_config(project, PROJECT.stacks["app"]) == {
        "bucket": "b",
        "key": "example/app/terraform.tfstate",
        "region": "us-east-1",
        "use_lockfile": True,
        "encrypt": True,
    }


def test_spec_render_other_sources_are_not_implemented_and_bad_source_is_an_error(tmp_path, registry):
    wf = workflow(
        [
            {
                "id": "s",
                "type": "spec-render",
                "source": {"terraform_state": "x"},
                "output": "specs/x.yaml",
                "on_failure": "continue",
            },
            {
                "id": "a",
                "type": "spec-render",
                "source": {"ansible": {"inventory": "i", "host": "h"}},
                "output": "specs/y.yaml",
                "on_failure": "continue",
            },
            {
                "id": "m",
                "type": "spec-render",
                "source": {"terraform_plan": str(tmp_path / "missing.json")},
                "output": "z.yaml",
            },
        ]
    )
    r = run(wf, tmp_path, registry)
    assert "terraform_state" in r.states["s"]["error"] and "not implemented in this phase" in r.states["s"]["error"]
    assert "'ansible' is not implemented" in r.states["a"]["error"]
    assert r.states["m"]["status"] == "errored" and "does not exist" in r.states["m"]["error"]
