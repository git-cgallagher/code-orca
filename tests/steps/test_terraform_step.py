"""The terraform and spec-render executors without a real terraform binary: stack resolution, the Phase 3
refusals, pre-plan secret registration, required_env, backend config, the spec-render source gate, and the
session's behaviour on a fake engine (init diagnostics, deadline, child env, plan warnings, gates)."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

from codeorca.models import Workflow
from codeorca.project import NeverRender, Project, load_project
from codeorca.redact import SecretRegistry
from codeorca.rundir import RunDir, stack_lock
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
REFERENCE = ROOT / "examples" / "reference"
PROJECT = load_project(REFERENCE / "codeorca.yaml")  # model access only; runs go through a tmp copy
SECRET = "FIXTURE-SECRET-override-001"

# A fake `terraform`: stdout and exit code per subcommand (FAKE_STDOUT_<sub> / FAKE_EXIT_<sub>, else FAKE_STDOUT
# / 0); `plan -out=<f>` creates the file so the sha256 binding has something to hash.
FAKE_ENGINE = r"""#!/bin/sh
sub=$1
[ "$sub" = providers ] && sub=providers_schema
for a in "$@"; do case "$a" in -out=*) : > "${a#-out=}";; esac; done
eval "out=\${FAKE_STDOUT_$sub:-\$FAKE_STDOUT}"
eval "code=\${FAKE_EXIT_$sub:-0}"
printf '%s\n' "$out"
exit "$code"
"""
PLAN_DOC = {
    "format_version": "1.2",
    "terraform_version": "1.14.7",
    "complete": True,
    "applyable": True,
    "errored": False,
    "variables": {"environment": {"value": "dev"}},
    "resource_changes": [],
    "configuration": {"root_module": {"variables": {"environment": {}}}},
    "prior_state": {
        "values": {
            "outputs": {
                "app_fqdn": {"sensitive": False, "value": "app-dev.example.com"},
                "api_token": {"sensitive": False, "value": "FIXTURE-NOT-FLAGGED-token-value"},
                "app_host": {"sensitive": False, "value": "127.0.0.1"},
            }
        }
    },
}


def workflow(steps: list[dict], **kw) -> Workflow:
    return Workflow.model_validate({"api": "codeorca/v1", "kind": "workflow", "name": "t", "steps": steps, **kw})


@pytest.fixture
def project(tmp_path: Path) -> Project:
    root = tmp_path / "reference"
    shutil.copytree(REFERENCE, root, ignore=shutil.ignore_patterns(".codeorca", "specs", ".terraform*", "*.tfstate*"))
    return load_project(root / "codeorca.yaml")


@pytest.fixture
def fake_engine(tmp_path: Path) -> Path:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    engine = bindir / "terraform"
    engine.write_text(FAKE_ENGINE, encoding="utf-8")
    engine.chmod(0o700)
    return bindir


def run(wf: Workflow, tmp_path, registry: SecretRegistry, project: Project, env: dict | None = None) -> Runner:
    executors = default_executors()
    executors["terraform"] = terraform_step.make_executor(registry)
    executors["spec-render"] = spec_render_step.make_executor(registry)
    base = {"PATH": "/nonexistent", "CODEORCA_REDACTION_KEY": "example-not-secret-key"}
    runner = Runner(
        project, wf, {}, RunDir(tmp_path / "runs"), executors, env={**base, **(env or {})}, sleep=lambda s: None
    )
    runner.run()
    return runner


@pytest.fixture
def registry() -> SecretRegistry:
    return SecretRegistry(b"example-not-secret-key", "env:x")


def test_apply_and_migrate_backend_fail_with_the_phase3_message(tmp_path, registry, project):
    wf = workflow(
        [
            {"id": "a", "type": "terraform", "stack": "app", "action": "apply", "plan_file": "p.tfplan"},
            {"id": "m", "type": "terraform", "stack": "app", "action": "migrate_backend", "on_failure": "continue"},
        ],
        fail_fast=False,
    )
    r = run(wf, tmp_path, registry, project)
    assert r.states["a"]["status"] == "failed" and r.states["a"]["error"] == PHASE3_APPLY
    assert r.states["m"]["status"] == "failed" and r.states["m"]["error"] == PHASE3_MIGRATE


def test_unknown_stack_and_missing_engine_are_errored_steps(tmp_path, registry, project):
    wf = workflow(
        [
            {"id": "u", "type": "terraform", "stack": "nope", "action": "plan", "on_failure": "continue"},
            {"id": "e", "type": "terraform", "stack": "app", "action": "validate"},
        ]
    )
    r = run(wf, tmp_path, registry, project)
    assert r.states["u"]["status"] == "errored" and "unknown stack 'nope'" in r.states["u"]["error"]
    assert r.states["e"]["status"] == "errored" and "not found on PATH" in r.states["e"]["error"]
    # the session still recorded what it tried, and the lock landed under the tmp copy, not the checkout
    assert (r.run_dir.steps_dir / "e" / "argv.json").exists()
    assert (project.root / ".codeorca" / "runs" / "locks" / "app.lock").exists()


def test_declared_sensitive_variables_are_read_from_the_tf_files(tmp_path):
    assert declared_sensitive_variables(REFERENCE / "terraform" / "app") == {"app_secret"}
    (tmp_path / "a.tf").write_text(
        'variable "db_password" {\n  type = string\n  sensitive = true // rotated monthly\n}\n'
        'variable "plain" {\n  type = string\n  /* sensitive = true */\n}\n'
        'variable "hashed" {\n  sensitive = true # yes\n}\n',
        encoding="utf-8",
    )
    (tmp_path / "v.tf.json").write_text(
        json.dumps({"variable": {"json_secret": {"type": "string", "sensitive": True}, "json_plain": {}}}),
        encoding="utf-8",
    )
    assert declared_sensitive_variables(tmp_path) == {"db_password", "hashed", "json_secret"}


def test_register_overrides_before_terraform_runs(registry):
    env = {
        "TF_VAR_app_secret": SECRET + "-env",
        "TF_VAR_environment": "dev",
        "TF_VAR_api_token": "FIXTURE-SECRET-envonly-001",  # not declared sensitive, not overridden: denylist only
        "TF_VAR_short_token": "abc1234",  # denylisted name, value too short for the registry
    }
    registered = register_overrides(
        registry,
        {"app_secret": SECRET, "environment": "prod", "db_password": "short"},
        {"app_secret"},
        ("(?i)password", "(?i)token"),
        env,
    )
    assert registered.names == ["api_token", "app_secret"]
    assert registered.unprotected == ["db_password", "short_token"]  # listed as NOT protected, never as registered
    assert SECRET not in registry.redact(SECRET) and (SECRET + "-env") not in registry.redact(SECRET + "-env")
    assert "FIXTURE-SECRET-envonly-001" not in registry.redact("x FIXTURE-SECRET-envonly-001 y")
    assert registry.redact("prod") == "prod"  # not sensitive, not registered
    assert registry.redact("dev") == "dev"


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


def test_spec_render_other_sources_are_not_implemented_and_bad_source_is_an_error(tmp_path, registry, project):
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
    r = run(wf, tmp_path, registry, project)
    assert "terraform_state" in r.states["s"]["error"] and "not implemented in this phase" in r.states["s"]["error"]
    assert "'ansible' is not implemented" in r.states["a"]["error"]
    assert r.states["m"]["status"] == "errored" and "does not exist" in r.states["m"]["error"]


# ---------------------------------------------------------------- the session on a fake engine


def tf(id: str, action: str, **kw) -> dict:
    return {"id": id, "type": "terraform", "stack": "app", "action": action, **kw}


def test_init_failure_reports_the_json_diagnostics(tmp_path, registry, project, fake_engine):
    diag = {
        "@level": "error",
        "@message": "Error: Missing region value",
        "diagnostic": {"severity": "error", "summary": "Missing region value", "detail": "The region must be set"},
    }
    env = {"PATH": str(fake_engine), "FAKE_STDOUT_init": json.dumps(diag), "FAKE_EXIT_init": "1"}
    r = run(workflow([tf("v", "validate")]), tmp_path, registry, project, env)
    error = r.states["v"]["error"]
    assert r.states["v"]["status"] == "errored"
    assert "init failed (exit 1)" in error and "Missing region value: The region must be set" in error


def test_terraform_step_timeout_is_a_deadline_over_the_session(tmp_path, registry, project):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    sleeper = bindir / "terraform"
    sleeper.write_text(f"#!/bin/sh\nexec {sys.executable} -c 'import time; time.sleep(30)'\n", encoding="utf-8")
    sleeper.chmod(0o700)
    wf = workflow([tf("v", "validate", timeout="500ms", retry={"limit": 1, "policy": "error"})])
    r = run(wf, tmp_path, registry, project, {"PATH": str(bindir)})
    assert r.states["v"]["status"] == "errored" and r.states["v"]["error"].startswith("timeout:")
    assert r.states["v"]["attempts"] == 2  # retry.policy: error covers the timeout, as for shell steps
    argv = json.loads((r.run_dir.steps_dir / "v" / "argv.json").read_text())
    assert argv and argv[0][1] == "init"  # the deadline hit during init: nothing else was tried


def test_child_env_never_carries_the_redaction_key_or_tf_cli_args(tmp_path, registry, project, fake_engine):
    env = {
        "PATH": str(fake_engine),
        "FAKE_STDOUT": '{"valid": true, "terraform_version": "1.14.7"}',
        "TF_CLI_ARGS_plan": "-destroy",
    }
    wf = workflow([tf("v", "validate"), {"id": "s", "type": "shell", "run": [sys.executable, "-c", "pass"]}])
    r = run(wf, tmp_path, registry, project, env)
    assert r.states["v"]["status"] == "succeeded" and r.states["s"]["status"] == "succeeded"
    for step in ("v", "s"):
        names = json.loads((r.run_dir.steps_dir / step / "env-names.json").read_text())
        assert "CODEORCA_REDACTION_KEY" not in names and "PATH" in names
    assert "TF_CLI_ARGS_plan" not in json.loads((r.run_dir.steps_dir / "v" / "env-names.json").read_text())


def plan_env(fake_engine: Path, doc: dict, schema: dict | None = None) -> dict:
    return {
        "PATH": str(fake_engine),
        "FAKE_STDOUT_init": "{}",
        "FAKE_STDOUT_version": '{"terraform_version": "1.14.7"}',
        "FAKE_STDOUT_plan": "Plan: 0 to add.",
        "FAKE_EXIT_plan": "2",
        "FAKE_STDOUT_show": json.dumps(doc),
        "FAKE_STDOUT_providers_schema": json.dumps(schema or {"format_version": "1.0", "provider_schemas": {}}),
    }


def test_plan_warns_on_an_incomplete_plan_and_filters_prior_outputs(tmp_path, registry, project, fake_engine):
    doc = {**PLAN_DOC, "complete": False}
    stack = project.stacks["app"].model_copy(update={"never_render": NeverRender(outputs=["app_fqdn"])})
    project = project.model_copy(update={"stacks": {"app": stack}})
    r = run(workflow([tf("p", "plan")]), tmp_path, registry, project, plan_env(fake_engine, doc))
    assert r.states["p"]["status"] == "succeeded", r.states["p"]["error"]
    result = json.loads((r.run_dir.steps_dir / "p" / "result.json").read_text())
    assert result["summary"]["complete"] is False
    assert any(w.startswith("incomplete plan") for w in result["warnings"])
    assert "app_fqdn" not in result["prior_outputs"]  # never_render.outputs applies to the step result too
    assert result["prior_outputs"]["api_token"] == {"value": "<redacted:key>"}  # and so does the key denylist
    assert result["prior_outputs"]["app_host"] == {"value": "127.0.0.1"}
    assert "FIXTURE-NOT-FLAGGED-token-value" not in (r.run_dir.steps_dir / "p" / "result.json").read_text()
    assert "FIXTURE-NOT-FLAGGED-token-value" not in (r.run_dir.steps_dir / "p" / "stdout.log").read_text()
    log = (r.run_dir.steps_dir / "p" / "stdout.log").read_text()
    assert "format_version" not in log and "Plan: 0 to add." in log  # show -json never logged; the plan text is
    assert result["unprotected_overrides"] == []


def test_plan_refuses_an_unsupported_plan_format(tmp_path, registry, project, fake_engine):
    doc = {**PLAN_DOC, "format_version": "2.0"}
    r = run(workflow([tf("p", "plan")]), tmp_path, registry, project, plan_env(fake_engine, doc))
    assert r.states["p"]["status"] == "errored" and "format_version '2.0'" in r.states["p"]["error"]
    assert not (r.run_dir.steps_dir / "p" / "plan.json").exists()


def test_short_sensitive_override_is_reported_as_unprotected(tmp_path, registry, project, fake_engine):
    wf = workflow([tf("p", "plan", var_overrides={"app_secret": "abc1234", "environment": "dev"})])
    r = run(wf, tmp_path, registry, project, plan_env(fake_engine, PLAN_DOC))
    assert r.states["p"]["status"] == "succeeded", r.states["p"]["error"]
    result = json.loads((r.run_dir.steps_dir / "p" / "result.json").read_text())
    assert result["registered_overrides"] == [] and result["unprotected_overrides"] == ["app_secret"]
    assert any("not scrubbed: app_secret" in w for w in result["warnings"])


def test_locked_stack_is_an_errored_step(tmp_path, registry, project, fake_engine):
    env = {"PATH": str(fake_engine), "FAKE_STDOUT": '{"valid": true}'}
    with stack_lock(project.root / project.state_dir, "app"):
        r = run(workflow([tf("v", "validate")]), tmp_path, registry, project, env)
    assert r.states["v"]["status"] == "errored" and "stack 'app' is locked" in r.states["v"]["error"]
    assert not (r.run_dir.steps_dir / "v" / "argv.json").exists()  # nothing ran
