"""The ``ansible`` executor through the runner: handoff files (0600, gone afterwards, the step-dir inventory stays),
redaction of a handed-over secret in events.jsonl, rc mapping, check_unsupported policy, the role playbook,
timeouts, the recorded argv/env names, and the pure helpers."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import time
from pathlib import Path

import pytest
from ansible_support import requires_ansible

from codeorca.models import Workflow
from codeorca.project import Project, load_project
from codeorca.redact import SecretRegistry
from codeorca.rundir import RunDir
from codeorca.runner import EXIT_FAILED, EXIT_OK, Runner
from codeorca.secrets import line_hook
from codeorca.steps import ansible as ansible_step
from codeorca.steps import default_executors
from codeorca.steps.ansible import effective_check_unsupported, register_secret_values

SECRET = "FIXTURE-SECRET-handoff-001"
DENYLIST = ("(?i)password", "(?i)secret", "(?i)token")


def registry(*values: str) -> SecretRegistry:
    reg = SecretRegistry(b"example-not-secret-key", "test", mode="sha256")
    for v in values:
        reg.add(v)
    return reg


def workflow(steps: list[dict]) -> Workflow:
    return Workflow.model_validate({"api": "codeorca/v1", "kind": "workflow", "name": "t", "steps": steps})


def inline_inventory(**hostvars) -> dict:
    host = {"ansible_connection": "local", "ansible_python_interpreter": "{{ ansible_playbook_python }}", **hostvars}
    return {"inline": {"app": {"hosts": {"app-host": host}}}}


def ansible(id: str = "cfg", **kw) -> dict:
    step = {"id": id, "type": "ansible", "playbook": "ansible/site.yml", "inventory": inline_inventory(app_port=8080)}
    step.update(kw)
    return step


def run(project: Project, wf: Workflow, tmp_path: Path, reg: SecretRegistry, **kw) -> tuple[int, Runner]:
    executors = {**default_executors(), "ansible": ansible_step.make_executor(reg)}
    runner = Runner(
        project, wf, {}, RunDir(tmp_path / "runs"), executors, sleep=lambda s: None, stream=line_hook(reg), **kw
    )
    return runner.run(), runner


def events_of(runner: Runner, step_id: str) -> list[dict]:
    path = runner.run_dir.steps_dir / step_id / "events.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


# ---------------------------------------------------------------------------------------- pure helpers


def test_effective_check_unsupported_is_the_stricter_of_project_and_step(project_root):
    project = load_project(project_root / "codeorca.yaml")  # project says warn
    assert effective_check_unsupported(project, "warn") == "warn"
    assert effective_check_unsupported(project, "fail") == "fail"
    assert effective_check_unsupported(project, "ignore") == "warn"
    assert effective_check_unsupported(None, "ignore") == "warn"


def test_register_secret_values_walks_nested_keys():
    reg = registry()
    trees = {
        "extra_vars": {
            "db_password": SECRET,
            "plain": "visible-value-1",
            "nested": {"api_token": {"v": "FIXTURE-SECRET-2"}},
        },
        "inventory": {"app": {"hosts": {"h": {"ansible_password": "short"}}}},
    }
    registered, unprotected = register_secret_values(reg, trees, DENYLIST)
    assert registered == ["api_token", "db_password"]
    assert unprotected == ["ansible_password"]  # 5 characters: below the registry minimum, reported by name
    assert reg.redact(f"x {SECRET} y FIXTURE-SECRET-2 visible-value-1") == (
        f"x {reg.placeholder(SECRET)} y {reg.placeholder('FIXTURE-SECRET-2')} visible-value-1"
    )


# ---------------------------------------------------------------------------------------- live runs


@requires_ansible
def test_handoff_files_are_private_while_the_play_runs_and_gone_afterwards(project_root, tmp_path):
    project = load_project(project_root / "codeorca.yaml")
    wf = workflow([ansible(extra_vars={"scratch_dir": str(tmp_path), "echo_value": "plain"})])
    rc, r = run(project, wf, tmp_path, registry())
    assert rc == EXIT_OK, r.states["cfg"]
    step_dir = r.run_dir.steps_dir / "cfg"
    seen = [
        e for e in events_of(r, "cfg") if e["type"] == "runner" and e["task"] == "handoff files as the play sees them"
    ]
    files = {Path(f["path"]).name: f["mode"] for f in seen[0]["result"]["files"]}
    handoff_dir = r.run_dir.handoff_dir / "cfg"
    assert files == {"inventory.yml": "0600", "extra-vars.json": "0600"}
    assert all(Path(f["path"]).parent == handoff_dir for f in seen[0]["result"]["files"])
    assert not handoff_dir.exists()
    kept = step_dir / "inventory.yml"
    assert kept.is_file() and stat.S_IMODE(kept.stat().st_mode) == 0o600
    assert "app-host" in kept.read_text() and "ansible_connection" in kept.read_text()
    kept_vars = step_dir / "extra-vars.json"
    assert stat.S_IMODE(kept_vars.stat().st_mode) == 0o600
    assert json.loads(kept_vars.read_text()) == {"scratch_dir": str(tmp_path), "echo_value": "plain"}
    assert r.states["cfg"]["outputs"] == {"inventory_path": str(kept)}
    result = json.loads((step_dir / "result.json").read_text())
    assert result["rc"] == 0 and result["stats"]["app-host"]["ok"] >= 6 and result["failed_hosts"] == []
    assert result["events_path"] == str(step_dir / "events.jsonl") and result["inventory_path"] == str(kept)
    assert (step_dir / "stderr.log").exists()
    argv = json.loads((step_dir / "argv.json").read_text())[0]
    assert argv[-1].endswith("ansible/site.yml") and "-i" in argv and "--check" not in argv
    names = json.loads((step_dir / "env-names.json").read_text())
    assert "ANSIBLE_STDOUT_CALLBACK" in names and "CODEORCA_REDACTION_KEY" not in names and "ANSIBLE_DEBUG" not in names
    assert (tmp_path / "hello.txt").exists()


@requires_ansible
def test_handed_over_secret_never_reaches_the_run_dir(project_root, tmp_path):
    project = load_project(project_root / "codeorca.yaml")
    reg = registry(SECRET)  # integration seeds the registry; here the test does
    wf = workflow(
        [
            ansible(
                extra_vars={"scratch_dir": str(tmp_path), "echo_value": SECRET},
                outputs={"stats": "${{ result.stats }}"},
            )
        ]
    )
    rc, r = run(project, wf, tmp_path, reg, redact=lambda d: json.loads(reg.redact(json.dumps(d))))
    assert rc == EXIT_OK
    events = events_of(r, "cfg")
    echo = [e for e in events if e["type"] == "runner" and e["task"] == "echo handed-over value"][0]
    assert (
        echo["msg"] == f"value={reg.placeholder(SECRET)}"
    )  # the task ran with the real value; the file has the placeholder
    for path in r.run_dir.path.rglob("*"):
        if path.is_file():
            assert SECRET not in path.read_text(encoding="utf-8", errors="replace"), path
    assert r.states["cfg"]["outputs"]["stats"]["app-host"]["ok"] >= 6


@requires_ansible
def test_kept_inventory_copy_is_redacted_by_key_and_value(project_root, tmp_path):
    project = load_project(project_root / "codeorca.yaml")
    reg = registry()
    step = ansible(
        extra_vars={"scratch_dir": str(tmp_path)},
        inventory=inline_inventory(app_port=8080, ansible_password="FIXTURE-SECRET-inventory-pw", note="pw-is-visible"),
    )
    rc, r = run(project, workflow([step]), tmp_path, reg)
    assert rc == EXIT_OK
    result = json.loads((r.run_dir.steps_dir / "cfg" / "result.json").read_text())
    assert result["registered_vars"] == ["ansible_password"]
    kept = (r.run_dir.steps_dir / "cfg" / "inventory.yml").read_text()
    assert "FIXTURE-SECRET-inventory-pw" not in kept and "pw-is-visible" in kept and "ansible_password" in kept


@requires_ansible
def test_secret_named_extra_vars_are_registered_by_the_step_itself(project_root, tmp_path):
    project = load_project(project_root / "codeorca.yaml")
    reg = registry()
    wf = workflow([ansible(extra_vars={"scratch_dir": str(tmp_path), "echo_value": SECRET, "app_password": SECRET})])
    rc, r = run(project, wf, tmp_path, reg)
    assert rc == EXIT_OK
    result = json.loads((r.run_dir.steps_dir / "cfg" / "result.json").read_text())
    assert result["registered_vars"] == ["app_password"] and result["unprotected_vars"] == []
    assert SECRET not in (r.run_dir.steps_dir / "cfg" / "events.jsonl").read_text()
    kept_vars = json.loads((r.run_dir.steps_dir / "cfg" / "extra-vars.json").read_text())
    assert kept_vars["app_password"] == "<redacted:key>" and SECRET not in json.dumps(kept_vars)
    assert result["extra_vars_path"] == str(r.run_dir.steps_dir / "cfg" / "extra-vars.json")


@requires_ansible
def test_failed_task_maps_to_failed_with_the_redacted_message(project_root, tmp_path):
    project = load_project(project_root / "codeorca.yaml")
    reg = registry(SECRET)
    wf = workflow([ansible(extra_vars={"scratch_dir": str(tmp_path), "echo_value": SECRET, "do_fail": True})])
    rc, r = run(project, wf, tmp_path, reg)
    assert rc == EXIT_FAILED and r.states["cfg"]["status"] == "failed"
    error = r.states["cfg"]["error"]
    assert error.startswith(
        "ansible-playbook exited 2 (failed hosts); failed hosts: app-host; last failure: [app-host]"
    )
    assert "failing task: deliberate failure with" in error and SECRET not in error and reg.placeholder(SECRET) in error
    result = json.loads((r.run_dir.steps_dir / "cfg" / "result.json").read_text())
    assert result["rc"] == 2 and result["failed_hosts"] == ["app-host"] and result["status_text"] == "failed hosts"
    assert not (r.run_dir.handoff_dir / "cfg").exists()
    assert (r.run_dir.steps_dir / "cfg" / "inventory.yml").exists()


@requires_ansible
def test_dry_run_is_check_and_diff_with_the_unsupported_task_warned(project_root, tmp_path):
    project = load_project(project_root / "codeorca.yaml")
    wf = workflow([ansible(extra_vars={"scratch_dir": str(tmp_path)})])
    rc, r = run(project, wf, tmp_path, registry(), dry_run=True)
    assert rc == EXIT_OK and r.states["cfg"]["status"] == "succeeded"
    result = json.loads((r.run_dir.steps_dir / "cfg" / "result.json").read_text())
    assert result["check_unsupported"] == [["app-host", "check-unsupported task"]]
    assert result["warnings"] == [
        "task(s) skipped because the module does not support check mode: app-host: check-unsupported task"
    ]
    argv = json.loads((r.run_dir.steps_dir / "cfg" / "argv.json").read_text())[0]
    assert "--check" in argv and "--diff" in argv
    assert not (tmp_path / "hello.txt").exists()


@requires_ansible
def test_check_unsupported_fail_fails_the_step_and_ignore_only_lists(project_root, tmp_path):
    project = load_project(project_root / "codeorca.yaml")
    wf = workflow([ansible(extra_vars={"scratch_dir": str(tmp_path)}, check_unsupported="fail")])
    rc, r = run(project, wf, tmp_path, registry(), dry_run=True)
    assert rc == EXIT_FAILED and r.states["cfg"]["status"] == "failed"
    assert r.states["cfg"]["error"].startswith("check_unsupported: task(s) skipped")

    project.ansible.check_unsupported = "ignore"
    wf = workflow([ansible(extra_vars={"scratch_dir": str(tmp_path)}, check_unsupported="ignore")])
    rc, r = run(project, wf, tmp_path / "second", registry(), dry_run=True)
    assert rc == EXIT_OK
    result = json.loads((r.run_dir.steps_dir / "cfg" / "result.json").read_text())
    assert result["check_unsupported"] == [["app-host", "check-unsupported task"]] and result["warnings"] == []


@requires_ansible
def test_role_step_generates_an_import_role_playbook(project_root, tmp_path):
    project = load_project(project_root / "codeorca.yaml")
    step = ansible(
        id="role", role="app_config", extra_vars={"app_config_dir": str(tmp_path), "app_config_name": "demo"}
    )
    del step["playbook"]
    rc, r = run(project, workflow([step]), tmp_path, registry())
    assert rc == EXIT_OK, r.states["role"]
    generated = r.run_dir.steps_dir / "role" / "playbook.yml"
    assert generated.is_file() and "ansible.builtin.import_role" in generated.read_text()
    assert (tmp_path / "app.conf").read_text() == "# fixture role template\nname = demo\nhost = app-host\n"
    tasks = {e["task"] for e in events_of(r, "role") if e["type"] == "runner"}
    assert any("Render the app config" in t for t in tasks)
    names = json.loads((r.run_dir.steps_dir / "role" / "env-names.json").read_text())
    assert "ANSIBLE_ROLES_PATH" in names


@requires_ansible
def test_timeout_kills_the_sleeping_task(project_root, tmp_path):
    project = load_project(project_root / "codeorca.yaml")
    wf = workflow([ansible(playbook="ansible/sleep.yml", timeout="6s", extra_vars={"sleep_seconds": "60.0917"})])
    started = time.monotonic()
    rc, r = run(project, wf, tmp_path, registry())
    assert time.monotonic() - started < 30
    assert rc == EXIT_FAILED and r.states["cfg"]["status"] == "errored"
    assert r.states["cfg"]["error"].startswith("timeout:")
    assert not (r.run_dir.handoff_dir / "cfg").exists()
    assert json.loads((r.run_dir.steps_dir / "cfg" / "argv.json").read_text())  # recorded even on a timeout
    assert any(e.get("type") == "task_start" for e in events_of(r, "cfg")), "the deadline fired before the play began"
    time.sleep(1)
    out = subprocess.run(["ps", "-axo", "pid=,command="], capture_output=True, text=True, check=False).stdout
    assert not [line for line in out.splitlines() if "sleep 60.0917" in line]  # the module's command is dead too


@requires_ansible
def test_inventory_path_is_used_as_given(project_root, tmp_path):
    project = load_project(project_root / "codeorca.yaml")
    wf = workflow([ansible(inventory={"path": "ansible/inventory.yml"}, extra_vars={"scratch_dir": str(tmp_path)})])
    rc, r = run(project, wf, tmp_path, registry())
    assert rc == EXIT_OK
    assert r.states["cfg"]["outputs"]["inventory_path"] == str(project_root / "ansible" / "inventory.yml")
    assert not (r.run_dir.steps_dir / "cfg" / "inventory.yml").exists()


def test_missing_playbook_is_an_errored_step(project_root, tmp_path):
    project = load_project(project_root / "codeorca.yaml")
    wf = workflow([ansible(playbook="ansible/nope.yml")])
    rc, r = run(project, wf, tmp_path, registry())
    assert rc == EXIT_FAILED and r.states["cfg"]["status"] == "errored"
    assert "does not exist" in r.states["cfg"]["error"]
    assert not (r.run_dir.handoff_dir / "cfg").exists()


@requires_ansible
def test_project_ansible_env_reaches_the_child(project_root, tmp_path):
    project = load_project(project_root / "codeorca.yaml")
    project.ansible.env["ANSIBLE_HOST_KEY_CHECKING"] = "False"
    wf = workflow([ansible(extra_vars={"scratch_dir": str(tmp_path)})])
    rc, r = run(
        project, wf, tmp_path, registry(), env={**os.environ, "CODEORCA_REDACTION_KEY": "k", "ANSIBLE_DEBUG": "1"}
    )
    assert rc == EXIT_OK
    names = json.loads((r.run_dir.steps_dir / "cfg" / "env-names.json").read_text())
    assert (
        "ANSIBLE_HOST_KEY_CHECKING" in names and "ANSIBLE_DEBUG" not in names and "CODEORCA_REDACTION_KEY" not in names
    )


@pytest.mark.parametrize("bad", [{"inline": {}}])
def test_empty_inline_inventory_is_refused_by_the_model(bad):
    with pytest.raises(ValueError):
        workflow([ansible(inventory=bad)])
