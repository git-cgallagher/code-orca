"""``spec-render`` with ``source.ansible``: the pure helpers of ``codeorca.steps.host_spec`` (no ansible needed) and
the step through the runner over the host-spec fixture inventory (skipped without ansible-core).

The fixture tree (``tests/fixtures/ansible_host``) is copied under ``<project>/ansible`` so its ``roles/`` is the
project's ``ansible/roles``. Every secret-looking value in it is a ``FIXTURE-SECRET-*`` placeholder."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import stat
from pathlib import Path

import pytest

from codeorca.models import Workflow
from codeorca.project import load_project
from codeorca.redact import SecretRegistry, scan_outputs
from codeorca.rundir import RunDir
from codeorca.runner import Runner
from codeorca.specs.ansible_vars import SECRET_DECLARED, SKIPPED_KEY, VAULT
from codeorca.steps import default_executors, host_spec
from codeorca.steps import spec_render as spec_render_step

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures" / "ansible_host"
KEY = "example-not-secret-key"
FIXTURE_SECRETS = (
    "FIXTURE-SECRET-declared-nolog-001",
    "FIXTURE-SECRET-nested-nolog-001",
    "FIXTURE-SECRET-play-token-001",
)
requires_ansible = pytest.mark.skipif(importlib.util.find_spec("ansible") is None, reason="ansible-core not installed")

PLAYBOOK = """\
- name: Fixture play the spec play mirrors
  hosts: web
  gather_facts: false
  vars:
    play_only: "{{ app_name }}-play"
    play_token: FIXTURE-SECRET-play-token-001
  roles:
    - role: app_config
"""


# ------------------------------------------------------------------------------------------- pure helpers


def test_playbook_scope_reads_roles_vars_and_vars_files(tmp_path: Path):
    pb = tmp_path / "site.yml"
    pb.write_text(
        """\
- hosts: app
  vars: {a: 1}
  vars_files: [vars/common.yml, /abs/x.yml]
  roles: [plain, {role: ns.col.fq}, {name: by_name}, "{{ templated }}"]
  tasks:
    - block:
        - ansible.builtin.import_role: {name: in_block}
    - include_role: short
- import_playbook: other.yml
- hosts: db
  vars: {a: 2, b: 3}
""",
        encoding="utf-8",
    )
    roles, play_vars, vars_files = host_spec.playbook_scope(pb)
    assert roles == ["plain", "ns.col.fq", "by_name", "in_block", "short"]
    assert play_vars == {"a": 2, "b": 3}
    assert vars_files == [str(tmp_path / "vars" / "common.yml"), "/abs/x.yml"]
    vaulted = tmp_path / "vaulted.yml"
    vaulted.write_text("- hosts: all\n  vars:\n    x: !vault |\n      $ANSIBLE_VAULT;1.1;AES256\n", encoding="utf-8")
    assert host_spec.playbook_scope(vaulted) == ([], {}, [])


def test_handoff_markers_cover_inventory_markers_declared_secrets_names_and_denied_lookups():
    vars_json = {"vars": {"db_password": {"resolved": SKIPPED_KEY}, "plain": {"resolved": "x"}}}
    specs = {"api_credential": {"no_log": True}, "port": {"type": "int"}}
    candidates = {
        "home": "{{ lookup('env', 'HOME') }}",
        "motd": "{{ lookup('file', 'motd.txt') }}",
        "role_secret": "abc",
    }
    markers = host_spec.handoff_markers(
        vars_json, specs, candidates, ["listed_token"], ["(?i)password", "(?i)secret", "(?i)token"], ["*.env"]
    )
    assert markers == {
        "api_credential": SECRET_DECLARED,
        "db_password": SKIPPED_KEY,
        "home": "<skipped: lookup ansible.builtin.env is a secret source>",
        "listed_token": SKIPPED_KEY,
        "role_secret": SKIPPED_KEY,
    }


def test_merge_play_scope_overlap_rules(tmp_path: Path):
    tpl = str(tmp_path / "t.j2")
    vars_json = {
        "vars": {
            "kept_marker": {"declared": "x", "resolved": SECRET_DECLARED},
            "both": {"declared": "{{ x }}", "resolved": None, "error": "AnsibleUndefinedVariable: x", "source": "s"},
            "inv_only": {"declared": 1, "resolved": 1, "source": "s"},
        },
        "templates": {tpl: None},
        "errors": {"vars": {"both": "AnsibleUndefinedVariable: x"}, "templates": {tpl: "undefined"}},
    }
    play = {
        "vars": {"kept_marker": "clear", "both": 5, "new": [1], "spec_secret": "clear", "a_token": "clear"},
        "templates": {tpl: "rendered\n"},
        "errors": {},
    }
    specs = {"new": {"type": "list", "role": "r", "description": "d"}, "spec_secret": {"no_log": True}}
    out = host_spec.merge_play_scope(vars_json, play, specs, ["(?i)token"], "ansible/site.yml", tmp_path)
    v = out["vars"]
    assert v["kept_marker"] == {"declared": "x", "resolved": SECRET_DECLARED, "scope": "inventory"}
    assert v["both"] == {"declared": "{{ x }}", "resolved": 5, "source": "s", "scope": "play"}
    assert v["inv_only"]["scope"] == "inventory"
    assert v["new"] == {
        "source": "play: ansible/site.yml",
        "type": "list",
        "role": "r",
        "description": "d",
        "resolved": [1],
        "scope": "play",
    }
    assert v["spec_secret"]["resolved"] == SECRET_DECLARED and v["a_token"]["resolved"] == SKIPPED_KEY
    assert out["templates"] == {"t.j2": "rendered\n"}
    assert out["errors"] == {"vars": {}, "templates": {}}
    assert vars_json["vars"]["both"]["resolved"] is None  # pure: the input is untouched


def test_stage_inventory_merges_extra_vars_and_copies_playbook_group_vars(tmp_path: Path):
    step_dir = tmp_path / "run" / "steps" / "configure"
    step_dir.mkdir(parents=True)
    inventory = step_dir / "inventory.yml"
    inventory.write_text('app:\n  hosts:\n    app-host:\n      ansible_host: "127.0.0.1"\n', encoding="utf-8")
    vars_dir = tmp_path / "project" / "ansible"
    (vars_dir / "group_vars").mkdir(parents=True)
    (vars_dir / "group_vars" / "app.yml").write_text("x: 1\n", encoding="utf-8")
    staging = tmp_path / "run" / "handoff" / "spec" / "inventory"
    staged, copied, warnings = host_spec.stage_inventory(inventory, "app-host", {"env": "dev"}, vars_dir, staging)
    assert staged == staging / "inventory.yml" and copied == vars_dir and warnings == []
    assert stat.S_IMODE(staged.stat().st_mode) == 0o600 and stat.S_IMODE(staging.stat().st_mode) == 0o700
    assert '"env": "dev"' in staged.read_text() and (staging / "group_vars" / "app.yml").is_file()
    # nothing to add: the inventory is used in place
    assert host_spec.stage_inventory(inventory, "app-host", {}, None, staging) == (inventory, None, [])

    doc = {"vars": {"env": {"source": "inventory.yml (host entry)"}, "x": {"source": "group_vars/app.yml"}}}
    host_spec.relabel_sources(
        doc, extra_names=["env"], producer="configure", copied_from=vars_dir, root=tmp_path / "project"
    )
    assert doc["vars"]["env"]["source"] == "extra_vars (step configure)"
    assert doc["vars"]["x"]["source"] == "ansible/group_vars/app.yml"


def test_spec_stack_and_child_env_policy():
    from codeorca.project import AnsibleConfig

    assert host_spec.spec_stack(Path("specs/app/hosts/h.yaml"), "h") == "app"
    assert host_spec.spec_stack(Path("specs/h.yaml"), "h") == "h"
    env = host_spec.child_env(
        {"PATH": "/bin", "CODEORCA_REDACTION_KEY": "k", "ANSIBLE_DEBUG": "1", "ANSIBLE_LOG_PATH": "/tmp/x.log"},
        AnsibleConfig(env={"ANSIBLE_NOCOLOR": "1"}),
    )
    assert env == {
        "PATH": "/bin",
        "ANSIBLE_NOCOLOR": "1",
        "ANSIBLE_DEBUG": "False",
        "ANSIBLE_VERBOSITY": "0",
        "ANSIBLE_LOG_PATH": os.devnull,
        "ANSIBLE_KEEP_REMOTE_FILES": "False",
    }


# ------------------------------------------------------------------------------------------- live runs


@pytest.fixture
def project_root(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    shutil.copytree(FIXTURES, root / "ansible")
    (root / "ansible" / "play.yml").write_text(PLAYBOOK, encoding="utf-8")
    (root / "codeorca.yaml").write_text(
        "\n".join(
            [
                "api: codeorca/v1",
                "project: hostspec",
                "runtime:",
                "  {image: example, terraform: '1.14.7', ansible_core: '2.21.5', python: '>=3.13', pwsh: '7.6.*'}",
                "backend: {type: local}",
                "redaction:",
                "  placeholder: hmac",
                "  hmac_key: ssm:/example/redaction-key",
                '  key_denylist: ["(?i)password", "(?i)secret", "(?i)token"]',
                '  lookup_denylist: ["ansible.builtin.env", "amazon.aws.*"]',
                "",
            ]
        ),
        encoding="utf-8",
    )
    return root


def registry() -> SecretRegistry:
    reg = SecretRegistry(KEY.encode(), "env:test")
    return reg


def run_spec(root: Path, source: dict, output: str = "specs/web/hosts/web1.yaml") -> Runner:
    project = load_project(root / "codeorca.yaml")
    wf = Workflow.model_validate(
        {
            "api": "codeorca/v1",
            "kind": "workflow",
            "name": "hostspec",
            "steps": [{"id": "spec", "type": "spec-render", "source": {"ansible": source}, "output": output}],
        }
    )
    executors = {**default_executors(), "spec-render": spec_render_step.make_executor(registry())}
    import os

    env = {k: v for k, v in os.environ.items() if k != "CODEORCA_REDACTION_KEY"}
    runner = Runner(project, wf, {}, RunDir(root / ".codeorca" / "runs"), executors, env=env, cwd=root)
    runner.run()
    return runner


def all_secrets_registry() -> SecretRegistry:
    reg = registry()
    for value in FIXTURE_SECRETS:
        reg.add(value)
    return reg


@requires_ansible
def test_inventory_scope_only(project_root: Path):
    r = run_spec(
        project_root,
        {"inventory": "ansible/inventory/hosts.yml", "host": "web1", "templates": ["ansible/templates/site.conf.j2"]},
    )
    assert r.states["spec"]["status"] == "succeeded", r.states["spec"]
    spec = project_root / "specs" / "web" / "hosts" / "web1.yaml"
    text = spec.read_text()
    assert "stack: web" in text and "kind: ansible_host" in text and "scope: play" not in text
    assert "inventory_source: ansible/inventory/hosts.yml" in text
    assert "ansible/templates/site.conf.j2: |" in text  # a literal block, one line per rendered line
    assert r.run_dir.run_id not in text
    document = json.loads((r.run_dir.steps_dir / "spec" / host_spec.HOST_VARS_FILE).read_text())
    v = document["vars"]
    assert all(entry["scope"] == "inventory" for entry in v.values())
    assert v["app_port"]["resolved"] == 8080
    assert v["app_config_api_credential"]["resolved"] == SECRET_DECLARED
    assert v["db_password"]["resolved"] == SKIPPED_KEY and v["vaulted_value"]["resolved"] == VAULT
    assert v["app_name"]["source"] == "group_vars/all.yml"
    assert stat.S_IMODE((r.run_dir.steps_dir / "spec" / host_spec.HOST_VARS_FILE).stat().st_mode) == 0o600
    meta = (spec.parent / "web1.meta.yaml").read_text()
    assert f"run_id: {r.run_dir.run_id}" in meta and "source: steps/spec/host-vars.json" in meta
    assert (r.run_dir.specs_dir / "web" / "hosts" / "web1.yaml").read_text() == text
    assert not any(s in text for s in FIXTURE_SECRETS)
    assert scan_outputs(r.run_dir.path, all_secrets_registry()) == []


@requires_ansible
def test_play_scope_on_a_local_playbook(project_root: Path):
    r = run_spec(
        project_root,
        {
            "inventory": "ansible/inventory/hosts.yml",
            "host": "web1",
            "play_scope": {
                "playbook": "ansible/play.yml",
                "vars": ["app_config_rotate_days", "app_config_banner", "play_only", "play_token", "app_port", "nope"],
            },
            "templates": ["ansible/roles/app_config/templates/app.conf.j2"],
        },
    )
    assert r.states["spec"]["status"] == "succeeded", r.states["spec"]
    step_dir = r.run_dir.steps_dir / "spec"
    v = json.loads((step_dir / host_spec.HOST_VARS_FILE).read_text())["vars"]
    assert v["app_config_rotate_days"] == {
        "default": 30,
        "description": "Days between credential rotations.",
        "resolved": 30,
        "role": "app_config",
        "scope": "play",
        "source": "play: ansible/play.yml",
        "type": "int",
    }
    assert v["app_config_banner"]["resolved"] == "demo (prod)"  # role default over host_vars/web1 app_env
    assert v["play_only"]["resolved"] == "demo-play" and v["play_only"]["scope"] == "play"
    assert v["play_token"]["resolved"] == SKIPPED_KEY  # a play var named like a secret never renders
    assert v["app_port"]["resolved"] == 8080 and v["app_port"]["scope"] == "play"
    assert v["nope"]["resolved"] == "<undefined>"
    assert v["db_password"]["scope"] == "inventory"
    text = (project_root / "specs" / "web" / "hosts" / "web1.yaml").read_text()
    assert "credential = <secret: declared>" in text and "listen = 10.0.0.11:8080" in text
    assert "roles:\n  - app_config" in text
    argv = json.loads((step_dir / "argv.json").read_text())[0]
    assert argv[-3:-1] == ["--check", "--diff"] and argv[argv.index("-e") + 1].startswith("@")
    assert not (r.run_dir.handoff_dir / "spec").exists()  # the play file and the -e file are gone
    assert (step_dir / "play-scope.yml").is_file() and (step_dir / "play-scope-events.jsonl").is_file()
    assert not any(s in text for s in FIXTURE_SECRETS)
    assert scan_outputs(r.run_dir.path, all_secrets_registry()) == []


@requires_ansible
def test_vars_subprocess_failure_fails_the_step_and_leaves_the_spec_alone(project_root: Path):
    spec = project_root / "specs" / "web" / "hosts" / "web1.yaml"
    spec.parent.mkdir(parents=True)
    spec.write_text("committed: true\n", encoding="utf-8")
    r = run_spec(project_root, {"inventory": "ansible/inventory/hosts.yml", "host": "not-a-host", "templates": []})
    state = r.states["spec"]
    assert state["status"] == "failed" and "exited 2" in state["error"]
    assert spec.read_text() == "committed: true\n"
    assert not (r.run_dir.steps_dir / "spec" / host_spec.HOST_VARS_FILE).exists()
    assert "not-a-host" in (r.run_dir.steps_dir / "spec" / "stderr.log").read_text()
