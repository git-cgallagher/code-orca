"""Review fixes for the Ansible host spec (Phase 2): every way a secret reached a spec, a host-vars.json or the play
scope's events file, and the precedence/provenance fixes. Live runs reuse the fixture project of
``test_spec_render_ansible`` (``tests/fixtures/ansible_host`` copied under ``<project>/ansible``).

Every leak test greps the WHOLE project directory (committed spec, run dir: staged spec, host-vars.json,
play-scope-events.jsonl, stderr.log) for the cleartext: an unregistered value is invisible to ``scan_outputs``."""

from __future__ import annotations

import json
import shutil
import textwrap
from pathlib import Path

import pytest
from test_spec_render_ansible import FIXTURES, requires_ansible, run_spec

from codeorca.specs.ansible_vars import SECRET_DECLARED, SKIPPED_KEY, VAULT, load_argument_specs, merge_specs
from codeorca.steps import host_spec

SPEC = Path("specs/web/hosts/web1.yaml")
VAULT_BLOCK = "\n".join(
    line
    for line in (FIXTURES / "inventory" / "group_vars" / "all.yml").read_text().splitlines()
    if line.startswith("          ") and line.strip()
)  # the fixture ciphertext of FIXTURE-SECRET-vaulted-001 (password: vault-pass.txt, vault id "fixture")


def leaks(root: Path, value: str) -> list[str]:
    """Every output file holding ``value``: the committed spec tree and the whole run dir (inputs excluded)."""
    outputs = [p for d in ("specs", ".codeorca") for p in (root / d).rglob("*")]
    return sorted(
        str(p.relative_to(root))
        for p in outputs
        if p.is_file() and value in p.read_text(encoding="utf-8", errors="ignore")
    )


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text), encoding="utf-8")


def spec_text(root: Path) -> str:
    return (root / SPEC).read_text(encoding="utf-8")


def host_vars(r) -> dict:
    return json.loads((r.run_dir.steps_dir / "spec" / host_spec.HOST_VARS_FILE).read_text())


PLAY_SOURCE = {
    "inventory": "ansible/inventory/hosts.yml",
    "host": "web1",
    "play_scope": {"playbook": "ansible/play.yml", "vars": ["app_port"]},
}


# ------------------------------------------------------------------------- denied lookups in template text


@requires_ansible
@pytest.mark.parametrize("play", [False, True])
def test_a_denied_lookup_written_in_a_listed_template_never_runs(project_root, monkeypatch, play):
    monkeypatch.setenv("CODEORCA_PROBE_VAL", "FIXTURE-ENVSECRET-xyz-0001")
    write(
        project_root / "ansible/templates/leak.j2",
        "# DNS lookup (cached)\nhome = {{ lookup('env', 'CODEORCA_PROBE_VAL') }}\n",
    )
    source = {**PLAY_SOURCE} if play else {"inventory": "ansible/inventory/hosts.yml", "host": "web1"}
    source["templates"] = ["ansible/templates/leak.j2", "ansible/templates/site.conf.j2"]
    r = run_spec(project_root, source)
    assert r.states["spec"]["status"] == "succeeded", r.states["spec"]
    assert leaks(project_root, "FIXTURE-ENVSECRET-xyz-0001") == []
    templates = host_vars(r)["templates"]
    assert templates["ansible/templates/leak.j2"] == "<skipped: lookup ansible.builtin.env is a secret source>"
    assert templates["ansible/templates/site.conf.j2"]  # the other template still renders


# --------------------------------------------------------------------------------- play-scope candidates


@requires_ansible
def test_vars_files_values_get_markers_and_denied_lookups_never_run(project_root, monkeypatch):
    monkeypatch.setenv("CODEORCA_PROBE_VAL", "FIXTURE-ENVSECRET-xyz-0003")
    write(
        project_root / "ansible/play.yml",
        """\
        - hosts: web
          gather_facts: false
          vars_files: [app-vars.yml]
          roles: [app_config]
        """,
    )
    write(
        project_root / "ansible/app-vars.yml",
        """\
        db_password: FIXTURE-PLAINTEXT-dbpass-0003
        app_conn: "{{ lookup('ansible.builtin.env', 'CODEORCA_PROBE_VAL') }}"
        """,
    )
    write(project_root / "ansible/templates/pw.j2", "pw = {{ db_password }}\n")
    source = {**PLAY_SOURCE, "templates": ["ansible/templates/pw.j2"]}
    source["play_scope"] = {"playbook": "ansible/play.yml", "vars": ["app_conn"]}
    r = run_spec(project_root, source)
    assert r.states["spec"]["status"] == "succeeded", r.states["spec"]
    assert leaks(project_root, "FIXTURE-PLAINTEXT-dbpass-0003") == []
    assert leaks(project_root, "FIXTURE-ENVSECRET-xyz-0003") == []
    doc = host_vars(r)
    assert doc["templates"]["ansible/templates/pw.j2"] == f"pw = {SKIPPED_KEY}\n"
    assert doc["vars"]["app_conn"]["resolved"] == "<skipped: lookup ansible.builtin.env is a secret source>"


@requires_ansible
@pytest.mark.parametrize("play", [False, True])
def test_a_nested_denylist_named_leaf_renders_as_a_marker_in_templates(project_root, play):
    write(
        project_root / "ansible/inventory/group_vars/web.yml",
        """\
        app_db: {user: app, password: FIXTURE-NESTED-dbpass-0008}
        """,
    )
    write(project_root / "ansible/templates/db.j2", "db = postgres://{{ app_db.user }}:{{ app_db.password }}@db/app\n")
    source = {**PLAY_SOURCE} if play else {"inventory": "ansible/inventory/hosts.yml", "host": "web1"}
    source["templates"] = ["ansible/templates/db.j2"]
    r = run_spec(project_root, source)
    assert r.states["spec"]["status"] == "succeeded", r.states["spec"]
    assert leaks(project_root, "FIXTURE-NESTED-dbpass-0008") == []
    assert host_vars(r)["templates"]["ansible/templates/db.j2"] == f"db = postgres://app:{SKIPPED_KEY}@db/app\n"


@requires_ansible
def test_one_vault_entry_in_role_defaults_no_longer_hides_the_rest_of_the_file(project_root):
    write(
        project_root / "ansible/roles/app_config/defaults/main.yml",
        "app_config_rotate_days: 30\n"
        'app_config_banner: "{{ app_name }} ({{ app_env }})"\n'
        "app_db_password: FIXTURE-VAULTFILE-plain-0011\n"
        f"app_unused_vaulted: !vault |\n{VAULT_BLOCK}\n",
    )
    write(project_root / "ansible/templates/dbpw.j2", "dbpw = {{ app_db_password }}\n")
    r = run_spec(project_root, {**PLAY_SOURCE, "templates": ["ansible/templates/dbpw.j2"]})
    assert r.states["spec"]["status"] == "succeeded", r.states["spec"]
    assert leaks(project_root, "FIXTURE-VAULTFILE-plain-0011") == []
    assert host_vars(r)["templates"]["ansible/templates/dbpw.j2"] == f"dbpw = {SKIPPED_KEY}\n"


@requires_ansible
def test_role_vars_in_the_main_directory_form_are_seen(project_root):
    write(
        project_root / "ansible/roles/app_config/vars/main/secrets.yml", "app_db_password: FIXTURE-ROLEVARSDIR-0010\n"
    )
    write(project_root / "ansible/templates/dbpw.j2", "dbpw = {{ app_db_password }}\n")
    r = run_spec(project_root, {**PLAY_SOURCE, "templates": ["ansible/templates/dbpw.j2"]})
    assert r.states["spec"]["status"] == "succeeded", r.states["spec"]
    assert leaks(project_root, "FIXTURE-ROLEVARSDIR-0010") == []
    assert host_vars(r)["templates"]["ansible/templates/dbpw.j2"] == f"dbpw = {SKIPPED_KEY}\n"


def test_role_vars_files_mirror_ansible_role_loading(tmp_path: Path):
    from codeorca.specs.ansible_files import find_vars_files, role_vars_files

    role = tmp_path / "r"
    write(role / "defaults/main.yaml", "a: 1\n")
    write(role / "vars/main/b.yml", "b: 1\n")
    write(role / "vars/main/sub/c.json", '{"c": 1}\n')
    write(role / "vars/main/.hidden.yml", "h: 1\n")
    assert role_vars_files(role, "defaults") == [role / "defaults/main.yaml"]
    assert role_vars_files(role, "vars") == [role / "vars/main/b.yml", role / "vars/main/sub/c.json"]
    # group_vars: an extensionless file or a directory counts, and the first hit wins (dir before name.yml)
    write(tmp_path / "gv/all", "x: 1\n")
    write(tmp_path / "gv/all.yml", "y: 1\n")
    assert find_vars_files(tmp_path / "gv", "all") == [tmp_path / "gv/all"]


# ------------------------------------------------------------------------------------------------ vault


@requires_ansible
@pytest.mark.parametrize("how", ["env", "ansible.cfg"])
def test_play_scope_never_decrypts_a_vaulted_role_default(project_root, monkeypatch, how):
    write(
        project_root / "ansible/roles/app_config/defaults/main.yml",
        "app_config_rotate_days: 30\n"
        'app_config_banner: "{{ app_name }} ({{ app_env }})"\n'
        f"app_note: !vault |\n{VAULT_BLOCK}\n",
    )
    write(project_root / "ansible/templates/note.j2", "note = {{ app_note }}\n")
    password = project_root / "ansible" / "vault-pass.txt"
    if how == "env":
        monkeypatch.setenv("ANSIBLE_VAULT_IDENTITY_LIST", f"fixture@{password}")
    else:
        write(project_root / "ansible.cfg", f"[defaults]\nvault_identity_list = fixture@{password}\n")
    source = {**PLAY_SOURCE, "templates": ["ansible/templates/note.j2"]}
    source["play_scope"] = {"playbook": "ansible/play.yml", "vars": ["app_note"]}
    r = run_spec(project_root, source)
    assert r.states["spec"]["status"] == "succeeded", r.states["spec"]
    assert leaks(project_root, "FIXTURE-SECRET-vaulted-001") == []
    doc = host_vars(r)
    assert doc["vars"]["app_note"]["resolved"] == VAULT
    assert doc["templates"]["ansible/templates/note.j2"] == f"note = {VAULT}\n"


# ---------------------------------------------------------------------------------------- argument specs


@requires_ansible
def test_no_log_from_a_roles_dir_next_to_the_playbook_reaches_the_inventory_scope(project_root):
    playbooks = project_root / "playbooks"
    write(playbooks / "site.yml", "- hosts: web\n  gather_facts: false\n  roles: [other]\n")
    write(playbooks / "roles/other/tasks/main.yml", "- ansible.builtin.debug: {msg: hi}\n")
    write(
        playbooks / "roles/other/meta/argument_specs.yml",
        "argument_specs:\n  main:\n    options:\n      other_dsn: {type: str, no_log: true}\n",
    )
    write(
        project_root / "ansible/inventory/group_vars/web.yml", "other_dsn: postgres://app:FIXTURE-PLAINDSN-99@db/app\n"
    )
    source = {"inventory": "ansible/inventory/hosts.yml", "host": "web1"}
    source["play_scope"] = {"playbook": "playbooks/site.yml", "vars": []}
    r = run_spec(project_root, source)
    assert r.states["spec"]["status"] == "succeeded", r.states["spec"]
    assert leaks(project_root, "FIXTURE-PLAINDSN-99") == []
    assert host_vars(r)["vars"]["other_dsn"]["resolved"] == SECRET_DECLARED


def test_no_log_is_or_ed_across_roles_and_meta_main_is_read(tmp_path: Path):
    from ruamel.yaml import YAML

    def load(path: Path):
        return YAML(typ="safe", pure=True).load(path.read_text())

    write(tmp_path / "a/meta/argument_specs.yml", "argument_specs:\n  main:\n    options:\n      conn: {type: str}\n")
    write(
        tmp_path / "b/meta/argument_specs.yml",
        "argument_specs:\n  main:\n    options:\n      conn: {type: str, no_log: true}\n"
        "  other:\n    options:\n      since: {type: str, default: 2024-01-01}\n",
    )
    write(
        tmp_path / "c/meta/main.yml", "argument_specs:\n  main:\n    options:\n      c_dsn: {type: str, no_log: true}\n"
    )
    specs = load_argument_specs(tmp_path, load)
    assert specs["conn"] == {"role": "a", "type": "str", "no_log": True}  # docs from a, no_log from b
    assert specs["c_dsn"]["no_log"] is True and specs["c_dsn"]["role"] == "c"
    assert specs["since"]["default"] == "2024-01-01"  # a YAML date, as JSON
    json.dumps(specs)
    assert merge_specs({"x": {"role": "a"}}, {"x": {"role": "b", "no_log": True}}) == {
        "x": {"role": "a", "no_log": True}
    }


@requires_ansible
def test_a_date_default_does_not_crash_the_vars_subprocess(project_root):
    write(
        project_root / "ansible/roles/app_config/meta/argument_specs.yml",
        (project_root / "ansible/roles/app_config/meta/argument_specs.yml").read_text()
        + "  dated:\n    options:\n      when_date: {type: str, default: 2024-01-01}\n",
    )
    write(project_root / "ansible/inventory/group_vars/web.yml", "when_date: soon\n")
    r = run_spec(project_root, {**PLAY_SOURCE, "play_scope": {"playbook": "ansible/play.yml", "vars": ["when_date"]}})
    assert r.states["spec"]["status"] == "succeeded", r.states["spec"]
    assert host_vars(r)["vars"]["when_date"]["default"] == "2024-01-01"


def test_handoff_markers_use_the_resolved_fqcn_of_a_short_lookup_name():
    candidates = {"db_conn": "{{ lookup('aws_ssm', '/app/db') }}"}
    assert host_spec.handoff_markers({"vars": {}}, {}, candidates, [], [], ["amazon.aws.aws_ssm"]) == {}
    markers = host_spec.handoff_markers(
        {"vars": {}}, {}, candidates, [], [], ["amazon.aws.aws_ssm"], fqcns={"aws_ssm": "amazon.aws.aws_ssm"}
    )
    assert markers == {"db_conn": "<skipped: lookup amazon.aws.aws_ssm is a secret source>"}
    assert host_spec.lookup_names(list(candidates.values())) == ["aws_ssm"]


# ---------------------------------------------------------------------------------- precedence, provenance


@requires_ansible
def test_extra_vars_outrank_host_vars_files(project_root):
    staged = project_root / "producer"
    staged.mkdir()
    shutil.copy(project_root / "ansible/inventory/hosts.yml", staged / "hosts.yml")
    shutil.copytree(project_root / "ansible/inventory/group_vars", staged / "group_vars")
    write(staged / "host_vars/web1.yml", "app_bucket: from-host-vars-file\n")
    (staged / "extra-vars.json").write_text(json.dumps({"app_bucket": "example-app-123456789012"}))
    r = run_spec(project_root, {"inventory": "producer/hosts.yml", "host": "web1"})
    assert r.states["spec"]["status"] == "succeeded", r.states["spec"]
    entry = host_vars(r)["vars"]["app_bucket"]
    assert entry["resolved"] == "example-app-123456789012" and entry["source"] == "extra_vars"


@requires_ansible
def test_only_plays_that_target_the_host_feed_its_spec(project_root):
    write(
        project_root / "ansible/play.yml",
        """\
        - hosts: web
          gather_facts: false
          roles: [app_config]
        - hosts: elsewhere
          gather_facts: false
          roles: [other_role]
        """,
    )
    write(project_root / "ansible/roles/other_role/defaults/main.yml", "app_config_rotate_days: 9999\n")
    write(project_root / "ansible/roles/other_role/tasks/main.yml", "- ansible.builtin.debug: {msg: x}\n")
    r = run_spec(
        project_root,
        {**PLAY_SOURCE, "play_scope": {"playbook": "ansible/play.yml", "vars": ["app_config_rotate_days"]}},
    )
    assert r.states["spec"]["status"] == "succeeded", r.states["spec"]
    doc = host_vars(r)
    assert doc["vars"]["app_config_rotate_days"]["resolved"] == 30
    assert doc["play_scope"]["roles"] == ["app_config"]


@requires_ansible
def test_one_failing_template_does_not_hide_the_others_or_the_vars(project_root):
    write(project_root / "ansible/templates/bad.j2", "{{ not_defined_anywhere }}\n")
    source = {
        **PLAY_SOURCE,
        "templates": ["ansible/templates/bad.j2", "ansible/roles/app_config/templates/app.conf.j2"],
    }
    source["play_scope"] = {"playbook": "ansible/play.yml", "vars": ["app_config_rotate_days"]}
    r = run_spec(project_root, source)
    assert r.states["spec"]["status"] == "failed" and "bad.j2" in r.states["spec"]["error"]
    doc = host_vars(r)
    assert "listen = 10.0.0.11:8080" in doc["templates"]["ansible/roles/app_config/templates/app.conf.j2"]
    assert doc["vars"]["app_config_rotate_days"]["scope"] == "play"
    assert list(doc["errors"]["play"]) == ["codeorca:template:ansible/templates/bad.j2"]


def test_play_scope_events_record_tasks_that_never_ran():
    from codeorca.specs.ansible_host import parse_play_scope_events

    parsed = parse_play_scope_events([], "h", ["codeorca:template:/a.j2", "codeorca:vars"])
    assert parsed["errors"] == {"codeorca:template:/a.j2": "not run", "codeorca:vars": "not run"}


def test_merge_labels_a_play_scope_value_with_its_real_source(tmp_path: Path):
    vars_json = {
        "vars": {
            "app_region": {"declared": "us-east-1", "resolved": "us-east-1", "source": "group_vars/app.yml"},
            "app_bucket": {"declared": "b", "resolved": "b", "source": "extra_vars (step c)"},
        }
    }
    play = {
        "vars": {"app_region": "eu-west-1", "app_listen_port": 8080, "app_bucket": "b"},
        "provenance": {
            "app_region": [host_spec.RANK_PLAY_VARS, "play vars: ansible/site.yml"],
            "app_listen_port": [host_spec.RANK_ROLE_DEFAULTS, "role defaults: app_config"],
            "app_bucket": [host_spec.RANK_ROLE_VARS, "role vars: app_config"],
        },
    }
    v = host_spec.merge_play_scope(vars_json, play, {}, [], "ansible/site.yml", tmp_path)["vars"]
    assert v["app_region"] == {"resolved": "eu-west-1", "source": "play vars: ansible/site.yml", "scope": "play"}
    assert v["app_listen_port"]["source"] == "role defaults: app_config"
    assert v["app_bucket"]["source"] == "extra_vars (step c)"  # extra vars outrank everything
