"""The redacted host document, the play-scope play generator and the events parser (no ansible-core needed)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from ruamel.yaml import YAML

from codeorca.redact import KEY_PLACEHOLDER, SecretRegistry
from codeorca.specs import render_spec_yaml, write_spec
from codeorca.specs.ansible_host import (
    KIND,
    build_host_document,
    header_for,
    marker_vars,
    parse_play_scope_events,
    render_play_scope_playbook,
)
from codeorca.specs.ansible_vars import SECRET_DECLARED, SKIPPED_KEY, VAULT

SECRET = "FIXTURE-SECRET-seeded-in-registry-001"
DENYLIST = ["(?i)password", "(?i)secret", "(?i)token"]


def vars_json() -> dict:
    """A subprocess document as ``ansible_vars`` emits it, with a seeded secret echoed where it could leak."""
    return {
        "host": "web1",
        "inventory_source": "/work/inventory/hosts.yml",
        "engine": {"name": "ansible-core", "version": "2.21.5"},
        "vars": {
            "app_port": {
                "declared": "{{ 8000 + 80 }}",
                "resolved": 8080,
                "source": "group_vars/all.yml",
                "type": "int",
            },
            "db_password": {"declared": SKIPPED_KEY, "resolved": SKIPPED_KEY, "source": "group_vars/all.yml"},
            "app_config_api_credential": {"declared": SECRET_DECLARED, "resolved": SECRET_DECLARED, "no_log": True},
            "vaulted_value": {"declared": VAULT, "resolved": VAULT, "source": "group_vars/all.yml"},
            "echoed": {"declared": "{{ handoff_value }}", "resolved": SECRET, "source": "unknown"},
            "nested": {
                "declared": {"url": "{{ x }}", "auth": {"token": "{{ t }}"}},
                "resolved": {"url": "http://example", "auth": {"token": "example-not-secret-tok"}},
                "source": "group_vars/all.yml",
            },
            "broken": {
                "declared": "{{ nope }}",
                "resolved": None,
                "error": "AnsibleUndefinedVariable: 'nope' is undefined",
            },
        },
        "templates": {"templates/site.conf.j2": f"url http://example\nauth {SECRET}\n", "bad.j2": None},
        "errors": {"vars": {"broken": "AnsibleUndefinedVariable: 'nope' is undefined"}, "templates": {"bad.j2": "x"}},
    }


@pytest.fixture
def registry() -> SecretRegistry:
    reg = SecretRegistry(b"example-not-secret-key", "env:abcd1234")
    reg.add(SECRET)
    return reg


def test_document_is_redacted_and_keeps_every_var_name(registry):
    doc = build_host_document(vars_json(), registry, DENYLIST)
    text = json.dumps(doc)
    assert SECRET not in text
    assert doc["kind"] == KIND and doc["host"] == "web1"
    v = doc["vars"]
    # the var NAMES survive the key denylist: it applies inside the value trees only
    assert set(v) == {
        "app_port",
        "db_password",
        "app_config_api_credential",
        "vaulted_value",
        "echoed",
        "nested",
        "broken",
    }
    assert v["db_password"]["declared"] == SKIPPED_KEY and v["db_password"]["source"] == "group_vars/all.yml"
    assert (
        v["app_config_api_credential"]["resolved"] == SECRET_DECLARED
        and v["app_config_api_credential"]["no_log"] is True
    )
    assert v["vaulted_value"]["resolved"] == VAULT
    assert v["app_port"]["resolved"] == 8080 and v["app_port"]["type"] == "int"
    assert v["echoed"]["resolved"] == registry.placeholder(SECRET)  # the registry scrub, stable placeholder
    assert v["nested"]["resolved"]["auth"]["token"] == KEY_PLACEHOLDER  # denylist inside a value tree
    assert v["nested"]["declared"]["auth"]["token"] == KEY_PLACEHOLDER
    assert v["nested"]["resolved"]["url"] == "http://example"
    assert v["broken"]["resolved"] is None and v["broken"]["error"].startswith("AnsibleUndefinedVariable")
    assert doc["templates"]["templates/site.conf.j2"] == f"url http://example\nauth {registry.placeholder(SECRET)}\n"
    assert doc["templates"]["bad.j2"] is None
    assert doc["errors"]["templates"] == {"bad.j2": "x"}


def test_document_renders_through_the_spec_writer_and_passes_the_gate(registry, tmp_path: Path):
    doc = build_host_document(vars_json(), registry, DENYLIST)
    header = header_for(doc, registry.key_id, "abc1234", workflow="rollout", stack="app")
    assert header["kind"] == KIND and header["engine"] == "ansible-core/2.21.5" and header["stack"] == "app"
    text = render_spec_yaml(doc, header)
    assert text.startswith("codeorca:\n  pipeline: ")
    assert SECRET not in text and "FIXTURE-SECRET" not in text
    spec, side = write_spec(tmp_path / "web1.yaml", doc, header, {"run_id": "r1"}, registry)
    assert spec.read_text() == text and side.name == "web1.meta.yaml"
    # the gate holds when something unredacted is handed to the writer
    leaky = dict(doc)
    leaky["templates"] = {"x": SECRET}
    with pytest.raises(Exception, match="redaction gate"):
        write_spec(tmp_path / "leaky.yaml", leaky, header, None, registry)
    assert not (tmp_path / "leaky.yaml").exists()


def test_marker_vars_lift_every_marker_and_nothing_else():
    doc = vars_json()
    doc["vars"]["from_env"] = {
        "declared": "{{ lookup('env', 'X') }}",
        "resolved": "<skipped: lookup ansible.builtin.env is a secret source>",
    }
    assert marker_vars(doc) == {
        "app_config_api_credential": SECRET_DECLARED,
        "db_password": SKIPPED_KEY,
        "from_env": "<skipped: lookup ansible.builtin.env is a secret source>",
        "vaulted_value": VAULT,
    }
    assert marker_vars({"vars": {}}) == {}


# --------------------------------------------------------------------------------------------- play scope


def test_play_scope_playbook_is_valid_yaml_check_mode_and_never_dumps_hostvars(tmp_path: Path):
    tpl = tmp_path / "templates" / "nginx.conf.j2"
    tpl.parent.mkdir()
    tpl.write_text("x")
    text = render_play_scope_playbook(
        tmp_path / "spec-play.yml",
        ["app_port", "app_url"],
        [tpl],
        tmp_path / "out",
        host="web1",
        roles=["app_config", "git_cgallagher.isc.kea_dhcp"],
        play_vars={"play_only": 1},
        vars_files=["vars/common.yml"],
    )
    assert "hostvars" not in text
    plays = YAML(typ="safe", pure=True).load(text)
    assert len(plays) == 1
    play = plays[0]
    assert play["hosts"] == "web1" and play["connection"] == "local" and play["gather_facts"] is False
    assert play["vars"] == {"play_only": 1} and play["vars_files"] == ["vars/common.yml"]
    tasks = {t["name"]: t for t in play["tasks"]}
    assert tasks["codeorca:role:app_config"] == {
        "name": "codeorca:role:app_config",
        "ansible.builtin.import_role": {"name": "app_config"},
        "when": False,
    }
    assert "codeorca:role:git_cgallagher.isc.kea_dhcp" in tasks
    template_task = tasks[f"codeorca:template:{tpl}"]
    assert template_task["ansible.builtin.template"] == {
        "src": "templates/nginx.conf.j2",
        "dest": str(tmp_path / "out" / "nginx.conf.j2"),
    }
    assert template_task["check_mode"] is True and template_task["diff"] is True
    vars_task = tasks["codeorca:vars"]
    content = vars_task["ansible.builtin.copy"]["content"]
    assert content.startswith("{{ {") and content.endswith("} | to_nice_json }}")
    assert "'app_port': app_port | default('<undefined>')" in content
    assert vars_task["check_mode"] is True and vars_task["diff"] is True
    assert text == render_play_scope_playbook(
        tmp_path / "spec-play.yml",
        ["app_port", "app_url"],
        [tpl],
        tmp_path / "out",
        host="web1",
        roles=["app_config", "git_cgallagher.isc.kea_dhcp"],
        play_vars={"play_only": 1},
        vars_files=["vars/common.yml"],
    )


@pytest.mark.parametrize("bad", ["hostvars", "vars", "groups", "a-b", "x; y", "hostvars[inventory_hostname]", ""])
def test_play_scope_refuses_non_identifiers_and_dumps(bad, tmp_path: Path):
    with pytest.raises(ValueError):
        render_play_scope_playbook(tmp_path / "p.yml", [bad], [], tmp_path)


def test_play_scope_without_vars_has_no_copy_task(tmp_path: Path):
    plays = YAML(typ="safe", pure=True).load(
        render_play_scope_playbook(tmp_path / "p.yml", [], ["t.j2"], tmp_path / "o")
    )
    assert [t["name"] for t in plays[0]["tasks"]] == ["codeorca:template:t.j2"]
    assert plays[0]["tasks"][0]["ansible.builtin.template"]["src"] == "t.j2"


def test_events_parser_reads_both_diff_placements_and_errors():
    rendered = "server_name example;\n"
    dump = json.dumps({"app_port": 8080, "app_url": "http://example"})
    events = [
        {"type": "playbook_start"},
        {"type": "task", "host": "web1", "task": "codeorca:role:app_config", "status": "skipped", "result": {}},
        {
            "type": "task",
            "host": "web1",
            "task": "codeorca:template:templates/a.j2",
            "status": "ok",
            "result": {"changed": True, "diff": [{"before": "", "after": rendered}]},
        },
        {
            "type": "task",
            "host": "web1",
            "task": "codeorca:template:templates/b.j2",
            "status": "changed",
            "result": {},
            "diff": {"before": "", "after": "b-rendered"},
        },
        {
            "type": "task",
            "host": "web1",
            "task": "codeorca:template:templates/c.j2",
            "status": "failed",
            "result": {"failed": True, "msg": "AnsibleUndefinedVariable: 'x' is undefined"},
        },
        {"type": "task", "host": "web1", "task": "codeorca:template:templates/d.j2", "status": "ok", "result": {}},
        {"type": "task", "host": "web1", "task": "codeorca:vars", "result": {"diff": [{"after": dump, "before": ""}]}},
        {
            "type": "task",
            "host": "web2",
            "task": "codeorca:vars",
            "result": {"diff": [{"after": '{"other": 1}', "before": ""}]},
        },
        {
            "type": "task",
            "host": "web1",
            "task": "unrelated task",
            "status": "ok",
            "result": {"diff": [{"after": "ignored"}]},
        },
        "not an event",
    ]
    parsed = parse_play_scope_events(events, host="web1")
    assert parsed["vars"] == {"app_port": 8080, "app_url": "http://example"}
    assert parsed["templates"] == {"templates/a.j2": rendered, "templates/b.j2": "b-rendered"}
    assert parsed["errors"]["codeorca:template:templates/c.j2"].startswith("AnsibleUndefinedVariable")
    assert parsed["errors"]["codeorca:template:templates/d.j2"].startswith("no diff")
    everyone = parse_play_scope_events(events)
    assert everyone["vars"] == {"app_port": 8080, "app_url": "http://example", "other": 1}
    bad = parse_play_scope_events([{"task": "codeorca:vars", "status": "ok", "diff": [{"after": "not json"}]}])
    assert bad["vars"] == {} and bad["errors"] == {"codeorca:vars": "vars dump is not JSON"}
