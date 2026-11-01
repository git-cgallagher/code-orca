"""The inventory-scope renderer: pure helpers (no ansible needed) and the subprocess over the fixture inventory
(skipped without ansible-core; ``pip install -e '.[ansible]'``)."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

from codeorca.specs.ansible_host import AnsibleVarsError, run_vars_subprocess
from codeorca.specs.ansible_vars import (
    SECRET_DECLARED,
    SKIPPED_KEY,
    SKIPPED_LOOKUP_DYNAMIC,
    VAULT,
    is_magic,
    load_argument_specs,
    lookup_denied,
    lookup_skip_reason,
    lookups_in,
    vars_files_for,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "ansible_host"
INVENTORY = FIXTURES / "inventory" / "hosts.yml"
ROLES = FIXTURES / "roles"
TEMPLATES = [FIXTURES / "templates" / "site.conf.j2", FIXTURES / "roles" / "app_config" / "templates" / "app.conf.j2"]
LOOKUP_DENYLIST = ["ansible.builtin.env", "amazon.aws.*", "community.hashi_vault.*"]
KEY_DENYLIST = ["(?i)password", "(?i)token"]
KEY_PATTERNS = tuple(re.compile(p) for p in KEY_DENYLIST)

# --------------------------------------------------------------------------------------------- pure helpers


def test_magic_vars_are_skipped_but_connection_basics_kept():
    for name in ("hostvars", "groups", "omit", "vars", "group_names", "inventory_hostname", "inventory_dir"):
        assert is_magic(name)
    for name in ("playbook_dir", "ansible_playbook_python", "ansible_facts", "ansible_python_interpreter"):
        assert is_magic(name)
    for name in ("ansible_host", "ansible_port", "ansible_user", "ansible_connection", "app_name"):
        assert not is_magic(name)


def test_lookups_are_found_in_nested_values_with_literal_names_only():
    value = {
        "a": "{{ lookup('env', 'HOME') }}",
        "b": ['{{ query("ansible.builtin.file", path) }}'],
        "c": "{{ q(name) }}",
    }
    found = lookups_in(value)
    assert ("env", ", 'HOME') ") in found or ("env", ", 'HOME'") in found
    assert any(n == "ansible.builtin.file" for n, _ in found)
    assert (None, "") in found  # q(name): not a literal -> fail closed
    assert lookups_in("{{ seq(1) }} {{ sequence }}") == []  # ``seq(`` is not ``q(``


def test_lookup_skip_reason_denylist_argument_and_dynamic():
    resolve = {"env": "ansible.builtin.env", "file": "ansible.builtin.file"}.get
    assert lookup_denied("env", "ansible.builtin.env", ["ansible.builtin.env"])
    assert lookup_denied("amazon.aws.ssm_parameter", None, ["amazon.aws.*"])
    assert not lookup_denied("file", "ansible.builtin.file", ["amazon.aws.*"])
    env = lookup_skip_reason("{{ lookup('env', 'HOME') }}", LOOKUP_DENYLIST, KEY_PATTERNS, resolve)
    assert env == "<skipped: lookup ansible.builtin.env is a secret source>"
    ssm = lookup_skip_reason("{{ lookup('amazon.aws.ssm_parameter', '/x') }}", LOOKUP_DENYLIST, KEY_PATTERNS, resolve)
    assert ssm == "<skipped: lookup amazon.aws.ssm_parameter is a secret source>"
    arg = lookup_skip_reason("{{ lookup('file', api_token_path) }}", LOOKUP_DENYLIST, KEY_PATTERNS, resolve)
    assert arg == "<skipped: lookup ansible.builtin.file argument matches the key denylist>"
    assert (
        lookup_skip_reason("{{ lookup(plugin, 'x') }}", LOOKUP_DENYLIST, KEY_PATTERNS, resolve)
        == SKIPPED_LOOKUP_DYNAMIC
    )
    assert lookup_skip_reason("{{ lookup('file', '/etc/motd') }}", LOOKUP_DENYLIST, KEY_PATTERNS, resolve) is None
    assert lookup_skip_reason({"n": 1, "s": "plain"}, LOOKUP_DENYLIST, KEY_PATTERNS, resolve) is None


def test_argument_specs_cover_every_entry_point_and_nested_no_log():
    from ruamel.yaml import YAML

    specs = load_argument_specs(ROLES, lambda p: YAML(typ="safe", pure=True).load(p.read_text()))
    assert specs["app_config_api_credential"]["no_log"] is True
    assert specs["app_config_api_credential"]["role"] == "app_config"
    assert specs["app_config_extra"]["no_log"] is True  # nested option token: no_log
    assert specs["app_port"] == {
        "role": "app_config",
        "type": "int",
        "default": 8080,
        "description": "Port the app listens on.",
    }
    assert specs["app_config_listen"]["required"] is True
    assert specs["app_config_rotate_days"]["default"] == 30  # the ``rotate`` entry point
    assert load_argument_specs(FIXTURES / "nope", lambda p: None) == {}


def test_vars_files_for_covers_file_and_directory_forms(tmp_path: Path):
    base = tmp_path / "group_vars"
    (base / "web").mkdir(parents=True)
    (base / "all.yml").write_text("a: 1\n")
    (base / "web" / "10-main.yaml").write_text("b: 1\n")
    (base / "web" / ".hidden.yml").write_text("c: 1\n")
    (base / "web" / "notes.txt").write_text("x")
    assert vars_files_for(base, "all") == [base / "all.yml"]
    assert vars_files_for(base, "web") == [base / "web" / "10-main.yaml"]
    assert vars_files_for(base, "db") == []


# ---------------------------------------------------------------------------------------------- subprocess


@pytest.fixture(scope="module")
def env(tmp_path_factory) -> dict[str, str]:
    """A minimal child environment: ansible needs a writable HOME for ``~/.ansible/tmp``."""
    return {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path_factory.mktemp("home"))}


@pytest.fixture(scope="module")
def web1(env) -> dict:
    pytest.importorskip("ansible")
    stderr: list[str] = []
    doc = run_vars_subprocess(
        sys.executable,
        INVENTORY,
        "web1",
        ROLES,
        LOOKUP_DENYLIST,
        KEY_DENYLIST,
        TEMPLATES,
        {**env, "CODEORCA_REDACTION_KEY": "example-not-secret-key"},
        stderr=stderr.append,
    )
    doc["_stderr"] = stderr
    return doc


def test_subprocess_document_shape(web1):
    assert web1["host"] == "web1"
    assert web1["inventory_source"] == str(INVENTORY)
    assert web1["engine"]["name"] == "ansible-core" and web1["engine"]["version"]
    assert set(web1["vars"]) >= {"app_name", "app_port", "db_password", "vaulted_value", "from_env", "motd", "from_ssm"}
    assert not any(k in web1["vars"] for k in ("hostvars", "groups", "inventory_hostname", "ansible_facts", "omit"))
    assert all(isinstance(line, str) for line in web1["_stderr"])


def test_declared_resolved_source_triple(web1):
    v = web1["vars"]
    assert v["app_port"]["declared"] == "{{ 8000 + 80 }}"
    assert v["app_port"]["resolved"] == 8080 and isinstance(v["app_port"]["resolved"], int)
    assert v["app_port"]["source"] == "group_vars/all.yml"
    assert v["app_url"]["resolved"] == "http://demo-prod.example.com:8080"
    assert v["nested"]["resolved"] == {"url": "http://demo-prod.example.com:8080/api", "ports": [80, 8080]}
    assert v["listen_ip"] == {"declared": "{{ ansible_host }}", "resolved": "10.0.0.11", "source": "group_vars/all.yml"}


def test_provenance_follows_precedence(web1):
    v = web1["vars"]
    assert v["app_env"] == {"declared": "prod", "resolved": "prod", "source": "hosts.yml (host entry)"}
    assert v["app_tier"]["source"] == "group_vars/web.yml"
    assert v["site_role"]["source"] == "host_vars/web1.yml"
    assert v["ansible_host"]["source"] == "hosts.yml (host entry)"


def test_web2_sees_the_group_value_and_not_web1s_host_vars():
    pytest.importorskip("ansible")
    doc = run_vars_subprocess(
        sys.executable, INVENTORY, "web2", None, LOOKUP_DENYLIST, KEY_DENYLIST, [], {"PATH": "/usr/bin:/bin"}
    )
    assert doc["vars"]["app_env"] == {"declared": "staging", "resolved": "staging", "source": "group_vars/web.yml"}
    assert "site_role" not in doc["vars"]
    assert doc["vars"]["app_url"]["resolved"] == "http://demo-staging.example.com:8080"
    assert "role" not in doc["vars"]["app_port"]  # no --roles-path: no enrichment


def test_vault_lookups_and_denylists(web1):
    v = web1["vars"]
    assert v["vaulted_value"] == {"declared": VAULT, "resolved": VAULT, "source": "group_vars/all.yml"}
    assert v["from_env"]["resolved"] == "<skipped: lookup ansible.builtin.env is a secret source>"
    assert v["from_env"]["declared"] == "{{ lookup('env', 'HOME') }}"
    assert v["motd"]["resolved"] == "hello from a file lookup"  # the file lookup ran
    assert v["from_ssm"]["resolved"] == "<skipped: lookup amazon.aws.ssm_parameter is a secret source>"
    assert v["from_query"]["resolved"] == "<skipped: lookup ansible.builtin.file argument matches the key denylist>"
    assert v["db_password"] == {"declared": SKIPPED_KEY, "resolved": SKIPPED_KEY, "source": "group_vars/all.yml"}
    assert "FIXTURE-SECRET" not in json.dumps(web1)


def test_argument_spec_enrichment_and_declared_secret(web1):
    v = web1["vars"]
    cred = v["app_config_api_credential"]
    assert cred["declared"] == SECRET_DECLARED and cred["resolved"] == SECRET_DECLARED
    assert cred["role"] == "app_config" and cred["no_log"] is True and cred["type"] == "str"
    assert v["app_config_extra"]["resolved"] == SECRET_DECLARED  # nested no_log marks the whole var
    assert v["app_port"]["role"] == "app_config" and v["app_port"]["default"] == 8080
    assert v["app_config_listen"]["required"] is True and v["app_config_listen"]["resolved"] == "10.0.0.11:8080"


def test_templates_render_with_markers_in_place(web1):
    site = web1["templates"][str(TEMPLATES[0])]
    assert "server_name demo-prod.example.com;" in site
    assert "listen 10.0.0.11:8080;" in site
    assert f"db_password {SKIPPED_KEY};" in site
    assert "env <skipped: lookup ansible.builtin.env is a secret source>;" in site
    app = web1["templates"][str(TEMPLATES[1])]
    assert f"credential = {SECRET_DECLARED}" in app
    assert "motd = hello from a file lookup" in app
    assert web1["errors"]["templates"] == {}


def test_one_bad_key_errors_alone(web1):
    v = web1["vars"]
    assert v["broken"]["resolved"] is None
    assert v["broken"]["error"].startswith("AnsibleUndefinedVariable:")
    assert web1["errors"]["vars"] == {"broken": v["broken"]["error"]}
    assert v["app_url"]["resolved"] == "http://demo-prod.example.com:8080"


def test_unknown_host_and_bad_template_are_reported():
    pytest.importorskip("ansible")
    lines: list[str] = []
    with pytest.raises(AnsibleVarsError, match="exited 2"):
        run_vars_subprocess(
            sys.executable, INVENTORY, "nope", None, [], [], [], {"PATH": "/usr/bin:/bin"}, stderr=lines.append
        )
    assert any("nope" in line for line in lines)
    doc = run_vars_subprocess(
        sys.executable, INVENTORY, "web2", None, [], [], ["/nonexistent/x.j2"], {"PATH": "/usr/bin:/bin"}
    )
    assert doc["templates"] == {"/nonexistent/x.j2": None}
    assert doc["errors"]["templates"]["/nonexistent/x.j2"].startswith("FileNotFoundError:")


def test_subprocess_prints_nothing_but_the_document(env):
    pytest.importorskip("ansible")
    import subprocess

    out = subprocess.run(
        [sys.executable, "-m", "codeorca.specs.ansible_vars", "--inventory", str(INVENTORY), "--host", "web2"],
        capture_output=True,
        text=True,
        env={**env, "ANSIBLE_NOCOLOR": "1"},
        check=True,
    )
    assert json.loads(out.stdout)["host"] == "web2"
    assert out.stdout.count("\n") == 1
