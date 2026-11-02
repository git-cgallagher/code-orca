"""The playbook lint: every rule over the fixtures with a stub module resolver (no ansible-core), the source
heuristic, and the installed-module resolver (skipped without ansible-core)."""

from __future__ import annotations

from pathlib import Path

import pytest

from codeorca.lint import RULES, lint_playbooks
from codeorca.lint.ansible import flagged_names, no_log_from_source, resolve_installed_module

FIXTURES = Path(__file__).resolve().parent / "fixtures"
PLAYBOOK = FIXTURES / "playbook.yml"
TASKS = FIXTURES / "tasks.yml"
LOOKUP_DENYLIST = ["amazon.aws.*", "community.hashi_vault.*"]

# What an installed ansible-core 2.21.5 resolves to (verified): copy hides content, user hides password, uri's
# url_password has the alias password, lineinfile and shell hide nothing, the example collection is absent.
STUB = {
    "ansible.builtin.copy": frozenset({"content"}),
    "ansible.builtin.user": frozenset({"password", "ssh_key_passphrase"}),
    "ansible.builtin.uri": frozenset({"url_password", "password"}),
    "ansible.builtin.lineinfile": frozenset(),
    "ansible.builtin.shell": frozenset(),
    "ansible.builtin.file": frozenset(),
}


def stub_resolver(module: str):
    return STUB.get(module)


def findings(*paths: Path, resolver=stub_resolver) -> list[tuple[int, str]]:
    out = lint_playbooks(paths, lookup_denylist=LOOKUP_DENYLIST, resolve_module=resolver)
    assert all(set(f) == {"file", "line", "rule", "level", "message"} and f["rule"] in RULES for f in out)
    return [(f["line"], f["rule"]) for f in out]


def test_every_rule_fires_on_its_line_and_nowhere_else():
    assert findings(PLAYBOOK) == [
        (5, "no-hostvars-dump"),
        (9, "no-hostvars-dump"),
        (13, "no-hostvars-dump"),
        (17, "debug-secret-name"),
        (21, "debug-secret-name"),
        (25, "secret-to-plain-param"),
        (40, "secret-to-plain-param"),
        (43, "secret-to-plain-param"),
        (48, "unknown-module"),
        (52, "redundant-task-no-log"),
        (71, "secret-to-plain-param"),
    ]


def test_levels_and_messages():
    out = {
        f["line"]: f for f in lint_playbooks([PLAYBOOK], lookup_denylist=LOOKUP_DENYLIST, resolve_module=stub_resolver)
    }
    assert out[48]["level"] == "info" and out[52]["level"] == "info"
    assert out[25]["level"] == "warning"
    assert "db_password" in out[25]["message"] and "lineinfile" in out[25]["message"]
    assert "lookup:amazon.aws.ssm_parameter" in out[43]["message"]
    assert "_raw_params" in out[40]["message"]
    assert out[5]["message"].startswith("debug var: hostvars[inventory_hostname]")
    assert out[5]["file"] == str(PLAYBOOK)


def test_task_file_with_a_vaulted_value_is_parsed_and_linted():
    assert findings(TASKS) == [(2, "secret-to-plain-param")]


def test_findings_are_sorted_across_files():
    both = findings(TASKS, PLAYBOOK)
    files = [f["file"] for f in lint_playbooks([TASKS, PLAYBOOK], resolve_module=stub_resolver)]
    assert files == sorted(files) and len(both) == 12


def test_custom_key_denylist_changes_what_is_a_secret():
    out = lint_playbooks([PLAYBOOK], key_denylist=["^app_secret$"], lookup_denylist=[], resolve_module=stub_resolver)
    rules = [(f["line"], f["rule"]) for f in out]
    assert (71, "secret-to-plain-param") in rules
    assert (25, "secret-to-plain-param") not in rules  # db_password is not a secret under this denylist
    assert (17, "debug-secret-name") not in rules
    assert (43, "secret-to-plain-param") not in rules  # no lookup denylist
    assert (5, "no-hostvars-dump") in rules  # independent of the denylist
    with pytest.raises(ValueError, match="bare 'key'"):
        lint_playbooks([PLAYBOOK], key_denylist=["(?i)key"], resolve_module=stub_resolver)


def test_flagged_names_ignores_string_literals_and_filters():
    refs = flagged_names("{{ db_password | b64encode }} {{ 'password' }} {{ x.api_token }}", _patterns(), ())
    assert refs == ["db_password"]
    assert flagged_names({"a": ["{{ lookup('amazon.aws.ssm_parameter', '/p') }}"]}, _patterns(), ["amazon.aws.*"]) == [
        "lookup:amazon.aws.ssm_parameter"
    ]
    assert flagged_names("plain text with password word", _patterns(), ()) == []
    assert flagged_names(42, _patterns(), ()) == []


def _patterns():
    from codeorca.redact import DEFAULT_KEY_DENYLIST, compile_key_denylist

    return compile_key_denylist(DEFAULT_KEY_DENYLIST)


def test_no_log_from_source_reads_both_argument_spec_shapes_at_their_own_level():
    source = """
argument_spec = dict(
    name=dict(type='str', required=True),
    password=dict(type='str', no_log=True, aliases=['pw', "passwd"]),
    extra=dict(type='dict', options=dict(token=dict(type='str', no_log=True))),
)
other = {'api_key': {'type': 'str', 'no_log': True}, 'url': {'type': 'str'}}
"""
    assert no_log_from_source(source) == {"password", "pw", "passwd", "token", "api_key"}
    assert "argument_spec" not in no_log_from_source(source)
    assert "extra" not in no_log_from_source(source)


def test_installed_module_resolver():
    pytest.importorskip("ansible")
    assert resolve_installed_module("ansible.builtin.user") >= {"password"}
    assert resolve_installed_module("uri") >= {"url_password", "password"}
    assert "content" in resolve_installed_module("ansible.builtin.copy")
    assert resolve_installed_module("ansible.builtin.lineinfile") == frozenset()
    assert resolve_installed_module("example.collection.widget") is None
    assert findings(PLAYBOOK, resolver=resolve_installed_module) == findings(PLAYBOOK)
