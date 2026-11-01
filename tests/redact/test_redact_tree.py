"""redact_tree: value scrub in every encoding at every depth, key denylist, bare-``key`` refusal."""

from __future__ import annotations

import pytest

from codeorca.redact import DEFAULT_KEY_DENYLIST, KEY_PLACEHOLDER, PLACEHOLDER_RE, compile_key_denylist, redact_tree


def test_tree_keeps_shape_and_replaces_every_encoding(registry, encode):
    registry.add("FIXTURE-SECRET-abc123")
    ph = registry.placeholder("FIXTURE-SECRET-abc123")
    enc = encode("FIXTURE-SECRET-abc123")
    tree = {
        "plain": "hello",
        "n": 3,
        "flag": True,
        "nothing": None,
        "list": [enc["raw"], {"deep": [enc["base64"], 1]}, (enc["url"],)],
        "text": f'{{"pw": "{enc["json"]}"}}',
    }
    out = redact_tree(tree, registry)
    assert out == {
        "plain": "hello",
        "n": 3,
        "flag": True,
        "nothing": None,
        "list": [ph, {"deep": [ph, 1]}, (ph,)],
        "text": f'{{"pw": "{ph}"}}',
    }
    assert tree["list"][0] == "FIXTURE-SECRET-abc123"  # input untouched


def test_dict_keys_holding_a_secret_are_scrubbed(registry):
    registry.add("FIXTURE-SECRET-abc123")
    out = redact_tree({"by_token": {"FIXTURE-SECRET-abc123": "host1"}}, registry)
    assert list(out["by_token"]) == [registry.placeholder("FIXTURE-SECRET-abc123")]


def test_key_denylist_replaces_the_value_whatever_its_shape(registry):
    tree = {
        "db_password": "hunter2",
        "api_token": {"nested": "structure", "n": 1},
        "tokens": ["a", "b"],
        "input_wo": "FIXTURE",
        "input_wo_version": 2,
        "name": "ok",
        "ssh_key_file": "/home/example/.ssh/id_ed25519",
        "GPG_KEY": "0123456789ABCDEF",
        "unset_secret": None,
    }
    out = redact_tree(tree, registry, DEFAULT_KEY_DENYLIST)
    assert out["db_password"] == KEY_PLACEHOLDER
    assert out["api_token"] == KEY_PLACEHOLDER
    assert out["tokens"] == KEY_PLACEHOLDER
    assert out["input_wo"] == KEY_PLACEHOLDER
    assert out["input_wo_version"] == 2  # the `_wo$` anchor spares the version counter
    assert out["name"] == "ok"
    assert out["ssh_key_file"] == tree["ssh_key_file"]  # no bare `key` pattern in the default list
    assert out["GPG_KEY"] == tree["GPG_KEY"]
    assert out["unset_secret"] is None


def test_key_denylist_applies_at_every_depth_and_inside_lists(registry):
    tree = {"hosts": [{"name": "a", "vars": {"ansible_password": "x"}}, {"name": "b", "secret": {"k": "v"}}]}
    out = redact_tree(tree, registry, ["(?i)password", "(?i)secret"])
    assert out == {
        "hosts": [
            {"name": "a", "vars": {"ansible_password": KEY_PLACEHOLDER}},
            {"name": "b", "secret": KEY_PLACEHOLDER},
        ]
    }


def test_key_denylist_is_pure_and_does_not_register(registry):
    before = registry.size
    redact_tree({"secret": "ssm:/example/app/api-token"}, registry, DEFAULT_KEY_DENYLIST)
    assert registry.size == before
    assert (
        redact_tree({"path": "ssm:/example/app/api-token"}, registry, DEFAULT_KEY_DENYLIST)["path"]
        == "ssm:/example/app/api-token"
    )


def test_key_denylist_matches_key_name_by_search(registry):
    out = redact_tree({"tls_private_key": "x", "private_key_pem": "y", "keyring": "z"}, registry, ["(?i)private_key"])
    assert out == {"tls_private_key": KEY_PLACEHOLDER, "private_key_pem": KEY_PLACEHOLDER, "keyring": "z"}


@pytest.mark.parametrize("bad", ["key", "(?i)key", "^key$", "(?i)^key$", " key "])
def test_bare_key_pattern_is_refused(registry, bad):
    with pytest.raises(ValueError, match="bare 'key'"):
        compile_key_denylist([bad])
    with pytest.raises(ValueError):
        redact_tree({"a": "b"}, registry, [bad])


def test_key_like_patterns_that_are_not_bare_are_allowed():
    assert len(compile_key_denylist(["(?i)api_key", "(?i)private_key", "secret_key"])) == 3
    assert compile_key_denylist(None) == ()


def test_value_and_key_rules_combine(registry):
    registry.add("FIXTURE-SECRET-abc123")
    out = redact_tree({"msg": "token is FIXTURE-SECRET-abc123", "token": "FIXTURE-SECRET-abc123"}, registry, ["token"])
    assert out["token"] == KEY_PLACEHOLDER
    assert PLACEHOLDER_RE.search(out["msg"]) and "FIXTURE" not in out["msg"]
