"""Structural masking from Terraform's sibling maps and the provider schema walk."""

from __future__ import annotations

from codeorca.redact import (
    SENSITIVE,
    UNKNOWN,
    mask_by_map,
    mask_by_schema,
    merge_unknown,
    schema_sensitive_paths,
    sensitive_leaves,
)

# ------------------------------------------------------------------------------------------- mask_by_map


def test_mask_by_map_handles_every_shape_terraform_emits():
    values = {
        "id": "abc",
        "password": "FIXTURE-SECRET-1",
        "tags": {"env": "dev", "token": "FIXTURE-SECRET-2"},
        "rules": [{"cidr": "10.0.0.0/8", "psk": "FIXTURE-SECRET-3"}, {"cidr": "10.1.0.0/16", "psk": "n/a"}],
        "empty_obj": {},
        "empty_list": [],
        "unset": None,
        "blob": {"user": "u", "pass": "FIXTURE-SECRET-4"},
    }
    smap = {
        "password": True,
        "tags": {"token": True},
        "rules": [{"psk": True}, {}],
        "empty_obj": {},
        "empty_list": [],
        "unset": True,
        "blob": True,
    }
    out = mask_by_map(values, smap)
    assert out == {
        "id": "abc",
        "password": SENSITIVE,
        "tags": {"env": "dev", "token": SENSITIVE},
        "rules": [{"cidr": "10.0.0.0/8", "psk": SENSITIVE}, {"cidr": "10.1.0.0/16", "psk": "n/a"}],
        "empty_obj": {},
        "empty_list": [],
        "unset": None,
        "blob": SENSITIVE,  # a sensitive object collapses: its key names are not shown either
    }
    assert values["password"] == "FIXTURE-SECRET-1"  # input untouched


def test_mask_by_map_with_the_flag_variants_terraform_uses_for_nothing_sensitive():
    v = {"a": "x", "l": [1, 2]}
    for smap in (False, None, {}, []):
        assert mask_by_map(v, smap) == v
    assert mask_by_map("hello", False) == "hello"
    assert mask_by_map(None, True) is None


def test_mask_by_map_whole_value_true_and_shape_mismatch_fail_closed():
    assert mask_by_map("FIXTURE-SECRET-x", True) == SENSITIVE
    assert mask_by_map(["a", "b"], True) == SENSITIVE
    assert mask_by_map(["a", "b"], [True, False]) == [SENSITIVE, "b"]
    assert mask_by_map(["a", "b", "c"], [True]) == [SENSITIVE, "b", "c"]
    # a non-empty map against a value of another shape: mask rather than guess
    assert mask_by_map("scalar", {"x": True}) == SENSITIVE
    assert mask_by_map({"x": "y"}, [True]) == SENSITIVE


def test_sensitive_leaves_yields_every_flagged_scalar_as_str():
    values = {
        "password": "FIXTURE-SECRET-1",
        "port": 5432,
        "tags": {"token": "FIXTURE-SECRET-2"},
        "blob": {"n": 7, "b": True, "x": None},
    }
    smap = {"password": True, "port": True, "tags": {"token": True}, "blob": True}
    assert sorted(sensitive_leaves(values, smap)) == ["5432", "7", "FIXTURE-SECRET-1", "FIXTURE-SECRET-2"]
    assert list(sensitive_leaves(values, False)) == []
    assert list(sensitive_leaves(["a", "b"], [False, True])) == ["b"]


def test_sensitive_leaves_from_the_plan_fixture(load_json):
    plan = load_json("plan.json")
    leaves: set[str] = set()
    for rc in plan["resource_changes"]:
        ch = rc["change"]
        leaves.update(sensitive_leaves(ch["after"], ch["after_sensitive"]))
    for oc in plan["output_changes"].values():
        leaves.update(sensitive_leaves(oc["after"], oc["after_sensitive"]))
    assert leaves == {"FIXTURE-SECRET-abc123"}


# ----------------------------------------------------------------------------------------- merge_unknown


def test_merge_unknown_adds_keys_that_after_omits_and_marks_present_ones():
    after = {"keepers": None, "length": 12, "input": {"plain": "hello"}}
    unknown = {"bcrypt_hash": True, "id": True, "input": {}, "output": True, "nested": {"deep": True}, "length": False}
    out = merge_unknown(after, unknown)
    assert out == {
        "keepers": None,
        "length": 12,
        "input": {"plain": "hello"},
        "bcrypt_hash": UNKNOWN,
        "id": UNKNOWN,
        "output": UNKNOWN,
        "nested": {"deep": UNKNOWN},
    }
    assert "id" not in after  # input untouched


def test_merge_unknown_lists_and_whole_values():
    assert merge_unknown(None, True) == UNKNOWN
    assert merge_unknown({"a": 1}, True) == UNKNOWN
    assert merge_unknown(["a", "b"], [False, True]) == ["a", UNKNOWN]
    assert merge_unknown(["a"], [False, True]) == ["a", UNKNOWN]  # unknown element not in `after`
    assert merge_unknown([{"x": 1}], [{"y": True}]) == [{"x": 1, "y": UNKNOWN}]
    assert merge_unknown(None, [True, {"y": True}]) == [UNKNOWN, {"y": UNKNOWN}]
    for flag in (False, None, {}, []):
        assert merge_unknown({"a": 1}, flag) == {"a": 1}
    assert merge_unknown(SENSITIVE, {"x": True}) == SENSITIVE  # merge runs before masking; a late call is a no-op


def test_merge_then_mask_over_the_plan_fixture(load_json):
    plan = load_json("plan.json")
    by_addr = {rc["address"]: rc["change"] for rc in plan["resource_changes"]}
    pw = by_addr["random_password.pw"]
    out = mask_by_map(merge_unknown(pw["after"], pw["after_unknown"]), pw["after_sensitive"])
    assert out["id"] == UNKNOWN and out["result"] == SENSITIVE and out["bcrypt_hash"] == SENSITIVE
    assert out["length"] == 12
    t = by_addr["terraform_data.t"]
    out = mask_by_map(merge_unknown(t["after"], t["after_unknown"]), t["after_sensitive"])
    assert out == {
        "input": {"plain": "hello", "pw": SENSITIVE},
        "triggers_replace": None,
        "id": UNKNOWN,
        "output": UNKNOWN,
    }


# ------------------------------------------------------------------------------------ provider schema


def test_schema_sensitive_paths_walks_attributes_nested_type_and_block_types(load_json):
    paths = schema_sensitive_paths(load_json("providers-schema.json"))
    assert paths == {
        ("random_password", ("result",)),
        ("random_password", ("bcrypt_hash",)),
        ("example_thing", ("password_wo",)),  # write_only
        ("example_thing", ("credentials", "secret")),  # nested_type
        ("example_thing", ("credentials", "tokens", "value")),  # nested_type inside nested_type
        ("example_thing", ("auth", "private_key")),  # block_types
        ("example_thing", ("auth", "header", "bearer")),  # block inside a block
        ("example_lookup", ("connection_string",)),  # data source
        ("example_token", ("token",)),  # ephemeral resource
        ("provider:registry.terraform.io/example/example", ("api_token",)),
    }


def test_schema_sensitive_paths_tolerates_unknown_kinds_and_shapes():
    assert schema_sensitive_paths({}) == set()
    weird = {
        "format_version": "1.0",
        "provider_schemas": {
            "p": {
                "functions": {"f": {"description": "no block here"}},
                "resource_identity_schemas": {"r": {"version": 0, "attributes": {}}},
                "future_schemas": {"x": {"block": {"attributes": {"s": {"type": "string", "sensitive": True}}}}},
                "resource_schemas": {"r": {"block": {"attributes": None, "block_types": None}}},
                "provider": {"block": {}},
            }
        },
    }
    assert schema_sensitive_paths(weird) == {("x", ("s",))}


def test_mask_by_schema_applies_paths_through_lists(load_json):
    paths = schema_sensitive_paths(load_json("providers-schema.json"))
    values = {
        "name": "thing",
        "password_wo": "FIXTURE-SECRET-wo",
        "password_wo_version": 1,
        "credentials": {
            "username": "u",
            "secret": "FIXTURE-SECRET-s",
            "tokens": [{"label": "a", "value": "FIXTURE-SECRET-t"}],
        },
        "auth": [
            {
                "method": "basic",
                "private_key": "FIXTURE-SECRET-k",
                "header": [{"name": "h", "bearer": "FIXTURE-SECRET-b"}],
            }
        ],
    }
    out = mask_by_schema(values, paths, "example_thing")
    assert out == {
        "name": "thing",
        "password_wo": SENSITIVE,
        "password_wo_version": 1,
        "credentials": {"username": "u", "secret": SENSITIVE, "tokens": [{"label": "a", "value": SENSITIVE}]},
        "auth": [{"method": "basic", "private_key": SENSITIVE, "header": [{"name": "h", "bearer": SENSITIVE}]}],
    }
    assert mask_by_schema(values, paths, "unknown_type") == values
    assert mask_by_schema(
        {"api_token": "x", "endpoint": "e"}, paths, "provider:registry.terraform.io/example/example"
    ) == {
        "api_token": SENSITIVE,
        "endpoint": "e",
    }
