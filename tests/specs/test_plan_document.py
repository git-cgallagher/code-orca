"""The Terraform plan document and the YAML spec writer, over the 1.14.7 fixtures (no terraform binary)."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from codeorca.policy import Policy, plan_gate
from codeorca.redact import KEY_PLACEHOLDER, PLACEHOLDER_RE, SecretRegistry, scan_outputs
from codeorca.specs import (
    META_KEY,
    NEVER_RENDERED,
    SpecGateError,
    build_header,
    meta_path,
    render_spec_yaml,
    write_spec,
)
from codeorca.specs.terraform_plan import (
    build_plan_document,
    gate_word,
    header_for,
    mask_with_placeholders,
    provenance,
    redact_values,
    seed_registry,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "terraform"
REDACT_FIXTURES = Path(__file__).resolve().parents[1] / "redact" / "fixtures"
SECRET = "FIXTURE-SECRET-tf-input-001"
DENYLIST = ["(?i)password", "(?i)secret", "(?i)token"]


def load(name: str, root: Path = FIXTURES) -> dict:
    return json.loads((root / name).read_text(encoding="utf-8"))


@pytest.fixture
def registry() -> SecretRegistry:
    return SecretRegistry(b"example-not-secret-key", "env:abcd1234")


def build(plan: dict, registry: SecretRegistry, **kw) -> dict:
    seed_registry(registry, plan)
    kw.setdefault("providers_schema", load("providers_schema.json"))
    kw.setdefault("policy_verdict", plan_gate(plan, Policy()))
    kw.setdefault("key_denylist", DENYLIST)
    kw.setdefault("exit_code", 2)
    return build_plan_document(plan, registry=registry, stack="app", **kw)


def by_address(doc: dict, address: str) -> dict:
    return next(e for e in doc["resource_changes"] if e["address"] == address)


# ------------------------------------------------------------------------------------------------- seeding + masking


def test_first_plan_seeds_the_sensitive_input_and_masks_it_everywhere(registry):
    plan = load("plan.json")
    assert SECRET in json.dumps(plan)  # the fixture is raw on purpose
    doc = build(plan, registry, never_render={"outputs": ["app_token"], "resources": []})
    dumped = json.dumps(doc)
    assert SECRET not in dumped
    assert doc["variables"] == {"app_secret": {"sensitive": True}, "environment": {"sensitive": False, "value": "dev"}}
    app = by_address(doc, "terraform_data.app")
    expected = registry.placeholder(SECRET)
    # map-flagged leaf -> stable placeholder (not "(sensitive)", not "<redacted:key>" although `secret` is denylisted)
    assert app["after"]["input"] == {"name": "example-app-dev", "secret": expected}
    assert app["after"]["id"] == "(known after apply)" and app["after"]["output"] == "(known after apply)"
    assert app["before"] is None and app["actions"] == ["create"] and app["replace_paths"] == []
    assert app["provenance"] == {"input": "<- local.app_name, var.app_secret", "triggers_replace": "<- var.environment"}
    assert by_address(doc, "terraform_data.app_secret")["after"]["input"] == expected
    assert doc["output_changes"]["app_token"] == {"actions": ["create"], "rendered": NEVER_RENDERED}
    assert doc["output_changes"]["app_fqdn"]["provenance"] == "<- var.environment"
    assert doc["summary"]["counts"] == {"add": 2, "change": 0, "remove": 0, "replace": 0}
    assert doc["summary"]["exit_code"] == 2 and doc["summary"]["gate"]["passed"] is True
    assert doc["never_rendered"] == {"outputs": ["app_token"], "resources": []}
    assert doc["engine"] == {"name": "terraform", "version": "1.14.7"}
    assert "timestamp" not in dumped


def test_sensitive_output_shows_its_placeholder_when_not_never_rendered(registry):
    doc = build(load("plan.json"), registry)
    token = doc["output_changes"]["app_token"]
    assert token["sensitive"] is True and token["value"] == registry.placeholder(SECRET)


def test_replace_plan_carries_previous_value_replace_paths_and_action_reason(registry):
    doc = build(load("replace-plan.json"), registry)
    app = by_address(doc, "terraform_data.app")
    assert app["actions"] == ["delete", "create"] and app["action_reason"] == "replace_because_cannot_update"
    assert app["replace_paths"] == [["triggers_replace"]]
    assert app["before"]["input"]["secret"] == registry.placeholder(SECRET)
    # the echoed `output` attribute carries no sensitivity flag: only the value scrub catches it
    assert app["before"]["output"]["secret"] == registry.placeholder(SECRET)
    fqdn = doc["output_changes"]["app_fqdn"]
    assert fqdn["actions"] == ["update"] and fqdn["previous"] == "app-dev.example.com"
    assert fqdn["value"] == "app-prod.example.com"
    assert "previous" not in doc["output_changes"]["app_host"]
    assert doc["summary"]["replacements"] == ["terraform_data.app"]
    assert SECRET not in json.dumps(doc)


def test_delete_plan_gate_verdict_and_never_render_resources(registry):
    plan = load("delete-plan.json")
    verdict = plan_gate(plan, Policy(stateful_types=["aws_s3_bucket", "aws_ssm_parameter"]))
    doc = build(
        plan,
        registry,
        policy_verdict=verdict,
        never_render={"outputs": [], "resources": ["aws_ssm_parameter.*"]},
        exit_code=2,
    )
    assert doc["summary"]["gate"]["passed"] is False
    # the stateful bucket and the critical-tagged instance are blocked; the plain replacement is not
    assert [b["address"] for b in doc["summary"]["gate"]["blocked"]] == ["aws_s3_bucket.state", "aws_instance.gateway"]
    assert gate_word(doc) == "blocked"
    setting = by_address(doc, "aws_ssm_parameter.setting")
    assert setting["rendered"] == NEVER_RENDERED and "before" not in setting and "after" not in setting
    assert by_address(doc, "aws_instance.gateway")["after"]["tags"] == {"Name": "gateway", "critical": "true"}


def test_masking_order_unknown_then_map_then_schema_then_denylist(registry):
    schema = load("providers-schema.json", REDACT_FIXTURES)
    plan = {
        "format_version": "1.2",
        "resource_changes": [
            {
                "address": "random_password.pw",
                "type": "random_password",
                "mode": "managed",
                "change": {
                    "actions": ["create"],
                    "before": None,
                    "after": {
                        "length": 12,
                        "result": "FIXTURE-SECRET-unflagged-result",
                        "api_token": "plain-value-1234",
                    },
                    "after_sensitive": {},  # Terraform forgot: the schema says result is sensitive
                    "after_unknown": {"id": True, "bcrypt_hash": True},
                    "before_sensitive": False,
                },
            },
            {
                "address": "terraform_data.t",
                "type": "terraform_data",
                "mode": "managed",
                "change": {
                    "actions": ["update"],
                    "before": {"input": {"pw": "FIXTURE-SECRET-before-1", "plain": "hello"}},
                    "before_sensitive": {"input": {"pw": True}},
                    "after": {"input": {"pw": "FIXTURE-SECRET-after-2", "plain": "hello"}},
                    "after_sensitive": {"input": {"pw": True}},
                    "after_unknown": {"output": True},
                },
            },
        ],
        "resource_drift": [
            {
                "address": "terraform_data.t",
                "type": "terraform_data",
                "mode": "managed",
                "change": {
                    "actions": ["update"],
                    "before": {"input": {"pw": "FIXTURE-SECRET-before-1", "plain": "hello"}},
                    "before_sensitive": {"input": {"pw": True}},
                    "after": {"input": {"pw": "FIXTURE-SECRET-before-1", "plain": "drifted"}},
                    "after_sensitive": {"input": {"pw": True}},
                    "after_unknown": {},
                },
            }
        ],
        "configuration": {"root_module": {}},
    }
    doc = build(plan, registry, providers_schema=schema)
    pw = by_address(doc, "random_password.pw")
    assert pw["after"]["id"] == "(known after apply)"
    assert (
        pw["after"]["bcrypt_hash"] == "(sensitive)"
    )  # unknown AND schema-sensitive: the schema mask wins (fail closed)
    assert pw["after"]["result"] == "(sensitive)"  # schema path, no map
    assert pw["after"]["api_token"] == KEY_PLACEHOLDER  # denylisted key over a plain value
    assert pw["after"]["length"] == 12
    t = by_address(doc, "terraform_data.t")
    assert t["before"]["input"]["pw"] == registry.placeholder("FIXTURE-SECRET-before-1")
    assert t["after"]["input"]["pw"] == registry.placeholder("FIXTURE-SECRET-after-2")
    assert t["after"]["input"]["pw"] != t["before"]["input"]["pw"]  # the diff shows a secret CHANGED
    assert t["after"]["output"] == "(known after apply)" and t["after"]["input"]["plain"] == "hello"
    assert doc["drift"][0]["after"]["input"] == {
        "pw": registry.placeholder("FIXTURE-SECRET-before-1"),
        "plain": "drifted",
    }
    assert "FIXTURE-SECRET" not in json.dumps(doc).replace("FIXTURE-SECRET-unflagged-result", "")
    # the unflagged, unregistered schema-masked value never reached the document either
    assert "FIXTURE-SECRET-unflagged-result" not in json.dumps(doc)


def test_sensitive_variable_values_and_defaults_are_dropped_not_masked(registry):
    plan = load("plan.json", REDACT_FIXTURES)  # db_password sensitive with a default; eph_token ephemeral
    doc = build(plan, registry)
    assert doc["variables"]["db_password"] == {"sensitive": True}
    assert "FIXTURE-SECRET-abc123" not in json.dumps(doc)
    # a non-sensitive variable whose name matches the denylist is key-redacted, not shown
    assert doc["variables"]["eph_token"] == {"sensitive": False, "value": KEY_PLACEHOLDER}
    assert "FIXTURE-EPHEMERAL-xyz" not in json.dumps(doc)


def test_mask_with_placeholders_and_redact_values_helpers(registry):
    registry.add("FIXTURE-SECRET-leaf-1")
    masked = mask_with_placeholders(
        {"a": "FIXTURE-SECRET-leaf-1", "obj": {"k": "v"}, "n": None, "l": ["x", "y"]},
        {"a": True, "obj": True, "n": True, "l": [False, True]},
        registry,
    )
    assert masked["a"] == registry.placeholder("FIXTURE-SECRET-leaf-1")
    assert masked["obj"] == registry.placeholder('{"k": "v"}') and masked["n"] is None
    assert masked["l"] == ["x", registry.placeholder("y")]
    out = redact_values(
        {"password": masked["a"], "token": "plain-value-1234", "x": "FIXTURE-SECRET-leaf-1"}, registry, DENYLIST
    )
    assert out == {"password": masked["a"], "token": KEY_PLACEHOLDER, "x": masked["a"]}


def test_provenance_walks_nested_blocks_and_module_calls(registry):
    assert provenance(
        {"tags": {"Name": {"references": ["var.name"]}}, "ingress": [{"cidr": {"references": ["local.c"]}}]}
    ) == {
        "ingress.cidr": "<- local.c",
        "tags.Name": "<- var.name",
    }
    plan = copy.deepcopy(load("plan.json"))
    root = plan["configuration"]["root_module"]
    plan["configuration"]["root_module"] = {
        "module_calls": {"m": {"module": root}},
        "variables": root["variables"],
        "outputs": root["outputs"],
    }
    for rc in plan["resource_changes"]:
        rc["address"] = "module.m." + rc["address"] + '["a"]'
    doc = build(plan, registry)
    assert (
        by_address(doc, 'module.m.terraform_data.app["a"]')["provenance"]["input"]
        == "<- local.app_name, var.app_secret"
    )


# ----------------------------------------------------------------------------------------------- yaml rendering


def test_render_is_deterministic_header_first_and_body_free_of_run_metadata(registry):
    doc = build(load("plan.json"), registry)
    doc[META_KEY] = {"run_id": "20260101T000000Z-abcdef", "plan_sha256": "f" * 64}
    header = header_for(doc, registry.key_id, "abc123", workflow="plan-only", backend_key="example/app.tfstate")
    text = render_spec_yaml(doc, header)
    assert text == render_spec_yaml(dict(reversed(list(doc.items()))), header)  # key order on input is irrelevant
    assert text.startswith("codeorca:\n  pipeline: codeorca/")
    for key in ("kind", "workflow", "stack", "backend_key", "engine", "git_sha", "redaction_key", "gate"):
        assert f"\n  {key}: " in text.split("\ndrift:")[0]
    assert "run_id" not in text and "20260101" not in text and "plan_sha256" not in text and "generated_at" not in text
    assert "redaction_key: env:abcd1234" in text and "gate: pass" in text
    assert PLACEHOLDER_RE.search(text) and SECRET not in text
    assert (
        build_header(stack="s", engine="terraform/1.14.7", gate="pass", redaction_key="k", git_sha=None)["stack"] == "s"
    )


def test_write_spec_sidecar_and_gate(tmp_path, registry):
    doc = build(load("plan.json"), registry)
    doc[META_KEY] = {"run_id": "20260101T000000Z-abcdef", "plan_sha256": "f" * 64, "registry_size": registry.size}
    header = header_for(doc, registry.key_id, None)
    spec, sidecar = write_spec(
        tmp_path / "specs" / "app" / "plan.yaml", doc, header, {"durations_s": {"plan": 0.1}}, registry
    )
    assert spec.exists() and sidecar == meta_path(spec) and sidecar.name == "plan.meta.yaml"
    side = sidecar.read_text(encoding="utf-8")
    assert "run_id: 20260101T000000Z-abcdef" in side and "generated_at:" in side and "entropy_warnings: 0" in side
    assert "plan_sha256: " + "f" * 64 in side and "durations_s:" in side
    assert scan_outputs(tmp_path, registry) == []
    # the gate: a leaked value in the document removes both files and raises
    leaked = dict(doc)
    leaked["summary"] = dict(doc["summary"], note=SECRET)
    with pytest.raises(SpecGateError) as e:
        write_spec(tmp_path / "specs" / "app" / "plan.yaml", leaked, header, None, registry)
    assert SECRET not in str(e.value)
    assert not spec.exists() and not sidecar.exists()


def test_seed_registry_also_registers_denylist_named_variables(registry):
    """A variable the stack forgot to flag but whose NAME the project denylists is a secret: the document hides
    it under ``variables`` and an attribute that echoes the value must not show it either."""
    plan = load("plan.json", REDACT_FIXTURES)  # eph_token: not sensitive, matches (?i)token
    plan["resource_changes"].append(
        {
            "address": "terraform_data.echo",
            "type": "terraform_data",
            "mode": "managed",
            "change": {
                "actions": ["create"],
                "before": None,
                "after": {"input": "FIXTURE-EPHEMERAL-xyz", "plain": "x"},
                "after_sensitive": {},
                "after_unknown": {"id": True, "output": True},
            },
        }
    )
    grown = seed_registry(registry, plan, DENYLIST)
    assert grown >= 1 and "FIXTURE-EPHEMERAL-xyz" not in registry.redact("FIXTURE-EPHEMERAL-xyz")
    doc = build_plan_document(plan, load("providers_schema.json"), registry, "app", None, DENYLIST)
    echo = by_address(doc, "terraform_data.echo")
    assert echo["after"]["input"] == registry.placeholder("FIXTURE-EPHEMERAL-xyz")
    # registered, so the variable shows the stable placeholder (a diff shows it changed) instead of <redacted:key>
    assert doc["variables"]["eph_token"]["value"] == registry.placeholder("FIXTURE-EPHEMERAL-xyz")
    assert "FIXTURE-EPHEMERAL-xyz" not in json.dumps(doc)
