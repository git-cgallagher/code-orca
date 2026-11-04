"""tfjson against the captured 1.14.7 fixtures: tolerant streams, plan summary, sensitivity flags, prior outputs."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codeorca import tfjson

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "terraform"
SECRET = "FIXTURE-SECRET-tf-input-001"


def load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def lines(name: str) -> list[str]:
    return (FIXTURES / name).read_text(encoding="utf-8").splitlines(keepends=True)


# ---------------------------------------------------------------- streams


def test_parse_json_stream_keeps_non_json_lines_and_drops_blanks():
    messages = tfjson.parse_json_stream(lines("init-mixed.jsonl"))
    logs = [m for m in messages if m.get("type") is None]
    assert logs[0] == {"@level": "log", "@message": "- Installing hashicorp/null v3.2.4..."}
    assert all(m["@level"] == "log" for m in logs)
    assert len(logs) == 6  # 8 non-JSON lines in the file, two of them blank or whitespace-only
    assert not any(m["@message"].strip() == "" for m in logs)
    assert any(
        m.get("type") == "init_output" and m.get("message_code") == "output_init_success_message" for m in messages
    )
    assert messages[-1]["@message"].startswith('you run "terraform init"')


def test_parse_json_stream_raw_init_capture_is_all_json():
    messages = tfjson.parse_json_stream(lines("init.jsonl"))
    assert messages and all("type" in m for m in messages)
    assert messages[0]["type"] == "version" and messages[0]["terraform"] == "1.17.1"


def test_parse_json_stream_accepts_a_string_and_non_object_json():
    messages = tfjson.parse_json_stream('{"a": 1}\n\n42\n"text"\n[1]\nplain\n')
    assert messages == [
        {"a": 1},
        {"@level": "log", "@message": "42"},
        {"@level": "log", "@message": '"text"'},
        {"@level": "log", "@message": "[1]"},
        {"@level": "log", "@message": "plain"},
    ]


def test_apply_stream_parses_and_sensitive_output_carries_no_value():
    messages = tfjson.parse_json_stream(lines("apply.jsonl"))
    assert tfjson.diagnostics(messages) == []
    summary = next(m for m in messages if m["type"] == "change_summary")
    assert summary["changes"]["add"] == 2 and summary["changes"]["remove"] == 0
    outputs = next(m for m in messages if m["type"] == "outputs")["outputs"]
    assert outputs["app_token"]["sensitive"] is True and "value" not in outputs["app_token"]
    assert SECRET not in (FIXTURES / "apply.jsonl").read_text(encoding="utf-8")  # 1.14.7 and 1.17.1 omit it (AGENTS.md gotcha)


def test_diagnostics_filters_by_level():
    messages = [{"@level": "info"}, {"@level": "error", "@message": "boom"}, {"@level": "warn"}]
    assert tfjson.diagnostics(messages) == [{"@level": "error", "@message": "boom"}]
    assert len(tfjson.diagnostics(messages, levels=("error", "warn"))) == 2


# ---------------------------------------------------------------- format versions


@pytest.mark.parametrize("version", ["1.0", "1.2", "1.99", 1, 1.0])
def test_supported_format_major_one(version):
    assert tfjson.is_supported_format(version)


@pytest.mark.parametrize("version", ["2.0", "0.1", "", None, "x.y", True, 2])
def test_unsupported_format(version):
    assert not tfjson.is_supported_format(version)


def test_fixture_format_versions():
    assert load("plan.json")["format_version"] == "1.2"  # the docs say 1.0; parse by major
    assert load("state.json")["format_version"] == "1.0"
    assert tfjson.is_supported_format(load("replace-plan.json")["format_version"])


# ---------------------------------------------------------------- plan summary


def test_plan_summary_create_plan():
    summary = tfjson.plan_summary(load("plan.json"))
    assert summary == {
        "applyable": True,
        "complete": True,
        "errored": False,
        "counts": {"add": 2, "change": 0, "remove": 0, "replace": 0},
        "replacements": [],
        "format_version": "1.2",
    }


def test_plan_summary_replace_plan_counts_replacement_once():
    summary = tfjson.plan_summary(load("replace-plan.json"))
    assert summary["counts"] == {"add": 0, "change": 0, "remove": 0, "replace": 1}
    assert summary["replacements"] == ["terraform_data.app"]
    assert summary["applyable"] and not summary["errored"]


def test_plan_summary_hand_crafted_delete_plan():
    summary = tfjson.plan_summary(load("delete-plan.json"))
    assert summary["counts"] == {"add": 0, "change": 1, "remove": 1, "replace": 2}
    assert summary["replacements"] == ["aws_instance.gateway", "terraform_data.app"]


def test_plan_summary_on_empty_document_is_fail_closed():
    assert tfjson.plan_summary({}) == {
        "applyable": False,
        "complete": False,
        "errored": False,
        "counts": {"add": 0, "change": 0, "remove": 0, "replace": 0},
        "replacements": [],
        "format_version": None,
    }


# ---------------------------------------------------------------- sensitivity


def test_sensitive_variables_come_from_configuration_not_the_variables_block():
    plan = load("plan.json")
    assert tfjson.sensitive_variables(plan) == ["app_secret"]
    # the values block carries the secret in plain text with no flag at all
    assert plan["variables"]["app_secret"] == {"value": SECRET}
    assert "sensitive" not in plan["variables"]["app_secret"]


def test_sensitive_outputs_from_every_place_the_plan_flags_them():
    assert tfjson.sensitive_outputs(load("plan.json")) == ["app_token"]
    assert tfjson.sensitive_outputs(load("replace-plan.json")) == ["app_token"]
    assert tfjson.sensitive_outputs(
        {"output_changes": {"x": {"after_sensitive": True}, "y": {"after_sensitive": False}}}
    ) == ["x"]


def test_prior_outputs_excludes_sensitive():
    prior = tfjson.prior_outputs(load("replace-plan.json"))
    assert set(prior) == {"app_bucket", "app_fqdn", "app_host"}
    assert prior["app_host"] == "127.0.0.1"
    assert "app_token" not in prior
    assert SECRET not in json.dumps(prior)
    assert tfjson.prior_outputs({}) == {} and tfjson.prior_outputs({"prior_state": {"values": {}}}) == {}


def test_prior_state_outputs_are_re_evaluated_on_1_14_7():
    """Documents the Terraform behaviour the renderer must not misread (see tfjson.prior_outputs)."""
    first = load("plan.json")
    assert first["prior_state"]["values"]["root_module"] == {}  # nothing existed yet...
    assert tfjson.prior_outputs(first)["app_fqdn"] == "app-dev.example.com"  # ...yet the outputs are listed
    assert tfjson.previous_outputs(first) == {}  # output_changes say every output is created: no previous value
    replace = load("replace-plan.json")
    assert tfjson.prior_outputs(replace)["app_fqdn"] == "app-prod.example.com"  # the NEW value
    assert tfjson.previous_outputs(replace)["app_fqdn"] == "app-dev.example.com"  # what the state recorded
    assert "app_token" not in tfjson.previous_outputs(replace)
    assert SECRET not in json.dumps(tfjson.previous_outputs(replace))


def test_state_outputs_from_state_and_output_documents():
    assert tfjson.state_outputs(load("state.json")) == {
        "app_bucket": "example-app-123456789012",
        "app_fqdn": "app-dev.example.com",
        "app_host": "127.0.0.1",
    }
    assert tfjson.state_outputs(load("outputs.json"))["app_host"] == "127.0.0.1"
    assert "app_token" not in tfjson.state_outputs(load("outputs.json"))
    assert tfjson.state_outputs(load("outputs.json"), include_sensitive=True)["app_token"] == SECRET
    assert tfjson.state_outputs({"format_version": "1.0"}) == {}
    # an `output -json` map whose outputs happen to be named like state-document keys is still an outputs map
    tricky = {
        "values": {"sensitive": False, "type": "string", "value": "v"},
        "format_version": {"sensitive": False, "type": "string", "value": "f"},
        "other": {"sensitive": True, "type": "string", "value": "s"},
    }
    assert tfjson.state_outputs(tricky) == {"values": "v", "format_version": "f"}
    assert tfjson.state_outputs({"format_version": "1.0", "values": {"root_module": {}}}) == {}


def test_fixtures_hold_the_placeholder_in_plain_text():
    """Documents what the adapter does NOT do: plan, state and output JSON carry secrets; redaction is downstream."""
    for name in ("plan.json", "replace-plan.json", "state.json", "outputs.json"):
        assert SECRET in (FIXTURES / name).read_text(encoding="utf-8"), name
