"""Deny floor: every forbidden argv raises naming its rule; allowed ones pass; YAML cannot widen the floor.

Plan gate: deletes of stateful or critical resources block, `allow_delete_of` waives an exact address, and a
replacement is reported but only blocked when stateful/critical.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from codeorca.policy import DENY_FLOOR, DenyRule, GateVerdict, Policy, PolicyError, check_argv, parse_argv, plan_gate

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "terraform"
POLICY = Policy(
    stateful_types=["aws_s3_bucket", "aws_dynamodb_table", "aws_kms_key"],
    transient_errors=["Error acquiring the state lock", "429"],
)


def load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


# ---------------------------------------------------------------- deny floor

FORBIDDEN = [
    (["terraform", "destroy"], "destroy"),
    (["terraform", "destroy", "-auto-approve"], "destroy"),
    (["terraform", "apply", "-destroy", "p.tfplan"], "apply-destroy"),
    (["terraform", "apply", "-destroy"], "apply-destroy"),
    (["terraform", "plan", "-destroy", "-out=p.tfplan"], "plan-destroy"),
    (["terraform", "state", "rm", "aws_s3_bucket.b"], "state-surgery"),
    (["terraform", "state", "mv", "a.b", "a.c"], "state-surgery"),
    (["terraform", "state", "push", "x.tfstate"], "state-surgery"),
    (["terraform", "state", "pull"], "state-surgery"),
    (["terraform", "state", "replace-provider", "a", "b"], "state-surgery"),
    (["terraform", "state"], "state-surgery"),
    (["terraform", "force-unlock", "-force", "LOCKID"], "force-unlock"),
    (["terraform", "workspace", "delete", "dev"], "workspace-delete"),
    (["terraform", "import", "aws_s3_bucket.b", "name"], "import"),
    (["terraform", "taint", "aws_s3_bucket.b"], "taint"),
    (["terraform", "untaint", "aws_s3_bucket.b"], "untaint"),
    (["terraform", "plan", "-target=aws_s3_bucket.b", "-out=p"], "target"),
    (["terraform", "plan", "-target", "aws_s3_bucket.b", "-out=p"], "target"),
    (["terraform", "apply", "-target=aws_s3_bucket.b", "p.tfplan"], "target"),
    (["terraform", "apply", "--target=x", "p.tfplan"], "target"),
    (["terraform", "apply", "-auto-approve", "p.tfplan"], "auto-approve"),
    (["terraform", "apply", "-auto-approve"], "auto-approve"),
    (["terraform", "apply"], "bare-apply"),
    (["terraform", "apply", "-no-color", "-input=false", "-json"], "bare-apply"),
    (["terraform", "apply", "-lock-timeout", "60s"], "bare-apply"),  # separate-token value is not a plan file
    (["terraform", "init", "-migrate-state"], "migrate-state"),
    (["terraform", "init", "-force-copy"], "migrate-state"),
    (["terraform", "init", "-migrate-state", "-force-copy"], "migrate-state"),
    (["/usr/local/bin/terraform", "-chdir=stack", "destroy"], "destroy"),
    (["tofu", "state", "rm", "x"], "state-surgery"),
]

ALLOWED = [
    ["terraform", "init", "-no-color", "-input=false", "-json"],
    ["terraform", "init", "-no-color", "-input=false", "-json", "-lockfile=readonly", "-reconfigure"],
    ["terraform", "init", "-backend-config=/tmp/backend.hcl"],
    ["terraform", "validate", "-no-color", "-json"],
    ["terraform", "plan", "-no-color", "-input=false", "-lock-timeout=60s", "-detailed-exitcode", "-out=p.tfplan"],
    ["terraform", "plan", "-lock=false", "-detailed-exitcode", "-out=p.tfplan", "-var-file=run.tfvars"],
    ["terraform", "plan", "-refresh-only", "-out=p.tfplan"],
    ["terraform", "show", "-no-color", "-json", "p.tfplan"],
    ["terraform", "show", "-no-color", "-json"],
    ["terraform", "apply", "-no-color", "-input=false", "-json", "p.tfplan"],
    ["terraform", "apply", "-lock-timeout=60s", "run/steps/apply/plan.tfplan"],
    ["terraform", "output", "-no-color", "-json"],
    ["terraform", "providers", "schema", "-no-color", "-json"],
    ["terraform", "providers", "lock"],
    ["terraform", "test", "-no-color", "-json"],
    ["terraform", "state", "list"],
    ["terraform", "state", "show", "terraform_data.app"],
    ["terraform", "workspace", "list"],
    ["terraform", "workspace", "show"],
    ["terraform", "fmt", "-check"],
    ["terraform", "version", "-json"],
]


@pytest.mark.parametrize(("argv", "rule"), FORBIDDEN, ids=[" ".join(a[1:]) for a, _ in FORBIDDEN])
def test_forbidden_argv_raises_naming_the_rule(argv: list[str], rule: str):
    with pytest.raises(PolicyError) as info:
        check_argv(argv)
    assert info.value.rule == rule
    assert str(info.value).startswith(f"{rule}: ")


@pytest.mark.parametrize("argv", ALLOWED, ids=[" ".join(a[1:]) for a in ALLOWED])
def test_allowed_argv_passes(argv: list[str]):
    parsed = check_argv(argv)
    assert parsed.engine == argv[0]


def test_migrate_state_only_through_the_explicit_exception():
    argv = ["terraform", "init", "-no-color", "-input=false", "-migrate-state", "-force-copy"]
    with pytest.raises(PolicyError):
        check_argv(argv)
    assert check_argv(argv, allow_migrate_state=True).subcommand == ("init",)
    # The exception is scoped to init: it never lets -migrate-state ride on anything else.
    with pytest.raises(PolicyError) as info:
        check_argv(["terraform", "apply", "-migrate-state", "p.tfplan"], allow_migrate_state=True)
    assert info.value.rule == "migrate-state"


def test_empty_argv_is_refused():
    with pytest.raises(PolicyError) as info:
        check_argv([])
    assert info.value.rule == "empty-argv"


def test_parse_argv_splits_compound_subcommands_flags_and_positionals():
    parsed = parse_argv(["terraform", "-chdir=s", "state", "show", "-no-color", "-state", "x.tfstate", "a.b"])
    assert parsed.global_flags == ("chdir",)
    assert parsed.subcommand == ("state", "show")
    assert parsed.flags == ("no-color", "state")
    assert parsed.positionals == ("a.b",)


def test_floor_is_immutable_and_complete():
    assert isinstance(DENY_FLOOR, tuple)
    assert all(isinstance(r, DenyRule) for r in DENY_FLOOR)
    with pytest.raises(AttributeError):
        DENY_FLOOR[0].name = "renamed"  # type: ignore[misc]
    names = {r.name for r in DENY_FLOOR}
    assert names >= {
        "destroy",
        "apply-destroy",
        "plan-destroy",
        "state-surgery",
        "force-unlock",
        "workspace-delete",
        "import",
        "taint",
        "untaint",
        "target",
        "auto-approve",
        "bare-apply",
        "migrate-state",
    }


@pytest.mark.parametrize(
    "widening",
    [
        {"deny_floor": []},
        {"allow": ["destroy"]},
        {"allowed_subcommands": ["destroy"]},
        {"permit_target": True},
        {"stateful_types": ["aws_s3_bucket"], "auto_approve": True},
    ],
)
def test_yaml_policy_cannot_widen_the_floor(widening: dict):
    """A project-file policy has no field that reaches the floor; unknown keys are rejected outright."""
    with pytest.raises(ValidationError):
        Policy.model_validate(widening)
    # And even a permissive-looking Policy changes nothing: check_argv takes no policy at all.
    with pytest.raises(PolicyError):
        check_argv(["terraform", "destroy"])


def test_policy_defaults():
    policy = Policy()
    assert policy.stateful_types == [] and policy.transient_errors == []
    assert policy.critical_tag_pair() == ("critical", "true")
    assert Policy(critical_tag="Tier=gold").critical_tag_pair() == ("Tier", "gold")


# ---------------------------------------------------------------- plan gate


def test_gate_blocks_delete_of_stateful_type():
    verdict = plan_gate(load("delete-plan.json"), POLICY)
    assert isinstance(verdict, GateVerdict) and not verdict.passed
    by_address = {b.address: b for b in verdict.blocked}
    assert by_address["aws_s3_bucket.state"].actions == ["delete"]
    assert "stateful type aws_s3_bucket" in by_address["aws_s3_bucket.state"].reason
    assert verdict.model_dump()["blocked"][0].keys() == {"address", "actions", "reason"}


def test_gate_blocks_replacement_of_critical_tagged_resource():
    verdict = plan_gate(load("delete-plan.json"), POLICY)
    by_address = {b.address: b for b in verdict.blocked}
    assert by_address["aws_instance.gateway"].actions == ["delete", "create"]
    assert "tagged critical=true" in by_address["aws_instance.gateway"].reason
    # the update of a stateful aws_ssm_parameter is not a delete, and is not in the policy's list anyway
    assert "aws_ssm_parameter.setting" not in by_address


def test_gate_reports_replacements_without_blocking_non_stateful_ones():
    verdict = plan_gate(load("delete-plan.json"), POLICY)
    assert verdict.replacements == ["aws_instance.gateway", "terraform_data.app"]
    assert "terraform_data.app" not in {b.address for b in verdict.blocked}


def test_gate_allow_delete_of_waives_exact_addresses_only():
    plan = load("delete-plan.json")
    partial = plan_gate(plan, POLICY, allow_delete_of=["aws_s3_bucket.state"])
    assert not partial.passed and [b.address for b in partial.blocked] == ["aws_instance.gateway"]
    full = plan_gate(plan, POLICY, allow_delete_of=["aws_s3_bucket.state", "aws_instance.gateway"])
    assert full.passed and full.blocked == [] and full.replacements == ["aws_instance.gateway", "terraform_data.app"]
    # a prefix or a different index is not the same address
    other = plan_gate(plan, POLICY, allow_delete_of=["aws_s3_bucket", "aws_s3_bucket.state[0]"])
    assert "aws_s3_bucket.state" in {b.address for b in other.blocked}


def test_gate_critical_tag_is_read_from_prior_tags_when_after_is_null():
    plan = {
        "resource_changes": [
            {
                "address": "aws_instance.old",
                "type": "aws_instance",
                "change": {"actions": ["delete"], "before": {"tags_all": {"critical": "true"}}, "after": None},
            }
        ]
    }
    verdict = plan_gate(plan, Policy())
    assert not verdict.passed and verdict.blocked[0].reason == "tagged critical=true"


def test_gate_passes_real_create_and_replace_plans():
    assert plan_gate(load("plan.json"), POLICY).passed
    replace = plan_gate(load("replace-plan.json"), POLICY)
    assert replace.passed and replace.replacements == ["terraform_data.app"]
    # narrowing: declaring terraform_data stateful turns the same replacement into a block
    narrowed = Policy(stateful_types=["terraform_data"])
    assert [b.address for b in plan_gate(load("replace-plan.json"), narrowed).blocked] == ["terraform_data.app"]


def test_gate_tolerates_missing_or_null_sections():
    assert plan_gate({}, POLICY).passed
    assert plan_gate({"resource_changes": None}, POLICY).passed
    assert plan_gate({"resource_changes": [{"address": "x", "change": None}]}, POLICY).passed
