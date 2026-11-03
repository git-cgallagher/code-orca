"""Model rules for gates and the apply-side Terraform actions, one negative test each."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from codeorca.models import Workflow


def wf(steps: list[dict]) -> Workflow:
    return Workflow.model_validate({"api": "codeorca/v1", "kind": "workflow", "name": "t", "steps": steps})


def gate(**kw) -> dict:
    return {"id": "approve", "type": "gate", "message": "m", **kw}


def test_gate_fields_are_typed_and_referenceable_as_outputs():
    w = wf(
        [
            gate(fields={"ticket": {"type": "string", "required": True}, "count": {"type": "int", "default": 1}}),
            {"id": "b", "type": "shell", "needs": ["approve"], "run": ["${{ steps.approve.outputs.ticket }}"]},
        ]
    )
    assert w.steps[0].fields["count"].default == 1


def test_an_undeclared_gate_field_reference_fails():
    with pytest.raises(ValidationError, match="declares no output 'ticket'"):
        wf([gate(), {"id": "b", "type": "shell", "needs": ["approve"], "run": ["${{ steps.approve.outputs.ticket }}"]}])


@pytest.mark.parametrize(
    ("fields", "match"),
    [
        ({"t": {"type": "float"}}, "string"),
        ({"t": {"type": "int", "default": "3"}}, "is not a int"),
        ({"t": {"type": "bool", "default": 1}}, "is not a bool"),
        ({"t": {"type": "string", "secret": True}}, "Extra inputs"),
        ({"approved": {"type": "bool"}}, "implicit gate outputs"),
        ({"bad-name": {"type": "string"}}, "pattern"),
    ],
)
def test_bad_gate_fields_are_refused(fields, match):
    with pytest.raises(ValidationError, match=match):
        wf([gate(fields=fields)])


def test_a_gate_cannot_continue_on_failure():
    with pytest.raises(ValidationError, match="rejection must block"):
        wf([gate(on_failure="continue")])


@pytest.mark.parametrize("action", ["apply", "migrate_backend"])
def test_apply_and_migrate_take_no_var_overrides(action):
    step = {"id": "a", "type": "terraform", "stack": "app", "action": action, "var_overrides": {"x": 1}}
    if action == "apply":
        step["plan_file"] = "p.tfplan"
    with pytest.raises(ValidationError, match="takes no var_overrides"):
        wf([step])
