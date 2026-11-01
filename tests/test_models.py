"""The reference workflow validates; each negative case fails for the right reason; the committed schema is current."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from codeorca.config import load_workflow
from codeorca.models import Workflow, workflow_json_schema

ROOT = Path(__file__).resolve().parent.parent
REFERENCE = ROOT / "examples" / "reference" / "workflows" / "demo-rollout.yaml"
NEGATIVE = ROOT / "tests" / "negative"


def test_reference_workflow_validates():
    wf = load_workflow(REFERENCE)
    assert wf.name == "demo-rollout"
    assert len(wf.steps) == 8 and len(wf.finally_) == 1
    order = wf.order()
    assert order.index("plan_app") < order.index("approve") < order.index("apply_app") < order.index("configure")


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("undeclared-output.yaml", "declares no output 'prior'"),
        ("destroy.yaml", "Input should be 'plan', 'apply', 'output', 'validate', 'test' or 'migrate_backend'"),
        ("cycle.yaml", "dependency cycle"),
        ("yaml11-on-key.yaml", "retry.on"),
    ],
)
def test_negative_cases_fail(case: str, message: str):
    with pytest.raises(ValidationError) as info:
        load_workflow(NEGATIVE / case)
    assert message in str(info.value)


def test_committed_schema_matches_models():
    committed = json.loads((ROOT / "schema" / "codeorca-workflow.schema.json").read_text(encoding="utf-8"))
    assert committed == workflow_json_schema()


BASE = {"api": "codeorca/v1", "kind": "workflow", "name": "t"}
STEP = {"type": "shell", "run": ["true"]}


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ({"steps": [{"id": "a", **STEP}, {"id": "a", **STEP}]}, "duplicate step id 'a'"),
        ({"steps": [{"id": "a", **STEP}], "finally": [{"id": "a", **STEP}]}, "duplicate step id 'a'"),
        ({"steps": [{"id": "a", **STEP, "needs": ["nope"]}]}, "a: needs unknown step nope"),
        ({"steps": [{"id": "a", **STEP}], "finally": [{"id": "f", **STEP, "needs": ["a"]}]}, "finally step f: needs"),
        (
            {"steps": [{"id": "a", **STEP, "retry": {"limit": 1}, "on_failure": "continue"}]},
            "retry and on_failure: continue cannot be combined",
        ),
        ({"steps": [{"id": "a", **STEP, "run": ["${{ steps.zz.outputs.x }}"]}]}, "a: references unknown step zz"),
        (
            {
                "steps": [
                    {"id": "a", **STEP, "outputs": {"x": "1"}},
                    {"id": "b", **STEP, "run": ["${{ steps.a.outputs.x }}"]},
                ]
            },
            "b: references a.outputs.x but does not (transitively) need a",
        ),
        ({"steps": [{"id": "a", **STEP, "shell": "bash"}]}, "Extra inputs are not permitted"),
        ({"steps": [{"id": "a", **STEP}], "bogus": 1}, "Extra inputs are not permitted"),
        ({"steps": [{"id": "a", **STEP, "retry": {"limit": 1, "backoff": {"duration": "5 seconds"}}}]}, "duration"),
        ({"steps": [{"id": "a", **STEP, "retry": {"limit": 1, "backoff": {"duration": "1.5s"}}}]}, "duration"),
        ({"steps": [{"id": "a", **STEP, "retry": {"limit": 1, "backoff": {"jitter": 1}}}]}, "Extra inputs"),
        (
            {
                "steps": [
                    {"id": "a", "type": "spec-render", "source": {"terraform_plan": "x"}, "output": "specs/plan.yaml"},
                    {"id": "b", "type": "spec-render", "source": {"terraform_plan": "y"}, "output": "specs/plan.yaml"},
                ]
            },
            "spec-render output 'specs/plan.yaml' is written by steps a and b",
        ),
    ],
)
def test_model_rules_reject_with_field_precise_messages(data: dict, message: str):
    with pytest.raises(ValidationError) as info:
        Workflow.model_validate({**BASE, **data})
    assert message in str(info.value)


def test_backoff_accepts_durations_and_numbers():
    wf = Workflow.model_validate(
        {
            **BASE,
            "steps": [{"id": "a", **STEP, "retry": {"limit": 1, "backoff": {"duration": "1s", "max_duration": 2}}}],
        }
    )
    assert wf.steps[0].retry.backoff.duration == "1s" and wf.steps[0].retry.backoff.max_duration == 2.0
    assert wf.steps[0].retry.backoff.factor == 1.0
