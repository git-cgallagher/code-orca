"""The reference workflow validates; each negative case fails for the right reason; the committed schema is current."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from codeorca.config import load_workflow
from codeorca.models import workflow_json_schema

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
