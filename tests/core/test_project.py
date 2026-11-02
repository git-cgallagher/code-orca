"""The project-file model: the reference file validates; each rule fails for its named reason."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest
from pydantic import ValidationError

from codeorca.config import load_yaml
from codeorca.project import Project, load_project, project_json_schema

ROOT = Path(__file__).resolve().parent.parent.parent
REFERENCE = ROOT / "examples" / "reference" / "codeorca.yaml"


@pytest.fixture
def reference() -> dict:
    return load_yaml(REFERENCE)


def test_reference_project_validates():
    project = load_project(REFERENCE)
    assert project.project == "example"
    assert project.backend.type == "local"
    assert project.max_parallel == 1
    assert project.stack_order() == ("app",)
    assert project.stacks["app"].never_render.outputs == ["app_token"]
    assert project.root == REFERENCE.parent
    assert project.gate.max_age == "24h"


def test_s3_backend_requires_bucket_region_account(reference):
    data = copy.deepcopy(reference)
    data["backend"] = {"type": "s3", "region": "us-east-1", "account_id": "123456789012"}
    with pytest.raises(ValidationError, match="backend type s3 requires bucket"):
        Project.model_validate(data)
    data["backend"] = {"type": "s3", "bucket": "b", "region": "us-east-1", "account_id": "123456789012"}
    assert Project.model_validate(data).backend.bucket == "b"


def test_account_id_must_be_a_quoted_twelve_digit_string(reference):
    data = copy.deepcopy(reference)
    data["backend"] = {"type": "s3", "bucket": "b", "region": "r", "account_id": 123456789012}
    with pytest.raises(ValidationError, match="account_id"):
        Project.model_validate(data)


def test_local_backend_requires_nothing(reference):
    data = copy.deepcopy(reference)
    data["backend"] = {"type": "local"}
    assert Project.model_validate(data).backend.type == "local"


def test_depends_on_cycle_fails(reference):
    data = copy.deepcopy(reference)
    net = copy.deepcopy(data["stacks"]["app"])
    data["stacks"]["network"] = net
    data["stacks"]["app"]["depends_on"] = ["network"]
    data["stacks"]["network"]["depends_on"] = ["app"]
    with pytest.raises(ValidationError, match="dependency cycle"):
        Project.model_validate(data)


def test_depends_on_unknown_stack_fails(reference):
    data = copy.deepcopy(reference)
    data["stacks"]["app"]["depends_on"] = ["ghost"]
    with pytest.raises(ValidationError, match="depends_on unknown stack 'ghost'"):
        Project.model_validate(data)


def test_stack_order_follows_depends_on(reference):
    data = copy.deepcopy(reference)
    data["stacks"]["network"] = copy.deepcopy(data["stacks"]["app"])
    data["stacks"]["app"]["depends_on"] = ["network"]
    assert Project.model_validate(data).stack_order() == ("network", "app")


def test_max_parallel_two_fails(reference):
    data = copy.deepcopy(reference)
    data["max_parallel"] = 2
    with pytest.raises(ValidationError, match="max_parallel must be 1"):
        Project.model_validate(data)


def test_unknown_key_fails(reference):
    data = copy.deepcopy(reference)
    data["stacks"]["app"]["workspace"] = "prod"
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        Project.model_validate(data)


def test_stack_secret_must_be_an_ssm_reference(reference):
    data = copy.deepcopy(reference)
    data["stacks"]["app"]["secrets"] = {"EXAMPLE_API_TOKEN": "FIXTURE-SECRET-literal-value"}
    with pytest.raises(ValidationError, match="ssm:/"):
        Project.model_validate(data)
    data["stacks"]["app"]["secrets"] = {"EXAMPLE_API_TOKEN": "ssm:/example/app/api-token"}
    assert Project.model_validate(data).stacks["app"].secrets["EXAMPLE_API_TOKEN"].startswith("ssm:/")


def test_hmac_placeholder_requires_key(reference):
    data = copy.deepcopy(reference)
    del data["redaction"]["hmac_key"]
    with pytest.raises(ValidationError, match="hmac requires hmac_key"):
        Project.model_validate(data)
    data["redaction"]["placeholder"] = "sha256"
    assert Project.model_validate(data).redaction.placeholder == "sha256"


def test_project_schema_is_draft_2020_12():
    schema = project_json_schema()
    assert schema["$schema"].endswith("2020-12/schema")
    assert schema["additionalProperties"] is False
    assert "stacks" in schema["properties"]


@pytest.mark.parametrize("tag", ["critical", "=true", "critical=", ""])
def test_critical_tag_must_be_key_equals_value(reference, tag):
    data = copy.deepcopy(reference)
    data["policy"]["critical_tag"] = tag
    with pytest.raises(ValidationError, match="critical_tag"):
        Project.model_validate(data)


def test_project_ansible_env_may_not_set_forced_names():
    from codeorca.project import AnsibleConfig

    # forced by the adapter anyway: refusing beats silently overriding the consumer's setting
    for name in ("ANSIBLE_DEBUG", "ANSIBLE_LOG_PATH", "ANSIBLE_CALLBACKS_ENABLED", "CODEORCA_REDACTION_KEY"):
        with pytest.raises(ValueError, match=name):
            AnsibleConfig(env={name: "x"})
    assert AnsibleConfig(env={"ANSIBLE_NOCOLOR": "1"}).env == {"ANSIBLE_NOCOLOR": "1"}
