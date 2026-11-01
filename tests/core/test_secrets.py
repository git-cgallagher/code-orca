"""Run-wide redaction wiring: registry builder (env key, env seeding, fail-closed), the runner's line hook and
record filter, the Terraform stream callback."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

from codeorca.models import Workflow
from codeorca.project import load_project
from codeorca.redact import PLACEHOLDER_RE, SecretRegistry
from codeorca.rundir import RunDir
from codeorca.runner import Runner
from codeorca.secrets import (
    KEY_ENV_VAR,
    RedactionKeyMissing,
    build_registry,
    env_secret_names,
    key_denylist,
    line_hook,
    record_filter,
    seed_inputs,
    terraform_stream,
)
from codeorca.steps import default_executors

ROOT = Path(__file__).resolve().parents[2]
PROJECT = load_project(ROOT / "examples" / "reference" / "codeorca.yaml")
KEY = "example-not-secret-key-value"
SECRET = "FIXTURE-SECRET-env-token-001"


def test_hmac_mode_without_the_env_key_fails_closed_naming_the_variable():
    with pytest.raises(RedactionKeyMissing) as e:
        build_registry(PROJECT, {})
    assert KEY_ENV_VAR in str(e.value) and "Phase 3" in str(e.value)


def test_key_id_is_env_prefixed_sha256_prefix_and_the_key_itself_is_registered():
    registry = build_registry(PROJECT, {KEY_ENV_VAR: KEY})
    assert registry.key_id == "env:" + hashlib.sha256(KEY.encode()).hexdigest()[:8]
    assert registry.mode == "hmac"
    assert KEY not in registry.redact(f"key={KEY}")


def test_sha256_mode_needs_no_key():
    project = PROJECT.model_copy(update={"redaction": PROJECT.redaction.model_copy(update={"placeholder": "sha256"})})
    registry = build_registry(project, {})
    assert registry.mode == "sha256" and registry.key_id == "none"


def test_env_seeding_registers_values_only_for_token_secret_and_required_env_names():
    stack = PROJECT.stacks["app"].model_copy(
        update={"secrets": {"EXAMPLE_API_TOKEN": "ssm:/example/token"}, "required_env": ["EXAMPLE_REQUIRED"]}
    )
    project = PROJECT.model_copy(update={"stacks": {"app": stack}})
    assert env_secret_names(project) >= {"AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "EXAMPLE_API_TOKEN"}
    env = {
        KEY_ENV_VAR: KEY,
        "AWS_SECRET_ACCESS_KEY": SECRET + "-aws",
        "EXAMPLE_API_TOKEN": SECRET + "-api",
        "EXAMPLE_REQUIRED": SECRET + "-req",
        "UNRELATED": SECRET + "-unrelated",
    }
    registry = build_registry(project, env)
    text = " ".join(env.values())
    out = registry.redact(text)
    for suffix in ("-aws", "-api", "-req"):
        assert SECRET + suffix not in out
    assert SECRET + "-unrelated" in out  # not a declared secret name: not seeded
    # names are never registered
    assert registry.redact("AWS_SECRET_ACCESS_KEY EXAMPLE_API_TOKEN") == "AWS_SECRET_ACCESS_KEY EXAMPLE_API_TOKEN"


def test_seed_inputs_matches_the_key_denylist_on_the_input_name():
    registry = SecretRegistry(KEY.encode(), "env:x")
    matched = seed_inputs(registry, {"env": "prod", "app_secret": SECRET, "n": 3}, key_denylist(PROJECT))
    assert matched == ["app_secret"]
    assert SECRET not in registry.redact(SECRET)
    assert registry.redact("prod") == "prod"


def test_line_hook_and_record_filter():
    registry = SecretRegistry(KEY.encode(), "env:x")
    registry.add(SECRET)
    hook = line_hook(registry)
    assert PLACEHOLDER_RE.search(hook("stdout", f"token={SECRET}"))
    filt = record_filter(registry, key_denylist(PROJECT))
    record = {
        "inputs": {"app_secret": SECRET, "env": "dev"},
        "vars": {"password": "short"},
        "steps": {"secret_step": {"status": "succeeded", "outputs": {"x": f"echo {SECRET}"}}},
    }
    out = filt(record)
    assert out["inputs"] == {"app_secret": "<redacted:key>", "env": "dev"}
    assert out["vars"] == {"password": "<redacted:key>"}
    assert out["steps"]["secret_step"]["status"] == "succeeded"  # step ids are never denylisted
    assert SECRET not in json.dumps(out) and PLACEHOLDER_RE.search(out["steps"]["secret_step"]["outputs"]["x"])


def test_terraform_stream_redacts_values_split_across_chunks():
    registry = SecretRegistry(KEY.encode(), "env:x")
    registry.add(SECRET)
    seen: list[tuple[str, str]] = []
    callback, flush = terraform_stream(registry, lambda ch, line: seen.append((ch, line)))
    head, tail = SECRET[:10], SECRET[10:]
    callback(f"value={head}", "stdout")
    callback(f"{tail} end\n", "stdout")
    callback("plain\n", "stderr")
    flush()
    text = "\n".join(line for _, line in seen)
    assert SECRET not in text and "<redacted:hmac:" in text
    assert ("stderr", "plain") in seen


def test_runner_redact_filter_scrubs_run_json_results_and_outputs(tmp_path):
    registry = SecretRegistry(KEY.encode(), "env:x")
    registry.add(SECRET)
    wf = Workflow.model_validate(
        {
            "api": "codeorca/v1",
            "kind": "workflow",
            "name": "t",
            "inputs": {"app_secret": {"type": "string", "default": SECRET}},
            "steps": [
                {
                    "id": "a",
                    "type": "shell",
                    "run": [
                        sys.executable,
                        "-c",
                        "import os, json; json.dump({'leak': os.environ['LEAK']}, "
                        "open(os.environ['CODEORCA_OUTPUT_FILE'], 'w'))",
                    ],
                    "outputs": {"leak": "${{ result.output.leak }}"},
                }
            ],
        }
    )
    rd = RunDir(tmp_path)
    runner = Runner(
        PROJECT,
        wf,
        {},
        rd,
        default_executors(),
        env={"PATH": "/usr/bin:/bin", "LEAK": SECRET},
        stream=line_hook(registry),
        redact=record_filter(registry, key_denylist(PROJECT)),
    )
    assert runner.run() == 0
    for path in rd.path.rglob("*"):
        if path.is_file():
            assert SECRET not in path.read_text(encoding="utf-8"), path
    assert rd.read_run()["inputs"] == {"app_secret": "<redacted:key>"}
    assert PLACEHOLDER_RE.search(rd.read_outputs("a")["leak"])
