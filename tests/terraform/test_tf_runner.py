"""TerraformRunner: offline plumbing tests with a fake engine, then end-to-end tests against the real reference
stack (skipped when `terraform` is not on PATH). Nothing here redacts; the stream callback is where that attaches."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import time
from pathlib import Path

import pytest

from codeorca import tfjson
from codeorca.adapters.terraform import (
    EngineNotFound,
    PlanBindingError,
    PlanResult,
    TerraformError,
    TerraformRunner,
    is_transient,
    plan_file_sha256,
    render_backend_hcl,
)
from codeorca.policy import PolicyError

ROOT = Path(__file__).resolve().parents[2]
STACK = ROOT / "examples" / "reference" / "terraform" / "app"
SECRET = "FIXTURE-SECRET-tf-input-001"
TERRAFORM = shutil.which("terraform")
needs_terraform = pytest.mark.skipif(TERRAFORM is None, reason="terraform not on PATH")

FAKE_ENGINE = """#!/bin/sh
# Fake engine: echoes its argv and selected env to stdout, one diagnostic to stderr, exits $FAKE_EXIT.
for a in "$@"; do printf 'arg:%s\\n' "$a"; done
printf 'env:TF_IN_AUTOMATION=%s TF_INPUT=%s' "$TF_IN_AUTOMATION" "$TF_INPUT"
printf ' TF_LOG=%s TF_WORKSPACE=%s\\n' "${TF_LOG-unset}" "${TF_WORKSPACE-unset}"
printf '%s\\n' "$FAKE_STDOUT"
printf 'diag on stderr\\n' >&2
exit "${FAKE_EXIT:-0}"
"""


@pytest.fixture
def fake_engine(tmp_path: Path) -> Path:
    path = tmp_path / "fake-terraform"
    path.write_text(FAKE_ENGINE, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def base_env(home: Path) -> dict[str, str]:
    return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home)}


# ---------------------------------------------------------------- offline: plumbing with a fake engine


def test_run_sets_automation_env_adds_flags_streams_both_channels_and_records_argv(tmp_path, fake_engine):
    seen: list[tuple[str, str]] = []
    env = base_env(tmp_path) | {"FAKE_STDOUT": '{"@level":"info","@message":"hi","type":"log"}', "TF_WORKSPACE": "dev"}
    runner = TerraformRunner(tmp_path, env, engine=str(fake_engine), stream=lambda line, ch: seen.append((ch, line)))
    result = runner.init(lockfile_readonly=True, reconfigure=True)

    assert result.exit_code == 0
    assert result.argv[0] == str(fake_engine)
    assert result.argv[1:] == ["init", "-no-color", "-input=false", "-json", "-lockfile=readonly", "-reconfigure"]
    assert "env:TF_IN_AUTOMATION=1 TF_INPUT=0 TF_LOG=unset TF_WORKSPACE=dev" in result.stdout_lines
    assert "TF_LOG" not in result.env_names and "TF_LOG" not in runner.env  # never set here
    assert runner.workspace == "dev"
    assert result.env_names == sorted(env | {"TF_IN_AUTOMATION": "", "TF_INPUT": ""})
    assert result.stderr_lines == ["diag on stderr"]
    assert {"@level": "info", "@message": "hi", "type": "log"} in result.messages
    assert {"@level": "log", "@message": "arg:init"} in result.messages  # non-JSON lines kept, not dropped
    # the stream callback saw every line, with its newline, on the right channel
    assert ("stdout", "arg:init\n") in seen
    assert ("stderr", "diag on stderr\n") in seen
    assert "".join(line for ch, line in seen if ch == "stdout") == result.stdout + "\n"
    assert runner.history == [result] or runner.history[0].argv == result.argv


def test_plan_preserves_detailed_exitcode_2_and_lock_flags(tmp_path, fake_engine):
    env = base_env(tmp_path) | {"FAKE_EXIT": "2"}
    runner = TerraformRunner(tmp_path, env, engine=str(fake_engine), lock_timeout="5m")
    out = tmp_path / "plan.tfplan"
    out.write_bytes(b"fake plan")
    result = runner.plan(out, var_file=tmp_path / "run.tfvars")
    assert isinstance(result, PlanResult)
    assert result.exit_code == 2 and result.changed and result.plan_file == str(out)
    assert result.argv[1:] == [
        "plan",
        "-no-color",
        "-input=false",
        "-lock-timeout=5m",
        "-detailed-exitcode",
        f"-out={out}",
        f"-var-file={tmp_path / 'run.tfvars'}",
    ]
    assert stat.S_IMODE(out.stat().st_mode) == 0o600

    unlocked = TerraformRunner(tmp_path, base_env(tmp_path) | {"FAKE_EXIT": "0"}, engine=str(fake_engine), lock=False)
    assert "-lock=false" in unlocked.plan(out).argv and not unlocked.plan(out).changed
    assert "-lock-timeout=60s" in unlocked.plan(out, lock=True).argv  # per-call override


def test_plan_exit_1_is_returned_not_raised_but_odd_codes_raise(tmp_path, fake_engine):
    runner = TerraformRunner(tmp_path, base_env(tmp_path) | {"FAKE_EXIT": "1"}, engine=str(fake_engine))
    result = runner.plan(tmp_path / "p.tfplan")
    assert result.exit_code == 1 and not result.changed
    with pytest.raises(TerraformError):
        TerraformRunner(tmp_path, base_env(tmp_path) | {"FAKE_EXIT": "3"}, engine=str(fake_engine)).plan(tmp_path / "p")


def test_apply_refuses_wrong_sha256_before_running_anything(tmp_path):
    plan = tmp_path / "plan.tfplan"
    plan.write_bytes(b"approved plan bytes")
    runner = TerraformRunner(tmp_path, base_env(tmp_path), engine="definitely-not-an-engine")
    good = hashlib.sha256(b"approved plan bytes").hexdigest()
    assert plan_file_sha256(plan) == good

    with pytest.raises(PlanBindingError, match="does not match"):
        runner.apply(plan, "0" * 64)
    with pytest.raises(PlanBindingError):
        runner.apply(plan, "")
    with pytest.raises(PlanBindingError, match="does not exist"):
        runner.apply(tmp_path / "missing.tfplan", good)
    assert runner.history == []  # nothing was executed: the refusal happens before _run

    plan.write_bytes(b"tampered after approval")
    with pytest.raises(PlanBindingError):
        runner.apply(plan, good)
    # with the right digest the next thing is the engine lookup, i.e. _run was reached
    plan.write_bytes(b"approved plan bytes")
    with pytest.raises(EngineNotFound):
        runner.apply(plan, good.upper())


def test_apply_argv_and_stream_parse(tmp_path, fake_engine):
    plan = tmp_path / "plan.tfplan"
    plan.write_bytes(b"plan")
    env = base_env(tmp_path) | {"FAKE_STDOUT": '{"@level":"error","@message":"Error: boom","type":"diagnostic"}'}
    runner = TerraformRunner(tmp_path, env, engine=str(fake_engine))
    result = runner.apply(plan, plan_file_sha256(plan))
    assert result.argv[1:] == ["apply", "-no-color", "-input=false", "-lock-timeout=60s", "-json", str(plan)]
    assert "-auto-approve" not in result.argv and "-lock=false" not in result.argv
    assert result.plan_sha256 == plan_file_sha256(plan)
    assert result.errors == [{"@level": "error", "@message": "Error: boom", "type": "diagnostic"}]


def test_every_method_goes_through_the_floor(tmp_path, fake_engine, monkeypatch):
    """A method that assembled a forbidden argv would be stopped by _run, whatever the engine says."""
    runner = TerraformRunner(tmp_path, base_env(tmp_path), engine=str(fake_engine))
    with pytest.raises(PolicyError) as info:
        runner._run(["destroy"])
    assert info.value.rule == "destroy" and runner.history == []
    with pytest.raises(PolicyError) as info:
        runner._run(["apply", "-auto-approve", "p.tfplan"])
    assert info.value.rule == "auto-approve"
    with pytest.raises(PolicyError) as info:
        runner._run(["init", "-migrate-state"])
    assert info.value.rule == "migrate-state"
    assert runner._run(["init", "-migrate-state"], allow_migrate_state=True).exit_code == 0


def test_stream_callback_is_never_entered_concurrently(tmp_path):
    chatty = tmp_path / "chatty"
    chatty.write_text(
        "#!/bin/sh\ni=0; while [ $i -lt 300 ]; do printf 'out %s\\n' $i; printf 'err %s\\n' $i >&2; i=$((i+1)); done\n",
        encoding="utf-8",
    )
    chatty.chmod(0o700)
    inside = False
    overlaps = 0
    seen: list[str] = []

    def stream(line: str, channel: str) -> None:
        nonlocal inside, overlaps
        if inside:
            overlaps += 1
        inside = True
        seen.append(f"{channel}:{line}")
        time.sleep(0)  # yield to the other reader thread: without the runner's lock this overlaps hundreds of times
        inside = False

    runner = TerraformRunner(tmp_path, base_env(tmp_path), engine=str(chatty), stream=stream)
    result = runner._run(["version"])  # any allowed subcommand; the fake engine ignores it
    assert result.exit_code == 0
    assert overlaps == 0
    assert len(seen) == 600 and sum(s.startswith("stdout:out ") for s in seen) == 300
    assert len(result.stdout_lines) == 300 and len(result.stderr_lines) == 300


def test_engine_not_found(tmp_path):
    runner = TerraformRunner(tmp_path, {"PATH": str(tmp_path), "HOME": str(tmp_path)}, engine="terraform")
    with pytest.raises(EngineNotFound):
        runner.validate()
    with pytest.raises(EngineNotFound):
        TerraformRunner(tmp_path, base_env(tmp_path), engine=str(tmp_path / "nope")).validate()


def test_init_backend_config_writes_non_secret_hcl_and_refuses_credentials(tmp_path, fake_engine):
    runner = TerraformRunner(tmp_path, base_env(tmp_path), engine=str(fake_engine))
    result = runner.init(backend_config={"bucket": "example-tfstate", "use_lockfile": True, "region": "us-east-1"})
    flag = next(a for a in result.argv if a.startswith("-backend-config="))
    hcl_path = Path(flag.split("=", 1)[1])
    assert hcl_path.suffix == ".hcl" and not hcl_path.exists()  # temporary, removed after the run
    assert render_backend_hcl({"bucket": "b", "use_lockfile": True, "n": 3, "q": 'say "hi"'}) == (
        'bucket = "b"\nn = 3\nq = "say \\"hi\\""\nuse_lockfile = true\n'
    )
    for key in ("access_key", "secret_key", "token", "password", "sas_token", "client_secret", "AWS_SESSION_TOKEN"):
        with pytest.raises(ValueError, match="credential"):
            runner.init(backend_config={"bucket": "b", key: "FIXTURE-SECRET-backend"})
    assert len(runner.history) == 1  # the refusals never reached the engine
    with pytest.raises(ValueError, match="scalars"):
        render_backend_hcl({"assume_role": {"role_arn": "x"}})
    with pytest.raises(ValueError, match="identifier"):
        render_backend_hcl({"bad key": "x"})


def test_validate_exit_1_returns_the_document(tmp_path, fake_engine):
    doc = {"format_version": "1.0", "valid": False, "error_count": 1, "diagnostics": [{"severity": "error"}]}
    env = base_env(tmp_path) | {"FAKE_EXIT": "1", "FAKE_STDOUT": json.dumps(doc)}
    runner = TerraformRunner(tmp_path, env, engine=str(fake_engine))
    # the fake engine prefixes argv echo lines, so the document must be the whole stdout: use a quiet variant
    quiet = tmp_path / "quiet"
    quiet.write_text('#!/bin/sh\nprintf \'%s\\n\' "$FAKE_STDOUT"\nexit "${FAKE_EXIT:-0}"\n', encoding="utf-8")
    quiet.chmod(0o700)
    runner = TerraformRunner(tmp_path, env, engine=str(quiet))
    assert runner.validate() == doc
    assert runner.history[-1].argv[1:] == ["validate", "-no-color", "-json"]
    with pytest.raises(TerraformError, match="did not return JSON"):
        TerraformRunner(tmp_path, env | {"FAKE_STDOUT": "not json"}, engine=str(quiet)).validate()


def test_json_documents_raise_on_failure_or_non_object(tmp_path):
    quiet = tmp_path / "quiet"
    quiet.write_text(
        '#!/bin/sh\nprintf \'%s\\n\' "$FAKE_STDOUT"\necho failed >&2\nexit "${FAKE_EXIT:-0}"\n', encoding="utf-8"
    )
    quiet.chmod(0o700)
    env = base_env(tmp_path)
    assert TerraformRunner(tmp_path, env | {"FAKE_STDOUT": '{"a":1}'}, engine=str(quiet)).show_state() == {"a": 1}
    with pytest.raises(TerraformError, match="exit 1"):
        TerraformRunner(tmp_path, env | {"FAKE_STDOUT": "{}", "FAKE_EXIT": "1"}, engine=str(quiet)).output_json()
    with pytest.raises(TerraformError, match="expected an object"):
        TerraformRunner(tmp_path, env | {"FAKE_STDOUT": "[1]"}, engine=str(quiet)).providers_schema()


def test_test_refuses_apply_mode_run_blocks_up_front(tmp_path, fake_engine):
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "apply.tftest.hcl").write_text('run "x" {\n  command = apply\n}\n', encoding="utf-8")
    (tests / "plan.tftest.hcl").write_text('run "y" {\n  command = plan\n}\n', encoding="utf-8")
    runner = TerraformRunner(tmp_path, base_env(tmp_path), engine=str(fake_engine))
    with pytest.raises(PolicyError) as info:
        runner.test()
    assert info.value.rule == "test-apply" and "apply.tftest.hcl" in str(info.value) and runner.history == []
    result = runner.test(plan_mode_only=False)
    assert result["argv"][1:] == ["test", "-no-color", "-json"] and result["exit_code"] == 0


def test_is_transient_matches_policy_patterns():
    patterns = ["Error acquiring the state lock", "RequestLimitExceeded", "429"]
    assert is_transient("Error: Error acquiring the state lock\nLock Info: ...", patterns)
    assert is_transient("status 429 Too Many Requests", patterns)
    assert not is_transient("Error: Invalid value for variable", patterns)
    assert not is_transient("anything", [])
    assert not is_transient("anything", [""])


# ---------------------------------------------------------------- live: the real reference stack


@pytest.fixture
def stack(tmp_path: Path) -> Path:
    work = tmp_path / "app"
    shutil.copytree(STACK, work)
    return work


def tfvars(path: Path, environment: str) -> Path:
    path.write_text(f'app_secret = "{SECRET}"\nenvironment = "{environment}"\n', encoding="utf-8")
    return path


@needs_terraform
def test_live_exit_code_2_preserved_end_to_end_and_apply_bound_to_sha256(tmp_path, stack):
    seen: list[str] = []
    runner = TerraformRunner(stack, base_env(tmp_path), stream=lambda line, ch: seen.append(line))
    init = runner.init()
    assert init.exit_code == 0
    assert any(m.get("message_code") == "output_init_success_message" for m in init.messages)

    plan = runner.plan(tmp_path / "plan.tfplan", var_file=tfvars(tmp_path / "dev.tfvars", "dev"))
    assert plan.exit_code == 2 and plan.changed  # never collapsed into failure
    assert stat.S_IMODE(Path(plan.plan_file).stat().st_mode) == 0o600

    document = runner.show_plan(plan.plan_file)
    assert tfjson.is_supported_format(document["format_version"])
    assert tfjson.plan_summary(document)["counts"]["add"] == 2
    # the adapter does not redact: show -json still carries the sensitive input in plain text
    assert document["variables"]["app_secret"]["value"] == SECRET
    assert SECRET in json.dumps(document)
    assert tfjson.sensitive_variables(document) == ["app_secret"]
    assert SECRET in "".join(seen)  # and so did the stream, which is where a StreamRedactor attaches
    assert not any(p.suffix == ".json" for p in tmp_path.rglob("*") if p.is_file())  # nothing written by the runner

    digest = plan_file_sha256(plan.plan_file)
    with pytest.raises(PlanBindingError):
        runner.apply(plan.plan_file, "f" * 64)
    applied = runner.apply(plan.plan_file, digest)
    assert applied.exit_code == 0 and applied.errors == [] and applied.plan_sha256 == digest
    assert any(m.get("type") == "change_summary" and m["changes"]["add"] == 2 for m in applied.messages)

    state = runner.show_state()  # through the runner, never the state file
    assert tfjson.state_outputs(state) == {
        "app_bucket": "example-app-123456789012",
        "app_fqdn": "app-dev.example.com",
        "app_host": "127.0.0.1",
    }
    outputs = runner.output_json()
    assert outputs["app_token"] == {"sensitive": True, "type": "string", "value": SECRET}
    assert (
        "terraform_data"
        in runner.providers_schema()["provider_schemas"]["terraform.io/builtin/terraform"]["resource_schemas"]
    )

    again = runner.plan(tmp_path / "again.tfplan", var_file=tmp_path / "dev.tfvars")
    assert again.exit_code == 0 and not again.changed

    replace = runner.plan(tmp_path / "replace.tfplan", var_file=tfvars(tmp_path / "prod.tfvars", "prod"))
    assert replace.exit_code == 2
    replace_doc = runner.show_plan(replace.plan_file)
    assert tfjson.replacements(replace_doc) == ["terraform_data.app"]
    assert tfjson.previous_outputs(replace_doc) == {
        "app_bucket": "example-app-123456789012",
        "app_fqdn": "app-dev.example.com",
        "app_host": "127.0.0.1",
    }
    if init.messages[0].get("terraform", "").startswith("1.14."):
        # observed on 1.14.7 only (the fixture-pinned test in test_tf_json.py is the record): re-evaluated outputs
        assert tfjson.prior_outputs(replace_doc)["app_fqdn"] == "app-prod.example.com"

    # every argv the run directory will record, in order, all policy-checked
    subcommands = [r.argv[1] for r in runner.history]
    assert subcommands == ["init", "plan", "show", "apply", "show", "output", "providers", "plan", "plan", "show"]
    assert all(r.env_names and "TF_INPUT" in r.env_names for r in runner.history)
    assert runner.test()["passed"]  # no test files: "Success! 0 passed"


@needs_terraform
def test_live_validate_reports_invalid_without_raising(tmp_path, stack):
    (stack / "bad.tf").write_text('resource "terraform_data" "x" {\n  nope = 1\n}\n', encoding="utf-8")
    runner = TerraformRunner(stack, base_env(tmp_path))
    assert runner.init().exit_code == 0
    document = runner.validate()
    assert document["valid"] is False and document["error_count"] == 1
    assert document["diagnostics"][0]["range"]["filename"] == "bad.tf"
    assert runner.history[-1].exit_code == 1
    (stack / "bad.tf").unlink()
    assert runner.validate()["valid"] is True


@needs_terraform
def test_live_plan_error_is_exit_1(tmp_path, stack):
    runner = TerraformRunner(stack, base_env(tmp_path))
    runner.init()
    result = runner.plan(tmp_path / "p.tfplan")  # app_secret has no default and TF_INPUT=0: no prompt, exit 1
    assert result.exit_code == 1 and not result.changed
    assert "app_secret" in result.stderr + result.stdout
    assert not (tmp_path / "p.tfplan").exists()
