"""Phase 3 CLI wiring without terraform or AWS: the gate/python/powershell executors, the SSM key fetcher and
resolver handed through, ``codeorca resume`` refusing without a terminal, ``codeorca lint powershell``.

No test here reaches AWS: the suite-wide conftest empties the AWS config, and the tests that build a registry from
a project naming ``redaction.hmac_key`` either set ``CODEORCA_REDACTION_KEY`` or inject the key fetcher; the
no-network tests make boto3 session creation raise (``no_boto3_session``)."""

from __future__ import annotations

import inspect
import json
import shutil
import sys
from pathlib import Path

import pytest

from codeorca import cli
from codeorca.redact import SecretRegistry, scan_outputs
from codeorca.rundir import list_runs

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = ROOT / "examples" / "reference"
KEY = "example-not-secret-cli-key"
SECRET = "FIXTURE-SECRET-cli-resolver-001"


def reference_copy(tmp_path: Path, monkeypatch, *, key: bool = True) -> Path:
    root = tmp_path / "reference"
    shutil.copytree(REFERENCE, root, ignore=shutil.ignore_patterns(".codeorca", "specs", ".terraform*", "*.tfstate*"))
    if key:
        monkeypatch.setenv("CODEORCA_REDACTION_KEY", KEY)
    else:
        monkeypatch.delenv("CODEORCA_REDACTION_KEY", raising=False)
    return root


def write_workflow(root: Path, name: str, body: str) -> None:
    (root / "workflows" / f"{name}.yaml").write_text(
        f"api: codeorca/v1\nkind: workflow\nname: {name}\n{body}", encoding="utf-8"
    )


def only_run(root: Path) -> Path:
    runs = list_runs(root / ".codeorca" / "runs")
    assert len(runs) == 1
    return root / ".codeorca" / "runs" / runs[0]


# --- executors -------------------------------------------------------------------------------------------------


def test_executors_register_gate_python_and_powershell():
    executors = cli._executors(SecretRegistry(b"example-not-secret", "env:test"))
    assert executors["gate"].__name__ == "run_gate"
    assert executors["python"].__name__ == "run_python"
    assert executors["powershell"].__name__ == "run_powershell"
    assert executors["terraform"].__name__ == "run_terraform"


def test_cli_never_wires_isatty_or_prompt():
    """The approval invariant in code: the CLI builds the gate executor and calls resume() with their defaults; no
    option, flag or env var reaches ``isatty=``/``prompt=``."""
    source = inspect.getsource(cli)
    assert "isatty=" not in source and "prompt=" not in source
    assert "gate_step.make_executor(registry)" in source


def test_resolver_closes_over_the_helpers_and_terraform(monkeypatch):
    seen: list[str] = []

    def resolver(ref: str) -> str:
        seen.append(ref)
        return SECRET

    registry = SecretRegistry(b"example-not-secret", "env:test")
    executors = cli._executors(registry, resolver)
    for name in ("python", "powershell", "terraform"):
        cells = [c.cell_contents for c in executors[name].__closure__ or ()]
        assert resolver in cells, name


# --- SSM key fetcher and resolver through `codeorca run` ---------------------------------------------------------


def test_run_uses_the_ssm_key_fetcher_when_the_env_key_is_unset(tmp_path, monkeypatch, capsys):
    root = reference_copy(tmp_path, monkeypatch, key=False)
    write_workflow(root, "hello", f"steps:\n  - id: a\n    type: shell\n    run: [{sys.executable!r}, '-c', 'pass']\n")
    asked: list[str] = []

    def fake_ssm_key_fetcher(project=None, **kw):
        def fetch(ref: str):
            asked.append(ref)
            return b"example-not-secret-fetched-key", f"{ref}@7"

        return fetch

    monkeypatch.setattr("codeorca.secrets.ssm_key_fetcher", fake_ssm_key_fetcher)
    assert cli.main(["run", "hello", "-p", str(root / "codeorca.yaml")]) == 0
    assert asked == ["ssm:/codeorca/redaction-key"]


def test_env_key_set_means_no_aws_call_at_all(tmp_path, monkeypatch, capsys, no_boto3_session):
    root = reference_copy(tmp_path, monkeypatch)
    write_workflow(root, "hello", f"steps:\n  - id: a\n    type: shell\n    run: [{sys.executable!r}, '-c', 'pass']\n")
    assert cli.main(["run", "hello", "-p", str(root / "codeorca.yaml")]) == 0
    assert no_boto3_session == []


def test_unset_key_fails_closed_without_reaching_aws(tmp_path, monkeypatch, capsys, no_boto3_session):
    root = reference_copy(tmp_path, monkeypatch, key=False)
    write_workflow(root, "hello", f"steps:\n  - id: a\n    type: shell\n    run: [{sys.executable!r}, '-c', 'pass']\n")
    assert cli.main(["run", "hello", "-p", str(root / "codeorca.yaml")]) == 1
    err = capsys.readouterr().err
    assert "could not fetch the redaction key ssm:/codeorca/redaction-key" in err and "CODEORCA_REDACTION_KEY" in err
    assert len(no_boto3_session) == 1
    assert list_runs(root / ".codeorca" / "runs") == []


HELPER = """import json, os, sys
value = os.environ["EXAMPLE_API_TOKEN"]
print("token is", value)
with open(os.environ["CODEORCA_OUTPUT_FILE"], "w", encoding="utf-8") as f:
    json.dump({"length": len(value), "echo": value}, f)
"""


def test_resolver_reaches_a_python_helper_and_its_value_is_redacted(tmp_path, monkeypatch, capsys):
    root = reference_copy(tmp_path, monkeypatch)
    (root / "helpers" / "echo_token.py").write_text(HELPER, encoding="utf-8")
    write_workflow(
        root,
        "secret-helper",
        "steps:\n  - id: h\n    type: python\n    script: helpers/echo_token.py\n"
        '    env: { EXAMPLE_API_TOKEN: { secret: "ssm:/example/app/api-token" } }\n'
        '    outputs: { length: "${{ result.output.length }}" }\n',
    )
    asked: list[str] = []

    def fake_make_resolver(project, registry, **kw):
        def resolve(ref: str) -> str:
            asked.append(ref)
            registry.add(SECRET)  # the real provider registers before returning
            return SECRET

        return resolve

    monkeypatch.setattr("codeorca.providers.make_resolver", fake_make_resolver)
    assert cli.main(["run", "secret-helper", "-p", str(root / "codeorca.yaml")]) == 0
    assert SECRET not in capsys.readouterr().out
    assert asked == ["ssm:/example/app/api-token"]
    run_dir = only_run(root)
    record = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    assert record["steps"]["h"]["outputs"]["length"] == len(SECRET)
    check = SecretRegistry(KEY.encode(), "env:test")
    check.add(SECRET)
    assert scan_outputs(run_dir, check) == []
    assert "<redacted:hmac:" in (run_dir / "steps" / "h" / "stdout.log").read_text(encoding="utf-8")


def test_no_provider_fails_only_the_step_that_needs_a_secret(tmp_path, monkeypatch, capsys):
    root = reference_copy(tmp_path, monkeypatch)
    (root / "helpers" / "echo_token.py").write_text(HELPER, encoding="utf-8")
    write_workflow(
        root,
        "secret-helper",
        "fail_fast: false\nsteps:\n"
        f"  - id: plain\n    type: shell\n    run: [{sys.executable!r}, '-c', 'pass']\n"
        "  - id: h\n    type: python\n    script: helpers/echo_token.py\n"
        '    env: { EXAMPLE_API_TOKEN: { secret: "ssm:/example/app/api-token" } }\n',
    )
    monkeypatch.setattr("codeorca.providers.make_resolver", lambda project, registry, **kw: None)
    assert cli.main(["run", "secret-helper", "-p", str(root / "codeorca.yaml")]) == 1
    record = json.loads((only_run(root) / "run.json").read_text(encoding="utf-8"))
    assert record["steps"]["plain"]["status"] == "succeeded"
    assert record["steps"]["h"]["status"] == "errored"
    assert "pip install 'code-orca[aws]'" in record["steps"]["h"]["error"]


# --- resume ---------------------------------------------------------------------------------------------------

GATED = f"""steps:
  - id: approve
    type: gate
    message: ship it?
  - id: after
    type: shell
    needs: [approve]
    run: [{sys.executable!r}, '-c', 'pass']
"""


@pytest.mark.parametrize("decision", ["--approve", "--reject"])
def test_resume_refuses_without_a_terminal(tmp_path, monkeypatch, capsys, decision):
    """No terminal (as an agent's pipe): the run waits, resume refuses either way. ``os.isatty`` is patched, so
    the test does not depend on pytest's fd capture (``pytest -s`` in a terminal would otherwise prompt)."""
    monkeypatch.setattr("os.isatty", lambda fd: False)
    root = reference_copy(tmp_path, monkeypatch)
    write_workflow(root, "gated", GATED)
    p = str(root / "codeorca.yaml")
    assert cli.main(["run", "gated", "-p", p]) == 3
    out = capsys.readouterr().out
    assert "waiting at a gate" in out and "codeorca resume" in out
    assert cli.main(["resume", "latest", decision, "-p", p]) == 1
    err = capsys.readouterr().err
    assert "interactive terminal" in err and "no flag or environment variable" in err
    record = json.loads((only_run(root) / "run.json").read_text(encoding="utf-8"))
    assert record["status"] == "waiting" and record["steps"]["after"]["status"] is None


SECRET_INPUT = "FIXTURE-SECRET-cli-resume-input-001"
SECRET_FIELD = "FIXTURE-SECRET-cli-resume-field-001"
SECRET_GATED = f"""inputs:
  api_token: {{ type: string }}
steps:
  - id: approve
    type: gate
    message: ship it?
    fields:
      ticket: {{ type: string }}
      change_token: {{ type: string, required: true }}
  - id: after
    type: shell
    needs: [approve]
    run: [{sys.executable!r}, '-c', 'import sys; print(sys.argv[1:])', '${{{{ inputs.api_token }}}}',
          '${{{{ steps.approve.outputs.change_token }}}}', '${{{{ steps.approve.outputs.ticket }}}}']
    outputs:
      seen: "${{{{ steps.approve.outputs.change_token }}}}"
"""


def _waiting_secret_run(root: Path, monkeypatch) -> str:
    monkeypatch.setattr("os.isatty", lambda fd: False)
    write_workflow(root, "secret-gated", SECRET_GATED)
    p = str(root / "codeorca.yaml")
    assert cli.main(["run", "secret-gated", "-p", p, "--input", f"api_token={SECRET_INPUT}"]) == 3
    return p


def test_cli_resume_on_a_terminal_asks_secrets_shows_the_binding_and_redacts(tmp_path, monkeypatch, capsys):
    """The CLI's own resume wiring (registry, redact, cwd, getpass, the confirmation), not a hand-built copy:
    os.isatty is patched (resume() resolves it at call time), the secrets come through getpass."""
    root = reference_copy(tmp_path, monkeypatch)
    p = _waiting_secret_run(root, monkeypatch)
    capsys.readouterr()
    monkeypatch.setattr("os.isatty", lambda fd: True)
    asked: list[str] = []

    def fake_getpass(prompt: str) -> str:
        asked.append(prompt)
        return SECRET_INPUT if prompt.startswith("input api_token") else SECRET_FIELD

    monkeypatch.setattr("getpass.getpass", fake_getpass)
    monkeypatch.setattr("builtins.input", lambda prompt="": "approve")
    assert cli.main(["resume", "latest", "--approve", "--field", "ticket=CHG-1", "-p", p]) == 0
    out = capsys.readouterr().out
    assert "gate approve: ship it?" in out  # what the approval binds is shown before it is confirmed
    assert [a.split()[1] for a in asked] == ["api_token", "change_token"]
    run_dir = only_run(root)
    record = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    assert record["status"] == "succeeded" and record["steps"]["after"]["status"] == "succeeded"
    stdout_log = (run_dir / "steps" / "after" / "stdout.log").read_text(encoding="utf-8")
    assert "CHG-1" in stdout_log and "<redacted:" in stdout_log  # the step got the values; the log is scrubbed
    for path in run_dir.rglob("*"):
        if path.is_file():
            data = path.read_bytes()
            assert SECRET_INPUT.encode() not in data and SECRET_FIELD.encode() not in data, path
    assert SECRET_INPUT not in out and SECRET_FIELD not in out


def test_cli_resume_refuses_a_secret_named_field_on_the_command_line(tmp_path, monkeypatch, capsys):
    """Review finding: a field named like a secret could only be passed as --field (ps, shell history)."""
    root = reference_copy(tmp_path, monkeypatch)
    p = _waiting_secret_run(root, monkeypatch)
    capsys.readouterr()
    monkeypatch.setattr("os.isatty", lambda fd: True)
    monkeypatch.setattr("getpass.getpass", lambda prompt: pytest.fail("asked before refusing"))
    assert cli.main(["resume", "latest", "--approve", "--field", f"change_token={SECRET_FIELD}", "-p", p]) == 1
    err = capsys.readouterr().err
    assert "named like a secret" in err and "never taken from the command line" in err
    assert SECRET_FIELD not in err
    assert json.loads((only_run(root) / "run.json").read_text(encoding="utf-8"))["status"] == "waiting"


def test_cli_resume_without_the_typed_confirmation_changes_nothing(tmp_path, monkeypatch, capsys):
    root = reference_copy(tmp_path, monkeypatch)
    p = _waiting_secret_run(root, monkeypatch)
    monkeypatch.setattr("os.isatty", lambda fd: True)
    monkeypatch.setattr("getpass.getpass", lambda prompt: SECRET_INPUT if "api_token" in prompt else SECRET_FIELD)
    monkeypatch.setattr("builtins.input", lambda prompt="": "yes")
    assert cli.main(["resume", "latest", "--approve", "-p", p]) == 1
    assert "not confirmed" in capsys.readouterr().err
    assert json.loads((only_run(root) / "run.json").read_text(encoding="utf-8"))["status"] == "waiting"


def test_resume_needs_exactly_one_decision(capsys):
    with pytest.raises(SystemExit):
        cli.main(["resume", "latest"])
    with pytest.raises(SystemExit):
        cli.main(["resume", "latest", "--approve", "--reject"])


def test_resume_has_no_bypass_option():
    parser = cli.build_parser()
    sub = next(a for a in parser._actions if a.dest == "command")
    options = {o for a in sub.choices["resume"]._actions for o in a.option_strings}
    assert options == {"-h", "--help", "--approve", "--reject", "--field", "-p", "--project"}


# --- lint powershell --------------------------------------------------------------------------------------------


def test_lint_powershell_prints_findings_and_exits_on_warning(tmp_path, monkeypatch, capsys):
    from codeorca.lint.ansible import Finding

    found = [
        Finding(file="a.ps1", line=3, rule="PSAvoidUsingWriteHost", level="warning", message="no Write-Host"),
        Finding(file="a.ps1", line=9, rule="Note", level="info", message="fyi"),
    ]
    calls: list[tuple] = []

    def fake_lint(paths, settings=None, **kw):
        calls.append((list(paths), settings))
        return found

    monkeypatch.setattr("codeorca.steps.powershell_step.lint_powershell", fake_lint)
    script = tmp_path / "a.ps1"
    script.write_text("Write-Host hi\n", encoding="utf-8")
    assert cli.main(["lint", "powershell", str(script)]) == 1
    out = capsys.readouterr().out
    assert "a.ps1:3 PSAvoidUsingWriteHost warning no Write-Host" in out and "a.ps1:9 Note info fyi" in out
    assert calls == [([str(script)], None)]

    found[:] = [found[1]]
    assert cli.main(["lint", "powershell", str(script)]) == 0  # info only


def test_lint_powershell_ansible_settings_and_missing_path(tmp_path, monkeypatch, capsys):
    calls: list = []
    monkeypatch.setattr(
        "codeorca.steps.powershell_step.lint_powershell",
        lambda paths, settings=None, **kw: calls.append(settings) or [],
    )
    monkeypatch.setattr("codeorca.steps.powershell_step.ansible_pslint_settings", lambda: Path("/x/settings.psd1"))
    assert cli.main(["lint", "powershell", str(tmp_path), "--ansible-settings"]) == 0
    assert calls == [Path("/x/settings.psd1")]
    monkeypatch.setattr("codeorca.steps.powershell_step.ansible_pslint_settings", lambda: None)
    assert cli.main(["lint", "powershell", str(tmp_path), "--ansible-settings"]) == 1
    assert "needs ansible-core" in capsys.readouterr().err
    assert cli.main(["lint", "powershell", str(tmp_path / "nope.ps1")]) == 1
