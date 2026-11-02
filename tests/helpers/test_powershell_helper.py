"""The ``powershell`` helper step: ``-File`` keeps exit code 3, ``-WhatIf`` under ``--dry-run`` honoured by a
``SupportsShouldProcess`` script, a script without it refused under ``--dry-run``, the output file, secret env.
The live tests skip without ``pwsh`` on PATH; the textual ``SupportsShouldProcess`` check and the missing-pwsh
path run everywhere."""

from __future__ import annotations

import json

import pytest
from helper_support import SECRET, SECRET_REF

from codeorca.redact import PLACEHOLDER_RE, scan_outputs
from codeorca.runner import EXIT_FAILED, EXIT_OK
from codeorca.steps.powershell_step import declares_should_process, find_pwsh

needs_pwsh = pytest.mark.skipif(find_pwsh() is None, reason="pwsh not on PATH")
PWSH_TIMEOUT = "120s"  # pwsh starts in about a second; generous for a cold CI runner


def ps(id: str, script: str = "ps/emit.ps1", **kw) -> dict:
    return {"id": id, "type": "powershell", "script": script, "timeout": PWSH_TIMEOUT, **kw}


def output(runner, step_id: str):
    return runner.run_dir.read_result(step_id)["output"]


@needs_pwsh
def test_file_mode_preserves_exit_code_3(run_workflow):
    rc, r = run_workflow([ps("a", args=["-ExitCode", "3", "-Word", "three"])])
    assert rc == EXIT_FAILED and r.states["a"]["status"] == "failed"
    assert r.run_dir.read_result("a")["exit_code"] == 3
    assert r.states["a"]["error"].startswith("ps/emit.ps1 exited 3") and "failing with 3" in r.states["a"]["error"]
    assert output(r, "a")["word"] == "three"


@needs_pwsh
def test_argv_shape_and_output_file(run_workflow, project_root):
    rc, r = run_workflow([ps("a", args=["-Word", "hello"], outputs={"word": "${{ result.output.word }}"})])
    assert rc == EXIT_OK, r.states
    argv = json.loads((r.run_dir.steps_dir / "a" / "argv.json").read_text())
    assert argv[1:] == [
        "-NoProfile",
        "-NonInteractive",
        "-File",
        str((project_root / "ps" / "emit.ps1").resolve()),
        "-Word",
        "hello",
    ]
    assert argv[0].endswith("pwsh")
    assert r.states["a"]["outputs"] == {"word": "hello"}
    out = output(r, "a")
    assert out["whatif"] is False and out["dry_run"] is None
    assert (r.run_dir.steps_dir / "a" / "marker.txt").exists()  # ShouldProcess said yes on a real run


@needs_pwsh
def test_dry_run_appends_whatif_and_the_script_honours_it(run_workflow):
    rc, r = run_workflow([ps("a", args=["-Word", "dry"])], dry_run=True)
    assert rc == EXIT_OK, r.states
    argv = json.loads((r.run_dir.steps_dir / "a" / "argv.json").read_text())
    assert argv[-1] == "-WhatIf"
    out = output(r, "a")
    assert out["whatif"] is True and out["dry_run"] == "1"
    assert not (r.run_dir.steps_dir / "a" / "marker.txt").exists()  # ShouldProcess said no
    assert "What if:" in (r.run_dir.steps_dir / "a" / "stdout.log").read_text()


@needs_pwsh
def test_script_without_should_process_runs_normally(run_workflow):
    rc, r = run_workflow([ps("a", script="ps/no_should_process.ps1")])
    assert rc == EXIT_OK, r.states
    assert (r.run_dir.steps_dir / "a" / "marker.txt").exists()


@needs_pwsh
def test_script_without_should_process_is_refused_under_dry_run(run_workflow):
    rc, r = run_workflow([ps("a", script="ps/no_should_process.ps1")], dry_run=True)
    assert rc == EXIT_FAILED and r.states["a"]["status"] == "errored"
    assert "SupportsShouldProcess" in r.states["a"]["error"]
    assert not (r.run_dir.steps_dir / "a" / "argv.json").exists()  # nothing started
    assert not (r.run_dir.steps_dir / "a" / "marker.txt").exists()


@needs_pwsh
def test_secret_env_is_registered_and_never_reaches_the_run_dir(run_workflow, registry):
    rc, r = run_workflow([ps("a", env={"HELPER_SECRET": {"secret": SECRET_REF}})])
    assert rc == EXIT_OK, r.states
    assert registry.count_matches(SECRET) == 1
    step_dir = r.run_dir.steps_dir / "a"
    assert PLACEHOLDER_RE.search(output(r, "a")["secret_echo"])
    assert PLACEHOLDER_RE.search((step_dir / "stdout.log").read_text())
    assert PLACEHOLDER_RE.search((step_dir / "stderr.log").read_text())
    assert scan_outputs(r.run_dir.path, registry) == []


def test_missing_pwsh_errors_the_step(run_workflow):
    rc, r = run_workflow([ps("a")], env={"PATH": "/nonexistent"})
    assert rc == EXIT_FAILED and r.states["a"]["status"] == "errored"
    assert "pwsh not found" in r.states["a"]["error"]


@pytest.mark.parametrize(
    ("text", "declared"),
    [
        ("[CmdletBinding(SupportsShouldProcess)]\nparam()\n", True),
        ("[cmdletbinding( supportsshouldprocess = $true, ConfirmImpact = 'High' )]\nparam()\n", True),
        ("#Requires -Version 7\n<# help #>\n[CmdletBinding(SupportsShouldProcess=$True)]\nparam()\n", True),
        ("[CmdletBinding(SupportsShouldProcess = $false)]\nparam()\n", False),
        ("[CmdletBinding()]\nparam()\n", False),
        ("# [CmdletBinding(SupportsShouldProcess)]\n[CmdletBinding()]\nparam()\n", False),
        ("<#\n[CmdletBinding(SupportsShouldProcess)]\n#>\nparam()\n", False),
        ("param()\nfunction f {\n    [CmdletBinding(SupportsShouldProcess)]\n    param()\n}\n", False),
        ("Write-Output 'no binding at all'\n", False),
    ],
)
def test_declares_should_process_textual_check(text, declared):
    assert declares_should_process(text) is declared
