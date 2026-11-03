"""``lint_powershell``: PSScriptAnalyzer through pwsh on a clean and a dirty script (skipped without pwsh or the
module), and the fail-closed edges through a fake ``pwsh`` on PATH (run everywhere)."""

from __future__ import annotations

import functools
import json
import os
import subprocess
from pathlib import Path

import pytest
from helper_support import FIXTURES

from codeorca.steps.powershell_step import ansible_pslint_settings, find_pwsh, lint_powershell

PS = FIXTURES / "ps"


@functools.cache
def _pssa_available() -> bool:
    pwsh = find_pwsh()
    if pwsh is None:
        return False
    proc = subprocess.run(
        [pwsh, "-NoProfile", "-NonInteractive", "-Command", "@(Get-Module -ListAvailable PSScriptAnalyzer).Count"],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    return proc.returncode == 0 and proc.stdout.strip() not in ("", "0")


needs_pssa = pytest.mark.skipif(not _pssa_available(), reason="pwsh or the PSScriptAnalyzer module is not installed")


@needs_pssa
def test_clean_script_has_no_findings():
    assert lint_powershell([PS / "clean.ps1"]) == []


@needs_pssa
def test_dirty_script_findings():
    findings = lint_powershell([PS / "dirty.ps1"])
    rules = {f["rule"] for f in findings}
    assert {"PSAvoidUsingCmdletAliases", "PSAvoidUsingWriteHost"} <= rules
    assert all(Path(f["file"]).name == "dirty.ps1" and f["line"] > 0 and f["level"] == "warning" for f in findings)
    assert [f["line"] for f in findings] == sorted(f["line"] for f in findings)


@needs_pssa
@pytest.mark.skipif(ansible_pslint_settings() is None, reason="ansible-core (ansible_test) is not installed")
def test_ansible_pslint_settings_add_the_style_rules():
    settings = ansible_pslint_settings()
    assert lint_powershell([PS / "clean.ps1", PS / "emit.ps1"], settings) == []
    rules = {f["rule"] for f in lint_powershell([PS / "dirty.ps1"], settings)}
    assert {"PSPlaceOpenBrace", "PSAvoidSemicolonsAsLineTerminators", "PSUseConsistentIndentation"} <= rules


@needs_pssa
def test_a_directory_is_recursed():
    rules = {f["rule"] for f in lint_powershell([PS])}
    assert "PSAvoidUsingWriteHost" in rules


def test_missing_pwsh_is_one_info_finding():
    findings = lint_powershell([PS / "clean.ps1"], env={"PATH": "/nonexistent"})
    assert [(f["rule"], f["level"]) for f in findings] == [("pwsh-not-found", "info")]


def _fake_pwsh(tmp_path: Path, body: str) -> dict[str, str]:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    fake = bindir / "pwsh"
    fake.write_text(f"#!/bin/sh\n{body}\n")
    fake.chmod(0o755)
    return {"PATH": f"{bindir}{os.pathsep}/usr/bin{os.pathsep}/bin"}


def test_missing_module_is_one_info_finding(tmp_path):
    env = _fake_pwsh(tmp_path, "echo __CODEORCA_NO_PSSCRIPTANALYZER__")
    findings = lint_powershell([PS / "clean.ps1"], env=env)
    assert [(f["rule"], f["level"]) for f in findings] == [("psscriptanalyzer-not-found", "info")]


def test_a_failing_pwsh_is_an_error_finding(tmp_path):
    env = _fake_pwsh(tmp_path, "echo 'analyzer blew up' >&2; exit 1")
    findings = lint_powershell([PS / "clean.ps1"], env=env)
    assert [(f["rule"], f["level"]) for f in findings] == [("pslint-error", "error")]
    assert "analyzer blew up" in findings[0]["message"]


def test_unexpected_json_shape_is_an_error_not_silence(tmp_path):
    env = _fake_pwsh(tmp_path, """echo '[[{"file": "x.ps1", "line": 1}]]'""")
    findings = lint_powershell([PS / "clean.ps1"], env=env)
    assert [f["rule"] for f in findings] == ["pslint-error"]


def test_paths_travel_in_the_environment_not_the_command(tmp_path):
    seen = tmp_path / "seen"
    env = _fake_pwsh(
        tmp_path, f'printf %s "$CODEORCA_PSLINT_PATHS" > "{seen}.env"; printf %s "$*" > "{seen}.argv"; echo "[]"'
    )
    tricky = tmp_path / "it's $(here).ps1"
    tricky.write_text("Write-Output 1\n")
    assert lint_powershell([tricky], env=env) == []
    assert json.loads(Path(f"{seen}.env").read_text()) == [str(tricky)]
    assert str(tricky) not in Path(f"{seen}.argv").read_text()
