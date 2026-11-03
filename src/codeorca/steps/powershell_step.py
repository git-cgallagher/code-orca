"""The ``powershell`` helper step (plan section 5.8) and ``lint_powershell`` (PSScriptAnalyzer).

argv: ``[<pwsh>, "-NoProfile", "-NonInteractive", "-File", <script>, *args]`` (+ ``"-WhatIf"`` under ``--dry-run``).
``pwsh`` is looked up on the child environment's ``PATH``; a missing ``pwsh`` errors the step.

- **``-File``, never ``-Command``**: ``-Command`` collapses every non-zero exit to 1, ``-File`` returns the
  script's own ``exit N`` (a test proves 3 survives). Arguments are bound by PowerShell's parameter binder, so an
  ``args:`` item that starts with ``-`` is a parameter name, as on a command line.
- **Dry run**: ``-WhatIf`` is appended after ``args`` (and ``CODEORCA_DRY_RUN=1`` is set, as for every helper).
  ``-WhatIf`` means something only to a script that declares ``[CmdletBinding(SupportsShouldProcess)]``; any other
  script would fail to bind it or, worse, ignore it and make real changes. So under ``--dry-run`` the executor
  refuses a script whose text does not declare it, before anything runs or any secret is resolved.
  **The check is textual, not a parse** (:func:`declares_should_process`): ``<# #>`` block comments and ``#``
  line comments are dropped, then the text before the first ``{`` (the script-level attribute area, ahead of the
  ``param`` block and any function body) must hold ``[CmdletBinding(... SupportsShouldProcess ...)]`` that is not
  ``= $false``/``= 0``. A ``#`` inside a string ahead of the first ``{`` is read as a comment, and a
  ``{`` inside a string there ends the area early; both are unusual in a script header and fail closed (refused).
- ``POWERSHELL_TELEMETRY_OPTOUT=1``, ``POWERSHELL_UPDATECHECK=Off`` and ``NO_COLOR=1`` are set unless the environment
  sets them (no ANSI escapes in ``stderr.log`` or a step error).
- Everything else (script path, env and secrets, outputs, timeouts) is the shared contract in ``steps/helpers.py``.

``lint_powershell(paths, settings=None)`` runs ``Invoke-ScriptAnalyzer`` through ``pwsh`` and returns findings in
the shape ``codeorca lint ansible`` uses (``{file, line, rule, level, message}``). ``settings`` is a PSScriptAnalyzer
settings file; for a helper that may later move into an Ansible collection, pass ansible-core's pslint settings
(``ansible_test/_util/controller/sanity/pslint/settings.psd1``, found by :func:`ansible_pslint_settings` when
ansible-core is installed), so it passes ``ansible-test sanity`` without a reformat. Missing ``pwsh`` or a missing
PSScriptAnalyzer module is a single ``info`` finding, not an exception.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
from collections.abc import Iterable, Mapping
from pathlib import Path

from codeorca.lint.ansible import Finding
from codeorca.redact import SecretRegistry
from codeorca.runner import REDACTION_KEY_ENV_VAR, Executor, StepContext, StepResult
from codeorca.steps.helpers import HelperError, SecretResolver, run_helper

PWSH = "pwsh"
PWSH_FLAGS = ("-NoProfile", "-NonInteractive")
# no telemetry or update check; NO_COLOR keeps ANSI error formatting out of the logs (honoured since 7.4)
QUIET_ENV = {"POWERSHELL_TELEMETRY_OPTOUT": "1", "POWERSHELL_UPDATECHECK": "Off", "NO_COLOR": "1"}

_BLOCK_COMMENT = re.compile(r"<#.*?#>", re.S)
_LINE_COMMENT = re.compile(r"#[^\n]*")
_CMDLET_BINDING = re.compile(r"\[\s*CmdletBinding\s*\((?P<args>[^)]*)\)\s*\]", re.I)
_SHOULD_PROCESS = re.compile(r"\bSupportsShouldProcess\b(?:\s*=\s*(?P<value>\$\w+|\d+))?", re.I)


def find_pwsh(env: Mapping[str, str] | None = None) -> str | None:
    """``pwsh`` on ``env['PATH']`` (the process PATH when ``env`` is None)."""
    path = (env if env is not None else os.environ).get("PATH")
    return shutil.which(PWSH, path=path)


def declares_should_process(text: str) -> bool:
    """True when the script-level ``[CmdletBinding()]`` declares ``SupportsShouldProcess`` (textual check; see the
    module docstring for what it does not parse)."""
    stripped = _LINE_COMMENT.sub("", _BLOCK_COMMENT.sub("", text))
    brace = stripped.find("{")
    header = stripped if brace < 0 else stripped[:brace]
    for binding in _CMDLET_BINDING.finditer(header):
        m = _SHOULD_PROCESS.search(binding.group("args"))
        if m is None:
            continue
        value = (m.group("value") or "").lower()
        if value not in ("$false", "0"):
            return True
    return False


def _preflight(script: Path, ctx: StepContext) -> None:
    if find_pwsh(ctx.env) is None:
        raise HelperError(f"step {ctx.step.id}: pwsh not found on PATH (install PowerShell 7 to run this step)")
    if ctx.dry_run:
        text = script.read_text(encoding="utf-8-sig", errors="replace")
        if not declares_should_process(text):
            raise HelperError(
                f"step {ctx.step.id}: --dry-run appends -WhatIf, but {script.name} does not declare "
                "[CmdletBinding(SupportsShouldProcess)]; refusing to run it (it could ignore -WhatIf and make changes)"
            )


def build_argv(script: Path, args: list[str], ctx: StepContext, env: Mapping[str, str]) -> list[str]:
    pwsh = find_pwsh(env)
    if pwsh is None:  # the step's own env may have replaced PATH
        raise HelperError(f"step {ctx.step.id}: pwsh not found on the step environment's PATH")
    argv = [pwsh, *PWSH_FLAGS, "-File", str(script), *args]
    if ctx.dry_run:
        argv.append("-WhatIf")
    return argv


def make_executor(registry: SecretRegistry, resolve_secret: SecretResolver | None = None) -> Executor:
    """The ``powershell`` executor bound to the run's registry and the SSM resolver (``None``: a step with a
    ``{secret: ...}`` env entry fails)."""

    def run_powershell(step, ctx: StepContext) -> StepResult:
        return run_helper(step, ctx, registry, resolve_secret, build_argv, preflight=_preflight, extra_env=QUIET_ENV)

    run_powershell.__name__ = "run_powershell"
    return run_powershell


# --- lint ------------------------------------------------------------------------------------------------------

_LINT_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$PSStyle.OutputRendering = 'PlainText'
if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
    Write-Output '__CODEORCA_NO_PSSCRIPTANALYZER__'
    exit 0
}
Import-Module PSScriptAnalyzer
$paths = @($env:CODEORCA_PSLINT_PATHS | ConvertFrom-Json)
$settings = $env:CODEORCA_PSLINT_SETTINGS
$records = foreach ($p in $paths) {
    if ($settings) {
        Invoke-ScriptAnalyzer -Path $p -Recurse -Settings $settings
    }
    else {
        Invoke-ScriptAnalyzer -Path $p -Recurse
    }
}
$out = @($records | ForEach-Object {
        [pscustomobject]@{
            file = [string]$_.ScriptPath
            line = [int]$_.Line
            rule = [string]$_.RuleName
            severity = [string]$_.Severity
            message = [string]$_.Message
        }
    })
# -InputObject keeps an array an array (0 and 1 elements included); -AsArray here would nest it
ConvertTo-Json -InputObject $out -Depth 3 -Compress
"""

_NO_PSSA = "__CODEORCA_NO_PSSCRIPTANALYZER__"
_LEVELS = {"error": "error", "parseerror": "error", "warning": "warning", "information": "info"}


def ansible_pslint_settings() -> Path | None:
    """ansible-core's ``pslint/settings.psd1`` (what ``ansible-test sanity`` lints collection PowerShell with), or
    ``None`` when ansible-core (its ``ansible_test`` package) is not installed."""
    spec = importlib.util.find_spec("ansible_test")
    if spec is None or not spec.submodule_search_locations:
        return None
    for base in spec.submodule_search_locations:
        candidate = Path(base) / "_util" / "controller" / "sanity" / "pslint" / "settings.psd1"
        if candidate.is_file():
            return candidate
    return None


def _info(rule: str, message: str) -> Finding:
    return Finding(file="", line=0, rule=rule, level="info", message=message)


def lint_powershell(
    paths: Iterable[str | os.PathLike[str]],
    settings: str | os.PathLike[str] | None = None,
    *,
    env: Mapping[str, str] | None = None,
    timeout: float = 300.0,
) -> list[Finding]:
    """PSScriptAnalyzer over ``paths`` (files or directories, recursed) via ``pwsh``; findings sorted by file and
    line. ``settings``: a settings file (``.psd1``), e.g. :func:`ansible_pslint_settings`. ``pwsh`` or the
    PSScriptAnalyzer module missing -> one ``info`` finding and nothing else; a failing ``pwsh`` -> one ``error``
    finding with its stderr tail. The paths travel in an environment variable, never in the command text."""
    paths = [str(Path(p)) for p in paths]
    base = dict(env if env is not None else os.environ)
    pwsh = find_pwsh(base)
    if pwsh is None:
        return [_info("pwsh-not-found", "pwsh not found on PATH; PowerShell lint skipped")]
    if not paths:
        return []
    child = {k: v for k, v in base.items() if k != REDACTION_KEY_ENV_VAR}
    for k, v in QUIET_ENV.items():
        child.setdefault(k, v)
    child["CODEORCA_PSLINT_PATHS"] = json.dumps(paths)
    child.pop("CODEORCA_PSLINT_SETTINGS", None)
    if settings is not None:
        child["CODEORCA_PSLINT_SETTINGS"] = str(Path(settings))
    try:
        proc = subprocess.run(
            [pwsh, *PWSH_FLAGS, "-Command", _LINT_SCRIPT],
            env=child,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return [Finding(file="", line=0, rule="pslint-error", level="error", message=f"pwsh exceeded {timeout}s")]
    except OSError as e:
        return [Finding(file="", line=0, rule="pslint-error", level="error", message=f"cannot start pwsh: {e}")]
    stdout = proc.stdout.strip()
    if _NO_PSSA in stdout:
        return [_info("psscriptanalyzer-not-found", "PSScriptAnalyzer module not installed; PowerShell lint skipped")]
    try:
        records = json.loads(stdout) if proc.returncode == 0 else None
    except json.JSONDecodeError:
        records = None
    if not isinstance(records, list) or not all(isinstance(r, dict) for r in records):  # never drop silently
        tail = (proc.stderr.strip() or stdout)[-2000:]
        return [
            Finding(
                file="",
                line=0,
                rule="pslint-error",
                level="error",
                message=f"Invoke-ScriptAnalyzer failed (exit {proc.returncode}){': ' + tail if tail else ''}",
            )
        ]
    findings = [
        Finding(
            file=str(r.get("file") or ""),
            line=int(r.get("line") or 0),
            rule=str(r.get("rule") or ""),
            level=_LEVELS.get(str(r.get("severity") or "").lower(), "warning"),
            message=str(r.get("message") or ""),
        )
        for r in records
    ]
    findings.sort(key=lambda f: (f["file"], f["line"], f["rule"]))
    return findings
