"""Shared machinery of the ``python`` and ``powershell`` helper steps (plan section 5.8).

The contract both helpers follow (they run their child through ``shell.run_argv``, the shell step's machinery):

- **Script path.** ``script:`` is relative to the project root (``project.root``; the process cwd when there is no
  project). It is resolved with symlinks followed and must stay inside the root and be an existing file; the
  resolved absolute path is what goes on the argv. The child runs with the project root as its cwd, so a helper's
  own relative paths mean the same thing as its ``script:``.
- **argv arrays only.** The executor builds the argv (``python_step``/``powershell_step``); ``args:`` items are
  ``str()``-ed (a whole-expression template may render to a native int or bool) and never pass through a shell.
- **Environment.** The child gets the runner's environment (``CODEORCA_*`` included, never the redaction key) plus
  the step's ``env:``. A literal value is passed as is; ``{secret: ssm:/path}`` is resolved through the injected
  ``resolve_secret`` (the SSM wrapper; integration wires it) and **registered with the run's registry before the
  child starts**. A literal whose NAME matches the project's key denylist is registered too. A value shorter than
  the registry's ``min_length`` (8) cannot be scrubbed: the step result lists its NAME under ``unprotected_env``
  with a warning (the terraform step's ``unprotected_overrides`` precedent). Values go into the child env only:
  ``env-names.json`` records names, argv.json/logs/the output file go through the registry. A step ``env:`` name
  starting with ``CODEORCA_`` is refused (the orchestrator owns those, the redaction key among them).
- **Redaction does not depend on the runner's stream hook.** The executor holds the registry, so every log line,
  argv item and the output file go through ``registry.redact`` first and then through ``ctx.stream`` (when set).
- **Outputs.** The child writes JSON to ``$CODEORCA_OUTPUT_FILE``; it is rewritten through the redactor whatever
  the exit status and then parsed (non-JSON fails the step). stdout/stderr are logs, never parsed.
- **Dry run.** ``CODEORCA_DRY_RUN=1`` under ``--dry-run`` (and removed from the child env otherwise, so an operator
  shell that exported it cannot make a real run believe it is a dry run). PowerShell adds ``-WhatIf``.
- **Result** ``{exit_code, stdout_path, stderr_path, output}`` (+ ``unprotected_env``/``warnings`` when any);
  exit 0 is ``succeeded``, anything else ``failed`` with the redacted stderr tail. Timeouts kill the process group
  (``StepTimeout`` -> ``errored``); retries are the runner's.
"""

from __future__ import annotations

import dataclasses
import os
import re
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from codeorca.models import SecretRef
from codeorca.redact import SecretRegistry, compile_key_denylist
from codeorca.runner import StepContext, StepError, StepResult
from codeorca.secrets import key_denylist
from codeorca.steps.shell import run_argv

SecretResolver = Callable[[str], str]
"""``resolve_secret("ssm:/path") -> value``: the SSM wrapper (implementer C's provider; integration wires it)."""

ArgvBuilder = Callable[[Path, list[str], StepContext, Mapping[str, str]], list[str]]
"""``build_argv(script, args, ctx, child_env) -> argv`` for one helper type."""

Preflight = Callable[[Path, StepContext], None]
"""Checks a helper type runs before any secret is resolved (raise ``HelperError`` to refuse the step)."""

RESERVED_ENV_PREFIX = "CODEORCA_"
DRY_RUN_ENV = "CODEORCA_DRY_RUN"
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class HelperError(StepError):
    """A helper step cannot start (bad script path, unresolvable secret, missing interpreter, policy)."""


def project_root(ctx: StepContext) -> Path:
    """The directory ``script:`` paths are relative to: the project root, else the process cwd."""
    root = ctx.project.root if ctx.project is not None and ctx.project.root is not None else Path.cwd()
    return Path(root).resolve()


def resolve_script(step_id: str, script: Any, root: Path) -> Path:
    """``script`` resolved against ``root`` with symlinks followed; refused outside ``root`` or when missing."""
    text = str(script)
    if not text.strip():
        raise HelperError(f"step {step_id}: script is empty")
    root = root.resolve()
    candidate = Path(text)
    joined = candidate if candidate.is_absolute() else root / candidate
    resolved = joined.resolve()  # follows every symlink, `..` included
    if not resolved.is_relative_to(root):
        raise HelperError(f"step {step_id}: script {text!r} resolves outside the project root {str(root)!r}")
    if not resolved.exists():
        raise HelperError(f"step {step_id}: script {text!r} not found under {str(root)!r}")
    if not resolved.is_file():
        raise HelperError(f"step {step_id}: script {text!r} is not a file")
    return resolved


def redacting_context(ctx: StepContext, registry: SecretRegistry) -> StepContext:
    """A copy of ``ctx`` whose stream hook scrubs with ``registry`` first, then applies the runner's hook."""
    outer = ctx.stream

    def stream(name: str, line: str) -> str:
        line = registry.redact(line)
        return outer(name, line) if outer is not None else line

    return dataclasses.replace(ctx, stream=stream)


def _secret_ref(value: Any) -> str | None:
    if isinstance(value, SecretRef):
        return value.secret
    if isinstance(value, Mapping) and set(value) == {"secret"}:
        return str(value["secret"])
    return None


def child_env(
    step,
    ctx: StepContext,
    registry: SecretRegistry,
    resolve_secret: SecretResolver | None,
) -> tuple[dict[str, str], list[str]]:
    """The child environment and the NAMES of values that could not be registered (too short to scrub).

    Every secret is resolved and registered before this returns, i.e. before any child starts."""
    env = dict(ctx.env)
    if ctx.dry_run:
        env[DRY_RUN_ENV] = "1"
    else:
        env.pop(DRY_RUN_ENV, None)
    patterns = compile_key_denylist(key_denylist(ctx.project))
    unprotected: list[str] = []
    step_env: Mapping[Any, Any] = step.env or {}
    for raw_name, value in step_env.items():
        name = str(raw_name)
        if not _ENV_NAME.match(name):
            raise HelperError(f"step {step.id}: env name {name!r} is not a valid environment variable name")
        if name.upper().startswith(RESERVED_ENV_PREFIX):
            raise HelperError(f"step {step.id}: env {name!r}: names starting with {RESERVED_ENV_PREFIX} are reserved")
        ref = _secret_ref(value)
        if ref is not None:
            if resolve_secret is None:
                from codeorca.providers import NO_PROVIDER_MESSAGE

                raise HelperError(
                    f"step {step.id}: env {name!r} is a secret reference ({ref}) but no secret resolver is "
                    f"configured for this run: {NO_PROVIDER_MESSAGE}"
                )
            try:
                resolved = resolve_secret(ref)
            except Exception as e:  # noqa: BLE001 - any resolver failure is this step's error
                raise HelperError(
                    f"step {step.id}: env {name!r}: cannot resolve {ref}: {registry.redact(str(e))}"
                ) from None
            if resolved is None:
                raise HelperError(f"step {step.id}: env {name!r}: {ref} resolved to nothing")
            text = str(resolved)
            if not registry.add(text) and not _protected(registry, text):
                unprotected.append(name)
            env[name] = text
            continue
        if isinstance(value, Mapping | list | tuple):
            raise HelperError(f"step {step.id}: env {name!r} must be a string or {{secret: ssm:/...}}")
        text = "" if value is None else str(value)
        if any(p.search(name) for p in patterns) and text:
            if not registry.add(text) and not _protected(registry, text):
                unprotected.append(name)
        env[name] = text
    return env, sorted(set(unprotected))


def _protected(registry: SecretRegistry, value: str) -> bool:
    """True when ``value`` is already scrubbed (registered earlier); False when it is too short to register."""
    return len(value.strip()) >= registry.min_length


def run_helper(
    step,
    ctx: StepContext,
    registry: SecretRegistry,
    resolve_secret: SecretResolver | None,
    build_argv: ArgvBuilder,
    *,
    preflight: Preflight | None = None,
    extra_env: Mapping[str, str] | None = None,
) -> StepResult:
    """Resolve the script, run ``preflight``, build the env (secrets registered), build the argv, run it."""
    root = project_root(ctx)
    script = resolve_script(step.id, step.script, root)
    if preflight is not None:
        preflight(script, ctx)
    env, unprotected = child_env(step, ctx, registry, resolve_secret)
    for name, value in (extra_env or {}).items():
        env.setdefault(name, value)
    args = [str(a) for a in (step.args or [])]
    argv = build_argv(script, args, ctx, env)
    rctx = redacting_context(ctx, registry)
    label = os.path.relpath(script, root)
    result = run_argv(step.id, argv, env, rctx, cwd=root, label=label)
    if unprotected:
        result.result["unprotected_env"] = unprotected
        result.result["warnings"] = [
            f"env {name!r} is shorter than {registry.min_length} characters and cannot be redacted"
            for name in unprotected
        ]
    return result
