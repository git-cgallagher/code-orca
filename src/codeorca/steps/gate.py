"""The ``gate`` step (plan sections 5.2 and 5.9): a human approval, bound to the plan files the run produced.

Three ways through a gate:

- ``--dry-run``: auto-approved, ``approver: dry-run``, and the result says so (``dry_run: true``). An apply in
  the same run is a dry-run apply too (skipped), and an apply refuses a dry-run approval in a real run.
- **Interactive** (stdin AND stdout are terminals): the rendered message (through the registry), the specs the
  run has staged so far (``<run>/specs/``) and every plan file with its sha256 are printed; the approver types
  ``approve`` or ``reject`` (case-insensitive; anything else asks again; end of input is a reject), then each
  typed field (``fields: {name: {type: string|int|bool, required, default}}``). The result records the
  ``decision``, the ``approver`` (the OS user), ``decided_at`` (UTC) and ``plans`` (``{step: {path, sha256}}``:
  the binding an ``apply`` checks). The step's ``timeout`` bounds the prompt; on expiry ``on_timeout`` decides:
  ``fail`` -> failed, ``cancel`` -> cancelled, ``warn`` -> skipped with a warning. **No timeout ever approves.**
- **Non-interactive** (no terminal, e.g. an agent or CI): ``non_interactive: wait`` stops the run (status
  ``waiting``, exit 3) with the plan binding recorded and ``codeorca resume <run-id> --approve`` as the way on;
  ``non_interactive: fail`` fails the step. ``codeorca.resume`` re-checks the terminal: there is no environment
  variable or flag that approves without one (the approval invariant).

Outputs: ``approved`` (bool), ``approver`` (str) and one output per typed field. A field whose name matches the
key denylist has its value registered before anything is written. The gate's rendered ``allow_delete_of`` is
recorded in the result too: the apply step reads it from there.
"""

from __future__ import annotations

import getpass
import os
import select
import sys
import threading
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from codeorca.adapters.terraform import plan_file_sha256
from codeorca.models import GateField
from codeorca.redact import SecretRegistry, compile_key_denylist
from codeorca.rundir import RunDir
from codeorca.runner import Executor, StepContext, StepResult
from codeorca.secrets import key_denylist

DECISIONS = ("approve", "reject")
DRY_RUN_APPROVER = "dry-run"
WAITING_REASON = "waiting for approval"

Prompt = Callable[[str, float | None], str]
"""``prompt(text, timeout_s)`` -> one line typed by the approver (without the newline). Raises ``EOFError`` at
end of input and ``TimeoutError`` when ``timeout_s`` passed with no answer."""


class FieldError(ValueError):
    """A gate field value is missing, unknown, or not of the declared type."""


def now_utc() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def parse_utc(text: str) -> datetime:
    when = datetime.fromisoformat(str(text))
    return when if when.tzinfo is not None else when.replace(tzinfo=UTC)


def current_user() -> str:
    try:
        return getpass.getuser()
    except (OSError, KeyError):  # no login name in a bare container: the uid still names who it was
        return f"uid:{os.getuid()}"


def is_terminal(isatty: Callable[[int], bool]) -> bool:
    """True only when stdin AND stdout are terminals. Nothing else (no env var, no flag) can make this true."""
    try:
        return bool(isatty(0)) and bool(isatty(1))
    except (OSError, ValueError):
        return False


def collect_plans(run_dir: RunDir, states: Mapping[str, Mapping[str, Any]]) -> dict[str, dict[str, str]]:
    """``{step_id: {path, sha256, planned_at}}`` for every succeeded step whose result names a plan file that
    exists. ``planned_at`` is when the runner recorded that step finished (run.json): ``gate.max_age`` bounds the
    plan's own age as well as the decision's, so a prompt left open for days cannot approve a stale plan."""
    plans: dict[str, dict[str, str]] = {}
    finished = {sid: (st or {}).get("finished") for sid, st in ((run_dir.read_run() or {}).get("steps") or {}).items()}
    for sid, state in states.items():
        if (state or {}).get("status") != "succeeded":
            continue
        result = run_dir.read_result(sid) or {}
        files = result.get("files") if isinstance(result.get("files"), dict) else {}
        plan_file = files.get("plan_file")
        if not plan_file:
            continue
        path = Path(str(plan_file)).resolve()
        if path.is_file():
            entry = {"path": str(path), "sha256": plan_file_sha256(path)}
            if finished.get(sid):
                entry["planned_at"] = str(finished[sid])
            plans[sid] = entry
    return plans


def plan_binding_problems(plans: Mapping[str, Mapping[str, str]]) -> list[str]:
    """What no longer matches a recorded binding (a missing file or a different sha256); empty when intact."""
    problems: list[str] = []
    for sid, entry in sorted(plans.items()):
        path = Path(str(entry.get("path", "")))
        if not path.is_file():
            problems.append(f"plan file of step {sid} ({path}) is gone")
        elif plan_file_sha256(path) != entry.get("sha256"):
            problems.append(f"plan file of step {sid} ({path}) changed since the gate recorded it")
    return problems


def collect_specs(run_dir: RunDir) -> list[str]:
    if not run_dir.specs_dir.is_dir():
        return []
    return sorted(str(p) for p in run_dir.specs_dir.rglob("*") if p.is_file())


def coerce_field(name: str, spec: GateField, raw: Any) -> Any:
    """A typed value from what was typed (or passed as ``--field k=v``). Raises ``FieldError``."""
    if spec.type == "string":
        if isinstance(raw, str):
            return raw
        raise FieldError(f"field {name!r}: expected a string")
    if spec.type == "int":
        if isinstance(raw, bool):
            raise FieldError(f"field {name!r}: expected an int, got a bool")
        try:
            return int(raw)
        except (TypeError, ValueError):
            raise FieldError(f"field {name!r}: {raw!r} is not an int") from None
    if isinstance(raw, bool):
        return raw
    lowered = str(raw).strip().lower()
    if lowered in ("true", "yes", "y"):
        return True
    if lowered in ("false", "no", "n"):
        return False
    raise FieldError(f"field {name!r}: {raw!r} is not true or false")


def coerce_fields(specs: Mapping[str, GateField], given: Mapping[str, Any]) -> dict[str, Any]:
    """Every declared field, typed: ``given`` wins, then the default; a required field with neither raises."""
    unknown = sorted(set(given) - set(specs))
    if unknown:
        raise FieldError(f"unknown field(s): {', '.join(unknown)}; declared: {', '.join(sorted(specs)) or '(none)'}")
    values: dict[str, Any] = {}
    for name, spec in specs.items():
        if name in given and given[name] is not None:
            values[name] = coerce_field(name, spec, given[name])
        elif spec.default is not None:
            values[name] = spec.default
        elif spec.required:
            raise FieldError(f"field {name!r} is required")
        else:
            values[name] = None
    return values


def register_fields(registry: SecretRegistry, values: Mapping[str, Any], denylist) -> None:
    """A field named like a secret (``ticket_token``) is registered before any record carries it."""
    patterns = compile_key_denylist(denylist)
    for name, value in values.items():
        if value is not None and not isinstance(value, bool) and any(p.search(name) for p in patterns):
            registry.add(str(value))


def terminal_prompt(text: str, timeout: float | None) -> str:
    """The default prompt: write ``text`` to stdout, read one line from stdin, bounded by ``timeout``."""
    sys.stdout.write(text)
    sys.stdout.flush()
    if timeout is not None:
        if timeout <= 0:
            raise TimeoutError
        try:
            ready, _, _ = select.select([sys.stdin], [], [], timeout)
        except (OSError, ValueError):  # not selectable (a non-fd stdin): fall back to a watchdog thread
            return _threaded_readline(timeout)
        if not ready:
            raise TimeoutError
    line = sys.stdin.readline()
    if line == "":
        raise EOFError
    return line.rstrip("\r\n")


def _threaded_readline(timeout: float) -> str:
    box: dict[str, str] = {}
    reader = threading.Thread(target=lambda: box.setdefault("line", sys.stdin.readline()), daemon=True)
    reader.start()
    reader.join(timeout)
    if reader.is_alive():
        raise TimeoutError
    line = box.get("line", "")
    if line == "":
        raise EOFError
    return line.rstrip("\r\n")


class _Deadline:
    def __init__(self, seconds: float | None):
        self.at = None if seconds is None else time.monotonic() + seconds

    def remaining(self) -> float | None:
        return None if self.at is None else max(0.0, self.at - time.monotonic())


def _base_result(step, ctx: StepContext, registry: SecretRegistry) -> dict[str, Any]:
    return {
        "message": registry.redact(str(step.message)),
        "plans": collect_plans(ctx.run_dir, ctx.context.get("steps") or {}),
        "specs": collect_specs(ctx.run_dir),
        "allow_delete_of": [str(a) for a in (step.allow_delete_of or [])],
        # when the gate started asking (or waiting): gate.max_age is measured from here too, on both paths
        "waiting_since": now_utc(),
    }


def _approved(step, result: dict[str, Any], approver: str, values: dict[str, Any]) -> StepResult:
    return StepResult(
        "succeeded",
        outputs={**values, "approved": True, "approver": approver},
        result={**result, "decision": "approve", "approver": approver, "decided_at": now_utc(), "fields": values},
    )


def _rejected(step, result: dict[str, Any], approver: str, reason: str = "rejected") -> StepResult:
    return StepResult(
        "failed",
        result={**result, "decision": "reject", "approver": approver, "decided_at": now_utc(), "fields": {}},
        error=f"gate {step.id}: {reason} by {approver}",
    )


def make_executor(
    registry: SecretRegistry,
    *,
    prompt: Prompt | None = None,
    isatty: Callable[[int], bool] | None = None,
    out: Callable[[str], None] | None = None,
    getuser: Callable[[], str] = current_user,
) -> Executor:
    """The ``gate`` executor bound to the run's registry. ``prompt``/``isatty``/``out`` are injectable for tests;
    the defaults read the real terminal (``terminal_prompt``, ``os.isatty``, ``print``)."""
    ask = prompt or terminal_prompt
    tty = isatty or os.isatty
    say = out or (lambda text: print(text, flush=True))

    def run_gate(step, ctx: StepContext) -> StepResult:
        return execute(step, ctx, registry, ask, tty, say, getuser)

    run_gate.__name__ = "run_gate"
    return run_gate


def execute(
    step,
    ctx: StepContext,
    registry: SecretRegistry,
    ask: Prompt,
    tty: Callable[[int], bool],
    say: Callable[[str], None],
    getuser: Callable[[], str],
) -> StepResult:
    base = _base_result(step, ctx, registry)
    specs: Mapping[str, GateField] = step.fields or {}
    denylist = key_denylist(ctx.project)
    if ctx.dry_run:
        values = {name: spec.default for name, spec in specs.items()}  # nobody typed anything: defaults only
        result = _approved(
            step, {**base, "dry_run": True, "note": "auto-approved: --dry-run"}, DRY_RUN_APPROVER, values
        )
        say(f"gate {step.id}: auto-approved (--dry-run)")
        return result
    if not is_terminal(tty):
        if step.non_interactive == "fail":
            return StepResult(
                "failed",
                result={**base, "decision": None, "reason": "no terminal"},
                error=f"gate {step.id}: no terminal to ask on (non_interactive: fail)",
            )
        return StepResult(
            "waiting",
            result={
                **base,
                "decision": None,
                "reason": WAITING_REASON,
                "resume": f"codeorca resume {ctx.run_id} --approve",
                "waiting_since": now_utc(),
            },
        )
    approver = getuser()
    _show(step, base, say)
    deadline = _Deadline(ctx.timeout)
    try:
        decision = _ask_decision(ask, say, deadline)
        if decision == "reject":
            return _rejected(step, base, approver)
        values = _ask_fields(specs, ask, say, deadline)
    except EOFError:
        return _rejected(step, base, approver, "rejected (end of input)")
    except TimeoutError:
        return _timed_out(step, base, ctx.timeout)
    register_fields(registry, values, denylist)
    return _approved(step, base, approver, values)


def _show(step, base: Mapping[str, Any], say: Callable[[str], None]) -> None:
    lines = [f"gate {step.id}: {base['message']}"]
    if base["specs"]:
        lines.append("specs written by this run:")
        lines.extend(f"  {p}" for p in base["specs"])
    if base["plans"]:
        lines.append("plan files (the approval binds to these sha256):")
        lines.extend(f"  {sid}: {e['path']}  sha256 {e['sha256']}" for sid, e in sorted(base["plans"].items()))
    if base["allow_delete_of"]:
        lines.append("deletes waived by this gate: " + ", ".join(base["allow_delete_of"]))
    say("\n".join(lines))


def _ask_decision(ask: Prompt, say: Callable[[str], None], deadline: _Deadline) -> str:
    while True:
        answer = ask("type approve or reject: ", deadline.remaining()).strip().lower()
        if answer in DECISIONS:
            return answer
        say("please type exactly 'approve' or 'reject'")


def _ask_fields(
    specs: Mapping[str, GateField], ask: Prompt, say: Callable[[str], None], deadline: _Deadline
) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for name, spec in specs.items():
        hint = spec.type + (", required" if spec.required else "")
        if spec.default is not None:
            hint += f", default {spec.default!r}"
        while True:
            raw = ask(f"{name} ({hint}): ", deadline.remaining()).strip()
            if raw == "":
                if spec.default is not None:
                    values[name] = spec.default
                    break
                if spec.required:
                    say(f"{name} is required")
                    continue
                values[name] = None
                break
            try:
                values[name] = coerce_field(name, spec, raw)
                break
            except FieldError as e:
                say(str(e))
    return values


def _timed_out(step, base: dict[str, Any], timeout: float | None) -> StepResult:
    detail = f"gate {step.id}: no decision within {timeout:g}s (on_timeout: {step.on_timeout})"
    result = {**base, "decision": None, "timed_out": True}
    if step.on_timeout == "cancel":
        return StepResult("cancelled", result=result, error=detail)
    if step.on_timeout == "warn":
        return StepResult("skipped", result={**result, "warning": detail}, error=None)
    return StepResult("failed", result=result, error=detail)


__all__ = [
    "DECISIONS",
    "DRY_RUN_APPROVER",
    "FieldError",
    "Prompt",
    "coerce_field",
    "coerce_fields",
    "collect_plans",
    "collect_specs",
    "current_user",
    "is_terminal",
    "make_executor",
    "now_utc",
    "parse_utc",
    "plan_binding_problems",
    "register_fields",
    "terminal_prompt",
]
