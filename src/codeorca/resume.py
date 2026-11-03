"""``codeorca resume <run-id> --approve | --reject`` (plan sections 5.3 and 5.9): decide a waiting gate, then
finish the run from its persisted state.

**The approval invariant**: an agent-launched run can reach exit 3 at a gate and nothing further. ``resume``
refuses unless stdin AND stdout are terminals, for either decision. There is deliberately no environment
variable and no keyword (``force=``, ``yes=`` ...) that skips the check: ``isatty`` is injectable for tests
only, and the CLI never passes it.

Refusals (``ResumeRefused``, nothing is written):

- no terminal; the run is not ``waiting``; another resume holds the run (``<run>/.resume.lock``);
- the workflow changed since the run stopped (``workflow_sha256`` in run.json);
- approve only: the gate has waited longer than ``project.gate.max_age`` (a fresh plan is needed: start a new
  run), or a plan file the gate recorded is gone or no longer matches its sha256 (tamper check);
- a typed field is unknown, mistyped, or required and missing;
- a remaining step needs an input that run.json holds redacted (an input whose name matched the key denylist,
  or whose value was registered) and ``secret_inputs`` does not supply it again; a supplied value that does not
  match what the run recorded (part by part for a partially redacted string or a list/map input:
  ``matches_recorded``), or names an input that was not redacted, is refused too; the refusal never quotes a
  typed value.

On approve the gate becomes ``succeeded`` (``decision``, ``approver``, ``decided_at``, ``fields``; outputs
``approved``/``approver``/the fields); on reject it becomes ``failed`` and its dependents are ``omitted``. Then
the runner continues: completed steps are replayed from run.json (never re-executed), the steps that never ran
run, and ``finally`` runs once. run.json gains ``resumes`` (``{gate, decision, approver, resumed_at}``) and the
latest ``resumed_at``/``decision``.

Integration contract: build the registry as ``codeorca run`` does, register the re-supplied secret inputs
(``registry=`` here does that, or ``seed_inputs`` before the call), and pass the same ``executors``/``stream``/
``redact``/``env`` the run would get. A later gate in the same run prompts on the terminal (it is one).
"""

from __future__ import annotations

import fcntl
import os
import re
import time
from collections.abc import Callable, Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from codeorca.config import load_workflow
from codeorca.expr import ExpressionError, render_tree
from codeorca.models import Workflow
from codeorca.project import Project
from codeorca.redact import KEY_PLACEHOLDER, PLACEHOLDER_RE, SecretRegistry
from codeorca.rundir import RunDir
from codeorca.runner import Executor, InputError, RunError, Runner, StepResult, coerce_input, parse_duration
from codeorca.runner import workflow_sha256 as digest_workflow
from codeorca.steps.gate import (
    FieldError,
    coerce_fields,
    current_user,
    is_terminal,
    now_utc,
    parse_utc,
    plan_binding_problems,
    register_fields,
)

DEFAULT_MAX_AGE = "24h"
LOCK_FILE = ".resume.lock"
TTY_REFUSAL = (
    "resume needs an interactive terminal on stdin and stdout: an agent-launched or piped run stops at the gate "
    "(exit 3) and nothing further. There is no flag or environment variable that bypasses this; run "
    "`codeorca resume` yourself in a terminal."
)


class ResumeRefused(RunError):
    """The run cannot be resumed as asked; nothing was changed."""


def resume(
    project: Project | None,
    run_dir: RunDir,
    decision: str,
    *,
    fields: Mapping[str, Any] | None = None,
    executors: Mapping[str, Executor],
    isatty: Callable[[int], bool] = os.isatty,
    secret_inputs: Mapping[str, Any] | None = None,
    workflow: Workflow | None = None,
    env: Mapping[str, str] | None = None,
    stream: Callable[[str, str], str] | None = None,
    redact: Callable[[Any], Any] | None = None,
    registry: SecretRegistry | None = None,
    cwd: Path | None = None,
    getuser: Callable[[], str] = current_user,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    """Decide the waiting gate of ``run_dir`` and finish the run; returns the run's exit code (0/1/3)."""
    if decision not in ("approve", "reject"):
        raise ValueError(f"decision must be 'approve' or 'reject', not {decision!r}")
    if not is_terminal(isatty):
        raise ResumeRefused(TTY_REFUSAL)
    lock_path = run_dir.path / LOCK_FILE
    with open(lock_path, "a+", encoding="utf-8") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ResumeRefused(f"run {run_dir.run_id} is being resumed by another process") from None
        try:
            return _resume_locked(
                project,
                run_dir,
                decision,
                fields=dict(fields or {}),
                executors=executors,
                secret_inputs=dict(secret_inputs or {}),
                workflow=workflow,
                env=env,
                stream=stream,
                redact=redact,
                registry=registry,
                cwd=cwd,
                getuser=getuser,
                sleep=sleep,
            )
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _resume_locked(
    project: Project | None,
    run_dir: RunDir,
    decision: str,
    *,
    fields: dict[str, Any],
    executors: Mapping[str, Executor],
    secret_inputs: dict[str, Any],
    workflow: Workflow | None,
    env,
    stream,
    redact,
    registry: SecretRegistry | None,
    cwd: Path | None,
    getuser: Callable[[], str],
    sleep,
) -> int:
    record = run_dir.read_run()
    if not record:
        raise ResumeRefused(f"run {run_dir.run_id}: no run.json")
    if record.get("status") != "waiting":
        raise ResumeRefused(f"run {run_dir.run_id} is {record.get('status')!r}, not waiting at a gate")
    workflow = workflow or _load_workflow(project, str(record.get("workflow") or ""))
    recorded_digest = record.get("workflow_sha256")
    if recorded_digest and recorded_digest != digest_workflow(workflow):
        raise ResumeRefused(f"workflow {workflow.name!r} changed since run {run_dir.run_id} stopped; start a new run")
    states = record.get("steps") or {}
    waiting = [sid for sid, st in states.items() if (st or {}).get("status") == "waiting"]
    steps = {s.id: s for s in [*workflow.steps, *workflow.finally_]}
    if len(waiting) != 1 or waiting[0] not in steps or steps[waiting[0]].type != "gate":
        raise ResumeRefused(f"run {run_dir.run_id}: expected exactly one waiting gate, found {waiting or 'none'}")
    gate_id = waiting[0]
    gate = steps[gate_id]
    gate_result = dict(run_dir.read_result(gate_id) or {})

    values: dict[str, Any] = {}
    if decision == "approve":
        _check_age(project, gate_id, gate_result, states[gate_id])
        problems = plan_binding_problems(gate_result.get("plans") or {})
        if problems:
            raise ResumeRefused(f"gate {gate_id}: {'; '.join(problems)}; re-plan in a new run")
        try:
            values = coerce_fields(gate.fields, fields)
        except FieldError as e:
            raise ResumeRefused(f"gate {gate_id}: {e}") from None
    elif fields:
        raise ResumeRefused("--field is for --approve only")

    remaining = remaining_steps(workflow, record)
    inputs, needed_vars = _resolve_inputs(workflow, record, remaining, secret_inputs, registry)

    runner = Runner.restore(
        project,
        workflow,
        record,
        run_dir,
        executors,
        inputs=inputs,
        env=env,
        stream=stream,
        redact=redact,
        sleep=sleep,
        cwd=cwd,
    )
    _rerender_vars(runner, workflow, needed_vars)
    if registry is not None:
        from codeorca.secrets import key_denylist

        register_fields(registry, values, key_denylist(project))

    approver = getuser()
    decided_at = now_utc()
    kept = {k: v for k, v in gate_result.items() if k not in ("status", "attempts", "reason", "resume")}
    if decision == "approve":
        result = StepResult(
            "succeeded",
            outputs={**values, "approved": True, "approver": approver},
            result={
                **kept,
                "decision": "approve",
                "approver": approver,
                "decided_at": decided_at,
                "fields": values,
                "resumed": True,
            },
        )
    else:
        result = StepResult(
            "failed",
            result={**kept, "decision": "reject", "approver": approver, "decided_at": decided_at, "resumed": True},
            error=f"gate {gate_id}: rejected by {approver}",
        )
    runner.add_resume({"gate": gate_id, "decision": decision, "approver": approver, "resumed_at": decided_at})
    runner.settle(gate_id, result)
    return runner.run()


def _load_workflow(project: Project | None, name: str) -> Workflow:
    if project is None or project.root is None or not name:
        raise ResumeRefused("cannot find the run's workflow; pass it explicitly")
    for suffix in (".yaml", ".yml"):
        path = project.root / project.workflows_dir / f"{name}{suffix}"
        if path.is_file():
            return load_workflow(path)
    raise ResumeRefused(f"workflow {name!r} not found under {project.root / project.workflows_dir}")


def _check_age(project: Project | None, gate_id: str, gate_result: Mapping[str, Any], state: Mapping[str, Any]):
    since_text = gate_result.get("waiting_since") or state.get("finished") or state.get("started")
    if not since_text:
        raise ResumeRefused(f"gate {gate_id}: no waiting time recorded; start a new run")
    max_age_text = project.gate.max_age if project is not None else DEFAULT_MAX_AGE
    # the oldest of: when the gate started waiting, and when each plan it recorded was made
    times = [parse_utc(str(since_text))]
    for entry in (gate_result.get("plans") or {}).values():
        if isinstance(entry, Mapping) and entry.get("planned_at"):
            times.append(parse_utc(str(entry["planned_at"])))
    age = (datetime.now(UTC) - min(times)).total_seconds()
    if age > parse_duration(max_age_text):
        raise ResumeRefused(
            f"gate {gate_id} has waited {age / 3600:.1f}h, longer than gate.max_age {max_age_text}: the plan it "
            "would approve is stale; a fresh plan is needed (start a new run)"
        )


# --- redacted inputs --------------------------------------------------------------------------------------------


def is_redacted(value: Any) -> bool:
    """True when a persisted value is (or holds) a redaction marker: it cannot be replayed."""
    if isinstance(value, str):
        return value == KEY_PLACEHOLDER or bool(PLACEHOLDER_RE.search(value))
    if isinstance(value, dict):
        return any(is_redacted(v) for v in value.values())
    if isinstance(value, list | tuple):
        return any(is_redacted(v) for v in value)
    return False


def _strings(obj: Any) -> Iterable[str]:
    if isinstance(obj, BaseModel):
        obj = obj.model_dump(by_alias=True)
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield str(k)
            yield from _strings(v)
    elif isinstance(obj, list | tuple):
        for v in obj:
            yield from _strings(v)


def _leaves(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for v in value.values():
            yield from _leaves(v)
    elif isinstance(value, list | tuple):
        for v in value:
            yield from _leaves(v)
    elif value is not None and not isinstance(value, bool):
        yield str(value)


_WHOLE = object()


def _references(texts: Iterable[str], namespace: str) -> set[str] | object:
    """Names under ``namespace`` (``inputs``/``vars``) the texts reference; ``_WHOLE`` when the namespace itself
    is used as a value (``inputs | tojson``), which needs every name."""
    attr = re.compile(rf"\b{namespace}\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)")
    item = re.compile(rf"\b{namespace}\s*\[\s*['\"]([^'\"]+)['\"]\s*\]")
    bare = re.compile(rf"\b{namespace}\b(?!\s*[.\[])")
    names: set[str] = set()
    for text in texts:
        if bare.search(text):
            return _WHOLE
        names.update(attr.findall(text))
        names.update(item.findall(text))
    return names


def remaining_steps(workflow: Workflow, record: Mapping[str, Any]) -> list:
    """The steps (``finally`` included) that have no status in run.json yet."""
    states = record.get("steps") or {}
    return [s for s in [*workflow.steps, *workflow.finally_] if (states.get(s.id) or {}).get("status") is None]


def _used_names(workflow: Workflow, remaining: list) -> tuple[set[str], set[str]]:
    """(input names, var names) the remaining steps reference, directly or through a var."""
    step_texts = [t for s in remaining for t in _strings(s)]
    var_refs = _references(step_texts, "vars")
    var_names = set(workflow.vars) if var_refs is _WHOLE else set(var_refs) & set(workflow.vars)  # type: ignore[arg-type]
    var_texts = [t for name in var_names for t in _strings(workflow.vars[name])]
    input_refs = _references([*step_texts, *var_texts], "inputs")
    used = set(workflow.inputs) if input_refs is _WHOLE else set(input_refs)  # type: ignore[arg-type]
    return used, var_names


def needed_secret_inputs(workflow: Workflow, record: Mapping[str, Any]) -> list[str]:
    """The inputs run.json holds redacted that a remaining step (or a var it uses) references: what a resume must
    be given again (``secret_inputs``). The CLI asks for them on the terminal, never through a flag."""
    persisted = dict(record.get("inputs") or {})
    redacted = {name for name, value in persisted.items() if is_redacted(value)}
    used, _ = _used_names(workflow, remaining_steps(workflow, record))
    return sorted(used & redacted & set(workflow.inputs))


def _resolve_inputs(
    workflow: Workflow,
    record: Mapping[str, Any],
    remaining: list,
    secret_inputs: Mapping[str, Any],
    registry: SecretRegistry | None,
) -> tuple[dict[str, Any], set[str]]:
    """The persisted inputs with the re-supplied secrets overlaid; also the var names the remaining steps use."""
    persisted = dict(record.get("inputs") or {})
    redacted = {name for name, value in persisted.items() if is_redacted(value)}
    unknown = sorted(set(secret_inputs) - set(workflow.inputs))
    if unknown:
        raise ResumeRefused(f"unknown secret input(s): {', '.join(unknown)}")
    not_redacted = sorted(set(secret_inputs) - redacted)
    if not_redacted:
        raise ResumeRefused(
            f"input(s) {', '.join(not_redacted)} were recorded in clear; a resume replays them and cannot change them"
        )
    used, var_names = _used_names(workflow, remaining)
    missing = sorted((used & redacted) - set(secret_inputs))
    if missing:
        raise ResumeRefused(
            "the remaining steps need input(s) that run.json holds redacted: "
            + ", ".join(missing)
            + "; supply them again (secret inputs are never persisted in clear)"
        )
    inputs = dict(persisted)
    for name, raw in secret_inputs.items():
        if registry is not None:
            # before coercion: whatever goes wrong next, nothing printed or written may carry what was typed
            for leaf in {str(raw), *_leaves(raw)}:
                registry.add(leaf)
        try:
            value = coerce_input(name, workflow.inputs[name], raw)
        except InputError:
            # value-free: InputError quotes the value, and a short one is not registered
            raise ResumeRefused(
                f"input {name!r}: the value typed again is not a valid {workflow.inputs[name].type}"
                + (" (or not one of its enum values)" if workflow.inputs[name].enum is not None else "")
            ) from None
        recorded = persisted.get(name)
        if registry is not None and not matches_recorded(value, recorded, registry):
            raise ResumeRefused(f"input {name!r} does not match the value the run started with")
        if registry is not None:
            for leaf in _leaves(value):
                registry.add(leaf)
        inputs[name] = value
    needed_vars = {name for name in var_names if is_redacted((record.get("vars") or {}).get(name))}
    return inputs, needed_vars


def matches_recorded(value: Any, recorded: Any, registry: SecretRegistry) -> bool:
    """True when ``value`` is what the run persisted as ``recorded`` (the same shape, every clear part equal, every
    ``<redacted:hmac:...>`` standing for the matching part of ``value``). A ``<redacted:key>`` leaf (redacted by
    its NAME) cannot be checked and matches anything; a partially redacted string (``u:<redacted:...>@h``) or a
    list/map input is checked part by part, so a re-supplied value cannot differ from the one the plan was made
    with."""
    if isinstance(recorded, str) and recorded == KEY_PLACEHOLDER:
        return True
    if isinstance(recorded, dict):
        if not isinstance(value, dict) or len(value) != len(recorded):
            return False
        unmatched = dict(recorded)
        for key, item in value.items():
            rkey = key if key in unmatched else None
            if rkey is None:
                rkey = next(
                    (rk for rk in unmatched if isinstance(rk, str) and _matches_text(str(key), rk, registry)), None
                )
            if rkey is None or not matches_recorded(item, unmatched.pop(rkey), registry):
                return False
        return not unmatched
    if isinstance(recorded, list):
        return (
            isinstance(value, list)
            and len(value) == len(recorded)
            and all(matches_recorded(v, r, registry) for v, r in zip(value, recorded, strict=True))
        )
    if isinstance(recorded, str) and PLACEHOLDER_RE.search(recorded):
        return isinstance(value, str) and _matches_text(value, recorded, registry)
    return value == recorded


def _matches_text(text: str, template: str, registry: SecretRegistry) -> bool:
    """``text`` matches ``template`` (literal parts plus placeholders); every split is tried."""
    tokens: list[tuple[bool, str]] = []
    pos = 0
    for m in PLACEHOLDER_RE.finditer(template):
        if m.start() > pos:
            tokens.append((False, template[pos : m.start()]))
        tokens.append((True, m.group(0)))
        pos = m.end()
    if pos < len(template):
        tokens.append((False, template[pos:]))

    def stands_for(part: str, placeholder: str) -> bool:
        return bool(part) and (registry.placeholder(part) == placeholder or registry.redact(part) == placeholder)

    def walk(i: int, at: int) -> bool:
        if i == len(tokens):
            return at == len(text)
        is_placeholder, piece = tokens[i]
        if not is_placeholder:
            return text.startswith(piece, at) and walk(i + 1, at + len(piece))
        return any(stands_for(text[at:end], piece) and walk(i + 1, end) for end in range(at + 1, len(text) + 1))

    return walk(0, 0)


def _rerender_vars(runner: Runner, workflow: Workflow, names: set[str]) -> None:
    """A var that a remaining step uses and run.json holds redacted is rendered again from the full inputs."""
    if not names:
        return
    ctx = runner.context(with_steps=False)
    for name in sorted(names):
        try:
            runner.vars[name] = render_tree(workflow.vars[name], ctx)
        except ExpressionError as e:
            raise ResumeRefused(f"vars.{name}: {e}") from None


__all__ = ["ResumeRefused", "TTY_REFUSAL", "is_redacted", "needed_secret_inputs", "remaining_steps", "resume"]
