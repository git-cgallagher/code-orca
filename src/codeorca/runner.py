"""The DAG runner (plan sections 5.2 and 5.3): sequential ``graphlib`` scheduling, one process.

Step statuses and their propagation (the plan's step-semantics table):

- ``succeeded`` / ``failed`` (the executor ran, exit status decides) / ``errored`` (the executor raised, timed out,
  or the step's outputs could not be evaluated).
- ``omitted``: a step in ``needs`` did not succeed (``failed``/``errored`` with ``on_failure: continue`` still
  counts as met) and ``when`` names no override function (``always()``, ``failure()``, ``cancelled()``).
- ``skipped``: ``when`` evaluated to ``False``.
- ``cancelled``: ``fail_fast`` stopped scheduling after a blocking failure; dependents of the failed step are
  ``omitted``, unrelated steps are ``cancelled``; a step whose ``when`` names an override function is still
  evaluated and runs if it is ``True``. A step whose *executor* returns ``cancelled`` (a gate's
  ``on_timeout: cancel``) cancels the run: later unrelated steps are ``cancelled``, ``cancelled()`` is true, and
  the run is ``failed`` (exit 1): a cancelled approval is not success.
- ``waiting``: an executor (a gate) asked the run to stop; scheduling stops, the run is persisted, exit 3.
  ``finally`` steps do NOT run at a wait: the run is not over, and they run once, at its real end, after
  ``codeorca resume`` (``codeorca.resume``) decided the gate.
- ``cached``: reserved for ``cache:`` (not implemented in this phase).

``redact`` (optional) is applied to every record the runner persists: run.json (inputs, vars, step states),
each ``result.json`` and ``outputs/<id>.json``. Integration passes the registry scrub so a secret handed in as
an input or echoed by a step never reaches the run directory in clear.

Outputs are evaluated from the executor's typed ``result`` only for ``succeeded`` steps; every other status
leaves ``steps.<id>.outputs`` as ``None`` so a bare reference raises and ``| default()`` works (expr.py).

Resume (``Runner.restore``): a runner built from a persisted run.json replays every step that already has a
status (its status and outputs come from run.json, the executor is not called again), runs the steps that never
ran, then ``finally``. ``codeorca.resume`` decides the waiting gate first (``settle``).

Deliberately NOT implemented in this phase (the runner raises ``NotImplementedInPhase`` when a workflow uses
them): ``for_each``, ``cache: {sources, status}``, ``max_parallel > 1``.

Exit codes: 0 every step succeeded (or was skipped/omitted/failed-with-continue), 1 a blocking failure,
3 waiting at a gate.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from graphlib import TopologicalSorter
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel

from codeorca import __version__
from codeorca.expr import ExpressionError, evaluate_when, names_override_function, render_tree, status_functions
from codeorca.models import Input, Workflow
from codeorca.project import Project
from codeorca.rundir import RunDir

Status = Literal["succeeded", "failed", "errored", "skipped", "omitted", "cached", "cancelled", "waiting"]
STATUSES: frozenset[str] = frozenset(
    {"succeeded", "failed", "errored", "skipped", "omitted", "cached", "cancelled", "waiting"}
)
MET_STATUSES = frozenset({"succeeded", "cached"})
NOT_RUN_STATUSES = frozenset({"skipped", "omitted", "cancelled"})

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_WAITING = 3

# The HMAC redaction key: stripped from every child environment (secrets.py owns the name; no import cycle here).
REDACTION_KEY_ENV_VAR = "CODEORCA_REDACTION_KEY"

# Control fields the runner owns; everything else on a step is type-specific and rendered before execution.
CONTROL_FIELDS = frozenset(
    {"id", "type", "needs", "when", "timeout", "retry", "on_failure", "for_each", "outputs", "cache"}
)

_DURATION_UNIT = {"ns": 1e-9, "us": 1e-6, "ms": 1e-3, "s": 1.0, "m": 60.0, "h": 3600.0}
_DURATION_PART = re.compile(r"(\d+(?:\.\d+)?)(ns|us|ms|s|m|h)")


class RunError(RuntimeError):
    """The run could not start (bad inputs, unsupported features)."""


class InputError(RunError):
    """A workflow input is missing, unknown, of the wrong type, or not in its enum."""


class NotImplementedInPhase(RunError):
    """The workflow uses a feature the runner does not implement yet."""


class StepError(Exception):
    """Raised by an executor for an infrastructure failure (not a non-zero exit); the step becomes ``errored``."""


class StepTimeout(StepError):
    """The step exceeded its ``timeout``."""


def parse_duration(text: str) -> float:
    """Go duration (``1h30m``, ``500ms``) to seconds. Accepts the same subset as the ``Duration`` model type."""
    if not isinstance(text, str) or not text:
        raise ValueError(f"invalid duration {text!r}")
    pos, total = 0, 0.0
    for m in _DURATION_PART.finditer(text):
        if m.start() != pos:
            raise ValueError(f"invalid duration {text!r}")
        total += float(m.group(1)) * _DURATION_UNIT[m.group(2)]
        pos = m.end()
    if pos != len(text):
        raise ValueError(f"invalid duration {text!r}")
    return total


@dataclass
class StepResult:
    """What an executor returns. ``result`` is the typed object the step's ``outputs:`` expressions read."""

    status: str
    outputs: dict[str, Any] = field(default_factory=dict)  # outputs an executor sets itself (implicit outputs)
    result: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def __post_init__(self):
        if self.status not in STATUSES:
            raise ValueError(f"unknown step status {self.status!r}")


@dataclass
class StepContext:
    """Everything an executor may need. ``step`` is the step model with its type-specific fields already
    rendered; ``context`` is the data context the expressions see; ``stream`` is the optional line hook
    (``stream(name, line) -> line``) integration uses to attach the redactor."""

    step: BaseModel
    run_dir: RunDir
    step_dir: Path
    run_id: str
    context: dict[str, Any]
    project: Project | None
    dry_run: bool = False
    timeout: float | None = None
    attempt: int = 1
    env: dict[str, str] = field(default_factory=dict)
    stream: Callable[[str, str], str] | None = None
    # the whole workflow, for executors that need the graph (an apply checks the gates it transitively needs)
    workflow: Workflow | None = None

    def line_filter(self, name: str) -> Callable[[str], str] | None:
        if self.stream is None:
            return None
        hook = self.stream
        return lambda line: hook(name, line)


Executor = Callable[[Any, StepContext], StepResult]


def executor_cancelled(state: Mapping[str, Any]) -> bool:
    """A step its executor cancelled (status ``cancelled`` with an error: a gate's ``on_timeout: cancel``), as
    opposed to one the runner cancelled without running it (``fail_fast``: no error recorded)."""
    return state.get("status") == "cancelled" and bool(state.get("error"))


def _render_obj(obj: Any, ctx: Mapping[str, Any]) -> Any:
    if isinstance(obj, BaseModel):
        return obj.model_copy(update={name: _render_obj(getattr(obj, name), ctx) for name in type(obj).model_fields})
    return render_tree(obj, ctx)


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def workflow_sha256(workflow: Workflow) -> str:
    """A digest of the validated workflow: a resume refuses when the workflow changed since the run stopped."""
    return hashlib.sha256(workflow.model_dump_json(by_alias=True).encode("utf-8")).hexdigest()


def project_sha256(project: Project | None) -> str | None:
    """A digest of the loaded project (codeorca.yaml as validated): what decides whether an approved apply may
    proceed (``policy``, ``gate.max_age``, ``backend``, ``stacks``) comes from it, so a resume refuses when it
    changed since the run stopped, as it does for the workflow."""
    if project is None:
        return None
    return hashlib.sha256(project.model_dump_json(by_alias=True).encode("utf-8")).hexdigest()


def _git_sha(cwd: Path | None) -> str | None:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=cwd, capture_output=True, text=True, timeout=5, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip() if out.returncode == 0 else None


def coerce_input(name: str, spec: Input, value: Any) -> Any:
    """CLI inputs arrive as strings; coerce to the declared type (JSON for list/map), then check the enum."""
    kind = spec.type
    try:
        if kind == "string":
            if not isinstance(value, str):
                raise InputError(f"input {name!r}: expected a string, got {type(value).__name__}")
        elif kind == "int":
            if isinstance(value, bool):
                raise InputError(f"input {name!r}: expected an int, got bool")
            value = int(value) if isinstance(value, int | str) else _bad(name, "int", value)
        elif kind == "bool":
            if isinstance(value, str):
                lowered = value.strip().lower()
                if lowered not in {"true", "false"}:
                    raise InputError(f"input {name!r}: expected true or false, got {value!r}")
                value = lowered == "true"
            elif not isinstance(value, bool):
                _bad(name, "bool", value)
        elif kind == "list":
            if isinstance(value, str):
                value = json.loads(value)
            if not isinstance(value, list):
                _bad(name, "list", value)
        elif kind == "map":
            if isinstance(value, str):
                value = json.loads(value)
            if not isinstance(value, dict):
                _bad(name, "map", value)
    except (ValueError, json.JSONDecodeError) as e:
        if isinstance(e, InputError):
            raise
        raise InputError(f"input {name!r}: cannot read {value!r} as {kind}: {e}") from None
    if spec.enum is not None and value not in spec.enum:
        raise InputError(f"input {name!r}: {value!r} is not one of {spec.enum}")
    return value


def _bad(name: str, kind: str, value: Any):
    raise InputError(f"input {name!r}: expected {kind}, got {type(value).__name__}")


def resolve_inputs(workflow: Workflow, given: Mapping[str, Any]) -> dict[str, Any]:
    unknown = sorted(set(given) - set(workflow.inputs))
    if unknown:
        raise InputError(f"unknown input(s): {', '.join(unknown)}")
    resolved: dict[str, Any] = {}
    for name, spec in workflow.inputs.items():
        # ``None`` for an optional input is what a previous resolve produced: resolving twice is idempotent
        if name in given and given[name] is not None:
            resolved[name] = coerce_input(name, spec, given[name])
        elif spec.default is not None:
            resolved[name] = coerce_input(name, spec, spec.default)
        elif spec.required:
            raise InputError(f"input {name!r} is required")
        else:
            resolved[name] = None
    return resolved


class Runner:
    def __init__(
        self,
        project: Project | None,
        workflow: Workflow,
        inputs: Mapping[str, Any],
        run_dir: RunDir,
        executors: Mapping[str, Executor],
        dry_run: bool = False,
        *,
        env: Mapping[str, str] | None = None,
        stream: Callable[[str, str], str] | None = None,
        redact: Callable[[Any], Any] | None = None,
        sleep: Callable[[float], None] = time.sleep,
        cwd: Path | None = None,
        key_id: str | None = None,
        _restored: Mapping[str, Any] | None = None,
    ):
        self.project = project
        self.workflow = workflow
        self.run_dir = run_dir
        self.executors = dict(executors)
        self.dry_run = dry_run
        self.base_env = dict(env) if env is not None else dict(os.environ)
        self.stream = stream
        self.redact = redact  # applied to every record the runner persists (run.json, result.json, outputs)
        self.sleep = sleep
        self.cwd = cwd
        # a restored run keeps its persisted inputs verbatim: a redacted value (``<redacted:key>``) of an int
        # input must not be re-coerced; ``codeorca.resume`` overlays the secret inputs supplied again
        self.inputs = dict(inputs) if _restored is not None else resolve_inputs(workflow, inputs)
        self._check_supported()
        self.steps: dict[str, Any] = {s.id: s for s in workflow.steps}
        self.states: dict[str, dict[str, Any]] = {
            s.id: {"status": None, "outputs": None, "error": None, "attempts": 0}
            for s in [*workflow.steps, *workflow.finally_]
        }
        self.cancelled = False
        self.status: str = "running"
        self.started = _now()
        self.exit_code: int | None = None
        self.transient = [re.compile(p) for p in (project.policy.transient_errors if project else [])]
        self.workflow_sha256 = workflow_sha256(workflow)
        self.project_sha256 = project_sha256(project)
        self.resumes: list[dict[str, Any]] = []
        # which redaction key made the run's placeholders (``SecretRegistry.key_id``, never the key): a resume
        # with another key would make post-gate placeholders disagree with pre-gate ones, so it refuses
        self.key_id = key_id
        if _restored is not None:
            self._restore(_restored)
            return  # nothing is persisted until the resumed run starts (run.json stays the waiting record)
        self.git_sha = _git_sha(cwd)
        self.vars = self._render_vars()  # once, over the inputs only: run.json carries RESOLVED vars
        self.persist()  # the run exists on disk as soon as it is created

    @classmethod
    def restore(
        cls,
        project: Project | None,
        workflow: Workflow,
        record: Mapping[str, Any],
        run_dir: RunDir,
        executors: Mapping[str, Executor],
        *,
        inputs: Mapping[str, Any] | None = None,
        vars: Mapping[str, Any] | None = None,
        env: Mapping[str, str] | None = None,
        stream: Callable[[str, str], str] | None = None,
        redact: Callable[[Any], Any] | None = None,
        sleep: Callable[[float], None] = time.sleep,
        cwd: Path | None = None,
    ) -> Runner:
        """A runner over a persisted run (run.json ``record``): states, outputs, start time, git SHA and dry-run
        flag come from the record; ``inputs``/``vars`` default to the persisted ones (the caller passes them when
        it re-supplied redacted secret inputs). Steps that already have a status are replayed, not re-run."""
        runner = cls(
            project,
            workflow,
            dict(record.get("inputs") or {}) if inputs is None else inputs,
            run_dir,
            executors,
            bool(record.get("dry_run")),
            env=env,
            stream=stream,
            redact=redact,
            sleep=sleep,
            cwd=cwd,
            _restored=record,
        )
        if vars is not None:
            runner.vars = dict(vars)
        return runner

    def _restore(self, record: Mapping[str, Any]) -> None:
        if record.get("run_id") != self.run_dir.run_id:
            raise RunError(f"run.json names run {record.get('run_id')!r}, not {self.run_dir.run_id!r}")
        self.started = record.get("started") or self.started
        self.git_sha = record.get("git_sha")
        self.vars = dict(record.get("vars") or {})
        self.resumes = list(record.get("resumes") or [])
        self.key_id = record.get("redaction_key_id") or self.key_id
        persisted = record.get("steps") or {}
        for sid, state in self.states.items():
            if isinstance(persisted.get(sid), dict):
                state.update(persisted[sid])
        # what fail_fast decided before the stop still holds
        for s in [*self.workflow.steps, *self.workflow.finally_]:
            st = self.states[s.id]["status"]
            if st in ("failed", "errored") and s.on_failure != "continue" and self.workflow.fail_fast:
                self.cancelled = True
            if executor_cancelled(self.states[s.id]):
                self.cancelled = True

    def _render_vars(self) -> dict[str, Any]:
        """Workflow ``vars`` rendered over ``inputs``/``run``/``project`` (never ``steps``: a var is fixed for the
        whole run). A reference the context cannot satisfy is a ``RunError`` before anything runs."""
        ctx = self.context(with_steps=False)
        try:
            return render_tree(dict(self.workflow.vars), ctx)
        except ExpressionError as e:
            raise RunError(f"vars: {e}") from None

    # --- preconditions ---------------------------------------------------------------------------------------
    def _check_supported(self) -> None:
        for s in [*self.workflow.steps, *self.workflow.finally_]:
            if s.for_each is not None:
                raise NotImplementedInPhase(f"step {s.id}: for_each is not implemented in this phase")
            if s.cache is not None:
                raise NotImplementedInPhase(f"step {s.id}: cache is not implemented in this phase")
            if s.type not in self.executors:
                raise RunError(f"step {s.id}: no executor registered for type {s.type!r}")
        if self.project is not None and self.project.max_parallel != 1:
            raise NotImplementedInPhase("max_parallel > 1 is not implemented in this phase")

    # --- context ---------------------------------------------------------------------------------------------
    def context(self, extra: Mapping[str, Any] | None = None, *, with_steps: bool = True) -> dict[str, Any]:
        ctx: dict[str, Any] = {
            "inputs": dict(self.inputs),
            "run": {
                "id": self.run_dir.run_id,
                "status": self.status,
                "dir": str(self.run_dir.path),
                "dry_run": self.dry_run,
            },
            "project": self.project.project if self.project else None,
        }
        if with_steps:
            ctx["vars"] = dict(self.vars)
            ctx["steps"] = {sid: {"status": st["status"], "outputs": st["outputs"]} for sid, st in self.states.items()}
        if extra:
            ctx.update(extra)
        return ctx

    # --- the run ---------------------------------------------------------------------------------------------
    def run(self) -> int:
        """Run the workflow. Whatever escapes the scheduling loop (an interrupt, an executor raising something
        that is not an ``Exception``, a bug) still leaves run.json finished: status ``failed``, the step that was
        running ``cancelled`` with the reason, every step that never ran ``cancelled`` too."""
        try:
            return self._run()
        except BaseException as e:
            self._abort(e)
            raise

    def _abort(self, exc: BaseException) -> None:
        reason = "interrupted" if isinstance(exc, KeyboardInterrupt) else f"{type(exc).__name__}: {exc}"
        for state in self.states.values():
            if state["status"] is None:
                state["status"] = "cancelled"
                if state.get("started") and not state.get("finished"):
                    state["error"] = reason
                    state["finished"] = _now()
        self.status = "failed"
        self.exit_code = EXIT_FAILED
        self.persist(finished=True)

    def _run(self) -> int:
        self.status = "running"
        self.persist()
        sorter = TopologicalSorter(self.workflow.graph())
        sorter.prepare()
        waiting = False
        while sorter.is_active() and not waiting:
            ready = sorted(sorter.get_ready(), key=lambda sid: list(self.steps).index(sid))
            for sid in ready:
                if self.states[sid]["status"] is not None:
                    # a resumed run: this step finished before the stop; its status and outputs are replayed
                    sorter.done(sid)
                    if self.states[sid]["status"] == "waiting":
                        waiting = True
                        break
                    continue
                status = self._run_step(self.steps[sid], final=False)
                sorter.done(sid)
                if status == "waiting":
                    waiting = True
                    break
        if waiting:
            # the run is not over: finally steps run once, at the real end, after the gate is decided (resume)
            self.status = "waiting"
        else:
            self.status = "failed" if self._blocked() else "succeeded"
            for step in self.workflow.finally_:
                if self.states[step.id]["status"] is not None:
                    continue  # ran before a stop (a run.json written before finally moved to the real end)
                if self._run_step(step, final=True) == "waiting":
                    # the model refuses a gate in finally; should a waiting step get here anyway, it is an error,
                    # never a silent exit 0 with an unanswered gate
                    state = self.states[step.id]
                    state.update({"status": "errored", "error": "a step cannot wait in finally (no gate there)"})
                    self.persist()
            if self._blocked():
                self.status = "failed"
        self.exit_code = {"succeeded": EXIT_OK, "failed": EXIT_FAILED, "waiting": EXIT_WAITING}[self.status]
        self.persist(finished=True)
        return self.exit_code

    def _blocked(self) -> bool:
        """True when a step failed or errored without ``on_failure: continue``, or its executor cancelled it (a
        gate's ``on_timeout: cancel``: a cancelled approval is not success, so the run exits 1)."""
        for s in [*self.workflow.steps, *self.workflow.finally_]:
            state = self.states[s.id]
            if state["status"] in ("failed", "errored") and s.on_failure != "continue":
                return True
            if executor_cancelled(state):
                return True
        return False

    def _needs(self, step) -> tuple[bool, bool]:
        """(needs_met, needs_failed)."""
        met, failed = True, False
        for n in step.needs:
            st = self.states[n]["status"]
            if st in MET_STATUSES:
                continue
            if st in ("failed", "errored"):
                failed = True
                if self.steps[n].on_failure == "continue":
                    continue
            met = False
        return met, failed

    def _decide(self, step, final: bool) -> str | None:
        """Return the status to record without running, or None to run the step."""
        if final:
            # finally steps always run; their status functions describe the run, not a needs list
            needs_met, needs_failed, blocked = self.status == "succeeded", self.status == "failed", False
        else:
            needs_met, needs_failed = self._needs(step)
            blocked = self.cancelled or not needs_met
        if step.when is None:
            if not blocked:
                return None
            return "omitted" if not needs_met else "cancelled"
        if blocked and not names_override_function(step.when):
            return "omitted" if not needs_met else "cancelled"
        ctx = self.context(status_functions(needs_met, needs_failed, self.cancelled))
        try:
            wanted = evaluate_when(step.when, ctx)
        except ExpressionError as e:
            self.states[step.id]["error"] = str(e)
            return "errored"
        if wanted:
            return None
        if final:
            return "skipped"
        if not needs_met:
            return "omitted"
        return "cancelled" if self.cancelled else "skipped"

    def _run_step(self, step, final: bool) -> str:
        state = self.states[step.id]
        decided = self._decide(step, final)
        if decided is not None:
            state["status"] = decided
            self.run_dir.write_outputs(step.id, None)
            self._after_step(step)
            return decided

        state["started"] = _now()
        try:
            rendered = self._render_step(step)
        except ExpressionError as e:
            return self._finish(step, "errored", None, None, str(e))

        timeout = parse_duration(step.timeout) if step.timeout else None
        attempts = 1 + max(0, step.retry.limit)
        result: StepResult | None = None
        for attempt in range(1, attempts + 1):
            state["attempts"] = attempt
            result = self._execute(rendered, timeout, attempt)
            if result.status not in ("failed", "errored") or attempt == attempts:
                break
            if not self._retryable(step, result):
                break
            self.sleep(self._backoff(step, attempt))
        assert result is not None
        return self._record_result(step, result)

    def _record_result(self, step, result: StepResult) -> str:
        state = self.states[step.id]
        self.run_dir.write_result(
            step.id, self._scrub({"status": result.status, "attempts": state["attempts"], **result.result})
        )
        outputs: dict[str, Any] | None = None
        status = result.status
        error = result.error
        if status == "succeeded":
            try:
                outputs = self._outputs(step, result)
            except ExpressionError as e:
                status, error = "errored", str(e)
        return self._finish(step, status, outputs, result.result, error)

    def settle(self, step_id: str, result: StepResult) -> str:
        """Decide a step that is ``waiting`` (a gate, from ``codeorca.resume``): its result.json, outputs and
        status are recorded exactly as if its executor had returned ``result``; returns the final status."""
        state = self.states.get(step_id)
        if state is None or state["status"] != "waiting":
            raise RunError(f"step {step_id!r} is not waiting")
        if result.status == "waiting":
            raise RunError(f"step {step_id!r}: a waiting step must be decided, not left waiting")
        step = self.steps[step_id]
        state["status"] = None  # _finish sets it; _outputs must not see the stale 'waiting'
        return self._record_result(step, result)

    def add_resume(self, entry: Mapping[str, Any]) -> None:
        """Record one resume (``{gate, decision, approver, resumed_at}``) in run.json."""
        self.resumes.append(dict(entry))

    def _finish(self, step, status: str, outputs, result, error: str | None) -> str:
        state = self.states[step.id]
        state.update({"status": status, "outputs": outputs, "error": error, "finished": _now()})
        self.run_dir.write_outputs(step.id, self._scrub(outputs))
        self._after_step(step)
        return status

    def _after_step(self, step) -> None:
        state = self.states[step.id]
        st = state["status"]
        if st in ("failed", "errored") and step.on_failure != "continue" and self.workflow.fail_fast:
            self.cancelled = True
        if executor_cancelled(state):
            self.cancelled = True  # the run was cancelled (a gate's on_timeout: cancel): cancelled() is true
        self.persist()

    def _render_step(self, step):
        """Render the type-specific fields (never the control fields) and return a copy. The walk is over the
        model objects, not a dump, so nested models stay models; there is no re-validation, so a whole-expression
        template may yield a native bool/int/dict where the model said str (executors ``str()`` argv items)."""
        ctx = self.context()
        rendered = {
            name: _render_obj(getattr(step, name), ctx)
            for name in type(step).model_fields
            if name not in CONTROL_FIELDS
        }
        return step.model_copy(update=rendered)

    def _execute(self, rendered, timeout: float | None, attempt: int) -> StepResult:
        step_dir = self.run_dir.step_dir(rendered.id)
        env = {k: v for k, v in self.base_env.items() if k != REDACTION_KEY_ENV_VAR}  # no child needs the key
        env.update(
            {
                "CODEORCA_RUN_ID": self.run_dir.run_id,
                "CODEORCA_RUN_DIR": str(self.run_dir.path),
                "CODEORCA_STEP_ID": rendered.id,
                "CODEORCA_STEP_DIR": str(step_dir),
                "CODEORCA_OUTPUT_FILE": str(step_dir / "output.json"),
            }
        )
        if self.dry_run:
            env["CODEORCA_DRY_RUN"] = "1"
        # one output file per attempt: what a failed attempt wrote must not become a later attempt's output
        Path(env["CODEORCA_OUTPUT_FILE"]).unlink(missing_ok=True)
        ctx = StepContext(
            step=rendered,
            run_dir=self.run_dir,
            step_dir=step_dir,
            run_id=self.run_dir.run_id,
            context=self.context(),
            project=self.project,
            dry_run=self.dry_run,
            timeout=timeout,
            attempt=attempt,
            env=env,
            stream=self.stream,
            workflow=self.workflow,
        )
        try:
            return self.executors[rendered.type](rendered, ctx)
        except StepTimeout as e:
            return StepResult("errored", error=f"timeout: {e}")
        except Exception as e:  # noqa: BLE001 - an executor crash is the step's error, not the run's
            return StepResult("errored", error=f"{type(e).__name__}: {e}")

    def _retryable(self, step, result: StepResult) -> bool:
        policy = step.retry.policy
        if policy == "failure":
            return result.status in ("failed", "errored")
        if policy == "error":
            return result.status == "errored"
        text = result.error or ""
        return any(rx.search(text) for rx in self.transient)

    def _backoff(self, step, attempt: int) -> float:
        b = step.retry.backoff
        base_s = parse_duration(b.duration) if isinstance(b.duration, str) else float(b.duration)
        wait = base_s * (b.factor ** (attempt - 1))
        if b.max_duration is not None:
            cap = b.max_duration
            wait = min(wait, parse_duration(cap) if isinstance(cap, str) else float(cap))
        return wait

    def _outputs(self, step, result: StepResult) -> dict[str, Any]:
        ctx = self.context({"result": result.result})
        outputs: dict[str, Any] = dict(result.outputs)
        for name, template in step.outputs.items():
            value = render_tree(template, ctx)
            try:
                # outputs are persisted and replayed as JSON; a range, dict_items or nested Undefined is an error
                # at the producer, not a crash at persist time
                value = json.loads(json.dumps(value))
            except (TypeError, ValueError) as e:
                raise ExpressionError(f"output {name!r} of step {step.id}: not JSON-serializable: {e}") from None
            outputs[name] = value
        return outputs

    # --- persistence -----------------------------------------------------------------------------------------
    def record(self, finished: bool = False) -> dict[str, Any]:
        last = self.resumes[-1] if self.resumes else {}
        return {
            "run_id": self.run_dir.run_id,
            "codeorca": __version__,
            "workflow": self.workflow.name,
            "workflow_sha256": self.workflow_sha256,
            "project_sha256": self.project_sha256,
            "redaction_key_id": self.key_id,
            "project": self.project.project if self.project else None,
            "git_sha": self.git_sha,
            "dry_run": self.dry_run,
            "inputs": self.inputs,
            "vars": self.vars,
            "status": self.status,
            "exit_code": self.exit_code,
            "started": self.started,
            "finished": _now() if finished else None,
            "steps": self.states,
            "resumes": self.resumes,
            "resumed_at": last.get("resumed_at"),
            "decision": last.get("decision"),
        }

    def persist(self, finished: bool = False) -> None:
        self.run_dir.write_run(self._scrub(self.record(finished)))

    def _scrub(self, data: Any) -> Any:
        return self.redact(data) if self.redact is not None else data
