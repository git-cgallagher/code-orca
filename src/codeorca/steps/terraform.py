"""The ``terraform`` step (plan section 5.4) and the shared stack session ``codeorca drift`` reuses.

What a step does, in order:

1. resolve ``project.stacks[step.stack]`` (unknown stack = error), ``workdir = project.root / stack.dir``;
2. take the per-stack ``flock`` under ``state_dir`` (``StackLocked`` becomes an errored step);
3. build the child environment (the runner's env, ``TF_PLUGIN_CACHE_DIR`` honoured when set) and the non-secret
   backend configuration (``local``: none; ``s3``: bucket, key, region, ``use_lockfile``, ``encrypt``);
4. check every ``required_env`` name is set (names only in the message), then register, **before** any
   Terraform process starts, the values of ``var_overrides`` and of every ``TF_VAR_<name>`` in the environment
   whose variable the stack declares ``sensitive = true`` (found by reading the ``*.tf`` / ``*.tf.json`` files:
   the plan JSON that knows for sure only exists after Terraform ran) or whose name matches the key denylist.
   A value too short for the registry (``min_length``) is reported under ``unprotected_overrides``;
5. ``init -json`` (``-lockfile=readonly`` when ``CI`` is set), then the action:

   - ``validate`` -> ``{valid, diagnostics}``; ``valid: false`` is a failed step, not an error;
   - ``plan`` -> ``plan.tfplan`` (0600) in the step dir, ``show -json`` and ``providers schema`` in memory, the
     registry seeded from the plan, the plan gate, the redacted plan document written as ``plan.json``; exit 0
     and 2 both succeed (``changed`` says which), exit 1 fails;
   - ``output`` -> ``output -json`` seeded and redacted into ``tf-outputs.json`` (sensitive values become their
     placeholder);
   - ``test`` -> ``terraform test`` in plan mode only;
   - ``apply`` and ``migrate_backend`` -> failed with the Phase 3 message (apply needs the gate and the plan
     sha256 binding; migrate_backend needs the backend bootstrap).

Every Terraform stdout/stderr line goes through a ``StreamRedactor`` before it reaches ``stdout.log`` /
``stderr.log`` (the ``-json`` documents the adapter parses in memory are never streamed at all, and the
human-readable ``plan`` output is held back and written only after the registry was seeded from ``show -json``:
it prints state-held values, such as a computed attribute echoing a secret, that nothing earlier could know);
``argv.json``
holds every argv the session ran and ``env-names.json`` the child env's names. The child never sees
``CODEORCA_REDACTION_KEY`` or ``TF_CLI_ARGS*``. ``var_overrides`` are rendered into a 0600 temporary
``.tfvars.json`` passed with ``-var-file`` (last wins) and deleted afterwards. The step's ``timeout`` is a
deadline over the whole session (init included); expiry is ``StepTimeout``. Under ``--dry-run`` nothing
changes: every action here is already read-only.

Known gap: ``plan``'s stderr (diagnostics) streams live; a diagnostic that quotes a value only the plan JSON
would later flag is written as Terraform printed it.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
import time
from collections.abc import Callable, Mapping
from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from codeorca import policy, tfjson
from codeorca.adapters.terraform import (
    PlanResult,
    TerraformError,
    TerraformRunner,
    TerraformTimeout,
    plan_file_sha256,
)
from codeorca.project import Project, Stack
from codeorca.redact import SecretRegistry, compile_key_denylist, redact_tree
from codeorca.rundir import RunDir, StackLocked, stack_lock
from codeorca.runner import Executor, StepContext, StepError, StepResult, StepTimeout
from codeorca.secrets import KEY_ENV_VAR, terraform_stream
from codeorca.secrets import key_denylist as project_key_denylist
from codeorca.specs import META_KEY
from codeorca.specs.terraform_plan import build_plan_document, seed_registry

PLAN_FILE = "plan.tfplan"
PLAN_JSON = "plan.json"
TF_OUTPUTS_JSON = "tf-outputs.json"
PHASE3_APPLY = "apply needs the gate (Phase 3): the apply step binds to an approved plan sha256 and is not wired yet"
PHASE3_MIGRATE = "migrate_backend needs the backend bootstrap (Phase 3) and is not wired yet"

_VARIABLE_BLOCK = re.compile(r'variable\s+"([^"]+)"\s*\{', re.MULTILINE)
_SENSITIVE_TRUE = re.compile(r"^\s*sensitive\s*=\s*true\s*(#.*|//.*)?$", re.MULTILINE)
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
TF_VAR_PREFIX = "TF_VAR_"


class UnknownStack(StepError):
    pass


def resolve_stack(project: Project | None, name: str) -> tuple[Stack, Path]:
    if project is None or project.root is None:
        raise StepError("terraform steps need a project file (-p codeorca.yaml)")
    stack = project.stacks.get(name)
    if stack is None:
        raise UnknownStack(f"unknown stack {name!r}; known: {', '.join(sorted(project.stacks)) or '(none)'}")
    workdir = (project.root / stack.dir).resolve()
    if not workdir.is_dir():
        raise StepError(f"stack {name!r}: directory {workdir} does not exist")
    return stack, workdir


def backend_config(project: Project, stack: Stack) -> dict[str, object]:
    """Non-secret ``-backend-config`` values; credentials never travel this way (the adapter refuses them)."""
    backend = project.backend
    if backend.type == "local":
        return {}
    return {
        "bucket": backend.bucket,
        "key": stack.key,
        "region": backend.region,
        "use_lockfile": True,
        "encrypt": True,
    }


def declared_sensitive_variables(workdir: Path) -> set[str]:
    """Variable names whose ``variable`` block in ``*.tf`` / ``*.tf.json`` says ``sensitive = true`` (a textual
    pre-plan read, ``#``, ``//`` and ``/* */`` comments tolerated; the plan JSON confirms it after the fact)."""
    found: set[str] = set()
    for tf in sorted(workdir.glob("*.tf")):
        text = _BLOCK_COMMENT.sub("", tf.read_text(encoding="utf-8", errors="replace"))
        for m in _VARIABLE_BLOCK.finditer(text):
            body = _block_body(text, m.end())
            if _SENSITIVE_TRUE.search(body):
                found.add(m.group(1))
    for tf in sorted(workdir.glob("*.tf.json")):
        try:
            document = json.loads(tf.read_text(encoding="utf-8", errors="replace"))
        except ValueError:
            continue
        variables = document.get("variable") if isinstance(document, dict) else None
        blocks = variables if isinstance(variables, list) else [variables]
        for block in blocks:
            if isinstance(block, dict):
                for name, spec in block.items():
                    if isinstance(spec, dict) and spec.get("sensitive") is True:
                        found.add(str(name))
    return found


def _block_body(text: str, start: int) -> str:
    depth = 1
    i = start
    while i < len(text) and depth:
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        i += 1
    return text[start : i - 1]


@dataclass
class Registered:
    """What ``register_overrides`` protected: ``names`` got at least one leaf into the registry; ``unprotected``
    are secret-looking names whose every value was too short for the registry (nothing scrubs them)."""

    names: list[str] = field(default_factory=list)
    unprotected: list[str] = field(default_factory=list)


def register_overrides(
    registry: SecretRegistry,
    overrides: Mapping[str, Any],
    sensitive_names: set[str],
    denylist: tuple[str, ...],
    env: Mapping[str, str] | None = None,
) -> Registered:
    """Register the values of ``overrides`` and of every ``TF_VAR_<name>`` in ``env`` for variables that are
    declared sensitive or whose name matches the key denylist."""
    patterns = compile_key_denylist(denylist)
    accepted: set[str] = set()
    tried: set[str] = set()

    def secret_name(name: str) -> bool:
        return name in sensitive_names or any(p.search(name) for p in patterns)

    for name, value in overrides.items():
        if secret_name(name):
            tried.add(name)
            if _add_leaves(registry, value):
                accepted.add(name)
    for key, value in (env or {}).items():
        name = key[len(TF_VAR_PREFIX) :] if key.startswith(TF_VAR_PREFIX) else None
        if name and value and secret_name(name):
            tried.add(name)
            if _add_leaves(registry, value):
                accepted.add(name)
    return Registered(sorted(accepted), sorted(tried - accepted))


def check_required_env(stack: Stack, env: Mapping[str, str]) -> None:
    missing = [name for name in stack.required_env if not env.get(name)]
    if missing:
        raise StepError(f"required_env not set: {', '.join(missing)}")


def _add_leaves(registry: SecretRegistry, value: Any) -> bool:
    """Register every scalar leaf; True when at least one leaf is protected (new or already known)."""
    if isinstance(value, dict):
        return any([_add_leaves(registry, v) for v in value.values()])
    if isinstance(value, list | tuple):
        return any([_add_leaves(registry, v) for v in value])
    if value is None or isinstance(value, bool):
        return False
    text = str(value)
    return registry.add(text) or registry.count_matches(text) > 0


def _write_json(path: Path, data: Any, mode: int | None = None) -> Path:
    """Atomic write; with ``mode`` the file is created with that mode before any content lands in it."""
    tmp = path.with_name(path.name + ".tmp")
    text = json.dumps(data, indent=2, sort_keys=True) + "\n"
    if mode is None:
        tmp.write_text(text, encoding="utf-8")
    else:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, mode)
    os.replace(tmp, path)
    return path


def _gated_json(path: Path, data: Any, registry: SecretRegistry) -> Path:
    """Write a redacted document (0600) only after its text passed the registry scan: a hit is a StepError and
    nothing touches the disk."""
    hits = registry.count_matches(json.dumps(data, indent=2, sort_keys=True))
    if hits:
        raise StepError(f"redaction gate: registered value found in {path.name} ({hits} matches); not written")
    return _write_json(path, data, mode=0o600)


def _tail(text: str, limit: int = 2000) -> str:
    tail = text.strip()[-limit:]
    return f": {tail}" if tail else ""


@dataclass
class StackSession:
    """One locked Terraform session on one stack: runner, redacted logs, argv/env-names record."""

    project: Project
    stack_name: str
    stack: Stack
    workdir: Path
    registry: SecretRegistry
    step_dir: Path
    runner: TerraformRunner
    flush: Callable[[], None]
    state_dir: Path
    emit: Callable[[str, str], None] = lambda channel, line: None  # (channel, redacted line) -> the log sink
    durations: dict[str, float] = field(default_factory=dict)
    engine_version: str | None = None

    def record(self) -> None:
        _write_json(self.step_dir / "argv.json", [list(r.argv) for r in self.runner.history])
        _write_json(self.step_dir / "env-names.json", sorted(self.runner.env))

    def timed(self, name: str, call: Callable[[], Any]) -> Any:
        started = time.monotonic()
        try:
            return call()
        finally:
            self.durations[name] = round(time.monotonic() - started, 3)
            self.flush()

    def init(self) -> None:
        readonly = bool(self.runner.env.get("CI"))
        result = self.timed("init", lambda: self.runner.init(backend_config(self.project, self.stack), readonly))
        if result.exit_code != 0:
            # init -json puts its diagnostics on stdout as @level error messages; stderr is usually empty
            detail = "; ".join(_diagnostic_text(d) for d in tfjson.diagnostics(result.messages)) or result.stderr
            raise TerraformError(f"init failed (exit {result.exit_code}){_tail(self.registry.redact(detail))}")
        try:
            self.engine_version = str(self.timed("version", self.runner.version).get("terraform_version"))
        except TerraformError:
            self.engine_version = None

    def version_text(self) -> str | None:
        return self.engine_version


def _diagnostic_text(message: Mapping[str, Any]) -> str:
    diag = message.get("diagnostic") if isinstance(message.get("diagnostic"), dict) else {}
    parts = [str(message.get("@message") or diag.get("summary") or "")]
    if diag.get("detail"):
        parts.append(str(diag["detail"]).strip())
    return ": ".join(p for p in parts if p)


def open_session(
    project: Project | None,
    stack_name: str,
    registry: SecretRegistry,
    step_dir: Path,
    env: Mapping[str, str],
    stack_ctx: ExitStack,
    *,
    run_dir: RunDir | None = None,
    step_id: str | None = None,
    line_filter: Callable[[str], Callable[[str], str] | None] | None = None,
    lock: bool | None = None,
    timeout: float | None = None,
) -> StackSession:
    """Lock the stack, open the redacted log sinks and build the runner. Resources are released by ``stack_ctx``.
    ``timeout`` (seconds) becomes the session deadline for every Terraform command."""
    stack, workdir = resolve_stack(project, stack_name)
    assert project is not None and project.root is not None
    check_required_env(stack, env)
    state_dir = project.root / project.state_dir
    try:
        stack_ctx.enter_context(stack_lock(state_dir, stack_name))
    except StackLocked as e:
        raise StepError(str(e)) from None
    step_dir.mkdir(parents=True, exist_ok=True)
    sinks: dict[str, Any] = {}
    if run_dir is not None and step_id is not None:
        for channel in ("stdout", "stderr"):
            sink = run_dir.line_sink(step_id, channel, line_filter(channel) if line_filter else None)
            sinks[channel] = stack_ctx.enter_context(sink)
    else:
        from codeorca.rundir import LineSink

        for channel in ("stdout", "stderr"):
            sinks[channel] = stack_ctx.enter_context(LineSink(step_dir / f"{channel}.log"))

    def emit(channel: str, line: str) -> None:
        sinks[channel].write_line(line)

    callback, flush = terraform_stream(registry, emit)
    child_env = {k: v for k, v in env.items() if k != KEY_ENV_VAR}  # the HMAC key is nobody's business but ours
    register_overrides(registry, {}, declared_sensitive_variables(workdir), project_key_denylist(project), child_env)
    runner = TerraformRunner(
        workdir,
        child_env,
        stream=callback,
        lock=stack.plan_lock if lock is None else lock,
        plugin_cache_dir=child_env.get("TF_PLUGIN_CACHE_DIR"),
        deadline=None if timeout is None else time.monotonic() + timeout,
    )
    return StackSession(project, stack_name, stack, workdir, registry, step_dir, runner, flush, state_dir, emit)


@dataclass
class PlanOutcome:
    exit_code: int
    changed: bool
    plan_file: str
    plan_json: str
    document: dict[str, Any]
    result: dict[str, Any]
    error: str | None = None


def plan_stack(
    session: StackSession,
    *,
    var_overrides: Mapping[str, Any] | None = None,
    lock: bool | None = None,
    run_id: str | None = None,
    step_id: str | None = None,
) -> PlanOutcome:
    """``plan`` -> ``show -json`` -> seed -> gate -> redacted document (``plan.json``). The sensitive overrides
    must already be registered (``register_overrides``) before this is called."""
    project, stack, registry, step_dir = session.project, session.stack, session.registry, session.step_dir
    out = step_dir / PLAN_FILE
    tmpdir: str | None = None
    try:
        var_file: Path | None = None
        if var_overrides:
            tmpdir = tempfile.mkdtemp(prefix="codeorca-vars-")
            var_file = Path(tmpdir, "overrides.tfvars.json")
            var_file.write_text(json.dumps(dict(var_overrides), sort_keys=True) + "\n", encoding="utf-8")
            var_file.chmod(0o600)
        plan: PlanResult = session.timed(
            "plan", lambda: session.runner.plan(out, var_file, lock=lock, stream_stdout=False)
        )
    finally:
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def log_plan_output() -> None:
        # held back until now: the registry knows everything the plan JSON (or the failure) can tell it
        for line in plan.stdout_lines:
            session.emit("stdout", registry.redact(line))

    if plan.exit_code == 1:
        log_plan_output()
        error = f"plan failed (exit 1){_tail(registry.redact(plan.stderr))}"
        result = {"exit_code": 1, "changed": False, "files": {"plan_file": None, "plan_json": None}}
        return PlanOutcome(1, False, "", "", {}, result, error)

    plan_json = session.timed("show", lambda: session.runner.show_plan(plan.plan_file))
    if not tfjson.is_supported_format(plan_json.get("format_version")):
        raise TerraformError(
            f"show -json format_version {plan_json.get('format_version')!r} is not a 1.x plan format this version "
            "of codeorca can render"
        )
    providers_schema = session.timed("providers_schema", session.runner.providers_schema)
    denylist = project_key_denylist(project)
    seed_registry(registry, plan_json, denylist)
    log_plan_output()
    verdict = policy.plan_gate(
        plan_json,
        policy.Policy(
            stateful_types=project.policy.stateful_types,
            critical_tag=project.policy.critical_tag,
            transient_errors=project.policy.transient_errors,
        ),
    )
    document = build_plan_document(
        plan_json,
        providers_schema,
        registry,
        session.stack_name,
        verdict,
        denylist,
        stack.never_render.model_dump(),
        exit_code=plan.exit_code,
        engine_version=session.version_text(),
    )
    document[META_KEY] = {
        "run_id": run_id,
        "step_id": step_id,
        "plan_sha256": plan_file_sha256(plan.plan_file),
        "durations_s": dict(session.durations),
        "registry_size": registry.size,
    }
    plan_json_path = _gated_json(step_dir / PLAN_JSON, document, registry)

    never_outputs = set(stack.never_render.outputs)
    prior = tfjson.prior_outputs(plan_json)
    previous = tfjson.previous_outputs(plan_json)
    flat = {
        name: previous.get(name, prior.get(name))
        for name in sorted(set(prior) | set(previous))
        if name not in never_outputs
    }
    prior_outputs = {name: {"value": value} for name, value in redact_tree(flat, registry, denylist).items()}
    warnings: list[str] = []
    if not document["summary"]["complete"]:
        warnings.append("incomplete plan: Terraform reports complete=false (a targeted or errored plan); not applyable")
    result = {
        "exit_code": plan.exit_code,
        "changed": plan.changed,
        "files": {"plan_file": str(out), "plan_json": str(plan_json_path)},
        "summary": document["summary"],
        "gate": verdict.model_dump(),
        "warnings": warnings,
        "prior_outputs": prior_outputs,
        "sensitive_variables": tfjson.sensitive_variables(plan_json),
        "sensitive_outputs": tfjson.sensitive_outputs(plan_json),
        "engine_version": session.version_text(),
    }
    return PlanOutcome(plan.exit_code, plan.changed, str(out), str(plan_json_path), document, result)


def output_stack(session: StackSession) -> dict[str, Any]:
    registry = session.registry
    doc = session.timed("output", session.runner.output_json)
    for spec in doc.values():
        if isinstance(spec, dict) and spec.get("sensitive"):
            _add_leaves(registry, spec.get("value"))
    denylist = project_key_denylist(session.project)
    tf_outputs: dict[str, Any] = {}
    for name in sorted(doc):
        spec = doc[name] if isinstance(doc[name], dict) else {"value": doc[name]}
        sensitive = bool(spec.get("sensitive"))
        value = spec.get("value")
        if sensitive and value is not None:
            text = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
            value = registry.placeholder(text)
        else:
            value = redact_tree(value, registry, denylist)
        tf_outputs[name] = {"value": value, "sensitive": sensitive, "type": spec.get("type")}
    path = _gated_json(session.step_dir / TF_OUTPUTS_JSON, tf_outputs, registry)
    return {"tf_outputs": tf_outputs, "files": {"tf_outputs": str(path)}}


def make_executor(registry: SecretRegistry) -> Executor:
    """The ``terraform`` executor bound to the run's registry."""

    def run_terraform(step, ctx: StepContext) -> StepResult:
        return execute(step, ctx, registry)

    run_terraform.__name__ = "run_terraform"
    return run_terraform


def execute(step, ctx: StepContext, registry: SecretRegistry) -> StepResult:
    action = step.action
    if action == "apply":
        return StepResult("failed", error=PHASE3_APPLY)
    if action == "migrate_backend":
        return StepResult("failed", error=PHASE3_MIGRATE)
    project = ctx.project
    stack_name = str(step.stack)
    with ExitStack() as resources:
        session = open_session(
            project,
            stack_name,
            registry,
            ctx.step_dir,
            ctx.env,
            resources,
            run_dir=ctx.run_dir,
            step_id=step.id,
            line_filter=ctx.line_filter,
            timeout=ctx.timeout,
        )
        overrides = dict(step.var_overrides or {})
        registered = register_overrides(
            registry, overrides, declared_sensitive_variables(session.workdir), project_key_denylist(project), ctx.env
        )
        try:
            session.init()
            if action == "validate":
                result = _validate(session)
            elif action == "plan":
                result = _plan(session, overrides, ctx, registered)
            elif action == "output":
                result = StepResult("succeeded", result=output_stack(session))
            elif action == "test":
                result = _test(session)
            else:  # pragma: no cover - the model's enum stops here
                raise StepError(f"unknown terraform action {action!r}")
        except policy.PolicyError as e:
            raise StepError(f"policy: {e}") from None
        except TerraformTimeout as e:
            raise StepTimeout(f"step {step.id}: {registry.redact(str(e))}") from None
        except TerraformError as e:
            raise StepError(registry.redact(str(e))) from None
        finally:
            session.record()
        result.outputs.setdefault("stack", stack_name)
        return result


def _validate(session: StackSession) -> StepResult:
    doc = session.timed("validate", session.runner.validate)
    result = {
        "valid": bool(doc.get("valid")),
        "error_count": doc.get("error_count", 0),
        "warning_count": doc.get("warning_count", 0),
        "diagnostics": redact_tree(doc.get("diagnostics") or [], session.registry),
    }
    if result["valid"]:
        return StepResult("succeeded", result=result)
    first = next(iter(result["diagnostics"]), {}) or {}
    return StepResult("failed", result=result, error=f"validate: {first.get('summary', 'invalid configuration')}")


def _plan(session: StackSession, overrides: dict[str, Any], ctx: StepContext, registered: Registered) -> StepResult:
    outcome = plan_stack(session, var_overrides=overrides, run_id=ctx.run_id, step_id=ctx.step.id)
    outcome.result["registered_overrides"] = registered.names
    outcome.result["unprotected_overrides"] = registered.unprotected  # too short to scrub: names only, never values
    if registered.unprotected:
        outcome.result.setdefault("warnings", []).append(
            "sensitive variable value(s) shorter than the registry minimum are not scrubbed: "
            + ", ".join(registered.unprotected)
        )
    if outcome.exit_code == 1:
        return StepResult("failed", result=outcome.result, error=outcome.error)
    return StepResult("succeeded", result=outcome.result)


def _test(session: StackSession) -> StepResult:
    doc = session.timed("test", lambda: session.runner.test(plan_mode_only=True))
    result = {
        "exit_code": doc["exit_code"],
        "passed": doc["passed"],
        "summary": redact_tree(doc.get("summary") or {}, session.registry),
        "errors": redact_tree(doc.get("errors") or [], session.registry),
    }
    if doc["passed"]:
        return StepResult("succeeded", result=result)
    return StepResult("failed", result=result, error=f"terraform test exited {doc['exit_code']}")
