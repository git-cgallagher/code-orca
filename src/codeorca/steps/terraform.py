"""The ``terraform`` step (plan section 5.4) and the shared stack session ``codeorca drift`` reuses.

What a step does, in order:

1. resolve ``project.stacks[step.stack]`` (unknown stack = error), ``workdir = project.root / stack.dir``;
2. take the per-stack ``flock`` under ``state_dir`` (``StackLocked`` becomes an errored step);
3. build the child environment (the runner's env, ``TF_PLUGIN_CACHE_DIR`` honoured when set, plus the stack's
   ``secrets:`` resolved through the SSM resolver into the child env only and registered first) and the non-secret
   backend configuration (``local``: none; ``s3``: ``codeorca.bootstrap.s3.backend_settings``: bucket, key, region,
   ``use_lockfile``, ``encrypt``, ``kms_key_id`` under ``encryption: kms:<arn>``);
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
   - ``apply`` -> see "Apply" below; ``migrate_backend`` -> see "migrate_backend" below.

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

``plan``'s stderr (diagnostics) is held back the same way: a diagnostic can quote a state-held value too.
Every other command's stderr streams live through the redactor, which at that point knows the pre-registered
values only (inputs, ``TF_VAR_*`` of sensitive or denylist-named variables, env tokens).

Apply (plan sections 5.4 and 5.9), refused (``failed``, nothing run) unless every check holds:

1. ``plan_file`` resolves inside ``<run>/steps/<id>/plan.tfplan`` of a ``terraform`` ``plan`` step of the same
   stack in THIS workflow that succeeded and whose result names that file (a relative path is relative to the
   run dir); under ``--dry-run`` the step stops here as ``skipped`` (plan only, nothing applied);
2. the step (transitively) needs a ``gate`` that succeeded with ``decision: approve`` and recorded this plan
   file's current sha256 (a dry-run approval never counts in a real run); the newest such approval wins;
3. that approval is younger than ``project.gate.max_age``;
4. ``show -json`` of the plan seeds the registry (a resumed run is a fresh process: the plan's sensitive values
   are registered before anything streams), the plan is applyable/complete/not errored, and the plan gate,
   run again with the approving gate's ``allow_delete_of``, passes.

Then ``TerraformRunner.apply(plan_file, sha256)`` (the adapter refuses a mismatch again), streamed through the
redactor; on success ``output -json`` gives the redacted ``tf_outputs`` (``tf-outputs.json``) and the plan file is
deleted. Retries: an attempt after the first runs only when the previous attempt failed with ``Error acquiring
the state lock`` before Terraform reported any change (``apply-attempt.json`` in the step dir records it);
anything else is refused whatever ``retry:`` says.

migrate_backend (plan section 5.11): needs an approving gate upstream (as above, no plan binding), then probes the
NEW backend from a temporary copy of the stack dir (``init -reconfigure -backend-config`` + ``state list``; the
state file is never read) and refuses when the target already holds a state with resources; then ``init
-migrate-state -force-copy -backend-config=<rendered>`` in the stack dir, the one argv ``check_argv`` lets through
with ``allow_migrate_state=True``. It runs without ``-json`` (``-json`` and ``-migrate-state`` are mutually
exclusive on 1.14.7). ``backend.type: local`` renders no backend config and is refused.
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
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from codeorca import policy, tfjson
from codeorca.adapters.terraform import (
    PlanResult,
    TerraformError,
    TerraformRunner,
    TerraformTimeout,
    plan_file_sha256,
    render_backend_hcl,
)
from codeorca.models import _ancestors
from codeorca.project import Project, Stack
from codeorca.redact import SecretRegistry, compile_key_denylist, redact_tree
from codeorca.rundir import RunDir, StackLocked, stack_lock
from codeorca.runner import Executor, StepContext, StepError, StepResult, StepTimeout
from codeorca.secrets import KEY_ENV_VAR, terraform_stream
from codeorca.secrets import key_denylist as project_key_denylist
from codeorca.specs import META_KEY
from codeorca.specs.terraform_plan import build_plan_document, seed_registry

SecretResolver = Callable[[str], str]

PLAN_FILE = "plan.tfplan"
PLAN_JSON = "plan.json"
TF_OUTPUTS_JSON = "tf-outputs.json"
APPLY_MARKER = "apply-attempt.json"
LOCK_ERROR = "Error acquiring the state lock"
DEFAULT_MAX_AGE = "24h"
# -json message types that mean Terraform started changing something (a retry after one of these is refused)
CHANGE_MESSAGE_TYPES = frozenset(
    {"apply_start", "apply_progress", "apply_complete", "apply_errored", "provision_start", "provision_complete"}
)

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
    """Non-secret ``-backend-config`` values; credentials never travel this way (the adapter refuses them).
    ``local``: none; ``s3``: exactly what the bootstrap writes into ``backend.hcl``
    (:func:`codeorca.bootstrap.s3.backend_settings`, ``kms_key_id`` under ``encryption: kms:<arn>``)."""
    if project.backend.type == "local":
        return {}
    from codeorca.bootstrap.s3 import backend_settings

    return backend_settings(project, stack)


def resolve_stack_secrets(
    stack_name: str, stack: Stack, registry: SecretRegistry, resolve_secret: SecretResolver | None
) -> dict[str, str]:
    """``stacks.<name>.secrets`` (``{ENV_NAME: ssm:/path}``) resolved for the CHILD env only, each value registered
    before it is returned (the resolver registers; this registers again, harmlessly, so an injected resolver that
    does not still cannot leak). No provider (boto3 missing): ``NO_PROVIDER_MESSAGE``; an ``SSMError`` keeps its
    value-free message. A stack without secrets never touches the resolver."""
    if not stack.secrets:
        return {}
    from codeorca.providers import NO_PROVIDER_MESSAGE, SSMError

    if resolve_secret is None:
        raise StepError(f"stack {stack_name!r}: {NO_PROVIDER_MESSAGE}")
    resolved: dict[str, str] = {}
    for name, ref in sorted(stack.secrets.items()):
        try:
            value = resolve_secret(str(ref))
        except SSMError as e:
            raise StepError(f"stack {stack_name!r}: secret {name}: {e}") from None
        except Exception as e:  # noqa: BLE001 - value-free: the exception class only
            raise StepError(f"stack {stack_name!r}: secret {name}: cannot resolve {ref}: {type(e).__name__}") from None
        if value is None:
            raise StepError(f"stack {stack_name!r}: secret {name}: {ref} resolved to nothing")
        registry.add(str(value))
        resolved[str(name)] = str(value)
    return resolved


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
    resolve_secret: SecretResolver | None = None,
) -> StackSession:
    """Lock the stack, open the redacted log sinks and build the runner. Resources are released by ``stack_ctx``.
    ``timeout`` (seconds) becomes the session deadline for every Terraform command. The stack's ``secrets:`` are
    resolved through ``resolve_secret`` into the child env only (registered before any Terraform process starts),
    then ``required_env`` is checked against that env (a name listed in both is satisfied by the secret)."""
    stack, workdir = resolve_stack(project, stack_name)
    assert project is not None and project.root is not None
    secret_env = resolve_stack_secrets(stack_name, stack, registry, resolve_secret)
    env = {**env, **secret_env}
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
            "plan", lambda: session.runner.plan(out, var_file, lock=lock, stream_stdout=False, stream_stderr=False)
        )
    finally:
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def log_plan_output() -> None:
        # held back until now: the registry knows everything the plan JSON (or the failure) can tell it
        for line in plan.stdout_lines:
            session.emit("stdout", registry.redact(line))
        for line in plan.stderr_lines:
            session.emit("stderr", registry.redact(line))

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


def make_executor(registry: SecretRegistry, resolve_secret: SecretResolver | None = None) -> Executor:
    """The ``terraform`` executor bound to the run's registry and the SSM resolver (``None``: a stack with
    ``secrets:`` fails its step with ``NO_PROVIDER_MESSAGE``)."""

    def run_terraform(step, ctx: StepContext) -> StepResult:
        return execute(step, ctx, registry, resolve_secret)

    run_terraform.__name__ = "run_terraform"
    return run_terraform


def execute(
    step, ctx: StepContext, registry: SecretRegistry, resolve_secret: SecretResolver | None = None
) -> StepResult:
    action = step.action
    if action == "apply":
        return apply_step(step, ctx, registry, resolve_secret)
    if action == "migrate_backend":
        return migrate_step(step, ctx, registry, resolve_secret)
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
            resolve_secret=resolve_secret,
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


# --- apply + migrate_backend (Phase 3) ------------------------------------------------------------------------------


class Refused(Exception):
    """A precondition of apply/migrate_backend does not hold; the step fails and nothing ran."""


@dataclass
class Approval:
    gate_id: str
    decided_at: str
    approver: str
    allow_delete_of: list[str]
    plan_sha256: str | None = None


def _workflow_steps(ctx: StepContext) -> dict[str, Any]:
    if ctx.workflow is None:
        raise Refused("this step needs the workflow graph (StepContext.workflow) to find its gate")
    return {s.id: s for s in ctx.workflow.steps}


def resolve_plan_file(step, ctx: StepContext) -> tuple[Path, str]:
    """``(plan file, producing step id)``; refuses anything but this run's own ``plan`` output for this stack."""
    steps = _workflow_steps(ctx)
    run_root = ctx.run_dir.path.resolve()
    steps_root = (run_root / "steps").resolve()
    raw = Path(str(step.plan_file))
    path = (raw if raw.is_absolute() else run_root / raw).resolve()
    if not path.is_relative_to(steps_root):
        raise Refused(f"plan_file {raw} is outside this run's directory; only a plan this run produced is applied")
    parts = path.relative_to(steps_root).parts
    if len(parts) != 2 or parts[1] != PLAN_FILE:
        raise Refused(f"plan_file {raw} is not a step's {PLAN_FILE} in this run")
    producer = steps.get(parts[0])
    if producer is None or producer.type != "terraform" or producer.action != "plan":
        raise Refused(f"plan_file {raw} was not produced by a terraform plan step of this workflow")
    if str(producer.stack) != str(step.stack):
        raise Refused(f"plan_file {raw} is a plan of stack {producer.stack!r}, not {step.stack!r}")
    state = (ctx.context.get("steps") or {}).get(producer.id) or {}
    if state.get("status") != "succeeded":
        raise Refused(f"plan step {producer.id} did not succeed (status {state.get('status')!r})")
    result = ctx.run_dir.read_result(producer.id) or {}
    named = ((result.get("files") or {}) if isinstance(result.get("files"), dict) else {}).get("plan_file")
    if not named or Path(str(named)).resolve() != path:
        raise Refused(f"plan step {producer.id} does not name {raw} as its plan file")
    if not path.is_file():
        raise Refused(f"plan file {path} is gone (already applied, or removed); re-plan in a new run")
    return path, producer.id


def find_approval(step, ctx: StepContext, plan_path: Path | None = None) -> Approval:
    """The newest approving gate this step transitively needs (bound to ``plan_path``'s current sha256 when
    given). Refuses when there is none."""
    steps = _workflow_steps(ctx)
    ancestors = _ancestors(ctx.workflow.graph(), step.id)  # type: ignore[union-attr]
    current = plan_file_sha256(plan_path) if plan_path is not None else None
    reasons: list[str] = []
    found: list[Approval] = []
    for gid in sorted(ancestors):
        gate = steps.get(gid)
        if gate is None or gate.type != "gate":
            continue
        status = ((ctx.context.get("steps") or {}).get(gid) or {}).get("status")
        result = ctx.run_dir.read_result(gid) or {}
        if status != "succeeded" or result.get("decision") != "approve":
            reasons.append(f"gate {gid} is {status!r} (decision {result.get('decision')!r})")
            continue
        if result.get("dry_run") and not ctx.dry_run:
            reasons.append(f"gate {gid} was auto-approved by --dry-run")
            continue
        sha = None
        if plan_path is not None:
            entries = [e for e in (result.get("plans") or {}).values() if Path(str(e.get("path"))) == plan_path]
            if not entries:
                reasons.append(f"gate {gid} did not see plan file {plan_path}")
                continue
            sha = entries[0].get("sha256")
            if sha != current:
                reasons.append(f"plan file {plan_path} changed after gate {gid} approved it")
                continue
        found.append(
            Approval(
                gid,
                str(result.get("decided_at") or ""),
                str(result.get("approver") or ""),
                [str(a) for a in (result.get("allow_delete_of") or [])],
                sha,
            )
        )
    if not found:
        detail = "; ".join(reasons) or "the step needs no gate"
        raise Refused(f"step {step.id} needs an approving gate upstream ({detail})")
    return max(found, key=lambda a: a.decided_at)


def check_approval_age(project: Project | None, approval: Approval) -> None:
    from codeorca.runner import parse_duration
    from codeorca.steps.gate import parse_utc

    max_age = project.gate.max_age if project is not None else DEFAULT_MAX_AGE
    try:
        decided = parse_utc(approval.decided_at)
    except ValueError:
        raise Refused(f"gate {approval.gate_id} recorded no valid decision time") from None
    age = (datetime.now(UTC) - decided).total_seconds()
    if age > parse_duration(max_age):
        raise Refused(
            f"the approval of gate {approval.gate_id} is older than gate.max_age {max_age}; re-plan and re-approve"
        )


def _marker(ctx: StepContext) -> Path:
    return ctx.step_dir / APPLY_MARKER


def _check_retry(ctx: StepContext) -> None:
    if ctx.attempt <= 1:
        return
    try:
        previous = json.loads(_marker(ctx).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        previous = {}
    if not previous.get("lock_error_before_change"):
        raise Refused(
            "apply is retried only after a state-lock error before any change; the previous attempt failed with: "
            + str(previous.get("error") or "an error before Terraform ran")
        )


def apply_step(
    step, ctx: StepContext, registry: SecretRegistry, resolve_secret: SecretResolver | None = None
) -> StepResult:
    try:
        _check_retry(ctx)
        plan_path, producer = resolve_plan_file(step, ctx)
        if ctx.dry_run:
            return StepResult(
                "skipped",
                result={
                    "dry_run": True,
                    "applied": False,
                    "plan_file": str(plan_path),
                    "note": "plan only (--dry-run)",
                },
                outputs={"stack": str(step.stack)},
            )
        approval = find_approval(step, ctx, plan_path)
        check_approval_age(ctx.project, approval)
    except Refused as e:
        return StepResult("failed", error=f"apply refused: {e}")
    _write_json(_marker(ctx), {"attempt": ctx.attempt, "lock_error_before_change": False, "error": None})
    with ExitStack() as resources:
        try:
            session = open_session(
                ctx.project,
                str(step.stack),
                registry,
                ctx.step_dir,
                ctx.env,
                resources,
                run_dir=ctx.run_dir,
                step_id=step.id,
                line_filter=ctx.line_filter,
                timeout=ctx.timeout,
                resolve_secret=resolve_secret,
            )
        except StepError as e:
            _write_json(_marker(ctx), {"attempt": ctx.attempt, "lock_error_before_change": False, "error": str(e)})
            raise
        try:
            session.init()
            result = _apply(session, ctx, plan_path, producer, approval)
        except policy.PolicyError as e:
            raise StepError(f"policy: {e}") from None
        except TerraformTimeout as e:
            raise StepTimeout(f"step {step.id}: {registry.redact(str(e))}") from None
        except TerraformError as e:
            raise StepError(registry.redact(str(e))) from None
        finally:
            session.record()
        result.outputs.setdefault("stack", str(step.stack))
        return result


def _apply(session: StackSession, ctx: StepContext, plan_path: Path, producer: str, approval: Approval) -> StepResult:
    registry, project = session.registry, session.project
    denylist = project_key_denylist(project)
    plan_json = session.timed("show", lambda: session.runner.show_plan(plan_path))
    seed_registry(registry, plan_json, denylist)  # before anything of the apply streams
    base: dict[str, Any] = {
        "plan_file": str(plan_path),
        "plan_step": producer,
        "plan_sha256": approval.plan_sha256,
        "gate": approval.gate_id,
        "approver": approval.approver,
        "applied": False,
    }
    problems = [
        text
        for flag, text in (
            (plan_json.get("applyable") is False, "the plan is not applyable"),
            (plan_json.get("errored") is True, "the plan errored"),
            (plan_json.get("complete") is False, "the plan is incomplete (complete=false)"),
        )
        if flag
    ]
    if problems:
        return StepResult("failed", result=base, error="apply refused: " + "; ".join(problems))
    verdict = policy.plan_gate(
        plan_json,
        policy.Policy(
            stateful_types=project.policy.stateful_types,
            critical_tag=project.policy.critical_tag,
            transient_errors=project.policy.transient_errors,
        ),
        approval.allow_delete_of,
    )
    base["gate_verdict"] = verdict.model_dump()
    if not verdict.passed:
        blocked = ", ".join(f"{b.address} ({b.reason})" for b in verdict.blocked)
        return StepResult(
            "failed",
            result=base,
            error=f"apply refused by the plan gate: {blocked}; list the address in gate {approval.gate_id}'s "
            "allow_delete_of to waive it",
        )
    applied = session.timed("apply", lambda: session.runner.apply(plan_path, approval.plan_sha256 or ""))
    text = registry.redact("\n".join([*applied.stdout_lines, *applied.stderr_lines]))
    changed = any(m.get("type") in CHANGE_MESSAGE_TYPES for m in applied.messages)
    base["exit_code"] = applied.exit_code
    if applied.exit_code != 0:
        lock_error = LOCK_ERROR in text and not changed
        detail = "; ".join(_diagnostic_text(d) for d in applied.errors) or applied.stderr
        error = f"apply failed (exit {applied.exit_code}){_tail(registry.redact(detail))}"
        if lock_error and LOCK_ERROR not in error:
            error += f" ({LOCK_ERROR})"
        _write_json(_marker(ctx), {"attempt": ctx.attempt, "lock_error_before_change": lock_error, "error": error})
        return StepResult("failed", result={**base, "lock_error": lock_error}, error=error)
    _write_json(_marker(ctx), {"attempt": ctx.attempt, "lock_error_before_change": False, "error": None})
    plan_path.unlink(missing_ok=True)  # it embeds sensitive values and prior state in clear: gone once applied
    outputs = output_stack(session)
    return StepResult("succeeded", result={**base, "applied": True, "plan_deleted": True, **outputs})


def migrate_step(
    step, ctx: StepContext, registry: SecretRegistry, resolve_secret: SecretResolver | None = None
) -> StepResult:
    try:
        approval = find_approval(step, ctx)
        check_approval_age(ctx.project, approval)
        if ctx.dry_run:
            return StepResult(
                "skipped", result={"dry_run": True, "migrated": False}, outputs={"stack": str(step.stack)}
            )
    except Refused as e:
        return StepResult("failed", error=f"migrate_backend refused: {e}")
    with ExitStack() as resources:
        session = open_session(
            ctx.project,
            str(step.stack),
            registry,
            ctx.step_dir,
            ctx.env,
            resources,
            run_dir=ctx.run_dir,
            step_id=step.id,
            line_filter=ctx.line_filter,
            timeout=ctx.timeout,
            resolve_secret=resolve_secret,
        )
        try:
            config = backend_config(session.project, session.stack)
            if not config:
                raise Refused(f"backend.type {session.project.backend.type} renders no backend config to migrate to")
            result = migrate_stack(session, config)
        except Refused as e:
            return StepResult("failed", error=f"migrate_backend refused: {e}", outputs={"stack": str(step.stack)})
        except policy.PolicyError as e:
            raise StepError(f"policy: {e}") from None
        except TerraformTimeout as e:
            raise StepTimeout(f"step {step.id}: {registry.redact(str(e))}") from None
        except TerraformError as e:
            raise StepError(registry.redact(str(e))) from None
        finally:
            session.record()
        result["gate"] = approval.gate_id
        result["approver"] = approval.approver
        return StepResult("succeeded", result=result, outputs={"stack": str(step.stack)})


_COPY_IGNORE = shutil.ignore_patterns(".terraform", "terraform.tfstate", "terraform.tfstate.*", "*.tfplan")


def target_state_resources(session: StackSession, config: Mapping[str, object]) -> list[str]:
    """``state list`` against the backend ``config`` from a temporary copy of the stack dir initialised with
    ``-reconfigure`` (the stack's own ``.terraform`` and local state are not copied). Empty = no state there."""
    tmp = Path(tempfile.mkdtemp(prefix="codeorca-migrate-probe-"))
    try:
        copy = tmp / "stack"
        shutil.copytree(session.workdir, copy, ignore=_COPY_IGNORE, symlinks=True)
        probe = TerraformRunner(
            copy,
            session.runner.env,
            plugin_cache_dir=session.runner.env.get("TF_PLUGIN_CACHE_DIR"),
            deadline=session.runner.deadline,
        )
        init = session.timed("probe_init", lambda: probe.init(config, reconfigure=True))
        if init.exit_code != 0:
            detail = "; ".join(_diagnostic_text(d) for d in tfjson.diagnostics(init.messages)) or init.stderr
            raise TerraformError(f"probe init of the target backend failed{_tail(session.registry.redact(detail))}")
        listed = session.timed(
            "probe_state_list",
            lambda: probe._run(["state", "list", "-no-color"], stream_stdout=False, stream_stderr=False),
        )
        if listed.exit_code == 0:
            return [line.strip() for line in listed.stdout_lines if line.strip()]
        if "No state file was found" in listed.stdout + listed.stderr:
            return []
        raise TerraformError(
            f"state list against the target backend failed (exit {listed.exit_code})"
            f"{_tail(session.registry.redact(listed.stderr))}"
        )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def migrate_stack(session: StackSession, config: Mapping[str, object]) -> dict[str, Any]:
    """Refuse when the target already holds a state; otherwise ``init -migrate-state -force-copy`` (no ``-json``:
    the two are mutually exclusive on 1.14.7) with ``config`` rendered into a temporary 0600 ``.hcl``."""
    existing = target_state_resources(session, config)
    if existing:
        raise Refused(
            f"the target backend already holds a state ({len(existing)} resources); refusing to overwrite it "
            "(no silent overwrite: point the stack at an empty key or adopt that state instead)"
        )
    hcl = render_backend_hcl(config)  # refuses credential-looking keys before anything is written
    tmp = tempfile.mkdtemp(prefix="codeorca-backend-")
    try:
        hcl_path = Path(tmp, "backend.hcl")
        hcl_path.write_text(hcl, encoding="utf-8")
        hcl_path.chmod(0o600)
        args = ["init", "-no-color", "-input=false", "-migrate-state", "-force-copy", f"-backend-config={hcl_path}"]
        result = session.timed("migrate", lambda: session.runner._run(args, allow_migrate_state=True))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if result.exit_code != 0:
        raise TerraformError(
            f"init -migrate-state failed (exit {result.exit_code}){_tail(session.registry.redact(result.stderr))}"
        )
    return {"migrated": True, "exit_code": 0, "backend": dict(config), "target_was_empty": True}
