"""The ``ansible`` step (plan section 5.5): ``ansible-playbook`` through the adapter, with the generated inventory and
the extra-vars handoff as 0600 files that exist only while the playbook runs.

What a step does, in order:

1. resolve the playbook (``project.root`` relative; the current directory when there is no project) or, for
   ``role:``, generate a one-task ``import_role`` playbook into the step dir (``playbook.yml``; the project's
   ``roles/`` and ``collections/`` are put on ``ANSIBLE_ROLES_PATH`` / ``ANSIBLE_COLLECTIONS_PATH`` when they exist,
   because a generated playbook does not sit next to them);
2. register, **before** the process starts, every ``extra_vars`` and inline-inventory leaf whose key matches the
   key denylist (``ansible_password``, ``db_token`` ...); a value too short for the registry is reported by name
   under ``unprotected_vars``;
3. write the inline inventory (``generate_inventory``) and the extra vars (``write_handoff``) as 0600 files under
   ``<run dir>/handoff/<step id>/`` (0700), and the inventory copy the host-spec renderer needs later as
   ``<step dir>/inventory.yml`` (values redacted through the registry and the key denylist before it is written;
   ``inventory.path`` steps keep the path as given), plus ``<step dir>/extra-vars.json`` (0600, redacted the same
   way) so a ``spec-render`` step can show the handed-over values with ``source: extra_vars``;
4. run ``ansible-playbook`` from the project root (``--check --diff`` under ``--dry-run``; the step's ``timeout``
   kills the whole process group); every stdout JSONL line goes through the stream redactor into
   ``<step dir>/events.jsonl``, everything else into ``stderr.log``; ``argv.json`` and ``env-names.json`` are recorded;
5. delete the handoff directory whatever happened (a timeout and an interrupt included);
6. map the exit code: 0 is ``succeeded``; anything else is ``failed`` with an error naming the failed and
   unreachable hosts and the last failed task's ``msg`` (redacted, truncated); a playbook that could not be started
   is ``errored``.

``check_unsupported`` (a task Ansible skipped because the module cannot run in check mode) is handled per the
stricter of ``project.ansible.check_unsupported`` and the step's own field (``ignore`` < ``warn`` < ``fail``; both
default to ``warn`` and an explicit step value cannot be told from the default, hence "stricter wins"):
``warn`` adds a warning to the result, ``fail`` fails the step, ``ignore`` only lists them.

``result`` = ``{rc, status_text, stats, failed_hosts, unreachable_hosts, check_unsupported, events_path,
stderr_path, inventory_path, extra_vars_path, playbook, duration_s, registered_vars, unprotected_vars, warnings}``.
The implicit output is ``inventory_path`` only (``models.IMPLICIT_OUTPUTS``).
"""

from __future__ import annotations

import json
import os
import shutil
from collections.abc import Mapping
from contextlib import ExitStack
from pathlib import Path
from typing import Any

from codeorca.adapters.ansible import (
    AnsibleError,
    AnsibleResult,
    AnsibleRunner,
    AnsibleTimeout,
    generate_inventory,
    generate_role_playbook,
    plain_tree,
    write_handoff,
    write_private,
)
from codeorca.project import AnsibleConfig, Project
from codeorca.redact import SecretRegistry, compile_key_denylist, redact_tree
from codeorca.rundir import LineSink
from codeorca.runner import Executor, StepContext, StepError, StepResult, StepTimeout
from codeorca.secrets import key_denylist as project_key_denylist
from codeorca.secrets import terraform_stream

EVENTS_FILE = "events.jsonl"
STDERR_FILE = "stderr.log"
INVENTORY_FILE = "inventory.yml"
EXTRA_VARS_FILE = "extra-vars.json"
GENERATED_PLAYBOOK = "playbook.yml"
_STRICTNESS = {"ignore": 0, "warn": 1, "fail": 2}
_ERROR_LIMIT = 2000


def make_executor(registry: SecretRegistry) -> Executor:
    """The ``ansible`` executor bound to the run's registry."""

    def run_ansible(step, ctx: StepContext) -> StepResult:
        return execute(step, ctx, registry)

    run_ansible.__name__ = "run_ansible"
    return run_ansible


def effective_check_unsupported(project: Project | None, step_value: str) -> str:
    """The stricter of the project's and the step's ``check_unsupported``."""
    project_value = project.ansible.check_unsupported if project is not None else "warn"
    return max((project_value, step_value), key=lambda v: _STRICTNESS.get(v, 1))


def register_secret_values(registry: SecretRegistry, trees: Mapping[str, Any], denylist: tuple[str, ...]):
    """Register every scalar leaf under a key that matches the key denylist, anywhere in ``trees``. Returns
    ``(registered key names, unprotected key names)``: a key whose every value was too short to register is
    unprotected (nothing scrubs it)."""
    patterns = compile_key_denylist(denylist)
    registered: set[str] = set()
    tried: set[str] = set()

    def walk(node: Any, secret: bool, name: str | None) -> None:
        if isinstance(node, Mapping):
            for key, value in node.items():
                key_text = str(key)
                hit = secret or any(p.search(key_text) for p in patterns)
                walk(value, hit, key_text if hit and not secret else name)
        elif isinstance(node, list | tuple):
            for value in node:
                walk(value, secret, name)
        elif secret and name is not None and node is not None and not isinstance(node, bool):
            tried.add(name)
            text = str(node)
            if registry.add(text) or registry.count_matches(text) > 0:
                registered.add(name)

    walk(trees, False, None)
    return sorted(registered), sorted(tried - registered)


def _root(project: Project | None) -> Path:
    if project is not None and project.root is not None:
        return project.root
    return Path.cwd()


def _resolve_under(root: Path, relative: str, what: str) -> Path:
    path = Path(relative)
    path = path if path.is_absolute() else root / path
    path = path.resolve()
    if not path.exists():
        raise StepError(f"{what} {relative!r} does not exist (resolved to {path})")
    return path


def _prepend_path(env: dict[str, str], name: str, directory: Path) -> None:
    if not directory.is_dir():
        return
    existing = env.get(name)
    env[name] = f"{directory}{os.pathsep}{existing}" if existing else str(directory)


def _write_json(path: Path, data: Any) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def execute(step, ctx: StepContext, registry: SecretRegistry) -> StepResult:
    project = ctx.project
    root = _root(project)
    config: AnsibleConfig = project.ansible if project is not None else AnsibleConfig()
    denylist = project_key_denylist(project)
    step_dir = ctx.step_dir
    step_dir.mkdir(parents=True, exist_ok=True)
    handoff_dir = ctx.run_dir.handoff_dir / step.id

    inline = dict(step.inventory.inline) if step.inventory.inline else None
    extra_vars = dict(step.extra_vars or {})
    registered, unprotected = register_secret_values(
        registry, {"extra_vars": extra_vars, "inventory": inline or {}}, denylist
    )

    env = dict(ctx.env)
    env.update({k: str(v) for k, v in config.env.items()})
    if step.playbook:
        playbook = _resolve_under(root, str(step.playbook), "playbook")
    else:
        playbook = step_dir / GENERATED_PLAYBOOK
        playbook.write_text(generate_role_playbook(str(step.role)), encoding="utf-8")
        _prepend_path(env, "ANSIBLE_ROLES_PATH", root / "roles")
        _prepend_path(env, "ANSIBLE_COLLECTIONS_PATH", root / "collections")

    warnings: list[str] = []
    if unprotected:
        warnings.append(
            "secret-named variable value(s) shorter than the registry minimum are not scrubbed: "
            + ", ".join(unprotected)
        )

    with ExitStack() as resources:
        events_path = step_dir / EVENTS_FILE
        sinks = {
            "stdout": resources.enter_context(LineSink(events_path, ctx.line_filter("stdout"))),
            "stderr": resources.enter_context(ctx.run_dir.line_sink(step.id, "stderr", ctx.line_filter("stderr"))),
        }

        def emit(channel: str, line: str) -> None:
            sinks[channel].write_line(line)

        callback, flush = terraform_stream(registry, emit)  # a StreamRedactor per channel; the name is historical
        runner = AnsibleRunner(root, env, stream=callback, local_temp=step_dir / "tmp")
        outcome: AnsibleResult | None = None
        error: str | None = None
        try:
            # inside the try: the live inventory may hold ansible_password & co., and anything that raises after it
            # was written (a TypeError while dumping the extra vars) must still delete it
            inventory_path, kept_inventory = _prepare_inventory(
                step, root, inline, handoff_dir, step_dir, registry, denylist
            )
            extra_vars_file = write_handoff(handoff_dir, EXTRA_VARS_FILE, extra_vars) if extra_vars else None
            kept_extra_vars = _keep_extra_vars(step_dir, extra_vars, registry, denylist)
            try:
                outcome = runner.run(
                    playbook,
                    inventory_path,
                    extra_vars_file=extra_vars_file,
                    tags=list(step.tags or []),
                    skip_tags=list(step.skip_tags or []),
                    limit=str(step.limit) if step.limit else None,
                    check=ctx.dry_run,
                    diff=ctx.dry_run,
                    timeout=ctx.timeout,
                )
            except AnsibleTimeout as e:
                raise StepTimeout(f"step {step.id}: {registry.redact(str(e))}") from None
            except AnsibleError as e:
                raise StepError(f"step {step.id}: {registry.redact(str(e))}") from None
            finally:
                flush()
                _write_json(step_dir / "argv.json", [[registry.redact(a) for a in r.argv] for r in runner.history])
                _write_json(step_dir / "env-names.json", sorted(runner.env))
        finally:
            shutil.rmtree(handoff_dir, ignore_errors=True)  # the handoff files live exactly as long as the playbook
            shutil.rmtree(step_dir / "tmp", ignore_errors=True)  # ANSIBLE_LOCAL_TEMP: a killed run leaves it behind

    assert outcome is not None
    mode = effective_check_unsupported(project, str(step.check_unsupported))
    check_unsupported = [[registry.redact(h), registry.redact(t)] for h, t in outcome.check_unsupported]
    if check_unsupported:
        names = "; ".join(f"{h}: {t}" for h, t in check_unsupported)
        if mode == "warn":
            warnings.append(f"task(s) skipped because the module does not support check mode: {names}")
        elif mode == "fail":
            error = f"check_unsupported: task(s) skipped because the module does not support check mode: {names}"

    result = {
        "rc": outcome.rc,
        "status_text": outcome.describe(),
        "stats": redact_tree(outcome.stats, registry),
        "failed_hosts": [registry.redact(h) for h in outcome.failed_hosts],
        "unreachable_hosts": [registry.redact(h) for h in outcome.unreachable_hosts],
        "check_unsupported": check_unsupported,
        "events_path": str(events_path),
        "stderr_path": str(step_dir / STDERR_FILE),
        "inventory_path": str(kept_inventory),
        "extra_vars_path": str(kept_extra_vars) if kept_extra_vars else None,
        "playbook": str(playbook),
        "duration_s": outcome.duration_s,
        "registered_vars": registered,
        "unprotected_vars": unprotected,
        "warnings": warnings,
    }
    outputs = {"inventory_path": str(kept_inventory)}
    if outcome.rc != 0:
        error = registry.redact(_failure_text(outcome))
    if error is not None:
        return StepResult("failed", outputs=outputs, result=result, error=error[:_ERROR_LIMIT])
    return StepResult("succeeded", outputs=outputs, result=result)


def _keep_extra_vars(
    step_dir: Path, extra_vars: Mapping[str, Any], registry: SecretRegistry, denylist: tuple[str, ...]
) -> Path | None:
    """``<step dir>/extra-vars.json`` (0600): the extra vars with registered values scrubbed and denylist-named keys
    replaced by ``<redacted:key>``, for the host-spec renderer. A stale copy from an earlier attempt is removed."""
    path = step_dir / EXTRA_VARS_FILE
    path.unlink(missing_ok=True)
    if not extra_vars:
        return None
    kept = redact_tree(json.loads(json.dumps(plain_tree(dict(extra_vars)))), registry, denylist)
    return write_private(path, json.dumps(kept, indent=2, sort_keys=True) + "\n")


def _prepare_inventory(
    step,
    root: Path,
    inline: dict[str, Any] | None,
    handoff_dir: Path,
    step_dir: Path,
    registry: SecretRegistry,
    denylist: tuple[str, ...],
) -> tuple[Path, Path]:
    """``(inventory passed to ansible-playbook, inventory path exposed as the implicit output)``."""
    if inline is None:
        path = _resolve_under(root, str(step.inventory.path), "inventory")
        return path, path
    try:
        text = generate_inventory(inline)
        kept_text = registry.redact(generate_inventory(redact_tree(inline, registry, denylist)))
    except ValueError as e:
        raise StepError(f"step {step.id}: {e}") from None
    handoff_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(handoff_dir, 0o700)
    live = write_private(handoff_dir / INVENTORY_FILE, text)
    kept = write_private(step_dir / INVENTORY_FILE, kept_text)
    return live, kept


def _failure_text(outcome: AnsibleResult) -> str:
    parts = [f"ansible-playbook exited {outcome.rc} ({outcome.describe()})"]
    if outcome.failed_hosts:
        parts.append("failed hosts: " + ", ".join(outcome.failed_hosts))
    if outcome.unreachable_hosts:
        parts.append("unreachable hosts: " + ", ".join(outcome.unreachable_hosts))
    last = outcome.last_failure()
    if last is not None:
        # never the exception text of a no_log result: it is the uncensored fail/assert message
        msg = last.get("msg") or (None if last.get("no_log") else last.get("exception")) or ""
        parts.append(f"last failure: [{last.get('host')}] {last.get('task')}: {msg}".rstrip(": "))
    elif not (outcome.failed_hosts or outcome.unreachable_hosts) and outcome.stderr_lines:
        # no host failed (a parser/CLI error exits 4 or 5 with no stats): the reason is only on stderr
        tail = "\n".join(outcome.stderr_lines).strip()[-_ERROR_LIMIT // 2 :]
        parts.append(tail)
    return "; ".join(parts)
