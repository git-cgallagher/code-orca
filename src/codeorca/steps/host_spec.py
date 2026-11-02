"""``spec-render`` with ``source.ansible``: the Ansible host spec (plan section 5.6), both scopes, one document.

``source.ansible: {inventory, host, play_scope?: {playbook, vars}, templates}`` renders
``specs/<stack-or-host>/hosts/<host>.yaml`` (``output``) and its ``.meta.yaml`` sidecar. What happens, in order:

1. **Inventory** is a project-relative path or an ``ansible`` step's ``inventory_path`` output
   (``<run>/steps/<id>/inventory.yml``, the redacted copy that step kept). When needed, a **staged inventory** is
   built under ``<run>/handoff/<step id>/inventory/`` (0700, deleted when the step ends): the inventory file, with
   the producing step's handed-over extra vars (``<step dir>/extra-vars.json``, already redacted) merged into the
   host's entry, plus a **copy** of the playbook-adjacent ``group_vars``/``host_vars`` (the play-scope playbook's
   directory, else ``<project>/ansible``) when the inventory has none of its own. A copy, not a symlink: the
   provenance labels are made relative to the inventory directory after ``resolve()``. Staging happens only when
   there are extra vars or vars to borrow; a project inventory with its own ``group_vars`` is used in place.
2. **Inventory scope**: ``run_vars_subprocess`` (``python -m codeorca.specs.ansible_vars``) over that inventory,
   roles path ``<project>/ansible/roles``, the project's key and lookup denylists, the listed templates; stderr
   lines go through the registry into the step's ``stderr.log``; the child env drops the redaction key and forces
   ``ANSIBLE_DEBUG=False``, ``ANSIBLE_LOG_PATH=/dev/null``, ``ANSIBLE_VERBOSITY=0`` (the play scope's runner forces
   the adapter's whole ``FORCED_ENV``): forced, not dropped, because a consumer's ``ansible.cfg`` would turn them
   back on.
3. **Play scope** (optional): the roles, play ``vars`` and ``vars_files`` of ``play_scope.playbook`` are read from
   the file (a play var that gets a marker is left out), ``render_play_scope_playbook`` generates the check-mode
   play (written to the handoff dir, a registry-redacted copy kept as ``play-scope.yml``), and ``AnsibleRunner``
   runs it on the same inventory with ``--check --diff`` and a 0600 ``-e @`` file (deleted afterwards) holding
   the redacted extra vars overlaid with **markers**: every inventory-scope marker (``marker_vars``),
   ``<secret: declared>`` for every ``no_log`` option of the roles' argument specs, ``<skipped: key matches
   denylist>`` for every denylist-named var the inventory, the play vars or the roles' ``defaults``/``vars``
   define, and ``<skipped: lookup … is a secret source>`` for a play or role var whose lookup is on the denylist.
   ``-e`` outranks everything, so the play never renders those values. Both output channels are **held** until
   the parsed vars have registered any denylist-named or ``no_log`` value that still came out in clear, then
   written through the stream redactor (``play-scope-events.jsonl``, ``stderr.log``).
4. **Merge** (deterministic): inventory entries get ``scope: inventory``. A play-scope var replaces the entry's
   ``resolved`` (keeping ``declared``/``source``, dropping an inventory-scope ``error``) and gets ``scope: play``,
   unless the inventory already rendered it as a marker (the marker stays). Argument-spec fields enrich play-scope
   entries; a ``no_log`` or denylist-named var is a marker whatever the play printed. A play-scope template
   replaces the inventory-scope attempt (role defaults are invisible there) and drops its error. Template keys,
   provenance labels and ``inventory_source`` are project-relative (``run:steps/<id>/inventory.yml`` for a run-dir
   inventory), so the body holds no run id and a second run diffs empty.
5. ``build_host_document`` (registry scrub + key denylist on value trees), the redacted document saved as
   ``<step dir>/host-vars.json`` (0600, what ``codeorca render`` re-renders from), then ``header_for`` +
   ``write_spec`` (gate before any write) and a staged copy under ``<run>/specs/``.

A failing vars subprocess fails the step and writes nothing. A play scope that exits non-zero still writes the
spec (its ``errors.play`` says why) and then fails the step.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import ExitStack
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML

from codeorca.adapters.ansible import (
    DROPPED_ENV,
    HARDENED_ENV,
    AnsibleError,
    AnsibleRunner,
    AnsibleTimeout,
    describe_rc,
    generate_inventory,
    write_handoff,
    write_private,
)
from codeorca.project import AnsibleConfig, Project
from codeorca.redact import SecretRegistry, compile_key_denylist
from codeorca.rundir import LineSink, RunDir
from codeorca.runner import StepContext, StepError, StepResult, StepTimeout
from codeorca.secrets import key_denylist as project_key_denylist
from codeorca.secrets import terraform_stream
from codeorca.specs import SpecGateError, write_spec
from codeorca.specs.ansible_host import (
    TEMPLATE_TASK_PREFIX,
    AnsibleVarsError,
    build_host_document,
    header_for,
    is_marker,
    marker_vars,
    parse_play_scope_events,
    render_play_scope_playbook,
    run_vars_subprocess,
)
from codeorca.specs.ansible_vars import (
    SECRET_DECLARED,
    SKIPPED_KEY,
    SPEC_FIELDS,
    load_argument_specs,
    lookup_skip_reason,
)
from codeorca.steps.ansible import link_search_dirs

HOST_VARS_FILE = "host-vars.json"
PLAY_FILE = "play-scope.yml"
PLAY_EVENTS_FILE = "play-scope-events.jsonl"
PLAY_VARS_FILE = "play-vars.json"
STDERR_FILE = "stderr.log"
EXTRA_VARS_SIBLING = "extra-vars.json"
VARS_DIRS = ("group_vars", "host_vars")
ROLE_ACTIONS = frozenset(
    f"{prefix}{verb}_role" for prefix in ("", "ansible.builtin.", "ansible.legacy.") for verb in ("import", "include")
)
TASK_SECTIONS = ("pre_tasks", "tasks", "post_tasks", "handlers")
_ERROR_LIMIT = 2000


# ------------------------------------------------------------------------------------------------ helpers


def _root(project: Project | None) -> Path:
    if project is not None and project.root is not None:
        return project.root
    return Path.cwd()


def _resolve(root: Path, value: str, what: str) -> Path:
    path = Path(str(value))
    path = (path if path.is_absolute() else root / path).resolve()
    if not path.exists():
        raise StepError(f"spec-render: {what} {value!r} does not exist (resolved to {path})")
    return path


def _label(path: Path, root: Path, run_dir: RunDir) -> str:
    """A stable, checkout-independent name for ``path``: ``run:<relative to the run dir>`` inside the run
    directory, project-relative inside the project, the bare name otherwise."""
    resolved = path.resolve()
    try:
        return "run:" + resolved.relative_to(run_dir.path.resolve()).as_posix()
    except ValueError:
        pass
    try:
        return resolved.relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name


def _rel(path: str, root: Path) -> str:
    if not os.path.isabs(path):
        return path
    try:
        return Path(path).resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return os.path.relpath(path, root)


def _yaml_load(path: Path) -> Any:
    yaml = YAML(typ="safe", pure=True)
    return yaml.load(path.read_text(encoding="utf-8"))


def _safe_load(path: Path) -> Any:
    """``_yaml_load`` that returns ``None`` for a file plain YAML cannot read (a ``!vault`` tag, a syntax error)."""
    try:
        return _yaml_load(path)
    except Exception:  # noqa: BLE001 - best effort: the play itself reports real errors
        return None


def child_env(ctx_env: Mapping[str, str], config: AnsibleConfig) -> dict[str, str]:
    """The step env plus ``project.ansible.env``, minus the adapter's ``DROPPED_ENV`` (the redaction key) and with
    its ``HARDENED_ENV`` forced: dropping ``ANSIBLE_DEBUG``/``ANSIBLE_LOG_PATH``/``ANSIBLE_VERBOSITY`` is not enough,
    since each has an ``ansible.cfg`` twin that env outranks."""
    env = dict(ctx_env)
    env.update({k: str(v) for k, v in config.env.items()})
    env = {k: v for k, v in env.items() if k not in DROPPED_ENV}
    env.update(HARDENED_ENV)
    return env


def spec_stack(output: Path, host: str) -> str:
    """``specs/<stack>/hosts/<host>.yaml`` -> ``<stack>``; any other layout -> the host name."""
    if output.parent.name == "hosts" and output.parent.parent.name:
        return output.parent.parent.name
    return host


# --------------------------------------------------------------------------------------- playbook reading


def playbook_scope(path: Path) -> tuple[list[str], dict[str, Any], list[str]]:
    """``(roles, play vars, vars_files)`` of a playbook, read as plain YAML: ``roles:`` entries (a string or
    ``{role|name: …}``) and ``import_role``/``include_role`` tasks (blocks included) of every play, the plays'
    ``vars`` merged in order and their ``vars_files`` made absolute against the playbook's directory. A role name
    that is templated or not a plain name/FQCN is left out; a playbook plain YAML cannot read yields nothing."""
    data = _safe_load(path)
    roles: list[str] = []
    play_vars: dict[str, Any] = {}
    vars_files: list[str] = []
    base = path.parent

    def add_role(name: Any) -> None:
        if isinstance(name, str) and name and "{" not in name and name not in roles:
            if all(ch.isalnum() or ch in "_.-" for ch in name):
                roles.append(name)

    def walk(tasks: Any) -> None:
        if not isinstance(tasks, list):
            return
        for task in tasks:
            if not isinstance(task, Mapping):
                continue
            for section in ("block", "rescue", "always"):
                walk(task.get(section))
            for action in ROLE_ACTIONS & set(task):
                spec = task[action]
                add_role(spec.get("name") if isinstance(spec, Mapping) else spec)

    for play in data if isinstance(data, list) else []:
        if not isinstance(play, Mapping) or any("import_playbook" in str(k) for k in play):
            continue
        for entry in play.get("roles") or []:
            add_role(entry.get("role") or entry.get("name") if isinstance(entry, Mapping) else entry)
        for section in TASK_SECTIONS:
            walk(play.get(section))
        if isinstance(play.get("vars"), Mapping):
            play_vars.update({str(k): v for k, v in play["vars"].items()})
        for item in play.get("vars_files") or []:
            if isinstance(item, str) and item:
                vars_files.append(item if os.path.isabs(item) else str(base / item))
    return roles, play_vars, vars_files


def role_vars(roles: Sequence[str], roles_dirs: Sequence[Path]) -> dict[str, Any]:
    """Raw ``defaults`` then ``vars`` (``main.yml``/``main.yaml``) of every role found in ``roles_dirs`` (by the last
    FQCN segment for a collection role that is vendored there), used only to decide which markers to hand over."""
    found: dict[str, Any] = {}
    for role in roles:
        name = role.rsplit(".", 1)[-1]
        role_dir = next((d / name for d in roles_dirs if (d / name).is_dir()), None)
        if role_dir is None:
            continue
        for sub in ("defaults", "vars"):
            for candidate in ("main.yml", "main.yaml"):
                data = _safe_load(role_dir / sub / candidate) if (role_dir / sub / candidate).is_file() else None
                if isinstance(data, Mapping):
                    found.update({str(k): v for k, v in data.items()})
    return found


def argument_specs(roles_dirs: Sequence[Path]) -> dict[str, dict[str, Any]]:
    specs: dict[str, dict[str, Any]] = {}
    for directory in roles_dirs:
        for name, spec in load_argument_specs(directory, _safe_load).items():
            specs.setdefault(name, spec)
    return specs


def _short_fqcn(name: str) -> str | None:
    return name if "." in name else f"ansible.builtin.{name}"


def handoff_markers(
    vars_json: Mapping[str, Any],
    specs: Mapping[str, Mapping[str, Any]],
    candidates: Mapping[str, Any],
    allow_list: Sequence[str],
    key_denylist: Sequence[str],
    lookup_denylist: Sequence[str],
) -> dict[str, str]:
    """Every marker the play must see in place of a value (see the module docstring, step 3)."""
    patterns = compile_key_denylist(key_denylist)
    markers = marker_vars(vars_json)
    for name, spec in specs.items():
        if spec.get("no_log") is True:
            markers.setdefault(name, SECRET_DECLARED)
    known = set(vars_json.get("vars") or {}) | set(candidates) | set(allow_list)
    for name in sorted(known):
        if name not in markers and any(p.search(name) for p in patterns):
            markers[name] = SKIPPED_KEY
    for name, raw in sorted(candidates.items()):
        if name in markers:
            continue
        reason = lookup_skip_reason(raw, lookup_denylist, patterns, _short_fqcn)
        if reason:
            markers[name] = reason
    return dict(sorted(markers.items()))


# -------------------------------------------------------------------------------------------- inventory


def _merge_host_vars(tree: Any, host: str, extra: Mapping[str, Any]) -> bool:
    """Merge ``extra`` into every entry of ``host`` in a YAML inventory tree (in place); True when found."""
    found = False
    if not isinstance(tree, dict):
        return False
    for group in tree.values():
        if not isinstance(group, dict):
            continue
        hosts = group.get("hosts")
        if isinstance(hosts, dict) and host in hosts:
            current = hosts[host] if isinstance(hosts[host], dict) else {}
            hosts[host] = {**current, **extra}
            found = True
        if isinstance(group.get("children"), dict):
            found = _merge_host_vars(group["children"], host, extra) or found
    return found


def stage_inventory(
    inventory: Path,
    host: str,
    extra_vars: Mapping[str, Any],
    vars_dir: Path | None,
    staging: Path,
) -> tuple[Path, Path | None, list[str]]:
    """``(inventory to use, directory whose group_vars/host_vars were copied or None, warnings)``."""
    warnings: list[str] = []
    own_vars = any((inventory.parent / d).is_dir() for d in VARS_DIRS)
    borrow = (
        vars_dir is not None
        and not own_vars
        and vars_dir.resolve() != inventory.parent.resolve()
        and any((vars_dir / d).is_dir() for d in VARS_DIRS)
    )
    if not extra_vars and not borrow:
        return inventory, None, warnings
    if inventory.is_dir() or inventory.suffix not in (".yml", ".yaml"):
        warnings.append(f"inventory {inventory.name} is not a YAML file: extra vars and playbook group_vars not staged")
        return inventory, None, warnings
    staging.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(staging, 0o700)
    target = staging / inventory.name
    text = inventory.read_text(encoding="utf-8")
    if extra_vars:
        tree = _safe_load(inventory)
        if isinstance(tree, dict) and _merge_host_vars(tree, host, extra_vars):
            text = generate_inventory(tree)
        else:
            warnings.append(f"host {host!r} not found in a plain-YAML {inventory.name}: extra vars not shown")
    write_private(target, text)
    copied = None
    if borrow:
        assert vars_dir is not None
        for name in VARS_DIRS:
            if (vars_dir / name).is_dir():
                shutil.copytree(vars_dir / name, staging / name, symlinks=False)
        copied = vars_dir
    elif own_vars:
        for name in VARS_DIRS:
            if (inventory.parent / name).is_dir():
                shutil.copytree(inventory.parent / name, staging / name, symlinks=False)
    return target, copied, warnings


def relabel_sources(
    vars_json: dict[str, Any],
    *,
    extra_names: Sequence[str],
    producer: str | None,
    copied_from: Path | None,
    root: Path,
) -> None:
    """Make provenance labels stable and truthful after staging (in place)."""
    prefix = None
    if copied_from is not None:
        prefix = _rel(str(copied_from.resolve()), root).rstrip("/")
    for name, entry in (vars_json.get("vars") or {}).items():
        if not isinstance(entry, dict):
            continue
        source = str(entry.get("source", ""))
        if name in extra_names:
            entry["source"] = f"extra_vars (step {producer})" if producer else "extra_vars"
        elif prefix and source.split("/", 1)[0] in VARS_DIRS:
            entry["source"] = f"{prefix}/{source}" if prefix not in ("", ".") else source


# ------------------------------------------------------------------------------------------------ merge


def _task_key(task: str, root: Path) -> str:
    if task.startswith(TEMPLATE_TASK_PREFIX):
        return TEMPLATE_TASK_PREFIX + _rel(task[len(TEMPLATE_TASK_PREFIX) :], root)
    return task


def merge_play_scope(
    vars_json: Mapping[str, Any],
    play: Mapping[str, Any] | None,
    specs: Mapping[str, Mapping[str, Any]],
    key_denylist: Sequence[str],
    playbook_label: str,
    root: Path,
) -> dict[str, Any]:
    """The inventory-scope document with the play-scope results folded in (module docstring, step 4). Pure."""
    patterns = compile_key_denylist(key_denylist)
    out = json.loads(json.dumps(dict(vars_json), default=str))
    variables: dict[str, Any] = out.setdefault("vars", {})
    for entry in variables.values():
        if isinstance(entry, dict):
            entry.setdefault("scope", "inventory")
    errors = out.setdefault("errors", {})
    errors.setdefault("vars", {})
    template_errors = {_rel(k, root): v for k, v in (errors.get("templates") or {}).items()}
    out["templates"] = {_rel(k, root): v for k, v in (out.get("templates") or {}).items()}
    if play is not None:
        for name, value in sorted((play.get("vars") or {}).items()):
            entry = variables.get(name)
            if isinstance(entry, dict) and is_marker(entry.get("resolved")):
                continue
            new = dict(entry) if isinstance(entry, dict) else {"source": f"play: {playbook_label}"}
            spec = specs.get(name) or {}
            for field in SPEC_FIELDS:
                if field in spec:
                    new.setdefault(field, spec[field])
            if "role" in spec:
                new.setdefault("role", spec["role"])
            if spec.get("no_log") is True:
                new["declared"] = new["resolved"] = SECRET_DECLARED
            elif any(p.search(name) for p in patterns):
                new["declared"] = new["resolved"] = SKIPPED_KEY
            else:
                new["resolved"] = value
            new.pop("error", None)
            errors["vars"].pop(name, None)
            new["scope"] = "play"
            variables[name] = new
        for path, text in (play.get("templates") or {}).items():
            key = _rel(str(path), root)
            out["templates"][key] = text
            template_errors.pop(key, None)
        play_errors = {_task_key(k, root): v for k, v in (play.get("errors") or {}).items()}
        if play_errors:
            errors["play"] = play_errors
    errors["templates"] = template_errors
    return out


# ------------------------------------------------------------------------------------------- the step


def _deadline(timeout: float | None) -> Callable[[], float | None]:
    end = None if timeout is None else time.monotonic() + timeout

    def remaining() -> float | None:
        return None if end is None else max(end - time.monotonic(), 0.1)

    return remaining


def _register_clear_values(
    registry: SecretRegistry, values: Mapping[str, Any], specs: Mapping[str, Mapping[str, Any]], patterns
) -> None:
    """Register the leaves of every play-scope value that should have been a marker but came out in clear."""

    def leaves(node: Any):
        if isinstance(node, Mapping):
            for v in node.values():
                yield from leaves(v)
        elif isinstance(node, list | tuple):
            for v in node:
                yield from leaves(v)
        elif node is not None and not isinstance(node, bool):
            yield str(node)

    for name, value in values.items():
        secret = (specs.get(name) or {}).get("no_log") is True or any(p.search(name) for p in patterns)
        if secret and not is_marker(value):
            for leaf in leaves(value):
                registry.add(leaf)


def execute(step, ctx: StepContext, registry: SecretRegistry) -> StepResult:
    """The ``spec-render`` executor for ``source.ansible``."""
    project = ctx.project
    root = _root(project)
    config = project.ansible if project is not None else AnsibleConfig()
    denylist = project_key_denylist(project)
    lookup_denylist = tuple(project.redaction.lookup_denylist) if project is not None else ()
    source = step.source.ansible
    host = str(source.host)
    step_dir = ctx.step_dir
    step_dir.mkdir(parents=True, exist_ok=True)
    handoff = ctx.run_dir.handoff_dir / step.id
    remaining = _deadline(ctx.timeout)
    env = child_env(ctx.env, config)

    inventory = _resolve(root, str(source.inventory), "inventory")
    templates = [_resolve(root, str(t), "template") for t in source.templates]
    play_scope = source.play_scope
    playbook = _resolve(root, str(play_scope.playbook), "play_scope.playbook") if play_scope else None
    vars_dir = playbook.parent if playbook is not None else root / "ansible"
    roles_dirs: list[Path] = []
    for candidate in ([playbook.parent / "roles"] if playbook else []) + [root / "ansible" / "roles", root / "roles"]:
        if candidate.is_dir() and candidate.resolve() not in [d.resolve() for d in roles_dirs]:
            roles_dirs.append(candidate)
    roles_path = root / "ansible" / "roles"
    specs = argument_specs(roles_dirs)

    extra_vars: dict[str, Any] = {}
    producer = None
    sibling = inventory.parent / EXTRA_VARS_SIBLING
    if inventory.is_file() and sibling.is_file():
        loaded = json.loads(sibling.read_text(encoding="utf-8"))
        extra_vars = loaded if isinstance(loaded, dict) else {}
        try:
            producer = inventory.parent.resolve().relative_to(ctx.run_dir.steps_dir.resolve()).as_posix()
        except ValueError:
            producer = None

    warnings: list[str] = []
    play_result: dict[str, Any] | None = None
    play_rc: int | None = None
    with ExitStack() as resources:
        stderr_filter = ctx.line_filter("stderr") or registry.redact
        stderr_sink = resources.enter_context(ctx.run_dir.line_sink(step.id, "stderr", stderr_filter))
        try:
            staged, copied_from, stage_warnings = stage_inventory(
                inventory, host, extra_vars, vars_dir, handoff / "inventory"
            )
            warnings += stage_warnings
            try:
                vars_json = run_vars_subprocess(
                    sys.executable,
                    staged,
                    host,
                    roles_path if roles_path.is_dir() else None,
                    lookup_denylist,
                    denylist,
                    [str(t) for t in templates],
                    env,
                    stderr=lambda line: stderr_sink.write_line(registry.redact(line)),
                    cwd=root,
                    timeout=remaining(),
                )
            except AnsibleVarsError as e:
                message = registry.redact(str(e))
                if "timed out" in message:
                    raise StepTimeout(f"step {step.id}: {message}") from None
                return StepResult("failed", result={"warnings": warnings}, error=f"spec-render: {message}")
            relabel_sources(
                vars_json,
                extra_names=[k for k in extra_vars if _merged(staged, inventory)],
                producer=producer,
                copied_from=copied_from,
                root=root,
            )
            if play_scope is not None and playbook is not None:
                play_result, play_rc = _run_play_scope(
                    step,
                    ctx,
                    registry,
                    vars_json=vars_json,
                    inventory=staged,
                    playbook=playbook,
                    allow_list=list(play_scope.vars),
                    templates=templates,
                    extra_vars=extra_vars,
                    specs=specs,
                    roles_dirs=roles_dirs,
                    root=root,
                    env=env,
                    denylist=denylist,
                    lookup_denylist=lookup_denylist,
                    handoff=handoff,
                    stderr_sink=stderr_sink,
                    timeout=remaining(),
                )
        finally:
            shutil.rmtree(handoff, ignore_errors=True)

    playbook_label = _label(playbook, root, ctx.run_dir) if playbook is not None else ""
    merged = merge_play_scope(vars_json, play_result, specs, denylist, playbook_label, root)
    merged["inventory_source"] = _label(inventory, root, ctx.run_dir)
    document = build_host_document(merged, registry, denylist, base_dir=root)
    if play_scope is not None:
        document["play_scope"] = {
            "playbook": playbook_label,
            "vars": sorted(play_scope.vars),
            "roles": (play_result or {}).get("roles", []),
        }
    output = _output_path(root, str(step.output))
    run = ctx.run_dir.read_run() or {}
    result = write_host_spec(
        document,
        output,
        ctx.run_dir,
        step.id,
        registry,
        git_sha=run.get("git_sha"),
        workflow=run.get("workflow"),
    )
    result["warnings"] = warnings
    if play_rc is not None:
        result["play_scope_rc"] = play_rc
    outputs = {"path": result["path"]}
    if play_rc not in (None, 0):
        failed = "; ".join(f"{k}: {v}" for k, v in (document.get("errors", {}).get("play") or {}).items())
        status = (play_result or {}).get("status_text") or describe_rc(play_rc)
        error = f"play scope exited {play_rc} ({status})" + (f"; {failed}" if failed else "")
        return StepResult("failed", outputs=outputs, result=result, error=registry.redact(error)[:_ERROR_LIMIT])
    return StepResult("succeeded", outputs=outputs, result=result)


def _merged(staged: Path, inventory: Path) -> bool:
    return staged.resolve() != inventory.resolve()


def _output_path(root: Path, output: str) -> Path:
    out = Path(output)
    return out if out.is_absolute() else root / out


def _run_play_scope(
    step,
    ctx: StepContext,
    registry: SecretRegistry,
    *,
    vars_json: Mapping[str, Any],
    inventory: Path,
    playbook: Path,
    allow_list: list[str],
    templates: list[Path],
    extra_vars: Mapping[str, Any],
    specs: Mapping[str, Mapping[str, Any]],
    roles_dirs: list[Path],
    root: Path,
    env: dict[str, str],
    denylist: Sequence[str],
    lookup_denylist: Sequence[str],
    handoff: Path,
    stderr_sink: LineSink,
    timeout: float | None,
) -> tuple[dict[str, Any], int]:
    host = str(step.source.ansible.host)
    roles, play_vars, vars_files = playbook_scope(playbook)
    candidates = {**role_vars(roles, roles_dirs), **play_vars}
    markers = handoff_markers(vars_json, specs, candidates, allow_list, denylist, lookup_denylist)
    handoff.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(handoff, 0o700)
    play_path = handoff / PLAY_FILE
    try:
        text = render_play_scope_playbook(
            play_path,
            allow_list,
            [str(t) for t in templates],
            ctx.step_dir / "play-out",
            host=host,
            roles=roles,
            # a marker'd name never enters the generated play: -e would override it anyway, and a literal secret in
            # the playbook's own vars must not reach the kept copy of the play
            play_vars={k: v for k, v in play_vars.items() if k not in markers} or None,
            vars_files=vars_files,
        )
    except ValueError as e:
        raise StepError(f"step {step.id}: {e}") from None
    write_private(play_path, text)
    write_private(ctx.step_dir / PLAY_FILE, registry.redact(text))
    play_vars_file = write_handoff(handoff, PLAY_VARS_FILE, {**dict(extra_vars), **markers})

    # the roles dirs and the collections dir as playbook-adjacent symlinks: ANSIBLE_ROLES_PATH /
    # ANSIBLE_COLLECTIONS_PATH would replace Ansible's defaults and any ansible.cfg paths
    play_env = dict(env)
    links = handoff / "roles"
    links.mkdir(mode=0o700, exist_ok=True)
    for directory in roles_dirs:
        for role_dir in sorted(d for d in directory.iterdir() if d.is_dir() and not d.name.startswith(".")):
            if not (links / role_dir.name).exists():
                (links / role_dir.name).symlink_to(role_dir.resolve(), target_is_directory=True)
    collections = next((c for c in (playbook.parent / "collections", root / "collections") if c.is_dir()), None)
    link_search_dirs(handoff, None, collections)

    held: list[tuple[str, str]] = []  # (line, channel): nothing is written before the clear values are registered
    runner = AnsibleRunner(
        root, play_env, stream=lambda line, channel: held.append((line, channel)), local_temp=ctx.step_dir / "tmp"
    )
    outcome = None
    try:
        outcome = runner.run(
            play_path, inventory, extra_vars_file=play_vars_file, check=True, diff=True, timeout=timeout
        )
    except AnsibleTimeout as e:
        raise StepTimeout(f"step {step.id}: play scope: {registry.redact(str(e))}") from None
    except AnsibleError as e:
        raise StepError(f"step {step.id}: play scope: {registry.redact(str(e))}") from None
    finally:
        parsed = parse_play_scope_events(outcome.events, host) if outcome is not None else {"vars": {}}
        _register_clear_values(registry, parsed.get("vars") or {}, specs, compile_key_denylist(denylist))
        with LineSink(ctx.step_dir / PLAY_EVENTS_FILE) as events_sink:
            sinks = {"stdout": events_sink, "stderr": stderr_sink}
            callback, flush = terraform_stream(registry, lambda channel, line: sinks[channel].write_line(line))
            for line, channel in held:
                callback(line, channel)
            flush()
        argv = [[registry.redact(a) for a in r.argv] for r in runner.history]
        (ctx.step_dir / "argv.json").write_text(json.dumps(argv, indent=2) + "\n", encoding="utf-8")
        shutil.rmtree(ctx.step_dir / "tmp", ignore_errors=True)  # ANSIBLE_LOCAL_TEMP
    parsed["roles"] = roles
    parsed["status_text"] = outcome.describe()
    if not outcome.stats_seen and outcome.rc != 0 and outcome.stderr_lines:
        # a play that did not parse leaves its reason on stderr only
        tail = "\n".join(outcome.stderr_lines).strip()[-500:]
        parsed.setdefault("errors", {})["ansible-playbook"] = registry.redact(tail)
    return parsed, outcome.rc


def write_host_spec(
    document: Mapping[str, Any],
    output: Path,
    run_dir: RunDir,
    step_id: str,
    registry: SecretRegistry,
    *,
    git_sha: str | None,
    workflow: str | None,
    save: bool = True,
) -> dict[str, Any]:
    """Persist ``host-vars.json`` (when ``save``), then render the spec + sidecar and stage both under the run
    dir. ``codeorca render`` calls this with ``save=False`` on the document read back from ``host-vars.json``."""
    step_dir = run_dir.step_dir(step_id)
    host_vars = step_dir / HOST_VARS_FILE
    text = json.dumps(document, indent=2, sort_keys=True) + "\n"
    if registry.count_matches(text):
        raise StepError(f"redaction gate: registered value found in the host document; not written: {host_vars}")
    if save:
        write_private(host_vars, text)
    host = str(document.get("host", ""))
    stack = spec_stack(output, host)
    header = header_for(document, registry.key_id, git_sha, stack=stack, workflow=workflow)
    meta = {"run_id": run_dir.run_id, "source": host_vars.relative_to(run_dir.path).as_posix(), "host": host}
    try:
        spec_path, sidecar = write_spec(output, document, header, meta, registry)
    except SpecGateError as e:
        raise StepError(str(e)) from None
    staged_dir = run_dir.specs_dir / stack / "hosts"
    staged_dir.mkdir(parents=True, exist_ok=True)
    staged = [shutil.copy2(p, staged_dir / p.name) for p in (spec_path, sidecar)]
    return {
        "path": str(spec_path),
        "meta_path": str(sidecar),
        "host_vars_path": str(host_vars),
        "staged": [str(p) for p in staged],
        "stack": stack,
        "host": host,
        "gate": header["gate"],
    }


def read_host_document(run_dir: RunDir, step_id: str) -> dict[str, Any] | None:
    path = run_dir.steps_dir / step_id / HOST_VARS_FILE
    if not path.is_file():
        return None
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or document.get("kind") != "ansible_host":
        raise StepError(f"spec-render: {path} is not an ansible_host document")
    return document


__all__ = [
    "HOST_VARS_FILE",
    "argument_specs",
    "execute",
    "handoff_markers",
    "merge_play_scope",
    "playbook_scope",
    "read_host_document",
    "relabel_sources",
    "spec_stack",
    "stage_inventory",
    "write_host_spec",
]
