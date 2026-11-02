"""``spec-render`` with ``source.ansible``: the Ansible host spec (plan section 5.6), both scopes, one document.

``source.ansible: {inventory, host, play_scope?: {playbook, vars}, templates}`` renders
``specs/<stack-or-host>/hosts/<host>.yaml`` (``output``) and its ``.meta.yaml`` sidecar. What happens, in order:

1. **Inventory** is a project-relative path or an ``ansible`` step's ``inventory_path`` output
   (``<run>/steps/<id>/inventory.yml``, the redacted copy that step kept, with its redacted ``extra-vars.json``
   next to it). When the inventory has no ``group_vars``/``host_vars`` of its own, a **staged inventory** is built
   under ``<run>/handoff/<step id>/inventory/`` (0700, deleted when the step ends): the inventory file plus a
   **copy** of the playbook-adjacent ``group_vars``/``host_vars`` (the play-scope playbook's directory, else
   ``<project>/ansible``). The extra vars are never merged into the host entry (``host_vars`` files would outrank
   them there): the vars subprocess overlays them on top and the play scope passes them with ``-e``.
2. **Play scope, read first** (optional): every play of ``play_scope.playbook`` is read as YAML with ``!vault``
   values opaque (``specs.ansible_files``), and so are its roles' ``defaults``/``vars`` (every file Ansible reads,
   the ``main/`` directory form included) and its ``vars_files``. A file that does not parse fails the step before
   anything runs (fail closed: a play we cannot see into is not run).
3. **Inventory scope**: ``run_vars_subprocess`` (``python -m codeorca.specs.ansible_vars``) over that inventory,
   every roles dir (``<playbook dir>/roles``, ``<project>/ansible/roles``, ``<project>/roles``) for argument specs,
   the project's key and lookup denylists, the listed templates (a template whose own text calls a denied lookup is
   a marker and is never rendered, in either scope), the extra vars, the plays' host patterns (which plays target
   the host) and the lookup plugin names the play scope will see (resolved to FQCNs by ansible's loader); stderr
   lines go through the registry into the step's ``stderr.log``; the child env drops the redaction key and forces
   ``ANSIBLE_DEBUG=False``, ``ANSIBLE_LOG_PATH=/dev/null``, ``ANSIBLE_VERBOSITY=0`` (the play scope's runner forces
   the adapter's whole ``FORCED_ENV``): forced, not dropped, because a consumer's ``ansible.cfg`` would turn them
   back on.
4. **Play run**: only the plays whose ``hosts`` match the host give the generated check-mode play its roles, vars
   and ``vars_files`` (a play var that gets a marker is left out); ``AnsibleRunner`` runs it on the same inventory
   with ``--check --diff``, the project roles linked next to it, a random vault password (a consumer's vault
   config never decrypts anything here) and a 0600 ``-e @`` file (deleted afterwards) holding the redacted extra
   vars overlaid with **markers**, computed over EVERY play: every inventory-scope marker (``marker_vars``),
   ``<secret: declared>`` for every ``no_log`` option of the roles' argument specs, ``<skipped: key matches
   denylist>`` for every denylist-named var, ``<vault>`` for a vaulted role/play/vars_files value,
   ``<skipped: lookup … is a secret source>`` for a value whose lookup is on the denylist, and, for a var whose
   tree holds a denylist-named key (or a vaulted leaf) deeper down, the whole tree with those leaves replaced.
   ``-e`` outranks everything, so the play never renders those values. Every literal secret leaf of those sources
   is registered before the play starts; both output channels are **held** until the parsed vars have registered
   any value that still came out in clear, then written through the stream redactor (``play-scope-events.jsonl``,
   ``stderr.log``). Template tasks run with ``ignore_errors`` (one bad template hides nothing) and a task that
   never ran is ``not run`` in ``errors.play``.
5. **Merge** (deterministic): inventory entries get ``scope: inventory``. A play-scope var replaces the entry's
   ``resolved`` (dropping an inventory-scope ``error``) and gets ``scope: play``, unless the inventory already
   rendered it as a marker (the marker stays); its ``source`` names the play-scope source that won (``role
   defaults: <role>``, ``play vars: <playbook>``, ``vars_files: <file>``, ``role vars: <role>``; the inventory
   ``declared`` is dropped when that source outranks the inventory; extra vars keep their label). Argument-spec
   fields enrich play-scope entries; a ``no_log`` var is ``<secret: declared>`` in every entry and a denylist-named
   one a marker whatever the play printed. A play-scope template replaces the inventory-scope attempt (role
   defaults are invisible there) and drops its error. Template keys, provenance labels and ``inventory_source`` are
   project-relative (``run:steps/<id>/inventory.yml`` for a run-dir inventory), so the body holds no run id and a
   second run diffs empty.
6. ``build_host_document`` (registry scrub + key denylist on value trees), the redacted document saved as
   ``<step dir>/host-vars.json`` (0600, what ``codeorca render`` re-renders from), then ``header_for`` +
   ``write_spec`` (gate before any write) and a staged copy under ``<run>/specs/``.

A failing vars subprocess fails the step and writes nothing. A play scope that exits non-zero, or whose template or
vars task failed, still writes the spec (its ``errors.play`` says why) and then fails the step.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import ExitStack
from dataclasses import dataclass, field
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
from codeorca.specs.ansible_files import (
    VarsFileError,
    VaultValue,
    load_mapping_files,
    load_vars_yaml,
    role_vars_files,
)
from codeorca.specs.ansible_host import (
    TEMPLATE_TASK_PREFIX,
    VARS_TASK_NAME,
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
    VAULT,
    load_argument_specs,
    lookup_skip_reason,
    lookups_in,
    merge_specs,
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

# Precedence ranks (higher wins), ansible-core's variable precedence for the sources the play scope reads.
RANK_ROLE_DEFAULTS = 1
RANK_INVENTORY = 2
RANK_PLAY_VARS = 3
RANK_VARS_FILES = 4
RANK_ROLE_VARS = 5


@dataclass
class PlaySource:
    """One play of ``play_scope.playbook`` as plain YAML: its host pattern, roles, ``vars``, ``vars_files``."""

    hosts: str
    roles: list[str] = field(default_factory=list)
    vars: dict[str, Any] = field(default_factory=dict)
    vars_files: list[Any] = field(default_factory=list)  # absolute paths, or a list of alternatives


def read_playbook(path: Path) -> list[PlaySource]:
    """Every play of a playbook, read as plain YAML with ``!vault`` values opaque (``ansible_files``): ``roles:``
    entries (a string or ``{role|name: …}``) and ``import_role``/``include_role`` tasks (blocks included), ``vars``
    and ``vars_files`` (made absolute against the playbook's directory; a list entry is a list of alternatives). A
    role name that is templated or not a plain name/FQCN is left out. A playbook that is not YAML raises
    ``VarsFileError``: the caller fails closed instead of running a play it cannot see into."""
    data = load_vars_yaml(path)
    base = path.parent
    plays: list[PlaySource] = []

    def absolute(item: str) -> str:
        return item if os.path.isabs(item) or "{{" in item else str(base / item)

    for play in data if isinstance(data, list) else []:
        if not isinstance(play, Mapping) or any("import_playbook" in str(k) for k in play):
            continue
        hosts = play.get("hosts", "all")
        pattern = ",".join(str(h) for h in hosts) if isinstance(hosts, list) else str(hosts)
        source = PlaySource(hosts=pattern)

        def add_role(name: Any, roles: list[str] = source.roles) -> None:
            if isinstance(name, str) and name and "{" not in name and name not in roles:
                if all(ch.isalnum() or ch in "_.-" for ch in name):
                    roles.append(name)

        def walk(tasks: Any, add=add_role) -> None:
            if not isinstance(tasks, list):
                return
            for task in tasks:
                if not isinstance(task, Mapping):
                    continue
                for section in ("block", "rescue", "always"):
                    walk(task.get(section))
                for action in ROLE_ACTIONS & set(task):
                    spec = task[action]
                    add(spec.get("name") if isinstance(spec, Mapping) else spec)

        for entry in play.get("roles") or []:
            add_role(entry.get("role") or entry.get("name") if isinstance(entry, Mapping) else entry)
        for section in TASK_SECTIONS:
            walk(play.get(section))
        if isinstance(play.get("vars"), Mapping):
            source.vars = {str(k): v for k, v in play["vars"].items()}
        for item in play.get("vars_files") or []:
            if isinstance(item, str) and item:
                source.vars_files.append(absolute(item))
            elif isinstance(item, list):
                source.vars_files.append([absolute(str(i)) for i in item if i])
        plays.append(source)
    return plays


def playbook_scope(path: Path) -> tuple[list[str], dict[str, Any], list[Any]]:
    """``(roles, play vars, vars_files)`` of every play of a playbook merged in order (see :func:`read_playbook`)."""
    return merge_plays(read_playbook(path))


def merge_plays(plays: Sequence[PlaySource]) -> tuple[list[str], dict[str, Any], list[Any]]:
    roles: list[str] = []
    play_vars: dict[str, Any] = {}
    vars_files: list[Any] = []
    for play in plays:
        roles += [r for r in play.roles if r not in roles]
        play_vars.update(play.vars)
        vars_files += [f for f in play.vars_files if f not in vars_files]
    return roles, play_vars, vars_files


def _role_dir(role: str, roles_dirs: Sequence[Path]) -> Path | None:
    name = role.rsplit(".", 1)[-1]  # a collection role vendored under a roles dir, by its last FQCN segment
    return next((d / name for d in roles_dirs if (d / name).is_dir()), None)


def role_vars(roles: Sequence[str], roles_dirs: Sequence[Path]) -> dict[str, Any]:
    """Raw ``defaults`` then ``vars`` of every role found in ``roles_dirs`` (every file Ansible reads: ``main.yml``,
    ``main.yaml``, ``main.json``, a ``main/`` directory), used only to decide which markers to hand over."""
    return {name: max(values, key=lambda v: v[0])[2] for name, values in role_sources(roles, roles_dirs).items()}


def role_sources(roles: Sequence[str], roles_dirs: Sequence[Path]) -> dict[str, list[tuple[int, str, Any]]]:
    """``{name: [(rank, label, raw value)]}`` from every role's ``defaults`` and ``vars`` files."""
    out: dict[str, list[tuple[int, str, Any]]] = {}
    for role in roles:
        role_dir = _role_dir(role, roles_dirs)
        if role_dir is None:
            continue
        for sub, rank in (("defaults", RANK_ROLE_DEFAULTS), ("vars", RANK_ROLE_VARS)):
            label = f"role {sub}: {role}"
            for _path, data in load_mapping_files(role_vars_files(role_dir, sub)):
                for key, value in data.items():
                    out.setdefault(key, []).append((rank, label, value))
    return out


def vars_files_sources(vars_files: Sequence[Any], root: Path) -> tuple[dict[str, list[tuple[int, str, Any]]], list]:
    """``({name: [(rank, label, raw value)]}, warnings)`` from a play's ``vars_files`` (the first existing file of a
    list of alternatives). A templated path cannot be read here: a warning (its values reach the play unseen)."""
    out: dict[str, list[tuple[int, str, Any]]] = {}
    warnings: list[str] = []
    for item in vars_files:
        options = item if isinstance(item, list) else [item]
        if any("{{" in str(o) for o in options):
            warnings.append(f"vars_files entry {options!r} is templated: its values are not checked before the play")
            continue
        path = next((Path(o) for o in options if Path(o).is_file()), None)
        if path is None:
            continue
        for _path, data in load_mapping_files([path]):
            label = f"vars_files: {_rel(str(path), root)}"
            for key, value in data.items():
                out.setdefault(key, []).append((RANK_VARS_FILES, label, value))
    return out, warnings


def play_candidates(
    plays: Sequence[PlaySource], roles_dirs: Sequence[Path], root: Path, playbook_label: str
) -> tuple[dict[str, list[tuple[int, str, Any]]], list[str]]:
    """``({name: [(rank, label, raw value)]}, warnings)`` over the role defaults/vars, play vars and vars_files of
    ``plays``: every value the play scope will see that the inventory scope did not."""
    roles, play_vars, vars_files = merge_plays(plays)
    out = role_sources(roles, roles_dirs)
    for key, value in play_vars.items():
        out.setdefault(key, []).append((RANK_PLAY_VARS, f"play vars: {playbook_label}", value))
    files, warnings = vars_files_sources(vars_files, root)
    for key, values in files.items():
        out.setdefault(key, []).extend(values)
    return out, warnings


def argument_specs(roles_dirs: Sequence[Path]) -> dict[str, dict[str, Any]]:
    """Every roles dir's argument specs: the first documentation wins, ``no_log`` is OR-ed over all of them."""
    return merge_specs(*(load_argument_specs(d, _safe_load) for d in roles_dirs))


def _short_fqcn(name: str) -> str | None:
    return name if "." in name else f"ansible.builtin.{name}"


def lookup_names(values: Any) -> list[str]:
    """Every literal lookup plugin name in ``values`` (to have the vars subprocess resolve them to FQCNs)."""
    return sorted({name for name, _args in lookups_in(values) if name})


def _secret_tree(value: Any, patterns) -> tuple[Any, bool]:
    """``(value with every leaf under a denylist-named key (below the top) replaced by SKIPPED_KEY and every vaulted
    leaf by VAULT, changed)``."""
    changed = False

    def walk(node: Any, secret: bool) -> Any:
        nonlocal changed
        if isinstance(node, VaultValue):
            changed = True
            return VAULT
        if isinstance(node, Mapping):
            return {str(k): walk(v, secret or any(p.search(str(k)) for p in patterns)) for k, v in node.items()}
        if isinstance(node, list | tuple):
            return [walk(v, secret) for v in node]
        if secret and not is_marker(node):
            changed = True
            return SKIPPED_KEY
        return node

    return walk(value, False), changed


def handoff_markers(
    vars_json: Mapping[str, Any],
    specs: Mapping[str, Mapping[str, Any]],
    candidates: Mapping[str, Any],
    allow_list: Sequence[str],
    key_denylist: Sequence[str],
    lookup_denylist: Sequence[str],
    *,
    fqcns: Mapping[str, str | None] | None = None,
    extra_names: Sequence[str] = (),
) -> dict[str, Any]:
    """Every marker the play must see in place of a value (see the module docstring, step 3). ``candidates`` maps a
    name to its raw value, or to ``[(rank, label, raw value)]`` from :func:`play_candidates`. ``fqcns`` maps a lookup
    plugin name to the FQCN the vars subprocess resolved (routing redirects included, ``aws_ssm`` ->
    ``amazon.aws.aws_ssm``); a name it does not know falls back to ``ansible.builtin.<name>``. A var whose value tree
    holds a denylist-named key or a vaulted leaf deeper down gets the whole tree with those leaves replaced (``-e``
    replaces a var wholesale), from its highest-precedence source; extra vars are already redacted."""
    patterns = compile_key_denylist(key_denylist)
    resolved = dict(fqcns or {})

    def resolve(name: str) -> str | None:
        return resolved.get(name) or _short_fqcn(name)

    sources: dict[str, list[tuple[int, str, Any]]] = {
        name: (value if _is_ranked(value) else [(RANK_PLAY_VARS, "", value)]) for name, value in candidates.items()
    }
    for name, entry in (vars_json.get("vars") or {}).items():
        if isinstance(entry, Mapping) and "declared" in entry:
            sources.setdefault(str(name), []).append((RANK_INVENTORY, "inventory", entry["declared"]))

    markers: dict[str, Any] = dict(marker_vars(vars_json))
    for name, spec in specs.items():
        if spec.get("no_log") is True:
            markers.setdefault(name, SECRET_DECLARED)
    known = set(vars_json.get("vars") or {}) | set(candidates) | set(allow_list)
    for name in sorted(known):
        if name not in markers and any(p.search(name) for p in patterns):
            markers[name] = SKIPPED_KEY
    for name in sorted(candidates):
        if name in markers:
            continue
        for _rank, _label, raw in sources[name]:
            if isinstance(raw, VaultValue):
                markers[name] = VAULT
                break
            reason = lookup_skip_reason(raw, lookup_denylist, patterns, resolve)
            if reason:
                markers[name] = reason
                break
    for name in sorted(sources):
        if name in markers or name in extra_names:
            continue
        _rank, _label, top = max(sources[name], key=lambda v: v[0])
        masked, changed = _secret_tree(top, patterns)
        if changed:
            markers[name] = masked
    return dict(sorted(markers.items()))


def _is_ranked(value: Any) -> bool:
    return (
        isinstance(value, list)
        and bool(value)
        and all(isinstance(v, tuple) and len(v) == 3 and isinstance(v[0], int) for v in value)
    )


def secret_values(
    trees: Mapping[str, Any], specs: Mapping[str, Mapping[str, Any]], key_denylist: Sequence[str]
) -> list[str]:
    """Every literal leaf the registry must know before the play: the whole value of a ``no_log`` or denylist-named
    var, and every leaf under a denylist-named key deeper down. ``trees`` maps a name to a raw value or to
    ``[(rank, label, raw value)]``. Templates (``{{``) and markers are skipped: what they render is the play's."""
    patterns = compile_key_denylist(key_denylist)
    found: list[str] = []

    def walk(node: Any, secret: bool) -> None:
        if isinstance(node, Mapping):
            for k, v in node.items():
                walk(v, secret or any(p.search(str(k)) for p in patterns))
        elif isinstance(node, list | tuple):
            for v in node:
                walk(v, secret)
        elif secret and node is not None and not isinstance(node, bool | VaultValue) and not is_marker(node):
            text = str(node)
            if "{{" not in text and "{%" not in text:
                found.append(text)

    for name, value in trees.items():
        top = (specs.get(name) or {}).get("no_log") is True or any(p.search(name) for p in patterns)
        for _rank, _label, raw in value if _is_ranked(value) else [(0, "", value)]:
            walk(raw, top)
    return found


# -------------------------------------------------------------------------------------------- inventory


def stage_inventory(
    inventory: Path,
    host: str,
    vars_dir: Path | None,
    staging: Path,
) -> tuple[Path, Path | None, list[str]]:
    """``(inventory to use, directory whose group_vars/host_vars were copied or None, warnings)``. Staging happens
    only to borrow a playbook-adjacent ``group_vars``/``host_vars`` for an inventory that has none of its own; the
    producing step's extra vars are NOT merged into the host entry (``host_vars`` files would outrank them there):
    the vars subprocess overlays them on top (``--extra-vars-file``) and the play scope passes them with ``-e``."""
    warnings: list[str] = []
    own_vars = any((inventory.parent / d).is_dir() for d in VARS_DIRS)
    borrow = (
        vars_dir is not None
        and not own_vars
        and vars_dir.resolve() != inventory.parent.resolve()
        and any((vars_dir / d).is_dir() for d in VARS_DIRS)
    )
    if not borrow:
        return inventory, None, warnings
    if inventory.is_dir():
        warnings.append(f"inventory {inventory.name} is a directory: playbook group_vars not staged")
        return inventory, None, warnings
    assert vars_dir is not None
    staging.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(staging, 0o700)
    target = staging / inventory.name
    write_private(target, inventory.read_text(encoding="utf-8"))
    for name in VARS_DIRS:
        if (vars_dir / name).is_dir():
            shutil.copytree(vars_dir / name, staging / name, symlinks=False)
    return target, vars_dir, warnings


def relabel_sources(
    vars_json: dict[str, Any],
    *,
    producer: str | None,
    copied_from: Path | None,
    root: Path,
) -> None:
    """Make provenance labels stable and truthful after staging (in place): the subprocess's ``extra_vars`` source
    names the producing step; ``group_vars``/``host_vars`` labels of a borrowed tree get its project-relative dir."""
    prefix = None
    if copied_from is not None:
        prefix = _rel(str(copied_from.resolve()), root).rstrip("/")
    for entry in (vars_json.get("vars") or {}).values():
        if not isinstance(entry, dict):
            continue
        source = str(entry.get("source", ""))
        if source == "extra_vars":
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
    """The inventory-scope document with the play-scope results folded in (module docstring, step 4). Pure.

    ``play["provenance"]`` (``{name: [rank, label]}``, the highest-precedence play-scope source of each name) labels
    a play-scope value truthfully: when it outranks the inventory (play vars, ``vars_files``, role vars) the entry's
    ``source`` becomes that label and the inventory ``declared`` is dropped (it is not what produced ``resolved``);
    a name only role defaults define is ``role defaults: <role>``. Extra vars keep their label (they outrank all).
    A ``no_log`` var is ``<secret: declared>`` in every entry, whichever scope produced it."""
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
        provenance = {str(k): tuple(v) for k, v in (play.get("provenance") or {}).items()}
        for name, value in sorted((play.get("vars") or {}).items()):
            entry = variables.get(name)
            if isinstance(entry, dict) and is_marker(entry.get("resolved")):
                continue
            rank, label = provenance.get(name, (None, None))
            if isinstance(entry, dict):
                new = dict(entry)
                from_extra = str(new.get("source", "")).startswith("extra_vars")
                if label and not from_extra and rank is not None and rank > RANK_INVENTORY:
                    new["source"] = label
                    new.pop("declared", None)
            else:
                new = {"source": label or f"play: {playbook_label}"}
            spec = specs.get(name) or {}
            for field_name in SPEC_FIELDS:
                if field_name in spec:
                    new.setdefault(field_name, spec[field_name])
            if "role" in spec:
                new.setdefault("role", spec["role"])
            if any(p.search(name) for p in patterns):
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
    for name, entry in variables.items():  # no_log wins over every scope (a role outside the subprocess's view too)
        if isinstance(entry, dict) and (specs.get(name) or {}).get("no_log") is True:
            entry["declared"] = entry["resolved"] = SECRET_DECLARED
            entry.pop("error", None)
            errors["vars"].pop(name, None)
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
    """Register every play-scope leaf that should have been a marker but came out in clear: the whole value of a
    ``no_log`` or denylist-named var, and every leaf under a denylist-named key deeper down."""

    def walk(node: Any, secret: bool) -> None:
        if isinstance(node, Mapping):
            for k, v in node.items():
                walk(v, secret or any(p.search(str(k)) for p in patterns))
        elif isinstance(node, list | tuple):
            for v in node:
                walk(v, secret)
        elif secret and node is not None and not isinstance(node, bool) and not is_marker(node):
            registry.add(str(node))

    for name, value in values.items():
        walk(value, (specs.get(name) or {}).get("no_log") is True or any(p.search(name) for p in patterns))


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
    playbook_label = _label(playbook, root, ctx.run_dir) if playbook is not None else ""
    vars_dir = playbook.parent if playbook is not None else root / "ansible"
    roles_dirs: list[Path] = []
    for candidate in ([playbook.parent / "roles"] if playbook else []) + [root / "ansible" / "roles", root / "roles"]:
        if candidate.is_dir() and candidate.resolve() not in [d.resolve() for d in roles_dirs]:
            roles_dirs.append(candidate)
    specs = argument_specs(roles_dirs)

    warnings: list[str] = []
    plays: list[PlaySource] = []
    candidates: dict[str, list[tuple[int, str, Any]]] = {}
    if playbook is not None:
        try:  # before anything runs: a file the play would read but we cannot is a refusal, not a blind spot
            plays = read_playbook(playbook)
            candidates, candidate_warnings = play_candidates(plays, roles_dirs, root, playbook_label)
        except VarsFileError as e:
            raise StepError(f"spec-render: play scope: {e}") from None
        warnings += candidate_warnings

    extra_vars: dict[str, Any] = {}
    extra_vars_file: Path | None = None
    producer = None
    sibling = inventory.parent / EXTRA_VARS_SIBLING
    if inventory.is_file() and sibling.is_file():
        loaded = json.loads(sibling.read_text(encoding="utf-8"))
        extra_vars = loaded if isinstance(loaded, dict) else {}
        extra_vars_file = sibling if extra_vars else None
        try:
            producer = inventory.parent.resolve().relative_to(ctx.run_dir.steps_dir.resolve()).as_posix()
        except ValueError:
            producer = None

    play_result: dict[str, Any] | None = None
    play_rc: int | None = None
    with ExitStack() as resources:
        stderr_filter = ctx.line_filter("stderr") or registry.redact
        stderr_sink = resources.enter_context(ctx.run_dir.line_sink(step.id, "stderr", stderr_filter))
        try:
            staged, copied_from, stage_warnings = stage_inventory(inventory, host, vars_dir, handoff / "inventory")
            warnings += stage_warnings
            try:
                vars_json = run_vars_subprocess(
                    sys.executable,
                    staged,
                    host,
                    roles_dirs,
                    lookup_denylist,
                    denylist,
                    [str(t) for t in templates],
                    env,
                    stderr=lambda line: stderr_sink.write_line(registry.redact(line)),
                    cwd=root,
                    timeout=remaining(),
                    extra_vars_file=extra_vars_file,
                    play_hosts=sorted({p.hosts for p in plays}),
                    resolve_lookups=lookup_names([v for values in candidates.values() for _r, _l, v in values]),
                )
            except AnsibleVarsError as e:
                message = registry.redact(str(e))
                if "timed out" in message:
                    raise StepTimeout(f"step {step.id}: {message}") from None
                return StepResult("failed", result={"warnings": warnings}, error=f"spec-render: {message}")
            play_matches = vars_json.pop("_play_hosts", None) or {}
            fqcns = vars_json.pop("_lookup_fqcns", None) or {}
            skipped_templates = set(vars_json.pop("_skipped_templates", None) or [])
            relabel_sources(vars_json, producer=producer, copied_from=copied_from, root=root)
            if play_scope is not None and playbook is not None:
                matching = [p for p in plays if play_matches.get(p.hosts, True)]
                play_result, play_rc = _run_play_scope(
                    step,
                    ctx,
                    registry,
                    vars_json=vars_json,
                    inventory=staged,
                    playbook=playbook,
                    playbook_label=playbook_label,
                    plays=matching,
                    candidates=candidates,
                    fqcns=fqcns,
                    allow_list=list(play_scope.vars),
                    templates=[t for t in templates if str(t) not in skipped_templates],
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
                warnings += play_result.pop("warnings", [])
        finally:
            shutil.rmtree(handoff, ignore_errors=True)

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
    play_errors = document.get("errors", {}).get("play") or {}
    if play_rc not in (None, 0) or play_errors:
        # template tasks run with ignore_errors (one bad template must not hide the rest), so rc 0 can still mean
        # a template failed: the spec is written whole, the step fails
        failed = "; ".join(f"{k}: {v}" for k, v in play_errors.items())
        status = (play_result or {}).get("status_text") or describe_rc(play_rc or 0)
        error = f"play scope exited {play_rc} ({status})" + (f"; {failed}" if failed else "")
        return StepResult("failed", outputs=outputs, result=result, error=registry.redact(error)[:_ERROR_LIMIT])
    return StepResult("succeeded", outputs=outputs, result=result)


def _output_path(root: Path, output: str) -> Path:
    out = Path(output)
    return out if out.is_absolute() else root / out


def _unvault(value: Any) -> Any:
    if isinstance(value, VaultValue):
        return VAULT
    if isinstance(value, Mapping):
        return {str(k): _unvault(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_unvault(v) for v in value]
    return value


def _run_play_scope(
    step,
    ctx: StepContext,
    registry: SecretRegistry,
    *,
    vars_json: Mapping[str, Any],
    inventory: Path,
    playbook: Path,
    playbook_label: str,
    plays: Sequence[PlaySource],
    candidates: Mapping[str, list[tuple[int, str, Any]]],
    fqcns: Mapping[str, str | None],
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
    """Run the check-mode spec play. ``plays`` are the source plays whose ``hosts`` match the host (their roles,
    vars and vars_files go into the generated play); ``candidates`` cover EVERY play (markers are conservative)."""
    host = str(step.source.ansible.host)
    roles, play_vars, vars_files = merge_plays(plays)
    try:
        matching, warnings = play_candidates(plays, roles_dirs, root, playbook_label)
    except VarsFileError as e:
        raise StepError(f"spec-render: play scope: {e}") from None
    provenance = {name: list(max(values, key=lambda v: v[0])[:2]) for name, values in matching.items()}
    markers = handoff_markers(
        vars_json, specs, candidates, allow_list, denylist, lookup_denylist, fqcns=fqcns, extra_names=list(extra_vars)
    )
    # every literal secret the play could print is known before it starts (nested denylist-named leaves included)
    trees: dict[str, Any] = {name: list(values) for name, values in candidates.items()}
    for name, entry in (vars_json.get("vars") or {}).items():
        if isinstance(entry, Mapping) and "declared" in entry:
            trees.setdefault(str(name), []).append((RANK_INVENTORY, "inventory", entry["declared"]))
    for value in secret_values(trees, specs, denylist):
        registry.add(value)

    handoff.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(handoff, 0o700)
    play_path = handoff / PLAY_FILE
    expected = [f"{TEMPLATE_TASK_PREFIX}{t}" for t in templates] + ([VARS_TASK_NAME] if allow_list else [])
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
            play_vars={k: _unvault(v) for k, v in play_vars.items() if k not in markers} or None,
            vars_files=[f[0] if isinstance(f, list) and len(f) == 1 else f for f in vars_files],
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
    # no vault secret ever reaches the spec play: a vault password the consumer configured (env or ansible.cfg) is
    # replaced by a random one, so a vaulted value the markers missed fails to decrypt instead of rendering in clear
    no_vault = write_private(handoff / "vault-none.txt", secrets.token_hex(24) + "\n")
    play_env["ANSIBLE_VAULT_PASSWORD_FILE"] = str(no_vault)
    play_env["ANSIBLE_VAULT_IDENTITY_LIST"] = f"codeorca-none@{no_vault}"
    play_env["ANSIBLE_ASK_VAULT_PASS"] = "False"

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
        parsed = (
            parse_play_scope_events(outcome.events, host, expected if outcome.stats_seen else ())
            if outcome is not None
            else {"vars": {}}
        )
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
    parsed["provenance"] = provenance
    parsed["warnings"] = warnings
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
