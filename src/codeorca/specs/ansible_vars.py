"""Inventory-scope variable renderer for the Ansible host spec (plan section 5.6), run as a SUBPROCESS::

    python -m codeorca.specs.ansible_vars --inventory <path> --host <name> [--roles-path <dir>]
        [--lookup-denylist <fnmatch> ...] [--key-denylist <regex> ...] [--template <path.j2> ...]

It prints exactly one JSON document to stdout and nothing else; everything ansible-core itself prints (warnings,
deprecations, a lookup's chatter) is diverted to stderr at the file-descriptor level. The document may hold
secrets: the caller (``codeorca.specs.ansible_host.run_vars_subprocess``) keeps it in memory and redacts it;
this module never writes a file.

What it does, per host, with the public internal API verified at ansible-core 2.21.5 (``DataLoader`` ->
``InventoryManager`` -> ``VariableManager.get_vars(host=)`` -> ``Templar``):

- ``declared``: the value as loaded (templates still strings), ``resolved``: templated **key by key** so one
  bad key cannot mask the rest (an error is reported per key as ``error: "ExceptionName: message"``),
  ``source``: the ``group_vars``/``host_vars`` file or inventory entry the value came from (derived, see below).
- A var declared ``no_log: true`` in a role's ``meta/argument_specs.yml`` (``--roles-path``, nested options
  included) is ``<secret: declared>`` in both slots and never templated; vars found in a spec also carry
  ``role``, ``type``, ``description``, ``default``, ``required`` and ``no_log``.
- A var whose name matches ``--key-denylist`` is ``<skipped: key matches denylist>`` in both slots.
- A vaulted value (``EncryptedString``, detected before templating) is ``<vault>``; no vault secret is ever
  loaded here (no ``VaultSecretsContext``), so it could not be decrypted even by accident.
- Lookups execute during ``Templar.template()`` (``disable_lookups`` is a deprecated no-op), so every string
  leaf is regex-scanned for ``lookup(``/``query(``/``q(`` first; the plugin name is resolved to its FQCN when
  the plugin is installed. A lookup whose name (raw or FQCN) matches ``--lookup-denylist``, whose arguments
  match the key denylist, or whose plugin name is not a string literal, makes the var
  ``<skipped: lookup <name> is a secret source>`` (resp. ``... key matches denylist`` /
  ``... non-literal lookup``) and it is not templated. Other lookups (``file``, ``template`` ...) run.
- Templating uses the host's variables with every secret/skipped/vaulted var replaced by its marker, so a
  plain var or a ``--template`` file that references one renders the marker, never the value.
- ``--template`` files are read and wrapped with ``trust_as_template`` (an untrusted string is silently returned
  unrendered on 2.19+); ``_ANSIBLE_TEMPLAR_UNTRUSTED_TEMPLATE_BEHAVIOR=error`` is set before ansible is imported
  so a forgotten trust tag raises instead.
- Magic vars are skipped: ``hostvars``, ``groups``, ``omit``, ``vars``, ``group_names``, ``inventory_*``,
  ``playbook_dir``, ``ansible_playbook_python`` and every ``ansible_*`` except ``ansible_host``,
  ``ansible_port``, ``ansible_user``, ``ansible_connection``.
- Types are native (``"{{ 8000 + 80 }}"`` -> ``8080``); tagged containers are converted to plain ones before
  ``json.dumps``.

Provenance is derived, not reported by ansible: the ``group_vars``/``host_vars`` files next to the inventory are
loaded in precedence order (inventory group entries, ``group_vars`` for ``all`` then by group depth, the inventory
host entry, ``host_vars``) and the last file defining a key wins. Vars from a playbook-adjacent
``group_vars``, a vars plugin or ``-e`` are ``unknown``; play vars, role defaults and ``set_fact`` are never
visible here (play scope is a separate check-mode play, see ``ansible_host``).

Every ``ansible`` import is inside a function: the package must import without ansible-core installed.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

SECRET_DECLARED = "<secret: declared>"
SKIPPED_KEY = "<skipped: key matches denylist>"
VAULT = "<vault>"
SKIPPED_LOOKUP_FMT = "<skipped: lookup {name} is a secret source>"
SKIPPED_LOOKUP_ARG = "<skipped: lookup {name} argument matches the key denylist>"
SKIPPED_LOOKUP_DYNAMIC = "<skipped: non-literal lookup plugin name>"
UNTRUSTED_ENV = "_ANSIBLE_TEMPLAR_UNTRUSTED_TEMPLATE_BEHAVIOR"

MAGIC_SKIP = frozenset({"hostvars", "groups", "omit", "vars", "group_names", "playbook_dir", "ansible_playbook_python"})
CONNECTION_KEEP = frozenset({"ansible_host", "ansible_port", "ansible_user", "ansible_connection"})
VARS_FILE_SUFFIXES = (".yml", ".yaml", ".json")
SPEC_FIELDS = ("type", "description", "default", "required", "no_log")

# ``lookup('name', ...)`` / ``query("name", ...)`` / ``q('name', ...)`` with a literal plugin name; ``args`` is the
# text up to the first closing parenthesis (enough to match a denylist regex against the arguments).
LOOKUP_RE = re.compile(r"\b(?:lookup|query|q)\s*\(\s*(?P<quote>['\"])(?P<name>[\w.]+)(?P=quote)(?P<args>[^)]*)")
ANY_LOOKUP_RE = re.compile(r"\b(?:lookup|query|q)\s*\(")


def is_magic(name: str) -> bool:
    if name in MAGIC_SKIP or name.startswith("inventory_"):
        return True
    return name.startswith("ansible_") and name not in CONNECTION_KEEP


# ------------------------------------------------------------------------------------------------ pure helpers


def lookups_in(value: Any) -> list[tuple[str | None, str]]:
    """``[(plugin name or None when not a literal, argument text)]`` for every lookup call in every string leaf."""
    found: list[tuple[str | None, str]] = []
    for text in _string_leaves(value):
        literal_spans = []
        for m in LOOKUP_RE.finditer(text):
            found.append((m.group("name"), m.group("args")))
            literal_spans.append(m.start())
        for m in ANY_LOOKUP_RE.finditer(text):
            if m.start() not in literal_spans:
                found.append((None, ""))
    return found


def _string_leaves(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _string_leaves(v)
    elif isinstance(value, list | tuple):
        for v in value:
            yield from _string_leaves(v)


def lookup_denied(name: str, fqcn: str | None, patterns: Sequence[str]) -> bool:
    candidates = {name} | ({fqcn} if fqcn else set())
    return any(fnmatch.fnmatchcase(c, p) for c in candidates for p in patterns)


def lookup_skip_reason(
    value: Any,
    lookup_patterns: Sequence[str],
    key_patterns: Sequence[re.Pattern[str]],
    resolve: Any,
) -> str | None:
    """The marker that replaces ``resolved`` when a lookup in ``value`` must not run, else ``None``.
    ``resolve(name) -> fqcn | None`` maps a plugin name to its FQCN (``None`` when not installed)."""
    for name, args in lookups_in(value):
        if name is None:
            return SKIPPED_LOOKUP_DYNAMIC
        fqcn = resolve(name)
        shown = fqcn or name
        if lookup_denied(name, fqcn, lookup_patterns):
            return SKIPPED_LOOKUP_FMT.format(name=shown)
        if any(p.search(args) for p in key_patterns):
            return SKIPPED_LOOKUP_ARG.format(name=shown)
    return None


def load_argument_specs(roles_path: str | os.PathLike[str], load_yaml: Any) -> dict[str, dict[str, Any]]:
    """``{var name: {role, type, description, default, required, no_log}}`` over every
    ``<roles_path>/*/meta/argument_specs.yml`` (every entry point). A nested option with ``no_log: true`` marks its
    top-level var ``no_log``. The first role (sorted by name) that documents a var wins."""
    specs: dict[str, dict[str, Any]] = {}
    root = Path(roles_path)
    if not root.is_dir():
        return specs
    for role_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        for candidate in ("argument_specs.yml", "argument_specs.yaml"):
            spec_file = role_dir / "meta" / candidate
            if spec_file.is_file():
                break
        else:
            continue
        data = load_yaml(spec_file)
        entry_points = (data or {}).get("argument_specs") if isinstance(data, dict) else None
        if not isinstance(entry_points, dict):
            continue
        for ep in entry_points.values():
            options = (ep or {}).get("options") if isinstance(ep, dict) else None
            if not isinstance(options, dict):
                continue
            for var, opt in options.items():
                if not isinstance(opt, dict) or var in specs:
                    continue
                entry: dict[str, Any] = {"role": role_dir.name}
                for field in SPEC_FIELDS:
                    if field in opt:
                        entry[field] = opt[field]
                if _nested_no_log(opt):
                    entry["no_log"] = True
                specs[str(var)] = entry
    return specs


def _nested_no_log(opt: dict[str, Any]) -> bool:
    if opt.get("no_log") is True:
        return True
    nested = opt.get("options")
    if isinstance(nested, dict):
        return any(isinstance(o, dict) and _nested_no_log(o) for o in nested.values())
    return False


def vars_files_for(base: Path, name: str) -> list[Path]:
    """``base/<name>.yml|.yaml|.json`` and every vars file inside ``base/<name>/`` (sorted, hidden files skipped)."""
    files = [base / f"{name}{suffix}" for suffix in VARS_FILE_SUFFIXES]
    found = [f for f in files if f.is_file()]
    folder = base / name
    if folder.is_dir():
        found.extend(
            sorted(
                p
                for p in folder.iterdir()
                if p.is_file() and not p.name.startswith(".") and p.suffix in VARS_FILE_SUFFIXES
            )
        )
    return found


# -------------------------------------------------------------------------------------------- ansible side


def _plain(value: Any, encrypted_type: type, marker: str = VAULT) -> Any:
    """Tagged containers/scalars -> plain Python; ``EncryptedString`` leaves -> ``marker`` (never decrypted)."""
    if isinstance(value, encrypted_type):
        return marker
    if isinstance(value, dict):
        return {str(k): _plain(v, encrypted_type, marker) for k, v in value.items()}
    if isinstance(value, list | tuple | set):
        return [_plain(v, encrypted_type, marker) for v in value]
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        return int(value)
    if isinstance(value, float):
        return float(value)
    if isinstance(value, str):
        return str.__str__(value)
    return str(value)


def _contains_encrypted(value: Any, encrypted_type: type) -> bool:
    if isinstance(value, encrypted_type):
        return True
    if isinstance(value, dict):
        return any(_contains_encrypted(v, encrypted_type) for v in value.values())
    if isinstance(value, list | tuple):
        return any(_contains_encrypted(v, encrypted_type) for v in value)
    return False


def _error_text(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"


def collect(
    inventory: str,
    host_name: str,
    roles_path: str | None,
    lookup_denylist: Sequence[str],
    key_denylist: Sequence[str],
    templates: Sequence[str],
) -> dict[str, Any]:
    """The whole document for one host. Imports ansible; ``UNTRUSTED_ENV`` must already be set."""
    from ansible.inventory.helpers import sort_groups
    from ansible.inventory.manager import InventoryManager
    from ansible.parsing.dataloader import DataLoader
    from ansible.parsing.vault import EncryptedString
    from ansible.plugins.loader import init_plugin_loader, lookup_loader
    from ansible.release import __version__ as ansible_version
    from ansible.template import Templar, trust_as_template
    from ansible.vars.manager import VariableManager

    init_plugin_loader()
    inventory_path = Path(inventory).resolve()
    inventory_dir = inventory_path if inventory_path.is_dir() else inventory_path.parent
    loader = DataLoader()
    loader.set_basedir(str(inventory_dir))
    manager = InventoryManager(loader=loader, sources=[str(inventory_path)])
    host = manager.get_host(host_name)
    if host is None:
        raise SystemExit(f"host {host_name!r} is not in inventory {inventory_path}")
    variable_manager = VariableManager(loader=loader, inventory=manager)
    hostvars = variable_manager.get_vars(host=host)

    def load_yaml(path: Path) -> Any:
        return loader.load_from_file(str(path.resolve()))

    key_patterns = tuple(re.compile(p) for p in key_denylist)
    specs = load_argument_specs(roles_path, load_yaml) if roles_path else {}

    # provenance: inventory group entries < group_vars (all, then by depth) < inventory host entry < host_vars
    sources: dict[str, str] = {}
    inventory_name = inventory_path.name if inventory_path.is_file() else "inventory"
    groups = sort_groups(host.get_groups())
    for group in groups:
        for key in group.vars:
            sources[key] = f"{inventory_name} (group {group.name} entry)"
    for group in groups:
        for path in vars_files_for(inventory_dir / "group_vars", group.name):
            _record_sources(sources, load_yaml(path), path, inventory_dir)
    for key in host.vars:
        if key not in ("inventory_file", "inventory_dir"):
            sources[key] = f"{inventory_name} (host entry)"
    for path in vars_files_for(inventory_dir / "host_vars", host.name):
        _record_sources(sources, load_yaml(path), path, inventory_dir)

    fqcn_cache: dict[str, str | None] = {}

    def resolve(name: str) -> str | None:
        if name not in fqcn_cache:
            try:
                ctx = lookup_loader.find_plugin_with_context(name)
                fqcn_cache[name] = ctx.resolved_fqcn if ctx.resolved else None
            except Exception:  # a broken plugin must not stop the scan
                fqcn_cache[name] = None
        return fqcn_cache[name]

    # pass 1: classify every var without templating anything
    entries: dict[str, dict[str, Any]] = {}
    safe_vars: dict[str, Any] = dict(hostvars)
    to_render: list[str] = []
    for name in sorted(hostvars):
        if is_magic(name):
            continue
        raw = hostvars[name]
        entry: dict[str, Any] = {"declared": _plain(raw, EncryptedString), "source": sources.get(name, "unknown")}
        spec = specs.get(name)
        if spec:
            entry.update(spec)
        if spec and spec.get("no_log") is True:
            entry["declared"] = entry["resolved"] = SECRET_DECLARED
        elif any(p.search(name) for p in key_patterns):
            entry["declared"] = entry["resolved"] = SKIPPED_KEY
        elif _contains_encrypted(raw, EncryptedString):
            entry["resolved"] = VAULT
        else:
            reason = lookup_skip_reason(raw, lookup_denylist, key_patterns, resolve)
            if reason:
                entry["resolved"] = reason
            else:
                to_render.append(name)
        if "resolved" in entry:
            safe_vars[name] = entry["resolved"]
        entries[name] = entry

    # pass 2: template key by key over the sanitised variables
    templar = Templar(loader=loader, variables=safe_vars)
    errors: dict[str, dict[str, str]] = {"vars": {}, "templates": {}}
    for name in to_render:
        try:
            entries[name]["resolved"] = _plain(templar.template(hostvars[name]), EncryptedString)
        except Exception as exc:
            entries[name]["resolved"] = None
            entries[name]["error"] = errors["vars"][name] = _error_text(exc)

    rendered_templates: dict[str, str | None] = {}
    for template in templates:
        try:
            text = Path(template).read_text(encoding="utf-8")
            result = templar.template(trust_as_template(text))
            rendered_templates[template] = (
                result if isinstance(result, str) else json.dumps(_plain(result, EncryptedString))
            )
        except Exception as exc:
            rendered_templates[template] = None
            errors["templates"][template] = _error_text(exc)

    return {
        "host": host.name,
        "inventory_source": str(inventory_path),
        "engine": {"name": "ansible-core", "version": ansible_version},
        "vars": entries,
        "templates": rendered_templates,
        "errors": errors,
    }


def _record_sources(sources: dict[str, str], data: Any, path: Path, inventory_dir: Path) -> None:
    if isinstance(data, dict):
        try:
            label = str(path.resolve().relative_to(inventory_dir))
        except ValueError:
            label = str(path)
        for key in data:
            sources[str(key)] = label


# ---------------------------------------------------------------------------------------------------- CLI


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="python -m codeorca.specs.ansible_vars", description=__doc__.split("\n\n")[0])
    parser.add_argument("--inventory", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--roles-path")
    parser.add_argument("--lookup-denylist", action="append", default=[], metavar="FNMATCH")
    parser.add_argument("--key-denylist", action="append", default=[], metavar="REGEX")
    parser.add_argument("--template", action="append", default=[], metavar="PATH")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    os.environ[UNTRUSTED_ENV] = "error"  # before the first ansible import: the templar reads it at import
    # forced, not popped: env beats ansible.cfg, which could turn debug or a file log back on
    os.environ.update({"ANSIBLE_DEBUG": "False", "ANSIBLE_VERBOSITY": "0", "ANSIBLE_LOG_PATH": os.devnull})
    # Only the document may reach stdout: park the real stdout and point fd 1 at stderr for everything else.
    sys.stdout.flush()
    saved = os.dup(1)
    os.dup2(2, 1)
    try:
        document = collect(
            args.inventory, args.host, args.roles_path, args.lookup_denylist, args.key_denylist, args.template
        )
    except SystemExit as exc:
        print(f"ansible_vars: {exc}", file=sys.stderr)
        return 2
    payload = json.dumps(document, sort_keys=True).encode("utf-8")
    with os.fdopen(saved, "wb") as out:
        out.write(payload)
        out.write(b"\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
