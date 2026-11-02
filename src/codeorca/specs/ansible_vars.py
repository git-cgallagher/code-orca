"""Inventory-scope variable renderer for the Ansible host spec (plan section 5.6), run as a SUBPROCESS::

    python -m codeorca.specs.ansible_vars --inventory <path> --host <name> [--roles-path <dir> ...]
        [--lookup-denylist <fnmatch> ...] [--key-denylist <regex> ...] [--template <path.j2> ...]
        [--extra-vars-file <json>] [--play-hosts <pattern> ...] [--resolve-lookup <name> ...]

It prints exactly one JSON document to stdout and nothing else; everything ansible-core itself prints (warnings,
deprecations, a lookup's chatter) is diverted to stderr at the file-descriptor level. The document may hold
secrets: the caller (``codeorca.specs.ansible_host.run_vars_subprocess``) keeps it in memory and redacts it;
this module never writes a file.

What it does, per host, with the public internal API verified at ansible-core 2.21.5 (``DataLoader`` ->
``InventoryManager`` -> ``VariableManager.get_vars(host=)`` -> ``Templar``):

- ``declared``: the value as loaded (templates still strings), ``resolved``: templated **key by key** so one
  bad key cannot mask the rest (an error is reported per key as ``error: "ExceptionName: message"``),
  ``source``: the ``group_vars``/``host_vars`` file or inventory entry the value came from (derived, see below).
- A var declared ``no_log: true`` in a role's argument spec (``meta/argument_specs.yml``, else the
  ``argument_specs`` key of ``meta/main.yml``, as ansible-core reads it; every ``--roles-path``; nested options
  included; ``no_log`` wins when ANY role or entry point says so) is ``<secret: declared>`` in both slots and
  never templated; vars found in a spec also carry ``role``, ``type``, ``description``, ``default``, ``required``
  and ``no_log`` (from the first role that documents them, as plain JSON: a YAML date default becomes a string).
- A var whose name matches ``--key-denylist`` is ``<skipped: key matches denylist>`` in both slots. A var whose
  value tree has a denylist-named key deeper down (``app_db: {user: app, password: …}``) is templated, and seen by
  every template, with those leaves replaced by the marker (``build_host_document`` key-redacts its own trees).
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
  so a forgotten trust tag raises instead. Before rendering, the template TEXT gets the same lookup scan as a var
  value: a denied lookup makes the template's result the ``<skipped: …>`` marker (it is listed in
  ``_skipped_templates`` so the play scope does not render it either). Rendering mirrors the ``template`` action:
  searchpath = the template's directory and its ``templates/`` sibling dir (``{% include %}`` works) and the action's
  variables (``ansible_managed``, ``template_path`` ...) via ``generate_ansible_template_vars``.
- ``--extra-vars-file`` (JSON, the producing step's redacted extra vars) is overlaid on top of ``get_vars``:
  extra vars outrank everything, ``host_vars`` files included; their source is ``extra_vars``.
- Underscore keys are for the caller only and never reach a spec: ``_play_hosts`` (``{pattern: bool}``, whether the
  host matches each ``--play-hosts`` pattern, via ``InventoryManager.get_hosts``; a templated pattern counts as a
  match), ``_lookup_fqcns`` (``{name: fqcn | null}`` for every ``--resolve-lookup``, routing redirects followed) and
  ``_skipped_templates``.
- Magic vars are skipped: ``hostvars``, ``groups``, ``omit``, ``vars``, ``group_names``, ``inventory_*``,
  ``playbook_dir``, ``ansible_playbook_python`` and every ``ansible_*`` except ``ansible_host``,
  ``ansible_port``, ``ansible_user``, ``ansible_connection``.
- Types are native (``"{{ 8000 + 80 }}"`` -> ``8080``); tagged containers are converted to plain ones before
  ``json.dumps``.

Provenance is derived, not reported by ansible: the ``group_vars``/``host_vars`` files next to the inventory, found
with ``DataLoader.find_vars_files`` (Ansible's own selection: extensionless and nested files included, the first of
``name``/``name.yml``/``name.yaml``/``name.json`` only), are loaded in precedence order (inventory group entries,
``group_vars`` for ``all`` then by group depth, the inventory host entry, ``host_vars``) and the last file defining
a key wins; labels are relative to the inventory directory without resolving symlinks (a shared, symlinked
``group_vars/all.yml`` keeps a checkout-independent label). Vars from a playbook-adjacent
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


JINJA_CODE_RE = re.compile(r"\{\{.*?\}\}|\{%.*?%\}", re.DOTALL)


def jinja_code(text: str) -> str:
    """Only the ``{{ … }}`` and ``{% … %}`` parts of a template: prose such as "DNS lookup (cached)" is not a call."""
    return "\n".join(JINJA_CODE_RE.findall(text))


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


ARGUMENT_SPEC_FILES = ("argument_specs.yml", "argument_specs.yaml")
META_MAIN_FILES = ("main.yml", "main.yaml", "main.json", "main")


def role_entry_points(role_dir: Path, load_yaml: Any) -> dict[str, Any]:
    """The ``argument_specs`` entry points of one role: ``meta/argument_specs.yml|yaml``, else the
    ``argument_specs`` key of ``meta/main.yml|yaml|json`` (ansible-core's fallback, ``Role._load_argument_specs``)."""
    meta = role_dir / "meta"
    for names in (ARGUMENT_SPEC_FILES, META_MAIN_FILES):
        spec_file = next((meta / n for n in names if (meta / n).is_file()), None)
        if spec_file is None:
            continue
        data = load_yaml(spec_file)
        entry_points = data.get("argument_specs") if isinstance(data, dict) else None
        if isinstance(entry_points, dict):
            return entry_points
        if names is ARGUMENT_SPEC_FILES:
            return {}
    return {}


def _jsonable(value: Any) -> Any:
    """Plain JSON data (a YAML date default is a ``datetime.date``, which ``json.dumps`` refuses)."""
    return json.loads(json.dumps(value, default=str))


def load_argument_specs(roles_path: str | os.PathLike[str], load_yaml: Any) -> dict[str, dict[str, Any]]:
    """``{var name: {role, type, description, default, required, no_log}}`` over every role under ``roles_path``
    (every entry point). A nested option with ``no_log: true`` marks its top-level var ``no_log``. The first role
    (sorted by name) and entry point that documents a var gives the documentation fields; ``no_log`` is OR-ed over
    all of them, so a later role's ``no_log: true`` is never lost."""
    specs: dict[str, dict[str, Any]] = {}
    root = Path(roles_path)
    if not root.is_dir():
        return specs
    for role_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        for ep in role_entry_points(role_dir, load_yaml).values():
            options = (ep or {}).get("options") if isinstance(ep, dict) else None
            if not isinstance(options, dict):
                continue
            for var, opt in options.items():
                if not isinstance(opt, dict):
                    continue
                name = str(var)
                if name not in specs:
                    entry: dict[str, Any] = {"role": role_dir.name}
                    for field in SPEC_FIELDS:
                        if field in opt:
                            entry[field] = _jsonable(opt[field])
                    specs[name] = entry
                if _nested_no_log(opt):
                    specs[name]["no_log"] = True
    return specs


def merge_specs(*spec_maps: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Several roles dirs' specs: the first documentation wins, ``no_log`` is OR-ed."""
    merged: dict[str, dict[str, Any]] = {}
    for specs in spec_maps:
        for name, spec in specs.items():
            if name not in merged:
                merged[name] = dict(spec)
            elif spec.get("no_log") is True:
                merged[name]["no_log"] = True
    return merged


def _nested_no_log(opt: dict[str, Any]) -> bool:
    if opt.get("no_log") is True:
        return True
    nested = opt.get("options")
    if isinstance(nested, dict):
        return any(isinstance(o, dict) and _nested_no_log(o) for o in nested.values())
    return False


def vars_files_for(base: Path, name: str) -> list[Path]:
    """The vars files Ansible reads for ``base/<name>`` (``DataLoader.find_vars_files``, mirrored by
    ``codeorca.specs.ansible_files``)."""
    from codeorca.specs.ansible_files import find_vars_files

    return find_vars_files(base, name)


def mask_denylisted(value: Any, key_patterns: Sequence[re.Pattern[str]], encrypted_type: type | None = None):
    """``(copy of value with every leaf under a denylist-named key replaced by SKIPPED_KEY (and every vaulted
    leaf by VAULT), changed)``. Only keys BELOW the top level are tested: the top-level name is the caller's."""
    changed = False

    def walk(node: Any, secret: bool) -> Any:
        nonlocal changed
        if encrypted_type is not None and isinstance(node, encrypted_type):
            changed = True
            return VAULT
        if isinstance(node, dict):
            out = {}
            for k, v in node.items():
                hit = secret or any(p.search(str(k)) for p in key_patterns)
                out[k] = walk(v, hit)
            return out
        if isinstance(node, list | tuple):
            return [walk(v, secret) for v in node]
        if secret:
            changed = True
            return SKIPPED_KEY
        return node

    return walk(value, False), changed


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
    roles_paths: Sequence[str] | str | None,
    lookup_denylist: Sequence[str],
    key_denylist: Sequence[str],
    templates: Sequence[str],
    *,
    extra_vars_file: str | None = None,
    play_hosts: Sequence[str] = (),
    resolve_lookups: Sequence[str] = (),
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

    if isinstance(roles_paths, str):
        roles_paths = [roles_paths]

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
    hostvars = dict(variable_manager.get_vars(host=host))
    extra_vars: dict[str, Any] = {}
    if extra_vars_file:
        loaded = json.loads(Path(extra_vars_file).read_text(encoding="utf-8"))
        extra_vars = loaded if isinstance(loaded, dict) else {}
        hostvars.update(extra_vars)  # -e outranks everything, host_vars files included

    def load_yaml(path: Path) -> Any:
        return loader.load_from_file(str(path.resolve()))

    key_patterns = tuple(re.compile(p) for p in key_denylist)
    specs = merge_specs(*(load_argument_specs(p, load_yaml) for p in (roles_paths or ())))

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
    for key in extra_vars:
        sources[str(key)] = "extra_vars"

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
            entry.update(_jsonable(spec))
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
        elif name in to_render:
            # a denylist-named key deeper in the tree: every template sees the marker there, never the value
            masked, changed = mask_denylisted(raw, key_patterns)
            if changed:
                safe_vars[name] = masked
        entries[name] = entry

    # pass 2: template key by key over the sanitised variables
    templar = Templar(loader=loader, variables=safe_vars)
    errors: dict[str, dict[str, str]] = {"vars": {}, "templates": {}}
    for name in to_render:
        try:
            entries[name]["resolved"] = _plain(templar.template(safe_vars[name]), EncryptedString)
        except Exception as exc:
            entries[name]["resolved"] = None
            entries[name]["error"] = errors["vars"][name] = _error_text(exc)

    rendered_templates: dict[str, str | None] = {}
    skipped_templates: list[str] = []
    for template in templates:
        try:
            text = Path(template).read_text(encoding="utf-8")
            reason = lookup_skip_reason(jinja_code(text), lookup_denylist, key_patterns, resolve)
            if reason:
                # the text itself calls a denied lookup: never rendered, in either scope
                rendered_templates[template] = reason
                skipped_templates.append(template)
                continue
            result = _render_template(templar, safe_vars, template, trust_as_template(text), inventory_dir)
            rendered_templates[template] = (
                result if isinstance(result, str) else json.dumps(_plain(result, EncryptedString))
            )
        except Exception as exc:
            rendered_templates[template] = None
            errors["templates"][template] = _error_text(exc)

    matches: dict[str, bool] = {}
    for pattern in play_hosts:
        if "{{" in pattern or "{%" in pattern:
            matches[pattern] = True  # cannot evaluate a templated pattern here: assume it targets the host
            continue
        try:
            matches[pattern] = any(h.name == host.name for h in manager.get_hosts(pattern=pattern))
        except Exception:  # a pattern ansible refuses: conservative
            matches[pattern] = True

    return {
        "host": host.name,
        "inventory_source": str(inventory_path),
        "engine": {"name": "ansible-core", "version": ansible_version},
        "vars": entries,
        "templates": rendered_templates,
        "errors": errors,
        "_play_hosts": matches,
        "_lookup_fqcns": {name: resolve(name) for name in resolve_lookups},
        "_skipped_templates": skipped_templates,
    }


def _render_template(templar: Any, variables: dict[str, Any], template: str, text: str, basedir: Path) -> Any:
    """Render like the ``template`` action: searchpath = the template's dir and its ``templates/`` sibling (plus the
    loader basedir), and the action's own variables (``ansible_managed``, ``template_path`` ...)."""
    source = Path(template).resolve()
    searchpath: list[str] = []
    for path in (str(basedir), str(source.parent)):
        searchpath += [os.path.join(path, "templates"), path]
    template_vars = dict(variables)
    try:
        from ansible.template import generate_ansible_template_vars

        template_vars.update(generate_ansible_template_vars(str(template), fullpath=str(source)))
    except Exception:  # deprecated in 2.23: the template still renders without the extras
        pass
    data_templar = templar.copy_with_new_env(searchpath=searchpath, available_variables=template_vars)
    return data_templar.template(text, escape_backslashes=False)


def _record_sources(sources: dict[str, str], data: Any, path: Path, inventory_dir: Path) -> None:
    if isinstance(data, dict):
        # lexical, never resolved: a symlink to a shared file outside the inventory dir keeps a relative label
        label = os.path.relpath(path, inventory_dir)
        if label.startswith(".."):
            label = path.name
        for key in data:
            sources[str(key)] = label


# ---------------------------------------------------------------------------------------------------- CLI


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="python -m codeorca.specs.ansible_vars", description=__doc__.split("\n\n")[0])
    parser.add_argument("--inventory", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--roles-path", action="append", default=[], metavar="DIR")
    parser.add_argument("--lookup-denylist", action="append", default=[], metavar="FNMATCH")
    parser.add_argument("--key-denylist", action="append", default=[], metavar="REGEX")
    parser.add_argument("--template", action="append", default=[], metavar="PATH")
    parser.add_argument("--extra-vars-file", metavar="JSON")
    parser.add_argument("--play-hosts", action="append", default=[], metavar="PATTERN")
    parser.add_argument("--resolve-lookup", action="append", default=[], metavar="NAME")
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
            args.inventory,
            args.host,
            args.roles_path,
            args.lookup_denylist,
            args.key_denylist,
            args.template,
            extra_vars_file=args.extra_vars_file,
            play_hosts=args.play_hosts,
            resolve_lookups=args.resolve_lookup,
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
