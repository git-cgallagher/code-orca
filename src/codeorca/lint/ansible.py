"""Playbook lint for secret handling (plan sections 5.5 and 5.7). Rules:

- ``no-hostvars-dump`` (warning): ``ansible.builtin.debug`` with ``var: hostvars[...]``, ``var: hostvars``,
  ``var: vars`` or a ``msg`` that reads ``hostvars``; it prints every secret in clear and ``no_log`` cannot help.
- ``debug-secret-name`` (warning): ``debug`` whose ``var`` or ``msg`` references a variable whose name matches
  the key denylist.
- ``secret-to-plain-param`` (warning): a secret-named variable (or a lookup on the lookup denylist) passed to a
  module parameter that the module does not declare ``no_log`` and the task has no ``no_log: true``.
  Resolution is for installed modules through ``ansible.plugins.loader.module_loader`` (``ansible.builtin.*``
  and installed collections): the DOCUMENTATION's ``options`` (``no_log: true``, ``aliases``) first, then, since
  almost no builtin module documents ``no_log`` (at 2.21.5 only ``expect`` does, while ``user`` and ``uri`` carry it
  in the code's ``argument_spec``), a textual scan of the module source for ``name=dict(... no_log=True ...)`` /
  ``'name': {... 'no_log': True ...}``. That scan is a heuristic: it misses specs built in helper functions.
  A free-form argument (``shell``/``command`` strings) is never ``no_log``.
- ``unknown-module`` (info): the module could not be resolved, so the rule above could not be checked.
- ``redundant-task-no-log`` (info): task-level ``no_log: true`` on a task that passes no secret-named value.

Parsing is ruamel round-trip (line numbers, ``!vault`` tags tolerated). Files are playbooks (a list of plays) or
task lists (roles' ``tasks/*.yml``, ``handlers``); ``block``/``rescue``/``always`` are walked. The ``action:`` /
``local_action:`` forms are read in their mapping shape; a string form is treated as free-form. Dynamic module
names and ``args:`` merged with a free-form string are out of scope. Every ``ansible`` import is lazy, so the
module imports without ansible-core; ``resolve_module`` is injectable for tests.
"""

from __future__ import annotations

import fnmatch
import os
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any, TypedDict

from ruamel.yaml import YAML

from codeorca.redact import DEFAULT_KEY_DENYLIST, compile_key_denylist


class Finding(TypedDict):
    file: str
    line: int
    rule: str
    level: str
    message: str


RULES: dict[str, str] = {
    "no-hostvars-dump": "debug of hostvars/vars prints every secret in clear",
    "debug-secret-name": "debug of a secret-named variable",
    "secret-to-plain-param": "secret-named value passed to a module parameter without no_log",
    "unknown-module": "module could not be resolved; secret-to-plain-param not checked",
    "redundant-task-no-log": "task-level no_log on a task that passes no secret-named value",
}

ModuleResolver = Callable[[str], "frozenset[str] | None"]
"""``resolve(module name) -> names of the parameters the module declares no_log``, or ``None`` when unknown."""

TASK_KEYWORDS = frozenset(
    {
        "name",
        "when",
        "loop",
        "loop_control",
        "register",
        "no_log",
        "check_mode",
        "diff",
        "vars",
        "tags",
        "become",
        "become_user",
        "become_method",
        "become_flags",
        "become_exe",
        "delegate_to",
        "delegate_facts",
        "ignore_errors",
        "ignore_unreachable",
        "changed_when",
        "failed_when",
        "until",
        "retries",
        "delay",
        "notify",
        "args",
        "action",
        "local_action",
        "environment",
        "run_once",
        "any_errors_fatal",
        "throttle",
        "timeout",
        "module_defaults",
        "connection",
        "remote_user",
        "port",
        "collections",
        "listen",
        "poll",
        "async",
        "debugger",
        "block",
        "rescue",
        "always",
        "secret",
    }
)
HOSTVARS_RE = re.compile(r"^\s*(hostvars|vars)\s*(\[|\.|$)")
HOSTVARS_IN_TEXT_RE = re.compile(r"\bhostvars\s*(\[|\.)")
JINJA_BLOCK_RE = re.compile(r"\{\{(.*?)\}\}|\{%(.*?)%\}", re.S)
STRING_LITERAL_RE = re.compile(r"'[^']*'|\"[^\"]*\"")
IDENT_RE = re.compile(r"(?<![\w.])([A-Za-z_][A-Za-z0-9_]*)(?!\s*\()")
LOOKUP_RE = re.compile(r"\b(?:lookup|query|q)\s*\(\s*(['\"])([\w.]+)\1")
BUILTIN_PREFIXES = ("ansible.builtin.", "ansible.legacy.")


# ------------------------------------------------------------------------------------------------- scanning


def flagged_names(value: Any, key_patterns: Sequence[re.Pattern[str]], lookup_patterns: Sequence[str]) -> list[str]:
    """Identifiers only: the NAMES of variables whose name matches a key pattern, and ``lookup:<plugin>`` for
    denied lookups, referenced from the Jinja expressions in ``value`` (any depth). Never a value: a quoted
    string inside an expression is not a reference and literal text is never returned, so a finding built from
    this list is safe to print."""
    found: list[str] = []
    for text in _strings(value):
        for m in LOOKUP_RE.finditer(text):
            name = m.group(2)
            if any(fnmatch.fnmatchcase(name, p) for p in lookup_patterns):
                found.append(f"lookup:{name}")
        for block in JINJA_BLOCK_RE.finditer(text):
            expr = block.group(1) or block.group(2) or ""
            expr = STRING_LITERAL_RE.sub("''", expr)
            for ident in IDENT_RE.findall(expr):
                if any(p.search(ident) for p in key_patterns) and ident not in found:
                    found.append(ident)
    return found


def _strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for v in value.values():
            yield from _strings(v)
    elif isinstance(value, list | tuple):
        for v in value:
            yield from _strings(v)


def _line(node: Any, fallback: int) -> int:
    lc = getattr(node, "lc", None)
    if lc is not None and getattr(lc, "line", None) is not None:
        return int(lc.line) + 1
    return fallback


def _task_module(task: Mapping[str, Any]) -> tuple[str | None, Any]:
    """``(module name, its args)``: the one key that is not a task keyword, or the ``action``/``local_action``
    form. ``args`` is a mapping, a free-form string, or ``None``."""
    for key in ("action", "local_action"):
        if key in task:
            spec = task[key]
            if isinstance(spec, Mapping) and "module" in spec:
                params = {k: v for k, v in spec.items() if k != "module"}
                params.update(task.get("args") or {} if isinstance(task.get("args"), Mapping) else {})
                return str(spec["module"]), params
            if isinstance(spec, str):
                return spec.split(None, 1)[0] if spec.strip() else None, spec
    for key, value in task.items():
        if key in TASK_KEYWORDS or str(key).startswith("with_"):
            continue
        params = value
        if isinstance(task.get("args"), Mapping):
            params = (
                dict(task["args"])
                if value is None
                else (dict(value, **task["args"]) if isinstance(value, Mapping) else value)
            )
        return str(key), params
    return None, None


def _normalise_module(name: str) -> str:
    for prefix in BUILTIN_PREFIXES:
        if name.startswith(prefix):
            return name[len(prefix) :]
    return name


# ------------------------------------------------------------------------------------------- the lint


def lint_playbooks(
    paths: Iterable[str | os.PathLike[str]],
    key_denylist: Sequence[str] = DEFAULT_KEY_DENYLIST,
    lookup_denylist: Sequence[str] = (),
    *,
    resolve_module: ModuleResolver | None = None,
) -> list[Finding]:
    """Lint playbooks and task files; findings sorted by file and line. ``resolve_module`` defaults to the
    installed-module resolver (:func:`resolve_installed_module`, needs ansible-core)."""
    key_patterns = compile_key_denylist(key_denylist)
    resolver = resolve_module or resolve_installed_module
    findings: list[Finding] = []
    for path in paths:
        file = Path(path)
        data = _load(file)
        for task in _tasks(data):
            findings.extend(_lint_task(task, str(file), key_patterns, tuple(lookup_denylist), resolver))
    findings.sort(key=lambda f: (f["file"], f["line"], f["rule"]))
    return findings


def _load(file: Path) -> Any:
    yaml = YAML(typ="rt", pure=True)
    with file.open(encoding="utf-8") as fh:
        return yaml.load(fh)


def _tasks(data: Any) -> Iterable[Mapping[str, Any]]:
    """Every task mapping in a playbook (plays' ``pre_tasks``/``tasks``/``post_tasks``/``handlers``) or a task
    list, blocks walked."""
    if not isinstance(data, list):
        return
    for item in data:
        if not isinstance(item, Mapping):
            continue
        if "hosts" in item:  # a play
            for section in ("pre_tasks", "tasks", "post_tasks", "handlers"):
                yield from _walk_tasks(item.get(section))
        else:
            yield from _walk_tasks([item])


def _walk_tasks(items: Any) -> Iterable[Mapping[str, Any]]:
    if not isinstance(items, list):
        return
    for task in items:
        if not isinstance(task, Mapping):
            continue
        if any(k in task for k in ("block", "rescue", "always")):
            for section in ("block", "rescue", "always"):
                yield from _walk_tasks(task.get(section))
        else:
            yield task


def _lint_task(
    task: Mapping[str, Any],
    file: str,
    key_patterns: Sequence[re.Pattern[str]],
    lookup_patterns: Sequence[str],
    resolver: ModuleResolver,
) -> list[Finding]:
    out: list[Finding] = []
    line = _line(task, 0)
    module, params = _task_module(task)
    task_no_log = task.get("no_log") is True

    def add(rule: str, message: str, level: str = "warning") -> None:
        out.append({"file": file, "line": line, "rule": rule, "level": level, "message": message})

    if module is None:
        return out
    short = _normalise_module(module)
    if short == "debug":
        var = params.get("var") if isinstance(params, Mapping) else None
        msg = params.get("msg") if isinstance(params, Mapping) else params
        if isinstance(var, str) and HOSTVARS_RE.match(var):
            add("no-hostvars-dump", f"debug var: {var.strip()} prints every variable of the host in clear")
        elif isinstance(msg, str) and HOSTVARS_IN_TEXT_RE.search(msg):
            add("no-hostvars-dump", "debug msg reads hostvars")
        refs = []
        if isinstance(var, str):
            refs = flagged_names("{{ " + var + " }}", key_patterns, lookup_patterns)
        refs += [r for r in flagged_names(msg, key_patterns, lookup_patterns) if r not in refs]
        if refs:
            add("debug-secret-name", f"debug prints secret-named {', '.join(refs)}")
        return out

    secret_params: dict[str, list[str]] = {}
    if isinstance(params, Mapping):
        for name, value in params.items():
            refs = flagged_names(value, key_patterns, lookup_patterns)
            if refs:
                secret_params[str(name)] = refs
    elif isinstance(params, str):
        refs = flagged_names(params, key_patterns, lookup_patterns)
        if refs:
            secret_params["_raw_params"] = refs

    if task_no_log and not secret_params:
        add("redundant-task-no-log", f"no_log: true on {module} but no parameter carries a secret-named value", "info")
    if not secret_params or task_no_log:
        return out
    no_log_params = resolver(module)
    if no_log_params is None:
        add("unknown-module", f"{module} could not be resolved; secret-to-plain-param not checked", "info")
        return out
    for name, refs in sorted(secret_params.items()):
        if name not in no_log_params:
            add("secret-to-plain-param", f"{module} parameter {name} receives {', '.join(refs)} but is not no_log")
    return out


# ------------------------------------------------------------------------------------ module resolution

_resolver_cache: dict[str, frozenset[str] | None] = {}
_ARG_ENTRY_RE = re.compile(r"\b([A-Za-z_]\w*)\s*=\s*dict\(|['\"]([A-Za-z_]\w*)['\"]\s*:\s*(?:dict\(|\{)")
_ALIASES_RE = re.compile(r"\baliases['\"]?\s*[=:]\s*[\[(]([^\])]*)[\])]")
_NO_LOG_RE = re.compile(r"\bno_log['\"]?\s*[=:]\s*True\b")


def _ensure_plugin_loader() -> None:
    from ansible.plugins import loader

    if getattr(loader, "_codeorca_initialised", False):
        return
    try:
        loader.init_plugin_loader()
    except Exception:  # already initialised by the host process: collection resolution still works
        pass
    loader._codeorca_initialised = True  # type: ignore[attr-defined]


def resolve_installed_module(module: str) -> frozenset[str] | None:
    """Parameters declared ``no_log`` by an installed module, or ``None`` when it cannot be resolved."""
    if module in _resolver_cache:
        return _resolver_cache[module]
    try:
        from ansible.plugins.loader import fragment_loader, module_loader
        from ansible.utils.plugin_docs import get_docstring

        _ensure_plugin_loader()
        ctx = module_loader.find_plugin_with_context(module)
        if not ctx.resolved or not ctx.plugin_resolved_path:
            _resolver_cache[module] = None
            return None
        names: set[str] = set()
        doc, _examples, _returns, _meta = get_docstring(ctx.plugin_resolved_path, fragment_loader=fragment_loader)
        for name, opt in ((doc or {}).get("options") or {}).items():
            if isinstance(opt, Mapping) and opt.get("no_log") is True:
                names.add(str(name))
                names.update(str(a) for a in opt.get("aliases") or [])
        names.update(no_log_from_source(Path(ctx.plugin_resolved_path).read_text(encoding="utf-8", errors="replace")))
        _resolver_cache[module] = frozenset(names)
    except Exception:
        _resolver_cache[module] = None
    return _resolver_cache[module]


def no_log_from_source(source: str) -> set[str]:
    """Heuristic over a module's Python source: parameter names (and aliases) whose ``argument_spec`` entry says
    ``no_log=True`` (``name=dict(...)`` and ``'name': {...}`` / ``'name': dict(...)`` shapes). Only the entry's own
    level counts: ``argument_spec=dict(password=dict(no_log=True))`` names ``password``, not ``argument_spec``."""
    names: set[str] = set()
    for m in _ARG_ENTRY_RE.finditer(source):
        name = m.group(1) or m.group(2)
        body = _own_level(source, m.end())
        if _NO_LOG_RE.search(body):
            names.add(name)
            for aliases in _ALIASES_RE.finditer(body):
                names.update(a.strip().strip("'\"") for a in aliases.group(1).split(",") if a.strip())
    return names


def _own_level(source: str, start: int) -> str:
    """The text of a ``dict(``/``{`` body from ``start`` to its closing bracket, with nested ``(``/``{`` groups
    blanked out (``[`` lists such as ``aliases=[...]`` stay)."""
    depth = 0
    out: list[str] = []
    for ch in source[start:]:
        if ch in "({":
            depth += 1
        elif ch in ")}":
            if depth == 0:
                break
            depth -= 1
        elif depth == 0:
            out.append(ch)
    return "".join(out)


__all__ = ["RULES", "Finding", "ModuleResolver", "lint_playbooks", "no_log_from_source", "resolve_installed_module"]
