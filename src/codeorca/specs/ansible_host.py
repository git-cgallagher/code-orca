"""The Ansible host spec (plan section 5.6): the redacted document, the play-scope spec play and its parser.

Two scopes feed one document per host:

1. **Inventory scope** comes from ``codeorca.specs.ansible_vars``, run as a subprocess by
   :func:`run_vars_subprocess` (stdout captured in memory, never streamed or written; stderr streamed line by line
   to a callback the caller redacts). :func:`build_host_document` turns that JSON into the spec body: the
   registry scrub over everything and the key denylist over each var's ``declared``/``resolved`` value trees
   only (never over the ``vars`` mapping itself, whose keys are the var names: ``vars.db_password`` must keep its
   triple). The subprocess already replaced declared secrets, denylist-named vars, vaulted values and denied
   lookups by markers, so nothing is registered here beyond what the caller seeded.
2. **Play scope** (role defaults and vars, play ``vars``, ``vars_files``), which ``get_vars(host=)`` never sees:
   :func:`render_play_scope_playbook` generates a check-mode play (``connection: local``, ``gather_facts: false``)
   whose tasks are one ``ansible.builtin.template`` per listed template (``check_mode`` + ``diff``: the rendered
   file is ``diff[0].after``), one ``ansible.builtin.copy`` of an explicit, allow-listed variable set rendered
   with ``to_nice_json`` (same capture), and one static ``ansible.builtin.import_role`` per role with
   ``when: false``: a static import exposes the role's defaults and vars to the play while every task of the
   role is skipped (verified on 2.21.5; nothing is written in check mode). It never emits ``debug var=hostvars``.
   Running the play is the Ansible step's job (Phase 2 adapter); :func:`parse_play_scope_events` reads the
   adapter's JSONL events back into ``{vars, templates, errors}``. Ansible itself templates there, so without
   help a declared secret or a denied lookup renders in clear: :func:`marker_vars` lifts every marker of the
   inventory-scope document into play ``vars`` (play vars outrank inventory vars and role defaults, verified),
   so the play sees ``<secret: declared>`` where the inventory had the value and the denied lookup never runs.
   Role ``vars/`` and ``set_fact`` outrank play vars: a secret defined there is the adapter's redactor's job.
"""

from __future__ import annotations

import io
import json
import os
import re
import subprocess
import threading
from collections.abc import Callable, Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML

from codeorca.redact import SecretRegistry, redact_tree
from codeorca.specs import META_KEY
from codeorca.specs.ansible_vars import SECRET_DECLARED, SKIPPED_KEY, UNTRUSTED_ENV, VAULT

KIND = "ansible_host"
TEMPLATE_TASK_PREFIX = "codeorca:template:"
VARS_TASK_NAME = "codeorca:vars"
ROLE_TASK_PREFIX = "codeorca:role:"
UNDEFINED = "<undefined>"
# codeorca_jsonl event types that never carry a task result: a ``task_start`` shares the task name with its
# ``runner`` event and must not count as a result without a diff.
NON_RESULT_EVENTS = frozenset(
    {
        "playbook_start",
        "play_start",
        "task_start",
        "handler_start",
        "retry",
        "notify",
        "include",
        "no_hosts_matched",
        "no_hosts_remaining",
        "stats",
        "log",
    }
)
FORBIDDEN_VARS = frozenset({"hostvars", "vars", "groups", "omit", "ansible_facts", "environment"})
IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# Environment never handed to the subprocess: the redaction key (no child sees it) and the no_log bypass.
STRIPPED_ENV = ("CODEORCA_REDACTION_KEY", "ANSIBLE_DEBUG")
# Forced in the subprocess (``adapters.ansible.HARDENED_ENV``): env beats ``ansible.cfg``, which could otherwise turn
# debug, a file log or verbosity back on (the display logs warnings and lookup chatter to ``log_path``).
FORCED_ENV = {
    "ANSIBLE_DEBUG": "False",
    "ANSIBLE_VERBOSITY": "0",
    "ANSIBLE_LOG_PATH": os.devnull,
    "ANSIBLE_KEEP_REMOTE_FILES": "False",
}


class AnsibleVarsError(RuntimeError):
    """The variable subprocess failed or printed something that is not one JSON document."""


# --------------------------------------------------------------------------------------------- the document


def build_host_document(
    vars_json: Mapping[str, Any],
    registry: SecretRegistry,
    key_denylist: Sequence[str] = (),
    *,
    base_dir: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """The redacted spec body from the subprocess document. Keys are sorted by the YAML writer later.

    With ``base_dir`` (the project directory), ``inventory_source`` and the template keys are recorded relative
    to it, so a regeneration from another checkout (a CI runner, another machine) diffs empty."""
    patterns = tuple(key_denylist)

    def rel(path: str) -> str:
        if base_dir is None or not os.path.isabs(path):
            return path
        return os.path.relpath(path, base_dir)

    variables: dict[str, Any] = {}
    for name, entry in (vars_json.get("vars") or {}).items():
        if not isinstance(entry, Mapping):
            continue
        out = dict(entry)
        for slot in ("declared", "resolved", "default"):
            if slot in out:
                out[slot] = redact_tree(out[slot], registry, patterns)
        variables[str(name)] = redact_tree(out, registry)
    templates = {
        rel(str(path)): (registry.redact(text) if isinstance(text, str) else text)
        for path, text in (vars_json.get("templates") or {}).items()
    }
    errors = redact_tree(dict(vars_json.get("errors") or {}), registry)
    engine = dict(vars_json.get("engine") or {"name": "ansible-core", "version": None})
    return {
        "kind": KIND,
        "host": registry.redact(str(vars_json.get("host", ""))),
        "inventory_source": registry.redact(rel(str(vars_json.get("inventory_source", "")))),
        "engine": redact_tree(engine, registry),
        "vars": variables,
        "templates": templates,
        "errors": errors,
    }


def header_for(document: Mapping[str, Any], registry_key_id: str, git_sha: str | None, **extra: Any) -> dict[str, Any]:
    from codeorca.specs import build_header  # local import: specs/__init__ does not import this module

    engine = document.get("engine") or {}
    return build_header(
        kind=str(document.get("kind", KIND)),
        stack=str(extra.pop("stack", document.get("host", ""))),
        engine=f"{engine.get('name', 'ansible-core')}/{engine.get('version')}",
        gate=str(extra.pop("gate", "pass")),
        redaction_key=registry_key_id,
        git_sha=git_sha,
        **extra,
    )


def strip_meta(document: Mapping[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in document.items() if k != META_KEY}


def is_marker(value: Any) -> bool:
    """A value the subprocess put in place of a secret: declared, denylisted, vaulted or a skipped lookup."""
    return isinstance(value, str) and (value in (SECRET_DECLARED, SKIPPED_KEY, VAULT) or value.startswith("<skipped: "))


def marker_vars(vars_json: Mapping[str, Any]) -> dict[str, str]:
    """``{var name: marker}`` for every inventory-scope var whose ``resolved`` is a marker, to pass as
    ``play_vars`` to :func:`render_play_scope_playbook` so the play never renders those values either."""
    out: dict[str, str] = {}
    for name, entry in (vars_json.get("vars") or {}).items():
        if isinstance(entry, Mapping) and is_marker(entry.get("resolved")):
            out[str(name)] = str(entry["resolved"])
    return dict(sorted(out.items()))


# ------------------------------------------------------------------------------------------ the subprocess


def run_vars_subprocess(
    python_executable: str,
    inventory: str | os.PathLike[str],
    host: str,
    roles_path: str | os.PathLike[str] | None,
    lookup_denylist: Iterable[str],
    key_denylist: Iterable[str],
    templates: Iterable[str | os.PathLike[str]],
    env: Mapping[str, str],
    *,
    stderr: Callable[[str], None] | None = None,
    cwd: str | os.PathLike[str] | None = None,
    timeout: float | None = None,
) -> dict[str, Any]:
    """Run ``python -m codeorca.specs.ansible_vars`` and return its parsed JSON document.

    stdout is read whole into memory (it may hold secrets: the caller redacts the document); every stderr line
    goes to ``stderr(line)`` as it arrives (the caller's redacting sink). The child environment is ``env`` minus
    ``CODEORCA_REDACTION_KEY``, with ``FORCED_ENV`` and the untrusted-template guard set. A non-zero exit or a
    stdout that is not one JSON object raises :class:`AnsibleVarsError` with the exit code only, never the output.
    ``timeout`` (seconds) kills the child: an executed lookup (``pipe``, ``url``) can hang.
    """
    argv = [str(python_executable), "-m", "codeorca.specs.ansible_vars", "--inventory", str(inventory), "--host", host]
    if roles_path:
        argv += ["--roles-path", str(roles_path)]
    for pattern in lookup_denylist:
        argv += ["--lookup-denylist", pattern]
    for pattern in key_denylist:
        argv += ["--key-denylist", pattern]
    for template in templates:
        argv += ["--template", str(template)]
    child_env = {k: v for k, v in env.items() if k not in STRIPPED_ENV}
    child_env.update(FORCED_ENV)
    child_env[UNTRUSTED_ENV] = "error"
    child_env.setdefault("ANSIBLE_NOCOLOR", "1")

    proc = subprocess.Popen(
        argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, env=child_env, cwd=cwd
    )
    assert proc.stdout is not None and proc.stderr is not None
    sink = stderr or (lambda _line: None)

    def drain() -> None:
        for raw in iter(proc.stderr.readline, b""):
            sink(raw.decode("utf-8", "replace").rstrip("\r\n"))

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    timer: threading.Timer | None = None
    timed_out = False
    if timeout is not None:

        def _kill() -> None:
            nonlocal timed_out
            timed_out = True
            proc.kill()

        timer = threading.Timer(timeout, _kill)
        timer.start()
    try:
        out = proc.stdout.read()
        code = proc.wait()
    finally:
        if timer is not None:
            timer.cancel()
        reader.join()
        proc.stdout.close()
        proc.stderr.close()
    if timed_out:
        raise AnsibleVarsError(f"ansible_vars for host {host!r} timed out after {timeout}s")
    if code != 0:
        raise AnsibleVarsError(f"ansible_vars for host {host!r} exited {code} (see its stderr)")
    try:
        document = json.loads(out.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise AnsibleVarsError(f"ansible_vars for host {host!r} did not print one JSON document") from exc
    if not isinstance(document, dict) or "vars" not in document:
        raise AnsibleVarsError(f"ansible_vars for host {host!r} printed an unexpected document shape")
    return document


# ------------------------------------------------------------------------------------------- play scope


def render_play_scope_playbook(
    playbook_path: str | os.PathLike[str],
    vars: Sequence[str],  # noqa: A002 - the plan's name for the allow list
    templates: Sequence[str | os.PathLike[str]],
    out_dir: str | os.PathLike[str],
    *,
    host: str = "all",
    roles: Sequence[str] = (),
    play_vars: Mapping[str, Any] | None = None,
    vars_files: Sequence[str] = (),
) -> str:
    """YAML text of the check-mode spec play. ``playbook_path`` is where the caller will write it: template
    ``src`` paths are made relative to its directory (Ansible resolves them from there) and every ``dest`` is
    under ``out_dir`` (never written in check mode). ``vars`` is the explicit allow list dumped by the copy task;
    a name that is not an identifier, or one of ``hostvars``/``vars``/``groups``..., is refused.
    """
    for name in vars:
        if not IDENTIFIER_RE.match(name) or name in FORBIDDEN_VARS:
            raise ValueError(f"play-scope var {name!r} is not a plain variable name")
    for role in roles:
        if not re.match(r"^[A-Za-z0-9_.\-]+$", role):
            raise ValueError(f"role name {role!r} is not a role or FQCN")
    base = Path(playbook_path).resolve().parent
    out = Path(out_dir)
    tasks: list[dict[str, Any]] = []
    for role in roles:
        tasks.append(
            {
                "name": f"{ROLE_TASK_PREFIX}{role}",
                "ansible.builtin.import_role": {"name": role},
                "when": False,  # static import: defaults/vars enter the play scope, every task is skipped
            }
        )
    for template in templates:
        path = Path(template)
        src = os.path.relpath(path.resolve(), base) if path.is_absolute() or path.exists() else str(path)
        tasks.append(
            {
                "name": f"{TEMPLATE_TASK_PREFIX}{template}",
                "ansible.builtin.template": {"src": src, "dest": str(out / path.name)},
                "check_mode": True,
                "diff": True,
            }
        )
    if vars:
        pairs = ", ".join(f"'{name}': {name} | default('{UNDEFINED}')" for name in vars)
        tasks.append(
            {
                "name": VARS_TASK_NAME,
                "ansible.builtin.copy": {
                    "content": "{{ {" + pairs + "} | to_nice_json }}",
                    "dest": str(out / "vars.json"),
                },
                "check_mode": True,
                "diff": True,
            }
        )
    play: dict[str, Any] = {
        "name": "codeorca play-scope spec",
        "hosts": host,
        "connection": "local",
        "gather_facts": False,
    }
    if vars_files:
        play["vars_files"] = list(vars_files)
    if play_vars:
        play["vars"] = dict(play_vars)
    play["tasks"] = tasks
    yaml = YAML(typ="safe", pure=True)
    yaml.default_flow_style = False
    yaml.sort_base_mapping_type_on_output = False
    yaml.width = 4096
    buf = io.StringIO()
    buf.write("# generated by codeorca: check-mode spec play; role tasks are skipped, variables are an allow list\n")
    yaml.dump([play], buf)
    return buf.getvalue()


def parse_play_scope_events(events: Iterable[Mapping[str, Any]], host: str | None = None) -> dict[str, Any]:
    """``{vars, templates, errors}`` from the adapter's JSONL events (dicts with ``type``, ``host``, ``task``,
    ``status``, ``result``, ``diff``). Tasks are matched by name, not order; the diff is taken from
    ``event["diff"]`` or ``result["diff"]``, as a list or a single dict."""
    variables: dict[str, Any] = {}
    templates: dict[str, str] = {}
    errors: dict[str, str] = {}
    for event in events:
        if not isinstance(event, Mapping) or event.get("type") in NON_RESULT_EVENTS:
            continue
        task = str(event.get("task") or "")
        if host is not None and event.get("host") not in (None, host):
            continue
        if not (task == VARS_TASK_NAME or task.startswith(TEMPLATE_TASK_PREFIX)):
            continue
        result = event.get("result") if isinstance(event.get("result"), Mapping) else {}
        status = str(event.get("status") or ("failed" if result.get("failed") else "ok")).lower()
        if status in ("failed", "unreachable"):
            errors[task] = str(result.get("msg") or event.get("msg") or status)
            continue
        if status == "skipped":
            errors[task] = "skipped"
            continue
        after = _diff_after(event.get("diff"), result.get("diff"))
        if after is None:
            errors[task] = "no diff in the task result (check_mode + diff missing?)"
            continue
        if task == VARS_TASK_NAME:
            try:
                parsed = json.loads(after)
            except ValueError:
                errors[task] = "vars dump is not JSON"
                continue
            if isinstance(parsed, dict):
                variables.update(parsed)
            else:
                errors[task] = "vars dump is not a mapping"
        else:
            templates[task[len(TEMPLATE_TASK_PREFIX) :]] = after
    return {"vars": variables, "templates": templates, "errors": errors}


def _diff_after(*candidates: Any) -> str | None:
    for diff in candidates:
        if isinstance(diff, Mapping):
            diff = [diff]
        if isinstance(diff, list):
            for item in diff:
                if isinstance(item, Mapping) and isinstance(item.get("after"), str):
                    return item["after"]
    return None


__all__ = [
    "KIND",
    "AnsibleVarsError",
    "build_host_document",
    "header_for",
    "is_marker",
    "marker_vars",
    "parse_play_scope_events",
    "render_play_scope_playbook",
    "run_vars_subprocess",
    "strip_meta",
]
