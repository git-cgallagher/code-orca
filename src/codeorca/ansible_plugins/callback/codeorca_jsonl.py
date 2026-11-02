"""``codeorca_jsonl``: the stdout callback code-orca installs in every ``ansible-playbook`` it runs.

It prints exactly one JSON object per line to stdout for every event and NOTHING else: no banners, no
``PLAY RECAP``, and no ``[ERROR]: Task failed`` line (the default callback prints that one through
``Display.error``, which an aggregate callback cannot intercept; this plugin never calls the display at all).
Whatever ansible-core itself writes (``[WARNING]``, ``[DEPRECATION WARNING]``, ``ERROR!`` for a playbook that
does not parse) goes to stderr. The orchestrator parses stdout line by line (``codeorca.adapters.ansible``) and
redacts every line before it reaches the run directory; this plugin does not redact (it has no registry) and
does not try to un-censor what ``no_log`` already hid.

This module is loaded by path inside the playbook process, so it imports only the standard library and
``ansible``: ``codeorca`` may not be installed in the execution environment.

Event schema (every event carries ``type`` and ``ts``; the other keys are present when they apply and ``null``
otherwise, so a consumer can rely on the names):

``type``             one of ``playbook_start``, ``play_start``, ``task_start``, ``handler_start``, ``runner``,
                     ``item``, ``retry``, ``notify``, ``include``, ``no_hosts_matched``, ``no_hosts_remaining``,
                     ``stats``
``ts``               UTC ISO-8601 timestamp (seconds)
``playbook``         (``playbook_start``) the playbook path as given to ansible-playbook
``play``             the current play's name
``task``             the current task's name (``runner``/``item``/``retry``/``task_start``)
``action``           the task's action (``ansible.builtin.debug`` ...)
``path``             ``file:line`` of the task when known
``host``             the inventory host name (``runner``/``item``/``retry``/``notify``)
``status``           ``runner``/``item``: ``ok``, ``failed``, ``unreachable`` or ``skipped``
``changed``          bool (``runner``/``item``)
``ignore_errors``    bool: the failure was ignored (``runner``/``item`` with status ``failed``; ``unreachable``
                     under ``ignore_unreachable``)
``no_log``           bool: the result was censored by ``no_log`` (Ansible did it; ``result`` holds the censored dict,
                     and ``exception``/``warnings``/``deprecations`` are ``null``: Ansible censors ``result.result``
                     but not ``TaskResult.exception``, which carries a ``fail``/``assert`` message verbatim)
``check_mode``       bool: the task ran in check mode
``check_unsupported`` bool: the result says the module does not support check mode (it was skipped, not run)
``msg``              the result's ``msg`` when it is a string
``result``           the full result dict (``_ansible_*`` keys dropped; ``results`` dropped on a loop's summary
                     result, the per-item results arrive as ``item`` events; on an ``item`` event with a
                     ``loop_control.label`` the loop variable is replaced by the label and ``ansible_loop`` is
                     dropped, as the default callback shows only the label: playbooks label to hide credentials)
``item``             the loop item's label (``item`` events; ``(censored due to no_log)`` when censored)
``diff``             the result's ``diff`` when present (``runner``/``item``)
``warnings`` / ``deprecations`` / ``exception``  text summaries of what the task result carried
``attempts``         (``retry``) attempts so far
``handler``          (``notify``) the handler name; a ``notify`` event's ``task``/``action``/``path`` are ``null``
                     (it fires when results are processed, after later tasks may have started)
``included``         (``include``) the included file
``hosts``            (``play_start``) the play's host pattern; (``include``) the hosts it was included for
``stats``            (``stats``) per host ``{ok, changed, failed, unreachable, skipped, rescued, ignored}``
``custom``           (``stats``) the KEYS of the ``set_stats`` data per scope (``{"_run": ["k"]}``), never values:
                     the aggregate cannot tell which data came from a ``no_log`` task

Lines are JSON with ``ensure_ascii`` on: U+2028/U+2029/U+0085 in a result would otherwise be emitted raw, and a
consumer that splits on ``str.splitlines()`` (the stream redactor's sink did) cut one event into broken lines.
"""

from __future__ import annotations

import datetime
import json
import re
import sys

from ansible.plugins.callback import CallbackBase

DOCUMENTATION = """
    name: codeorca_jsonl
    type: stdout
    short_description: one JSON object per line, nothing else
    version_added: "0.0.1"
    description:
      - Machine-readable stdout for code-orca. Every playbook, play, task, host result, item, handler and stats
        event is one JSON line; no banner, recap or error line is ever printed to stdout.
      - Results censored by no_log stay censored; redaction is the orchestrator's job.
"""

# A skipped result whose message says the module could not run in check mode. The wordings in ansible-core 2.21.5:
# module_utils/basic.py and the action base class say "does not support check mode"; command/shell skip themselves
# with "Command would have run if not in check mode"; action/script.py raises "Check mode is not supported for this
# task."; action/fetch.py "check mode not (yet) supported for this module". action/raw.py returns ``skipped`` with
# no message at all, which ``_result_event`` catches separately (a skip in check mode with no msg and no
# ``skip_reason``: a ``when:`` or empty-loop skip always has one).
CHECK_UNSUPPORTED = re.compile(
    r"does not support check mode|would have run if not in check mode|check mode (?:is )?not (?:\(yet\) )?supported",
    re.IGNORECASE,
)

_INTERNAL_PREFIX = "_ansible_"


def _now() -> str:
    return datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds")


def _plain(value):
    """Reduce Ansible's tagged containers and anything else to plain JSON-compatible data."""
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_plain(v) for v in value]
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    return str(value)


def _strip_internal(result):
    """A copy of a result dict without the ``_ansible_*`` bookkeeping keys."""
    if not isinstance(result, dict):
        return _plain(result)
    return {str(k): _plain(v) for k, v in result.items() if not str(k).startswith(_INTERNAL_PREFIX)}


def _summary_text(summary) -> str:
    """One line for an ansible-core ``ErrorSummary``/``WarningSummary``/``DeprecationSummary`` (2.19+), following
    the event chain the way the display does, with a ``str()`` fallback for anything else."""
    event = getattr(summary, "event", None)
    if event is None:
        return str(summary)
    parts = []
    seen = 0
    while event is not None and seen < 20:
        msg = getattr(event, "msg", None)
        if msg:
            parts.append(str(msg))
        help_text = getattr(event, "help_text", None)
        if help_text:
            parts.append(str(help_text))
        chain = getattr(event, "chain", None)
        event = getattr(chain, "event", None) if chain is not None and getattr(chain, "follow", True) else None
        seen += 1
    return " ".join(parts) if parts else str(summary)


def _task_path(task) -> str | None:
    try:
        path = task.get_path()
    except Exception:  # noqa: BLE001 - a path is a nicety; never fail an event over it
        return None
    return str(path) if path else None


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = "stdout"
    CALLBACK_NAME = "codeorca_jsonl"

    def __init__(self, display=None, options=None):
        super().__init__(display=display, options=options)
        self._play_name: str | None = None
        self._task_name: str | None = None
        self._task_action: str | None = None
        self._task_path: str | None = None
        self._task_check_mode: bool | None = None

    # ------------------------------------------------------------------------------------------------ output
    def _emit(self, event_type: str, **fields) -> None:
        event = {"type": event_type, "ts": _now(), "play": self._play_name}
        event.update(fields)
        # ensure_ascii: U+2028/U+2029/U+0085 must never appear raw (``str.splitlines`` splits on them)
        sys.stdout.write(json.dumps(event, default=str, ensure_ascii=True, sort_keys=False) + "\n")
        sys.stdout.flush()  # one line per event, however the process ends (a timeout kill loses nothing buffered)

    def _task_fields(self, task=None) -> dict:
        if task is not None:
            return {
                "task": task.get_name(),
                "action": task.action,
                "path": _task_path(task),
                "check_mode": bool(task.check_mode) if task.check_mode is not None else None,
            }
        return {
            "task": self._task_name,
            "action": self._task_action,
            "path": self._task_path,
            "check_mode": self._task_check_mode,
        }

    def _result_event(self, event_type: str, result, status: str, ignore_errors: bool = False) -> None:
        raw = result.result  # already censored by Ansible when no_log applies; never un-censor
        data = _strip_internal(raw)
        if event_type == "runner" and isinstance(data.get("results"), list):
            data.pop("results")  # the per-item results were emitted as ``item`` events already
        msg = data.get("msg")
        skipped = status == "skipped"
        task_fields = self._task_fields(result.task)
        reasons = (msg, data.get("skip_reason"), data.get("skipped_reason"))
        no_log = bool(raw.get("_ansible_no_log")) or bool(getattr(result.task, "no_log", False))
        check_unsupported = skipped and (
            any(isinstance(text, str) and CHECK_UNSUPPORTED.search(text) for text in reasons)
            # raw (and any module that skips silently): in check mode with no reason at all; a censored result has
            # lost its skip_reason too, so it cannot be told from a when: skip (residual)
            or (bool(task_fields.get("check_mode")) and not any(reasons) and "censored" not in data)
        )
        if event_type == "item" and not no_log and "_ansible_item_label" in raw:
            loop_var = raw.get("ansible_loop_var") or "item"
            if loop_var in data:
                data[str(loop_var)] = _plain(raw["_ansible_item_label"])
            data.pop("ansible_loop", None)  # extended loop info carries allitems
        fields = {
            **task_fields,
            "host": result.host.get_name(),
            "status": status,
            "changed": bool(result.is_changed()),
            "ignore_errors": bool(ignore_errors),
            "no_log": no_log,
            "check_unsupported": bool(check_unsupported),
            "msg": msg if isinstance(msg, str) else None,
            "result": data,
            "diff": data.get("diff"),
            # Ansible censors result.result under no_log, but not these: the exception summary is the verbatim
            # fail/assert message. Never un-censor.
            "warnings": None if no_log else [_summary_text(w) for w in (result.warnings or [])],
            "deprecations": None if no_log else [_summary_text(d) for d in (result.deprecations or [])],
            "exception": _summary_text(result.exception) if result.exception is not None and not no_log else None,
        }
        if event_type == "item":
            label = raw.get("_ansible_item_label", raw.get("item")) if not no_log else "(censored due to no_log)"
            fields["item"] = _plain(label)
        self._emit(event_type, **fields)

    # ------------------------------------------------------------------------------------------------ playbook
    def v2_playbook_on_start(self, playbook):
        self._emit("playbook_start", playbook=getattr(playbook, "_file_name", None))

    def v2_playbook_on_play_start(self, play):
        self._play_name = play.get_name()
        hosts = play.hosts
        self._emit("play_start", hosts=_plain(hosts), check_mode=bool(play.check_mode) if play.check_mode else None)

    def v2_playbook_on_task_start(self, task, is_conditional):
        self._remember(task)
        self._emit("task_start", **self._task_fields(task), handler=False)

    def v2_playbook_on_handler_task_start(self, task):
        self._remember(task)
        self._emit("handler_start", **self._task_fields(task), handler=True)

    def _remember(self, task) -> None:
        self._task_name = task.get_name()
        self._task_action = task.action
        self._task_path = _task_path(task)
        self._task_check_mode = bool(task.check_mode) if task.check_mode is not None else None

    def v2_playbook_on_notify(self, handler, host):
        # fires while results are processed, when a later task may already have started (serial/free strategies):
        # the last task_start is not the notifying task, so no task attribution at all
        self._emit(
            "notify",
            host=host.get_name(),
            handler=handler.get_name(),
            task=None,
            action=None,
            path=None,
            check_mode=None,
        )

    def v2_playbook_on_include(self, included_file):
        task = getattr(included_file, "_task", None)  # the include task itself, not the last task_start
        self._emit(
            "include",
            included=str(included_file._filename),
            hosts=[h.get_name() for h in included_file._hosts],
            **(self._task_fields(task) if task is not None else self._task_fields()),
        )

    def v2_playbook_on_no_hosts_matched(self):
        self._emit("no_hosts_matched")

    def v2_playbook_on_no_hosts_remaining(self):
        self._emit("no_hosts_remaining")

    def v2_playbook_on_stats(self, stats):
        per_host = {}
        for host in sorted(stats.processed.keys()):
            summary = stats.summarize(host)
            per_host[host] = {
                "ok": summary.get("ok", 0),
                "changed": summary.get("changed", 0),
                "failed": summary.get("failures", 0),
                "unreachable": summary.get("unreachable", 0),
                "skipped": summary.get("skipped", 0),
                "rescued": summary.get("rescued", 0),
                "ignored": summary.get("ignored", 0),
            }
        custom = getattr(stats, "custom", None) or {}
        # keys only: set_stats data from a no_log task would otherwise reach the events file in clear
        keys = {str(scope): sorted(str(k) for k in data) for scope, data in custom.items() if isinstance(data, dict)}
        self._emit("stats", stats=per_host, custom=keys)

    # ------------------------------------------------------------------------------------------------ results
    def v2_runner_on_ok(self, result):
        self._result_event("runner", result, "ok")

    def v2_runner_on_failed(self, result, ignore_errors=False):
        self._result_event("runner", result, "failed", ignore_errors=ignore_errors)

    def v2_runner_on_unreachable(self, result):
        # ignore_unreachable: the stats count it as ignored, not unreachable
        ignored = bool(getattr(result.task, "ignore_unreachable", False))
        self._result_event("runner", result, "unreachable", ignore_errors=ignored)

    def v2_runner_on_skipped(self, result):
        self._result_event("runner", result, "skipped")

    def v2_runner_item_on_ok(self, result):
        self._result_event("item", result, "ok")

    def v2_runner_item_on_failed(self, result):
        self._result_event("item", result, "failed", ignore_errors=bool(result.task.ignore_errors))

    def v2_runner_item_on_skipped(self, result):
        self._result_event("item", result, "skipped")

    def v2_runner_retry(self, result):
        data = _strip_internal(result.result)
        self._emit(
            "retry",
            **self._task_fields(result.task),
            host=result.host.get_name(),
            attempts=data.get("attempts"),
            retries=data.get("retries"),
            msg=data.get("msg") if isinstance(data.get("msg"), str) else None,
        )
