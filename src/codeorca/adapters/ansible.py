"""Ansible adapter: ``ansible-playbook`` as a subprocess with the ``codeorca_jsonl`` stdout callback (plan §5.5).

Command contract (verified on ansible-core 2.21.5):

- argv is a list, never a shell string: ``ansible-playbook -i <inventory> [-e @<extra vars json>] [--tags ...]
  [--skip-tags ...] [--limit ...] [--check --diff] <playbook>``. Values never travel on the command line
  (visible in ``ps``): extra vars go through a 0600 JSON file (``write_handoff``), the inventory through a 0600
  YAML file (``generate_inventory``).
- The child environment is the caller's minus ``CODEORCA_REDACTION_KEY`` (nobody's business but ours), with
  ``HARDENED_ENV`` **forced** (not merely dropped: every one of these has an ``ansible.cfg`` twin, and ansible-playbook
  runs from the project root where a consumer's ``ansible.cfg`` would turn it back on; env beats ini):
  ``ANSIBLE_DEBUG=False`` (debug bypasses ``no_log`` entirely), ``ANSIBLE_LOG_PATH=/dev/null`` (a file log is an
  unredacted copy of everything; an empty value resolves to the cwd), ``ANSIBLE_VERBOSITY=0`` (``-vvvv`` prints
  module arguments past the callback), ``ANSIBLE_KEEP_REMOTE_FILES=False`` (a kept ``AnsiballZ`` holds the module
  arguments verbatim) and ``ANSIBLE_CALLBACKS_ENABLED=codeorca_jsonl`` (an aggregate callback such as
  ``ansible.builtin.junit`` sees raw results and writes them past the redactor; an empty value fails at start with
  "A non-empty plugin name is required", and naming the stdout callback is a no-op). Also forced:
  ``ANSIBLE_STDOUT_CALLBACK=codeorca_jsonl``, ``ANSIBLE_CALLBACK_PLUGINS=<this package's callback dir>`` (joined
  in front of any caller value), ``ANSIBLE_NOCOLOR=1``, ``ANSIBLE_FORCE_COLOR=0``,
  ``ANSIBLE_RETRY_FILES_ENABLED=False``; ``ANSIBLE_HOST_KEY_CHECKING=True`` unless the caller set it, and
  ``ANSIBLE_LOCAL_TEMP`` when ``local_temp`` is given.
- stdout is the callback's JSONL: every line is parsed into an event; a line that is not JSON (a stray print from
  a plugin, an aggregate callback a consumer's ``ansible.cfg`` enabled) is kept as a ``{"type": "log"}`` event. The
  ``stream(line, channel)`` callback sees EVERY line: JSON stdout lines with channel ``stdout``, non-JSON stdout
  lines and all stderr lines with channel ``stderr`` (so a log line never lands in the events file). Redaction is
  the caller's job: ``stream`` is where the ``StreamRedactor`` attaches (this module does not import
  ``codeorca.redact``) and the in-memory ``events`` are UNREDACTED.
- The child runs in its own session, but a process-group kill is NOT enough: every ansible-core worker calls
  ``os.setsid()`` (``WORKER_SESSION_ISOLATION``, default on since 2.19; ``setpgid`` otherwise), so the worker, the
  module it runs and anything that module started are in groups of their own and outlive the leader. On a timeout
  the adapter SIGSTOPs the leader's group, lists its descendants (``/proc/*/stat`` on Linux, where a slim image has
  no ``ps``; ``ps -axo pid=,ppid=`` elsewhere), stops and SIGKILLs every one of them and their groups, then the
  leader's group, and raises ``AnsibleTimeout``. A detached ``async`` task survives (residual), and a killed
  ``connection: local`` module leaves its ``AnsiballZ_*.py`` (module arguments verbatim) under the remote tmp
  (``~/.ansible/tmp``, residual); the steps remove their own ``ANSIBLE_LOCAL_TEMP``.
- Exit codes are ansible-playbook's (``ansible.errors.ExitCode`` at 2.21.5), NOT a usable bitmask: 0 ok, 1 error,
  2 failed hosts, 4 unreachable hosts **and** ``PARSER_ERROR`` (both are 4: a playbook that does not parse exits 4
  with no stats), 5 invalid CLI option, 99 interrupted, 250 unexpected. A run with failed and unreachable hosts
  exits 4 (the strategy returns unreachable first), and ``RUN_FAILED_BREAK_PLAY`` (8) never leaves
  ``PlaybookExecutor`` (it becomes 2). So :meth:`AnsibleResult.describe` builds the status from the stats event:
  ``failed_hosts``/``unreachable_hosts`` come from it (``ignore_errors``, ``ignore_unreachable`` and rescued tasks
  produce failed results that are not failures), and a non-zero exit with no stats event is a parser/CLI error.
"""

from __future__ import annotations

import importlib.util
import io
import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.representer import SafeRepresenter

StreamCallback = Callable[[str, str], None]
"""``stream(line, channel)``: ``line`` keeps its trailing newline; ``channel`` is ``"stdout"`` (a JSONL event) or
``"stderr"`` (everything else). Calls from the two pipe-reader threads are serialized by a lock."""

CALLBACK_NAME = "codeorca_jsonl"
PLAYBOOK_PROGRAM = "ansible-playbook"
# Dropped from every child environment.
DROPPED_ENV = ("CODEORCA_REDACTION_KEY",)
# Forced in every ansible child (the vars subprocess included): env beats ``ansible.cfg``, so dropping these names
# would let a consumer's config turn them back on.
HARDENED_ENV = {
    "ANSIBLE_DEBUG": "False",
    "ANSIBLE_VERBOSITY": "0",
    "ANSIBLE_LOG_PATH": os.devnull,
    "ANSIBLE_KEEP_REMOTE_FILES": "False",
}
# Names a project's ``ansible.env`` may not set (``project.AnsibleConfig`` refuses them): they are forced anyway.
RESERVED_ENV = frozenset({*DROPPED_ENV, *HARDENED_ENV, "ANSIBLE_STDOUT_CALLBACK", "ANSIBLE_CALLBACKS_ENABLED"})
FORCED_ENV = {
    **HARDENED_ENV,
    "ANSIBLE_CALLBACKS_ENABLED": CALLBACK_NAME,  # no aggregate callback; empty fails, the stdout one is a no-op
    "ANSIBLE_STDOUT_CALLBACK": CALLBACK_NAME,
    "ANSIBLE_NOCOLOR": "1",
    "ANSIBLE_FORCE_COLOR": "0",
    "ANSIBLE_RETRY_FILES_ENABLED": "False",
}
DEFAULT_ENV = {"ANSIBLE_HOST_KEY_CHECKING": "True"}

RC_OK = 0
RC_ERROR = 1
RC_FAILED = 2
RC_UNREACHABLE = 4
RC_PARSER = 4  # ExitCode.PARSER_ERROR == HOST_UNREACHABLE on 2.21.5 ("FIXME: conflicts" upstream)
RC_INVALID_CLI = 5
RC_INTERRUPTED = 99
RC_UNEXPECTED = 250
STAT_KEYS = ("ok", "changed", "failed", "unreachable", "skipped", "rescued", "ignored")


class AnsibleError(RuntimeError):
    """ansible-playbook could not be started."""


class EngineNotFound(AnsibleError):
    pass


class AnsibleTimeout(AnsibleError):
    """The deadline passed while the playbook ran; the process group was killed."""


def callback_plugins_dir() -> Path:
    """The directory that holds ``codeorca_jsonl.py`` (the value of ``ANSIBLE_CALLBACK_PLUGINS``)."""
    from codeorca.ansible_plugins import callback

    return Path(callback.__file__).resolve().parent


_RC_TEXT = {
    RC_OK: "ok",
    RC_ERROR: "error",
    RC_FAILED: "failed hosts",
    RC_UNREACHABLE: "unreachable hosts or parser error",
    RC_INVALID_CLI: "invalid command-line option",
    RC_INTERRUPTED: "interrupted",
    RC_UNEXPECTED: "unexpected error",
}


def describe_rc(rc: int) -> str:
    """The exit code alone (prefer :meth:`AnsibleResult.describe`, which reads the stats): 4 is ambiguous."""
    return _RC_TEXT.get(rc, f"exit {rc}")


@dataclass
class AnsibleResult:
    rc: int
    stats: dict[str, dict[str, int]] = field(default_factory=dict)  # host -> {ok, changed, failed, ...}
    events: list[dict[str, Any]] = field(default_factory=list)  # UNREDACTED; never persist without redaction
    failed_hosts: list[str] = field(default_factory=list)
    unreachable_hosts: list[str] = field(default_factory=list)
    check_unsupported: list[tuple[str, str]] = field(default_factory=list)  # (host, task)
    argv: list[str] = field(default_factory=list)
    env_names: list[str] = field(default_factory=list)
    duration_s: float = 0.0
    stderr_lines: list[str] = field(default_factory=list)  # UNREDACTED

    @property
    def ok(self) -> bool:
        return self.rc == RC_OK

    @property
    def stats_seen(self) -> bool:
        """A stats event arrived: the playbook parsed and ran (a parser or CLI error never emits one)."""
        return any(event.get("type") == "stats" for event in self.events)

    def describe(self) -> str:
        """The status from the stats, not the exit code (4 is both "unreachable" and "parser error")."""
        if self.rc == RC_OK:
            return "ok"
        if not self.stats_seen:
            return "parser error" if self.rc == RC_PARSER else describe_rc(self.rc)
        parts = []
        if self.failed_hosts:
            parts.append("failed hosts")
        if self.unreachable_hosts:
            parts.append("unreachable hosts")
        return " and ".join(parts) if parts else describe_rc(self.rc)

    def last_failure(self) -> dict[str, Any] | None:
        """The last ``runner``/``item`` event with status ``failed`` (``unreachable``) that was not ignored, for a
        host the stats count as failed (unreachable). A rescued failure or an ``ignore_unreachable`` result is a
        failed event too, for a host the stats do not count, so it never replaces the real failure. Without a
        stats event (the run was killed) every non-ignored failure counts."""
        hosts = {"failed": set(self.failed_hosts), "unreachable": set(self.unreachable_hosts)}
        for event in reversed(self.events):
            status = event.get("status")
            if event.get("type") not in ("runner", "item") or status not in hosts or event.get("ignore_errors"):
                continue
            if self.stats_seen and event.get("host") not in hosts[status]:
                continue
            return event
        return None


def summarize(
    events: list[dict[str, Any]],
) -> tuple[dict[str, dict[str, int]], list[str], list[str], list[tuple[str, str]]]:
    """``(stats, failed_hosts, unreachable_hosts, check_unsupported)`` from a parsed event stream."""
    stats: dict[str, dict[str, int]] = {}
    check_unsupported: list[tuple[str, str]] = []
    for event in events:
        kind = event.get("type")
        if kind == "stats" and isinstance(event.get("stats"), dict):
            for host, counts in event["stats"].items():
                if isinstance(counts, dict):
                    stats[str(host)] = {k: int(counts.get(k, 0) or 0) for k in STAT_KEYS}
        elif kind in ("runner", "item") and event.get("check_unsupported"):
            pair = (str(event.get("host")), str(event.get("task")))
            if pair not in check_unsupported:
                check_unsupported.append(pair)
    failed = sorted(h for h, c in stats.items() if c["failed"])
    unreachable = sorted(h for h, c in stats.items() if c["unreachable"])
    return stats, failed, unreachable, check_unsupported


def generate_inventory(inline: Mapping[str, Any]) -> str:
    """Ansible inventory YAML from a step's ``inventory.inline`` mapping (top-level keys are groups, as the
    ``yaml`` inventory plugin reads them). Strings are quoted, so a value such as ``yes`` or ``on`` stays a string
    when Ansible reads the file as YAML 1.1."""
    if not isinstance(inline, Mapping) or not inline:
        raise ValueError("inventory.inline must be a non-empty mapping of groups")
    return _dump_yaml(_plain(dict(inline)))


def generate_role_playbook(
    role_fqcn: str,
    hosts: str = "all",
    extra: Mapping[str, Any] | None = None,
    *,
    gather_facts: bool = False,
) -> str:
    """One play, one ``ansible.builtin.import_role`` task. ``extra`` adds play keywords (``become``, ``vars``,
    ``gather_facts`` ...); ``hosts`` and ``tasks`` cannot be overridden."""
    if not role_fqcn or not isinstance(role_fqcn, str) or any(ch.isspace() for ch in role_fqcn):
        raise ValueError(f"invalid role name {role_fqcn!r}")
    play: dict[str, Any] = {"name": f"Run role {role_fqcn}", "hosts": hosts, "gather_facts": gather_facts}
    for key, value in (extra or {}).items():
        if key in ("hosts", "tasks", "roles"):
            raise ValueError(f"role playbook: play keyword {key!r} cannot be overridden")
        play[str(key)] = _plain(value)
    play["tasks"] = [{"name": f"Import role {role_fqcn}", "ansible.builtin.import_role": {"name": role_fqcn}}]
    return _dump_yaml([play])


def write_handoff(directory: str | os.PathLike[str], name: str, mapping: Mapping[str, Any]) -> Path:
    """Write ``mapping`` as JSON to ``<directory>/<name>`` (created 0600 before any byte lands); the directory is
    created 0700 when missing. Returns the path."""
    if "/" in name or name in ("", ".", ".."):
        raise ValueError(f"invalid handoff file name {name!r}")
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    path = directory / name
    # plain_tree first: str keys everywhere, or sort_keys raises on a mapping with int and str keys ({80: http, a: b})
    return write_private(path, json.dumps(plain_tree(dict(mapping)), indent=2, sort_keys=True) + "\n")


def write_private(path: str | os.PathLike[str], text: str) -> Path:
    """Create (or truncate) ``path`` with mode 0600 and write ``text``."""
    path = Path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.chmod(path, 0o600)
    return path


def plain_tree(value: Any) -> Any:
    """JSON/YAML-safe plain data: str keys, lists for every sequence/set, ``str()`` for anything else."""
    if isinstance(value, Mapping):
        return {str(k): plain_tree(v) for k, v in value.items()}
    if isinstance(value, list | tuple | set | frozenset):
        return [plain_tree(v) for v in value]
    if value is None or isinstance(value, bool | int | float | str):
        return value
    return str(value)


_plain = plain_tree


class _QuotedStrRepresenter(SafeRepresenter):
    """Every string quoted: Ansible reads inventory and playbook YAML as 1.1, where a bare ``yes``/``on``/``no`` is a
    bool. A subclass, because ``add_representer`` on the shared class would change every other dump in the process."""


def _represent_str(representer, value: str):
    style = "|" if "\n" in value else '"'
    return representer.represent_scalar("tag:yaml.org,2002:str", value, style=style)


_QuotedStrRepresenter.add_representer(str, _represent_str)


def _dump_yaml(data: Any) -> str:
    yaml = YAML(typ="safe", pure=True)
    yaml.Representer = _QuotedStrRepresenter
    yaml.default_flow_style = False
    out = io.StringIO()
    yaml.dump(data, out)
    return out.getvalue()


def build_env(
    env: Mapping[str, str],
    *,
    local_temp: str | os.PathLike[str] | None = None,
    callback_dir: str | os.PathLike[str] | None = None,
) -> dict[str, str]:
    """The child environment: see the module docstring for what is dropped, forced and defaulted."""
    child = {k: v for k, v in env.items() if k not in DROPPED_ENV}
    for name, value in DEFAULT_ENV.items():
        child.setdefault(name, value)
    plugins = str(Path(callback_dir) if callback_dir is not None else callback_plugins_dir())
    existing = child.get("ANSIBLE_CALLBACK_PLUGINS")
    child["ANSIBLE_CALLBACK_PLUGINS"] = f"{plugins}{os.pathsep}{existing}" if existing else plugins
    child.update(FORCED_ENV)
    if local_temp is not None:
        child["ANSIBLE_LOCAL_TEMP"] = str(local_temp)
    return child


class AnsibleRunner:
    """Runs ``ansible-playbook`` in one working directory; every invocation goes through ``run``."""

    def __init__(
        self,
        workdir: str | os.PathLike[str],
        env: Mapping[str, str],
        stream: StreamCallback | None = None,
        python_executable: str | os.PathLike[str] | None = None,
        *,
        local_temp: str | os.PathLike[str] | None = None,
    ):
        self.workdir = Path(workdir)
        self.stream = stream
        self.python_executable = python_executable
        self.env = build_env(env, local_temp=local_temp)
        self.history: list[AnsibleResult] = []
        self._stream_lock = threading.Lock()

    # ---------------------------------------------------------------- plumbing

    def program(self) -> list[str]:
        """The ansible-playbook argv prefix. With ``python_executable``: the ``ansible-playbook`` next to that
        interpreter, else ``[python, -m, ansible.cli.playbook]``. Without: ``ansible-playbook`` from PATH, else the
        one next to this process's interpreter when ansible-core is importable here (a venv whose ``bin`` is not
        on PATH, which is how the tests run)."""
        if self.python_executable is not None:
            python = Path(self.python_executable)
            sibling = python.parent / PLAYBOOK_PROGRAM
            return [str(sibling)] if os.access(sibling, os.X_OK) else [str(python), "-m", "ansible.cli.playbook"]
        found = shutil.which(PLAYBOOK_PROGRAM, path=self.env.get("PATH") or os.environ.get("PATH"))
        if found:
            return [found]
        if importlib.util.find_spec("ansible") is not None:
            sibling = Path(sys.executable).parent / PLAYBOOK_PROGRAM
            if os.access(sibling, os.X_OK):
                return [str(sibling)]
            return [sys.executable, "-m", "ansible.cli.playbook"]
        raise EngineNotFound(f"{PLAYBOOK_PROGRAM} not found on PATH and ansible-core is not installed here")

    def _emit(self, line: str, channel: str) -> None:
        if self.stream is not None:
            with self._stream_lock:
                self.stream(line, channel)

    def _pump_stdout(self, pipe, events: list[dict[str, Any]]) -> None:
        for line in iter(pipe.readline, ""):
            text = line.rstrip("\r\n")
            event: Any = None
            if text.startswith("{"):
                try:
                    event = json.loads(text)
                except ValueError:
                    event = None
            if isinstance(event, dict) and "type" in event:
                events.append(event)
                self._emit(line if line.endswith("\n") else line + "\n", "stdout")
            else:
                events.append({"type": "log", "channel": "stdout", "line": text})
                self._emit(line if line.endswith("\n") else line + "\n", "stderr")
        pipe.close()

    def _pump_stderr(self, pipe, sink: list[str]) -> None:
        for line in iter(pipe.readline, ""):
            sink.append(line.rstrip("\r\n"))
            self._emit(line if line.endswith("\n") else line + "\n", "stderr")
        pipe.close()

    # ---------------------------------------------------------------- the command

    def run(
        self,
        playbook: str | os.PathLike[str],
        inventory: str | os.PathLike[str],
        *,
        extra_vars_file: str | os.PathLike[str] | None = None,
        tags: list[str] | None = None,
        skip_tags: list[str] | None = None,
        limit: str | None = None,
        check: bool = False,
        diff: bool = False,
        timeout: float | None = None,
    ) -> AnsibleResult:
        argv = [*self.program(), "-i", str(inventory)]
        if extra_vars_file is not None:
            argv += ["-e", f"@{extra_vars_file}"]
        if tags:
            argv += ["--tags", ",".join(str(t) for t in tags)]
        if skip_tags:
            argv += ["--skip-tags", ",".join(str(t) for t in skip_tags)]
        if limit:
            argv += ["--limit", str(limit)]
        if check:
            argv.append("--check")
        if diff:
            argv.append("--diff")
        argv.append(str(playbook))
        started = time.monotonic()
        deadline = None if timeout is None else started + timeout

        def remaining() -> float | None:
            return None if deadline is None else max(deadline - time.monotonic(), 0.0)

        try:
            proc = subprocess.Popen(  # noqa: S603 - argv list, no shell
                argv,
                cwd=self.workdir,
                env=self.env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                start_new_session=True,  # its own process group: a timeout kills the forked workers too
            )
        except OSError as e:
            raise AnsibleError(f"cannot start {argv[0]!r}: {e}") from None
        events: list[dict[str, Any]] = []
        stderr: list[str] = []
        pumps = [
            threading.Thread(target=self._pump_stdout, args=(proc.stdout, events), daemon=True),
            threading.Thread(target=self._pump_stderr, args=(proc.stderr, stderr), daemon=True),
        ]
        for t in pumps:
            t.start()
        timed_out = False
        try:
            rc = proc.wait(timeout=remaining())
            if not _join_pumps(pumps, remaining):
                raise subprocess.TimeoutExpired(argv, timeout or 0)
        except subprocess.TimeoutExpired:
            timed_out = True
            _killpg(proc)
            rc = proc.wait()
            for t in pumps:
                t.join(timeout=5)
        except BaseException:  # an interrupt: the child is in its own session and would survive us
            _killpg(proc)
            proc.wait()
            raise
        stats, failed, unreachable, check_unsupported = summarize(events)
        result = AnsibleResult(
            rc=rc,
            stats=stats,
            events=events,
            failed_hosts=failed,
            unreachable_hosts=unreachable,
            check_unsupported=check_unsupported,
            argv=argv,
            env_names=sorted(self.env),
            duration_s=round(time.monotonic() - started, 3),
            stderr_lines=stderr,
        )
        self.history.append(result)
        if timed_out:
            raise AnsibleTimeout(f"ansible-playbook exceeded {timeout}s (killed after {result.duration_s:.1f}s)")
        return result


PUMP_GRACE_S = 2.0


def _join_pumps(pumps: list[threading.Thread], remaining: Callable[[], float | None]) -> bool:
    """Join the pipe readers after the leader exited; False when one is still alive. A worker holding the pipes open
    cannot keep the step alive past the deadline, but a leader that exited just before it gets ``PUMP_GRACE_S`` for
    the readers to drain the last lines (a run that finished in time is never reported as a timeout)."""
    for t in pumps:
        left = remaining()
        t.join(timeout=None if left is None else max(left, PUMP_GRACE_S))
        if t.is_alive():
            return False
    return True


def _proc_table(proc_root: Path = Path("/proc")) -> list[tuple[int, int]]:
    """``[(pid, ppid)]`` from ``/proc/<pid>/stat`` (Linux; slim images ship no ``ps``). ``comm`` may hold spaces and
    parentheses, so the fields are read after the LAST ``)``."""
    table: list[tuple[int, int]] = []
    try:
        entries = list(proc_root.iterdir())
    except OSError:
        return table
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            stat = (entry / "stat").read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue  # gone meanwhile
        fields = stat.rpartition(")")[2].split()
        if len(fields) >= 2 and fields[1].isdigit():
            table.append((int(entry.name), int(fields[1])))
    return table


def _ps_table() -> list[tuple[int, int]] | None:
    """``[(pid, ppid)]`` from ``ps`` (macOS has no ``/proc``); None when ``ps`` cannot run."""
    try:
        out = subprocess.run(  # noqa: S603 - fixed argv
            ["ps", "-axo", "pid=,ppid="], capture_output=True, text=True, timeout=10, check=False
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    table = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
            table.append((int(parts[0]), int(parts[1])))
    return table


def _process_table(proc_root: Path = Path("/proc")) -> list[tuple[int, int]]:
    """``/proc`` when it is there (Linux), else ``ps``; empty when neither works (the leader's group is still
    killed)."""
    if (proc_root / "self" / "stat").is_file():
        return _proc_table(proc_root)
    return _ps_table() or []


def _descendants(root: int, table: list[tuple[int, int]] | None = None) -> set[int]:
    """Every live descendant of ``root``."""
    children: dict[int, list[int]] = {}
    for pid, ppid in _process_table() if table is None else table:
        children.setdefault(ppid, []).append(pid)
    found: set[int] = set()
    stack = [root]
    while stack:
        for child in children.get(stack.pop(), ()):
            if child not in found:
                found.add(child)
                stack.append(child)
    return found


def _signal_all(pids: set[int], sig: int) -> None:
    for pid in sorted(pids, reverse=True):
        for sender in (os.killpg, os.kill):
            try:
                sender(pid, sig)
            except (ProcessLookupError, PermissionError):
                pass


def _killpg(proc: subprocess.Popen) -> None:
    """SIGKILL the leader's whole tree. The leader's group is SIGSTOPped first (it cannot fork a new worker while we
    look), then every descendant and its group is stopped and the tree listed again (a worker forked meanwhile is
    caught), then everything is SIGKILLed, the leader's group last. Workers are session leaders of their own, so the
    leader's group alone would leave the running module behind. A detached ``async`` task (``async_wrapper``
    double-forks to init) is outside the tree: residual."""
    _signal_all({proc.pid}, signal.SIGSTOP)
    pids = _descendants(proc.pid)
    _signal_all(pids, signal.SIGSTOP)
    pids |= _descendants(proc.pid)
    _signal_all(pids | {proc.pid}, signal.SIGKILL)
