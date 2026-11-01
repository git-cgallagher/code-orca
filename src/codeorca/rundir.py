"""The run directory (plan sections 5.3 and 5.10).

``<state_dir>/<run_id>/``
    ``run.json``            inputs, resolved vars, step statuses and outputs, git SHA: what a later resume replays
    ``steps/<id>/``         ``argv.json``, ``env-names.json`` (NAMES only, never values), ``result.json``,
                            ``stdout.log``, ``stderr.log`` (already redacted by the time they are written)
    ``outputs/<id>.json``   the step's declared outputs
    ``handoff/`` (0700)     Terraform -> Ansible handoff files (0600, deleted after each step)
    ``specs/``              staging before ``codeorca render`` copies to the project's ``specs_dir``
``<state_dir>/locks/<stack>.lock``   per-stack ``flock`` so two runs never touch one stack at once.

The run id is ``<UTC yyyymmddThhmmssZ>-<6 hex>``: sortable by time, unique enough for one state dir.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import secrets
import shutil
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, Any

RUN_ID = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]{6}$")
LOCKS_DIR = "locks"


class StackLocked(RuntimeError):
    """Another run holds the flock for this stack."""


def new_run_id(now: datetime | None = None) -> str:
    stamp = (now or datetime.now(UTC)).astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{secrets.token_hex(3)}"


def _write_json(path: Path, data: Any) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True, default=_json_default) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def _json_default(obj: Any):
    if isinstance(obj, Path):
        return str(obj)
    raise TypeError(f"{type(obj).__name__} is not JSON serializable")


class LineSink:
    """Appends lines to a log file; an optional ``filter`` (the stream redactor hook) rewrites each line first."""

    def __init__(self, path: Path, line_filter: Callable[[str], str] | None = None):
        self.path = path
        self._filter = line_filter
        self._fh: IO[str] | None = None

    def __enter__(self) -> LineSink:
        self._fh = open(self.path, "a", encoding="utf-8")
        return self

    def __exit__(self, *exc) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None

    def write_line(self, line: str) -> None:
        assert self._fh is not None, "LineSink used outside its context"
        if self._filter is not None:
            line = self._filter(line)
        self._fh.write(line if line.endswith("\n") else line + "\n")
        self._fh.flush()


class RunDir:
    def __init__(self, state_dir: str | Path, run_id: str | None = None):
        if run_id is not None and not RUN_ID.match(run_id):
            raise ValueError(f"invalid run id {run_id!r}")
        self.state_dir = Path(state_dir)
        self.run_id = run_id or new_run_id()
        self.path = self.state_dir / self.run_id
        self.steps_dir = self.path / "steps"
        self.outputs_dir = self.path / "outputs"
        self.handoff_dir = self.path / "handoff"
        self.specs_dir = self.path / "specs"
        self.run_json = self.path / "run.json"
        for d in (self.steps_dir, self.outputs_dir, self.specs_dir):
            d.mkdir(parents=True, exist_ok=True)
        self.handoff_dir.mkdir(mode=0o700, exist_ok=True)
        os.chmod(self.handoff_dir, 0o700)

    # per step -------------------------------------------------------------------------------------------------
    def step_dir(self, step_id: str) -> Path:
        d = self.steps_dir / step_id
        d.mkdir(parents=True, exist_ok=True)
        return d

    def write_argv(self, step_id: str, argv: list[str]) -> Path:
        p = self.step_dir(step_id) / "argv.json"
        _write_json(p, [str(a) for a in argv])
        return p

    def write_env_names(self, step_id: str, env: dict[str, Any] | list[str]) -> Path:
        """Only the NAMES of the child environment are recorded; values never touch the run dir."""
        names = sorted(env.keys() if isinstance(env, dict) else env)
        p = self.step_dir(step_id) / "env-names.json"
        _write_json(p, names)
        return p

    def write_result(self, step_id: str, result: dict[str, Any]) -> Path:
        p = self.step_dir(step_id) / "result.json"
        _write_json(p, result)
        return p

    def read_result(self, step_id: str) -> dict[str, Any] | None:
        p = self.steps_dir / step_id / "result.json"
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None

    def write_outputs(self, step_id: str, outputs: dict[str, Any] | None) -> Path:
        p = self.outputs_dir / f"{step_id}.json"
        _write_json(p, outputs)
        return p

    def read_outputs(self, step_id: str) -> dict[str, Any] | None:
        p = self.outputs_dir / f"{step_id}.json"
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None

    def line_sink(self, step_id: str, name: str, line_filter: Callable[[str], str] | None = None) -> LineSink:
        """``name`` is ``stdout`` or ``stderr``; use as a context manager."""
        return LineSink(self.step_dir(step_id) / f"{name}.log", line_filter)

    # the run record --------------------------------------------------------------------------------------------
    def write_run(self, record: dict[str, Any]) -> Path:
        _write_json(self.run_json, record)
        return self.run_json

    def read_run(self) -> dict[str, Any] | None:
        return json.loads(self.run_json.read_text(encoding="utf-8")) if self.run_json.exists() else None


@contextmanager
def stack_lock(state_dir: str | Path, stack: str) -> Iterator[Path]:
    """Exclusive, non-blocking ``flock`` on ``<state_dir>/locks/<stack>.lock`` held for the block's lifetime.

    Protects the run directory and the working tree, not Terraform state (the S3 ``use_lockfile`` does that).
    """
    if not re.match(r"^[A-Za-z0-9_.-]+$", stack):
        raise ValueError(f"invalid stack name {stack!r}")
    locks = Path(state_dir) / LOCKS_DIR
    locks.mkdir(parents=True, exist_ok=True)
    path = locks / f"{stack}.lock"
    fh = open(path, "a+", encoding="utf-8")  # the handle must stay open for as long as the lock is held
    try:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise StackLocked(f"stack {stack!r} is locked by another run ({path})") from None
        try:
            yield path
        finally:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
    finally:
        fh.close()


def list_runs(state_dir: str | Path) -> list[str]:
    """Run ids under ``state_dir``, oldest first (the id sorts by UTC time). ``locks/`` and strays are ignored."""
    root = Path(state_dir)
    if not root.is_dir():
        return []
    return sorted(p.name for p in root.iterdir() if p.is_dir() and RUN_ID.match(p.name))


def gc(state_dir: str | Path, keep: int) -> list[str]:
    """Delete all but the newest ``keep`` runs; returns the ids removed. Never touches ``locks/``."""
    if keep < 0:
        raise ValueError("keep must be >= 0")
    runs = list_runs(state_dir)
    doomed = runs[: max(0, len(runs) - keep)]
    for run_id in doomed:
        shutil.rmtree(Path(state_dir) / run_id)
    return doomed
