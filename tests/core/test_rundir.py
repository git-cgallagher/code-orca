"""The run directory: layout, run id format, names-only env record, per-stack flock, list_runs, gc."""

from __future__ import annotations

import json
import os
import stat
from datetime import UTC, datetime

import pytest

from codeorca.rundir import RUN_ID, RunDir, StackLocked, gc, list_runs, new_run_id, stack_lock


def test_run_id_format():
    rid = new_run_id(datetime(2026, 11, 1, 13, 5, 9, tzinfo=UTC))
    assert rid.startswith("20261101T130509Z-")
    assert RUN_ID.match(rid)
    assert new_run_id() != new_run_id()
    with pytest.raises(ValueError, match="invalid run id"):
        RunDir("/nonexistent", "not-a-run-id")


def test_layout(tmp_path):
    rd = RunDir(tmp_path)
    assert rd.path == tmp_path / rd.run_id
    for d in ("steps", "outputs", "handoff", "specs"):
        assert (rd.path / d).is_dir()
    assert stat.S_IMODE(os.stat(rd.handoff_dir).st_mode) == 0o700


def test_step_files_and_env_names_only(tmp_path):
    rd = RunDir(tmp_path)
    rd.write_argv("s", ["echo", 1])
    rd.write_env_names("s", {"PATH": "/bin", "FIXTURE_TOKEN": "FIXTURE-SECRET-value"})
    rd.write_result("s", {"exit_code": 0})
    rd.write_outputs("s", {"x": 1})
    with rd.line_sink("s", "stdout", lambda line: line.replace("FIXTURE-SECRET-value", "***")) as sink:
        sink.write_line("token=FIXTURE-SECRET-value")
        sink.write_line("plain\n")
    sdir = rd.steps_dir / "s"
    assert json.loads((sdir / "argv.json").read_text()) == ["echo", "1"]
    names = (sdir / "env-names.json").read_text()
    assert json.loads(names) == ["FIXTURE_TOKEN", "PATH"]
    assert "FIXTURE-SECRET-value" not in names and "/bin" not in names
    assert rd.read_result("s") == {"exit_code": 0}
    assert rd.read_outputs("s") == {"x": 1}
    assert (sdir / "stdout.log").read_text() == "token=***\nplain\n"
    rd.write_run({"status": "running"})
    assert rd.read_run() == {"status": "running"}


def test_stack_lock_is_exclusive_and_released(tmp_path):
    with stack_lock(tmp_path, "app") as path:
        assert path == tmp_path / "locks" / "app.lock"
        with pytest.raises(StackLocked, match="'app' is locked"):
            with stack_lock(tmp_path, "app"):
                pass
        with stack_lock(tmp_path, "network"):  # a different stack is independent
            pass
    with stack_lock(tmp_path, "app"):  # released on exit
        pass
    with pytest.raises(ValueError, match="invalid stack name"):
        with stack_lock(tmp_path, "../x"):
            pass


def test_list_runs_and_gc_ignore_locks(tmp_path):
    ids = [new_run_id(datetime(2026, 1, 1, 0, 0, s, tzinfo=UTC)) for s in range(4)]
    for rid in ids:
        RunDir(tmp_path, rid)
    with stack_lock(tmp_path, "app"):
        pass
    (tmp_path / "stray").mkdir()
    assert list_runs(tmp_path) == ids
    assert gc(tmp_path, keep=2) == ids[:2]
    assert list_runs(tmp_path) == ids[2:]
    assert (tmp_path / "locks" / "app.lock").exists()
    assert gc(tmp_path, keep=10) == []
    assert list_runs(tmp_path / "missing") == []
