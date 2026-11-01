"""The shell executor's run-dir hygiene: redacted argv, the output file after a bad exit or timeout, attempts
that do not bleed into each other, a background child past the deadline, an interrupt."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from codeorca.models import Workflow
from codeorca.project import load_project
from codeorca.rundir import RunDir
from codeorca.runner import EXIT_FAILED, EXIT_OK, Runner
from codeorca.steps import default_executors

ROOT = Path(__file__).resolve().parents[2]
PROJECT = load_project(ROOT / "examples" / "reference" / "codeorca.yaml")
PY = sys.executable
SECRET = "FIXTURE-SECRET-shell-value"


def hook(name: str, line: str) -> str:
    return line.replace(SECRET, "***")


def py(code: str) -> list[str]:
    return [PY, "-c", code]


def workflow(steps: list[dict], **kw) -> Workflow:
    return Workflow.model_validate({"api": "codeorca/v1", "kind": "workflow", "name": "t", "steps": steps, **kw})


def shell(id: str, run: list[str], **kw) -> dict:
    return {"id": id, "type": "shell", "run": run, **kw}


def run(wf: Workflow, tmp_path, **kw) -> tuple[int, Runner]:
    runner = Runner(PROJECT, wf, {}, RunDir(tmp_path), default_executors(), sleep=lambda s: None, stream=hook, **kw)
    return runner.run(), runner


def test_argv_json_is_written_through_the_stream_hook(tmp_path):
    wf = workflow([shell("a", py("pass") + [f"token={SECRET}"])])
    rc, r = run(wf, tmp_path)
    assert rc == EXIT_OK
    argv_text = (r.run_dir.steps_dir / "a" / "argv.json").read_text()
    assert SECRET not in argv_text and "token=***" in argv_text


def test_non_json_output_file_is_rewritten_through_the_hook_before_the_error(tmp_path):
    code = f"import os; open(os.environ['CODEORCA_OUTPUT_FILE'], 'w').write('not json {SECRET}')"
    wf = workflow([shell("a", py(code))])
    rc, r = run(wf, tmp_path)
    assert rc == EXIT_FAILED and r.states["a"]["status"] == "errored" and "not JSON" in r.states["a"]["error"]
    text = (r.run_dir.steps_dir / "a" / "output.json").read_text()
    assert SECRET not in text and "not json ***" in text


def test_output_file_written_before_a_timeout_is_rewritten_too(tmp_path):
    code = (
        f"import os, time; open(os.environ['CODEORCA_OUTPUT_FILE'], 'w').write('{{\"k\": \"{SECRET}\"}}'); "
        "time.sleep(30)"
    )
    wf = workflow([shell("a", py(code), timeout="300ms")])
    rc, r = run(wf, tmp_path)
    assert rc == EXIT_FAILED and r.states["a"]["error"].startswith("timeout:")
    text = (r.run_dir.steps_dir / "a" / "output.json").read_text()
    assert SECRET not in text and "***" in text


def test_a_failed_attempts_output_file_is_not_the_retried_steps_output(tmp_path):
    counter = tmp_path / "n"
    code = (
        f"import os, sys, json, pathlib; p = pathlib.Path({str(counter)!r}); "
        "n = int(p.read_text() or 0) if p.exists() else 0; p.write_text(str(n + 1)); "
        "(sys.exit(0) if n else "
        "(json.dump({'src': 'attempt1'}, open(os.environ['CODEORCA_OUTPUT_FILE'], 'w')), sys.exit(1)))"
    )
    wf = workflow([shell("a", py(code), retry={"limit": 2, "policy": "failure"})])
    rc, r = run(wf, tmp_path)
    assert rc == EXIT_OK and r.states["a"]["attempts"] == 2
    assert r.run_dir.read_result("a")["output"] is None  # the succeeding attempt wrote no output file


def test_background_child_holding_the_pipe_does_not_outlive_the_timeout(tmp_path):
    # the main process exits 0 at once; a grandchild keeps stdout open for 20s
    wf = workflow([shell("a", ["sh", "-c", "sleep 20 & echo parent-done; exit 0"], timeout="1s")])
    started = time.monotonic()
    rc, r = run(wf, tmp_path)
    assert time.monotonic() - started < 10
    assert rc == EXIT_FAILED and r.states["a"]["status"] == "errored" and r.states["a"]["error"].startswith("timeout:")


def test_transient_matching_sees_only_the_current_attempts_stderr(tmp_path):
    counter = tmp_path / "n"
    code = (
        f"import sys, pathlib; p = pathlib.Path({str(counter)!r}); n = int(p.read_text() or 0) if p.exists() else 0; "
        "p.write_text(str(n + 1)); "
        "print('Throttling' if n == 0 else 'permanent problem', file=sys.stderr); sys.exit(1)"
    )
    wf = workflow([shell("a", py(code), retry={"limit": 5, "policy": "transient"})])
    rc, r = run(wf, tmp_path)
    assert rc == EXIT_FAILED
    assert r.states["a"]["attempts"] == 2  # attempt 2's own stderr matched no transient pattern
    assert "Throttling" not in r.states["a"]["error"] and "permanent problem" in r.states["a"]["error"]


def test_interrupt_kills_the_process_group_and_propagates(tmp_path, monkeypatch):
    pid_file = tmp_path / "pid"
    real_wait = subprocess.Popen.wait
    calls = {"n": 0}

    def interrupted_wait(self, timeout=None):
        if self.args[0] == PY:  # only the step's child, not the runner's own git call
            calls["n"] += 1
        if calls["n"] == 1 and self.args[0] == PY:
            while not pid_file.exists():
                time.sleep(0.01)
            raise KeyboardInterrupt
        return real_wait(self, timeout=timeout)

    monkeypatch.setattr(subprocess.Popen, "wait", interrupted_wait)
    wf = workflow(
        [shell("a", py(f"import os, time; open({str(pid_file)!r}, 'w').write(str(os.getpid())); time.sleep(30)"))]
    )
    rd = RunDir(tmp_path)
    runner = Runner(PROJECT, wf, {}, rd, default_executors())
    with pytest.raises(KeyboardInterrupt):
        runner.run()
    pid = int(pid_file.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)  # reaped: the child did not survive the interrupt
    assert rd.read_run()["steps"]["a"]["status"] == "cancelled"


@pytest.mark.parametrize(
    "argv",
    [
        ["terraform", "-chdir=terraform/app", "destroy", "-auto-approve"],
        ["/usr/local/bin/tofu", "apply", "-target=a.b", "plan.tfplan"],
        ["terraform", "state", "rm", "a.b"],
    ],
)
def test_terraform_argv_in_a_shell_step_goes_through_the_deny_floor(tmp_path, argv):
    wf = workflow([shell("a", argv)])
    rc, r = run(wf, tmp_path)
    assert rc == EXIT_FAILED and r.states["a"]["status"] == "errored" and "policy:" in r.states["a"]["error"]
    assert not (r.run_dir.steps_dir / "a" / "argv.json").exists()  # refused before anything was recorded or run
