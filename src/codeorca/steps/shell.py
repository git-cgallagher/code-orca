"""The ``shell`` step: ``run: [argv]`` (an argv array, never a shell string), plan section 5.8.

- argv and the child environment's NAMES are recorded in the step dir (``argv.json``, ``env-names.json``);
  values never are, and argv items go through the stream hook first (an interpolated secret is scrubbed).
- stdout and stderr stream line by line into ``stdout.log`` / ``stderr.log`` through the run dir's line sink;
  ``StepContext.stream`` is the hook integration uses to attach the redactor to every line before it is written.
- ``timeout`` bounds the whole step, pipe drain included: a background child that inherited the pipes cannot keep
  the step alive past the deadline. Expiry kills the process group and raises ``StepTimeout`` (the runner records
  ``errored``). Without a timeout the step waits for the pipes to close, however long a grandchild holds them.
- An interrupt (Ctrl-C) while the child runs kills the process group before propagating: the child is in its own
  session, so the terminal's SIGINT never reaches it.
- Contract shared with the helpers: ``CODEORCA_OUTPUT_FILE`` names a JSON file the script may write; it comes
  back as ``result.output``. The child wrote it unredacted, so it is rewritten through the stream hook whenever it
  exists, before it is parsed and whatever the exit status (bad JSON and a timeout included).
  ``CODEORCA_DRY_RUN=1`` is set under ``--dry-run``. stdout is a log, never parsed.
- An argv whose program's basename is ``terraform``/``tofu`` goes through the Terraform deny floor
  (``policy.check_argv``), so the obvious ``run: [terraform, destroy]`` fails validation-style. This is a
  courtesy check, not a boundary: a wrapper (``env terraform ...``, ``sh -c "terraform destroy"``, a copied
  binary) is not inspected. The real boundary for helpers is the credentials and the review of what a
  workflow runs, as the plan says.
- ``result`` = ``{exit_code, stdout_path, stderr_path, output}``; exit 0 is ``succeeded``, anything else ``failed``.
  The error text ends with this attempt's stderr tail (the log file is appended across attempts; the tail is not).
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import threading
import time
from collections.abc import Callable
from pathlib import PurePath
from typing import IO

from codeorca import policy
from codeorca.rundir import LineSink
from codeorca.runner import StepContext, StepError, StepResult, StepTimeout

TERRAFORM_ENGINES = frozenset({"terraform", "tofu"})
_TAIL_LIMIT = 2000


class _Tail:
    """The last ``limit`` characters of what one attempt wrote to a channel (already redacted)."""

    def __init__(self, limit: int = _TAIL_LIMIT) -> None:
        self.limit = limit
        self.text = ""

    def add(self, line: str) -> None:
        self.text = (self.text + line + "\n")[-self.limit :]


def _pump(pipe: IO[str], sink: LineSink, tail: _Tail | None, line_filter: Callable[[str], str] | None) -> None:
    with pipe:
        for raw in pipe:
            line = raw.rstrip("\n")
            sink.write_line(line)
            if tail is not None:
                tail.add(line_filter(line) if line_filter else line)


def _killpg(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def run_shell(step, ctx: StepContext) -> StepResult:
    argv = [str(a) for a in step.run]
    if not argv:
        raise StepError(f"step {step.id}: run is empty")
    if PurePath(argv[0]).name in TERRAFORM_ENGINES:
        try:
            policy.check_argv(argv)
        except policy.PolicyError as e:
            raise StepError(f"step {step.id}: policy: {e}") from None
    return run_argv(step.id, argv, dict(ctx.env), ctx)


def run_argv(
    step_id: str,
    argv: list[str],
    env: dict[str, str],
    ctx: StepContext,
    *,
    cwd: str | os.PathLike[str] | None = None,
    label: str | None = None,
) -> StepResult:
    """Run one argv as the step's child process: everything the module docstring describes after the argv is
    built (argv.json through the hook, env NAMES, line-sinked logs, deadline + process-group kill, the output file
    rewritten and parsed). Shared by ``shell`` and the ``python``/``powershell`` helpers (``steps/helpers.py``).
    ``label`` names the program in the failure message (default ``argv[0]``)."""
    scrub = ctx.line_filter("stdout")
    ctx.run_dir.write_argv(step_id, [scrub(a) if scrub else a for a in argv])
    ctx.run_dir.write_env_names(step_id, env)
    out_sink = ctx.run_dir.line_sink(step_id, "stdout", ctx.line_filter("stdout"))
    err_sink = ctx.run_dir.line_sink(step_id, "stderr", ctx.line_filter("stderr"))
    err_tail = _Tail()
    output_file = env.get("CODEORCA_OUTPUT_FILE")
    deadline = time.monotonic() + ctx.timeout if ctx.timeout is not None else None

    def remaining() -> float | None:
        return None if deadline is None else max(deadline - time.monotonic(), 0.0)

    try:
        with out_sink, err_sink:
            try:
                proc = subprocess.Popen(
                    argv,
                    env=env,
                    cwd=cwd,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    start_new_session=True,  # its own process group, so a timeout kills children too
                )
            except OSError as e:
                raise StepError(f"step {step_id}: cannot start {argv[0]!r}: {e}") from None
            assert proc.stdout is not None and proc.stderr is not None
            pumps = [
                threading.Thread(target=_pump, args=(proc.stdout, out_sink, None, None), daemon=True),
                threading.Thread(
                    target=_pump, args=(proc.stderr, err_sink, err_tail, ctx.line_filter("stderr")), daemon=True
                ),
            ]
            for t in pumps:
                t.start()
            try:
                exit_code = proc.wait(timeout=remaining())
                for t in pumps:  # the pipes may be held open by a background child: bound the drain too
                    t.join(timeout=remaining())
                    if t.is_alive():
                        raise subprocess.TimeoutExpired(argv, ctx.timeout or 0)
            except subprocess.TimeoutExpired:
                _killpg(proc)
                proc.wait()
                for t in pumps:
                    t.join(timeout=5)
                raise StepTimeout(f"step {step_id}: exceeded {ctx.timeout}s") from None
            except BaseException:  # an interrupt: the child is in its own session and would survive us
                _killpg(proc)
                proc.wait()
                raise
    finally:
        _rewrite_output_file(output_file, scrub)
    output = None
    if output_file and os.path.exists(output_file):
        with open(output_file, encoding="utf-8") as fh:
            text = fh.read()
        try:
            output = json.loads(text)
        except json.JSONDecodeError as e:
            raise StepError(f"step {step_id}: {output_file} is not JSON: {e}") from None
    result = {
        "exit_code": exit_code,
        "stdout_path": str(out_sink.path),
        "stderr_path": str(err_sink.path),
        "output": output,
    }
    if exit_code == 0:
        return StepResult("succeeded", result=result)
    tail = err_tail.text.strip()
    name = label or argv[0]
    return StepResult("failed", result=result, error=f"{name} exited {exit_code}{': ' + tail if tail else ''}")


def _rewrite_output_file(output_file: str | None, scrub: Callable[[str], str] | None) -> None:
    """The child wrote this file itself; rewrite it through the redactor so the run dir never keeps a value the
    hook would have scrubbed from a log line. Runs whatever happened to the child."""
    if not output_file or scrub is None or not os.path.exists(output_file):
        return
    with open(output_file, encoding="utf-8") as fh:
        text = fh.read()
    with open(output_file, "w", encoding="utf-8") as fh:
        fh.write(scrub(text))
