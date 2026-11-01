"""The ``shell`` step: ``run: [argv]`` (an argv array, never a shell string), plan section 5.8.

- argv and the child environment's NAMES are recorded in the step dir (``argv.json``, ``env-names.json``);
  values never are.
- stdout and stderr stream line by line into ``stdout.log`` / ``stderr.log`` through the run dir's line sink;
  ``StepContext.stream`` is the hook integration uses to attach the redactor to every line before it is written.
- ``timeout`` kills the process group and raises ``StepTimeout`` (the runner records ``errored``).
- Contract shared with the helpers: ``CODEORCA_OUTPUT_FILE`` names a JSON file the script may write; it comes
  back as ``result.output`` and the file is rewritten through the stream hook (the child wrote it unredacted).
  ``CODEORCA_DRY_RUN=1`` is set under ``--dry-run``. stdout is a log, never parsed.
- ``result`` = ``{exit_code, stdout_path, stderr_path, output}``; exit 0 is ``succeeded``, anything else ``failed``.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import threading
from typing import IO

from codeorca.rundir import LineSink
from codeorca.runner import StepContext, StepError, StepResult, StepTimeout


def _pump(pipe: IO[str], sink: LineSink) -> None:
    with pipe:
        for line in pipe:
            sink.write_line(line.rstrip("\n"))


def run_shell(step, ctx: StepContext) -> StepResult:
    argv = [str(a) for a in step.run]
    if not argv:
        raise StepError(f"step {step.id}: run is empty")
    env = dict(ctx.env)
    ctx.run_dir.write_argv(step.id, argv)
    ctx.run_dir.write_env_names(step.id, env)
    out_sink = ctx.run_dir.line_sink(step.id, "stdout", ctx.line_filter("stdout"))
    err_sink = ctx.run_dir.line_sink(step.id, "stderr", ctx.line_filter("stderr"))
    output_file = env.get("CODEORCA_OUTPUT_FILE")
    with out_sink, err_sink:
        try:
            proc = subprocess.Popen(
                argv,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                start_new_session=True,  # its own process group, so a timeout kills children too
            )
        except OSError as e:
            raise StepError(f"step {step.id}: cannot start {argv[0]!r}: {e}") from None
        assert proc.stdout is not None and proc.stderr is not None
        pumps = [
            threading.Thread(target=_pump, args=(proc.stdout, out_sink), daemon=True),
            threading.Thread(target=_pump, args=(proc.stderr, err_sink), daemon=True),
        ]
        for t in pumps:
            t.start()
        try:
            exit_code = proc.wait(timeout=ctx.timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
            for t in pumps:
                t.join(timeout=5)
            raise StepTimeout(f"step {step.id}: exceeded {ctx.timeout}s") from None
        for t in pumps:
            t.join()
    output = None
    if output_file and os.path.exists(output_file):
        with open(output_file, encoding="utf-8") as fh:
            text = fh.read()
        try:
            output = json.loads(text)
        except json.JSONDecodeError as e:
            raise StepError(f"step {step.id}: {output_file} is not JSON: {e}") from None
        line_filter = ctx.line_filter("stdout")
        if line_filter is not None:
            # the child wrote this file itself; rewrite it through the redactor so the run dir never keeps a
            # value the hook would have scrubbed from a log line
            with open(output_file, "w", encoding="utf-8") as fh:
                fh.write(line_filter(text))
    result = {
        "exit_code": exit_code,
        "stdout_path": str(out_sink.path),
        "stderr_path": str(err_sink.path),
        "output": output,
    }
    if exit_code == 0:
        return StepResult("succeeded", result=result)
    return StepResult("failed", result=result, error=f"{argv[0]} exited {exit_code}{_stderr_tail(err_sink.path)}")


def _stderr_tail(path, limit: int = 2000) -> str:
    """The end of the (already redacted) stderr log, so ``retry.policy: transient`` can match the error text."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    tail = text[-limit:].strip()
    return f": {tail}" if tail else ""
