"""Terraform adapter: every invocation goes through ``TerraformRunner._run``, which checks the deny floor first.

Command contract (plan §5.4, verified on Terraform 1.14.7):

- ``TF_IN_AUTOMATION=1`` and ``TF_INPUT=0`` are always set; ``TF_LOG`` is never set here (a debug run passes it
  in ``env`` and only through a redacting stream callback); ``TF_WORKSPACE`` in ``env`` selects a workspace.
- ``-no-color`` and ``-input=false`` are added where the subcommand accepts them; flags are always ``-flag=value``.
- ``plan -detailed-exitcode``: exit 2 means changes and is returned, never collapsed into a failure.
- ``show -json`` / ``output -json`` / ``providers schema -json`` are parsed in memory. They hold sensitive
  values in plain text; this class never writes them. Redaction is the caller's job: ``stream`` receives every
  stdout/stderr line and is where a ``StreamRedactor`` attaches (this module does not import ``codeorca.redact``).
- ``apply`` runs only a plan file whose sha256 matches the approved one.
- Non-secret backend settings go through a temporary ``.hcl``; credential-looking keys are refused, because
  ``.terraform/terraform.tfstate`` persists ``-backend-config`` values in plain text.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from codeorca import policy, tfjson

StreamCallback = Callable[[str, str], None]
"""``stream(line, channel)``: ``line`` keeps its trailing newline (chunk pumps rely on it); ``channel`` is
``"stdout"`` or ``"stderr"``. It is called from the two pipe-reader threads, but never concurrently: calls are
serialized by a lock, so a stateful callback such as a ``StreamRedactor`` needs no locking of its own."""

# Keys whose value would be a credential. Credentials never travel through -backend-config.
CREDENTIAL_KEY_PATTERN = re.compile(
    r"(?i)(access_key|secret_key|session_token|token|password|passwd|secret|credential|client_secret|"
    r"sas_key|private_key|shared_credentials)"
)


class TerraformError(RuntimeError):
    """The engine could not be run, or a command failed in a way the caller cannot act on."""


class EngineNotFound(TerraformError):
    pass


class PlanBindingError(TerraformError):
    """The plan file on disk is not the one that was approved."""


@dataclass
class CommandResult:
    """What one invocation did. ``argv`` and ``env_names`` (names only, never values) feed the run directory."""

    argv: list[str]
    exit_code: int
    stdout_lines: list[str] = field(default_factory=list)
    stderr_lines: list[str] = field(default_factory=list)
    env_names: list[str] = field(default_factory=list)
    duration_s: float = 0.0

    @property
    def stdout(self) -> str:
        return "\n".join(self.stdout_lines)

    @property
    def stderr(self) -> str:
        return "\n".join(self.stderr_lines)

    def is_transient(self, patterns: Iterable[str]) -> bool:
        return is_transient(self.stdout + "\n" + self.stderr, patterns)


@dataclass
class InitResult(CommandResult):
    messages: list[dict] = field(default_factory=list)


@dataclass
class PlanResult(CommandResult):
    """``exit_code`` is 0 (no changes), 1 (error) or 2 (changes); ``changed`` is ``exit_code == 2``."""

    changed: bool = False
    plan_file: str = ""


@dataclass
class ApplyResult(CommandResult):
    plan_file: str = ""
    plan_sha256: str = ""
    messages: list[dict] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)


def plan_file_sha256(path: str | os.PathLike[str]) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_transient(text: str, patterns: Iterable[str]) -> bool:
    """True when any pattern (plain substring, e.g. ``policy.transient_errors``) occurs in the text."""
    return any(p and p in text for p in patterns)


def render_backend_hcl(backend_config: Mapping[str, object]) -> str:
    """Flat ``key = value`` HCL for ``-backend-config=<file>``. Refuses credential-looking keys and nested values."""
    lines = []
    for key in sorted(backend_config):
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            raise ValueError(f"backend config key {key!r} is not an identifier")
        if CREDENTIAL_KEY_PATTERN.search(key):
            raise ValueError(
                f"backend config key {key!r} looks like a credential; credentials go in the environment, never "
                "through -backend-config (Terraform persists it in plain text under .terraform/)"
            )
        value = backend_config[key]
        if isinstance(value, bool):
            rendered = "true" if value else "false"
        elif isinstance(value, int | float):
            rendered = repr(value)
        elif isinstance(value, str):
            escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
            rendered = f'"{escaped}"'
        else:
            raise ValueError(f"backend config key {key!r}: only scalars are rendered, got {type(value).__name__}")
        lines.append(f"{key} = {rendered}")
    return "\n".join(lines) + "\n"


def _read_test_commands(tests_dir: Path) -> list[tuple[Path, str]]:
    """``(file, command)`` for every ``command = ...`` in ``*.tftest.hcl`` under the tests directory."""
    found = []
    if not tests_dir.is_dir():
        return found
    pattern = re.compile(r"^\s*command\s*=\s*(\w+)", re.MULTILINE)
    for path in sorted(tests_dir.rglob("*.tftest.hcl")):
        for match in pattern.finditer(path.read_text(encoding="utf-8")):
            found.append((path, match.group(1)))
    return found


class TerraformRunner:
    """Runs Terraform in one working directory. One ``_run`` for everything; the deny floor runs first."""

    def __init__(
        self,
        workdir: str | os.PathLike[str],
        env: Mapping[str, str],
        engine: str = "terraform",
        stream: StreamCallback | None = None,
        lock: bool = True,
        lock_timeout: str = "60s",
        plugin_cache_dir: str | os.PathLike[str] | None = None,
    ):
        self.workdir = Path(workdir)
        self.engine = engine
        self.stream = stream
        self.lock = lock
        self.lock_timeout = lock_timeout
        base = dict(env)
        base["TF_IN_AUTOMATION"] = "1"
        base["TF_INPUT"] = "0"
        if plugin_cache_dir is not None:
            base["TF_PLUGIN_CACHE_DIR"] = str(plugin_cache_dir)
        self.env = base
        self.history: list[CommandResult] = []
        self._stream_lock = threading.Lock()

    # ---------------------------------------------------------------- plumbing

    @property
    def workspace(self) -> str | None:
        """Workspaces are selected only through ``TF_WORKSPACE`` (no ``workspace select`` prompts)."""
        return self.env.get("TF_WORKSPACE")

    def _engine_path(self) -> str:
        if os.sep in self.engine or (os.altsep and os.altsep in self.engine):
            if os.access(self.engine, os.X_OK):
                return self.engine
            raise EngineNotFound(f"engine {self.engine!r} is not executable")
        found = shutil.which(self.engine, path=self.env.get("PATH") or os.environ.get("PATH"))
        if not found:
            raise EngineNotFound(f"engine {self.engine!r} not found on PATH")
        return found

    def _pump(self, pipe, channel: str, sink: list[str]) -> None:
        for line in iter(pipe.readline, ""):
            sink.append(line.rstrip("\r\n"))
            if self.stream is not None:
                with self._stream_lock:  # stdout and stderr pumps share one callback; never re-enter it
                    self.stream(line, channel)
        pipe.close()

    def _run(self, args: list[str], *, allow_migrate_state: bool = False) -> CommandResult:
        """The single subprocess boundary: policy check, then line-pumped execution, then a recorded result."""
        argv = [self.engine, *args]
        policy.check_argv(argv, allow_migrate_state=allow_migrate_state)
        argv[0] = self._engine_path()
        started = time.monotonic()
        proc = subprocess.Popen(  # noqa: S603 - argv list, no shell, policy-checked above
            argv,
            cwd=self.workdir,
            env=self.env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        out: list[str] = []
        err: list[str] = []
        threads = [
            threading.Thread(target=self._pump, args=(proc.stdout, "stdout", out), daemon=True),
            threading.Thread(target=self._pump, args=(proc.stderr, "stderr", err), daemon=True),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        exit_code = proc.wait()
        result = CommandResult(
            argv=argv,
            exit_code=exit_code,
            stdout_lines=out,
            stderr_lines=err,
            env_names=sorted(self.env),
            duration_s=time.monotonic() - started,
        )
        self.history.append(result)
        return result

    def _json_document(self, args: list[str], what: str) -> dict:
        result = self._run(args)
        if result.exit_code != 0:
            raise TerraformError(f"{what} failed (exit {result.exit_code}): {result.stderr.strip()[:2000]}")
        try:
            document = json.loads(result.stdout)
        except ValueError as e:
            raise TerraformError(f"{what} did not return JSON: {e}") from None
        if not isinstance(document, dict):
            raise TerraformError(f"{what} returned {type(document).__name__}, expected an object")
        return document

    def _lock_flags(self, lock: bool | None) -> list[str]:
        use_lock = self.lock if lock is None else lock
        return [f"-lock-timeout={self.lock_timeout}"] if use_lock else ["-lock=false"]

    # ---------------------------------------------------------------- commands

    def init(
        self,
        backend_config: Mapping[str, object] | None = None,
        lockfile_readonly: bool = False,
        reconfigure: bool = False,
    ) -> InitResult:
        """``init -json``; backend settings (non-secret only) go through a temporary 0600 ``.hcl``."""
        args = ["init", "-no-color", "-input=false", "-json"]
        if lockfile_readonly:
            args.append("-lockfile=readonly")
        if reconfigure:
            args.append("-reconfigure")
        tmpdir: str | None = None
        try:
            if backend_config:
                hcl = render_backend_hcl(backend_config)  # refuses credential keys before anything is written
                tmpdir = tempfile.mkdtemp(prefix="codeorca-backend-")
                hcl_path = Path(tmpdir, "backend.hcl")
                hcl_path.write_text(hcl, encoding="utf-8")
                hcl_path.chmod(0o600)
                args.append(f"-backend-config={hcl_path}")
            result = self._run(args)
        finally:
            if tmpdir:
                shutil.rmtree(tmpdir, ignore_errors=True)
        return InitResult(**result.__dict__, messages=tfjson.parse_json_stream(result.stdout_lines))

    def validate(self) -> dict:
        """``validate -json``. Exit 1 means invalid and is reported in the document (``valid: false``)."""
        result = self._run(["validate", "-no-color", "-json"])
        try:
            document = json.loads(result.stdout)
        except ValueError:
            document = None
        if not isinstance(document, dict):
            raise TerraformError(
                f"validate did not return JSON (exit {result.exit_code}): {result.stderr.strip()[:2000]}"
            )
        if result.exit_code not in (0, 1):
            raise TerraformError(f"validate exited {result.exit_code}: {result.stderr.strip()[:2000]}")
        return document

    def plan(
        self, out: str | os.PathLike[str], var_file: str | os.PathLike[str] | None = None, lock: bool | None = None
    ) -> PlanResult:
        """``plan -detailed-exitcode -out=<out>``: exit 0 none, 1 error, 2 changes. Exit 2 is success."""
        out_path = Path(out)
        args = ["plan", "-no-color", "-input=false", *self._lock_flags(lock), "-detailed-exitcode", f"-out={out_path}"]
        if var_file is not None:
            args.append(f"-var-file={var_file}")
        result = self._run(args)
        if result.exit_code not in (0, 1, 2):
            raise TerraformError(f"plan exited {result.exit_code}: {result.stderr.strip()[:2000]}")
        if result.exit_code in (0, 2) and out_path.exists():
            out_path.chmod(0o600)  # the plan file embeds variable values and prior state in clear text
        return PlanResult(**result.__dict__, changed=result.exit_code == 2, plan_file=str(out_path))

    def show_plan(self, plan_file: str | os.PathLike[str]) -> dict:
        """``show -json <plan>``, in memory. Contains sensitive values in plain text; never written here."""
        return self._json_document(["show", "-no-color", "-json", str(plan_file)], "show plan")

    def show_state(self) -> dict:
        """``show -json`` of the current state, in memory only (a state routinely holds secrets)."""
        return self._json_document(["show", "-no-color", "-json"], "show state")

    def output_json(self) -> dict:
        return self._json_document(["output", "-no-color", "-json"], "output")

    def providers_schema(self) -> dict:
        return self._json_document(["providers", "schema", "-no-color", "-json"], "providers schema")

    def apply(self, plan_file: str | os.PathLike[str], expected_sha256: str) -> ApplyResult:
        """``apply -json <plan>``, refused unless ``sha256(plan_file) == expected_sha256`` (checked before any run)."""
        plan_path = Path(plan_file)
        if not plan_path.is_file():
            raise PlanBindingError(f"plan file {plan_path} does not exist")
        actual = plan_file_sha256(plan_path)
        if not expected_sha256 or actual.lower() != expected_sha256.lower():
            raise PlanBindingError(
                f"plan file {plan_path} sha256 {actual[:12]}… does not match the approved {expected_sha256[:12]}…; "
                "re-plan and re-approve"
            )
        args = ["apply", "-no-color", "-input=false", f"-lock-timeout={self.lock_timeout}", "-json", str(plan_path)]
        result = self._run(args)
        messages = tfjson.parse_json_stream(result.stdout_lines)
        return ApplyResult(
            **result.__dict__,
            plan_file=str(plan_path),
            plan_sha256=actual,
            messages=messages,
            errors=tfjson.diagnostics(messages),
        )

    def test(self, plan_mode_only: bool = True, tests_dir: str | os.PathLike[str] = "tests") -> dict:
        """``test -json``. With ``plan_mode_only`` a ``run`` block that says ``command = apply`` is refused up front.

        Terraform has no flag that forces plan mode (``run`` blocks default to apply), so the only enforcement
        is reading the ``*.tftest.hcl`` files before running them.
        """
        if plan_mode_only:
            apply_runs = [(p, c) for p, c in _read_test_commands(self.workdir / tests_dir) if c == "apply"]
            if apply_runs:
                names = ", ".join(str(p.relative_to(self.workdir)) for p, _ in apply_runs)
                raise policy.PolicyError("test-apply", f"terraform test run blocks with command = apply: {names}")
        result = self._run(["test", "-no-color", "-json"])
        messages = tfjson.parse_json_stream(result.stdout_lines)
        summary = next((m.get("test_summary") for m in messages if m.get("type") == "test_summary"), None) or {}
        return {
            "argv": result.argv,
            "exit_code": result.exit_code,
            "passed": result.exit_code == 0 and summary.get("status", "pass") == "pass",
            "summary": summary,
            "messages": messages,
            "errors": tfjson.diagnostics(messages),
        }
