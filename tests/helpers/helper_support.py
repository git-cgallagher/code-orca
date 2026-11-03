"""Shared setup for the helper-step tests: a throwaway project root holding the fixture scripts, a real
``SecretRegistry``, and a runner wired the way integration wires it (registry line hook + record filter).

A uniquely named module (``conftest.py`` re-exports its fixtures) so the test files can import its constants
without colliding with the other ``conftest`` modules."""

from __future__ import annotations

import hashlib
import os
import shutil
from collections.abc import Callable
from pathlib import Path

import pytest

from codeorca.models import Workflow
from codeorca.project import load_project
from codeorca.redact import DEFAULT_KEY_DENYLIST, SecretRegistry
from codeorca.rundir import RunDir
from codeorca.runner import Runner
from codeorca.secrets import line_hook, record_filter
from codeorca.steps import default_executors, powershell_step, python_step

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "helpers"
SECRET_REF = "ssm:/example/helper-secret"
SECRET = "FIXTURE-SECRET-helper-value-0001"
SHORT_REF = "ssm:/example/short"
SHORT = "short"  # under the registry's min_length (8): cannot be scrubbed
SECRETS = {SECRET_REF: SECRET, SHORT_REF: SHORT}


def sha16(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def fake_resolver(ref: str) -> str:
    return SECRETS[ref]


def make_project_root(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    root.mkdir()
    shutil.copytree(FIXTURES / "scripts", root / "scripts")
    shutil.copytree(FIXTURES / "ps", root / "ps")
    (root / "codeorca.yaml").write_text(
        "\n".join(
            [
                "api: codeorca/v1",
                "project: helpers",
                "runtime:",
                "  {image: example, terraform: '1.14.7', ansible_core: '2.21.5', python: '>=3.13', pwsh: '7.6.*'}",
                "backend: {type: local}",
                "redaction:",
                "  placeholder: hmac",
                "  hmac_key: ssm:/example/redaction-key",
                '  key_denylist: ["(?i)password", "(?i)secret", "(?i)token"]',
                "",
            ]
        ),
        encoding="utf-8",
    )
    return root


@pytest.fixture
def project_root(tmp_path: Path) -> Path:
    return make_project_root(tmp_path)


@pytest.fixture
def registry() -> SecretRegistry:
    return SecretRegistry(b"example-not-secret-hmac-key", "test")


def base_env() -> dict[str, str]:
    """The test process env without anything code-orca would set or strip itself."""
    return {k: v for k, v in os.environ.items() if not k.startswith("CODEORCA_")}


def workflow(steps: list[dict]) -> Workflow:
    return Workflow.model_validate({"api": "codeorca/v1", "kind": "workflow", "name": "t", "steps": steps})


@pytest.fixture
def run_workflow(project_root: Path, registry: SecretRegistry, tmp_path: Path) -> Callable[..., tuple[int, Runner]]:
    """``run_workflow(steps, dry_run=False, resolver=fake_resolver, hooks=True, project=True, env=None)``."""

    def _run(
        steps: list[dict],
        *,
        dry_run: bool = False,
        resolver=fake_resolver,
        hooks: bool = True,
        project: bool = True,
        env: dict[str, str] | None = None,
    ) -> tuple[int, Runner]:
        proj = load_project(project_root / "codeorca.yaml") if project else None
        executors = default_executors()
        executors["python"] = python_step.make_executor(registry, resolver)
        executors["powershell"] = powershell_step.make_executor(registry, resolver)
        kw = {}
        if hooks:
            kw = {"stream": line_hook(registry), "redact": record_filter(registry, DEFAULT_KEY_DENYLIST)}
        runner = Runner(
            proj,
            workflow(steps),
            {},
            RunDir(tmp_path / "runs"),
            executors,
            dry_run=dry_run,
            env=env if env is not None else base_env(),
            sleep=lambda s: None,
            **kw,
        )
        return runner.run(), runner

    return _run
