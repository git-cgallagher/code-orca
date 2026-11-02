"""The reference project's Ansible workflow end to end through the CLI: configure-local, then render.

Needs ``ansible-playbook`` (on PATH or next to the test interpreter; skipped otherwise). Runs on a temporary copy
of the reference project, and the role's ``app_config_dir`` is pointed at a temporary directory OUTSIDE that copy
(the rendered ``app.conf`` holds the token by design: it is the real configuration). The placeholder token
``FIXTURE-SECRET-reference-token-001`` is the workflow input's default; it must never reach a spec, a log or the
run directory.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

from codeorca import cli
from codeorca.redact import SecretRegistry, scan_outputs
from codeorca.rundir import list_runs

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = ROOT / "examples" / "reference"
TOKEN = "FIXTURE-SECRET-reference-token-001"
KEY = "example-not-secret-ci-key"
SPEC = Path("specs/app/hosts/app-host.yaml")
SIDECAR = Path("specs/app/hosts/app-host.meta.yaml")


def ansible_available() -> bool:
    # duplicated from tests/ansible/ansible_support.py: pytest puts only this file's directory on sys.path
    if shutil.which("ansible-playbook"):
        return True
    return (
        importlib.util.find_spec("ansible") is not None and (Path(sys.executable).parent / "ansible-playbook").exists()
    )


pytestmark = pytest.mark.skipif(not ansible_available(), reason="ansible-playbook is not available")


@pytest.fixture
def project(tmp_path: Path, monkeypatch) -> Path:
    root = tmp_path / "reference"
    shutil.copytree(REFERENCE, root, ignore=shutil.ignore_patterns(".codeorca", "specs", ".terraform*", "*.tfstate*"))
    monkeypatch.setenv("CODEORCA_REDACTION_KEY", KEY)
    return root


def body(text: str) -> str:
    """The spec minus its ``codeorca:`` header block."""
    lines = text.splitlines(keepends=True)
    end = next(i for i, line in enumerate(lines[1:], 1) if not line.startswith(" "))
    return "".join(lines[end:])


def run_ids(project: Path) -> list[str]:
    return list_runs(project / ".codeorca" / "runs")


def test_configure_local_end_to_end(project: Path, tmp_path: Path, capsys, monkeypatch):
    config_dir = tmp_path / "app-config"  # outside the project copy
    p = str(project / "codeorca.yaml")
    argv = ["run", "configure-local", "-p", p, "--input", f"config_dir={config_dir}"]
    assert cli.main(argv) == 0
    out = capsys.readouterr().out
    assert "configure  succeeded" in out and "host_spec  succeeded" in out and "show_spec  succeeded" in out
    assert TOKEN not in out
    assert TOKEN in (config_dir / "app.conf").read_text()  # the role really ran, with the real value

    spec, sidecar = project / SPEC, project / SIDECAR
    text = spec.read_text()
    assert "scope: inventory" in text and "scope: play" in text
    assert "kind: ansible_host" in text and "stack: app" in text and "workflow: configure-local" in text
    assert "inventory_source: run:steps/configure/inventory.yml" in text
    assert "  app_listen_port:\n    default: 8080\n" in text and "    resolved: 8080\n" in text
    assert "app_api_token:\n    declared: '<secret: declared>'" in text
    assert "    source: extra_vars (step configure)" in text
    assert "resolved: '<skipped: lookup ansible.builtin.env is a secret source>'" in text
    assert "source: ansible/group_vars/app.yml" in text
    assert "  ansible/roles/app_config/templates/app.conf.j2: |\n" in text
    assert "    listen_port = 8080\n" in text and "    api_token = <secret: declared>\n" in text
    assert "    environment = dev\n" in text and "    bucket = example-app-123456789012\n" in text
    (first_id,) = run_ids(project)
    assert first_id not in text and "generated_at" not in text
    meta = sidecar.read_text()
    assert f"run_id: {first_id}" in meta and "source: steps/host_spec/host-vars.json" in meta

    # nothing under the project holds the token, except the workflow file that defines the default
    for path in project.rglob("*"):
        if path.is_file() and path != project / "workflows" / "configure-local.yaml":
            assert TOKEN not in path.read_bytes().decode("utf-8", "replace"), path
    registry = SecretRegistry(KEY.encode(), "env:test")
    registry.add(TOKEN)
    registry.add(KEY)
    run_dir = project / ".codeorca" / "runs" / first_id
    assert scan_outputs(run_dir, registry) == []

    # a second run renders a byte-identical body
    assert cli.main(argv) == 0
    capsys.readouterr()
    second = spec.read_text()
    assert body(second) == body(text) and second == text
    assert len(run_ids(project)) == 2

    # `codeorca render` re-renders from host-vars.json: no subprocess, no playbook
    argv_files = sorted(run_dir.glob("steps/*/argv.json"))
    before = {f: f.read_text() for f in argv_files}

    def refuse(*_a, **_k):
        raise AssertionError("render must not run ansible")

    monkeypatch.setattr("codeorca.specs.ansible_host.run_vars_subprocess", refuse)
    monkeypatch.setattr("codeorca.steps.host_spec.run_vars_subprocess", refuse)
    monkeypatch.setattr("codeorca.adapters.ansible.AnsibleRunner.run", refuse)
    spec.unlink()
    sidecar.unlink()
    assert cli.main(["render", first_id, "-p", p]) == 0
    assert "host_spec" in capsys.readouterr().out
    assert spec.read_text() == text
    assert f"run_id: {first_id}" in sidecar.read_text()
    assert {f: f.read_text() for f in argv_files} == before
    assert json.loads((run_dir / "steps" / "host_spec" / "host-vars.json").read_text())["host"] == "app-host"
