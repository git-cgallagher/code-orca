"""Fixtures for the Ansible tests."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from ansible_support import FIXTURES


@pytest.fixture
def project_root(tmp_path: Path) -> Path:
    """A project directory with the fixtures copied under ``ansible/`` and a project file whose ``ansible.env``
    points ``ANSIBLE_ROLES_PATH`` at the fixture roles (the generated role playbook lives in the step dir)."""
    root = tmp_path / "project"
    shutil.copytree(FIXTURES, root / "ansible")
    (root / "codeorca.yaml").write_text(
        "\n".join(
            [
                "api: codeorca/v1",
                "project: anstest",
                "runtime:",
                "  {image: example, terraform: '1.14.7', ansible_core: '2.21.5', python: '>=3.13', pwsh: '7.6.*'}",
                "backend: {type: local}",
                "redaction: {placeholder: sha256}",
                "ansible:",
                f"  env: {{ANSIBLE_ROLES_PATH: '{root / 'ansible' / 'roles'}'}}",
                "  check_unsupported: warn",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return root
