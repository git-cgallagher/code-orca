"""Shared helpers for the Ansible adapter and step tests (importable: ``tests/`` is not a package, pytest puts this
directory on ``sys.path``). Everything runs offline against ``connection: local``.

The tests need ``ansible-playbook``: on PATH, or next to the interpreter running pytest (a venv whose ``bin`` is
not on PATH is how they run locally). Without either they skip."""

from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures" / "ansible"


def ansible_available() -> bool:
    if shutil.which("ansible-playbook"):
        return True
    return importlib.util.find_spec("ansible") is not None and (
        (Path(sys.executable).parent / "ansible-playbook").exists()
    )


requires_ansible = pytest.mark.skipif(not ansible_available(), reason="ansible-playbook is not available")
