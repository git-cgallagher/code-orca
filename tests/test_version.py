"""``codeorca.__version__`` comes from the installed metadata: pyproject.toml is the only version source."""

from __future__ import annotations

import tomllib
from pathlib import Path

import codeorca

ROOT = Path(__file__).resolve().parents[1]


def test_version_is_pyproject_s():
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert codeorca.__version__ == pyproject["project"]["version"]
