"""Fixtures shared by the spec-render step tests (``tests/`` is not a package; pytest puts this directory on
``sys.path``)."""

from __future__ import annotations

from pathlib import Path

import pytest
from test_spec_render_ansible import make_project_root


@pytest.fixture
def project_root(tmp_path: Path) -> Path:
    return make_project_root(tmp_path)
