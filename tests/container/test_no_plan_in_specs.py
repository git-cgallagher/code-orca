"""container/tests/no_plan_in_specs.py: the leak checks' guard against a plan file (a deflated zip) under specs/."""

from __future__ import annotations

import gzip
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "container" / "tests" / "no_plan_in_specs.py"
SECRET = b"FIXTURE-SECRET-specs-001"


def check(*dirs):
    return subprocess.run([sys.executable, "-I", str(SCRIPT), *map(str, dirs)], capture_output=True, text=True)


@pytest.fixture
def specs(tmp_path):
    d = tmp_path / "specs" / "app"
    d.mkdir(parents=True)
    (d / "plan.yaml").write_text("resources: []\n")
    (d / "plan.meta.yaml").write_text("sha256: 0\n")
    return d.parent


def plan_zip(path: Path) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("tfplan", b"x" * 64 + SECRET + b"y" * 64)
        z.writestr("tfstate", SECRET * 4)


def test_rendered_specs_pass(specs):
    proc = check(specs)
    assert proc.returncode == 0, proc.stderr


@pytest.mark.parametrize("name", ["plan.tfplan", "plan.bin", "copy"])
def test_a_plan_file_under_specs_fails_although_grep_cannot_see_the_secret(specs, name):
    plan = specs / "app" / name
    plan_zip(plan)
    assert SECRET not in plan.read_bytes()  # what grep -ra sees: nothing
    proc = check(specs)
    assert proc.returncode == 1
    assert str(plan) in proc.stderr


def test_other_archives_fail(specs):
    (specs / "app" / "bundle.gz").write_bytes(gzip.compress(SECRET))
    assert check(specs).returncode == 1


def test_a_missing_specs_dir_is_not_a_pass(tmp_path):
    assert check(tmp_path / "nope").returncode == 2
    assert check().returncode == 2
