"""``codeorca doctor`` with injected probes: no real terraform/ansible/pwsh needed."""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

import pytest

from codeorca import cli, doctor
from codeorca.doctor import VersionSpecError, matches, parse_version, run_checks
from codeorca.project import Runtime, load_project

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = ROOT / "examples" / "reference" / "codeorca.yaml"

RUNTIME = Runtime(
    image="ghcr.io/example/runtime:0.1.0",
    terraform="1.14.7",
    ansible_core="2.21.5",
    python=">=3.13,<3.15",
    pwsh="7.6.*",
    collections={"amazon.aws": "10.1.0"},
    python_packages={"boto3": "1.42.*"},
)
GOOD = {
    "terraform": lambda: "1.14.7",
    "ansible_core": lambda: "2.21.5",
    "python": lambda: "3.14.0",
    "pwsh": lambda: "7.6.1",
    "collections": lambda: {"amazon.aws": "10.1.0", "community.general": "13.5.0"},
    "python_packages": lambda: {"boto3": "1.42.9"},
}


@pytest.mark.parametrize(
    ("found", "spec", "exact", "ok"),
    [
        ("1.14.7", "1.14.7", True, True),
        ("1.14.8", "1.14.7", True, False),
        ("1.14.7", "==1.14.7", True, True),
        ("1.14", "1.14.0", True, True),  # padded
        ("3.14.0", ">=3.13,<3.15", False, True),
        ("3.15.0", ">=3.13,<3.15", False, False),
        ("3.13.0rc1", ">=3.13", False, True),  # pre-release suffix ignored
        ("7.6.1", "7.6.*", False, True),
        ("7.5.9", "7.6.*", False, False),
        ("anything", "*", False, True),
        ("2.21.5", "!=2.21.4,>2.20", False, True),
        (None, "*", False, False),
    ],
)
def test_matches(found, spec, exact, ok):
    assert matches(found, spec, exact=exact) is ok


def test_parse_version_and_bad_spec():
    assert parse_version("v1.2.3-beta") == (1, 2, 3) and parse_version("junk") is None
    with pytest.raises(VersionSpecError):
        matches("1.0", "~1.0")


def test_all_ok_and_observed_block():
    checks, observed = run_checks(RUNTIME, GOOD)
    assert all(c.ok for c in checks)
    assert [c.component for c in checks] == [
        "terraform",
        "ansible_core",
        "python",
        "pwsh",
        "collections.amazon.aws",
        "python_packages.boto3",
    ]
    assert observed["collections"] == {"amazon.aws": "10.1.0", "community.general": "13.5.0"}
    assert observed["python_packages"] == {"boto3": "1.42.9"} and observed["image"] == RUNTIME.image


def test_missing_tool_and_mismatch_are_reported():
    probes = dict(GOOD, pwsh=lambda: None, terraform=lambda: "1.13.0", collections=lambda: {})
    checks, _ = run_checks(RUNTIME, probes)
    by = {c.component: c.as_dict() for c in checks}
    assert by["pwsh"]["status"] == "missing" and by["terraform"]["status"] == "mismatch"
    assert by["collections.amazon.aws"]["status"] == "missing"
    assert by["python"]["status"] == "ok"


def test_crashing_probe_counts_as_missing():
    def boom():
        raise OSError("no")

    checks, _ = run_checks(RUNTIME, dict(GOOD, ansible_core=boom))
    assert next(c for c in checks if c.component == "ansible_core").found is None


@pytest.fixture
def project_file(tmp_path: Path) -> Path:
    root = tmp_path / "proj"
    shutil.copytree(REFERENCE.parent, root)
    text = (root / "codeorca.yaml").read_text(encoding="utf-8")
    text = text.replace('python: ">=3.13,<3.14"', 'python: ">=3.13,<3.15"')
    text = text.replace("collections: {}", 'collections: { "amazon.aws": "10.1.0" }')
    text = text.replace('boto3: ">=1.35"', 'boto3: "1.42.*"')
    (root / "codeorca.yaml").write_text(text, encoding="utf-8")
    runtime = load_project(root / "codeorca.yaml").runtime
    assert runtime.collections == {"amazon.aws": "10.1.0"} and runtime.python_packages == {"boto3": "1.42.*"}
    return root / "codeorca.yaml"


def test_cli_table_lock_and_json(monkeypatch, capsys, project_file):
    monkeypatch.setattr(doctor, "default_probes", lambda runtime: GOOD)
    assert cli.main(["doctor", "-p", str(project_file), "--lock"]) == 0
    out = capsys.readouterr().out
    assert re.search(r"^terraform\s+1\.14\.7\s+1\.14\.7\s+ok$", out, re.MULTILINE) and "doctor: ok" in out
    assert "runtime:\n" in out and "  terraform: 1.14.7\n" in out and "  amazon.aws: 10.1.0" in out

    monkeypatch.setattr(doctor, "default_probes", lambda runtime: dict(GOOD, pwsh=lambda: None))
    assert cli.main(["doctor", "-p", str(project_file), "--json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["ok"] is False
    assert {c["component"]: c["status"] for c in data["checks"]}["pwsh"] == "missing"
    assert data["observed"]["pwsh"] is None
