"""container/requirements/lock.sh resolves the base image the Dockerfile pins (the literal ``AS pinned-base`` line).

Run against a fake ``docker`` that records its argv, so no Docker or network is needed.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="bash script; not run on Windows")

ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / "container" / "requirements" / "lock.sh"
DOCKERFILE = ROOT / "container" / "Dockerfile"

FAKE_DOCKER = f"""#!{sys.executable}
import json, os, sys
with open(os.environ["FAKE_DOCKER_LOG"], "a") as f:
    f.write(json.dumps(sys.argv[1:]) + "\\n")
"""


def pinned_base() -> str:
    m = re.search(r"^FROM (\S+) AS pinned-base$", DOCKERFILE.read_text(), re.M)
    assert m, "no literal pinned-base stage in container/Dockerfile"
    return m[1]


@pytest.fixture
def env(tmp_path):
    fakebin = tmp_path / "fakebin"
    fakebin.mkdir()
    (fakebin / "docker").write_text(FAKE_DOCKER)
    (fakebin / "docker").chmod(0o755)
    log = tmp_path / "docker.log"
    return {"PATH": f"{fakebin}:/usr/bin:/bin", "FAKE_DOCKER_LOG": str(log)}, log


def test_the_pinned_base_is_a_digest_pinned_image():
    assert re.fullmatch(r"[a-z0-9.-]+/[^@\s]+@sha256:[0-9a-f]{64}", pinned_base())


def test_lock_runs_in_the_pinned_base_image(env):
    e, log = env
    proc = subprocess.run([str(LOCK)], env=e, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    (argv,) = [json.loads(line) for line in log.read_text().splitlines()]
    assert argv[0] == "run"
    assert pinned_base() in argv
    assert "pinned-base" not in argv  # the stage name is not an image


def test_print_base(env):
    e, log = env
    proc = subprocess.run([str(LOCK), "--print-base"], env=e, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == pinned_base()
    assert not log.exists()


def test_base_image_override_must_be_digest_pinned(env):
    e, log = env
    ref = "ghcr.io/example/runtime:9.9.9@sha256:" + "0" * 64
    proc = subprocess.run(
        [str(LOCK), "--print-base"], env=dict(e, BASE_IMAGE=ref), capture_output=True, text=True, timeout=60
    )
    assert proc.returncode == 0 and proc.stdout.strip() == ref
    for bad in ("pinned-base", "ghcr.io/example/runtime:9.9.9"):
        proc = subprocess.run([str(LOCK)], env=dict(e, BASE_IMAGE=bad), capture_output=True, text=True, timeout=60)
        assert proc.returncode == 1, bad
        assert "not a digest-pinned image reference" in proc.stderr
    assert not log.exists()
