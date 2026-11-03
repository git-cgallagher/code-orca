"""Static checks on container/Dockerfile and .github/workflows/image.yml for rules nothing else can test locally.

The image is built and published only in CI (amd64 is never built on this Mac), so these pin the review fixes:
the labels reach a released image without rebuilding layers, and a release can only come from a strict tag on main.
"""

from __future__ import annotations

import re
from pathlib import Path

from ruamel.yaml import YAML

ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = (ROOT / "container" / "Dockerfile").read_text()
WORKFLOW = YAML(typ="safe").load((ROOT / ".github" / "workflows" / "image.yml").read_text())


def runtime_stage() -> list[str]:
    stage = DOCKERFILE[DOCKERFILE.index("FROM base AS runtime") :]
    # instruction keywords at the start of a line (continuations are indented)
    return [m[1] + " " + m[2] for m in re.finditer(r"^([A-Z]+) (.*)$", stage, re.M)]


def steps(job: str) -> list[dict]:
    return WORKFLOW["jobs"][job]["steps"]


def step(job: str, name: str) -> dict:
    (s,) = [s for s in steps(job) if s.get("name") == name]
    return s


def test_label_args_are_declared_after_the_last_run():
    instr = runtime_stage()
    last_run = max(i for i, x in enumerate(instr) if x.startswith("RUN "))
    for arg in ("IMAGE_VERSION", "IMAGE_REVISION"):
        (i,) = [i for i, x in enumerate(instr) if x.startswith(f"ARG {arg}=")]
        assert i > last_run, f"ARG {arg} before a RUN rebuilds that layer for every new value"


def test_labels():
    assert 'org.opencontainers.image.version="${IMAGE_VERSION}"' in DOCKERFILE
    assert 'org.opencontainers.image.revision="${IMAGE_REVISION}"' in DOCKERFILE
    licenses = re.search(r'org\.opencontainers\.image\.licenses="([^"]+)"', DOCKERFILE)[1]
    assert set(licenses.split(" AND ")) >= {"MIT", "BUSL-1.1", "GPL-3.0-or-later"}  # ansible-core, ansible-lint


def test_both_build_steps_pass_the_same_label_build_args():
    build = step("image", "Build")["with"]
    push = step("image", "Push by digest")["with"]
    assert build["build-args"] == push["build-args"]  # identical inputs: the push is all cache hits
    names = {line.split("=", 1)[0] for line in build["build-args"].splitlines() if line}
    assert names == {"IMAGE_VERSION", "IMAGE_REVISION"}  # never a pin: the ARG defaults are the pins


def test_release_checks_run_in_both_jobs_on_a_full_checkout():
    for job in ("image", "manifest"):
        checkout = steps(job)[0]
        assert checkout["uses"].startswith("actions/checkout@")
        assert checkout["with"]["fetch-depth"] == 0
        (check,) = [s for s in steps(job) if ".github/ci/release-check.sh" in s.get("run", "")]
        assert check["if"] == "startsWith(github.ref, 'refs/tags/v')"


def test_latest_and_minor_tags_follow_the_release_check():
    tags = step("manifest", "Tags")["with"]["tags"]
    assert "enable=${{ steps.release.outputs.latest == 'true' }}" in [
        part for line in tags.splitlines() if "value=latest" in line for part in line.split(",")
    ]
    (minor,) = [line for line in tags.splitlines() if "{{major}}.{{minor}}" in line]
    assert "enable=${{ steps.release.outputs.minor == 'true' }}" in minor


def test_the_overwrite_guard_runs_before_the_tags_are_created():
    names = [s.get("name") for s in steps("manifest")]
    guard = step("manifest", "Refuse to overwrite an existing release")
    assert ".github/ci/refuse-overwrite.sh" in guard["run"]
    assert names.index("Refuse to overwrite an existing release") < names.index("Create the multi-arch manifest")
    create = step("manifest", "Create the multi-arch manifest")["run"]
    assert '"$IMAGE:$VERSION"' in create  # the version tag must be among the tags written
