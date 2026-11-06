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


def test_clean_checkout_check_sees_ignored_files():
    assert "git status --porcelain --ignored" in step("image", "The smoke test left the checkout clean")["run"]


def test_jobs_split_by_ref():
    # A tag never builds: the build and :main/:sha jobs skip tag refs, and only a tag PUSH releases (a manual run on
    # a tag would otherwise publish whatever that ref's workflow file says).
    assert WORKFLOW["jobs"]["image"]["if"] == "${{ !startsWith(github.ref, 'refs/tags/') }}"
    jobs = WORKFLOW["jobs"]
    assert jobs["manifest"]["if"] == "github.event_name != 'pull_request' && github.ref == 'refs/heads/main'"
    assert WORKFLOW["jobs"]["release"]["if"] == "github.event_name == 'push' && startsWith(github.ref, 'refs/tags/')"
    assert "refs/tags" not in WORKFLOW["env"]["PUBLISH"]


def test_every_main_push_builds_and_every_v_tag_runs():
    push = WORKFLOW["on"]["push"]
    assert "paths" not in push  # a release promotes the commit's :sha-<short>, so every main commit needs one
    assert push["tags"] == ["v*"]  # a malformed v* tag fails release-check loudly


def test_the_release_promotes_main_s_image_and_never_builds():
    release = steps("release")
    assert not [s for s in release if "build-push-action" in s.get("uses", "")]
    names = [s.get("name") for s in release]
    order = [
        "A release tag is strict, equals pyproject.toml's version and is on main",
        "Main's ci and image runs passed for this commit",
        "The image main tested",
        "Published releases, and whether this one moves :latest and :X.Y",
        "Refuse to overwrite an existing release",
        "Create the release index",
    ]
    assert [n for n in names if n in order] == order
    assert release[0]["with"]["fetch-depth"] == 0
    assert ".github/ci/release-source.sh" in step("release", "The image main tested")["run"]
    assert WORKFLOW["jobs"]["release"]["permissions"]["actions"] == "read"


def test_latest_and_minor_follow_the_release_check():
    create = step("release", "Create the release index")
    assert create["env"]["LATEST"] == "${{ steps.release.outputs.latest }}"
    assert create["env"]["MINOR"] == "${{ steps.release.outputs.minor }}"
    assert 'args=(-t "$IMAGE:$VERSION")' in create["run"]  # the version tag is always among the tags written
    published = step("release", "Published releases, and whether this one moves :latest and :X.Y")
    assert "published-versions.sh" in published["run"]
