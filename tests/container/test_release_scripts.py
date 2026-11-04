"""The release scripts .github/workflows/image.yml runs on a tag: .github/ci/release-check.sh and refuse-overwrite.sh.

release-check runs against throwaway git repos; refuse-overwrite against a fake ``docker`` (no registry is called).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="bash scripts; not run on Windows")

CI = Path(__file__).resolve().parents[2] / ".github" / "ci"
CHECK = CI / "release-check.sh"
REFUSE = CI / "refuse-overwrite.sh"


def git(repo, *args):
    env = dict(
        os.environ,
        GIT_AUTHOR_NAME="t",
        GIT_AUTHOR_EMAIL="t@example.com",
        GIT_COMMITTER_NAME="t",
        GIT_COMMITTER_EMAIL="t@example.com",
        GIT_CONFIG_GLOBAL="/dev/null",
        GIT_CONFIG_SYSTEM="/dev/null",
    )
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True, env=env)


def commit(repo, version, tag=None):
    (repo / "pyproject.toml").write_text(f'[project]\nname = "x"\nversion = "{version}"\n')
    git(repo, "add", "pyproject.toml")
    git(repo, "commit", "-q", "-m", version)
    if tag:
        git(repo, "tag", tag)
    return git(repo, "rev-parse", "HEAD").stdout.strip()


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    git(r, "init", "-q", "-b", "main")
    return r


def check(repo, ref, sha=None):
    out = repo.parent / "out"
    out.unlink(missing_ok=True)
    env = {"PATH": os.environ["PATH"], "RELEASE_MAIN_REF": "main", "GITHUB_OUTPUT": str(out)}
    if sha:
        env["GITHUB_SHA"] = sha
    proc = subprocess.run([str(CHECK), ref], cwd=repo, env=env, capture_output=True, text=True, timeout=60)
    outputs = dict(line.split("=", 1) for line in out.read_text().splitlines()) if out.exists() else {}
    return proc, outputs


def test_a_release_on_main(repo):
    commit(repo, "0.1.0", "v0.1.0")
    proc, out = check(repo, "v0.1.0")
    assert proc.returncode == 0, proc.stderr
    assert out == {"version": "0.1.0", "latest": "true", "minor": "true"}


@pytest.mark.parametrize("ref", ["v1.0.0rc1", "v1.0.0-rc.1", "v1.0", "v01.0.0", "v1.0.0+build", "1.0.0"])
def test_only_strict_release_tags(repo, ref):
    commit(repo, ref.lstrip("v"))
    proc, out = check(repo, ref)
    assert proc.returncode == 1
    assert "not a release tag" in proc.stderr
    assert out == {}


def test_tag_must_equal_pyproject(repo):
    commit(repo, "0.1.0")
    proc, _ = check(repo, "v0.1.1")
    assert proc.returncode == 1 and "does not match pyproject.toml version 0.1.0" in proc.stderr


def test_the_commit_must_be_on_main(repo):
    commit(repo, "0.0.1")
    git(repo, "checkout", "-q", "-b", "feature")
    sha = commit(repo, "0.1.0", "v0.1.0")
    proc, out = check(repo, "v0.1.0", sha=sha)
    assert proc.returncode == 1 and "is not on main" in proc.stderr
    assert out == {}


def test_a_backport_never_moves_latest(repo):
    commit(repo, "0.1.4", "v0.1.4")
    commit(repo, "0.2.0", "v0.2.0")
    sha = commit(repo, "0.1.5", "v0.1.5")  # on main after 0.2.0
    proc, out = check(repo, "v0.1.5", sha=sha)
    assert proc.returncode == 0, proc.stderr
    assert out == {"version": "0.1.5", "latest": "false", "minor": "true"}


def test_racing_tags_only_the_highest_moves_latest_and_minor(repo):
    old = commit(repo, "0.2.0", "v0.2.0")
    commit(repo, "0.2.1", "v0.2.1")
    git(repo, "checkout", "-q", "v0.2.0")  # the v0.2.0 run's checkout
    proc, out = check(repo, "v0.2.0", sha=old)
    assert proc.returncode == 0, proc.stderr
    assert out == {"version": "0.2.0", "latest": "false", "minor": "false"}
    git(repo, "checkout", "-q", "main")
    proc, out = check(repo, "v0.2.1")
    assert out == {"version": "0.2.1", "latest": "true", "minor": "true"}


def test_tags_off_main_or_not_strict_are_not_releases(repo):
    commit(repo, "0.1.0", "v0.1.0")
    git(repo, "tag", "v9.0.0rc1")
    git(repo, "checkout", "-q", "-b", "stray")
    commit(repo, "9.9.9", "v9.9.9")
    git(repo, "checkout", "-q", "main")
    proc, out = check(repo, "v0.1.0")
    assert proc.returncode == 0, proc.stderr
    assert out["latest"] == "true"


# ------------------------------------------------------------------------------------------------ refuse-overwrite
FAKE_DOCKER = f"""#!{sys.executable}
import os, sys
assert sys.argv[1:4] == ["buildx", "imagetools", "inspect"], sys.argv
mode = os.environ["FAKE_INSPECT"]
if mode == "exists":
    print(open(os.environ["FAKE_INDEX"]).read())
    sys.exit(0)
if mode == "notfound":
    print("ERROR: " + sys.argv[-1] + ": not found", file=sys.stderr)
else:
    print("ERROR: failed to do request: 503 Service Unavailable", file=sys.stderr)
sys.exit(1)
"""

A, B, C = ("a" * 64, "b" * 64, "c" * 64)


@pytest.fixture
def registry(tmp_path):
    fakebin = tmp_path / "fakebin"
    fakebin.mkdir()
    (fakebin / "docker").write_text(FAKE_DOCKER)
    (fakebin / "docker").chmod(0o755)
    digests = tmp_path / "digests"
    digests.mkdir()
    for d in (A, B):
        (digests / d).touch()
    index = tmp_path / "index.json"

    def refuse(mode, existing=()):
        index.write_text(json.dumps({"manifests": [{"digest": f"sha256:{d}"} for d in existing]}))
        out = tmp_path / "out"
        out.unlink(missing_ok=True)
        env = {
            "PATH": f"{fakebin}:{os.environ['PATH']}",
            "FAKE_INSPECT": mode,
            "FAKE_INDEX": str(index),
            "GITHUB_OUTPUT": str(out),
        }
        proc = subprocess.run(
            [str(REFUSE), "ghcr.io/example/runtime", "1.2.3", str(digests)],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        return proc, out.read_text() if out.exists() else ""

    return refuse


def test_absent_release_proceeds(registry):
    proc, out = registry("notfound")
    assert proc.returncode == 0, proc.stderr
    assert out == "rerun=false\n"


def test_a_registry_error_is_never_absent(registry):
    proc, out = registry("error")
    assert proc.returncode == 1
    assert "could not check" in proc.stderr and "503" in proc.stderr
    assert out == ""


@pytest.mark.parametrize("existing", [(A, C), (A,), (A, B, C), ()])
def test_an_existing_release_with_other_content_is_refused(registry, existing):
    proc, out = registry("exists", existing)
    assert proc.returncode == 1
    assert "already exists" in proc.stderr
    assert out == ""


def test_a_rerun_of_the_same_digests_may_attest_it(registry):
    proc, out = registry("exists", (B, A))
    assert proc.returncode == 0, proc.stderr
    assert out == "rerun=true\n"
