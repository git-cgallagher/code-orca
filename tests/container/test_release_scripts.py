"""The release scripts .github/workflows/image.yml runs on a tag push: .github/ci/release-check.sh, refuse-overwrite.sh,
release-source.sh, counted-releases.sh and main-runs-green.sh.

release-check runs against throwaway git repos; the others against a fake ``docker`` or ``gh`` (nothing is called).
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


# --------------------------------------------------------------------------------- release-check, published only
def test_only_published_releases_move_latest(repo):
    commit(repo, "0.1.0", "v0.1.0")
    commit(repo, "0.9.0", "v0.9.0")  # a tag whose run failed: no :0.9.0 on the registry
    sha = commit(repo, "0.2.0", "v0.2.0")
    out = repo.parent / "out"
    env = {
        "PATH": os.environ["PATH"],
        "RELEASE_MAIN_REF": "main",
        "GITHUB_OUTPUT": str(out),
        "RELEASE_COMMIT": sha,
        "RELEASED_VERSIONS": "0.1.0",
    }
    proc = subprocess.run([str(CHECK), "v0.2.0"], cwd=repo, env=env, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert dict(line.split("=", 1) for line in out.read_text().splitlines())["latest"] == "true"
    # without the registry's answer the stray v0.9.0 would count, and 0.2.0 would not move :latest
    out.unlink()
    del env["RELEASED_VERSIONS"]
    subprocess.run([str(CHECK), "v0.2.0"], cwd=repo, env=env, check=True, capture_output=True, timeout=60)
    assert dict(line.split("=", 1) for line in out.read_text().splitlines())["latest"] == "false"


def test_release_commit_wins_over_github_sha(repo):
    commit(repo, "0.0.1")
    git(repo, "checkout", "-q", "-b", "feature")
    off_main = commit(repo, "0.1.0", "v0.1.0")
    git(repo, "checkout", "-q", "main")
    out = repo.parent / "out"
    env = {"PATH": os.environ["PATH"], "RELEASE_MAIN_REF": "main", "GITHUB_OUTPUT": str(out)}
    env |= {"GITHUB_SHA": git(repo, "rev-parse", "main").stdout.strip(), "RELEASE_COMMIT": off_main}
    proc = subprocess.run([str(CHECK), "v0.0.1"], cwd=repo, env=env, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 1 and "is not on main" in proc.stderr


# --------------------------------------------------------------- release-source, counted-releases, main-runs-green
SOURCE = CI / "release-source.sh"
COUNTED = CI / "counted-releases.sh"
GREEN = CI / "main-runs-green.sh"
COMMIT = "1234567" + "0" * 33
INDEX = "sha256:" + "9" * 64

# A fake ``docker buildx imagetools inspect``: ``<ref>`` with --format '{{json .Manifest.Digest}}', --raw or
# --format '{{json .Image}}'. A tag resolves through FAKE_IMAGES' "tags" to an index digest; "indexes" hold the content.
FAKE_DOCKER_INSPECT = f"""#!{sys.executable}
import json, os, sys
assert sys.argv[1:4] == ["buildx", "imagetools", "inspect"], sys.argv
args = [a for a in sys.argv[4:] if a != "--raw"]
fmt = args[args.index("--format") + 1] if "--format" in args else None
ref = [a for a in args if a != "--format" and a != fmt][0]
reg = json.load(open(os.environ["FAKE_IMAGES"]))
if os.environ.get("FAKE_ERROR"):
    print("ERROR: failed to do request: 503 Service Unavailable", file=sys.stderr); sys.exit(1)
digest = ref.split("@", 1)[1] if "@" in ref else reg["tags"].get(ref)
if digest not in reg["indexes"]:
    print("ERROR: " + ref + ": not found", file=sys.stderr); sys.exit(1)
img = reg["indexes"][digest]
if fmt == "{{{{json .Manifest.Digest}}}}":
    print(json.dumps(digest))
elif fmt == "{{{{json .Image}}}}":
    print(json.dumps({{p: {{"config": {{"Labels": {{"org.opencontainers.image.revision": img["revision"].get(p)}}}}}}
                       for p in img["platforms"]}}))
else:
    print(json.dumps({{"manifests": [{{"digest": d, "platform": dict(zip(("os", "architecture"), p.split("/")))}}
                                    for p, d in img["platforms"].items()]}}))
"""

# A fake ``gh api <url> --jq <expr>``: serves FAKE_RUNS as the runs API would (filtered by the query's event, branch
# and head_sha), then runs the script's own --jq expression through the real jq.
FAKE_GH = f"""#!{sys.executable}
import json, os, subprocess, sys
from urllib.parse import parse_qs, urlsplit
assert sys.argv[1] == "api" and sys.argv[3] == "--jq", sys.argv
url = urlsplit(sys.argv[2])
q = {{k: v[0] for k, v in parse_qs(url.query).items()}}
runs = json.load(open(os.environ["FAKE_RUNS"]))
if "/workflows/" in url.path:
    wf = url.path.split("/workflows/")[1].split("/")[0]
    runs = [r for r in runs if r["path"].endswith("/" + wf)]
for key, field in (("event", "event"), ("branch", "head_branch"), ("head_sha", "head_sha")):
    if key in q:
        runs = [r for r in runs if r[field] == q[key]]
proc = subprocess.run(["jq", "-r", sys.argv[4]], input=json.dumps({{"workflow_runs": runs}}), text=True)
sys.exit(proc.returncode)
"""


def index(platforms=("linux/amd64", "linux/arm64"), revision=COMMIT):
    return {
        "platforms": {p: f"sha256:{c * 64}" for p, c in zip(platforms, "abcdef", strict=False)},
        "revision": {p: revision for p in platforms},
    }


def run_(wf, *, status="completed", conclusion="success", id=1, branch="main", sha=COMMIT):
    return {
        "path": f".github/workflows/{wf}",
        "status": status,
        "conclusion": conclusion,
        "id": id,
        "event": "push",
        "head_branch": branch,
        "head_sha": sha,
    }


@pytest.fixture
def fakes(tmp_path):
    fakebin = tmp_path / "fakebin2"
    fakebin.mkdir()
    for name, body in (("docker", FAKE_DOCKER_INSPECT), ("gh", FAKE_GH)):
        (fakebin / name).write_text(body)
        (fakebin / name).chmod(0o755)
    images, runs_file = tmp_path / "images.json", tmp_path / "runs.json"

    def run(script, *args, tags=None, indexes=None, runs=(), error=False):
        images.write_text(json.dumps({"tags": tags or {}, "indexes": indexes or {}}))
        runs_file.write_text(json.dumps(list(runs)))
        env = {
            "PATH": f"{fakebin}:{os.environ['PATH']}",
            "FAKE_IMAGES": str(images),
            "FAKE_RUNS": str(runs_file),
            "GITHUB_REPOSITORY": "o/r",
        }
        if error:
            env["FAKE_ERROR"] = "1"
        return subprocess.run([str(script), *args], env=env, capture_output=True, text=True, timeout=60)

    return run


def test_jq_is_available():
    # the fake gh runs the scripts' own --jq expressions; CI fails on a skipped test, so jq must be there
    assert subprocess.run(["jq", "--version"], capture_output=True).returncode == 0


def test_release_source_writes_both_platform_digests(fakes, tmp_path):
    out = tmp_path / "digests"
    out.mkdir()
    proc = fakes(SOURCE, "img", COMMIT, str(out), tags={"img:sha-1234567": INDEX}, indexes={INDEX: index()})
    assert proc.returncode == 0, proc.stderr
    assert sorted(p.name for p in out.iterdir()) == [A, B]
    assert proc.stdout == f"amd64=img@sha256:{A}\n"  # the amd64 image, by digest, for the release-time scan


@pytest.mark.parametrize(
    ("indexes", "message"),
    [
        ({}, "is missing"),
        ({INDEX: index(revision="1234567" + "f" * 33)}, "revision label"),
        ({INDEX: index(platforms=("linux/amd64",))}, "not exactly"),
        ({INDEX: index(platforms=("linux/amd64", "linux/arm64", "linux/s390x"))}, "not exactly"),
    ],
)
def test_release_source_refuses_anything_but_main_s_image(fakes, tmp_path, indexes, message):
    out = tmp_path / "digests"
    out.mkdir()
    tags = {"img:sha-1234567": INDEX} if indexes else {}
    proc = fakes(SOURCE, "img", COMMIT, str(out), tags=tags, indexes=indexes)
    assert proc.returncode == 1 and message in proc.stderr
    assert not list(out.iterdir())


def test_counted_releases(fakes):
    other = "sha256:" + "8" * 64
    proc = fakes(
        COUNTED,
        "img",
        "0.1.0",
        "0.2.0",
        "0.3.0",
        "0.4.0",
        "0.5.0",
        tags={"img:0.1.0": INDEX, "img:0.3.0": other},
        indexes={INDEX: index(), other: index()},
        runs=[
            run_("image.yml", branch="v0.2.0", conclusion="failure", id=5),  # failed, no image: a stray tag
            run_("image.yml", branch="v0.4.0", status="in_progress", conclusion=None, id=6),  # racing: counts
            run_("image.yml", branch="v0.5.0", conclusion="failure", id=7),
            run_("image.yml", branch="v0.5.0", status="queued", conclusion=None, id=8),  # re-run pending: counts
            run_("ci.yml", branch="v0.2.0", id=9),  # another workflow's run never decides
        ],
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.split() == ["0.1.0", "0.3.0", "0.4.0", "0.5.0"]
    assert fakes(COUNTED, "img").stdout.strip() == ""


def test_counted_releases_never_treats_a_registry_error_as_absent(fakes):
    proc = fakes(COUNTED, "img", "0.1.0", error=True)
    assert proc.returncode == 1 and "registry error" in proc.stderr


def test_main_runs_green(fakes):
    tag_run = run_("image.yml", status="in_progress", conclusion=None, id=99, branch="v0.1.0")  # the tag's own run
    proc = fakes(GREEN, COMMIT, runs=[run_("ci.yml"), run_("image.yml", id=2), tag_run])
    assert proc.returncode == 0, proc.stderr


@pytest.mark.parametrize(
    ("runs", "message"),
    [
        ([run_("ci.yml")], "no push run of .github/workflows/image.yml"),
        ([run_("ci.yml"), run_("image.yml", sha="f" * 40)], "no push run of .github/workflows/image.yml"),
        ([run_("ci.yml"), run_("image.yml", status="in_progress", conclusion=None, id=42)], "is in_progress (run 42)"),
        ([run_("ci.yml", conclusion="failure"), run_("image.yml")], "concluded failure"),
        ([run_("ci.yml"), run_("image.yml", conclusion="cancelled", id=3)], "Do not re-run that old main run"),
        # the newest run (highest id) decides
        ([run_("ci.yml"), run_("image.yml", id=1), run_("image.yml", conclusion="failure", id=9)], "failure"),
    ],
)
def test_main_runs_not_green(fakes, runs, message):
    proc = fakes(GREEN, COMMIT, runs=runs)
    assert proc.returncode == 1 and message in proc.stderr
