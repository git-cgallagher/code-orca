"""bin/codeorca, the local launch wrapper, run against a fake ``docker`` that records its argv (no Docker needed).

The wrapper's contract (its header comment): credentials and other secrets reach the container by NAME only, never
as a value on the argv; ``-it`` only when stdin and stdout are terminals; the Docker socket only on request; the
exit code is codeorca's; the post-run chown touches the project's state and specs dirs and nothing else.
"""

from __future__ import annotations

import json
import os
import pty
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="bash wrapper; not run on Windows")

WRAPPER = Path(__file__).resolve().parents[2] / "bin" / "codeorca"

SECRETS = {
    "AWS_ACCESS_KEY_ID": "FIXTURE-SECRET-wrapper-akid",
    "AWS_SECRET_ACCESS_KEY": "FIXTURE-SECRET-wrapper-001",
    "AWS_SESSION_TOKEN": "FIXTURE-SECRET-wrapper-token",
    "CODEORCA_REDACTION_KEY": "example-not-secret-wrapper",
    "TF_VAR_db_password": "FIXTURE-SECRET-wrapper-002",
}

# Records each call as one JSON line: argv, plus its kind ("info", "chown" or "run"). `docker info` answers from
# FAKE_DOCKER_DAEMON (down -> exit 1) and FAKE_DOCKER_ROOTLESS; the codeorca run exits FAKE_DOCKER_RC, the chown
# FAKE_CHOWN_RC, so exit-code propagation is tested on the run that matters.
FAKE_DOCKER = f"""#!{sys.executable}
import json, os, sys
argv = sys.argv[1:]
if argv[:1] == ["info"]:
    kind = "info"
elif "--entrypoint" in argv and argv[argv.index("--entrypoint") + 1] == "find":
    kind = "chown"
else:
    kind = "run"
with open(os.environ["FAKE_DOCKER_LOG"], "a") as f:
    f.write(json.dumps({{"argv": argv, "kind": kind, "chown": kind == "chown"}}) + "\\n")
if kind == "info":
    if os.environ.get("FAKE_DOCKER_DAEMON") == "down":
        print("failed to connect to the docker API", file=sys.stderr)
        sys.exit(1)
    opts = ["name=seccomp,profile=builtin"] + (["name=rootless"] if os.environ.get("FAKE_DOCKER_ROOTLESS") else [])
    print(json.dumps(opts))
    sys.exit(0)
sys.exit(int(os.environ.get("FAKE_CHOWN_RC" if kind == "chown" else "FAKE_DOCKER_RC", "0")))
"""

# The caller's uid:gid is the test's, not the process's: the suite also runs as root (inside the image), where the
# wrapper deliberately skips the chown.
FAKE_UID, FAKE_GID = "1001", "1002"
FAKE_ID = f"""#!/bin/sh
case $1 in
  -u) echo "${{FAKE_UID:-{FAKE_UID}}}" ;;
  -g) echo "${{FAKE_GID:-{FAKE_GID}}}" ;;
  *) exit 1 ;;
esac
"""


@pytest.fixture
def sandbox(tmp_path):
    fakebin = tmp_path / "fakebin"
    fakebin.mkdir()
    for name, text in (("docker", FAKE_DOCKER), ("id", FAKE_ID)):
        (fakebin / name).write_text(text)
        (fakebin / name).chmod(0o755)
    home = tmp_path / "home"
    home.mkdir()
    project = tmp_path / "project"
    project.mkdir()
    log = tmp_path / "docker.log"
    # A clean environment: whatever the developer's shell exports (real AWS_* included) never reaches the test.
    env = {"PATH": f"{fakebin}:/usr/bin:/bin", "HOME": str(home), "FAKE_DOCKER_LOG": str(log)}
    return {"env": env, "project": project, "home": home, "log": log, "fakebin": fakebin}


def run(sandbox, *args, extra_env=None, **kwargs):
    env = dict(sandbox["env"], **(extra_env or {}))
    kwargs.setdefault("stdin", subprocess.DEVNULL)
    kwargs.setdefault("stdout", subprocess.PIPE)
    kwargs.setdefault("stderr", subprocess.PIPE)
    proc = subprocess.run([str(WRAPPER), *args], cwd=sandbox["project"], env=env, timeout=60, **kwargs)
    calls = []
    if sandbox["log"].exists():
        calls = [json.loads(line) for line in sandbox["log"].read_text().splitlines()]
    return proc, calls


def the_run(calls):
    runs = [c["argv"] for c in calls if c["kind"] == "run"]
    assert len(runs) == 1, calls
    return runs[0]


def passed_names(argv):
    """Every value given to -e."""
    return [argv[i + 1] for i, a in enumerate(argv) if a == "-e"]


def test_secrets_are_passed_by_name_never_by_value(sandbox):
    proc, calls = run(sandbox, "validate", extra_env=SECRETS)
    assert proc.returncode == 0, proc.stderr
    for call in calls:
        flat = "\0".join(call["argv"])
        for value in SECRETS.values():
            assert value not in flat
        assert "--env-file" not in call["argv"]
    names = passed_names(the_run(calls))
    for name in SECRETS:
        assert name in names
    # names only: no `NAME=value` form for any of them
    assert not [n for n in names if "=" in n and n.split("=", 1)[0] in SECRETS]


def test_unset_aws_names_are_not_passed_and_empty_ones_are(sandbox):
    proc, calls = run(sandbox, "validate", extra_env={"AWS_REGION": "", "AWS_PROFILE": "example-terraform"})
    assert proc.returncode == 0
    names = passed_names(the_run(calls))
    assert "AWS_REGION" in names  # set (even empty) -> passed by name
    assert "AWS_PROFILE" in names
    assert "AWS_SECRET_ACCESS_KEY" not in names
    assert "AWS_SESSION_TOKEN" not in names


def test_wrapper_settings_are_not_passed_and_multiline_values_inject_nothing(sandbox):
    extra = {
        "CODEORCA_IMAGE": "example.invalid/code-orca-runtime:test",
        "CODEORCA_DOCKER_SOCKET": "0",
        "CODEORCA_FOO": "bar",
        "UNRELATED": "x\nCODEORCA_INJECTED=1\nTF_VAR_injected=1",
    }
    proc, calls = run(sandbox, "validate", extra_env=extra)
    assert proc.returncode == 0
    argv = the_run(calls)
    names = passed_names(argv)
    assert "CODEORCA_FOO" in names
    for absent in ("CODEORCA_IMAGE", "CODEORCA_DOCKER_SOCKET", "CODEORCA_INJECTED", "TF_VAR_injected", "UNRELATED"):
        assert absent not in names
    # the image comes from CODEORCA_IMAGE and the container command is codeorca + the arguments
    i = argv.index("example.invalid/code-orca-runtime:test")
    assert argv[i + 1 :] == ["codeorca", "validate"]


def test_default_image_and_mounts(sandbox):
    proc, calls = run(sandbox, "doctor")
    assert proc.returncode == 0
    argv = the_run(calls)
    assert "ghcr.io/git-cgallagher/code-orca-runtime:latest" in argv
    assert f"{sandbox['project']}:/work" in argv
    assert argv[argv.index("-w") + 1] == "/work"
    cache = sandbox["home"] / ".terraform.d" / "plugin-cache"
    assert cache.is_dir()  # created if absent
    assert f"{cache}:/root/.terraform.d/plugin-cache" in argv
    assert "TF_PLUGIN_CACHE_DIR=/root/.terraform.d/plugin-cache" in passed_names(argv)
    assert "SSH_AUTH_SOCK=/ssh-agent" in passed_names(argv) or sys.platform != "darwin"


def test_known_hosts_mounted_read_only_when_present(sandbox):
    _, calls = run(sandbox, "validate")
    assert not any(a.endswith(":/root/.ssh/known_hosts:ro") for a in the_run(calls))
    ssh = sandbox["home"] / ".ssh"
    ssh.mkdir()
    (ssh / "known_hosts").write_text("example.com ssh-ed25519 AAAAexample-not-secret\n")
    sandbox["log"].unlink()
    _, calls = run(sandbox, "validate")
    assert f"{ssh / 'known_hosts'}:/root/.ssh/known_hosts:ro" in the_run(calls)


def test_no_tty_flag_without_a_terminal(sandbox):
    _, calls = run(sandbox, "resume", "latest", "--approve")
    argv = the_run(calls)
    assert "-it" not in argv and "-t" not in argv and "-i" not in argv


def test_tty_flag_when_stdin_and_stdout_are_terminals(sandbox):
    leader, follower = pty.openpty()
    try:
        _, calls = run(sandbox, "resume", "latest", "--approve", stdin=follower, stdout=follower)
    finally:
        os.close(follower)
        os.close(leader)
    assert "-it" in the_run(calls)


def test_tty_flag_needs_both_ends(sandbox):
    leader, follower = pty.openpty()
    try:
        _, calls = run(sandbox, "validate", stdin=follower)  # stdout is a pipe
    finally:
        os.close(follower)
        os.close(leader)
    assert "-it" not in the_run(calls)


def test_docker_socket_only_on_request(sandbox):
    sock = "/var/run/docker.sock:/var/run/docker.sock"
    for value in (None, "0", "yes", "true"):
        if sandbox["log"].exists():
            sandbox["log"].unlink()
        extra = {} if value is None else {"CODEORCA_DOCKER_SOCKET": value}
        _, calls = run(sandbox, "validate", extra_env=extra)
        assert sock not in the_run(calls), value
    sandbox["log"].unlink()
    _, calls = run(sandbox, "validate", extra_env={"CODEORCA_DOCKER_SOCKET": "1"})
    assert sock in the_run(calls)


@pytest.mark.parametrize("rc", [0, 1, 2, 3, 125])
def test_exit_code_is_codeorcas(sandbox, rc):
    proc, _ = run(sandbox, "run", "plan-only", extra_env={"FAKE_DOCKER_RC": str(rc)})
    assert proc.returncode == rc


def test_failed_chown_does_not_mask_the_exit_code(sandbox):
    (sandbox["project"] / "codeorca.yaml").write_text("api: codeorca/v1\n")
    (sandbox["project"] / ".codeorca").mkdir()
    for rc in (0, 3):
        proc, calls = run(sandbox, "run", "x", extra_env={"FAKE_DOCKER_RC": str(rc), "FAKE_CHOWN_RC": "1"})
        assert proc.returncode == rc
        assert any(c["chown"] for c in calls)
        assert b"could not chown" in proc.stderr
        sandbox["log"].unlink()


def chown_targets(calls):
    chowns = [c["argv"] for c in calls if c["chown"]]
    if not chowns:
        return None
    assert len(chowns) == 1
    argv = chowns[0]
    assert argv[: argv.index("--entrypoint")] == ["run", "--rm", "-v", argv[3], "-w", "/work"]
    # find -P <targets> -uid 0 -exec chown -h <uid>:<gid> -- {} +: only root-owned files change, never through a link
    tail = argv[argv.index("--entrypoint") + 3 :]
    assert tail[0] == "-P"
    i = tail.index("-uid")
    assert tail[i:] == ["-uid", "0", "-exec", "chown", "-h", f"{FAKE_UID}:{FAKE_GID}", "--", "{}", "+"]
    targets = tail[1:i]
    assert all(t.startswith("./") for t in targets)  # never parsed as a find expression
    return [t[2:] for t in targets]


def test_chown_targets_only_state_and_specs_dirs(sandbox):
    proj = sandbox["project"]
    (proj / "codeorca.yaml").write_text("api: codeorca/v1\nspecs_dir: out/specs   # comment\n")
    for d in (".codeorca/runs", "out/specs", "terraform/app/.terraform", "other"):
        (proj / d).mkdir(parents=True)
    _, calls = run(sandbox, "run", "plan-only")
    assert chown_targets(calls) == [".codeorca", "out/specs"]


@pytest.mark.parametrize(
    "flag",
    [
        ["-p", "sub/codeorca.yaml"],
        ["--project", "sub/codeorca.yaml"],
        ["-psub/codeorca.yaml"],
        ["--project=sub/codeorca.yaml"],
    ],
)
def test_chown_follows_the_project_file(sandbox, flag):
    sub = sandbox["project"] / "sub"
    sub.mkdir()
    (sub / "codeorca.yaml").write_text('api: codeorca/v1\nstate_dir: "state/runs"\n')
    for d in ("state/runs", "specs"):
        (sub / d).mkdir(parents=True)
    (sandbox["project"] / ".codeorca").mkdir()  # not this project's: left alone
    _, calls = run(sandbox, "run", "plan-only", *flag)
    assert chown_targets(calls) == ["sub/state", "sub/specs"]


@pytest.mark.parametrize(
    "form",
    [
        lambda p: ["-p", p],
        lambda p: ["--project", p],
        lambda p: [f"-p{p}"],
        lambda p: [f"--project={p}"],
    ],
)
def test_an_absolute_project_path_under_pwd_is_rewritten_for_the_container(sandbox, form):
    proj = sandbox["project"]
    (proj / "sub").mkdir()
    (proj / "sub" / "codeorca.yaml").write_text("api: codeorca/v1\n")
    (proj / "sub" / "specs").mkdir()
    proc, calls = run(sandbox, "run", "x", *form(str(proj / "sub" / "codeorca.yaml")))
    assert proc.returncode == 0, proc.stderr
    argv = the_run(calls)
    tail = argv[argv.index("codeorca") :]
    assert tail == ["codeorca", "run", "x", *form("sub/codeorca.yaml")]  # the path the container sees
    assert str(proj) not in " ".join(tail)
    assert chown_targets(calls) == ["sub/specs"]


@pytest.mark.parametrize("path", ["/etc/codeorca.yaml", "../outside/codeorca.yaml", "sub/../../codeorca.yaml"])
def test_a_project_file_outside_pwd_is_refused(sandbox, path):
    proc, calls = run(sandbox, "run", "x", "-p", path)
    assert proc.returncode == 64
    assert b"only" in proc.stderr and b"mounted" in proc.stderr
    assert calls == []  # not even docker info


@pytest.mark.parametrize(
    ("line", "command"),
    [
        ("state_dir: /var/tmp/codeorca/runs", "run"),
        ("state_dir: ../escape/runs", "resume"),
        ("specs_dir: /tmp/specs", "drift"),
        ("specs_dir: ../../specs", "summary"),
    ],
)
def test_a_state_or_specs_dir_outside_pwd_is_refused(sandbox, line, command):
    (sandbox["project"] / "codeorca.yaml").write_text(f"api: codeorca/v1\n{line}\n")
    proc, calls = run(sandbox, command, "latest")
    assert proc.returncode == 64, proc.stderr
    assert line.split(":")[0].encode() in proc.stderr
    assert calls == []


def test_paths_outside_pwd_do_not_block_commands_that_never_touch_them(sandbox):
    (sandbox["project"] / "codeorca.yaml").write_text("api: codeorca/v1\nstate_dir: /var/tmp/runs\n")
    for command in (["doctor"], ["validate", "workflows/x.yaml"]):
        proc, calls = run(sandbox, *command)
        assert proc.returncode == 0, proc.stderr
        assert chown_targets(calls) is None  # an absolute state_dir is never chowned
        sandbox["log"].unlink()


def test_a_state_dir_leaving_the_project_root_but_not_pwd_runs_and_is_not_chowned(sandbox):
    proj = sandbox["project"]
    (proj / "sub").mkdir()
    (proj / "sub" / "codeorca.yaml").write_text("api: codeorca/v1\nstate_dir: ../shared/runs\n")
    (proj / "shared" / "runs").mkdir(parents=True)
    (proj / "sub" / "specs").mkdir()
    proc, calls = run(sandbox, "run", "x", "-p", "sub/codeorca.yaml")
    assert proc.returncode == 0, proc.stderr
    assert chown_targets(calls) == ["sub/specs"]


def test_chown_refuses_symlinks_and_absolute_paths(sandbox, tmp_path):
    proj = sandbox["project"]
    outside = tmp_path / "outside"
    outside.mkdir()
    (proj / "codeorca.yaml").write_text("api: codeorca/v1\nspecs_dir: specs\n")
    (proj / "specs").symlink_to(outside)
    _, calls = run(sandbox, "run", "x")
    assert chown_targets(calls) is None  # nothing eligible: no chown container at all

    sandbox["log"].unlink()
    (proj / "codeorca.yaml").write_text("api: codeorca/v1\nspecs_dir: /etc\n")
    (proj / ".codeorca").mkdir()
    _, calls = run(sandbox, "doctor")
    assert chown_targets(calls) == [".codeorca"]


@pytest.mark.parametrize(
    ("yaml", "dirs", "want"),
    [
        ("state_dir: ./.codeorca/runs", [".codeorca/runs", "specs"], [".codeorca", "specs"]),
        ("state_dir: ././.codeorca//runs/.", [".codeorca/runs", "specs"], [".codeorca", "specs"]),
        ("specs_dir: .", [".codeorca/runs"], [".codeorca"]),
        ("specs_dir: ./", [".codeorca/runs"], [".codeorca"]),
        ("state_dir: .\nspecs_dir: specs/..", [".codeorca"], None),
    ],
)
def test_chown_never_targets_the_project_root(sandbox, yaml, dirs, want):
    proj = sandbox["project"]
    (proj / "codeorca.yaml").write_text(f"api: codeorca/v1\n{yaml}\n")
    for d in dirs:
        (proj / d).mkdir(parents=True)
    _, calls = run(sandbox, "run", "plan-only")
    assert chown_targets(calls) == want


def test_no_chown_without_a_project_file(sandbox):
    (sandbox["project"] / ".codeorca").mkdir()
    _, calls = run(sandbox, "validate")
    assert chown_targets(calls) is None


def test_no_chown_for_a_root_caller_or_under_rootless_docker(sandbox):
    (sandbox["project"] / "codeorca.yaml").write_text("api: codeorca/v1\n")
    (sandbox["project"] / ".codeorca").mkdir()
    _, calls = run(sandbox, "run", "x")
    assert chown_targets(calls) == [".codeorca"]
    for extra in ({"FAKE_UID": "0", "FAKE_GID": "0"}, {"FAKE_DOCKER_ROOTLESS": "1"}):
        sandbox["log"].unlink()
        proc, calls = run(sandbox, "run", "x", extra_env=dict(extra, FAKE_DOCKER_RC="3"))
        assert proc.returncode == 3
        assert chown_targets(calls) is None, extra


def test_docker_missing(sandbox, tmp_path):
    # A PATH holding only what the wrapper needs, so a docker in /usr/bin (Linux runners) is not found either.
    tools = tmp_path / "tools"
    tools.mkdir()
    for tool in ("bash", "env", "uname", "sed", "head", "dirname", "mkdir"):
        found = shutil.which(tool, path="/usr/bin:/bin")
        assert found, tool
        (tools / tool).symlink_to(found)
    (tools / "id").symlink_to(sandbox["fakebin"] / "id")
    proc, calls = run(sandbox, "run", "x", extra_env={"PATH": str(tools)})
    assert proc.returncode == 69
    assert b"docker is not on PATH" in proc.stderr
    assert b"could not chown" not in proc.stderr
    assert calls == []


def test_docker_daemon_unreachable(sandbox):
    (sandbox["project"] / "codeorca.yaml").write_text("api: codeorca/v1\n")
    (sandbox["project"] / ".codeorca").mkdir()
    proc, calls = run(sandbox, "run", "x", extra_env={"FAKE_DOCKER_DAEMON": "down"})
    assert proc.returncode == 69  # never 1, which is codeorca's "workflow failed"
    assert b"cannot reach the Docker daemon" in proc.stderr
    assert [c["kind"] for c in calls] == ["info"]


@pytest.mark.parametrize("rc", [125, 126, 127])
def test_no_chown_when_the_container_never_started(sandbox, rc):
    (sandbox["project"] / "codeorca.yaml").write_text("api: codeorca/v1\n")
    (sandbox["project"] / ".codeorca").mkdir()
    proc, calls = run(sandbox, "run", "x", extra_env={"FAKE_DOCKER_RC": str(rc)})
    assert proc.returncode == rc
    assert chown_targets(calls) is None
    assert b"did not start" in proc.stderr


def test_home_unset(sandbox):
    env = {k: v for k, v in sandbox["env"].items() if k != "HOME"}
    proc = subprocess.run(
        [str(WRAPPER), "validate", "x.yaml"],
        cwd=sandbox["project"],
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    calls = [json.loads(line) for line in sandbox["log"].read_text().splitlines()]
    argv = the_run(calls)
    assert not any("known_hosts" in a or "plugin-cache" in a for a in argv)
