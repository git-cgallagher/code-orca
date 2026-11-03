"""The ``python`` helper step: outputs to a dependent step, secret env resolved + registered + never on disk,
exit codes, ``-I`` isolation, dry run, script-path containment, timeouts."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from helper_support import SECRET, SECRET_REF, SHORT_REF, sha16

from codeorca.redact import PLACEHOLDER_RE, scan_outputs
from codeorca.runner import EXIT_FAILED, EXIT_OK


def py(id: str, script: str = "scripts/emit.py", **kw) -> dict:
    return {"id": id, "type": "python", "script": script, **kw}


def output(runner, step_id: str):
    return runner.run_dir.read_result(step_id)["output"]


def test_outputs_flow_to_a_dependent_step(run_workflow):
    steps = [
        py("a", args=["0"], env={"GREETING": "hello-from-a"}, outputs={"greeting": "${{ result.output.greeting }}"}),
        py("b", needs=["a"], args=["0", "${{ steps.a.outputs.greeting }}"]),
    ]
    rc, r = run_workflow(steps)
    assert rc == EXIT_OK, r.states
    assert r.states["a"]["outputs"] == {"greeting": "hello-from-a"}
    assert output(r, "b")["args"] == ["0", "hello-from-a"]
    result = r.run_dir.read_result("b")
    assert result["exit_code"] == 0 and Path(result["stdout_path"]).name == "stdout.log"


def test_argv_is_isolated_interpreter_on_the_resolved_script(run_workflow, project_root):
    rc, r = run_workflow([py("a", args=["0", "x y"])])
    assert rc == EXIT_OK
    argv = json.loads((r.run_dir.steps_dir / "a" / "argv.json").read_text())
    assert argv == [sys.executable, "-I", str((project_root / "scripts" / "emit.py").resolve()), "0", "x y"]
    out = output(r, "a")
    assert out["isolated"] is True
    assert Path(out["cwd"]).resolve() == project_root.resolve()  # the child runs in the project root


@pytest.mark.parametrize("hooks", [True, False], ids=["runner-hooks", "no-runner-hooks"])
def test_secret_env_is_registered_and_never_reaches_the_run_dir(run_workflow, registry, hooks):
    rc, r = run_workflow([py("a", args=["0"], env={"HELPER_SECRET": {"secret": SECRET_REF}})], hooks=hooks)
    assert rc == EXIT_OK, r.states
    assert registry.count_matches(SECRET) == 1  # registered
    out = output(r, "a")
    assert out["secret_sha"] == sha16(SECRET)  # the child got the real value
    assert PLACEHOLDER_RE.search(out["secret_echo"])  # the output file was rewritten through the registry
    step_dir = r.run_dir.steps_dir / "a"
    assert PLACEHOLDER_RE.search((step_dir / "stdout.log").read_text())
    assert PLACEHOLDER_RE.search((step_dir / "stderr.log").read_text())
    assert "HELPER_SECRET" in json.loads((step_dir / "env-names.json").read_text())
    assert scan_outputs(r.run_dir.path, registry) == []


def test_secret_in_a_failing_steps_error_is_redacted(run_workflow, registry):
    rc, r = run_workflow([py("a", args=["4"], env={"HELPER_SECRET": {"secret": SECRET_REF}})])
    assert rc == EXIT_FAILED
    assert r.states["a"]["status"] == "failed"
    assert SECRET not in r.states["a"]["error"] and "stderr sees <redacted:" in r.states["a"]["error"]
    assert scan_outputs(r.run_dir.path, registry) == []


def test_secret_reference_without_a_resolver_fails_the_step(run_workflow):
    rc, r = run_workflow([py("a", env={"HELPER_SECRET": {"secret": SECRET_REF}})], resolver=None)
    assert rc == EXIT_FAILED and r.states["a"]["status"] == "errored"
    assert "no secret resolver" in r.states["a"]["error"]
    assert not (r.run_dir.steps_dir / "a" / "argv.json").exists()  # nothing started


def test_resolver_failure_errors_the_step(run_workflow):
    def broken(ref: str) -> str:
        raise RuntimeError(f"AccessDenied for {ref}")

    rc, r = run_workflow([py("a", env={"HELPER_SECRET": {"secret": SECRET_REF}})], resolver=broken)
    assert r.states["a"]["status"] == "errored" and "cannot resolve" in r.states["a"]["error"]


def test_short_secret_is_reported_unprotected_by_name(run_workflow):
    rc, r = run_workflow([py("a", args=["0"], env={"SHORT_SECRET": {"secret": SHORT_REF}})])
    assert rc == EXIT_OK
    result = r.run_dir.read_result("a")
    assert result["unprotected_env"] == ["SHORT_SECRET"]
    assert "cannot be redacted" in result["warnings"][0]


def test_denylist_named_literal_env_is_registered(run_workflow, registry):
    literal = "FIXTURE-SECRET-literal-token-02"
    rc, r = run_workflow([py("a", args=["0"], env={"API_TOKEN": literal})])
    assert rc == EXIT_OK
    assert registry.count_matches(literal) == 1


def test_reserved_env_names_are_refused(run_workflow):
    rc, r = run_workflow([py("a", env={"CODEORCA_OUTPUT_FILE": "/tmp/elsewhere"})])
    assert r.states["a"]["status"] == "errored" and "reserved" in r.states["a"]["error"]


@pytest.mark.parametrize("code", [1, 3, 42])
def test_exit_codes(run_workflow, code):
    rc, r = run_workflow([py("a", args=[str(code)])])
    assert rc == EXIT_FAILED and r.states["a"]["status"] == "failed"
    assert r.run_dir.read_result("a")["exit_code"] == code
    error = r.states["a"]["error"]
    assert error.startswith(f"scripts/emit.py exited {code}") and f"failing with {code}" in error
    assert output(r, "a")["args"] == [str(code)]  # the output file is read whatever the exit status


def test_isolated_mode_does_not_import_a_planted_module(run_workflow, project_root):
    rc, r = run_workflow([py("a", script="scripts/isolated/uses_json.py")])
    assert rc == EXIT_OK, r.states
    planted = (project_root / "scripts" / "isolated").resolve()
    assert not Path(output(r, "a")["json_module"]).resolve().is_relative_to(planted)


def test_dry_run_sets_the_flag(run_workflow):
    rc, r = run_workflow([py("a", args=["0"])], dry_run=True)
    assert rc == EXIT_OK and output(r, "a")["dry_run"] == "1"


def test_a_real_run_never_inherits_the_dry_run_flag(run_workflow):
    env = {"PATH": "/usr/bin:/bin", "CODEORCA_DRY_RUN": "1"}
    rc, r = run_workflow([py("a", args=["0"])], env=env)
    assert rc == EXIT_OK and output(r, "a")["dry_run"] is None


@pytest.mark.parametrize(
    ("script", "message"),
    [
        ("../outside.py", "outside the project root"),
        ("/etc/hosts", "outside the project root"),
        ("scripts/link.py", "outside the project root"),
        ("scripts/missing.py", "not found"),
        ("scripts", "not a file"),
    ],
)
def test_script_paths_are_contained(run_workflow, project_root, script, message):
    outside = project_root.parent / "outside.py"
    outside.write_text("print('escaped')\n")
    (project_root / "scripts" / "link.py").symlink_to(outside)
    rc, r = run_workflow([py("a", script=script)])
    assert rc == EXIT_FAILED and r.states["a"]["status"] == "errored"
    assert message in r.states["a"]["error"]
    assert not (r.run_dir.steps_dir / "a" / "argv.json").exists()


def test_without_a_project_scripts_resolve_against_the_cwd(run_workflow, project_root, monkeypatch):
    monkeypatch.chdir(project_root)
    rc, r = run_workflow([py("a", args=["0"])], project=False)
    assert rc == EXIT_OK and output(r, "a")["args"] == ["0"]


def test_timeout_errors_the_step(run_workflow):
    rc, r = run_workflow([py("a", script="scripts/sleep.py", timeout="500ms")])
    assert rc == EXIT_FAILED and r.states["a"]["status"] == "errored"
    assert r.states["a"]["error"].startswith("timeout:")


def test_retry_reruns_a_failed_helper(run_workflow):
    rc, r = run_workflow([py("a", args=["2"], retry={"limit": 2, "policy": "failure"})])
    assert rc == EXIT_FAILED and r.states["a"]["attempts"] == 3


def test_secret_never_reaches_the_child_argv_or_env_names_values(run_workflow, registry):
    rc, r = run_workflow([py("a", args=["0", SECRET], env={"HELPER_SECRET": {"secret": SECRET_REF}})])
    assert rc == EXIT_OK
    argv_text = (r.run_dir.steps_dir / "a" / "argv.json").read_text()
    assert SECRET not in argv_text and PLACEHOLDER_RE.search(argv_text)
    assert scan_outputs(r.run_dir.path, registry) == []


@pytest.mark.parametrize("encoding", ["latin-1", "utf-16"], ids=["latin1", "utf16-bom"])
def test_a_non_utf8_output_file_is_rewritten_scrubbed_not_left_in_clear(run_workflow, project_root, registry, encoding):
    """Review finding: a strict UTF-8 read raised before the scrubbed rewrite, leaving the child's raw file (and
    the secret it echoed) in the run dir."""
    (project_root / "scripts" / "enc.py").write_text(
        "import json, os\n"
        "doc = {'token': os.environ['HELPER_SECRET'], 'city': 'M\\u00fcnchen'}\n"
        f"data = json.dumps(doc, ensure_ascii=False).encode({encoding!r})\n"
        "open(os.environ['CODEORCA_OUTPUT_FILE'], 'wb').write(data)\n"
    )
    rc, r = run_workflow([py("a", script="scripts/enc.py", env={"HELPER_SECRET": {"secret": SECRET_REF}})])
    raw = (r.run_dir.steps_dir / "a" / "output.json").read_bytes()
    for form in ("utf-8", "utf-16-le", "utf-16-be"):
        assert SECRET.encode(form) not in raw
    assert rc == EXIT_OK, r.states
    assert PLACEHOLDER_RE.fullmatch(output(r, "a")["token"])
    assert scan_outputs(r.run_dir.path, registry) == []


def test_an_output_file_that_cannot_be_rewritten_is_removed(tmp_path, monkeypatch):
    from codeorca.steps import shell

    target = tmp_path / "output.json"
    target.write_text('{"token": "FIXTURE-SECRET-unwritable-0001"}', encoding="utf-8")

    def boom(text: str) -> str:
        raise RuntimeError("scrub failed")

    with pytest.raises(RuntimeError):
        shell._rewrite_output_file(str(target), boom)
    assert not target.exists()
