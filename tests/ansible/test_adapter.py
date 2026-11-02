"""The adapter and the ``codeorca_jsonl`` callback against the fixture playbook: only JSON on stdout, every event
kind, no_log censoring, check-mode detection, the exit-code mapping, the generated files and the child env."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import time
from pathlib import Path

import pytest
from ansible_support import FIXTURES, requires_ansible
from ruamel.yaml import YAML

from codeorca.adapters import ansible as adapter
from codeorca.adapters.ansible import (
    AnsibleResult,
    AnsibleRunner,
    AnsibleTimeout,
    build_env,
    callback_plugins_dir,
    describe_rc,
    generate_inventory,
    generate_role_playbook,
    summarize,
    write_handoff,
)

SECRET = "FIXTURE-SECRET-adapter-001"


class Capture:
    def __init__(self) -> None:
        self.lines: list[tuple[str, str]] = []

    def __call__(self, line: str, channel: str) -> None:
        self.lines.append((channel, line))

    def channel(self, name: str) -> list[str]:
        return [line for ch, line in self.lines if ch == name]


def run_fixture(tmp_path: Path, *, do_fail: bool, check: bool = False, env: dict | None = None):
    handoff = tmp_path / "handoff"
    extra = write_handoff(handoff, "extra-vars.json", {"scratch_dir": str(tmp_path), "do_fail": do_fail})
    capture = Capture()
    runner = AnsibleRunner(FIXTURES, {**os.environ, **(env or {})}, stream=capture, local_temp=tmp_path / "tmp")
    result = runner.run(
        FIXTURES / "site.yml", FIXTURES / "inventory.yml", extra_vars_file=extra, check=check, diff=check, timeout=120
    )
    return result, capture, runner


# ---------------------------------------------------------------------------------------- pure functions


def test_describe_rc_knows_4_is_ambiguous_and_describe_reads_the_stats():
    assert describe_rc(0) == "ok"
    assert describe_rc(2) == "failed hosts"
    assert describe_rc(4) == "unreachable hosts or parser error"  # ExitCode.PARSER_ERROR == HOST_UNREACHABLE
    assert describe_rc(1) == "error"
    assert describe_rc(5) == "invalid command-line option"
    assert describe_rc(99) == "interrupted"
    assert describe_rc(250) == "unexpected error"
    stats = {"type": "stats", "stats": {}}
    assert AnsibleResult(4, events=[]).describe() == "parser error"  # no stats event: nothing ran
    assert AnsibleResult(4, events=[stats], unreachable_hosts=["a"]).describe() == "unreachable hosts"
    both = AnsibleResult(4, events=[stats], failed_hosts=["b"], unreachable_hosts=["a"])
    assert both.describe() == "failed hosts and unreachable hosts"  # one run, rc 4 (unreachable wins)


def test_last_failure_ignores_rescued_and_ignore_unreachable_results():
    events = [
        {"type": "runner", "host": "a", "task": "real", "status": "failed", "msg": "the-real-failure"},
        {"type": "runner", "host": "b", "task": "rescued step", "status": "failed", "msg": "rescued"},
        {"type": "runner", "host": "dead", "task": "ping", "status": "unreachable", "ignore_errors": True},
        {"type": "runner", "host": "c", "task": "rescued later", "status": "unreachable", "msg": "noise"},
        {"type": "stats", "stats": {}},
    ]
    result = AnsibleResult(2, events=events, failed_hosts=["a"])
    assert result.last_failure()["msg"] == "the-real-failure"


def test_summarize_reads_stats_and_check_unsupported():
    events = [
        {"type": "runner", "host": "a", "task": "t1", "status": "skipped", "check_unsupported": True},
        {"type": "runner", "host": "a", "task": "t1", "status": "skipped", "check_unsupported": True},
        {"type": "runner", "host": "a", "task": "t2", "status": "failed", "ignore_errors": True},
        {
            "type": "stats",
            "stats": {"a": {"ok": 2, "failed": 0, "unreachable": 0}, "b": {"failed": 1, "unreachable": 1}},
        },
    ]
    stats, failed, unreachable, unsupported = summarize(events)
    assert stats["a"] == {
        "ok": 2,
        "changed": 0,
        "failed": 0,
        "unreachable": 0,
        "skipped": 0,
        "rescued": 0,
        "ignored": 0,
    }
    assert failed == ["b"] and unreachable == ["b"]
    assert unsupported == [("a", "t1")]


def test_last_failure_skips_ignored_failures():
    events = [
        {"type": "runner", "host": "a", "task": "ignored", "status": "failed", "ignore_errors": True, "msg": "x"},
        {"type": "runner", "host": "a", "task": "real", "status": "failed", "ignore_errors": False, "msg": "boom"},
        {"type": "runner", "host": "a", "task": "later", "status": "ok"},
    ]
    assert AnsibleResult(2, events=events).last_failure()["task"] == "real"
    assert AnsibleResult(0, events=[events[0]]).last_failure() is None


def test_generate_inventory_quotes_strings_and_keeps_types():
    text = generate_inventory({"app": {"hosts": {"h1": {"ansible_host": "10.0.0.1", "port": 22, "flag": "yes"}}}})
    data = YAML(typ="safe", pure=True).load(text)
    assert data["app"]["hosts"]["h1"] == {"ansible_host": "10.0.0.1", "port": 22, "flag": "yes"}
    assert '"yes"' in text  # a bare yes would be a bool to Ansible's YAML 1.1 reader
    with pytest.raises(ValueError):
        generate_inventory({})


def test_generate_role_playbook_is_one_import_role_play():
    text = generate_role_playbook("acme.app.config", hosts="web", extra={"become": True, "vars": {"a": 1}})
    plays = YAML(typ="safe", pure=True).load(text)
    assert len(plays) == 1
    play = plays[0]
    assert play["hosts"] == "web" and play["gather_facts"] is False and play["become"] is True
    assert play["vars"] == {"a": 1}
    assert play["tasks"] == [
        {"name": "Import role acme.app.config", "ansible.builtin.import_role": {"name": "acme.app.config"}}
    ]
    with pytest.raises(ValueError):
        generate_role_playbook("acme.app.config", extra={"tasks": []})
    with pytest.raises(ValueError):
        generate_role_playbook("not a role")


def test_write_handoff_is_private(tmp_path):
    path = write_handoff(tmp_path / "h", "vars.json", {"k": "v"})
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert json.loads(path.read_text()) == {"k": "v"}
    with pytest.raises(ValueError):
        write_handoff(tmp_path / "h", "../x.json", {})


def test_build_env_drops_forces_and_defaults():
    env = build_env(
        {
            "PATH": "/bin",
            "CODEORCA_REDACTION_KEY": "k",
            "ANSIBLE_DEBUG": "1",
            "ANSIBLE_LOG_PATH": "/tmp/x",
            "ANSIBLE_VERBOSITY": "3",
            "ANSIBLE_STDOUT_CALLBACK": "default",
            "ANSIBLE_CALLBACK_PLUGINS": "/custom",
            "ANSIBLE_HOST_KEY_CHECKING": "False",
        },
        local_temp="/tmp/t",
    )
    assert "CODEORCA_REDACTION_KEY" not in env
    # forced, not dropped: each has an ansible.cfg twin that only an env value outranks
    assert env["ANSIBLE_DEBUG"] == "False" and env["ANSIBLE_VERBOSITY"] == "0"
    assert env["ANSIBLE_LOG_PATH"] == os.devnull and env["ANSIBLE_KEEP_REMOTE_FILES"] == "False"
    assert env["ANSIBLE_CALLBACKS_ENABLED"] == "codeorca_jsonl"
    assert env["ANSIBLE_STDOUT_CALLBACK"] == "codeorca_jsonl"
    assert env["ANSIBLE_CALLBACK_PLUGINS"].split(os.pathsep) == [str(callback_plugins_dir()), "/custom"]
    assert env["ANSIBLE_HOST_KEY_CHECKING"] == "False"  # the caller's choice survives
    assert build_env({})["ANSIBLE_HOST_KEY_CHECKING"] == "True"
    assert env["ANSIBLE_NOCOLOR"] == "1" and env["ANSIBLE_FORCE_COLOR"] == "0"
    assert env["ANSIBLE_RETRY_FILES_ENABLED"] == "False" and env["ANSIBLE_LOCAL_TEMP"] == "/tmp/t"
    assert (callback_plugins_dir() / "codeorca_jsonl.py").is_file()


def test_callback_module_imports_nothing_from_codeorca():
    text = (callback_plugins_dir() / "codeorca_jsonl.py").read_text(encoding="utf-8")
    assert "codeorca" not in [line.split()[1] for line in text.splitlines() if line.startswith(("import ", "from "))]
    assert "from codeorca" not in text and "import codeorca" not in text


# ---------------------------------------------------------------------------------------- live runs


@requires_ansible
def test_stdout_is_only_json_events_even_when_a_task_fails(tmp_path):
    result, capture, _ = run_fixture(tmp_path, do_fail=True)
    assert result.rc == 2
    stdout = capture.channel("stdout")
    assert stdout, "no events reached the stream"
    for line in stdout:
        assert line.endswith("\n")
        event = json.loads(line)  # every stdout line is a JSON object
        assert "type" in event and "ts" in event
    assert not [e for e in result.events if e["type"] == "log"], "a non-JSON line reached stdout"
    # the default callback's lines never appear: every stdout line is a JSON object (asserted above), and none of
    # them is a display line ("Task failed" does occur, inside the failed event's exception summary)
    assert not any(line.startswith(("[ERROR]", "fatal:", "PLAY", "TASK", "ok:", "changed:")) for line in stdout)
    kinds = {e["type"] for e in result.events}
    assert {"playbook_start", "play_start", "task_start", "runner", "item", "stats"} <= kinds


@requires_ansible
def test_stats_failed_hosts_and_the_failed_result_dict(tmp_path):
    result, _, _ = run_fixture(tmp_path, do_fail=True)
    assert result.stats == {
        "app-host": {"ok": 7, "changed": 1, "failed": 1, "unreachable": 0, "skipped": 1, "rescued": 0, "ignored": 0}
    }
    assert result.failed_hosts == ["app-host"] and result.unreachable_hosts == []
    last = result.last_failure()
    assert last["task"] == "failing task" and last["status"] == "failed" and last["ignore_errors"] is False
    assert last["result"]["msg"] == "deliberate failure with nothing to echo"  # the full result dict is there
    assert last["msg"] == last["result"]["msg"]
    assert last["exception"]  # the summary text, not a display line
    changed = [e for e in result.events if e["type"] == "runner" and e["task"] == "changed task"][0]
    assert changed["status"] == "ok" and changed["changed"] is True
    assert (tmp_path / "hello.txt").read_text() == "hello from app-host\n"
    skipped = [e for e in result.events if e["type"] == "runner" and e["task"] == "skipped task"][0]
    assert skipped["status"] == "skipped" and skipped["check_unsupported"] is False
    items = [e for e in result.events if e["type"] == "item"]
    assert [e["item"] for e in items] == ["one", "two"] and all(e["task"] == "looped task" for e in items)
    assert result.argv[-1].endswith("site.yml") and "-e" in result.argv
    assert result.duration_s > 0


@requires_ansible
def test_a_clean_run_exits_zero_and_the_command_task_runs(tmp_path):
    result, capture, _ = run_fixture(tmp_path, do_fail=False)
    assert result.rc == 0 and result.ok and result.failed_hosts == []
    assert result.check_unsupported == []
    command = [e for e in result.events if e["type"] == "runner" and e["task"] == "check-unsupported task"][0]
    assert command["status"] == "ok" and command["check_unsupported"] is False
    failing = [e for e in result.events if e["type"] == "runner" and e["task"] == "failing task"][0]
    assert failing["status"] == "skipped" and failing["check_unsupported"] is False  # when: false, not a failure
    assert not capture.channel("stderr") or all(
        "[WARNING]" in line or line.strip() for line in capture.channel("stderr")
    )


@requires_ansible
def test_no_log_result_stays_censored_in_the_events(tmp_path):
    result, capture, _ = run_fixture(tmp_path, do_fail=False)
    event = [e for e in result.events if e["type"] == "runner" and e["task"] == "no_log task"][0]
    assert event["no_log"] is True and event["msg"] is None
    assert "censored" in event["result"]
    assert "FIXTURE-SECRET-nolog-001" not in json.dumps(result.events)
    assert not any("FIXTURE-SECRET-nolog-001" in line for _, line in capture.lines)


@requires_ansible
def test_check_mode_detects_the_unsupported_command_task(tmp_path):
    result, _, _ = run_fixture(tmp_path, do_fail=False, check=True)
    assert result.rc == 0
    assert result.check_unsupported == [("app-host", "check-unsupported task")]
    event = [e for e in result.events if e["type"] == "runner" and e["task"] == "check-unsupported task"][0]
    assert event["status"] == "skipped" and event["check_unsupported"] is True and event["check_mode"] is True
    changed = [e for e in result.events if e["type"] == "runner" and e["task"] == "changed task"][0]
    assert changed["diff"] and changed["diff"][0]["after"] == "hello from app-host\n"  # --diff reaches the event
    assert not (tmp_path / "hello.txt").exists()
    assert "--check" in result.argv and "--diff" in result.argv


@requires_ansible
def test_child_env_never_carries_the_redaction_key_or_debug(tmp_path):
    env = {"CODEORCA_REDACTION_KEY": SECRET, "ANSIBLE_DEBUG": "1", "ANSIBLE_LOG_PATH": str(tmp_path / "unredacted.log")}
    result, capture, runner = run_fixture(tmp_path, do_fail=False, env=env)
    assert result.rc == 0
    assert "CODEORCA_REDACTION_KEY" not in runner.env and "CODEORCA_REDACTION_KEY" not in result.env_names
    assert runner.env["ANSIBLE_DEBUG"] == "False" and runner.env["ANSIBLE_LOG_PATH"] == os.devnull
    assert not (tmp_path / "unredacted.log").exists()
    assert SECRET not in json.dumps(result.events)


CFG_SECRET = "FIXTURE-DEBUGLEAK-nolog-0009"
CFG_PLAYBOOK = f"""- hosts: all
  gather_facts: false
  tasks:
    - name: hidden command
      ansible.builtin.command: echo {CFG_SECRET}
      no_log: true
"""


@requires_ansible
def test_project_ansible_cfg_cannot_turn_debug_log_verbosity_or_aggregate_callbacks_back_on(tmp_path):
    # ansible-playbook runs from the project root, so the consumer's ansible.cfg is read; env beats ini
    project = tmp_path / "proj"
    project.mkdir()
    (project / "ansible.cfg").write_text(
        "[defaults]\ndebug = True\nverbosity = 4\nlog_path = ./ansible.log\n"
        "callbacks_enabled = ansible.builtin.junit\nkeep_remote_files = True\n",
        encoding="utf-8",
    )
    (project / "pb.yml").write_text(CFG_PLAYBOOK, encoding="utf-8")
    (project / "inv.yml").write_text(
        "all:\n  hosts:\n    h1:\n      ansible_connection: local\n"
        "      ansible_python_interpreter: '{{ ansible_playbook_python }}'\n",
        encoding="utf-8",
    )
    capture = Capture()
    env = {**os.environ, "JUNIT_OUTPUT_DIR": str(project / "junit")}
    runner = AnsibleRunner(project, env, stream=capture, local_temp=tmp_path / "tmp")
    result = runner.run(project / "pb.yml", project / "inv.yml", timeout=120)
    assert result.rc == 0, capture.lines
    assert CFG_SECRET not in "".join(line for _, line in capture.lines)
    assert not (project / "ansible.log").exists()
    assert not (project / "junit").exists()
    assert [e["type"] for e in result.events].count("stats") == 1  # the stdout callback is loaded once


SLEEP_MARKER = "60.0731"  # an unusual duration: the survivor check must not match another process's `sleep 60`


def live_sleepers(marker: str) -> list[str]:
    out = subprocess.run(["ps", "-axo", "pid=,command="], capture_output=True, text=True, check=False).stdout
    return [line for line in out.splitlines() if f"sleep {marker}" in line]


@requires_ansible
def test_timeout_kills_the_workers_and_the_running_module(tmp_path):
    assert not live_sleepers(SLEEP_MARKER), "a previous run left a sleeper behind"
    extra = write_handoff(tmp_path / "handoff", "extra-vars.json", {"sleep_seconds": SLEEP_MARKER})
    runner = AnsibleRunner(FIXTURES, dict(os.environ), local_temp=tmp_path / "tmp")
    started = time.monotonic()
    with pytest.raises(AnsibleTimeout):
        # 6 s: ansible-playbook needs ~2 s to reach the task; a deadline that fires earlier never exercises the kill
        runner.run(FIXTURES / "sleep.yml", FIXTURES / "inventory.yml", extra_vars_file=extra, timeout=6)
    assert time.monotonic() - started < 25
    assert runner.history and runner.history[-1].rc != 0
    task_started = any(e.get("type") == "task_start" and e.get("task") == "sleep" for e in runner.history[-1].events)
    assert task_started, "the sleep task never started: the kill was not exercised"
    time.sleep(1)
    # ansible-core workers setsid() themselves: killing the leader's group alone leaves the module running
    assert live_sleepers(SLEEP_MARKER) == []


@requires_ansible
def test_unreachable_host_maps_to_exit_4(tmp_path):
    inventory = tmp_path / "unreachable.yml"
    inventory.write_text(
        generate_inventory(
            {
                "app": {
                    "hosts": {
                        "nowhere": {
                            "ansible_host": "127.0.0.1",
                            "ansible_port": 1,
                            "ansible_connection": "ssh",
                            "ansible_user": "nobody",
                            "ansible_ssh_common_args": "-o ConnectTimeout=2 -o StrictHostKeyChecking=no",
                        }
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    runner = AnsibleRunner(FIXTURES, {**os.environ, "ANSIBLE_HOST_KEY_CHECKING": "False"}, local_temp=tmp_path / "tmp")
    result = runner.run(FIXTURES / "sleep.yml", inventory, timeout=120)  # a command task needs the connection
    assert result.rc == adapter.RC_UNREACHABLE
    assert result.unreachable_hosts == ["nowhere"] and result.failed_hosts == []
    assert result.last_failure()["status"] == "unreachable"
    assert result.describe() == "unreachable hosts"


# ------------------------------------------------------------------------------- callback edge cases (review)


def run_edge(tmp_path: Path, edge: str, *, check: bool = False):
    extra = write_handoff(tmp_path / "handoff", "extra-vars.json", {"scratch_dir": str(tmp_path), "edge": edge})
    capture = Capture()
    runner = AnsibleRunner(FIXTURES, dict(os.environ), stream=capture, local_temp=tmp_path / "tmp")
    result = runner.run(
        FIXTURES / "edges.yml", FIXTURES / "inventory.yml", extra_vars_file=extra, check=check, diff=check, timeout=120
    )
    return result, capture


@requires_ansible
def test_no_log_failure_exception_and_warnings_are_never_emitted(tmp_path):
    from codeorca.steps.ansible import _failure_text

    result, capture = run_edge(tmp_path, "nolog_fail")
    assert result.rc == 2
    stdout = "".join(capture.channel("stdout"))
    assert "FIXTURE-UNREG-nolog-0006" not in stdout
    event = [e for e in result.events if e["type"] == "runner" and e["task"] == "no_log assert"][0]
    assert event["no_log"] is True and event["exception"] is None and event["warnings"] is None
    assert "FIXTURE-UNREG-nolog-0006" not in _failure_text(result)


@requires_ansible
def test_loop_control_label_hides_the_loop_item_in_the_result(tmp_path):
    result, capture = run_edge(tmp_path, "loop_label")
    assert result.rc == 0
    assert "FIXTURE-LOOPITEM-zz9-plural" not in "".join(line for _, line in capture.lines)
    items = [e for e in result.events if e["type"] == "item" and e["task"] == "labelled loop"]
    assert [e["item"] for e in items] == ["alice"] and items[0]["result"]["item"] == "alice"


@requires_ansible
def test_unicode_line_separators_never_split_an_event(tmp_path):
    result, capture = run_edge(tmp_path, "separators")
    assert result.rc == 0
    for line in capture.channel("stdout"):
        assert len(line.rstrip("\n").splitlines()) == 1  # what the stream redactor's sink does
        json.loads(line)
    event = [e for e in result.events if e["type"] == "runner" and e["task"] == "line separators"][0]
    assert event["result"]["msg"] == "a b\u0085c d"


@requires_ansible
def test_set_stats_values_never_reach_the_stats_event(tmp_path):
    result, capture = run_edge(tmp_path, "set_stats")
    assert "FIXTURE-SECRETSTATS-hhhh8888" not in "".join(line for _, line in capture.lines)
    stats = [e for e in result.events if e["type"] == "stats"][0]
    assert stats["custom"] == {"_run": ["tok"]}


@requires_ansible
def test_raw_script_and_fetch_are_check_unsupported(tmp_path):
    result, _ = run_edge(tmp_path, "check_unsupported", check=True)
    assert {task for _, task in result.check_unsupported} == {
        "raw check-unsupported",
        "script check-unsupported",
        "fetch check-unsupported",
    }
    when_skipped = [e for e in result.events if e["type"] == "runner" and e["task"] == "labelled loop"]
    assert when_skipped and not when_skipped[0]["check_unsupported"]  # a when: skip in check mode is not unsupported


@requires_ansible
def test_notify_events_carry_no_task_attribution(tmp_path):
    result, _ = run_edge(tmp_path, "notify")
    notify = [e for e in result.events if e["type"] == "notify"]
    assert notify and all(e["task"] is None and e["handler"] == "edge handler" for e in notify)


def test_ascii_escaped_json_still_matches_a_registered_non_ascii_value():
    from codeorca.redact import SecretRegistry

    reg = SecretRegistry(b"example-not-secret-key", "test", mode="sha256")
    value = "FIXTURE-SECRET-café- -001"
    reg.add(value)
    line = json.dumps({"msg": value}, ensure_ascii=True)  # what the callback prints now
    assert reg.count_matches(line) == 1 and "caf" not in reg.redact(line)


@requires_ansible
def test_a_playbook_that_does_not_parse_reports_the_parser_error(tmp_path):
    from codeorca.steps.ansible import _failure_text

    playbook = tmp_path / "bad.yml"
    playbook.write_text("- hosts: all\n  tasks:\n    - debug: {msg: x}\n      bogus_keyword: 1\n")
    runner = AnsibleRunner(FIXTURES, dict(os.environ), local_temp=tmp_path / "tmp")
    result = runner.run(playbook, FIXTURES / "inventory.yml", timeout=120)
    assert result.rc == 4 and not result.stats_seen
    assert result.describe() == "parser error"
    text = _failure_text(result)
    assert "parser error" in text and "bogus_keyword" in text
