"""``codeorca lint ansible``: output format, exit codes, directory expansion, project denylists. Module resolution
needs ansible-core for ``secret-to-plain-param``; the assertions here hold either way."""

from __future__ import annotations

from pathlib import Path

from codeorca import cli

ROOT = Path(__file__).resolve().parents[2]
LINT_FIXTURES = ROOT / "tests" / "lint" / "fixtures"
REFERENCE = ROOT / "examples" / "reference"


def test_findings_are_printed_one_per_line_and_warnings_exit_1(capsys):
    assert cli.main(["lint", "ansible", str(LINT_FIXTURES)]) == 1
    out = capsys.readouterr().out.splitlines()
    playbook = str(LINT_FIXTURES / "playbook.yml")
    assert f"{playbook}:5 no-hostvars-dump warning debug var: hostvars[inventory_hostname] prints every variable" in (
        "\n".join(out)
    )
    assert any(line.startswith(f"{playbook}:17 debug-secret-name warning ") for line in out)
    for line in out:
        location, rule, level, _message = line.split(" ", 3)
        assert location.rsplit(":", 1)[1].isdigit() and level in ("info", "warning", "error") and rule


def test_reference_ansible_tree_is_clean_with_the_project_denylists(capsys):
    rc = cli.main(["lint", "ansible", "-p", str(REFERENCE / "codeorca.yaml"), str(REFERENCE / "ansible")])
    captured = capsys.readouterr()
    assert rc == 0, captured.out
    assert "lint: 0 finding(s); exit 0" in captured.err


def test_info_only_findings_exit_0_and_vars_trees_are_skipped(tmp_path: Path, capsys):
    tasks = tmp_path / "roles" / "r" / "tasks" / "main.yml"
    tasks.parent.mkdir(parents=True)
    task = '- name: Unknown module\n  example.collection.widget: {value: "{{ db_password }}"}\n'
    tasks.write_text(task, encoding="utf-8")
    bad_vars = tmp_path / "group_vars" / "all.yml"
    bad_vars.parent.mkdir()
    bad_vars.write_text("{ not: [valid\n", encoding="utf-8")  # skipped: vars trees hold no tasks
    assert cli.main(["lint", "ansible", str(tmp_path)]) == 0
    assert "unknown-module info" in capsys.readouterr().out


def test_unparsable_file_and_missing_path(tmp_path: Path, capsys):
    broken = tmp_path / "site.yml"
    broken.write_text("- hosts: all\n  tasks: [\n", encoding="utf-8")
    assert cli.main(["lint", "ansible", str(broken)]) == 1
    assert f"{broken}:0 parse-error error " in capsys.readouterr().out
    assert cli.main(["lint", "ansible", str(tmp_path / "missing")]) == 1
    assert "neither a file nor a directory" in capsys.readouterr().err
