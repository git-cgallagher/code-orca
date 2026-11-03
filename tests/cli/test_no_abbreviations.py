"""codeorca takes no abbreviated long options: bin/codeorca matches -p/--project exactly to find the project file."""

from __future__ import annotations

import pytest

from codeorca.cli import build_parser


@pytest.mark.parametrize(
    "argv",
    [
        ["run", "x", "--proj", "codeorca.yaml"],
        ["run", "x", "--pro=codeorca.yaml"],
        ["summary", "latest", "--projec", "codeorca.yaml"],
        ["runs", "gc", "--keep", "1", "--proj", "codeorca.yaml"],
        ["lint", "ansible", "--proj", "codeorca.yaml", "playbooks"],
        ["run", "x", "--dry"],
    ],
)
def test_abbreviated_options_are_rejected(argv, capsys):
    with pytest.raises(SystemExit) as e:
        build_parser().parse_args(argv)
    assert e.value.code == 2
    assert "unrecognized arguments" in capsys.readouterr().err


def test_the_full_spellings_still_parse():
    args = build_parser().parse_args(["run", "x", "--project", "p.yaml", "--dry-run"])
    assert args.project == "p.yaml" and args.dry_run
    assert build_parser().parse_args(["run", "x", "-pp.yaml"]).project == "p.yaml"
