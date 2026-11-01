"""codeorca command line. Phase 0 ships `validate` and `schema export`; the run engine lands in Phase 1."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from pydantic import ValidationError

from codeorca import __version__
from codeorca.config import load_workflow
from codeorca.models import workflow_json_schema


def cmd_validate(args: argparse.Namespace) -> int:
    rc = 0
    for path in args.files:
        try:
            wf = load_workflow(path)
        except ValidationError as e:
            print(f"{path}: INVALID\n{e}", file=sys.stderr)
            rc = 1
            continue
        except Exception as e:  # noqa: BLE001 - a CLI reports, it does not crash
            print(f"{path}: ERROR {type(e).__name__}: {e}", file=sys.stderr)
            rc = 1
            continue
        order = " -> ".join(wf.order())
        print(f"{path}: OK {wf.name}: {len(wf.steps)} steps, {len(wf.finally_)} finally; order = {order}")
    return rc


def cmd_schema_export(args: argparse.Namespace) -> int:
    out = Path(args.dir)
    out.mkdir(parents=True, exist_ok=True)
    target = out / "codeorca-workflow.schema.json"
    text = json.dumps(workflow_json_schema(), indent=2) + "\n"
    if args.check:
        if not target.exists() or target.read_text(encoding="utf-8") != text:
            print(f"{target}: out of date; run `codeorca schema export {out}`", file=sys.stderr)
            return 1
        print(f"{target}: up to date")
        return 0
    target.write_text(text, encoding="utf-8")
    print(f"wrote {target}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="codeorca", description="Terraform + Ansible orchestrator")
    parser.add_argument("--version", action="version", version=f"codeorca {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("validate", help="validate workflow files against the models (no side effects)")
    p.add_argument("files", nargs="+")
    p.set_defaults(func=cmd_validate)

    s = sub.add_parser("schema", help="JSON Schema for editors")
    ssub = s.add_subparsers(dest="schema_command", required=True)
    e = ssub.add_parser("export", help="write schema/codeorca-workflow.schema.json")
    e.add_argument("dir", nargs="?", default="schema")
    e.add_argument("--check", action="store_true", help="fail if the committed schema differs from the models")
    e.set_defaults(func=cmd_schema_export)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
