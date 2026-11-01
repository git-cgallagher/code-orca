"""Regenerate the Terraform fixtures from the reference stack, through the runner (never by reading a state file).

    .venv/bin/python tests/fixtures/terraform/regenerate.py

Copies ``examples/reference/terraform/app`` into a temporary directory (local state, provider-free, offline),
runs init -> plan -> show -> apply -> show/output/providers schema -> a second plan that forces a replacement,
and writes the captured documents here. Every secret is the placeholder ``FIXTURE-SECRET-tf-input-001``, which
the fixtures hold in plain text on purpose: the tests assert it is there, because redaction is a later stage.

``delete-plan.json`` is hand-written (there is no ``terraform destroy`` here) and is left untouched.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
STACK = ROOT / "examples" / "reference" / "terraform" / "app"
PLACEHOLDER = "FIXTURE-SECRET-tf-input-001"  # a documented test placeholder, never a real value

sys.path.insert(0, str(ROOT / "src"))
from codeorca.adapters.terraform import TerraformRunner, plan_file_sha256  # noqa: E402


def dump(name: str, document: object) -> None:
    (HERE / name).write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def raw(name: str, lines: list[str]) -> None:
    (HERE / name).write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="codeorca-fixtures-") as tmp:
        work = Path(tmp, "app")
        shutil.copytree(STACK, work)
        # Variables travel as TF_VAR_* in the child environment (nothing is written to a tfvars file).
        env = {"PATH": os.environ["PATH"], "HOME": tmp, "TF_VAR_app_secret": PLACEHOLDER, "TF_VAR_environment": "dev"}
        runner = TerraformRunner(work, env)

        init = runner.init()
        raw("init.jsonl", init.stdout_lines + init.stderr_lines)
        assert init.exit_code == 0, init.stderr

        plan = runner.plan(Path(tmp, "plan.tfplan"))
        assert plan.exit_code == 2, (plan.exit_code, plan.stderr)
        dump("plan.json", runner.show_plan(plan.plan_file))

        apply = runner.apply(plan.plan_file, plan_file_sha256(plan.plan_file))
        raw("apply.jsonl", apply.stdout_lines + apply.stderr_lines)
        assert apply.exit_code == 0, apply.stderr

        dump("state.json", runner.show_state())
        dump("outputs.json", runner.output_json())
        dump("providers_schema.json", runner.providers_schema())

        runner.env["TF_VAR_environment"] = "prod"  # the second plan replaces terraform_data.app
        replace = runner.plan(Path(tmp, "replace.tfplan"))
        assert replace.exit_code == 2, (replace.exit_code, replace.stderr)
        dump("replace-plan.json", runner.show_plan(replace.plan_file))

    for result in runner.history:
        print(result.exit_code, " ".join(Path(a).name if i == 0 else a for i, a in enumerate(result.argv)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
