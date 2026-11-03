"""Fails when a specs dir holds a Terraform plan file or any other archive.

A plan file is a zip whose ``tfplan``/``tfstate`` entries carry sensitive values DEFLATE-compressed, so the
``grep -ra`` leak checks (container/tests/smoke.sh, .github/workflows/ci.yml) cannot see a secret inside one. Plan
files belong in the run dir only (0600, deleted after apply), never in specs/, which is meant to be reviewed and
committed. Usage, from smoke.sh and ci.yml:
    python3 -I container/tests/no_plan_in_specs.py <specs dir>...
Exit 0: none found; 1: the offending paths are printed; 2: a specs dir does not exist (the check would be vacuous).
"""

from __future__ import annotations

import sys
import tarfile
import zipfile
from pathlib import Path


def offending(specs: Path) -> list[str]:
    bad = []
    for p in sorted(specs.rglob("*")):
        if p.is_symlink() or not p.is_file():
            continue
        if p.suffix == ".tfplan" or zipfile.is_zipfile(p) or tarfile.is_tarfile(p):
            bad.append(str(p))
            continue
        with p.open("rb") as f:
            if f.read(2) == b"\x1f\x8b":  # gzip
                bad.append(str(p))
    return bad


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    bad = []
    for d in map(Path, argv):
        if not d.is_dir():
            print(f"no_plan_in_specs: {d} is not a directory", file=sys.stderr)
            return 2
        bad += offending(d)
    for b in bad:
        print(f"a plan file or archive is under specs: {b}", file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
