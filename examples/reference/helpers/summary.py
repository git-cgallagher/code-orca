"""Reference ``finally`` helper: ``codeorca summary <run id>`` for the project this script belongs to.

A ``python`` step runs with the project root as its cwd and the interpreter that runs code-orca, so the summary
needs neither ``codeorca`` on PATH nor a ``-p`` that depends on where the operator stood.
"""

import sys
from pathlib import Path

from codeorca.cli import main

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: summary.py <run-id>")
    project = Path(__file__).resolve().parents[1] / "codeorca.yaml"
    raise SystemExit(main(["summary", sys.argv[1], "-p", str(project)]))
