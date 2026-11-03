"""Reference wrapper for the state-backend bootstrap (plan section 5.11): ``codeorca.bootstrap.s3.main``.

Run by ``workflows/bootstrap-backend.yaml`` as a ``python`` step. With no ``--project`` it uses the
``codeorca.yaml`` next to this ``helpers/`` directory. ``CODEORCA_DRY_RUN=1`` (``codeorca run --dry-run``) writes
nothing; the JSON result goes to ``$CODEORCA_OUTPUT_FILE``.
"""

import sys
from pathlib import Path

from codeorca.bootstrap.s3 import main

if __name__ == "__main__":
    argv = sys.argv[1:]
    if not any(a == "--project" or a.startswith("--project=") for a in argv):
        argv = ["--project", str(Path(__file__).resolve().parents[1] / "codeorca.yaml"), *argv]
    raise SystemExit(main(argv))
