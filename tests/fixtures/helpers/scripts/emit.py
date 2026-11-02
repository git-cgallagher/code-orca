"""Fixture helper: reports what it saw into $CODEORCA_OUTPUT_FILE, logs HELPER_SECRET, exits with argv[1]."""

import hashlib
import json
import os
import sys


def main() -> int:
    args = sys.argv[1:]
    code = int(args[0]) if args else 0
    secret = os.environ.get("HELPER_SECRET", "")
    if secret:
        print(f"stdout sees {secret}")
        print(f"stderr sees {secret}", file=sys.stderr)
    out = {
        "args": args,
        "dry_run": os.environ.get("CODEORCA_DRY_RUN"),
        "greeting": os.environ.get("GREETING"),
        "secret_echo": secret or None,
        "secret_sha": hashlib.sha256(secret.encode()).hexdigest()[:16] if secret else None,
        "cwd": os.getcwd(),
        "isolated": bool(sys.flags.isolated),
    }
    with open(os.environ["CODEORCA_OUTPUT_FILE"], "w", encoding="utf-8") as fh:
        json.dump(out, fh)
    if code:
        print(f"failing with {code}", file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())
