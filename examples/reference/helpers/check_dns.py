"""Reference python helper (``demo-rollout``'s ``dns_check``): resolve a name, offline.

``--name`` defaults to ``localhost``, which every host resolves without a network. Writes ``{"resolved": bool,
"name": ..., "addresses": [...], "dry_run": bool}`` to ``$CODEORCA_OUTPUT_FILE`` (the helper contract: stdout is a
log, the output file is the result) and exits 1 when the name does not resolve.

``CODEORCA_DRY_RUN=1`` (``codeorca run --dry-run``) is honoured: a helper must not change anything then. This one
only reads (a lookup), so it runs the same check and says it was a dry run; a helper that writes something would
skip the write here.
"""

import argparse
import json
import os
import socket
import sys


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--name", default="localhost")
    args = parser.parse_args(argv)
    dry_run = os.environ.get("CODEORCA_DRY_RUN") == "1"
    try:
        infos = socket.getaddrinfo(args.name, None, proto=socket.IPPROTO_TCP)
        addresses = sorted({info[4][0] for info in infos})
    except OSError:
        addresses = []
    resolved = bool(addresses)
    print(
        f"{args.name}: {'resolves to ' + ', '.join(addresses) if resolved else 'does not resolve'}"
        f"{' (dry run: read-only check)' if dry_run else ''}"
    )
    output = os.environ.get("CODEORCA_OUTPUT_FILE")
    if output:
        with open(output, "w", encoding="utf-8") as f:
            json.dump({"resolved": resolved, "name": args.name, "addresses": addresses, "dry_run": dry_run}, f)
    return 0 if resolved else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
