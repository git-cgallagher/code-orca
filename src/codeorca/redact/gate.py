"""The post-render gate (stage 6): no registered value, in any encoding, in any output file."""

from __future__ import annotations

import os
import re
from collections.abc import Sequence
from pathlib import Path

from codeorca.redact.registry import SecretRegistry


def scan_outputs(
    root: str | os.PathLike[str], registry: SecretRegistry, extra_patterns: Sequence[str] = ()
) -> list[tuple[str, int]]:
    """Scan every file under ``root`` for registered values (any encoding) and ``extra_patterns`` regexes.

    Returns ``[(relative_posix_path, match_count)]`` for the files that hit, sorted by path. The report never
    carries a matched value, so it is safe to print and to put in a result file. Files are read as UTF-8 with
    replacement, so a binary file is scanned for the textual forms it may embed. An unreadable file raises:
    a tree the gate cannot read in full cannot be declared clean.
    """
    root_path = Path(root)
    extras = [re.compile(p) for p in extra_patterns]
    hits: list[tuple[str, int]] = []
    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames.sort()
        for name in sorted(filenames):
            path = Path(dirpath) / name
            rel = path.relative_to(root_path).as_posix()
            text = path.read_bytes().decode("utf-8", "replace")
            n = registry.count_matches(text) + sum(1 for p in extras for _ in p.finditer(text))
            if n:
                hits.append((rel, n))
    hits.sort()
    return hits
