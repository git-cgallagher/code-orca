"""Entropy scan (stage 5): warnings only. High-entropy tokens are flagged for a human, never auto-redacted,
because ARNs, UUIDs, checksums and bcrypt hashes look exactly like secrets to a Shannon test."""

from __future__ import annotations

import math
import re

TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_\-]{32,}")
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
# arn:partition:service:region:account:resource — a token inside one is an identifier, not a secret.
ARN_RE = re.compile(r"arn:[A-Za-z0-9\-]*:[A-Za-z0-9\-]*:[A-Za-z0-9\-]*:[A-Za-z0-9\-]*:[^\s\"',]+")
PLACEHOLDER_RE = re.compile(r"<redacted:[a-z0-9]+:[0-9a-f]{8}>|<redacted:key>")

BASE64_LIMIT = 4.5  # detect-secrets defaults
HEX_LIMIT = 3.0
CHECKSUM_HEX_LENGTHS = frozenset({32, 40, 64, 96, 128})  # md5, sha1/git, sha256, sha384, sha512


def shannon_entropy(s: str) -> float:
    n = len(s)
    if n == 0:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _allowlisted(token: str, line: str, start: int, end: int) -> bool:
    if UUID_RE.match(token):
        return True
    if HEX_RE.match(token) and len(token) in CHECKSUM_HEX_LENGTHS:
        return True
    for m in ARN_RE.finditer(line):
        if m.start() <= start and end <= m.end():
            return True
    return False


def redacted_snippet(token: str) -> str:
    """Enough to find the token in the file, never enough to use it."""
    return f"{token[:4]}…({len(token)} chars)"


def entropy_warnings(text: str) -> list[tuple[int, str]]:
    """``[(line_no, redacted_snippet)]`` for every token of 32+ characters whose Shannon entropy is at or above
    the detect-secrets thresholds (4.5 bits for base64-ish, 3.0 for hex), skipping UUIDs, checksum-length hex
    strings, anything inside an ARN and this package's own placeholders. Line numbers are 1-based."""
    out: list[tuple[int, str]] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        if not line:
            continue
        placeholders = [(m.start(), m.end()) for m in PLACEHOLDER_RE.finditer(line)]
        for m in TOKEN_RE.finditer(line):
            token = m.group(0)
            if any(s <= m.start() and m.end() <= e for s, e in placeholders):
                continue
            if _allowlisted(token, line, m.start(), m.end()):
                continue
            limit = HEX_LIMIT if HEX_RE.match(token) else BASE64_LIMIT
            if shannon_entropy(token) >= limit:
                out.append((line_no, redacted_snippet(token)))
    return out
