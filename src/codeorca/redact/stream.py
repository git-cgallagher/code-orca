"""StreamRedactor: chunk-safe value scrub for subprocess stdout/stderr and ``-json`` streams."""

from __future__ import annotations

from codeorca.redact.registry import SecretRegistry

# A line longer than this is emitted in pieces (the tail is still retained): a newline-free stream must not
# grow the buffer without bound.
MAX_HELD_LINE = 1 << 20


class StreamRedactor:
    """Feed arbitrary chunks, get back redacted text in whole lines.

    Invariant: ``feed`` only emits text that no later chunk can change. The buffer keeps a raw tail of
    ``longest registered encoding - 1`` characters (recomputed on every feed, because the registry grows
    mid-run), so a value split across two reads is matched once the second read arrives. The cut is moved
    before any current match that would straddle it (a multi-line PEM key spanning the line boundary) and
    then back to a line start, so output is whole lines. Text already emitted cannot be fixed by a later
    registration: register a secret before the process that might print it starts.
    """

    def __init__(self, registry: SecretRegistry) -> None:
        self.registry = registry
        self._buf = ""

    @property
    def pending(self) -> int:
        """Characters held back, waiting for more input or ``flush``."""
        return len(self._buf)

    def feed(self, chunk: str) -> str:
        if chunk:
            self._buf += chunk
        buf = self._buf
        tail = max(self.registry.max_len() - 1, 0)
        limit = len(buf) - tail  # everything before this index is final whatever comes next
        if limit <= 0:
            return ""
        nl = buf.rfind("\n", 0, limit)
        if nl >= 0:
            cut = self._safe_cut(buf, nl + 1, align_lines=True)
        elif len(buf) > MAX_HELD_LINE + tail:
            cut = self._safe_cut(buf, limit, align_lines=False)  # one enormous line: emit it in pieces
        else:
            return ""
        if cut <= 0:
            return ""
        out, self._buf = buf[:cut], buf[cut:]
        return self.registry.redact(out)

    def _safe_cut(self, buf: str, cut: int, align_lines: bool) -> int:
        """Move ``cut`` before any current match that straddles it, re-aligning to a line start when asked.
        Matches never overlap and ``cut`` only decreases, so this terminates."""
        pattern = self.registry.pattern()
        if pattern is None:
            return cut
        while cut > 0:
            straddling = next((m for m in pattern.finditer(buf) if m.start() < cut < m.end()), None)
            if straddling is None:
                return cut
            cut = straddling.start()
            if align_lines:
                nl = buf.rfind("\n", 0, cut)
                cut = nl + 1 if nl >= 0 else 0
        return cut

    def flush(self) -> str:
        out, self._buf = self._buf, ""
        return self.registry.redact(out)
