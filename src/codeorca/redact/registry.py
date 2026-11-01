"""SecretRegistry: the known-secret values of one run, in process memory only.

Every consumer of a secret inside the orchestrator registers it here *before* using it (the SSM wrapper
before returning a SecureString, the Terraform adapter for every sensitive leaf, the YAML ``secrets:`` list
at start-up). The registry then supplies the matcher that scrubs rendered documents and subprocess streams.

Hard rules:
- never serialised: ``__reduce__``/``__reduce_ex__`` raise, so pickling, ``copy.copy`` and multiprocessing
  hand-off all fail loudly;
- never logged: ``repr`` and ``str`` show the count only;
- values shorter than ``min_length`` are ignored (short values would shred unrelated words).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import urllib.parse
from collections.abc import Iterator

PLACEHOLDER_RE = re.compile(r"<redacted:(hmac|sha256):[0-9a-f]{8}>")


def _encodings(value: str) -> Iterator[str]:
    """Every textual form a registered value may take in a log, a JSON document or an env dump."""
    yield value
    js = json.dumps(value)[1:-1]  # JSON-escaped, non-ASCII as \\uXXXX
    if js != value:
        yield js
    js_raw = json.dumps(value, ensure_ascii=False)[1:-1]  # JSON-escaped, UTF-8 kept (Terraform's style)
    if js_raw != value and js_raw != js:
        yield js_raw
    uq = urllib.parse.quote(value, safe="")
    if uq != value:
        yield uq
    uq_plus = urllib.parse.quote_plus(value, safe="")
    if uq_plus != value and uq_plus != uq:
        yield uq_plus
    raw = value.encode("utf-8")
    b64 = base64.b64encode(raw).decode("ascii")
    yield b64
    b64url = base64.urlsafe_b64encode(raw).decode("ascii")
    if b64url != b64:
        yield b64url


class SecretRegistry:
    """Known-secret values for one run. Lives only in process memory."""

    __slots__ = ("_cache", "_generation", "_key", "_min_length", "_mode", "_values", "key_id")

    def __init__(self, key: bytes, key_id: str, min_length: int = 8, mode: str = "hmac") -> None:
        if mode not in ("hmac", "sha256"):
            raise ValueError(f"placeholder mode must be 'hmac' or 'sha256', not {mode!r}")
        if not isinstance(key, bytes | bytearray):
            raise TypeError("key must be bytes")
        if mode == "hmac" and not key:
            raise ValueError("hmac mode needs a non-empty key (an empty key degrades to a plain hash)")
        if min_length < 1:
            raise ValueError("min_length must be >= 1")
        self._key = bytes(key)
        self.key_id = key_id  # name/version of the key, recorded in spec headers; never the key itself
        self._min_length = min_length
        self._mode = mode
        self._values: set[str] = set()
        self._generation = 0
        self._cache: tuple[int, re.Pattern[str] | None, dict[str, str], int] | None = None
        # The key is a secret too: scrub its textual form wherever it might be echoed.
        key_text = self._key.decode("utf-8", "replace")
        if key_text:
            self.add(key_text)

    # ----------------------------------------------------------------- registration
    @staticmethod
    def _normalize(value: str) -> str:
        return value.strip()

    def add(self, value: str | None) -> None:
        """Register ``value``. ``None`` is ignored; containers are refused (register each leaf instead)."""
        if value is None:
            return
        if isinstance(value, bool | dict | list | tuple | set | frozenset | bytes):
            raise TypeError(f"SecretRegistry.add takes a str, not {type(value).__name__}")
        if not isinstance(value, str):
            value = str(value)  # int/float leaves of a sensitive map
        s = self._normalize(value)
        if len(s) < self._min_length or s in self._values:
            return
        self._values.add(s)
        self._generation += 1

    @property
    def size(self) -> int:
        return len(self._values)

    @property
    def min_length(self) -> int:
        return self._min_length

    @property
    def mode(self) -> str:
        return self._mode

    @property
    def generation(self) -> int:
        """Bumps on every new value, so callers can cache derived data and notice growth."""
        return self._generation

    # ----------------------------------------------------------------- placeholders
    def placeholder(self, value: str) -> str:
        """``<redacted:hmac:8hex>``: stable per (key, value), so a spec diff shows a secret *changed*."""
        data = self._normalize(str(value)).encode("utf-8")
        if self._mode == "sha256":
            digest = hashlib.sha256(data).hexdigest()[:8]
        else:
            digest = hmac.new(self._key, data, hashlib.sha256).hexdigest()[:8]
        return f"<redacted:{self._mode}:{digest}>"

    # ----------------------------------------------------------------- matching
    def _compiled(self) -> tuple[re.Pattern[str] | None, dict[str, str], int]:
        """(pattern, encoding -> original value, longest encoding), cached per generation."""
        if self._cache is not None and self._cache[0] == self._generation:
            return self._cache[1], self._cache[2], self._cache[3]
        enc_to_value: dict[str, str] = {}
        for v in self._values:
            for enc in _encodings(v):
                enc_to_value.setdefault(enc, v)
        if enc_to_value:
            alts = sorted(enc_to_value, key=lambda e: (-len(e), e))  # longest alternative first
            pattern: re.Pattern[str] | None = re.compile("|".join(re.escape(e) for e in alts))
            max_len = len(alts[0])
        else:
            pattern, max_len = None, 0
        self._cache = (self._generation, pattern, enc_to_value, max_len)
        return pattern, enc_to_value, max_len

    def pattern(self) -> re.Pattern[str] | None:
        """Regex matching every encoding of every registered value, or ``None`` when empty."""
        return self._compiled()[0]

    def max_len(self) -> int:
        """Length of the longest registered encoding (0 when empty). Sizes the stream tail buffer."""
        return self._compiled()[2]

    def redact(self, text: str) -> str:
        """Replace every encoding of every registered value in ``text`` by the value's placeholder."""
        pattern, enc_to_value, _ = self._compiled()
        if pattern is None or not text:
            return text
        return pattern.sub(lambda m: self.placeholder(enc_to_value[m.group(0)]), text)

    def count_matches(self, text: str) -> int:
        pattern = self.pattern()
        return 0 if pattern is None else sum(1 for _ in pattern.finditer(text))

    # ----------------------------------------------------------------- hard rules
    def __reduce__(self):
        raise TypeError("SecretRegistry must never be pickled, copied or serialised")

    def __reduce_ex__(self, protocol):
        raise TypeError("SecretRegistry must never be pickled, copied or serialised")

    def __repr__(self) -> str:
        return f"<SecretRegistry size={len(self._values)}>"

    __str__ = __repr__
