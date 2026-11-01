"""Value scrub over text and trees (stages 3 and 4 of the pipeline): registry matches and the key denylist."""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from typing import Any

from codeorca.redact.registry import SecretRegistry

KEY_PLACEHOLDER = "<redacted:key>"

# The plan's project-file default (section 5.2). A bare ``key`` is deliberately absent: it would hit
# ``ssh_key_file``, ``GPG_KEY``, ``key_name`` and every ``*_key_id``.
DEFAULT_KEY_DENYLIST: tuple[str, ...] = (
    "(?i)password",
    "(?i)secret",
    "(?i)token",
    "(?i)api_key",
    "(?i)access_key",
    "(?i)private_key",
    "_wo$",
)

_FLAGS_PREFIX = re.compile(r"^\(\?[aiLmsux]+\)")


def compile_key_denylist(patterns: Iterable[str] | None) -> tuple[re.Pattern[str], ...]:
    """Compile key-name patterns, refusing a bare ``key`` (with or without flags/anchors)."""
    compiled: list[re.Pattern[str]] = []
    for p in patterns or ():
        body = _FLAGS_PREFIX.sub("", p).strip().strip("^$")
        if body.lower() == "key":
            raise ValueError(f"key denylist pattern {p!r} is a bare 'key': it would match ssh_key_file and GPG_KEY")
        compiled.append(re.compile(p))
    return tuple(compiled)


def redact_text(text: str, registry: SecretRegistry) -> str:
    """Replace every encoding of every registered value with the value's placeholder."""
    return registry.redact(text)


def _key_denied(key: Any, denylist: Sequence[re.Pattern[str]]) -> bool:
    if not denylist or not isinstance(key, str):
        return False
    return any(p.search(key) for p in denylist)


def redact_tree(obj: Any, registry: SecretRegistry, key_denylist: Sequence[str] | None = None) -> Any:
    """Return ``obj`` with the same shape, every string holding a registered value (any encoding) replaced by
    its placeholder, and every value under a key matching one of ``key_denylist`` (regexes matched against the
    key name with ``re.search``) replaced by ``<redacted:key>`` whatever its type or depth.

    Pure: nothing is registered here. A value under a denylisted key is often a secret *name* (``secret:
    ssm:/app/api-token``); registering it would shred that name from every spec and log. Callers that want a
    denylisted value scrubbed from later output register it themselves. Dict keys are scrubbed through the
    value matcher as well (a map keyed by a token must not leak the token), but never key-denylisted.

    Scope the denylist to *value* trees (``before``/``after``, outputs, inventory vars). Over configuration
    metadata it destroys what a renderer needs: ``configuration.root_module.variables.db_password`` collapses
    to ``<redacted:key>`` and its ``sensitive: true`` flag with it. Run ``redact_tree(meta, registry)`` with no
    denylist over metadata; the value scrub still applies there.
    """
    denylist = compile_key_denylist(key_denylist)
    return _redact(obj, registry, denylist)


def _redact(obj: Any, registry: SecretRegistry, denylist: Sequence[re.Pattern[str]]) -> Any:
    if isinstance(obj, dict):
        out: dict[Any, Any] = {}
        for k, v in obj.items():
            new_k = registry.redact(k) if isinstance(k, str) else k
            if _key_denied(k, denylist) and v is not None:
                out[new_k] = KEY_PLACEHOLDER
            else:
                out[new_k] = _redact(v, registry, denylist)
        return out
    if isinstance(obj, list):
        return [_redact(v, registry, denylist) for v in obj]
    if isinstance(obj, tuple):
        return tuple(_redact(v, registry, denylist) for v in obj)
    if isinstance(obj, str):
        return registry.redact(obj)
    return obj
