"""Redaction pipeline: the component that makes committed specs and run logs safe to share.

Terraform's sensitivity flags (``after_sensitive``, ``before_sensitive``, ``sensitive_values``,
``outputs.*.sensitive``) are correct but incomplete: a computed attribute echoing a sensitive input is
unmarked, ``nonsensitive()``, ephemeral-variable defaults and the plan's ``variables`` block all leak, and the
apply ``-json`` stream behaves differently from its docs. Ansible ``fail:`` messages leak past ``no_log``
and ``ANSIBLE_DEBUG=1`` bypasses ``no_log`` entirely. So the pipeline has six stages, each catching what the
previous cannot (design plan section 5.7):

1. **Structural masking** from Terraform's own maps and provider-schema paths (``sensitive``/``write_only``,
   walking ``nested_type`` and ``block_types``): :func:`mask_by_map`, :func:`merge_unknown`,
   :func:`schema_sensitive_paths`, :func:`mask_by_schema`. ``never_render`` entries are dropped by the
   caller before this stage.
2. **SecretRegistry** (:class:`SecretRegistry`): every known secret value, in process memory only, seeded
   from every leaf at a sensitive path (:func:`sensitive_leaves`), sensitive variable values, vaulted
   Ansible values, every SecureString the orchestrator fetches, env tokens and the project's ``secrets:``
   list. Minimum length 8; matched in raw, JSON-escaped, URL-quoted and base64 forms, longest first.
3. **Value scrub** over the *whole* rendered document, after rendering (:func:`redact_tree`,
   :func:`redact_text`), and a chunk-safe :class:`StreamRedactor` on every subprocess stream.
4. **Key-regex denylist** (``redact_tree(..., key_denylist=...)``, :data:`DEFAULT_KEY_DENYLIST`): a bare
   ``key`` pattern is refused, it would hit ``ssh_key_file`` and ``GPG_KEY``.
5. **Entropy scan** (:func:`entropy_warnings`): warnings only.
6. **Gate** (:func:`scan_outputs`): a registry hit in any output file is a hard failure, reported as path
   and count only.

Placeholders are ``<redacted:hmac:8hex>`` = HMAC-SHA256(key, value)[:8] (``sha256`` only when a project
asks for it explicitly): stable per key and value, so a spec diff shows that a secret *changed* without
showing it, and keyed so a short secret is not an offline brute-force oracle.

**Residual risk, stated plainly** (plan section 5.7): until ansible-core 2.22's source-side masking, the
pipeline catches only *declared or discovered* values (registry seeds, flag maps, key patterns). An
undeclared secret that a role interpolates into a ``fail:`` or ``debug:`` message, or that arrives through a
lookup the orchestrator never saw, is not caught. Mitigations: the lookup deny-list, the lint that forbids
``debug var=hostvars[...]``, ``no_log`` on every task that handles a secret, and the entropy warnings.
Two smaller limits of this implementation: text a :class:`StreamRedactor` has already emitted cannot be
fixed by a later registration (register before the process starts), and when one registered value is a
proper prefix or suffix of another that starts earlier in the text, the regex replaces the leftmost match,
so a fragment of the longer value can survive (register the longer value on its own, not as an overlap).
"""

from __future__ import annotations

from codeorca.redact.entropy import entropy_warnings
from codeorca.redact.gate import scan_outputs
from codeorca.redact.registry import PLACEHOLDER_RE, SecretRegistry
from codeorca.redact.stream import StreamRedactor
from codeorca.redact.terraform import (
    SENSITIVE,
    UNKNOWN,
    mask_by_map,
    mask_by_schema,
    merge_unknown,
    schema_sensitive_paths,
    sensitive_leaves,
)
from codeorca.redact.text import DEFAULT_KEY_DENYLIST, KEY_PLACEHOLDER, compile_key_denylist, redact_text, redact_tree

__all__ = [
    "DEFAULT_KEY_DENYLIST",
    "KEY_PLACEHOLDER",
    "PLACEHOLDER_RE",
    "SENSITIVE",
    "UNKNOWN",
    "SecretRegistry",
    "StreamRedactor",
    "compile_key_denylist",
    "entropy_warnings",
    "mask_by_map",
    "mask_by_schema",
    "merge_unknown",
    "redact_text",
    "redact_tree",
    "scan_outputs",
    "schema_sensitive_paths",
    "sensitive_leaves",
]
