"""Run-wide redaction wiring: one ``SecretRegistry`` per run, seeded before any subprocess starts.

Phase 1 has no SSM wrapper, so the HMAC key comes from the environment variable ``CODEORCA_REDACTION_KEY``
(its UTF-8 bytes); the key id recorded in spec headers is ``env:<sha256(key)[:8]>``. The SSM-backed key named by
``redaction.hmac_key`` arrives in Phase 3. A project whose ``redaction.placeholder`` is ``hmac`` fails closed when
the variable is absent; ``sha256`` mode needs no key.

Seeds (values only; names are recorded nowhere):

- the well-known cloud session tokens (``AWS_SECRET_ACCESS_KEY``, ``AWS_SESSION_TOKEN``);
- every name in a stack's ``secrets:`` and ``required_env`` that is present in the environment;
- workflow input values whose *name* matches the project's key denylist (``app_secret``, ``api_token`` ...), so
  a secret handed in on ``--input`` is scrubbed from run.json, logs and specs from the first persist on.

The two hooks the runner and the Terraform adapter take are built here too: ``line_hook`` for
``Runner(stream=...)`` (every stdout/stderr line any executor writes goes through ``registry.redact``) and
``terraform_stream`` for ``TerraformRunner(stream=...)`` (a chunk-safe ``StreamRedactor`` per channel).
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from codeorca.project import Project
from codeorca.redact import DEFAULT_KEY_DENYLIST, SecretRegistry, StreamRedactor, compile_key_denylist, redact_tree

KEY_ENV_VAR = "CODEORCA_REDACTION_KEY"
ENV_TOKEN_NAMES: tuple[str, ...] = ("AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN")


class RedactionKeyMissing(RuntimeError):
    """``placeholder: hmac`` but no key is available in this phase."""


def key_id_for(key: bytes) -> str:
    return "env:" + hashlib.sha256(key).hexdigest()[:8]


def key_denylist(project: Project | None) -> tuple[str, ...]:
    """The project's ``redaction.key_denylist`` or the package default when the project lists none."""
    if project is not None and project.redaction.key_denylist:
        return tuple(project.redaction.key_denylist)
    return DEFAULT_KEY_DENYLIST


def env_secret_names(project: Project | None) -> set[str]:
    """Environment variable NAMES whose values are secrets: the cloud tokens plus every stack's ``secrets:`` and
    ``required_env`` entries."""
    names = set(ENV_TOKEN_NAMES)
    if project is not None:
        for stack in project.stacks.values():
            names.update(stack.secrets)
            names.update(stack.required_env)
    return names


def build_registry(project: Project | None, env: Mapping[str, str]) -> SecretRegistry:
    """The run's registry: key from ``CODEORCA_REDACTION_KEY`` (hmac) and seeds from the environment."""
    mode = project.redaction.placeholder if project is not None else "hmac"
    raw = env.get(KEY_ENV_VAR)
    if mode == "hmac":
        if not raw:
            raise RedactionKeyMissing(
                f"redaction.placeholder is hmac but {KEY_ENV_VAR} is not set; in this phase the HMAC key comes "
                "from that environment variable (the SSM-backed key named by redaction.hmac_key arrives in Phase 3)"
            )
        key = raw.encode("utf-8")
        registry = SecretRegistry(key, key_id_for(key), mode="hmac")
    else:
        key = raw.encode("utf-8") if raw else b""
        registry = SecretRegistry(key, key_id_for(key) if key else "none", mode="sha256")
    seed_from_env(registry, project, env)
    return registry


def seed_from_env(registry: SecretRegistry, project: Project | None, env: Mapping[str, str]) -> int:
    """Register the values of every secret-bearing environment variable that is set. Returns how many were set."""
    seeded = 0
    for name in sorted(env_secret_names(project)):
        value = env.get(name)
        if value:
            registry.add(value)
            seeded += 1
    return seeded


def seed_inputs(registry: SecretRegistry, inputs: Mapping[str, Any], denylist: Iterable[str]) -> list[str]:
    """Register the values of inputs whose name matches the key denylist; returns the matching names."""
    patterns = compile_key_denylist(denylist)
    matched: list[str] = []
    for name, value in inputs.items():
        if any(p.search(name) for p in patterns):
            matched.append(name)
            for leaf in _leaves(value):
                registry.add(leaf)
    return sorted(matched)


def _leaves(value: Any):
    if isinstance(value, dict):
        for v in value.values():
            yield from _leaves(v)
    elif isinstance(value, list | tuple):
        for v in value:
            yield from _leaves(v)
    elif value is None or isinstance(value, bool):
        return
    else:
        yield str(value)


def line_hook(registry: SecretRegistry) -> Callable[[str, str], str]:
    """For ``Runner(stream=...)``: ``hook(channel, line) -> redacted line``."""

    def hook(_channel: str, line: str) -> str:
        return registry.redact(line)

    return hook


def record_filter(registry: SecretRegistry, denylist: Iterable[str]) -> Callable[[Any], Any]:
    """For ``Runner(redact=...)``: the registry scrub over a whole record, plus the key denylist over its ``inputs``
    and ``vars`` (value trees); step ids and result keys are never denylisted."""
    patterns = tuple(denylist)

    def _filter(record: Any) -> Any:
        if isinstance(record, dict):
            out = dict(record)
            for key in ("inputs", "vars"):
                if key in out:
                    out[key] = redact_tree(out[key], registry, patterns)
            return redact_tree(out, registry)
        return redact_tree(record, registry)

    return _filter


def terraform_stream(
    registry: SecretRegistry, sink: Callable[[str, str], None]
) -> tuple[Callable[[str, str], None], Callable[[], None]]:
    """For ``TerraformRunner(stream=...)``: ``(callback, flush)``. The callback takes ``(line, channel)`` as the
    adapter emits it; redacted whole lines reach ``sink(channel, line)``. Call ``flush`` after each command."""
    redactors = {"stdout": StreamRedactor(registry), "stderr": StreamRedactor(registry)}

    def _emit(channel: str, text: str) -> None:
        for line in text.splitlines():
            sink(channel, line)

    def callback(line: str, channel: str) -> None:
        redactor = redactors.setdefault(channel, StreamRedactor(registry))
        _emit(channel, redactor.feed(line))

    def flush() -> None:
        for channel, redactor in redactors.items():
            _emit(channel, redactor.flush())

    return callback, flush
