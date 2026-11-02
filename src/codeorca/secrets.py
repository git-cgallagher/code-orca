"""Run-wide redaction wiring: one ``SecretRegistry`` per run, seeded before any subprocess starts.

The HMAC key (``redaction.placeholder: hmac``) is resolved in this order, and never any other way:

1. ``CODEORCA_REDACTION_KEY`` when it is set (the explicit override, kept from Phase 1): its UTF-8 bytes, key id
   ``env:<sha256(key)[:8]>``. SSM is not called at all, so a run with the variable set is deterministic and never
   touches a credential provider.
2. Otherwise the SSM SecureString named by ``redaction.hmac_key``, fetched through
   :func:`codeorca.providers.ssm.fetch_parameter` (time-limited) when the caller passes ``key_fetcher`` (the CLI does,
   see :func:`ssm_key_fetcher`): key id ``<ref>@<version>`` (the spec header names the key and its version, never its
   value). A parameter that is not a SecureString is refused.
3. Anything else fails closed (:class:`RedactionKeyMissing`) with a message naming the parameter (never a value):
   a failed fetch never falls back silently to another key.

``sha256`` mode needs no key.

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
    """``placeholder: hmac`` but no key could be resolved (the message names the parameter, never a value)."""


# ``key_fetcher(ref) -> (key bytes, key id)``; raises on any failure.
KeyFetcher = Callable[[str], tuple[bytes, str]]


def key_id_for(key: bytes) -> str:
    return "env:" + hashlib.sha256(key).hexdigest()[:8]


def ssm_key_fetcher(
    project: Project | None = None, *, session_factory=None, timeout_s: float = 10
) -> KeyFetcher | None:
    """The SSM-backed key fetcher for :func:`build_registry`, or ``None`` when boto3 is not installed (and no
    ``session_factory`` is injected). Region: ``backend.region`` for an s3 backend, else boto3's chain."""
    from codeorca.providers import project_region
    from codeorca.providers.ssm import boto3_available, fetch_parameter

    if session_factory is None and not boto3_available():
        return None
    region = project_region(project)

    def fetch(ref: str) -> tuple[bytes, str]:
        param = fetch_parameter(ref, session_factory=session_factory, region=region, timeout_s=timeout_s)
        if param.type != "SecureString":
            raise RedactionKeyMissing(
                f"redaction.hmac_key {ref} is a {param.type} parameter; the redaction key must be a SecureString"
            )
        if not param.value:
            raise RedactionKeyMissing(f"redaction.hmac_key {ref} is empty")
        version = param.version if param.version is not None else "unknown"
        return param.value.encode("utf-8"), f"{ref}@{version}"

    return fetch


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


def build_registry(
    project: Project | None, env: Mapping[str, str], *, key_fetcher: KeyFetcher | None = None
) -> SecretRegistry:
    """The run's registry: the HMAC key (order in the module docstring) and seeds from the environment.

    ``key_fetcher`` is how the SSM-backed key is reached (``ssm_key_fetcher(project)``); without it only the
    environment variable can supply the key."""
    mode = project.redaction.placeholder if project is not None else "hmac"
    raw = env.get(KEY_ENV_VAR)
    if mode == "hmac":
        key, key_id = _resolve_hmac_key(project, raw, key_fetcher)
        registry = SecretRegistry(key, key_id, mode="hmac")  # registers the key's own text too
    else:
        key = raw.encode("utf-8") if raw else b""
        registry = SecretRegistry(key, key_id_for(key) if key else "none", mode="sha256")
    seed_from_env(registry, project, env)
    return registry


def _resolve_hmac_key(project: Project | None, raw: str | None, key_fetcher: KeyFetcher | None) -> tuple[bytes, str]:
    if raw:
        key = raw.encode("utf-8")
        return key, key_id_for(key)
    ref = project.redaction.hmac_key if project is not None else None
    if not ref:
        raise RedactionKeyMissing(
            f"redaction.placeholder is hmac but no redaction.hmac_key and {KEY_ENV_VAR} is not set"
        )
    if key_fetcher is None:
        raise RedactionKeyMissing(
            f"redaction.placeholder is hmac: the key {ref} cannot be fetched (no SSM provider: install the aws extra, "
            f"pip install 'code-orca[aws]') and {KEY_ENV_VAR} is not set"
        )
    from codeorca.providers.ssm import SSMError

    try:
        return key_fetcher(ref)
    except RedactionKeyMissing:
        raise
    except SSMError as e:  # the message names the parameter and a reason code only
        raise RedactionKeyMissing(
            f"could not fetch the redaction key {ref}: {e}; refusing to run without it (set {KEY_ENV_VAR} to supply "
            "an explicit key instead)"
        ) from None
    except Exception as e:  # noqa: BLE001 - fail closed, naming the parameter and the error class only
        raise RedactionKeyMissing(
            f"could not fetch the redaction key {ref}: {type(e).__name__}; refusing to run without it (set "
            f"{KEY_ENV_VAR} to supply an explicit key instead)"
        ) from None


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
