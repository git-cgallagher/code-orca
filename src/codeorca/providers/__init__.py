"""Secret providers (plan section 5.9). v1 has one: AWS SSM Parameter Store (:mod:`codeorca.providers.ssm`).

Integration entry points:

- :func:`make_resolver` ``(project, registry) -> Callable[[str], str] | None``: the ``resolve_secret(ref)`` callable
  the helpers (``env: {X: {secret: ssm:/…}}``) and the terraform/ansible steps use; every value it returns is
  registered in ``registry`` first. ``None`` when boto3 is not installed: the step that needs a secret then fails
  with :data:`NO_PROVIDER_MESSAGE`.
- :func:`make_secrets` the same, returning the :class:`SSMSecrets` object (``unprotected`` lists refs whose value
  was too short to register).

Failures raise :class:`SSMError` (message: parameter name + reason code, never the value).
"""

from __future__ import annotations

from collections.abc import Callable

from codeorca.providers.ssm import (
    SSMError,
    SSMSecrets,
    SSMTimeout,
    SSMUnavailable,
    boto3_available,
    fetch_parameter,
)

NO_PROVIDER_MESSAGE = (
    "this step needs an ssm:/ secret but boto3 is not installed; install the aws extra: pip install 'code-orca[aws]'"
)

__all__ = [
    "NO_PROVIDER_MESSAGE",
    "SSMError",
    "SSMSecrets",
    "SSMTimeout",
    "SSMUnavailable",
    "boto3_available",
    "declared_secret_refs",
    "fetch_parameter",
    "make_resolver",
    "make_secrets",
    "project_region",
]


def declared_secret_refs(project) -> set[str]:
    """Every ``ssm:/`` reference the project declares as a secret: ``stacks.*.secrets`` and ``redaction.hmac_key``."""
    refs: set[str] = set()
    if project is None:
        return refs
    for stack in project.stacks.values():
        refs.update(stack.secrets.values())
    if project.redaction.hmac_key:
        refs.add(project.redaction.hmac_key)
    return refs


def project_region(project) -> str | None:
    """``backend.region`` for an s3 backend; otherwise ``None`` (boto3's own region chain applies)."""
    if project is not None and project.backend.type == "s3":
        return project.backend.region
    return None


def make_secrets(project, registry, *, session_factory=None, timeout_s: float = 10) -> SSMSecrets | None:
    if session_factory is None and not boto3_available():
        return None
    return SSMSecrets(
        registry,
        session_factory=session_factory,
        region=project_region(project),
        timeout_s=timeout_s,
        secret_refs=declared_secret_refs(project),
    )


def make_resolver(project, registry, *, session_factory=None, timeout_s: float = 10) -> Callable[[str], str] | None:
    secrets = make_secrets(project, registry, session_factory=session_factory, timeout_s=timeout_s)
    return None if secrets is None else secrets.resolve_secret
