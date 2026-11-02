"""SSM Parameter Store secrets provider (plan section 5.9): ``ssm:/path`` references resolved in process memory.

Every SecureString the orchestrator fetches is registered in the run's ``SecretRegistry`` **before** the value is
returned, so a value can never reach a log, a spec or an output file ahead of the redactor. Rules:

- ``get(ref)`` registers a ``SecureString`` always, and a ``String``/``StringList`` only when ``ref`` is one of the
  project's declared secret references (``stacks.*.secrets``, ``redaction.hmac_key``);
  ``resolve_secret(ref)`` (what the helpers and the terraform/ansible steps call) registers whatever it returns:
  a value fetched as a secret is a secret regardless of its parameter type.
- Values are cached per run in this object's memory only (never on disk, never pickled: ``__reduce__`` raises);
  ``repr`` shows counts only.
- Every AWS call is time-limited twice over: botocore's ``connect_timeout``/``read_timeout`` with
  ``retries={'max_attempts': 2}``, and a wall-clock deadline around the whole call (credential resolution
  included: a ``credential_process`` such as aws-vault hangs silently once the macOS keychain locks, and no botocore
  timeout covers that). On expiry the call is abandoned on a daemon thread and :class:`SSMError` is raised.
- Errors name the parameter and the error code only: never the value, never the service's message or response.
- boto3 is imported lazily (it is the ``aws`` extra); :func:`boto3_available` says whether it is installed.

Region: the ``region`` argument, else boto3's own chain (``AWS_REGION``/``AWS_DEFAULT_REGION``/profile).
``codeorca.providers.make_resolver`` passes ``backend.region`` when the project's backend is s3.
"""

from __future__ import annotations

import importlib.util
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

# The error codes an SSM/S3/STS ClientError may carry are safe to show; the message is not (it can echo input).
_TIMEOUT_ERRORS = ("ConnectTimeoutError", "ReadTimeoutError", "EndpointConnectionError", "ConnectionClosedError")

SessionFactory = Callable[[], Any]


class SSMError(RuntimeError):
    """An SSM parameter could not be fetched. The message names the parameter and a reason code, nothing else."""


class SSMUnavailable(SSMError):
    """boto3 is not installed (``pip install 'code-orca[aws]'``)."""


def boto3_available() -> bool:
    return importlib.util.find_spec("boto3") is not None


def parse_ref(ref: str) -> str:
    """``ssm:/path/name`` -> ``/path/name``; anything else is refused."""
    if not isinstance(ref, str) or not ref.startswith("ssm:/") or len(ref) <= len("ssm:/"):
        raise SSMError(f"not an ssm:/ reference: {ref!r}" if isinstance(ref, str) else "not an ssm:/ reference")
    return ref[len("ssm:") :]


def aws_config(timeout_s: float):
    """The botocore ``Config`` every code-orca AWS client uses (SSM, STS, S3)."""
    from botocore.config import Config

    return Config(connect_timeout=timeout_s, read_timeout=timeout_s, retries={"max_attempts": 2})


def default_session_factory(region: str | None = None) -> SessionFactory:
    def factory():
        if not boto3_available():
            raise SSMUnavailable("boto3 is not installed; install the aws extra: pip install 'code-orca[aws]'")
        import boto3

        return boto3.Session(region_name=region) if region else boto3.Session()

    return factory


def call_with_deadline(
    fn: Callable[[], Any], deadline_s: float, what: str, error: type[Exception] | None = None
) -> Any:
    """Run ``fn`` on a daemon thread and wait at most ``deadline_s``; a hung call is abandoned (the daemon thread
    cannot keep the process alive) and ``error`` (default :class:`SSMError`) names ``what`` only."""
    box: dict[str, Any] = {}

    def target() -> None:
        try:
            box["value"] = fn()
        except BaseException as e:  # noqa: BLE001 - re-raised on the caller's thread
            box["error"] = e

    thread = threading.Thread(target=target, name="codeorca-aws-call", daemon=True)
    thread.start()
    thread.join(deadline_s)
    if thread.is_alive():
        raise (error or SSMError)(f"{what}: no answer within {deadline_s:g} s (credential provider or endpoint hung)")
    if "error" in box:
        raise box["error"]
    return box.get("value")


def describe_error(e: BaseException) -> str:
    """A safe reason for an AWS exception: the ClientError code, or the exception class name. Never the message."""
    response = getattr(e, "response", None)
    if isinstance(response, dict):
        code = (response.get("Error") or {}).get("Code")
        if isinstance(code, str) and code:
            return code
    name = type(e).__name__
    if name in _TIMEOUT_ERRORS:
        return f"{name} (endpoint unreachable or too slow)"
    return name


@dataclass(frozen=True, slots=True, repr=False)
class Fetched:
    """One parameter as fetched. ``repr`` never shows the value."""

    name: str
    value: str
    type: str
    version: int | None

    def __repr__(self) -> str:
        return f"Fetched(name={self.name!r}, type={self.type!r}, version={self.version!r})"

    def __reduce__(self):
        raise TypeError("a fetched SSM parameter is never serialised")


def fetch_parameter(
    ref: str,
    *,
    session_factory: SessionFactory | None = None,
    region: str | None = None,
    timeout_s: float = 10,
    deadline_s: float | None = None,
) -> Fetched:
    """One ``GetParameter`` (``WithDecryption=True``), time-limited; no registry, no cache. The building block of
    :class:`SSMSecrets` and of the redaction-key fetch (which runs before any registry exists)."""
    name = parse_ref(ref)
    factory = session_factory or default_session_factory(region)
    deadline = deadline_s if deadline_s is not None else 4 * timeout_s

    def call() -> dict:
        session = factory()
        kwargs: dict[str, Any] = {"config": aws_config(timeout_s)}
        if region:
            kwargs["region_name"] = region
        client = session.client("ssm", **kwargs)
        return client.get_parameter(Name=name, WithDecryption=True)

    try:
        response = call_with_deadline(call, deadline, f"ssm get_parameter {name}")
    except SSMError:
        raise
    except Exception as e:  # noqa: BLE001 - every failure becomes a value-free SSMError
        raise SSMError(f"ssm get_parameter {name} failed: {describe_error(e)}") from None
    try:
        param = response["Parameter"]
        value = param["Value"]
        ptype = param.get("Type", "String")
        version = param.get("Version")
    except (KeyError, TypeError):
        raise SSMError(f"ssm get_parameter {name}: unexpected response shape") from None
    if not isinstance(value, str):
        raise SSMError(f"ssm get_parameter {name}: value is not a string")
    return Fetched(name=name, value=value, type=str(ptype), version=int(version) if version is not None else None)


class SSMSecrets:
    """``ssm:/`` references for one run, registered before they are returned, cached in memory only."""

    __slots__ = (
        "_cache",
        "_deadline_s",
        "_factory",
        "_region",
        "_registry",
        "_secret_refs",
        "timeout_s",
        "unprotected",
    )

    def __init__(
        self,
        registry,
        *,
        session_factory: SessionFactory | None = None,
        region: str | None = None,
        timeout_s: float = 10,
        deadline_s: float | None = None,
        secret_refs: Iterable[str] = (),
    ) -> None:
        self._registry = registry  # None only for the redaction-key fetch, before the registry exists
        self._factory = session_factory or default_session_factory(region)
        self._region = region
        self.timeout_s = timeout_s
        self._deadline_s = deadline_s
        self._secret_refs = frozenset(secret_refs)
        self._cache: dict[str, Fetched] = {}
        # refs whose value was too short for the registry (nothing scrubs it); names only, for a warning
        self.unprotected: list[str] = []

    def __repr__(self) -> str:
        return f"SSMSecrets(cached={len(self._cache)})"

    __str__ = __repr__

    def __reduce__(self):
        raise TypeError("SSMSecrets holds secret values and is never serialised")

    def __reduce_ex__(self, protocol):
        raise TypeError("SSMSecrets holds secret values and is never serialised")

    def _register(self, ref: str, value: str, *, flag_short: bool = True) -> None:
        if self._registry is None:
            return
        self._registry.add(value)
        if flag_short and len(value.strip()) < self._registry.min_length and ref not in self.unprotected:
            self.unprotected.append(ref)  # too short to register: nothing scrubs it (reported by name only)

    def fetch(self, ref: str, *, as_secret: bool = False) -> Fetched:
        """The parameter (value, type, version), registered per the rules in the module docstring, then cached."""
        cached = self._cache.get(ref)
        if cached is None:
            cached = fetch_parameter(
                ref,
                session_factory=self._factory,
                region=self._region,
                timeout_s=self.timeout_s,
                deadline_s=self._deadline_s,
            )
        if as_secret or cached.type == "SecureString" or ref in self._secret_refs:
            self._register(ref, cached.value)  # BEFORE the value leaves this object
            if cached.type == "StringList":
                for item in cached.value.split(","):
                    self._register(ref, item, flag_short=False)
        self._cache[ref] = cached
        return cached

    def get(self, ref: str) -> str:
        return self.fetch(ref).value

    def resolve_secret(self, ref: str) -> str:
        """For helpers and the terraform/ansible steps: the value, registered whatever its parameter type."""
        return self.fetch(ref, as_secret=True).value
