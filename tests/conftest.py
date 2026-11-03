"""Suite-wide guard: no test ever reaches real AWS.

The CLI builds its registry with the SSM-backed redaction key fetcher (``ssm_key_fetcher``) and an SSM resolver, so a
test that runs ``codeorca`` without ``CODEORCA_REDACTION_KEY`` on a project naming ``redaction.hmac_key`` would ask
SSM with whatever credentials the developer's shell has (an aws-vault ``credential_process`` hangs silently once the
keychain locks, and no botocore timeout covers credential resolution). Every test therefore runs with the AWS
profile, role, container and static-key variables removed (``AWS_CREDENTIAL_FILE`` too),
``AWS_CONFIG_FILE``/``AWS_SHARED_CREDENTIALS_FILE``/``BOTO_CONFIG`` pointing at an empty file (``BOTO_CONFIG``
replaces the legacy ``~/.boto`` and ``/etc/boto.cfg`` lookup) and the instance metadata service disabled:
botocore then finds no credentials and fails before any request. The moto conftests (``tests/providers``,
``tests/bootstrap``) set their own fake keys on top.

``no_boto3_session`` makes boto3 session creation itself raise (and counts the attempts) for tests that must prove
no AWS call was even attempted.
"""

from __future__ import annotations

import pytest

AWS_ENV_DROP = (
    "AWS_PROFILE",
    "AWS_DEFAULT_PROFILE",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_SECURITY_TOKEN",
    "AWS_ROLE_ARN",
    "AWS_ROLE_SESSION_NAME",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "AWS_ENDPOINT_URL",
    "AWS_ENDPOINT_URL_SSM",
    "AWS_VAULT",
    "AWS_CREDENTIAL_FILE",  # botocore's legacy OriginalEC2Provider reads keys from this file
)


@pytest.fixture(autouse=True)
def _no_real_aws(monkeypatch, tmp_path_factory):
    for name in AWS_ENV_DROP:
        monkeypatch.delenv(name, raising=False)
    empty = tmp_path_factory.getbasetemp() / "aws-config-empty"
    if not empty.exists():
        empty.write_text("", encoding="utf-8")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(empty))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(empty))
    # botocore's legacy BotoProvider reads BOTO_CONFIG, else ~/.boto and /etc/boto.cfg: point it at the empty file
    monkeypatch.setenv("BOTO_CONFIG", str(empty))
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setenv("AWS_METADATA_SERVICE_TIMEOUT", "1")
    monkeypatch.setenv("AWS_METADATA_SERVICE_NUM_ATTEMPTS", "1")


@pytest.fixture
def no_boto3_session(monkeypatch) -> list[tuple]:
    """boto3 session creation raises; the returned list records every attempt (empty = no AWS call attempted)."""
    attempts: list[tuple] = []
    boto3 = pytest.importorskip("boto3")

    class NoNetwork(RuntimeError):
        pass

    def refuse(*args, **kwargs):
        attempts.append((args, kwargs))
        raise NoNetwork("boto3 session creation is refused in tests (no network)")

    monkeypatch.setattr(boto3, "Session", refuse)
    return attempts
