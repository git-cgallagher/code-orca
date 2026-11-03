"""Hermetic AWS for these tests: moto's ``mock_aws`` around every test, fake static credentials, no profile.

A developer's ``AWS_PROFILE`` (aws-vault ``credential_process``) must never engage here: a locked keychain hangs it,
and no botocore timeout covers credential resolution. moto is a dev dependency; the tests skip without it.
"""

from __future__ import annotations

import pytest

moto = pytest.importorskip("moto")

AWS_ENV_DROP = (
    "AWS_PROFILE",
    "AWS_DEFAULT_PROFILE",
    "AWS_SESSION_TOKEN",
    "AWS_SECURITY_TOKEN",
    "AWS_ROLE_ARN",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_ENDPOINT_URL",
)


@pytest.fixture(autouse=True)
def aws(monkeypatch, tmp_path_factory):
    for name in AWS_ENV_DROP:
        monkeypatch.delenv(name, raising=False)
    empty = tmp_path_factory.mktemp("aws-config") / "none"
    empty.write_text("")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(empty))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(empty))
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    with moto.mock_aws():
        yield
