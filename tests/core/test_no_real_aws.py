"""The suite-wide AWS guard (tests/conftest.py) also closes botocore's two legacy credential sources."""

from __future__ import annotations

import os
from pathlib import Path

import pytest


def test_legacy_botocore_credential_sources_are_closed():
    """Review finding: AWS_CREDENTIAL_FILE (OriginalEC2Provider) and BOTO_CONFIG / ~/.boto / /etc/boto.cfg
    (BotoProvider) were still consulted."""
    assert "AWS_CREDENTIAL_FILE" not in os.environ
    boto_config = Path(os.environ["BOTO_CONFIG"])
    assert boto_config.is_file() and boto_config.read_text(encoding="utf-8") == ""


def test_botocore_finds_no_credentials():
    botocore_session = pytest.importorskip("botocore.session")

    assert botocore_session.get_session().get_credentials() is None
