"""The SSM-backed redaction key: key id ``<ref>@<version>``, the env var only when set, fail closed otherwise."""

from __future__ import annotations

import sys
from pathlib import Path

import boto3
import pytest

from codeorca.project import load_project
from codeorca.providers import ssm as ssm_mod
from codeorca.secrets import KEY_ENV_VAR, RedactionKeyMissing, build_registry, key_id_for, ssm_key_fetcher

ROOT = Path(__file__).resolve().parents[2]
PROJECT = load_project(ROOT / "examples" / "reference" / "codeorca.yaml")
REF = PROJECT.redaction.hmac_key  # ssm:/codeorca/redaction-key
KEY = "FIXTURE-SECRET-redaction-key-001"
ENV_KEY = "example-not-secret-env-key"


def put_key(value: str = KEY, ptype: str = "SecureString", times: int = 1) -> None:
    client = boto3.client("ssm", region_name="us-east-1")
    for _ in range(times):
        client.put_parameter(Name=REF[len("ssm:") :], Value=value, Type=ptype, Overwrite=True)


def test_key_from_ssm_has_ref_at_version_id_and_is_registered():
    put_key(times=3)  # version 3
    registry = build_registry(PROJECT, {}, key_fetcher=ssm_key_fetcher(PROJECT))
    assert registry.key_id == f"{REF}@3"
    assert KEY not in registry.key_id
    assert KEY not in registry.redact(f"key={KEY}")
    assert registry.mode == "hmac"


def test_placeholders_depend_on_the_ssm_key():
    put_key()
    a = build_registry(PROJECT, {}, key_fetcher=ssm_key_fetcher(PROJECT))
    b = build_registry(PROJECT, {KEY_ENV_VAR: ENV_KEY})
    value = "FIXTURE-SECRET-some-value-01"
    assert a.placeholder(value) != b.placeholder(value)


def test_explicit_env_var_wins_and_ssm_is_never_called():
    calls: list[str] = []

    def fetcher(ref):
        calls.append(ref)
        raise AssertionError("SSM must not be called when the env var is set")

    registry = build_registry(PROJECT, {KEY_ENV_VAR: ENV_KEY}, key_fetcher=fetcher)
    assert calls == []
    assert registry.key_id == key_id_for(ENV_KEY.encode())


def test_failed_fetch_without_env_var_fails_closed_naming_the_parameter():
    # nothing stored in moto: ParameterNotFound
    with pytest.raises(RedactionKeyMissing) as e:
        build_registry(PROJECT, {}, key_fetcher=ssm_key_fetcher(PROJECT))
    msg = str(e.value)
    assert REF[len("ssm:") :] in msg and "ParameterNotFound" in msg and KEY_ENV_VAR in msg
    assert e.value.__cause__ is None


def test_failure_message_never_carries_a_value():
    def fetcher(ref):
        raise RuntimeError(f"leaky {KEY}")

    with pytest.raises(RedactionKeyMissing) as e:
        build_registry(PROJECT, {}, key_fetcher=fetcher)
    assert KEY not in str(e.value) and "RuntimeError" in str(e.value)


def test_a_plain_string_key_parameter_is_refused():
    put_key(ptype="String")
    with pytest.raises(RedactionKeyMissing) as e:
        build_registry(PROJECT, {}, key_fetcher=ssm_key_fetcher(PROJECT))
    assert "SecureString" in str(e.value) and KEY not in str(e.value)


def test_no_fetcher_and_no_env_var_fails_closed():
    with pytest.raises(RedactionKeyMissing) as e:
        build_registry(PROJECT, {})
    assert REF in str(e.value) and KEY_ENV_VAR in str(e.value)


def test_without_boto3_there_is_no_fetcher(monkeypatch):
    monkeypatch.setattr(ssm_mod.importlib.util, "find_spec", lambda name: None)
    monkeypatch.setitem(sys.modules, "boto3", None)
    assert ssm_key_fetcher(PROJECT) is None


def test_hung_ssm_fails_closed_within_the_deadline():
    import time

    def hung():
        time.sleep(5)

    fetcher = ssm_key_fetcher(PROJECT, session_factory=hung, timeout_s=0.05)
    start = time.monotonic()
    with pytest.raises(RedactionKeyMissing) as e:
        build_registry(PROJECT, {}, key_fetcher=fetcher)
    assert time.monotonic() - start < 3 and "no answer within" in str(e.value)
