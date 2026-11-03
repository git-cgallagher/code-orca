"""SSMSecrets over moto: registration before return, value-free errors, time limits, memory-only cache."""

from __future__ import annotations

import pickle
import sys
import time
from pathlib import Path

import boto3
import pytest

from codeorca import providers
from codeorca.project import load_project
from codeorca.providers import ssm as ssm_mod
from codeorca.providers.ssm import SSMError, SSMSecrets, SSMTimeout, fetch_parameter, parse_ref
from codeorca.redact import SecretRegistry

ROOT = Path(__file__).resolve().parents[2]
PROJECT = load_project(ROOT / "examples" / "reference" / "codeorca.yaml")
SECURE = "FIXTURE-SECRET-ssm-secure-001"
PLAIN = "FIXTURE-SECRET-ssm-plain-0002"


def registry() -> SecretRegistry:
    return SecretRegistry(b"example-not-secret-key", "env:test")


def put(name: str, value: str, ptype: str = "SecureString") -> None:
    boto3.client("ssm", region_name="us-east-1").put_parameter(Name=name, Value=value, Type=ptype, Overwrite=True)


class RecordingSession:
    """Wraps a real boto3 Session and records the kwargs every ``client()`` call got."""

    def __init__(self) -> None:
        self.session = boto3.Session(region_name="us-east-1")
        self.calls: list[tuple[str, dict]] = []

    def client(self, service, **kwargs):
        self.calls.append((service, kwargs))
        return self.session.client(service, **kwargs)


def test_parse_ref_accepts_ssm_refs_only():
    assert parse_ref("ssm:/a/b") == "/a/b"
    for bad in ("/a/b", "ssm:a", "ssm:/", "secretsmanager:/x"):
        with pytest.raises(SSMError):
            parse_ref(bad)


class SpyRegistry(SecretRegistry):
    """Records, at each ``add``, whether the SecureString is already scrubbed and whether ``get`` has returned."""

    def __init__(self) -> None:
        self.returned = False
        self.adds: list[tuple[bool, bool]] = []
        super().__init__(b"example-not-secret-key", "env:test")  # registers the key itself through add()

    def add(self, value):
        result = super().add(value)
        self.adds.append((value == SECURE, self.returned))
        return result


def test_secure_string_is_registered_before_get_returns():
    put("/example/secure", SECURE)
    reg = SpyRegistry()
    value = SSMSecrets(reg).get("ssm:/example/secure")
    reg.returned = True
    assert value == SECURE
    assert (True, False) in reg.adds, "registered inside get(), before the value was returned"
    assert SECURE not in reg.redact(f"x={SECURE}")


def test_plain_string_is_not_registered_by_get_unless_declared_or_resolved_as_secret():
    put("/example/plain", PLAIN, "String")
    reg = registry()
    assert SSMSecrets(reg).get("ssm:/example/plain") == PLAIN
    assert PLAIN in reg.redact(PLAIN)  # a plain String fetched with get(): not a secret

    reg2 = registry()
    SSMSecrets(reg2, secret_refs={"ssm:/example/plain"}).get("ssm:/example/plain")
    assert PLAIN not in reg2.redact(PLAIN)  # declared in the project's secrets: registered

    reg3 = registry()
    assert SSMSecrets(reg3).resolve_secret("ssm:/example/plain") == PLAIN
    assert PLAIN not in reg3.redact(PLAIN)  # fetched as a secret: a secret regardless of type


def test_string_list_items_are_registered_too():
    put("/example/list", f"{SECURE},{PLAIN}", "StringList")
    reg = registry()
    SSMSecrets(reg).resolve_secret("ssm:/example/list")
    out = reg.redact(f"a {SECURE} b {PLAIN}")
    assert SECURE not in out and PLAIN not in out


def test_short_value_is_reported_unprotected_by_ref_only():
    put("/example/short", "abc")
    secrets = SSMSecrets(registry())
    assert secrets.resolve_secret("ssm:/example/short") == "abc"
    assert secrets.unprotected == ["ssm:/example/short"]


def test_missing_parameter_error_names_the_parameter_and_code_only():
    put("/example/other", SECURE)
    with pytest.raises(SSMError) as e:
        SSMSecrets(registry()).get("ssm:/example/missing")
    msg = str(e.value)
    assert "/example/missing" in msg and "ParameterNotFound" in msg
    assert SECURE not in msg
    assert e.value.__cause__ is None and e.value.__suppress_context__


def test_error_from_the_client_never_carries_the_service_message():
    class Boom(Exception):
        def __init__(self):
            super().__init__(f"service said {SECURE}")
            self.response = {"Error": {"Code": "AccessDeniedException", "Message": f"echo {SECURE}"}}

    class Client:
        def get_parameter(self, **_):
            raise Boom()

    class Session:
        def client(self, *_a, **_k):
            return Client()

    with pytest.raises(SSMError) as e:
        SSMSecrets(registry(), session_factory=Session).get("ssm:/example/x")
    assert "AccessDeniedException" in str(e.value) and SECURE not in str(e.value)
    assert e.value.__cause__ is None and e.value.__suppress_context__


def test_clients_get_the_time_limited_config():
    put("/example/secure", SECURE)
    session = RecordingSession()
    SSMSecrets(registry(), session_factory=lambda: session, timeout_s=7).get("ssm:/example/secure")
    service, kwargs = session.calls[0]
    config = kwargs["config"]
    assert service == "ssm"
    assert config.connect_timeout == 7 and config.read_timeout == 7
    # retries={"max_attempts": 2} (two retries); botocore normalises it to three attempts in total
    assert config.retries["total_max_attempts"] == 3


def test_a_hung_credential_provider_hits_the_wall_clock_deadline():
    def hung_factory():
        time.sleep(5)  # stands in for aws-vault waiting on a locked keychain
        raise AssertionError("never reached")

    start = time.monotonic()
    with pytest.raises(SSMError) as e:
        fetch_parameter("ssm:/example/x", session_factory=hung_factory, timeout_s=0.1, deadline_s=0.3)
    assert time.monotonic() - start < 3
    assert "no answer within" in str(e.value) and "/example/x" in str(e.value)


def test_unreachable_endpoint_is_a_value_free_error():
    from botocore.exceptions import EndpointConnectionError

    class Client:
        def get_parameter(self, **_):
            raise EndpointConnectionError(endpoint_url="https://ssm.example.invalid")

    class Session:
        def client(self, *_a, **_k):
            return Client()

    with pytest.raises(SSMError) as e:
        fetch_parameter("ssm:/example/x", session_factory=Session)
    assert "EndpointConnectionError" in str(e.value) and "unreachable" in str(e.value)


def test_cache_is_in_memory_only_and_never_serialised(tmp_path, monkeypatch):
    put("/example/secure", SECURE)
    monkeypatch.chdir(tmp_path)
    calls = {"n": 0}
    session = boto3.Session(region_name="us-east-1")

    def factory():
        calls["n"] += 1
        return session

    secrets = SSMSecrets(registry(), session_factory=factory)
    assert secrets.get("ssm:/example/secure") == SECURE
    assert secrets.get("ssm:/example/secure") == SECURE
    assert calls["n"] == 1  # second get served from the in-memory cache
    assert list(tmp_path.iterdir()) == []  # nothing written anywhere near the run
    assert SECURE not in repr(secrets) and SECURE not in str(secrets)
    with pytest.raises(TypeError):
        pickle.dumps(secrets)
    fetched = secrets.fetch("ssm:/example/secure")
    assert SECURE not in repr(fetched)
    with pytest.raises(TypeError):
        pickle.dumps(fetched)


def test_make_resolver_registers_and_resolves():
    put("/example/app/api-token", SECURE)
    reg = registry()
    resolve = providers.make_resolver(PROJECT, reg)
    assert resolve is not None
    assert resolve("ssm:/example/app/api-token") == SECURE
    assert SECURE not in reg.redact(SECURE)


def test_make_resolver_is_none_without_boto3(monkeypatch):
    monkeypatch.setattr(ssm_mod.importlib.util, "find_spec", lambda name: None)
    monkeypatch.setitem(sys.modules, "boto3", None)
    assert providers.make_resolver(PROJECT, registry()) is None
    assert "aws" in providers.NO_PROVIDER_MESSAGE


def test_declared_refs_and_region():
    stack = PROJECT.stacks["app"].model_copy(update={"secrets": {"EXAMPLE_API_TOKEN": "ssm:/example/app/api-token"}})
    project = PROJECT.model_copy(update={"stacks": {"app": stack}})
    assert providers.declared_secret_refs(project) == {"ssm:/example/app/api-token", "ssm:/codeorca/redaction-key"}
    assert providers.project_region(project) is None  # local backend: boto3's own chain
    backend = project.backend.model_copy(
        update={"type": "s3", "bucket": "b", "region": "eu-west-1", "account_id": "123456789012"}
    )
    assert providers.project_region(project.model_copy(update={"backend": backend})) == "eu-west-1"


def test_after_one_hang_the_run_starts_no_further_credential_process():
    """Review finding: each fetch after a hang built a new session and started another credential_process child
    (abandoned, never killed). One session per run, and a latch: later fetches fail at once."""
    started: list[int] = []

    class HungSession:
        def client(self, *_a, **_k):
            started.append(1)  # stands in for botocore spawning the credential_process
            time.sleep(5)

    factory_calls: list[int] = []

    def factory():
        factory_calls.append(1)
        return HungSession()

    secrets = SSMSecrets(None, session_factory=factory, timeout_s=0.05, deadline_s=0.2)
    with pytest.raises(SSMTimeout):
        secrets.resolve_secret("ssm:/example/a")
    begin = time.monotonic()
    with pytest.raises(SSMTimeout, match="an earlier AWS call in this run hung"):
        secrets.resolve_secret("ssm:/example/b")
    assert time.monotonic() - begin < 0.1
    assert started == [1] and factory_calls == [1]


def test_one_session_serves_every_fetch_of_a_run():
    class Client:
        def get_parameter(self, Name, **_):
            return {"Parameter": {"Value": f"value-of-{Name}", "Type": "String", "Version": 1}}

    class Session:
        def client(self, *_a, **_k):
            return Client()

    made: list[int] = []
    secrets = SSMSecrets(None, session_factory=lambda: made.append(1) or Session())
    assert secrets.get("ssm:/example/a") == "value-of-/example/a"
    assert secrets.get("ssm:/example/b") == "value-of-/example/b"
    assert made == [1]
