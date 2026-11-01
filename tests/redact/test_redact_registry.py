"""SecretRegistry: placeholders, encodings, minimum length, no serialisation, no value in repr."""

from __future__ import annotations

import copy
import pickle
import re

import pytest

from codeorca.redact import PLACEHOLDER_RE, SecretRegistry, redact_text


def test_placeholder_stable_for_same_value_and_differs_for_changed_value(key, key_id):
    a, b = SecretRegistry(key, key_id), SecretRegistry(key, key_id)
    assert a.placeholder("FIXTURE-SECRET-abc123") == b.placeholder("FIXTURE-SECRET-abc123")
    assert a.placeholder("FIXTURE-SECRET-abc123") != a.placeholder("FIXTURE-SECRET-abc124")
    assert re.fullmatch(r"<redacted:hmac:[0-9a-f]{8}>", a.placeholder("FIXTURE-SECRET-abc123"))
    assert PLACEHOLDER_RE.fullmatch(a.placeholder("FIXTURE-SECRET-abc123"))


def test_placeholder_depends_on_key(key):
    assert SecretRegistry(b"other-key", "k2").placeholder("x" * 20) != SecretRegistry(key, "k1").placeholder("x" * 20)


def test_placeholder_matches_between_add_path_and_direct_call(registry):
    registry.add("  FIXTURE-SECRET-padded  ")  # normalised on registration
    ph = registry.placeholder("FIXTURE-SECRET-padded")
    assert redact_text("v=FIXTURE-SECRET-padded;", registry) == f"v={ph};"
    assert registry.placeholder("  FIXTURE-SECRET-padded  ") == ph


def test_sha256_mode_only_when_asked(key, key_id):
    reg = SecretRegistry(key, key_id, mode="sha256")
    assert re.fullmatch(r"<redacted:sha256:[0-9a-f]{8}>", reg.placeholder("FIXTURE-SECRET-abc123"))
    assert SecretRegistry(key, key_id).placeholder("x").startswith("<redacted:hmac:")
    with pytest.raises(ValueError):
        SecretRegistry(key, key_id, mode="md5")
    with pytest.raises(ValueError):
        SecretRegistry(b"", key_id)  # an empty HMAC key is a plain hash


def test_short_values_are_ignored(registry):
    before = registry.size
    registry.add("ab")
    registry.add("1234567")
    assert registry.size == before
    assert redact_text("cab table 1234567", registry) == "cab table 1234567"
    registry.add("12345678")
    assert registry.size == before + 1
    assert "12345678" not in redact_text("x 12345678 y", registry)


def test_min_length_is_configurable(key, key_id):
    reg = SecretRegistry(key, key_id, min_length=4)
    reg.add("abcd")
    assert "abcd" not in redact_text("x abcd y", reg)


def test_every_encoding_of_a_registered_value_is_matched(registry, encode):
    value = 'FIXTURE-SECRET-"quoted"/slash+plus ünï'
    registry.add(value)
    ph = registry.placeholder(value)
    for name, enc in encode(value).items():
        assert redact_text(f"[{enc}]", registry) == f"[{ph}]", name
    assert "FIXTURE" not in redact_text(" ".join(encode(value).values()), registry)


def test_none_ignored_and_containers_refused(registry):
    registry.add(None)
    for bad in ({"a": "FIXTURE-SECRET-x"}, ["FIXTURE-SECRET-x"], True, b"FIXTURE-SECRET-x"):
        with pytest.raises(TypeError):
            registry.add(bad)  # type: ignore[arg-type]
    registry.add(123456789)  # numeric leaf of a sensitive map
    assert "123456789" not in redact_text("id=123456789", registry)


def test_the_key_itself_is_registered(registry, key):
    assert key.decode() not in redact_text(f"key is {key.decode()}!", registry)


def test_registry_never_pickles_or_copies(registry):
    registry.add("FIXTURE-SECRET-abc123")
    for fn in (pickle.dumps, copy.copy, copy.deepcopy):
        with pytest.raises(TypeError):
            fn(registry)


def test_repr_shows_only_the_count(registry, key, key_id):
    registry.add("FIXTURE-SECRET-abc123")
    for text in (repr(registry), str(registry)):
        assert "FIXTURE" not in text and key.decode() not in text and key_id not in text
        assert "size=2" in text  # the key and the value
    assert registry.size == 2
    assert registry.key_id == key_id


def test_pattern_cache_follows_growth(registry):
    g0 = registry.generation
    assert registry.max_len() > 0  # the key is registered
    registry.add("FIXTURE-SECRET-much-longer-than-the-key-text-is")
    assert registry.generation > g0
    assert registry.max_len() >= len("FIXTURE-SECRET-much-longer-than-the-key-text-is")
    registry.add("FIXTURE-SECRET-much-longer-than-the-key-text-is")  # duplicate: no growth
    assert registry.generation == g0 + 1


def test_add_reports_whether_the_value_was_accepted(registry):
    assert registry.add("FIXTURE-SECRET-accepted") is True
    assert registry.add("FIXTURE-SECRET-accepted") is False  # already known
    assert registry.add("short") is False  # below min_length: nothing protects it, the caller must know
    assert registry.add(None) is False


def test_multiline_value_registers_each_line_too(registry):
    pem = (
        "-----BEGIN FIXTURE PRIVATE KEY-----\nFIXTUREAAAAB3NzaC1yc2E\nFIXTURECCCCB3NzaC1yc2E\n"
        "-----END FIXTURE PRIVATE KEY-----"
    )
    assert registry.add(pem) is True
    # the whole value is one placeholder; a single line printed on its own (a line-by-line log) is matched as well
    assert redact_text(pem, registry) == registry.placeholder(pem)
    assert "FIXTUREAAAA" not in redact_text("FIXTUREAAAAB3NzaC1yc2E\n", registry)
    assert redact_text("-----END FIXTURE PRIVATE KEY-----", registry) == registry.placeholder(
        "-----END FIXTURE PRIVATE KEY-----"
    )
    assert "FIXTURE" not in "\n".join(redact_text(line, registry) for line in pem.splitlines())


def test_go_html_safe_json_escaping_is_an_encoding(registry):
    """Terraform's -json output (Go encoding/json) escapes <, > and & as \\u003c, \\u003e, \\u0026."""
    value = 'FIXTURE<&>"-33333333'
    registry.add(value)
    go = '{"value":"FIXTURE\\u003c\\u0026\\u003e\\"-33333333"}'
    assert go.count("\\u003c") == 1 and value not in go
    ph = registry.placeholder(value)
    assert redact_text(go, registry) == f'{{"value":"{ph}"}}'
    assert registry.count_matches(go) == 1  # the gate sees the Go form too
    from codeorca.redact import StreamRedactor

    s = StreamRedactor(registry)
    assert s.feed(go + "\n") + s.flush() == f'{{"value":"{ph}"}}\n'
