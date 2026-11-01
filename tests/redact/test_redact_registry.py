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
