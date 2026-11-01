"""entropy_warnings: flags long high-entropy tokens, skips the obvious non-secrets, never prints the token."""

from __future__ import annotations

from codeorca.redact import SecretRegistry, entropy_warnings, redact_text

HIGH = "aGVsbG8gd29ybGQgdGhpcyBpcyBhIGxvbmcgYmFzZTY0IHN0cmluZyB3aXRoIGVudHJvcHk="  # base64, 72 chars
HEX_SECRET = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a0812"  # 66 hex: not a checksum length


def test_flags_high_entropy_tokens_with_line_numbers_and_redacted_snippets():
    text = f"first line fine\nkey: {HIGH}\nthird\nhex: {HEX_SECRET}\n"
    found = entropy_warnings(text)
    assert [ln for ln, _ in found] == [2, 4]
    for _, snippet in found:
        assert HIGH not in snippet and HEX_SECRET not in snippet
        assert snippet.endswith(" chars)") and len(snippet) < 20


def test_allowlists_arns_uuids_and_checksums():
    text = "\n".join(
        [
            "arn:aws:iam::123456789012:role/abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH",
            "arn:aws:kms:us-east-1:123456789012:key/0123abcd-ef45-6789-abcd-0123456789ab",
            "id: 3f2504e0-4f89-41d3-9a0c-0305e82c3301",
            "sha256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            "git: 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
            "md5: 9e107d9d372bb6826bd81d3542a419d6",
            "ph: <redacted:hmac:9f86d081> <redacted:key>",
            "low: " + "a" * 40 + " " + "ab" * 20,
        ]
    )
    assert entropy_warnings(text) == []


def test_short_tokens_are_not_flagged():
    dense = "Zx9Qw3Lp7Rt2Vb5Nm8Kc1Jh4Gf6Dd0Sa"  # 32 distinct characters
    assert len(dense) == 32
    assert entropy_warnings("x " + dense[:31] + "\n") == []
    assert entropy_warnings("x " + dense + "\n") != []


def test_placeholders_do_not_trip_the_scan(key, key_id):
    reg = SecretRegistry(key, key_id)
    reg.add(HIGH)
    out = redact_text(f"token {HIGH} end\n", reg)
    assert entropy_warnings(out) == []


def test_empty_and_blank_input():
    assert entropy_warnings("") == []
    assert entropy_warnings("\n\n  \n") == []
