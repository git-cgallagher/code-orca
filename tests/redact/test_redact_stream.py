"""StreamRedactor: whole lines out, secrets split across chunks caught, registry growth mid-stream honoured."""

from __future__ import annotations

import json
import urllib.parse

from codeorca.redact import PLACEHOLDER_RE, StreamRedactor
from codeorca.redact.stream import MAX_HELD_LINE


def pump(sr: StreamRedactor, text: str, size: int) -> str:
    return "".join(sr.feed(text[i : i + size]) for i in range(0, len(text), size)) + sr.flush()


def test_secret_split_across_chunks_in_every_encoding(registry):
    s = 'FIXTURE-SECRET-"quoted"/slash'
    registry.add(s)
    text = f"raw: {s} json: {json.dumps(s)} url: {urllib.parse.quote(s, safe='')}\nnext line\n"
    for size in (1, 3, 7, 64, 10_000):
        sr = StreamRedactor(registry)
        out = pump(sr, text, size)
        assert "FIXTURE" not in out, size
        assert out.count("<redacted:hmac:") == 3, size
        assert out.endswith("next line\n") and sr.pending == 0


def test_output_is_whole_lines_until_flush(registry):
    registry.add("FIXTURE-SECRET-abc123")
    sr = StreamRedactor(registry)
    text = "line one\n" + "x" * (registry.max_len() * 2) + "\nline thr"  # first newline well before the tail
    out = sr.feed(text)
    assert out == "line one\n"
    assert out + sr.flush() == text


def test_registry_growth_mid_stream_extends_the_tail(registry):
    sr = StreamRedactor(registry)
    out0 = sr.feed("prefix line\n")
    registry.add("FIXTURE-SECRET-registered-late-and-long-enough-to-exceed-the-key")
    chunks = ["abc FIXTURE-SECRET-registered-late-and-long-enou", "gh-to-exceed-the-key tail\n"]
    out = out0 + "".join(sr.feed(c) for c in chunks) + sr.flush()
    assert out.startswith("prefix line\n")
    assert "FIXTURE" not in out and out.count("<redacted:hmac:") == 1


def test_secret_registered_just_before_its_chunk_arrives(registry):
    sr = StreamRedactor(registry)
    held = sr.feed("short\n")  # may be held back by the tail sized from the key
    registry.add("FIXTURE-SECRET-late-value")
    out = held + sr.feed("x FIXTURE-SECRET-late-value y\n") + sr.flush()
    assert out == f"short\nx {registry.placeholder('FIXTURE-SECRET-late-value')} y\n"


def test_multiline_secret_straddling_the_line_cut(registry):
    """A PEM-shaped secret spans lines; the cut must never land inside it (the prototype's line-aligned cut
    did and emitted its first lines)."""
    pem = (
        "-----BEGIN FIXTURE KEY-----\n"
        + "\n".join(f"FIXTURESECRETLINE{i:02d}" for i in range(12))
        + "\n-----END FIXTURE KEY-----"
    )
    registry.add(pem)
    for trailing in (10, 100, 300, len(pem), len(pem) * 3):
        text = "before\n" + pem + "\nafter " + "z" * trailing + "\nend\n"
        for size in (5, 50, 400):
            out = pump(StreamRedactor(registry), text, size)
            assert "FIXTURESECRETLINE" not in out and "BEGIN FIXTURE" not in out, (trailing, size)
            assert out == f"before\n{registry.placeholder(pem)}\nafter " + "z" * trailing + "\nend\n"


def test_secret_inside_the_tail_window_is_held_whole(registry):
    """A single-line secret whose start falls just inside the tail is never split: the line-aligned cut lands
    before it (the straddle case proper is the multi-line PEM test above)."""
    s = "FIXTURE-SECRET-abcdefghijklmnopqrstuvwxyz"
    registry.add(s)
    tail = registry.max_len() - 1
    # the natural cut (len - tail) lands one char into the secret; the emitted part must stop before it
    body = "a\n" * 20
    text = body + "p " + s + " q\n" + "r" * (tail - len(" q\n") - 1)
    sr = StreamRedactor(registry)
    out = sr.feed(text)
    assert "FIXTURE" not in out
    rest = sr.flush()
    assert "FIXTURE" not in rest and (out + rest).count(registry.placeholder(s)) == 1
    assert out + rest == body + "p " + registry.placeholder(s) + " q\n" + "r" * (tail - len(" q\n") - 1)


def test_newline_free_stream_is_bounded_and_still_redacted(registry):
    s = "FIXTURE-SECRET-inside-a-giant-single-line"
    registry.add(s)
    filler = "0123456789" * (MAX_HELD_LINE // 10)
    text = filler + s + filler + s + "\n"
    sr = StreamRedactor(registry)
    out = ""
    max_pending = 0
    for i in range(0, len(text), 65_536):
        out += sr.feed(text[i : i + 65_536])
        max_pending = max(max_pending, sr.pending)
    out += sr.flush()
    assert "FIXTURE" not in out and out.count(registry.placeholder(s)) == 2
    assert max_pending < MAX_HELD_LINE + 65_536 + registry.max_len() + 1
    assert out == filler + registry.placeholder(s) + filler + registry.placeholder(s) + "\n"


def test_empty_registry_passes_text_through(key, key_id):
    from codeorca.redact import SecretRegistry

    reg = SecretRegistry(key, key_id, min_length=1000)  # nothing registered, not even the key
    assert reg.size == 0
    sr = StreamRedactor(reg)
    assert sr.feed("a\nb") == "a\n"
    assert sr.flush() == "b"
    assert sr.feed("") == "" and sr.flush() == ""


def test_log_fixture_pumped_in_tiny_chunks(registry, fixtures_dir, fixture_secrets):
    for v in fixture_secrets:
        registry.add(v)
    for name in ("ansible-stdout.log", "terraform-trace.log"):
        text = (fixtures_dir / name).read_text(encoding="utf-8", errors="replace")
        assert "FIXTURE-" in text
        out = pump(StreamRedactor(registry), text, 7)
        assert "FIXTURE-" not in out, name
        assert PLACEHOLDER_RE.search(out), name
        assert out.count("\n") == text.count("\n")
