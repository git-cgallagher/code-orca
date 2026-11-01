"""scan_outputs: the post-render gate reports path and count, never a value."""

from __future__ import annotations

import base64
import json
import os

import pytest

from codeorca.redact import scan_outputs


def test_clean_tree_reports_nothing(tmp_path, registry):
    registry.add("FIXTURE-SECRET-abc123")
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "spec.json").write_text(json.dumps({"x": registry.placeholder("FIXTURE-SECRET-abc123")}))
    (tmp_path / "log.txt").write_text("nothing to see\n")
    assert scan_outputs(tmp_path, registry) == []


def test_hits_in_every_encoding_are_counted_per_file(tmp_path, registry, encode):
    registry.add("FIXTURE-SECRET-abc123")
    enc = encode("FIXTURE-SECRET-abc123")
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "b.log").write_text(f"{enc['raw']} and {enc['base64']}\n")
    (tmp_path / "a.json").write_text(json.dumps({"v": enc["raw"]}))  # json.dumps keeps it raw: 1 hit
    (tmp_path / "c.txt").write_text(enc["url"] + "\n" + enc["json"])
    (tmp_path / "clean.txt").write_text("ok\n")
    (tmp_path / "bin.dat").write_bytes(b"\x00\xff" + b"FIXTURE-SECRET-abc123" + b"\x00")
    report = scan_outputs(str(tmp_path), registry)
    assert report == [("a.json", 1), ("bin.dat", 1), ("c.txt", 2), ("nested/b.log", 2)]
    assert "FIXTURE" not in repr(report)


def test_extra_patterns_add_to_the_count(tmp_path, registry):
    (tmp_path / "x.txt").write_text("EXKEY-ABCDEFGH and extok_notarealtokenexample\n")
    assert scan_outputs(tmp_path, registry) == []
    assert scan_outputs(tmp_path, registry, [r"EXKEY-[A-Z]{8}", r"extok_[A-Za-z0-9]+"]) == [("x.txt", 2)]
    assert scan_outputs(tmp_path, registry, extra_patterns=(r"EXKEY-[A-Z]{8}",)) == [("x.txt", 1)]


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads a mode-0 file; nothing to test")
def test_unreadable_file_raises_rather_than_passing(tmp_path, registry):
    p = tmp_path / "secret.txt"
    p.write_text(base64.b64encode(b"FIXTURE-SECRET-abc123").decode())
    p.chmod(0)
    try:
        with pytest.raises(OSError):
            scan_outputs(tmp_path, registry)
    finally:
        p.chmod(0o600)
