"""Spec rendering (plan section 5.6): deterministic, redacted YAML documents meant to be committed.

A spec is built in two stages so that the second is pure and fixture-testable:

1. an adapter-side builder turns engine JSON into a **redacted document** (``terraform_plan.build_plan_document``:
   the only stage that sees secrets) and the executor writes that document under the run directory;
2. ``render_spec_yaml`` / ``write_spec`` turn a document into YAML (file to file, no subprocess), which is what
   the ``spec-render`` step and ``codeorca render`` do.

Determinism rules: keys sorted, block style, no run id, timestamp, duration or plan sha256 in the body. Those go
in the ``<name>.meta.yaml`` sidecar. The header carries what a reader needs to trust the document: pipeline
versions, stack, engine version, git SHA, the redaction key id and the gate verdict.

The final gate: the rendered spec text and the sidecar text are scanned with the run's registry **before**
anything is written; a hit raises ``SpecGateError`` (path and count only, never a value) and the destination,
typically a committed spec, is left exactly as it was. Writes go through a temp file in the same directory and
``os.replace``, so a spec is replaced whole or not at all.
"""

from __future__ import annotations

import io
import os
import tempfile
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML

from codeorca import __version__
from codeorca.redact import SecretRegistry, entropy_warnings

SPEC_FORMAT = 1
REDACTION_FORMAT = 1
NEVER_RENDERED = "<never rendered: stack policy>"
META_KEY = "meta"  # a document key the body never renders; its content feeds the sidecar

HEADER_ORDER = ("pipeline", "kind", "workflow", "stack", "backend_key", "engine", "git_sha", "redaction_key", "gate")


class SpecGateError(RuntimeError):
    """A registered value survived into a written spec; the files have been removed."""


def pipeline_id() -> str:
    return f"codeorca/{__version__} spec/{SPEC_FORMAT} redaction/{REDACTION_FORMAT}"


def sort_tree(obj: Any) -> Any:
    """Recursively sort mapping keys (as strings) so two renders of equal data are byte-identical."""
    if isinstance(obj, Mapping):
        return {str(k): sort_tree(obj[k]) for k in sorted(obj, key=str)}
    if isinstance(obj, list | tuple):
        return [sort_tree(v) for v in obj]
    return obj


def _yaml() -> YAML:
    yaml = YAML(typ="safe", pure=True)
    yaml.default_flow_style = False
    yaml.sort_base_mapping_type_on_output = False  # we sort ourselves, so the header keeps its order
    yaml.width = 4096  # never fold a long value: a diff must show one changed line per changed value
    yaml.explicit_start = False
    return yaml


def _dump(data: Any) -> str:
    buf = io.StringIO()
    _yaml().dump(data, buf)
    return buf.getvalue()


def build_header(
    *,
    stack: str,
    engine: str,
    gate: str,
    redaction_key: str,
    git_sha: str | None,
    kind: str = "terraform_plan",
    workflow: str | None = None,
    backend_key: str | None = None,
) -> dict[str, Any]:
    header = {
        "pipeline": pipeline_id(),
        "kind": kind,
        "workflow": workflow,
        "stack": stack,
        "backend_key": backend_key,
        "engine": engine,
        "git_sha": git_sha,
        "redaction_key": redaction_key,
        "gate": gate,
    }
    return {k: header[k] for k in HEADER_ORDER if header[k] is not None}


def render_spec_yaml(document: Mapping[str, Any], header: Mapping[str, Any]) -> str:
    """The spec text: a ``codeorca:`` header (fixed key order) followed by the document body (keys sorted).

    ``document[META_KEY]`` is skipped: it belongs in the sidecar.
    """
    ordered_header = {k: header[k] for k in HEADER_ORDER if k in header}
    ordered_header.update({k: v for k, v in header.items() if k not in ordered_header})
    body = sort_tree({k: v for k, v in document.items() if k != META_KEY})
    return _dump({"codeorca": ordered_header}) + _dump(body)


def meta_path(path: str | os.PathLike[str]) -> Path:
    """``plan.yaml`` -> ``plan.meta.yaml``, ``plan.yml`` -> ``plan.meta.yml``; any other name keeps its full name
    (``plan.json`` -> ``plan.json.meta.yaml``), so two specs that differ only in suffix never share a sidecar."""
    p = Path(path)
    if p.suffix in (".yaml", ".yml"):
        return p.with_name(f"{p.stem}.meta{p.suffix}")
    return p.with_name(f"{p.name}.meta.yaml")


def write_spec(
    path: str | os.PathLike[str],
    document: Mapping[str, Any],
    header: Mapping[str, Any],
    meta: Mapping[str, Any] | None,
    registry: SecretRegistry | None = None,
) -> tuple[Path, Path]:
    """Write ``path`` and its ``.meta.yaml`` sidecar (``meta_path``); returns both paths.

    The sidecar carries the generation metadata (run id, timestamp, plan sha256, durations, registry size) and
    the entropy warning count of the written spec. With a ``registry`` both texts are scanned in memory first; a
    hit raises ``SpecGateError`` and nothing on disk changes. Each file is written atomically.
    """
    spec_path = Path(path)
    text = render_spec_yaml(document, header)
    side = dict(document.get(META_KEY) or {})
    side.update(meta or {})
    side.setdefault("generated_at", datetime.now(UTC).isoformat(timespec="seconds"))
    side["entropy_warnings"] = len(entropy_warnings(text))
    side["spec"] = spec_path.name
    sidecar = meta_path(spec_path)
    side_text = _dump(sort_tree(side))
    if registry is not None:
        hits = [(str(p), n) for p, t in ((spec_path, text), (sidecar, side_text)) if (n := registry.count_matches(t))]
        if hits:
            report = ", ".join(f"{p} ({n})" for p, n in hits)
            raise SpecGateError(f"redaction gate: registered value found in rendered spec; not written: {report}")
    spec_path.parent.mkdir(parents=True, exist_ok=True)
    _replace(spec_path, text)
    _replace(sidecar, side_text)
    return spec_path, sidecar


def _replace(path: Path, text: str) -> None:
    """Atomic write: a temp file beside the target, then ``os.replace`` (a crash leaves the old file intact)."""
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, 0o644)  # a spec is meant to be committed and read
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def scan_files(paths: list[Path], registry: SecretRegistry) -> list[tuple[str, int]]:
    """``scan_outputs`` for an explicit file list: ``[(path, match_count)]`` for files that hit."""
    hits: list[tuple[str, int]] = []
    for p in paths:
        text = p.read_bytes().decode("utf-8", "replace")
        n = registry.count_matches(text)
        if n:
            hits.append((str(p), n))
    return hits


__all__ = [
    "META_KEY",
    "NEVER_RENDERED",
    "SpecGateError",
    "build_header",
    "meta_path",
    "pipeline_id",
    "render_spec_yaml",
    "scan_files",
    "sort_tree",
    "write_spec",
]
