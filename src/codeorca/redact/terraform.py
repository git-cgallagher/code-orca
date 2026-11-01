"""Structural masking from Terraform's own metadata (stage 1 of the pipeline).

Terraform (1.14.7) never marks a value in place: ``terraform show -json`` emits the plain value and a sibling
map of the same shape with ``true`` at sensitive leaves (``after_sensitive``, ``before_sensitive``,
``sensitive_values``, ``outputs.*.sensitive``), and ``after_unknown`` in the same style for values only
known after apply. The maps are exactly as emitted: ``true``, ``false``, ``{}`` or ``[]`` for a value with
nothing to flag, nested dicts/lists mirroring the value. ``after`` omits unknown attributes entirely, so
``merge_unknown`` must *add* keys. The flags are correct but incomplete (a computed attribute echoing a
sensitive input is unmarked), which is why the value scrub in :mod:`codeorca.redact.text` runs last.

Order of use: ``merge_unknown`` first (it needs the raw shape), then ``mask_by_map``/``mask_by_schema``,
then ``redact_tree`` over the whole document. ``mask_by_schema`` leaves a leaf that already carries a registry
placeholder alone (the spec renderer masks map-flagged leaves with placeholders first).
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Any

from codeorca.redact.registry import PLACEHOLDER_RE

SENSITIVE = "(sensitive)"
UNKNOWN = "(known after apply)"


def _is_truthy_container(m: Any) -> bool:
    return isinstance(m, dict | list) and len(m) > 0


def mask_by_map(values: Any, sensitive_map: Any) -> Any:
    """Return ``values`` with ``'(sensitive)'`` wherever ``sensitive_map`` says ``true``.

    A ``true`` node collapses its whole subtree (a sensitive object's key names are not shown either, as
    ``terraform show`` does), except that a ``None`` value stays ``None`` (an unset secret is not a secret).
    ``false``, ``None``, ``{}`` and ``[]`` mean nothing to flag. A non-empty map whose shape does not match the
    value fails closed: the value is masked.
    """
    if sensitive_map is True:
        return None if values is None else SENSITIVE
    if not _is_truthy_container(sensitive_map):
        return values
    if isinstance(sensitive_map, dict):
        if isinstance(values, dict):
            return {k: mask_by_map(v, sensitive_map.get(k, False)) for k, v in values.items()}
        return None if values is None else SENSITIVE
    if isinstance(values, list):
        n = len(sensitive_map)
        return [mask_by_map(v, sensitive_map[i] if i < n else False) for i, v in enumerate(values)]
    return None if values is None else SENSITIVE


def sensitive_leaves(values: Any, sensitive_map: Any) -> Iterator[str]:
    """Yield the string form of every scalar leaf that ``sensitive_map`` flags, for registry seeding."""
    if sensitive_map is True:
        yield from _leaves(values)
        return
    if not _is_truthy_container(sensitive_map):
        return
    if isinstance(sensitive_map, dict):
        if isinstance(values, dict):
            for k, v in values.items():
                yield from sensitive_leaves(v, sensitive_map.get(k, False))
        else:
            yield from _leaves(values)
        return
    if isinstance(values, list):
        n = len(sensitive_map)
        for i, v in enumerate(values):
            yield from sensitive_leaves(v, sensitive_map[i] if i < n else False)
    else:
        yield from _leaves(values)


def _leaves(value: Any) -> Iterator[str]:
    if isinstance(value, dict):
        for v in value.values():
            yield from _leaves(v)
    elif isinstance(value, list | tuple):
        for v in value:
            yield from _leaves(v)
    elif value is None or isinstance(value, bool):
        return
    else:
        yield str(value)


def merge_unknown(values: Any, after_unknown: Any) -> Any:
    """Return ``values`` with ``'(known after apply)'`` wherever ``after_unknown`` says ``true``.

    Keys that ``after_unknown`` flags but ``values`` lacks are added (Terraform omits unknown attributes from
    ``after``). A ``true`` over a whole list or object replaces it. A non-empty map against a scalar value
    (which only happens after masking) leaves the value as it is: merge before masking.
    """
    if after_unknown is True:
        return UNKNOWN
    if not _is_truthy_container(after_unknown):
        return values
    if isinstance(after_unknown, dict):
        if values is None:
            base: dict[Any, Any] = {}
        elif isinstance(values, dict):
            base = dict(values)
        else:
            return values
        for k, u in after_unknown.items():
            if u is True:
                base[k] = UNKNOWN
            elif _is_truthy_container(u):
                base[k] = merge_unknown(base.get(k), u)
        return base
    # list
    if values is None:
        return [merge_unknown(None, u) if (u is True or _is_truthy_container(u)) else None for u in after_unknown]
    if not isinstance(values, list):
        return values
    out = list(values)
    for i, u in enumerate(after_unknown):
        if u is True:
            if i < len(out):
                out[i] = UNKNOWN
            else:
                out.append(UNKNOWN)
        elif _is_truthy_container(u):
            if i < len(out):
                out[i] = merge_unknown(out[i], u)
            else:
                out.append(merge_unknown(None, u))
    return out


def schema_sensitive_paths(providers_schema_json: dict) -> set[tuple[str, tuple[str, ...]]]:
    """From ``terraform providers schema -json``: ``{(resource_type, path)}`` for every attribute flagged
    ``sensitive`` or ``write_only``, walking ``attributes``, ``nested_type`` and ``block_types`` recursively.

    Every ``*_schemas`` kind with a ``block`` is walked (resource, data source, ephemeral, list, and whatever a
    later Terraform adds); entries without a block (``functions``, ``resource_identity_schemas``) are skipped.
    A provider's own configuration block is keyed ``provider:<full provider name>``. Paths name attributes and
    block types only, never list indices: a path applies at every element of a list or set along the way.
    """
    out: set[tuple[str, tuple[str, ...]]] = set()

    def walk(block: Any, path: tuple[str, ...], acc: set[tuple[str, ...]]) -> None:
        if not isinstance(block, dict):
            return
        for name, attr in (block.get("attributes") or {}).items():
            if not isinstance(attr, dict):
                continue
            if attr.get("sensitive") or attr.get("write_only"):
                acc.add((*path, name))
            nested = attr.get("nested_type")
            if isinstance(nested, dict):
                walk(nested, (*path, name), acc)
        for name, bt in (block.get("block_types") or {}).items():
            if isinstance(bt, dict):
                walk(bt.get("block"), (*path, name), acc)

    for provider_name, prov in (providers_schema_json.get("provider_schemas") or {}).items():
        if not isinstance(prov, dict):
            continue
        for kind, schemas in prov.items():
            if not kind.endswith("_schemas") or not isinstance(schemas, dict):
                continue
            for rtype, rs in schemas.items():
                if not isinstance(rs, dict) or "block" not in rs:
                    continue
                acc: set[tuple[str, ...]] = set()
                walk(rs["block"], (), acc)
                out.update((rtype, p) for p in acc)
        provider_block = prov.get("provider")
        if isinstance(provider_block, dict) and "block" in provider_block:
            acc = set()
            walk(provider_block["block"], (), acc)
            out.update((f"provider:{provider_name}", p) for p in acc)
    return out


def mask_by_schema(values: Any, schema_paths: Iterable[tuple[str, tuple[str, ...]]], resource_type: str) -> Any:
    """Belt and braces for values Terraform gave no sensitivity map for (``terraform output -json`` leaves, data
    sources, hand-built specs): mask every attribute path that ``schema_sensitive_paths`` flagged for
    ``resource_type``. Lists and sets are transparent to the path, as in the schema walk."""
    paths = {p for rt, p in schema_paths if rt == resource_type}
    if not paths:
        return values
    return _mask_paths(values, paths, ())


def _mask_paths(values: Any, paths: set[tuple[str, ...]], at: tuple[str, ...]) -> Any:
    if isinstance(values, dict):
        out: dict[Any, Any] = {}
        for k, v in values.items():
            p = (*at, k)
            if p in paths:
                # a value already masked by the map (a stable placeholder) keeps its change signal; a marker
                # such as ``(known after apply)`` still collapses to ``(sensitive)`` (fail closed)
                already = isinstance(v, str) and PLACEHOLDER_RE.fullmatch(v) is not None
                out[k] = v if already else (None if v is None else SENSITIVE)
            else:
                out[k] = _mask_paths(v, paths, p)
        return out
    if isinstance(values, list):
        return [_mask_paths(v, paths, at) for v in values]
    return values
