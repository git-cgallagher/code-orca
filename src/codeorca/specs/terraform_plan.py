"""The Terraform plan document (plan section 5.6): ``show -json <plan>`` -> redacted, deterministic dict.

This is the only stage of spec rendering that sees secrets, so its inputs and order matter:

- ``seed_registry`` first: every sensitive variable value, sensitive output value (``output_changes[].after`` /
  ``before``, ``planned_values`` and ``prior_state`` outputs flagged sensitive) and every leaf under a
  ``*_sensitive`` map goes into the registry, so the value scrub catches a secret wherever Terraform's flags
  did not follow it (a computed attribute echoing a sensitive input, ``nonsensitive()``).
- Then per value tree (``before``/``after``/outputs): ``merge_unknown`` -> ``mask_by_map`` -> ``mask_by_schema``
  -> ``redact_tree(key_denylist)``. The map mask renders a flagged leaf as its **placeholder**
  (``<redacted:hmac:…>``, stable per value, so a spec diff shows that a secret changed without showing it)
  rather than ``(sensitive)``; a flagged object collapses to one placeholder of its canonical JSON. The key
  denylist is applied **only** to value trees, never to the configuration metadata (it would collapse
  ``variables.db_password`` to ``<redacted:key>`` and lose its ``sensitive`` flag), and it leaves a value that
  is already a placeholder or a ``(known after apply)`` / ``(sensitive)`` marker alone.
- ``never_render`` entries are dropped before any of that; the name stays with ``<never rendered: stack policy>``.
- Sensitive variables keep their name and flag; their value is dropped, not masked, and declared defaults are
  dropped too (an ephemeral variable's default re-enters plan JSON in clear text).

Nothing here carries a timestamp, run id or path: the document is the spec body.
"""

from __future__ import annotations

import fnmatch
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from codeorca import tfjson
from codeorca.policy import GateVerdict
from codeorca.redact import (
    KEY_PLACEHOLDER,
    PLACEHOLDER_RE,
    SENSITIVE,
    UNKNOWN,
    SecretRegistry,
    compile_key_denylist,
    mask_by_schema,
    merge_unknown,
    redact_tree,
    schema_sensitive_paths,
    sensitive_leaves,
)
from codeorca.specs import META_KEY, NEVER_RENDERED

KIND = "terraform_plan"
_INSTANCE_KEY = re.compile(r"\[[^\]]*\]")


# ------------------------------------------------------------------------------------------------- seeding


def seed_registry(registry: SecretRegistry, plan_json: Mapping[str, Any], key_denylist: Sequence[str] = ()) -> int:
    """Register every value the plan marks sensitive, plus the value of every variable whose NAME matches
    ``key_denylist`` (the project treats it as a secret even when the stack forgot ``sensitive = true``; once
    registered it renders as its placeholder under ``variables`` and cannot survive in an attribute that echoes
    it). Returns the registry growth."""
    before = registry.size
    sensitive_vars = set(tfjson.sensitive_variables(plan_json))
    patterns = compile_key_denylist(key_denylist)
    for name, spec in (plan_json.get("variables") or {}).items():
        if isinstance(spec, dict) and (name in sensitive_vars or any(p.search(name) for p in patterns)):
            _add_leaves(registry, spec.get("value"))
    for change in (plan_json.get("output_changes") or {}).values():
        if not isinstance(change, dict):
            continue
        if change.get("after_sensitive") is True:
            _add_leaves(registry, change.get("after"))
        if change.get("before_sensitive") is True:
            _add_leaves(registry, change.get("before"))
    for block in (
        (plan_json.get("planned_values") or {}).get("outputs"),
        ((plan_json.get("prior_state") or {}).get("values") or {}).get("outputs"),
    ):
        for spec in (block or {}).values():
            if isinstance(spec, dict) and spec.get("sensitive"):
                _add_leaves(registry, spec.get("value"))
    for rc in [*(plan_json.get("resource_changes") or []), *(plan_json.get("resource_drift") or [])]:
        change = (rc or {}).get("change") or {}
        for side in ("before", "after"):
            for leaf in sensitive_leaves(change.get(side), change.get(f"{side}_sensitive")):
                registry.add(leaf)
    for values in (plan_json.get("planned_values"), (plan_json.get("prior_state") or {}).get("values")):
        _seed_module(registry, (values or {}).get("root_module"))
    return registry.size - before


def _seed_module(registry: SecretRegistry, module: Any) -> None:
    if not isinstance(module, dict):
        return
    for res in module.get("resources") or []:
        if isinstance(res, dict):
            for leaf in sensitive_leaves(res.get("values"), res.get("sensitive_values")):
                registry.add(leaf)
    for child in module.get("child_modules") or []:
        _seed_module(registry, child)


def _add_leaves(registry: SecretRegistry, value: Any) -> None:
    if isinstance(value, dict):
        for v in value.values():
            _add_leaves(registry, v)
    elif isinstance(value, list | tuple):
        for v in value:
            _add_leaves(registry, v)
    elif value is None or isinstance(value, bool):
        return
    else:
        registry.add(str(value))


# ---------------------------------------------------------------------------------------------- provenance


def _config_resources(plan_json: Mapping[str, Any]) -> dict[str, dict]:
    """``{config address: expressions}`` over the root module and every module call (addresses prefixed)."""
    out: dict[str, dict] = {}

    def walk(module: Any, prefix: str) -> None:
        if not isinstance(module, dict):
            return
        for res in module.get("resources") or []:
            if isinstance(res, dict) and res.get("address"):
                out[prefix + str(res["address"])] = res.get("expressions") or {}
        for name, call in (module.get("module_calls") or {}).items():
            if isinstance(call, dict):
                walk(call.get("module"), f"{prefix}module.{name}.")

    walk(((plan_json.get("configuration") or {}).get("root_module")), "")
    return out


def _references(expr: Any, path: str, acc: dict[str, str]) -> None:
    if isinstance(expr, dict):
        refs = expr.get("references")
        if isinstance(refs, list) and refs:
            acc[path] = "<- " + ", ".join(str(r) for r in refs)
        for key, value in expr.items():
            if key in ("references", "constant_value"):
                continue
            _references(value, f"{path}.{key}" if path else str(key), acc)
    elif isinstance(expr, list):
        for item in expr:
            _references(item, path, acc)


def provenance(expressions: Mapping[str, Any] | None) -> dict[str, str]:
    """``{attribute path: "<- var.x, local.y"}`` from a configuration ``expressions`` block."""
    acc: dict[str, str] = {}
    for attr, expr in (expressions or {}).items():
        _references(expr, str(attr), acc)
    return dict(sorted(acc.items()))


def _config_address(address: str) -> str:
    """``module.m["a"].aws_x.y[0]`` -> ``module.m.aws_x.y`` (instance keys are not in the configuration)."""
    return _INSTANCE_KEY.sub("", address)


# -------------------------------------------------------------------------------------------------- values


def placeholder_for(registry: SecretRegistry, value: Any) -> Any:
    """The placeholder of a scalar, or of a container's canonical JSON; ``None`` stays ``None``."""
    if value is None:
        return None
    text = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
    return registry.placeholder(text)


def mask_with_placeholders(values: Any, sensitive_map: Any, registry: SecretRegistry) -> Any:
    """``mask_by_map`` whose masked leaves are the registry placeholders instead of ``(sensitive)``."""
    if sensitive_map is True:
        return placeholder_for(registry, values)
    if not isinstance(sensitive_map, dict | list) or not sensitive_map:
        return values
    if isinstance(sensitive_map, dict):
        if isinstance(values, dict):
            return {k: mask_with_placeholders(v, sensitive_map.get(k, False), registry) for k, v in values.items()}
        return placeholder_for(registry, values)
    if isinstance(values, list):
        n = len(sensitive_map)
        return [mask_with_placeholders(v, sensitive_map[i] if i < n else False, registry) for i, v in enumerate(values)]
    return placeholder_for(registry, values)


def _is_marker(value: Any) -> bool:
    return isinstance(value, str) and (value in (SENSITIVE, UNKNOWN) or PLACEHOLDER_RE.fullmatch(value) is not None)


def redact_values(obj: Any, registry: SecretRegistry, key_denylist: Sequence[str]) -> Any:
    """``redact_tree`` for spec value trees: the registry scrub over everything, then the key denylist, which
    keeps a leaf that is already a placeholder or a marker (a denylisted key over a masked value must not turn a
    stable ``<redacted:hmac:…>`` into ``<redacted:key>`` and lose the change signal)."""
    patterns = compile_key_denylist(key_denylist)
    return _deny(redact_tree(obj, registry), patterns)


def _deny(obj: Any, patterns) -> Any:
    if isinstance(obj, dict):
        out: dict[Any, Any] = {}
        for k, v in obj.items():
            if isinstance(k, str) and any(p.search(k) for p in patterns) and v is not None and not _is_marker(v):
                out[k] = KEY_PLACEHOLDER
            else:
                out[k] = _deny(v, patterns)
        return out
    if isinstance(obj, list):
        return [_deny(v, patterns) for v in obj]
    return obj


def _value_tree(
    value: Any,
    sensitive_map: Any,
    unknown_map: Any,
    schema_paths: Iterable[tuple[str, tuple[str, ...]]],
    resource_type: str,
    registry: SecretRegistry,
    key_denylist: Sequence[str],
) -> Any:
    merged = merge_unknown(value, unknown_map) if unknown_map is not None else value
    masked = mask_with_placeholders(merged, sensitive_map, registry)
    masked = mask_by_schema(masked, schema_paths, resource_type)
    return redact_values(masked, registry, key_denylist)


def _never_rendered_resource(address: str, patterns: Iterable[str]) -> bool:
    return any(fnmatch.fnmatchcase(address, p) or fnmatch.fnmatchcase(_config_address(address), p) for p in patterns)


def _resource_entry(
    rc: Mapping[str, Any],
    config: Mapping[str, dict],
    schema_paths: Iterable[tuple[str, tuple[str, ...]]],
    registry: SecretRegistry,
    key_denylist: Sequence[str],
    never_resources: Sequence[str],
) -> dict[str, Any]:
    change = rc.get("change") or {}
    address = str(rc.get("address", "<unknown>"))
    rtype = str(rc.get("type", ""))
    entry: dict[str, Any] = {
        "address": address,
        "type": rtype,
        "mode": rc.get("mode"),
        "actions": list(change.get("actions") or []),
        "action_reason": rc.get("action_reason"),
        "replace_paths": [list(p) for p in (change.get("replace_paths") or [])],
    }
    if _never_rendered_resource(address, never_resources):
        entry["rendered"] = NEVER_RENDERED
        return entry
    entry["before"] = _value_tree(
        change.get("before"), change.get("before_sensitive"), None, schema_paths, rtype, registry, key_denylist
    )
    entry["after"] = _value_tree(
        change.get("after"),
        change.get("after_sensitive"),
        change.get("after_unknown"),
        schema_paths,
        rtype,
        registry,
        key_denylist,
    )
    entry["provenance"] = provenance(config.get(_config_address(address)))
    return entry


def _output_value(change: Mapping[str, Any], side: str, registry: SecretRegistry, key_denylist: Sequence[str]) -> Any:
    value = change.get(side)
    if side == "after" and change.get("after_unknown") is True:
        return UNKNOWN
    if change.get(f"{side}_sensitive") is True:
        if value is None:
            return None
        return placeholder_for(registry, value)
    if side == "after" and isinstance(change.get("after_unknown"), dict | list):
        value = merge_unknown(value, change.get("after_unknown"))
    if isinstance(change.get(f"{side}_sensitive"), dict | list):
        value = mask_with_placeholders(value, change.get(f"{side}_sensitive"), registry)
    return redact_values(value, registry, key_denylist)


# ------------------------------------------------------------------------------------------------ document


def build_plan_document(
    plan_json: Mapping[str, Any],
    providers_schema: Mapping[str, Any] | None,
    registry: SecretRegistry,
    stack: str,
    policy_verdict: GateVerdict | Mapping[str, Any] | None,
    key_denylist: Sequence[str] = (),
    never_render: Mapping[str, Sequence[str]] | None = None,
    *,
    exit_code: int | None = None,
    engine_version: str | None = None,
) -> dict[str, Any]:
    """The redacted plan document. Seed the registry (``seed_registry``) before calling this: ``redact_tree`` is
    pure and only scrubs what the registry already knows."""
    never = never_render or {}
    never_outputs = set(never.get("outputs") or [])
    never_resources = list(never.get("resources") or [])
    schema_paths = schema_sensitive_paths(dict(providers_schema)) if providers_schema else set()
    config = _config_resources(plan_json)
    verdict = _verdict_dict(policy_verdict)

    summary = tfjson.plan_summary(plan_json)
    summary["exit_code"] = exit_code
    summary["gate"] = verdict

    sensitive_vars = set(tfjson.sensitive_variables(plan_json))
    declared = ((plan_json.get("configuration") or {}).get("root_module") or {}).get("variables") or {}
    plain_values = {
        name: (spec or {}).get("value")
        for name, spec in (plan_json.get("variables") or {}).items()
        if name not in sensitive_vars
    }
    plain_values = redact_values(plain_values, registry, key_denylist)
    variables: dict[str, Any] = {}
    for name in sorted(set(plan_json.get("variables") or {}) | set(declared)):
        entry: dict[str, Any] = {"sensitive": name in sensitive_vars}
        if name not in sensitive_vars and name in plain_values:
            entry["value"] = plain_values[name]
        variables[name] = entry

    resource_changes = [
        _resource_entry(rc, config, schema_paths, registry, key_denylist, never_resources)
        for rc in (plan_json.get("resource_changes") or [])
        if isinstance(rc, dict)
    ]
    resource_changes.sort(key=lambda e: e["address"])
    drift = [
        _resource_entry(rc, config, schema_paths, registry, key_denylist, never_resources)
        for rc in (plan_json.get("resource_drift") or [])
        if isinstance(rc, dict)
    ]
    drift.sort(key=lambda e: e["address"])

    config_outputs = (((plan_json.get("configuration") or {}).get("root_module") or {}).get("outputs")) or {}
    output_changes: dict[str, Any] = {}
    for name, change in sorted((plan_json.get("output_changes") or {}).items()):
        if not isinstance(change, dict):
            continue
        actions = list(change.get("actions") or [])
        if name in never_outputs:
            output_changes[name] = {"actions": actions, "rendered": NEVER_RENDERED}
            continue
        sensitive = change.get("after_sensitive") is True or change.get("before_sensitive") is True
        entry = {
            "actions": actions,
            "sensitive": sensitive,
            "value": _output_value(change, "after", registry, key_denylist),
            "provenance": provenance({"value": (config_outputs.get(name) or {}).get("expression")}).get("value"),
        }
        if any(a in actions for a in ("update", "delete")):
            entry["previous"] = _output_value(change, "before", registry, key_denylist)
        output_changes[name] = entry

    return {
        "kind": KIND,
        "stack": stack,
        "engine": {"name": "terraform", "version": engine_version or plan_json.get("terraform_version")},
        "summary": summary,
        "variables": variables,
        "resource_changes": resource_changes,
        "output_changes": output_changes,
        "drift": drift,
        "never_rendered": {"outputs": sorted(never_outputs), "resources": sorted(never_resources)},
    }


def _verdict_dict(verdict: GateVerdict | Mapping[str, Any] | None) -> dict[str, Any]:
    if verdict is None:
        return {"passed": True, "blocked": [], "replacements": []}
    if isinstance(verdict, GateVerdict):
        return verdict.model_dump()
    return dict(verdict)


def gate_word(document: Mapping[str, Any]) -> str:
    """``pass`` or ``blocked`` for the spec header."""
    return "pass" if ((document.get("summary") or {}).get("gate") or {}).get("passed", True) else "blocked"


def header_for(document: Mapping[str, Any], registry_key_id: str, git_sha: str | None, **extra: Any) -> dict[str, Any]:
    from codeorca.specs import build_header  # local import: specs/__init__ does not import this module

    engine = document.get("engine") or {}
    return build_header(
        kind=str(document.get("kind", KIND)),
        stack=str(document.get("stack", "")),
        engine=f"{engine.get('name', 'terraform')}/{engine.get('version')}",
        gate=gate_word(document),
        redaction_key=registry_key_id,
        git_sha=git_sha,
        **extra,
    )


def strip_meta(document: Mapping[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in document.items() if k != META_KEY}
