"""Pure parsers over Terraform's JSON: ``-json`` message streams and ``show -json`` plan / state documents.

Nothing here shells out or redacts. Plan JSON holds sensitive values in plain text (its ``variables`` block,
``after`` values, prior-state outputs); these helpers only tell the caller *which* names are sensitive so the
redaction pipeline can act. Verified against Terraform 1.14.7: plan ``format_version`` is ``"1.2"`` (the
docs still say 1.0), so parse by major version and ignore unknown keys.
"""

from __future__ import annotations

import json
from collections.abc import Iterable


def parse_json_stream(lines: Iterable[str] | str) -> list[dict]:
    """Parse a ``-json`` stream line by line.

    Blank lines are dropped. A line that is not a JSON object (``init -json`` can print plain text) is kept
    as ``{"@level": "log", "@message": <line>}`` so nothing a subprocess said is lost.
    """
    if isinstance(lines, str):
        lines = lines.splitlines()
    messages: list[dict] = []
    for raw in lines:
        line = raw.rstrip("\r\n")
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
        except ValueError:
            parsed = None
        if isinstance(parsed, dict):
            messages.append(parsed)
        else:
            messages.append({"@level": "log", "@message": line})
    return messages


def diagnostics(messages: Iterable[dict], levels: Iterable[str] = ("error",)) -> list[dict]:
    """Messages of the given ``@level``s (default: errors) from a parsed stream."""
    wanted = set(levels)
    return [m for m in messages if m.get("@level") in wanted]


def is_supported_format(format_version: object) -> bool:
    """True for major version 1 of the plan/state/validate JSON formats (``"1.0"``, ``"1.2"``, ...)."""
    if isinstance(format_version, bool) or format_version is None:
        return False
    if isinstance(format_version, int | float):
        return int(format_version) == 1
    major = str(format_version).split(".", 1)[0]
    return major.isdigit() and int(major) == 1


def _resource_changes(plan_json: dict) -> list[dict]:
    return [rc for rc in (plan_json.get("resource_changes") or []) if isinstance(rc, dict)]


def replacements(plan_json: dict) -> list[str]:
    """Addresses whose actions contain both ``delete`` and ``create`` (either order)."""
    out = []
    for rc in _resource_changes(plan_json):
        actions = set((rc.get("change") or {}).get("actions") or [])
        if {"delete", "create"} <= actions:
            out.append(rc.get("address", "<unknown>"))
    return out


def plan_summary(plan_json: dict) -> dict:
    """Headline facts of a plan: applyability flags, action counts, replacements, format version.

    Counts put each resource in one bucket: a replacement counts once under ``replace`` (Terraform's own
    ``Plan:`` line would count it as one add plus one destroy). ``no-op`` and ``read`` count nowhere.
    """
    counts = {"add": 0, "change": 0, "remove": 0, "replace": 0}
    for rc in _resource_changes(plan_json):
        actions = set((rc.get("change") or {}).get("actions") or [])
        if {"delete", "create"} <= actions:
            counts["replace"] += 1
        elif "create" in actions:
            counts["add"] += 1
        elif "update" in actions:
            counts["change"] += 1
        elif "delete" in actions:
            counts["remove"] += 1
    return {
        "applyable": bool(plan_json.get("applyable", False)),
        "complete": bool(plan_json.get("complete", False)),
        "errored": bool(plan_json.get("errored", False)),
        "counts": counts,
        "replacements": replacements(plan_json),
        "format_version": plan_json.get("format_version"),
    }


def _root_module(plan_json: dict) -> dict:
    return ((plan_json.get("configuration") or {}).get("root_module")) or {}


def sensitive_variables(plan_json: dict) -> list[str]:
    """Names of root-module variables declared ``sensitive = true``.

    The plan's top-level ``variables`` block carries the values with no flag at all; the flag lives only
    under ``configuration.root_module.variables``.
    """
    variables = _root_module(plan_json).get("variables") or {}
    return sorted(name for name, spec in variables.items() if isinstance(spec, dict) and spec.get("sensitive"))


def sensitive_outputs(plan_json: dict) -> list[str]:
    """Names of outputs flagged sensitive anywhere the plan says so (configuration, planned values, changes)."""
    names: set[str] = set()
    for name, spec in (_root_module(plan_json).get("outputs") or {}).items():
        if isinstance(spec, dict) and spec.get("sensitive"):
            names.add(name)
    for name, spec in ((plan_json.get("planned_values") or {}).get("outputs") or {}).items():
        if isinstance(spec, dict) and spec.get("sensitive"):
            names.add(name)
    for name, change in (plan_json.get("output_changes") or {}).items():
        if isinstance(change, dict) and change.get("after_sensitive") is True:
            names.add(name)
    for name, spec in (((plan_json.get("prior_state") or {}).get("values") or {}).get("outputs") or {}).items():
        if isinstance(spec, dict) and spec.get("sensitive"):
            names.add(name)
    return sorted(names)


def prior_outputs(plan_json: dict) -> dict[str, object]:
    """``{name: value}`` for the NON-sensitive outputs of ``prior_state`` only; ``{}`` when there is none.

    Sensitive outputs are dropped, not masked: their names come back from ``sensitive_outputs``.

    Observed on 1.14.7 (fixtures ``plan.json`` / ``replace-plan.json``): ``prior_state.values.outputs`` holds the
    root outputs **re-evaluated against the current configuration and variables**, so a first plan already lists
    them and a plan that changes an output shows the *new* value here, while ``prior_state.root_module`` is the
    real prior. The value the state recorded is ``output_changes[name].before``: see ``previous_outputs``.
    """
    outputs = ((plan_json.get("prior_state") or {}).get("values") or {}).get("outputs") or {}
    return {
        name: spec.get("value")
        for name, spec in outputs.items()
        if isinstance(spec, dict) and not spec.get("sensitive")
    }


def previous_outputs(plan_json: dict) -> dict[str, object]:
    """``{name: before}`` from ``output_changes`` for outputs that existed before and were not sensitive.

    This is what the state recorded before this plan (``prior_outputs`` is re-evaluated, see there). An output
    being created (``actions == ["create"]``) has no previous value and is left out.
    """
    out: dict[str, object] = {}
    for name, change in (plan_json.get("output_changes") or {}).items():
        if not isinstance(change, dict) or "create" in (change.get("actions") or []):
            continue
        if change.get("before_sensitive") is True or change.get("after_sensitive") is True:
            continue
        out[name] = change.get("before")
    return out


def state_outputs(state_json: dict, include_sensitive: bool = False) -> dict[str, object]:
    """``{name: value}`` from a ``show -json`` state or an ``output -json`` document; sensitive dropped by default.

    A state document has a string ``format_version`` and ``values.outputs``; an ``output -json`` document *is*
    the outputs map, whose entries are ``{sensitive, type, value}`` whatever their names (an output may well be
    called ``values`` or ``format_version``).
    """
    values = state_json.get("values")
    looks_like_state = isinstance(state_json.get("format_version"), str) or (
        isinstance(values, dict) and "value" not in values and ("outputs" in values or "root_module" in values)
    )
    if looks_like_state:
        outputs = (values or {}).get("outputs") or {} if isinstance(values, dict) else {}
    else:
        outputs = state_json
    if not isinstance(outputs, dict):
        return {}
    return {
        name: spec.get("value")
        for name, spec in outputs.items()
        if isinstance(spec, dict) and (include_sensitive or not spec.get("sensitive"))
    }
