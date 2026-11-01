"""Acceptance (plan section 5.7): after the pipeline, no FIXTURE-* value survives in any output file, in raw,
JSON-escaped, URL-quoted or base64 form, and the outputs still carry the structure a spec reader needs."""

from __future__ import annotations

import json
import re
from pathlib import Path

from codeorca.redact import (
    DEFAULT_KEY_DENYLIST,
    KEY_PLACEHOLDER,
    PLACEHOLDER_RE,
    SENSITIVE,
    UNKNOWN,
    SecretRegistry,
    StreamRedactor,
    entropy_warnings,
    mask_by_map,
    mask_by_schema,
    merge_unknown,
    redact_tree,
    scan_outputs,
    schema_sensitive_paths,
    sensitive_leaves,
)

FIXTURE_RE = re.compile(r"FIXTURE-(SECRET|EPHEMERAL)-[A-Za-z0-9-]+")
# What a run declares before anything is rendered: the project's `secrets:` values, vaulted Ansible values
# and the ephemeral variable (the plan's configuration JSON carries no `ephemeral` flag).
DECLARED = (
    "FIXTURE-SECRET-token-999",
    "FIXTURE-SECRET-vaulted",
    "FIXTURE-SECRET-loop1",
    "FIXTURE-SECRET-argv",
    "FIXTURE-EPHEMERAL-xyz",
)


def _mask_change(change: dict, registry: SecretRegistry, schema_paths, rtype: str | None) -> dict:
    out = dict(change)
    for side in ("before", "after"):
        smap = change.get(f"{side}_sensitive", False)
        for leaf in sensitive_leaves(change.get(side), smap):
            registry.add(leaf)
        value = change.get(side)
        if side == "after":
            value = merge_unknown(value, change.get("after_unknown", False))
        value = mask_by_map(value, smap)
        if rtype is not None:
            value = mask_by_schema(value, schema_paths, rtype)
        out[side] = value
    return out


def _mask_resource_values(res: dict, registry: SecretRegistry, schema_paths) -> dict:
    out = dict(res)
    for leaf in sensitive_leaves(res.get("values"), res.get("sensitive_values", {})):
        registry.add(leaf)
    v = mask_by_map(res.get("values"), res.get("sensitive_values", {}))
    out["values"] = mask_by_schema(v, schema_paths, res.get("type", ""))
    return out


def _mask_module(mod: dict, registry: SecretRegistry, schema_paths) -> dict:
    out = dict(mod)
    out["resources"] = [_mask_resource_values(r, registry, schema_paths) for r in mod.get("resources", [])]
    if "child_modules" in mod:
        out["child_modules"] = [_mask_module(m, registry, schema_paths) for m in mod["child_modules"]]
    return out


def _mask_outputs(outputs: dict, registry: SecretRegistry) -> dict:
    out = {}
    for name, o in outputs.items():
        flag = o.get("sensitive", False)
        for leaf in sensitive_leaves(o.get("value"), flag):
            registry.add(leaf)
        out[name] = {**o, "value": mask_by_map(o.get("value"), flag)}
    return out


def build(registry: SecretRegistry, fixtures: Path, out_dir: Path, load_json) -> dict[str, dict]:
    """Stages 1-4 over the three Terraform documents, then the stream over both logs."""
    schema_paths = schema_sensitive_paths(load_json("providers-schema.json"))
    for v in DECLARED:
        registry.add(v)

    plan = load_json("plan.json")
    cfg_vars = plan["configuration"]["root_module"]["variables"]
    for name, meta in cfg_vars.items():
        if meta.get("sensitive"):
            registry.add(plan["variables"][name]["value"])
    plan["resource_changes"] = [
        {**rc, "change": _mask_change(rc["change"], registry, schema_paths, rc.get("type"))}
        for rc in plan["resource_changes"]
    ]
    plan["output_changes"] = {
        k: _mask_change(oc, registry, schema_paths, None) for k, oc in plan["output_changes"].items()
    }
    plan["planned_values"] = {
        "outputs": _mask_outputs(plan["planned_values"].get("outputs", {}), registry),
        "root_module": _mask_module(plan["planned_values"]["root_module"], registry, schema_paths),
    }
    if "values" in plan.get("prior_state", {}):
        pv = plan["prior_state"]["values"]
        plan["prior_state"]["values"] = {
            "outputs": _mask_outputs(pv.get("outputs", {}), registry),
            "root_module": _mask_module(pv.get("root_module", {}), registry, schema_paths),
        }

    state = load_json("state.json")
    state["values"] = {
        "outputs": _mask_outputs(state["values"]["outputs"], registry),
        "root_module": _mask_module(state["values"]["root_module"], registry, schema_paths),
    }
    output = _mask_outputs(load_json("output.json"), registry)

    # Stage 3+4 over the WHOLE document, `variables` and `configuration` defaults included (the leak paths).
    specs = {
        "plan": redact_tree(plan, registry, DEFAULT_KEY_DENYLIST),
        "state": redact_tree(state, registry, DEFAULT_KEY_DENYLIST),
        "output": redact_tree(output, registry, DEFAULT_KEY_DENYLIST),
    }
    for name, spec in specs.items():
        (out_dir / f"{name}.spec.json").write_text(json.dumps(spec, indent=1, sort_keys=True), encoding="utf-8")
    for name in ("ansible-stdout.log", "terraform-trace.log"):
        sr = StreamRedactor(registry)
        with (
            (fixtures / name).open(encoding="utf-8", errors="replace") as fh,
            (out_dir / name).open("w", encoding="utf-8") as o,
        ):
            while chunk := fh.read(7):  # tiny chunks exercise the tail buffer
                o.write(sr.feed(chunk))
            o.write(sr.flush())
    return specs


def test_no_fixture_secret_in_any_output_in_any_encoding(
    tmp_path, registry, fixtures_dir, load_json, fixture_secrets, encode
):
    specs = build(registry, fixtures_dir, tmp_path, load_json)
    files = sorted(p for p in tmp_path.rglob("*") if p.is_file())
    assert len(files) == 5
    texts = {p.name: p.read_text(encoding="utf-8") for p in files}

    # 1. the regex the plan names: nothing FIXTURE-shaped anywhere
    leaks = {name: len(FIXTURE_RE.findall(t)) for name, t in texts.items() if FIXTURE_RE.search(t)}
    assert leaks == {}
    # 2. the four encodings of every known placeholder secret, computed independently of the package
    for value in fixture_secrets:
        for enc_name, enc in encode(value).items():
            for name, t in texts.items():
                assert enc not in t, (value, enc_name, name)
    # 3. the gate agrees
    assert scan_outputs(tmp_path, registry) == []
    assert scan_outputs(tmp_path, registry, [FIXTURE_RE.pattern]) == []
    # 4. positive assertions: a pipeline that blanked everything must not pass
    plan = specs["plan"]
    assert plan["variables"]["db_password"] == KEY_PLACEHOLDER  # key denylist on the variable name
    assert plan["variables"]["eph_token"] == KEY_PLACEHOLDER  # `(?i)token` matches the name too
    assert plan["configuration"]["root_module"]["variables"]["db_password"] == KEY_PLACEHOLDER
    assert plan["configuration"]["root_module"]["variables"]["eph_token"] == KEY_PLACEHOLDER
    changes = {rc["address"]: rc["change"] for rc in plan["resource_changes"]}
    assert changes["random_password.pw"]["after"]["result"] == SENSITIVE
    assert changes["random_password.pw"]["after"]["id"] == UNKNOWN
    assert changes["random_password.pw"]["after"]["length"] == 12
    assert changes["terraform_data.t"]["after"]["input"] == {"plain": "hello", "pw": SENSITIVE}
    assert changes["terraform_data.t"]["after"]["output"] == UNKNOWN
    assert plan["output_changes"]["pw_out"]["after"] == SENSITIVE
    assert PLACEHOLDER_RE.fullmatch(plan["output_changes"]["pw_nonsensitive"]["after"])  # the nonsensitive() leak
    assert plan["output_changes"]["plain"]["after"] == "hello"
    state = specs["state"]
    res = {r["address"]: r["values"] for r in state["values"]["root_module"]["resources"]}
    assert res["random_password.pw"]["result"] == SENSITIVE and res["random_password.pw"]["bcrypt_hash"] == SENSITIVE
    assert res["terraform_data.t"]["input"]["pw"] == SENSITIVE
    assert PLACEHOLDER_RE.fullmatch(res["terraform_data.t"]["output"]["pw"])  # the unflagged computed echo
    assert res["terraform_data.t"]["output"]["plain"] == "hello"
    assert state["values"]["outputs"]["pw_out"]["value"] == SENSITIVE
    assert PLACEHOLDER_RE.fullmatch(state["values"]["outputs"]["pw_nonsensitive"]["value"])
    assert specs["output"]["plain"]["value"] == "hello" and specs["output"]["pw_out"]["value"] == SENSITIVE
    log = texts["ansible-stdout.log"]
    assert "token is <redacted:hmac:" in log and "[ERROR]: Task failed: Action failed: boom <redacted:hmac:" in log
    assert '"vaulted": "<redacted:hmac:' in log
    assert texts["terraform-trace.log"].count("\n") == (fixtures_dir / "terraform-trace.log").read_text().count("\n")
    # 5. the entropy scan over the outputs runs and never echoes a placeholder secret
    for name, t in texts.items():
        for _, snippet in entropy_warnings(t):
            assert "FIXTURE" not in snippet, name


def test_value_scrub_without_denylist_still_catches_every_leak_path(tmp_path, registry, fixtures_dir, load_json):
    """Stage 3 alone (no key denylist) replaces the sensitive variable value with its hmac placeholder."""
    schema_paths = schema_sensitive_paths(load_json("providers-schema.json"))
    plan = load_json("plan.json")
    registry.add(plan["variables"]["db_password"]["value"])
    registry.add("FIXTURE-EPHEMERAL-xyz")
    plan["resource_changes"] = [
        {**rc, "change": _mask_change(rc["change"], registry, schema_paths, rc.get("type"))}
        for rc in plan["resource_changes"]
    ]
    out = redact_tree(plan, registry)
    ph = registry.placeholder("FIXTURE-SECRET-abc123")
    assert out["variables"]["db_password"]["value"] == ph
    assert out["configuration"]["root_module"]["variables"]["db_password"]["default"] == ph
    assert out["planned_values"]["outputs"]["pw_out"]["value"] == ph  # planned_values left unmasked on purpose here
    assert out["output_changes"]["pw_nonsensitive"]["after"] == ph
    assert FIXTURE_RE.search(json.dumps(out)) is None
