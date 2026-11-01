"""Terraform policy: the deny floor (code, never YAML) and the plan gate.

Two layers, both fail-closed:

- ``DENY_FLOOR`` is a tuple of frozen rules over a Terraform argv. ``check_argv`` runs before every
  subprocess the adapter starts. Nothing in a project file can reach it: ``Policy`` has no field that
  names the floor, ``check_argv`` takes no ``Policy``, and ``DENY_FLOOR`` is immutable.
- ``Policy`` (``extra='forbid'``) holds what a project file *may* say, and all of it only narrows:
  stateful types and the critical tag add plan-gate blocks; transient error patterns limit retries.
- ``plan_gate`` ports ``aws-account-baseline/PLAN-SAFETY-HOOK.md``: any ``resource_changes[].change.actions``
  containing ``delete`` on a stateful type, or on a resource whose prior or planned tags carry the critical
  tag, blocks unless the gate step lists that exact address in ``allow_delete_of``.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, Field

# ``key=value``; a tag with no ``=`` would partition to (key, "") and never match a resource (silently off).
CRITICAL_TAG_PATTERN = r"^[^=]+=.+$"


class PolicyError(ValueError):
    """An argv or plan violates the deny floor. ``rule`` names the rule that fired."""

    def __init__(self, rule: str, detail: str):
        super().__init__(f"{rule}: {detail}")
        self.rule = rule
        self.detail = detail


# Two-word subcommands: the token after these is part of the subcommand, not a positional.
_COMPOUND = frozenset({"state", "workspace", "providers", "metadata"})

# Flags that take a value as a separate token when no ``=`` is given (Go flag package semantics).
# The adapter always emits ``-flag=value``; this list keeps hand-written argvs from hiding a value in the
# positionals, which matters for the bare-apply rule.
FLAGS_WITH_VALUES = frozenset(
    {
        "backend-config",
        "backup",
        "chdir",
        "filter",
        "from-module",
        "lock-timeout",
        "lockfile",
        "out",
        "parallelism",
        "plugin-dir",
        "replace",
        "state",
        "state-out",
        "target",
        "test-directory",
        "var",
        "var-file",
        "exclude",
        "generate-config-out",
        "cloud-run",
    }
)


@dataclass(frozen=True)
class ParsedArgv:
    """A Terraform command line, split for rule matching."""

    engine: str
    subcommand: tuple[str, ...]
    flags: tuple[str, ...]  # names only, leading dashes and ``=value`` removed, position preserved
    positionals: tuple[str, ...]
    global_flags: tuple[str, ...]  # flags before the subcommand (``-chdir``, ``-version``)

    def has_flag(self, name: str) -> bool:
        return name in self.flags or name in self.global_flags


def _flag_name(token: str) -> str:
    return token.lstrip("-").split("=", 1)[0]


def parse_argv(argv: Sequence[str]) -> ParsedArgv:
    """Split ``[engine, *global_flags, subcommand[, sub], *args]``; ``argv[0]`` is the engine binary."""
    if not argv:
        raise PolicyError("empty-argv", "an empty command line is not a Terraform invocation")
    engine = argv[0]
    rest = list(argv[1:])
    global_flags: list[str] = []
    while rest and rest[0].startswith("-"):
        global_flags.append(_flag_name(rest.pop(0)))
    subcommand: list[str] = []
    if rest:
        subcommand.append(rest.pop(0))
        if subcommand[0] in _COMPOUND and rest and not rest[0].startswith("-"):
            subcommand.append(rest.pop(0))
    flags: list[str] = []
    positionals: list[str] = []
    i = 0
    while i < len(rest):
        tok = rest[i]
        if tok == "--":
            positionals.extend(rest[i + 1 :])
            break
        if tok.startswith("-"):
            name = _flag_name(tok)
            flags.append(name)
            if "=" not in tok and name in FLAGS_WITH_VALUES and i + 1 < len(rest):
                i += 1  # the next token is this flag's value, not a positional
        else:
            positionals.append(tok)
        i += 1
    return ParsedArgv(engine, tuple(subcommand), tuple(flags), tuple(positionals), tuple(global_flags))


@dataclass(frozen=True)
class DenyRule:
    name: str
    description: str
    matches: Callable[[ParsedArgv], bool]


def _sub(*words: str) -> Callable[[ParsedArgv], bool]:
    return lambda p: p.subcommand[: len(words)] == words


def _sub_with_flag(word: str, flag: str) -> Callable[[ParsedArgv], bool]:
    return lambda p: p.subcommand[:1] == (word,) and flag in p.flags


def _flag(flag: str) -> Callable[[ParsedArgv], bool]:
    return lambda p: p.has_flag(flag)


STATE_READ_ONLY = frozenset({"list", "show"})

# The floor. A tuple of frozen rules: nothing at run time can add to, remove from or reorder it.
DENY_FLOOR: tuple[DenyRule, ...] = (
    DenyRule("destroy", "`terraform destroy` is never run by the orchestrator", _sub("destroy")),
    DenyRule("apply-destroy", "`apply -destroy` is destroy by another name", _sub_with_flag("apply", "destroy")),
    DenyRule("plan-destroy", "`plan -destroy` produces a destroy plan", _sub_with_flag("plan", "destroy")),
    DenyRule(
        "state-surgery",
        "`state` subcommands other than list/show (rm, mv, push, pull, replace-provider) rewrite or dump state",
        lambda p: p.subcommand[:1] == ("state",) and (len(p.subcommand) < 2 or p.subcommand[1] not in STATE_READ_ONLY),
    ),
    DenyRule("force-unlock", "`force-unlock` discards another run's lock", _sub("force-unlock")),
    DenyRule("workspace-delete", "`workspace delete` removes a state", _sub("workspace", "delete")),
    DenyRule("import", "CLI `import` adopts resources outside the reviewed plan", _sub("import")),
    DenyRule("taint", "`taint` forces a replacement outside the plan", _sub("taint")),
    DenyRule("untaint", "`untaint` edits state", _sub("untaint")),
    DenyRule("target", "`-target` applies a partial plan", _flag("target")),
    DenyRule("auto-approve", "`-auto-approve` skips the reviewed plan file", _flag("auto-approve")),
    DenyRule(
        "bare-apply",
        "`apply` must name a reviewed plan file (a bare apply plans and applies in one step)",
        lambda p: p.subcommand[:1] == ("apply",) and not p.positionals,
    ),
    DenyRule(
        "migrate-state",
        "`-migrate-state` / `-force-copy` move state; only the explicit migrate_backend action may use them",
        lambda p: p.has_flag("migrate-state") or p.has_flag("force-copy"),
    ),
)

_ALLOWED_WITH_MIGRATE = frozenset({"migrate-state"})


def check_argv(argv: Sequence[str], *, allow_migrate_state: bool = False) -> ParsedArgv:
    """Raise ``PolicyError`` naming the first deny-floor rule the argv hits; return the parse otherwise.

    ``allow_migrate_state`` is the single sanctioned exception, for the ``migrate_backend`` action, and it
    waives only the ``migrate-state`` rule (and only on ``init``).
    """
    parsed = parse_argv(argv)
    for rule in DENY_FLOOR:
        if rule.name in _ALLOWED_WITH_MIGRATE and allow_migrate_state and parsed.subcommand[:1] == ("init",):
            continue
        if rule.matches(parsed):
            raise PolicyError(rule.name, f"{rule.description}; argv: {list(argv)!r}")
    return parsed


class Policy(BaseModel):
    """What a project file may say about Terraform safety. Every field narrows; none can widen the floor."""

    model_config = ConfigDict(extra="forbid")

    stateful_types: list[str] = []
    critical_tag: str = Field(default="critical=true", pattern=CRITICAL_TAG_PATTERN)
    transient_errors: list[str] = []

    def critical_tag_pair(self) -> tuple[str, str]:
        """``key=value``. The key is compared exactly (cloud tag keys are case-sensitive); the value
        case-insensitively."""
        key, _, value = self.critical_tag.partition("=")
        return key, value


class BlockedChange(BaseModel):
    model_config = ConfigDict(extra="forbid")
    address: str
    actions: list[str]
    reason: str


class GateVerdict(BaseModel):
    model_config = ConfigDict(extra="forbid")
    passed: bool
    blocked: list[BlockedChange] = []
    replacements: list[str] = []


def _tags(obj: object) -> dict:
    """Merge ``tags`` and ``tags_all`` from a before/after object (either may be absent or null)."""
    merged: dict = {}
    if isinstance(obj, dict):
        for key in ("tags", "tags_all"):
            value = obj.get(key)
            if isinstance(value, dict):
                merged.update(value)
    return merged


def _is_critical(change: dict, tag: tuple[str, str]) -> bool:
    key, value = tag
    for side in ("before", "after"):
        tags = _tags(change.get(side))
        if key in tags and str(tags[key]).lower() == value.lower():
            return True
    return False


def is_replacement(actions: Sequence[str]) -> bool:
    return "delete" in actions and "create" in actions


def plan_gate(plan_json: dict, policy: Policy, allow_delete_of: Sequence[str] = ()) -> GateVerdict:
    """Inspect a ``show -json`` plan; block deletes (including replacements) of stateful or critical resources."""
    stateful = set(policy.stateful_types)
    critical = policy.critical_tag_pair()
    waived = set(allow_delete_of)
    blocked: list[BlockedChange] = []
    replacements: list[str] = []
    for rc in plan_json.get("resource_changes") or []:
        change = rc.get("change") or {}
        actions = list(change.get("actions") or [])
        address = rc.get("address", "<unknown>")
        if "delete" not in actions:
            continue
        if is_replacement(actions):
            replacements.append(address)
        reasons: list[str] = []
        if rc.get("type") in stateful:
            reasons.append(f"stateful type {rc.get('type')}")
        if _is_critical(change, critical):
            reasons.append(f"tagged {policy.critical_tag}")
        if reasons and address not in waived:
            blocked.append(BlockedChange(address=address, actions=actions, reason="; ".join(reasons)))
    return GateVerdict(passed=not blocked, blocked=blocked, replacements=replacements)
