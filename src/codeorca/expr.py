"""Expressions: ``${{ ... }}`` interpolation and bare ``when:`` conditions (plan section 5.2).

- Jinja2 ``ImmutableSandboxedEnvironment`` with ``StrictUndefined``: a typo'd name raises instead of rendering
  empty; mutating methods (``append``, ``update``) and dunder access (``__class__``) are refused.
- Delimiters are ``${{`` / ``}}`` so Ansible's own ``{{ x }}`` in extra_vars, inventory and playbooks passes
  through untouched. Block (``{% %}``) and comment (``{# #}``) syntax is disabled by using delimiters nobody
  types by accident.
- The context is data only: dicts, lists, str, int, float, bool, None. The GitHub-Actions-style status
  functions ``success()``, ``always()``, ``failure()``, ``cancelled()`` are the only callables, and the runner
  builds them per step (``status_functions``).
- Outputs of a skipped or omitted step are ``None``. ``StrictUndefined`` turns attribute access on ``None``
  into an Undefined (verified on Jinja2 3.1.6: ``'None' has no attribute 'y'`` is raised only when the value
  is used), so ``steps.x.outputs.y | default(...)`` works and a bare reference raises. No custom Undefined
  subclass is needed; what IS needed is that every step id exists in ``ctx["steps"]`` (the runner
  pre-populates ``{"status": None, "outputs": None}``), because ``steps.missing.outputs`` fails one level up
  where ``default()`` cannot catch it.
- ``compile_expression(undefined_to_none=False)`` returns the Undefined object instead of raising, so every
  native evaluation checks for it explicitly.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from typing import Any

import jinja2
from jinja2 import StrictUndefined, TemplateSyntaxError, UndefinedError, nodes
from jinja2.sandbox import ImmutableSandboxedEnvironment

VAR_START = "${{"
VAR_END = "}}"
# A string that is exactly one expression is evaluated natively (keeps bool/int/dict types); anything else
# is string interpolation.
_WHOLE = re.compile(r"^\s*\$\{\{(?P<expr>(?:(?!\}\}).)*)\}\}\s*$", re.DOTALL)
_ANY = re.compile(r"\$\{\{")
# Status functions that override the implicit ``success()`` (GitHub Actions rule): if a step's needs are unmet
# the runner decides without evaluating unless the expression text names one of these.
OVERRIDE_FUNCTION_NAMES = frozenset({"always", "failure", "cancelled"})
OVERRIDE_FUNCTIONS = re.compile(r"\b(always|failure|cancelled)\s*\(")  # the fallback for unparsable text
STATUS_FUNCTION_NAMES = ("success", "always", "failure", "cancelled")


class ExpressionError(ValueError):
    """An expression failed: syntax, undefined name, sandbox refusal, or a ``when`` that is not a bool."""


def make_environment() -> ImmutableSandboxedEnvironment:
    return ImmutableSandboxedEnvironment(
        undefined=StrictUndefined,
        variable_start_string=VAR_START,
        variable_end_string=VAR_END,
        block_start_string="${%",
        block_end_string="%}",
        comment_start_string="${#",
        comment_end_string="#}",
        autoescape=False,
        keep_trailing_newline=True,
    )


ENV = make_environment()


def _check_defined(value: Any, source: str) -> Any:
    if isinstance(value, jinja2.Undefined):
        try:
            value._fail_with_undefined_error()
        except UndefinedError as e:
            raise ExpressionError(f"{source}: {e}") from None
    return value


def has_expression(text: str) -> bool:
    return bool(_ANY.search(text))


def render(template: str, ctx: Mapping[str, Any]) -> str:
    """Interpolate ``${{ ... }}`` inside a string; always returns a string."""
    if not has_expression(template):
        return template
    try:
        return ENV.from_string(template).render(dict(ctx))
    except Exception as e:  # noqa: BLE001 - ZeroDivisionError, a filter's ValueError: the step's error, not a crash
        raise ExpressionError(f"{template!r}: {type(e).__name__}: {e}") from None


def evaluate(expression: str, ctx: Mapping[str, Any]) -> Any:
    """Evaluate a bare expression natively (no delimiters); an Undefined result is an error."""
    try:
        compiled = ENV.compile_expression(expression, undefined_to_none=False)
        value = compiled(**dict(ctx))
    except Exception as e:  # noqa: BLE001 - any failure while evaluating is the expression's error
        raise ExpressionError(f"{expression!r}: {type(e).__name__}: {e}") from None
    return _check_defined(value, repr(expression))


def render_value(template: Any, ctx: Mapping[str, Any]) -> Any:
    """Render a scalar: a string that is exactly one ``${{ expr }}`` yields the expression's native value
    (bool, int, dict, ...); any other string is interpolated; non-strings pass through."""
    if not isinstance(template, str):
        return template
    m = _WHOLE.match(template)
    if m:
        return evaluate(m.group("expr").strip(), ctx)
    return render(template, ctx)


def render_tree(obj: Any, ctx: Mapping[str, Any]) -> Any:
    """``render_value`` applied recursively to dicts and lists (keys are rendered as strings)."""
    if isinstance(obj, dict):
        return {render(k, ctx) if isinstance(k, str) else k: render_tree(v, ctx) for k, v in obj.items()}
    if isinstance(obj, list):
        return [render_tree(v, ctx) for v in obj]
    return render_value(obj, ctx)


def evaluate_when(expression: str, ctx: Mapping[str, Any]) -> bool:
    """A ``when:`` condition must evaluate to a real bool (``type(result) is bool``), else ExpressionError."""
    value = evaluate(expression, ctx)
    if type(value) is not bool:
        raise ExpressionError(f"when {expression!r}: must evaluate to a bool, got {type(value).__name__} {value!r}")
    return value


def names_override_function(expression: str) -> bool:
    """True when the expression calls ``always()``, ``failure()`` or ``cancelled()`` (decided before evaluation:
    ``steps.x.outputs.y and always()`` would raise before ``always`` runs). Read from the parsed expression, so
    the words inside a string literal or an attribute call do not count; an unparsable expression falls back to
    the text, and evaluation then reports the syntax error."""
    try:
        tree = ENV.parse(f"{VAR_START} {expression} {VAR_END}")
    except TemplateSyntaxError:
        return bool(OVERRIDE_FUNCTIONS.search(expression))
    return any(
        isinstance(call.node, nodes.Name) and call.node.name in OVERRIDE_FUNCTION_NAMES
        for call in tree.find_all(nodes.Call)
    )


def status_functions(needs_met: bool, needs_failed: bool, cancelled: bool) -> dict[str, Callable[[], bool]]:
    """GitHub-Actions-style status functions for one step, from the outcome of the steps it needs and the
    run's fail_fast state. They go into the per-step context dict, never into the shared environment."""
    return {
        "success": lambda: needs_met and not cancelled,
        "always": lambda: True,
        "failure": lambda: needs_failed,
        "cancelled": lambda: cancelled,
    }
