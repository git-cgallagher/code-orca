"""Expressions: interpolation, Ansible braces untouched, when must be a bool, undefined raises, default() on
skipped outputs, the sandbox refuses dunder access and mutation."""

from __future__ import annotations

import pytest

from codeorca.expr import (
    ExpressionError,
    evaluate,
    evaluate_when,
    names_override_function,
    render,
    render_tree,
    render_value,
    status_functions,
)

CTX = {
    "inputs": {"env": "dev", "count": 3},
    "vars": {"region": "us-east-1"},
    "steps": {
        "a": {"status": "succeeded", "outputs": {"x": "hello", "changed": True, "tf": {"host": {"value": "h1"}}}},
        "skip": {"status": "skipped", "outputs": None},
        "later": {"status": None, "outputs": None},
    },
    "run": {"id": "20260101T000000Z-abcdef", "status": "running"},
}


def test_interpolation():
    assert render("env=${{ inputs.env }} host=${{ steps.a.outputs.tf.host.value }}", CTX) == "env=dev host=h1"


def test_ansible_braces_pass_through_untouched():
    text = "{{ ansible_host }} and {% if x %}y{% endif %} and {# c #} but ${{ inputs.env }}"
    assert render(text, CTX) == "{{ ansible_host }} and {% if x %}y{% endif %} and {# c #} but dev"
    assert render("{{ untouched }}", CTX) == "{{ untouched }}"


def test_render_value_keeps_native_types_for_a_whole_expression():
    assert render_value("${{ steps.a.outputs.changed }}", CTX) is True
    assert render_value("${{ inputs.count }}", CTX) == 3
    assert render_value("${{ steps.a.outputs.tf }}", CTX) == {"host": {"value": "h1"}}
    assert render_value("n=${{ inputs.count }}", CTX) == "n=3"
    assert render_value(7, CTX) == 7
    assert render_value("plain", CTX) == "plain"


def test_render_tree_recurses():
    tree = {"a": ["${{ inputs.count }}", "x-${{ inputs.env }}"], "b": {"c": "${{ steps.a.outputs.changed }}"}}
    assert render_tree(tree, CTX) == {"a": [3, "x-dev"], "b": {"c": True}}


def test_when_must_be_a_bool():
    assert evaluate_when("steps.a.status == 'succeeded'", CTX) is True
    assert evaluate_when("inputs.count > 5", CTX) is False
    with pytest.raises(ExpressionError, match="must evaluate to a bool, got str"):
        evaluate_when("inputs.env", CTX)
    with pytest.raises(ExpressionError, match="must evaluate to a bool, got int"):
        evaluate_when("inputs.count", CTX)


def test_undefined_name_raises():
    with pytest.raises(ExpressionError, match="UndefinedError: 'dict object' has no attribute 'nope'"):
        render("${{ inputs.nope }}", CTX)
    with pytest.raises(ExpressionError, match="UndefinedError"):
        evaluate_when("steps.a.outputs.nope == 1", CTX)


def test_undefined_native_result_raises_not_returns():
    # compile_expression(undefined_to_none=False) returns an Undefined object; evaluate must turn it into an error
    with pytest.raises(ExpressionError, match="'None' has no attribute 'y'"):
        evaluate("steps.skip.outputs.y", CTX)
    with pytest.raises(ExpressionError):
        render_value("${{ steps.skip.outputs.y }}", CTX)


def test_skipped_outputs_default_works_bare_reference_raises():
    assert render("${{ steps.skip.outputs.y | default('fallback') }}", CTX) == "fallback"
    assert render_value("${{ steps.skip.outputs.y | default(false) }}", CTX) is False
    assert evaluate_when("steps.skip.outputs.y | default(false)", CTX) is False
    with pytest.raises(ExpressionError, match="'None' has no attribute 'y'"):
        render("${{ steps.skip.outputs.y }}", CTX)
    # a step that has not run yet behaves the same: the runner pre-populates every id
    assert render("${{ steps.later.outputs.y | default('d') }}", CTX) == "d"


def test_empty_string_is_never_silently_produced():
    with pytest.raises(ExpressionError):
        render("-e @${{ steps.skip.outputs.handoff }}", CTX)


@pytest.mark.parametrize(
    "template",
    [
        "${{ ''.__class__ }}",
        "${{ steps.a.outputs.x.__class__.__mro__ }}",
        "${{ [].append(1) }}",
        "${{ steps.a.outputs.tf.update({'z': 1}) }}",
        "${{ steps.a.outputs.tf.pop('host') }}",
    ],
)
def test_sandbox_blocks_dunder_and_mutation(template):
    with pytest.raises(ExpressionError, match="SecurityError"):
        render(template, CTX)


def test_syntax_error_is_an_expression_error():
    with pytest.raises(ExpressionError, match="TemplateSyntaxError"):
        render("${{ inputs.env ", CTX)
    with pytest.raises(ExpressionError, match="TemplateSyntaxError"):
        evaluate_when("steps.a.status ==", CTX)


def test_status_functions_in_context():
    fns = status_functions(needs_met=True, needs_failed=False, cancelled=False)
    assert evaluate_when("success()", {**CTX, **fns}) is True
    assert evaluate_when("failure()", {**CTX, **fns}) is False
    assert evaluate_when("always() and steps.a.status in ['succeeded', 'skipped']", {**CTX, **fns}) is True
    fns = status_functions(needs_met=False, needs_failed=True, cancelled=True)
    assert evaluate_when("success()", {**CTX, **fns}) is False
    assert evaluate_when("failure()", {**CTX, **fns}) is True
    assert evaluate_when("cancelled()", {**CTX, **fns}) is True


def test_names_override_function_reads_calls_from_the_parsed_expression():
    assert names_override_function("always()")
    assert names_override_function("steps.x.outputs.y and failure ()")
    assert names_override_function("not cancelled() and (always() or 1)")
    assert not names_override_function("success()")
    assert not names_override_function("steps.x.status == 'always'")
    assert not names_override_function("vars.always_on")
    assert not names_override_function("steps.b.outputs.m != 'failure()'")  # inside a string literal
    assert not names_override_function("inputs.always()")  # an attribute call, not the status function
    assert names_override_function("always( ")  # unparsable: falls back to the text so evaluation reports it
