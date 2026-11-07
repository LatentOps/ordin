"""Optional diagnostic limits preserve validation truth without allocating all errors."""

import tracemalloc

import pytest

from ordin import schema


def limited(value, contract, *, maximum=4):
    return schema.validate_instance(
        value, contract, maximum_errors=maximum, maximum_error_characters=128
    )


def test_default_diagnostics_remain_complete_and_bounded_mode_stops_work(monkeypatch):
    value = [{}] * 1000
    contract = {"type": "array", "items": {"type": "object", "required": ["a", "b", "c"]}}
    ordinary = schema.validate_instance(value, contract)
    assert len(ordinary) == 3000
    calls = 0
    original = schema._type_matches

    def counted(instance, expected):
        nonlocal calls
        calls += 1
        return original(instance, expected)

    monkeypatch.setattr(schema, "_type_matches", counted)
    assert limited(value, contract) == ordinary[:4]
    assert calls < 10


@pytest.mark.parametrize("keyword", ["anyOf", "oneOf"])
@pytest.mark.parametrize("nested", [False, True])
def test_failed_large_alternative_does_not_hide_a_later_valid_branch(keyword, nested):
    bad = {"type": "array", "items": {"type": "object", "required": ["absent"] * 64}}
    contract = {keyword: [bad, {"type": "array"}]}
    value = [{}] * 1000
    if nested:
        contract = {"type": "object", "properties": {"payload": {"anyOf": [contract]}}}
        value = {"payload": value}
    assert limited(value, contract, maximum=1) == []


def test_oneof_still_detects_two_successes_after_a_large_failed_branch():
    contract = {
        "oneOf": [
            {"items": {"required": ["absent"] * 64}},
            {"type": "array"},
            {"anyOf": [{"type": "string"}, {"type": "array"}]},
        ]
    }
    assert limited([{}] * 1000, contract, maximum=1)


@pytest.mark.parametrize(
    "value,contract",
    [
        (None, {"type": ["object", "null"]}),
        (True, {"type": "integer"}),
        (1.5, {"type": "number", "minimum": 0, "maximum": 2}),
        (-1, {"type": "integer", "minimum": 0}),
        (3, {"type": "number", "maximum": 2}),
        ("valid", {"const": "valid"}),
        ("invalid", {"enum": ["valid"]}),
        ("abc", {"type": "string", "minLength": 2, "maxLength": 5, "pattern": "^a"}),
        ("", {"type": "string", "minLength": 1}),
        ("long", {"type": "string", "maxLength": 2, "pattern": "^a"}),
        ("x", {"pattern": "["}),
        ([True, 1], {"type": "array", "uniqueItems": True}),
        ([1, 1.0], {"type": "array", "uniqueItems": True}),
        ([], {"type": "array", "minItems": 1}),
        ([1, 2], {"type": "array", "maxItems": 1, "items": {"type": "string"}}),
        ({"x": 1}, {"type": "object", "additionalProperties": {"type": "integer"}}),
        ({"x": 1}, {"type": "object", "additionalProperties": False}),
        ({"x": 1}, {"type": "object", "maxProperties": 0}),
        ({}, {"type": "object", "required": ["x"]}),
        (1, {"anyOf": [{"type": "string"}, {"type": "integer"}]}),
        (1, {"oneOf": [{"type": "number"}, {"type": "integer"}]}),
        (1, {"anyOf": []}),
        (1, {"oneOf": []}),
    ],
)
def test_bounded_validation_agrees_with_default_validity(value, contract):
    assert bool(limited(value, contract, maximum=1)) == bool(
        schema.validate_instance(value, contract)
    )


@pytest.mark.parametrize("as_property", [False, True])
def test_diagnostic_text_is_bounded_before_rendering_a_large_instance(as_property):
    large = "private-value-" + "x" * 262144
    value, contract = large, {"enum": ["allow", "block"]}
    if as_property:
        value = {large: 1}
        contract = {"type": "object", "additionalProperties": {"type": "string"}}
    tracemalloc.start()
    try:
        errors = limited(value, contract, maximum=1)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert errors and all(len(error) <= 128 for error in errors)
    assert peak < 65536


@pytest.mark.parametrize("parameter", ["maximum_errors", "maximum_error_characters"])
@pytest.mark.parametrize("value", [0, -1, True, 1.5])
def test_invalid_diagnostic_budgets_cannot_turn_failure_into_success(parameter, value):
    with pytest.raises(ValueError, match="positive integers"):
        schema.validate_instance("invalid", {"const": "valid"}, **{parameter: value})
