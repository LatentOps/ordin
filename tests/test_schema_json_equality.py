"""JSON value equality must keep booleans distinct from numeric flags."""

import pytest

from ordin.schema import validate_instance, validate_named_schema


@pytest.mark.parametrize("bounded", [False, True])
@pytest.mark.parametrize("keyword", ["const", "enum"])
@pytest.mark.parametrize(
    "expected,actual",
    [
        (False, 0),
        (True, 1),
        (0, False),
        (1.0, True),
        ([False], [0]),
        ({"flag": True}, {"flag": 1}),
        ({"nested": [False, {"flag": True}]}, {"nested": [0, {"flag": 1}]}),
    ],
)
def test_constants_and_enums_reject_boolean_number_substitution(bounded, keyword, expected, actual):
    contract = {keyword: [expected] if keyword == "enum" else expected}
    limits = {"maximum_errors": 1, "maximum_error_characters": 128} if bounded else {}
    assert validate_instance(actual, contract, **limits)


@pytest.mark.parametrize("bounded", [False, True])
@pytest.mark.parametrize("keyword", ["const", "enum"])
@pytest.mark.parametrize(
    "expected,actual",
    [
        (False, False),
        (True, True),
        (None, None),
        (1, 1.0),
        (0.0, -0.0),
        ("one", "one"),
        ([1, False], [1.0, False]),
        ({"number": 1, "flag": True}, {"flag": True, "number": 1.0}),
    ],
)
def test_equal_json_values_remain_valid(bounded, keyword, expected, actual):
    contract = {keyword: [expected] if keyword == "enum" else expected}
    limits = {"maximum_errors": 1, "maximum_error_characters": 128} if bounded else {}
    assert validate_instance(actual, contract, **limits) == []


@pytest.mark.parametrize("bounded", [False, True])
@pytest.mark.parametrize("keyword", ["anyOf", "oneOf"])
def test_composed_constant_branches_retain_json_type_distinctions(bounded, keyword):
    contract = {keyword: [{"const": True}, {"const": 1}]}
    limits = {"maximum_errors": 1, "maximum_error_characters": 128} if bounded else {}
    assert validate_instance(True, contract, **limits) == []
    assert validate_instance(1, contract, **limits) == []
    assert validate_instance(False, contract, **limits)


@pytest.mark.parametrize("bounded", [False, True])
@pytest.mark.parametrize("field,value", [("execution_authority", 0), ("owner_rewrite_possible", 1)])
def test_trace_checkpoint_requires_actual_boolean_disclaimers(bounded, field, value):
    payload = {
        "schema_version": "ordin.trace_checkpoint.v1",
        "event_count": 0,
        "capture_digest": "0" * 64,
        "owner_rewrite_possible": True,
        "execution_authority": False,
    }
    limits = {"maximum_errors": 1, "maximum_error_characters": 128} if bounded else {}
    assert validate_named_schema("trace_checkpoint", payload, **limits) == []
    payload[field] = value
    assert validate_named_schema("trace_checkpoint", payload, **limits)
