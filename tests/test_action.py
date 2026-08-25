import pytest

from ordin import ActionEnvelope, ActionReview, ExecutionContext, Ordin, review_action
from ordin.review import review_command
from ordin.schema import validate_named_schema


def test_shell_action_review_preserves_command_review_decision_and_risk():
    context = ExecutionContext(
        cwd="/workspace/repo",
        repo_root="/workspace/repo",
        agent="test-agent",
    )
    action = ActionEnvelope.shell(
        "rm -rf ./build",
        intent="remove generated build output",
        context=context,
        action_id="action-1",
    )

    generic = review_action(action)
    command = review_command(
        "rm -rf ./build",
        intent="remove generated build output",
        context=context,
    )

    assert generic.decision == command.decision
    assert generic.risk == command.risk
    assert generic.reasons == command.reasons
    assert generic.adapter == "shell"
    assert "filesystem.delete" in generic.effects
    assert "filesystem.recursive_delete" in generic.effects
    assert {resource.type for resource in generic.resources} == {"path"}
    assert any(resource.value == "/workspace/repo/build" for resource in generic.resources)


def test_action_envelope_and_review_round_trip_against_public_schemas():
    action = ActionEnvelope(
        kind="tool",
        operation="call",
        parameters={"name": "lookup", "arguments": {"query": "status"}},
        intent="inspect status",
        context=ExecutionContext(agent="test-agent"),
        action_id="tool-1",
    )

    payload = action.as_dict()
    assert validate_named_schema("action_envelope", payload) == []
    assert ActionEnvelope.from_dict(payload) == action

    review = review_action(action)
    assert review.decision == "ask"
    assert review.risk == "unknown"
    assert review.adapter is None
    assert validate_named_schema("action_review", review.as_dict()) == []


def test_known_action_kind_without_adapter_fails_closed():
    review = review_action(
        ActionEnvelope(
            kind="mcp",
            operation="call",
            parameters={"server": "filesystem", "tool": "read_file"},
        )
    )

    assert review.decision == "ask"
    assert review.uncertain is True
    assert review.effects == []
    assert "no semantic adapter" in review.reasons[0]


def test_future_unknown_action_kind_fails_closed_instead_of_becoming_invalid():
    review = review_action(
        ActionEnvelope(
            kind="robot",
            operation="move",
            parameters={"distance_m": 1.0},
        )
    )

    assert review.decision == "ask"
    assert review.risk == "unknown"
    assert "not classified" in review.reasons[0]


def test_shell_action_requires_exact_command_text():
    action = ActionEnvelope(kind="shell", operation="execute", parameters={})
    review = review_action(action)

    assert review.decision == "block"
    assert review.risk == "critical"
    assert review.adapter == "shell"


def test_action_envelope_rejects_non_json_and_unbounded_parameters():
    with pytest.raises(ValueError, match="non-JSON"):
        ActionEnvelope(kind="tool", operation="call", parameters={"value": object()})

    value = "leaf"
    for _ in range(10):
        value = [value]
    with pytest.raises(ValueError, match="nesting depth"):
        ActionEnvelope(kind="tool", operation="call", parameters={"value": value})


def test_ordin_review_action_accepts_mapping_and_applies_default_context():
    ordin = Ordin(
        context=ExecutionContext(
            cwd="/workspace/repo",
            repo_root="/workspace/repo",
            agent="coding-agent",
        )
    )
    payload = ActionEnvelope.shell("rm -rf ./build").as_dict()

    review = ordin.review_action(payload)

    assert isinstance(review, ActionReview)
    assert review.action.context == ordin.context
    assert review.adapter == "shell"
    assert any(resource.value == "/workspace/repo/build" for resource in review.resources)


def test_schema_validator_enforces_action_bounds_and_extra_properties():
    payload = ActionEnvelope(kind="tool", operation="call").as_dict()
    payload["unexpected"] = True
    errors = validate_named_schema("action_envelope", payload)
    assert any("unexpected property" in error for error in errors)

    payload = ActionEnvelope(kind="tool", operation="call").as_dict()
    payload["kind"] = "a" * 65
    errors = validate_named_schema("action_envelope", payload)
    assert any("longer than 64" in error for error in errors)
