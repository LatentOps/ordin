import pytest

from ordin import (
    ActionEnvelope,
    ActionHistory,
    ActionObservation,
    ExecutionCapabilityProfile,
    MCPAdapter,
    ObservationHistory,
    ObservedResource,
    Ordin,
    TemporalPolicySet,
    TemporalPredicate,
    TemporalRule,
    ToolCallAdapter,
    ToolResourceBinding,
    ToolSemanticRule,
    ToolSemanticsRegistry,
    derive_capabilities,
)
from ordin.schema import validate_named_schema


def _registry() -> ToolSemanticsRegistry:
    return ToolSemanticsRegistry(
        registry_id="execution-tests",
        version="1",
        rules=(
            ToolSemanticRule(
                id="public-read",
                kind="mcp",
                server="filesystem-local",
                tool="read_file",
                effects=("filesystem.read",),
                resources=(ToolResourceBinding(argument="path", type="path"),),
            ),
            ToolSemanticRule(
                id="secret-read",
                kind="mcp",
                server="vault-local",
                tool="read_secret",
                effects=("secret.read",),
                resources=(ToolResourceBinding(argument="name", type="secret"),),
            ),
            ToolSemanticRule(
                id="upload",
                kind="tool",
                runtime="agent-runtime",
                tool="upload_file",
                effects=("network.upload",),
                resources=(ToolResourceBinding(argument="destination", type="url"),),
            ),
        ),
    )


def test_capability_derivation_is_conservative_and_scoped():
    read_profile = derive_capabilities(
        "tool",
        ("filesystem.read", "network.download"),
        (
            ObservedResource(type="path", value="/workspace/README.md"),
            ObservedResource(type="url", value="https://example.com/archive"),
        ),
    )
    assert read_profile.filesystem == "read"
    assert read_profile.filesystem_scopes == ("/workspace/README.md",)
    assert read_profile.network == "read"
    assert read_profile.network_scopes == ("https://example.com/archive",)
    assert read_profile.privilege_escalation is False
    assert read_profile.process_execution is False

    write_profile = derive_capabilities(
        "tool",
        ("filesystem.delete", "network.upload", "privilege.escalate", "code.execute"),
        (),
    )
    assert write_profile.filesystem == "write"
    assert write_profile.network == "write"
    assert write_profile.privilege_escalation is True
    assert write_profile.process_execution is True

    unknown = derive_capabilities("mcp", (), ())
    assert unknown.filesystem == "unknown"
    assert unknown.network == "unknown"
    assert unknown.privilege_escalation is None
    assert unknown.process_execution is None


def test_capability_profile_round_trip_and_validation():
    profile = ExecutionCapabilityProfile(
        filesystem="write",
        filesystem_scopes=("/workspace/build",),
        network="none",
        privilege_escalation=False,
        process_execution=True,
    )
    payload = profile.as_dict()

    assert validate_named_schema("execution_capabilities", payload) == []
    assert ExecutionCapabilityProfile.from_dict(payload) == profile

    with pytest.raises(ValueError, match="filesystem capability scope"):
        ExecutionCapabilityProfile(filesystem_scopes=("",))


def test_action_review_includes_deterministic_capabilities():
    ordin = Ordin(tool_semantics=_registry())
    action = MCPAdapter(server="filesystem-local").adapt(
        "read_file",
        {"path": "/workspace/README.md"},
    )

    review = ordin.review_action(action)

    assert review.capabilities is not None
    assert review.capabilities.filesystem == "read"
    assert review.capabilities.filesystem_scopes == ("/workspace/README.md",)
    assert review.capabilities.network == "none"
    assert validate_named_schema("action_review", review.as_dict()) == []

    unknown = ordin.review_action(
        MCPAdapter(server="unconfigured").adapt("unknown", {"value": "example"})
    )
    assert unknown.capabilities is not None
    assert unknown.capabilities.filesystem == "unknown"
    assert unknown.capabilities.network == "unknown"


def test_observation_round_trip_is_bounded_and_schema_valid():
    observation = ActionObservation(
        action_id="action-1",
        exit_code=0,
        effects=("filesystem.read",),
        resources=(ObservedResource(type="path", value="/workspace/README.md"),),
        metadata={"runtime": "test-agent", "attempt": 1},
    )
    payload = observation.as_dict()

    assert validate_named_schema("action_observation", payload) == []
    assert ActionObservation.from_dict(payload) == observation

    history = ObservationHistory(observations=(observation,))
    history_payload = history.as_dict()
    assert validate_named_schema("observation_history", history_payload) == []
    assert ObservationHistory.from_dict(history_payload) == history

    with pytest.raises(ValueError, match="valid 1 to 64 character identifier"):
        ObservedResource(type="INVALID TYPE", value="x")
    with pytest.raises(ValueError, match="duplicate"):
        ObservationHistory(observations=(observation, observation))


def test_observed_effect_can_strengthen_later_temporal_review():
    policy = TemporalPolicySet(
        policy_id="observed-only",
        version="1",
        rules=(
            TemporalRule(
                id="observed-secret-upload",
                risk="critical",
                category="observed_secret_exfiltration",
                within_actions=2,
                pattern=(
                    TemporalPredicate(signals_any=("signal:observed-effect:secret.read",)),
                    TemporalPredicate(signals_any=("effect:network.upload",)),
                ),
                reason="observed secret access precedes an upload",
            ),
        ),
    )
    ordin = Ordin(tool_semantics=_registry(), temporal_policy=policy)
    prior = MCPAdapter(server="filesystem-local").adapt(
        "read_file",
        {"path": "/workspace/README.md"},
        action_id="prior-1",
    )
    history = ActionHistory(actions=(prior,))
    current = ToolCallAdapter(runtime="agent-runtime").adapt(
        "upload_file",
        {"destination": "https://example.com/collect"},
    )

    without_observation = ordin.review_action(current, history=history)
    assert "observed_secret_exfiltration" not in without_observation.trajectory_categories

    observations = ObservationHistory(
        observations=(
            ActionObservation(
                action_id="prior-1",
                effects=("secret.read",),
            ),
        )
    )
    with_observation = ordin.review_action(
        current,
        history=history,
        observations=observations,
    )

    assert with_observation.decision == "block"
    assert with_observation.risk == "critical"
    assert "observed_secret_exfiltration" in with_observation.trajectory_categories


def test_observation_cannot_erase_predicted_danger():
    ordin = Ordin(tool_semantics=_registry())
    prior = MCPAdapter(server="vault-local").adapt(
        "read_secret",
        {"name": "deployment-token"},
        action_id="secret-1",
    )
    history = ActionHistory(actions=(prior,))
    observations = ObservationHistory(
        observations=(
            ActionObservation(
                action_id="secret-1",
                effects=("filesystem.read",),
            ),
        )
    )
    current = ToolCallAdapter(runtime="agent-runtime").adapt(
        "upload_file",
        {"destination": "https://example.com/collect"},
    )

    review = ordin.review_action(current, history=history, observations=observations)

    assert review.decision == "block"
    assert "trajectory_secret_exfiltration" in review.trajectory_categories


def test_observations_require_exact_unique_history_action_ids():
    ordin = Ordin()
    current = ActionEnvelope.shell("git status --short")
    observations = ObservationHistory(
        observations=(ActionObservation(action_id="missing", exit_code=0),)
    )

    with pytest.raises(ValueError, match="matching action history"):
        ordin.review_action(current, observations=observations)

    history = ActionHistory(
        actions=(ActionEnvelope.shell("git status --short", action_id="known"),)
    )
    with pytest.raises(ValueError, match="unknown action_id"):
        ordin.review_action(current, history=history, observations=observations)

    duplicate_history = ActionHistory(
        actions=(
            ActionEnvelope.shell("git status --short", action_id="dup"),
            ActionEnvelope.shell("git log -1 --oneline", action_id="dup"),
        )
    )
    duplicate_observation = ObservationHistory(
        observations=(ActionObservation(action_id="dup", exit_code=0),)
    )
    with pytest.raises(ValueError, match="unique matching action_id"):
        ordin.review_action(
            current,
            history=duplicate_history,
            observations=duplicate_observation,
        )


def test_public_api_accepts_schema_valid_observation_mapping():
    ordin = Ordin(tool_semantics=_registry())
    prior = MCPAdapter(server="filesystem-local").adapt(
        "read_file",
        {"path": "/workspace/README.md"},
        action_id="prior-1",
    )
    history = ActionHistory(actions=(prior,))
    observations = ObservationHistory(
        observations=(ActionObservation(action_id="prior-1", exit_code=0),)
    )
    current = ToolCallAdapter(runtime="agent-runtime").adapt(
        "upload_file",
        {"destination": "https://example.com/collect"},
    )

    review = ordin.review_action(
        current.as_dict(),
        history=history.as_dict(),
        observations=observations.as_dict(),
    )

    assert review.capabilities is not None
    assert review.capabilities.network == "write"
