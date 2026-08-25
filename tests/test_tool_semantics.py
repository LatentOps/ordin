import json
from types import MappingProxyType

import pytest

from ordin import (
    ActionHistory,
    AgentGate,
    MCPAdapter,
    Ordin,
    ToolCallAdapter,
    ToolResourceBinding,
    ToolSemanticRule,
    ToolSemanticsRegistry,
    load_tool_semantics,
)


def _registry() -> ToolSemanticsRegistry:
    return ToolSemanticsRegistry(
        registry_id="tests",
        version="1",
        rules=(
            ToolSemanticRule(
                id="fs-read",
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


def test_exact_mcp_identity_produces_trusted_effects_and_resources():
    ordin = Ordin(tool_semantics=_registry())
    action = MCPAdapter(server="filesystem-local").adapt(
        "read_file", {"path": "/workspace/README.md"}
    )

    review = ordin.review_action(action)

    assert review.decision == "allow"
    assert review.risk == "low"
    assert review.effects == ["filesystem.read"]
    assert [(resource.type, resource.value) for resource in review.resources] == [
        ("path", "/workspace/README.md")
    ]
    assert review.adapter == "tool-semantics:fs-read"


def test_wrong_server_does_not_reuse_semantics_for_same_tool_name():
    ordin = Ordin(tool_semantics=_registry())
    action = MCPAdapter(server="different-server").adapt(
        "read_file", {"path": "/workspace/README.md"}
    )

    review = ordin.review_action(action)

    assert review.decision == "ask"
    assert review.risk == "unknown"
    assert review.effects == []


def test_generic_runtime_identity_is_exact():
    ordin = Ordin(tool_semantics=_registry())

    matched = ordin.review_action(
        ToolCallAdapter(runtime="agent-runtime").adapt(
            "upload_file", {"destination": "https://example.com/upload"}
        )
    )
    unmatched = ordin.review_action(
        ToolCallAdapter(runtime="other-runtime").adapt(
            "upload_file", {"destination": "https://example.com/upload"}
        )
    )

    assert matched.effects == ["network.upload"]
    assert matched.decision != "ask"
    assert unmatched.decision == "ask"
    assert unmatched.effects == []


def test_registry_rejects_unknown_effects_and_duplicate_identities():
    with pytest.raises(ValueError, match="unknown effects"):
        ToolSemanticsRegistry(
            registry_id="invalid",
            version="1",
            rules=(
                ToolSemanticRule(
                    id="bad",
                    kind="mcp",
                    server="filesystem-local",
                    tool="read_file",
                    effects=("not.a.real.effect",),
                ),
            ),
        )

    rule = ToolSemanticRule(
        id="one",
        kind="mcp",
        server="filesystem-local",
        tool="read_file",
        effects=("filesystem.read",),
    )
    duplicate = ToolSemanticRule(
        id="two",
        kind="mcp",
        server="filesystem-local",
        tool="read_file",
        effects=("filesystem.read",),
    )
    with pytest.raises(ValueError, match="duplicate tool semantics identity"):
        ToolSemanticsRegistry(
            registry_id="duplicate",
            version="1",
            rules=(rule, duplicate),
        )


def test_compiled_registry_uses_read_only_exact_lookup():
    compiled = _registry().compile()

    assert isinstance(compiled.by_identity, MappingProxyType)
    assert compiled is _registry().compile()
    with pytest.raises(TypeError):
        compiled.by_identity[("mcp", "filesystem-local", "read_file")] = None  # type: ignore[index]


def test_tool_semantics_feed_temporal_review():
    ordin = Ordin(tool_semantics=_registry())
    history = ActionHistory(
        actions=(
            MCPAdapter(server="vault-local").adapt("read_secret", {"name": "deployment-token"}),
        )
    )
    current = ToolCallAdapter(runtime="agent-runtime").adapt(
        "upload_file", {"destination": "https://example.com/collect"}
    )

    review = ordin.review_action(current, history=history)

    assert review.decision == "block"
    assert review.risk == "critical"
    assert "trajectory_secret_exfiltration" in review.trajectory_categories


def test_agent_gate_uses_same_registry_and_never_needs_parallel_safety_logic():
    gate = AgentGate(Ordin(tool_semantics=_registry()))

    decision = gate.evaluate_mcp(
        MCPAdapter(server="filesystem-local"),
        "read_file",
        {"path": "/workspace/README.md"},
    )

    assert decision.may_execute
    assert decision.review.effects == ["filesystem.read"]


def test_loader_validates_schema_and_compiles_exact_identities(tmp_path):
    path = tmp_path / "tools.json"
    path.write_text(json.dumps(_registry().as_dict()), encoding="utf-8")

    compiled = load_tool_semantics(path)
    action = MCPAdapter(server="filesystem-local").adapt(
        "read_file", {"path": "/workspace/README.md"}
    )

    assert compiled.find(action) is not None

    invalid = tmp_path / "invalid.json"
    invalid.write_text(
        json.dumps(
            {
                "schema_version": "ordin.tool_semantics.v1",
                "registry_id": "invalid",
                "version": "1",
                "rules": [
                    {
                        "id": "missing-server",
                        "kind": "mcp",
                        "tool": "read_file",
                        "effects": ["filesystem.read"],
                        "resources": [],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="MCP tool semantics require an exact server identity"):
        load_tool_semantics(invalid)
