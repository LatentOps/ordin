from ordin.data import data_health, find_command
from ordin.graph import (
    build_effect_graph,
    effects_for_tokens,
    validate_effect_graph_data,
)
from ordin.shell import shell_tokens


def _effect_names(command: str) -> set[str]:
    return {item.effect for item in effects_for_tokens(shell_tokens(command))}


def _produced_effect_ids(graph, source: str, effect_type: str) -> set[str]:
    targets = {edge.target for edge in graph.outgoing(source, "produces")}
    return {
        target
        for target in targets
        if graph.nodes[target].type == "effect" and graph.nodes[target].label == effect_type
    }


def test_builds_typed_nodes_and_edges_from_command_cards():
    graph = build_effect_graph()

    assert "command:rm" in graph.nodes
    assert graph.nodes["command:rm"].type == "command"
    assert "flag:rm:command:-r" in graph.nodes
    assert "subcommand:git:reset" in graph.nodes
    assert "privilege:container_runtime_access" in graph.nodes

    rm_delete_effects = _produced_effect_ids(
        graph,
        "command:rm",
        "filesystem.delete",
    )
    assert rm_delete_effects
    assert all(
        graph.nodes[node_id].metadata["effect_type"] == "filesystem.delete"
        for node_id in rm_delete_effects
    )
    assert any(
        edge.source == "command:rm"
        and edge.relation == "safer_alternative"
        and edge.target == "command:find"
        for edge in graph.edges
    )
    assert any(
        edge.source == "command:docker"
        and edge.relation == "requires"
        and edge.target == "privilege:container_runtime_access"
        for edge in graph.edges
    )


def test_effect_resources_keep_producer_provenance():
    graph = build_effect_graph()
    rm_delete_effects = _produced_effect_ids(
        graph,
        "command:rm",
        "filesystem.delete",
    )
    assert rm_delete_effects

    rm_resources = {
        edge.target
        for effect_id in rm_delete_effects
        for edge in graph.outgoing(effect_id, "affects")
    }
    assert "resource:filesystem.target" in rm_resources
    assert "resource:repository.working_tree" not in rm_resources

    git_clean_effects = _produced_effect_ids(
        graph,
        "subcommand:git:clean",
        "filesystem.delete",
    )
    assert git_clean_effects
    git_clean_resources = {
        edge.target
        for effect_id in git_clean_effects
        for edge in graph.outgoing(effect_id, "affects")
    }
    assert "resource:repository.working_tree" in git_clean_resources
    assert "resource:filesystem.target" not in git_clean_resources


def test_graph_export_has_stable_schema_version():
    payload = build_effect_graph().as_dict()
    assert payload["schema_version"] == "ordin.effect_graph.v1"
    assert payload["nodes"]
    assert payload["edges"]


def test_static_effect_resolution_handles_command_flags():
    effects = _effect_names("rm -rf build/")
    assert "filesystem.delete" in effects
    assert "filesystem.recursive_delete" in effects
    assert "confirmation.bypass" in effects


def test_static_effect_resolution_handles_subcommands_and_flags():
    effects = _effect_names("git reset --hard HEAD~1")
    assert "git.local_write" in effects
    assert "git.history_rewrite" in effects


def test_static_effect_resolution_handles_multi_token_subcommands():
    effects = _effect_names("docker system prune -a")
    assert "container.prune" in effects


def test_static_effect_resolution_normalizes_python_module_execution():
    effects = _effect_names("python -m pip install requests")
    assert "package.install" in effects


def test_unmigrated_command_cards_remain_valid_and_loadable():
    head = find_command("head")
    assert head is not None
    assert "effects" not in head

    graph = build_effect_graph()
    assert "command:head" in graph.nodes


def test_effect_graph_data_validates_cleanly():
    assert validate_effect_graph_data() == []


def test_data_health_includes_effect_graph_validation():
    health = data_health()
    assert health["effect_count"] >= 20
    assert health["graph_node_count"] > health["command_count"]
    assert health["graph_edge_count"] > 0
    assert health["graph_errors"] == []
    assert health["ok"] is True


def test_validation_rejects_unknown_effect_and_missing_alternative():
    commands = [
        {
            "schema_version": "ordin.command_card.v1",
            "command": "demo",
            "summary": "Demo command.",
            "aliases": [],
            "intents": [],
            "default_risk": "low",
            "risk_tags": [],
            "effects": ["missing.effect"],
            "safer_alternatives": ["not-present"],
        }
    ]
    errors = validate_effect_graph_data(
        commands=commands,
        catalog={},
    )
    assert any("unknown effect" in error for error in errors)
    assert any("missing safer alternative" in error for error in errors)
