from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .indexer import DEFAULT_INDEX_PATH


ROOT = Path(__file__).resolve().parents[1]
SOURCE_DATA_DIR = ROOT / "data"
PACKAGE_DATA_DIR = Path(__file__).resolve().parent / "resources"
DATA_DIR = SOURCE_DATA_DIR if SOURCE_DATA_DIR.exists() else PACKAGE_DATA_DIR
INDEX_ENV_VAR = "COMMANDGRAPH_INDEX"


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_synonyms() -> dict[str, list[str]]:
    return load_json(DATA_DIR / "synonyms.json")


def load_risk_rules() -> list[dict[str, Any]]:
    payload = load_json(DATA_DIR / "risk_rules.json")
    return payload["rules"]


def load_effect_catalog() -> dict[str, dict[str, Any]]:
    payload = load_json(DATA_DIR / "effects.json")
    effects = payload.get("effects", {})
    return effects if isinstance(effects, dict) else {}


def load_man_index(path: Path | None = None) -> list[dict[str, Any]]:
    index_path = path
    if index_path is None:
        configured = os.environ.get(INDEX_ENV_VAR)
        index_path = Path(configured) if configured else DEFAULT_INDEX_PATH
    if not index_path.exists():
        return []

    try:
        payload = load_json(index_path)
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(payload, dict):
        return []
    if payload.get("schema_version") != "commandgraph.man_index.v1":
        return []
    entries = payload.get("entries", [])
    return entries if isinstance(entries, list) else []


def load_commands(include_man_index: bool = True) -> list[dict[str, Any]]:
    commands_dir = DATA_DIR / "commands"
    commands = []
    for path in sorted(commands_dir.glob("*.json")):
        commands.append(load_json(path))
    if include_man_index:
        known = {command.get("command") for command in commands}
        for entry in load_man_index():
            if entry.get("command") not in known:
                commands.append(entry)
                known.add(entry.get("command"))
    return commands


def find_command(command_name: str) -> dict[str, Any] | None:
    normalized = command_name.strip().lower()
    for command in load_commands(include_man_index=True):
        if command.get("command", "").lower() == normalized:
            return command
    return None


def data_health() -> dict[str, Any]:
    commands = load_commands(include_man_index=False)
    risk_rules = load_risk_rules()
    effect_catalog = load_effect_catalog()
    command_names = [command.get("command") for command in commands]
    missing_schema = [
        command.get("command", "<unknown>")
        for command in commands
        if not command.get("schema_version")
    ]
    duplicate_commands = sorted(
        {
            command
            for command in command_names
            if command_names.count(command) > 1
        }
    )

    from .graph import build_effect_graph, validate_effect_graph_data

    graph_errors = validate_effect_graph_data(
        commands=commands,
        catalog=effect_catalog,
    )
    graph_node_count = 0
    graph_edge_count = 0
    if not graph_errors:
        graph = build_effect_graph(
            commands=commands,
            catalog=effect_catalog,
        )
        graph_node_count = len(graph.nodes)
        graph_edge_count = len(graph.edges)

    return {
        "command_count": len(commands),
        "risk_rule_count": len(risk_rules),
        "effect_count": len(effect_catalog),
        "graph_node_count": graph_node_count,
        "graph_edge_count": graph_edge_count,
        "graph_errors": graph_errors,
        "missing_schema": missing_schema,
        "duplicate_commands": duplicate_commands,
        "ok": (
            not missing_schema
            and not duplicate_commands
            and not graph_errors
        ),
    }
