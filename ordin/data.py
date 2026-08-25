from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from . import EFFECT_CATALOG_SCHEMA_VERSION, RISK_RULES_SCHEMA_VERSION
from .indexer import DEFAULT_INDEX_PATH
from .packs import (
    discover_packs,
    enabled_packs,
    load_pack_commands,
    load_pack_effect_catalog,
    load_pack_risk_rules,
    pack_file_errors,
)


ROOT = Path(__file__).resolve().parents[1]
SOURCE_DATA_DIR = ROOT / "data"
PACKAGE_DATA_DIR = Path(__file__).resolve().parent / "resources"
DATA_DIR = SOURCE_DATA_DIR if SOURCE_DATA_DIR.exists() else PACKAGE_DATA_DIR
INDEX_ENV_VAR = "ORDIN_INDEX"


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_synonyms() -> dict[str, list[str]]:
    return load_json(DATA_DIR / "synonyms.json")


def _load_core_commands() -> list[dict[str, Any]]:
    commands_dir = DATA_DIR / "commands"
    return [load_json(path) for path in sorted(commands_dir.glob("*.json"))]


def _load_core_risk_rules() -> list[dict[str, Any]]:
    payload = load_json(DATA_DIR / "risk_rules.json")
    rules = payload.get("rules", []) if isinstance(payload, dict) else []
    return [rule for rule in rules if isinstance(rule, dict)]


def _load_core_effect_catalog() -> dict[str, dict[str, Any]]:
    payload = load_json(DATA_DIR / "effects.json")
    effects = payload.get("effects", {}) if isinstance(payload, dict) else {}
    return (
        {
            name: definition
            for name, definition in effects.items()
            if isinstance(name, str) and isinstance(definition, dict)
        }
        if isinstance(effects, dict)
        else {}
    )


def load_risk_rules() -> list[dict[str, Any]]:
    rules = list(_load_core_risk_rules())
    for pack in enabled_packs():
        rules.extend(load_pack_risk_rules(pack))
    return rules


def load_effect_catalog() -> dict[str, dict[str, Any]]:
    effects = dict(_load_core_effect_catalog())
    for pack in enabled_packs():
        for name, definition in load_pack_effect_catalog(pack).items():
            if name in effects and effects[name] != definition:
                raise ValueError(f"enabled command pack {pack.name!r} redefines effect {name!r}")
            effects[name] = definition
    return effects


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
    if payload.get("schema_version") != "ordin.man_index.v1":
        return []
    entries = payload.get("entries", [])
    return entries if isinstance(entries, list) else []


def load_commands(include_man_index: bool = True) -> list[dict[str, Any]]:
    commands = list(_load_core_commands())
    for pack in enabled_packs():
        commands.extend(load_pack_commands(pack))
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
    packs = discover_packs()
    active_packs = enabled_packs()
    pack_errors = pack_file_errors(packs)

    core_commands = _load_core_commands()
    all_pack_commands = [command for pack in packs for command in load_pack_commands(pack)]
    validation_commands = [*core_commands, *all_pack_commands]
    commands = load_commands(include_man_index=False)

    core_rules = _load_core_risk_rules()
    all_pack_rules = [rule for pack in packs for rule in load_pack_risk_rules(pack)]
    validation_rules = [*core_rules, *all_pack_rules]
    risk_rules = load_risk_rules()
    risk_payload = {
        "schema_version": RISK_RULES_SCHEMA_VERSION,
        "rules": validation_rules,
    }

    effect_catalog = load_effect_catalog()
    validation_effect_catalog = dict(_load_core_effect_catalog())
    for pack in packs:
        for name, definition in load_pack_effect_catalog(pack).items():
            if name in validation_effect_catalog and validation_effect_catalog[name] != definition:
                pack_errors.append(f"pack {pack.name!r} redefines effect {name!r}")
            validation_effect_catalog[name] = definition
    effect_payload = {
        "schema_version": EFFECT_CATALOG_SCHEMA_VERSION,
        "effects": validation_effect_catalog,
    }

    command_names: list[str] = []
    for command in validation_commands:
        command_name = command.get("command")
        if isinstance(command_name, str):
            command_names.append(command_name)
    missing_schema = [
        command.get("command", "<unknown>")
        for command in validation_commands
        if not command.get("schema_version")
    ]
    duplicate_commands = sorted(
        {command for command in command_names if command_names.count(command) > 1}
    )

    from .analyzers import analyzer_pack_bindings
    from .graph import build_effect_graph, validate_effect_graph_data
    from .schema import (
        SCHEMA_FILES,
        resource_parity_errors,
        validate_command_card_schemas,
        validate_named_schema,
        validate_risk_rule_semantics,
        validate_schema_files,
        validate_template_semantics,
    )

    temporal_rule_count = 0
    try:
        from .temporal import default_temporal_policy

        temporal_rule_count = len(default_temporal_policy().policy.rules)
    except ValueError as exc:
        schema_errors = [f"temporal policy: {exc}"]
    else:
        schema_errors = []

    source_temporal = SOURCE_DATA_DIR / "temporal_policies.json"
    package_temporal = PACKAGE_DATA_DIR / "temporal_policies.json"
    temporal_parity_errors: list[str] = []
    if source_temporal.exists() and package_temporal.exists():
        if source_temporal.read_bytes() != package_temporal.read_bytes():
            temporal_parity_errors.append("temporal_policies.json differs from packaged resource")

    schema_errors.extend(validate_schema_files())
    schema_errors.extend(validate_command_card_schemas(validation_commands))
    schema_errors.extend(
        f"risk rules: {error}" for error in validate_named_schema("risk_rules", risk_payload)
    )
    schema_errors.extend(
        f"effect catalog: {error}"
        for error in validate_named_schema("effect_catalog", effect_payload)
    )
    for pack in packs:
        schema_errors.extend(
            f"pack {pack.name}: {error}"
            for error in validate_named_schema("command_pack", pack.manifest)
        )

    bindings = analyzer_pack_bindings()
    for pack in packs:
        for analyzer in pack.analyzers:
            if analyzer not in bindings:
                pack_errors.append(f"pack {pack.name!r} references unknown analyzer {analyzer!r}")
            elif bindings[analyzer] != pack.name:
                pack_errors.append(
                    f"pack {pack.name!r} analyzer {analyzer!r} is bound to {bindings[analyzer]!r}"
                )

    risk_rule_errors = validate_risk_rule_semantics(risk_payload)
    template_errors = validate_template_semantics(validation_commands)
    parity_errors = [*resource_parity_errors(), *temporal_parity_errors]

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
        schema_errors.extend(
            f"effect graph: {error}"
            for error in validate_named_schema("effect_graph", graph.as_dict())
        )

    from .packs import pack_list_payload

    schema_errors.extend(
        f"pack list: {error}" for error in validate_named_schema("pack_list", pack_list_payload())
    )

    schema_errors = sorted(set(schema_errors))
    risk_rule_errors = sorted(set(risk_rule_errors))
    template_errors = sorted(set(template_errors))
    parity_errors = sorted(set(parity_errors))
    pack_errors = sorted(set(pack_errors))

    return {
        "command_count": len(commands),
        "known_command_count": len(validation_commands),
        "risk_rule_count": len(risk_rules),
        "known_risk_rule_count": len(validation_rules),
        "effect_count": len(effect_catalog),
        "temporal_rule_count": temporal_rule_count,
        "schema_count": len(SCHEMA_FILES),
        "pack_count": len(packs),
        "loaded_pack_count": len(active_packs),
        "loaded_packs": [pack.name for pack in active_packs],
        "pack_errors": pack_errors,
        "graph_node_count": graph_node_count,
        "graph_edge_count": graph_edge_count,
        "schema_errors": schema_errors,
        "risk_rule_errors": risk_rule_errors,
        "template_errors": template_errors,
        "resource_parity_errors": parity_errors,
        "graph_errors": graph_errors,
        "missing_schema": missing_schema,
        "duplicate_commands": duplicate_commands,
        "ok": (
            not missing_schema
            and not duplicate_commands
            and not schema_errors
            and not risk_rule_errors
            and not template_errors
            and not parity_errors
            and not pack_errors
            and not graph_errors
        ),
    }
