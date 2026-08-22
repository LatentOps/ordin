from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

from . import EFFECT_GRAPH_SCHEMA_VERSION
from .data import find_command, load_commands, load_effect_catalog
from .shell import _strip_wrappers


GRAPH_NODE_TYPES = {
    "command",
    "intent",
    "flag",
    "subcommand",
    "effect",
    "resource",
    "privilege",
}
GRAPH_RELATIONS = {
    "satisfies",
    "contains",
    "produces",
    "affects",
    "safer_alternative",
    "requires",
}
VALID_RISKS = {"low", "medium", "high", "critical"}


@dataclass(frozen=True)
class EffectSpec:
    effect: str
    resource: str | None = None


@dataclass(frozen=True)
class EffectEvidence:
    effect: str
    risk: str
    category: str
    reason: str
    source: str
    resource: str | None = None
    safer_next_step: str | None = None


@dataclass(frozen=True)
class GraphNode:
    id: str
    type: str
    label: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "label": self.label,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class GraphEdge:
    source: str
    relation: str
    target: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "relation": self.relation,
            "target": self.target,
            "metadata": self.metadata,
        }


class CommandEffectGraph:
    def __init__(self) -> None:
        self.nodes: dict[str, GraphNode] = {}
        self.edges: list[GraphEdge] = []

    def add_node(
        self,
        node_id: str,
        node_type: str,
        label: str,
        metadata: dict[str, Any] | None = None,
    ) -> GraphNode:
        if node_type not in GRAPH_NODE_TYPES:
            raise ValueError(f"unsupported graph node type: {node_type}")
        existing = self.nodes.get(node_id)
        if existing is not None:
            if existing.type != node_type:
                raise ValueError(
                    f"graph node {node_id!r} changes type "
                    f"from {existing.type!r} to {node_type!r}"
                )
            return existing
        node = GraphNode(
            id=node_id,
            type=node_type,
            label=label,
            metadata=metadata or {},
        )
        self.nodes[node_id] = node
        return node

    def add_edge(
        self,
        source: str,
        relation: str,
        target: str,
        metadata: dict[str, Any] | None = None,
    ) -> GraphEdge:
        if relation not in GRAPH_RELATIONS:
            raise ValueError(f"unsupported graph relation: {relation}")
        if source not in self.nodes:
            raise ValueError(f"graph edge source does not exist: {source}")
        if target not in self.nodes:
            raise ValueError(f"graph edge target does not exist: {target}")
        edge = GraphEdge(
            source=source,
            relation=relation,
            target=target,
            metadata=metadata or {},
        )
        if edge not in self.edges:
            self.edges.append(edge)
        return edge

    def outgoing(
        self,
        node_id: str,
        relation: str | None = None,
    ) -> list[GraphEdge]:
        return [
            edge
            for edge in self.edges
            if edge.source == node_id
            and (relation is None or edge.relation == relation)
        ]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": EFFECT_GRAPH_SCHEMA_VERSION,
            "nodes": [
                self.nodes[node_id].as_dict()
                for node_id in sorted(self.nodes)
            ],
            "edges": [
                edge.as_dict()
                for edge in sorted(
                    self.edges,
                    key=lambda item: (
                        item.source,
                        item.relation,
                        item.target,
                    ),
                )
            ],
        }


def _effect_specs(raw: Any) -> list[EffectSpec]:
    if raw is None:
        return []
    values = raw if isinstance(raw, list) else [raw]
    specs: list[EffectSpec] = []
    for value in values:
        if isinstance(value, str):
            specs.append(EffectSpec(effect=value))
            continue
        if not isinstance(value, dict):
            continue
        effect = value.get("effect") or value.get("type")
        if not isinstance(effect, str) or not effect:
            continue
        resource = value.get("resource")
        specs.append(
            EffectSpec(
                effect=effect,
                resource=resource if isinstance(resource, str) else None,
            )
        )
    return specs


def _effect_node_id(effect: str) -> str:
    return f"effect:{effect}"


def _resource_node_id(resource: str) -> str:
    return f"resource:{resource}"


def _add_effect_edges(
    graph: CommandEffectGraph,
    source_id: str,
    raw_effects: Any,
    catalog: dict[str, dict[str, Any]],
) -> None:
    for spec in _effect_specs(raw_effects):
        definition = catalog.get(spec.effect, {})
        effect_id = _effect_node_id(spec.effect)
        graph.add_node(
            effect_id,
            "effect",
            spec.effect,
            {
                key: value
                for key, value in definition.items()
                if key in {"risk", "category", "description"}
            },
        )
        graph.add_edge(source_id, "produces", effect_id)
        if spec.resource:
            resource_id = _resource_node_id(spec.resource)
            graph.add_node(resource_id, "resource", spec.resource)
            graph.add_edge(effect_id, "affects", resource_id)


def _add_flag_nodes(
    graph: CommandEffectGraph,
    parent_id: str,
    command_name: str,
    scope_name: str,
    flags: Any,
    catalog: dict[str, dict[str, Any]],
) -> None:
    if not isinstance(flags, dict):
        return
    for canonical_flag, metadata in flags.items():
        if not isinstance(canonical_flag, str) or not isinstance(metadata, dict):
            continue
        flag_id = f"flag:{command_name}:{scope_name}:{canonical_flag}"
        graph.add_node(
            flag_id,
            "flag",
            canonical_flag,
            {"aliases": metadata.get("aliases", [])},
        )
        graph.add_edge(parent_id, "contains", flag_id)
        _add_effect_edges(
            graph,
            flag_id,
            metadata.get("effects", []),
            catalog,
        )


def build_effect_graph(
    commands: list[dict[str, Any]] | None = None,
    catalog: dict[str, dict[str, Any]] | None = None,
) -> CommandEffectGraph:
    commands = (
        load_commands(include_man_index=False)
        if commands is None
        else commands
    )
    catalog = load_effect_catalog() if catalog is None else catalog
    graph = CommandEffectGraph()

    for entry in commands:
        command_name = entry.get("command")
        if not isinstance(command_name, str) or not command_name:
            continue
        graph.add_node(
            f"command:{command_name}",
            "command",
            command_name,
            {
                "summary": entry.get("summary", ""),
                "default_risk": entry.get("default_risk", "unknown"),
            },
        )

    for entry in commands:
        command_name = entry.get("command")
        if not isinstance(command_name, str) or not command_name:
            continue
        command_id = f"command:{command_name}"

        for index, intent in enumerate(entry.get("intents", [])):
            if not isinstance(intent, str) or not intent:
                continue
            intent_id = f"intent:{command_name}:{index}"
            graph.add_node(intent_id, "intent", intent)
            graph.add_edge(intent_id, "satisfies", command_id)

        _add_effect_edges(
            graph,
            command_id,
            entry.get("effects", []),
            catalog,
        )
        _add_flag_nodes(
            graph,
            command_id,
            command_name,
            "command",
            entry.get("flags", {}),
            catalog,
        )

        subcommands = entry.get("subcommands", {})
        if isinstance(subcommands, dict):
            for subcommand, metadata in subcommands.items():
                if not isinstance(subcommand, str) or not isinstance(metadata, dict):
                    continue
                subcommand_id = f"subcommand:{command_name}:{subcommand}"
                graph.add_node(subcommand_id, "subcommand", subcommand)
                graph.add_edge(command_id, "contains", subcommand_id)
                _add_effect_edges(
                    graph,
                    subcommand_id,
                    metadata.get("effects", []),
                    catalog,
                )
                _add_flag_nodes(
                    graph,
                    subcommand_id,
                    command_name,
                    subcommand,
                    metadata.get("flags", {}),
                    catalog,
                )

        for privilege in entry.get("requires_privileges", []):
            if not isinstance(privilege, str) or not privilege:
                continue
            privilege_id = f"privilege:{privilege}"
            graph.add_node(privilege_id, "privilege", privilege)
            graph.add_edge(command_id, "requires", privilege_id)

        for alternative in entry.get("safer_alternatives", []):
            target = (
                alternative.get("command")
                if isinstance(alternative, dict)
                else alternative
            )
            if not isinstance(target, str) or not target:
                continue
            target_id = f"command:{target}"
            if target_id not in graph.nodes:
                continue
            metadata = {}
            if isinstance(alternative, dict) and isinstance(
                alternative.get("reason"),
                str,
            ):
                metadata["reason"] = alternative["reason"]
            graph.add_edge(
                command_id,
                "safer_alternative",
                target_id,
                metadata,
            )

    return graph


def _flag_matches(
    token: str,
    canonical: str,
    aliases: Iterable[str],
) -> bool:
    candidates = [canonical, *aliases]
    for candidate in candidates:
        if token == candidate:
            return True
        if candidate.startswith("--") and token.startswith(f"{candidate}="):
            return True
        if (
            candidate.startswith("-")
            and not candidate.startswith("--")
            and len(candidate) == 2
            and token.startswith("-")
            and not token.startswith("--")
            and len(token) > 2
            and candidate[1] in token[1:]
        ):
            return True
    return False


def _matching_subcommand(
    subcommands: Any,
    args: Sequence[str],
) -> tuple[str, dict[str, Any], int] | None:
    if not isinstance(subcommands, dict):
        return None
    candidates: list[tuple[int, str, dict[str, Any]]] = []
    for name, metadata in subcommands.items():
        if not isinstance(name, str) or not isinstance(metadata, dict):
            continue
        parts = name.split()
        if list(args[: len(parts)]) == parts:
            candidates.append((len(parts), name, metadata))
    if not candidates:
        return None
    length, name, metadata = max(candidates, key=lambda item: item[0])
    return name, metadata, length


def _evidence_from_effects(
    raw_effects: Any,
    source: str,
    catalog: dict[str, dict[str, Any]],
) -> list[EffectEvidence]:
    evidence: list[EffectEvidence] = []
    for spec in _effect_specs(raw_effects):
        definition = catalog.get(spec.effect)
        if not definition:
            continue
        risk = definition.get("risk")
        category = definition.get("category")
        reason = definition.get("reason")
        if (
            risk not in VALID_RISKS
            or not isinstance(category, str)
            or not isinstance(reason, str)
        ):
            continue
        safer_next_step = definition.get("safer_next_step")
        evidence.append(
            EffectEvidence(
                effect=spec.effect,
                risk=risk,
                category=category,
                reason=reason,
                source=source,
                resource=spec.resource,
                safer_next_step=(
                    safer_next_step
                    if isinstance(safer_next_step, str)
                    else None
                ),
            )
        )
    return evidence


def _flag_effect_evidence(
    flags: Any,
    args: Sequence[str],
    source_prefix: str,
    catalog: dict[str, dict[str, Any]],
) -> list[EffectEvidence]:
    if not isinstance(flags, dict):
        return []
    evidence: list[EffectEvidence] = []
    for canonical, metadata in flags.items():
        if not isinstance(canonical, str) or not isinstance(metadata, dict):
            continue
        aliases = [
            alias
            for alias in metadata.get("aliases", [])
            if isinstance(alias, str)
        ]
        if any(
            _flag_matches(token, canonical, aliases)
            for token in args
        ):
            evidence.extend(
                _evidence_from_effects(
                    metadata.get("effects", []),
                    f"{source_prefix} flag {canonical}",
                    catalog,
                )
            )
    return evidence


def _normalized_command_tokens(tokens: Sequence[str]) -> list[str]:
    remaining = _strip_wrappers(tokens)
    if not remaining:
        return []
    executable = remaining[0].rsplit("/", 1)[-1].lower()
    if (
        executable in {"python", "python3"}
        and len(remaining) >= 3
        and remaining[1] == "-m"
    ):
        module = remaining[2].rsplit("/", 1)[-1].lower()
        return [module, *remaining[3:]]
    return [executable, *remaining[1:]]


def effects_for_tokens(tokens: Sequence[str]) -> list[EffectEvidence]:
    normalized = _normalized_command_tokens(tokens)
    if not normalized:
        return []
    command_name = normalized[0].lower()
    entry = find_command(command_name)
    if entry is None:
        return []

    catalog = load_effect_catalog()
    args = normalized[1:]
    evidence = _evidence_from_effects(
        entry.get("effects", []),
        f"command {command_name}",
        catalog,
    )
    evidence.extend(
        _flag_effect_evidence(
            entry.get("flags", {}),
            args,
            f"command {command_name}",
            catalog,
        )
    )

    matched_subcommand = _matching_subcommand(
        entry.get("subcommands", {}),
        args,
    )
    if matched_subcommand:
        subcommand, metadata, length = matched_subcommand
        evidence.extend(
            _evidence_from_effects(
                metadata.get("effects", []),
                f"subcommand {command_name} {subcommand}",
                catalog,
            )
        )
        evidence.extend(
            _flag_effect_evidence(
                metadata.get("flags", {}),
                args[length:],
                f"subcommand {command_name} {subcommand}",
                catalog,
            )
        )

    unique: list[EffectEvidence] = []
    seen: set[tuple[str, str, str | None]] = set()
    for item in evidence:
        key = (item.effect, item.source, item.resource)
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def _iter_effect_owners(entry: dict[str, Any]) -> Iterable[tuple[str, Any]]:
    command_name = entry.get("command", "<unknown>")
    yield f"command {command_name}", entry.get("effects", [])

    flags = entry.get("flags", {})
    if isinstance(flags, dict):
        for flag, metadata in flags.items():
            if isinstance(metadata, dict):
                yield (
                    f"command {command_name} flag {flag}",
                    metadata.get("effects", []),
                )

    subcommands = entry.get("subcommands", {})
    if isinstance(subcommands, dict):
        for subcommand, metadata in subcommands.items():
            if not isinstance(metadata, dict):
                continue
            yield (
                f"command {command_name} subcommand {subcommand}",
                metadata.get("effects", []),
            )
            sub_flags = metadata.get("flags", {})
            if isinstance(sub_flags, dict):
                for flag, flag_metadata in sub_flags.items():
                    if isinstance(flag_metadata, dict):
                        yield (
                            (
                                f"command {command_name} subcommand "
                                f"{subcommand} flag {flag}"
                            ),
                            flag_metadata.get("effects", []),
                        )


def validate_effect_graph_data(
    commands: list[dict[str, Any]] | None = None,
    catalog: dict[str, dict[str, Any]] | None = None,
) -> list[str]:
    commands = (
        load_commands(include_man_index=False)
        if commands is None
        else commands
    )
    catalog = load_effect_catalog() if catalog is None else catalog
    errors: list[str] = []

    for effect_name, definition in catalog.items():
        if not isinstance(effect_name, str) or not effect_name:
            errors.append("effect catalog contains an empty effect name")
            continue
        if not isinstance(definition, dict):
            errors.append(f"effect {effect_name!r} must be an object")
            continue
        if definition.get("risk") not in VALID_RISKS:
            errors.append(
                f"effect {effect_name!r} has invalid risk "
                f"{definition.get('risk')!r}"
            )
        if not isinstance(definition.get("category"), str):
            errors.append(f"effect {effect_name!r} is missing category")
        if not isinstance(definition.get("reason"), str):
            errors.append(f"effect {effect_name!r} is missing reason")

    command_names = {
        entry.get("command")
        for entry in commands
        if isinstance(entry.get("command"), str)
    }
    for entry in commands:
        command_name = entry.get("command", "<unknown>")
        for owner, raw_effects in _iter_effect_owners(entry):
            for spec in _effect_specs(raw_effects):
                if spec.effect not in catalog:
                    errors.append(
                        f"{owner} references unknown effect {spec.effect!r}"
                    )

        for field_name in ("flags", "subcommands"):
            value = entry.get(field_name, {})
            if value is not None and not isinstance(value, dict):
                errors.append(
                    f"command {command_name!r} field {field_name!r} "
                    "must be an object"
                )

        privileges = entry.get("requires_privileges", [])
        if not isinstance(privileges, list) or any(
            not isinstance(item, str) or not item
            for item in privileges
        ):
            errors.append(
                f"command {command_name!r} has invalid requires_privileges"
            )

        alternatives = entry.get("safer_alternatives", [])
        if not isinstance(alternatives, list):
            errors.append(
                f"command {command_name!r} safer_alternatives must be a list"
            )
            continue
        for alternative in alternatives:
            target = (
                alternative.get("command")
                if isinstance(alternative, dict)
                else alternative
            )
            if not isinstance(target, str) or not target:
                errors.append(
                    f"command {command_name!r} has invalid safer alternative"
                )
            elif target not in command_names:
                errors.append(
                    f"command {command_name!r} references missing safer "
                    f"alternative {target!r}"
                )

    if not errors:
        try:
            build_effect_graph(commands=commands, catalog=catalog)
        except ValueError as exc:
            errors.append(str(exc))

    return sorted(set(errors))
