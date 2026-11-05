"""Bounded data-only temporal predicates over protected swarm evidence."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import json
from typing import Any, Mapping

from ordin._json_contracts import load_configuration
from ordin._runtime_json import digest
from ordin.action import KNOWN_ACTION_KINDS
from ordin.data import load_effect_catalog
from ordin.temporal import TemporalActionEvidence, TemporalPredicate

from .causal_graph import EDGE_KINDS
from .events import EVENT_KINDS
from .labels import LABELS
from .models import counter, identifier, timestamp

SCHEMA_VERSION = "ordin.swarm_temporal_policy_set.v1"
EVIDENCE_CLASSES = frozenset(
    {"host_authenticated", "backend_observed", "backend_enforced", "current_proposal"}
)
RELATIONS = frozenset({"any", "same", "different", "sibling", "child"})
ORIGINS = frozenset(
    {
        "authorized_user",
        "repository_file",
        "mcp_result",
        "web_content",
        "model_reasoning",
        "unknown_origin",
    }
)


def _values(values: tuple[str, ...], name: str, allowed=None) -> None:
    if (
        type(values) is not tuple
        or len(values) > 16
        or any(type(value) is not str for value in values)
        or len(set(values)) != len(values)
    ):
        raise ValueError("invalid bounded temporal selectors")
    for value in values:
        if name != "transfer_edges":
            identifier(value, name)
        if allowed is not None and value not in allowed:
            raise ValueError("unknown temporal selector")


@dataclass(frozen=True, slots=True)
class SwarmTemporalPredicate:
    effects_any: tuple[str, ...] = ()
    action_kinds: tuple[str, ...] = ()
    operations: tuple[str, ...] = ()
    event_kinds: tuple[str, ...] = ()
    evidence_classes: tuple[str, ...] = (
        "host_authenticated",
        "backend_observed",
        "backend_enforced",
    )
    labels_any: tuple[str, ...] = ()
    origins_any: tuple[str, ...] = ()
    transfer_edges: tuple[str, ...] = ()
    sink_kinds: tuple[str, ...] = ()
    sink_ids: tuple[str, ...] = ()
    agent_relation: str = "any"
    effect_evidence: str = "intended"
    requires_lineage: bool = False
    _compiled: TemporalPredicate | None = field(default=None, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        for name, allowed in (
            ("effects_any", set(load_effect_catalog())),
            ("action_kinds", KNOWN_ACTION_KINDS),
            ("operations", None),
            ("event_kinds", EVENT_KINDS),
            ("evidence_classes", EVIDENCE_CLASSES),
            ("labels_any", LABELS),
            ("origins_any", ORIGINS),
            ("transfer_edges", EDGE_KINDS - {"hypothesized_influence"}),
            ("sink_kinds", {"network", "mcp", "tool", "message", "file", "database"}),
            ("sink_ids", None),
        ):
            _values(getattr(self, name), name, allowed)
        if not any(
            (
                self.effects_any,
                self.action_kinds,
                self.operations,
                self.event_kinds,
                self.labels_any,
                self.origins_any,
                self.transfer_edges,
            )
        ):
            raise ValueError("temporal predicate requires a concrete selector")
        if (
            not self.evidence_classes
            or type(self.agent_relation) is not str
            or self.agent_relation not in RELATIONS
        ):
            raise ValueError("invalid temporal evidence or actor relation")
        if (
            type(self.effect_evidence) is not str
            or self.effect_evidence not in {"intended", "observed"}
            or type(self.requires_lineage) is not bool
        ):
            raise ValueError("invalid temporal effect/lineage predicate")
        prefix = "effect:" if self.effect_evidence == "intended" else "signal:observed-effect:"
        object.__setattr__(
            self,
            "_compiled",
            TemporalPredicate(
                tuple(prefix + effect for effect in self.effects_any),
                self.action_kinds,
                self.operations,
            )
            if self.effects_any
            else None,
        )

    def semantic_match(self, evidence: TemporalActionEvidence) -> bool:
        """Reuse core compiled signal/kind/operation matching, never shell parsing."""
        if not self.effects_any:
            return (not self.action_kinds or evidence.kind in self.action_kinds) and (
                not self.operations or evidence.operation in self.operations
            )
        if self._compiled is None:
            raise ValueError("temporal effect predicate was not compiled")
        return self._compiled.matches(evidence)

    def as_dict(self) -> dict[str, Any]:
        return {
            name: list(getattr(self, name))
            for name in (
                "effects_any",
                "action_kinds",
                "operations",
                "event_kinds",
                "evidence_classes",
                "labels_any",
                "origins_any",
                "transfer_edges",
                "sink_kinds",
                "sink_ids",
            )
        } | {
            "agent_relation": self.agent_relation,
            "effect_evidence": self.effect_evidence,
            "requires_lineage": self.requires_lineage,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> SwarmTemporalPredicate:
        if type(payload) is not dict or set(payload) - {
            name for name, value in cls.__dataclass_fields__.items() if value.init
        }:
            raise ValueError("invalid temporal predicate fields")
        values = dict(payload)
        for name in (
            "effects_any",
            "action_kinds",
            "operations",
            "event_kinds",
            "evidence_classes",
            "labels_any",
            "origins_any",
            "transfer_edges",
            "sink_kinds",
            "sink_ids",
        ):
            if name in values:
                if type(values[name]) is not list or len(values[name]) > 16:
                    raise ValueError("invalid temporal selector collection")
                values[name] = tuple(values[name])
        return cls(**values)


@dataclass(frozen=True, slots=True)
class SwarmTemporalRule:
    rule_id: str
    severity: str
    pattern: tuple[SwarmTemporalPredicate, ...]
    within_events: int = 64
    within_seconds: float = 300
    scope: str = "task"
    aggregation: str = "path"
    quota: int = 1
    count_by: str = "events"
    same_sink: bool = False
    prevention: str = "deny"

    def __post_init__(self) -> None:
        identifier(self.rule_id, "rule_id")
        if (
            type(self.severity) is not str
            or type(self.prevention) is not str
            or self.severity not in {"medium", "high", "critical"}
            or self.prevention
            not in {
                "escalate",
                "deny",
            }
        ):
            raise ValueError("invalid temporal severity/prevention")
        if (
            type(self.pattern) is not tuple
            or not 2 <= len(self.pattern) <= 8
            or any(type(p) is not SwarmTemporalPredicate for p in self.pattern)
        ):
            raise ValueError("bounded temporal pattern required")
        for predicate in self.pattern:
            predicate.__post_init__()
        if (
            type(self.within_events) is not int
            or not len(self.pattern) <= self.within_events <= 128
            or not 1 <= timestamp(self.within_seconds) <= 86400
        ):
            raise ValueError("invalid temporal window")
        if (
            type(self.scope) is not str
            or type(self.aggregation) is not str
            or type(self.count_by) is not str
            or self.scope not in {"task", "swarm"}
            or self.aggregation not in {"path", "causal_ancestors"}
            or self.count_by not in {"events", "actions", "agents"}
        ):
            raise ValueError("unknown temporal aggregation")
        if (
            type(self.quota) is not int
            or not 1 <= self.quota <= 64
            or type(self.same_sink) is not bool
        ):
            raise ValueError("invalid temporal quota")
        if self.aggregation == "path" and (self.quota != 1 or self.count_by != "events"):
            raise ValueError("path rules do not aggregate unrelated events")
        if self.aggregation == "path" and self.pattern[0].agent_relation != "any":
            raise ValueError("first path step has no preceding actor")
        if self.aggregation == "causal_ancestors" and len(self.pattern) != 2:
            raise ValueError(
                "causal quota requires one prior predicate and current final predicate"
            )
        if self.aggregation == "causal_ancestors" and self.quota >= self.within_events:
            raise ValueError("causal quota must fit its bounded event window")
        final = self.pattern[-1]
        if final.origins_any or final.transfer_edges:
            raise ValueError(
                "current origin/transfer selectors belong on authenticated prior steps"
            )
        if (
            final.evidence_classes != ("current_proposal",)
            or final.effect_evidence != "intended"
            or final.event_kinds not in {(), ("proposed",)}
        ):
            raise ValueError("final temporal step must be the exact current proposal")
        if not (final.effects_any or final.action_kinds or final.operations):
            raise ValueError("final temporal step needs exact action semantics")

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "pattern": [p.as_dict() for p in self.pattern],
            "within_events": self.within_events,
            "within_seconds": self.within_seconds,
            "scope": self.scope,
            "aggregation": self.aggregation,
            "quota": self.quota,
            "count_by": self.count_by,
            "same_sink": self.same_sink,
            "prevention": self.prevention,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> SwarmTemporalRule:
        if type(payload) is not dict or set(payload) - set(cls.__dataclass_fields__):
            raise ValueError("invalid temporal rule fields")
        values = dict(payload)
        pattern = values.get("pattern")
        if type(pattern) is not list or not 2 <= len(pattern) <= 8:
            raise ValueError("bounded temporal pattern required")
        values["pattern"] = tuple(SwarmTemporalPredicate.from_dict(value) for value in pattern)
        return cls(**values)


@dataclass(frozen=True, slots=True)
class SwarmTemporalPolicySet:
    policy_id: str
    revision: int
    rules: tuple[SwarmTemporalRule, ...]

    def __post_init__(self) -> None:
        identifier(self.policy_id, "policy_id")
        counter(self.revision, "policy_revision")
        if (
            self.revision == 0
            or type(self.rules) is not tuple
            or not 1 <= len(self.rules) <= 64
            or any(type(rule) is not SwarmTemporalRule for rule in self.rules)
        ):
            raise ValueError("bounded versioned temporal policy required")
        for rule in self.rules:
            rule.__post_init__()
        if len({rule.rule_id for rule in self.rules}) != len(self.rules):
            raise ValueError("duplicate temporal rule id")

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "policy_id": self.policy_id,
            "revision": self.revision,
            "rules": [r.as_dict() for r in self.rules],
        }

    @property
    def digest(self) -> str:
        self.__post_init__()
        return digest(self.as_dict())

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> SwarmTemporalPolicySet:
        from ordin.schema import validate_named_schema

        try:
            bounded = (
                type(payload) is dict
                and len(json.dumps(payload, allow_nan=False).encode("utf-8")) <= 262144
            )
        except (TypeError, ValueError, UnicodeError, RecursionError):
            bounded = False
        if not bounded or validate_named_schema("swarm_temporal_policy_set", payload):
            raise ValueError("invalid swarm temporal policy schema")
        return cls(
            payload["policy_id"],
            payload["revision"],
            tuple(SwarmTemporalRule.from_dict(value) for value in payload["rules"]),
        )

    def compile(self) -> CompiledSwarmTemporalPolicy:
        self.__post_init__()
        return CompiledSwarmTemporalPolicy(self, tuple(rule.pattern for rule in self.rules))


@dataclass(frozen=True, slots=True)
class CompiledSwarmTemporalPolicy:
    policy: SwarmTemporalPolicySet
    patterns: tuple[tuple[SwarmTemporalPredicate, ...], ...]


def load_swarm_temporal_policy(path: str | Path) -> CompiledSwarmTemporalPolicy:
    payload = load_configuration(path, label="swarm temporal policy", maximum=262144)
    return SwarmTemporalPolicySet.from_dict(dict(payload)).compile()


def default_swarm_temporal_policy() -> CompiledSwarmTemporalPolicy:
    source = Path(__file__).resolve().parents[2] / "data/swarm_temporal_policies.json"
    packaged = Path(__file__).resolve().parents[1] / "resources/swarm_temporal_policies.json"
    return load_swarm_temporal_policy(source if source.exists() else packaged)
