"""Bounded declarative policy data; parsing never grants deployment authority."""

from __future__ import annotations

from dataclasses import dataclass, fields
import json
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

from ordin._runtime_json import digest
from ordin.action import KNOWN_ACTION_KINDS
from ordin.data import load_effect_catalog
from ordin.schema import validate_named_schema

from .budgets import METRICS
from .labels import LABELS
from .models import counter, identifier

SCHEMA_VERSION = "ordin.swarm_policy_set.v1"
CAPABILITIES = frozenset(
    {
        "identity",
        "protected_facts",
        "source_flow",
        "temporal",
        "budget.admission",
        "delegation.online",
        "broker.enforce",
        "filesystem.enforce",
        "process.enforce",
    }
)
MESSAGE_CLASSES = frozenset({"data", "task_handoff", "tool_result"})


def _text(value: str, *, maximum: int = 512) -> None:
    if (
        type(value) is not str
        or not 1 <= len(value) <= maximum
        or any(ord(c) < 32 or ord(c) == 127 for c in value)
        or "*" in value
    ):
        raise ValueError("invalid bounded exact policy value")
    if value.partition(":")[0].lower() in {"http", "https"} and "://" in value:
        try:
            parsed = urlsplit(value)
            if (
                not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.fragment
            ):
                raise ValueError("invalid exact URL")
            parsed.port
        except ValueError:
            raise ValueError("invalid exact destination URL") from None
    elif any(c in value for c in "?[]"):
        raise ValueError("wildcard policy expressions are unsupported")


def _strings(values: tuple[str, ...], *, allowed=None, maximum: int = 32) -> None:
    if (
        type(values) is not tuple
        or len(values) > maximum
        or any(type(v) is not str for v in values)
        or len(set(values)) != len(values)
    ):
        raise ValueError("invalid bounded immutable policy selectors")
    for value in values:
        identifier(value, "policy_selector")
        if allowed is not None and value not in allowed:
            raise ValueError("unknown policy selector")


def _typed(values: tuple, model, maximum=32) -> None:
    if (
        type(values) is not tuple
        or len(values) > maximum
        or any(type(v) is not model for v in values)
        or len(set(values)) != len(values)
    ):
        raise ValueError("invalid bounded typed policy selectors")
    for value in values:
        value.__post_init__()


@dataclass(frozen=True, slots=True)
class SwarmPolicyTool:
    kind: str
    scope: str
    name: str

    def __post_init__(self) -> None:
        if type(self.kind) is not str or self.kind not in {"tool", "mcp"}:
            raise ValueError("unknown policy tool kind")
        _text(self.scope, maximum=128)
        _text(self.name, maximum=128)

    def as_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "scope": self.scope, "name": self.name}


@dataclass(frozen=True, slots=True)
class SwarmPolicyResource:
    type: str
    value: str

    def __post_init__(self) -> None:
        identifier(self.type, "resource_type")
        _text(self.value)

    def as_dict(self) -> dict[str, str]:
        return {"type": self.type, "value": self.value}


@dataclass(frozen=True, slots=True)
class SwarmPolicyPermissions:
    """None inherits the protected maximum; an empty tuple allows no values."""

    action_kinds: tuple[str, ...] | None = None
    effects: tuple[str, ...] | None = None
    tools: tuple[SwarmPolicyTool, ...] | None = None
    resources: tuple[SwarmPolicyResource, ...] | None = None
    destinations: tuple[str, ...] | None = None
    data_labels: tuple[str, ...] | None = None
    message_classes: tuple[str, ...] | None = None

    def __post_init__(self) -> None:
        for name, allowed in (
            ("action_kinds", KNOWN_ACTION_KINDS),
            ("effects", set(load_effect_catalog())),
            ("data_labels", LABELS - {"unclassified"}),
            ("message_classes", MESSAGE_CLASSES),
        ):
            value = getattr(self, name)
            if value is not None:
                _strings(value, allowed=allowed, maximum=64)
        for name, model in (("tools", SwarmPolicyTool), ("resources", SwarmPolicyResource)):
            value = getattr(self, name)
            if value is not None:
                _typed(value, model, maximum=64)
        if self.destinations is not None:
            if (
                type(self.destinations) is not tuple
                or len(self.destinations) > 64
                or len(set(self.destinations)) != len(self.destinations)
            ):
                raise ValueError("invalid bounded destination policy")
            for value in self.destinations:
                _text(value)

    def as_dict(self) -> dict[str, Any]:
        return {
            field.name: None
            if (value := getattr(self, field.name)) is None
            else [v.as_dict() if hasattr(v, "as_dict") else v for v in value]
            for field in fields(self)
        }

    @classmethod
    def from_dict(cls, value: dict) -> SwarmPolicyPermissions:
        if type(value) is not dict or set(value) - {field.name for field in fields(cls)}:
            raise ValueError("unknown policy permission fields")
        parsed: dict[str, Any] = {}
        for name, raw in value.items():
            if raw is not None and (type(raw) is not list or len(raw) > 64):
                raise ValueError("invalid policy permission list")
            model = (
                SwarmPolicyTool
                if name == "tools"
                else SwarmPolicyResource
                if name == "resources"
                else None
            )
            parsed[name] = None if raw is None else tuple(model(**v) if model else v for v in raw)
        return cls(**parsed)


@dataclass(frozen=True, slots=True)
class SwarmBudgetCondition:
    scope: str
    metric: str
    remaining_lte: int

    def __post_init__(self) -> None:
        if (
            self.scope not in {"tenant", "swarm", "task", "agent"}
            or self.metric not in METRICS
            or type(self.remaining_lte) is not int
            or not 0 <= self.remaining_lte <= 10**15
        ):
            raise ValueError("invalid bounded budget policy condition")

    def as_dict(self) -> dict[str, Any]:
        return {"scope": self.scope, "metric": self.metric, "remaining_lte": self.remaining_lte}


@dataclass(frozen=True, slots=True)
class SwarmBudgetConstraint:
    scope: str
    metric: str
    maximum: int
    subject: str | None = None

    def __post_init__(self) -> None:
        SwarmBudgetCondition(self.scope, self.metric, self.maximum)
        if self.subject is not None:
            identifier(self.subject, "budget_subject")
        if self.scope in {"tenant", "swarm"} and self.subject is not None:
            raise ValueError("budget aggregate scope cannot select claimed identities")

    def as_dict(self) -> dict[str, Any]:
        return {
            "scope": self.scope,
            "metric": self.metric,
            "maximum": self.maximum,
            "subject": self.subject,
        }


@dataclass(frozen=True, slots=True)
class SwarmPolicySelector:
    tenant_ids: tuple[str, ...] = ()
    swarm_ids: tuple[str, ...] = ()
    task_ids: tuple[str, ...] = ()
    agent_ids: tuple[str, ...] = ()
    role_ids: tuple[str, ...] = ()
    action_kinds: tuple[str, ...] = ()
    operations: tuple[str, ...] = ()
    effects_any: tuple[str, ...] = ()
    effects_all: tuple[str, ...] = ()
    tools_any: tuple[SwarmPolicyTool, ...] = ()
    resources_any: tuple[SwarmPolicyResource, ...] = ()
    destinations_any: tuple[str, ...] = ()
    data_labels_any: tuple[str, ...] = ()
    message_classes_any: tuple[str, ...] = ()
    temporal_categories_any: tuple[str, ...] = ()
    budgets: tuple[SwarmBudgetCondition, ...] = ()

    def __post_init__(self) -> None:
        for name, allowed in (
            ("tenant_ids", None),
            ("swarm_ids", None),
            ("task_ids", None),
            ("agent_ids", None),
            ("role_ids", None),
            ("operations", None),
            ("action_kinds", KNOWN_ACTION_KINDS),
            ("effects_any", set(load_effect_catalog())),
            ("effects_all", set(load_effect_catalog())),
            ("data_labels_any", LABELS),
            ("message_classes_any", MESSAGE_CLASSES),
            ("temporal_categories_any", None),
        ):
            _strings(getattr(self, name), allowed=allowed)
        _typed(self.tools_any, SwarmPolicyTool)
        _typed(self.resources_any, SwarmPolicyResource)
        _typed(self.budgets, SwarmBudgetCondition)
        if (
            type(self.destinations_any) is not tuple
            or len(self.destinations_any) > 32
            or len(set(self.destinations_any)) != len(self.destinations_any)
        ):
            raise ValueError("invalid bounded destination selectors")
        for value in self.destinations_any:
            _text(value)

    def as_dict(self) -> dict[str, Any]:
        return {
            field.name: [
                v.as_dict() if hasattr(v, "as_dict") else v for v in getattr(self, field.name)
            ]
            for field in fields(self)
        }

    @classmethod
    def from_dict(cls, value: dict) -> SwarmPolicySelector:
        if type(value) is not dict or set(value) - {field.name for field in fields(cls)}:
            raise ValueError("unknown policy selector fields")
        parsed: dict[str, Any] = {}
        for name, raw in value.items():
            if type(raw) is not list or len(raw) > 32:
                raise ValueError("invalid bounded policy selector list")
            model = (
                SwarmPolicyTool
                if name == "tools_any"
                else SwarmPolicyResource
                if name == "resources_any"
                else SwarmBudgetCondition
                if name == "budgets"
                else None
            )
            parsed[name] = tuple(model(**v) if model else v for v in raw)
        return cls(**parsed)


@dataclass(frozen=True, slots=True)
class SwarmPolicyRule:
    rule_id: str
    disposition: str
    match: SwarmPolicySelector = SwarmPolicySelector()

    def __post_init__(self) -> None:
        identifier(self.rule_id, "rule_id")
        if (
            type(self.disposition) is not str
            or self.disposition not in {"execute", "escalate", "deny"}
            or type(self.match) is not SwarmPolicySelector
        ):
            raise ValueError("invalid typed swarm policy rule")
        self.match.__post_init__()

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "disposition": self.disposition,
            "match": self.match.as_dict(),
        }


@dataclass(frozen=True, slots=True)
class SwarmPolicySet:
    policy_id: str
    revision: int
    tenant_id: str
    swarm_id: str
    permissions: SwarmPolicyPermissions = SwarmPolicyPermissions()
    rules: tuple[SwarmPolicyRule, ...] = ()
    default_disposition: str = "deny"
    unknown_disposition: str = "deny"
    required_checks: tuple[str, ...] = ()
    required_capabilities: tuple[str, ...] = ("identity",)
    budgets: tuple[SwarmBudgetConstraint, ...] = ()
    delegation_maximum_digest: str | None = None
    enforcement_scope: str = "review_only"

    def __post_init__(self) -> None:
        for name in ("policy_id", "tenant_id", "swarm_id"):
            identifier(getattr(self, name), name)
        counter(self.revision, "policy_revision")
        if self.revision == 0 or type(self.permissions) is not SwarmPolicyPermissions:
            raise ValueError("policy requires exact version and typed permissions")
        self.permissions.__post_init__()
        _typed(self.rules, SwarmPolicyRule, maximum=128)
        if len({v.rule_id for v in self.rules}) != len(self.rules):
            raise ValueError("duplicate policy rule ID")
        if (
            type(self.default_disposition) is not str
            or self.default_disposition not in {"execute", "escalate", "deny"}
            or type(self.unknown_disposition) is not str
            or self.unknown_disposition not in {"escalate", "deny"}
        ):
            raise ValueError("unknown policy facts cannot authorize execution")
        _strings(self.required_checks, maximum=64)
        _strings(self.required_capabilities, allowed=CAPABILITIES)
        _typed(self.budgets, SwarmBudgetConstraint, maximum=64)
        if len({(v.scope, v.metric, v.subject) for v in self.budgets}) != len(self.budgets):
            raise ValueError("duplicate policy budget selector")
        if self.delegation_maximum_digest is not None:
            from .events import _hex

            _hex(self.delegation_maximum_digest, "delegation maximum digest")
        if type(self.enforcement_scope) is not str or self.enforcement_scope not in {
            "review_only",
            "broker_owned_fresh_worker_route",
            "all_agent_paths",
        }:
            raise ValueError("unknown required policy enforcement scope")
        if len(json.dumps(self.as_dict(), allow_nan=False).encode()) > 65536:
            raise ValueError("declarative policy byte limit exceeded")

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "policy_id": self.policy_id,
            "revision": self.revision,
            "tenant_id": self.tenant_id,
            "swarm_id": self.swarm_id,
            "permissions": self.permissions.as_dict(),
            "rules": [v.as_dict() for v in self.rules],
            "default_disposition": self.default_disposition,
            "unknown_disposition": self.unknown_disposition,
            "required_checks": list(self.required_checks),
            "required_capabilities": list(self.required_capabilities),
            "budgets": [v.as_dict() for v in self.budgets],
            "delegation_maximum_digest": self.delegation_maximum_digest,
            "enforcement_scope": self.enforcement_scope,
        }

    @property
    def digest(self) -> str:
        self.__post_init__()
        return digest(self.as_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> SwarmPolicySet:
        try:
            if (
                type(value) is not dict
                or len(json.dumps(value).encode()) > 65536
                or validate_named_schema("swarm_policy_set", value)
            ):
                raise ValueError("invalid policy")
            return cls(
                value["policy_id"],
                value["revision"],
                value["tenant_id"],
                value["swarm_id"],
                SwarmPolicyPermissions.from_dict(value["permissions"]),
                tuple(
                    SwarmPolicyRule(
                        v["rule_id"], v["disposition"], SwarmPolicySelector.from_dict(v["match"])
                    )
                    for v in value["rules"]
                ),
                value["default_disposition"],
                value["unknown_disposition"],
                tuple(value["required_checks"]),
                tuple(value["required_capabilities"]),
                tuple(SwarmBudgetConstraint(**v) for v in value["budgets"]),
                value["delegation_maximum_digest"],
                value["enforcement_scope"],
            )
        except (KeyError, TypeError, ValueError, UnicodeError, RecursionError, OverflowError):
            raise ValueError("invalid bounded declarative swarm policy") from None


def load_swarm_policy_set(path: str | Path) -> SwarmPolicySet:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate policy key")
            result[key] = value
        return result

    try:
        with Path(path).open("rb") as stream:
            raw = stream.read(65537)
        if len(raw) > 65536:
            raise ValueError("policy too large")
        return SwarmPolicySet.from_dict(json.loads(raw, object_pairs_hook=unique))
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
        raise ValueError("invalid explicit swarm policy file") from None
