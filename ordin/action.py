from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Mapping

from . import ACTION_ENVELOPE_SCHEMA_VERSION, ACTION_REVIEW_SCHEMA_VERSION
from .context import ExecutionContext
from .policy import Decision, DecisionResultMixin
from .review import review_command
from .semantics import semantic_evidence_for_command


ACTION_KIND_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]*$")
MAX_ACTION_KIND_LENGTH = 64
MAX_OPERATION_LENGTH = 128
MAX_ACTION_ID_LENGTH = 128
MAX_PARAMETER_DEPTH = 8
MAX_PARAMETER_ITEMS = 128
MAX_PARAMETER_STRING_LENGTH = 32768
KNOWN_ACTION_KINDS = frozenset(("shell", "file", "network", "mcp", "database", "tool"))


JsonValue = Any


def _validate_identifier(value: str, *, name: str, maximum: int, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be non-empty text")
    if len(value) > maximum:
        raise ValueError(f"{name} must be at most {maximum} characters")
    if pattern.fullmatch(value) is None:
        raise ValueError(f"{name} contains unsupported characters")
    return value


def _validate_json_value(value: JsonValue, *, path: str = "parameters", depth: int = 0) -> None:
    if depth > MAX_PARAMETER_DEPTH:
        raise ValueError(f"{path} exceeds maximum nesting depth {MAX_PARAMETER_DEPTH}")
    if value is None or isinstance(value, (str, bool, int, float)):
        if isinstance(value, str) and len(value) > MAX_PARAMETER_STRING_LENGTH:
            raise ValueError(
                f"{path} string must be at most {MAX_PARAMETER_STRING_LENGTH} characters"
            )
        return
    if isinstance(value, list):
        if len(value) > MAX_PARAMETER_ITEMS:
            raise ValueError(f"{path} must contain at most {MAX_PARAMETER_ITEMS} items")
        for index, item in enumerate(value):
            _validate_json_value(item, path=f"{path}[{index}]", depth=depth + 1)
        return
    if isinstance(value, Mapping):
        if len(value) > MAX_PARAMETER_ITEMS:
            raise ValueError(f"{path} must contain at most {MAX_PARAMETER_ITEMS} properties")
        for key, item in value.items():
            if not isinstance(key, str) or not key:
                raise ValueError(f"{path} keys must be non-empty strings")
            if len(key) > MAX_OPERATION_LENGTH:
                raise ValueError(f"{path} key must be at most {MAX_OPERATION_LENGTH} characters")
            _validate_json_value(item, path=f"{path}.{key}", depth=depth + 1)
        return
    raise ValueError(f"{path} contains a non-JSON value of type {type(value).__name__}")


def _copy_json_mapping(value: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    def clone(item: JsonValue) -> JsonValue:
        if isinstance(item, Mapping):
            return {str(key): clone(child) for key, child in item.items()}
        if isinstance(item, list):
            return [clone(child) for child in item]
        return item

    return {str(key): clone(item) for key, item in value.items()}


@dataclass(frozen=True)
class ActionResource:
    type: str
    value: str

    def __post_init__(self) -> None:
        _validate_identifier(
            self.type,
            name="resource type",
            maximum=MAX_ACTION_KIND_LENGTH,
            pattern=ACTION_KIND_PATTERN,
        )
        if not isinstance(self.value, str) or not self.value:
            raise ValueError("resource value must be non-empty text")
        if len(self.value) > MAX_PARAMETER_STRING_LENGTH:
            raise ValueError(
                f"resource value must be at most {MAX_PARAMETER_STRING_LENGTH} characters"
            )

    def as_dict(self) -> dict[str, str]:
        return {"type": self.type, "value": self.value}


@dataclass(frozen=True)
class ActionEnvelope:
    """Caller-owned description of an action Ordin may review but never execute."""

    kind: str
    operation: str
    parameters: Mapping[str, JsonValue] = field(default_factory=dict)
    intent: str | None = None
    context: ExecutionContext | None = None
    action_id: str | None = None

    def __post_init__(self) -> None:
        _validate_identifier(
            self.kind,
            name="action kind",
            maximum=MAX_ACTION_KIND_LENGTH,
            pattern=ACTION_KIND_PATTERN,
        )
        _validate_identifier(
            self.operation,
            name="action operation",
            maximum=MAX_OPERATION_LENGTH,
            pattern=ACTION_KIND_PATTERN,
        )
        if self.action_id is not None:
            if not isinstance(self.action_id, str) or not self.action_id.strip():
                raise ValueError("action_id must be non-empty text or null")
            if len(self.action_id) > MAX_ACTION_ID_LENGTH:
                raise ValueError(f"action_id must be at most {MAX_ACTION_ID_LENGTH} characters")
        if self.intent is not None and not isinstance(self.intent, str):
            raise ValueError("action intent must be a string or null")
        if not isinstance(self.parameters, Mapping):
            raise ValueError("action parameters must be a JSON object")
        _validate_json_value(self.parameters)
        object.__setattr__(self, "parameters", _copy_json_mapping(self.parameters))

    @classmethod
    def shell(
        cls,
        command: str,
        *,
        intent: str | None = None,
        context: ExecutionContext | None = None,
        action_id: str | None = None,
    ) -> "ActionEnvelope":
        if not isinstance(command, str) or not command.strip():
            raise ValueError("shell action requires non-empty command text")
        return cls(
            kind="shell",
            operation="execute",
            parameters={"command": command},
            intent=intent,
            context=context,
            action_id=action_id,
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": ACTION_ENVELOPE_SCHEMA_VERSION,
            "action_id": self.action_id,
            "kind": self.kind,
            "operation": self.operation,
            "parameters": _copy_json_mapping(self.parameters),
            "intent": self.intent,
            "context": self.context.as_dict() if self.context else None,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ActionEnvelope":
        if not isinstance(payload, Mapping):
            raise ValueError("action envelope must be a JSON object")
        schema_version = payload.get("schema_version")
        if schema_version not in {None, ACTION_ENVELOPE_SCHEMA_VERSION}:
            raise ValueError(f"unsupported action envelope schema: {schema_version!r}")
        kind = payload.get("kind")
        operation = payload.get("operation")
        parameters = payload.get("parameters", {})
        intent = payload.get("intent")
        action_id = payload.get("action_id")
        if not isinstance(kind, str):
            raise ValueError("action envelope requires string kind")
        if not isinstance(operation, str):
            raise ValueError("action envelope requires string operation")
        if not isinstance(parameters, Mapping):
            raise ValueError("action envelope parameters must be a JSON object")
        if intent is not None and not isinstance(intent, str):
            raise ValueError("action envelope intent must be a string or null")
        if action_id is not None and not isinstance(action_id, str):
            raise ValueError("action envelope action_id must be a string or null")
        return cls(
            kind=kind,
            operation=operation,
            parameters=parameters,
            intent=intent,
            context=ExecutionContext.from_dict(payload.get("context")),
            action_id=action_id,
        )


@dataclass(frozen=True)
class ActionReview(DecisionResultMixin):
    action: ActionEnvelope
    decision: Decision
    risk: str
    reasons: list[str]
    safer_next_step: str | None
    effects: list[str]
    resources: list[ActionResource]
    adapter: str | None
    intent_alignment: str = "not_applicable"
    trajectory_categories: list[str] = field(default_factory=list)
    policy: dict[str, str] | None = None
    policy_matches: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": ACTION_REVIEW_SCHEMA_VERSION,
            "action": self.action.as_dict(),
            "decision": self.decision,
            "risk": self.risk,
            "reasons": list(self.reasons),
            "safer_next_step": self.safer_next_step,
            "effects": list(self.effects),
            "resources": [resource.as_dict() for resource in self.resources],
            "adapter": self.adapter,
            "intent_alignment": self.intent_alignment,
            "trajectory_categories": list(self.trajectory_categories),
        }
        if self.policy is not None:
            payload["policy"] = dict(self.policy)
        if self.policy_matches:
            payload["policy_matches"] = [dict(item) for item in self.policy_matches]
        return payload


def _resources_from_semantics(
    command: str, context: ExecutionContext | None
) -> list[ActionResource]:
    resolved = semantic_evidence_for_command(command, context=context)
    seen: set[tuple[str, str]] = set()
    resources: list[ActionResource] = []
    for item in resolved.evidence:
        if not item.resource:
            continue
        resource_type, separator, value = item.resource.partition(":")
        if not separator or not resource_type or not value:
            resource_type, value = "unknown", item.resource
        resource_type = resource_type.lower().replace("_", "-")
        key = (resource_type, value)
        if key in seen:
            continue
        seen.add(key)
        resources.append(ActionResource(type=resource_type, value=value))
    return resources


def review_action(action: ActionEnvelope) -> ActionReview:
    """Review a generic action through a registered deterministic adapter."""

    if action.kind == "shell" and action.operation == "execute":
        command = action.parameters.get("command")
        if not isinstance(command, str) or not command.strip():
            return ActionReview(
                action=action,
                decision="block",
                risk="critical",
                reasons=["shell.execute action requires non-empty parameters.command"],
                safer_next_step="Provide the exact command text before review.",
                effects=[],
                resources=[],
                adapter="shell",
            )
        command_review = review_command(
            command,
            intent=action.intent,
            context=action.context,
        )
        semantics = semantic_evidence_for_command(command, context=action.context)
        return ActionReview(
            action=action,
            decision=command_review.decision,
            risk=command_review.risk,
            reasons=list(command_review.reasons),
            safer_next_step=command_review.safer_next_step,
            effects=list(semantics.effects),
            resources=_resources_from_semantics(command, action.context),
            adapter="shell",
            intent_alignment=command_review.intent_alignment,
            trajectory_categories=list(command_review.trajectory_categories or []),
        )

    known_kind = action.kind in KNOWN_ACTION_KINDS
    scope = f"{action.kind}.{action.operation}"
    if known_kind:
        reason = f'no semantic adapter is registered for action "{scope}"'
    else:
        reason = f'action kind "{action.kind}" is not classified by Ordin'
    return ActionReview(
        action=action,
        decision="ask",
        risk="unknown",
        reasons=[reason],
        safer_next_step=(
            "Require explicit review or add a deterministic semantic adapter before execution."
        ),
        effects=[],
        resources=[],
        adapter=None,
    )
