from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from . import ACTION_TRACE_SCHEMA_VERSION


MAX_TRACE_ACTIONS = 32


@dataclass(frozen=True)
class TraceAction:
    command: str

    def as_dict(self) -> dict[str, Any]:
        return {"command": self.command}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "TraceAction":
        if not isinstance(payload, Mapping):
            raise ValueError("trace action must be a JSON object")
        command = payload.get("command")
        if not isinstance(command, str) or not command.strip():
            raise ValueError("trace action requires non-empty command text")
        return cls(command=command)


@dataclass(frozen=True)
class ActionTrace:
    actions: tuple[TraceAction, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": ACTION_TRACE_SCHEMA_VERSION,
            "actions": [action.as_dict() for action in self.actions],
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any] | None) -> "ActionTrace | None":
        if payload is None:
            return None
        if not isinstance(payload, Mapping):
            raise ValueError("trace must be a JSON object")
        schema_version = payload.get("schema_version")
        if schema_version not in {None, ACTION_TRACE_SCHEMA_VERSION}:
            raise ValueError(f"unsupported action trace schema: {schema_version!r}")
        raw_actions = payload.get("actions")
        if not isinstance(raw_actions, list):
            raise ValueError("trace.actions must be an array")
        if len(raw_actions) > MAX_TRACE_ACTIONS:
            raise ValueError(
                f"trace contains {len(raw_actions)} actions; maximum is {MAX_TRACE_ACTIONS}"
            )
        return cls(actions=tuple(TraceAction.from_dict(action) for action in raw_actions))
