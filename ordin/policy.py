from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol, TypeAlias, cast, runtime_checkable


Decision: TypeAlias = Literal["allow", "warn", "ask", "block"]
FailThreshold: TypeAlias = Literal["warn", "ask", "block"]

DECISION_ORDER: dict[Decision, int] = {
    "allow": 0,
    "warn": 1,
    "ask": 2,
    "block": 3,
}
DECISION_EXIT_CODES: dict[Decision, int] = {
    "allow": 0,
    "warn": 10,
    "ask": 20,
    "block": 30,
}
FAIL_THRESHOLDS = frozenset(("warn", "ask", "block"))


@runtime_checkable
class SupportsDecision(Protocol):
    decision: str


def validate_decision(value: str) -> Decision:
    if value not in DECISION_ORDER:
        raise ValueError(f"unsupported review decision: {value!r}")
    return cast(Decision, value)


def validate_fail_threshold(value: str) -> FailThreshold:
    if value not in FAIL_THRESHOLDS:
        raise ValueError(f"unsupported enforcement threshold: {value!r}")
    return cast(FailThreshold, value)


def decision_value(value: str | SupportsDecision) -> Decision:
    if isinstance(value, str):
        return validate_decision(value)
    return validate_decision(value.decision)


class DecisionResultMixin:
    """Ergonomic decision properties shared by public review result types."""

    decision: Decision

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"

    @property
    def warned(self) -> bool:
        return self.decision == "warn"

    @property
    def uncertain(self) -> bool:
        return self.decision == "ask"

    @property
    def blocked(self) -> bool:
        return self.decision == "block"

    @property
    def requires_attention(self) -> bool:
        return self.decision != "allow"


@dataclass(frozen=True)
class ReviewPolicy:
    """Caller-controlled enforcement policy for Ordin review decisions.

    `fail_on="warn"` is conservative and permits only `allow`. `fail_on="ask"`
    permits warnings while requiring escalation for uncertain or blocked actions.
    `fail_on="block"` permits warnings and asks but still rejects explicit blocks.
    """

    fail_on: FailThreshold = "warn"

    def __post_init__(self) -> None:
        object.__setattr__(self, "fail_on", validate_fail_threshold(self.fail_on))

    def allows(self, value: str | SupportsDecision) -> bool:
        decision = decision_value(value)
        return DECISION_ORDER[decision] < DECISION_ORDER[self.fail_on]

    def requires_escalation(self, value: str | SupportsDecision) -> bool:
        decision = decision_value(value)
        return decision != "block" and not self.allows(decision)

    def exit_code(self, value: str | SupportsDecision) -> int:
        decision = decision_value(value)
        return 0 if self.allows(decision) else DECISION_EXIT_CODES[decision]
