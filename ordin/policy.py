from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol, TypeAlias, cast, runtime_checkable


Decision: TypeAlias = Literal["allow", "warn", "ask", "block"]
FailThreshold: TypeAlias = Literal["warn", "ask", "block"]

# Review aggregation and execution enforcement answer different questions.
#
# REVIEW_PRECEDENCE chooses the dominant review label when multiple findings are
# combined. Known elevated risk (warn) is more informative than uncertainty
# (ask), matching Ordin's v0.1 behavior for compound shell findings.
#
# ENFORCEMENT_ORDER controls fail-on thresholds. Here `ask` is stricter than
# `warn` because an uncertain action requires explicit approval.
REVIEW_PRECEDENCE: dict[Decision, int] = {
    "allow": 0,
    "ask": 1,
    "warn": 2,
    "block": 3,
}
ENFORCEMENT_ORDER: dict[Decision, int] = {
    "allow": 0,
    "warn": 1,
    "ask": 2,
    "block": 3,
}
# Internal compatibility alias for existing review aggregation code.
DECISION_ORDER = REVIEW_PRECEDENCE

DECISION_EXIT_CODES: dict[Decision, int] = {
    "allow": 0,
    "warn": 10,
    "ask": 20,
    "block": 30,
}
FAIL_THRESHOLDS = frozenset(("warn", "ask", "block"))


@runtime_checkable
class SupportsDecision(Protocol):
    @property
    def decision(self) -> str: ...


def validate_decision(value: str) -> Decision:
    if value not in REVIEW_PRECEDENCE:
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


def stronger_decision(current: Decision, candidate: Decision) -> Decision:
    """Return the dominant review label without applying execution policy."""

    if REVIEW_PRECEDENCE[candidate] > REVIEW_PRECEDENCE[current]:
        return candidate
    return current


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
    """Caller-controlled execution policy for Ordin review decisions.

    `fail_on="warn"` is conservative and permits only `allow`. `fail_on="ask"`
    permits warnings while requiring approval for uncertain or blocked actions.
    `fail_on="block"` permits warnings and asks but still rejects explicit blocks.
    """

    fail_on: FailThreshold = "warn"

    def __post_init__(self) -> None:
        object.__setattr__(self, "fail_on", validate_fail_threshold(self.fail_on))

    def allows(self, value: str | SupportsDecision) -> bool:
        decision = decision_value(value)
        return ENFORCEMENT_ORDER[decision] < ENFORCEMENT_ORDER[self.fail_on]

    def requires_escalation(self, value: str | SupportsDecision) -> bool:
        decision = decision_value(value)
        return decision != "block" and not self.allows(decision)

    def exit_code(self, value: str | SupportsDecision) -> int:
        decision = decision_value(value)
        return 0 if self.allows(decision) else DECISION_EXIT_CODES[decision]
