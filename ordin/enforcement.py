from __future__ import annotations

from .policy import (
    DECISION_EXIT_CODES as DECISION_EXIT_CODES,
    DECISION_ORDER,
    FAIL_THRESHOLDS as FAIL_THRESHOLDS,
    ReviewPolicy,
    validate_decision,
    validate_fail_threshold,
)


ENFORCEMENT_ORDER = DECISION_ORDER


def enforcement_exit_code(
    decision: str,
    *,
    enforce: bool = False,
    fail_on: str | None = None,
) -> int:
    validated_decision = validate_decision(decision)
    if not enforce and fail_on is None:
        return 0

    threshold = validate_fail_threshold(fail_on or "warn")
    return ReviewPolicy(fail_on=threshold).exit_code(validated_decision)
