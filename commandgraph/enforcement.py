from __future__ import annotations


DECISION_EXIT_CODES = {
    "allow": 0,
    "warn": 10,
    "ask": 20,
    "block": 30,
}
ENFORCEMENT_ORDER = {
    "allow": 0,
    "warn": 1,
    "ask": 2,
    "block": 3,
}
FAIL_THRESHOLDS = {"warn", "ask", "block"}


def enforcement_exit_code(
    decision: str,
    *,
    enforce: bool = False,
    fail_on: str | None = None,
) -> int:
    if decision not in DECISION_EXIT_CODES:
        raise ValueError(f"unsupported review decision: {decision!r}")
    if fail_on is not None and fail_on not in FAIL_THRESHOLDS:
        raise ValueError(f"unsupported enforcement threshold: {fail_on!r}")
    if not enforce and fail_on is None:
        return 0

    threshold = fail_on or "warn"
    if ENFORCEMENT_ORDER[decision] < ENFORCEMENT_ORDER[threshold]:
        return 0
    return DECISION_EXIT_CODES[decision]
