import pytest

from ordin import ReviewPolicy
from ordin.policy import (
    ENFORCEMENT_ORDER,
    REVIEW_PRECEDENCE,
    decision_value,
    stronger_decision,
    validate_decision,
    validate_fail_threshold,
)
from ordin.risk import RiskReview, check_command


def test_review_precedence_preserves_existing_safety_labels():
    assert REVIEW_PRECEDENCE == {"allow": 0, "ask": 1, "warn": 2, "block": 3}
    assert stronger_decision("ask", "warn") == "warn"
    assert stronger_decision("warn", "ask") == "warn"


def test_enforcement_order_requires_approval_for_ask():
    assert ENFORCEMENT_ORDER == {"allow": 0, "warn": 1, "ask": 2, "block": 3}


@pytest.mark.parametrize(
    ("fail_on", "allowed"),
    [
        ("warn", {"allow"}),
        ("ask", {"allow", "warn"}),
        ("block", {"allow", "warn", "ask"}),
    ],
)
def test_review_policy_thresholds(fail_on, allowed):
    policy = ReviewPolicy(fail_on=fail_on)
    for decision in ("allow", "warn", "ask", "block"):
        assert policy.allows(decision) is (decision in allowed)
        assert policy.exit_code(decision) == (
            0 if decision in allowed else {"warn": 10, "ask": 20, "block": 30}[decision]
        )


def test_policy_accepts_review_objects_and_exposes_result_properties():
    review = RiskReview(
        decision="ask",
        risk="unknown",
        reasons=["unclassified"],
    )
    assert review.allowed is False
    assert review.warned is False
    assert review.uncertain is True
    assert review.blocked is False
    assert review.requires_attention is True
    assert ReviewPolicy(fail_on="ask").requires_escalation(review) is True


def test_known_warning_remains_dominant_in_compound_review():
    review = check_command("mystery-command && rm -rf ./build")
    assert review.decision == "warn"
    assert review.risk == "high"
    assert "unclassified_command" in (review.risk_categories or [])


def test_invalid_decisions_and_thresholds_fail_explicitly():
    with pytest.raises(ValueError, match="unsupported review decision"):
        validate_decision("maybe")
    with pytest.raises(ValueError, match="unsupported enforcement threshold"):
        validate_fail_threshold("allow")
    with pytest.raises(ValueError, match="unsupported enforcement threshold"):
        ReviewPolicy(fail_on="allow")  # type: ignore[arg-type]


def test_decision_value_reads_review_objects():
    review = RiskReview(decision="warn", risk="high", reasons=["test"])
    assert decision_value(review) == "warn"
