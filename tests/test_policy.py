import pytest

from ordin import ReviewPolicy
from ordin.policy import DECISION_ORDER, decision_value, validate_decision, validate_fail_threshold
from ordin.risk import RiskReview, check_command


def test_decision_order_is_monotonic_for_agent_enforcement():
    assert DECISION_ORDER == {"allow": 0, "warn": 1, "ask": 2, "block": 3}


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


def test_unknown_compound_segment_cannot_be_weakened_to_warning():
    review = check_command("mystery-command && rm -rf ./build")
    assert review.decision == "ask"
    assert review.risk == "high"
    assert ReviewPolicy(fail_on="ask").allows(review) is False


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
