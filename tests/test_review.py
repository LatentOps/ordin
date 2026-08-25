from ordin.review import review_command


def test_review_reports_intent_alignment():
    review = review_command("chmod +x script.sh", intent="make file runnable")
    payload = review.as_dict()
    assert payload["schema_version"] == "ordin.review.v1"
    assert payload["intent_alignment"] == "matched"
    assert review.decision in {"allow", "warn"}


def test_review_warns_when_command_mismatches_intent():
    review = review_command("curl https://example.com", intent="make file runnable")
    assert review.decision == "warn"
    assert review.risk == "medium"
    assert review.intent_alignment == "mismatch"


def test_review_asks_for_unclassified_command_without_intent():
    review = review_command("definitely-not-a-command --flag")
    assert review.decision == "ask"
    assert review.risk == "unknown"
    assert review.intent_alignment == "not_provided"
