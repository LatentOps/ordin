import json
import pytest

from ordin import (
    ActionEnvelope,
    ActionHistory,
    ActionObservation,
    JsonlAuditSink,
    ObservationHistory,
    Ordin,
    verify_audit_jsonl,
)
from ordin.audit import build_audit_event
from ordin.schema import validate_named_schema


def test_audit_is_disabled_by_default_and_review_remains_write_free(tmp_path):
    audit_path = tmp_path / "audit.jsonl"

    review = Ordin().review_action(ActionEnvelope.shell("git status --short"))

    assert review.allowed
    assert not audit_path.exists()


def test_audit_event_is_versioned_digest_only_and_redacted_by_default():
    review = Ordin().review_action(
        ActionEnvelope.shell(
            "rm -rf /tmp/private-token.txt",
            action_id="private-customer-step",
        )
    )
    event = build_audit_event(review, timestamp="2026-08-29T00:00:00+00:00")
    payload = event.as_dict()

    assert validate_named_schema("audit_event", payload) == []
    assert len(payload["action_digest"]) == 64
    serialized = json.dumps(payload, sort_keys=True)
    assert "rm -rf /tmp/private-token.txt" not in serialized
    assert "/tmp/private-token.txt" not in serialized
    assert "private-customer-step" not in serialized
    assert all(record["summary"] is None for record in payload["provenance"]["records"])


def test_audit_does_not_copy_caller_observation_metadata():
    history = ActionHistory(
        actions=(ActionEnvelope.shell("git status --short", action_id="step-1"),)
    )
    review = Ordin().review_action(
        ActionEnvelope.shell("git log -1 --oneline"),
        history=history,
        observations=ObservationHistory(
            observations=(
                ActionObservation(
                    action_id="step-1",
                    exit_code=0,
                    metadata={"api_key": "do-not-record-this"},
                ),
            )
        ),
    )

    event = build_audit_event(review, timestamp="2026-08-29T00:00:00+00:00")
    serialized = json.dumps(event.as_dict(), sort_keys=True)

    assert "do-not-record-this" not in serialized
    assert "api_key" not in serialized


def test_audit_resource_values_can_be_explicitly_included():
    review = Ordin().review_action(ActionEnvelope.shell("rm -rf /tmp/private-token.txt"))

    redacted = build_audit_event(review, timestamp="2026-08-29T00:00:00+00:00")
    explicit = build_audit_event(
        review,
        timestamp="2026-08-29T00:00:00+00:00",
        include_resource_values=True,
    )

    redacted_values = [
        record["resource"]["value"]
        for record in redacted.as_dict()["provenance"]["records"]
        if record["resource"] is not None
    ]
    explicit_values = [
        record["resource"]["value"]
        for record in explicit.as_dict()["provenance"]["records"]
        if record["resource"] is not None
    ]
    assert redacted_values
    assert all(value.startswith("sha256:") for value in redacted_values)
    assert "/tmp/private-token.txt" in explicit_values


def test_audit_can_explicitly_include_action_ids():
    review = Ordin().review_action(
        ActionEnvelope.shell("git status --short", action_id="step-visible-by-choice")
    )

    default = build_audit_event(review, timestamp="2026-08-29T00:00:00+00:00")
    explicit = build_audit_event(
        review,
        timestamp="2026-08-29T00:00:00+00:00",
        include_action_ids=True,
    )

    assert "step-visible-by-choice" not in json.dumps(default.as_dict(), sort_keys=True)
    assert "step-visible-by-choice" in json.dumps(explicit.as_dict(), sort_keys=True)


def test_jsonl_audit_sink_appends_and_verifies_hash_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    sink = JsonlAuditSink(path, hash_chain=True, fsync=False)
    gate = Ordin(audit=sink)

    gate.review_action(ActionEnvelope.shell("git status --short"))
    gate.review_action(ActionEnvelope.shell("ls -la"))

    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    second = json.loads(lines[1])
    assert first["previous_hash"] is None
    assert len(first["event_hash"]) == 64
    assert second["previous_hash"] == first["event_hash"]

    verification = verify_audit_jsonl(path, require_hash_chain=True)
    assert verification.ok
    assert verification.event_count == 2
    assert verification.last_hash == second["event_hash"]


def test_hash_chain_verification_detects_tampering(tmp_path):
    path = tmp_path / "audit.jsonl"
    sink = JsonlAuditSink(path, hash_chain=True, fsync=False)
    gate = Ordin(audit=sink)
    gate.review_action(ActionEnvelope.shell("git status --short"))
    gate.review_action(ActionEnvelope.shell("ls -la"))

    lines = path.read_text(encoding="utf-8").splitlines()
    payload = json.loads(lines[0])
    payload["decision"] = "block"
    lines[0] = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    verification = verify_audit_jsonl(path, require_hash_chain=True)
    assert not verification.ok
    assert any("event_hash mismatch" in error for error in verification.errors)


def test_hash_chain_verification_detects_removed_middle_event(tmp_path):
    path = tmp_path / "audit.jsonl"
    sink = JsonlAuditSink(path, hash_chain=True, fsync=False)
    gate = Ordin(audit=sink)
    gate.review_action(ActionEnvelope.shell("git status --short"))
    gate.review_action(ActionEnvelope.shell("ls -la"))
    gate.review_action(ActionEnvelope.shell("pwd"))

    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text(lines[0] + "\n" + lines[2] + "\n", encoding="utf-8")

    verification = verify_audit_jsonl(path, require_hash_chain=True)
    assert not verification.ok
    assert any("previous_hash" in error for error in verification.errors)


def test_hash_chained_sink_rejects_preexisting_tampered_file(tmp_path):
    path = tmp_path / "audit.jsonl"
    sink = JsonlAuditSink(path, hash_chain=True, fsync=False)
    Ordin(audit=sink).review_action(ActionEnvelope.shell("git status --short"))

    raw = path.read_text(encoding="utf-8")
    path.write_text(raw.replace('"risk":"low"', '"risk":"critical"'), encoding="utf-8")

    with pytest.raises(ValueError, match="existing audit hash chain is invalid"):
        JsonlAuditSink(path, hash_chain=True, fsync=False)


def test_audit_sink_failure_is_not_silently_ignored(tmp_path, monkeypatch):
    path = tmp_path / "audit.jsonl"
    sink = JsonlAuditSink(path, fsync=False)

    def fail_open(*args, **kwargs):
        raise OSError("disk unavailable")

    monkeypatch.setattr("ordin.audit.os.open", fail_open)
    with pytest.raises(OSError, match="disk unavailable"):
        Ordin(audit=sink).review_action(ActionEnvelope.shell("git status --short"))
    assert not path.exists()


def test_verify_missing_audit_file_is_explicit(tmp_path):
    verification = verify_audit_jsonl(tmp_path / "missing.jsonl")

    assert not verification.ok
    assert verification.event_count == 0
    assert verification.errors == ("audit file does not exist",)


def test_audit_verifier_rejects_decision_provenance_disagreement(tmp_path):
    path = tmp_path / "audit.jsonl"
    event = build_audit_event(
        Ordin().review_action(ActionEnvelope.shell("git status --short")),
        timestamp="2026-08-29T00:00:00+00:00",
    ).as_dict()
    event["decision"] = "block"
    path.write_text(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")

    verification = verify_audit_jsonl(path)

    assert not verification.ok
    assert any("decision disagrees with provenance" in error for error in verification.errors)


def test_ordin_rejects_invalid_audit_sink():
    with pytest.raises(ValueError, match="callable record"):
        Ordin(audit=object())  # type: ignore[arg-type]
