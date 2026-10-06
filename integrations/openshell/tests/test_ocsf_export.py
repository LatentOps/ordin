import json
from dataclasses import replace

import pytest

from ordin import ActionEnvelope, Ordin
from ordin.enforcement_backend import CompilationResult
from ordin.runtime_boundary import CapabilityVerificationResult, DOMAINS
from ordin_openshell.ocsf_export import (
    export_review_findings,
    export_boundary_findings,
    export_compiler_findings,
    export_correlation_findings,
)
from ordin_openshell.observations import parse_openshell_event, OpenShellEventError
from ordin.provenance import ProvenanceRecord


def test_detection_finding_constants_and_digest_only_privacy_are_deterministic():
    review = Ordin().review_action(
        ActionEnvelope.shell("rm -rf /", action_id="sensitive-action-id")
    )
    review = replace(
        review,
        reasons=["Bearer REAL-SECRET-VALUE"],
        trajectory_categories=["trajectory_policy_bypass_attempt"],
    )
    events = export_review_findings(review, time_ms=1791280000000)
    assert len(events) == 2
    assert events == export_review_findings(review, time_ms=1791280000000)
    encoded = json.dumps(events)
    assert (
        "REAL-SECRET-VALUE" not in encoded
        and "sensitive-action-id" not in encoded
        and "rm -rf" not in encoded
    )
    for event in events:
        assert (
            event["category_uid"],
            event["class_uid"],
            event["activity_id"],
            event["type_uid"],
        ) == (2, 2004, 1, 200401)
        assert event["metadata"]["version"] == "1.8.0"
        assert event["metadata"]["product"]["name"] == "Ordin"
        assert event["metadata"]["profiles"] == ["security_control"]
        assert len(event["finding_info"]["uid"]) == 64
        assert "backend_enforced" not in encoded and "raw_data" not in event
        with pytest.raises(OpenShellEventError):
            parse_openshell_event(event)


def test_ordinary_unknown_ask_is_not_exported_as_a_security_policy_finding():
    unknown = Ordin().review_action(ActionEnvelope("unknown", "call", action_id="ask"))
    assert unknown.decision == "ask" and export_review_findings(unknown, time_ms=1) == ()
    assert unknown.provenance is not None
    policy = replace(
        unknown,
        provenance=unknown.provenance.append(
            ProvenanceRecord(
                source="action_policy", kind="rule", code="policy.requires_approval", decision="ask"
            )
        ),
    )
    assert (
        export_review_findings(policy, time_ms=1)[0]["metadata"]["event_code"]
        == "security_policy_approval"
    )


def test_boundary_compiler_and_correlation_exports_hash_sensitive_counterexamples():
    boundary = CapabilityVerificationResult(
        "exceeds_boundary",
        "runtime_boundary_exceeded",
        "a" * 64,
        "b" * 64,
        {d: True for d in DOMAINS},
        counterexample={"secret": "RAW-SECRET-VALUE"},
    )
    compiler = CompilationResult(
        "unsupported",
        "openshell",
        "openshell_compiler_unrepresentable",
        reasons=("RAW-SECRET-VALUE",),
        unsupported_fields=("filesystem.primitive_would_widen",),
    )
    correlation = {
        "status": "rejected",
        "reason_code": "runtime_observation_action_mismatch",
        "raw_payload": {"authorization": "RAW-SECRET-VALUE"},
    }
    events = (
        *export_boundary_findings(boundary, time_ms=1),
        *export_compiler_findings(compiler, time_ms=1),
        *export_correlation_findings(correlation, time_ms=1),
    )
    assert len(events) == 3 and "RAW-SECRET-VALUE" not in json.dumps(events)
    assert (
        export_boundary_findings(
            replace(boundary, result="within_boundary", counterexample=None), time_ms=1
        )
        == ()
    )
    assert (
        export_compiler_findings(
            CompilationResult(
                "unsupported",
                "openshell",
                "openshell_compiler_unrepresentable",
                unsupported_fields=("network.protocol",),
            ),
            time_ms=1,
        )
        == ()
    )
    assert export_correlation_findings({"status": "accepted"}, time_ms=1) == ()


@pytest.mark.parametrize("time_ms", [True, -1, 1.5, 2**54])
def test_export_timestamp_is_explicit_bounded_and_never_read_from_a_clock(time_ms):
    review = Ordin().review_action(ActionEnvelope.shell("rm -rf /"))
    with pytest.raises(ValueError):
        export_review_findings(review, time_ms=time_ms)
