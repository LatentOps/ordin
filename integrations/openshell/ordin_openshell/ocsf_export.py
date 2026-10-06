"""Optional, deterministic OCSF 1.8 Detection Finding export with digest privacy.

These findings describe Ordin decisions/diagnostics, not runtime enforcement or
remote attestation. This exporter does not replace the local hash-chained audit.
"""

from __future__ import annotations

from typing import Any, Mapping

from ordin import __version__
from ordin.action import ActionReview
from ordin.audit import action_digest
from ordin._runtime_json import canonical_json, digest, freeze, MAX_RUNTIME_BYTES
from ordin.enforcement_backend import CompilationResult
from ordin.runtime_boundary import CapabilityVerificationResult
from ordin.runtime_requests import RequestVerificationResult

OCSF_VERSION = "1.8.0"
TITLES = {
    "decision_block": "Ordin blocked a reviewed action",
    "security_policy_approval": "Ordin security policy requires approval",
    "trajectory_policy_bypass": "Ordin detected repeated attempts against an enforced boundary",
    "boundary_exceedance": "Requested capabilities exceed the configured boundary",
    "compiler_widening_rejection": "Policy compilation rejected authority expansion",
    "runtime_correlation_failure": "Runtime evidence could not be correlated to its reviewed action",
}
SEVERITY = {"unknown": 0, "low": 2, "medium": 3, "high": 4, "critical": 5}


def _time(time_ms: int) -> None:
    if type(time_ms) is not int or not 0 <= time_ms <= 0x1FFFFFFFFFFFFF:
        raise ValueError("ocsf_export_timestamp_invalid")


def _finding(
    kind: str,
    time_ms: int,
    source_digest: str,
    *,
    severity: int,
    references: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    if kind not in TITLES or type(time_ms) is not int or not 0 <= time_ms <= 0x1FFFFFFFFFFFFF:
        raise ValueError("ocsf_export_input_invalid")
    if (
        not isinstance(source_digest, str)
        or len(source_digest) != 64
        or any(c not in "0123456789abcdef" for c in source_digest)
    ):
        raise ValueError("ocsf_export_digest_invalid")
    links = dict(references or {})
    if any(
        not isinstance(v, str) or len(v) != 64 or any(c not in "0123456789abcdef" for c in v)
        for v in links.values()
    ):
        raise ValueError("ocsf_export_reference_invalid")
    finding_id = digest({"kind": kind, "source_digest": source_digest})
    result = {
        "category_uid": 2,
        "class_uid": 2004,
        "activity_id": 1,
        "type_uid": 200401,
        "severity_id": severity,
        "time": time_ms,
        "status_id": 1,
        "is_alert": True,
        "message": TITLES[kind],
        "metadata": {
            "version": OCSF_VERSION,
            "uid": digest({"finding": finding_id, "time": time_ms}),
            "product": {"name": "Ordin", "vendor_name": "LatentOps", "version": __version__},
            "profiles": ["security_control"],
            "event_code": kind,
            "original_event_uid": source_digest,
        },
        "finding_info": {
            "uid": finding_id,
            "title": TITLES[kind],
            "types": [kind],
            "created_time": time_ms,
        },
        "unmapped": {"ordin": {"finding_kind": kind, "source_digest": source_digest, **links}},
    }
    freeze(result)
    if len(canonical_json(result).encode()) > MAX_RUNTIME_BYTES:
        raise ValueError("ocsf_export_size")
    return result


def export_review_findings(review: ActionReview, *, time_ms: int) -> tuple[dict[str, Any], ...]:
    _time(time_ms)
    if not isinstance(review, ActionReview):
        raise ValueError("ocsf_export_review_invalid")
    # No free-form reasons, action/tool arguments, resource names or IDs survive.
    source = digest(
        {
            "action_digest": action_digest(review),
            "decision": review.decision,
            "risk": review.risk,
            "provenance_digest": review.provenance.digest if review.provenance else None,
        }
    )
    links = {"action_digest": action_digest(review)}
    if review.provenance:
        links["provenance_digest"] = review.provenance.digest
    kinds = []
    if review.decision == "block":
        kinds.append("decision_block")
    if (
        review.decision == "ask"
        and review.provenance
        and any(
            r.source in {"action_policy", "temporal_policy"} and r.decision == "ask"
            for r in review.provenance.records
        )
    ):
        kinds.append("security_policy_approval")
    if "trajectory_policy_bypass_attempt" in review.trajectory_categories:
        kinds.append("trajectory_policy_bypass")
    return tuple(
        _finding(kind, time_ms, source, severity=SEVERITY[review.risk], references=links)
        for kind in kinds
    )


def export_boundary_findings(
    result: CapabilityVerificationResult | RequestVerificationResult, *, time_ms: int
) -> tuple[dict[str, Any], ...]:
    _time(time_ms)
    if not isinstance(result, (CapabilityVerificationResult, RequestVerificationResult)):
        raise ValueError("ocsf_export_boundary_invalid")
    if result.result != "exceeds_boundary":
        return ()
    return (
        _finding(
            "boundary_exceedance",
            time_ms,
            digest(result.as_dict()),
            severity=4,
            references={
                "contract_digest": result.contract_digest,
                "boundary_digest": result.boundary_digest,
            },
        ),
    )


def export_compiler_findings(
    result: CompilationResult, *, time_ms: int
) -> tuple[dict[str, Any], ...]:
    _time(time_ms)
    if not isinstance(result, CompilationResult):
        raise ValueError("ocsf_export_compilation_invalid")
    widening = {"filesystem.primitive_would_widen", "base_policy.would_widen_or_change_authority"}
    if result.status == "success" or not widening.intersection(result.unsupported_fields):
        return ()
    return (_finding("compiler_widening_rejection", time_ms, digest(result.as_dict()), severity=4),)


def export_correlation_findings(
    result: Mapping[str, Any], *, time_ms: int
) -> tuple[dict[str, Any], ...]:
    _time(time_ms)
    # Use only status plus an integrity digest. Payloads/reasons are never echoed.
    if (
        not isinstance(result, Mapping)
        or not isinstance(result.get("status"), str)
        or result["status"] not in {"accepted", "rejected", "uncorrelated"}
    ):
        raise ValueError("ocsf_export_correlation_invalid")
    freeze(result)
    if result.get("status") not in {"rejected", "uncorrelated"}:
        return ()
    return (_finding("runtime_correlation_failure", time_ms, digest(result), severity=3),)
