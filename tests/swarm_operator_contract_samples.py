"""Data-only canonical operator/audit contracts, never live credentials."""

from ordin._runtime_json import digest
from ordin.swarm.audit import SwarmAuditVerification


def operator_contract_samples():
    ref, sha = "hmac:" + "a" * 64, "a" * 64
    event = {
        "schema_version": "ordin.swarm_audit_event.v1",
        "sequence": 1,
        "admitted_at": 100,
        "kind": "decision",
        "state": "reviewed",
        "evidence": "intent",
        "refs": {"action": ref},
        "facts": {"disposition": "escalate", "risk": "high"},
        "previous_hash": "0" * 64,
        "execution_authority": False,
    }
    event["event_hash"] = digest(event)
    bundle = {
        "schema_version": "ordin.swarm_audit_bundle.v1",
        "tenant_ref": ref,
        "journal_ref": ref,
        "scope_ref": None,
        "first_sequence": 1,
        "tail_sequence": 1,
        "base_hash": "0" * 64,
        "tail_hash": event["event_hash"],
        "events": [event],
        "privacy": "tenant_keyed_hmac_metadata",
        "execution_authority": False,
    }
    snapshot = {
        "schema_version": "ordin.swarm_operator_snapshot.v1",
        "tenant_ref": ref,
        "swarm_ref": ref,
        "scope_ref": ref,
        "observed_at": 100,
        "coordinator_online": False,
        "verified_live_source": False,
        "agents": [],
        "coverage": [],
        "graph": {"nodes": [], "edges": [], "paths": [], "successful_exploitation": "unknown"},
        "budgets": [],
        "permissions": [],
        "policy": {
            "policy_ref": None,
            "policy_epoch": None,
            "owner_fence": None,
            "claim": "committed_metadata_not_permission",
            "budget_configured": [],
        },
        "incidents": [],
        "timeline": [],
        "metrics": {
            "intent_reviews": 0,
            "observed_completions": 0,
            "reported_completions": 0,
            "unknown_outcomes": 0,
            "advisory_risk_signals": 0,
            "window": "retained_audit_only",
            "complete_history": False,
        },
        "proof_gaps": ["unmediated_paths_uncovered", "prehistory_unknown"],
        "unmediated_paths": "uncovered",
        "prehistory": "unknown",
        "execution_authority": False,
    }
    retention = {
        "schema_version": "ordin.swarm_artifact_retention.v1",
        "resources_scanned": 1,
        "versions_removed": 1,
        "grants_removed": 0,
        "tombstones_retained": 1,
        "remaining_eligible_resources": 0,
        "labels_preserved": True,
        "high_water_preserved": True,
        "raw_backing_access": "uncovered",
        "execution_authority": False,
    }
    return {
        "swarm_audit_event": event,
        "swarm_audit_bundle": bundle,
        "swarm_audit_checkpoint": {
            "schema_version": "ordin.swarm_audit_checkpoint.v1",
            "tenant_ref": ref,
            "journal_ref": ref,
            "scope_ref": None,
            "tail_sequence": 1,
            "tail_hash": event["event_hash"],
            "execution_authority": False,
        },
        "swarm_audit_verification": SwarmAuditVerification(
            True, 1, 1, sha, "not_supplied", ("audit.owner_can_rewrite_unanchored_history",)
        ).as_dict(),
        "swarm_operator_snapshot": snapshot,
        "swarm_operator_list": {
            "schema_version": "ordin.swarm_operator_list.v1",
            "scopes": [{"scope_ref": ref, "agents": [], "proof_gaps": []}],
            "execution_authority": False,
        },
        "swarm_operator_view": {
            "schema_version": "ordin.swarm_operator_view.v1",
            "scope_ref": ref,
            "view": "graph",
            "data": snapshot["graph"],
            "proof_gaps": [],
            "execution_authority": False,
        },
        "swarm_operator_explanation": {
            "schema_version": "ordin.swarm_operator_explanation.v1",
            "scope_ref": ref,
            "action_ref": ref,
            "events": [event],
            "proof_gaps": [],
            "successful_exploitation": "unknown",
            "execution_authority": False,
        },
        "swarm_operator_control": {
            "schema_version": "ordin.swarm_operator_control.v1",
            "scope_ref": ref,
            "operation": "pause",
            "receipt_ref": ref,
            "status": "logical_fence_recorded",
            "execution_authority": False,
        },
        "swarm_artifact_retention": retention,
        "swarm_operator_retention": {
            "schema_version": "ordin.swarm_operator_retention.v1",
            "scope_ref": ref,
            "audit_first_sequence": 1,
            "artifact_result": retention,
            "execution_authority": False,
        },
        "swarm_operator_request": {
            "schema_version": "ordin.swarm_operator_request.v1",
            "operation": "status",
            "scope_ref": None,
            "arguments": {},
        },
        "swarm_operator_response": {
            "schema_version": "ordin.swarm_operator_response.v1",
            "status": "ok",
            "result": snapshot,
            "execution_authority": False,
        },
    }
