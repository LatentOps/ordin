"""Canonical data-only governance reports, never original human authority."""

from ordin.approval import ApprovalScope
from ordin.swarm.approval import (
    SwarmApprovalBinding,
    SwarmApprovalPolicy,
    SwarmApprovalRequest,
    SwarmRecoveryRequest,
)


def approval_contract_samples():
    policy = SwarmApprovalPolicy("fixture")
    hashes = dict.fromkeys(
        (
            "scope_digest",
            "principal_digest",
            "session_digest",
            "context_digest",
            "action_digest",
            "review_digest",
            "gate_digest",
            "policy_digest",
            "evidence_digest",
            "delegation_digest",
            "budget_digest",
            "capabilities_digest",
            "operator_maximum_digest",
            "directory_digest",
        ),
        "a" * 64,
    )
    epochs = {"policy_epoch": 0, "revocation_epoch": 0, "owner_fence": 1}
    binding = SwarmApprovalBinding(**hashes, **epochs)
    request = SwarmApprovalRequest(
        "a" * 32,
        binding,
        policy.digest,
        "escalate",
        "medium",
        ("filesystem.read",),
        ("approve",),
        1,
        110,
    )
    recovery = SwarmRecoveryRequest(
        "b" * 32, "b" * 64, "c" * 64, "a" * 64, 0, 1, 2, ("recover",), 2, 110, "safety_recovery"
    )
    scope = ApprovalScope(
        **{
            key: value for key, value in hashes.items() if key in ApprovalScope.__dataclass_fields__
        },
        **epochs,
    )
    return {
        "swarm_approval_policy": policy.as_dict(),
        "swarm_approval": request.as_dict(),
        "swarm_recovery_request": recovery.as_dict(),
        "swarm_approval_receipt": {
            "schema_version": "ordin.swarm_approval_receipt.v1",
            "receipt_id": "c" * 32,
            "request_id": request.request_id,
            "request_digest": request.digest,
            "binding_digest": binding.digest,
            "expires_at": 110,
            "status": "approved",
            "execution_authority": False,
        },
        "swarm_approval_resolution": {
            "schema_version": "ordin.swarm_approval_resolution.v1",
            "request_id": request.request_id,
            "status": "pending",
            "votes": 0,
            "quorum": 1,
            "execution_authority": False,
        },
        "swarm_approval_queue": {
            "schema_version": "ordin.swarm_approval_queue.v1",
            "scope_digest": "a" * 64,
            "policy_epoch": 0,
            "owner_fence": 1,
            "requests": [{"request": request.as_dict(), "status": "pending", "vote_count": 0}],
            "recoveries": [{"request": recovery.as_dict(), "status": "pending", "vote_count": 0}],
            "execution_authority": False,
        },
        "swarm_approval_audit": {
            "schema_version": "ordin.swarm_approval_audit.v1",
            "scope_digest": "a" * 64,
            "journal_head": "b" * 64,
            "records": [
                {
                    "request_id": request.request_id,
                    "kind": "action",
                    "binding_digest": binding.digest,
                    "status": "pending",
                    "expires_at": 110,
                    "votes": [],
                }
            ],
            "execution_authority": False,
        },
        "approval_scope": scope.as_dict(),
        "approval_satisfaction": {
            "schema_version": "ordin.approval_satisfaction.v1",
            "satisfaction_id": "fixture",
            "action_digest": "a" * 64,
            "review_digest": "b" * 64,
            "configuration_digest": "c" * 64,
            "scope": scope.as_dict(),
            "source_binding": "d" * 64,
            "host_approval_digest": "e" * 64,
            "expires_at": 110,
            "fulfilled_obligation": "operator_review",
            "execution_authority": False,
        },
        "approval_execution_lease": {
            "schema_version": "ordin.approval_execution_lease.v1",
            "lease_id": "d" * 32,
            "satisfaction_digest": "a" * 64,
            "base_contract_digest": "b" * 64,
            "scope_digest": scope.digest,
            "expires_at": 110,
            "execution_authority": False,
        },
    }
