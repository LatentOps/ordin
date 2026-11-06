"""Canonical data-only coordinator contracts, never live capabilities."""

from ordin.swarm.coordinator import CoordinatorRecord, CoordinatorFenceReceipt, CoordinatorDispatch
from ordin.swarm.models import SwarmIdentity


def coordinator_contract_samples():
    sha = "a" * 64
    status = {
        "schema_version": "ordin.swarm_coordinator_status.v1",
        "scope_digest": sha,
        "database_digest": sha,
        "backend": "postgresql",
        "mode": "multi_host_postgresql",
        "online": True,
        "policy_epoch": 1,
        "policy_digest": sha,
        "owner_fence": 1,
        "journal_sequence": 5,
        "checkpoint_sequence": 5,
        "journal_incomplete": False,
        "projection_lag": 0,
        "prehistory": "unknown",
        "workload_count": 2,
        "grant_count": 2,
        "reservations": {"uncertain": 1},
        "unmediated_execution": "uncovered",
        "physical_enforcement": False,
        "execution_authority": False,
    }
    return {
        "swarm_coordinator_record": CoordinatorRecord(
            "lease", sha, sha, sha, 1, 1, 200, "current"
        ).as_dict(),
        "swarm_coordinator_fence": CoordinatorFenceReceipt(sha, 1, sha, 1, 1).as_dict(),
        "swarm_coordinator_dispatch": CoordinatorDispatch(
            "unknown", sha, sha, "coordinator.effect_uncertain"
        ).as_dict(),
        "swarm_coordinator_status": status,
        "swarm_coordinator_offline": {
            "schema_version": "ordin.swarm_coordinator_offline.v1",
            "scope_digest": sha,
            "online": False,
            "coverage": "unknown",
            "requires_online_authority": True,
            "physical_enforcement": False,
            "execution_authority": False,
        },
        "swarm_coordinator_policy": {
            "schema_version": "ordin.swarm_coordinator_policy.v1",
            "scope_digest": sha,
            "policy_epoch": 1,
            "policy_digest": sha,
            "runtime_binding": sha,
            "owner_fence": 1,
            "prehistory": "unknown",
            "execution_authority": False,
        },
        "swarm_coordinator_producer": {
            "schema_version": "ordin.swarm_coordinator_producer.v1",
            "registry_id": "registry",
            "identity": SwarmIdentity(
                "tenant", "swarm", "agent", "runtime", "session", 1, 1
            ).as_dict(),
            "source_id": "source",
            "next_sequence": 1,
            "prehistory": "unknown",
            "execution_authority": False,
        },
        "swarm_coordinator_revocation": {
            "schema_version": "ordin.swarm_coordinator_revocation.v1",
            "scope_digest": sha,
            "revocation_epoch": 1,
            "status": "revoked",
            "execution_authority": False,
        },
        "swarm_coordinator_request": {
            "schema_version": "ordin.swarm_coordinator_request.v1",
            "operation": "admit",
            "arguments": {},
        },
        "swarm_coordinator_response": {
            "schema_version": "ordin.swarm_coordinator_response.v1",
            "status": "ok",
            "result": status,
            "reason_code": None,
            "execution_authority": False,
        },
    }
