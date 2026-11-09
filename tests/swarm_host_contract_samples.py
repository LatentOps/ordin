"""Core-only managed-host data examples; no optional host import or live authority."""

from ordin._runtime_json import digest


def host_contract_samples(tmp_path):
    profile = {
        "schema_version": "ordin.swarm_tool_host_profile.v1",
        "profile_id": "contract-host",
        "tenant_id": "tenant",
        "swarm_id": "swarm",
        "task_id": "contract-task",
        "workspace": str(tmp_path / "workspace"),
        "files": [{"name": "document.txt", "label": "private_code"}],
        "actors": [
            {
                "agent_id": "reader",
                "read_files": ["document.txt"],
                "write_files": [],
                "http_routes": [],
                "peers": [],
            }
        ],
        "http_routes": [],
        "limits": {"requests": 8, "output_bytes": 16384, "concurrency": 1, "lifetime_seconds": 60},
    }
    profile_digest = digest(profile)
    return {
        "swarm_tool_host_profile": profile,
        "swarm_tool_host_client": {
            "schema_version": "ordin.swarm_tool_host_client.v1",
            "host": "127.0.0.1",
            "port": 9443,
            "server_hostname": "localhost",
            "profile_digest": profile_digest,
            "actor_id": "reader",
        },
        "swarm_tool_host_endpoint": {
            "schema_version": "ordin.swarm_tool_host_endpoint.v1",
            "host": "127.0.0.1",
            "port": 9443,
            "profile_digest": profile_digest,
            "incarnation": "a" * 32,
            "online_evidence": False,
        },
        "swarm_tool_host_result": {
            "schema_version": "ordin.swarm_tool_host_result.v1",
            "status": "denied",
            "reason_codes": ["host.example_unconfigured"],
            "forwarded": False,
            "physical_enforcement": False,
            "data": {},
            "execution_authority": False,
        },
        "swarm_tool_host_status": {
            "schema_version": "ordin.swarm_tool_host_status.v1",
            "online": False,
            "profile_digest": profile_digest,
            "policy_epoch": None,
            "owner_fence": None,
            "actor": "reader",
            "execution_boundary": "managed_owned_tools",
            "client_process_confinement": "not_established",
            "unmediated_tools": "uncovered",
            "max_tool_data_bytes": 16384,
            "current_task_expires_at": 0,
            "retained_data": {
                "retained_resources": 0,
                "inbox_messages": 0,
                "retained_bytes_total": 0,
                "uncertain_handoff_holds": 0,
                "pending_custody_reservations": 0,
                "uncertain_custody_holds": 0,
                "capacity_bytes": 16384,
                "complete_taint_tracking": False,
            },
            "execution_authority": False,
        },
        "swarm_tool_host_evaluation": {
            "schema_version": "ordin.swarm_tool_host_evaluation.v1",
            "profile_digest": profile_digest,
            "scope": "offline_fixed_two_agent_workflow",
            "operator_mode": "scripted_fixture_exact_authenticated_review",
            "hosted_models_used": False,
            "client_process_confinement": "not_established",
            "complete_taint_tracking": False,
            "protected_fixture": "not_requested",
            "fixed_tests_exercised": False,
            "benign_total": 0,
            "benign_completed": 0,
            "false_blocks": 0,
            "attack_total": 0,
            "attacks_stopped": 0,
            "false_allows": 0,
            "duration_ms": 0,
            "cases": [],
            "complete": False,
            "passed": False,
            "failure_reason": "host.evaluation_incomplete",
            "execution_authority": False,
        },
    }
