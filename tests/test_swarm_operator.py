"""Real operator TLS/RBAC over original sources, never JSON roles or permits."""

from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
import json

import pytest

from ordin import ActionEnvelope, AgentGate
from ordin.schema import validate_named_schema
from ordin.swarm.audit import SwarmAuditJournal
from ordin.swarm.diagnostics import SwarmAuditSource
from ordin.swarm.gate import SwarmGate
from ordin.swarm.incident import IncidentPolicy, IncidentSignalSource, SwarmContainmentController
from ordin.swarm.operator_auth import SwarmOperatorDirectory
from ordin.swarm.operator_api import SwarmOperatorAPI, SwarmOperatorClient
from ordin.swarm.workload_auth import WorkloadAuthenticator
from tests.test_swarm_coordinator import configured
from tests.test_swarm_delegation import server_context, tls_pair, fingerprint


@contextmanager
def operator_fixture(tmp_path, *, roles=("observe", "export", "pause", "revoke", "retain")):
    with configured(tmp_path) as data:
        operator = data["operator"]
        signals = IncidentSignalSource(operator=operator)
        controller = SwarmContainmentController(
            data["coordinator"],
            data["scope"],
            control=data["control"],
            operator=operator,
            policy=IncidentPolicy("operators", 1),
            signals=signals,
        )
        journal = SwarmAuditJournal(
            tmp_path / "audit.db",
            key=b"P" * 32,
            tenant_id="tenant",
            operator=operator,
            clock=data["clock"],
            create=True,
        )
        source = SwarmAuditSource(
            journal,
            data["coordinator"],
            data["scope"],
            control=data["control"],
            operator=operator,
            containment=controller,
        )
        tls = server_context()
        auth = WorkloadAuthenticator(data["registry"], tls, operator=operator, clock=data["clock"])
        directory = SwarmOperatorDirectory(
            auth,
            operator=operator,
            roles=("observe", "export", "pause", "revoke", "retain", "approve", "deny"),
        )
        member = directory.enroll(
            principal_id="private-human",
            certificate_digest=fingerprint("broker-a"),
            roles=roles,
            task_ids=("task",),
            operator=operator,
        )
        with tls_pair(tls, "broker-a") as (server, client):
            channel = directory.authenticate(server)
            api = SwarmOperatorAPI(directory, (source,), operator=operator)
            try:
                yield data, source, controller, directory, channel, api, server, client, member
            finally:
                source.close(operator=operator)


def request(operation, **arguments):
    return {
        "schema_version": "ordin.swarm_operator_request.v1",
        "operation": operation,
        "scope_ref": None,
        "arguments": arguments,
    }


def test_original_gate_and_coordinator_records_remain_intent_and_redacted(tmp_path):
    with operator_fixture(tmp_path) as (data, source, _, _, channel, api, *_):
        gate = SwarmGate(data["registry"], AgentGate())
        gate.bind_audit(source, operator=data["operator"])
        context = data["contexts"]["child"]
        row = data["registry"]._agents["child"]
        adapter = data["registry"]._channels[row.channel][0]
        action = ActionEnvelope.shell("rm -rf /", action_id="SYNTHETIC_PRIVATE_ACTION")
        decision = gate.evaluate_action(context, action, channel=row.channel, adapter=adapter)
        assert decision.disposition == "deny"
        snapshot = api.handle(channel, request("status"))
        assert not validate_named_schema("swarm_operator_snapshot", snapshot)
        assert snapshot["metrics"]["intent_reviews"] == 1
        assert snapshot["metrics"]["observed_completions"] == 0
        assert snapshot["timeline"][0]["evidence"] == "intent"
        assert "rm -rf" not in json.dumps(
            snapshot
        ) and "SYNTHETIC_PRIVATE_ACTION" not in json.dumps(snapshot)
        assert all(row["verified_state"] != "physically_enforced" for row in snapshot["coverage"])
        with pytest.raises(ValueError):
            source.record_decision(gate, context, decision.as_dict())


def test_read_role_cannot_export_pause_or_inject_json_roles(tmp_path):
    with operator_fixture(tmp_path, roles=("observe",)) as (
        data,
        source,
        _,
        directory,
        channel,
        api,
        *_,
    ):
        assert api.handle(channel, request("status"))["execution_authority"] is False
        for operation, arguments in (
            ("export", {}),
            ("pause", {"scope_kind": "agent", "actor_ref": source.actor_ref("child")}),
        ):
            with pytest.raises(ValueError):
                api.handle(channel, request(operation, **arguments))
        malformed = request("status")
        malformed["role"] = "policy_admin"
        with pytest.raises(ValueError):
            api.handle(channel, malformed)
        with pytest.raises(ValueError):
            api.handle(data["channels"]["child"], request("status"))
        directory.revoke(next(iter(directory._members)), operator=data["operator"])
        with pytest.raises(ValueError):
            api.handle(channel, request("status"))


def test_authenticated_pause_publishes_actor_fence_without_permissions(tmp_path):
    with operator_fixture(tmp_path) as (data, source, _, _, channel, api, *_):
        result = api.handle(
            channel, request("pause", scope_kind="agent", actor_ref=source.actor_ref("child"))
        )
        assert result["status"] == "logical_fence_recorded" and not result["execution_authority"]
        assert not validate_named_schema("swarm_operator_control", result)
        with pytest.raises(ValueError):
            data["coordinator"].admit(data["scope"], data["channels"]["child"])
        status = api.handle(channel, request("status"))
        actor = next(
            row for row in status["agents"] if row["actor_ref"] == source.actor_ref("child")
        )
        assert actor["containment"] == "permission_fenced"
        assert status["incidents"][0]["operation"] == "pause"


def test_actual_mutual_tls_client_round_trip(tmp_path):
    with operator_fixture(tmp_path) as (_, _, _, _, _, api, server, client, _):
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(api.serve_one, server)
            result = SwarmOperatorClient(client).request("status")
            pending.result(timeout=10)
        assert result["verified_live_source"] and not result["execution_authority"]


def test_diagnostic_sink_failure_never_changes_core_decision(tmp_path, monkeypatch):
    import sqlite3

    with operator_fixture(tmp_path) as (data, source, _, _, channel, api, *_):

        def unavailable(**arguments):
            raise sqlite3.OperationalError("synthetic unavailable sink")

        monkeypatch.setattr(source.journal, "_append", unavailable)
        gate = SwarmGate(data["registry"], AgentGate())
        gate.bind_audit(source, operator=data["operator"])
        context = data["contexts"]["child"]
        row = data["registry"]._agents["child"]
        decision = gate.evaluate_action(
            context,
            ActionEnvelope.shell("rm -rf /"),
            channel=row.channel,
            adapter=data["registry"]._channels[row.channel][0],
        )
        assert decision.disposition == "deny"
        assert not source.flush(operator=data["operator"])
        snapshot = api.handle(channel, request("status"))
        assert "capture_unavailable" in snapshot["proof_gaps"]
        assert snapshot["metrics"]["observed_completions"] == 0


def test_authenticated_retention_sweep_preserves_labels_and_version_tombstones(tmp_path):
    from tests.test_swarm_coordinator_projections import protected_storage

    with operator_fixture(tmp_path) as (data, _, _, _, channel, api, *_):
        gateway, _, source, address, collect = protected_storage(data)
        text = "SYNTHETIC_RETAINED_SECRET"
        gateway.write(source, address, text, expected_version=0, inputs=(collect(text),), ttl=1)
        data["coordinator"].checkpoint(data["scope"], control=data["control"])
        data["now"][0] += 2
        with pytest.raises(ValueError):
            gateway.sweep(operator=object(), tenant_id="tenant", swarm_id="swarm", task_id="task")
        result = api.handle(channel, request("sweep", maximum_resources=256))
        assert result["artifact_result"]["versions_removed"] == 1
        assert not validate_named_schema("swarm_operator_retention", result)
        resource = gateway._resources[address]
        assert (
            resource.highwater == 1 and resource.labels.labels == ("secret",) and resource.deleted
        )
        with pytest.raises(ValueError):
            gateway.write(
                source,
                address,
                "public",
                expected_version=0,
                inputs=(collect("public", ("public",)),),
            )
        with data["store"].transaction() as transaction:
            state = transaction.scope(data["scope"].scope_key)
            assert not state["artifact_pending"]
            assert any(
                row["deleted"] and row["version"] == 1 and row["labels"] == ["secret"]
                for row in state["artifact_floors"].values()
            )
