"""Protected causal sources, task isolation and preemptive operator fences."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from copy import copy
from threading import Event
import json
import sqlite3

import pytest

from ordin import ActionEnvelope, AgentGate
from ordin._runtime_json import digest
from ordin.schema import validate_named_schema
from ordin.swarm.causal_graph import SwarmCausalGraph
from ordin.swarm.events import EventRef, SwarmEvent
from ordin.swarm.gate import SwarmGate
from ordin.swarm.ingest import SwarmEventIngestor
from tests.test_swarm_coordinator import prepare
from tests.test_swarm_delegation import fingerprint, tls_pair
from tests.test_swarm_operator import operator_fixture, request
from ordin.swarm.operator_api import SwarmOperatorAPI


def bound_graph(data, source):
    context = data["contexts"]["child"]
    row = data["registry"]._agents["child"]
    adapter = data["registry"]._channels[row.channel][0]
    ingest = SwarmEventIngestor(data["registry"])
    producer = ingest.bind_source(context, row.channel, adapter, source_id="protected")
    graph = SwarmCausalGraph(ingest, producer, context)
    source.bind_causal_graph(graph, operator=data["operator"])
    return context, row.channel, adapter, ingest, producer, graph


def test_causal_candidate_requires_exact_original_review_and_protected_parents(tmp_path):
    with operator_fixture(tmp_path) as (data, source, _, _, human, api, *_):
        context, channel, adapter, ingest, producer, graph = bound_graph(data, source)
        action = ActionEnvelope.shell("rm -rf /", action_id="SYNTHETIC_PRIVATE_ACTION")
        gate = SwarmGate(data["registry"], AgentGate())
        gate.bind_audit(source, operator=data["operator"])
        decision = gate.evaluate_action(context, action, channel=channel, adapter=adapter)

        def event(name, kind, sequence, *, parents=(), **options):
            return SwarmEvent(
                name,
                kind,
                context.registry_id,
                context.identity,
                producer.source_id,
                sequence,
                100,
                evidence_class="host_authenticated",
                parent_event_ids=tuple(EventRef("tenant", "swarm", parent) for parent in parents),
                **options,
            )

        ingest.ingest(producer, event("SYNTHETIC_PRIVATE_MESSAGE", "message_received", 1))
        ingest.ingest(
            producer,
            event(
                "proposal",
                "proposed",
                2,
                parents=("SYNTHETIC_PRIVATE_MESSAGE",),
                action_id=action.action_id,
                action_digest=decision.action_digest,
            ),
        )
        ingest.ingest(
            producer,
            event(
                "review",
                "reviewed",
                3,
                parents=("proposal",),
                action_id=action.action_id,
                action_digest=decision.action_digest,
            ),
        )
        snapshot = api.handle(human, request("status"))
        assert not validate_named_schema("swarm_operator_snapshot", snapshot)
        assert snapshot["graph"]["paths"][0]["disposition"] == "deny"
        assert snapshot["graph"]["paths"][0]["evidence"] == "intent"
        assert len(snapshot["graph"]["paths"][0]["event_refs"]) == 3
        assert snapshot["graph"]["successful_exploitation"] == "unknown"
        assert snapshot["metrics"]["observed_completions"] == 0
        assert snapshot["timeline"][0]["refs"]["task"]
        assert any(
            row["kind"] == "message" and row["evidence"] == "reported"
            for row in snapshot["timeline"]
        )
        assert "SYNTHETIC_PRIVATE" not in json.dumps(snapshot)
        assert "rm -rf" not in json.dumps(snapshot)
        with pytest.raises(ValueError):
            source.bind_causal_graph(copy(graph), operator=data["operator"])
        with pytest.raises(ValueError):
            source.record_ingested(ingest, copy(ingest._records["review"]))
        data["registry"].pause(context, channel, adapter)
        unavailable = api.handle(human, request("status"))
        assert unavailable["graph"]["paths"] == []
        assert "protected_causal_source_unavailable" in unavailable["proof_gaps"]


def test_task_rbac_and_foreign_scope_references_cannot_read_or_control(tmp_path):
    with operator_fixture(tmp_path) as (data, source, _, directory, _, api, *_):
        directory.enroll(
            principal_id="foreign-task-human",
            certificate_digest=fingerprint("broker-b"),
            roles=("observe", "pause"),
            task_ids=("other-task",),
            operator=data["operator"],
        )
        with tls_pair(directory.authenticator._tls, "broker-b") as (server, _):
            foreign = directory.authenticate(server)
            for operation, arguments in (
                ("status", {}),
                ("list", {}),
                ("pause", {"scope_kind": "agent", "actor_ref": source.actor_ref("child")}),
            ):
                with pytest.raises(ValueError):
                    api.handle(foreign, request(operation, **arguments))
        with pytest.raises(ValueError):
            api.handle(data["channels"]["child"], request("incidents"))


def test_cross_tenant_channels_references_and_sources_never_authorize(tmp_path):
    with (
        operator_fixture(tmp_path / "one", tenant="one") as first,
        operator_fixture(tmp_path / "two", tenant="two") as second,
    ):
        data, source, _, directory, human, api, *_ = first
        _, other, _, _, foreign, _, *_ = second
        assert source.actor_ref("child") != other.actor_ref("child")
        with pytest.raises(ValueError):
            api.handle(foreign, request("incidents"))
        packet = request("status")
        packet["scope_ref"] = other.journal.redactor.ref("scope", other._scope.scope_key)
        with pytest.raises(ValueError):
            api.handle(human, packet)
        with pytest.raises(ValueError):
            SwarmOperatorAPI(directory, (other,), operator=data["operator"])


def test_protected_graph_filters_foreign_tasks_and_does_not_join_model_claims(tmp_path):
    with operator_fixture(tmp_path) as (data, source, _, _, human, api, *_):
        context, _, _, ingest, producer, _ = bound_graph(data, source)
        adapter = object()
        channel = data["registry"].bind_channel(adapter, runtime_id="other")
        other = data["registry"].enroll(
            channel,
            adapter,
            agent_id="PRIVATE_FOREIGN_AGENT",
            session_id="foreign",
            task_id="other-task",
        )
        other_source = ingest.bind_source(other, channel, adapter, source_id="foreign")
        ingest.ingest(
            other_source,
            SwarmEvent(
                "PRIVATE_FOREIGN_EVENT",
                "message_received",
                other.registry_id,
                other.identity,
                "foreign",
                1,
                100,
                evidence_class="host_authenticated",
            ),
        )
        claims = ingest.bind_source(
            context,
            producer and data["registry"]._agents["child"].channel,
            data["registry"]._channels[data["registry"]._agents["child"].channel][0],
            source_id="model",
            role="asserted",
        )
        ingest.ingest(
            claims,
            SwarmEvent(
                "claim",
                "message_received",
                context.registry_id,
                context.identity,
                "model",
                1,
                100,
                evidence_class="caller_asserted",
            ),
        )
        source.record_risk(
            severity="critical",
            confidence=1,
            model_ref="model",
            action_ref="claim",
            operator=data["operator"],
        )
        snapshot = api.handle(human, request("status"))
        assert len(snapshot["graph"]["nodes"]) == 1
        assert snapshot["graph"]["nodes"][0]["evidence"] == "diagnostic"
        assert snapshot["graph"]["paths"] == []
        assert all(
            row["actor_ref"] != source.actor_ref("PRIVATE_FOREIGN_AGENT")
            for row in snapshot["agents"]
        )
        assert source.journal.redactor.ref("event", "PRIVATE_FOREIGN_EVENT") not in json.dumps(
            snapshot
        )
        assert source.journal.redactor.ref("message", "PRIVATE_FOREIGN_EVENT") not in json.dumps(
            snapshot
        )


def test_operator_pause_commits_fence_before_inflight_callback_releases(tmp_path):
    with operator_fixture(tmp_path) as (data, source, _, _, human, api, *_):
        _, _, reserved = prepare(data)
        entered, release = Event(), Event()

        def callback(action):
            entered.set()
            assert release.wait(10)
            return "host callback completed"

        with ThreadPoolExecutor(max_workers=2) as pool:
            dispatch = pool.submit(
                data["coordinator"].guarded_dispatch,
                data["scope"],
                data["channels"]["broker-b"],
                reserved.reference,
                forward=callback,
            )
            assert entered.wait(5)
            try:
                pause = pool.submit(
                    api.handle,
                    human,
                    request("pause", scope_kind="agent", actor_ref=source.actor_ref("child")),
                )
                assert pause.result(timeout=5)["status"] == "logical_fence_recorded"
                with data["store"].transaction() as transaction:
                    state = transaction.scope(data["scope"].scope_key)
                    assert state["subjects"][digest(["tenant", "swarm", "child"])]["revoked"]
                assert not dispatch.done()
            finally:
                release.set()
            dispatch.result(timeout=10)


def test_budget_projection_rejects_tampered_accounting(tmp_path):
    with operator_fixture(tmp_path) as (data, _, _, _, human, api, *_):
        prepare(data)
        with closing(sqlite3.connect(data["store"].path)) as connection, connection:
            connection.execute("UPDATE coordinator_buckets SET maximum=999999")
        snapshot = api.handle(human, request("status"))
        assert snapshot["budgets"] == [] and "coordinator_unavailable" in snapshot["proof_gaps"]


def test_closed_capture_is_explicitly_unavailable_and_never_reopens_on_query(tmp_path):
    with operator_fixture(tmp_path) as (data, source, _, _, human, api, *_):
        assert source.close(operator=data["operator"])
        status = api.handle(human, request("status"))
        assert {"capture_unavailable", "capture_pending_or_unavailable"} <= set(
            status["proof_gaps"]
        )
        assert not source._worker.is_alive()
        bundle = api.handle(human, request("export"))
        assert not bundle["capture_status"]["flushed"]


def test_timeline_window_explicitly_reports_projection_truncation(tmp_path):
    with operator_fixture(tmp_path) as (data, source, _, _, human, api, *_):
        for index in range(21):
            source.record_risk(
                severity="high",
                confidence=1,
                model_ref="model",
                action_ref=str(index),
                operator=data["operator"],
            )
        assert source.flush(operator=data["operator"], timeout=5)
        snapshot = api.handle(human, request("status"))
        assert (
            len(snapshot["timeline"]) == 20 and snapshot["metrics"]["advisory_risk_signals"] == 21
        )
        assert "projection_truncated" in snapshot["proof_gaps"]


def test_transactional_audit_storage_fault_is_explicit_without_partial_capture(
    tmp_path, monkeypatch
):
    with operator_fixture(tmp_path) as (data, source, _, _, human, api, *_):
        save = source.journal._save

        def storage_failure(connection, meta):
            save(connection, meta)
            raise sqlite3.OperationalError("owned transactional storage failure")

        with monkeypatch.context() as patch:
            patch.setattr(source.journal, "_save", storage_failure)
            for index in range(3):
                source.record_risk(
                    severity="high",
                    confidence=1,
                    model_ref="fixed",
                    action_ref=str(index),
                    operator=data["operator"],
                )
            assert not source.flush(operator=data["operator"], timeout=5)
        assert source._fault and not source._queue.unfinished_tasks
        assert source.journal.export(operator=data["operator"])["events"] == []
        snapshot = api.handle(human, request("status"))
        assert "capture_unavailable" in snapshot["proof_gaps"]


def test_audit_queue_overflow_is_explicit_and_cannot_change_a_core_deny(tmp_path, monkeypatch):
    from ordin.swarm.audit import verify_swarm_audit, SwarmAuditPolicy

    with operator_fixture(tmp_path, audit_policy=SwarmAuditPolicy(maximum_events=2)) as (
        data,
        source,
        _,
        _,
        human,
        api,
        *_,
    ):
        started, release = Event(), Event()
        original = source.journal._append

        def blocked(**arguments):
            started.set()
            assert release.wait(15)
            return original(**arguments)

        monkeypatch.setattr(source.journal, "_append", blocked)
        source.record_risk(
            severity="high",
            confidence=1,
            model_ref="fixed",
            action_ref="first",
            operator=data["operator"],
        )
        assert started.wait(5)
        try:
            for index in range(6):
                source.record_risk(
                    severity="high",
                    confidence=1,
                    model_ref="fixed",
                    action_ref=str(index),
                    operator=data["operator"],
                )
            assert source._dropped and source._queue.qsize() == source._queue.maxsize
            status = api.handle(human, request("status"))
            assert {"capture_overflow", "capture_pending_or_unavailable"} <= set(
                status["proof_gaps"]
            )
            bundle = api.handle(human, request("export"))
            verified = verify_swarm_audit(bundle)
            assert verified.valid and "audit.capture_incomplete" in verified.proof_gaps
            context = data["contexts"]["child"]
            row = data["registry"]._agents["child"]
            gate = SwarmGate(data["registry"], AgentGate())
            gate.bind_audit(source, operator=data["operator"])
            assert (
                gate.evaluate_action(
                    context,
                    ActionEnvelope.shell("rm -rf /"),
                    channel=row.channel,
                    adapter=data["registry"]._channels[row.channel][0],
                ).disposition
                == "deny"
            )
        finally:
            release.set()
        assert source.flush(operator=data["operator"], timeout=5)


def test_retention_backend_fault_keeps_durable_pending_hold(tmp_path, monkeypatch):
    from tests.test_swarm_coordinator_projections import protected_storage

    with operator_fixture(tmp_path) as (data, _, _, _, human, api, *_):
        gateway, _, producer, address, collect = protected_storage(data)
        gateway.write(
            producer, address, "secret", expected_version=0, inputs=(collect("secret"),), ttl=1
        )
        data["coordinator"].checkpoint(data["scope"], control=data["control"])
        data["now"][0] += 2

        def unavailable(*args):
            raise OSError("owned retention fault")

        monkeypatch.setattr(gateway, "_drop", unavailable)
        with pytest.raises(ValueError):
            api.handle(human, request("sweep", maximum_resources=256))
        with data["store"].transaction() as transaction:
            state = transaction.scope(data["scope"].scope_key)
            assert state["artifact_pending"]
            assert state["artifact_floors"]
        assert gateway._fault and gateway._resources[address].highwater == 1


def test_operator_retention_preserves_other_task_artifacts(tmp_path):
    from dataclasses import replace
    import hashlib

    from ordin.assurance import register_instruction_origin
    from ordin.swarm.source_flow import Sensitivity
    from tests.test_swarm_coordinator_projections import protected_storage

    with operator_fixture(tmp_path) as (data, _, _, _, human, api, *_):
        gateway, _, producer, address, collect = protected_storage(data)
        gateway.write(
            producer, address, "owned", expected_version=0, inputs=(collect("owned"),), ttl=1
        )
        adapter = object()
        channel = data["registry"].bind_channel(adapter, runtime_id="other-storage")
        context = data["registry"].enroll(
            channel,
            adapter,
            agent_id="other-storage",
            session_id="other-storage",
            task_id="other-task",
        )
        other = gateway._ingest.bind_source(context, channel, adapter, source_id="other-storage")
        host = replace(
            data["auth"].require(data["channels"]["child"], role="workload").source,
            principal="other-storage",
            session_digest="f" * 64,
        )
        gateway._flow.bind_actor(other, context, host)
        text = "FOREIGN_PRIVATE_ARTIFACT"
        gateway._ingest.ingest(
            other,
            SwarmEvent(
                "other-input",
                "artifact_read",
                context.registry_id,
                context.identity,
                other.source_id,
                1,
                100,
                evidence_class="host_authenticated",
                resource_digests=(hashlib.sha256(text.encode()).hexdigest(),),
            ),
        )
        origin = register_instruction_origin(
            host,
            origin_id="other-input",
            kind="repository_file",
            classification="sensitive",
            content=text,
        )
        lineage = gateway._flow.register(
            other, event_id="other-input", origin=origin, sensitivity=Sensitivity(("secret",))
        )
        foreign = replace(address, key="foreign")
        gateway.write(other, foreign, text, expected_version=0, inputs=(lineage,), ttl=1)
        data["coordinator"].checkpoint(data["scope"], control=data["control"])
        data["now"][0] += 2
        result = api.handle(human, request("sweep", maximum_resources=256))
        assert result["artifact_result"]["resources_scanned"] == 1
        assert not gateway._resources[address].versions
        assert len(gateway._resources[foreign].versions) == 1
        assert gateway._resources[foreign].labels.labels == ("secret",)
        assert text not in json.dumps(result)
