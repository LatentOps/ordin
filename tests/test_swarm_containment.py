"""Containment at real mTLS/native/DB boundaries, including races and recovery."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Event
from contextlib import ExitStack, contextmanager
import json
import time

import pytest

from ordin._runtime_json import digest
from ordin.swarm.coordinator_store import CoordinatorRejected
from ordin.swarm.incident import (
    IncidentPolicy,
    IncidentScope,
    IncidentSignal,
    IncidentSignalSource,
    IncidentResumeReceipt,
    SwarmContainmentController,
)
from tests.test_swarm_coordinator import configured, prepare
from tests.assurance.test_delegating_gate import action


@contextmanager
def second_scope(data, tmp_path, *, temporal_policy=None, core=None):
    """Another independently authenticated host/issuer on the same DB authority."""
    from ordin import AgentGate, Ordin
    from ordin.assurance import AssuranceGate, DelegationIssuer, HostEvidenceSource
    from ordin.swarm import InMemoryAgentRegistry
    from ordin.swarm.delegation import SwarmDelegationService
    from ordin.swarm.workload_auth import WorkloadAuthenticator
    from tests.assurance.test_delegation import maximum
    from tests.assurance.test_invariants import SEMANTICS
    from tests.assurance.test_profiles import REPO, POLICY_HASH, approve, selected, config_profile
    from tests.test_swarm_delegation import fingerprint, server_context, tls_pair

    tmp_path.mkdir()
    operator, coordinator, clock = data["operator"], data["coordinator"], data["clock"]
    profile = approve(selected(tmp_path, config_profile()))
    host = HostEvidenceSource("parent", REPO, "a" * 64, 0, POLICY_HASH, profile.selection_digest)
    rights = maximum()
    issuer = DelegationIssuer(host, profile, rights, rights, clock=clock)
    root = issuer.authorize_root(rights, grant_id="other-root", expires_at=clock() + 100)
    registry = InMemoryAgentRegistry("tenant", "other-swarm", clock=clock)
    adapter = object()
    local = registry.bind_channel(adapter, runtime_id="other-host")
    context = registry.enroll(
        local, adapter, agent_id="parent", session_id="other-session", task_id="task"
    )
    engine, event_source, ingest = None, None, None
    if temporal_policy is not None:
        from ordin.swarm import SwarmCausalGraph, SwarmEventIngestor, SwarmTemporalEngine

        ingest = SwarmEventIngestor(registry)
        event_source = ingest.bind_source(context, local, adapter, source_id="other-events")
        engine = SwarmTemporalEngine(
            SwarmCausalGraph(ingest, event_source, context), temporal_policy, clock=clock
        )
    tls = server_context()
    auth = WorkloadAuthenticator(registry, tls, operator=operator, clock=clock)
    native = SwarmDelegationService(
        issuer,
        AssuranceGate(AgentGate(core or Ordin(tool_semantics=SEMANTICS)), profile),
        auth,
        operator=operator,
    )
    enrollment = auth.enroll_workload(
        host_id="host-b",
        certificate_digest=fingerprint("parent"),
        context=context,
        source=host,
        channel=local,
        adapter=adapter,
        operator=operator,
    )
    auth.enroll_broker(
        host_id="host-b", certificate_digest=fingerprint("broker-b"), operator=operator
    )
    with ExitStack() as stack:
        server, _ = stack.enter_context(tls_pair(tls, "parent"))
        workload = auth.authenticate(server)
        broker_server, _ = stack.enter_context(tls_pair(tls, "broker-b"))
        broker = auth.authenticate(broker_server)
        grant = native.publish_root(enrollment, root, operator=operator)
        handle = coordinator.register_scope(
            native,
            data["budget"],
            control=data["control"],
            broker_channels=(broker,),
            temporal=engine,
        )
        coordinator.initialize_scope(handle, control=data["control"])
        coordinator.start(handle, control=data["control"])
        lease = coordinator.admit(handle, workload)
        coordinator.bind_grant(handle, workload, lease.reference, grant.grant_id)
        yield {
            "scope": handle,
            "workload": workload,
            "broker": broker,
            "lease": lease,
            "native": native,
            "grant": grant.grant_id,
            "context": context,
            "engine": engine,
            "source": event_source,
            "ingest": ingest,
        }


def prepare_other(data, other):
    coordinator, scope = data["coordinator"], other["scope"]
    proposed = action("other-action")
    evaluated = coordinator.evaluate(
        scope,
        other["workload"],
        other["lease"].reference,
        other["grant"],
        proposed,
        idempotency_key="other-evaluate",
    )
    return coordinator.reserve(
        scope,
        other["workload"],
        other["lease"].reference,
        evaluated.reference,
        proposed,
        idempotency_key="other-reserve",
    )


def controller(data, *, maximum=256):
    signals = IncidentSignalSource(operator=data["operator"])
    value = SwarmContainmentController(
        data["coordinator"],
        data["scope"],
        control=data["control"],
        operator=data["operator"],
        policy=IncidentPolicy("incidents", 1, max_affected=maximum),
        signals=signals,
    )
    return value, signals


def signal(data, source, kind="agent", *, agent="parent"):
    return source.operator_signal(
        IncidentScope(
            kind,
            "tenant",
            None if kind == "tenant" else "swarm",
            agent if kind in {"agent", "delegation_subtree", "action"} else None,
            task_id="task" if kind == "task" else None,
            action_digest=digest(action("one").as_dict()) if kind == "action" else None,
        ),
        severity="critical",
        operator=data["operator"],
    )


def settled(value, receipt, data):
    assert value._original(receipt).done.wait(5), "owned notifications did not settle"
    return value.status(receipt, operator=data["operator"])


@pytest.mark.parametrize("kind", ["agent", "delegation_subtree", "task", "swarm", "tenant"])
def test_parent_scope_fences_cached_descendant_and_cancels_queued_budget(tmp_path, kind):
    with configured(tmp_path) as data:
        value, source = controller(data)
        proposed, _, reserved = prepare(data)
        receipt = value.revoke(signal(data, source, kind), operator=data["operator"])
        report = settled(value, receipt, data)
        assert report["affected_agents"] == 2 and report["proof_gaps"] == []
        assert not report["completed_effects_undone"] and report["unmediated_paths"] == "uncovered"
        called = []
        with pytest.raises((ValueError, CoordinatorRejected)):
            data["coordinator"].guarded_dispatch(
                data["scope"],
                data["channels"]["broker-b"],
                reserved.reference,
                forward=lambda current: called.append(current),
            )
        with pytest.raises(ValueError):
            data["native"].review(data["channels"]["child"], data["references"]["child"], proposed)
        assert called == []
        with data["store"].transaction() as transaction:
            state = transaction.scope(data["scope"].scope_key)
            assert state["reservations"][reserved.reference]["status"] == "canceled"
            assert (
                transaction.connection.execute("SELECT held FROM coordinator_buckets").fetchone()[0]
                == 0
            )
        serialized = json.dumps(report)
        assert "read_file" not in serialized and "approval" not in serialized


def test_action_fence_blocks_cached_native_admission_without_pausing_other_actions(tmp_path):
    with configured(tmp_path, limit=4) as data:
        value, source = controller(data)
        proposed = action("one")
        cached = data["native"].review(
            data["channels"]["child"], data["references"]["child"], proposed
        )
        receipt = value.quarantine(
            signal(data, source, "action", agent="child"), operator=data["operator"]
        )
        assert settled(value, receipt, data)["affected_agents"] == 1
        with pytest.raises(ValueError):
            data["native"].guarded_dispatch(
                data["channels"]["broker-b"],
                cached.admission_id,
                proposed,
                lambda current: pytest.fail("fenced native action reached callback"),
            )
        assert (
            data["native"]
            .review(data["channels"]["child"], data["references"]["child"], action("different"))
            .disposition
            == "execute"
        )


def test_receipts_signals_operator_and_blast_radius_are_not_json_authority(tmp_path):
    with configured(tmp_path) as data:
        value, source = controller(data, maximum=1)
        original = signal(data, source)
        with pytest.raises(ValueError, match="blast radius"):
            value.pause(original, operator=data["operator"])
        with pytest.raises(ValueError):
            value.pause(IncidentSignal(original.signal_id), operator=data["operator"])
        with pytest.raises(ValueError):
            value.pause(original, operator=object())
        other = source.operator_signal(
            IncidentScope("agent", "foreign", "swarm", "parent"),
            severity="critical",
            operator=data["operator"],
        )
        with pytest.raises(ValueError):
            value.pause(other, operator=data["operator"])


def test_resume_requires_fresh_fence_original_reconciliation_and_never_restores_old_grants(
    tmp_path,
):
    with configured(tmp_path) as data:
        value, source = controller(data)
        prepare(data)
        receipt = value.pause(signal(data, source), operator=data["operator"])
        settled(value, receipt, data)
        with pytest.raises(ValueError, match="new policy epoch or owner fence"):
            value.approve_resume(receipt, operator=data["operator"])
        data["coordinator"].start(data["scope"], control=data["control"], takeover=True)
        approval = value.approve_resume(receipt, operator=data["operator"])
        with pytest.raises(ValueError):
            value.resume(replace(receipt), approval, operator=data["operator"])
        with pytest.raises(ValueError):
            value.resume(
                receipt, IncidentResumeReceipt(approval.receipt_id), operator=data["operator"]
            )
        assert value.resume(receipt, approval, operator=data["operator"])["resumed"]
        with pytest.raises(ValueError):
            value.resume(receipt, approval, operator=data["operator"])
        with pytest.raises(ValueError):
            data["native"].review(
                data["channels"]["child"], data["references"]["child"], action("new")
            )


def test_pause_during_host_callback_returns_unknown_without_waiting_for_issuer_lock(tmp_path):
    with configured(tmp_path) as data:
        value, source = controller(data)
        _, _, reserved = prepare(data)
        entered, release = Event(), Event()

        def callback(current):
            entered.set()
            assert release.wait(10)
            return "already-in-flight"

        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(
                data["coordinator"].guarded_dispatch,
                data["scope"],
                data["channels"]["broker-b"],
                reserved.reference,
                forward=callback,
            )
            assert entered.wait(5)
            started = time.monotonic()
            receipt = value.pause(signal(data, source), operator=data["operator"])
            assert time.monotonic() - started < 2
            report = value.status(receipt, operator=data["operator"])
            assert not report["notifications_complete"] and not report["completed_effects_undone"]
            with pytest.raises(ValueError):
                value.approve_resume(receipt, operator=data["operator"])
            release.set()
            assert future.result(5).status == "unknown"
        settled(value, receipt, data)
        with data["store"].transaction() as transaction:
            assert (
                transaction.scope(data["scope"].scope_key)["reservations"][reserved.reference][
                    "status"
                ]
                == "uncertain"
            )


def test_partition_and_restart_cannot_resurrect_contained_work(tmp_path):
    with configured(tmp_path) as data:
        value, source = controller(data)
        receipt = value.quarantine(signal(data, source), operator=data["operator"])
        settled(value, receipt, data)
        data["coordinator"]._available = False
        with pytest.raises((ValueError, CoordinatorRejected)):
            value.approve_resume(receipt, operator=data["operator"])
        assert not value.status(receipt, operator=data["operator"])["coordinator_online"]


def test_unrelated_swarm_remains_available_after_narrow_quarantine(tmp_path):
    with configured(tmp_path / "first") as data, second_scope(data, tmp_path / "second") as other:
        value, source = controller(data)
        receipt = value.quarantine(signal(data, source), operator=data["operator"])
        settled(value, receipt, data)
        reserved = prepare_other(data, other)
        calls = []
        result = data["coordinator"].guarded_dispatch(
            other["scope"],
            other["broker"],
            reserved.reference,
            forward=lambda current: calls.append(current) or "unrelated-safe",
        )
        assert result.status == "host_completed" and len(calls) == 1


def test_tenant_pause_with_two_inflight_hosts_reports_unknown_without_claiming_rollback(tmp_path):
    with configured(tmp_path / "first") as data, second_scope(data, tmp_path / "second") as other:
        value, source = controller(data)
        _, _, first = prepare(data)
        second = prepare_other(data, other)
        entered = [Event(), Event()]
        releases = [Event(), Event()]

        def callback(index):
            def forward(current):
                entered[index].set()
                assert releases[index].wait(15)
                return "completed-before-ack"

            return forward

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [
                pool.submit(
                    data["coordinator"].guarded_dispatch,
                    data["scope"],
                    data["channels"]["broker-b"],
                    first.reference,
                    forward=callback(0),
                ),
                pool.submit(
                    data["coordinator"].guarded_dispatch,
                    other["scope"],
                    other["broker"],
                    second.reference,
                    forward=callback(1),
                ),
            ]
            try:
                assert all(value.wait(5) for value in entered)
                receipt = value.pause(signal(data, source, "tenant"), operator=data["operator"])
                report = value.status(receipt, operator=data["operator"])
                assert len(report["durable_outcomes"]) == 2
                assert {item["status"] for item in report["durable_outcomes"]} == {"unknown"}
                assert not report["completed_effects_undone"]
            finally:
                for release in releases:
                    release.set()
            assert all(future.result(10).status == "unknown" for future in futures)
        settled(value, receipt, data)
        data["coordinator"].start(data["scope"], control=data["control"], takeover=True)
        data["coordinator"].start(other["scope"], control=data["control"], takeover=True)
        with pytest.raises(ValueError):
            value.approve_resume(receipt, operator=data["operator"])


def test_all_five_cascade_templates_are_data_only_and_automatic_rules_are_explicit():
    from ordin.swarm.incident import incident_temporal_policy, cascade_incident_rules
    from ordin.swarm.temporal_policy import SwarmTemporalPolicySet
    from ordin.swarm.incident_rules import CASCADE_RULE_IDS

    policy = incident_temporal_policy()
    assert tuple(rule.rule_id for rule in policy.rules) == CASCADE_RULE_IDS
    assert SwarmTemporalPolicySet.from_dict(policy.as_dict()).digest == policy.digest
    assert IncidentPolicy("off", 1).automatic_rules == ()
    assert len(cascade_incident_rules(CASCADE_RULE_IDS)) == 5
    with pytest.raises(ValueError):
        cascade_incident_rules(("model-claimed-compromise",))
    with pytest.raises(ValueError):
        cascade_incident_rules((CASCADE_RULE_IDS[0], CASCADE_RULE_IDS[0]))


def test_automatic_repeated_denials_require_current_original_temporal_facts(tmp_path):
    from ordin import ActionEnvelope
    from ordin.swarm import EventRef, SwarmEvent
    from ordin.swarm.incident import incident_temporal_policy, cascade_incident_rules

    with (
        configured(tmp_path / "first") as data,
        second_scope(
            data, tmp_path / "second", temporal_policy=incident_temporal_policy()
        ) as other,
    ):
        signals = IncidentSignalSource(operator=data["operator"])
        value = SwarmContainmentController(
            data["coordinator"],
            other["scope"],
            control=data["control"],
            operator=data["operator"],
            policy=IncidentPolicy(
                "automatic",
                1,
                cascade_incident_rules(("incident_repeated_denials",), max_affected=1),
            ),
            signals=signals,
        )
        engine, context, source, ingest = (
            other["engine"],
            other["context"],
            other["source"],
            other["ingest"],
        )
        sequence = 0
        previous = ()

        def emit(key, kind, proposed, review=None):
            nonlocal sequence, previous
            sequence += 1
            event = SwarmEvent(
                key,
                kind,
                context.registry_id,
                context.identity,
                source.source_id,
                sequence,
                99999999,
                "host_authenticated",
                action_id=proposed.action_id,
                action_digest=digest(proposed.as_dict()),
                review_event_id=review,
                parent_event_ids=tuple(
                    EventRef("tenant", "other-swarm", name) for name in previous
                ),
            )
            ingest.ingest(source, event)
            engine.record_event(source, key, action=proposed)
            previous = (key,)

        for index in range(3):
            proposed = ActionEnvelope.shell(
                "rm -f /fixture/file", action_id="attempt-" + str(index)
            )
            emit("review-" + str(index), "reviewed", proposed)
            emit("deny-" + str(index), "denied", proposed, "review-" + str(index))
        proposed = ActionEnvelope.shell("git status", action_id="next-proposal")
        original = value.temporal_signal(
            engine, context, source, proposed, parent_event_ids=previous
        )
        with pytest.raises(ValueError):
            value.quarantine(IncidentSignal(original.signal_id))
        emit("later-review", "reviewed", ActionEnvelope.shell("git status", action_id="later"))
        with pytest.raises(ValueError, match="current original configured"):
            value.quarantine(original)
        current = value.temporal_signal(
            engine, context, source, proposed, parent_event_ids=previous
        )
        receipt = value.quarantine(current)
        assert value._original(receipt).done.wait(5)
        report = value.status(receipt, operator=data["operator"])
        assert report["affected_agents"] == 1 and not report["resumed"]


def test_group_resume_reconciles_every_member_before_clearing_tenant_barrier(tmp_path):
    with configured(tmp_path / "first") as data, second_scope(data, tmp_path / "second") as other:
        value, source = controller(data)
        prepare(data)
        prepare_other(data, other)
        receipt = value.pause(signal(data, source, "tenant"), operator=data["operator"])
        settled(value, receipt, data)
        data["coordinator"].start(data["scope"], control=data["control"], takeover=True)
        with pytest.raises(ValueError):
            value.approve_resume(receipt, operator=data["operator"])
        data["coordinator"].start(other["scope"], control=data["control"], takeover=True)
        approval = value.approve_resume(receipt, operator=data["operator"])
        assert value.resume(receipt, approval, operator=data["operator"])["resumed"]
        with data["store"].transaction() as transaction:
            states = [
                transaction.scope(handle.scope_key) for handle in (data["scope"], other["scope"])
            ]
            assert all(
                state["fences"][str(state["revocation_epoch"])]["reconciled"] for state in states
            )
            assert (
                transaction.connection.execute("SELECT state FROM coordinator_barriers").fetchone()[
                    0
                ]
                == "reconciled"
            )


def test_lost_fence_ack_never_leaves_cached_native_admission_open(tmp_path, monkeypatch):
    from ordin.swarm.coordinator_store import CoordinatorUnavailable

    with configured(tmp_path) as data:
        value, source = controller(data)
        proposed, _, _ = prepare(data)
        original = data["store"].transaction

        @contextmanager
        def lost_ack():
            with original() as transaction:
                yield transaction
            raise CoordinatorUnavailable("lost durable acknowledgement")

        monkeypatch.setattr(data["store"], "transaction", lost_ack)
        selected = signal(data, source)
        with pytest.raises(CoordinatorUnavailable):
            value.pause(selected, operator=data["operator"])
        monkeypatch.setattr(data["store"], "transaction", original)
        with pytest.raises(ValueError):
            data["native"].review(data["channels"]["child"], data["references"]["child"], proposed)
        with pytest.raises(ValueError, match="already used"):
            value.pause(selected, operator=data["operator"])
        with original() as transaction:
            assert transaction.scope(data["scope"].scope_key)["revocation_epoch"] == 1


def test_scoped_credential_route_is_revoked_without_exposing_private_bytes(tmp_path):
    from ordin import Ordin
    from ordin.assurance import RestSemantics
    from ordin.runtime_contract import CredentialBinding
    from ordin.swarm.credential_broker import SwarmCredentialBroker
    from tests.test_swarm_delegation import GET

    with (
        configured(tmp_path / "first") as data,
        second_scope(
            data, tmp_path / "second", core=Ordin(rest_semantics=RestSemantics())
        ) as other,
    ):
        secret = b"SYNTHETIC_INCIDENT_PRIVATE_CREDENTIAL"
        vault = SwarmCredentialBroker(other["native"], operator=data["operator"])
        route = vault.register(
            binding=CredentialBinding("fixture-key", "fixture.invalid", 443),
            action=GET,
            credential=secret,
            forward=lambda request: pytest.fail("revoked credential forwarded"),
            operator=data["operator"],
        )
        signals = IncidentSignalSource(operator=data["operator"])
        value = SwarmContainmentController(
            data["coordinator"],
            other["scope"],
            control=data["control"],
            operator=data["operator"],
            policy=IncidentPolicy("credentials", 1),
            signals=signals,
            credentials=(
                (vault, route, IncidentScope("agent", "tenant", "other-swarm", "parent")),
            ),
        )
        selected_signal = signals.operator_signal(
            IncidentScope("agent", "tenant", "other-swarm", "parent"),
            severity="critical",
            operator=data["operator"],
        )
        receipt = value.revoke(selected_signal, operator=data["operator"])
        report = settled(value, receipt, data)
        assert vault._routes[route].revoked
        assert vault._routes[route].secret == b""
        assert secret.decode() not in json.dumps(report) + json.dumps(vault.audit())
