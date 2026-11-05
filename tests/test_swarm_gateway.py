from concurrent.futures import ThreadPoolExecutor
from copy import copy
from dataclasses import replace

import pytest

from ordin import ActionEnvelope
from ordin.swarm import CoverageManifest, InMemoryAgentRegistry, SwarmEventIngestor, SwarmGate
from ordin.swarm import SwarmAssessmentSource, SwarmPolicy
from ordin._runtime_json import digest
from ordin.swarm.gateway import ForwardTicket, GatewayAgent, GatewayOutcome, SwarmToolGateway


def host(*, mode="intercept", events=True):
    now = [100.0]
    registry = InMemoryAgentRegistry("tenant", "swarm", clock=lambda: now[0])
    journal = SwarmEventIngestor(registry) if events else None
    gate = SwarmGate(registry, events=journal)
    gateway = SwarmToolGateway(events=journal, clock=lambda: now[0])

    def enroll(name, *, approval_ui=False):
        adapter = object()
        channel = registry.bind_channel(adapter, runtime_id="fixture")
        context = registry.enroll(
            channel,
            adapter,
            agent_id=name,
            session_id="session-" + name,
            coverage=CoverageManifest(mode),
        )
        handle = gateway.bind_agent(
            context,
            gate,
            channel,
            adapter,
            routes=frozenset({"sdk", "mcp", "shell", "file"}),
            approval_ui=approval_ui,
        )
        return handle, context, channel, adapter

    return registry, journal, gateway, enroll, now


def benign():
    return ActionEnvelope.shell("git status --short", action_id="model-supplied-id")


def test_benign_forward_is_one_use_exact_and_host_correlated():
    _, journal, gateway, enroll, _ = host()
    actor, context, _, _ = enroll("a")
    original = benign()
    authorization = gateway.prepare(actor, original)
    assert authorization.disposition == "execute"
    assert authorization.action_id != original.action_id
    called = []
    result = gateway.forward(
        actor, authorization.ticket, lambda action: called.append(action.as_dict()) or "ok"
    )
    assert result.value == "ok" and result.status == "completed"
    assert called[0]["parameters"] == original.as_dict()["parameters"]
    assert called[0]["action_id"] == authorization.action_id
    with pytest.raises(ValueError):
        gateway.forward(actor, authorization.ticket, lambda action: called.append(action))
    assert len(called) == 1
    records = journal.snapshot()
    assert [r.event.event_kind for r in records] == [
        "proposed",
        "reviewed",
        "reserved",
        "committed",
        "forwarded",
        "completed",
    ]
    assert all(r.event.evidence_class == "host_authenticated" for r in records)


def test_forbidden_and_unsupported_approval_paths_get_no_forwarding_ticket():
    _, journal, gateway, enroll, _ = host()
    actor, _, _, _ = enroll("a")
    blocked = gateway.prepare(actor, ActionEnvelope.shell("rm -rf /"))
    assert blocked.disposition == "deny" and blocked.ticket is None
    uncertain = gateway.prepare(actor, ActionEnvelope.shell("unknown_future_tool --opaque"))
    assert uncertain.disposition == "deny" and uncertain.ticket is None
    actor_ui, _, _, _ = enroll("ui", approval_ui=True)
    escalation = gateway.prepare(actor_ui, ActionEnvelope.shell("unknown_future_tool --opaque"))
    assert escalation.disposition == "escalate" and escalation.ticket is None
    assert "forwarded" not in {r.event.event_kind for r in journal.snapshot()}


def test_two_agents_keep_histories_and_ticket_authority_separate():
    _, journal, gateway, enroll, _ = host()
    a, _, _, _ = enroll("a")
    b, _, _, _ = enroll("b")
    authorization = gateway.prepare(a, benign())
    with pytest.raises(ValueError):
        gateway.forward(b, authorization.ticket, lambda action: None)
    assert gateway.forward(a, authorization.ticket, lambda action: "a").value == "a"
    other = gateway.prepare(b, benign())
    assert gateway.forward(b, other.ticket, lambda action: "b").value == "b"
    assert authorization.action_id != other.action_id
    for actor in (a, b):
        session = gateway._actors[actor].session.snapshot()
        assert len(session["history"]["actions"]) == 1
    assert {r.event.identity.agent_id for r in journal.snapshot()} == {"a", "b"}


def test_changed_action_expiry_and_epoch_changes_consume_without_calling_executor():
    for kind in ("action", "expiry", "epoch"):
        registry, _, gateway, enroll, now = host()
        actor, _, _, _ = enroll("a")
        authorization = gateway.prepare(actor, benign())
        proposed = gateway._pending[authorization.ticket].action
        if kind == "expiry":
            now[0] = 131
        elif kind == "epoch":
            registry.advance_policy_epoch(1)
        called = []
        with pytest.raises(ValueError):
            gateway.forward(
                actor,
                authorization.ticket,
                lambda action: called.append(action),
                action=replace(proposed, parameters={"command": "rm -rf /"})
                if kind == "action"
                else proposed,
            )
        assert called == []


def test_executor_failure_is_not_retried_and_records_only_a_host_failure():
    _, journal, gateway, enroll, _ = host()
    actor, _, _, _ = enroll("a")
    authorization = gateway.prepare(actor, benign())
    calls = []

    def failing(action):
        calls.append(action.action_id)
        raise OSError("private-upstream-error")

    with pytest.raises(OSError):
        gateway.forward(actor, authorization.ticket, failing)
    with pytest.raises(ValueError):
        gateway.forward(actor, authorization.ticket, failing)
    assert len(calls) == 1
    assert journal.snapshot()[-1].event.event_kind == "failed"
    assert "private-upstream-error" not in str([r.event.as_dict() for r in journal.snapshot()])


def test_observe_only_and_uncovered_routes_are_reported_and_cannot_forward():
    _, _, gateway, enroll, _ = host(mode="observe")
    actor, _, _, _ = enroll("a")
    assert gateway.prepare(actor, benign()).ticket is None
    status = gateway.status(actor)
    assert status["mode"] == "observe" and set(status["routes"].values()) == {"coverage_gap"}


def test_current_evidence_snapshot_changes_invalidate_pending_decision():
    _, _, gateway, enroll, _ = host()
    a, _, _, _ = enroll("a")
    b, _, _, _ = enroll("b")
    first = gateway.prepare(a, benign())
    second = gateway.prepare(b, benign())
    gateway.forward(b, second.ticket, lambda action: None)
    with pytest.raises(ValueError, match="stale"):
        gateway.forward(a, first.ticket, lambda action: None)


def test_copied_or_constructed_handles_never_forward():
    _, _, gateway, enroll, _ = host()
    actor, _, _, _ = enroll("a")
    authorization = gateway.prepare(actor, benign())
    for bad in (copy(authorization.ticket), ForwardTicket(authorization.ticket.ticket_id)):
        with pytest.raises(ValueError):
            gateway.forward(actor, bad, lambda action: None)
    for bad in (copy(actor), GatewayAgent(actor.binding_id)):
        with pytest.raises(ValueError):
            gateway.prepare(bad, benign())
    gateway.forward(actor, authorization.ticket, lambda action: None)


def test_pending_host_result_does_not_invent_completion():
    _, journal, gateway, enroll, _ = host()
    actor, _, _, _ = enroll("a")
    authorization = gateway.prepare(actor, benign())
    result = gateway.forward(
        actor, authorization.ticket, lambda action: GatewayOutcome({"task": "later"}, "pending")
    )
    assert result.status == "pending"
    assert journal.snapshot()[-1].event.event_kind == "forwarded"


def test_host_assessment_provider_gets_exact_host_assigned_action_and_review_inputs():
    registry, _, gateway, enroll, _ = host(events=False)
    provider = SwarmAssessmentSource("checks", clock=lambda: 100)
    policy = SwarmPolicy("budget", "1", required_checks=("budget",))
    gate = SwarmGate(registry, policy=policy, assessment_source=provider)
    adapter = object()
    channel = registry.bind_channel(adapter, runtime_id="fixture")
    context = registry.enroll(
        channel,
        adapter,
        agent_id="checked",
        session_id="checked",
        coverage=CoverageManifest("intercept"),
    )
    seen = []

    def facts(context, action, gate, options):
        seen.append(action.action_id)
        return (
            provider.issue(
                check_id="budget",
                status="satisfied",
                action_digest=digest(action.as_dict()),
                context_digest=digest(context.as_dict()),
                policy_digest=gate.policy_digest,
                snapshot_digest=gate.evidence_snapshot_digest(context, **options),
            ),
        )

    actor = gateway.bind_agent(
        context, gate, channel, adapter, routes=frozenset({"sdk"}), assessment_provider=facts
    )
    authorization = gateway.prepare(actor, benign())
    assert authorization.ticket is not None and seen == [authorization.action_id]
    assert gateway.forward(actor, authorization.ticket, lambda action: "ok").value == "ok"


def test_tenant_bindings_do_not_share_forwarding_authority_or_history():
    gateway = SwarmToolGateway(clock=lambda: 100)
    handles = []
    for tenant in ("tenant-a", "tenant-b"):
        registry = InMemoryAgentRegistry(tenant, "same-name", clock=lambda: 100)
        adapter = object()
        channel = registry.bind_channel(adapter, runtime_id="same-runtime")
        context = registry.enroll(
            channel,
            adapter,
            agent_id="same-agent",
            session_id="same-session",
            coverage=CoverageManifest("intercept"),
        )
        handles.append(
            gateway.bind_agent(
                context, SwarmGate(registry), channel, adapter, routes=frozenset({"sdk"})
            )
        )
    authorization = gateway.prepare(handles[0], benign())
    with pytest.raises(ValueError):
        gateway.forward(handles[1], authorization.ticket, lambda action: None)
    gateway.forward(handles[0], authorization.ticket, lambda action: None)
    assert gateway._actors[handles[1]].session.snapshot()["history"]["actions"] == []
    assert gateway.status(handles[0])["identity"]["tenant_id"] == "tenant-a"
    assert gateway.status(handles[1])["identity"]["tenant_id"] == "tenant-b"
