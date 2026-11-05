"""Atomic shared holds, one-use forwarding and durable conservative recovery."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from copy import copy
from dataclasses import replace
import json
from threading import Barrier

import pytest

from ordin import ActionEnvelope
from ordin.swarm import CoverageManifest, InMemoryAgentRegistry
from ordin.swarm.budgets import (
    BudgetCost,
    BudgetError,
    BudgetLedger,
    BudgetLimit,
    BudgetObservation,
    BudgetObservationSource,
    BudgetPolicy,
    BudgetTicket,
)
from ordin.swarm.budget_store import InMemoryBudgetStore, SQLiteBudgetStore


def configured(*, limits=None, store=None, max_reservations=4096):
    now = [100.0]
    registry = InMemoryAgentRegistry(
        "tenant", "swarm", clock=lambda: now[0], heartbeat_timeout=3600
    )
    values = {}
    for name, parent, task in (
        ("parent", None, "parent-task"),
        ("a", "parent", "task-a"),
        ("b", "parent", "task-b"),
    ):
        adapter = object()
        channel = registry.bind_channel(adapter, runtime_id="fixture")
        context = registry.enroll(
            channel,
            adapter,
            agent_id=name,
            session_id="session-" + name,
            parent_agent_id=parent,
            task_id=task,
            coverage=CoverageManifest("intercept"),
        )
        values[name] = (context, channel, adapter)
    operator = object()
    observations = BudgetObservationSource()
    policy = BudgetPolicy(
        0, limits or (BudgetLimit("swarm", "requests", 100),), max_reservations=max_reservations
    )
    ledger = BudgetLedger(
        registry,
        policy,
        store=store,
        clock=lambda: now[0],
        operator=operator,
        observations=observations,
    )
    return ledger, registry, values, now, operator, observations


def action(identity="operation"):
    return ActionEnvelope.shell("git status", action_id=identity)


def reserve(ledger, actor, *, key="operation", amount=70, metric="requests"):
    context, channel, adapter = actor
    return ledger.reserve(
        context,
        action(key),
        channel=channel,
        adapter=adapter,
        idempotency_key=key,
        costs=(BudgetCost(metric, amount),),
    )


def report(ledger, actor):
    context, channel, adapter = actor
    return ledger.report(context, channel=channel, adapter=adapter)


def begin(ledger, ticket, actor, key="operation"):
    context, channel, adapter = actor
    ledger.begin_forward(ticket, context, action(key), channel=channel, adapter=adapter)


def test_two_concurrent_70_requests_under_100_across_1000_schedules():
    ledger, _, actors, _, _, _ = configured()

    def attempt(name, identity, barrier):
        barrier.wait(timeout=5)
        try:
            return reserve(ledger, actors[name], key=identity)
        except BudgetError as exc:
            assert exc.reason_code == "budget.limit_exceeded"
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        for schedule in range(1000):
            barrier = Barrier(2)
            names = ("a", "b") if schedule % 2 else ("b", "a")
            futures = [
                executor.submit(attempt, name, f"{schedule}-{name}", barrier) for name in names
            ]
            tickets = [future.result(timeout=10) for future in futures]
            admitted = [ticket for ticket in tickets if ticket is not None]
            assert len(admitted) == 1
            assert report(ledger, actors["a"])["limits"][0]["reserved"] == 70
            ledger.cancel(admitted[0])
    assert report(ledger, actors["a"])["limits"][0]["consumed"] == 0


def test_reserve_is_not_consumption_and_cancel_expiry_are_safe_and_idempotent():
    ledger, _, actors, now, _, _ = configured()
    ticket = reserve(ledger, actors["a"])
    state = report(ledger, actors["a"])["limits"][0]
    assert (state["reserved"], state["consumed"], state["observed"]) == (70, 0, None)
    assert reserve(ledger, actors["a"]) is ticket
    ledger.cancel(ticket)
    ledger.cancel(ticket)
    with pytest.raises(BudgetError):
        begin(ledger, ticket, actors["a"])
    other = reserve(ledger, actors["a"], key="expire")
    now[0] += 31
    assert ledger.expire() == 1
    assert report(ledger, actors["a"])["limits"][0]["reserved"] == 0
    with pytest.raises(BudgetError):
        begin(ledger, other, actors["a"], "expire")


def test_original_ticket_action_context_and_epoch_bindings_are_required():
    ledger, registry, actors, _, _, _ = configured()
    ticket = reserve(ledger, actors["a"])
    for forged in (copy(ticket), BudgetTicket(ticket.reservation_id)):
        with pytest.raises(BudgetError):
            begin(ledger, forged, actors["a"])
    with pytest.raises(ValueError):
        BudgetTicket.from_dict({"reservation_id": ticket.reservation_id})
    with pytest.raises(BudgetError):
        begin(ledger, ticket, actors["b"])
    with pytest.raises(BudgetError):
        begin(ledger, ticket, actors["a"], "changed")
    registry.advance_policy_epoch(1)
    with pytest.raises(ValueError):
        begin(ledger, ticket, actors["a"])
    ledger.cancel(ticket)  # Stale, never-forwarded work can safely release its hold.


def test_unknown_outcome_retains_hold_after_timeout_until_protected_settlement():
    ledger, _, actors, now, operator, observations = configured()
    ticket = reserve(ledger, actors["a"])
    begin(ledger, ticket, actors["a"])
    with pytest.raises(BudgetError):
        begin(ledger, ticket, actors["a"])
    ledger.uncertain(ticket)
    now[0] += 31
    assert ledger.expire() == 0
    with pytest.raises(BudgetError):
        ledger.cancel(ticket)
    with pytest.raises(BudgetError):
        reserve(ledger, actors["b"], key="other")
    receipt = observations.record(
        ticket.reservation_id,
        action(),
        actors["a"][0],
        outcome="no_effect",
        costs=(BudgetCost("requests", 0),),
    )
    with pytest.raises(BudgetError):
        ledger.reconcile(ticket.reservation_id, operator=object(), observation=receipt)
    assert (
        ledger.reconcile(ticket.reservation_id, operator=operator, observation=receipt)
        == "released"
    )
    assert (
        ledger.reconcile(ticket.reservation_id, operator=operator, observation=receipt)
        == "released"
    )
    assert report(ledger, actors["a"])["limits"][0]["remaining"] == 100


def test_consumed_and_observed_spend_are_distinct_and_cannot_be_refunded_by_json():
    ledger, _, actors, _, _, observations = configured()
    ticket = reserve(ledger, actors["a"])
    begin(ledger, ticket, actors["a"])
    forged = BudgetObservation(
        ticket.reservation_id, "a" * 64, "b" * 64, "no_effect", (BudgetCost("requests", 0),)
    )
    for value in (forged, {"costs": {"requests": 0}}):
        with pytest.raises(BudgetError):
            ledger.commit(ticket, observation=value)
    assert ledger.commit(ticket) == "committed"
    assert ledger.commit(ticket) == "committed"
    state = report(ledger, actors["a"])["limits"][0]
    assert (state["reserved"], state["consumed"], state["observed"]) == (0, 70, None)
    other = reserve(ledger, actors["a"], key="measured", amount=20)
    begin(ledger, other, actors["a"], "measured")
    receipt = observations.record(
        other.reservation_id,
        action("measured"),
        actors["a"][0],
        outcome="completed",
        costs=(BudgetCost("requests", 10),),
    )
    assert ledger.commit(other, observation=receipt) == "committed"
    state = report(ledger, actors["a"])["limits"][0]
    assert state["consumed"] == 80 and state["observed"] == 10
    assert "session-a" not in json.dumps(report(ledger, actors["a"]))


def test_unknown_cost_default_deny_and_bounded_effect_fallback_cannot_escape_parent_limit():
    ledger, _, actors, _, _, _ = configured(limits=(BudgetLimit("swarm", "dollar_micros", 100),))
    with pytest.raises(BudgetError, match="unknown_cost"):
        reserve(ledger, actors["a"], amount=None, metric="dollar_micros")
    ledger, _, actors, _, _, _ = configured(
        limits=(
            BudgetLimit(
                "swarm",
                "dollar_micros",
                100,
                unknown_ceiling=70,
                unknown_effects=("network.upload",),
            ),
            BudgetLimit(
                "agent",
                "dollar_micros",
                100,
                subject="parent",
                unknown_ceiling=50,
                unknown_effects=("network.upload",),
            ),
        )
    )
    context, channel, adapter = actors["a"]
    ticket = ledger.reserve(
        context,
        action(),
        channel=channel,
        adapter=adapter,
        idempotency_key="unknown",
        costs=(BudgetCost("dollar_micros", None),),
        effects=("network.upload",),
    )
    assert all(v["reserved"] == 70 for v in report(ledger, actors["a"])["limits"])
    ledger.cancel(ticket)
    with pytest.raises(BudgetError, match="unknown_cost"):
        ledger.reserve(
            context,
            action(),
            channel=channel,
            adapter=adapter,
            idempotency_key="unknown2",
            costs=(),
            effects=("filesystem.read",),
        )


def test_ancestors_tasks_and_sibling_spend_do_not_reset_on_child_rename_or_restart():
    ledger, registry, actors, _, _, _ = configured(
        limits=(
            BudgetLimit("swarm", "requests", 1000),
            BudgetLimit("agent", "requests", 100),
            BudgetLimit("task", "requests", 100, subject="parent-task"),
        )
    )
    ticket = reserve(ledger, actors["a"])
    begin(ledger, ticket, actors["a"])
    ledger.commit(ticket)
    with pytest.raises(BudgetError, match="limit_exceeded"):
        reserve(ledger, actors["b"], key="sibling")
    context, channel, adapter = actors["a"]
    new_adapter = object()
    new_channel = registry.bind_channel(new_adapter, runtime_id="fixture")
    restarted = registry.restart(
        context,
        channel,
        adapter,
        new_channel=new_channel,
        new_adapter=new_adapter,
        session_id="new-session",
    )
    with pytest.raises(BudgetError, match="limit_exceeded"):
        reserve(ledger, (restarted, new_channel, new_adapter), key="restart")
    renamed = registry.enroll(
        new_channel,
        new_adapter,
        agent_id="renamed-child",
        session_id="renamed",
        parent_agent_id="parent",
        task_id="different-task",
    )
    with pytest.raises(BudgetError, match="limit_exceeded"):
        reserve(ledger, (renamed, new_channel, new_adapter), key="rename")


def test_overlapping_selectors_charge_once_at_stricter_limit_and_concurrency_releases():
    ledger, _, actors, _, _, _ = configured(
        limits=(
            BudgetLimit("agent", "requests", 100),
            BudgetLimit("agent", "requests", 80, subject="parent"),
            BudgetLimit("swarm", "concurrency", 1),
        )
    )
    context, channel, adapter = actors["a"]
    ticket = ledger.reserve(
        context,
        action(),
        channel=channel,
        adapter=adapter,
        idempotency_key="operation",
        costs=(BudgetCost("requests", 70), BudgetCost("concurrency", 1)),
    )
    begin(ledger, ticket, actors["a"])
    ledger.commit(ticket)
    states = report(ledger, actors["a"])["limits"]
    assert len(states) == 3
    assert sorted(v["consumed"] for v in states) == [0, 70, 70]
    assert next(v for v in states if v["metric"] == "concurrency")["remaining"] == 1


def test_persistent_recovery_fences_old_reserved_tickets_and_retains_forwarding_hold(tmp_path):
    path = tmp_path / "budget.sqlite"
    ledger, registry, actors, now, operator, observations = configured(
        store=SQLiteBudgetStore(path, create=True)
    )
    first = reserve(ledger, actors["a"], amount=20)
    second = reserve(ledger, actors["b"], key="forwarded", amount=70)
    begin(ledger, second, actors["b"], "forwarded")
    restored = BudgetLedger(
        registry,
        ledger.policy,
        store=SQLiteBudgetStore(path),
        clock=lambda: now[0],
        operator=operator,
        observations=observations,
    )
    with pytest.raises(BudgetError, match="fenced"):
        begin(ledger, first, actors["a"])
    state = report(restored, actors["a"])["limits"][0]
    assert state["reserved"] == 70 and state["consumed"] == 0
    now[0] += 31
    assert restored.expire() == 0
    with pytest.raises(BudgetError):
        reserve(restored, actors["a"], key="post-recovery", amount=40)
    receipt = observations.record(
        second.reservation_id,
        action("forwarded"),
        actors["b"][0],
        outcome="completed",
        costs=(BudgetCost("requests", 60),),
    )
    assert (
        restored.reconcile(second.reservation_id, operator=operator, observation=receipt)
        == "committed"
    )
    assert report(restored, actors["a"])["limits"][0]["consumed"] == 60


def test_failed_begin_expiry_is_durable_and_backward_clock_is_rejected(tmp_path):
    path = tmp_path / "budget.sqlite"
    ledger, registry, actors, now, operator, _ = configured(
        store=SQLiteBudgetStore(path, create=True)
    )
    ticket = reserve(ledger, actors["a"])
    now[0] += 31
    with pytest.raises(BudgetError):
        begin(ledger, ticket, actors["a"])
    assert ledger.reservation_status(ticket)["status"] == "expired"
    now[0] = 110
    with pytest.raises(ValueError, match="clock"):
        report(ledger, actors["a"])
    with pytest.raises(BudgetError, match="clock"):
        BudgetLedger(
            registry,
            ledger.policy,
            store=SQLiteBudgetStore(path),
            clock=lambda: now[0],
            operator=operator,
        )


def test_observed_bound_overrun_blocks_new_work_until_later_policy_epoch():
    ledger, _, actors, _, _, observations = configured()
    ticket = reserve(ledger, actors["a"], amount=10)
    begin(ledger, ticket, actors["a"])
    receipt = observations.record(
        ticket.reservation_id,
        action(),
        actors["a"][0],
        outcome="completed",
        costs=(BudgetCost("requests", 20),),
    )
    assert ledger.commit(ticket, observation=receipt) == "overrun"
    assert report(ledger, actors["a"])["limits"][0]["blocked"]
    with pytest.raises(BudgetError, match="exceeded_bound"):
        reserve(ledger, actors["a"], key="after-overrun", amount=1)


def test_same_coordinator_registry_views_share_tenant_limit_across_swarms():
    ledger, _, actors, now, _, _ = configured(limits=(BudgetLimit("tenant", "requests", 100),))
    other = InMemoryAgentRegistry("tenant", "other-swarm", clock=lambda: now[0])
    adapter = object()
    channel = other.bind_channel(adapter, runtime_id="fixture")
    context = other.enroll(channel, adapter, agent_id="different-root", session_id="session")
    view = ledger.for_registry(other)
    reserve(ledger, actors["a"])
    with pytest.raises(BudgetError, match="limit_exceeded"):
        reserve(view, (context, channel, adapter), key="other-swarm")
    assert report(view, (context, channel, adapter))["limits"][0]["reserved"] == 70
    with pytest.raises(BudgetError, match="idempotency"):
        reserve(view, (context, channel, adapter), key="operation", amount=1)


def test_lost_begin_acknowledgement_keeps_durable_hold_and_cannot_cancel_as_unforwarded(
    tmp_path, monkeypatch
):
    store = SQLiteBudgetStore(tmp_path / "budget.sqlite", create=True)
    ledger, registry, actors, now, operator, _ = configured(store=store)
    ticket = reserve(ledger, actors["a"])
    original = store.transaction

    @contextmanager
    def lost_ack():
        with original() as connection:
            yield connection
        raise ValueError("simulated acknowledgement loss after atomic commit")

    monkeypatch.setattr(store, "transaction", lost_ack)
    with pytest.raises(ValueError, match="acknowledgement"):
        begin(ledger, ticket, actors["a"])
    monkeypatch.setattr(store, "transaction", original)
    with pytest.raises(BudgetError):
        ledger.cancel(ticket)
    restored = BudgetLedger(
        registry,
        ledger.policy,
        store=SQLiteBudgetStore(store.path),
        clock=lambda: now[0],
        operator=operator,
    )
    assert report(restored, actors["a"])["limits"][0]["reserved"] == 70
    with pytest.raises(BudgetError):
        reserve(restored, actors["b"], key="would-overspend")


def test_interrupted_sql_transaction_rolls_back_all_bucket_updates(tmp_path):
    store = SQLiteBudgetStore(tmp_path / "budget.sqlite", create=True)
    ledger, _, actors, _, _, _ = configured(store=store)
    ticket = reserve(ledger, actors["a"])
    with pytest.raises(RuntimeError):
        with store.transaction() as connection:
            connection.execute("UPDATE budget_buckets SET held=0")
            raise RuntimeError("interrupted before commit")
    assert report(ledger, actors["a"])["limits"][0]["reserved"] == 70
    ledger.cancel(ticket)


def test_missing_or_replaced_persistent_history_never_silently_resets_quota(tmp_path):
    path = tmp_path / "budget.sqlite"
    with pytest.raises(ValueError, match="initialization"):
        SQLiteBudgetStore(path)
    store = SQLiteBudgetStore(path, create=True)
    ledger, _, actors, _, _, _ = configured(store=store)
    reserve(ledger, actors["a"])
    with pytest.raises(ValueError):
        SQLiteBudgetStore(path, create=True)
    path.unlink()
    with pytest.raises(ValueError):
        reserve(ledger, actors["b"], key="missing")
    assert not path.exists()
    with pytest.raises(ValueError):
        SQLiteBudgetStore(path)
    path.touch()
    with pytest.raises(ValueError):
        SQLiteBudgetStore(path)
    with pytest.raises(ValueError):
        reserve(ledger, actors["b"], key="replacement")


def test_policy_epoch_recovery_preserves_consumed_spend():
    ledger, registry, actors, now, operator, _ = configured()
    ticket = reserve(ledger, actors["a"])
    begin(ledger, ticket, actors["a"])
    ledger.commit(ticket)
    registry.advance_policy_epoch(1)
    renewed = {}
    for name in ("parent", "a"):
        context, channel, adapter = actors[name]
        next_adapter = object()
        next_channel = registry.bind_channel(next_adapter, runtime_id="fixture")
        next_context = registry.restart(
            context,
            channel,
            adapter,
            new_channel=next_channel,
            new_adapter=next_adapter,
            session_id="epoch1-" + name,
        )
        renewed[name] = (next_context, next_channel, next_adapter)
    restored = BudgetLedger(
        registry,
        replace(ledger.policy, policy_epoch=1),
        store=ledger._store,
        clock=lambda: now[0],
        operator=operator,
    )
    assert report(restored, renewed["a"])["limits"][0]["consumed"] == 70
    with pytest.raises(BudgetError, match="stale_policy"):
        reserve(ledger, renewed["a"], key="stale-policy", amount=1)
    with pytest.raises(BudgetError, match="limit_exceeded"):
        reserve(restored, renewed["a"], key="no-reset", amount=40)


def gateway_fixture(*, metric="requests", maximum=1, cost_provider=None):
    from ordin.swarm import SwarmGate, SwarmToolGateway

    ledger, registry, actors, now, _, _ = configured(
        limits=(BudgetLimit("swarm", metric, maximum),)
    )
    gate = SwarmGate(registry)
    gateway = SwarmToolGateway(
        clock=lambda: now[0], budget_ledger=ledger, budget_cost_provider=cost_provider
    )
    handles = {}
    for name in ("a", "b"):
        context, channel, adapter = actors[name]
        handles[name] = gateway.bind_agent(
            context, gate, channel, adapter, routes=frozenset({"sdk"})
        )
    return ledger, gateway, actors, handles, now


def test_gateway_reserves_only_executable_actions_and_requires_host_operation_key():
    ledger, gateway, actors, handles, _ = gateway_fixture()
    blocked = gateway.prepare(
        handles["a"], ActionEnvelope.shell("rm -rf /"), budget_idempotency_key="blocked"
    )
    assert blocked.disposition == "deny" and blocked.budget_reservation_id is None
    missing = gateway.prepare(handles["a"], action())
    assert (
        missing.disposition == "deny"
        and missing.budget_reason_code == "budget.missing_idempotency_key"
    )
    assert report(ledger, actors["a"])["limits"][0]["consumed"] == 0
    authorized = gateway.prepare(handles["a"], action(), budget_idempotency_key="host-operation")
    assert authorized.ticket is not None and authorized.budget_reservation_id is not None
    assert report(ledger, actors["a"])["limits"][0]["reserved"] == 1
    denied = gateway.prepare(handles["b"], action("b"), budget_idempotency_key="second-operation")
    assert denied.disposition == "deny" and denied.budget_reason_code == "budget.limit_exceeded"
    calls = []
    gateway.forward(
        handles["a"], authorized.ticket, lambda selected: calls.append(selected) or "ok"
    )
    assert len(calls) == 1
    assert report(ledger, actors["a"])["limits"][0]["consumed"] == 1


def test_gateway_safe_cancel_and_expired_ticket_release_without_executor():
    ledger, gateway, actors, handles, now = gateway_fixture()
    authorization = gateway.prepare(handles["a"], action(), budget_idempotency_key="cancel")
    gateway.cancel(handles["a"], authorization.ticket)
    assert report(ledger, actors["a"])["limits"][0]["remaining"] == 1
    expired = gateway.prepare(handles["a"], action(), budget_idempotency_key="expire")
    now[0] += 31
    calls = []
    with pytest.raises(ValueError):
        gateway.forward(handles["a"], expired.ticket, lambda selected: calls.append(selected))
    assert not calls and report(ledger, actors["a"])["limits"][0]["remaining"] == 1


def test_gateway_revocation_fences_pending_ticket_even_when_budget_cleanup_fails(monkeypatch):
    ledger, gateway, _, handles, _ = gateway_fixture()
    authorization = gateway.prepare(handles["a"], action(), budget_idempotency_key="revoked")

    def unavailable(ticket):
        raise OSError("private budget path")

    monkeypatch.setattr(ledger, "cancel", unavailable)
    gateway.revoke_agent(handles["a"])
    calls = []
    with pytest.raises(ValueError):
        gateway.forward(handles["a"], authorization.ticket, lambda selected: calls.append(selected))
    assert not calls


@pytest.mark.parametrize("kind", ["exception", "pending", "failed"])
def test_gateway_ambiguous_outcomes_retain_holds_and_retry_cannot_reissue(kind):
    from ordin.swarm import GatewayOutcome

    ledger, gateway, actors, handles, _ = gateway_fixture()
    authorization = gateway.prepare(
        handles["a"], action(), budget_idempotency_key="logical-operation"
    )
    calls = []

    def execute(selected):
        calls.append(selected)
        if kind == "exception":
            raise TimeoutError("private external credential")
        return GatewayOutcome("unknown", kind)

    if kind == "exception":
        with pytest.raises(TimeoutError):
            gateway.forward(handles["a"], authorization.ticket, execute)
    else:
        gateway.forward(handles["a"], authorization.ticket, execute)
    assert len(calls) == 1
    state = report(ledger, actors["a"])["limits"][0]
    assert state["reserved"] == 1 and state["consumed"] == 0
    retry = gateway.prepare(handles["a"], action(), budget_idempotency_key="logical-operation")
    assert retry.ticket is None and retry.disposition == "deny"
    with pytest.raises(ValueError):
        gateway.forward(handles["a"], authorization.ticket, execute)
    assert len(calls) == 1


def test_gateway_unknown_cost_stays_restricted_and_model_cost_fields_are_ignored():
    ledger, gateway, actors, handles, _ = gateway_fixture(metric="dollar_micros", maximum=100)
    denied = gateway.prepare(handles["a"], action(), budget_idempotency_key="unknown")
    assert denied.disposition == "deny" and denied.budget_reason_code == "budget.unknown_cost"
    ledger, gateway, actors, handles, _ = gateway_fixture(maximum=1)
    proposed = ActionEnvelope(
        "shell", "execute", {"command": "git status", "actual_cost": 0, "budget": {"requests": 0}}
    )
    authorized = gateway.prepare(handles["a"], proposed, budget_idempotency_key="known")
    assert authorized.ticket is not None
    gateway.forward(handles["a"], authorized.ticket, lambda selected: "ok")
    assert report(ledger, actors["a"])["limits"][0]["consumed"] == 1
    ledger, gateway, actors, handles, _ = gateway_fixture(
        maximum=1, cost_provider=lambda *args: (BudgetCost("requests", 0),)
    )
    authorization = gateway.prepare(handles["a"], action(), budget_idempotency_key="zero-cost")
    gateway.forward(handles["a"], authorization.ticket, lambda selected: "ok")
    assert report(ledger, actors["a"])["limits"][0]["consumed"] == 1


def test_late_authenticated_settlement_refines_conservative_consumption_once():
    ledger, _, actors, _, operator, observations = configured()
    ticket = reserve(ledger, actors["a"])
    begin(ledger, ticket, actors["a"])
    ledger.commit(ticket)
    assert report(ledger, actors["a"])["limits"][0]["consumed"] == 70
    receipt = observations.record(
        ticket.reservation_id,
        action(),
        actors["a"][0],
        outcome="completed",
        costs=(BudgetCost("requests", 40),),
    )
    assert (
        ledger.reconcile(ticket.reservation_id, operator=operator, observation=receipt)
        == "committed"
    )
    assert (
        ledger.reconcile(ticket.reservation_id, operator=operator, observation=receipt)
        == "committed"
    )
    assert ledger.commit(ticket) == "committed"
    state = report(ledger, actors["a"])["limits"][0]
    assert state["consumed"] == 40 and state["observed"] == 40 and state["reserved"] == 0
    conflicting = observations.record(
        ticket.reservation_id,
        action(),
        actors["a"][0],
        outcome="completed",
        costs=(BudgetCost("requests", 20),),
    )
    with pytest.raises(BudgetError, match="conflicting"):
        ledger.reconcile(ticket.reservation_id, operator=operator, observation=conflicting)


def test_physical_budget_requirement_cannot_be_satisfied_by_cost_estimate_or_json_flag():
    _, registry, actors, now, operator, _ = configured()
    policy = BudgetPolicy(
        0, (BudgetLimit("swarm", "requests", 100),), require_physical_enforcement=True
    )
    ledger = BudgetLedger(registry, policy, clock=lambda: now[0], operator=operator)
    with pytest.raises(BudgetError, match="physical_enforcement_unavailable"):
        reserve(ledger, actors["a"], amount=1)
    output = report(ledger, actors["a"])
    assert output["enforcement"] == "unsupported" and output["physical_enforcement"] is False


def test_budget_reports_are_versioned_schema_valid_and_audit_is_scoped_to_operator():
    from ordin.schema import validate_named_schema

    ledger, _, actors, _, operator, _ = configured()
    ticket = reserve(ledger, actors["a"])
    for name, value in (
        ("swarm_budget", report(ledger, actors["a"])),
        ("swarm_budget_reservation", ledger.reservation_status(ticket)),
        ("swarm_budget_audit", ledger.audit(operator=operator)),
    ):
        assert validate_named_schema(name, value) == []
        assert value["execution_authority"] is False
        assert "tenant" not in str(value.get("context_digest", ""))
    with pytest.raises(BudgetError):
        ledger.audit(operator=object())
    assert (
        ledger.audit(operator=operator, limit=1)["reservations"][0]["reservation_id"]
        == ticket.reservation_id
    )
