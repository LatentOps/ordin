"""Actual durable initialization and attach, without starting an owned worker."""

import json
import os
from types import SimpleNamespace

from ordin import ActionEnvelope
from ordin.swarm import CoverageManifest, InMemoryAgentRegistry
from ordin.swarm.budget_store import SQLiteBudgetStore
from ordin.swarm.budgets import BudgetCost, BudgetLedger
from ordin.swarm.coordinator_store import CoordinatorClock, SQLiteCoordinatorStore
from ordin_swarm import host_authority
from ordin_swarm.host_pki import _new_file
from ordin_swarm.host_profiles import load_host_profile
from test_tool_host_profiles import document


def test_new_host_budget_is_initialized_then_attached_without_resetting_spend_or_uncertainty(
    tmp_path, monkeypatch
):
    root = tmp_path / "installation"
    root.mkdir(mode=0o700)
    (root / "state").mkdir(mode=0o700)
    _new_file(root / "profile.json", json.dumps(document(root)).encode())
    profile = load_host_profile(root)
    monkeypatch.setattr(
        host_authority, "make_backend", lambda *args, **kwargs: SimpleNamespace(close=lambda: None)
    )
    operator = object()
    host_authority.initialize_host_authority_files(profile, operator=operator)
    store = SQLiteBudgetStore(root / "state" / "budget.sqlite", create=False)
    clock = CoordinatorClock(
        SQLiteCoordinatorStore(root / "state" / "coordinator.sqlite", create=False)
    )
    registry = InMemoryAgentRegistry(profile.tenant_id, profile.swarm_id, clock=clock)
    ledger = BudgetLedger(
        registry,
        host_authority._budget_policy(profile, 0),
        store=store,
        clock=clock,
        operator=operator,
    )
    adapter = object()
    channel = registry.bind_channel(adapter, runtime_id="host-reader")
    context = registry.enroll(
        channel,
        adapter,
        agent_id="reader",
        session_id="first",
        task_id=profile.task_id,
        coverage=CoverageManifest("intercept"),
    )
    tickets = []
    for index in range(2):
        action = ActionEnvelope.shell("git status --short", action_id="initial-" + str(index))
        ticket = ledger.reserve(
            context,
            action,
            channel=channel,
            adapter=adapter,
            idempotency_key="initial-" + str(index),
            costs=(
                BudgetCost("requests", 1),
                BudgetCost("concurrency", 1),
                BudgetCost("output_bytes", 8),
            ),
        )
        ledger.begin_forward(ticket, context, action, channel=channel, adapter=adapter)
        tickets.append(ticket)
    ledger.commit(tickets[0])
    ledger.uncertain(tickets[1])
    with store.transaction() as connection:
        before = [
            tuple(row)
            for row in connection.execute(
                "SELECT bucket,metric,held,consumed FROM budget_buckets ORDER BY bucket"
            )
        ]
    registry.advance_policy_epoch(1)
    BudgetLedger(
        registry,
        host_authority._budget_policy(profile, 1),
        store=SQLiteBudgetStore(store.path, create=False),
        clock=clock,
        operator=operator,
    )
    with store.transaction() as connection:
        after = [
            tuple(row)
            for row in connection.execute(
                "SELECT bucket,metric,held,consumed FROM budget_buckets ORDER BY bucket"
            )
        ]
        statuses = [
            row[0]
            for row in connection.execute("SELECT status FROM budget_reservations ORDER BY status")
        ]
    assert before == after and statuses == ["committed", "uncertain"]
    assert any(row[2] > 0 for row in after) and any(row[3] > 0 for row in after)
    if os.name == "posix":
        assert store.path.stat().st_mode & 0o077 == 0
