"""In-memory accounting keeps one original connection until its last owner leaves."""

from concurrent.futures import ThreadPoolExecutor
import gc
import sqlite3
from threading import Event
import weakref

import pytest

from ordin.swarm.budget_store import InMemoryBudgetStore
from tests.test_swarm_budgets import configured, report


def tracked_connections(monkeypatch, *, fail_first_close=False):
    original = sqlite3.connect
    connections = []

    class Connection(sqlite3.Connection):
        close_calls = 0

        def close(self):
            self.close_calls += 1
            if fail_first_close and self.close_calls == 1:
                raise sqlite3.OperationalError("owned transient close failure")
            super().close()

    def connect(*args, **kwargs):
        connection = original(*args, factory=Connection, **kwargs)
        connections.append(connection)
        return connection

    monkeypatch.setattr(sqlite3, "connect", connect)
    return connections


def assert_closed(connection):
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        connection.execute("SELECT 1")


def test_close_is_idempotent_and_never_recreates_accounting(monkeypatch):
    connections = tracked_connections(monkeypatch)
    store = InMemoryBudgetStore()
    store.close()
    store.close()
    with pytest.raises(ValueError, match="closed"):
        with store.transaction():
            pytest.fail("closed store admitted a transaction")
    del store
    gc.collect()
    assert len(connections) == 1 and connections[0].close_calls == 1
    assert_closed(connections[0])


def test_final_owner_collection_closes_the_original_connection_once(monkeypatch):
    connections = tracked_connections(monkeypatch)
    store = InMemoryBudgetStore()
    reference = weakref.ref(store)
    del store
    gc.collect()
    assert reference() is None
    assert connections[0].close_calls == 1
    assert_closed(connections[0])


def test_registry_view_retains_original_store_until_all_views_leave(monkeypatch):
    connections = tracked_connections(monkeypatch)
    ledger, registry, actors, _, _, _ = configured()
    reference = weakref.ref(ledger._store)
    view = ledger.for_registry(registry)
    del ledger
    gc.collect()
    assert reference() is not None
    assert report(view, actors["a"])["limits"][0]["remaining"] == 100
    assert connections[0].close_calls == 0
    del view
    gc.collect()
    assert reference() is None and connections[0].close_calls == 1
    assert_closed(connections[0])


def test_active_transaction_keeps_its_store_alive(monkeypatch):
    connections = tracked_connections(monkeypatch)
    store = InMemoryBudgetStore()
    reference = weakref.ref(store)
    transaction = store.transaction()
    with transaction as connection:
        del store
        gc.collect()
        assert reference() is not None
        assert connection.execute("SELECT 1").fetchone()[0] == 1
        assert connections[0].close_calls == 0
    del transaction
    gc.collect()
    assert reference() is None and connections[0].close_calls == 1
    assert_closed(connection)


def test_close_cannot_interrupt_current_transaction(monkeypatch):
    connections = tracked_connections(monkeypatch)
    store = InMemoryBudgetStore()
    try:
        with store.transaction() as connection:
            with pytest.raises(ValueError, match="transaction"):
                store.close()
            assert connection.execute("SELECT 1").fetchone()[0] == 1
        assert connections[0].close_calls == 0
    finally:
        store.close()
    assert connections[0].close_calls == 1


def test_close_waits_for_other_thread_transaction(monkeypatch):
    connections = tracked_connections(monkeypatch)
    store = InMemoryBudgetStore()
    started, release = Event(), Event()

    def transact():
        with store.transaction() as connection:
            started.set()
            assert release.wait(timeout=5)
            assert connection.execute("SELECT 1").fetchone()[0] == 1

    with ThreadPoolExecutor(max_workers=2) as executor:
        transaction = executor.submit(transact)
        assert started.wait(timeout=5)
        closing = executor.submit(store.close)
        try:
            assert not closing.done()
        finally:
            release.set()
        transaction.result(timeout=5)
        closing.result(timeout=5)
    assert connections[0].close_calls == 1
    assert_closed(connections[0])


def test_failed_explicit_close_retains_retry_and_finalizer_custody(monkeypatch):
    connections = tracked_connections(monkeypatch, fail_first_close=True)
    store = InMemoryBudgetStore()
    with pytest.raises(sqlite3.OperationalError, match="transient close"):
        store.close()
    with store.transaction() as connection:
        assert connection.execute("SELECT 1").fetchone()[0] == 1
    store.close()
    del store
    gc.collect()
    assert connections[0].close_calls == 2
    assert_closed(connections[0])


def test_last_owner_can_be_collected_on_a_different_thread(monkeypatch):
    connections = tracked_connections(monkeypatch)
    owners = [InMemoryBudgetStore()]
    reference = weakref.ref(owners[0])

    def collect_owner():
        owners.clear()
        gc.collect()

    with ThreadPoolExecutor(max_workers=1) as executor:
        executor.submit(collect_owner).result(timeout=5)
    assert reference() is None and connections[0].close_calls == 1
    assert_closed(connections[0])
