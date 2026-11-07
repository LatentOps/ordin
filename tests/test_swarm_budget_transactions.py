"""Interrupted transactions unwind safely without changing business-denial commits."""

import asyncio
import sqlite3

import pytest

from ordin.swarm.budget_store import BudgetRejected, InMemoryBudgetStore, SQLiteBudgetStore


INTERRUPTIONS = (RuntimeError, KeyboardInterrupt, SystemExit, GeneratorExit, asyncio.CancelledError)


def initialize(connection):
    connection.execute("INSERT INTO budget_meta VALUES(1,?,0,1,?,100)", ("a" * 64, "b" * 32))


@pytest.mark.parametrize("persistent", [False, True], ids=["memory", "sqlite"])
@pytest.mark.parametrize("initialized", [False, True], ids=["initializing", "initialized"])
@pytest.mark.parametrize("exception_type", INTERRUPTIONS, ids=lambda value: value.__name__)
def test_interruption_rolls_back_and_allows_a_clean_retry(
    tmp_path, persistent, initialized, exception_type
):
    store = (
        SQLiteBudgetStore(tmp_path / "budget.db", create=True)
        if persistent
        else InMemoryBudgetStore()
    )
    if initialized:
        with store.transaction() as connection:
            initialize(connection)
    failure = exception_type("interrupted budget update")
    with pytest.raises(exception_type) as caught:
        with store.transaction() as connection:
            if not initialized:
                initialize(connection)
            connection.execute("UPDATE budget_meta SET last_now=200")
            connection.execute("INSERT INTO budget_buckets VALUES('bucket','requests',1,0,0,0,-1)")
            raise failure
    assert caught.value is failure

    with store.transaction() as connection:
        row = connection.execute("SELECT last_now FROM budget_meta").fetchone()
        assert (None if row is None else row[0]) == (100 if initialized else None)
        assert connection.execute("SELECT count(*) FROM budget_buckets").fetchone()[0] == 0
        if not initialized:
            initialize(connection)
        connection.execute("UPDATE budget_meta SET last_now=300")
    with store.transaction() as connection:
        assert connection.execute("SELECT last_now FROM budget_meta").fetchone()[0] == 300


def test_interruption_after_begin_does_not_poison_the_reusable_connection(monkeypatch):
    failure = KeyboardInterrupt("interrupted immediately after BEGIN")

    class InterruptingConnection(sqlite3.Connection):
        interrupt_next_begin = False

        def execute(self, sql, parameters=()):
            result = super().execute(sql, parameters)
            if self.interrupt_next_begin and sql == "BEGIN IMMEDIATE":
                self.interrupt_next_begin = False
                raise failure
            return result

    original_connect = sqlite3.connect

    def connect(*args, **kwargs):
        return original_connect(*args, **kwargs, factory=InterruptingConnection)

    monkeypatch.setattr(sqlite3, "connect", connect)
    store = InMemoryBudgetStore()
    with store.transaction() as connection:
        initialize(connection)
    store._connection.interrupt_next_begin = True
    with pytest.raises(KeyboardInterrupt) as caught:
        with store.transaction():
            pytest.fail("an interrupted BEGIN must not admit the transaction body")
    assert caught.value is failure
    with store.transaction() as connection:
        assert connection.execute("SELECT last_now FROM budget_meta").fetchone()[0] == 100


def test_nested_memory_transaction_refusal_preserves_the_outer_transaction():
    store = InMemoryBudgetStore()
    with store.transaction() as connection:
        initialize(connection)
        with pytest.raises(ValueError, match="nested"):
            with store.transaction():
                pytest.fail("nested transactions must not be admitted")
        connection.execute("UPDATE budget_meta SET last_now=200")
    with store.transaction() as connection:
        assert connection.execute("SELECT last_now FROM budget_meta").fetchone()[0] == 200


@pytest.mark.parametrize("persistent", [False, True], ids=["memory", "sqlite"])
def test_business_rejection_still_commits_safe_housekeeping(tmp_path, persistent):
    store = (
        SQLiteBudgetStore(tmp_path / "budget.db", create=True)
        if persistent
        else InMemoryBudgetStore()
    )
    with store.transaction() as connection:
        initialize(connection)
    failure = BudgetRejected("deliberate business denial")
    with pytest.raises(BudgetRejected) as caught:
        with store.transaction() as connection:
            connection.execute("UPDATE budget_meta SET last_now=200")
            raise failure
    assert caught.value is failure
    with store.transaction() as connection:
        assert connection.execute("SELECT last_now FROM budget_meta").fetchone()[0] == 200
