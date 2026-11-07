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


def commit_fault_connections(monkeypatch):
    class FaultConnection(sqlite3.Connection):
        commit_failure = None
        fail_after_commit = False
        rollback_failure = None
        fail_after_rollback = False

        def commit(self):
            failure = self.commit_failure
            self.commit_failure = None
            if failure is not None:
                if self.fail_after_commit:
                    super().commit()
                raise failure
            return super().commit()

        def rollback(self):
            failure = self.rollback_failure
            self.rollback_failure = None
            if failure is not None:
                if self.fail_after_rollback:
                    super().rollback()
                raise failure
            return super().rollback()

    original_connect = sqlite3.connect

    def connect(*args, **kwargs):
        return original_connect(*args, **kwargs, factory=FaultConnection)

    monkeypatch.setattr(sqlite3, "connect", connect)


@pytest.mark.parametrize("persistent", [False, True], ids=["memory", "sqlite"])
@pytest.mark.parametrize("initialized", [False, True], ids=["initializing", "initialized"])
@pytest.mark.parametrize("business_denial", [False, True], ids=["normal", "business-denial"])
@pytest.mark.parametrize("committed", [False, True], ids=["before-commit", "lost-ack"])
@pytest.mark.parametrize(
    "exception_type",
    [KeyboardInterrupt, SystemExit, asyncio.CancelledError],
    ids=lambda value: value.__name__,
)
def test_interrupted_commit_preserves_history_and_bootstrap_permission(
    tmp_path, monkeypatch, persistent, initialized, business_denial, committed, exception_type
):
    commit_fault_connections(monkeypatch)
    store = (
        SQLiteBudgetStore(tmp_path / "budget.db", create=True)
        if persistent
        else InMemoryBudgetStore()
    )
    if initialized:
        with store.transaction() as connection:
            initialize(connection)
    failure = exception_type("interrupted commit")
    with pytest.raises(exception_type) as caught:
        with store.transaction() as connection:
            if not initialized:
                initialize(connection)
            connection.execute("UPDATE budget_meta SET last_now=200")
            connection.commit_failure = failure
            connection.fail_after_commit = committed
            if business_denial:
                raise BudgetRejected("deliberate business denial")
    assert caught.value is failure
    assert store._allow_initialize is (not initialized and not committed)
    with store.transaction() as connection:
        row = connection.execute("SELECT last_now FROM budget_meta").fetchone()
        expected = 200 if committed else 100 if initialized else None
        assert (None if row is None else row[0]) == expected
        if row is None:
            initialize(connection)
        connection.execute("UPDATE budget_meta SET last_now=300")
    with store.transaction() as connection:
        assert connection.execute("SELECT last_now FROM budget_meta").fetchone()[0] == 300


@pytest.mark.parametrize("persistent", [False, True], ids=["memory", "sqlite"])
@pytest.mark.parametrize("rolled_back", [False, True], ids=["rollback-failed", "rollback-lost-ack"])
def test_unknown_rollback_never_restores_bootstrap_or_replaces_original_failure(
    tmp_path, monkeypatch, persistent, rolled_back
):
    commit_fault_connections(monkeypatch)
    store = (
        SQLiteBudgetStore(tmp_path / "budget.db", create=True)
        if persistent
        else InMemoryBudgetStore()
    )
    failure = KeyboardInterrupt("interrupted commit")
    with pytest.raises(KeyboardInterrupt) as caught:
        with store.transaction() as connection:
            initialize(connection)
            connection.commit_failure = failure
            connection.rollback_failure = RuntimeError("rollback unavailable")
            connection.fail_after_rollback = rolled_back
    assert caught.value is failure
    assert not store._allow_initialize
    with pytest.raises(ValueError):
        with store.transaction():
            pytest.fail("an unknown rollback must not allow fresh initialization")


@pytest.mark.parametrize("persistent", [False, True], ids=["memory", "sqlite"])
@pytest.mark.parametrize("business_denial", [False, True], ids=["normal", "business-denial"])
def test_pristine_transaction_does_not_consume_initialization_permission(
    tmp_path, persistent, business_denial
):
    store = (
        SQLiteBudgetStore(tmp_path / "budget.db", create=True)
        if persistent
        else InMemoryBudgetStore()
    )
    if business_denial:
        with pytest.raises(BudgetRejected):
            with store.transaction():
                raise BudgetRejected("no initialization attempted")
    else:
        with store.transaction():
            pass
    with store.transaction() as connection:
        initialize(connection)
    with store.transaction() as connection:
        assert connection.execute("SELECT last_now FROM budget_meta").fetchone()[0] == 100


@pytest.mark.parametrize("phase", ["before-begin", "after-begin", "before-commit", "after-commit"])
@pytest.mark.parametrize(
    "exception_type",
    [RuntimeError, KeyboardInterrupt, SystemExit, asyncio.CancelledError],
    ids=lambda value: value.__name__,
)
@pytest.mark.parametrize("cleanup_failure", [False, True], ids=["closed", "close-lost-ack"])
def test_failed_memory_constructor_closes_connection_without_replacing_failure(
    monkeypatch, phase, exception_type, cleanup_failure
):
    original_connect = sqlite3.connect
    failure = exception_type("constructor interrupted")
    retained = []

    class FaultConnection(sqlite3.Connection):
        armed = True

        def execute(self, sql, parameters=()):
            if self.armed and sql == "BEGIN IMMEDIATE" and phase == "before-begin":
                self.armed = False
                raise failure
            result = super().execute(sql, parameters)
            if self.armed and sql == "BEGIN IMMEDIATE" and phase == "after-begin":
                self.armed = False
                raise failure
            return result

        def commit(self):
            if self.armed and phase == "before-commit":
                self.armed = False
                raise failure
            result = super().commit()
            if self.armed and phase == "after-commit":
                self.armed = False
                raise failure
            return result

        def close(self):
            result = super().close()
            if cleanup_failure:
                raise RuntimeError("connection close acknowledgement unavailable")
            return result

    def connect(*args, **kwargs):
        connection = original_connect(*args, **kwargs, factory=FaultConnection)
        retained.append(connection)
        return connection

    monkeypatch.setattr(sqlite3, "connect", connect)
    with pytest.raises(exception_type) as caught:
        InMemoryBudgetStore()
    assert caught.value is failure
    assert len(retained) == 1
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        retained[0].execute("SELECT 1")
