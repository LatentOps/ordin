"""Bounded local atomic budget transactions; not an eventually consistent cache."""

from contextlib import contextmanager
from pathlib import Path
import os
import sqlite3
from threading import RLock
from typing import Iterator, Protocol

from ordin._private_storage import private_database


class BudgetRejected(ValueError):
    """Business denial before admission changes; preserve safe housekeeping."""


_TABLES = (
    "CREATE TABLE IF NOT EXISTS budget_meta (singleton INTEGER PRIMARY KEY CHECK(singleton=1), policy_digest TEXT NOT NULL, epoch INTEGER NOT NULL, generation INTEGER NOT NULL, nonce TEXT NOT NULL, last_now REAL NOT NULL)",
    "CREATE TABLE IF NOT EXISTS budget_buckets (bucket TEXT PRIMARY KEY, metric TEXT NOT NULL, held INTEGER NOT NULL CHECK(held>=0), consumed INTEGER NOT NULL CHECK(consumed>=0), observed INTEGER NOT NULL CHECK(observed>=0), observations INTEGER NOT NULL CHECK(observations>=0), blocked_epoch INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS budget_reservations (reservation_id TEXT PRIMARY KEY, idempotency_digest TEXT NOT NULL UNIQUE, context_digest TEXT NOT NULL, action_digest TEXT NOT NULL, costs_digest TEXT NOT NULL, epoch INTEGER NOT NULL, generation INTEGER NOT NULL, status TEXT NOT NULL, expires_at REAL NOT NULL, settlement_digest TEXT)",
    "CREATE TABLE IF NOT EXISTS budget_items (reservation_id TEXT NOT NULL REFERENCES budget_reservations(reservation_id), bucket TEXT NOT NULL REFERENCES budget_buckets(bucket), metric TEXT NOT NULL, amount INTEGER NOT NULL CHECK(amount>=0), PRIMARY KEY(reservation_id,bucket))",
    "CREATE INDEX IF NOT EXISTS budget_expiry ON budget_reservations(status,expires_at)",
)


def _schema(connection: sqlite3.Connection) -> None:
    connection.row_factory = sqlite3.Row
    if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
        raise ValueError("budget store requires foreign-key integrity")
    if connection.execute("PRAGMA synchronous").fetchone()[0] < 2:
        raise ValueError("budget store requires durable commit synchronization")
    for statement in _TABLES:
        connection.execute(statement)


class BudgetStore(Protocol):
    def transaction(self): ...


class InMemoryBudgetStore:
    """Stable in-process test backend with the same SQL transaction semantics."""

    def __init__(self) -> None:
        self._connection = sqlite3.connect(
            ":memory:", isolation_level=None, check_same_thread=False
        )
        self._connection.execute("PRAGMA trusted_schema=OFF")
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._connection.execute("PRAGMA max_page_count=16384")
        self._lock = RLock()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                _schema(self._connection)
                yield self._connection
                self._connection.commit()
            except BudgetRejected:
                self._connection.commit()
                raise
            except sqlite3.Error:
                self._connection.rollback()
                raise ValueError("budget transaction unavailable or corrupt") from None
            except Exception:
                self._connection.rollback()
                raise


class SQLiteBudgetStore:
    """Explicit private SQLite file; BEGIN IMMEDIATE protects all ledger updates.

    One active protected coordinator may have multiple registry views. Starting a
    new coordinator fences older tickets and recovers outstanding uncertainty.
    This adapter does not claim a multi-host consensus or network partition lease.
    """

    def __init__(self, path: str | Path, *, create: bool = False) -> None:
        self.path = Path(path).absolute()
        if type(create) is not bool:
            raise ValueError("budget initialization must be explicit host configuration")
        try:
            if create:
                descriptor = os.open(
                    self.path,
                    os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                )
                os.close(descriptor)
            else:
                # Opening an absent/uninitialized file after restart must never
                # silently create a new zero-spend accounting domain.
                with private_database(
                    self.path, "swarm_budget", readonly=True, create=False, foreign_keys=True
                ) as connection:
                    if (
                        connection.execute(
                            "SELECT count(*) FROM budget_meta WHERE singleton=1"
                        ).fetchone()[0]
                        != 1
                    ):
                        raise ValueError("budget store has no initialized coordinator")
            info = self.path.stat()
            self._identity = (info.st_dev, info.st_ino)
        except (OSError, sqlite3.Error, ValueError):
            raise ValueError(
                "budget store requires explicit initialization or valid existing history"
            ) from None

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        try:
            info = self.path.stat()
            if (info.st_dev, info.st_ino) != self._identity:
                raise ValueError("budget file was replaced")
            with private_database(
                self.path, "swarm_budget", create=False, foreign_keys=True
            ) as connection:
                _schema(connection)
                try:
                    yield connection
                except BudgetRejected:
                    connection.commit()
                    raise
        except BudgetRejected:
            raise
        except (OSError, sqlite3.Error, ValueError):
            raise ValueError("budget transaction unavailable or corrupt") from None
