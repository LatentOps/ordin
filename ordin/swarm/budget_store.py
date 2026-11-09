"""Bounded local atomic budget transactions; not an eventually consistent cache."""

from contextlib import contextmanager
from pathlib import Path
import os
import re
import sqlite3
from threading import RLock
from typing import Iterator, Protocol
from weakref import finalize

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


_DEFINITIONS = {
    ("table", "budget_meta"): _TABLES[0],
    ("table", "budget_buckets"): _TABLES[1],
    ("table", "budget_reservations"): _TABLES[2],
    ("table", "budget_items"): _TABLES[3],
    ("index", "budget_expiry"): _TABLES[4],
}


def _normalized_sql(value: str) -> str:
    return " ".join(
        re.sub(r"\bIF\s+NOT\s+EXISTS\b", "", value, flags=re.IGNORECASE).casefold().split()
    )


def _validate_schema(connection: sqlite3.Connection) -> None:
    connection.row_factory = sqlite3.Row
    if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
        raise ValueError("budget store requires foreign-key integrity")
    if connection.execute("PRAGMA synchronous").fetchone()[0] < 2:
        raise ValueError("budget store requires durable commit synchronization")
    rows = connection.execute(
        "SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
    ).fetchall()
    definitions = {(row["type"], row["name"]): row["sql"] for row in rows}
    if definitions.keys() != _DEFINITIONS.keys() or any(
        type(definitions[key]) is not str
        or _normalized_sql(definitions[key]) != _normalized_sql(expected)
        for key, expected in _DEFINITIONS.items()
    ):
        raise ValueError("budget schema unavailable or changed; history cannot be recreated")


def _initialize_schema(connection: sqlite3.Connection) -> None:
    if connection.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchone() is not None:
        raise ValueError("budget schema initialization requires an empty new database")
    for statement in _TABLES:
        connection.execute(statement)
    _validate_schema(connection)


def _validate_history(connection: sqlite3.Connection, allow_initialize: bool) -> None:
    _validate_schema(connection)
    count = connection.execute("SELECT count(*) FROM budget_meta").fetchone()[0]
    if count == 1:
        return
    if (
        count != 0
        or not allow_initialize
        or any(
            connection.execute("SELECT 1 FROM " + table + " LIMIT 1").fetchone() is not None
            for table in ("budget_buckets", "budget_reservations", "budget_items")
        )
    ):
        raise ValueError("budget coordinator history unavailable; reinitialization denied")


def _rollback_initialization(connection: sqlite3.Connection, previously_allowed: bool) -> bool:
    """Restore bootstrap permission only after a confirmed pristine rollback."""
    try:
        connection.rollback()
        if not previously_allowed:
            return False
        _validate_history(connection, True)
        return connection.execute("SELECT 1 FROM budget_meta LIMIT 1").fetchone() is None
    except BaseException:
        # Cleanup must preserve the original failure. An unknown rollback or
        # history state cannot grant permission to initialize a new domain.
        return False


class BudgetStore(Protocol):
    def transaction(self): ...


class InMemoryBudgetStore:
    """Stable in-process test backend with the same SQL transaction semantics."""

    def __init__(self) -> None:
        self._connection = sqlite3.connect(
            ":memory:", isolation_level=None, check_same_thread=False
        )
        try:
            self._connection.execute("PRAGMA trusted_schema=OFF")
            self._connection.execute("PRAGMA foreign_keys=ON")
            self._connection.execute("PRAGMA max_page_count=16384")
            self._lock = RLock()
            self._allow_initialize = True
            self._connection.execute("BEGIN IMMEDIATE")
            _initialize_schema(self._connection)
            self._connection.commit()
            self._closed = False
            # The callback retains only the original connection, not its store.
            # Shared ledger views keep the store alive until its last owner leaves.
            self._finalizer = finalize(self, self._connection.close)
        except BaseException:
            try:
                # Closing an unreturned connection also rolls back partial setup.
                self._connection.close()
            except BaseException:
                # Preserve the original startup failure if cleanup also fails.
                pass
            raise

    def close(self) -> None:
        """Close the original store after active transactions, without resetting it."""
        with self._lock:
            if self._closed:
                return
            if self._connection.in_transaction:
                raise ValueError("cannot close an active budget transaction")
            # Preserve finalizer custody if an explicit close fails and needs retry.
            self._connection.close()
            self._closed = True
            self._finalizer.detach()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            if self._closed:
                raise ValueError("budget store is closed")
            if self._connection.in_transaction:
                raise ValueError("nested budget transaction refused")
            previously_allowed = self._allow_initialize
            rejected = None
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                _validate_history(self._connection, previously_allowed)
                try:
                    yield self._connection
                except BudgetRejected as error:
                    rejected = error
                initialized = (
                    self._connection.execute("SELECT 1 FROM budget_meta LIMIT 1").fetchone()
                    is not None
                )
                self._allow_initialize = False
                self._connection.commit()
                self._allow_initialize = previously_allowed and not initialized
            except sqlite3.Error:
                self._allow_initialize = _rollback_initialization(
                    self._connection, previously_allowed
                )
                raise ValueError("budget transaction unavailable or corrupt") from None
            except BaseException:
                # Cancellation and process-level interruptions must not leave
                # the reusable connection holding an uncommitted transaction.
                self._allow_initialize = _rollback_initialization(
                    self._connection, previously_allowed
                )
                raise
            if rejected is not None:
                raise rejected


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
        self._allow_initialize = create
        self._lock = RLock()
        try:
            if create:
                descriptor = os.open(
                    self.path,
                    os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                )
                os.close(descriptor)
                with private_database(
                    self.path, "swarm_budget", create=False, foreign_keys=True
                ) as connection:
                    _initialize_schema(connection)
            else:
                # Opening an absent/uninitialized file after restart must never
                # silently create a new zero-spend accounting domain.
                with private_database(
                    self.path, "swarm_budget", readonly=True, create=False, foreign_keys=True
                ) as connection:
                    _validate_history(connection, False)
            info = self.path.stat()
            self._identity = (info.st_dev, info.st_ino)
        except (OSError, sqlite3.Error, ValueError):
            raise ValueError(
                "budget store requires explicit initialization or valid existing history"
            ) from None

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        # Initialization permission is local state and must remain serialized
        # through commit/rollback even after the database releases its lock.
        with self._lock:
            yield from self._transaction()

    def _transaction(self) -> Iterator[sqlite3.Connection]:
        previously_allowed = self._allow_initialize
        rejected = None
        try:
            info = self.path.stat()
            if (info.st_dev, info.st_ino) != self._identity:
                raise ValueError("budget file was replaced")
            with private_database(
                self.path, "swarm_budget", create=False, foreign_keys=True
            ) as connection:
                _validate_history(connection, previously_allowed)
                try:
                    try:
                        yield connection
                    except BudgetRejected as error:
                        rejected = error
                    initialized = (
                        connection.execute("SELECT 1 FROM budget_meta LIMIT 1").fetchone()
                        is not None
                    )
                    self._allow_initialize = False
                    connection.commit()
                    self._allow_initialize = previously_allowed and not initialized
                except BaseException:
                    self._allow_initialize = _rollback_initialization(
                        connection, previously_allowed
                    )
                    raise
                if rejected is not None:
                    raise rejected
        except BudgetRejected:
            raise
        except (OSError, sqlite3.Error, ValueError):
            raise ValueError("budget transaction unavailable or corrupt") from None
