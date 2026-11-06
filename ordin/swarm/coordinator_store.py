"""Protected transactional coordinator persistence, not a replicated local cache.

PostgreSQL serializes authority transitions using a database row lock. SQLite is
explicitly limited to a single protected host/dev coordinator. Neither adapter
silently initializes absent history or treats JSON as a live grant/permit.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
import importlib
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import time
from typing import Any, Callable
from uuid import uuid4

from ordin._private_storage import private_database
from ordin._runtime_json import digest

from .events import _hex
from .models import identifier, timestamp

SCHEMA_VERSION = 1
MAX_SCOPE_BYTES = 8 * 1024 * 1024
MAX_ROOT_BYTES = 32768
MAX_SCOPES = 64
MAX_RESULT_BYTES = 65536

TABLES = (
    "CREATE TABLE coordinator_meta (singleton INTEGER PRIMARY KEY CHECK(singleton=1), version INTEGER NOT NULL, manifest TEXT NOT NULL, database_id TEXT NOT NULL, last_now DOUBLE PRECISION NOT NULL, scopes_json TEXT NOT NULL, checksum TEXT NOT NULL)",
    "CREATE TABLE coordinator_scopes (scope_key TEXT PRIMARY KEY, state_json TEXT NOT NULL, state_digest TEXT NOT NULL)",
    "CREATE TABLE coordinator_barriers (realm_key TEXT PRIMARY KEY, epoch BIGINT NOT NULL CHECK(epoch>0), state TEXT NOT NULL, intent_digest TEXT NOT NULL, checksum TEXT NOT NULL)",
    "CREATE TABLE coordinator_buckets (bucket TEXT PRIMARY KEY, tenant_digest TEXT NOT NULL, metric TEXT NOT NULL, maximum BIGINT NOT NULL CHECK(maximum>=0), held BIGINT NOT NULL CHECK(held>=0), consumed BIGINT NOT NULL CHECK(consumed>=0), observed BIGINT NOT NULL CHECK(observed>=0), blocked_epoch BIGINT NOT NULL, checksum TEXT NOT NULL)",
    "CREATE TABLE coordinator_items (scope_key TEXT NOT NULL REFERENCES coordinator_scopes(scope_key), reservation_id TEXT NOT NULL, bucket TEXT NOT NULL REFERENCES coordinator_buckets(bucket), metric TEXT NOT NULL, amount BIGINT NOT NULL CHECK(amount>=0), PRIMARY KEY(scope_key,reservation_id,bucket))",
    "CREATE TABLE coordinator_requests (scope_key TEXT NOT NULL REFERENCES coordinator_scopes(scope_key), operation TEXT NOT NULL, idempotency_key TEXT NOT NULL, request_digest TEXT NOT NULL, result_json TEXT NOT NULL, PRIMARY KEY(scope_key,operation,idempotency_key))",
    "CREATE TABLE coordinator_outbox (scope_key TEXT NOT NULL REFERENCES coordinator_scopes(scope_key), sequence BIGINT NOT NULL CHECK(sequence>0), event_id TEXT NOT NULL, record_json TEXT NOT NULL, record_digest TEXT NOT NULL, acknowledged INTEGER NOT NULL CHECK(acknowledged IN (0,1)), PRIMARY KEY(scope_key,sequence), UNIQUE(scope_key,event_id))",
    "CREATE TABLE coordinator_checkpoints (scope_key TEXT NOT NULL REFERENCES coordinator_scopes(scope_key), sequence BIGINT NOT NULL CHECK(sequence>=0), state_json TEXT NOT NULL, state_digest TEXT NOT NULL, PRIMARY KEY(scope_key,sequence))",
)
TABLE_NAMES = tuple(statement.split()[2] for statement in TABLES)
MANIFEST = digest({"version": SCHEMA_VERSION, "tables": TABLES})
_active_transaction: ContextVar[tuple[object, float, Any] | None] = ContextVar(
    "ordin_coordinator_transaction", default=None
)


class CoordinatorUnavailable(ValueError):
    """Unavailable/corrupt authority; never fall back to an allow decision."""


class CoordinatorRejected(ValueError):
    """Business denial; safe expiry/fencing housekeeping may still commit."""


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate stored key")
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError("non-finite stored value")


def _bounded_json(value, maximum):
    remaining = min(maximum, 262144)

    def visit(node, depth):
        nonlocal remaining
        remaining -= 1
        if remaining < 0 or depth > 32:
            raise ValueError("coordinator JSON depth or node limit")
        if type(node) is dict:
            for key, item in node.items():
                if type(key) is not str:
                    raise ValueError("coordinator JSON string key required")
                visit(item, depth + 1)
        elif type(node) is list:
            for item in node:
                visit(item, depth + 1)
        elif type(node) not in {str, int, float, bool, type(None)}:
            raise ValueError("coordinator data-only JSON required")
        elif type(node) is float and not math.isfinite(node):
            raise ValueError("coordinator finite JSON number required")

    visit(value, 0)


def encode(value: Any, maximum: int = MAX_SCOPE_BYTES) -> str:
    try:
        _bounded_json(value, maximum)
        text = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        )
        if len(text.encode("utf-8")) > maximum:
            raise ValueError("stored record limit")
        return text
    except (TypeError, ValueError, UnicodeError, RecursionError, OverflowError):
        raise CoordinatorUnavailable("coordinator record is invalid or exceeds its bound") from None


def decode(value: str, maximum: int = MAX_SCOPE_BYTES) -> dict[str, Any]:
    try:
        if type(value) is not str or len(value.encode("utf-8")) > maximum:
            raise ValueError("stored record limit")
        result = json.loads(value, object_pairs_hook=_unique, parse_constant=_reject_constant)
        _bounded_json(result, maximum)
        if type(result) is not dict:
            raise ValueError("stored object required")
        return result
    except (TypeError, ValueError, UnicodeError, RecursionError, OverflowError):
        raise CoordinatorUnavailable("coordinator history is unavailable or corrupt") from None


class _Row(Mapping):
    def __init__(self, keys, values):
        self._keys, self._values = tuple(keys), tuple(values)
        self._mapping = dict(zip(self._keys, self._values))

    def __getitem__(self, key):
        return self._values[key] if type(key) is int else self._mapping[key]

    def __iter__(self):
        return iter(self._keys)

    def __len__(self):
        return len(self._keys)


class _Cursor:
    def __init__(self, cursor):
        self._cursor = cursor
        self._keys = tuple(item[0] for item in cursor.description) if cursor.description else ()

    def fetchone(self):
        value = self._cursor.fetchone()
        return _Row(self._keys, value) if value is not None else None

    def fetchall(self):
        return [_Row(self._keys, value) for value in self._cursor.fetchall()]


class _Connection:
    def __init__(self, connection, *, postgres: bool):
        self.raw, self.postgres = connection, postgres

    def execute(self, sql: str, parameters=()):
        # Statements are internal fixed SQL; workload input is always parameterized.
        return _Cursor(
            self.raw.execute(sql.replace("?", "%s") if self.postgres else sql, parameters)
        )


def _root_checksum(
    database_id: str, last_now: float, scopes: list[str], barriers: list[str]
) -> str:
    return digest([SCHEMA_VERSION, MANIFEST, database_id, last_now, scopes, barriers])


def _read_root(connection: _Connection, *, lock: bool = False):
    rows = connection.execute(
        "SELECT * FROM coordinator_meta" + (" FOR UPDATE" if lock and connection.postgres else "")
    ).fetchall()
    if len(rows) != 1:
        raise CoordinatorUnavailable("coordinator root history missing; reinitialization denied")
    row = rows[0]
    try:
        if (
            type(row["scopes_json"]) is not str
            or len(row["scopes_json"].encode("utf-8")) > MAX_ROOT_BYTES
        ):
            raise ValueError("root bound")
        index = decode(row["scopes_json"], MAX_ROOT_BYTES)
        if set(index) != {"scopes", "barriers"}:
            raise ValueError("root index shape")
        scopes, barriers = index["scopes"], index["barriers"]
        if (
            row["singleton"] != 1
            or row["version"] != SCHEMA_VERSION
            or row["manifest"] != MANIFEST
            or type(scopes) is not list
            or len(scopes) > MAX_SCOPES
            or len(set(scopes)) != len(scopes)
            or scopes != sorted(scopes)
            or type(barriers) is not list
            or len(barriers) > MAX_SCOPES * 3
            or len(set(barriers)) != len(barriers)
            or barriers != sorted(barriers)
        ):
            raise ValueError("root shape")
        _hex(row["database_id"], "coordinator database identity")
        for scope in [*scopes, *barriers]:
            _hex(scope, "coordinator scope")
        last_now = timestamp(row["last_now"])
        if row["checksum"] != _root_checksum(row["database_id"], last_now, scopes, barriers):
            raise ValueError("root checksum")
        actual = sorted(
            value[0]
            for value in connection.execute("SELECT scope_key FROM coordinator_scopes").fetchall()
        )
        if actual != scopes:
            raise ValueError("scope history missing")
        actual_barriers = sorted(
            value[0]
            for value in connection.execute("SELECT realm_key FROM coordinator_barriers").fetchall()
        )
        if actual_barriers != barriers:
            raise ValueError("containment barrier history missing")
    except (TypeError, ValueError, KeyError, RecursionError):
        raise CoordinatorUnavailable("coordinator root history unavailable or corrupt") from None
    return row, scopes


def _initialize(connection: _Connection, now: float) -> str:
    for statement in TABLES:
        connection.execute(statement)
    database_id = uuid4().hex + uuid4().hex
    connection.execute(
        "INSERT INTO coordinator_meta VALUES(1,?,?,?,?,?,?)",
        (
            SCHEMA_VERSION,
            MANIFEST,
            database_id,
            now,
            '{"scopes":[],"barriers":[]}',
            _root_checksum(database_id, now, [], []),
        ),
    )
    return database_id


def _normalized(sql: str) -> str:
    return " ".join(sql.casefold().split())


def _validate_sqlite(connection: _Connection) -> int:
    rows = connection.execute(
        "SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
    ).fetchall()
    expected = {
        (statement.split()[1].lower(), statement.split()[2]): _normalized(statement)
        for statement in TABLES
    }
    actual = {(row["type"], row["name"]): _normalized(row["sql"]) for row in rows}
    if actual != expected or connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
        raise CoordinatorUnavailable("coordinator schema changed; history cannot be recreated")
    if connection.execute("PRAGMA synchronous").fetchone()[0] < 2 or connection.execute(
        "PRAGMA journal_mode"
    ).fetchone()[0] not in {"delete", "truncate", "persist", "wal"}:
        raise CoordinatorUnavailable("coordinator durable journaling unavailable")
    if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise CoordinatorUnavailable("coordinator relational history is incomplete")
    return connection.execute("PRAGMA schema_version").fetchone()[0]


class CoordinatorTransaction:
    def __init__(self, connection: _Connection, root, scopes: list[str], now: float):
        self.connection, self.now = connection, now
        self.database_id = root["database_id"]
        self._scopes = scopes
        self._barriers = decode(root["scopes_json"], MAX_ROOT_BYTES)["barriers"]
        self._loaded: dict[str, dict[str, Any]] = {}

    def scope(self, key: str) -> dict[str, Any]:
        _hex(key, "coordinator scope")
        if key not in self._scopes:
            raise CoordinatorRejected("coordinator.scope_unavailable")
        if key not in self._loaded:
            row = self.connection.execute(
                "SELECT * FROM coordinator_scopes WHERE scope_key=?", (key,)
            ).fetchone()
            if row is None:
                raise CoordinatorUnavailable("coordinator scope history missing")
            state = decode(row["state_json"])
            if (
                digest(state) != row["state_digest"]
                or state.get("scope_key") != key
                or state.get("version") != 1
            ):
                raise CoordinatorUnavailable("coordinator scope state changed")
            self._loaded[key] = state
        return self._loaded[key]

    def register_barrier(self, key: str) -> None:
        _hex(key, "coordinator barrier")
        if key not in self._barriers:
            if len(self._barriers) >= MAX_SCOPES * 3:
                raise CoordinatorRejected("coordinator.barrier_history_capacity")
            self._barriers.append(key)
            self._barriers.sort()

    def create_scope(self, key: str, state: dict[str, Any]) -> None:
        _hex(key, "coordinator scope")
        if key in self._scopes or len(self._scopes) >= MAX_SCOPES:
            raise CoordinatorRejected("coordinator.scope_exists_or_capacity")
        if state.get("scope_key") != key or state.get("version") != 1:
            raise ValueError("typed coordinator scope required")
        text = encode(state)
        self.connection.execute(
            "INSERT INTO coordinator_scopes VALUES(?,?,?)", (key, text, digest(state))
        )
        self._scopes.append(key)
        self._scopes.sort()
        self._loaded[key] = state

    def request(self, scope: str, operation: str, key: str, request_digest: str):
        identifier(operation, "coordinator operation")
        _hex(key, "coordinator idempotency digest")
        _hex(request_digest, "coordinator request digest")
        row = self.connection.execute(
            "SELECT request_digest,result_json FROM coordinator_requests WHERE scope_key=? AND operation=? AND idempotency_key=?",
            (scope, operation, key),
        ).fetchone()
        if row is None:
            return None
        if row["request_digest"] != request_digest:
            raise CoordinatorRejected("coordinator.idempotency_conflict")
        return decode(row["result_json"], MAX_RESULT_BYTES)

    def record_request(
        self,
        scope: str,
        operation: str,
        key: str,
        request_digest: str,
        result: dict[str, Any],
        *,
        maximum: int = 4096,
    ) -> None:
        if (
            self.connection.execute(
                "SELECT count(*) FROM coordinator_requests WHERE scope_key=?", (scope,)
            ).fetchone()[0]
            >= maximum
        ):
            raise CoordinatorRejected("coordinator.idempotency_history_capacity")
        self.connection.execute(
            "INSERT INTO coordinator_requests VALUES(?,?,?,?,?)",
            (scope, operation, key, request_digest, encode(result, MAX_RESULT_BYTES)),
        )

    def append(
        self, scope: str, kind: str, reference: str, payload: dict[str, Any], *, maximum: int = 4096
    ) -> dict[str, Any]:
        state = self.scope(scope)
        identifier(kind, "coordinator journal kind")
        if state["sequence"] >= maximum:
            state["incomplete"] = True
            raise CoordinatorRejected("coordinator.journal_capacity")
        sequence = state["sequence"] + 1
        record = {
            "sequence": sequence,
            "kind": kind,
            "reference_digest": digest(reference),
            "payload": payload,
            "previous_digest": state["journal_head"],
            "admitted_at": self.now,
        }
        text = encode(record, 65536)
        checksum = digest(record)
        self.connection.execute(
            "INSERT INTO coordinator_outbox VALUES(?,?,?,?,?,0)",
            (scope, sequence, digest([scope, sequence, checksum]), text, checksum),
        )
        state["sequence"], state["journal_head"] = sequence, checksum
        return record

    def checkpoint(self, scope: str, projection: dict[str, Any]) -> dict[str, Any]:
        state = self.scope(scope)
        rows = self.connection.execute(
            "SELECT * FROM coordinator_outbox WHERE scope_key=? ORDER BY sequence", (scope,)
        ).fetchall()
        head = "0" * 64
        for index, row in enumerate(rows, 1):
            record = decode(row["record_json"], 65536)
            if (
                row["sequence"] != index
                or record.get("sequence") != index
                or record.get("previous_digest") != head
                or digest(record) != row["record_digest"]
            ):
                raise CoordinatorUnavailable("coordinator journal continuity failed")
            head = row["record_digest"]
        if len(rows) != state["sequence"] or head != state["journal_head"]:
            raise CoordinatorUnavailable("coordinator journal history missing")
        snapshot = {
            "sequence": state["sequence"],
            "journal_head": head,
            "projection": projection,
            "prehistory": "unknown",
            "live_authority": False,
        }
        checksum = digest(snapshot)
        existing = self.connection.execute(
            "SELECT state_digest FROM coordinator_checkpoints WHERE scope_key=? AND sequence=?",
            (scope, state["sequence"]),
        ).fetchone()
        if existing is not None and existing[0] != checksum:
            raise CoordinatorUnavailable("coordinator checkpoint conflicts with its journal head")
        if existing is None:
            self.connection.execute(
                "INSERT INTO coordinator_checkpoints VALUES(?,?,?,?)",
                (scope, state["sequence"], encode(snapshot), checksum),
            )
        self.connection.execute(
            "UPDATE coordinator_outbox SET acknowledged=1 WHERE scope_key=? AND sequence<=?",
            (scope, state["sequence"]),
        )
        self.connection.execute(
            "DELETE FROM coordinator_checkpoints WHERE scope_key=? AND sequence<?",
            (scope, state["checkpoint_sequence"]),
        )
        state["checkpoint_sequence"], state["checkpoint_digest"] = state["sequence"], checksum
        return snapshot

    def verify_journal_head(self, scope: str) -> None:
        state = self.scope(scope)
        summary = self.connection.execute(
            "SELECT count(*) AS n,min(sequence) AS first,max(sequence) AS last FROM coordinator_outbox WHERE scope_key=?",
            (scope,),
        ).fetchone()
        if (
            summary["n"] != state["sequence"]
            or state["sequence"]
            and (summary["first"] != 1 or summary["last"] != state["sequence"])
        ):
            raise CoordinatorUnavailable("coordinator journal history missing")
        if state["sequence"]:
            row = self.connection.execute(
                "SELECT record_json,record_digest FROM coordinator_outbox WHERE scope_key=? AND sequence=?",
                (scope, state["sequence"]),
            ).fetchone()
            if (
                row is None
                or digest(decode(row["record_json"], 65536)) != row["record_digest"]
                or row["record_digest"] != state["journal_head"]
            ):
                raise CoordinatorUnavailable("coordinator journal head changed")
        if state["checkpoint_digest"] is not None:
            row = self.connection.execute(
                "SELECT state_json,state_digest FROM coordinator_checkpoints WHERE scope_key=? AND sequence=?",
                (scope, state["checkpoint_sequence"]),
            ).fetchone()
            if (
                row is None
                or digest(decode(row["state_json"])) != row["state_digest"]
                or row["state_digest"] != state["checkpoint_digest"]
            ):
                raise CoordinatorUnavailable("coordinator checkpoint history missing or changed")

    def flush(self) -> None:
        for key, state in self._loaded.items():
            text = encode(state)
            self.connection.execute(
                "UPDATE coordinator_scopes SET state_json=?,state_digest=? WHERE scope_key=?",
                (text, digest(state), key),
            )
        self.connection.execute(
            "UPDATE coordinator_meta SET last_now=?,scopes_json=?,checksum=? WHERE singleton=1",
            (
                self.now,
                encode({"scopes": self._scopes, "barriers": self._barriers}, MAX_ROOT_BYTES),
                _root_checksum(self.database_id, self.now, self._scopes, self._barriers),
            ),
        )


class SQLiteCoordinatorStore:
    """Single-host/dev durable authority; not a shared-file multi-host database."""

    backend = "sqlite"
    multi_host = False

    def __init__(
        self, path: str | Path, *, create: bool = False, clock: Callable[[], float] = time.time
    ):
        if type(create) is not bool or not callable(clock):
            raise ValueError("explicit coordinator initialization/clock required")
        self.path, self._clock = Path(path).absolute(), clock
        self._available = True
        try:
            if create:
                descriptor = os.open(
                    self.path,
                    os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                )
                os.close(descriptor)
                with private_database(
                    self.path, "swarm_coordinator", create=False, foreign_keys=True
                ) as raw:
                    connection = _Connection(raw, postgres=False)
                    self.identity = _initialize(connection, timestamp(clock()))
                    self._schema = _validate_sqlite(connection)
            else:
                with private_database(
                    self.path, "swarm_coordinator", readonly=True, create=False, foreign_keys=True
                ) as raw:
                    connection = _Connection(raw, postgres=False)
                    self._schema = _validate_sqlite(connection)
                    self.identity = _read_root(connection)[0]["database_id"]
            info = self.path.stat()
            self._file_identity = (info.st_dev, info.st_ino)
        except (OSError, ValueError, sqlite3.Error):
            raise CoordinatorUnavailable(
                "coordinator store needs explicit initialization or intact existing history"
            ) from None

    def _connection(self, raw):
        if not self._available:
            raise CoordinatorUnavailable("coordinator database unavailable")
        info = self.path.stat()
        if (info.st_dev, info.st_ino) != self._file_identity:
            raise CoordinatorUnavailable("coordinator database file replaced")
        connection = _Connection(raw, postgres=False)
        if connection.execute("PRAGMA schema_version").fetchone()[0] != self._schema:
            raise CoordinatorUnavailable("coordinator database schema changed")
        if connection.execute("PRAGMA synchronous").fetchone()[0] < 2:
            raise CoordinatorUnavailable("coordinator durable synchronization unavailable")
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise CoordinatorUnavailable("coordinator relational history missing")
        return connection

    def server_time(self) -> float:
        active = _active_transaction.get()
        if active is not None and active[0] is self:
            return active[1]
        try:
            with private_database(
                self.path, "swarm_coordinator", readonly=True, create=False, foreign_keys=True
            ) as raw:
                row, _ = _read_root(self._connection(raw))
                now = timestamp(self._clock())
                if row["database_id"] != self.identity or now < row["last_now"]:
                    raise CoordinatorUnavailable(
                        "coordinator server clock moved backward or database changed"
                    )
                return now
        except (OSError, ValueError, sqlite3.Error):
            raise CoordinatorUnavailable("coordinator database clock unavailable") from None

    @contextmanager
    def transaction(self) -> Iterator[CoordinatorTransaction]:
        if _active_transaction.get() is not None:
            raise CoordinatorUnavailable("nested coordinator authority transaction refused")
        rejected = None
        try:
            with private_database(
                self.path, "swarm_coordinator", create=False, foreign_keys=True
            ) as raw:
                connection = self._connection(raw)
                row, scopes = _read_root(connection, lock=True)
                now = timestamp(self._clock())
                if row["database_id"] != self.identity or now < row["last_now"]:
                    raise CoordinatorUnavailable(
                        "coordinator server clock moved backward or database changed"
                    )
                transaction = CoordinatorTransaction(connection, row, scopes, now)
                token = _active_transaction.set((self, now, transaction))
                try:
                    try:
                        yield transaction
                    except CoordinatorRejected as error:
                        rejected = error
                    transaction.flush()
                finally:
                    _active_transaction.reset(token)
        except CoordinatorRejected:
            raise
        except (OSError, ValueError, sqlite3.Error):
            raise CoordinatorUnavailable("coordinator transaction unavailable or corrupt") from None
        if rejected is not None:
            raise rejected


class PostgresCoordinatorStore:
    """Optional PostgreSQL authority, serialized by an actual database row lock.

    Every mutator locks coordinator_meta before reading scoped accounting state.
    READ COMMITTED then observes the latest committed state after lock acquisition;
    no local process lock or eventually consistent cache grants hard authority.
    """

    backend = "postgresql"
    multi_host = True

    def __init__(self, dsn: str, *, schema: str = "ordin_swarm", create: bool = False):
        if (
            type(dsn) is not str
            or not 1 <= len(dsn) <= 4096
            or type(schema) is not str
            or re.fullmatch(r"[a-z][a-z0-9_]{0,62}", schema) is None
            or type(create) is not bool
        ):
            raise ValueError("protected PostgreSQL connection/schema configuration required")
        try:
            self._driver = importlib.import_module("psycopg")
        except ImportError:
            raise CoordinatorUnavailable("optional PostgreSQL driver is not installed") from None
        self._dsn, self._schema_name, self._available = dsn, schema, True
        try:
            with self._connect(set_schema=False) as raw:
                if create:
                    if (
                        raw.execute(
                            "SELECT 1 FROM pg_namespace WHERE nspname=%s", (schema,)
                        ).fetchone()
                        is not None
                    ):
                        raise CoordinatorUnavailable(
                            "coordinator schema already exists; reinitialization denied"
                        )
                    raw.execute('CREATE SCHEMA "' + schema + '"')
                raw.execute('SET LOCAL search_path TO "' + schema + '",pg_catalog')
                connection = _Connection(raw, postgres=True)
                if create:
                    now = self._db_time(connection)
                    self.identity = _initialize(connection, now)
                self._validate_schema(connection)
                self.identity = _read_root(connection)[0]["database_id"]
        except Exception:
            raise CoordinatorUnavailable(
                "PostgreSQL coordinator requires explicit new schema or intact history"
            ) from None

    def _connect(self, *, set_schema=True):
        if not self._available:
            raise CoordinatorUnavailable("coordinator database unavailable")
        raw = self._driver.connect(
            self._dsn, connect_timeout=3, sslmode="verify-full", target_session_attrs="read-write"
        )
        try:
            host = raw.info.host
            if host.startswith("/") and (
                not Path(host).is_dir() or Path(host).stat().st_mode & 0o002
            ):
                raise CoordinatorUnavailable(
                    "coordinator Unix database socket directory is not protected"
                )
            raw.execute("SET LOCAL lock_timeout='3s'")
            raw.execute("SET LOCAL statement_timeout='10s'")
            raw.execute("SET LOCAL idle_in_transaction_session_timeout='10s'")
            if set_schema:
                raw.execute('SET LOCAL search_path TO "' + self._schema_name + '",pg_catalog')
            return raw
        except Exception:
            raw.close()
            raise

    @staticmethod
    def _db_time(connection: _Connection) -> float:
        return timestamp(
            float(connection.execute("SELECT EXTRACT(EPOCH FROM clock_timestamp())").fetchone()[0])
        )

    def _validate_schema(self, connection: _Connection) -> None:
        if (
            connection.execute("SHOW fsync").fetchone()[0] != "on"
            or connection.execute("SHOW full_page_writes").fetchone()[0] != "on"
            or connection.execute("SHOW synchronous_commit").fetchone()[0]
            not in {"on", "remote_apply"}
        ):
            raise CoordinatorUnavailable(
                "coordinator PostgreSQL durability configuration unavailable"
            )
        names = {
            row[0]
            for row in connection.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema=? AND table_type='BASE TABLE'",
                (self._schema_name,),
            ).fetchall()
        }
        if names != set(TABLE_NAMES):
            raise CoordinatorUnavailable("coordinator PostgreSQL schema missing or changed")
        # Detect removed/altered columns, keys and unexpected user triggers rather
        # than trusting a version row in a partially recreated database.
        expected_columns = {
            "coordinator_meta": (
                "singleton",
                "version",
                "manifest",
                "database_id",
                "last_now",
                "scopes_json",
                "checksum",
            ),
            "coordinator_scopes": ("scope_key", "state_json", "state_digest"),
            "coordinator_barriers": ("realm_key", "epoch", "state", "intent_digest", "checksum"),
            "coordinator_buckets": (
                "bucket",
                "tenant_digest",
                "metric",
                "maximum",
                "held",
                "consumed",
                "observed",
                "blocked_epoch",
                "checksum",
            ),
            "coordinator_items": ("scope_key", "reservation_id", "bucket", "metric", "amount"),
            "coordinator_requests": (
                "scope_key",
                "operation",
                "idempotency_key",
                "request_digest",
                "result_json",
            ),
            "coordinator_outbox": (
                "scope_key",
                "sequence",
                "event_id",
                "record_json",
                "record_digest",
                "acknowledged",
            ),
            "coordinator_checkpoints": ("scope_key", "sequence", "state_json", "state_digest"),
        }
        expected_keys = {
            "coordinator_meta": ("singleton",),
            "coordinator_scopes": ("scope_key",),
            "coordinator_barriers": ("realm_key",),
            "coordinator_buckets": ("bucket",),
            "coordinator_items": ("scope_key", "reservation_id", "bucket"),
            "coordinator_requests": ("scope_key", "operation", "idempotency_key"),
            "coordinator_outbox": ("scope_key", "sequence"),
            "coordinator_checkpoints": ("scope_key", "sequence"),
        }
        for name, columns in expected_columns.items():
            actual = connection.execute(
                "SELECT column_name,data_type,is_nullable FROM information_schema.columns WHERE table_schema=? AND table_name=? ORDER BY ordinal_position",
                (self._schema_name, name),
            ).fetchall()
            numeric = {
                "singleton",
                "version",
                "maximum",
                "held",
                "consumed",
                "observed",
                "blocked_epoch",
                "amount",
                "sequence",
                "epoch",
                "acknowledged",
            }
            expected_types = tuple(
                "double precision"
                if name == "coordinator_meta" and column == "last_now"
                else "integer"
                if column in {"singleton", "version", "acknowledged"}
                else "bigint"
                if column in numeric
                else "text"
                for column in columns
            )
            if (
                tuple(row[0] for row in actual) != columns
                or tuple(row[1] for row in actual) != expected_types
                or any(row[2] != "NO" for row in actual)
            ):
                raise CoordinatorUnavailable("coordinator PostgreSQL columns changed")
            keys = connection.execute(
                "SELECT k.column_name FROM information_schema.table_constraints c JOIN information_schema.key_column_usage k ON c.constraint_catalog=k.constraint_catalog AND c.constraint_schema=k.constraint_schema AND c.constraint_name=k.constraint_name WHERE c.table_schema=? AND c.table_name=? AND c.constraint_type='PRIMARY KEY' ORDER BY k.ordinal_position",
                (self._schema_name, name),
            ).fetchall()
            if tuple(row[0] for row in keys) != expected_keys[name]:
                raise CoordinatorUnavailable("coordinator PostgreSQL authority keys changed")
        foreign = connection.execute(
            "SELECT c.table_name,k.column_name,f.table_name,f.column_name FROM information_schema.table_constraints c JOIN information_schema.key_column_usage k ON c.constraint_catalog=k.constraint_catalog AND c.constraint_schema=k.constraint_schema AND c.constraint_name=k.constraint_name JOIN information_schema.constraint_column_usage f ON c.constraint_catalog=f.constraint_catalog AND c.constraint_schema=f.constraint_schema AND c.constraint_name=f.constraint_name WHERE c.table_schema=? AND c.constraint_type='FOREIGN KEY'",
            (self._schema_name,),
        ).fetchall()
        if {(row[0], row[1], row[2], row[3]) for row in foreign} != {
            ("coordinator_items", "scope_key", "coordinator_scopes", "scope_key"),
            ("coordinator_items", "bucket", "coordinator_buckets", "bucket"),
            ("coordinator_requests", "scope_key", "coordinator_scopes", "scope_key"),
            ("coordinator_outbox", "scope_key", "coordinator_scopes", "scope_key"),
            ("coordinator_checkpoints", "scope_key", "coordinator_scopes", "scope_key"),
        }:
            raise CoordinatorUnavailable("coordinator PostgreSQL history references changed")
        checks = connection.execute(
            "SELECT t.relname,pg_get_constraintdef(c.oid,true) FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname=? AND c.contype='c'",
            (self._schema_name,),
        ).fetchall()
        normalized = {(row[0], re.sub(r"[\s()\"]", "", row[1]).lower()) for row in checks}
        expected_checks = {
            ("coordinator_meta", "checksingleton=1"),
            ("coordinator_barriers", "checkepoch>0"),
            *(
                ("coordinator_buckets", "check" + column + ">=0")
                for column in ("maximum", "held", "consumed", "observed")
            ),
            ("coordinator_items", "checkamount>=0"),
            ("coordinator_outbox", "checksequence>0"),
            ("coordinator_outbox", "checkacknowledged=anyarray[0,1]"),
            ("coordinator_checkpoints", "checksequence>=0"),
        }
        if normalized != expected_checks:
            raise CoordinatorUnavailable("coordinator PostgreSQL checks changed")
        unique = connection.execute(
            "SELECT c.table_name,k.column_name,k.ordinal_position FROM information_schema.table_constraints c JOIN information_schema.key_column_usage k ON c.constraint_catalog=k.constraint_catalog AND c.constraint_schema=k.constraint_schema AND c.constraint_name=k.constraint_name WHERE c.table_schema=? AND c.constraint_type='UNIQUE' ORDER BY c.table_name,k.ordinal_position",
            (self._schema_name,),
        ).fetchall()
        if [(row[0], row[1], row[2]) for row in unique] != [
            ("coordinator_outbox", "scope_key", 1),
            ("coordinator_outbox", "event_id", 2),
        ]:
            raise CoordinatorUnavailable("coordinator PostgreSQL uniqueness changed")
        foreign_rules = connection.execute(
            "SELECT r.update_rule,r.delete_rule,r.match_option FROM information_schema.referential_constraints r WHERE r.constraint_schema=?",
            (self._schema_name,),
        ).fetchall()
        if len(foreign_rules) != 5 or any(
            tuple(row.values()) != ("NO ACTION", "NO ACTION", "NONE") for row in foreign_rules
        ):
            raise CoordinatorUnavailable("coordinator PostgreSQL reference rules changed")
        if (
            connection.execute(
                "SELECT 1 FROM information_schema.table_constraints WHERE table_schema=? AND (is_deferrable<>'NO' OR initially_deferred<>'NO') LIMIT 1",
                (self._schema_name,),
            ).fetchone()
            is not None
        ):
            raise CoordinatorUnavailable("coordinator PostgreSQL deferred authority constraint")
        if (
            connection.execute(
                "SELECT 1 FROM information_schema.triggers WHERE trigger_schema=? LIMIT 1",
                (self._schema_name,),
            ).fetchone()
            is not None
        ):
            raise CoordinatorUnavailable("unexpected coordinator database trigger")

    def server_time(self) -> float:
        active = _active_transaction.get()
        if active is not None and active[0] is self:
            return active[1]
        try:
            with self._connect() as raw:
                connection = _Connection(raw, postgres=True)
                root, _ = _read_root(connection)
                now = self._db_time(connection)
                if root["database_id"] != self.identity or now < root["last_now"]:
                    raise CoordinatorUnavailable(
                        "coordinator database clock moved backward or identity changed"
                    )
                return now
        except Exception:
            raise CoordinatorUnavailable("coordinator database clock unavailable") from None

    @contextmanager
    def transaction(self) -> Iterator[CoordinatorTransaction]:
        if _active_transaction.get() is not None:
            raise CoordinatorUnavailable("nested coordinator authority transaction refused")
        rejected = None
        try:
            with self._connect() as raw:
                connection = _Connection(raw, postgres=True)
                self._validate_schema(connection)
                row, scopes = _read_root(connection, lock=True)
                now = self._db_time(connection)
                if row["database_id"] != self.identity or now < row["last_now"]:
                    raise CoordinatorUnavailable(
                        "coordinator database clock moved backward or identity changed"
                    )
                transaction = CoordinatorTransaction(connection, row, scopes, now)
                token = _active_transaction.set((self, now, transaction))
                try:
                    try:
                        yield transaction
                    except CoordinatorRejected as error:
                        rejected = error
                    transaction.flush()
                finally:
                    _active_transaction.reset(token)
        except CoordinatorRejected:
            raise
        except Exception:
            raise CoordinatorUnavailable(
                "coordinator PostgreSQL transaction unavailable or corrupt"
            ) from None
        if rejected is not None:
            raise rejected


class CoordinatorClock:
    """Original trusted DB clock shared by registry, collectors and authority service."""

    def __init__(self, store: SQLiteCoordinatorStore | PostgresCoordinatorStore):
        if type(store) not in {SQLiteCoordinatorStore, PostgresCoordinatorStore}:
            raise ValueError("original coordinator database clock required")
        self._store = store
        self.database_id = store.identity

    def __call__(self) -> int:
        # Core delegation clocks use integer seconds. All registry/temporal
        # users share this same DB epoch domain; store leases retain precision.
        value = self._store.server_time()
        if not 0 <= value < 2**53:
            raise CoordinatorUnavailable(
                "coordinator database clock outside supported grant domain"
            )
        return int(value)
