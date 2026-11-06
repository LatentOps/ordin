"""Durable database transactions, explicit initialization and lost-history refusal."""

import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest

from ordin._runtime_json import digest
from ordin.swarm.coordinator_store import (
    CoordinatorClock,
    CoordinatorRejected,
    CoordinatorUnavailable,
    PostgresCoordinatorStore,
    SQLiteCoordinatorStore,
)


SCOPE = digest(["tenant", "swarm"])


def initial():
    return {
        "version": 1,
        "scope_key": SCOPE,
        "sequence": 0,
        "journal_head": "0" * 64,
        "checkpoint_sequence": 0,
        "checkpoint_digest": None,
        "incomplete": False,
        "count": 0,
    }


def store(tmp_path, *, clock=lambda: 100):
    backend = SQLiteCoordinatorStore(tmp_path / "coordinator.db", create=True, clock=clock)
    with backend.transaction() as transaction:
        transaction.create_scope(SCOPE, initial())
    return backend


def test_initialization_is_explicit_and_reopen_preserves_state(tmp_path):
    missing = tmp_path / "missing.db"
    with pytest.raises(CoordinatorUnavailable):
        SQLiteCoordinatorStore(missing)
    assert not missing.exists()
    backend = store(tmp_path)
    with backend.transaction() as transaction:
        transaction.scope(SCOPE)["count"] = 7
    recovered = SQLiteCoordinatorStore(backend.path, clock=lambda: 100)
    assert recovered.identity == backend.identity
    with recovered.transaction() as transaction:
        assert transaction.scope(SCOPE)["count"] == 7
    with pytest.raises(CoordinatorUnavailable):
        SQLiteCoordinatorStore(backend.path, create=True)


def test_request_idempotency_and_journal_checkpoint_are_atomic(tmp_path):
    backend = store(tmp_path)
    key, payload = digest("request"), digest("payload")
    with backend.transaction() as transaction:
        assert transaction.request(SCOPE, "reserve", key, payload) is None
        transaction.record_request(SCOPE, "reserve", key, payload, {"reservation_digest": "a" * 64})
        transaction.append(
            SCOPE, "reserved", "private-control-reference", {"action_digest": "b" * 64}
        )
        snapshot = transaction.checkpoint(SCOPE, {"graph": [], "live_authority": False})
    assert snapshot["prehistory"] == "unknown" and not snapshot["live_authority"]
    with backend.transaction() as transaction:
        assert transaction.request(SCOPE, "reserve", key, payload) == {
            "reservation_digest": "a" * 64
        }
        assert transaction.scope(SCOPE)["sequence"] == 1
        assert (
            transaction.connection.execute(
                "SELECT count(*) FROM coordinator_outbox WHERE acknowledged=1"
            ).fetchone()[0]
            == 1
        )
    with pytest.raises(CoordinatorRejected, match="idempotency"):
        with backend.transaction() as transaction:
            transaction.request(SCOPE, "reserve", key, digest("changed"))


def test_unknown_failure_rolls_back_but_business_denial_commits_safe_housekeeping(tmp_path):
    backend = store(tmp_path)
    with pytest.raises(RuntimeError, match="interrupted"):
        with backend.transaction() as transaction:
            transaction.scope(SCOPE)["count"] = 8
            transaction.append(SCOPE, "reserved", "reservation", {})
            raise RuntimeError("interrupted")
    with backend.transaction() as transaction:
        assert transaction.scope(SCOPE)["count"] == transaction.scope(SCOPE)["sequence"] == 0
    with pytest.raises(CoordinatorRejected):
        with backend.transaction() as transaction:
            transaction.scope(SCOPE)["incomplete"] = True
            raise CoordinatorRejected("coordinator.history_incomplete")
    with backend.transaction() as transaction:
        assert transaction.scope(SCOPE)["incomplete"]


@pytest.mark.parametrize("corruption", ["root", "scope", "schema", "scope-data", "journal"])
def test_missing_corrupt_or_changed_history_is_never_recreated(tmp_path, corruption):
    backend = store(tmp_path)
    with backend.transaction() as transaction:
        transaction.append(SCOPE, "reserved", "reservation", {})
    with sqlite3.connect(backend.path) as connection:
        if corruption == "root":
            connection.execute("DELETE FROM coordinator_meta")
        elif corruption == "scope":
            connection.execute("DELETE FROM coordinator_scopes")
        elif corruption == "schema":
            connection.execute("DROP TABLE coordinator_requests")
        elif corruption == "scope-data":
            connection.execute("UPDATE coordinator_scopes SET state_json='{}'")
        else:
            connection.execute("DELETE FROM coordinator_outbox")
    with pytest.raises(CoordinatorUnavailable):
        with backend.transaction() as transaction:
            transaction.scope(SCOPE)
            transaction.checkpoint(SCOPE, {})
    with pytest.raises(CoordinatorUnavailable):
        SQLiteCoordinatorStore(backend.path, create=True)


def test_db_clock_is_original_shared_source_and_backward_clock_fails_closed(tmp_path):
    now = [100.0]
    backend = store(tmp_path, clock=lambda: now[0])
    clock = CoordinatorClock(backend)
    assert clock() == 100
    with backend.transaction() as transaction:
        now[0] = 102
        assert clock() == 102
        assert transaction.now == 100  # Accounting keeps its admission timestamp.
        now[0] = 101
        with pytest.raises(CoordinatorUnavailable):
            clock()
        now[0] = 102
    assert clock() == 102
    now[0] = 101
    with pytest.raises(CoordinatorUnavailable):
        clock()  # The latest observed time survives the transaction commit.
    now[0] = 102
    with backend.transaction():
        pass
    now[0] = 99
    with pytest.raises(CoordinatorUnavailable):
        clock()
    with pytest.raises(CoordinatorUnavailable):
        with backend.transaction():
            pytest.fail("backward-clock transaction entered")


@pytest.mark.parametrize("backend_kind", ("sqlite", "postgres"))
def test_transaction_clock_does_not_rewind_shared_authenticated_host_clock(
    tmp_path, monkeypatch, backend_kind
):
    from tests.test_swarm_coordinator import configured

    backend = postgres_fixture() if backend_kind == "postgres" else None
    current = [backend.server_time()] if backend is not None else None
    if backend is not None:
        monkeypatch.setattr(backend, "_db_time", lambda connection: current[0])
    with configured(tmp_path, backend=backend) as data:
        channel = data["channels"]["parent"]
        with data["store"].transaction() as transaction:
            started = transaction.now
            (current if current is not None else data["now"])[0] += 2
            # This second request has no active transaction and observes the
            # actual later DB clock. The first transaction must not present its
            # older accounting timestamp as a new host authentication time.
            with ThreadPoolExecutor(max_workers=1) as executor:
                executor.submit(data["auth"].require, channel, role="workload").result(timeout=5)
            assert data["auth"].require(channel, role="workload") is not None
            assert transaction.now == started


def test_concurrent_connections_serialize_updates_at_database_boundary(tmp_path):
    backend = store(tmp_path)

    def reserve(_):
        connection = SQLiteCoordinatorStore(backend.path, clock=lambda: 100)
        try:
            with connection.transaction() as transaction:
                state = transaction.scope(SCOPE)
                if state["count"] >= 1:
                    raise CoordinatorRejected("coordinator.limit_exceeded")
                state["count"] += 1
            return "reserved"
        except CoordinatorRejected:
            return "denied"

    with ThreadPoolExecutor(max_workers=4) as executor:
        outcomes = list(executor.map(reserve, range(8)))
    assert outcomes.count("reserved") == 1
    with backend.transaction() as transaction:
        assert transaction.scope(SCOPE)["count"] == 1


def test_distinct_processes_cannot_overspend_single_host_dev_state(tmp_path):
    backend = store(tmp_path)
    command = """from ordin.swarm.coordinator_store import SQLiteCoordinatorStore,CoordinatorRejected
from ordin._runtime_json import digest
import sys
store=SQLiteCoordinatorStore(sys.argv[1],clock=lambda:100)
try:
 with store.transaction() as tx:
  state=tx.scope(digest(['tenant','swarm']))
  if state['count']>=1: raise CoordinatorRejected('coordinator.limit_exceeded')
  state['count']+=1
 print('reserved')
except CoordinatorRejected: print('denied')
"""
    processes = [
        subprocess.Popen(
            [sys.executable, "-c", command, str(backend.path)],
            cwd=Path(__file__).resolve().parents[1],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(3)
    ]
    outcomes = []
    for process in processes:
        output, error = process.communicate(timeout=15)
        assert process.returncode == 0, error
        outcomes.append(output.strip())
    assert outcomes.count("reserved") == 1


def test_optional_postgres_uses_real_owned_fixture_when_requested():
    dsn = os.environ.get("ORDIN_COORDINATOR_TEST_PG_DSN")
    if not dsn or os.environ.get("ORDIN_COORDINATOR_TEST_PG_ALLOW_CREATE") != "owned-fixture":
        pytest.skip("explicit owned PostgreSQL fixture not requested")
    schema = "ordin_test_" + uuid4().hex
    backend = PostgresCoordinatorStore(dsn, schema=schema, create=True)
    with backend.transaction() as transaction:
        transaction.create_scope(SCOPE, initial())

    def reserve(_):
        other = PostgresCoordinatorStore(dsn, schema=schema)
        try:
            with other.transaction() as transaction:
                state = transaction.scope(SCOPE)
                if state["count"] >= 1:
                    raise CoordinatorRejected("coordinator.limit_exceeded")
                state["count"] += 1
            return "reserved"
        except CoordinatorRejected:
            return "denied"

    with ThreadPoolExecutor(max_workers=4) as executor:
        outcomes = list(executor.map(reserve, range(8)))
    assert outcomes.count("reserved") == 1
    reopened = PostgresCoordinatorStore(dsn, schema=schema)
    assert reopened.identity == backend.identity and reopened.multi_host
    with reopened.transaction() as transaction:
        assert transaction.scope(SCOPE)["count"] == 1


@pytest.mark.parametrize("after_commit", [False, True])
def test_process_crash_never_publishes_partial_transition(tmp_path, after_commit):
    backend = store(tmp_path)
    source = tmp_path / "crash.py"
    source.write_text(
        "import os,sys\nfrom ordin.swarm.coordinator_store import SQLiteCoordinatorStore\n"
        "backend=SQLiteCoordinatorStore(sys.argv[1],clock=lambda:100)\n"
        "with backend.transaction() as tx:\n"
        f"    tx.scope('{SCOPE}')['count']=1\n"
        + ("    os._exit(17)\n" if not after_commit else "os._exit(17)\n"),
        encoding="utf-8",
    )
    environment = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1]))
    result = subprocess.run(
        [sys.executable, str(source), str(backend.path)], env=environment, check=False, timeout=30
    )
    assert result.returncode == 17
    with backend.transaction() as transaction:
        assert transaction.scope(SCOPE)["count"] == int(after_commit)


def postgres_fixture():
    if os.environ.get("ORDIN_COORDINATOR_TEST_PG_ALLOW_CREATE") != "owned-fixture":
        pytest.skip("requires explicitly owned PostgreSQL fixture")
    dsn = os.environ.get("ORDIN_COORDINATOR_TEST_PG_DSN")
    if not dsn:
        pytest.skip("requires explicitly owned PostgreSQL fixture")
    return PostgresCoordinatorStore(dsn, schema="ordin_test_" + uuid4().hex, create=True)


def test_initial_migration_reference_matches_runtime_manifest():
    from ordin.swarm.coordinator_store import MANIFEST, TABLES

    root = Path(__file__).resolve().parents[1]
    source = (root / "integrations/swarm/ordin_swarm/migrations/0001-coordinator.sql").read_text(
        encoding="utf-8"
    )
    assert "-- Manifest: " + MANIFEST in source
    ddl = "\n".join(line for line in source.splitlines() if not line.startswith("--"))
    assert tuple(part.strip() for part in ddl.split(";") if part.strip()) == TABLES


@pytest.mark.parametrize("change", ["check", "unique", "nullable", "missing_table"])
def test_real_postgresql_missing_or_changed_constraints_fail_closed(change):
    backend = postgres_fixture()
    statements = {
        "check": "ALTER TABLE coordinator_buckets DROP CONSTRAINT coordinator_buckets_held_check",
        "unique": "ALTER TABLE coordinator_outbox DROP CONSTRAINT coordinator_outbox_scope_key_event_id_key",
        "nullable": "ALTER TABLE coordinator_buckets ALTER COLUMN held DROP NOT NULL",
        "missing_table": "DROP TABLE coordinator_requests",
    }
    with backend._connect() as raw:
        raw.execute(statements[change])
    with pytest.raises(CoordinatorUnavailable):
        with backend.transaction():
            pytest.fail("changed schema became authority")
    with pytest.raises(CoordinatorUnavailable):
        PostgresCoordinatorStore(backend._dsn, schema=backend._schema_name, create=True)


@pytest.mark.parametrize(
    "raw",
    [
        '{"value":1e309}',
        '{"value":NaN}',
        '{"value":1,"value":2}',
        '{"value":' + "[" * 33 + "0" + "]" * 33 + "}",
    ],
)
def test_transport_and_stored_json_are_bounded_finite_data_only(raw):
    from ordin.swarm.coordinator_store import decode

    with pytest.raises(CoordinatorUnavailable):
        decode(raw)


def test_real_postgresql_two_authenticated_hosts_and_tenant_isolation(tmp_path):
    from tests.test_swarm_coordinator import configured, prepare

    backend = postgres_fixture()
    with configured(tmp_path / "a", backend=backend, tenant="tenant-a") as first:

        def reserve(who):
            try:
                prepare(first, who, request="host-" + who)
                return "reserved"
            except CoordinatorRejected:
                return "denied"

        with ThreadPoolExecutor(max_workers=2) as executor:
            assert sorted(executor.map(reserve, ("parent", "child"))) == ["denied", "reserved"]
        with configured(tmp_path / "b", backend=backend, tenant="tenant-b") as second:
            prepare(second)
            with pytest.raises(ValueError):
                second["coordinator"].budget_report(
                    second["scope"], first["channels"]["child"], first["leases"]["child"].reference
                )
            for data in (first, second):
                report = data["coordinator"].budget_report(
                    data["scope"], data["channels"]["parent"], data["leases"]["parent"].reference
                )
                assert report["limits"][0]["reserved"] == 1
