"""Validation descriptors refuse special files before SQLite can inspect them."""

import os
from pathlib import Path
import subprocess
import sys

import pytest

from ordin import _private_storage
from ordin.swarm.budget_store import SQLiteBudgetStore
from ordin.swarm.coordinator_store import SQLiteCoordinatorStore


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="requires POSIX FIFOs")
@pytest.mark.parametrize("caller", ["helper", "budget", "coordinator"])
@pytest.mark.parametrize("through_symlink", [False, True])
def test_fifo_attachment_rejects_without_waiting_for_a_writer(tmp_path, caller, through_symlink):
    fifo = tmp_path / "database.fifo"
    os.mkfifo(fifo, 0o600)
    selected = fifo
    if through_symlink:
        selected = tmp_path / "linked.fifo"
        selected.symlink_to(fifo)
    code = """
from pathlib import Path
import sys
repo=Path(sys.argv[1])
sys.path.insert(0,str(repo))
from ordin import _private_storage
from ordin.swarm.budget_store import SQLiteBudgetStore
from ordin.swarm.coordinator_store import SQLiteCoordinatorStore
assert Path(_private_storage.__file__).resolve().is_relative_to(repo.resolve())
def forbidden_connect(*args,**kwargs):
    raise AssertionError("special files must fail before SQLite connection")
_private_storage.sqlite3.connect=forbidden_connect
try:
    if sys.argv[3]=="helper":
        with _private_storage.private_database(sys.argv[2],"swarm_budget",readonly=True,create=False):
            raise AssertionError("special file admitted")
    elif sys.argv[3]=="budget":
        SQLiteBudgetStore(sys.argv[2])
        raise AssertionError("special budget file admitted")
    else:
        SQLiteCoordinatorStore(sys.argv[2])
        raise AssertionError("special coordinator file admitted")
except (ValueError,OSError):
    pass
"""
    subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            code,
            str(Path(_private_storage.__file__).parents[1]),
            str(selected),
            caller,
        ],
        check=True,
        timeout=5,
        capture_output=True,
        text=True,
    )


def test_regular_private_database_still_supports_readonly_inspection(tmp_path):
    path = tmp_path / "private.db"
    with _private_storage.private_database(path, "session") as connection:
        connection.execute("CREATE TABLE sample (value INTEGER)")
        connection.execute("INSERT INTO sample VALUES(7)")
    with _private_storage.private_database(
        path, "session", readonly=True, create=False
    ) as connection:
        assert connection.execute("SELECT value FROM sample").fetchone()[0] == 7


def test_regular_budget_history_still_attaches(tmp_path):
    path = tmp_path / "budget.db"
    created = SQLiteBudgetStore(path, create=True)
    with created.transaction() as connection:
        connection.execute("INSERT INTO budget_meta VALUES(1,?,0,1,?,100)", ("a" * 64, "b" * 32))
    reopened = SQLiteBudgetStore(path)
    with reopened.transaction() as connection:
        assert connection.execute("SELECT last_now FROM budget_meta").fetchone()[0] == 100


def test_regular_coordinator_history_still_attaches(tmp_path):
    path = tmp_path / "coordinator.db"
    created = SQLiteCoordinatorStore(path, create=True, clock=lambda: 100)
    reopened = SQLiteCoordinatorStore(path, clock=lambda: 100)
    assert reopened.identity == created.identity
    assert reopened.server_time() == 100
