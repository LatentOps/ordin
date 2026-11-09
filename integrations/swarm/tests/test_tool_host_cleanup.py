"""Fake live-child stop failures retain original upper cleanup custody for retry."""

from contextlib import ExitStack
import os
import stat
from threading import Event, RLock
from types import SimpleNamespace

import pytest

from ordin_swarm.host_authority import HostAuthority, _HostCleanupIncomplete
from ordin_swarm.host_runtime import ManagedToolHost, HostClient
from ordin_swarm.host_service import ManagedHostServer


class LiveBackend:
    def __init__(self):
        self.attempts, self.live, self.database_open = 0, True, True

    def close(self):
        self.attempts += 1
        if self.attempts == 1:
            raise RuntimeError("original child remains live")
        self.live, self.database_open = False, False


def authority():
    original = object.__new__(HostAuthority)
    original._close_lock = RLock()
    original._closing = original._cleanup_complete = False
    original.operator = object()
    original.backend = LiveBackend()
    original.auth = SimpleNamespace(fence=lambda **kwargs: None)
    original.stack = ExitStack()
    controls = []
    original.stack.callback(lambda: controls.append("released"))
    return original, controls


def host_with_lock(tmp_path, original):
    host = object.__new__(ManagedToolHost)
    host._lock, host._close_lock = RLock(), RLock()
    host._closed = host._cleanup_complete = False
    host._operator, host._authority = original.operator, original
    host._clients, host._approvals = (
        {},
        {"unknown": SimpleNamespace(client=None, fulfilling=False, result={"status": "unknown"})},
    )
    host.shutdown_requested = Event()
    host._lock_fd = os.open(tmp_path / "host.lock", os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    return host


def test_service_host_authority_retry_preserves_live_backend_controls_lock_and_unknown_result(
    tmp_path,
):
    original, controls = authority()
    host = host_with_lock(tmp_path, original)
    descriptor, prior_result = host._lock_fd, host._approvals["unknown"].result
    touches = []
    original.ledger = SimpleNamespace(
        cancel=lambda *args: touches.append("cancel"), commit=lambda *args: touches.append("commit")
    )
    closed, joined = [], []

    class Connection:
        attempts = 0

        def shutdown(self, how):
            closed.append("shutdown")

        def close(self):
            closed.append("connection")
            self.attempts += 1
            if self.attempts == 1:
                raise OSError("transport cleanup failed once")

    class Worker:
        def join(self, timeout):
            joined.append(timeout)

        def is_alive(self):
            return False

    server = object.__new__(ManagedHostServer)
    server.host, server.listener = host, SimpleNamespace(close=lambda: closed.append("listener"))
    server._lock, server._close_lock = RLock(), RLock()
    server._cleanup_complete = False
    server._sockets, server._threads = {Connection()}, {Worker()}
    with pytest.raises(_HostCleanupIncomplete) as stopped:
        server.close()
    assert stopped.value.cleanup_owner is server
    assert str(stopped.value) == "managed host cleanup remains incomplete"
    assert host._closed and host.shutdown_requested.is_set()
    assert not host._cleanup_complete and not server._cleanup_complete
    assert original.backend.live and original.backend.database_open and controls == []
    assert "listener" in closed and "connection" in closed and joined
    os.fstat(descriptor)
    with pytest.raises(ValueError, match="closed"):
        host.require_client(HostClient("cannot-reenroll"))
    stopped.value.retry_cleanup()
    assert original.backend.attempts == 2 and not original.backend.live
    assert controls == ["released"] and host._lock_fd is None
    assert host._cleanup_complete and server._cleanup_complete
    assert host._approvals["unknown"].result is prior_result and prior_result["status"] == "unknown"
    assert touches == []
    with pytest.raises(OSError):
        os.fstat(descriptor)
    server.close()
    host.close()
    original.close()
    assert original.backend.attempts == 2 and controls == ["released"]


def test_authority_constructor_preserves_original_cause_and_original_cleanup_owner(
    tmp_path, monkeypatch
):
    from ordin_swarm import host_authority
    from ordin_swarm.host_profiles import ToolHostProfile
    from test_tool_host_profiles import document

    profile = ToolHostProfile.from_dict(document(tmp_path), configuration_root=tmp_path)
    monkeypatch.setattr(ToolHostProfile, "require_unchanged", lambda self: None)
    monkeypatch.setattr(host_authority, "check_private_directory", lambda *args: None)
    monkeypatch.setattr(host_authority, "SQLiteCoordinatorStore", lambda *args, **kwargs: object())
    monkeypatch.setattr(host_authority, "CoordinatorClock", lambda store: lambda: 100)
    monkeypatch.setattr(host_authority, "PrivateHostPKI", lambda profile: object())
    backend = LiveBackend()
    monkeypatch.setattr(host_authority, "make_backend", lambda *args, **kwargs: backend)
    cause = ValueError("private original construction cause")

    def fail(*args):
        raise cause

    monkeypatch.setattr(host_authority, "host_core", fail)
    with pytest.raises(_HostCleanupIncomplete) as failed:
        HostAuthority(profile, operator=object())
    assert failed.value.__cause__ is cause
    owner = failed.value.cleanup_owner
    assert type(owner) is HostAuthority and owner.backend is backend and owner._closing
    with pytest.raises(ValueError, match="draining"):
        owner.maintenance()
    failed.value.retry_cleanup()
    assert owner._cleanup_complete and backend.attempts == 2


def test_partial_host_constructor_retains_lock_until_original_authority_retry_succeeds(
    tmp_path, monkeypatch
):
    import sys
    from ordin_swarm import host_runtime
    from ordin_swarm.host_profiles import ToolHostProfile
    from test_tool_host_profiles import document

    profile = ToolHostProfile.from_dict(document(tmp_path), configuration_root=tmp_path)
    (tmp_path / "state").mkdir()
    (tmp_path / "state" / "host.lock").write_bytes(b"")
    original, controls = authority()
    cause = ValueError("original startup failure")
    # Only emulate advisory-lock platform mechanics. Actual child/control
    # ownership and descriptor lifetime use the production upper close paths.
    operations = SimpleNamespace(
        name="posix",
        O_RDWR=os.O_RDWR,
        O_NOFOLLOW=0,
        O_NONBLOCK=0,
        open=os.open,
        close=os.close,
        set_inheritable=os.set_inheritable,
        geteuid=lambda: 0,
        fstat=lambda fd: SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_nlink=1, st_uid=0),
    )
    monkeypatch.setattr(host_runtime, "os", operations)
    monkeypatch.setitem(
        sys.modules, "fcntl", SimpleNamespace(flock=lambda *args: None, LOCK_EX=1, LOCK_NB=2)
    )

    def incomplete(*args, **kwargs):
        raise _HostCleanupIncomplete(original) from cause

    monkeypatch.setattr(host_runtime, "HostAuthority", incomplete)
    with pytest.raises(_HostCleanupIncomplete) as failed:
        ManagedToolHost(profile, operator=original.operator)
    host = failed.value.cleanup_owner
    descriptor = host._lock_fd
    os.fstat(descriptor)
    assert failed.value.__cause__ is cause and host._closed and host.shutdown_requested.is_set()
    with pytest.raises(_HostCleanupIncomplete):
        failed.value.retry_cleanup()
    os.fstat(descriptor)
    assert controls == []
    failed.value.retry_cleanup()
    assert host._cleanup_complete and host._lock_fd is None and controls == ["released"]


def test_evaluator_cannot_replace_a_live_cleanup_owner_with_a_json_failure_report(
    tmp_path, monkeypatch
):
    from ordin_swarm import host_evaluation

    attempts = []
    owner = SimpleNamespace(close=lambda: attempts.append("cleanup"))
    failure = _HostCleanupIncomplete(owner)

    def incomplete(*args, **kwargs):
        raise failure

    monkeypatch.setattr(host_evaluation, "_run_evaluation", incomplete)
    with pytest.raises(_HostCleanupIncomplete) as observed:
        host_evaluation.run_evaluation(tmp_path / "new")
    assert observed.value is failure and observed.value.cleanup_owner is owner
    observed.value.retry_cleanup()
    assert attempts == ["cleanup"]


def test_failed_client_is_retained_while_other_clients_and_authority_are_attempted(tmp_path):
    from ordin_swarm.host_runtime import _Client

    original, controls = authority()
    original.auth.close = lambda channel: None
    host = host_with_lock(tmp_path, original)
    descriptor = host._lock_fd
    prior_result = host._approvals["unknown"].result

    class Socket:
        def __init__(self, fail=False):
            self.fail, self.alive, self.attempts = fail, True, 0

        def shutdown(self, how):
            pass

        def close(self):
            self.attempts += 1
            if self.fail and self.attempts == 1:
                raise OSError("original socket still alive")
            self.alive = False

        def fileno(self):
            return 99 if self.alive else -1

    broken, healthy = Socket(True), Socket()
    first, second = HostClient("broken"), HostClient("healthy")
    row = _Client(broken, "reader", object())
    host._clients = {first: row, second: _Client(healthy, "writer", object())}
    with pytest.raises(_HostCleanupIncomplete) as failed:
        host.close()
    assert host._clients.get(first) is row and row.closing and broken.alive
    assert second not in host._clients and not healthy.alive
    assert original.backend.attempts == 1 and controls == []
    os.fstat(descriptor)
    with pytest.raises(ValueError):
        host.require_client(first)
    failed.value.retry_cleanup()
    assert broken.attempts == 2 and not broken.alive and not host._clients
    assert healthy.attempts == 1 and original.backend.attempts == 2
    assert host._cleanup_complete and host._lock_fd is None and controls == ["released"]
    assert host._approvals["unknown"].result is prior_result
    host.close()
    assert broken.attempts == 2 and healthy.attempts == 1


def test_cli_api_preserves_owner_and_console_supervises_cleanup_without_effect_replay(
    tmp_path, monkeypatch, capsys
):
    import json
    from ordin_swarm import host_cli

    calls = []

    class Owner:
        attempts = 0

        def close(self):
            self.attempts += 1
            if self.attempts == 1:
                raise KeyboardInterrupt
            if self.attempts < 3:
                raise _HostCleanupIncomplete(self) from RuntimeError("private child diagnostic")

    owner = Owner()
    cause = ValueError("private construction cause")
    failure = _HostCleanupIncomplete(owner)

    def fail_doctor(*args, **kwargs):
        calls.append("effect")
        raise failure from cause

    monkeypatch.setattr(host_cli, "doctor", fail_doctor)
    arguments = ["doctor", "--directory", str(tmp_path)]
    with pytest.raises(_HostCleanupIncomplete) as propagated:
        host_cli.main(arguments)
    assert propagated.value is failure and propagated.value.__cause__ is cause
    assert propagated.value.cleanup_owner is owner and owner.attempts == 0
    assert capsys.readouterr().err == ""
    pauses = []
    monkeypatch.setattr(host_cli.time, "sleep", pauses.append)
    monkeypatch.setattr(host_cli.signal, "signal", lambda *args: None)
    before = len(calls)
    assert host_cli.entrypoint(arguments) == 2
    assert calls[before:] == ["effect"]  # One command; only cleanup repeats.
    assert owner.attempts == 3 and calls == ["effect", "effect"]
    assert pauses == [0.25, 0.25]
    output = capsys.readouterr()
    assert output.out == "" and "private" not in output.err
    messages = [json.loads(line) for line in output.err.splitlines()]
    assert [message["status"] for message in messages] == ["cleanup_incomplete", "cleanup_complete"]
    assert messages[-1]["original_command_failed"] is True
