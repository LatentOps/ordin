"""Connection setup failures keep cleanup custody without exhausting admission."""

from contextlib import nullcontext
from threading import BoundedSemaphore, Event, RLock
from types import SimpleNamespace

import pytest

pytest.importorskip("ordin_swarm")

from ordin_swarm.host_authority import _HostCleanupIncomplete
from ordin_swarm.host_protocol import MCPHostSession
from ordin_swarm.host_runtime import HostClient, ManagedToolHost, _Client
from ordin_swarm.host_service import ManagedHostServer


@pytest.mark.parametrize("setup_failure", ["session", "input", "output"])
@pytest.mark.parametrize("close_failures", [1, 2])
def test_failed_client_cleanup_releases_connection_slot_and_keeps_original_retry_owner(
    setup_failure, close_failures
):
    class Transport:
        def __init__(self, *, secure=False):
            self.secure, self.open, self.closes, self.streams = secure, True, 0, []

        def settimeout(self, seconds):
            pass

        def shutdown(self, how):
            pass

        def fileno(self):
            return 42 if self.open else -1

        def close(self):
            self.closes += 1
            if self.secure and self.closes <= close_failures:
                raise OSError("private original socket close failure")
            self.open = False

        def makefile(self, mode):
            self.streams.append(mode)
            if mode == ("rb" if setup_failure == "input" else "wb"):
                raise OSError("private original stream setup failure")
            return nullcontext(object())

    raw, secure = Transport(), Transport(secure=True)
    host = object.__new__(ManagedToolHost)
    host._lock = RLock()
    host.shutdown_requested = Event()
    host.profile = SimpleNamespace(limits=SimpleNamespace(requests=64))
    client = HostClient("original")
    row = _Client(secure, "reader", object())
    host._clients, host._approvals = {client: row}, {}
    host._authority = SimpleNamespace(
        pki=SimpleNamespace(
            server_context=SimpleNamespace(wrap_socket=lambda *args, **kwargs: secure)
        ),
        expires_at=100,
        clock=lambda: 0,
        control_phase=lambda: nullcontext(),
        auth=SimpleNamespace(close=lambda channel: None),
    )
    host.bind_connection = lambda *args, **kwargs: client

    def require_client(selected):
        if setup_failure == "session":
            raise ValueError("original client changed before protocol construction")
        return row

    host.require_client = require_client
    server = object.__new__(ManagedHostServer)
    server.host, server._operator = host, object()
    server._lock = RLock()
    server._sockets = {raw}
    server._slots = BoundedSemaphore(1)
    assert server._slots.acquire(blocking=False)

    # Exercise real client close bookkeeping and both real setup-failure paths.
    with pytest.raises(_HostCleanupIncomplete) as failed:
        server._connection(raw)

    assert server._slots.acquire(blocking=False), "failed cleanup leaked admission capacity"
    with pytest.raises(ValueError):
        server._slots.release()
        server._slots.release()
    assert not raw.open and secure.open is (close_failures == 2)
    assert raw not in server._sockets
    assert (secure in server._sockets) is (close_failures == 2)
    assert not host.shutdown_requested.is_set()
    assert failed.value.cleanup_owner is host
    assert host._clients[client] is row and row.closing
    # The failed original row is still owned, even after the raw sockets close.
    host.close_client(client)
    assert host._clients == {} and secure.closes == 3


def test_protocol_close_retries_original_client_cleanup_without_reopening_admission():
    host = object.__new__(ManagedToolHost)
    host.profile = SimpleNamespace(limits=SimpleNamespace(requests=64))
    host.require_client = lambda client: None
    attempts = []

    def close_client(client):
        attempts.append(client)
        if len(attempts) == 1:
            raise _HostCleanupIncomplete(host)

    host.close_client = close_client
    client = HostClient("original")
    session = MCPHostSession(host, client)
    with pytest.raises(_HostCleanupIncomplete):
        session.close()
    with pytest.raises(ValueError, match="closed"):
        session.handle({"jsonrpc": "2.0", "id": 1, "method": "ping"})
    session.close()
    session.close()
    assert attempts == [client, client]


@pytest.mark.parametrize("failure", [None, OSError, KeyboardInterrupt])
def test_handshake_failure_keeps_failed_raw_transport_tracked_and_releases_one_slot(failure):
    class RawTransport:
        closes = 0

        def settimeout(self, seconds):
            pass

        def close(self):
            self.closes += 1
            if failure is not None:
                raise failure("original transport close failure")

    def handshake(*args, **kwargs):
        raise OSError("original TLS handshake failed")

    raw = RawTransport()
    server = object.__new__(ManagedHostServer)
    server.host = SimpleNamespace(
        _authority=SimpleNamespace(
            pki=SimpleNamespace(server_context=SimpleNamespace(wrap_socket=handshake))
        )
    )
    server._lock, server._sockets = RLock(), {raw}
    server._slots = BoundedSemaphore(1)
    assert server._slots.acquire(blocking=False)
    if failure is None:
        server._connection(raw)
    else:
        with pytest.raises(failure):
            server._connection(raw)
    assert raw.closes == 1
    assert (raw in server._sockets) is (failure is not None)
    assert server._slots.acquire(blocking=False)
    server._slots.release()
    with pytest.raises(ValueError):
        server._slots.release()


def test_normal_stdio_eof_closes_the_client_and_releases_one_connection_slot():
    from io import BytesIO

    class Transport:
        def __init__(self):
            self.open, self.closes = True, 0

        def settimeout(self, seconds):
            pass

        def shutdown(self, how):
            pass

        def fileno(self):
            return 42 if self.open else -1

        def close(self):
            self.open = False
            self.closes += 1

        def makefile(self, mode):
            return BytesIO()

    raw, secure = Transport(), Transport()
    host = object.__new__(ManagedToolHost)
    host._lock = RLock()
    host.profile = SimpleNamespace(limits=SimpleNamespace(requests=64))
    client = HostClient("original")
    host._clients, host._approvals = {client: _Client(secure, "reader", object())}, {}
    host.require_client = lambda selected: host._clients[selected]
    host.bind_connection = lambda *args, **kwargs: client
    host._authority = SimpleNamespace(
        pki=SimpleNamespace(
            server_context=SimpleNamespace(wrap_socket=lambda *args, **kwargs: secure)
        ),
        expires_at=100,
        clock=lambda: 0,
        control_phase=lambda: nullcontext(),
        auth=SimpleNamespace(close=lambda channel: None),
    )
    server = object.__new__(ManagedHostServer)
    server.host, server._operator = host, object()
    server._lock, server._sockets = RLock(), {raw}
    server._slots = BoundedSemaphore(1)
    assert server._slots.acquire(blocking=False)
    server._connection(raw)
    assert not host._clients and not server._sockets
    assert not raw.open and not secure.open and raw.closes == 1 and secure.closes == 2
    assert server._slots.acquire(blocking=False)
    server._slots.release()
    with pytest.raises(ValueError):
        server._slots.release()
