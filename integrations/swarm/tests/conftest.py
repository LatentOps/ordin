"""Conformance never uses hosted models, telemetry or runtime network access."""

import asyncio
import socket
import pytest

_RUNTIME_CONNECT = socket.socket.connect
_RUNTIME_CREATE_CONNECTION = socket.create_connection
_RUNTIME_BIND = socket.socket.bind
_RUNTIME_LISTEN = socket.socket.listen


@pytest.fixture
def owned_runtime_loopback(monkeypatch, no_runtime_network):
    """Explicit native fixtures may connect only to their live owned listeners."""
    bound, listeners = {}, {}

    def bind(connection, address):
        result = _RUNTIME_BIND(connection, address)
        endpoint = connection.getsockname()
        if connection.family == socket.AF_INET and endpoint[0] == "127.0.0.1":
            bound[connection] = endpoint
        return result

    def listen(connection, backlog=socket.SOMAXCONN):
        result = _RUNTIME_LISTEN(connection, backlog)
        endpoint = connection.getsockname()
        if bound.get(connection) == endpoint and endpoint[0] == "127.0.0.1":
            listeners[endpoint[1]] = connection
        return result

    def require_owned(address):
        if (
            type(address) is not tuple
            or len(address) != 2
            or address[0] != "127.0.0.1"
            or type(address[1]) is not int
        ):
            raise AssertionError("runtime fixture requires its own literal IPv4 loopback listener")
        listener = listeners.get(address[1])
        if listener is None or listener.fileno() < 0 or listener.getsockname() != address:
            raise AssertionError("runtime fixture endpoint is not a live owned listener")

    def connect(connection, address):
        require_owned(address)
        return _RUNTIME_CONNECT(connection, address)

    def create_connection(address, *args, **kwargs):
        require_owned(address)  # Reject hostnames before any resolver is called.
        return _RUNTIME_CREATE_CONNECTION(address, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "bind", bind)
    monkeypatch.setattr(socket.socket, "listen", listen)
    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket, "create_connection", create_connection)
    try:
        yield listeners
    finally:
        listeners.clear()
        bound.clear()


@pytest.fixture(autouse=True)
def no_runtime_network(monkeypatch, async_loop):
    for name, value in {
        "CREWAI_TELEMETRY_DISABLED": "true",
        "OTEL_SDK_DISABLED": "true",
        "ANONYMIZED_TELEMETRY": "false",
        "LANGSMITH_TRACING": "false",
        "LANGCHAIN_TRACING_V2": "false",
        "HF_HUB_OFFLINE": "1",
        "TRANSFORMERS_OFFLINE": "1",
        "DO_NOT_TRACK": "1",
        "AUTOGEN_DISABLE_RUNTIME_TRACING": "true",
    }.items():
        monkeypatch.setenv(name, value)
    for name in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "LANGSMITH_API_KEY"):
        monkeypatch.delenv(name, raising=False)

    def denied(*args, **kwargs):
        raise AssertionError("conformance attempted a runtime network connection")

    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket, "create_connection", denied)


@pytest.fixture
def async_loop():
    # Windows bootstraps its event-loop self-pipe with a local socketpair. Do
    # that before runtime networking is denied; SDK/model connections remain
    # denied throughout the actual coroutine execution.
    loop = asyncio.new_event_loop()
    try:
        yield loop
    finally:
        tasks = asyncio.all_tasks(loop)
        for task in tasks:
            task.cancel()
        if tasks:
            _, pending = loop.run_until_complete(asyncio.wait(tasks, timeout=1))
            assert not pending, "native async fixture left uncooperative tasks"
        loop.close()
