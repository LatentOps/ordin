"""Protocol conformance probes use no native authority or effect stand-ins."""

from threading import RLock
from types import SimpleNamespace

import pytest

pytest.importorskip("ordin_swarm")

from ordin_swarm.host_protocol import MCPHostSession
from ordin_swarm.host_runtime import HostClient, ManagedToolHost


@pytest.fixture
def protocol():
    # Exact classes are intentional; this fixture only exercises framing and
    # state transitions, never claims that a physical backend was established.
    host = object.__new__(ManagedToolHost)
    host.profile = SimpleNamespace(limits=SimpleNamespace(requests=4096))
    host._lock, host._protocol_ids = RLock(), set()
    host.require_client = lambda client: None
    host.close_client = lambda client: None
    host.tools = lambda client: []
    calls = []

    def call(client, tool, arguments, *, request_id):
        calls.append((client, tool, arguments, request_id))
        return {"status": "completed", "data": {}}

    host.call = call
    return host, calls


def message(request_id, method, params=None):
    value = {"jsonrpc": "2.0", "method": method}
    if request_id is not None:
        value["id"] = request_id
    if params is not None:
        value["params"] = params
    return value


def ready(host, name="one"):
    session = MCPHostSession(host, HostClient(name))
    result = session.handle(
        message(
            1,
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "offline", "version": "1"},
                "_meta": {},
            },
        )
    )
    assert result["result"]["protocolVersion"] == "2025-11-25"
    assert session.handle(message(None, "notifications/initialized", {"_meta": {}})) is None
    return session


def test_standard_optional_arguments_and_metadata_do_not_select_authority(protocol):
    host, calls = protocol
    session = ready(host)
    assert session.handle(message(2, "tools/list", {"_meta": {}}))["result"] == {"tools": []}
    output = session.handle(
        message(3, "tools/call", {"name": "receive", "_meta": {"progressToken": 1}})
    )
    assert output["result"]["isError"] is False
    assert calls[0][1:3] == ("receive", {})
    assert session.handle(message(4, "tools/list", {"cursor": "forged"}))["error"]["code"] == -32602
    assert session.handle(message(5, "tools/call", {"name": "receive", "actor": "operator"}))[
        "error"
    ]
    assert len(calls) == 1


def test_notifications_are_strict_and_never_execute_tools(protocol):
    host, calls = protocol
    session = ready(host)
    for params in ({"name": "write_artifact", "arguments": {}}, {}):
        with pytest.raises(ValueError):
            session.handle(message(None, "tools/call", params))
    with pytest.raises(ValueError):
        session.handle(message(None, "notifications/cancelled", {"requestId": True}))
    assert (
        session.handle(message(None, "notifications/cancelled", {"requestId": 3, "reason": "gone"}))
        is None
    )
    assert calls == []


def test_replay_history_is_shared_and_bounded_across_connections(protocol):
    host, _ = protocol
    first, second = ready(host), ready(host, "two")
    assert first.handle(message(1, "ping"))["error"]["code"] == -32600
    for request_id in range(2, 4096):
        first.handle(message(request_id, "ping"))
    assert len(host._protocol_ids) == 4096
    with pytest.raises(ValueError, match="global_request"):
        second.handle(message(2, "ping"))
    assert len(host._protocol_ids) == 4096
