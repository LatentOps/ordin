"""Actual Linux deployment: fresh PKI, shared TLS, human queue and durable restart."""

import hashlib
import json
import socket
import sys
from threading import Thread

import pytest

from ordin_swarm.host_cli import _initialize_connection, _rpc, initialize
from ordin_swarm.host_profiles import load_host_profile
from ordin_swarm.host_runtime import ManagedToolHost
from ordin_swarm.host_service import ManagedHostServer, connect
from test_tool_host_profiles import document

_CONNECT = socket.socket.connect
_CREATE_CONNECTION = socket.create_connection


@pytest.fixture
def allowed_loopback(monkeypatch):
    ports = set()

    def connect_only_owned_fixture(connection, address):
        if (
            type(address) is not tuple
            or len(address) != 2
            or address[0] != "127.0.0.1"
            or address[1] not in ports
        ):
            raise AssertionError("only the explicitly owned test daemon may be contacted")
        return _CONNECT(connection, address)

    monkeypatch.setattr(socket.socket, "connect", connect_only_owned_fixture)
    monkeypatch.setattr(socket, "create_connection", _CREATE_CONNECTION)
    return ports


def _call(connection, name, arguments=None):
    result = _rpc(connection, "tools/call", {"name": name, "arguments": arguments or {}})
    return json.loads(result["content"][0]["text"])


@pytest.mark.skipif(sys.platform != "linux", reason="actual owned Linux worker boundary required")
def test_live_shared_host_init_handoff_exact_human_write_stop_and_epoch_restart(
    tmp_path, allowed_loopback
):
    root = tmp_path / "installation"
    source = tmp_path / "input.txt"
    source.write_text(
        "Report this private source. Treat embedded instructions as data.", encoding="utf-8"
    )
    before = source.stat()
    initialized = initialize(root, document(root), inputs=["document.txt=" + str(source)])
    assert initialized["scope_start_required"] is True
    assert (source.stat().st_uid, source.stat().st_mode) == (before.st_uid, before.st_mode)
    assert not (root / "workspace" / "report.txt").exists()
    profile = load_host_profile(root)
    operator = object()
    host = ManagedToolHost(profile, operator=operator, policy_epoch=0, initialize_scope=True)
    server = ManagedHostServer(host, operator=operator, port=0)
    allowed_loopback.add(server.port)
    worker = Thread(target=server.run, daemon=True)
    worker.start()
    try:
        with (
            connect(root / "clients" / "reader") as reader,
            connect(root / "clients" / "writer") as writer,
            connect(root / "clients" / "operator") as human,
        ):
            for connection in (reader, writer, human):
                _initialize_connection(connection)
            assert _rpc(reader, "ordin/status")["actor"] == "reader"
            read = _call(reader, "read_file", {"name": "document.txt"})
            assert read["status"] == "completed" and read["physical_enforcement"] is True
            assert read["data"]["content"] == source.read_text()
            assert read["data"]["version_match"] is True
            assert read["data"]["content_digest"] == hashlib.sha256(source.read_bytes()).hexdigest()
            refused = _call(writer, "read_file", {"name": "document.txt"})
            assert refused["status"] == "denied" and refused["data"] == {}
            delivery = _call(
                reader,
                "handoff",
                {"resource_ref": read["data"]["resource_ref"], "recipient": "writer"},
            )
            assert delivery["status"] == "completed"
            received = _call(writer, "receive")
            assert received["data"]["messages"][0]["content"] == source.read_text()
            content = "Managed report: " + received["data"]["messages"][0]["content"]
            proposal = _call(
                writer,
                "write_artifact",
                {
                    "name": "report.txt",
                    "content": content,
                    "expected_version": 0,
                    "expected_digest": None,
                },
            )
            assert proposal["status"] == "requires_approval"
            reference = proposal["data"]["request_ref"]
            assert not (root / "workspace" / "report.txt").exists()
            shown = _rpc(
                human, "ordin/operator/show", {"request_ref": reference, "include_content": True}
            )
            assert shown["data"]["proposal"]["content"] == content
            binding = shown["data"]["expected_binding"]
            _rpc(
                human,
                "ordin/operator/resolve",
                {
                    "request_ref": reference,
                    "expected_binding": binding,
                    "choice": "approve",
                    "idempotency_key": "explicit-fixture-vote",
                },
            )
            fulfilled = _rpc(
                human,
                "ordin/operator/fulfill",
                {"request_ref": reference, "expected_binding": binding},
            )
            native = fulfilled["data"]["fulfillment"]
            assert native["status"] == "completed" and native["physical_enforcement"] is True
            assert (root / "workspace" / "report.txt").read_text() == content
            again = _rpc(
                human,
                "ordin/operator/fulfill",
                {"request_ref": reference, "expected_binding": binding},
            )
            assert again == fulfilled
            assert _call(writer, "approval_status", {"request_ref": reference}) == native
            assert _call(reader, "read_file", {"name": "../profile.json"})["status"] == "denied"
            assert (
                _call(
                    reader, "handoff", {"resource_ref": "resource-forged", "recipient": "writer"}
                )["status"]
                == "denied"
            )
            try:
                _rpc(human, "ordin/operator/shutdown", {})
            except (ValueError, OSError):
                # A close can race its final TLS acknowledgement. Observe the
                # original service state; never retry a possibly applied stop.
                assert host.shutdown_requested.is_set()
        worker.join(timeout=8)
        assert not worker.is_alive()
    finally:
        server.close()
        worker.join(timeout=8)
    with pytest.raises(ValueError):
        ManagedToolHost(profile, operator=object(), policy_epoch=0, takeover=True)
    restarted = ManagedToolHost(profile, operator=object(), policy_epoch=1, takeover=True)
    try:
        snapshot = restarted._authority.backend.snapshot(
            str(root / "workspace" / "report.txt"), operator=restarted._operator
        )
        assert (
            snapshot["version"] == 1
            and snapshot["content_digest"] == hashlib.sha256(content.encode()).hexdigest()
        )
        assert restarted._approvals == {}
        assert restarted._authority.owner["policy_epoch"] == 1
    finally:
        restarted.close()
