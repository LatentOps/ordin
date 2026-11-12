"""Actual Linux deployment: fresh PKI, shared TLS, human queue and durable restart."""

import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from threading import Thread
from types import SimpleNamespace

import pytest

pytest.importorskip("ordin_swarm")

from ordin_swarm.host_cli import _initialize_connection, _rpc, initialize
from ordin_swarm.host_authority import _HostCleanupIncomplete
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


@pytest.mark.parametrize("report_fails", [False, True])
def test_scripted_cli_server_construction_failure_closes_original_host(
    tmp_path, monkeypatch, report_fails
):
    module = sys.modules[__name__]
    closed = []
    host = SimpleNamespace(close=lambda: closed.append(True))
    construction_error = OSError("controlled server construction failure")
    monkeypatch.setattr(module, "initialize", lambda *args, **kwargs: None)
    monkeypatch.setattr(module, "load_host_profile", lambda *args: object())
    monkeypatch.setattr(module, "ManagedToolHost", lambda *args, **kwargs: host)

    def fail_construction(*args, **kwargs):
        raise construction_error

    def record(*args):
        if report_fails:
            raise OSError("controlled JUnit property failure")

    monkeypatch.setattr(module, "ManagedHostServer", fail_construction)
    with pytest.raises(OSError) as failure:
        test_scripted_installed_operator_cli_write_idempotency_and_real_expiry(
            tmp_path, set(), record
        )
    assert failure.value is construction_error
    assert closed == [True]


@pytest.mark.parametrize("stage", ["host", "server"])
def test_scripted_cli_preserves_acquisition_cleanup_owner(tmp_path, monkeypatch, stage):
    module = sys.modules[__name__]
    original = _HostCleanupIncomplete(object())
    closed = []

    def close():
        closed.append(True)
        raise OSError("controlled secondary host close failure")

    def host_factory(*args, **kwargs):
        if stage == "host":
            raise original
        return SimpleNamespace(close=close)

    def server_factory(*args, **kwargs):
        raise original

    def record(*args):
        raise OSError("controlled JUnit property failure")

    monkeypatch.setattr(module, "initialize", lambda *args, **kwargs: None)
    monkeypatch.setattr(module, "load_host_profile", lambda *args: object())
    monkeypatch.setattr(module, "ManagedToolHost", host_factory)
    monkeypatch.setattr(module, "ManagedHostServer", server_factory)
    with pytest.raises(_HostCleanupIncomplete) as failure:
        test_scripted_installed_operator_cli_write_idempotency_and_real_expiry(
            tmp_path, set(), record
        )
    assert failure.value is original
    assert failure.value.cleanup_owner is original.cleanup_owner
    assert closed == ([] if stage == "host" else [True])


@pytest.mark.parametrize("fault", ["write", "property", "size", "join", "alive"])
def test_scripted_cli_preserves_original_cleanup_custody(tmp_path, monkeypatch, fault):
    module = sys.modules[__name__]
    host = SimpleNamespace(close=lambda: None)
    server = SimpleNamespace(port=1, run=lambda: None)
    original = _HostCleanupIncomplete(server)
    monkeypatch.setattr(module, "initialize", lambda *args, **kwargs: None)
    monkeypatch.setattr(module, "load_host_profile", lambda *args: object())
    monkeypatch.setattr(module, "ManagedToolHost", lambda *args, **kwargs: host)
    monkeypatch.setattr(module, "ManagedHostServer", lambda *args, **kwargs: server)

    def cleanup():
        raise original

    def stop_before_transport():
        raise ValueError("controlled stop before any connection")

    def join(*args, **kwargs):
        if fault == "join":
            raise OSError("controlled join failure")

    server.close = cleanup
    worker = SimpleNamespace(
        start=stop_before_transport, ident=1, join=join, is_alive=lambda: fault == "alive"
    )
    monkeypatch.setattr(module, "Thread", lambda **kwargs: worker)
    original_write = Path.write_text

    def write(path, *args, **kwargs):
        if fault == "write" and path.name == "scripted-operator-cli-timing.json":
            raise OSError("controlled timing file failure")
        return original_write(path, *args, **kwargs)

    def record(*args):
        if fault == "property":
            raise OSError("controlled JUnit property failure")

    monkeypatch.setattr(Path, "write_text", write)
    if fault == "size":
        monkeypatch.setattr(
            module, "json", SimpleNamespace(dumps=lambda *args, **kwargs: "x" * 20_000)
        )
    with pytest.raises(_HostCleanupIncomplete) as failure:
        test_scripted_installed_operator_cli_write_idempotency_and_real_expiry(
            tmp_path, set(), record
        )
    assert failure.value is original
    assert failure.value.cleanup_owner is server


@pytest.mark.skipif(sys.platform != "linux", reason="actual owned Linux worker boundary required")
def test_scripted_installed_operator_cli_write_idempotency_and_real_expiry(
    tmp_path, allowed_loopback, record_testsuite_property
):
    """Measure a finite scripted operator through ordinary installed CLI entrypoints."""
    tmp_path.chmod(0o700)
    root = tmp_path / "installation"
    source = tmp_path / "input.txt"
    source.write_text("Owned scripted operator source", encoding="utf-8")
    initialize(root, document(root), inputs=["document.txt=" + str(source)])
    operator = object()
    content = "Owned scripted operator approved report"
    replacement = "Owned scripted operator expired replacement"
    measurements = {
        "operator_kind": "scripted",
        "scripted_operator": True,
        "human_review_not_measured": True,
        "human_participants": 0,
        "request_lifetime_cap_seconds": 30,
        "workflow_completed": False,
        "requests": [],
        "commands": [],
    }
    settings = {
        key: value
        for key, value in os.environ.items()
        if key in {"PATH", "TMPDIR", "TMP", "TEMP", "LANG", "LC_ALL"}
    }
    settings.update(
        PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",
        LANGCHAIN_TRACING_V2="false",
        LANGSMITH_TRACING="false",
        OTEL_SDK_DISABLED="true",
    )

    def command(phase, action, *arguments):
        started = time.time()
        started_monotonic = time.monotonic()
        observation = {
            "phase": phase,
            "action": action,
            "started_at": started,
            "seconds_until_request_expiry": measurements["requests"][-1]["expires_at"] - started,
            "returncode": None,
            "response_status": None,
            "request_status": None,
            "fulfillment_status": None,
            "timed_out": False,
        }
        measurements["commands"].append(observation)
        try:
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    "-m",
                    "ordin_swarm.host_cli",
                    "operator",
                    "--directory",
                    str(root),
                    action,
                    *arguments,
                ],
                cwd=tmp_path,
                env=settings,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=45,
                check=False,
            )
        except subprocess.TimeoutExpired:
            observation["timed_out"] = True
            raise
        finally:
            observation.update(
                finished_at=time.time(),
                elapsed_ms=round((time.monotonic() - started_monotonic) * 1000, 3),
                seconds_until_request_expiry_at_finish=(
                    measurements["requests"][-1]["expires_at"] - time.time()
                ),
            )
        observation["returncode"] = result.returncode
        for private_text in (source.read_text(), content, replacement):
            assert private_text.encode() not in result.stdout + result.stderr
        response = json.loads(result.stdout)
        data = response.get("data", {})
        observation.update(
            response_status=response.get("status"),
            request_status=data.get("request", {}).get("status"),
            fulfillment_status=data.get("fulfillment", {}).get("status"),
            reason_codes=response.get("reason_codes", []),
        )
        return result.returncode, response

    host = server = worker = None
    try:
        host = ManagedToolHost(
            load_host_profile(root), operator=operator, policy_epoch=0, initialize_scope=True
        )
        server = ManagedHostServer(host, operator=operator, port=0)
        allowed_loopback.add(server.port)
        worker = Thread(target=server.run, daemon=True)
        worker.start()
        with connect(root / "clients" / "writer") as writer:
            _initialize_connection(writer)
            proposal_started = time.time()
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
            proposal_returned = time.time()
            remaining = proposal["data"]["expires_at"] - proposal_returned
            measurements["requests"].append(
                {
                    "phase": "accepted",
                    "proposal_started_at": proposal_started,
                    "proposal_returned_at": proposal_returned,
                    "expires_at": proposal["data"]["expires_at"],
                    "remaining_at_return_seconds": remaining,
                }
            )
            assert 0 < remaining <= 30
            code, queued = command("accepted", "queue")
            assert code == 0
            row = next(
                row
                for row in queued["data"]["requests"]
                if row["request"]["request_id"] == reference
            )
            assert row["status"] == "pending"
            measurements["commands"][-1]["request_status"] = row["status"]
            preview = tmp_path / "accepted-preview.json"
            code, public_preview = command(
                "accepted",
                "show",
                "--request-ref",
                reference,
                "--include-content",
                "--preview",
                str(preview),
            )
            assert code == 0 and public_preview["status"] == "private_output_written"
            shown = json.loads(preview.read_text())
            measurements["commands"][-1]["request_status"] = shown["data"]["request"]["status"]
            assert shown["data"]["proposal"]["content"] == content
            assert preview.stat().st_mode & 0o077 == 0
            binding = shown["data"]["expected_binding"]
            code, resolved = command(
                "accepted",
                "approve",
                "--request-ref",
                reference,
                "--expected-binding",
                binding,
                "--idempotency-key",
                "scripted-operator-vote",
            )
            assert code == 0 and resolved["data"]["request"]["status"] == "approved"
            result_file = tmp_path / "accepted-fulfillment.json"
            code, public_result = command(
                "accepted",
                "fulfill",
                "--request-ref",
                reference,
                "--expected-binding",
                binding,
                "--private-result",
                str(result_file),
            )
            assert code == 0 and public_result["status"] == "private_output_written"
            fulfilled = json.loads(result_file.read_text())["data"]["fulfillment"]
            measurements["commands"][-1]["fulfillment_status"] = fulfilled["status"]
            assert fulfilled["status"] == "completed" and fulfilled["physical_enforcement"] is True
            assert (root / "workspace" / "report.txt").read_text() == content
            code, repeated = command(
                "accepted",
                "fulfill",
                "--request-ref",
                reference,
                "--expected-binding",
                binding,
            )
            assert code == 0 and repeated["data"]["fulfillment"]["status"] == "completed"
            assert _call(writer, "approval_status", {"request_ref": reference}) == fulfilled
            snapshot = host._authority.backend.snapshot(
                str(root / "workspace" / "report.txt"), operator=operator
            )
            assert snapshot["version"] == 1

            proposal_started = time.time()
            proposal = _call(
                writer,
                "write_artifact",
                {
                    "name": "report.txt",
                    "content": replacement,
                    "expected_version": 1,
                    "expected_digest": hashlib.sha256(content.encode()).hexdigest(),
                },
            )
            assert proposal["status"] == "requires_approval"
            reference = proposal["data"]["request_ref"]
            expires = proposal["data"]["expires_at"]
            proposal_returned = time.time()
            remaining = expires - proposal_returned
            measurements["requests"].append(
                {
                    "phase": "expired",
                    "proposal_started_at": proposal_started,
                    "proposal_returned_at": proposal_returned,
                    "expires_at": expires,
                    "remaining_at_return_seconds": remaining,
                }
            )
            assert 0 < remaining <= 30
            # Exercise the real 30-second deadline without replacing the service clock.
            time.sleep(max(0, max(expires + 0.1, proposal_started + 30.1) - time.time()))
            measurements["requests"][-1]["observed_after_at"] = time.time()
            assert time.time() > expires and time.time() - proposal_started > 30
            code, queued = command("expired", "queue")
            assert code == 0
            row = next(
                row
                for row in queued["data"]["requests"]
                if row["request"]["request_id"] == reference
            )
            assert row["status"] == "expired"
            measurements["commands"][-1]["request_status"] = row["status"]
            preview = tmp_path / "expired-preview.json"
            code, _ = command(
                "expired",
                "show",
                "--request-ref",
                reference,
                "--include-content",
                "--preview",
                str(preview),
            )
            assert code == 0
            shown = json.loads(preview.read_text())
            measurements["commands"][-1]["request_status"] = shown["data"]["request"]["status"]
            assert shown["data"]["request"]["status"] == "expired"
            code, rejected = command(
                "expired",
                "approve",
                "--request-ref",
                reference,
                "--expected-binding",
                shown["data"]["expected_binding"],
                "--idempotency-key",
                "scripted-expired-vote",
            )
            assert code == 2 and rejected["data"]["request"]["status"] == "expired"
            assert (
                _call(writer, "approval_status", {"request_ref": reference})["status"] == "denied"
            )
            assert (root / "workspace" / "report.txt").read_text() == content
            assert (
                host._authority.backend.snapshot(
                    str(root / "workspace" / "report.txt"), operator=operator
                )["version"]
                == 1
            )
            measurements["workflow_completed"] = True
    finally:
        primary_error = sys.exc_info()[1]
        cleanup_error = primary_error if isinstance(primary_error, _HostCleanupIncomplete) else None
        try:
            if server is not None:
                server.close()
            elif host is not None:
                host.close()
        except BaseException as error:
            cleanup_error = cleanup_error or error
        try:
            if worker is not None:
                if worker.ident is not None:
                    worker.join(timeout=8)
                assert not worker.is_alive()
        except BaseException as error:
            cleanup_error = cleanup_error or error
        try:
            measurements["original_server_stopped"] = worker is None or not worker.is_alive()
            measurements["original_cleanup_completed"] = cleanup_error is None
            encoded = json.dumps(measurements, sort_keys=True)
            assert len(encoded.encode("utf-8")) <= 16_384
            record_testsuite_property("ordin.operator_usability.scripted.v1", encoded)
            (tmp_path / "scripted-operator-cli-timing.json").write_text(
                encoded + "\n", encoding="utf-8"
            )
        except BaseException:
            if cleanup_error is None and primary_error is None:
                raise
        if cleanup_error is not None:
            raise cleanup_error


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
