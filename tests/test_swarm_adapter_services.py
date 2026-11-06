"""Original typed data services, reversible setup and real authenticated JSON."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import json
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "integrations/swarm"))
from ordin_swarm.sdk import SwarmSDK
from ordin_swarm.data_bridge import FrameworkDataBridge, FrameworkData
from ordin_swarm.cli import setup, uninstall, main, MANIFEST
from ordin_swarm.protocol import FrameworkJSONClient
from ordin import AgentGate
from ordin.swarm import (
    SwarmGate,
    SwarmToolGateway,
    SwarmArtifactGateway,
    MemoryArtifactStore,
    ArtifactAddress,
)
from ordin.swarm.coordinator_rpc import CoordinatorEndpoint
from tests.test_swarm_messages import configured
from tests.test_swarm_source_flow import root


def test_original_sdk_message_and_artifact_handoff_preserve_sensitive_lineage():
    messages, flow, hosts, event, inboxes, peers, data = configured(private_to_b=True)
    operator = flow._operator
    sdk = SwarmSDK(operator=operator)
    registry, events, contexts, sources, channels, adapters, _, _ = data
    gateway = SwarmToolGateway(events=events, clock=lambda: 100)
    gate = SwarmGate(registry, AgentGate(), events=events)
    sessions = {}
    for name in ("a", "b", "c"):
        native = object()
        sessions[name] = sdk.bind(
            native,
            contexts[name],
            gate,
            channels[name],
            adapters[name],
            gateway=gateway,
            identify=lambda native=native: native,
            operator=operator,
        )
    artifacts = SwarmArtifactGateway(
        flow,
        backend=MemoryArtifactStore(),
        operator=operator,
        workspaces=("work",),
        clock=lambda: 100,
    )
    bridge = FrameworkDataBridge(sdk, flow, operator=operator)
    for name in sessions:
        bridge.bind(
            sessions[name],
            sources[name],
            operator=operator,
            messages=messages,
            peer=peers[name],
            artifacts=artifacts,
        )
    value = "SYNTHETIC_PRIVATE_DATA"
    lineage = root(flow, hosts, event, sources, text=value)
    captured = bridge.capture(sessions["a"], lineage, value, operator=operator)
    address = ArtifactAddress(
        contexts["a"].identity.tenant_id,
        contexts["a"].identity.swarm_id,
        "work",
        "artifacts",
        "report",
    )
    artifacts.write(sources["a"], address, value, expected_version=0, inputs=(lineage,))
    read = bridge.read_artifact(sessions["a"], address)
    channel = messages.grant(peers["a"], peers["b"], sink_id="to-b")
    received = bridge.send(sessions["a"], sessions["b"], channel, read)
    assert (
        bridge.value(sessions["b"], received) == value
        and inboxes["b"][0].instruction_authority == "data"
    )
    use = bridge.use(sessions["b"], received, ("parameters", "body", "value"))
    assert flow._record(use.handle).sensitivity.labels == ("secret",)
    assert (
        data[6].build().reachable(flow._record(lineage).event_id, flow._record(use.handle).event_id)
    )
    for session, token in (
        (sessions["a"], received),
        (sessions["b"], FrameworkData(received.data_id)),
    ):
        with pytest.raises(ValueError):
            bridge.value(session, token)
    with pytest.raises(ValueError):
        bridge.capture(sessions["a"], lineage, "changed", operator=operator)
    with pytest.raises(ValueError):
        bridge.capture(sessions["a"], lineage, value, operator=object())
    denied = messages.grant(peers["b"], peers["c"], sink_id="to-c")
    with pytest.raises(ValueError):
        bridge.send(sessions["b"], sessions["c"], denied, received)
    assert not inboxes["c"] and value not in repr(captured)


def test_setup_is_dry_reversible_no_overwrite_and_never_runtime_authority(tmp_path, capsys):
    first = setup("custom", directory=tmp_path)
    assert first["dry_run"] and not (tmp_path / MANIFEST).exists()
    installed = setup("custom", directory=tmp_path, dry_run=False)
    assert not installed["runtime_installed"]
    original = (tmp_path / MANIFEST).read_bytes()
    with pytest.raises(ValueError):
        setup("custom", directory=tmp_path, dry_run=False)
    with pytest.raises(ValueError):
        uninstall("custom", directory=tmp_path, expected_digest="0" * 64)
    assert (tmp_path / MANIFEST).read_bytes() == original
    assert uninstall("custom", directory=tmp_path, expected_digest=installed["manifest_digest"])[
        "removed"
    ]
    assert main(["doctor", "--framework", "custom"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert not report["connected"] and not report["physical_enforcement"]


def test_framework_json_uses_real_tls_roles_and_original_online_scope(tmp_path):
    from tests.test_swarm_coordinator import configured as coordinator_fixture
    from tests.assurance.test_delegating_gate import action
    from ordin.swarm.coordinator_store import CoordinatorRejected

    with coordinator_fixture(tmp_path) as data:
        endpoint = CoordinatorEndpoint(data["coordinator"], data["scope"])
        server, client = data["sockets"]["child"]
        wire = FrameworkJSONClient(client)
        with ThreadPoolExecutor(max_workers=1) as pool:

            def serve(count):
                for _ in range(count):
                    endpoint.serve_one(server)

            pending = pool.submit(serve, 2)
            reserved = wire.prepare(
                lease=data["leases"]["child"].reference,
                grant=data["references"]["child"],
                action=action("framework-json"),
                idempotency_key="framework-json",
            )
            pending.result(timeout=10)
            assert reserved["status"] == "reserved" and not reserved["execution_authority"]
            pending = pool.submit(serve, 1)
            with pytest.raises(CoordinatorRejected):
                wire.request("dispatch", reservation=reserved["reference"])
            pending.result(timeout=10)
    with pytest.raises(ValueError):
        FrameworkJSONClient(object())
    assert not FrameworkJSONClient.contract()["callbacks_over_wire"]


def test_custom_runtime_live_routing_adopts_original_gateway_and_restores_dispatch():
    from tests.test_swarm_attach import ExistingHost, fixture, endpoint
    from ordin_swarm.adapters.custom import CustomRuntimeAdapter
    from ordin import ActionEnvelope

    registry, _, _, manager, _ = fixture()
    native = ExistingHost("live")
    original_thread = native.thread.ident
    adapter = CustomRuntimeAdapter(manager, endpoint(registry, native))
    operator = object()
    sdk = SwarmSDK(operator=operator)
    try:
        assert adapter.setup()["dry_run"] and native.router is None
        assert adapter.setup(dry_run=False)["state"] == "attached"
        session = adapter.bind_sdk(sdk, operator=operator)
        context = sdk.context(session)
        assert context is manager.context(adapter.handle)[0]
        tool = sdk.register_tool(
            session,
            name="read",
            runtime="custom",
            callback=lambda args: "ok",
            guard=lambda: None,
            action_builder=lambda args: ActionEnvelope.shell("git status"),
            route="shell",
            operator=operator,
        )
        assert sdk.invoke(session, tool, {}, request_id="live") == "ok"
        assert native.call("rm -rf /").disposition == "deny"
        assert native.thread.ident == original_thread and not native.calls
        sdk.close(session)
        assert native.router is None and adapter.status()["state"] == "detached"
        with pytest.raises(ValueError):
            sdk.context(session)
    finally:
        adapter.close()
        native.close()
