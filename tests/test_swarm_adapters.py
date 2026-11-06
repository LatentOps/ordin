"""Custom-runtime SDK controls. Real framework conformance is a separate suite."""

from concurrent.futures import ThreadPoolExecutor
from copy import copy
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "integrations/swarm"))
from ordin_swarm.sdk import SwarmSDK, FrameworkCall, FrameworkSession, SwarmToolRefused
from ordin import AgentGate, Ordin, ToolResourceBinding, ToolSemanticRule, ToolSemanticsRegistry
from ordin.swarm import (
    CoverageManifest,
    InMemoryAgentRegistry,
    SwarmEventIngestor,
    SwarmGate,
    SwarmToolGateway,
)


class CustomRuntime:
    def __init__(self):
        self.current = self


def sdk_fixture(tmp_path, *, count=2, runtime="custom", builders=None):
    operator = object()
    sdk = SwarmSDK(operator=operator)
    registry = InMemoryAgentRegistry("tenant", "swarm", clock=lambda: 100)
    events = SwarmEventIngestor(registry)
    core = Ordin(
        tool_semantics=ToolSemanticsRegistry(
            "framework-fixture",
            "1",
            (
                ToolSemanticRule(
                    "read",
                    "tool",
                    "read_file",
                    ("filesystem.read",),
                    runtime=runtime,
                    resources=(ToolResourceBinding("path", "path"),),
                ),
            ),
        )
    )
    gate = SwarmGate(registry, AgentGate(core), events=events)
    gateway = SwarmToolGateway(events=events, clock=lambda: 100)
    runtimes, sessions, contexts, channels, adapters = [], [], [], [], []
    for index in range(count):
        native = CustomRuntime()
        adapter = object()
        channel = registry.bind_channel(adapter, runtime_id="framework" + str(index))
        context = registry.enroll(
            channel,
            adapter,
            agent_id="agent" + str(index),
            session_id="session" + str(index),
            task_id="task",
            coverage=CoverageManifest("intercept"),
        )
        session = sdk.bind(
            native,
            context,
            gate,
            channel,
            adapter,
            gateway=gateway,
            identify=lambda native=native: native.current,
            operator=operator,
        )
        runtimes.append(native)
        sessions.append(session)
        contexts.append(context)
        channels.append(channel)
        adapters.append(adapter)
    target = tmp_path / "public.txt"
    target.write_text("benign public result")
    return sdk, operator, registry, events, gateway, runtimes, sessions, contexts, target


def register_reader(data, *, callback=None, guard=None):
    sdk, operator, *_ = data
    return sdk.register_tool(
        data[6][0],
        name="read_file",
        runtime="custom",
        callback=callback or (lambda arguments: Path(arguments["path"]).read_text()),
        guard=guard or (lambda: None),
        operator=operator,
    )


def test_custom_runtime_exact_once_original_session_and_linked_outcome(tmp_path):
    data = sdk_fixture(tmp_path)
    sdk, _, _, events, _, _, sessions, _, target = data
    tool = register_reader(data)
    prepared = sdk.prepare(sessions[0], tool, {"path": str(target)}, request_id="one")
    assert prepared.disposition == "execute", prepared
    result = sdk.forward(sessions[0], prepared.call)
    assert result.value == "benign public result" and not result.physical_enforcement
    assert sdk.verify_result(result, prepared.call) and not sdk.verify_result(
        copy(result), prepared.call
    )
    assert events.snapshot()[-1].event.event_kind == "completed"
    assert events.snapshot()[-1].event.identity is data[7][0].identity
    with pytest.raises(ValueError):
        sdk.forward(sessions[0], prepared.call)
    with pytest.raises(ValueError):
        sdk.prepare(sessions[0], tool, {"path": str(target)}, request_id="one")


@pytest.mark.parametrize("change", ["arguments", "session", "handle", "epoch", "runtime"])
def test_spoof_stale_and_mutated_sdk_calls_fail_before_callback(tmp_path, change):
    data = sdk_fixture(tmp_path)
    sdk, _, registry, _, _, runtimes, sessions, _, target = data
    called = []
    tool = register_reader(data, callback=lambda args: called.append(args))
    prepared = sdk.prepare(sessions[0], tool, {"path": str(target)}, request_id="one")
    actor, call, arguments = sessions[0], prepared.call, None
    if change == "arguments":
        arguments = {"path": str(tmp_path / "other")}
    elif change == "session":
        actor = sessions[1]
    elif change == "handle":
        call = FrameworkCall(call.call_id)
    elif change == "epoch":
        registry.advance_policy_epoch(1)
    else:
        runtimes[0].current = CustomRuntime()
    with pytest.raises(ValueError):
        sdk.forward(actor, call, arguments=arguments)
    assert not called


def test_sdk_concurrent_replay_forwards_only_one_effect(tmp_path):
    data = sdk_fixture(tmp_path)
    sdk, _, _, _, _, _, sessions, _, target = data
    called = []
    tool = register_reader(data, callback=lambda args: called.append(args) or "ok")
    prepared = sdk.prepare(sessions[0], tool, {"path": str(target)}, request_id="one")

    def forward(_):
        try:
            return sdk.forward(sessions[0], prepared.call).status
        except ValueError:
            return "refused"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(forward, range(2)))
    assert sorted(results) == ["completed", "refused"] and len(called) == 1


def test_callback_failure_propagates_once_and_private_error_is_not_journaled(tmp_path):
    data = sdk_fixture(tmp_path)
    sdk, _, _, events, _, _, sessions, _, target = data
    failure = OSError("private synthetic upstream failure")

    def callback(arguments):
        raise failure

    tool = register_reader(data, callback=callback)
    prepared = sdk.prepare(sessions[0], tool, {"path": str(target)}, request_id="one")
    with pytest.raises(OSError) as caught:
        sdk.forward(sessions[0], prepared.call)
    assert caught.value is failure
    assert events.snapshot()[-1].event.event_kind == "failed"
    assert "private synthetic" not in str([v.event.as_dict() for v in events.snapshot()])


def test_unknown_tool_approval_and_forged_identity_never_become_authority(tmp_path):
    data = sdk_fixture(tmp_path)
    sdk, operator, _, _, _, _, sessions, _, _ = data
    unknown = sdk.register_tool(
        sessions[0],
        name="unknown_tool",
        runtime="unknown",
        callback=lambda a: pytest.fail("unreviewed effect"),
        guard=lambda: None,
        operator=operator,
    )
    with pytest.raises(SwarmToolRefused):
        sdk.invoke(sessions[0], unknown, {}, request_id="one")
    with pytest.raises(ValueError):
        sdk.context(FrameworkSession(sessions[0].binding_id))
    status = sdk.status(sessions[0])
    assert not status["physical_enforcement"] and "provider_transport" in status["uncovered"]
    sdk.close(sessions[0])
    with pytest.raises(ValueError):
        sdk.context(sessions[0])


@pytest.mark.parametrize(
    "value",
    ["x" * 65537, float("nan"), 1 << 80, {1: "not a JSON key"}, [0] * 4096, object()],
    ids=("oversize", "nonfinite", "large-integer", "invalid-key", "node-limit", "python-object"),
)
def test_sdk_refuses_unbounded_or_non_json_input_before_effect(tmp_path, value):
    data = sdk_fixture(tmp_path)
    sdk = data[0]
    tool = register_reader(data, callback=lambda args: pytest.fail("invalid input forwarded"))
    with pytest.raises(ValueError):
        sdk.prepare(data[6][0], tool, {"path": value}, request_id="invalid")
