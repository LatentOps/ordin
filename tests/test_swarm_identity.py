from concurrent.futures import ThreadPoolExecutor
from copy import copy
from dataclasses import FrozenInstanceError, replace
import json
import subprocess
import sys
from threading import Barrier

import pytest

from ordin.action import ActionEnvelope
from ordin.schema import resource_parity_errors, validate_named_schema
from ordin.swarm import (
    CoverageEntry,
    CoverageManifest,
    HostChannel,
    InMemoryAgentRegistry,
    SwarmContext,
)


def host(**options):
    now = [100.0]
    registry = InMemoryAgentRegistry("tenant", "swarm", clock=lambda: now[0], **options)
    adapter = object()
    channel = registry.bind_channel(adapter, runtime_id="python")
    return registry, adapter, channel, now


def enroll(registry, adapter, channel, agent="a", **options):
    return registry.enroll(
        channel, adapter, agent_id=agent, session_id=f"session-{agent}", **options
    )


def test_two_running_agents_have_distinct_host_channels_and_sessions():
    registry = InMemoryAgentRegistry("tenant", "swarm")
    processes = [
        subprocess.Popen(
            [sys.executable, "-c", "import sys; sys.stdin.readline()"], stdin=subprocess.PIPE
        )
        for _ in range(2)
    ]
    try:
        channels = [registry.bind_channel(p, runtime_id="python") for p in processes]
        contexts = [
            enroll(registry, p, c, agent=str(i))
            for i, (p, c) in enumerate(zip(processes, channels))
        ]
        assert all(p.poll() is None for p in processes)
        assert len({c.identity.session_id for c in contexts}) == 2
        assert contexts[0].identity.generation < contexts[1].identity.generation
        for context, channel, process in zip(contexts, channels, processes):
            assert registry.authenticate(context, channel, process) is context
        with pytest.raises(ValueError):
            registry.authenticate(contexts[0], channels[1], processes[1])
    finally:
        for process in processes:
            try:
                process.communicate(b"done\n", timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=10)


def test_json_copies_and_parameter_claims_never_issue_principal_authority():
    registry, adapter, channel, _ = host()
    context = enroll(registry, adapter, channel)
    payload = context.as_dict()
    assert validate_named_schema("swarm_context", payload) == []
    restored = SwarmContext.from_dict(json.loads(json.dumps(payload)))
    assert restored.as_dict() == payload
    for candidate in (restored, replace(context), copy(context)):
        with pytest.raises(ValueError):
            registry.authenticate(candidate, channel, adapter)
    action = ActionEnvelope("tool", "call", {"agent_id": "victim", "tenant_id": "other"})
    original = action.as_dict()
    assert registry.authenticate(context, channel, adapter).identity.agent_id == "a"
    assert action.as_dict() == original
    assert "swarm" not in original
    assert resource_parity_errors() == []


def test_forged_adapter_channel_cross_scope_and_changed_identity_are_rejected():
    registry, adapter, channel, _ = host()
    context = enroll(registry, adapter, channel)
    for candidate in (copy(channel), HostChannel("tenant", "swarm", "python")):
        with pytest.raises(ValueError):
            registry.authenticate(context, candidate, adapter)
    with pytest.raises(ValueError):
        registry.authenticate(context, channel, object())
    for tenant, swarm in (("other", "swarm"), ("tenant", "other")):
        other = InMemoryAgentRegistry(tenant, swarm)
        other_channel = other.bind_channel(adapter, runtime_id="python")
        enroll(other, adapter, other_channel)
        with pytest.raises(ValueError):
            other.authenticate(context, other_channel, adapter)
    object.__setattr__(context.identity, "tenant_id", "changed")
    with pytest.raises(ValueError):
        registry.authenticate(context, channel, adapter)


def test_duplicate_principals_and_restarts_are_atomic():
    registry, adapter, channel, _ = host()
    barrier = Barrier(2)

    def attempt():
        barrier.wait(timeout=10)
        try:
            return enroll(registry, adapter, channel)
        except ValueError:
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: attempt(), range(2)))
    issued = [result for result in results if result is not None]
    assert len(issued) == 1
    old = issued[0]
    barrier = Barrier(2)

    def restart(session):
        barrier.wait(timeout=10)
        try:
            return registry.restart(
                old, channel, adapter, new_channel=channel, new_adapter=adapter, session_id=session
            )
        except ValueError:
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        restarted = list(executor.map(restart, ("restart-one", "restart-two")))
    assert sum(value is not None for value in restarted) == 1
    with pytest.raises(ValueError):
        registry.authenticate(old, channel, adapter)


def test_heartbeat_expiry_pause_end_and_restart_never_resurrect_old_context():
    registry, adapter, channel, now = host(heartbeat_timeout=10)
    context = enroll(registry, adapter, channel)
    now[0] = 109
    registry.heartbeat(context, channel, adapter)
    now[0] = 119
    assert registry.state(context, channel, adapter) == "stale"
    with pytest.raises(ValueError):
        registry.heartbeat(context, channel, adapter)
    with pytest.raises(ValueError):
        registry.restart(
            context,
            channel,
            adapter,
            new_channel=channel,
            new_adapter=adapter,
            session_id=context.identity.session_id,
        )
    fresh = registry.restart(
        context,
        channel,
        adapter,
        new_channel=channel,
        new_adapter=adapter,
        session_id="new-session",
    )
    assert fresh.identity.generation > context.identity.generation
    assert registry.authenticate(fresh, channel, adapter) is fresh
    registry.pause(fresh, channel, adapter)
    assert registry.state(fresh, channel, adapter) == "paused"
    with pytest.raises(ValueError):
        registry.authenticate(fresh, channel, adapter)
    registry.end(fresh, channel, adapter)
    assert registry.state(fresh, channel, adapter) == "ended"
    registry.forget_ended(fresh, channel, adapter)
    newer = enroll(registry, adapter, channel)
    assert newer.identity.generation > fresh.identity.generation
    for old in (context, fresh):
        with pytest.raises(ValueError):
            registry.authenticate(old, channel, adapter)


def test_parent_generation_and_policy_epoch_are_checked_at_every_use():
    registry, adapter, channel, _ = host()
    parent = enroll(registry, adapter, channel, "parent")
    child = enroll(
        registry, adapter, channel, "child", parent_agent_id="parent", delegation_id="grant"
    )
    registry.pause(parent, channel, adapter)
    assert registry.state(child, channel, adapter) == "stale"
    with pytest.raises(ValueError):
        registry.authenticate(child, channel, adapter)
    parent = registry.restart(
        parent, channel, adapter, new_channel=channel, new_adapter=adapter, session_id="parent-new"
    )
    with pytest.raises(ValueError):
        registry.authenticate(child, channel, adapter)
    child = registry.restart(
        child, channel, adapter, new_channel=channel, new_adapter=adapter, session_id="child-new"
    )
    assert child.identity.parent_generation == parent.identity.generation
    registry.advance_policy_epoch(1)
    for context in (parent, child):
        assert registry.state(context, channel, adapter) == "stale"
        with pytest.raises(ValueError):
            registry.authenticate(context, channel, adapter)
    for epoch in (0, 1, True):
        with pytest.raises(ValueError):
            registry.advance_policy_epoch(epoch)


def test_limits_and_channel_closure_do_not_drop_fences():
    registry, adapter, channel, _ = host(max_agents=1, max_channels=1)
    context = enroll(registry, adapter, channel)
    with pytest.raises(ValueError):
        enroll(registry, adapter, channel, "other")
    with pytest.raises(ValueError):
        registry.bind_channel(object(), runtime_id="other")
    with pytest.raises(ValueError):
        registry.forget_ended(context, channel, adapter)
    registry.close_channel(channel, adapter)
    new_channel = registry.bind_channel(adapter, runtime_id="python")
    fresh = enroll(registry, adapter, new_channel)
    assert fresh.identity.generation > context.identity.generation
    with pytest.raises(ValueError):
        registry.authenticate(context, new_channel, adapter)


def test_new_registry_rejects_old_context_even_with_identical_public_ids():
    first, adapter, channel, _ = host(registry_id="same-public-id")
    old = enroll(first, adapter, channel)
    second = InMemoryAgentRegistry(
        "tenant", "swarm", registry_id="same-public-id", clock=lambda: 100
    )
    current_channel = second.bind_channel(adapter, runtime_id="python")
    current = enroll(second, adapter, current_channel)
    assert current.as_dict() == old.as_dict()
    with pytest.raises(ValueError):
        second.authenticate(old, current_channel, adapter)
    assert second.authenticate(current, current_channel, adapter) is current


def test_parent_channel_changes_fence_a_child_on_an_independent_channel():
    registry, adapter, channel, _ = host()
    enroll(registry, adapter, channel, "parent")
    child_adapter = object()
    child_channel = registry.bind_channel(child_adapter, runtime_id="child-runtime")
    child = enroll(registry, child_adapter, child_channel, "child", parent_agent_id="parent")
    object.__setattr__(channel, "tenant_id", "changed")
    assert registry.state(child, child_channel, child_adapter) == "stale"
    with pytest.raises(ValueError):
        registry.authenticate(child, child_channel, child_adapter)


def test_schema_rejects_trailing_newlines_and_errors_do_not_echo_untrusted_content():
    registry, adapter, channel, _ = host()
    raw = enroll(registry, adapter, channel).as_dict()
    raw["identity"]["agent_id"] = "bad\n"
    assert validate_named_schema("swarm_context", raw)
    with pytest.raises(ValueError):
        SwarmContext.from_dict(raw)
    raw["identity"]["agent_id"] = "good"
    raw["coverage"]["mode"] = "private-canary-value"
    with pytest.raises(ValueError) as failure:
        SwarmContext.from_dict(raw)
    assert "private-canary-value" not in str(failure.value)


def test_encoded_context_limit_counts_multibyte_resources():
    registry, adapter, channel, _ = host()
    manifest = CoverageManifest(
        "observe",
        tuple(
            CoverageEntry("tool", f"route-{i}", "\U0001f642" * 512, "observer", "observe_only")
            for i in range(40)
        ),
    )
    with pytest.raises(ValueError, match="64 KiB"):
        enroll(registry, adapter, channel, coverage=manifest)
    assert enroll(registry, adapter, channel).identity.generation == 1


def test_deserializer_bounds_keys_and_rejects_container_enums_before_formatting_errors():
    class Unprintable(dict):
        def __repr__(self):
            raise AssertionError("untrusted container was formatted")

    registry, adapter, channel, _ = host()
    context = enroll(registry, adapter, channel)
    raw = context.as_dict()
    raw["x" * 129] = raw.pop("registry_id")
    with pytest.raises(ValueError, match="bounded.*keys"):
        SwarmContext.from_dict(raw)
    for field in ("mode", "state"):
        raw = context.as_dict()
        if field == "mode":
            raw["coverage"][field] = Unprintable()
        else:
            raw["coverage"]["entries"] = [
                {
                    "capability": "tool",
                    "route": "route",
                    "resource": "*",
                    "boundary_id": "host",
                    "state": Unprintable(),
                }
            ]
        with pytest.raises(ValueError, match="bounded text"):
            SwarmContext.from_dict(raw)


def test_late_enrollment_and_restart_keep_partial_coverage_explicit():
    registry, adapter, channel, now = host()
    manifest = CoverageManifest(
        "intercept",
        (
            CoverageEntry("tool.read", "mcp", "/workspace", "proxy", "mediated"),
            CoverageEntry("network", "direct", "*", "host", "coverage_gap"),
        ),
    )
    context = enroll(registry, adapter, channel, coverage=manifest)
    assert context.enrolled_at == now[0]
    assert context.as_dict()["coverage"]["entries"][1]["state"] == "coverage_gap"
    with pytest.raises(FrozenInstanceError):
        context.identity = context.identity
    snapshot = context.as_dict()
    snapshot["coverage"]["entries"].clear()
    assert len(context.coverage.entries) == 2
    fresh = registry.restart(
        context, channel, adapter, new_channel=channel, new_adapter=adapter, session_id="restarted"
    )
    assert fresh.coverage == CoverageManifest("uncovered")
    physical = CoverageManifest(
        "enforce", (CoverageEntry("network", "broker", "*", "unverified", "physically_enforced"),)
    )
    with pytest.raises(ValueError, match="broker receipt"):
        enroll(registry, adapter, channel, "physical", coverage=physical)


@pytest.mark.parametrize("value", ["", "a\n", "a b", "x" * 129, "../agent", None, 12])
def test_identifiers_are_bounded_and_malformed_ids_never_enroll(value):
    registry, adapter, channel, _ = host()
    with pytest.raises(ValueError):
        enroll(registry, adapter, channel, value)


def test_bad_clock_parent_depth_and_manifest_inputs_fail_closed():
    registry, adapter, channel, now = host(max_parent_depth=1)
    root = enroll(registry, adapter, channel)
    enroll(registry, adapter, channel, "child", parent_agent_id="a")
    with pytest.raises(ValueError):
        enroll(registry, adapter, channel, "grandchild", parent_agent_id="child")
    with pytest.raises(ValueError):
        enroll(registry, adapter, channel, "unknown-parent", parent_agent_id="missing")
    for invalid in (99, float("nan"), float("inf"), True, 10**1000):
        now[0] = invalid
        with pytest.raises(ValueError):
            registry.authenticate(root, channel, adapter)
    for mode, state in (
        ("observe", "mediated"),
        ("uncovered", "observe_only"),
        ("intercept", "physically_enforced"),
    ):
        with pytest.raises(ValueError):
            CoverageManifest(mode, (CoverageEntry("tool", "route", "*", "boundary", state),))
    raw = root.as_dict()
    raw["coverage"]["entries"] = [{}] * 65
    with pytest.raises(ValueError):
        SwarmContext.from_dict(raw)
