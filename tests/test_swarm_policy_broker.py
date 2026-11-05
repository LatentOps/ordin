"""Policy activation uses actual owned factory probes, never serialized readiness."""

from copy import copy
from dataclasses import replace

import pytest

from ordin import ActionEnvelope
from ordin.swarm import CoverageManifest
from ordin.swarm.authorization import BrokerActivationProof
from ordin.swarm.policy_compiler import SwarmPolicyMaximum
from ordin.swarm.policy_runtime import SwarmPolicyReplayCase, SwarmPolicyRuntime
from ordin.swarm.policy_set import (
    SwarmPolicyPermissions,
    SwarmPolicyResource,
    SwarmPolicySet,
    SwarmPolicyTool,
)
from tests.test_swarm_broker import fixture, require_kernel


def scoped_policy(target, *, required_capabilities=("broker.enforce",)):
    return SwarmPolicySet(
        "owned-reader",
        1,
        "tenant",
        "swarm",
        permissions=SwarmPolicyPermissions(
            action_kinds=("tool",),
            effects=("filesystem.read",),
            tools=(SwarmPolicyTool("tool", "fixture", "read_file"),),
            resources=(SwarmPolicyResource("path", str(target)),),
        ),
        default_disposition="execute",
        required_capabilities=required_capabilities,
        enforcement_scope="broker_owned_fresh_worker_route",
    )


def configured(data, selected):
    broker, _, _, _, action, _, _, _, _, _, clock, operator, _, _, registry = data
    maximum = SwarmPolicyMaximum("tenant", "swarm", selected.permissions)
    runtime = SwarmPolicyRuntime(registry, maximum, operator=operator, clock=lambda: clock[0])
    parent = registry._agents["parent"]
    context = parent.context
    return runtime, broker, registry, context, action, operator


def approved(runtime, broker, selected, context, action, operator):
    proof = broker.activation_proof(selected.digest, operator=operator)
    runtime.bind_enforcement(selected, broker, proof, operator=operator)
    proposal = runtime.prepare(selected)
    replay = (
        SwarmPolicyReplayCase("read", context, action, "benign"),
        SwarmPolicyReplayCase("destruction", context, ActionEnvelope.shell("rm -rf /"), "unsafe"),
    )
    simulation = runtime.simulate(proposal, replay, ordin=broker._gate._baseline.ordin)
    approval = runtime.approve(proposal, simulation, operator=operator)
    return approval, proof


def expire_factory_while_keeping_context_live(data, context):
    registry = data[14]
    row = registry._agents[context.identity.agent_id]
    data[10][0] += 29
    registry.heartbeat(context, row.channel, registry._channels[row.channel][0])
    data[10][0] += 2


def test_real_factory_can_activate_only_its_exact_route_and_never_grants_a_permit(tmp_path):
    require_kernel()
    with fixture(tmp_path) as data:
        selected = scoped_policy(data[13])
        runtime, broker, registry, old, action, operator = configured(data, selected)
        with pytest.raises(ValueError, match="capability unavailable"):
            runtime.prepare(selected)
        approval, proof = approved(runtime, broker, selected, old, action, operator)
        activation = runtime.activate(approval, operator=operator)
        assert activation.state == "active_requires_reenrollment"
        assert activation.as_dict()["physical_enforcement"] is False
        assert activation.as_dict()["execution_authority"] is False
        assert broker.verify_activation(proof, policy_digest=selected.digest)
        with pytest.raises(ValueError):
            with runtime.execution_guard(old, broker=broker):
                pytest.fail("old context survived activation")
        row = registry._agents["parent"]
        adapter = registry._channels[row.channel][0]
        context = registry.refresh_policy_context(
            old, row.channel, adapter, coverage=CoverageManifest("intercept")
        )
        with runtime.execution_guard(context, broker=broker):
            assert runtime.active_policy_digest == selected.digest
        # An ordinary callback cannot borrow the factory's capability.
        with pytest.raises(ValueError, match="original verified enforcing broker"):
            with runtime.execution_guard(context):
                pytest.fail("generic callback borrowed factory proof")
        assert not broker._pending
        assert not broker._service.issuer._pending


@pytest.mark.parametrize("fault", ("copy", "json", "policy", "operator", "expired"))
def test_factory_binding_rejects_nonoriginal_or_wrong_scope_proof(tmp_path, fault):
    require_kernel()
    with fixture(tmp_path) as data:
        selected = scoped_policy(data[13])
        runtime, broker, _, _, _, operator = configured(data, selected)
        proof = broker.activation_proof(selected.digest, operator=operator)
        if fault == "copy":
            proof = copy(proof)
        elif fault == "json":
            proof = {"proof_id": proof.proof_id, "physical_enforcement": True}
        elif fault == "policy":
            selected = replace(selected, revision=2)
        elif fault == "operator":
            operator = object()
        else:
            data[10][0] += 31
        with pytest.raises(ValueError):
            runtime.bind_enforcement(selected, broker, proof, operator=operator)
        assert not runtime._enforcement
        assert not broker._pending


def test_factory_readiness_expires_before_activation_and_while_policy_is_active(tmp_path):
    require_kernel()
    with fixture(tmp_path) as data:
        selected = scoped_policy(data[13])
        runtime, broker, registry, context, action, operator = configured(data, selected)
        approval, _ = approved(runtime, broker, selected, context, action, operator)
        expire_factory_while_keeping_context_live(data, context)
        with pytest.raises(ValueError, match="capability unavailable"):
            runtime.activate(approval, operator=operator)
        assert runtime.epoch == 0 and runtime.selection_digest is None
        approval, proof = approved(runtime, broker, selected, context, action, operator)
        runtime.activate(approval, operator=operator)
        row = registry._agents["parent"]
        context = registry.refresh_policy_context(
            context,
            row.channel,
            registry._channels[row.channel][0],
            coverage=CoverageManifest("intercept"),
        )
        before = runtime.binding_digest
        expire_factory_while_keeping_context_live(data, context)
        assert not broker.verify_activation(proof, policy_digest=selected.digest)
        assert runtime.binding_digest != before
        with pytest.raises(ValueError, match="original verified enforcing broker"):
            with runtime.execution_guard(context, broker=broker):
                pytest.fail("expired factory proof still enabled a route")


@pytest.mark.parametrize("fault", ("path", "tool", "write", "all_paths", "live_filesystem"))
def test_real_probe_cannot_attest_wider_paths_tools_effects_or_live_containment(tmp_path, fault):
    require_kernel()
    with fixture(tmp_path) as data:
        selected = scoped_policy(data[13])
        if fault == "path":
            selected = replace(
                selected,
                permissions=replace(
                    selected.permissions,
                    resources=(SwarmPolicyResource("path", str(data[13].parent)),),
                ),
            )
        elif fault == "tool":
            selected = replace(
                selected,
                permissions=replace(
                    selected.permissions,
                    tools=(SwarmPolicyTool("tool", "fixture", "write_file"),),
                ),
            )
        elif fault == "write":
            selected = replace(
                selected,
                permissions=replace(selected.permissions, effects=("filesystem.write",)),
            )
        elif fault == "all_paths":
            selected = replace(selected, enforcement_scope="all_agent_paths")
        else:
            selected = replace(selected, required_capabilities=("filesystem.enforce",))
        runtime, broker, _, _, _, operator = configured(data, selected)
        proof = broker.activation_proof(selected.digest, operator=operator)
        if fault == "live_filesystem":
            runtime.bind_enforcement(selected, broker, proof, operator=operator)
            with pytest.raises(ValueError, match="capability unavailable"):
                runtime.prepare(selected)
        else:
            with pytest.raises(ValueError):
                runtime.bind_enforcement(selected, broker, proof, operator=operator)
        assert not broker._pending


def test_serialized_factory_identifier_is_not_original_even_when_all_fields_match(tmp_path):
    require_kernel()
    with fixture(tmp_path) as data:
        selected = scoped_policy(data[13])
        runtime, broker, _, _, _, operator = configured(data, selected)
        proof = broker.activation_proof(selected.digest, operator=operator)
        with pytest.raises(ValueError):
            runtime.bind_enforcement(
                selected, broker, BrokerActivationProof(proof.proof_id), operator=operator
            )
