"""Policy activation uses actual owned factory probes, never serialized readiness."""

from copy import copy
from contextlib import ExitStack, contextmanager
from dataclasses import replace

import pytest

from ordin import ActionEnvelope
from ordin.swarm import CoverageManifest
from ordin.swarm.broker import SwarmExecutionBroker
from ordin.swarm.gate import SwarmGate
from ordin.swarm.policy_facts import SwarmBudgetFact
from ordin.swarm.authorization import BrokerActivationProof
from ordin.swarm.policy_compiler import SwarmPolicyMaximum
from ordin.swarm.policy_runtime import SwarmPolicyReplayCase, SwarmPolicyRuntime
from ordin.swarm.policy_set import (
    SwarmPolicyPermissions,
    SwarmPolicyResource,
    SwarmPolicySet,
    SwarmPolicyTool,
    SwarmBudgetCondition,
    SwarmPolicyRule,
    SwarmPolicySelector,
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


@contextmanager
def current_policy_broker(data, selected, *, shared_clock=None):
    """Activate, then actually re-enroll fresh epoch sources over real TLS channels."""
    from ordin.assurance import DelegationIssuer
    from ordin.swarm.delegation import SwarmDelegationService
    from ordin.swarm.workload_auth import WorkloadAuthenticator
    from tests.test_swarm_delegation import fingerprint, server_context, tls_pair

    old_broker, old_service, old_budget, backend = data[:4]
    clock, operator, rights, registry = data[10], data[11], data[12], data[14]
    clock_fn = shared_clock or (lambda: clock[0])
    old_enrollments = {
        row.context.identity.agent_id: row
        for row in old_service.authenticator._enrollments.values()
        if row.context is not None
    }
    maximum = SwarmPolicyMaximum(
        "tenant",
        "swarm",
        selected.permissions,
        budget_limits=old_budget.policy.limits,
        delegation_maximum_digest=rights.digest,
    )
    runtime = SwarmPolicyRuntime(
        registry,
        maximum,
        operator=operator,
        clock=clock_fn,
        budget_ledger=old_budget,
        delegation_service=old_service,
        delegation_operator=operator,
    )
    approved_policy, _ = approved(
        runtime, old_broker, selected, old_enrollments["parent"].context, data[4], operator
    )
    activation = runtime.activate(approved_policy, operator=operator)
    ledger = activation.budget_ledger
    assert ledger is not None
    assert ledger.policy.policy_epoch == 1 and not activation.as_dict()["physical_enforcement"]
    contexts, sources = {}, {}
    for name, row in old_enrollments.items():
        contexts[name] = registry.refresh_policy_context(
            row.context,
            row.registry_channel,
            row.adapter,
            coverage=CoverageManifest("intercept"),
        )
        sources[name] = replace(row.source, epoch=1)
    issuer = DelegationIssuer(
        sources["parent"], old_service.issuer.profile, rights, rights, clock=clock_fn
    )
    root = issuer.authorize_root(rights, grant_id="fresh-root", expires_at=clock_fn() + 100)
    tls = server_context()
    auth = WorkloadAuthenticator(registry, tls, operator=operator, clock=clock_fn)
    service = SwarmDelegationService(issuer, old_service.assurance, auth, operator=operator)
    with ExitStack() as stack:
        enrollments, sockets = {}, {}
        for name, row in old_enrollments.items():
            enrollments[name] = auth.enroll_workload(
                host_id=row.host_id,
                certificate_digest=row.certificate_digest,
                context=contexts[name],
                source=sources[name],
                channel=row.registry_channel,
                adapter=row.adapter,
                operator=operator,
                runtime_identity=row.runtime_identity,
            )
            sockets[name] = stack.enter_context(tls_pair(tls, name))[0]
        auth.enroll_broker(
            host_id="host-b", certificate_digest=fingerprint("broker-b"), operator=operator
        )
        broker_socket = stack.enter_context(tls_pair(tls, "broker-b"))[0]
        root_ref = service.publish_root(enrollments["parent"], root, operator=operator)
        runtime.rebind_sources(
            operator=operator, delegation_service=service, delegation_operator=operator
        )

        def facts(context, action, current_runtime, baseline):
            row = registry._agents[context.identity.agent_id]
            report = ledger.report(
                context, channel=row.channel, adapter=registry._channels[row.channel][0]
            )
            return current_runtime.facts_source.issue(
                context,
                action,
                policy_digest=current_runtime.binding_digest,
                snapshot_digest=current_runtime.evidence_digest(context),
                budgets=tuple(
                    SwarmBudgetFact(item["scope"], item["metric"], item["remaining"])
                    for item in report["limits"]
                ),
            )

        service.bind_policy_runtime(runtime, operator=operator, facts_provider=facts)
        child = service.issue_child(
            auth.authenticate(sockets["parent"]),
            root_ref.grant_id,
            enrollments["child"],
            rights,
            request_id="fresh-child",
            lifetime=60,
        )
        context = service.bind_delegation_context(child.grant_id, operator=operator)
        channel = auth.authenticate(sockets["child"])
        global_gate = SwarmGate(registry, service.assurance)
        broker = SwarmExecutionBroker(
            service,
            auth.authenticate(broker_socket),
            global_gate,
            ledger,
            backend,
            operator=operator,
            policy_runtime=runtime,
        )
        proof = broker.activation_proof(selected.digest, operator=operator)
        runtime.bind_enforcement(selected, broker, proof, operator=operator)
        yield runtime, broker, ledger, service, channel, child.grant_id, context, operator


@pytest.mark.parametrize("physical", (False, True))
def test_real_effect_joins_current_datadoc_and_post_reserve_budget_rule(tmp_path, physical):
    require_kernel()
    with fixture(tmp_path, physical=physical) as data:
        selected = replace(
            scoped_policy(data[13]),
            rules=(
                SwarmPolicyRule(
                    "reserve-exhaustion",
                    "deny",
                    SwarmPolicySelector(budgets=(SwarmBudgetCondition("swarm", "requests", 2),)),
                ),
            ),
        )
        with current_policy_broker(data, selected) as current:
            runtime, broker, ledger, _, channel, grant, context, _ = current
            first = broker.prepare(channel, grant, data[4], idempotency_key="first-policy-read")
            assert first.authorization is not None, first.as_dict()
            result = broker.dispatch(first.authorization)
            assert result.status == "completed" and result.physical_enforcement, result.as_dict()
            assert result.value == b"broker-owned-benign-data\n"
            second_action = replace(data[4], action_id="second-policy-read")
            second = broker.prepare(
                channel, grant, second_action, idempotency_key="second-policy-read"
            )
            assert second.disposition == "deny" and second.authorization is None, second.as_dict()
            assert any(
                fact.metric == "requests" and fact.remaining == 2
                for receipt in runtime.facts_source._issued
                for fact in receipt.budgets or ()
            )
            row = ledger._registry._agents[context.identity.agent_id]
            report = ledger.report(
                context, channel=row.channel, adapter=ledger._registry._channels[row.channel][0]
            )
            requests = next(item for item in report["limits"] if item["metric"] == "requests")
            assert requests["consumed"] == 1 and requests["reserved"] == 0
            assert data[13].read_bytes() == b"broker-owned-benign-data\n"


def test_uncapped_billing_budget_does_not_become_ready_from_a_kernel_file_factory(tmp_path):
    require_kernel()
    with fixture(tmp_path, physical=True, metric="dollar_micros") as data:
        selected = scoped_policy(data[13])
        maximum = SwarmPolicyMaximum(
            "tenant", "swarm", selected.permissions, budget_limits=data[2].policy.limits
        )
        runtime = SwarmPolicyRuntime(
            data[14],
            maximum,
            operator=data[11],
            clock=lambda: data[10][0],
            budget_ledger=data[2],
        )
        proof = data[0].activation_proof(selected.digest, operator=data[11])
        runtime.bind_enforcement(selected, data[0], proof, operator=data[11])
        assert not data[2].admission_available
        with pytest.raises(ValueError, match="capability unavailable"):
            runtime.prepare(selected)
        assert runtime.epoch == 0 and runtime.selection_digest is None


def test_reload_fences_actual_unused_broker_ticket_before_any_owned_effect(tmp_path, monkeypatch):
    require_kernel()
    with fixture(tmp_path) as data:
        selected = scoped_policy(data[13])
        with current_policy_broker(data, selected) as current:
            runtime, broker, _, _, channel, grant, _, operator = current
            preparation = broker.prepare(channel, grant, data[4], idempotency_key="before-reload")
            assert preparation.authorization is not None, preparation.as_dict()
            parent = runtime._registry._agents["parent"].context
            replacement = replace(selected, revision=2, default_disposition="deny")
            proof = broker.activation_proof(replacement.digest, operator=operator)
            runtime.bind_enforcement(replacement, broker, proof, operator=operator)
            proposal = runtime.prepare(replacement)
            simulation = runtime.simulate(
                proposal,
                (SwarmPolicyReplayCase("read", parent, data[4], "benign"),),
                ordin=broker._gate._baseline.ordin,
            )
            runtime.activate(
                runtime.approve(proposal, simulation, operator=operator), operator=operator
            )
            monkeypatch.setattr(
                broker._executor,
                "execute",
                lambda *a, **k: pytest.fail("old policy ticket reached the real executor"),
            )
            result = broker.dispatch(preparation.authorization)
            assert not result.forwarded and result.status != "completed", result.as_dict()
