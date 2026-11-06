"""Original online tickets, budgets, fresh global checks and actual contained effects."""

from contextlib import ExitStack, contextmanager
from dataclasses import replace
import json
from pathlib import Path
import sys
import tempfile

import pytest

from ordin import (
    AgentGate,
    Ordin,
    ToolCallAdapter,
    ToolResourceBinding,
    ToolSemanticRule,
    ToolSemanticsRegistry,
)
from ordin.assurance import AssuranceGate, DelegationAuthority, DelegationIssuer, HostEvidenceSource
from ordin.runtime_boundary import RuntimeCapabilityBoundary
from ordin.runtime_contract import FilesystemCapability, ToolCapability
from ordin.session import IntegrationSession, SessionIdentity
from ordin.swarm import CoverageManifest, InMemoryAgentRegistry, SwarmGate, SwarmPolicy, SwarmRule
from ordin.swarm.budget_store import InMemoryBudgetStore
from ordin.swarm.budgets import BudgetLedger, BudgetLimit, BudgetPolicy
from ordin.swarm.broker import SwarmExecutionBroker
from ordin.swarm.authorization import BrokerAuthorization
from ordin.swarm.delegation import SwarmDelegationService
from ordin.swarm.linux_backend import LinuxFileReadBackend
from ordin.swarm.workload_auth import WorkloadAuthenticator
from tests.assurance.test_profiles import REPO, POLICY_HASH, approve, selected, config_profile
from tests.test_swarm_delegation import server_context, tls_pair, fingerprint
from tests.test_swarm_linux_executor import supported


@contextmanager
def fixture(
    tmp_path,
    *,
    global_policy=None,
    mediated=True,
    physical=False,
    metric="output_bytes",
    shared_clock=None,
    executor_timeout_ms=3000,
    approval_decision=None,
):
    clock = [100]
    clock_fn = shared_clock or (lambda: clock[0])
    operator = object()
    workspace = (tmp_path / "workspace").resolve()
    workspace.mkdir(mode=0o700)
    target = workspace / "data.txt"
    target.write_bytes(b"broker-owned-benign-data\n")
    target.chmod(0o600)
    logical_path = str(target) if sys.platform == "linux" else "/owned/data.txt"
    semantics = ToolSemanticsRegistry(
        "broker-read",
        "1",
        (
            ToolSemanticRule(
                "read",
                "tool",
                "read_file",
                ("filesystem.read",),
                runtime="fixture",
                resources=(ToolResourceBinding("path", "path"),),
            ),
        ),
    )
    core = Ordin(tool_semantics=semantics)
    if approval_decision is not None:
        from ordin.action_policy import ActionPolicySet, ActionPolicyRule, ActionPolicyCondition

        core = Ordin(
            tool_semantics=semantics,
            action_policy=ActionPolicySet(
                "human-review",
                "1",
                (
                    ActionPolicyRule(
                        "read-approval",
                        approval_decision,
                        ActionPolicyCondition(effects_any=("filesystem.read",)),
                    ),
                ),
            ),
        )
    profile = approve(selected(tmp_path, config_profile()))
    identities = {
        name: SessionIdentity("owned-" + name, "session-" + name) for name in ("parent", "child")
    }
    sources = {
        name: HostEvidenceSource(
            name,
            REPO,
            IntegrationSession(identities[name], AgentGate(core)).runtime_session_digest,
            0,
            POLICY_HASH,
            profile.selection_digest,
        )
        for name in identities
    }
    rights = DelegationAuthority(
        RuntimeCapabilityBoundary(
            "owned-read-root",
            filesystem=(FilesystemCapability("read", logical_path, "exact"),),
            tools=(ToolCapability("fixture", None, "read_file"),),
        )
    )
    issuer = DelegationIssuer(sources["parent"], profile, rights, rights, clock=clock_fn)
    root = issuer.authorize_root(rights, grant_id="root", expires_at=clock_fn() + 100)
    registry = InMemoryAgentRegistry("tenant", "swarm", clock=clock_fn)
    tls = server_context()
    auth = WorkloadAuthenticator(registry, tls, operator=operator, clock=clock_fn)
    bootstrap = None
    if approval_decision is not None:
        from ordin.swarm.approval_service import SwarmApprovalBootstrap

        bootstrap = SwarmApprovalBootstrap(
            registry, tuple(sources.values()), profile, rights, operator=operator, clock=clock_fn
        )
    assurance = AssuranceGate(
        AgentGate(core, approval_source=bootstrap.authority if bootstrap is not None else None),
        profile,
    )
    service = SwarmDelegationService(issuer, assurance, auth, operator=operator)
    contexts, rchannels, adapters, enrollments, channels, sockets = {}, {}, {}, {}, {}, {}
    with ExitStack() as stack:
        for name in identities:
            adapter = object()
            rchannel = registry.bind_channel(adapter, runtime_id="owned-" + name)
            context = registry.enroll(
                rchannel,
                adapter,
                agent_id=name,
                session_id="session-" + name,
                task_id="task",
                coverage=CoverageManifest("intercept" if mediated else "observe"),
            )
            enrollment = auth.enroll_workload(
                host_id="host-a" if name == "parent" else "host-b",
                certificate_digest=fingerprint(name),
                context=context,
                source=sources[name],
                channel=rchannel,
                adapter=adapter,
                operator=operator,
                runtime_identity=identities[name],
            )
            server, client = stack.enter_context(tls_pair(tls, name))
            (
                contexts[name],
                rchannels[name],
                adapters[name],
                enrollments[name],
                channels[name],
                sockets[name],
            ) = context, rchannel, adapter, enrollment, auth.authenticate(server), (server, client)
        auth.enroll_broker(
            host_id="host-b", certificate_digest=fingerprint("broker-b"), operator=operator
        )
        server, client = stack.enter_context(tls_pair(tls, "broker-b"))
        broker_channel = auth.authenticate(server)
        root_ref = service.publish_root(enrollments["parent"], root, operator=operator)
        child = service.issue_child(
            channels["parent"],
            root_ref.grant_id,
            enrollments["child"],
            rights,
            request_id="child",
            lifetime=60,
        )
        contexts["child"] = service.bind_delegation_context(child.grant_id, operator=operator)
        channels["child"] = auth.authenticate(sockets["child"][0])
        ledger = BudgetLedger(
            registry,
            BudgetPolicy(
                0,
                (
                    BudgetLimit("swarm", "requests", 4),
                    BudgetLimit("swarm", "concurrency", 1),
                    BudgetLimit("swarm", metric, 1000000),
                ),
                require_physical_enforcement=physical,
            ),
            store=InMemoryBudgetStore(),
            clock=clock_fn,
            operator=operator,
        )
        gate = SwarmGate(registry, assurance, policy=global_policy)
        install = Path(
            stack.enter_context(tempfile.TemporaryDirectory(prefix="ordin-broker-executor-"))
        ).resolve()
        backend = LinuxFileReadBackend(
            workspace, ("data.txt",), install, operator=operator, timeout_ms=executor_timeout_ms
        )
        stack.callback(backend.close)
        broker = SwarmExecutionBroker(
            service, broker_channel, gate, ledger, backend, operator=operator
        )
        action = ToolCallAdapter("fixture").adapt(
            "read_file", {"path": logical_path}, action_id="broker-read"
        )
        values = (
            broker,
            service,
            ledger,
            backend,
            action,
            channels["child"],
            child.grant_id,
            contexts["child"],
            rchannels["child"],
            adapters["child"],
            clock,
            operator,
            rights,
            target,
            registry,
        )
        yield values + (bootstrap,) if bootstrap is not None else values


def require_kernel():
    if not supported():
        pytest.skip("real owned kernel broker unavailable; no weaker physical fallback")


def test_benign_bound_request_executes_once_and_settles_actual_owned_outcome(tmp_path):
    require_kernel()
    with fixture(tmp_path) as data:
        broker, service, ledger, backend, action, channel, grant, context, rchannel, adapter, *_ = (
            data
        )
        prepared = broker.prepare(channel, grant, action, idempotency_key="read")
        assert prepared.disposition == "execute", prepared.as_dict()
        authorization = prepared.authorization
        scope = broker.authorization_scope(authorization)
        assert scope.context is context and scope.action.as_dict() == action.as_dict()
        result = broker.dispatch(authorization)
        assert result.status == "completed", result.as_dict()
        assert result.value == b"broker-owned-benign-data\n" and result.physical_enforcement
        assert broker.verify_result(result, authorization)
        assert result.executor_outcome.observation.outcome == "completed"
        assert ledger.reservation_status(scope.budget_ticket)["status"] == "committed"
        assert (
            ledger.report(context, channel=rchannel, adapter=adapter)["limits"][0]["consumed"] >= 0
        )
        with pytest.raises(ValueError):
            broker.dispatch(authorization)
        assert "broker-owned-benign-data" not in json.dumps(result.as_dict()) + repr(result)


@pytest.mark.parametrize("change", ["arguments", "tool", "epoch", "grant", "policy", "expiry"])
def test_mutated_stale_revoked_and_changed_policy_fail_before_effect(tmp_path, change, monkeypatch):
    require_kernel()
    with fixture(tmp_path) as data:
        (
            broker,
            service,
            ledger,
            backend,
            action,
            channel,
            grant,
            context,
            _,
            _,
            clock,
            operator,
            _,
            target,
            registry,
        ) = data
        prepared = broker.prepare(channel, grant, action, idempotency_key="read")
        assert prepared.authorization, prepared.as_dict()
        selected = action
        if change == "arguments":
            selected = replace(
                action,
                parameters={
                    **action.parameters,
                    "arguments": {"path": str(target.parent / "other")},
                },
            )
        elif change == "tool":
            selected = replace(action, parameters={**action.parameters, "tool": "write_file"})
        elif change == "epoch":
            registry.advance_policy_epoch(1)
        elif change == "grant":
            service.operator_revoke(grant, operator=operator)
        elif change == "policy":
            broker._gate._policy = SwarmPolicy("changed", "2", rules=(SwarmRule("deny", "deny"),))
        else:
            clock[0] += 11
        monkeypatch.setattr(
            backend, "execute", lambda *a, **k: pytest.fail("stale or changed effect forwarded")
        )
        result = broker.dispatch(prepared.authorization, action=selected)
        assert result.status != "completed" and not result.forwarded


def test_fresh_global_deny_remains_stronger_than_valid_delegation(tmp_path, monkeypatch):
    require_kernel()
    with fixture(
        tmp_path,
        global_policy=SwarmPolicy(
            "deny", "1", rules=(SwarmRule("stop", "deny", effects=("filesystem.read",)),)
        ),
    ) as data:
        broker, service, ledger, backend, action, channel, grant, *_ = data
        monkeypatch.setattr(
            backend, "execute", lambda *a, **k: pytest.fail("global denial forwarded")
        )
        prepared = broker.prepare(channel, grant, action, idempotency_key="read")
        assert prepared.disposition == "deny" and prepared.authorization is None
        assert not service.issuer._pending


def test_missing_platform_and_observe_only_route_never_get_success(tmp_path):
    with fixture(tmp_path, mediated=False) as data:
        broker, _, _, _, action, channel, grant, *_ = data
        prepared = broker.prepare(channel, grant, action, idempotency_key="read")
        assert prepared.disposition == "deny" and prepared.authorization is None


def test_owned_factory_proof_is_scoped_finite_and_cannot_authorize_arbitrary_rights(tmp_path):
    require_kernel()
    with fixture(tmp_path) as data:
        broker, _, _, _, _, _, _, context, _, _, clock, operator, rights, *_ = data
        from ordin.swarm.authorization import BrokerActivationProof

        policy = "a" * 64
        proof = broker.activation_proof(policy, operator=operator)
        assert broker.verify_activation(proof, policy_digest=policy, context=context)
        assert not broker.verify_activation(
            BrokerActivationProof(proof.proof_id), policy_digest=policy
        )
        description = broker.describe_activation(proof)
        assert description["factory"] and not description["physical_policy_applied"]
        assert description["capabilities"] == ["broker.enforce"]
        assert broker.policy_fits(proof, rights, policy_digest=policy)
        broadened = replace(
            rights,
            capability=replace(
                rights.capability,
                filesystem=(FilesystemCapability("write", str(data[13]), "exact"),),
            ),
        )
        assert not broker.policy_fits(proof, broadened, policy_digest=policy)
        clock[0] += 31
        assert not broker.verify_activation(proof, policy_digest=policy)


def test_gateway_uses_original_broker_and_preserves_outer_request_binding(tmp_path):
    require_kernel()
    from ordin.swarm import SwarmToolGateway
    from ordin._runtime_json import digest

    with fixture(tmp_path) as data:
        broker, _, _, _, action, channel, grant, _, _, _, _, operator, *_ = data
        binding = broker.bind_gateway(channel, grant, operator=operator)
        gateway = SwarmToolGateway()
        actor = gateway.bind_broker_agent(broker, binding, routes=frozenset({"file"}))
        prepared = gateway.prepare(actor, action, route="file", budget_idempotency_key="gateway")
        assert prepared.disposition == "execute", prepared
        pending = gateway._pending[prepared.ticket]
        scope = broker.authorization_scope(pending.broker_authorization)
        assert scope.caller_digest == digest(action.as_dict())
        assert scope.action.action_id != action.action_id
        assert prepared.action_digest == digest(scope.action.as_dict())
        with pytest.raises(ValueError):
            gateway.forward(actor, prepared.ticket, lambda _: pytest.fail("callback bypass"))
        result = gateway.forward(actor, prepared.ticket, action=action)
        assert result.status == "completed" and result.value == b"broker-owned-benign-data\n"


@pytest.mark.parametrize(
    "metric,success", [("output_bytes", True), ("tokens", False), ("dollar_micros", False)]
)
def test_physical_budget_admission_only_accepts_current_real_executor_bounds(
    tmp_path, metric, success
):
    require_kernel()
    with fixture(tmp_path, physical=True, metric=metric) as data:
        broker, _, ledger, _, action, channel, grant, *_ = data
        prepared = broker.prepare(channel, grant, action, idempotency_key="physical")
        assert (prepared.authorization is not None) == success, prepared.as_dict()
        if success:
            result = broker.dispatch(prepared.authorization)
            assert result.status == "completed", result.as_dict()
        assert not ledger.report(data[7], channel=data[8], adapter=data[9])["physical_enforcement"]


def test_queued_cancel_and_copied_control_are_not_execution_evidence(tmp_path):
    require_kernel()
    with fixture(tmp_path) as data:
        broker, _, ledger, _, action, channel, grant, *_ = data
        prepared = broker.prepare(channel, grant, action, idempotency_key="cancel")
        auth = prepared.authorization
        receipt = broker.cancel(auth)
        assert receipt.status == "canceled" and not receipt.as_dict()["rollback_claim"]
        assert broker.verify_control_receipt(receipt, auth)
        assert not broker.verify_control_receipt(replace(receipt), auth)
        assert (
            ledger.reservation_status(broker.authorization_scope(auth).budget_ticket)["status"]
            == "canceled"
        )
        with pytest.raises(ValueError):
            broker.dispatch(auth)


def test_untrusted_executor_report_retains_uncertain_budget_and_no_retry(tmp_path, monkeypatch):
    require_kernel()
    from ordin.swarm.linux_backend import ExecutorOutcome

    with fixture(tmp_path) as data:
        broker, _, ledger, backend, action, channel, grant, *_ = data
        prepared = broker.prepare(channel, grant, action, idempotency_key="untrusted")
        scope = broker.authorization_scope(prepared.authorization)
        forged = ExecutorOutcome(
            "completed",
            "forged",
            scope.plan.contract.action_digest,
            scope.plan.contract.digest,
            scope.plan.policy_digest,
            True,
            "a" * 64,
            1,
            1,
            "b" * 64,
        )
        monkeypatch.setattr(backend, "execute", lambda *a, **k: forged)
        result = broker.dispatch(prepared.authorization)
        assert result.status == "unknown" and not result.physical_enforcement
        assert ledger.reservation_status(scope.budget_ticket)["status"] == "uncertain"
        with pytest.raises(ValueError):
            broker.dispatch(prepared.authorization)


def test_mediated_deny_and_uncovered_host_bypass_are_separate_claims(tmp_path):
    require_kernel()
    with fixture(
        tmp_path, global_policy=SwarmPolicy("deny", "1", rules=(SwarmRule("stop", "deny"),))
    ) as data:
        broker, _, _, _, action, channel, grant, *_ = data
        denied = broker.prepare(channel, grant, action, idempotency_key="deny")
        assert denied.disposition == "deny" and denied.authorization is None
        # Parent host access is deliberately outside the owned child boundary.
        assert data[13].read_bytes() == b"broker-owned-benign-data\n"


def test_owned_process_stop_does_not_wait_for_execution_barrier(tmp_path, monkeypatch):
    require_kernel()
    from threading import Event, Thread
    import ordin.swarm.linux_backend as module

    with fixture(tmp_path) as data:
        broker, _, ledger, backend, action, channel, grant, *_ = data
        prepared = broker.prepare(channel, grant, action, idempotency_key="running-stop")
        auth = prepared.authorization
        started, release, stop_returned = Event(), Event(), Event()
        original = module.subprocess.Popen

        def launch(*args, **kwargs):
            process = original(*args, **kwargs)
            started.set()
            assert release.wait(10)
            return process

        monkeypatch.setattr(module.subprocess, "Popen", launch)
        results, controls = [], []
        dispatch = Thread(target=lambda: results.append(broker.dispatch(auth)))
        dispatch.start()
        assert started.wait(10)

        def stop():
            controls.append(broker.request_stop(auth))
            stop_returned.set()

        stopper = Thread(target=stop)
        stopper.start()
        try:
            assert stop_returned.wait(5), "stop waited for the effect/issuer barrier"
        finally:
            release.set()
            dispatch.join(15)
            stopper.join(15)
        assert not dispatch.is_alive() and not stopper.is_alive()
        assert broker.verify_control_receipt(controls[0], auth)
        assert results[0].status == "canceled", results[0].as_dict()
        assert (
            ledger.reservation_status(broker.authorization_scope(auth).budget_ticket)["status"]
            == "uncertain"
        )
        final = broker.status(auth)
        assert final.status == "canceled" and broker.verify_control_receipt(final, auth)
