"""Real mTLS participants plus durable coordinator state, not JSON identity claims."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
from dataclasses import replace
import hashlib
import json
from pathlib import Path

import pytest

from ordin import ActionEnvelope, AgentGate, Ordin
from ordin.assurance import AssuranceGate, DelegationIssuer, HostEvidenceSource
from ordin.swarm import InMemoryAgentRegistry
from ordin.swarm.budgets import BudgetLimit, BudgetPolicy
from ordin.swarm.coordinator import SwarmCoordinator, CoordinatorControlSource, CoordinatorScope
from ordin.swarm.coordinator_store import (
    CoordinatorRejected,
    CoordinatorUnavailable,
    SQLiteCoordinatorStore,
)
from ordin.swarm.delegation import SwarmDelegationService
from ordin.swarm.workload_auth import WorkloadAuthenticator
from tests.test_swarm_delegation import fingerprint, server_context, tls_pair
from tests.assurance.test_delegation import maximum, child_max
from tests.assurance.test_delegating_gate import action
from tests.assurance.test_invariants import SEMANTICS
from tests.assurance.test_profiles import REPO, POLICY_HASH, approve, selected, config_profile


@contextmanager
def configured(
    tmp_path,
    *,
    limit=1,
    tenant="tenant",
    swarm="swarm",
    backend=None,
    epoch=0,
    lease=10,
    journal_lag=128,
    initialize=True,
    takeover=False,
):
    tmp_path.mkdir(parents=True, exist_ok=True)
    now = [100.0]
    store = backend or SQLiteCoordinatorStore(
        tmp_path / "coordinator.db", create=True, clock=lambda: now[0]
    )
    operator = object()
    coordinator = SwarmCoordinator(
        store, operator=operator, lease_lifetime=lease, max_journal_lag=journal_lag
    )
    clock = coordinator.clock
    profile_dir = tmp_path / "profile"
    profile_dir.mkdir()
    profile = approve(selected(profile_dir, config_profile()))
    parent = HostEvidenceSource(
        "parent", REPO, "a" * 64, epoch, POLICY_HASH, profile.selection_digest
    )
    rights = maximum()
    issuer = DelegationIssuer(parent, profile, rights, rights, clock=clock)
    root = issuer.authorize_root(rights, grant_id="root", expires_at=clock() + 100)
    registry = InMemoryAgentRegistry(tenant, swarm, clock=clock, policy_epoch=epoch)
    tls = server_context()
    auth = WorkloadAuthenticator(registry, tls, operator=operator, clock=clock)
    native = SwarmDelegationService(
        issuer,
        AssuranceGate(AgentGate(Ordin(tool_semantics=SEMANTICS)), profile),
        auth,
        operator=operator,
    )
    channels, contexts, enrollments, sockets = {}, {}, {}, {}
    with ExitStack() as stack:
        for name in ("parent", "child"):
            source = (
                parent
                if name == "parent"
                else replace(
                    parent, principal=name, session_digest=hashlib.sha256(name.encode()).hexdigest()
                )
            )
            adapter = object()
            host_channel = registry.bind_channel(adapter, runtime_id="fixture-" + name)
            context = registry.enroll(
                host_channel, adapter, agent_id=name, session_id="session-" + name, task_id="task"
            )
            enrollments[name] = auth.enroll_workload(
                host_id="host-a" if name == "parent" else "host-b",
                certificate_digest=fingerprint(name),
                context=context,
                source=source,
                channel=host_channel,
                adapter=adapter,
                operator=operator,
            )
            server, client = stack.enter_context(tls_pair(tls, name))
            sockets[name], channels[name], contexts[name] = (
                (server, client),
                auth.authenticate(server),
                context,
            )
        for name, host in (("broker-a", "host-a"), ("broker-b", "host-b")):
            enrollments[name] = auth.enroll_broker(
                host_id=host, certificate_digest=fingerprint(name), operator=operator
            )
            server, client = stack.enter_context(tls_pair(tls, name))
            sockets[name], channels[name] = (server, client), auth.authenticate(server)
        root_ref = native.publish_root(enrollments["parent"], root, operator=operator)
        child = native.issue_child(
            channels["parent"],
            root_ref.grant_id,
            enrollments["child"],
            child_max(),
            request_id="child",
            lifetime=30,
        )
        contexts["child"] = native.bind_delegation_context(child.grant_id, operator=operator)
        channels["child"] = auth.authenticate(sockets["child"][0])
        budget = BudgetPolicy(epoch, (BudgetLimit("swarm", "tool_calls", limit),))
        control = coordinator.control_source(operator=operator)
        scope = coordinator.register_scope(
            native,
            budget,
            control=control,
            broker_channels=(channels["broker-a"], channels["broker-b"]),
        )
        if initialize:
            coordinator.initialize_scope(scope, control=control)
        coordinator.start(scope, control=control, takeover=takeover)
        leases = {name: coordinator.admit(scope, channels[name]) for name in ("parent", "child")}
        references = {"parent": root_ref.grant_id, "child": child.grant_id}
        for name in references:
            coordinator.bind_grant(scope, channels[name], leases[name].reference, references[name])
        yield {
            "coordinator": coordinator,
            "scope": scope,
            "control": control,
            "store": store,
            "native": native,
            "auth": auth,
            "registry": registry,
            "clock": clock,
            "now": now,
            "operator": operator,
            "channels": channels,
            "contexts": contexts,
            "leases": leases,
            "references": references,
            "sockets": sockets,
            "budget": budget,
        }


def prepare(data, who="child", *, request="request", selected_action=None):
    coordinator, scope = data["coordinator"], data["scope"]
    proposed = selected_action or action(request)
    evaluated = coordinator.evaluate(
        scope,
        data["channels"][who],
        data["leases"][who].reference,
        data["references"][who],
        proposed,
        idempotency_key="evaluate-" + request,
    )
    reserved = coordinator.reserve(
        scope,
        data["channels"][who],
        data["leases"][who].reference,
        evaluated.reference,
        proposed,
        idempotency_key="reserve-" + request,
    )
    return proposed, evaluated, reserved


def test_original_mtls_scope_one_use_dispatch_and_full_bound_accounting(tmp_path):
    with configured(tmp_path) as data:
        coordinator, scope = data["coordinator"], data["scope"]
        proposed, _, reserved = prepare(data)
        report = coordinator.budget_report(
            scope, data["channels"]["child"], data["leases"]["child"].reference
        )
        assert report["limits"][0]["reserved"] == 1 and report["limits"][0]["consumed"] == 0
        calls = []
        result = coordinator.guarded_dispatch(
            scope,
            data["channels"]["broker-b"],
            reserved.reference,
            forward=lambda current: calls.append(current.as_dict()) or "ok",
        )
        assert result.status == "host_completed" and result.value == "ok"
        assert len(calls) == 1 and calls[0] == proposed.as_dict()
        with pytest.raises(CoordinatorRejected):
            coordinator.guarded_dispatch(
                scope,
                data["channels"]["broker-b"],
                reserved.reference,
                forward=lambda current: calls.append(current),
            )
        report = coordinator.budget_report(
            scope, data["channels"]["parent"], data["leases"]["parent"].reference
        )
        assert report["limits"][0]["reserved"] == 0 and report["limits"][0]["consumed"] == 1
        assert (
            not result.as_dict()["physical_enforcement"]
            and not result.as_dict()["execution_authority"]
        )


def test_two_authenticated_hosts_cannot_reserve_past_shared_swarm_budget(tmp_path):
    with configured(tmp_path) as data:

        def reserve(who):
            try:
                return prepare(data, who, request=who)[2]
            except CoordinatorRejected:
                return None

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(reserve, ("parent", "child")))
        assert sum(value is not None for value in outcomes) == 1
        report = data["coordinator"].budget_report(
            data["scope"], data["channels"]["parent"], data["leases"]["parent"].reference
        )
        assert report["limits"][0]["reserved"] == 1 and report["limits"][0]["remaining"] == 0


def test_original_scope_control_broker_host_and_foreign_lease_are_required(tmp_path):
    with configured(tmp_path) as data:
        coordinator, scope = data["coordinator"], data["scope"]
        with pytest.raises(ValueError):
            coordinator.status(scope, control=CoordinatorControlSource(data["control"].source_id))
        with pytest.raises(ValueError):
            coordinator.status(CoordinatorScope(scope.scope_key), control=data["control"])
        with pytest.raises(CoordinatorRejected):
            coordinator.policy_snapshot(
                scope, data["channels"]["parent"], data["leases"]["child"].reference
            )
        _, _, reserved = prepare(data)
        with pytest.raises(ValueError):
            coordinator.begin_forward(scope, data["channels"]["child"], reserved.reference)
        with pytest.raises(CoordinatorRejected):
            coordinator.begin_forward(scope, data["channels"]["broker-a"], reserved.reference)
        assert coordinator.cancel(
            scope, data["channels"]["child"], data["leases"]["child"].reference, reserved.reference
        )


def test_exact_evaluate_reserve_idempotency_and_changed_action_refusal(tmp_path):
    with configured(tmp_path) as data:
        coordinator, scope = data["coordinator"], data["scope"]
        proposed, evaluated, reserved = prepare(data)
        repeated = coordinator.reserve(
            scope,
            data["channels"]["child"],
            data["leases"]["child"].reference,
            evaluated.reference,
            proposed,
            idempotency_key="reserve-request",
        )
        assert repeated.reference == reserved.reference
        with pytest.raises(CoordinatorRejected):
            coordinator.reserve(
                scope,
                data["channels"]["child"],
                data["leases"]["child"].reference,
                evaluated.reference,
                action("changed"),
                idempotency_key="different",
            )
        assert coordinator.cancel(
            scope, data["channels"]["child"], data["leases"]["child"].reference, reserved.reference
        )
        assert not coordinator.cancel(
            scope, data["channels"]["child"], data["leases"]["child"].reference, reserved.reference
        )
        assert (
            coordinator.budget_report(
                scope, data["channels"]["child"], data["leases"]["child"].reference
            )["limits"][0]["remaining"]
            == 1
        )


def test_coordinator_partition_never_calls_executor_or_falls_back_to_core_allow(tmp_path):
    with configured(tmp_path) as data:
        coordinator, scope = data["coordinator"], data["scope"]
        _, _, reserved = prepare(data)
        data["store"]._available = False
        calls = []
        with pytest.raises(CoordinatorUnavailable):
            coordinator.guarded_dispatch(
                scope,
                data["channels"]["broker-b"],
                reserved.reference,
                forward=lambda current: calls.append(current),
            )
        assert not calls and not coordinator.status(scope, control=data["control"])["online"]
        assert Ordin().review_action(ActionEnvelope.shell("git status")).allowed
