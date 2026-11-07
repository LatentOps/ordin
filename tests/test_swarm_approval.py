"""Actual authenticated humans, durable quorum and original owned broker effects."""

from contextlib import contextmanager, ExitStack
from copy import copy
from dataclasses import replace

import pytest

from ordin.swarm.approval import SwarmApprovalPolicy
from ordin.swarm.approval_service import SwarmApprovalService
from ordin.swarm.coordinator import SwarmCoordinator
from ordin.swarm.coordinator_store import CoordinatorClock, SQLiteCoordinatorStore
from ordin.swarm.operator_auth import SwarmOperatorDirectory
from tests.test_swarm_broker import fixture, require_kernel
from tests.test_swarm_delegation import fingerprint, tls_pair


@contextmanager
def configured(
    tmp_path,
    *,
    decision="warn",
    quorum=False,
    policy=None,
    initialize=True,
    hard_limit=None,
    operator_roles=("approve", "observe", "break_glass", "recover"),
):
    now = [100.0]
    store = SQLiteCoordinatorStore(tmp_path / "authority.db", create=True, clock=lambda: now[0])
    clock = CoordinatorClock(store)
    (tmp_path / "broker").mkdir()
    with (
        fixture(tmp_path / "broker", shared_clock=clock, approval_decision=decision) as data,
        ExitStack() as stack,
    ):
        broker, native, ledger, _, action, channel, grant, _, _, _, _, operator, *_ = data
        coordinator = SwarmCoordinator(store, operator=operator, clock=clock)
        control = coordinator.control_source(operator=operator)
        coordinated_budget = (
            ledger.policy
            if hard_limit is None
            else replace(
                ledger.policy,
                limits=tuple(
                    replace(limit, maximum=hard_limit) if limit.metric == "requests" else limit
                    for limit in ledger.policy.limits
                ),
            )
        )
        scope = coordinator.register_scope(
            native,
            coordinated_budget,
            control=control,
            broker_channels=(broker._broker_channel,),
            brokers=(("host-b", broker),),
        )
        coordinator.initialize_scope(scope, control=control)
        coordinator.start(scope, control=control)
        parent_channel = next(
            handle
            for handle, row in native.authenticator._channels.items()
            if row.enrollment.context is not None
            and row.enrollment.context.identity.agent_id == "parent"
        )
        parent_ref = next(
            reference for reference, row in native._grants.items() if row.parent_ref is None
        )
        parent = coordinator.admit(scope, parent_channel)
        lease = coordinator.admit(scope, channel)
        coordinator.bind_grant(scope, parent_channel, parent.reference, parent_ref)
        coordinator.bind_grant(scope, channel, lease.reference, grant)
        directory = SwarmOperatorDirectory(
            native.authenticator,
            operator=operator,
            roles=operator_roles,
        )
        humans = {}
        for principal, credential in (("alice", "grandchild"), ("bob", "sibling")):
            directory.enroll(
                principal_id=principal,
                certificate_digest=fingerprint(credential),
                roles=operator_roles,
                task_ids=("task",),
                operator=operator,
            )
        for principal, credential in (("alice", "grandchild"), ("bob", "sibling")):
            server, _ = stack.enter_context(tls_pair(native.authenticator._tls, credential))
            humans[principal] = directory.authenticate(server)
        selected = coordinator._policy(coordinator._scope(scope))[1]
        proof = broker.activation_proof(selected, operator=operator)
        policy = policy or SwarmApprovalPolicy(
            "human", two_person_effects=("filesystem.read",) if quorum else ()
        )
        service = SwarmApprovalService(
            coordinator,
            scope,
            directory,
            data[15],
            policy,
            control=control,
            operator=operator,
            factory_proofs={"host-b": proof},
        )
        if initialize:
            service.initialize(operator=operator)
        yield (
            service,
            coordinator,
            scope,
            channel,
            lease.reference,
            grant,
            action,
            humans,
            now,
            data,
        )


@pytest.mark.parametrize("decision", ("warn", "ask"))
def test_actual_known_warning_is_approved_once_without_hiding_core_risk(tmp_path, decision):
    require_kernel()
    with configured(tmp_path, decision=decision) as data:
        service, _, _, channel, lease, grant, action, humans, _, native = data
        request = service.request(channel, lease, grant, action, idempotency_key="request")
        assert request.disposition == "escalate"
        resolution = service.resolve(
            humans["alice"], request.request_id, "approve", idempotency_key="vote"
        )
        assert resolution["status"] == "approved"
        receipt = resolution["receipt"]
        prepared = service.prepare(receipt, channel, lease, action)
        from ordin.schema import validate_named_schema

        assert not validate_named_schema("swarm_approval", request.as_dict())
        assert not validate_named_schema(
            "swarm_approval_receipt", service.describe_receipt(receipt)
        )
        assert not validate_named_schema(
            "swarm_approval_resolution", {k: v for k, v in resolution.items() if k != "receipt"}
        )
        assert not validate_named_schema(
            "swarm_approval_queue", service.snapshot(humans["alice"], task_id="task")
        )
        assert not validate_named_schema(
            "swarm_approval_audit", service.audit(humans["alice"], task_id="task")
        )
        original = service._approved(receipt)
        assert not validate_named_schema("approval_scope", original.scope.as_dict())
        assert not validate_named_schema("approval_satisfaction", original.satisfaction.as_dict())
        assert not validate_named_schema(
            "approval_execution_lease", original.execution_lease.as_dict()
        )
        authorization = service._approved(receipt).authorization
        review = native[0].authorization_scope(authorization).decision
        assert review.review.decision == decision and review.disposition == "escalate"
        assert review.approval_fulfilled and review.may_execute
        result = service.dispatch(receipt)
        assert result.status == "host_completed", result.as_dict()
        assert result.value == b"broker-owned-benign-data\n"
        with pytest.raises(ValueError):
            service.dispatch(receipt)
        assert prepared.reference is not None


def test_two_distinct_humans_are_required_and_copies_mutations_and_expiry_fail_closed(tmp_path):
    require_kernel()
    with configured(tmp_path, quorum=True) as data:
        service, _, _, channel, lease, grant, action, humans, now, _ = data
        request = service.request(channel, lease, grant, action, idempotency_key="quorum")
        with pytest.raises(ValueError):
            service.resolve(
                channel, request.request_id, "approve", idempotency_key="workload-self-approval"
            )
        first = service.resolve(
            humans["alice"], request.request_id, "approve", idempotency_key="first"
        )
        assert first["status"] == "pending" and "receipt" not in first
        again = service.resolve(
            humans["alice"], request.request_id, "approve", idempotency_key="another-key"
        )
        assert again["votes"] == 1
        final = service.resolve(
            humans["bob"], request.request_id, "approve", idempotency_key="second"
        )
        receipt = final["receipt"]
        with pytest.raises(ValueError):
            service.prepare(copy(receipt), channel, lease, action)
        with pytest.raises(ValueError):
            service.prepare(receipt, channel, lease, replace(action, action_id="mutated"))
        with pytest.raises(ValueError):
            service.prepare(
                receipt,
                channel,
                lease,
                replace(
                    action,
                    parameters={
                        **action.parameters,
                        "arguments": {"path": "/another-exact-action"},
                    },
                ),
            )
        foreign_channel = next(
            handle
            for handle, row in service.directory.authenticator._channels.items()
            if row.enrollment.context is not None
            and row.enrollment.context.identity.agent_id == "parent"
        )
        with pytest.raises(ValueError):
            service.prepare(receipt, foreign_channel, lease, action)
        now[0] += 11
        with pytest.raises(ValueError):
            service.prepare(receipt, channel, lease, action)


def test_review_is_pure_and_terminal_transitions_are_durable_and_secret_free(tmp_path):
    require_kernel()
    with configured(tmp_path) as data:
        service, coordinator, scope, channel, lease, grant, action, humans, now, _ = data
        request = service.request(channel, lease, grant, action, idempotency_key="pure")
        assert service.request(channel, lease, grant, action, idempotency_key="pure") is request
        with coordinator.store.transaction() as transaction:
            assert not transaction.scope(scope.scope_key)["reservations"]
        assert service.get_request(humans["alice"], request.request_id)["status"] == "pending"
        denied = service.resolve(humans["alice"], request.request_id, "deny", idempotency_key="no")
        assert denied["status"] == "denied" and "receipt" not in denied
        assert (
            service.cancel(humans["alice"], request.request_id, idempotency_key="cancel")["status"]
            == "denied"
        )
        second = service.request(channel, lease, grant, action, idempotency_key="expires")
        service.resolve(humans["alice"], second.request_id, "approve", idempotency_key="yes")
        now[0] += 11
        repeated = service.resolve(
            humans["alice"], second.request_id, "approve", idempotency_key="yes"
        )
        assert repeated["status"] == "expired" and "receipt" not in repeated
        assert (
            service.expire(humans["alice"], second.request_id, idempotency_key="expiry")["status"]
            == "expired"
        )
        import json

        report = json.dumps(service.snapshot(humans["alice"], task_id="task"))
        assert str(action.parameters["arguments"]["path"]) not in report
        assert "broker-owned-benign-data" not in report


def test_break_glass_is_explicit_human_only_quorum_and_never_waives_underlying_rights(tmp_path):
    require_kernel()
    policy = SwarmApprovalPolicy("emergency", break_glass=True, break_glass_lifetime=5)
    with configured(tmp_path, policy=policy) as data:
        service, _, _, channel, lease, grant, action, humans, now, _ = data
        with pytest.raises(ValueError):
            service.break_glass(
                channel,
                channel,
                lease,
                grant,
                action,
                reason_code="incident_response",
                idempotency_key="agent",
            )
        with pytest.raises(ValueError):
            service.break_glass(
                humans["alice"],
                channel,
                lease,
                grant,
                action,
                reason_code="secret prompt text",
                idempotency_key="reason",
            )
        request = service.break_glass(
            humans["alice"],
            channel,
            lease,
            grant,
            action,
            reason_code="incident_response",
            idempotency_key="emergency",
        )
        assert request.mode == "break_glass" and request.quorum == 2
        assert request.expires_at <= now[0] + 5
        first = service.resolve(
            humans["alice"], request.request_id, "approve", idempotency_key="one"
        )
        assert first["status"] == "pending" and "receipt" not in first
        final = service.resolve(humans["bob"], request.request_id, "approve", idempotency_key="two")
        service.prepare(final["receipt"], channel, lease, action)
        assert service.dispatch(final["receipt"]).status == "host_completed"


@pytest.mark.parametrize("decision", ("warn", "block"))
def test_core_block_unknown_and_unsupported_routes_never_enter_executable_approval(
    tmp_path, decision
):
    require_kernel()
    from ordin import ToolCallAdapter

    with configured(tmp_path, decision=decision) as data:
        service, _, _, channel, lease, grant, action, humans, _, native = data
        with pytest.raises(ValueError):
            service.break_glass(
                humans["alice"],
                channel,
                lease,
                grant,
                action,
                reason_code="availability",
                idempotency_key="disabled",
            )
        for proposed in (
            ToolCallAdapter("fixture").adapt("unknown_tool", {}, action_id="opaque"),
            replace(
                action,
                parameters={**action.parameters, "arguments": {"path": "/outside-authority"}},
            ),
        ):
            with pytest.raises(ValueError):
                service.request(
                    channel, lease, grant, proposed, idempotency_key="invalid-" + proposed.action_id
                )
        if decision == "block":
            with pytest.raises(ValueError):
                service.request(channel, lease, grant, action, idempotency_key="core-block")
        with pytest.raises(ValueError):
            native[1].review(channel, grant, action)


def test_concurrent_prepare_has_one_winner_and_cancel_closes_the_exact_job(tmp_path):
    require_kernel()
    from concurrent.futures import ThreadPoolExecutor

    with configured(tmp_path) as data:
        service, _, _, channel, lease, grant, action, humans, _, _ = data
        request = service.request(channel, lease, grant, action, idempotency_key="race")
        receipt = service.resolve(
            humans["alice"], request.request_id, "approve", idempotency_key="vote"
        )["receipt"]

        def prepare(_):
            try:
                return service.prepare(receipt, channel, lease, action)
            except ValueError:
                return None

        with ThreadPoolExecutor(max_workers=4) as pool:
            assert sum(result is not None for result in pool.map(prepare, range(4))) == 1
        assert (
            service.cancel(humans["alice"], request.request_id, idempotency_key="cancel")["status"]
            == "canceled"
        )
        with pytest.raises(ValueError):
            service.dispatch(receipt)
        value = service._approved(receipt)
        assert not value.original.source.verify_execution(
            value.execution_lease, value.original.broker._executor, object()
        )


def test_lost_approval_and_consumption_ack_never_publish_or_forward(tmp_path, monkeypatch):
    require_kernel()
    from ordin.swarm.coordinator_store import CoordinatorUnavailable

    with configured(tmp_path) as data:
        service, coordinator, scope, channel, lease, grant, action, humans, _, native = data
        request = service.request(channel, lease, grant, action, idempotency_key="fault")
        original_transaction = coordinator.store.transaction
        fail_status = ["approved"]

        @contextmanager
        def transaction():
            with original_transaction() as current:
                yield current
                row = current.scope(scope.scope_key)["governance"]["requests"][request.request_id]
                fail = row["status"] == fail_status[0]
            if fail:
                fail_status[0] = None
                raise CoordinatorUnavailable("owned synthetic committed acknowledgement loss")

        monkeypatch.setattr(coordinator.store, "transaction", transaction)
        with pytest.raises(ValueError):
            service.resolve(humans["alice"], request.request_id, "approve", idempotency_key="vote")
        assert not service._receipt_by_request
        receipt = service.resolve(
            humans["alice"], request.request_id, "approve", idempotency_key="vote"
        )["receipt"]
        service.prepare(receipt, channel, lease, action)
        calls = []
        executor = native[0]._executor
        original_execute = executor.execute

        def execute(*args, **kwargs):
            calls.append(True)
            return original_execute(*args, **kwargs)

        monkeypatch.setattr(executor, "execute", execute)
        fail_status[0] = "consumed"
        with pytest.raises(ValueError):
            service.dispatch(receipt)
        assert not calls
        assert service.get_request(humans["alice"], request.request_id)["status"] == "uncertain"
        with pytest.raises(ValueError):
            service.dispatch(receipt)


def test_initialization_lost_ack_can_recover_same_original_but_missing_history_cannot_reset(
    tmp_path, monkeypatch
):
    require_kernel()
    from ordin.swarm.coordinator_store import CoordinatorUnavailable

    with configured(tmp_path, decision="allow", initialize=False) as data:
        service, coordinator, scope, channel, lease, grant, action, humans, _, native = data
        original = coordinator.store.transaction

        @contextmanager
        def transaction():
            with original() as current:
                yield current
            raise CoordinatorUnavailable("owned synthetic initialization ACK loss")

        monkeypatch.setattr(coordinator.store, "transaction", transaction)
        with pytest.raises(ValueError):
            service.initialize(operator=native[11])
        assert native[1]._governance is None
        monkeypatch.setattr(coordinator.store, "transaction", original)
        with pytest.raises(ValueError, match="not acknowledged"):
            native[1].review(channel, grant, action)
        assert (
            not native[0]
            .prepare(channel, grant, action, idempotency_key="unacknowledged")
            .may_execute
        )
        service.initialize(operator=native[11], recover=True)
        assert native[1]._governance is service
        with original() as current:
            del current.scope(scope.scope_key)["governance"]
        with pytest.raises(ValueError):
            service.initialize(operator=native[11], recover=True)
        with pytest.raises(ValueError):
            service.snapshot(humans["alice"], task_id="task")


def test_recovery_needs_fresh_fence_original_evidence_and_distinct_human_quorum(tmp_path, capsys):
    require_kernel()
    from ordin.swarm.incident import (
        IncidentPolicy,
        IncidentScope,
        IncidentSignalSource,
        SwarmContainmentController,
    )

    with configured(tmp_path) as data:
        service, coordinator, scope, channel, lease, grant, action, humans, _, native = data
        operator = native[11]
        signals = IncidentSignalSource(operator=operator)
        controller = SwarmContainmentController(
            coordinator,
            scope,
            control=service._control,
            operator=operator,
            policy=IncidentPolicy("incidents", 1),
            signals=signals,
        )
        selected = IncidentScope("agent", "tenant", "swarm", agent_id="child")
        signal = signals.operator_signal(selected, severity="high", operator=operator)
        incident = controller.pause(signal, operator=operator)
        assert controller._original(incident).done.wait(10)
        with pytest.raises(ValueError):
            service.request_recovery(
                humans["alice"],
                controller,
                incident,
                task_id="task",
                reason_code="safety_recovery",
                idempotency_key="premature",
            )
        coordinator.start(scope, control=service._control, takeover=True)
        with pytest.raises(ValueError):
            service.request_recovery(
                humans["alice"],
                controller,
                copy(incident),
                task_id="task",
                reason_code="safety_recovery",
                idempotency_key="copy",
            )
        request = service.request_recovery(
            humans["alice"],
            controller,
            incident,
            task_id="task",
            reason_code="safety_recovery",
            idempotency_key="recovery",
        )
        from ordin.schema import validate_named_schema

        assert not validate_named_schema("swarm_recovery_request", request.as_dict())
        first = service.resolve_recovery(
            humans["alice"], request.request_id, "approve", idempotency_key="one"
        )
        assert first["status"] == "pending" and "approval" not in first
        second = service.resolve_recovery(
            humans["bob"], request.request_id, "approve", idempotency_key="two"
        )
        with pytest.raises(ValueError):
            service.resume(humans["alice"], copy(second["approval"]))
        from ordin.swarm.approval_cli import SwarmApprovalOperatorSession, main

        session = SwarmApprovalOperatorSession(service, humans["bob"])
        assert (
            main(
                ["approve", request.request_id, "--recovery", "--idempotency-key", "two"],
                session=session,
            )
            == 0
        )
        assert main(["resume", request.request_id], session=session) == 0
        assert controller._original(incident).resumed
        assert "receipt_id" not in capsys.readouterr().out
        with pytest.raises(ValueError):
            service.resume(humans["alice"], second["approval"])
        with pytest.raises(ValueError):
            native[1].review(channel, grant, action)


def test_operator_cli_approve_deny_cancel_expire_uses_original_tls_session(tmp_path, capsys):
    require_kernel()
    from ordin.swarm.approval_cli import SwarmApprovalOperatorSession, main

    with configured(tmp_path) as data:
        service, _, _, channel, lease, grant, action, humans, now, _ = data
        session = SwarmApprovalOperatorSession(service, humans["alice"])
        assert main(["queue", "--task", "task"], session=session) == 0
        for choice in ("approve", "deny", "cancel", "expire"):
            request = service.request(channel, lease, grant, action, idempotency_key=choice)
            if choice == "expire":
                now[0] += 11
            assert (
                main([choice, request.request_id, "--idempotency-key", choice], session=session)
                == 0
            )
        output = capsys.readouterr().out
        assert '"receipt"' not in output and '"approval"' not in output
        assert main(["approve", request.request_id, "--idempotency-key", "forged"]) == 2


def test_human_quorum_cannot_raise_a_hard_coordinated_budget(tmp_path, monkeypatch):
    require_kernel()
    with configured(tmp_path, hard_limit=0) as data:
        service, _, _, channel, lease, grant, action, humans, _, native = data
        request = service.request(channel, lease, grant, action, idempotency_key="hard-quota")
        receipt = service.resolve(
            humans["alice"], request.request_id, "approve", idempotency_key="vote"
        )["receipt"]
        monkeypatch.setattr(
            native[0]._executor, "execute", lambda *a, **k: pytest.fail("hard quota bypassed")
        )
        with pytest.raises(ValueError):
            service.prepare(receipt, channel, lease, action)
        assert not native[1].issuer._pending


def test_mutating_an_original_receipt_identifier_invalidates_it(tmp_path):
    require_kernel()
    with configured(tmp_path) as data:
        service, _, _, channel, lease, grant, action, humans, _, _ = data
        request = service.request(channel, lease, grant, action, idempotency_key="mutate-handle")
        receipt = service.resolve(
            humans["alice"], request.request_id, "approve", idempotency_key="vote"
        )["receipt"]
        object.__setattr__(receipt, "receipt_id", "f" * 32)
        with pytest.raises(ValueError):
            service.prepare(receipt, channel, lease, action)


@pytest.mark.parametrize(
    "change", ("human_revocation", "delegation_revocation", "epoch", "durable_mutation")
)
def test_changed_authority_or_history_cannot_forward_an_original_approved_job(
    tmp_path, monkeypatch, change
):
    require_kernel()
    with configured(tmp_path) as data:
        service, coordinator, scope, channel, lease, grant, action, humans, _, native = data
        request = service.request(channel, lease, grant, action, idempotency_key="change")
        receipt = service.resolve(
            humans["alice"], request.request_id, "approve", idempotency_key="vote"
        )["receipt"]
        service.prepare(receipt, channel, lease, action)
        monkeypatch.setattr(
            native[0]._executor,
            "execute",
            lambda *a, **k: pytest.fail("changed governance job forwarded"),
        )
        if change == "human_revocation":
            actor = next(
                row for row in service.directory._members.values() if row.principal_id == "alice"
            )
            service.directory.revoke(actor.enrollment_id, operator=native[11])
        elif change == "delegation_revocation":
            native[1].operator_revoke(grant, operator=native[11])
        elif change == "epoch":
            native[14].advance_policy_epoch(1)
        else:
            with coordinator.store.transaction() as transaction:
                row = transaction.scope(scope.scope_key)["governance"]["requests"][
                    request.request_id
                ]
                row["request"]["required_roles"] = ["observe"]
        try:
            result = service.dispatch(receipt)
        except ValueError:
            pass
        else:
            assert result.status != "host_completed"
        with pytest.raises(ValueError):
            service.dispatch(receipt)


def test_rotated_human_needs_fresh_request_votes_and_approval_receipt(tmp_path):
    require_kernel()
    with configured(tmp_path, quorum=True) as data, ExitStack() as stack:
        service, _, _, channel, lease, grant, action, humans, _, native = data
        request = service.request(channel, lease, grant, action, idempotency_key="before-rotation")
        service.resolve(humans["alice"], request.request_id, "approve", idempotency_key="alice")
        receipt = service.resolve(
            humans["bob"], request.request_id, "approve", idempotency_key="bob"
        )["receipt"]
        directory, operator = service.directory, native[11]
        old = directory.require(humans["alice"], task_id="task", roles=("approve",))
        directory.revoke(old.enrollment_id, operator=operator)
        current = directory.enroll(
            principal_id="alice",
            certificate_digest=fingerprint("outsider"),
            roles=("approve", "observe", "break_glass", "recover"),
            task_ids=("task",),
            operator=operator,
        )
        for person, credential in (("alice", "outsider"), ("bob", "sibling")):
            socket, _ = stack.enter_context(tls_pair(directory.authenticator._tls, credential))
            humans[person] = directory.authenticate(socket)
        with pytest.raises(ValueError):
            service.prepare(receipt, channel, lease, action)
        fresh = service.request(channel, lease, grant, action, idempotency_key="after-rotation")
        first = service.resolve(
            humans["alice"], fresh.request_id, "approve", idempotency_key="new-alice"
        )
        assert first["status"] == "pending" and first["votes"] == 1
        again = service.resolve(
            humans["alice"], fresh.request_id, "approve", idempotency_key="same-human"
        )
        assert again["status"] == "pending" and again["votes"] == 1
        final = service.resolve(
            humans["bob"], fresh.request_id, "approve", idempotency_key="new-bob"
        )
        assert final["status"] == "approved" and final["votes"] == 2
        assert current.enrollment_id != old.enrollment_id and final["receipt"] is not receipt
        prepared = service.prepare(final["receipt"], channel, lease, action)
        assert prepared.reference is not None
        assert service.dispatch(final["receipt"]).status == "host_completed"
