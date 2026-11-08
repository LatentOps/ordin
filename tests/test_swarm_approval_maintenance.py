"""Protected daemon maintenance never renews human votes or delegated authority."""

from contextlib import contextmanager
from copy import copy

import pytest

from ordin.swarm.coordinator_store import CoordinatorUnavailable
from tests.test_swarm_approval import configured
from tests.test_swarm_broker import require_kernel
from tests.test_swarm_delegation import fingerprint, tls_pair


def owner_fence(coordinator, scope):
    with coordinator.store.transaction() as transaction:
        return transaction.scope(scope.scope_key)["owner"]["fence"]


def test_factory_refresh_keeps_original_pending_deadline_and_votes(tmp_path):
    require_kernel()
    with configured(tmp_path, decision="warn", quorum=True) as data:
        service, coordinator, scope, channel, lease, grant, action, humans, now, native = data
        request = service.request(channel, lease, grant, action, idempotency_key="pending")
        service.resolve(humans["alice"], request.request_id, "approve", idempotency_key="one")
        broker, operator = native[0], native[11]
        now[0] += 2
        policy = coordinator._policy(coordinator._scope(scope))[1]
        proof = broker.activation_proof(policy, operator=operator)
        service.refresh_factory_proof(
            "host-b", proof, operator=operator, expected_owner_fence=owner_fence(coordinator, scope)
        )
        assert service._factory_proofs["host-b"] is proof
        pending = service.get_request(humans["alice"], request.request_id)
        assert pending["request"]["expires_at"] == request.expires_at
        assert pending["vote_count"] == 1 and pending["status"] == "pending"
        now[0] += 9
        with pytest.raises(ValueError):
            service.fulfill(humans["alice"], request.request_id)
        assert service.get_request(humans["alice"], request.request_id)["status"] == "expired"
        assert not broker._results


@pytest.mark.parametrize("change", ["operator", "fence", "host", "copy", "policy", "nested"])
def test_factory_refresh_requires_original_factory_policy_and_current_owner(tmp_path, change):
    require_kernel()
    with configured(tmp_path) as data:
        service, coordinator, scope, _, _, _, _, _, _, native = data
        broker, operator = native[0], native[11]
        old = service._factory_proofs["host-b"]
        selected = coordinator._policy(coordinator._scope(scope))[1]
        proof = broker.activation_proof(
            "a" * 64 if change == "policy" else selected, operator=operator
        )
        chosen = copy(proof) if change == "copy" else proof
        kwargs = {
            "operator": object() if change == "operator" else operator,
            "expected_owner_fence": owner_fence(coordinator, scope) + (change == "fence"),
        }
        host = "host-a" if change == "host" else "host-b"
        if change == "nested":
            with coordinator.store.transaction(), pytest.raises(ValueError):
                service.refresh_factory_proof(host, chosen, **kwargs)
        else:
            with pytest.raises(ValueError):
                service.refresh_factory_proof(host, chosen, **kwargs)
        assert service._factory_proofs["host-b"] is old


def test_factory_refresh_lost_commit_ack_does_not_publish_pin(tmp_path, monkeypatch):
    require_kernel()
    with configured(tmp_path) as data:
        service, coordinator, scope, _, _, _, _, _, _, native = data
        broker, operator = native[0], native[11]
        old = service._factory_proofs["host-b"]
        policy = coordinator._policy(coordinator._scope(scope))[1]
        proof = broker.activation_proof(policy, operator=operator)
        fence = owner_fence(coordinator, scope)
        original = coordinator.store.transaction

        @contextmanager
        def lost_ack():
            with original() as transaction:
                yield transaction
            raise CoordinatorUnavailable("owned committed refresh acknowledgement loss")

        monkeypatch.setattr(coordinator.store, "transaction", lost_ack)
        with pytest.raises(ValueError):
            service.refresh_factory_proof(
                "host-b", proof, operator=operator, expected_owner_fence=fence
            )
        assert service._factory_proofs["host-b"] is old
        monkeypatch.setattr(coordinator.store, "transaction", original)
        service.refresh_factory_proof(
            "host-b", proof, operator=operator, expected_owner_fence=fence
        )
        assert service._factory_proofs["host-b"] is proof


def test_same_mtls_broker_renews_at_31s_without_renewing_pending_human_request(tmp_path):
    require_kernel()
    with configured(tmp_path, decision="allow") as data:
        service, coordinator, scope, channel, lease, grant, action, humans, now, native = data
        broker, operator, auth = native[0], native[11], native[1].authenticator
        old_broker = broker._broker_channel
        original_socket = auth._channels[old_broker].socket
        workload_socket = auth._channels[channel].socket
        parent_channel = next(
            handle
            for handle, row in auth._channels.items()
            if row.enrollment.context is not None
            and row.enrollment.context.identity.agent_id == "parent"
        )
        parent_socket = auth._channels[parent_channel].socket
        parent_grant = next(
            reference for reference, row in native[1]._grants.items() if row.parent_ref is None
        )
        request = service.request(channel, lease, grant, action, idempotency_key="old")
        service.resolve(humans["alice"], request.request_id, "approve", idempotency_key="vote")
        now[0] += 20
        for enrollment in tuple(auth._enrollments.values()):
            if enrollment.role == "workload":
                native[14].heartbeat(
                    enrollment.context, enrollment.registry_channel, enrollment.adapter
                )
        coordinator.heartbeat(scope, control=service._control)
        now[0] += 11
        renewed = auth.authenticate(original_socket)
        assert renewed is not old_broker
        fence = owner_fence(coordinator, scope)
        coordinator.refresh_broker_channel(
            scope, renewed, control=service._control, operator=operator, expected_owner_fence=fence
        )
        assert coordinator._scope(scope).broker_channels["host-b"] is renewed
        assert broker._broker_channel is renewed
        with pytest.raises(ValueError):
            auth.require(old_broker, role="broker")
        with pytest.raises(ValueError):
            service.fulfill(humans["alice"], request.request_id)
        fresh_parent = auth.authenticate(parent_socket)
        parent_lease = coordinator.admit(scope, fresh_parent).reference
        coordinator.bind_grant(scope, fresh_parent, parent_lease, parent_grant)
        fresh_channel = auth.authenticate(workload_socket)
        fresh_lease = coordinator.admit(scope, fresh_channel).reference
        coordinator.bind_grant(scope, fresh_channel, fresh_lease, grant)
        evaluated = coordinator.evaluate(
            scope, fresh_channel, fresh_lease, grant, action, idempotency_key="fresh"
        )
        reservation = coordinator.reserve(
            scope,
            fresh_channel,
            fresh_lease,
            evaluated.reference,
            action,
            idempotency_key="reserve",
        )
        assert (
            coordinator.guarded_dispatch(scope, renewed, reservation.reference).status
            == "host_completed"
        )
        with coordinator.store.transaction() as transaction:
            retained = transaction.scope(scope.scope_key)["governance"]["requests"][
                request.request_id
            ]
            assert retained["expires_at"] == request.expires_at and len(retained["votes"]) == 1


@pytest.mark.parametrize("change", ["operator", "fence", "workload", "foreign_broker", "copy"])
def test_broker_refresh_rejects_foreign_identity_and_control(tmp_path, change):
    require_kernel()
    with configured(tmp_path) as data:
        service, coordinator, scope, workload, _, _, _, _, _, native = data
        broker, operator, auth = native[0], native[11], native[1].authenticator
        old = broker._broker_channel
        channel = copy(old) if change == "copy" else workload if change == "workload" else old
        if change == "foreign_broker":
            auth.enroll_broker(
                host_id="host-a", certificate_digest=fingerprint("broker-a"), operator=operator
            )
            with tls_pair(auth._tls, "broker-a") as (server, _):
                channel = auth.authenticate(server)
                with pytest.raises(ValueError):
                    coordinator.refresh_broker_channel(
                        scope,
                        channel,
                        control=service._control,
                        operator=operator,
                        expected_owner_fence=owner_fence(coordinator, scope),
                    )
        else:
            with pytest.raises(ValueError):
                coordinator.refresh_broker_channel(
                    scope,
                    channel,
                    control=service._control,
                    operator=object() if change == "operator" else operator,
                    expected_owner_fence=owner_fence(coordinator, scope) + (change == "fence"),
                )
        assert broker._broker_channel is old
        assert coordinator._scope(scope).broker_channels["host-b"] is old
