"""Verified rebind preserves runtime identity and exposes no JSON admission authority."""

import pytest

from ordin.swarm import SwarmGate, SwarmContext
from ordin.swarm.delegation import BrokerAdmissionScope
from tests.test_swarm_delegation import configured, issue
from tests.assurance.test_delegating_gate import action


def test_protected_rebind_preserves_physical_session_and_fences_old_authorization(tmp_path):
    with configured(tmp_path) as data:
        (
            service,
            auth,
            issuer,
            _,
            _,
            channels,
            sources,
            contexts,
            registry,
            rchannels,
            adapters,
            _,
            operator,
            _,
            sockets,
        ) = data
        child = issue(data)
        old = contexts["child"]
        pending = service.review(channels["child"], child.grant_id, action("before-rebind"))
        rebound = service.bind_delegation_context(child.grant_id, operator=operator)
        assert rebound.identity.session_id == old.identity.session_id
        assert rebound.identity.runtime_id == old.identity.runtime_id
        assert rebound.identity.generation > old.identity.generation
        assert (
            rebound.identity.delegation_id == service._grants[child.grant_id].handle.record.grant_id
        )
        assert service.bind_delegation_context(child.grant_id, operator=operator) is rebound
        assert not issuer._pending
        with pytest.raises(ValueError):
            registry.authenticate(old, rchannels["child"], adapters["child"])
        with pytest.raises(ValueError):
            auth.require(channels["child"], role="workload")
        with pytest.raises(ValueError):
            registry.authenticate(
                SwarmContext.from_dict(rebound.as_dict()), rchannels["child"], adapters["child"]
            )
        gate = SwarmGate(registry, service._grants[child.grant_id].gate, delegation_context=rebound)
        decision = gate.evaluate_action(
            rebound, action("global-preview"), channel=rchannels["child"], adapter=adapters["child"]
        )
        assert decision.may_execute
        fresh_channel = auth.authenticate(sockets["child"][0])
        fresh = service.review(fresh_channel, child.grant_id, action("fresh-after-rebind"))
        scope = service.admission_scope(channels["broker-b"], fresh.admission_id)
        assert scope.context is rebound and scope.source is sources["child"]
        assert scope.delegating_gate is service._grants[child.grant_id].gate
        assert scope.delegated_decision is service._admissions[fresh.admission_id].decision
        assert scope.review_context is scope.delegated_decision._context
        assert scope.review_history is scope.delegated_decision._history
        assert scope.as_dict()["execution_authority"] is False
        with pytest.raises(ValueError, match="JSON"):
            BrokerAdmissionScope.from_dict(scope.to_wire())
        with pytest.raises(ValueError):
            service.admission_scope(channels["broker-a"], fresh.admission_id)
        with pytest.raises(ValueError):
            service.guarded_dispatch(
                channels["broker-b"], pending.admission_id, action("before-rebind"), lambda a: None
            )
        assert (
            service.guarded_dispatch(
                channels["broker-b"],
                fresh.admission_id,
                action("fresh-after-rebind"),
                lambda a: None,
            ).status
            == "host_completed"
        )
        with pytest.raises(ValueError):
            service.admission_scope(channels["broker-b"], fresh.admission_id)


def test_registry_rebind_rejects_json_grant_wrong_parent_and_revoked_relationship(tmp_path):
    with configured(tmp_path) as data:
        (
            service,
            _,
            _,
            _,
            _,
            channels,
            sources,
            contexts,
            registry,
            rchannels,
            adapters,
            _,
            operator,
            *_,
        ) = data
        child = issue(data)
        arguments = dict(
            parent_context=contexts["parent"],
            parent_channel=rchannels["parent"],
            parent_adapter=adapters["parent"],
            issuer=service.issuer,
            grant=service._grants[child.grant_id].handle,
            parent_source=sources["parent"],
            child_source=sources["child"],
        )
        with pytest.raises(ValueError):
            registry.rebind_delegation(
                contexts["child"],
                rchannels["child"],
                adapters["child"],
                **{**arguments, "grant": child.to_wire()},
            )
        with pytest.raises(ValueError):
            registry.rebind_delegation(
                contexts["child"],
                rchannels["child"],
                adapters["child"],
                **{
                    **arguments,
                    "parent_context": contexts["sibling"],
                    "parent_channel": rchannels["sibling"],
                    "parent_adapter": adapters["sibling"],
                },
            )
        service.operator_revoke(child.grant_id, operator=operator)
        with pytest.raises(ValueError):
            service.bind_delegation_context(child.grant_id, operator=operator)
        assert (
            registry.authenticate(contexts["child"], rchannels["child"], adapters["child"])
            is contexts["child"]
        )


def test_rebinding_parent_fences_descendant_unused_admission_without_resetting_session(tmp_path):
    with configured(tmp_path) as data:
        service, auth, issuer, _, _, channels, _, contexts, _, _, _, _, operator, _, sockets = data
        child = issue(data)
        grandchild = issue(data, "grandchild", parent=("child", child.grant_id))
        pending = service.review(
            channels["grandchild"], grandchild.grant_id, action("old-descendant")
        )
        service.bind_delegation_context(child.grant_id, operator=operator)
        assert not issuer._pending
        with pytest.raises(ValueError):
            service.guarded_dispatch(
                channels["broker-b"], pending.admission_id, action("old-descendant"), lambda a: None
            )
        rebound = service.bind_delegation_context(grandchild.grant_id, operator=operator)
        assert rebound.identity.session_id == contexts["grandchild"].identity.session_id
        new_channel = auth.authenticate(sockets["grandchild"][0])
        fresh = service.review(new_channel, grandchild.grant_id, action("fresh-descendant"))
        scope = service.admission_scope(channels["broker-b"], fresh.admission_id)
        assert scope.ancestry_digest
        assert (
            service.guarded_dispatch(
                channels["broker-b"], fresh.admission_id, action("fresh-descendant"), lambda a: None
            ).status
            == "host_completed"
        )
