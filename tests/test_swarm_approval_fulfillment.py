"""Protected human fulfillment and selective ordinary-allow execution."""

from copy import copy

import pytest

from ordin import ActionPolicyCondition, ActionPolicyRule, ActionPolicySet
from tests.test_swarm_approval import configured
from tests.test_swarm_broker import require_kernel


def test_human_fulfillment_uses_retained_exact_request_once(tmp_path):
    require_kernel()
    with configured(tmp_path, decision="warn") as data:
        service, _, _, channel, lease, grant, action, humans, _, native = data
        request = service.request(channel, lease, grant, action, idempotency_key="original")
        with pytest.raises(ValueError):
            service.fulfill(humans["alice"], request.request_id)
        assert not native[0]._pending
        service.resolve(humans["alice"], request.request_id, "approve", idempotency_key="human")
        with pytest.raises(ValueError):
            service.fulfill(channel, request.request_id)
        with pytest.raises(ValueError):
            service.fulfill(copy(humans["alice"]), request.request_id)
        result = service.fulfill(humans["alice"], request.request_id)
        assert result.status == "host_completed"
        assert result.value == b"broker-owned-benign-data\n"
        authorization = next(iter(native[0]._pending))
        decision = native[0].authorization_scope(authorization).decision
        assert decision.review.decision == "warn"
        assert decision.disposition == "escalate" and decision.approval_fulfilled
        with pytest.raises(ValueError):
            service.fulfill(humans["alice"], request.request_id)


def test_fulfillment_requires_all_distinct_current_votes(tmp_path):
    require_kernel()
    with configured(tmp_path, decision="warn", quorum=True) as data:
        service, _, _, channel, lease, grant, action, humans, _, native = data
        request = service.request(channel, lease, grant, action, idempotency_key="quorum")
        service.resolve(humans["alice"], request.request_id, "approve", idempotency_key="first")
        with pytest.raises(ValueError):
            service.fulfill(humans["alice"], request.request_id)
        assert not native[0]._pending
        service.resolve(humans["bob"], request.request_id, "approve", idempotency_key="second")
        assert service.fulfill(humans["bob"], request.request_id).status == "host_completed"


@pytest.mark.parametrize("change", ["expired_lease", "human_closed", "revoked", "epoch"])
def test_fulfillment_cannot_reuse_stale_or_foreign_currentness(tmp_path, change):
    require_kernel()
    with configured(tmp_path, decision="warn") as data:
        service, _, _, channel, lease, grant, action, humans, now, native = data
        request = service.request(channel, lease, grant, action, idempotency_key="current")
        service.resolve(humans["alice"], request.request_id, "approve", idempotency_key="approve")
        if change == "expired_lease":
            now[0] += 11
        elif change == "human_closed":
            service.directory.close(humans["alice"])
        elif change == "revoked":
            native[1].operator_revoke(grant, operator=native[11])
        else:
            native[14].advance_policy_epoch(1)
        with pytest.raises(ValueError):
            service.fulfill(humans["alice"], request.request_id)
        assert not native[0]._results


def test_governance_installation_keeps_known_ordinary_allow_without_human_votes(tmp_path):
    require_kernel()
    with configured(tmp_path, decision="allow") as data:
        service, coordinator, scope, channel, lease, grant, action, humans, _, native = data
        evaluated = coordinator.evaluate(
            scope, channel, lease, grant, action, idempotency_key="allow"
        )
        assert evaluated.reference is not None
        reservation = coordinator.reserve(
            scope, channel, lease, evaluated.reference, action, idempotency_key="allow-reserve"
        )
        result = coordinator.guarded_dispatch(
            scope, native[0]._broker_channel, reservation.reference
        )
        assert result.status == "host_completed", result.as_dict()
        assert result.value == b"broker-owned-benign-data\n"
        assert not service._originals and not service._receipts
        assert service.snapshot(humans["alice"], task_id="task")["requests"] == []


@pytest.mark.parametrize("decision", ["warn", "ask", "block"])
def test_no_human_preparation_is_not_a_warning_or_block_bypass(tmp_path, decision):
    require_kernel()
    with configured(tmp_path, decision=decision) as data:
        _, coordinator, scope, channel, lease, grant, action, _, _, native = data
        with pytest.raises(ValueError):
            coordinator.evaluate(scope, channel, lease, grant, action, idempotency_key="no-votes")
        assert not native[0]._pending and not native[0]._results


def test_prior_allow_cannot_be_borrowed_after_core_context_becomes_warning(tmp_path):
    require_kernel()
    with configured(tmp_path, decision="allow") as data:
        _, coordinator, scope, channel, lease, grant, action, _, _, native = data
        evaluated = coordinator.evaluate(
            scope, channel, lease, grant, action, idempotency_key="first"
        )
        reservation = coordinator.reserve(
            scope, channel, lease, evaluated.reference, action, idempotency_key="held"
        )
        core = native[1].assurance.ordin
        changed_policy = ActionPolicySet(
            "changed-warning",
            "1",
            (
                ActionPolicyRule(
                    "warn", "warn", ActionPolicyCondition(effects_any=("filesystem.read",))
                ),
            ),
        )
        object.__setattr__(core, "action_policy", changed_policy.compile())
        try:
            result = coordinator.guarded_dispatch(
                scope, native[0]._broker_channel, reservation.reference
            )
        except ValueError:
            pass
        else:
            assert result.status != "host_completed"
        assert not any(result.physical_enforcement for result in native[0]._results)
