"""Real current policy, original broker, owned Linux effect and DB accounting."""

from dataclasses import replace
from copy import copy

import pytest

from ordin.swarm.budgets import BudgetPolicy
from ordin.swarm.coordinator import SwarmCoordinator
from ordin.swarm.coordinator_store import (
    CoordinatorClock,
    CoordinatorRejected,
    SQLiteCoordinatorStore,
)
from tests.test_swarm_broker import fixture, require_kernel
from tests.test_swarm_policy_broker import current_policy_broker, scoped_policy


@pytest.mark.parametrize("incident", [False, True])
def test_real_owned_broker_joins_db_budget_and_current_policy_without_double_consumption(
    tmp_path, incident
):
    require_kernel()
    store = SQLiteCoordinatorStore(tmp_path / "authority.db", create=True, clock=lambda: 100)
    clock = CoordinatorClock(store)
    (tmp_path / "broker").mkdir()
    with fixture(tmp_path / "broker", shared_clock=clock) as data:
        selected = scoped_policy(data[13])
        with current_policy_broker(data, selected, shared_clock=clock) as current:
            runtime, broker, _, service, channel, grant, context, operator = current
            coordinator = SwarmCoordinator(store, operator=operator, clock=clock)
            control = coordinator.control_source(operator=operator)
            scope = coordinator.register_scope(
                service,
                BudgetPolicy(
                    runtime.epoch,
                    tuple(
                        replace(limit, maximum=1) if limit.metric == "requests" else limit
                        for limit in runtime._budget.policy.limits
                    ),
                ),
                control=control,
                broker_channels=(broker._broker_channel,),
                brokers=(("host-b", broker),),
                runtime=runtime,
            )
            coordinator.initialize_scope(scope, control=control)
            view = coordinator.budget_view(scope, control=control)
            assert runtime._coordinator_budget is view
            coordinator.start(scope, control=control)
            parent_channel = next(
                handle
                for handle, row in service.authenticator._channels.items()
                if row.enrollment.context is not None
                and row.enrollment.context.identity.agent_id == "parent"
            )
            parent_grant = next(
                reference for reference, row in service._grants.items() if row.parent_ref is None
            )
            parent_lease = coordinator.admit(scope, parent_channel)
            child_lease = coordinator.admit(scope, channel)
            coordinator.bind_grant(scope, parent_channel, parent_lease.reference, parent_grant)
            coordinator.bind_grant(scope, channel, child_lease.reference, grant)
            before = runtime.evidence_digest(context)
            evaluated = coordinator.evaluate(
                scope, channel, child_lease.reference, grant, data[4], idempotency_key="evaluate"
            )
            reserved = coordinator.reserve(
                scope,
                channel,
                child_lease.reference,
                evaluated.reference,
                data[4],
                idempotency_key="reserve",
            )
            assert runtime.evidence_digest(context) != before
            if incident:
                authorization = coordinator._prepared[reserved.reference].authorization
                coordinator.begin_forward(scope, broker._broker_channel, reserved.reference)
                fence = coordinator.record_fence(
                    scope, control=control, kind="action", subject_digest=reserved.action_digest
                )
                coordinator.start(scope, control=control, takeover=True)
                receipt = broker.request_stop(authorization)
                assert receipt.status == "canceled"
                for forged in (copy(receipt), receipt.as_dict(), True):
                    with pytest.raises(CoordinatorRejected):
                        coordinator.reconcile_broker_outcome(
                            scope,
                            reserved.reference,
                            forged,
                            control=control,
                            revocation_epoch=fence.revocation_epoch,
                        )
                result = coordinator.reconcile_broker_outcome(
                    scope,
                    reserved.reference,
                    receipt,
                    control=control,
                    revocation_epoch=fence.revocation_epoch,
                )
                assert result.status == "canceled_holds_retained"
                with store.transaction() as transaction:
                    row = transaction.scope(scope.scope_key)["reservations"][reserved.reference]
                    assert (
                        row["status"] == "uncertain"
                        and row["incident_outcome"]["status"] == "canceled"
                    )
                    assert (
                        transaction.connection.execute(
                            "SELECT sum(held) FROM coordinator_buckets WHERE metric='requests'"
                        ).fetchone()[0]
                        == 1
                    )
                return
            result = coordinator.guarded_dispatch(scope, broker._broker_channel, reserved.reference)
            assert result.status == "host_completed", result.as_dict()
            assert result.value == b"broker-owned-benign-data\n"
            report = coordinator.budget_report(scope, channel, child_lease.reference)
            request_limit = next(row for row in report["limits"] if row["metric"] == "requests")
            assert request_limit["consumed"] == 1 and request_limit["reserved"] == 0
            with pytest.raises(CoordinatorRejected):
                coordinator.guarded_dispatch(scope, broker._broker_channel, reserved.reference)
            next_action = replace(data[4], action_id="no-second-budget")
            next_evaluation = coordinator.evaluate(
                scope,
                channel,
                child_lease.reference,
                grant,
                next_action,
                idempotency_key="next-evaluate",
            )
            with pytest.raises(CoordinatorRejected, match="budget"):
                coordinator.reserve(
                    scope,
                    channel,
                    child_lease.reference,
                    next_evaluation.reference,
                    next_action,
                    idempotency_key="next-reserve",
                )
