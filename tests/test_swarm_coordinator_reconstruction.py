"""Explicit fresh-policy restart retains spent and uncertain durable budgets."""

import pytest

from ordin.swarm.coordinator_store import CoordinatorRejected
from tests.test_swarm_coordinator import configured, prepare


def buckets(store):
    with store.transaction() as transaction:
        return [
            dict(row)
            for row in transaction.connection.execute(
                "SELECT bucket,maximum,held,consumed FROM coordinator_buckets ORDER BY bucket"
            ).fetchall()
        ]


def test_fresh_runtime_takeover_requires_fresh_epoch_and_retains_spent_and_uncertain(tmp_path):
    with configured(tmp_path / "first", limit=4) as first:
        coordinator, scope = first["coordinator"], first["scope"]
        _, _, completed = prepare(first, request="completed")
        result = coordinator.guarded_dispatch(
            scope, first["channels"]["broker-b"], completed.reference, forward=lambda _: "done"
        )
        assert result.status == "host_completed"
        _, _, uncertain = prepare(first, request="uncertain")
        coordinator.begin_forward(scope, first["channels"]["broker-b"], uncertain.reference)
        checkpoint = coordinator.checkpoint(scope, control=first["control"])
        assert not checkpoint["live_authority"]
        store, old_policy = first["store"], coordinator._policy(coordinator._scope(scope))[1]
        original = buckets(store)
        assert sum(row["consumed"] for row in original) == 1
        assert sum(row["held"] for row in original) == 1
        with pytest.raises(CoordinatorRejected, match="recovery_policy_mismatch"):
            with configured(
                tmp_path / "same-epoch",
                backend=store,
                limit=4,
                initialize=False,
                takeover=True,
            ):
                pytest.fail("new process policy cannot inherit unchanged epoch authority")
        assert buckets(store) == original
        with configured(
            tmp_path / "new-epoch",
            backend=store,
            limit=4,
            epoch=1,
            initialize=False,
            takeover=True,
        ) as new:
            assert new["scope"].scope_key == scope.scope_key
            assert (
                new["coordinator"]._policy(new["coordinator"]._scope(new["scope"]))[1] != old_policy
            )
            assert buckets(store) == original
            with store.transaction() as transaction:
                state = transaction.scope(scope.scope_key)
                assert state["policy_epoch"] == 1
                assert state["reservations"][uncertain.reference]["status"] == "uncertain"
                assert state["reservations"][completed.reference]["status"] == "committed"
            with pytest.raises(CoordinatorRejected):
                coordinator.begin_forward(scope, first["channels"]["broker-b"], uncertain.reference)
            _, _, fresh = prepare(new, request="fresh")
            assert fresh.reference is not None
            current = buckets(store)
            assert sum(row["consumed"] for row in current) == 1
            assert sum(row["held"] for row in current) == 2
