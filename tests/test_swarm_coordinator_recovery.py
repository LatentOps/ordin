"""Crash/partition/replay and authenticated causal history regressions."""

from contextlib import contextmanager
from dataclasses import replace
import json

import pytest

from ordin._runtime_json import digest
from ordin.swarm.coordinator import SwarmCoordinator
from ordin.swarm.coordinator_store import CoordinatorRejected, CoordinatorUnavailable
from ordin.swarm.events import EventRef, SwarmEvent
from tests.test_swarm_coordinator import configured, prepare


def restart(data):
    coordinator = SwarmCoordinator(data["store"], operator=data["operator"], clock=data["clock"])
    control = coordinator.control_source(operator=data["operator"])
    scope = coordinator.register_scope(
        data["native"],
        data["budget"],
        control=control,
        broker_channels=(data["channels"]["broker-a"], data["channels"]["broker-b"]),
    )
    return coordinator, scope, control


def test_takeover_fences_old_owner_and_retains_uncertain_budget(tmp_path):
    with configured(tmp_path) as data:
        old, old_scope = data["coordinator"], data["scope"]
        _, _, reserved = prepare(data)
        old.begin_forward(old_scope, data["channels"]["broker-b"], reserved.reference)
        new, scope, control = restart(data)
        with pytest.raises(CoordinatorRejected, match="active_owner"):
            new.start(scope, control=control)
        new.start(scope, control=control, takeover=True)
        with pytest.raises(CoordinatorRejected):
            old.begin_forward(old_scope, data["channels"]["broker-b"], reserved.reference)
        with data["store"].transaction() as transaction:
            state = transaction.scope(scope.scope_key)
            assert state["reservations"][reserved.reference]["status"] == "uncertain"
            assert all(row["status"] == "requires_revalidation" for row in state["grants"].values())
            bucket = transaction.connection.execute(
                "SELECT held,consumed FROM coordinator_buckets"
            ).fetchone()
            assert tuple(bucket.values()) == (1, 0)
        assert not new._prepared
        with pytest.raises(CoordinatorRejected):
            new.begin_forward(scope, data["channels"]["broker-b"], reserved.reference)


def test_lost_forward_ack_never_calls_executor_or_refunds_hold(tmp_path, monkeypatch):
    with configured(tmp_path) as data:
        coordinator, scope = data["coordinator"], data["scope"]
        _, _, reserved = prepare(data)
        original = data["store"].transaction

        @contextmanager
        def lost_ack():
            with original() as transaction:
                yield transaction
            raise CoordinatorUnavailable("lost durable acknowledgement")

        monkeypatch.setattr(data["store"], "transaction", lost_ack)
        called = []
        with pytest.raises(CoordinatorUnavailable):
            coordinator.guarded_dispatch(
                scope,
                data["channels"]["broker-b"],
                reserved.reference,
                forward=lambda action: called.append(action),
            )
        monkeypatch.setattr(data["store"], "transaction", original)
        assert called == []
        with original() as transaction:
            assert (
                transaction.scope(scope.scope_key)["reservations"][reserved.reference]["status"]
                == "forwarding"
            )
            assert (
                transaction.connection.execute("SELECT held FROM coordinator_buckets").fetchone()[0]
                == 1
            )


@pytest.mark.parametrize("mode", ["workload_expiry", "owner_expiry", "clock_rollback"])
def test_stale_leases_and_db_clock_skew_never_forward(tmp_path, mode):
    with configured(tmp_path) as data:
        coordinator, scope = data["coordinator"], data["scope"]
        _, _, reserved = prepare(data)
        data["now"][0] += {"workload_expiry": 11, "owner_expiry": 31, "clock_rollback": -1}[mode]
        called = []
        with pytest.raises((CoordinatorRejected, CoordinatorUnavailable)):
            coordinator.guarded_dispatch(
                scope,
                data["channels"]["broker-b"],
                reserved.reference,
                forward=lambda action: called.append(action),
            )
        assert called == []


def event(data, key, sequence, *, parents=(), who="child", timestamp=0):
    info = data["coordinator"].admission_context(
        data["scope"], data["channels"][who], data["leases"][who].reference
    )
    return SwarmEvent(
        key,
        "message_received",
        info["registry_id"],
        data["contexts"][who].identity,
        info["source_id"],
        sequence,
        timestamp,
        "host_authenticated",
        0,
        parent_event_ids=tuple(EventRef("tenant", "swarm", key) for key in parents),
    )


def ingest(data, value):
    return data["coordinator"].ingest_event(
        data["scope"], data["channels"]["child"], data["leases"]["child"].reference, value
    )


def test_event_backfill_resolves_gap_and_replay_preserves_unknown_prehistory(tmp_path):
    with configured(tmp_path) as data:
        second = event(data, "second", 2, parents=("first",), timestamp=999999999)
        assert ingest(data, second)["incomplete"]
        with pytest.raises(CoordinatorRejected, match="history_incomplete"):
            prepare(data)
        first = event(data, "first", 1, timestamp=1)
        assert not ingest(data, first)["incomplete"]
        assert ingest(data, second)["status"] == "duplicate"
        checkpoint = data["coordinator"].checkpoint(data["scope"], control=data["control"])
        assert checkpoint["prehistory"] == "unknown" and not checkpoint["live_authority"]
        assert {row["admitted_at"] for row in checkpoint["projection"]["events"].values()} == {100}
        assert "999999999" not in json.dumps(checkpoint)
        again = data["coordinator"].checkpoint(data["scope"], control=data["control"])
        assert again == checkpoint
        new, scope, control = restart(data)
        new.start(scope, control=control, takeover=True)
        with data["store"].transaction() as transaction:
            assert (
                transaction.scope(scope.scope_key)["events"] == checkpoint["projection"]["events"]
            )


def test_event_forgery_conflicts_cycles_and_backend_claims_rejected_without_mutation(tmp_path):
    with configured(tmp_path) as data:
        first = event(data, "first", 1, parents=("second",))
        ingest(data, first)
        with pytest.raises(CoordinatorRejected, match="producer"):
            ingest(data, replace(first, event_id="forged", source_id="forged", source_sequence=2))
        with pytest.raises(CoordinatorRejected, match="cycle"):
            ingest(data, event(data, "second", 2, parents=("first",)))
        with pytest.raises(CoordinatorRejected, match="conflict"):
            ingest(data, replace(first, timestamp=2))
        observed = replace(
            event(data, "observation", 2),
            event_kind="observed",
            action_id="action",
            action_digest="a" * 64,
            review_event_id="review",
            parent_event_ids=(EventRef("tenant", "swarm", "review"),),
            evidence_class="backend_enforced",
            observation_digest="b" * 64,
            observed_outcome="completed",
        )
        with pytest.raises(CoordinatorRejected, match="backend_receipt"):
            ingest(data, observed)
        with data["store"].transaction() as transaction:
            assert len(transaction.scope(data["scope"].scope_key)["events"]) == 1


def test_revocation_survives_restart_and_json_cannot_resume(tmp_path):
    with configured(tmp_path) as data:
        _, _, reserved = prepare(data)
        coordinator, scope = data["coordinator"], data["scope"]
        receipt = coordinator.record_fence(
            scope,
            control=data["control"],
            kind="subtree",
            subject_digest=digest(["tenant", "swarm", "parent"]),
        )
        with pytest.raises(CoordinatorRejected):
            coordinator.begin_forward(scope, data["channels"]["broker-b"], reserved.reference)
        with pytest.raises(CoordinatorRejected, match="original_recovery"):
            coordinator.reconcile_fence(scope, receipt, {"safe": True}, control=data["control"])
        new, new_scope, control = restart(data)
        new.start(new_scope, control=control, takeover=True)
        assert (
            new.recover_fence(new_scope, receipt.revocation_epoch, control=control).intent_digest
            == receipt.intent_digest
        )
        with pytest.raises(CoordinatorRejected):
            new.admit(new_scope, data["channels"]["child"])


def test_projection_lag_denies_until_checkpoint_and_contains_no_raw_action(tmp_path):
    with configured(tmp_path, journal_lag=4) as data:
        coordinator, scope = data["coordinator"], data["scope"]
        with pytest.raises(CoordinatorRejected, match="projection_lag"):
            prepare(data)
        coordinator.checkpoint(scope, control=data["control"])
        prepare(data, request="safe")
        raw = data["store"].path.read_bytes()
        assert b"approval" not in raw and b"read_file" not in raw
