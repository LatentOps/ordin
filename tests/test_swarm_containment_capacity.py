"""Concurrent containment admission reserves capacity before the durable fence."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest

from ordin.swarm.coordinator_store import CoordinatorRejected, CoordinatorUnavailable
from ordin.swarm.incident import IncidentPolicy, IncidentSignalSource, SwarmContainmentController
from tests.assurance.test_delegating_gate import action
from tests.test_swarm_containment import signal
from tests.test_swarm_coordinator import configured


def controller(data):
    signals = IncidentSignalSource(operator=data["operator"])
    value = SwarmContainmentController(
        data["coordinator"],
        data["scope"],
        control=data["control"],
        operator=data["operator"],
        policy=IncidentPolicy("capacity", 1, max_affected=2),
        signals=signals,
        max_incidents=1,
    )
    return value, signals


def epoch(data):
    with data["store"].transaction() as transaction:
        return transaction.scope(data["scope"].scope_key)["revocation_epoch"]


def test_pending_durable_fence_reserves_the_single_incident_slot(tmp_path, monkeypatch):
    with configured(tmp_path) as data:
        value, signals = controller(data)
        first = signal(data, signals, "action", agent="parent")
        second = signal(data, signals, "action", agent="child")
        original = data["coordinator"].record_fence
        entered, release = Event(), Event()
        calls = []

        def pause_first_fence(*args, **kwargs):
            calls.append(kwargs["actor_digest"])
            if len(calls) == 1:
                entered.set()
                assert release.wait(10), "test did not release the durable fence"
            return original(*args, **kwargs)

        monkeypatch.setattr(data["coordinator"], "record_fence", pause_first_fence)
        with ThreadPoolExecutor(max_workers=2) as pool:
            first_result = pool.submit(value.quarantine, first, operator=data["operator"])
            try:
                assert entered.wait(5), "first admission did not reach the durable boundary"
                rejected = pool.submit(value.quarantine, second, operator=data["operator"])
                with pytest.raises(ValueError, match="capacity"):
                    rejected.result(timeout=5)
                assert len(calls) == 1
                assert epoch(data) == 0
            finally:
                release.set()
            receipt = first_result.result(timeout=10)
        assert value._original(receipt).done.wait(5)
        assert epoch(data) == 1
        with pytest.raises(ValueError, match="capacity"):
            value.quarantine(second, operator=data["operator"])


@pytest.mark.parametrize("committed", [False, True], ids=["before-commit", "lost-ack"])
@pytest.mark.parametrize(
    "exception_type",
    [CoordinatorUnavailable, KeyboardInterrupt, asyncio.CancelledError],
    ids=lambda value: value.__name__,
)
def test_failed_admission_releases_only_capacity_not_its_consumed_signal_or_fence(
    tmp_path, monkeypatch, committed, exception_type
):
    with configured(tmp_path) as data:
        value, signals = controller(data)
        first = signal(data, signals, "action", agent="parent")
        original = data["coordinator"].record_fence
        failure = exception_type("interrupted containment admission")

        def interrupted_fence(*args, **kwargs):
            if committed:
                original(*args, **kwargs)
            raise failure

        monkeypatch.setattr(data["coordinator"], "record_fence", interrupted_fence)
        with pytest.raises(exception_type) as caught:
            value.quarantine(first, operator=data["operator"])
        assert caught.value is failure
        assert epoch(data) == int(committed)
        with pytest.raises(ValueError, match="already used"):
            value.quarantine(first, operator=data["operator"])
        if committed:
            with pytest.raises(CoordinatorRejected, match="fenced"):
                value.require_current(data["contexts"]["parent"], action("one"))

        monkeypatch.setattr(data["coordinator"], "record_fence", original)
        fresh = signal(data, signals, "action", agent="child")
        receipt = value.quarantine(fresh, operator=data["operator"])
        assert value._original(receipt).done.wait(5)
        assert epoch(data) == int(committed) + 1
        if committed:
            with pytest.raises(CoordinatorRejected, match="fenced"):
                value.require_current(data["contexts"]["parent"], action("one"))
