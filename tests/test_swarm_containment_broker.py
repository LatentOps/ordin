"""Stop an original owned Linux child and reconcile without erasing budget holds."""

from concurrent.futures import ThreadPoolExecutor
from copy import copy
import os
import signal
import time
from threading import Event

import pytest

from ordin.swarm.budgets import BudgetPolicy, BudgetLimit
from ordin.swarm.coordinator import SwarmCoordinator
from ordin.swarm.coordinator_store import CoordinatorClock, SQLiteCoordinatorStore
from ordin.swarm.incident import (
    IncidentPolicy,
    IncidentScope,
    IncidentSignalSource,
    SwarmContainmentController,
)
from tests.test_swarm_broker import fixture, require_kernel


def test_stop_original_owned_child_and_reconcile_current_incident_without_refund(
    tmp_path, monkeypatch
):
    require_kernel()
    store = SQLiteCoordinatorStore(tmp_path / "authority.db", create=True, clock=lambda: 100)
    clock = CoordinatorClock(store)
    (tmp_path / "broker").mkdir()
    with fixture(tmp_path / "broker", shared_clock=clock, executor_timeout_ms=10000) as data:
        (
            broker,
            native,
            ledger,
            backend,
            proposed,
            channel,
            grant,
            context,
            _,
            _,
            _,
            operator,
            *_,
        ) = data
        coordinator = SwarmCoordinator(store, operator=operator, clock=clock)
        control = coordinator.control_source(operator=operator)
        scope = coordinator.register_scope(
            native,
            BudgetPolicy(0, (BudgetLimit("swarm", "requests", 4),)),
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
        parent_grant = next(
            reference for reference, row in native._grants.items() if row.parent_ref is None
        )
        parent_lease = coordinator.admit(scope, parent_channel)
        lease = coordinator.admit(scope, channel)
        coordinator.bind_grant(scope, parent_channel, parent_lease.reference, parent_grant)
        coordinator.bind_grant(scope, channel, lease.reference, grant)
        signals = IncidentSignalSource(operator=operator)
        controller = SwarmContainmentController(
            coordinator,
            scope,
            control=control,
            operator=operator,
            policy=IncidentPolicy("owned-process", 1),
            signals=signals,
        )
        evaluated = coordinator.evaluate(
            scope, channel, lease.reference, grant, proposed, idempotency_key="evaluate"
        )
        reserved = coordinator.reserve(
            scope,
            channel,
            lease.reference,
            evaluated.reference,
            proposed,
            idempotency_key="reserve",
        )
        authorization = coordinator._prepared[reserved.reference].authorization
        original_scope = broker.authorization_scope(authorization)
        original_popen = __import__("subprocess").Popen
        started, children = Event(), []

        def stopped_owned_child(arguments, *args, **kwargs):
            process = original_popen(arguments, *args, **kwargs)
            if str(backend.worker) in arguments:
                # Only the just-created original fixture child is stopped. No
                # user/caller PID is accepted by the controller or executor.
                children.append(process)
                os.kill(process.pid, signal.SIGSTOP)
                started.set()
            return process

        monkeypatch.setattr("ordin.swarm.linux_backend.subprocess.Popen", stopped_owned_child)
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(
                coordinator.guarded_dispatch, scope, broker._broker_channel, reserved.reference
            )
            try:
                assert started.wait(5)
                deadline = time.monotonic() + 5
                job = broker._pending[authorization].owned_job
                while (
                    backend.job_status(job, operator=operator) != "running"
                    and time.monotonic() < deadline
                ):
                    time.sleep(0.005)
                assert backend.job_status(job, operator=operator) == "running"
                selected = signals.operator_signal(
                    IncidentScope("agent", "tenant", "swarm", "child"),
                    severity="critical",
                    operator=operator,
                )
                incident = controller.quarantine(selected, operator=operator)
                assert future.result(10).status == "unknown"
                assert controller._original(incident).done.wait(5)
            finally:
                for child in children:
                    if child.poll() is None:
                        child.kill()
                    child.wait(timeout=5)
        assert children and all(child.poll() is not None for child in children)
        status = broker.status(authorization)
        assert status.status == "canceled" and broker.verify_control_receipt(status, authorization)
        with pytest.raises(ValueError):
            controller.reconcile_job(incident, reserved.reference, copy(status), operator=operator)
        controller.reconcile_job(incident, reserved.reference, status, operator=operator)
        assert ledger.reservation_status(original_scope.budget_ticket)["status"] == "uncertain"
        with store.transaction() as transaction:
            row = transaction.scope(scope.scope_key)["reservations"][reserved.reference]
            assert row["status"] == "uncertain" and row["incident_outcome"]["status"] == "canceled"
            assert (
                transaction.connection.execute("SELECT held FROM coordinator_buckets").fetchone()[0]
                == 1
            )
        coordinator.start(scope, control=control, takeover=True)
        approval = controller.approve_resume(incident, operator=operator)
        assert controller.resume(incident, approval, operator=operator)["resumed"]
        with pytest.raises(ValueError):
            native.require_current(channel, grant)
