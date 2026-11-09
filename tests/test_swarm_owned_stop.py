"""Original-handle stop retries; deterministic faults create no native child."""

from threading import RLock

import pytest

from ordin import ToolCallAdapter
from ordin._runtime_json import digest
from ordin.enforcement_backend import EnforcementPlan
from ordin.runtime_contract import (
    RuntimeCapabilityContract,
    FilesystemCapability,
    ToolCapability,
    ProcessCapability,
    PrivilegeCapability,
)
from ordin.swarm.linux_backend import KernelJob, _Job
from ordin.swarm.owned_tools import LinuxOwnedToolsBackend
from ordin.swarm._owned_protocol import WRITE_PROTOCOL


class LifecycleProcess:
    """Deterministic Popen fault stand-in; this never launches or signals a PID."""

    def __init__(self):
        self.returncode = None
        self.kills = self.waits = 0
        self.refuse_stop = False

    def poll(self):
        return self.returncode

    def kill(self):
        self.kills += 1
        if self.refuse_stop:
            raise OSError("injected original-child kill failure")
        self.returncode = -9

    def wait(self, *, timeout):
        self.waits += 1
        assert self.returncode is not None
        return self.returncode


def retained_backend(*, process=None):
    """Bare concrete host state only; no install, forwarding or physical claim."""
    backend = LinuxOwnedToolsBackend.__new__(LinuxOwnedToolsBackend)
    operator = object()
    backend._operator = operator
    backend._lock, backend._jobs_lock = RLock(), RLock()
    backend._outcomes, backend._evidence = {}, {}
    backend._closing = False
    action = ToolCallAdapter("ordin-owned").adapt(
        "write_artifact",
        {
            "path": "/owned/report.txt",
            "content": "stop-only fixture",
            "expected_version": 0,
            "expected_digest": None,
        },
        action_id="owned-stop",
    )
    contract = RuntimeCapabilityContract(
        action.action_id,
        digest(action.as_dict()),
        "allow",
        "low",
        filesystem=(FilesystemCapability("write", "/owned/report.txt", "exact"),),
        tools=(ToolCapability("ordin-owned", None, "write_artifact"),),
        process=ProcessCapability(False, (), False),
        privilege=PrivilegeCapability(False),
        source={
            "kind": "tool",
            "operation": "call",
            "adapter": "owned_stop_fixture",
            "effects": ["filesystem.write"],
            "provenance_digest": None,
        },
    )
    plan = EnforcementPlan(backend.name, contract, {"profile": WRITE_PROTOCOL})
    job = KernelJob("original-upper-job")
    row = _Job(
        (plan.plan_id, contract.action_digest, contract.digest),
        state="unable_to_stop",
        process=process,
    )
    backend._jobs = {job: row}
    return backend, operator, plan, job, row


def test_unknown_owned_result_preserves_an_unstopped_original_child():
    process = LifecycleProcess()
    backend, operator, plan, job, row = retained_backend(process=process)
    result = backend._result(plan, "unknown", "broker.owned_uncertain", job=job)
    assert row.state == "unable_to_stop" and process.poll() is None
    assert row.outcome is result and result.status == "unknown"
    assert backend.verify_outcome(result, plan)


def test_owned_stop_retries_original_child_after_failed_cleanup_without_rewriting_unknown():
    process = LifecycleProcess()
    process.refuse_stop = True
    backend, operator, plan, job, row = retained_backend(process=process)
    result = backend._result(plan, "unknown", "broker.owned_uncertain", job=job)
    original = result.as_dict()
    assert backend.request_stop(job, operator=operator) == "unable_to_stop"
    assert process.kills == 1 and process.poll() is None
    process.refuse_stop = False
    assert backend.request_stop(job, operator=operator) == "unknown"
    assert process.kills == 2 and process.poll() == -9
    assert backend.request_stop(job, operator=operator) == "unknown"
    assert process.kills == 2 and row.outcome is result and result.as_dict() == original
    assert backend.verify_outcome(result, plan)


def test_stop_pins_original_pidfd_and_releases_only_its_duplicate(monkeypatch):
    process = LifecycleProcess()
    backend, operator, plan, job, row = retained_backend(process=process)
    row.pidfd = 1000
    result = backend._result(plan, "unknown", "broker.owned_uncertain", job=job)
    duplicates, closed, targets = [], [], []

    def duplicate(descriptor):
        duplicates.append(descriptor)
        return 1001

    def terminate(original, descriptor):
        targets.append((original, descriptor))
        return False

    monkeypatch.setattr("ordin.swarm.owned_tools.os.dup", duplicate)
    monkeypatch.setattr("ordin.swarm.owned_tools.os.close", closed.append)
    monkeypatch.setattr(backend, "_terminate", terminate)
    assert backend.request_stop(job, operator=operator) == "unable_to_stop"
    assert duplicates == [1000] and targets == [(process, 1001)] and closed == [1001]
    assert row.pidfd == 1000 and row.outcome is result and result.status == "unknown"


@pytest.mark.parametrize("recycled", [False, True])
def test_producer_exit_and_close_before_dup_never_signals_a_recycled_descriptor(
    monkeypatch, recycled
):
    process = LifecycleProcess()
    backend, operator, plan, job, row = retained_backend(process=process)
    row.pidfd = 1000
    result = backend._result(plan, "unknown", "broker.owned_uncertain", job=job)
    closed = []

    def duplicate(descriptor):
        assert descriptor == 1000
        # The producer first observes/reaps this SAME Popen, then closes the fd.
        process.returncode = 0
        row.pidfd = None
        if recycled:
            return 1001  # A duplicate of an unrelated, subsequently reused fd.
        raise OSError("original descriptor was already closed")

    def never_signal(*args):
        pytest.fail("terminal original child caused an unrelated fd to be signaled")

    monkeypatch.setattr("ordin.swarm.owned_tools.os.dup", duplicate)
    monkeypatch.setattr("ordin.swarm.owned_tools.os.close", closed.append)
    monkeypatch.setattr(
        "ordin.swarm.linux_backend.signal.pidfd_send_signal", never_signal, raising=False
    )
    assert backend.request_stop(job, operator=operator) == "unknown"
    assert process.kills == 0 and process.waits == 0
    assert closed == ([1001] if recycled else []) and row.outcome is result


@pytest.mark.parametrize(
    "status,code,expected", [("completed", 0, "completed"), ("canceled", -9, "canceled")]
)
def test_owned_terminal_stop_is_idempotent_and_rejects_foreign_custody(status, code, expected):
    process = LifecycleProcess()
    process.returncode = code
    backend, operator, plan, job, row = retained_backend(process=process)
    result = backend._result(plan, status, "broker.owned_terminal", job=job)
    with pytest.raises(ValueError):
        backend.request_stop(KernelJob(job.job_id), operator=operator)
    with pytest.raises(ValueError):
        backend.request_stop(job, operator=object())
    assert backend.request_stop(job, operator=operator) == expected
    assert backend.job_status(job, operator=operator) == (
        "canceled" if status == "canceled" else "finished"
    )
    assert backend.request_stop(job, operator=operator) == expected
    assert backend.job_status(job, operator=operator) == (
        "canceled" if status == "canceled" else "finished"
    )
    assert process.kills == 0 and row.outcome is result


def test_direct_close_retries_original_child_fences_execution_and_retains_failed_custody():
    process = LifecycleProcess()
    process.refuse_stop = True
    backend, operator, plan, job, row = retained_backend(process=process)
    result = backend._result(plan, "unknown", "broker.owned_uncertain", job=job)

    class Storage:
        closed = False

        def close(self):
            self.closed = True

    storage = backend._managed_state = Storage()
    backend._fd = -1
    with pytest.raises(RuntimeError, match="close must be retried"):
        backend.close()
    assert backend._closing and not storage.closed and backend._managed_state is storage
    assert row.outcome is result and process.poll() is None and row.state == "unable_to_stop"
    with pytest.raises(ValueError, match="closing"):
        backend.create_job(plan, operator=operator)
    with pytest.raises(ValueError, match="closing"):
        backend._verify_install()
    with pytest.raises(ValueError, match="closing"):
        backend.execute(plan, None, None, operator=operator, job=job)
    process.refuse_stop = False
    backend.close()
    assert storage.closed and backend._managed_state is None and process.poll() == -9
    assert (
        row.outcome is result
        and result.status == "unknown"
        and backend.verify_outcome(result, plan)
    )
    kills = process.kills
    backend.close()
    assert process.kills == kills and row.outcome is result


def test_close_rechecks_a_child_published_after_the_first_stop_snapshot(monkeypatch):
    process = LifecycleProcess()
    process.refuse_stop = True
    backend, operator, plan, job, row = retained_backend()
    row.state = "checking"

    class Storage:
        closed = False

        def close(self):
            self.closed = True

    storage = backend._managed_state = Storage()
    backend._fd = -1
    stop_jobs = backend._close_stop_jobs
    calls = []

    def publish_in_flight_child(jobs):
        stop_jobs(jobs)
        calls.append(tuple(jobs))
        if len(calls) == 1:
            # Creation was already in flight before close fenced admission.
            row.process = process
            row.state = "running"

    monkeypatch.setattr(backend, "_close_stop_jobs", publish_in_flight_child)
    with pytest.raises(RuntimeError, match="close must be retried"):
        backend.close()
    assert len(calls) == 1 and process.kills == 1 and not storage.closed
    assert backend._closing and row.state == "unable_to_stop"
    process.refuse_stop = False
    backend.close()
    assert process.poll() == -9 and storage.closed
