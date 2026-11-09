"""Actual owned-process confinement; unsupported platforms never substitute callbacks."""

from copy import copy
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import time

import pytest

from ordin.swarm.managed_process import (
    LinuxProtectedProcess,
    ProtectedProcessJob,
    ProtectedProcessLimits,
)


def factory(tmp_path, program, *, limits=None):
    target = tmp_path / "agent.py"
    target.write_text(program, encoding="utf-8")
    install = tmp_path / "install"
    install.mkdir(mode=0o700)
    operator = object()
    kwargs = {} if limits is None else {"limits": limits}
    engine = LinuxProtectedProcess(install, operator=operator, **kwargs)
    job = engine.create_job(
        target, hashlib.sha256(target.read_bytes()).hexdigest(), operator=operator
    )
    return engine, job, operator


def ready_or_unsupported(engine, job, operator):
    if engine.start(job, operator=operator):
        return
    outcome = engine.finish(job, operator=operator)
    assert outcome.status == "unsupported" and outcome.isolation_digest is None
    if os.environ.get("ORDIN_REQUIRED_PROTECTED_PROCESS") == "1":
        pytest.fail("required protected process kernel/privilege profile is unavailable")
    pytest.skip("qualified privileged Linux mount/Landlock/seccomp profile unavailable")


def test_new_owned_python_process_has_real_kernel_boundaries_and_no_host_environment(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("ORDIN_HOST_SECRET_CANARY", "must-not-enter-the-child")
    program = """
import os, ctypes, errno
assert 'ORDIN_HOST_SECRET_CANARY' not in os.environ
for path in ('/etc/passwd', '/proc/self/environ', '/forbidden'):
    try:
        open(path, 'rb')
    except OSError:
        pass
    else:
        raise AssertionError('host path became readable')
libc=ctypes.CDLL(None,use_errno=True)
assert libc.syscall(41,2,1,0)==-1 and ctypes.get_errno()==errno.EPERM
try:
    os.fork()
except PermissionError:
    pass
else:
    os._exit(99)
with open('/tmp/owned.txt','w') as target:
    target.write('private bounded scratch')
print('owned-agent-finished')
"""
    engine, job, operator = factory(tmp_path, program)
    try:
        ready_or_unsupported(engine, job, operator)
        engine.admit(job, operator=operator)
        result = engine.finish(job, operator=operator)
        assert result.status == "exited" and result.exit_code == 0
        assert b"owned-agent-finished" in result.output
        assert result.isolation_digest is not None and engine.verify_outcome(result)
        assert not engine.verify_outcome(copy(result))
        evidence = engine.evidence_record(result)
        assert evidence["test_correctness_verified"] is False
        assert all(evidence["isolation"]["isolation"]["checks"].values())
        with pytest.raises(ValueError):
            engine.admit(job, operator=operator)
    finally:
        engine.close(operator=operator)


def test_private_child_channel_carries_only_bounded_mcp_data(tmp_path):
    engine, job, operator = factory(tmp_path, "print(mcp.call('ping'))")
    try:
        ready_or_unsupported(engine, job, operator)
        engine.admit(job, operator=operator)
        request = engine.read_request(job, operator=operator)
        assert request == {"jsonrpc": "2.0", "id": 1, "method": "ping"}
        engine.reply(job, {"jsonrpc": "2.0", "id": 1, "result": {"owned": True}}, operator=operator)
        assert engine.read_request(job, operator=operator) is None
        result = engine.finish(job, operator=operator)
        assert result.status == "exited" and result.exit_code == 0
        assert b"True" in result.output
    finally:
        engine.close(operator=operator)


@pytest.mark.parametrize("value", [True, 0, -1, 1 << 80])
def test_invalid_hard_bounds_are_refused(value):
    with pytest.raises(ValueError):
        ProtectedProcessLimits(timeout_ms=value)


def test_foreign_operator_job_copy_and_changed_program_cannot_launch(tmp_path):
    engine, job, operator = factory(tmp_path, "print('selected')")
    for foreign in (copy(job), ProtectedProcessJob(job.job_id)):
        with pytest.raises(ValueError):
            engine.start(foreign, operator=operator)
    with pytest.raises(ValueError):
        engine.start(job, operator=object())
    (tmp_path / "agent.py").write_text("print('changed')")
    with pytest.raises(ValueError, match="differs"):
        engine.create_job(tmp_path / "agent.py", "a" * 64, operator=operator)
    engine.request_stop(job, operator=operator)
    assert not engine.start(job, operator=operator)
    assert engine.finish(job, operator=operator).status == "canceled"
    engine.close(operator=operator)


@pytest.mark.skipif(
    sys.platform == "linux" and os.geteuid() == 0, reason="privileged Linux starts kernel probes"
)
def test_unsupported_platform_never_launches_a_child(tmp_path, monkeypatch):
    import subprocess

    engine, job, operator = factory(tmp_path, "raise AssertionError('never run')")

    def forbidden(*args, **kwargs):
        pytest.fail("unsupported profile launched a process")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    assert not engine.start(job, operator=operator)
    result = engine.finish(job, operator=operator)
    assert result.status == "unsupported" and result.isolation_digest is None
    json.dumps(result.as_dict(), allow_nan=False)
    engine.close(operator=operator)


class LifecycleProcess:
    """No child is created: deterministic host lifecycle fault injection only."""

    def __init__(self):
        self.returncode = None
        self.kills = self.waits = 0
        self.refuse_stop = False

    def poll(self):
        return self.returncode

    def kill(self):
        self.kills += 1
        if self.refuse_stop:
            raise OSError("injected stop failure")
        self.returncode = -9

    def wait(self, *, timeout):
        self.waits += 1
        assert self.returncode is not None
        return self.returncode


def lifecycle_fixture(tmp_path):
    engine, job, operator = factory(tmp_path, "raise AssertionError('never launched')")
    row = engine._jobs[job]
    row.state = "ready"
    row.process = LifecycleProcess()
    row.deadline = time.monotonic() + 30
    row.ready = {"phase": "unit-test-ready"}
    row.channel = io.BytesIO()
    row.output = io.BytesIO(b"bounded unit diagnostic")
    return engine, job, operator, row


@pytest.mark.parametrize("error_type", [RuntimeError, KeyboardInterrupt])
@pytest.mark.parametrize("cleanup_failure", [False, True])
def test_watchdog_start_failure_never_acknowledges_and_reaps_original_child(
    tmp_path, monkeypatch, error_type, cleanup_failure
):
    engine, job, operator, row = lifecycle_fixture(tmp_path)
    if cleanup_failure:

        class UnreadableDiagnostic(io.BytesIO):
            def read(self, *args):
                raise OSError("injected diagnostic read failure")

        row.output.close()
        row.output = UnreadableDiagnostic()
    process, channel, output = row.process, row.channel, row.output
    fault = error_type("cannot start new thread")

    class BrokenThread:
        def __init__(self, **kwargs):
            pass

        def start(self):
            raise fault

    def never_acknowledge(*args, **kwargs):
        pytest.fail("unmonitored child received START acknowledgement")

    monkeypatch.setattr("ordin.swarm.managed_process.Thread", BrokenThread)
    monkeypatch.setattr(engine, "_send", never_acknowledge)
    with pytest.raises(error_type) as raised:
        engine.admit(job, operator=operator)
    assert raised.value is fault
    assert process.returncode == -9 and process.kills == process.waits == 1
    assert channel.closed and output.closed and row.channel is row.output is None
    outcome = engine.finish(job, operator=operator)
    assert outcome.status == "unknown" and engine.verify_outcome(outcome)
    assert row.stop_reason == "admission_failed"
    with pytest.raises(ValueError, match="kernel-ready"):
        engine.admit(job, operator=operator)
    engine.close(operator=operator)


def test_start_acknowledgement_follows_successful_watchdog_start(tmp_path, monkeypatch):
    engine, job, operator, row = lifecycle_fixture(tmp_path)
    events = []

    class StartedThread:
        def __init__(self, **kwargs):
            pass

        def start(self):
            events.append("watchdog-started")

    def acknowledge(row, message, maximum):
        assert events == ["watchdog-started"]
        events.append("start-acknowledged")

    monkeypatch.setattr("ordin.swarm.managed_process.Thread", StartedThread)
    monkeypatch.setattr(engine, "_send", acknowledge)
    engine.admit(job, operator=operator)
    assert events == ["watchdog-started", "start-acknowledged"]
    assert engine.request_stop(job, operator=operator) == "canceled"
    assert row.process.kills == 1 and row.process.poll() == -9
    assert engine.finish(job, operator=operator).status == "canceled"
    engine.close(operator=operator)


def test_failed_admission_uncertainty_is_retained_until_original_child_can_be_stopped(
    tmp_path, monkeypatch
):
    engine, job, operator, row = lifecycle_fixture(tmp_path)
    process, channel, output = row.process, row.channel, row.output
    process.refuse_stop = True

    class BrokenThread:
        def __init__(self, **kwargs):
            pass

        def start(self):
            raise RuntimeError("cannot start new thread")

    monkeypatch.setattr("ordin.swarm.managed_process.Thread", BrokenThread)
    with pytest.raises(RuntimeError, match="cannot start"):
        engine.admit(job, operator=operator)
    outcome = engine.finish(job, operator=operator)
    assert outcome.status == "unknown" and process.poll() is None
    assert not channel.closed and not output.closed
    process.refuse_stop = False
    engine.request_stop(job, operator=operator)
    assert process.poll() == -9
    # Explicit stopping never retries the workload or rewrites an unknown result.
    assert engine.finish(job, operator=operator) is outcome
    assert channel.closed and output.closed and engine.verify_outcome(outcome)
    engine.close(operator=operator)


@pytest.mark.parametrize("cancel", [True, False])
def test_native_sleeping_agent_is_stopped_by_cancel_or_original_wall_deadline(tmp_path, cancel):
    engine, job, operator = factory(
        tmp_path, "import time\ntime.sleep(60)\n", limits=ProtectedProcessLimits(timeout_ms=1500)
    )
    try:
        ready_or_unsupported(engine, job, operator)
        engine.admit(job, operator=operator)
        if cancel:
            assert engine.request_stop(job, operator=operator) == "canceled"
        outcome = engine.finish(job, operator=operator)
        assert outcome.status == ("canceled" if cancel else "unknown")
        assert outcome.exit_code is not None and outcome.exit_code < 0
        assert engine._jobs[job].process.poll() is not None
        assert outcome.isolation_digest is not None and engine.verify_outcome(outcome)
    finally:
        engine.close(operator=operator)
