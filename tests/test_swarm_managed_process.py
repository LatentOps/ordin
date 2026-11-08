"""Actual owned-process confinement; unsupported platforms never substitute callbacks."""

from copy import copy
import hashlib
import json
import os
from pathlib import Path
import sys

import pytest

from ordin.swarm.managed_process import (
    LinuxProtectedProcess,
    ProtectedProcessJob,
    ProtectedProcessLimits,
)


def factory(tmp_path, program):
    target = tmp_path / "agent.py"
    target.write_text(program, encoding="utf-8")
    install = tmp_path / "install"
    install.mkdir(mode=0o700)
    operator = object()
    engine = LinuxProtectedProcess(install, operator=operator)
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
