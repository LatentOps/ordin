"""Cleanup failures in an owned process cannot return completed test evidence."""

import io
from pathlib import Path
import subprocess
import threading
from types import SimpleNamespace

import pytest

from ordin.assurance._test_process import run_test_process
from .test_sandbox_tests import setup


@pytest.mark.parametrize("failure", ["wait_timeout", "wait_error", "kill_error"])
def test_process_cleanup_failure_returns_error_without_escaping(monkeypatch, tmp_path, failure):
    class Process:
        returncode = 0
        stdin = io.BytesIO()
        stdout = io.BytesIO(b"{}")
        stderr = io.BytesIO()

        def poll(self):
            return None if failure == "kill_error" else 0

        def wait(self, *, timeout):
            if failure == "wait_error":
                raise OSError("owned wait observation failure")
            raise subprocess.TimeoutExpired("owned test process", timeout)

        def kill(self):
            if failure == "kill_error":
                raise OSError("owned kill observation failure")

    class Tree:
        def close(self):
            pass

    monkeypatch.setattr(
        "ordin.assurance._test_process.launch_managed_process",
        lambda *args, **kwargs: (Process(), Tree()),
    )
    runtime = SimpleNamespace(
        executable=Path("owned-fixture"),
        arguments=(),
        trusted_cwd=tmp_path,
        private_home=tmp_path,
        timeout_ms=1,
        max_output_bytes=1024,
    )
    result = run_test_process(runtime, b"owned synthetic request", threading.Event())
    assert result["status"] == "error"
    assert result["stdout_bytes"] == 2


def test_unconfirmed_wait_cannot_issue_a_sandbox_receipt(setup, monkeypatch):
    from ordin.assurance import _test_process
    from ordin.assurance.sandbox_tests import run_sandbox_test

    launch = _test_process.launch_managed_process

    def uncertain_wait(*args, **kwargs):
        process, tree = launch(*args, **kwargs)
        wait = process.wait

        def unconfirmed(*args, **kwargs):
            wait(*args, **kwargs)
            raise subprocess.TimeoutExpired("owned cleanup observation", 2)

        monkeypatch.setattr(process, "wait", unconfirmed)
        return process, tree

    monkeypatch.setattr(_test_process, "launch_managed_process", uncertain_wait)
    scope, source, runtime, program, suite, consent, _ = setup
    result = run_sandbox_test(scope, source, runtime, program, suite, consent())
    assert result.status == "error" and not result.results and result.proof_gaps


def test_reader_thread_start_failure_cleans_up_and_returns_unavailable(setup, monkeypatch):
    from ordin.assurance.sandbox_tests import run_sandbox_test

    def unavailable(self):
        raise RuntimeError("owned unavailable reader thread")

    monkeypatch.setattr("ordin.assurance._test_process.threading.Thread.start", unavailable)
    scope, source, runtime, program, suite, consent, _ = setup
    result = run_sandbox_test(scope, source, runtime, program, suite, consent())
    assert result.status == "unavailable" and not result.results and result.proof_gaps


def test_busy_reader_cannot_block_cleanup_on_its_buffered_stream_lock(monkeypatch, tmp_path):
    entered, release = threading.Event(), threading.Event()
    lock = threading.Lock()

    class HeldStream(io.BytesIO):
        def read(self, count):
            with lock:
                entered.set()
                release.wait(10)
                return b""

        def close(self):
            with lock:
                super().close()

    stream = HeldStream()

    class Process:
        returncode = 0
        stdin, stdout, stderr = io.BytesIO(), stream, io.BytesIO()

        def poll(self):
            return 0

        def wait(self, *, timeout):
            return 0

    class Tree:
        def close(self):
            pass

    monkeypatch.setattr(
        "ordin.assurance._test_process.launch_managed_process",
        lambda *args, **kwargs: (Process(), Tree()),
    )
    runtime = SimpleNamespace(
        executable=Path("owned-fixture"),
        arguments=(),
        trusted_cwd=tmp_path,
        private_home=tmp_path,
        timeout_ms=100,
        max_output_bytes=1024,
    )
    results = []
    runner = threading.Thread(
        target=lambda: results.append(
            run_test_process(runtime, b"owned synthetic request", threading.Event())
        )
    )
    runner.start()
    try:
        assert entered.wait(2)
        runner.join(timeout=3)
        assert not runner.is_alive(), "cleanup waited for a busy buffered stream lock"
        assert results[0]["status"] == "error" and not stream.closed
    finally:
        release.set()
        runner.join(timeout=2)
