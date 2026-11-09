"""A scanner cannot outlive a failed host-side I/O setup."""

import io
from threading import Event, Lock, Thread

import pytest

from ordin.security import scanner
from .test_security_scanner import installation, fake


@pytest.mark.parametrize("failed_reader", [1, 2])
@pytest.mark.parametrize("failure", ["construct", "start"])
def test_reader_setup_failure_stops_and_reaps_original_child(
    installation, monkeypatch, failed_reader, failure
):
    selection = fake(installation[0], body="time.sleep(60)")
    launch, thread_class = scanner.launch_managed_process, scanner.threading.Thread
    processes, trees, readers, closed_trees = [], [], [], []

    def capture_launch(*args, **kwargs):
        process, tree = launch(*args, **kwargs)
        processes.append(process)
        trees.append(tree)
        close = tree.close

        def close_owned_tree():
            closed_trees.append(tree)
            close()

        monkeypatch.setattr(tree, "close", close_owned_tree)
        return process, tree

    def make_reader(*args, **kwargs):
        if len(readers) + 1 == failed_reader and failure == "construct":
            raise RuntimeError("injected host thread allocation failure")
        reader = thread_class(*args, **kwargs)
        readers.append(reader)
        if len(readers) == failed_reader and failure == "start":

            def fail_start():
                raise RuntimeError("injected host thread start failure")

            monkeypatch.setattr(reader, "start", fail_start)
        return reader

    monkeypatch.setattr(scanner, "launch_managed_process", capture_launch)
    monkeypatch.setattr(scanner.threading, "Thread", make_reader)
    try:
        status, code, _, _, _ = scanner._run(selection, ("--version",))
        assert status == "error"
        assert len(processes) == 1 and code is not None
        assert closed_trees == trees
        assert processes[0].poll() is not None
        assert all(not reader.is_alive() for reader in readers)
        assert processes[0].stdout.closed and processes[0].stderr.closed
    finally:
        # The regression must also clean up safely while running against old code.
        for tree in trees:
            tree.close()
        for process in processes:
            process.wait(timeout=2)
            for stream in (process.stdout, process.stderr):
                stream.close()
        for reader in readers:
            if reader.ident is not None:
                reader.join(timeout=2)


@pytest.mark.parametrize("operation", ["read", "close"])
def test_failed_output_reader_cannot_return_completed(installation, monkeypatch, operation):
    class FailedStream(io.BytesIO):
        def read(self, count):
            if operation == "read":
                raise OSError("injected scanner pipe read failure")
            return super().read(count)

        def close(self):
            super().close()
            if operation == "close":
                raise OSError("injected scanner pipe close failure")

    class Process:
        returncode = 0
        stdin = None
        stdout = FailedStream(b"0.2.0\n")
        stderr = io.BytesIO()

        def poll(self):
            return self.returncode

        def wait(self, *, timeout):
            return self.returncode

    class Tree:
        def close(self):
            pass

    monkeypatch.setattr(scanner, "launch_managed_process", lambda *a, **kw: (Process(), Tree()))
    status, code, _, _, _ = scanner._run(installation[0], ("--version",), cancel=Event())
    assert status == "error" and code == 0


def test_busy_output_reader_does_not_block_cleanup_on_stream_lock(installation, monkeypatch):
    entered, release, lock = Event(), Event(), Lock()

    class HeldStream(io.BytesIO):
        def read(self, count):
            with lock:
                entered.set()
                release.wait(10)
                return b""

        def close(self):
            with lock:
                super().close()

    held = HeldStream()

    class Process:
        returncode = 0
        stdout, stderr = held, io.BytesIO()

        def poll(self):
            return 0

        def wait(self, *, timeout):
            return 0

    class Tree:
        def close(self):
            pass

    monkeypatch.setattr(scanner, "launch_managed_process", lambda *a, **kw: (Process(), Tree()))
    results = []
    runner = Thread(target=lambda: results.append(scanner._run(installation[0], ("--version",))))
    runner.start()
    try:
        assert entered.wait(2)
        runner.join(timeout=3)
        assert not runner.is_alive(), "cleanup waited on a live buffered reader's lock"
        assert results[0][0] == "error" and not held.closed
    finally:
        release.set()
        runner.join(timeout=2)
