"""Windows job assignment precedes any child execution, including failures."""

import os
from pathlib import Path
import runpy
import subprocess
import sys
import time

import pytest

from ordin.assurance.codex_security import _process_tree, _suspended_process


pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows primary thread handles")


def test_import_with_process_denial_spy_does_not_construct_launcher(monkeypatch):
    def refuse(*args, **kwargs):
        pytest.fail("default import attempted process execution")

    monkeypatch.setattr(subprocess, "Popen", refuse)
    module = runpy.run_path(_suspended_process.__file__)
    assert callable(module["_windows_launcher"])
    assert subprocess.Popen is refuse


def launch(tmp_path):
    marker = tmp_path / "started.txt"
    environment = {key: os.environ[key] for key in ("SYSTEMROOT", "WINDIR") if key in os.environ}
    process, tree = _suspended_process.launch_managed_process(
        [
            sys.executable,
            "-I",
            "-c",
            "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('started')",
            str(marker),
        ],
        cwd=tmp_path,
        env=environment,
        stdin=subprocess.DEVNULL,
    )
    return process, tree, marker


def test_child_cannot_run_until_job_assignment(tmp_path, monkeypatch):
    original = _process_tree.ProcessTree.__init__

    def verify_suspension(self, process):
        assert process._initial_thread is not None
        time.sleep(0.1)
        assert not (tmp_path / "started.txt").exists()
        assert process.poll() is None
        original(self, process)
        assert process._initial_thread is None

    monkeypatch.setattr(_process_tree.ProcessTree, "__init__", verify_suspension)
    process, tree, marker = launch(tmp_path)
    try:
        assert process.wait(timeout=5) == 0
        assert marker.read_text() == "started"
    finally:
        tree.close()
        process.stdout.close()
        process.stderr.close()


def test_assignment_failure_kills_suspended_child_and_closes_handles(tmp_path, monkeypatch):
    children = []

    def fail(self, process):
        children.append(process)
        raise OSError("owned assignment failure")

    monkeypatch.setattr(_process_tree.ProcessTree, "__init__", fail)
    with pytest.raises(OSError, match="assignment failure"):
        launch(tmp_path)
    assert len(children) == 1
    assert children[0].poll() is not None
    assert children[0]._initial_thread is None
    assert children[0].stdout.closed and children[0].stderr.closed
    assert not (tmp_path / "started.txt").exists()


@pytest.mark.parametrize("operation", ["AssignProcessToJobObject", "ResumeThread"])
def test_job_or_resume_failure_never_executes_child(tmp_path, monkeypatch, operation):
    import ctypes

    original = ctypes.WinDLL
    children = []
    original_launch = _suspended_process._execute_suspended

    def capture(self, *args, **kwargs):
        original_launch(self, *args, **kwargs)
        children.append(self)

    class FailedFunction:
        def __call__(self, *args):
            return 0

    def kernel(*args, **kwargs):
        library = original(*args, **kwargs)
        setattr(library, operation, FailedFunction())
        return library

    monkeypatch.setattr(ctypes, "WinDLL", kernel)
    monkeypatch.setattr(_suspended_process, "_execute_suspended", capture)
    with pytest.raises(OSError, match="assignment|suspension"):
        launch(tmp_path)
    assert len(children) == 1 and children[0].poll() is not None
    assert children[0]._initial_thread is None
    assert children[0].stdout.closed and children[0].stderr.closed
    assert not (tmp_path / "started.txt").exists()


def test_windows_launcher_refuses_shell_and_relative_identity(tmp_path):
    # Refused before CreateProcess; there is no unsuspended fallback.
    with pytest.raises(ValueError, match="unsupported"):
        _suspended_process._windows_launcher()(
            [Path(sys.executable).name],
            cwd=tmp_path,
            env={},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=4 | subprocess.CREATE_NO_WINDOW,
        )


def test_normal_parent_exit_still_kills_descendant_holding_output_pipe(tmp_path):
    import ctypes
    from ctypes import wintypes

    code = (
        "import subprocess,sys; "
        "child=subprocess.Popen([sys.executable,'-I','-c','import time; time.sleep(60)']); "
        "print(child.pid,flush=True)"
    )
    environment = {key: os.environ[key] for key in ("SYSTEMROOT", "WINDIR") if key in os.environ}
    process, tree = _suspended_process.launch_managed_process(
        [sys.executable, "-I", "-c", code],
        cwd=tmp_path,
        env=environment,
        stdin=subprocess.DEVNULL,
    )
    kernel = ctypes.WinDLL("kernel32.dll", use_last_error=True)
    kernel.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    child_handle = None
    try:
        assert process.wait(timeout=5) == 0
        child = int(process.stdout.readline())
        child_handle = kernel.OpenProcess(0x100000, False, child)
        assert child_handle and kernel.WaitForSingleObject(child_handle, 0) == 258
        tree.close()
        assert kernel.WaitForSingleObject(child_handle, 5000) == 0
        assert process.stdout.read() == b""  # Descendant no longer retains the pipe.
    finally:
        tree.close()
        if child_handle:
            kernel.CloseHandle(child_handle)
        process.stdout.close()
        process.stderr.close()
