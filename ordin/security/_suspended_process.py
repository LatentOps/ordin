"""CPython Windows launch adapter retaining the suspended primary thread.

This private adapter supports the Windows Popen call shape in CPython 3.10+
and only the closed invocation used by the scanner and vetted test runner.
It changes no global subprocess functions. ProcessTree must assign the job
before resuming the retained thread. Job membership is lifetime management,
not filesystem, credential or network isolation.
"""

from __future__ import annotations

import os
import subprocess
import sys


def _windows_launcher():
    # Define the subclass only at an explicitly authorized launch. Ordinary
    # imports remain compatible with process-denial spies and make no changes
    # to subprocess.Popen or its module-level helpers.
    class SuspendedPopen(subprocess.Popen):
        _execute_child = _execute_suspended
        close_initial_thread = _close_initial_thread

    return SuspendedPopen


def _execute_suspended(
    self,
    args,
    executable,
    preexec_fn,
    close_fds,
    pass_fds,
    cwd,
    env,
    startupinfo,
    creationflags,
    shell,
    p2cread,
    p2cwrite,
    c2pread,
    c2pwrite,
    errread,
    errwrite,
    *unused_platform_options,
):
    # This hook is private to CPython. Reject other call shapes/options,
    # rather than falling back to a child that can run before assignment.
    if (
        os.name != "nt"
        or sys.implementation.name != "cpython"
        or not isinstance(args, (list, tuple))
        or not args
        or any(not isinstance(v, str) or "\x00" in v for v in args)
        or not os.path.isabs(args[0])
        or executable is not None
        or preexec_fn is not None
        or not close_fds
        or pass_fds
        or startupinfo is not None
        or shell
        or creationflags != 4 | getattr(subprocess, "CREATE_NO_WINDOW", 0)
        or -1 in (p2cread, c2pwrite, errwrite)
        or cwd is None
        or env is None
    ):
        raise ValueError("unsupported suspended process invocation")
    import _winapi  # type: ignore[import-not-found]

    info = getattr(subprocess, "STARTUPINFO")()
    info.dwFlags = getattr(_winapi, "STARTF_USESTDHANDLES")
    info.hStdInput, info.hStdOutput, info.hStdError = p2cread, c2pwrite, errwrite
    info.lpAttributeList = {
        "handle_list": list(dict.fromkeys(map(int, (p2cread, c2pwrite, errwrite))))
    }
    command = subprocess.list2cmdline(args)
    sys.audit("subprocess.Popen", args[0], command, cwd, env)
    try:
        process, thread, pid, _ = getattr(_winapi, "CreateProcess")(
            args[0], command, None, None, True, creationflags, env, os.fspath(cwd), info
        )
    finally:
        getattr(self, "_close_pipe_fds")(p2cread, p2cwrite, c2pread, c2pwrite, errread, errwrite)
    self._child_created = True
    self._handle = getattr(subprocess, "Handle")(process)
    self.pid = pid
    self._initial_thread = getattr(subprocess, "Handle")(thread)


def _close_initial_thread(self):
    thread = getattr(self, "_initial_thread", None)
    if thread is not None:
        thread.Close()
        self._initial_thread = None


def launch_managed_process(arguments, *, cwd, env, stdin):
    """Return a process already in its cleanup job/session, or clean up failure."""
    from ._process_tree import ProcessTree

    launcher = _windows_launcher() if os.name == "nt" else subprocess.Popen
    process = launcher(
        arguments,
        cwd=cwd,
        env=env,
        shell=False,
        stdin=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=os.name != "nt",
        creationflags=4 | getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0,
    )
    try:
        return process, ProcessTree(process)
    except BaseException:
        # Assignment/resume failure must never leave a suspended child or pipes.
        try:
            process.kill()
            process.wait(timeout=2)
        finally:
            closer = getattr(process, "close_initial_thread", None)
            if closer is not None:
                closer()
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
        raise
