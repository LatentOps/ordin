"""Process lifetime management, not a filesystem/credential/egress sandbox."""

from __future__ import annotations

import os
import subprocess


class ProcessTree:
    """Windows starts suspended, joins a kill-on-close job, then resumes.

    POSIX uses the subprocess-created session. An external trusted sandbox is
    still required against escape through other privileged process services.
    """

    def __init__(self, process: subprocess.Popen):
        self.process = process
        self.job = None
        self.kernel = None
        if os.name != "nt":
            return
        import ctypes
        from ctypes import wintypes

        class BasicLimits(ctypes.Structure):
            _fields_ = [
                ("process_time", ctypes.c_int64),
                ("job_time", ctypes.c_int64),
                ("flags", wintypes.DWORD),
                ("minimum", ctypes.c_size_t),
                ("maximum", ctypes.c_size_t),
                ("active", wintypes.DWORD),
                ("affinity", ctypes.c_size_t),
                ("priority", wintypes.DWORD),
                ("scheduling", wintypes.DWORD),
            ]

        class ExtendedLimits(ctypes.Structure):
            _fields_ = [
                ("basic", BasicLimits),
                ("io", ctypes.c_uint64 * 6),
                ("process_memory", ctypes.c_size_t),
                ("job_memory", ctypes.c_size_t),
                ("peak_process", ctypes.c_size_t),
                ("peak_job", ctypes.c_size_t),
            ]

        kernel = getattr(ctypes, "WinDLL")("kernel32.dll", use_last_error=True)
        signatures = {
            "CreateJobObjectW": ([wintypes.LPVOID, wintypes.LPCWSTR], wintypes.HANDLE),
            "SetInformationJobObject": (
                [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD],
                wintypes.BOOL,
            ),
            "AssignProcessToJobObject": ([wintypes.HANDLE, wintypes.HANDLE], wintypes.BOOL),
            "ResumeThread": ([wintypes.HANDLE], wintypes.DWORD),
            "CloseHandle": ([wintypes.HANDLE], wintypes.BOOL),
        }
        for name, (args, result) in signatures.items():
            function = getattr(kernel, name)
            function.argtypes, function.restype = args, result
        self.kernel = kernel
        self.job = kernel.CreateJobObjectW(None, None)
        if not self.job:
            raise OSError("scanner process job unavailable")
        limits = ExtendedLimits()
        limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE; no breakaway.
        try:
            if not kernel.SetInformationJobObject(
                self.job, 9, ctypes.byref(limits), ctypes.sizeof(limits)
            ):
                raise OSError("scanner process job limits unavailable")
            if not kernel.AssignProcessToJobObject(self.job, getattr(process, "_handle")):
                raise OSError("scanner process job assignment unavailable")
            thread = getattr(process, "_initial_thread", None)
            if thread is None:
                raise OSError("scanner initial thread unavailable")
            try:
                if kernel.ResumeThread(int(thread)) != 1:
                    raise OSError("scanner initial thread suspension changed")
            finally:
                getattr(process, "close_initial_thread")()
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        if os.name == "nt":
            if self.job is not None and self.kernel is not None:
                self.kernel.CloseHandle(self.job)
                self.job = None
        else:
            import signal

            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
