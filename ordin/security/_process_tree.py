"""Process lifetime management, not a filesystem/credential/egress sandbox."""

from __future__ import annotations

import os
import subprocess
import time


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
            "TerminateJobObject": ([wintypes.HANDLE, wintypes.UINT], wintypes.BOOL),
            "QueryInformationJobObject": (
                [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD, wintypes.LPVOID],
                wintypes.BOOL,
            ),
            "OpenProcess": ([wintypes.DWORD, wintypes.BOOL, wintypes.DWORD], wintypes.HANDLE),
            "WaitForSingleObject": ([wintypes.HANDLE, wintypes.DWORD], wintypes.DWORD),
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
                try:
                    self._end_windows_processes()
                finally:
                    self.kernel.CloseHandle(self.job)  # Kill-on-close remains the fallback.
                    self.job = None
        else:
            import signal

            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def _windows_process_ids(self):
        import ctypes
        from ctypes import wintypes

        assert self.kernel is not None

        class ProcessIds(ctypes.Structure):
            _fields_ = [
                ("assigned", wintypes.DWORD),
                ("listed", wintypes.DWORD),
                ("ids", ctypes.c_size_t * 4096),
            ]

        info = ProcessIds()
        if (
            not self.kernel.QueryInformationJobObject(
                self.job, 3, ctypes.byref(info), ctypes.sizeof(info), None
            )
            or info.listed > 4096
            or info.assigned != info.listed
        ):
            raise OSError("process job cleanup inventory unavailable")
        return set(info.ids[: info.listed])

    def _windows_total_processes(self):
        import ctypes
        from ctypes import wintypes

        assert self.kernel is not None

        class Accounting(ctypes.Structure):
            _fields_ = [
                ("times", ctypes.c_int64 * 4),
                ("faults", wintypes.DWORD),
                ("total", wintypes.DWORD),
                ("active", wintypes.DWORD),
                ("terminated", wintypes.DWORD),
            ]

        info = Accounting()
        if not self.kernel.QueryInformationJobObject(
            self.job, 1, ctypes.byref(info), ctypes.sizeof(info), None
        ):
            raise OSError("process job cleanup accounting unavailable")
        return info.total

    def _end_windows_processes(self):
        """Termination is asynchronous; confirm signaled job members before return.

        Retain handles before termination: Windows can remove a terminating
        member from the job list before its process handle is signaled. The
        monotonic total-process count detects a birth race; such cleanup stays
        unconfirmed. Enumerate this owned job only. Failure still closes the
        kill-on-close job in finally.
        """
        import ctypes

        assert self.kernel is not None

        deadline = time.monotonic() + 2
        handles = []
        try:
            total = self._windows_total_processes()
            processes = self._windows_process_ids()
            for pid in processes:
                handle = self.kernel.OpenProcess(0x100000, False, pid)  # SYNCHRONIZE only.
                if not handle:
                    if getattr(ctypes, "get_last_error")() == 87:  # Already exited.
                        continue
                    raise OSError("process job cleanup observation unavailable")
                handles.append(handle)
            if not self.kernel.TerminateJobObject(self.job, 1):
                raise OSError("process job termination unavailable")
            for handle in handles:
                remaining = max(0, int((deadline - time.monotonic()) * 1000))
                if self.kernel.WaitForSingleObject(handle, remaining) != 0:
                    raise OSError("process job cleanup deadline exceeded")
            if self._windows_total_processes() != total:
                raise OSError("process job cleanup inventory changed")
        finally:
            for handle in handles:
                self.kernel.CloseHandle(handle)
