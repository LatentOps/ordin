"""Explicit optional Linux kernel broker for the closed in-memory fixture DSL."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import sys
import threading

from ordin._runtime_json import digest as core_digest

from ._files import _directory, directory_entries, read_scoped_file
from ._json import digest, loads
from ._sandbox_worker import LINUX_FILTER_DIGEST, LINUX_PROTOCOL
from ._test_process import run_test_process
from .host import HostApproval
from .models import JsonRecord
from .sandbox_tests import VettedSandboxRuntime, SandboxTestRun, sandbox_test_action


@dataclass(frozen=True)
class LinuxIsolationEvidence(JsonRecord):
    SCHEMA = "linux_isolation_evidence"
    backend: str
    landlock_abi: int
    seccomp_mode: int
    no_new_privileges: int
    filter_digest: str
    limits: dict
    checks: dict
    environment_empty: bool
    pipe_only_transport: bool
    filesystem_access: str
    network_access: str
    process_creation: str
    executable_launch: str

    def __post_init__(self):
        super().__post_init__()
        if self.filter_digest != LINUX_FILTER_DIGEST:
            raise ValueError("Linux filter evidence differs from the fixed reviewed profile")

    def matches(self, runtime):
        return (
            self.limits["cpu_seconds"] == (runtime.cpu_seconds, runtime.cpu_seconds)
            and self.limits["memory_bytes"] == (runtime.memory_mib * 1048576,) * 2
            and self.limits["max_processes"] == (1, 1)
            and 1 <= runtime.max_processes
            and self.limits["max_descriptors"] == (3, 3)
            and self.limits["core_bytes"] == (0, 0)
        )


@dataclass(frozen=True)
class LinuxSandboxTestRun(SandboxTestRun):
    SCHEMA = "assurance_linux_sandbox_test"
    NESTED = {"isolation_evidence": LinuxIsolationEvidence}
    isolation_evidence: LinuxIsolationEvidence | None = None

    def __post_init__(self):
        super().__post_init__()
        if self.status == "completed" and self.isolation_evidence is None:
            raise ValueError("completed Linux run requires actual matched kernel evidence")


@dataclass(frozen=True)
class LinuxVettedSandboxRuntime(VettedSandboxRuntime):
    """Fixed copied worker and base interpreter; no arbitrary broker selection."""

    def verify(self, scope):
        super().verify(scope)
        if sys.platform != "linux" or os.uname().machine != "x86_64":
            raise ValueError("Linux x86-64 kernel broker is unavailable on this platform")
        expected = Path(getattr(sys, "_base_executable", sys.executable)).resolve(strict=True)
        if self.executable != expected or self.arguments != (
            "-I",
            "-S",
            "-u",
            str(self.worker),
            "--linux-isolated",
        ):
            raise ValueError("Linux broker command differs from its closed allowlist")
        from . import _sandbox_worker

        shipped = Path(_sandbox_worker.__file__).resolve(strict=True)
        raw = read_scoped_file(shipped.parent, shipped.name)
        if hashlib.sha256(raw).hexdigest() != self.worker_sha256:
            raise ValueError("Linux broker differs from the selected installed worker")


def install_linux_vetted_runtime(
    root, *, forbidden_roots, timeout_ms=3000, cpu_seconds=2, memory_mib=128, max_output_bytes=16384
):
    """Copy owned broker bytes into a fresh private operator-selected directory.

    Does not launch a process, change a host policy, download a dependency or
    certify isolation. Availability/receipt probes are separately explicit.
    """
    if sys.platform != "linux" or os.uname().machine != "x86_64":
        raise ValueError("Linux x86-64 kernel broker is unavailable on this platform")
    if not isinstance(root, Path) or not root.is_absolute() or ".." in root.parts:
        raise ValueError("Linux installation requires a canonical absolute selected root")
    if not isinstance(forbidden_roots, tuple) or not 1 <= len(forbidden_roots) <= 8:
        raise ValueError("Linux installation requires explicit target exclusions")
    for target in forbidden_roots:
        if not isinstance(target, Path) or not target.is_absolute() or root.is_relative_to(target):
            raise ValueError("Linux installation overlaps an excluded target")
    if directory_entries(root):
        raise ValueError("Linux broker installation must be fresh")
    info = root.stat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("Linux installation requires a private owned directory")
    for parent in (root, *root.parents):
        if (parent / ".git").exists():
            raise ValueError("Linux installation must be outside enclosing Git worktrees")
    from . import _sandbox_worker

    installed = Path(_sandbox_worker.__file__).resolve(strict=True)
    raw = read_scoped_file(installed.parent, installed.name)
    executable = Path(getattr(sys, "_base_executable", sys.executable)).resolve(strict=True)
    executable_sha = hashlib.sha256(
        read_scoped_file(executable.parent, executable.name, maximum=16777216)
    ).hexdigest()
    worker_sha = hashlib.sha256(raw).hexdigest()
    worker = root / "install/_sandbox_worker.py"
    runtime = LinuxVettedSandboxRuntime(
        executable,
        executable_sha,
        worker,
        worker_sha,
        ("-I", "-S", "-u", str(worker), "--linux-isolated"),
        root / "cwd",
        root / "home",
        digest("linux_broker_installation", [worker_sha, executable_sha, LINUX_FILTER_DIGEST]),
        forbidden_roots,
        timeout_ms=timeout_ms,
        cpu_seconds=cpu_seconds,
        memory_mib=memory_mib,
        max_processes=1,
        max_output_bytes=max_output_bytes,
    )
    with _directory(root) as (directory, _):
        if not isinstance(directory, int):
            raise ValueError("Linux installation directory descriptors are unavailable")
        pinned = os.fstat(directory)
        if pinned.st_uid != os.geteuid() or pinned.st_mode & 0o077:
            raise ValueError("Linux installation directory changed or lost protection")
        for name in ("install", "cwd", "home"):
            os.mkdir(name, 0o700, dir_fd=directory)
        install = os.open("install", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
        try:
            descriptor = os.open(
                "_sandbox_worker.py",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=install,
            )
            with os.fdopen(descriptor, "wb") as output:
                output.write(raw)
                output.flush()
                os.fsync(output.fileno())
        finally:
            os.close(install)
    if read_scoped_file(root, "install/_sandbox_worker.py") != raw:
        raise ValueError("Linux installation identity or bytes changed during preparation")
    return runtime


def parse_linux_isolation_reply(packet, runtime):
    evidence = LinuxIsolationEvidence.from_dict(packet["isolation"])
    if not evidence.matches(runtime):
        raise ValueError("kernel resource evidence differs from approved runtime limits")
    return evidence


def assess_linux_vetted_isolation(
    scope, source, profile, approval, runtime, program, suite, *, cancel=None
):
    """Actual kernel probe after review, before issuing target test consent.

    Only this owned benign predicate is run, not the reviewed target program.
    The protected host receipt is bound to the original selected setup.
    """
    if not isinstance(runtime, LinuxVettedSandboxRuntime):
        raise ValueError("kernel assessment requires the fixed Linux broker")
    source._check_profile(profile)
    action = sandbox_test_action(runtime, program, suite, source)
    if not isinstance(approval, HostApproval) or (
        approval.source_key != source.key
        or approval.profile_digest != profile.digest
        or approval.action_digest != core_digest(action.as_dict())
    ):
        raise ValueError("kernel probe requires current protected review approval")
    status = "inconclusive"
    gaps: tuple[str, ...] = ("Kernel broker unavailable, refused or unverified.",)
    try:
        runtime.verify(scope)
        payload = {
            "protocol": LINUX_PROTOCOL,
            "source_digest": "0" * 64,
            "suite_digest": "0" * 64,
            "runtime_digest": runtime.digest,
            "program": "def within_root(path, root):\n    return path == root or path.startswith(root + '/')\n",
            "cases": [
                {
                    "case_id": "probe-benign",
                    "path": "/synthetic/project/file",
                    "root": "/synthetic/project",
                },
                {
                    "case_id": "probe-outside",
                    "path": "/synthetic/project-other/file",
                    "root": "/synthetic/project",
                },
            ],
            "limits": runtime.limits,
        }
        wire = lambda value: json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
        payload["request_digest"] = hashlib.sha256(wire(payload)).hexdigest()
        observed = run_test_process(runtime, wire(payload), cancel or threading.Event())
        if observed["status"] == "completed":
            packet = loads(observed["stdout"])
            if (
                set(packet)
                != {
                    "protocol",
                    "request_digest",
                    "source_digest",
                    "suite_digest",
                    "results",
                    "isolation",
                }
                or packet["protocol"] != LINUX_PROTOCOL
                or packet["request_digest"] != payload["request_digest"]
                or packet["source_digest"] != "0" * 64
                or packet["suite_digest"] != "0" * 64
                or packet["results"]
                != [
                    {"case_id": "probe-benign", "actual": True},
                    {"case_id": "probe-outside", "actual": False},
                ]
            ):
                raise ValueError("kernel probe reply binding differs")
            parse_linux_isolation_reply(packet, runtime)
            runtime.verify(scope)
            status, gaps = "satisfied", ()
    except (OSError, ValueError, KeyError):
        pass
    return source.record_assessment(
        action,
        profile,
        assessment_id="linux-isolation:" + runtime.digest[:24],
        invariant_id="validation.sandbox",
        kind="validation_isolation",
        status=status,
        proof_gaps=gaps,
    )
