"""Explicit host-authorized test broker. No ordinary gate launches a test."""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from _thread import LockType
from typing import Any

from ordin import ActionEnvelope
from ordin._runtime_json import digest as core_digest

from ._files import directory_entries, read_scoped_file
from ._json import digest, loads, validate
from ._sandbox_worker import PROTOCOL
from ._test_process import run_test_process
from .host import HostEvidenceSource, HostApproval, HostConstraintAssessment
from .inventory import AuthorizedRepository, verify_source_reference
from .models import ApprovedSecurityProfile, JsonRecord
from .synthetic_tests import VettedProgram, SelectedSyntheticSuite
from .validation import _issue, _scope_pin_gaps
from .validation_models import _ValidationAuthority


@dataclass(frozen=True)
class VettedSandboxRuntime:
    executable: Path
    executable_sha256: str
    worker: Path
    worker_sha256: str
    arguments: tuple[str, ...]
    trusted_cwd: Path
    private_home: Path
    installation_digest: str
    forbidden_roots: tuple[Path, ...]
    timeout_ms: int = 3000
    cpu_seconds: int = 2
    memory_mib: int = 128
    max_processes: int = 2
    max_output_bytes: int = 16384

    def __post_init__(self):
        for path in (
            self.executable,
            self.worker,
            self.trusted_cwd,
            self.private_home,
            *self.forbidden_roots,
        ):
            if not isinstance(path, Path) or not path.is_absolute() or ".." in path.parts:
                raise ValueError("test runtime requires absolute canonical host paths")
        if (
            self.executable.suffix.lower() in {".cmd", ".bat", ".ps1"}
            or self.worker.name != "_sandbox_worker.py"
        ):
            raise ValueError("test runtime requires native broker and fixed installed worker")
        if (
            not isinstance(self.arguments, tuple)
            or not 1 <= len(self.arguments) <= 8
            or any(
                not isinstance(arg, str)
                or not 1 <= len(arg) <= 1024
                or any(ord(char) < 32 for char in arg)
                for arg in self.arguments
            )
        ):
            raise ValueError("test command allowlist is malformed")
        if (
            str(self.worker) not in self.arguments
            or not isinstance(self.forbidden_roots, tuple)
            or not 1 <= len(self.forbidden_roots) <= 8
        ):
            raise ValueError(
                "reviewed test command must bind installed worker and target exclusions"
            )
        for pin in (self.executable_sha256, self.worker_sha256, self.installation_digest):
            validate(
                "assurance_authority_ref", {"authority_id": "test-runtime", "boundary_digest": pin}
            )
        for value, lower, upper in (
            (self.timeout_ms, 100, 30000),
            (self.cpu_seconds, 1, 30),
            (self.memory_mib, 32, 1024),
            (self.max_processes, 1, 4),
            (self.max_output_bytes, 1024, 65536),
        ):
            if type(value) is not int or not lower <= value <= upper:
                raise ValueError("test resource budget malformed")

    @property
    def digest(self):
        return digest(
            "vetted_test_runtime",
            {
                "executable": self.executable_sha256,
                "worker": self.worker_sha256,
                "paths": [
                    core_digest(str(path))
                    for path in (self.executable, self.worker, self.trusted_cwd, self.private_home)
                ],
                "arguments": core_digest(list(self.arguments)),
                "installation": self.installation_digest,
                "exclusions": [core_digest(str(path)) for path in self.forbidden_roots],
                "limits": self.limits,
            },
        )

    @property
    def limits(self):
        return {
            "timeout_ms": self.timeout_ms,
            "cpu_seconds": self.cpu_seconds,
            "memory_mib": self.memory_mib,
            "max_processes": self.max_processes,
            "max_output_bytes": self.max_output_bytes,
        }

    def verify(self, scope):
        if not any(scope.root.is_relative_to(root) for root in self.forbidden_roots):
            raise ValueError("test runtime does not exclude the actual target root")
        for path in (self.executable, self.worker, self.trusted_cwd, self.private_home):
            if any(path.is_relative_to(root) for root in self.forbidden_roots):
                raise ValueError("test runtime must be outside target roots")
            directory = path if path in (self.trusted_cwd, self.private_home) else path.parent
            directory_entries(directory, maximum=4096)
            for parent in (directory, *directory.parents):
                try:
                    (parent / ".git").lstat()
                except FileNotFoundError:
                    continue
                raise ValueError("test runtime must be outside enclosing Git worktrees")
        for path, pin in (
            (self.executable, self.executable_sha256),
            (self.worker, self.worker_sha256),
        ):
            raw = read_scoped_file(path.parent, path.name, maximum=16777216)
            if hashlib.sha256(raw).hexdigest() != pin:
                raise ValueError("test installation differs from reviewed bytes")
        if directory_entries(self.private_home):
            raise ValueError("test private home must be fresh")
        if os.name == "posix" and self.private_home.stat().st_mode & 0o077:
            raise ValueError("test home permissions are not private")


def sandbox_test_action(runtime, program, suite, source):
    if (
        not isinstance(runtime, VettedSandboxRuntime)
        or not isinstance(program, VettedProgram)
        or not isinstance(suite, SelectedSyntheticSuite)
        or not isinstance(source, HostEvidenceSource)
        or program.repository != source.repository
    ):
        raise ValueError("test setup selection/source mismatch")
    return ActionEnvelope(
        "validation",
        "sandboxed_test",
        {
            "runtime_digest": runtime.digest,
            "program_digest": program.digest,
            "suite_digest": suite.digest,
            "source_key": source.key,
            "limits": runtime.limits,
            "disclosure": "Only vetted synthetic code and canonical synthetic test paths enter the isolated local broker.",
        },
    )


@dataclass(frozen=True)
class _ScopeSeal:
    payload_digest: str
    lock: LockType = field(default_factory=threading.Lock, compare=False)
    consumed: list[bool] = field(default_factory=lambda: [False], compare=False)


@dataclass(frozen=True)
class SandboxTestScope:
    source_key: str
    setup_digest: str
    profile_digest: str
    expires_at: float
    _seal: _ScopeSeal | None = field(default=None, repr=False, compare=False)

    def material(self):
        return {
            "source": self.source_key,
            "setup": self.setup_digest,
            "profile": self.profile_digest,
            "expires": self.expires_at,
        }

    def __post_init__(self):
        if not isinstance(self._seal, _ScopeSeal) or self._seal.payload_digest != digest(
            "sandbox_test_scope", self.material()
        ):
            raise ValueError("test scope requires actual protected approval/isolation")

    def consume(self, setup, source):
        assert isinstance(self._seal, _ScopeSeal)
        if (
            setup != self.setup_digest
            or source != self.source_key
            or time.monotonic() >= self.expires_at
        ):
            return False
        with self._seal.lock:
            if self._seal.consumed[0]:
                return False
            self._seal.consumed[0] = True
            return True


def authorize_sandbox_test(
    source, profile, approval, isolation, runtime, program, suite, *, lifetime_seconds=120
):
    if not isinstance(source, HostEvidenceSource) or not isinstance(
        profile, ApprovedSecurityProfile
    ):
        raise ValueError("test setup requires protected host/profile selection")
    source._check_profile(profile)
    action = sandbox_test_action(runtime, program, suite, source)
    setup = core_digest(action.as_dict())
    for value, expected in ((approval, HostApproval), (isolation, HostConstraintAssessment)):
        if (
            not isinstance(value, expected)
            or value.source_key != source.key
            or value.profile_digest != profile.digest
            or value.action_digest != setup
        ):
            raise ValueError("test approval/isolation belongs to another selected setup")
    if (
        isolation.kind != "validation_isolation"
        or isolation.invariant_id != "validation.sandbox"
        or isolation.status != "satisfied"
    ):
        raise ValueError("test no-egress/read-only/credential/resource isolation is unresolved")
    if type(lifetime_seconds) is not int or not 1 <= lifetime_seconds <= 300:
        raise ValueError("test scope lifetime malformed")
    values: dict[str, Any] = dict(
        source_key=source.key,
        setup_digest=setup,
        profile_digest=profile.digest,
        expires_at=time.monotonic() + lifetime_seconds,
    )
    material = {
        "source": values["source_key"],
        "setup": setup,
        "profile": profile.digest,
        "expires": values["expires_at"],
    }
    return SandboxTestScope(**values, _seal=_ScopeSeal(digest("sandbox_test_scope", material)))


@dataclass(frozen=True)
class SandboxTestRun(JsonRecord):
    SCHEMA = "assurance_sandbox_test"
    request_digest: str
    source_digest: str
    suite_digest: str
    runtime_digest: str
    source_key: str
    setup_digest: str
    status: str
    exit_code: int | None
    results: tuple
    stdout_digest: str
    stderr_digest: str
    stdout_bytes: int
    stderr_bytes: int
    elapsed_ms: float
    proof_gaps: tuple[str, ...]
    authority_origin: str = "protected_sandbox_test"
    advisory_only: bool = True
    _authority: _ValidationAuthority | None = field(default=None, repr=False, compare=False)

    def __post_init__(self):
        super().__post_init__()
        if (
            not isinstance(self._authority, _ValidationAuthority)
            or self._authority.payload_digest != self.digest
        ):
            raise ValueError("sandbox results require an actual protected run")
        if self.status == "completed" and (
            self.proof_gaps or self.exit_code != 0 or not self.results
        ):
            raise ValueError("sandbox completion requires complete matched observations")


def run_sandbox_test(
    scope: AuthorizedRepository, source, runtime, program, suite, consent, *, cancel=None
):
    if (
        not isinstance(scope, AuthorizedRepository)
        or source.repository != scope.repository
        or program.repository != scope.repository
    ):
        raise ValueError("test target/source scope mismatch")
    action = sandbox_test_action(runtime, program, suite, source)
    setup = core_digest(action.as_dict())
    payload = {
        "protocol": PROTOCOL,
        "source_digest": program.source.content_digest,
        "suite_digest": suite.source.content_digest,
        "runtime_digest": runtime.digest,
        "program": program._program,
        "cases": [case.as_dict() for case in suite.suite.cases],
        "limits": runtime.limits,
    }

    # This private transport carries vetted multiline code. Audit JSON keeps
    # its existing control-character ban; only this fixed typed payload differs.
    def wire(packet):
        data = json.dumps(
            packet, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode()
        if len(data) > 65536:
            raise ValueError("vetted test transport exceeds byte limit")
        return data

    request_digest = hashlib.sha256(wire(payload)).hexdigest()
    payload["request_digest"] = request_digest
    empty = hashlib.sha256(b"").hexdigest()
    observed = dict(
        status="refused",
        exit_code=None,
        stdout_digest=empty,
        stderr_digest=empty,
        stdout_bytes=0,
        stderr_bytes=0,
        elapsed_ms=0,
    )
    results, gaps = [], []
    cancel = cancel or threading.Event()
    if cancel.is_set():
        observed["status"] = "canceled"
        gaps.append("Test canceled before process creation.")
    elif not isinstance(consent, SandboxTestScope) or not consent.consume(setup, source.key):
        gaps.append("Protected test consent/isolation is missing, stale or already consumed.")
    else:
        try:
            runtime.verify(scope)
            if (
                _scope_pin_gaps(scope)
                or not verify_source_reference(scope, program.source)
                or not verify_source_reference(scope, suite.source)
                or time.monotonic() >= consent.expires_at
            ):
                raise ValueError("selected test source changed")
            observed = run_test_process(runtime, wire(payload), cancel)
            raw = observed.pop("stdout")
            if observed["status"] == "completed":
                packet = loads(raw)
                if (
                    set(packet)
                    != {"protocol", "request_digest", "source_digest", "suite_digest", "results"}
                    or packet["protocol"] != PROTOCOL
                    or packet["request_digest"] != request_digest
                    or packet["source_digest"] != program.source.content_digest
                    or packet["suite_digest"] != suite.source.content_digest
                    or not isinstance(packet["results"], list)
                    or len(packet["results"]) != len(suite.suite.cases)
                ):
                    raise ValueError("worker binding/result mismatch")
                for case, reply in zip(suite.suite.cases, packet["results"]):
                    if (
                        not isinstance(reply, dict)
                        or set(reply) != {"case_id", "actual"}
                        or reply["case_id"] != case.case_id
                        or type(reply["actual"]) is not bool
                    ):
                        raise ValueError("worker answer malformed")
                    results.append(
                        {
                            "case_digest": case.digest,
                            "expected": case.expected,
                            "actual": reply["actual"],
                        }
                    )
                runtime.verify(scope)
                if (
                    time.monotonic() >= consent.expires_at
                    or _scope_pin_gaps(scope)
                    or not verify_source_reference(scope, program.source)
                    or not verify_source_reference(scope, suite.source)
                ):
                    raise ValueError("test scope/source changed during execution")
            else:
                gaps.append(
                    "Vetted test broker failed, refused, timed out or was canceled; no closure is established."
                )
        except (OSError, ValueError):
            observed["status"] = "malformed" if observed["status"] == "completed" else "refused"
            results = []
            gaps.append(
                "Vetted source, installation, protocol or runtime scope could not be verified."
            )
    return _issue(
        SandboxTestRun,
        dict(
            request_digest=request_digest,
            source_digest=program.source.content_digest,
            suite_digest=suite.source.content_digest,
            runtime_digest=runtime.digest,
            source_key=source.key,
            setup_digest=setup,
            **observed,
            results=tuple(results),
            proof_gaps=tuple(gaps),
            authority_origin="protected_sandbox_test",
            advisory_only=True,
        ),
    )


async def run_sandbox_test_async(*args, **kwargs):
    import asyncio

    cancel = kwargs.pop("cancel", None) or threading.Event()
    task = asyncio.create_task(asyncio.to_thread(run_sandbox_test, *args, cancel=cancel, **kwargs))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        cancel.set()
        await asyncio.shield(task)
        raise
