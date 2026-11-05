"""Owned fresh Linux file-read executor with actual kernel outcome receipts."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import stat
import subprocess
import sys
import tempfile
from threading import RLock
from threading import Event
import time
from typing import Any
from uuid import uuid4

from ordin.action import ActionEnvelope
from ordin._runtime_json import digest, freeze, thaw
from ordin.enforcement_backend import BackendValidationResult, CompilationResult, EnforcementPlan
from ordin.execution import ObservedResource
from ordin.runtime_contract import RuntimeCapabilityContract
from ordin.runtime_observation import RuntimeEvidenceSource, RuntimeObservation

from .models import identifier

PROTOCOL = "ordin.swarm.linux_file_read.v1"
FILTER_DIGEST = "39ba6d1343b819518f4aa0465b533a048e3b174de064abf36cc9f356e8d0f261"
CHECKS = frozenset(
    {
        "new_path_read_denied",
        "new_path_write_denied",
        "network_socket_denied",
        "process_creation_denied",
        "executable_launch_denied",
        "memory_ceiling_enforced",
        "descriptor_write_denied",
        "output_frame_ceiling_enforced",
    }
)


def _wire(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode()


def _sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(65536):
            h.update(chunk)
    return h.hexdigest()


def _file_identity(descriptor: int) -> dict[str, int]:
    info = os.fstat(descriptor)
    return {
        "device": info.st_dev,
        "inode": info.st_ino,
        "mode": info.st_mode,
        "size": info.st_size,
        "mtime_ns": info.st_mtime_ns,
    }


@dataclass(frozen=True, eq=False, slots=True)
class ExecutorOutcome:
    status: str
    reason_code: str
    action_digest: str
    contract_digest: str
    policy_digest: str
    physical_enforcement: bool
    evidence_digest: str | None
    stdout_bytes: int
    payload_bytes: int
    payload_digest: str | None
    value: bytes | None = field(default=None, repr=False)
    observation: RuntimeObservation | None = field(default=None, repr=False)

    def as_dict(self) -> dict[str, Any]:
        from ordin.schema import validate_named_schema

        payload = {
            "schema_version": "ordin.swarm_executor_outcome.v1",
            "backend": "linux-owned-file-read-v1",
            "status": self.status,
            "reason_code": self.reason_code,
            "action_digest": self.action_digest,
            "contract_digest": self.contract_digest,
            "policy_digest": self.policy_digest,
            "physical_enforcement": self.physical_enforcement,
            "evidence_digest": self.evidence_digest,
            "stdout_bytes": self.stdout_bytes,
            "payload_bytes": self.payload_bytes,
            "payload_digest": self.payload_digest,
            "execution_authority": False,
        }
        if validate_named_schema("swarm_executor_outcome", payload):
            raise ValueError("invalid bounded executor report")
        return payload


@dataclass(frozen=True, eq=False, slots=True)
class KernelFactoryProof:
    proof_id: str


@dataclass(frozen=True, eq=False, slots=True)
class KernelJob:
    job_id: str


@dataclass
class _Job:
    binding: tuple[str, str, str]
    cancel: Event = field(default_factory=Event)
    state: str = "queued"
    process: Any = None
    pidfd: int | None = None
    outcome: ExecutorOutcome | None = None


class LinuxFileReadBackend:
    """Finite exact read_file route, not arbitrary code or an existing-agent sandbox.

    A read-only descriptor is opened only inside the final broker forwarding
    boundary. The child retains that descriptor and private pipes, denies all
    new path/network/process/exec access and drops privileges. The payload limit
    and the full serialized stdout ceiling are distinct measured quantities.
    """

    name = "linux-owned-file-read-v1"

    def __init__(
        self,
        workspace: Path,
        allowed_files: tuple[str, ...],
        install_root: Path,
        *,
        operator: object,
        tool_runtime: str = "fixture",
        tool_name: str = "read_file",
        path_argument: str = "path",
        max_payload_bytes: int = 65536,
        timeout_ms: int = 3000,
        memory_mib: int = 128,
        cpu_seconds: int = 2,
        max_outcomes: int = 4096,
    ) -> None:
        if (
            type(operator) is not object
            or type(allowed_files) is not tuple
            or not 1 <= len(allowed_files) <= 64
            or len(set(allowed_files)) != len(allowed_files)
        ):
            raise ValueError("protected operator and bounded explicit file routes required")
        for value in (*allowed_files, tool_runtime, tool_name, path_argument):
            identifier(value, "executor route")
        if any("/" in value or "\\" in value or value in {".", ".."} for value in allowed_files):
            raise ValueError("executor routes must name exact flat workspace files")
        if (
            type(max_payload_bytes) is not int
            or not 1 <= max_payload_bytes <= 65536
            or type(timeout_ms) is not int
            or not 1000 <= timeout_ms <= 10000
            or type(memory_mib) is not int
            or not 64 <= memory_mib <= 256
            or type(cpu_seconds) is not int
            or not 1 <= cpu_seconds <= 10
            or type(max_outcomes) is not int
            or not 1 <= max_outcomes <= 16384
        ):
            raise ValueError("invalid hard executor resource bounds")
        self.workspace, self.install_root = (
            Path(workspace).absolute(),
            Path(install_root).absolute(),
        )
        self.allowed_files, self.tool_runtime, self.tool_name, self.path_argument = (
            allowed_files,
            tool_runtime,
            tool_name,
            path_argument,
        )
        self.max_payload_bytes, self.timeout_ms, self.memory_mib, self.cpu_seconds = (
            max_payload_bytes,
            timeout_ms,
            memory_mib,
            cpu_seconds,
        )
        # This is a bound on the COMPLETE serialized child stdout frame, including
        # base64 expansion and fixed kernel/binding metadata, not just payload.
        self.max_stdout_bytes = max_payload_bytes * 2 + 8192
        self._operator, self._limit = operator, max_outcomes
        self._fd = -1
        self._nonce = uuid4().hex
        self._outcomes: dict[ExecutorOutcome, str] = {}
        self._evidence: dict[ExecutorOutcome, Any] = {}
        self._proofs: dict[KernelFactoryProof, tuple[str, str]] = {}
        self._sources: dict[str, RuntimeEvidenceSource] = {}
        self._lock = RLock()
        self._jobs_lock = RLock()
        self._jobs: dict[KernelJob, _Job] = {}
        self._shipped = Path(__file__).with_name("_file_worker.py").resolve()
        self._worker_digest = _sha(self._shipped)
        self._executable = Path(getattr(sys, "_base_executable", sys.executable)).resolve()
        self._executable_digest = _sha(self._executable)
        self._supported = (
            sys.platform == "linux" and os.name == "posix" and os.uname().machine == "x86_64"
        )
        self.uid = (
            65534
            if self._supported and os.geteuid() == 0
            else os.geteuid()
            if self._supported
            else None
        )
        self.gid = (
            65534
            if self._supported and os.geteuid() == 0
            else os.getegid()
            if self._supported
            else None
        )
        self._root_identity: tuple[int, int] | None = None
        self._boot: str | None = None
        if self._supported:
            self._install()

    def _private_directory(self, path: Path) -> None:
        if path.resolve(strict=True) != path:
            raise ValueError("executor directories must be canonical, without symlink parents")
        info = path.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise ValueError("executor directory must be private and owned")

    def _install(self) -> None:
        self._private_directory(self.workspace)
        self._private_directory(self.install_root)
        if self.install_root == self.workspace or self.install_root.is_relative_to(self.workspace):
            raise ValueError("executor installation must not overlap the agent workspace")
        if any(
            (parent / ".git").exists() for parent in (self.install_root, *self.install_root.parents)
        ) or any(self.install_root.iterdir()):
            raise ValueError("executor installation must be fresh and outside Git worktrees")
        self._fd = os.open(
            self.workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
        info = os.fstat(self._fd)
        self._root_identity = (info.st_dev, info.st_ino)
        self.worker = self.install_root / "_file_worker.py"
        descriptor = os.open(
            self.worker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(descriptor, "wb") as output:
            output.write(self._shipped.read_bytes())
            output.flush()
            os.fsync(output.fileno())
        self.cwd = self.install_root / "cwd"
        self.cwd.mkdir(mode=0o700)
        self._boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()

    @property
    def configuration_digest(self) -> str:
        return digest(
            {
                "backend": self.name,
                "workspace": str(self.workspace),
                "files": self.allowed_files,
                "runtime": self.tool_runtime,
                "tool": self.tool_name,
                "argument": self.path_argument,
                "worker": self._worker_digest,
                "executable": self._executable_digest,
                "uid": self.uid,
                "gid": self.gid,
                "payload": self.max_payload_bytes,
                "stdout": self.max_stdout_bytes,
                "timeout_ms": self.timeout_ms,
                "memory_mib": self.memory_mib,
                "cpu_seconds": self.cpu_seconds,
                "boot": self._boot,
                "incarnation": self._nonce,
            }
        )

    def _verify_install(self) -> None:
        if not self._supported or self._fd < 0:
            raise ValueError("Linux owned executor unavailable")
        self._private_directory(self.workspace)
        self._private_directory(self.install_root)
        info = self.workspace.lstat()
        if (info.st_dev, info.st_ino) != self._root_identity or Path(
            "/proc/sys/kernel/random/boot_id"
        ).read_text().strip() != self._boot:
            raise ValueError("executor workspace or kernel generation changed")
        if (
            _sha(self._shipped) != self._worker_digest
            or _sha(self.worker) != self._worker_digest
            or _sha(self._executable) != self._executable_digest
        ):
            raise ValueError("executor code identity changed")

    def compile(self, contract: RuntimeCapabilityContract) -> CompilationResult:
        if type(contract) is not RuntimeCapabilityContract:
            raise ValueError("exact typed capability contract required")
        unsupported = []
        if not self._supported:
            unsupported.append("runtime.linux_x86_64")
        if contract.grant_state != "eligible":
            unsupported.append("contract.non_executable_or_unknown")
        if len(contract.filesystem) != 1 or any(
            cap.access != "read"
            or cap.scope != "exact"
            or cap.path not in {str(self.workspace / name) for name in self.allowed_files}
            for cap in contract.filesystem
        ):
            unsupported.append("filesystem.exact_owned_read")
        if len(contract.tools) != 1 or any(
            (tool.runtime, tool.server, tool.tool, tool.operation)
            != (self.tool_runtime, None, self.tool_name, "call")
            for tool in contract.tools
        ):
            unsupported.append("tools.exact_read_file")
        if (
            contract.network
            or contract.credentials
            or contract.process.execution is not False
            or contract.process.executables
            or contract.process.spawn_children not in {None, False}
            or contract.privilege.escalation is not False
            or contract.privilege.required_euid not in {None, self.uid}
        ):
            unsupported.append("runtime.unrepresented_domain")
        if unsupported:
            return CompilationResult(
                "unsupported",
                self.name,
                "broker.executor_unrepresentable",
                unsupported_fields=tuple(unsupported),
            )
        try:
            self._verify_install()
        except (OSError, ValueError):
            return CompilationResult(
                "inconclusive",
                self.name,
                "broker.executor_identity_unavailable",
                unsupported_fields=("runtime.identity",),
            )
        policy = {
            "profile": PROTOCOL,
            "configuration_digest": self.configuration_digest,
            "path_digest": digest(contract.filesystem[0].path),
            "read_only_descriptor": 3,
            "new_paths": "deny",
            "network": "deny",
            "processes": "deny",
            "exec": "deny",
            "uid": self.uid,
            "gid": self.gid,
            "memory_bytes": self.memory_mib * 1048576,
            "cpu_seconds": self.cpu_seconds,
            "payload_bytes": self.max_payload_bytes,
            "stdout_frame_bytes": self.max_stdout_bytes,
            "filter_digest": FILTER_DIGEST,
        }
        plan = EnforcementPlan(
            self.name,
            contract,
            policy,
            metadata={"startup": "fresh_worker_only", "live_attach": "unsupported"},
        )
        return CompilationResult("success", self.name, "broker.executor_compiled", plan=plan)

    def validate(self, plan: EnforcementPlan) -> BackendValidationResult:
        if type(plan) is not EnforcementPlan or plan.backend != self.name:
            raise ValueError("owned executor plan required")
        rebuilt = self.compile(plan.contract)
        valid = (
            rebuilt.enforceable
            and rebuilt.plan is not None
            and rebuilt.plan.plan_id == plan.plan_id
        )
        return BackendValidationResult(
            "success" if valid else "invalid",
            self.name,
            plan.policy_digest,
            "broker.executor_plan_valid" if valid else "broker.executor_plan_changed",
            unsupported_fields=() if valid else ("plan.identity",),
        )

    def evidence_source(
        self, *, session_digest: str, policy_digest: str, context_digest: str
    ) -> RuntimeEvidenceSource:
        with self._lock:
            key = digest([session_digest, policy_digest, context_digest])
            if key not in self._sources:
                if len(self._sources) >= 256:
                    raise ValueError("executor reporting scope capacity reached")
                self._sources[key] = RuntimeEvidenceSource(
                    self.name,
                    session_digest,
                    "owned-worker-" + digest([self._nonce, context_digest])[:32],
                    policy_digest,
                )
            return self._sources[key]

    def create_job(self, plan: EnforcementPlan, *, operator: object) -> KernelJob:
        if operator is not self._operator or type(plan) is not EnforcementPlan:
            raise ValueError("protected executor owner and exact plan required")
        with self._jobs_lock:
            if len(self._jobs) >= self._limit:
                raise ValueError("owned executor job capacity reached")
            job = KernelJob(uuid4().hex)
            self._jobs[job] = _Job(
                (plan.plan_id, plan.contract.action_digest, plan.contract.digest)
            )
            return job

    def _job(self, job: KernelJob) -> _Job:
        if type(job) is not KernelJob or job not in self._jobs:
            raise ValueError("unknown original executor job")
        return self._jobs[job]

    def request_stop(self, job: KernelJob, *, operator: object) -> str:
        if operator is not self._operator:
            raise ValueError("protected executor operator required")
        with self._jobs_lock:
            row = self._job(job)
            if row.state in {"finished", "canceled"}:
                return "canceled" if row.state == "canceled" else "completed"
            row.cancel.set()
            if row.state == "queued":
                row.state = "canceled"
                return "canceled"
            if row.state == "unable_to_stop":
                return "unable_to_stop"
            return "unknown"

    def job_status(self, job: KernelJob, *, operator: object) -> str:
        if operator is not self._operator:
            raise ValueError("protected executor operator required")
        with self._jobs_lock:
            return self._job(job).state

    @staticmethod
    def _terminate(process, pidfd: int | None) -> bool:
        try:
            if process.poll() is not None:
                return True
            if pidfd is not None and hasattr(signal, "pidfd_send_signal"):
                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
            else:
                process.kill()  # Original owned Popen child; no caller PID is accepted.
            process.wait(timeout=2)
            return True
        except (OSError, subprocess.TimeoutExpired):
            return process.poll() is not None

    def _result(
        self,
        plan,
        status,
        reason,
        *,
        physical=False,
        evidence=None,
        stdout_bytes=0,
        value=None,
        observation=None,
        job: KernelJob | None = None,
    ):
        outcome = ExecutorOutcome(
            status,
            reason,
            plan.contract.action_digest,
            plan.contract.digest,
            plan.policy_digest,
            physical,
            digest(evidence) if evidence else None,
            stdout_bytes,
            len(value) if value is not None else 0,
            hashlib.sha256(value).hexdigest() if value is not None else None,
            value,
            observation,
        )
        self._outcomes[outcome] = digest(outcome.as_dict())
        if evidence is not None:
            self._evidence[outcome] = freeze(evidence)
        if job is not None:
            with self._jobs_lock:
                row = self._job(job)
                row.outcome = outcome
                row.state = "canceled" if status == "canceled" else "finished"
        return outcome

    def evidence_record(self, outcome: ExecutorOutcome, *, operator: object) -> dict[str, Any]:
        if operator is not self._operator:
            raise ValueError("protected executor operator required")
        with self._lock:
            if (
                type(outcome) is not ExecutorOutcome
                or outcome not in self._evidence
                or self._outcomes.get(outcome) != digest(outcome.as_dict())
            ):
                raise ValueError("original authenticated kernel receipt unavailable")
            return thaw(self._evidence[outcome])

    def verify_outcome(self, outcome: ExecutorOutcome, plan: EnforcementPlan) -> bool:
        with self._lock:
            return (
                type(outcome) is ExecutorOutcome
                and self._outcomes.get(outcome) == digest(outcome.as_dict())
                and outcome.action_digest == plan.contract.action_digest
                and outcome.contract_digest == plan.contract.digest
                and outcome.policy_digest == plan.policy_digest
            )

    def _target(self, action: ActionEnvelope, plan: EnforcementPlan) -> str:
        if (
            type(action) is not ActionEnvelope
            or digest(action.as_dict()) != plan.contract.action_digest
            or action.kind != "tool"
            or action.operation != "call"
            or set(action.parameters) != {"runtime", "tool", "arguments"}
        ):
            raise ValueError("executor action or tool identity changed")
        arguments = action.parameters["arguments"]
        if (
            action.parameters["runtime"] != self.tool_runtime
            or action.parameters["tool"] != self.tool_name
            or not isinstance(arguments, dict)
            or set(arguments) != {self.path_argument}
        ):
            raise ValueError("executor read arguments are unrepresented")
        path = arguments[self.path_argument]
        if (
            type(path) is not str
            or path != plan.contract.filesystem[0].path
            or path not in {str(self.workspace / name) for name in self.allowed_files}
        ):
            raise ValueError("executor target changed")
        return Path(path).name

    def execute(
        self,
        plan: EnforcementPlan,
        action: ActionEnvelope,
        source: RuntimeEvidenceSource,
        *,
        operator: object,
        job: KernelJob | None = None,
    ) -> ExecutorOutcome:
        if operator is not self._operator or type(source) is not RuntimeEvidenceSource:
            raise ValueError("protected executor owner and original reporting source required")
        with self._lock:
            if len(self._outcomes) >= self._limit:
                raise ValueError("executor outcome capacity reached")
            job = self.create_job(plan, operator=operator) if job is None else job
            with self._jobs_lock:
                job_state = self._job(job)
                if job_state.binding != (
                    plan.plan_id,
                    plan.contract.action_digest,
                    plan.contract.digest,
                ):
                    raise ValueError("owned executor job binding changed")
                if job_state.state == "canceled" or job_state.cancel.is_set():
                    return self._result(
                        plan, "canceled", "broker.executor_canceled_before_start", job=job
                    )
                if job_state.state != "queued":
                    raise ValueError("owned executor job already consumed")
                job_state.state = "checking"

            def emit(*args, **kwargs):
                return self._result(*args, **kwargs, job=job)

            if not self.validate(plan).ok:
                return emit(plan, "unsupported", "broker.executor_plan_changed")
            descriptor = None
            process = None
            output = None
            writer = None
            pidfd = None
            try:
                name = self._target(action, plan)
                descriptor = os.open(
                    name,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                    dir_fd=self._fd,
                )
                info = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) & 0o077
                    or info.st_nlink != 1
                    or info.st_size > self.max_payload_bytes
                ):
                    return emit(plan, "denied", "broker.executor_target_unverified")
                bound = _file_identity(descriptor)
                nonce = secrets.token_hex(32)
                packet = {
                    "protocol": PROTOCOL,
                    "nonce": nonce,
                    "action_digest": plan.contract.action_digest,
                    "contract_digest": plan.contract.digest,
                    "policy_digest": plan.policy_digest,
                    "file_descriptor": descriptor,
                    "file_identity": bound,
                    "uid": self.uid,
                    "gid": self.gid,
                    "memory_bytes": self.memory_mib * 1048576,
                    "cpu_seconds": self.cpu_seconds,
                    "max_payload_bytes": self.max_payload_bytes,
                    "max_output_frame_bytes": self.max_stdout_bytes,
                }
                packet["request_digest"] = hashlib.sha256(_wire(packet)).hexdigest()
                output = tempfile.TemporaryFile(mode="w+b")
                writer = os.open(
                    "/proc/self/fd/" + str(output.fileno()), os.O_WRONLY | os.O_CLOEXEC
                )
                if job_state.cancel.is_set():
                    return emit(plan, "canceled", "broker.executor_canceled_before_start")
                process = subprocess.Popen(
                    [str(self._executable), "-I", "-S", "-B", "-u", str(self.worker)],
                    cwd=self.cwd,
                    env={},
                    stdin=subprocess.PIPE,
                    stdout=writer,
                    stderr=subprocess.STDOUT,
                    close_fds=True,
                    pass_fds=(descriptor,),
                    start_new_session=True,
                )
                if hasattr(os, "pidfd_open"):
                    try:
                        pidfd = os.pidfd_open(process.pid)
                    except OSError:
                        pidfd = None
                with self._jobs_lock:
                    job_state.process, job_state.pidfd, job_state.state = process, pidfd, "running"
                try:
                    assert process.stdin is not None
                    data = _wire(packet)
                    if len(data) > 2048:
                        raise ValueError("executor control packet exceeds fixed pipe bound")
                    process.stdin.write(data)
                    process.stdin.close()
                    deadline = time.monotonic() + self.timeout_ms / 1000
                    while process.poll() is None:
                        if job_state.cancel.is_set() or time.monotonic() >= deadline:
                            canceled = job_state.cancel.is_set()
                            stopped = self._terminate(process, pidfd)
                            result = emit(
                                plan,
                                "canceled" if canceled and stopped else "unknown",
                                "broker.executor_canceled"
                                if canceled and stopped
                                else "broker.executor_timeout",
                            )
                            if not stopped:
                                with self._jobs_lock:
                                    job_state.state = "unable_to_stop"
                            return result
                        time.sleep(0.005)
                except (OSError, ValueError):
                    return emit(plan, "unknown", "broker.executor_control_failed")
                size = os.fstat(output.fileno()).st_size
                if size > self.max_stdout_bytes:
                    return emit(plan, "unknown", "broker.executor_frame_limit")
                output.seek(0)
                frame = output.read(self.max_stdout_bytes + 1)
                if process.returncode != 0:
                    return emit(
                        plan,
                        "unsupported",
                        "broker.kernel_restriction_unavailable",
                        stdout_bytes=len(frame),
                    )
                response = json.loads(frame)
                required = {
                    "protocol",
                    "request_digest",
                    "nonce",
                    "action_digest",
                    "contract_digest",
                    "policy_digest",
                    "status",
                    "payload",
                    "payload_digest",
                    "payload_bytes",
                    "file_identity",
                    "isolation",
                }
                if (
                    type(response) is not dict
                    or set(response) != required
                    or any(
                        response[key] != packet[key]
                        for key in (
                            "protocol",
                            "request_digest",
                            "nonce",
                            "action_digest",
                            "contract_digest",
                            "policy_digest",
                            "file_identity",
                        )
                    )
                ):
                    raise ValueError("executor response does not match actual forwarding")
                isolation = response["isolation"]
                expected_limits = {
                    "cpu_seconds": [self.cpu_seconds] * 2,
                    "memory_bytes": [self.memory_mib * 1048576] * 2,
                    "processes": [1, 1],
                    "descriptors": [4, 4],
                    "core_bytes": [0, 0],
                    "output_frame_bytes": [self.max_stdout_bytes] * 2,
                }
                if (
                    type(isolation) is not dict
                    or isolation.get("landlock_abi", 0) < 1
                    or isolation.get("seccomp_mode") != 2
                    or isolation.get("no_new_privileges") != 1
                    or isolation.get("filter_digest") != FILTER_DIGEST
                    or isolation.get("limits") != expected_limits
                    or isolation.get("uid") != self.uid
                    or isolation.get("gid") != self.gid
                    or isolation.get("environment_empty") is not True
                    or isolation.get("checks") != dict.fromkeys(CHECKS, True)
                    or isolation.get("filesystem_scope") != "preopened_exact_read_only_file"
                    or any(
                        isolation.get(key) != "denied"
                        for key in ("network_access", "process_creation", "executable_launch")
                    )
                ):
                    raise ValueError("executor kernel receipt is incomplete")
                self._verify_install()
                current = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self._fd)
                try:
                    if _file_identity(descriptor) != bound or _file_identity(current) != bound:
                        raise ValueError("executor target identity changed")
                finally:
                    os.close(current)
                value = None
                if response["status"] == "completed":
                    value = base64.b64decode(response["payload"], validate=True)
                    if (
                        len(value) > self.max_payload_bytes
                        or len(value) != response["payload_bytes"]
                        or hashlib.sha256(value).hexdigest() != response["payload_digest"]
                    ):
                        raise ValueError("executor payload binding differs")
                elif (
                    response["status"] != "denied"
                    or response["payload"] != ""
                    or response["payload_digest"] is not None
                    or response["payload_bytes"] != 0
                ):
                    raise ValueError("executor outcome unavailable")
                observation = source.observe(
                    plan.contract,
                    observation_id="worker-" + nonce,
                    trust="backend_observed" if value is not None else "backend_enforced",
                    enforcement_point="filesystem",
                    outcome="completed" if value is not None else "denied",
                    operation="filesystem.read",
                    effects=("filesystem.read",),
                    resources=(ObservedResource("path", str(self.workspace / name)),),
                    reason_code="broker.kernel_read_completed"
                    if value is not None
                    else "broker.kernel_read_denied",
                    metadata={
                        "event_digest": digest([isolation, nonce, plan.policy_digest, len(frame)]),
                        "request_id_digest": nonce,
                        "source_schema_version": PROTOCOL,
                    },
                )
                return emit(
                    plan,
                    response["status"],
                    "broker.kernel_read_completed"
                    if value is not None
                    else "broker.kernel_read_denied",
                    physical=True,
                    evidence=isolation,
                    stdout_bytes=len(frame),
                    value=value,
                    observation=observation,
                )
            except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
                return emit(plan, "unknown", "broker.executor_binding_or_runtime_failed")
            finally:
                if process is not None and process.poll() is None:
                    if not self._terminate(process, pidfd):
                        with self._jobs_lock:
                            job_state.state = "unable_to_stop"
                if pidfd is not None and process is not None and process.poll() is not None:
                    os.close(pidfd)
                    with self._jobs_lock:
                        job_state.pidfd = None
                if descriptor is not None:
                    os.close(descriptor)
                if writer is not None:
                    os.close(writer)
                if output is not None:
                    output.close()

    def close(self) -> None:
        with self._lock:
            if self._fd >= 0:
                os.close(self._fd)
                self._fd = -1
