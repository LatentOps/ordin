"""Original owned Linux Python processes; untrusted output is never authority.

The closed worker reports readiness before loading untrusted code. The parent
retains that handshake and the actual owned exit status independently of any
subsequent child output. No constructor or review starts a process.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import secrets
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
from threading import Event, RLock, Thread
import time
from typing import Any
from uuid import uuid4

from ordin._runtime_json import digest, freeze, thaw


PROCESS_PROTOCOL = "ordin.protected_python.v1"
MAX_PROCESS_FRAME = 65536
MAX_BOOTSTRAP_FRAME = 262144
MAX_AGENT_SOURCE = 65536
REQUIRED_PROCESS_ENV = "ORDIN_REQUIRED_PROTECTED_PROCESS"


def _wire(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _sha(path: Path) -> str:
    return hashlib.sha256(_source(path, 32 * 1048576)).hexdigest()


def _hex(value: str) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(c not in "0123456789abcdef" for c in value)
    ):
        raise ValueError("exact protected process digest required")


def _private_directory(path: Path, *, empty: bool = False) -> None:
    if path.resolve(strict=True) != path:
        raise ValueError("canonical owned process directory required")
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or (
        os.name == "posix" and (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077)
    ):
        raise ValueError("private owned process directory required")
    if empty and any(path.iterdir()):
        raise ValueError("fresh process installation directory required")


def _source(path: Path, maximum: int) -> bytes:
    """Read one exact regular object without waiting for a special-file writer."""
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_BINARY", 0),
    )
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > maximum:
            raise ValueError("bounded singly-linked regular process input required")
        chunks = bytearray()
        while len(chunks) <= maximum:
            part = os.read(descriptor, min(65536, maximum + 1 - len(chunks)))
            if not part:
                break
            chunks.extend(part)
        after = os.fstat(descriptor)
        if len(chunks) > maximum or (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError("process input changed while being captured")
        return bytes(chunks)
    finally:
        os.close(descriptor)


@dataclass(frozen=True, slots=True)
class ProtectedProcessLimits:
    timeout_ms: int = 10000
    cpu_seconds: int = 3
    memory_mib: int = 256
    output_bytes: int = 65536
    scratch_bytes: int = 4 * 1048576
    scratch_inodes: int = 128
    maximum_calls: int = 64

    def __post_init__(self) -> None:
        for value, low, high in (
            (self.timeout_ms, 1000, 60000),
            (self.cpu_seconds, 1, 30),
            (self.memory_mib, 128, 1024),
            (self.output_bytes, 8192, 1048576),
            (self.scratch_bytes, 1048576, 32 * 1048576),
            (self.scratch_inodes, 64, 1024),
            (self.maximum_calls, 1, 256),
        ):
            if type(value) is not int or not low <= value <= high:
                raise ValueError("invalid hard protected process bounds")
        if self.scratch_bytes % 4096:
            raise ValueError("scratch byte bound must use whole kernel pages")
        if self.scratch_bytes // min(self.output_bytes, 65536) + 3 >= self.scratch_inodes:
            raise ValueError("scratch inode budget must permit an independent byte-quota probe")

    def as_dict(self) -> dict[str, int]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


@dataclass(frozen=True, eq=False, slots=True)
class ProtectedProcessJob:
    job_id: str


@dataclass(frozen=True, eq=False, slots=True)
class ProtectedProcessOutcome:
    status: str
    exit_code: int | None
    binding_digest: str
    isolation_digest: str | None
    output_digest: str
    output_bytes: int
    output: bytes = field(repr=False)

    def as_dict(self) -> dict:
        return {
            "protocol": PROCESS_PROTOCOL,
            "status": self.status,
            "exit_code": self.exit_code,
            "binding_digest": self.binding_digest,
            "isolation_digest": self.isolation_digest,
            "output_digest": self.output_digest,
            "output_bytes": self.output_bytes,
            "output_trust": "untrusted_workload_diagnostic",
            "test_correctness_verified": False,
            "execution_authority": False,
        }


@dataclass
class _Process:
    job_id: str
    binding: str
    program: bytes
    mode: str = "agent"
    test_settings: dict[str, Any] = field(default_factory=dict)
    root: Path | None = None
    state: str = "queued"
    cancel: Event = field(default_factory=Event)
    process: Any = None
    pidfd: int | None = None
    channel: socket.socket | None = None
    output: Any = None
    deadline: float = 0
    ready: Any = None
    result: ProtectedProcessOutcome | None = None
    calls: int = 0
    stop_reason: str | None = None
    control_lock: Any = field(default_factory=RLock)
    finish_lock: Any = field(default_factory=RLock)


class LinuxProtectedProcess:
    """Closed fresh-agent factory. Host control and TLS remain outside its child.

    This first route deliberately exposes only preloaded standard-library Python,
    the injected MCP client, and private quota-limited scratch. It is not a
    launcher for an existing process, arbitrary interpreter, or host environment.
    """

    def __init__(
        self,
        install_root: Path,
        *,
        operator: object,
        limits: ProtectedProcessLimits = ProtectedProcessLimits(),
        maximum_jobs: int = 16,
    ):
        if type(operator) is not object or type(limits) is not ProtectedProcessLimits:
            raise ValueError("original host operator and exact process limits required")
        if type(maximum_jobs) is not int or not 1 <= maximum_jobs <= 64:
            raise ValueError("bounded protected process history required")
        self._operator, self.limits, self._maximum = operator, limits, maximum_jobs
        self.root = Path(install_root).absolute()
        self._jobs: dict[ProtectedProcessJob, _Process] = {}
        self._outcomes: dict[ProtectedProcessOutcome, str] = {}
        self._lock = RLock()
        self._shipped = Path(__file__).with_name("_managed_worker.py").resolve()
        self._worker_digest = _sha(self._shipped)
        self._interpreter = Path(getattr(sys, "_base_executable", sys.executable)).resolve()
        self._interpreter_digest = _sha(self._interpreter)
        self._nonce = secrets.token_hex(32)
        self._candidate = (
            sys.platform == "linux" and os.uname().machine == "x86_64" and os.geteuid() == 0
        )
        self.worker = self.root / "_managed_worker.py"
        if self._candidate:
            _private_directory(self.root, empty=True)
            if any((parent / ".git").exists() for parent in (self.root, *self.root.parents)):
                raise ValueError("protected worker installation must be outside Git")
            with self.worker.open("xb") as output:
                output.write(self._shipped.read_bytes())
                output.flush()
                os.fsync(output.fileno())
            self.worker.chmod(0o400)

    @property
    def configuration_digest(self) -> str:
        return digest(
            [
                PROCESS_PROTOCOL,
                self._nonce,
                self._worker_digest,
                self._interpreter_digest,
                self.limits.as_dict(),
                self._maximum,
            ]
        )

    @property
    def candidate(self) -> bool:
        """Platform prerequisite only; actual readiness must still be proved."""
        return self._candidate

    def _check(self, operator: object) -> None:
        if operator is not self._operator:
            raise ValueError("original protected process operator required")

    def _job(self, job: ProtectedProcessJob) -> _Process:
        row = self._jobs.get(job) if type(job) is ProtectedProcessJob else None
        if row is None or row.job_id != job.job_id:
            raise ValueError("original unchanged protected process job required")
        return row

    def create_job(
        self, program: Path, expected_digest: str, *, operator: object
    ) -> ProtectedProcessJob:
        self._check(operator)
        _hex(expected_digest)
        data = _source(Path(program), MAX_AGENT_SOURCE)
        if hashlib.sha256(data).hexdigest() != expected_digest:
            raise ValueError("operator-pinned agent source differs")
        data.decode("utf-8")
        with self._lock:
            if len(self._jobs) >= self._maximum:
                raise ValueError("protected process history capacity reached")
            job = ProtectedProcessJob(uuid4().hex)
            binding = digest([self.configuration_digest, job.job_id, expected_digest])
            self._jobs[job] = _Process(job.job_id, binding, data)
            return job

    def _prepare_test(
        self, settings: dict, binding: str, *, operator: object
    ) -> ProtectedProcessJob:
        self._check(operator)
        _hex(binding)
        if type(settings) is not dict or set(settings) != {
            "project_root",
            "snapshot",
            "snapshot_digest",
            "runtime_root",
            "runtime_digest",
            "stdlib_virtual",
            "selectors",
        }:
            raise ValueError("closed fixed-test bootstrap settings required")
        _hex(settings["snapshot_digest"])
        _hex(settings["runtime_digest"])
        with self._lock:
            if len(self._jobs) >= self._maximum:
                raise ValueError("protected process history capacity reached")
            job = ProtectedProcessJob(uuid4().hex)
            self._jobs[job] = _Process(
                job.job_id,
                digest([self.configuration_digest, job.job_id, binding]),
                b"",
                mode="pytest",
                test_settings=json.loads(_wire(settings)),
            )
            return job

    def _verify_install(self) -> None:
        _private_directory(self.root)
        if (
            _sha(self._shipped) != self._worker_digest
            or _sha(self.worker) != self._worker_digest
            or _sha(self._interpreter) != self._interpreter_digest
        ):
            raise ValueError("protected worker or interpreter identity changed")

    def _recv(self, row: _Process, maximum: int) -> dict:
        channel = row.channel
        if channel is None:
            raise ValueError("original private process channel unavailable")

        def exact(count: int) -> bytes:
            data = bytearray()
            while len(data) < count:
                if row.cancel.is_set() or time.monotonic() >= row.deadline:
                    raise TimeoutError("owned process canceled or deadline reached")
                readable, _, _ = select.select([channel], [], [], 0.05)
                if not readable:
                    if row.process.poll() is not None:
                        raise EOFError("owned process exited")
                    continue
                part = channel.recv(count - len(data))
                if not part:
                    raise EOFError("owned process channel closed")
                data.extend(part)
            return bytes(data)

        length = struct.unpack("!I", exact(4))[0]
        if not 1 <= length <= maximum:
            raise ValueError("protected process frame exceeds its bound")
        raw = exact(length)

        def unique(pairs):
            selected = {}
            for key, value in pairs:
                if key in selected:
                    raise ValueError("duplicate protected process frame field")
                selected[key] = value
            return selected

        try:
            result = json.loads(raw, object_pairs_hook=unique)
        except (RecursionError, UnicodeError) as exc:
            raise ValueError("private process frame is not bounded Unicode JSON") from exc
        if type(result) is not dict:
            raise ValueError("protected process frame requires an object")
        pending, count = [(result, 0)], 0
        while pending:
            value, depth = pending.pop()
            count += 1
            if count > 4096 or depth > 16:
                raise ValueError("private process JSON exceeds its structural bounds")
            if type(value) is dict:
                pending.extend((part, depth + 1) for pair in value.items() for part in pair)
            elif type(value) is list:
                pending.extend((part, depth + 1) for part in value)
        # Round-trip UTF-8 and finite numbers before any host dispatch.
        json.dumps(result, ensure_ascii=False, allow_nan=False).encode("utf-8")
        return result

    @staticmethod
    def _send(row: _Process, message: dict, maximum: int) -> None:
        raw = _wire(message)
        if not 1 <= len(raw) <= maximum or row.channel is None:
            raise ValueError("protected process reply exceeds its bound")
        row.channel.settimeout(0.1)
        try:
            row.channel.sendall(struct.pack("!I", len(raw)) + raw)
        finally:
            row.channel.settimeout(None)

    def start(self, job: ProtectedProcessJob, *, operator: object) -> bool:
        self._check(operator)
        with self._lock:
            row = self._job(job)
            if row.state == "canceled" and row.cancel.is_set():
                return False
            if row.state != "queued":
                raise ValueError("protected process job already started")
            if row.cancel.is_set():
                row.state = "canceled"
                return False
            row.state = "starting"
        if not self._candidate:
            row.state = "unsupported"
            return False
        child = writer = None
        try:
            self._verify_install()
            root = self.root / ("job-" + row.job_id)
            root.mkdir(mode=0o700)
            row.root = root
            jail = root / "jail"
            jail.mkdir(mode=0o755)
            (jail / "tmp").mkdir(mode=0o755)
            (jail / "scratch").mkdir(mode=0o755)
            (jail / "pytest.ini").write_text("[pytest]\naddopts =\n", encoding="utf-8")
            (jail / "pytest.ini").chmod(0o444)
            (jail / "forbidden").write_bytes(b"owned kernel denial canary")
            (jail / "forbidden").chmod(0o444)
            row.output = tempfile.TemporaryFile(mode="w+b")
            writer = os.open(
                "/proc/self/fd/" + str(row.output.fileno()), os.O_WRONLY | os.O_CLOEXEC
            )
            parent, child = socket.socketpair()
            row.channel = parent
            packet = {
                "protocol": PROCESS_PROTOCOL,
                "mode": row.mode,
                "nonce": secrets.token_hex(32),
                "binding": row.binding,
                "jail": str(jail),
                "ipc_fd": child.fileno(),
                "uid": 65534,
                "gid": 65534,
                "limits": self.limits.as_dict(),
                "program": row.program.decode("utf-8"),
            }
            if row.mode == "pytest":
                packet["test"] = row.test_settings
            raw = _wire(packet)
            if len(raw) > MAX_BOOTSTRAP_FRAME:
                raise ValueError("protected process bootstrap exceeds fixed bound")
            row.deadline = time.monotonic() + self.limits.timeout_ms / 1000
            process = subprocess.Popen(
                [str(self._interpreter), "-I", "-S", "-B", str(self.worker)],
                stdin=subprocess.PIPE,
                stdout=writer,
                stderr=writer,
                env={},
                cwd=self.root,
                close_fds=True,
                pass_fds=(child.fileno(),),
                start_new_session=True,
            )
            row.process = process
            child.close()
            child = None
            if hasattr(os, "pidfd_open"):
                row.pidfd = os.pidfd_open(process.pid)
            assert process.stdin is not None
            process.stdin.write(struct.pack("!I", len(raw)) + raw)
            process.stdin.close()
            ready = self._recv(row, 16384)
            self._validate_ready(row, packet, ready)
            row.ready = freeze(ready)
            row.state = "ready"
            return True
        except (OSError, ValueError, EOFError, TimeoutError, KeyError, TypeError):
            self._kill(row)
            row.state = "canceled" if row.cancel.is_set() else "unsupported"
            return False
        except BaseException:
            row.cancel.set()
            row.stop_reason = "interrupted"
            self._kill(row)
            if row.channel is not None:
                row.channel.close()
                row.channel = None
            raise
        finally:
            if child is not None:
                child.close()
            if writer is not None:
                os.close(writer)

    def _validate_ready(self, row: _Process, packet: dict, ready: dict) -> None:
        expected = {
            "host_read_denied",
            "project_write_denied",
            "socket_denied",
            "fork_denied",
            "exec_denied",
            "output_limit_enforced",
            "memory_limit_enforced",
            "scratch_byte_quota_enforced",
            "scratch_inode_quota_enforced",
            "descriptor_signal_denied",
        }
        if (
            set(ready) != {"protocol", "phase", "nonce", "binding", "isolation"}
            or ready["protocol"] != PROCESS_PROTOCOL
            or ready["phase"] != "ready"
            or ready["nonce"] != packet["nonce"]
            or ready["binding"] != row.binding
            or type(ready["isolation"]) is not dict
        ):
            raise ValueError("protected process readiness binding differs")
        isolation = ready["isolation"]
        if (
            isolation.get("checks") != dict.fromkeys(expected, True)
            or isolation.get("uid") != 65534
            or isolation.get("gid") != 65534
            or isolation.get("seccomp") != 2
            or isolation.get("no_new_privileges") != 1
            or isolation.get("landlock_abi", 0) < 1
            or isolation.get("limits") != self.limits.as_dict()
            or isolation.get("environment_empty") is not True
            or isolation.get("kernel_limits")
            != {
                "cpu_seconds": [self.limits.cpu_seconds] * 2,
                "address_space": [self.limits.memory_mib * 1048576] * 2,
                "processes": [1, 1],
                "descriptors": [16, 16],
                "output_file": [self.limits.output_bytes] * 2,
                "core": [0, 0],
            }
        ):
            raise ValueError("actual kernel readiness is incomplete")
        status = {}
        for line in Path(f"/proc/{row.process.pid}/status").read_text().splitlines():
            key, _, value = line.partition(":")
            status[key] = value.strip()
        if any(
            status.get(key) != value
            for key, value in {
                "NoNewPrivs": "1",
                "Seccomp": "2",
                "Threads": "1",
                "CapEff": "0000000000000000",
                "CapPrm": "0000000000000000",
                "CapInh": "0000000000000000",
                "CapAmb": "0000000000000000",
            }.items()
        ) or any(int(value) != 65534 for value in status["Uid"].split()):
            raise ValueError("external process isolation readback differs")
        for namespace in ("mnt", "net"):
            if os.readlink(f"/proc/{row.process.pid}/ns/{namespace}") == os.readlink(
                f"/proc/self/ns/{namespace}"
            ):
                raise ValueError("private process namespace unavailable")
        if row.root is None or os.readlink(f"/proc/{row.process.pid}/root") != str(
            row.root / "jail"
        ):
            raise ValueError("owned process root differs")

    def admit(self, job: ProtectedProcessJob, *, operator: object) -> None:
        self._check(operator)
        with self._lock:
            row = self._job(job)
            if row.state != "ready" or row.cancel.is_set():
                raise ValueError("original kernel-ready process required")
            self._send(
                row, {"protocol": PROCESS_PROTOCOL, "phase": "start", "binding": row.binding}, 4096
            )
            row.state = "running"
        Thread(
            target=self._watch, args=(row,), name="ordin-owned-process-deadline", daemon=True
        ).start()

    def _watch(self, row: _Process) -> None:
        while row.process is not None and row.process.poll() is None:
            if row.cancel.wait(0.01) or time.monotonic() >= row.deadline:
                row.stop_reason = "canceled" if row.cancel.is_set() else "timeout"
                self._kill(row)
                return

    def read_request(self, job: ProtectedProcessJob, *, operator: object) -> dict | None:
        self._check(operator)
        row = self._job(job)
        if row.state != "running":
            raise ValueError("original running process required")
        try:
            value = self._recv(row, MAX_PROCESS_FRAME)
        except EOFError:
            return None
        row.calls += 1
        if row.calls > self.limits.maximum_calls:
            self.request_stop(job, operator=operator)
            raise ValueError("protected process call bound reached")
        if (
            set(value) - {"jsonrpc", "id", "method", "params"}
            or value.get("jsonrpc") != "2.0"
            or type(value.get("method")) is not str
            or not 1 <= len(value["method"]) <= 128
        ):
            raise ValueError("child may send only bounded MCP client requests")
        return value

    def reply(self, job: ProtectedProcessJob, response: dict, *, operator: object) -> None:
        self._check(operator)
        row = self._job(job)
        if row.state != "running" or row.cancel.is_set():
            raise ValueError("original live process required")
        self._send(row, response, MAX_PROCESS_FRAME)

    @staticmethod
    def _kill(row: _Process) -> bool:
        with row.control_lock:
            process = row.process
            if process is None:
                return True
            try:
                if process.poll() is None:
                    if row.pidfd is not None and hasattr(signal, "pidfd_send_signal"):
                        signal.pidfd_send_signal(row.pidfd, signal.SIGKILL)
                    else:
                        process.kill()
                process.wait(timeout=2)
                return True
            except (OSError, subprocess.TimeoutExpired):
                return process.poll() is not None

    def request_stop(self, job: ProtectedProcessJob, *, operator: object) -> str:
        self._check(operator)
        with self._lock:
            row = self._job(job)
            row.cancel.set()
            if row.state == "queued":
                row.state = "canceled"
                return "canceled"
            return "completed" if row.result is not None else "unknown"

    def status(self, job: ProtectedProcessJob, *, operator: object) -> str:
        self._check(operator)
        with self._lock:
            return self._job(job).state

    def is_alive(self, job: ProtectedProcessJob, *, operator: object) -> bool:
        self._check(operator)
        row = self._job(job)
        return (
            row.process is not None
            and row.process.poll() is None
            and not row.cancel.is_set()
            and time.monotonic() < row.deadline
        )

    def finish(self, job: ProtectedProcessJob, *, operator: object) -> ProtectedProcessOutcome:
        self._check(operator)
        row = self._job(job)
        with row.finish_lock:
            return self._finish(row)

    def _finish(self, row: _Process) -> ProtectedProcessOutcome:
        if row.result is not None:
            return row.result
        if row.process is not None:
            while row.process.poll() is None and not row.cancel.is_set():
                if time.monotonic() >= row.deadline:
                    row.stop_reason = "timeout"
                    break
                time.sleep(0.005)
        if row.process is not None and row.process.poll() is None and not self._kill(row):
            row.state = "unable_to_stop"
            selected, code = "unknown", None
        else:
            code = row.process.returncode if row.process is not None else None
            selected = (
                "canceled"
                if row.cancel.is_set()
                else "unsupported"
                if row.ready is None and row.state == "unsupported"
                else "unknown"
                if row.stop_reason is not None or code is None or code < 0
                else "exited"
            )
            row.state = selected
        value = b""
        if row.output is not None:
            row.output.seek(0)
            value = row.output.read(self.limits.output_bytes + 1)
            if len(value) > self.limits.output_bytes:
                selected, value = "unknown", value[: self.limits.output_bytes]
        row.state = selected
        outcome = ProtectedProcessOutcome(
            selected,
            code,
            row.binding,
            digest(thaw(row.ready)) if row.ready is not None else None,
            hashlib.sha256(value).hexdigest(),
            len(value),
            value,
        )
        with self._lock:
            row.result = outcome
            self._outcomes[outcome] = digest(outcome.as_dict())
        if row.process is None or row.process.poll() is not None:
            if row.channel is not None:
                row.channel.close()
                row.channel = None
            if row.output is not None:
                row.output.close()
                row.output = None
            with row.control_lock:
                if row.pidfd is not None:
                    os.close(row.pidfd)
                    row.pidfd = None
        return outcome

    def evidence_record(self, outcome: ProtectedProcessOutcome) -> dict:
        if not self.verify_outcome(outcome):
            raise ValueError("original protected process outcome required")
        row = next(row for row in self._jobs.values() if row.result is outcome)
        return {
            "binding": row.binding,
            "isolation": thaw(row.ready) if row.ready is not None else None,
            "exit_code": outcome.exit_code,
            "output_digest": outcome.output_digest,
            "output_trust": "untrusted_workload_diagnostic",
            "test_correctness_verified": False,
        }

    def verify_outcome(self, outcome: ProtectedProcessOutcome) -> bool:
        return (
            type(outcome) is ProtectedProcessOutcome
            and self._outcomes.get(outcome) == digest(outcome.as_dict())
            and hashlib.sha256(outcome.output).hexdigest() == outcome.output_digest
        )

    def close(self, *, operator: object) -> None:
        self._check(operator)
        for job, row in tuple(self._jobs.items()):
            if row.result is None:
                self.request_stop(job, operator=operator)
                self.finish(job, operator=operator)
            if row.process is not None and row.process.poll() is None:
                raise RuntimeError("owned process outcome remains uncertain")
