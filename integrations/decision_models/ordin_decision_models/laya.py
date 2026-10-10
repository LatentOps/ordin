"""Explicit persistent local inference worker; import starts nothing."""

from __future__ import annotations

import asyncio
import hashlib
import os
import queue
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ordin import ActionEnvelope
from ordin._runtime_json import digest as core_digest
from ordin.assurance import (
    ApprovedSecurityProfile,
    HostApproval,
    HostConstraintAssessment,
    HostEvidenceSource,
)
from ordin.assurance._files import directory_entries
from ordin.assurance._json import canonical_json, digest, validate
from ordin.assurance.codex_security._process_tree import ProcessTree
from ordin.assurance.codex_security._validation import loads
from ordin.assurance.models import ModelAnswer

from .checkpoints import LocalCheckpoint, hash_local_file
from .protocol import ProviderDescriptor, SanitizedDecisionState, SecurityQuestionSet, evidence


@dataclass(frozen=True)
class LocalModelRuntime:
    python: Path
    python_sha256: str
    worker: Path
    worker_sha256: str
    trusted_cwd: Path
    private_home: Path
    installation_digest: str
    forbidden_roots: tuple[Path, ...]
    setup_deadline_ms: int = 120000
    max_calls: int = 32

    def __post_init__(self):
        for path in (
            self.python,
            self.worker,
            self.trusted_cwd,
            self.private_home,
            *self.forbidden_roots,
        ):
            if not isinstance(path, Path) or not path.is_absolute():
                raise ValueError("local runtime paths must be explicit absolute host selections")
        if (
            self.python.suffix.lower() in {".cmd", ".bat", ".ps1"}
            or self.worker.name != "_laya_worker.py"
            or not isinstance(self.forbidden_roots, tuple)
            or not 1 <= len(self.forbidden_roots) <= 8
        ):
            raise ValueError(
                "local runtime requires native interpreter, fixed worker and target exclusions"
            )
        for pin in (self.python_sha256, self.worker_sha256, self.installation_digest):
            validate(
                "assurance_authority_ref", {"authority_id": "local-runtime", "boundary_digest": pin}
            )
        if (
            type(self.setup_deadline_ms) is not int
            or not 1 <= self.setup_deadline_ms <= 300000
            or type(self.max_calls) is not int
            or not 1 <= self.max_calls <= 32
        ):
            raise ValueError("local setup/call budget invalid")

    @property
    def digest(self):
        return digest(
            "local_model_runtime",
            {
                "python_path": core_digest(str(self.python)),
                "python": self.python_sha256,
                "worker_path": core_digest(str(self.worker)),
                "worker": self.worker_sha256,
                "cwd": core_digest(str(self.trusted_cwd)),
                "home": core_digest(str(self.private_home)),
                "installation": self.installation_digest,
                "exclusions": [core_digest(str(path)) for path in self.forbidden_roots],
                "setup_deadline_ms": self.setup_deadline_ms,
                "max_calls": self.max_calls,
            },
        )

    def verify(self, checkpoint: LocalCheckpoint):
        paths = (self.python, self.worker, self.trusted_cwd, self.private_home, checkpoint.root)
        for path in paths:
            if any(path.is_relative_to(root) for root in self.forbidden_roots):
                raise ValueError("model runtime/checkpoint/home must be outside target roots")
            for parent in (path if path.is_dir() else path.parent, *path.parents):
                if (parent / ".git").exists():
                    raise ValueError(
                        "model runtime/checkpoint must be outside enclosing Git worktrees"
                    )
            directory_entries(path if path.is_dir() else path.parent, maximum=4096)
        for path, expected in (
            (self.python, self.python_sha256),
            (self.worker, self.worker_sha256),
        ):
            if hash_local_file(path.parent, path.name, maximum=134_217_728)[0] != expected:
                raise ValueError("local runtime differs from reviewed executable pin")
        if directory_entries(self.private_home):
            raise ValueError("local model setup requires fresh private home")
        if os.name == "posix" and self.private_home.stat().st_mode & 0o077:
            raise ValueError("local model home must be private")
        checkpoint.verify()


def local_setup_action(runtime: LocalModelRuntime, checkpoint: LocalCheckpoint):
    return ActionEnvelope(
        "decision_model",
        "local_setup",
        {
            "runtime_digest": runtime.digest,
            "checkpoint_digest": checkpoint.manifest_digest,
            "package_version": "0.4.1",
            "network": "disabled",
            "max_calls": runtime.max_calls,
            "disclosure": "Only selected sanitized semantic inputs reach the local isolated worker.",
        },
    )


@dataclass(frozen=True)
class _LocalSeal:
    digest: str


@dataclass(frozen=True)
class LocalModelScope:
    source_key: str
    profile_digest: str
    setup_digest: str
    consent_ref: str
    expires_at: float
    _seal: _LocalSeal | None = field(default=None, repr=False, compare=False)
    _lock: Any = field(default_factory=threading.Lock, repr=False, compare=False)
    _used: list[bool] = field(default_factory=lambda: [False], repr=False, compare=False)

    def material(self):
        return {
            "source": self.source_key,
            "profile": self.profile_digest,
            "setup": self.setup_digest,
            "consent": self.consent_ref,
            "expires_at": self.expires_at,
        }

    def __post_init__(self):
        if not isinstance(self._seal, _LocalSeal) or self._seal.digest != digest(
            "local_model_scope", self.material()
        ):
            raise ValueError(
                "local model scope requires explicit protected setup/isolation approval"
            )

    def consume(self, action):
        with self._lock:
            if (
                self._used[0]
                or time.monotonic() >= self.expires_at
                or self.setup_digest != core_digest(action.as_dict())
            ):
                return False
            self._used[0] = True
            return True


def authorize_local_model(
    source: HostEvidenceSource,
    profile: ApprovedSecurityProfile,
    approval: HostApproval,
    isolation: HostConstraintAssessment,
    runtime: LocalModelRuntime,
    checkpoint: LocalCheckpoint,
    *,
    lifetime_seconds=3600,
):
    if not isinstance(source, HostEvidenceSource) or not isinstance(
        profile, ApprovedSecurityProfile
    ):
        raise ValueError("local model setup requires protected host/profile")
    source._check_profile(profile)
    action = local_setup_action(runtime, checkpoint)
    bound = core_digest(action.as_dict())
    for value, model in ((approval, HostApproval), (isolation, HostConstraintAssessment)):
        if (
            not isinstance(value, model)
            or value.source_key != source.key
            or value.profile_digest != profile.digest
            or value.action_digest != bound
        ):
            raise ValueError("local setup consent/isolation is stale or from another scope")
    if (
        isolation.kind != "semantic_local_scope"
        or isolation.invariant_id != "semantic.local_scope"
        or isolation.status != "satisfied"
    ):
        raise ValueError("local model no-egress/read-only/resource isolation is unresolved")
    if type(lifetime_seconds) is not int or not 1 <= lifetime_seconds <= 3600:
        raise ValueError("local model scope lifetime invalid")
    values: dict[str, Any] = dict(
        source_key=source.key,
        profile_digest=profile.digest,
        setup_digest=bound,
        consent_ref=approval.receipt_id,
        expires_at=time.monotonic() + lifetime_seconds,
    )
    preview = object.__new__(LocalModelScope)
    for key, value in values.items():
        object.__setattr__(preview, key, value)
    return LocalModelScope(
        **values, _seal=_LocalSeal(digest("local_model_scope", preview.material()))
    )


class _WorkerIO:
    def __init__(self, process, tree):
        self.process, self.tree = process, tree
        self.responses: queue.Queue = queue.Queue(maxsize=1)
        self.stop_lock = threading.Lock()
        self.stopped = False
        self.overflow = threading.Event()
        self.stdout_bytes = self.stderr_bytes = 0
        self.stdout_hash, self.stderr_hash = hashlib.sha256(), hashlib.sha256()
        self.readers = [
            threading.Thread(target=self._stdout, daemon=True),
            threading.Thread(target=self._stderr, daemon=True),
        ]
        for reader in self.readers:
            reader.start()

    def stop(self):
        with self.stop_lock:
            if not self.stopped:
                self.stopped = True
                self.tree.close()
                if self.process.poll() is None:
                    try:
                        self.process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        self.process.kill()
                        self.process.wait(timeout=2)

    def _stdout(self):
        pipe = self.process.stdout
        try:
            while True:
                raw = pipe.readline(65537)
                if not raw:
                    break
                self.stdout_bytes += len(raw)
                self.stdout_hash.update(raw)
                if len(raw) > 65536 or not raw.endswith(b"\n") or self.stdout_bytes > 2_162_688:
                    self.overflow.set()
                    self.stop()
                    break
                try:
                    self.responses.put_nowait(raw)
                except queue.Full:
                    self.overflow.set()
                    self.stop()
                    break
        finally:
            pipe.close()

    def _stderr(self):
        pipe = self.process.stderr
        try:
            while True:
                raw = pipe.read1(8192)
                if not raw:
                    break
                self.stderr_bytes += len(raw)
                self.stderr_hash.update(raw)
                if self.stderr_bytes > 65536:
                    self.overflow.set()
                    self.stop()
                    break
        finally:
            pipe.close()

    def response(self, deadline, cancel=None):
        while True:
            if self.overflow.is_set():
                raise ValueError("worker output exceeded budget")
            if cancel is not None and cancel.is_set():
                raise InterruptedError("local model canceled")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("local model deadline exceeded")
            try:
                return loads(self.responses.get(timeout=min(0.02, remaining)))
            except queue.Empty:
                if self.process.poll() is not None or self.stopped:
                    raise OSError("local worker unavailable")

    def send(self, packet, deadline):
        raw = (canonical_json(packet) + "\n").encode()
        if len(raw) > 16384:
            raise ValueError("local request byte budget exceeded")
        done = threading.Event()
        failed = []

        def write():
            try:
                self.process.stdin.write(raw)
                self.process.stdin.flush()
            except (ValueError, OSError):
                failed.append(True)
            finally:
                done.set()

        sender = threading.Thread(target=write, daemon=True)
        sender.start()
        if not done.wait(max(0, deadline - time.monotonic())):
            self.stop()
            sender.join(timeout=2)
            raise TimeoutError("local worker input deadline exceeded")
        if failed:
            raise OSError("local worker input unavailable")

    def close(self):
        self.stop()
        try:
            self.process.stdin.close()
        except (ValueError, OSError):
            pass
        for reader in self.readers:
            if reader is not threading.current_thread():
                reader.join(timeout=2)


class LayaDecisionModel:
    def __init__(self, runtime: LocalModelRuntime, checkpoint: LocalCheckpoint):
        if not isinstance(runtime, LocalModelRuntime) or not isinstance(
            checkpoint, LocalCheckpoint
        ):
            raise ValueError("local model needs typed runtime/checkpoint selection")
        self.runtime, self.checkpoint = runtime, checkpoint
        self._descriptor = ProviderDescriptor(
            "laya",
            "laya:0.4.1:" + checkpoint.manifest_digest,
            "local",
            digest("laya_configuration", [runtime.digest, checkpoint.manifest_digest]),
        )
        self._worker: _WorkerIO | None = None
        self._scope: LocalModelScope | None = None
        self._expiry_timer: threading.Timer | None = None
        self._lock = threading.Lock()
        self._calls = 0
        self._setup_started = False

    @property
    def descriptor(self):
        return self._descriptor

    def initialize(self, scope: LocalModelScope, *, cancel: threading.Event | None = None):
        """Explicit model setup only, after an actual broker isolation assessment."""
        if cancel is not None and cancel.is_set():
            raise InterruptedError("local model setup canceled before launch")
        if not isinstance(scope, LocalModelScope) or not scope.consume(
            local_setup_action(self.runtime, self.checkpoint)
        ):
            raise ValueError("local model initialization lacks current explicit scope")
        with self._lock:
            if self._setup_started:
                raise ValueError("local model instance cannot reinitialize or reuse scope")
            self._setup_started = True
            self.runtime.verify(self.checkpoint)
            allowed = {"SYSTEMROOT", "WINDIR", "LANG", "LC_ALL"}
            env = {key: value for key, value in os.environ.items() if key.upper() in allowed}
            env.update(
                {
                    "HOME": str(self.runtime.private_home),
                    "USERPROFILE": str(self.runtime.private_home),
                    "PATH": str(self.runtime.python.parent),
                    "HF_HOME": str(self.runtime.private_home / "hf"),
                    "HF_HUB_OFFLINE": "1",
                    "TRANSFORMERS_OFFLINE": "1",
                    "HF_HUB_DISABLE_TELEMETRY": "1",
                    "USE_TF": "0",
                    "PYTHONNOUSERSITE": "1",
                    "PYTHONSAFEPATH": "1",
                    "OMP_NUM_THREADS": "1",
                    "TOKENIZERS_PARALLELISM": "false",
                    "TMP": str(self.runtime.private_home),
                    "TEMP": str(self.runtime.private_home),
                }
            )
            process = subprocess.Popen(
                [str(self.runtime.python), "-I", "-u", str(self.runtime.worker)],
                shell=False,
                cwd=self.runtime.trusted_cwd,
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=os.name == "posix",
                creationflags=(getattr(subprocess, "CREATE_NO_WINDOW", 0) | 4)
                if os.name == "nt"
                else 0,
            )
            try:
                tree = ProcessTree(process)
            except BaseException:
                process.kill()
                process.wait(timeout=2)
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()
                raise
            worker = self._worker = _WorkerIO(process, tree)
            try:
                deadline = time.monotonic() + self.runtime.setup_deadline_ms / 1000
                worker.send(
                    {"operation": "load", "checkpoint": self.checkpoint.worker_dict()}, deadline
                )
                ready = worker.response(deadline, cancel)
                if ready != {
                    "status": "ready",
                    "package_version": "0.4.1",
                    "manifest_digest": self.checkpoint.manifest_digest,
                    "device": self.checkpoint.device,
                    "max_tokens": self.checkpoint.max_tokens,
                }:
                    raise ValueError(
                        "local worker version/device/checkpoint handshake differs from selected contract"
                    )
                if time.monotonic() >= scope.expires_at:
                    raise ValueError("local model scope expired during setup")
                self._scope = scope
                timer = self._expiry_timer = threading.Timer(
                    max(0, scope.expires_at - time.monotonic()), self.close
                )
                timer.daemon = True
                timer.start()
            except BaseException:
                worker.close()
                raise

    def evaluate(
        self, state: SanitizedDecisionState, questions: SecurityQuestionSet, *, deadline_ms: int
    ):
        if type(deadline_ms) is not int or not 1 <= deadline_ms <= 30000:
            raise ValueError("local model deadline invalid")
        started = time.monotonic()
        deadline = started + deadline_ms / 1000
        if not isinstance(state, SanitizedDecisionState) or not isinstance(
            questions, SecurityQuestionSet
        ):
            raise ValueError("local model input requires current sanitized typed state")
        if not self._lock.acquire(timeout=deadline_ms / 1000):
            return evidence(self.descriptor, state, questions, error_class="timeout")
        error = "none"
        answers: tuple[ModelAnswer, ...] = ()
        try:
            worker, scope = self._worker, self._scope
            if worker is None or scope is None or worker.stopped:
                error = "unavailable"
            elif time.monotonic() >= scope.expires_at or state.host_source_key != scope.source_key:
                error = "refused"
                worker.close()
            elif scope.setup_digest != core_digest(
                local_setup_action(self.runtime, self.checkpoint).as_dict()
            ):
                error = "version_mismatch"
                worker.close()
            elif self._calls >= self.runtime.max_calls:
                error = "budget"
                worker.close()
            else:
                self._calls += 1
                request_id = "local:" + str(self._calls)
                worker.send(
                    {
                        "operation": "evaluate",
                        "request_id": request_id,
                        "state": state.as_dict(),
                        "question_set": questions.as_dict(),
                        "state_digest": state.digest,
                        "question_set_digest": questions.digest,
                    },
                    deadline,
                )
                response = worker.response(deadline)
                if response.get("request_id") != request_id:
                    error = "malformed"
                elif response.get("status") == "incomplete":
                    error = "refused"
                elif (
                    set(response)
                    != {
                        "status",
                        "request_id",
                        "state_digest",
                        "question_set_digest",
                        "manifest_digest",
                        "answers",
                        "input_tokens",
                    }
                    or response.get("status") != "completed"
                ):
                    error = "malformed"
                elif (
                    response["state_digest"] != state.digest
                    or response["manifest_digest"] != self.checkpoint.manifest_digest
                ):
                    error = "version_mismatch"
                elif (
                    response["question_set_digest"] != questions.digest
                    or not isinstance(response["answers"], dict)
                    or set(response["answers"]) != set(questions.question_ids)
                ):
                    error = "question_mismatch"
                elif (
                    type(response["input_tokens"]) is not int
                    or not 0 <= response["input_tokens"] <= 65536
                ):
                    error = "malformed"
                else:
                    answers = tuple(
                        ModelAnswer(key, response["answers"][key]) for key in questions.question_ids
                    )
                if error != "none":
                    worker.close()
        except TimeoutError:
            error = "timeout"
            self.close()
        except (ValueError, OSError):
            error = "malformed"
            self.close()
        finally:
            self._lock.release()
        return evidence(
            self.descriptor,
            state,
            questions,
            answers=answers,
            error_class=error,
            latency_ms=round((time.monotonic() - started) * 1000, 6),
            consent_ref=self._scope.consent_ref if self._scope else None,
        )

    async def evaluate_async(self, state, questions, *, deadline_ms):
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(self.evaluate, state, questions, deadline_ms=deadline_ms),
                deadline_ms / 1000,
            )
        except asyncio.CancelledError:
            self.close()
            raise
        except asyncio.TimeoutError:
            self.close()
            return evidence(self.descriptor, state, questions, error_class="timeout")

    def close(self):
        if self._expiry_timer is not None:
            self._expiry_timer.cancel()
        if self._worker is not None:
            self._worker.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def public_metrics(self):
        worker = self._worker
        return {
            "initialized": self._scope is not None,
            "calls": self._calls,
            "worker_stopped": worker.stopped if worker else True,
            "stdout_bytes": worker.stdout_bytes if worker else 0,
            "stderr_bytes": worker.stderr_bytes if worker else 0,
            "stdout_sha256": worker.stdout_hash.hexdigest()
            if worker
            else hashlib.sha256(b"").hexdigest(),
            "stderr_sha256": worker.stderr_hash.hexdigest()
            if worker
            else hashlib.sha256(b"").hexdigest(),
            "device": self.checkpoint.device,
            "checkpoint_digest": self.checkpoint.manifest_digest,
        }
