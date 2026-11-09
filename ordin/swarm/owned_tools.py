"""Closed owned tools over private managed data; no caller-provided executor code."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field, replace
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from ordin import ToolCallAdapter
from ordin.action import ActionEnvelope
from ordin.assurance.host import HostCredentialUse, HostEvidenceSource
from ordin._rest_semantics import HEADER, UNSUPPORTED_HEADERS
from ordin._runtime_json import digest
from ordin.enforcement_backend import BackendValidationResult, CompilationResult, EnforcementPlan
from ordin.execution import ObservedResource
from ordin.runtime_contract import (
    CredentialBinding,
    FilesystemCapability,
    ProcessCapability,
    PrivilegeCapability,
    RuntimeCapabilityContract,
    ToolCapability,
)
from ordin.runtime_requests import request_endpoint
from ordin.runtime_observation import RuntimeEvidenceSource

from .events import _hex
from .linux_backend import ExecutorOutcome, KernelJob, LinuxFileReadBackend, _sha
from .models import counter, identifier
from ._owned_protocol import WRITE_PROTOCOL, filter_digest, wire
from ._owned_state import OwnedFileState


def owned_file_identity(info):
    return {
        "device": info.st_dev,
        "inode": info.st_ino,
        "mode": info.st_mode,
        "size": info.st_size,
        "mtime_ns": info.st_mtime_ns,
        "ctime_ns": info.st_ctime_ns,
        "uid": info.st_uid,
        "gid": info.st_gid,
        "links": info.st_nlink,
    }


def _parse_write(action, contract, *, paths, runtime, tool, maximum, uid):
    """Bound data before hashing; this parser creates no authorization or job."""
    if (
        type(action) is not ActionEnvelope
        or type(contract) is not RuntimeCapabilityContract
        or action.kind != "tool"
        or action.operation != "call"
        or set(action.parameters) != {"runtime", "tool", "arguments"}
        or action.parameters["runtime"] != runtime
        or action.parameters["tool"] != tool
    ):
        raise ValueError("exact owned write identity required")
    arguments = action.parameters["arguments"]
    if type(arguments) is not dict or set(arguments) != {
        "path",
        "content",
        "expected_version",
        "expected_digest",
    }:
        raise ValueError("exact bounded managed-write arguments required")
    path, content = arguments["path"], arguments["content"]
    if (
        type(path) is not str
        or path not in paths
        or type(content) is not str
        or len(content) > maximum
    ):
        raise ValueError("managed destination or content bound exceeded")
    raw = content.encode("utf-8")
    if len(raw) > maximum:
        raise ValueError("managed UTF-8 byte bound exceeded")
    version = counter(arguments["expected_version"], "managed expected version")
    expected = arguments["expected_digest"]
    if (version == 0 and expected is not None) or (
        version != 0 and _hex(expected, "managed expected digest") != expected
    ):
        raise ValueError("managed version/digest condition incomplete")
    if (
        contract.unknowns
        or contract.decision == "block"
        or contract.action_digest != digest(action.as_dict())
        or contract.filesystem != (FilesystemCapability("write", path, "exact"),)
        or contract.tools != (ToolCapability(runtime, None, tool),)
        or contract.network
        or contract.credentials
        or contract.process.execution is not False
        or contract.process.executables
        or contract.process.spawn_children not in {None, False}
        or contract.privilege.escalation is not False
        or contract.privilege.required_euid not in {None, uid}
    ):
        raise ValueError("unrepresented managed-write capability")
    return path, raw, version, expected


@dataclass(frozen=True)
class OwnedHTTPRoute:
    route_id: str
    url: str
    addresses: tuple[str, ...]
    headers: tuple[tuple[str, str], ...] = ()
    max_response_bytes: int = 65536
    ca_file: Path | None = None
    credential_binding: CredentialBinding | None = None
    credential: bytes | None = field(default=None, repr=False, compare=False)
    allow_private: bool = False
    allow_http: bool = False

    def __post_init__(self):
        identifier(self.route_id, "owned HTTP route")
        if type(self.url) is not str:
            raise ValueError("literal owned HTTP URL required")
        endpoint = request_endpoint(self.url)
        parsed = urlsplit(self.url)
        if (
            type(self.url) is not str
            or endpoint is None
            or "?" in self.url
            or "#" in self.url
            or parsed.scheme not in {"http", "https"}
            or len(self.url.encode("utf-8")) > 4096
            or type(self.addresses) is not tuple
            or not 1 <= len(self.addresses) <= 16
            or len(set(self.addresses)) != len(self.addresses)
            or type(self.allow_private) is not bool
            or type(self.allow_http) is not bool
            or (parsed.scheme == "http" and not self.allow_http)
            or type(self.max_response_bytes) is not int
            or not 1 <= self.max_response_bytes <= 65536
            or type(self.headers) is not tuple
            or len(self.headers) > 16
        ):
            raise ValueError("exact bounded operator-selected HTTP route required")
        for address in self.addresses:
            if type(address) is not str or "%" in address:
                raise ValueError("literal canonical destination IP required")
            ip = ipaddress.ip_address(address)
            if (
                str(ip) != address
                or ip.is_multicast
                or ip.is_unspecified
                or ip.is_link_local
                or (ip.is_reserved and not ip.is_loopback)
            ):
                raise ValueError("unsupported exact destination IP")
            if not self.allow_private and (not ip.is_global or ip.is_loopback or ip.is_link_local):
                raise ValueError("private HTTP destination needs explicit operator selection")
        try:
            literal = ipaddress.ip_address(endpoint[0])
        except ValueError:
            literal = None
        if literal is not None and self.addresses != (str(literal),):
            raise ValueError("literal HTTP host must equal its pinned destination")
        normalized = {}
        if any(type(pair) is not tuple or len(pair) != 2 for pair in self.headers):
            raise ValueError("literal owned HTTP header pairs required")
        for name, value in self.headers:
            if (
                type(name) is not str
                or HEADER.fullmatch(name) is None
                or name.lower() in normalized
                or name.lower() in UNSUPPORTED_HEADERS
                or name.lower() in {"x-api-key", "accept-encoding"}
                or name.lower().startswith("proxy-")
                or type(value) is not str
                or not value.isascii()
                or len(value) > 2048
                or value != value.strip()
                or any(ord(char) < 32 or ord(char) == 127 for char in value)
            ):
                raise ValueError("ambiguous or unsupported owned HTTP headers")
            normalized[name.lower()] = value
        if self.credential is None:
            if self.credential_binding is not None:
                raise ValueError("credential binding needs original private bytes")
        elif (
            type(self.credential) is not bytes
            or not 1 <= len(self.credential) <= 16384
            or type(self.credential_binding) is not CredentialBinding
            or (self.credential_binding.host, self.credential_binding.port) != endpoint[:2]
            or parsed.scheme != "https"
            or any(value < 33 or value > 126 for value in self.credential)
            or re.fullmatch(rb"[A-Za-z0-9._~+/-]+=*", self.credential) is None
        ):
            raise ValueError("private destination-bound HTTPS bearer credential required")
        if self.ca_file is not None:
            object.__setattr__(self, "ca_file", Path(self.ca_file).absolute())
        if self.credential is not None and self.credential in wire(
            [
                self.route_id,
                self.public_parameters(),
                self.credential_binding.as_dict() if self.credential_binding else None,
                str(self.ca_file) if self.ca_file else None,
            ]
        ):
            raise ValueError("private credential must not appear in public route material")

    def public_parameters(self):
        return {"url": self.url, "method": "GET", "headers": dict(self.headers)}


@dataclass
class _CredentialReview:
    source: HostEvidenceSource
    profile_digest: str
    action_digest: str
    receipts: tuple[HostCredentialUse, ...]
    digests: tuple[str, ...]
    used: bool = False


class LinuxOwnedToolsBackend(LinuxFileReadBackend):
    """Exact read and CAS write routes inside a new managed workspace.

    Write kernel policy confines the worker to its managed directory; the closed
    immutable worker validates the one exact flat destination and packet. Raw
    host access outside this route remains uncovered. No user workspace is chowned.
    """

    name = "linux-owned-tools-v1"

    @staticmethod
    def worker_identity() -> tuple[int, int]:
        if sys.platform != "linux" or os.name != "posix" or os.uname().machine != "x86_64":
            raise ValueError("owned tools require Linux x86-64")
        return (65534, 65534) if os.geteuid() == 0 else (os.geteuid(), os.getegid())

    def __init__(
        self,
        workspace: Path,
        allowed_files: tuple[str, ...],
        install_root: Path,
        *,
        operator: object,
        initialize: bool = False,
        tool_runtime: str = "ordin-owned",
        read_tool: str = "read_file",
        write_tool: str = "write_artifact",
        http_routes: tuple[OwnedHTTPRoute, ...] = (),
        max_payload_bytes: int = 65536,
        max_write_bytes: int = 65536,
        timeout_ms: int = 3000,
        memory_mib: int = 128,
        cpu_seconds: int = 2,
        max_outcomes: int = 4096,
    ):
        if (
            type(initialize) is not bool
            or type(max_write_bytes) is not int
            or not 1 <= max_write_bytes <= 65536
            or type(http_routes) is not tuple
            or len(http_routes) > 16
            or any(type(route) is not OwnedHTTPRoute for route in http_routes)
            or len({route.route_id for route in http_routes}) != len(http_routes)
        ):
            raise ValueError("protected finite managed-tool configuration required")
        if type(allowed_files) is not tuple:
            raise ValueError("literal managed file routes required")
        route_materials = [
            digest(
                {
                    **route.public_parameters(),
                    "headers": {key.lower(): value for key, value in route.headers},
                }
            )
            for route in http_routes
        ]
        if len(set(route_materials)) != len(route_materials):
            raise ValueError("owned HTTP routes must not alias the same public operation")
        identifier(write_tool, "owned write tool")
        if write_tool == read_tool:
            raise ValueError("owned read and write routes must differ")
        for name in allowed_files:
            if name.startswith(".ordin-stage-"):
                raise ValueError("managed staging namespace is reserved")
        self.write_tool, self.max_write_bytes, self.http_routes = (
            write_tool,
            max_write_bytes,
            http_routes,
        )
        self._initialize_owned = initialize
        self._managed_state: OwnedFileState | None = None
        self._closing = False
        self._write_plans: dict[str, tuple[EnforcementPlan, ActionEnvelope, dict]] = {}
        self._credential_key = secrets.token_bytes(32)
        self._credential_reviews: dict[str, _CredentialReview] = {}
        self._extra_shipped = {
            name: Path(__file__).with_name(name)
            for name in ("_owned_protocol.py", "_owned_isolation.py", "_write_worker.py")
        }
        self._extra_digests = {name: _sha(path) for name, path in self._extra_shipped.items()}
        self._backend_digest = _sha(Path(__file__))
        try:
            super().__init__(
                workspace,
                allowed_files,
                install_root,
                operator=operator,
                tool_runtime=tool_runtime,
                tool_name=read_tool,
                path_argument="path",
                max_payload_bytes=max_payload_bytes,
                timeout_ms=timeout_ms,
                memory_mib=memory_mib,
                cpu_seconds=cpu_seconds,
                max_outcomes=max_outcomes,
            )
        except BaseException:
            if self._managed_state is not None:
                self._managed_state.close()
            if getattr(self, "_fd", -1) >= 0:
                os.close(self._fd)
                self._fd = -1
            raise

    def _private_directory(self, path):
        if path == self.workspace:
            if path.resolve(strict=True) != path:
                raise ValueError("managed workspace must be canonical")
            info, parent = path.lstat(), path.parent.lstat()
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != self.uid
                or stat.S_IMODE(info.st_mode) != 0o700
                or not stat.S_ISDIR(parent.st_mode)
                or parent.st_uid != os.geteuid()
                or stat.S_IMODE(parent.st_mode) & 0o077
                or path.parent.resolve(strict=True) != path.parent
            ):
                raise ValueError("new worker-owned workspace requires a private operator parent")
        else:
            super()._private_directory(path)

    def _file_owner(self):
        return self.uid

    def _install(self):
        super()._install()
        for name, path in self._extra_shipped.items():
            descriptor = os.open(
                self.install_root / name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
            with os.fdopen(descriptor, "wb") as destination:
                destination.write(path.read_bytes())
                destination.flush()
                os.fsync(destination.fileno())
        binding = digest(
            [str(self.workspace), self._root_identity, self.uid, self.gid, self.allowed_files]
        )
        initial = {}
        for name in self.allowed_files:
            info = self._stat_file(name)
            content_hash = None
            if info is not None and self._initialize_owned:
                descriptor = os.open(
                    name,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                    dir_fd=self._fd,
                )
                try:
                    before = owned_file_identity(os.fstat(descriptor))
                    content = bytearray()
                    while len(content) <= self.max_payload_bytes:
                        chunk = os.read(
                            descriptor, min(4096, self.max_payload_bytes + 1 - len(content))
                        )
                        if not chunk:
                            break
                        content.extend(chunk)
                    if (
                        before != info
                        or owned_file_identity(os.fstat(descriptor)) != info
                        or len(content) > self.max_payload_bytes
                    ):
                        raise ValueError("initial managed data changed")
                    content_hash = hashlib.sha256(content).hexdigest()
                finally:
                    os.close(descriptor)
            initial[name] = {
                "version": 0 if info is None else 1,
                "content_digest": content_hash,
                "identity": info,
                "pending": None,
            }
        state_name = ".ordin-owned-" + digest(str(self.workspace))[:24] + ".sqlite3"
        self._managed_state = OwnedFileState(
            self.workspace.parent / state_name, binding, initial, initialize=self._initialize_owned
        )
        for name in self.allowed_files:
            self._record(name)

    def _verify_install(self):
        if self._closing:
            raise ValueError("owned executor is closing")
        super()._verify_install()
        if _sha(Path(__file__)) != self._backend_digest:
            raise ValueError("owned backend code changed")
        for name, shipped in self._extra_shipped.items():
            installed = self.install_root / name
            info = installed.lstat()
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1
                or _sha(shipped) != self._extra_digests[name]
                or _sha(installed) != self._extra_digests[name]
            ):
                raise ValueError("owned worker installation changed")

    @property
    def configuration_digest(self):
        routes = [
            [
                route.route_id,
                route.url,
                route.addresses,
                route.headers,
                route.max_response_bytes,
                str(route.ca_file) if route.ca_file else None,
                route.credential_binding.as_dict() if route.credential_binding else None,
                hmac.new(self._credential_key, route.credential, hashlib.sha256).hexdigest()
                if route.credential
                else None,
                route.allow_private,
                route.allow_http,
            ]
            for route in self.http_routes
        ]
        return digest(
            [
                super().configuration_digest,
                self.write_tool,
                self.max_write_bytes,
                self._extra_digests,
                self._backend_digest,
                routes,
            ]
        )

    def _stat_file(self, name):
        try:
            info = os.stat(name, dir_fd=self._fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != self.uid
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
            or info.st_size > self.max_payload_bytes
        ):
            raise ValueError("managed file must be private, regular and singly linked")
        return owned_file_identity(info)

    def _record(self, name):
        if not self._supported or self._managed_state is None:
            raise ValueError("owned managed state unavailable")
        row = self._managed_state.record(name)
        if self._stat_file(name) != row["identity"]:
            raise ValueError("managed file changed outside its original write route")
        return row

    def snapshot(self, path, *, operator):
        if operator is not self._operator:
            raise ValueError("original managed workspace operator required")
        name = self._name(path)
        with self._lock:
            self._verify_install()
            row = self._record(name)
            return {
                "version": row["version"],
                "content_digest": row["content_digest"],
                "bytes": 0 if row["identity"] is None else row["identity"]["size"],
            }

    def _name(self, path):
        if type(path) is not str or path not in {
            str(self.workspace / name) for name in self.allowed_files
        }:
            raise ValueError("only exact configured managed paths are supported")
        return Path(path).name

    def compile(self, contract):
        compiled = super().compile(contract)
        if not compiled.enforceable or compiled.plan is None:
            return compiled
        try:
            row = self._record(self._name(contract.filesystem[0].path))
            if row["identity"] is None:
                raise ValueError("managed read has no current bytes")
            policy = {
                **compiled.plan.policy,
                "managed_version": row["version"],
                "managed_digest": row["content_digest"],
                "managed_identity": digest(row["identity"]),
            }
            plan = replace(compiled.plan, policy=policy)
            return CompilationResult("success", self.name, "broker.owned_read_compiled", plan=plan)
        except (OSError, ValueError):
            return CompilationResult(
                "inconclusive",
                self.name,
                "broker.managed_history_unavailable",
                unsupported_fields=("managed.history",),
            )

    def validate_action_requirements(self, action, contract):
        if type(contract) is not RuntimeCapabilityContract or type(action) is not ActionEnvelope:
            raise ValueError("complete original owned-tool requirements required")
        if action.kind != "tool" or action.parameters.get("tool") != self.write_tool:
            return super().validate_action_requirements(action, contract)
        path, _, version, expected = _parse_write(
            action,
            contract,
            paths=tuple(str(self.workspace / name) for name in self.allowed_files),
            runtime=self.tool_runtime,
            tool=self.write_tool,
            maximum=self.max_write_bytes,
            uid=self.uid,
        )
        name = self._name(path)
        row = self._record(name)
        if (version, expected) != (row["version"], row["content_digest"]):
            raise ValueError("managed version or digest changed")
        return name

    def _http_route(self, action):
        if (
            type(action) is not ActionEnvelope
            or action.kind != "network"
            or action.operation != "http.request"
        ):
            raise ValueError("exact host-selected REST action required")
        parameters = action.parameters
        if set(parameters) - {"url", "method", "headers"} or not {"url", "method"} <= set(
            parameters
        ):
            raise ValueError("owned GET has no query, body or unrepresented fields")
        headers = parameters.get("headers", {})
        if not isinstance(headers, dict) or any(type(key) is not str for key in headers):
            raise ValueError("literal owned GET headers required")
        normalized = {key.lower(): value for key, value in headers.items()}
        if len(normalized) != len(headers):
            raise ValueError("duplicate owned GET header")
        candidates = [
            route
            for route in self.http_routes
            if parameters["url"] == route.url
            and parameters["method"] == "GET"
            and normalized == {key.lower(): value for key, value in route.headers}
        ]
        if len(candidates) != 1:
            raise ValueError("owned GET differs from its configured exact route")
        return candidates[0]

    @staticmethod
    def _credential_review_key(source, profile, action):
        return digest([source.key, profile.digest, digest(action.as_dict())])

    def _verify_review(self, row, source, profile, action, supplied):
        if (
            row.source is not source
            or row.profile_digest != profile.digest
            or row.action_digest != digest(action.as_dict())
            or type(supplied) is not tuple
            or len(supplied) != len(row.receipts)
            or any(actual is not expected for actual, expected in zip(supplied, row.receipts))
        ):
            raise ValueError("original exact credential routing proof required")
        source._check_profile(profile)
        for receipt, expected in zip(row.receipts, row.digests):
            receipt.__post_init__()
            if receipt.digest != expected:
                raise ValueError("credential routing proof changed")

    def credential_uses(self, source, action, profile):
        if type(source) is not HostEvidenceSource:
            raise ValueError("original protected host source required")
        if action.kind != "network":
            return ()
        route = self._http_route(action)
        if route.credential is None:
            return ()
        if route.credential in wire(action.as_dict()):
            raise ValueError("credential must remain outside the action")
        key = self._credential_review_key(source, profile, action)
        with self._lock:
            previous = self._credential_reviews.get(key)
            if previous is not None:
                self._verify_review(previous, source, profile, action, previous.receipts)
                if previous.used:
                    raise ValueError("credential action was already consumed; no proof reissuance")
                return previous.receipts
            if len(self._credential_reviews) >= self._limit:
                raise ValueError("credential review history capacity reached")
            receipt = source.record_credential_use(
                action,
                profile,
                receipt_id="owned-credential-" + uuid4().hex,
                binding=route.credential_binding,
            )
            row = _CredentialReview(
                source, profile.digest, digest(action.as_dict()), (receipt,), (receipt.digest,)
            )
            self._credential_reviews[key] = row
            return row.receipts

    def verify_credential_uses(self, source, action, profile, supplied):
        if type(source) is not HostEvidenceSource or type(supplied) is not tuple:
            return False
        try:
            if action.kind != "network" or self._http_route(action).credential is None:
                return supplied == ()
            with self._lock:
                row = self._credential_reviews.get(
                    self._credential_review_key(source, profile, action)
                )
                if row is None:
                    return False
                self._verify_review(row, source, profile, action, supplied)
                return True
        except (ValueError, TypeError, UnicodeError):
            return False

    def compile_action(self, action, complete, *, source=None, credential_uses=()):
        if type(complete) is not RuntimeCapabilityContract:
            return CompilationResult(
                "unsupported",
                self.name,
                "broker.request_worker_unavailable",
                unsupported_fields=("requests.complete",),
            )
        if action.kind != "tool" or action.parameters.get("tool") != self.write_tool:
            return self.compile(complete)
        try:
            if not self._supported or complete.grant_state != "eligible":
                raise ValueError("current approved Linux managed-write requirements required")
            self._verify_install()
            name = self.validate_action_requirements(action, complete)
            row = self._record(name)
            captured = ActionEnvelope.from_dict(action.as_dict())
            content = captured.parameters["arguments"]["content"].encode("utf-8")
            policy = {
                "profile": WRITE_PROTOCOL,
                "configuration_digest": self.configuration_digest,
                "target_digest": digest(str(self.workspace / name)),
                "expected_version": row["version"],
                "expected_digest": row["content_digest"],
                "expected_identity": digest(row["identity"]),
                "content_digest": hashlib.sha256(content).hexdigest(),
                "write_bytes": self.max_write_bytes,
                "filter_digest": filter_digest("write"),
                "filesystem_scope": "managed_directory",
                "startup": "fresh_worker_only",
                "network": "deny",
                "processes": "deny",
                "exec": "deny",
            }
            plan = EnforcementPlan(self.name, complete, policy)
            with self._lock:
                if len(self._write_plans) >= self._limit and plan.plan_id not in self._write_plans:
                    raise ValueError("owned write plan capacity reached")
                previous = self._write_plans.get(plan.plan_id)
                if previous is not None:
                    # Budget/use-time rechecks must retain the one original
                    # plan, not invalidate another pending authorization.
                    plan = previous[0]
                else:
                    self._write_plans[plan.plan_id] = (plan, captured, row)
            return CompilationResult("success", self.name, "broker.owned_write_compiled", plan=plan)
        except (OSError, ValueError, UnicodeError):
            return CompilationResult(
                "unsupported",
                self.name,
                "broker.managed_write_unrepresentable",
                unsupported_fields=("managed.exact_write",),
            )

    def validate(self, plan):
        if type(plan) is not EnforcementPlan or plan.backend != self.name:
            raise ValueError("original owned-tool plan required")
        if plan.policy.get("profile") != WRITE_PROTOCOL:
            return super().validate(plan)
        try:
            original = self._write_plans.get(plan.plan_id)
            valid = (
                original is not None
                and original[0] is plan
                and plan.policy["configuration_digest"] == self.configuration_digest
                and self.validate_action_requirements(original[1], plan.contract)
                in self.allowed_files
                and self._record(self._name(original[1].parameters["arguments"]["path"]))
                == original[2]
            )
            self._verify_install()
        except (OSError, ValueError, KeyError, UnicodeError):
            valid = False
        return BackendValidationResult(
            "success" if valid else "invalid",
            self.name,
            plan.policy_digest,
            "broker.owned_plan_valid" if valid else "broker.owned_plan_changed",
        )

    def _run_owned(self, worker, packet, resource, job_state):
        control = output = None
        reader = writer = pidfd = None
        process = None
        try:
            data = wire(packet)
            if len(data) > 131072:
                raise ValueError("owned control frame bound exceeded")
            control = tempfile.TemporaryFile(mode="w+b")
            control.write(data)
            control.flush()
            reader = os.open("/proc/self/fd/" + str(control.fileno()), os.O_RDONLY | os.O_CLOEXEC)
            output = tempfile.TemporaryFile(mode="w+b")
            writer = os.open("/proc/self/fd/" + str(output.fileno()), os.O_WRONLY | os.O_CLOEXEC)
            if job_state.cancel.is_set():
                raise ValueError("owned job canceled before launch")
            if job_state.cancel.is_set():
                raise ValueError("owned worker canceled before process start")
            process = subprocess.Popen(
                [str(self._executable), "-I", "-S", "-B", "-u", str(worker)],
                cwd=self.cwd,
                env={},
                stdin=reader,
                stdout=writer,
                stderr=subprocess.STDOUT,
                close_fds=True,
                pass_fds=(resource,),
                start_new_session=True,
            )
            if hasattr(os, "pidfd_open"):
                try:
                    pidfd = os.pidfd_open(process.pid)
                except OSError:
                    pass
            with self._jobs_lock:
                job_state.process, job_state.pidfd, job_state.state = process, pidfd, "running"
            deadline = time.monotonic() + self.timeout_ms / 1000
            while process.poll() is None:
                if job_state.cancel.is_set() or time.monotonic() >= deadline:
                    if not self._terminate(process, pidfd):
                        job_state.state = "unable_to_stop"
                    raise ValueError("owned worker stopped or timed out; outcome may be uncertain")
                time.sleep(0.005)
            size = os.fstat(output.fileno()).st_size
            if size > self.max_stdout_bytes:
                raise ValueError("owned output frame exceeded its bound")
            output.seek(0)
            frame = output.read(self.max_stdout_bytes + 1)
            if process.returncode != 0:
                raise ValueError("owned kernel controls or effect unavailable")
            return json.loads(frame), len(frame)
        finally:
            if process is not None and process.poll() is None:
                if not self._terminate(process, pidfd):
                    job_state.state = "unable_to_stop"
            if pidfd is not None and process is not None and process.poll() is not None:
                os.close(pidfd)
                job_state.pidfd = None
            for descriptor in (reader, writer):
                if descriptor is not None:
                    os.close(descriptor)
            for handle in (control, output):
                if handle is not None:
                    handle.close()

    def _check_owned_receipt(self, response, packet, mode):
        if type(response) is not dict or any(
            response.get(key) != packet[key]
            for key in (
                "protocol",
                "request_digest",
                "nonce",
                "action_digest",
                "contract_digest",
                "policy_digest",
            )
        ):
            raise ValueError("owned response binding differs")
        isolation = response.get("isolation")
        expected_checks = {
            "outside_path_read_denied",
            "outside_path_write_denied",
            "file_size_ceiling_enforced",
            "new_socket_denied",
            "process_creation_denied",
            "executable_launch_denied",
            "memory_ceiling_enforced",
        }
        expected_limits = {
            "memory_bytes": [self.memory_mib * 1048576] * 2,
            "cpu_seconds": [self.cpu_seconds] * 2,
            "processes": [1, 1],
            "descriptors": [6 if mode == "write" else 4] * 2,
            "file_bytes": [packet["file_size_bound"]] * 2,
            "core_bytes": [0, 0],
        }
        if (
            type(isolation) is not dict
            or isolation.get("landlock_abi", 0) < 1
            or isolation.get("seccomp_mode") != 2
            or isolation.get("no_new_privileges") != 1
            or isolation.get("filter_digest") != filter_digest(mode)
            or isolation.get("uid") != self.uid
            or isolation.get("gid") != self.gid
            or isolation.get("environment_empty") is not True
            or isolation.get("checks") != dict.fromkeys(expected_checks, True)
            or isolation.get("limits") != expected_limits
            or isolation.get("filesystem_scope")
            != ("managed_directory" if mode == "write" else "no_new_paths")
            or isolation.get("network_scope")
            != ("denied" if mode == "write" else "one_preconnected_destination")
            or isolation.get("process_creation") != "denied"
            or isolation.get("executable_launch") != "denied"
        ):
            raise ValueError("owned kernel receipt incomplete")
        return isolation

    def create_job(self, plan: EnforcementPlan, *, operator: object) -> KernelJob:
        with self._jobs_lock:
            if self._closing:
                raise ValueError("owned executor is closing")
            return super().create_job(plan, operator=operator)

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
        outcome = super()._result(
            plan,
            status,
            reason,
            physical=physical,
            evidence=evidence,
            stdout_bytes=stdout_bytes,
            value=value,
            observation=observation,
            job=job,
        )
        self._retain_live_job_state(job)
        return outcome

    def _retain_live_job_state(self, job):
        if job is None:
            return
        with self._jobs_lock:
            row = self._job(job)
            if row.process is not None:
                try:
                    live = row.process.poll() is None
                except OSError:
                    live = True
                if live:
                    row.state = "unable_to_stop"

    def _stop_retained_owned_job(self, job, *, operator):
        """Retry only the original child; cleanup cannot resolve past effects."""
        if operator is not self._operator:
            raise ValueError("original owned operator required")
        with self._jobs_lock:
            row = self._job(job)
            row.cancel.set()
            process, pidfd = row.process, row.pidfd
            if process is None:
                if row.outcome is not None and row.outcome.status == "unknown":
                    return "unknown"
                return super().request_stop(job, operator=operator)
        pinned_pidfd = None
        try:
            # Producers close this fd only AFTER this same Popen is terminal.
            # A duplicate pins a still-live original; if close/reuse happened
            # first, _terminate's initial poll sees terminal Popen and sends no
            # signal through the possibly recycled duplicate.
            pinned_pidfd = os.dup(pidfd) if pidfd is not None else None
            stopped = self._terminate(process, pinned_pidfd)
        except OSError:
            try:
                stopped = process.poll() is not None
            except OSError:
                stopped = False
        finally:
            if pinned_pidfd is not None:
                os.close(pinned_pidfd)
        with self._jobs_lock:
            if not stopped:
                row.state = "unable_to_stop"
                return "unable_to_stop"
            if row.outcome is None or row.outcome.status == "canceled":
                row.state = "canceled"
                return "canceled"
            row.state = "finished"
            return "completed" if row.outcome.status in {"completed", "denied"} else "unknown"

    def request_stop(self, job: KernelJob, *, operator: object) -> str:
        return self._stop_retained_owned_job(job, operator=operator)

    def execute(self, plan, action, source, *, operator, job=None):
        if self._closing:
            raise ValueError("owned executor is closing")
        if plan.policy.get("profile") != WRITE_PROTOCOL:
            result = super().execute(plan, action, source, operator=operator, job=job)
            if result.status == "completed":
                try:
                    row = self._record(self._name(action.parameters["arguments"]["path"]))
                    if result.payload_digest != row["content_digest"]:
                        raise ValueError("managed read digest changed")
                except (OSError, ValueError):
                    return self._result(plan, "unknown", "broker.managed_read_changed", job=job)
            return result
        if operator is not self._operator or type(source) is not RuntimeEvidenceSource:
            raise ValueError("original owned executor operator required")
        self._require_approval_job(plan, job)
        with self._lock:
            if len(self._outcomes) >= self._limit:
                raise ValueError("executor outcome capacity reached")
            job = self.create_job(plan, operator=operator) if job is None else job
            with self._jobs_lock:
                state = self._job(job)
                if (
                    state.binding
                    != (plan.plan_id, plan.contract.action_digest, plan.contract.digest)
                    or state.state != "queued"
                ):
                    raise ValueError("owned write job consumed or changed")
                if state.cancel.is_set():
                    return self._result(
                        plan, "canceled", "broker.owned_canceled_before_start", job=job
                    )
                state.state = "checking"
            try:
                if not self.validate(plan).ok:
                    raise ValueError("owned write plan changed")
                name = self.validate_action_requirements(action, plan.contract)
                original = self._write_plans[plan.plan_id]
                row = original[2]
                raw = action.parameters["arguments"]["content"].encode("utf-8")
                nonce = secrets.token_hex(32)
                workspace_identity, state_store = self._root_identity, self._managed_state
                if workspace_identity is None or state_store is None:
                    raise ValueError("original managed workspace state unavailable")
                packet = {
                    "protocol": WRITE_PROTOCOL,
                    "nonce": nonce,
                    "action_digest": plan.contract.action_digest,
                    "contract_digest": plan.contract.digest,
                    "policy_digest": plan.policy_digest,
                    "resource_descriptor": self._fd,
                    "workspace_identity": list(workspace_identity),
                    "uid": self.uid,
                    "gid": self.gid,
                    "memory_bytes": self.memory_mib * 1048576,
                    "cpu_seconds": self.cpu_seconds,
                    "file_size_bound": max(8192, self.max_write_bytes),
                    "filter_digest": filter_digest("write"),
                    "name": name,
                    "content": base64.b64encode(raw).decode(),
                    "content_digest": hashlib.sha256(raw).hexdigest(),
                    "max_write_bytes": self.max_write_bytes,
                    "expected_identity": row["identity"],
                    "expected_digest": row["content_digest"],
                    "next_version": counter(row["version"] + 1, "managed version"),
                }
                packet["request_digest"] = hashlib.sha256(wire(packet)).hexdigest()
                self._require_approval_job(plan, job)
                state_store.begin(
                    name,
                    row,
                    nonce=nonce,
                    action_digest=plan.contract.action_digest,
                    content_digest=packet["content_digest"],
                )
                response, frame_size = self._run_owned(
                    self.install_root / "_write_worker.py", packet, self._fd, state
                )
                if set(response) != {
                    "protocol",
                    "request_digest",
                    "nonce",
                    "action_digest",
                    "contract_digest",
                    "policy_digest",
                    "status",
                    "identity",
                    "content_digest",
                    "version",
                    "isolation",
                }:
                    raise ValueError("owned write receipt shape changed")
                evidence = self._check_owned_receipt(response, packet, "write")
                actual = self._stat_file(name)
                if (
                    response["status"] != "completed"
                    or actual is None
                    or actual != response["identity"]
                    or response["content_digest"] != packet["content_digest"]
                    or response["version"] != packet["next_version"]
                ):
                    raise ValueError("owned write actual result differs")
                current = state_store.finish(
                    name,
                    nonce,
                    identity=actual,
                    content_digest=packet["content_digest"],
                    completed=True,
                )
                value = wire(
                    {
                        "version": current["version"],
                        "content_digest": current["content_digest"],
                        "bytes": actual["size"],
                    }
                )
                observation = source.observe(
                    plan.contract,
                    observation_id="owned-write-" + nonce,
                    trust="backend_observed",
                    enforcement_point="filesystem",
                    outcome="completed",
                    operation="filesystem.write",
                    effects=("filesystem.write",),
                    resources=(ObservedResource("path", str(self.workspace / name)),),
                    reason_code="broker.managed_write_completed",
                    metadata={
                        "event_digest": digest([evidence, nonce, plan.policy_digest]),
                        "request_id_digest": nonce,
                        "source_schema_version": WRITE_PROTOCOL,
                    },
                )
                return self._result(
                    plan,
                    "completed",
                    "broker.managed_write_completed",
                    physical=True,
                    evidence=evidence,
                    stdout_bytes=frame_size,
                    value=value,
                    observation=observation,
                    job=job,
                )
            except (OSError, ValueError, KeyError, TypeError, UnicodeError):
                return self._result(plan, "unknown", "broker.managed_write_uncertain", job=job)

    def permissions_fit(self, permissions):
        maximum = permissions.capability
        paths = {str(self.workspace / name) for name in self.allowed_files}
        return (
            not maximum.network
            and not maximum.credentials
            and not permissions.requests
            and not permissions.network_grants
            and not permissions.rest_requests
            and not maximum.allow_any_executable
            and maximum.process.execution is False
            and not maximum.process.executables
            and maximum.process.spawn_children in {None, False}
            and maximum.privilege.escalation is False
            and maximum.privilege.required_euid in {None, self.uid}
            and all(
                value.access in {"read", "write"} and value.scope == "exact" and value.path in paths
                for value in maximum.filesystem
            )
            and all(
                value.runtime == self.tool_runtime
                and value.server is None
                and value.tool in {self.tool_name, self.write_tool}
                and value.operation == "call"
                for value in maximum.tools
            )
        )

    def factory_probe(self, root, *, operator, policy_digest):
        """Operator-owned scratch self-test, never an approval of a workload action."""
        if operator is not self._operator:
            raise ValueError("original owned factory operator required")
        workspace, install = root / "workspace", root / "install"
        workspace.mkdir(mode=0o700)
        install.mkdir(mode=0o700)
        uid, gid = self.worker_identity()
        if os.geteuid() == 0:
            os.chown(workspace, uid, gid)
        probe = LinuxOwnedToolsBackend(
            workspace,
            ("probe.txt",),
            install,
            operator=operator,
            initialize=True,
            tool_runtime=self.tool_runtime,
            read_tool=self.tool_name,
            write_tool=self.write_tool,
            max_payload_bytes=self.max_payload_bytes,
            max_write_bytes=self.max_write_bytes,
            timeout_ms=self.timeout_ms,
            memory_mib=self.memory_mib,
            cpu_seconds=self.cpu_seconds,
        )
        try:
            target = str(workspace / "probe.txt")
            text = "owned-factory-write\n"
            if len(text.encode()) > self.max_write_bytes:
                text = "x" * self.max_write_bytes
            action = ToolCallAdapter(self.tool_runtime).adapt(
                self.write_tool,
                {"path": target, "content": text, "expected_version": 0, "expected_digest": None},
                action_id="factory-" + uuid4().hex,
            )
            # This is the explicit protected owner's fresh temporary self-test,
            # not a core review result, model approval, or a user-data permit.
            contract = RuntimeCapabilityContract(
                action.action_id,
                digest(action.as_dict()),
                "allow",
                "low",
                filesystem=(FilesystemCapability("write", target, "exact"),),
                tools=(ToolCapability(self.tool_runtime, None, self.write_tool),),
                process=ProcessCapability(execution=False, spawn_children=False),
                privilege=PrivilegeCapability(escalation=False),
                source={
                    "kind": "tool",
                    "adapter": "owned_factory_probe",
                    "operation": "call",
                    "effects": ["filesystem.write"],
                    "provenance_digest": None,
                },
            )
            compiled = probe.compile_action(action, contract)
            if not compiled.enforceable or compiled.plan is None:
                raise ValueError("owned write factory cannot compile its scratch probe")
            source = probe.evidence_source(
                session_digest=digest([self._nonce, policy_digest]),
                policy_digest=compiled.plan.policy_digest,
                context_digest=digest(self._nonce),
            )
            outcome = probe.execute(compiled.plan, action, source, operator=operator)
            if (
                outcome.status != "completed"
                or not outcome.physical_enforcement
                or not probe.verify_outcome(outcome, compiled.plan)
            ):
                raise ValueError("owned write factory probe did not complete")
            evidence = probe.evidence_record(outcome, operator=operator)
            description = {
                "scope": "broker_owned_fresh_managed_worker_route",
                "capabilities": ["broker.enforce"],
                "factory": True,
                "requires_action_admission": True,
                "physical_policy_applied": False,
                "supported_action_kinds": ["tool"],
                "operations": ["call"],
                "effects": ["filesystem.read", "filesystem.write"],
                "tool_runtime": self.tool_runtime,
                "tool_name": self.tool_name,
                "write_tool": self.write_tool,
                "path_argument": self.path_argument,
                "files": [str(self.workspace / name) for name in self.allowed_files],
                "filesystem_scope": "managed_directory_kernel_boundary_with_exact_software_target",
                "requires_warning_approval": True,
                "limits": {
                    "uid": self.uid,
                    "gid": self.gid,
                    "memory_bytes": self.memory_mib * 1048576,
                    "cpu_seconds": self.cpu_seconds,
                    "processes": 1,
                    "payload_bytes": self.max_payload_bytes,
                    "write_bytes": self.max_write_bytes,
                    "combined_output_frame_bytes": self.max_stdout_bytes,
                },
                "evidence_digest": digest(evidence),
                "execution_authority": False,
            }
            return probe, outcome, compiled.plan, evidence, description
        except BaseException:
            probe.close()
            raise

    def close(self):
        # Fence admission before waiting on an active forwarding thread. Stop
        # again after acquiring the execution lock to cover child publication
        # between the first snapshot and the forwarding thread observing cancel.
        with self._jobs_lock:
            self._closing = True
            jobs = tuple(self._jobs)
        self._close_stop_jobs(jobs)
        with self._lock:
            with self._jobs_lock:
                jobs = tuple(self._jobs)
            self._close_stop_jobs(jobs)
            if self._managed_state is not None:
                self._managed_state.close()
                self._managed_state = None
            super().close()

    def _close_stop_jobs(self, jobs):
        unable = False
        for job in jobs:
            try:
                unable = (
                    self.request_stop(job, operator=self._operator) == "unable_to_stop" or unable
                )
            except (OSError, ValueError, RuntimeError):
                unable = True
        if unable:
            # Keep original process/pidfd and parent storage custody for retry.
            raise RuntimeError("owned worker cleanup remains uncertain; close must be retried")
