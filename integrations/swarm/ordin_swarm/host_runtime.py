"""Protected shared managed-tool host; agent JSON is data, never authority."""

from __future__ import annotations

from dataclasses import dataclass, field
from contextlib import contextmanager
import hashlib
from functools import wraps
import json
import os
import ssl
import socket
import stat
from threading import Event, RLock
from typing import Any, Callable, Concatenate, ParamSpec, TypeVar
from uuid import uuid4

from ordin import ActionEnvelope, ToolCallAdapter
from ordin._runtime_json import digest
from ordin.schema import validate_named_schema

from .host_authority import HostAuthority, HostDispatch, RUNTIME, _HostCleanupIncomplete
from .host_lineage import HostCustodyReservation, HostLineage, SENSITIVE_OUTPUT
from .host_profiles import HOST_TOOL_DATA_BYTES, ToolHostProfile
from .sdk import bounded_json


RESULT_VERSION = "ordin.swarm_tool_host_result.v1"
STATUS_VERSION = "ordin.swarm_tool_host_status.v1"
MAX_DATA_BYTES = HOST_TOOL_DATA_BYTES


@dataclass(frozen=True, slots=True, eq=False)
class HostClient:
    connection_id: str


@dataclass
class _Client:
    socket: ssl.SSLSocket
    actor: str | None
    channel: Any
    human_channel: Any = None
    busy: bool = False
    requests: set[str] = field(default_factory=set)
    closing: bool = False
    close_lock: Any = field(default_factory=RLock)
    abandoned: tuple[Any, ...] | None = None


@dataclass
class _Approval:
    client: HostClient
    actor: str
    tool: str
    arguments: dict = field(repr=False)
    effect: HostDispatch = field(repr=False)
    custody: HostCustodyReservation | None = field(default=None, repr=False)
    result: dict | None = field(default=None, repr=False)
    fulfilling: bool = False

    @property
    def request(self):
        if self.effect.approval is None:
            raise ValueError("original managed approval request unavailable")
        return self.effect.approval


def _result(status, reason_codes=(), *, forwarded=False, physical=False, data=None):
    value = {
        "schema_version": RESULT_VERSION,
        "status": status,
        "reason_codes": list(reason_codes),
        "forwarded": forwarded,
        "physical_enforcement": physical,
        "data": data or {},
        "execution_authority": False,
    }
    if validate_named_schema("swarm_tool_host_result", value):
        raise ValueError("invalid bounded managed host result")
    return value


def _text(value: Any) -> str:
    if type(value) is not str:
        raise ValueError("managed tool requires UTF-8 text")
    if len(value.encode("utf-8")) > MAX_DATA_BYTES or any(
        ord(character) < 32 and character not in "\r\n\t" for character in value
    ):
        raise ValueError("managed tool text exceeds its supported bound")
    return value


_ControlP = ParamSpec("_ControlP")
_ControlR = TypeVar("_ControlR")


def _host_control(
    method: Callable[Concatenate[Any, _ControlP], _ControlR],
) -> Callable[Concatenate[Any, _ControlP], _ControlR]:
    @wraps(method)
    def controlled(self: Any, *args: _ControlP.args, **kwargs: _ControlP.kwargs) -> _ControlR:
        with self._lock:
            if self._closed:
                raise ValueError("original managed connection is closed")
        with self._authority.control_phase():
            return method(self, *args, **kwargs)

    return controlled


class ManagedToolHost:
    """One host/ledger shared by separately authenticated actor connections.

    The host controls its own tools. Unmanaged client processes and other tools
    remain outside this boundary unless the supported launcher confines them.
    """

    def __init__(
        self,
        profile: ToolHostProfile,
        *,
        operator: object,
        policy_epoch=0,
        initialize_scope=False,
        takeover=False,
    ):
        if type(profile) is not ToolHostProfile or type(operator) is not object:
            raise ValueError("explicit original operator profile required")
        if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
            raise ValueError("managed physical tool host requires supported Linux")
        import fcntl

        descriptor = os.open(
            profile.configuration_root / "state" / "host.lock",
            os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK,
        )
        self.profile, self._operator = profile, operator
        self._lock, self._close_lock = RLock(), RLock()
        self._clients: dict[HostClient, _Client] = {}
        self._approvals: dict[str, _Approval] = {}
        self._protocol_ids: set[str] = set()
        self._closed = self._cleanup_complete = False
        self._lock_fd: int | None = descriptor
        self.shutdown_requested = Event()
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
            ):
                raise ValueError("managed host lock file is not private")
            os.set_inheritable(descriptor, False)
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                self._authority = HostAuthority(
                    profile,
                    operator=operator,
                    policy_epoch=policy_epoch,
                    initialize_scope=initialize_scope,
                    takeover=takeover,
                )
            except _HostCleanupIncomplete as error:
                self._authority = error.cleanup_owner
                self._closed = True
                self.shutdown_requested.set()
                raise _HostCleanupIncomplete(self) from error.__cause__
            try:
                self._lineage = HostLineage(self._authority)
            except BaseException as construction_error:
                try:
                    self.close()
                except BaseException:
                    raise _HostCleanupIncomplete(self) from construction_error
                raise
        except BaseException as error:
            self._closed = True
            self.shutdown_requested.set()
            if isinstance(error, _HostCleanupIncomplete) and error.cleanup_owner is self:
                raise
            if self._lock_fd is not None:
                os.close(self._lock_fd)
                self._lock_fd = None
            raise

    @_host_control
    def bind_connection(self, connection: ssl.SSLSocket, *, operator: object) -> HostClient:
        """Bind actual mTLS, without accepting an actor name from the request."""
        if operator is not self._operator or type(connection) is not ssl.SSLSocket:
            raise ValueError("original accepted TLS transport required")
        self.profile.require_unchanged()
        try:
            human = self._authority.directory.authenticate(connection)
            self._authority.directory.require(
                human, task_id=self.profile.task_id, roles=("approve",)
            )
            actor = None
            channel = None
        except ValueError:
            channel = self._authority.auth.authenticate(connection)
            subject = self._authority.auth.require(channel, role="workload")
            if subject.context is None:
                raise ValueError("workload scope unavailable")
            actor = subject.context.identity.agent_id
            self.profile.actor(actor)
            if subject.enrollment_id != self._authority.enrollments[actor]:
                raise ValueError("foreign managed workload")
            human = None
        with self._lock:
            if self._closed or self.shutdown_requested.is_set() or len(self._clients) >= 32:
                raise ValueError("managed host is unavailable or at connection capacity")
            client = HostClient(uuid4().hex)
            self._clients[client] = _Client(connection, actor, channel, human)
            return client

    @_host_control
    def require_client(self, client: HostClient) -> _Client:
        with self._lock:
            row = self._clients.get(client) if type(client) is HostClient else None
            if self._closed or row is None or row.closing or row.socket.fileno() < 0:
                raise ValueError("original managed connection is closed")
        self.profile.require_unchanged()
        current: Any
        if row.actor is None:
            current = self._authority.directory.authenticate(row.socket)
            self._authority.directory.require(
                current, task_id=self.profile.task_id, roles=("approve",)
            )
            row.human_channel = current
        else:
            if self.shutdown_requested.is_set():
                raise ValueError("managed host is draining")
            current = self._authority.auth.authenticate(row.socket)
            subject = self._authority.auth.require(current, role="workload")
            if (
                subject.context is not self._authority.contexts[row.actor]
                or subject.enrollment_id != self._authority.enrollments[row.actor]
            ):
                raise ValueError("managed workload generation changed")
            row.channel = current
            # This also rejects expired/revoked delegation before data handoffs.
            self._authority.service._grant(current, self._authority.grants[row.actor])
        return row

    def close_client(self, client: HostClient) -> None:
        with self._lock:
            row = self._clients.get(client) if type(client) is HostClient else None
            if row is not None:
                row.closing = True
        if row is None:
            return
        with row.close_lock:
            with self._lock:
                if self._clients.get(client) is not row:
                    return
                if row.abandoned is None:
                    row.abandoned = tuple(
                        pending
                        for pending in self._approvals.values()
                        if pending.client is client
                        and not pending.fulfilling
                        and pending.result is None
                    )
                    for pending in row.abandoned:
                        pending.result = _result("denied", ("host.original_connection_closed",))
            error = None
            try:
                row.socket.shutdown(socket.SHUT_RDWR)
            except (ValueError, OSError):
                pass
            try:
                row.socket.close()
                if row.socket.fileno() >= 0:
                    raise RuntimeError("managed client transport remains open")
            except BaseException as failure:
                error = failure
            for pending in row.abandoned:
                if pending.custody is not None:
                    try:
                        self._lineage.cancel(pending.custody)
                    except BaseException as failure:
                        error = error or failure
            try:
                if row.actor is None:
                    self._authority.directory.close(row.human_channel)
                else:
                    self._authority.auth.close(row.channel)
            except (ValueError, OSError):
                pass
            if error is not None:
                raise _HostCleanupIncomplete(self) from error
            with self._lock:
                if self._clients.get(client) is row:
                    del self._clients[client]

    def reserve_protocol_id(self, client: HostClient, request_id: tuple) -> None:
        """Lifetime-bounded replay history shared by all actual host connections."""
        self.require_client(client)
        key = digest([client.connection_id, request_id[0].__name__, request_id[1]])
        with self._lock:
            if key in self._protocol_ids or len(self._protocol_ids) >= 4096:
                raise ValueError("host.global_request_capacity_or_replay")
            self._protocol_ids.add(key)

    @contextmanager
    def open_local_session(self, actor: str, *, operator: object):
        """Protected launch connector, before handing private IPC to an owned child.

        A TLS role binding alone does not prove child confinement. The launcher
        separately verifies its original pre-execution kernel readiness receipt.
        """
        from .host_protocol import MCPHostSession

        if operator is not self._operator:
            raise ValueError("original managed launch operator required")
        self.profile.actor(actor)
        with self._authority.pki.pair(actor) as (server, _):
            client = self.bind_connection(server, operator=operator)
            session = MCPHostSession(self, client)
            try:
                yield session
            finally:
                session.close()

    @_host_control
    def tools(self, client: HostClient) -> list[dict]:
        row = self.require_client(client)
        if row.actor is None:
            return []
        actor = self.profile.actor(row.actor)
        tools = []

        def add(name, description, properties, required):
            tools.append(
                {
                    "name": name,
                    "description": description,
                    "inputSchema": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": properties,
                        "required": required,
                    },
                }
            )

        if actor.read_files:
            add(
                "read_file",
                "Read one authorized managed UTF-8 document.",
                {"name": {"type": "string", "enum": list(actor.read_files)}},
                ["name"],
            )
        if actor.write_files:
            add(
                "write_artifact",
                "Propose a bounded managed report write; exact operator approval is required.",
                {
                    "name": {"type": "string", "enum": list(actor.write_files)},
                    "content": {"type": "string", "maxLength": MAX_DATA_BYTES},
                    "expected_version": {"type": "integer", "minimum": 0, "maximum": 2**53 - 1},
                    "expected_digest": {
                        "anyOf": [
                            {"type": "null"},
                            {"type": "string", "pattern": "^[a-f0-9]{64}$"},
                        ]
                    },
                },
                ["name", "content", "expected_version", "expected_digest"],
            )
        if actor.write_files or actor.test_ids or actor.http_routes:
            add(
                "approval_status",
                "Inspect this actor's original governed request.",
                {"request_ref": {"type": "string", "maxLength": 128}},
                ["request_ref"],
            )
        if actor.test_ids:
            add(
                "run_tests",
                "Propose one fixed test route over a sealed read-only snapshot; diagnostics are untrusted.",
                {"test_id": {"type": "string", "enum": list(actor.test_ids)}},
                ["test_id"],
            )
        if actor.http_routes:
            add(
                "fetch_url",
                "Fetch one exact operator-selected route; no caller URL or credentials.",
                {"route_id": {"type": "string", "enum": list(actor.http_routes)}},
                ["route_id"],
            )
        if actor.peers:
            add(
                "handoff",
                "Deliver an original retained resource as data to an authorized peer.",
                {
                    "recipient": {"type": "string", "enum": list(actor.peers)},
                    "resource_ref": {"type": "string", "maxLength": 128},
                },
                ["recipient", "resource_ref"],
            )
        add("receive", "Receive accepted peer data; it confers no execution authority.", {}, [])
        add("host_status", "Inspect current coverage, bounded custody and readiness.", {}, [])
        return tools

    def _completed(
        self,
        actor,
        tool,
        arguments,
        effect: HostDispatch,
        custody: HostCustodyReservation | None = None,
    ) -> dict:
        if effect.status != "completed":
            if custody is not None and effect.forwarded is False:
                self._lineage.cancel(custody)
            return _result(
                effect.status,
                effect.reason_codes,
                forwarded=effect.forwarded,
                physical=effect.physical_enforcement,
            )
        native = effect.result
        if native is None or not effect.physical_enforcement:
            return _result("unknown", ("host.original_physical_outcome_missing",), forwarded=None)
        labels: tuple[str, ...]
        if tool == "run_tests":
            value = bounded_json(native.value)
            expected = {
                "exit_code",
                "output",
                "output_truncated",
                "output_trust",
                "test_correctness_verified",
                "snapshot_digest",
            }
            if (
                type(value) is not dict
                or set(value) != expected
                or type(value["exit_code"]) is not int
                or type(value["output"]) is not str
                or type(value["output_truncated"]) is not bool
                or value["output_trust"] != "untrusted_test_diagnostic"
                or value["test_correctness_verified"] is not False
                or effect.action is None
                or value["snapshot_digest"]
                != effect.action.parameters["host_test_snapshot"]["digest"]
                or len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
                > MAX_DATA_BYTES
            ):
                return _result("unknown", ("host.test_output_unrepresented",), forwarded=True)
            labels = tuple(
                sorted(
                    set(SENSITIVE_OUTPUT)
                    | (
                        {"unclassified"}
                        if any(file.label == "unclassified" for file in self.profile.files)
                        else set()
                    )
                )
            )
            resource = self._lineage.capture(
                actor,
                value["output"],
                labels,
                kind="artifact_read",
                origin_kind="mcp_result",
                reservation=custody,
            )
            data = {
                **value,
                "resource_ref": resource.reference,
                "labels": list(resource.labels),
                "instruction_authority": "data",
            }
        elif tool == "write_artifact":
            text = arguments["content"]
            resource = self._lineage.capture(
                actor,
                text,
                self._lineage.labels_for_file(arguments["name"]),
                kind="artifact_write",
                reservation=custody,
            )
            data = {
                "resource_ref": resource.reference,
                "labels": list(resource.labels),
                "version": arguments["expected_version"] + 1,
                "content_digest": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            }
        else:
            if tool == "fetch_url":
                route = next(
                    r for r in self.profile.http_routes if r.route_id == arguments["route_id"]
                )
                if route.credential_file is not None:
                    return _result(
                        "completed",
                        forwarded=effect.forwarded,
                        physical=True,
                        data={
                            "receipt": "credentialed_request_completed",
                            "response_body_disclosed": False,
                        },
                    )
                labels = (route.response_label,)
            else:
                labels = self._lineage.labels_for_file(arguments["name"])
            if type(native.value) is not bytes or len(native.value) > MAX_DATA_BYTES:
                return _result("unknown", ("host.result_bound_or_type",), forwarded=True)
            try:
                text = native.value.decode("utf-8")
            except UnicodeError:
                return _result("unknown", ("host.utf8_document_required",), forwarded=True)
            resource = self._lineage.capture(
                actor,
                text,
                labels,
                kind="artifact_read",
                origin_kind="repository_file" if tool == "read_file" else "web_content",
                reservation=custody,
            )
            data = {
                "content": text,
                "resource_ref": resource.reference,
                "labels": list(resource.labels),
                "instruction_authority": "data",
            }
            if tool == "read_file":
                # This digest names returned bytes, never a write-only lookup.
                # Snapshot occurs separately: a concurrent update must be
                # explicit rather than assigning its version to older bytes.
                returned_digest = hashlib.sha256(native.value).hexdigest()
                data.update(content_digest=returned_digest, version=None, version_match=False)
                try:
                    snapshot = self._authority.backend.snapshot(
                        str(self.profile.workspace / arguments["name"]), operator=self._operator
                    )
                    matches = snapshot["content_digest"] == returned_digest and snapshot[
                        "bytes"
                    ] == len(native.value)
                    data.update(
                        current_version=snapshot["version"],
                        version=snapshot["version"] if matches else None,
                        version_match=matches,
                    )
                except (ValueError, OSError, RuntimeError):
                    data["current_version"] = None
        return _result("completed", forwarded=effect.forwarded, physical=True, data=data)

    @_host_control
    def call(self, client: HostClient, tool: str, arguments: dict, *, request_id: str) -> dict:
        row = self.require_client(client)
        if row.actor is None:
            return _result("denied", ("host.operator_is_not_workload",))
        captured = bounded_json(arguments)
        if (
            type(captured) is not dict
            or type(request_id) is not str
            or not 1 <= len(request_id) <= 256
        ):
            raise ValueError("bounded original host request required")
        actor = self.profile.actor(row.actor)
        key = digest([client.connection_id, request_id])
        with self._lock:
            if (
                self._closed
                or self._clients.get(client) is not row
                or row.closing
                or row.busy
                or key in row.requests
                or len(row.requests) >= self.profile.limits.requests
            ):
                return _result("denied", ("host.busy_replayed_or_at_capacity",))
            row.requests.add(key)
            row.busy = True
        may_have_forwarded = False
        custody = None
        retained_for_approval = False
        try:
            if tool == "host_status" and not captured:
                return _result("completed", data=self.status(client))
            if tool == "handoff" and set(captured) == {"resource_ref", "recipient"}:
                if (
                    type(captured["recipient"]) is not str
                    or captured["recipient"] not in actor.peers
                    or type(captured["resource_ref"]) is not str
                ):
                    return _result("denied", ("host.handoff_arguments_invalid",))
                self._lineage.require(row.actor, captured["resource_ref"])
                may_have_forwarded = True
                data = self._lineage.handoff(
                    row.actor, captured["resource_ref"], captured["recipient"]
                )
                return _result("completed", forwarded=True, data=data)
            if tool == "receive" and not captured:
                may_have_forwarded = True
                return _result("completed", data=self._lineage.receive(row.actor))
            if tool == "approval_status" and set(captured) == {"request_ref"}:
                if type(captured["request_ref"]) is not str or len(captured["request_ref"]) > 128:
                    return _result("denied", ("host.invalid_approval_reference",))
                with self._lock:
                    pending = self._approvals.get(captured["request_ref"])
                    if pending is None or pending.actor != row.actor:
                        return _result("denied", ("host.foreign_approval_reference",))
                    eligible = pending.result is None and not pending.fulfilling
                current_time = self._authority.clock() if eligible else None
                with self._lock:
                    if (
                        pending.result is None
                        and not pending.fulfilling
                        and current_time is not None
                        and current_time >= pending.request.expires_at
                    ):
                        pending.result = _result("denied", ("host.approval_expired",))
                        if pending.custody is not None:
                            self._lineage.cancel(pending.custody)
                    return pending.result or _result(
                        "requires_approval", data={"request_ref": captured["request_ref"]}
                    )
            if (
                tool == "read_file"
                and set(captured) == {"name"}
                and captured["name"] in actor.read_files
            ):
                custody = self._lineage.reserve(row.actor, MAX_DATA_BYTES)
                action = ToolCallAdapter(RUNTIME).adapt(
                    "read_file",
                    {"path": str(self.profile.workspace / captured["name"])},
                    action_id="host-" + uuid4().hex,
                )
            elif (
                tool == "run_tests"
                and set(captured) == {"test_id"}
                and type(captured["test_id"]) is str
                and captured["test_id"] in actor.test_ids
            ):
                custody = self._lineage.reserve(row.actor, MAX_DATA_BYTES)
                action = ToolCallAdapter(RUNTIME).adapt(
                    "run_tests", captured, action_id="host-" + uuid4().hex
                )
            elif (
                tool == "write_artifact"
                and set(captured) == {"name", "content", "expected_version", "expected_digest"}
                and captured["name"] in actor.write_files
            ):
                _text(captured["content"])
                version, expected = captured["expected_version"], captured["expected_digest"]
                if (
                    type(version) is not int
                    or not 0 <= version <= 2**53 - 1
                    or version == 0
                    and expected is not None
                    or version > 0
                    and (
                        type(expected) is not str
                        or len(expected) != 64
                        or any(character not in "0123456789abcdef" for character in expected)
                    )
                ):
                    return _result("denied", ("host.invalid_write_version_or_digest",))
                custody = self._lineage.reserve(row.actor, len(captured["content"].encode("utf-8")))
                action = ToolCallAdapter(RUNTIME).adapt(
                    "write_artifact",
                    {
                        "path": str(self.profile.workspace / captured["name"]),
                        "content": captured["content"],
                        "expected_version": captured["expected_version"],
                        "expected_digest": captured["expected_digest"],
                    },
                    action_id="host-" + uuid4().hex,
                )
            elif (
                tool == "fetch_url"
                and set(captured) == {"route_id"}
                and captured["route_id"] in actor.http_routes
            ):
                route = next(
                    r for r in self.profile.http_routes if r.route_id == captured["route_id"]
                )
                if route.credential_file is None:
                    custody = self._lineage.reserve(
                        row.actor, min(route.response_limit_bytes, MAX_DATA_BYTES)
                    )
                action = ActionEnvelope(
                    "network",
                    "http.request",
                    {"url": route.url, "method": "GET"},
                    action_id="host-" + uuid4().hex,
                )
            else:
                return _result("denied", ("host.tool_or_arguments_not_authorized",))
            if self.shutdown_requested.is_set():
                return _result("denied", ("host.draining",))
            may_have_forwarded = True
            effect = self._authority.dispatch(
                row.actor, row.channel, action, request_id="tool-" + key
            )
            if effect.status == "requires_approval":
                if effect.approval is None:
                    raise ValueError("original managed approval request unavailable")
                reference = effect.approval.request_id
                with self._lock:
                    if len(self._approvals) >= min(1024, self.profile.limits.requests):
                        if custody is not None:
                            self._lineage.cancel(custody)
                        return _result("denied", ("host.approval_history_capacity",))
                    self._approvals[reference] = _Approval(
                        client, row.actor, tool, captured, effect, custody=custody
                    )
                    retained_for_approval = True
                return _result(
                    "requires_approval",
                    effect.reason_codes,
                    data={
                        "request_ref": reference,
                        "binding_digest": effect.approval.binding.digest,
                        "expires_at": effect.approval.expires_at,
                    },
                )
            return self._completed(row.actor, tool, captured, effect, custody)
        except (ValueError, OSError, RuntimeError):
            return _result(
                "unknown" if may_have_forwarded else "denied",
                ("host.unavailable_or_unrepresented",),
                forwarded=None if may_have_forwarded else False,
            )
        finally:
            if custody is not None and not retained_for_approval:
                if may_have_forwarded:
                    self._lineage.uncertain(custody)
                else:
                    self._lineage.cancel(custody)
            with self._lock:
                row.busy = False

    @_host_control
    def operator_call(self, client: HostClient, operation: str, arguments: dict) -> dict:
        row = self.require_client(client)
        if row.actor is not None or row.human_channel is None:
            return _result("denied", ("host.authenticated_operator_required",))
        parameters = bounded_json(arguments)
        if type(parameters) is not dict:
            return _result("denied", ("host.operator_arguments_invalid",))
        service = self._authority.governance
        human = row.human_channel
        if operation == "queue" and not set(parameters) - {"offset", "limit"}:
            offset, limit = parameters.get("offset", 0), parameters.get("limit", 8)
            if (
                type(offset) is not int
                or not 0 <= offset <= 1024
                or type(limit) is not int
                or not 1 <= limit <= 8
            ):
                return _result("denied", ("host.operator_page_invalid",))
            snapshot = service.snapshot(human, task_id=self.profile.task_id)
            requests = snapshot["requests"]
            return _result(
                "completed",
                data={
                    "requests": requests[offset : offset + limit],
                    "total": len(requests),
                    "next_offset": offset + limit if offset + limit < len(requests) else None,
                },
            )
        if operation == "shutdown" and not parameters:
            self._authority.directory.require(
                human, task_id=self.profile.task_id, roles=("policy_admin",)
            )
            self.shutdown_requested.set()
            # Local admission closes immediately. Original jobs are stopped by
            # owned handles during close; already-started effects are not undone.
            self.request_shutdown(operator=self._operator)
            return _result(
                "completed",
                data={
                    "shutdown_requested": True,
                    "new_admission_disabled": True,
                    "running_effects_may_be_uncertain": True,
                },
            )
        if operation not in {"show", "resolve", "fulfill"}:
            return _result("denied", ("host.operator_method_unavailable",))
        allowed = (
            {"request_ref", "include_content"}
            if operation == "show"
            else {"request_ref", "expected_binding", "choice", "idempotency_key"}
            if operation == "resolve"
            else {"request_ref", "expected_binding"}
        )
        if operation == "show":
            if "include_content" not in parameters:
                parameters["include_content"] = False
            if type(parameters["include_content"]) is not bool:
                return _result("denied", ("host.operator_arguments_invalid",))
        if set(parameters) != allowed:
            return _result("denied", ("host.operator_arguments_invalid",))
        reference = parameters["request_ref"]
        if type(reference) is not str or not 1 <= len(reference) <= 128:
            return _result("denied", ("host.invalid_approval_reference",))
        with self._lock:
            pending = self._approvals.get(reference)
        if pending is None:
            return _result("denied", ("host.original_request_unavailable",))
        current = service.get_request(human, reference)
        binding = pending.request.binding.digest
        if operation == "show":
            content = pending.arguments.get("content")
            test_scope = None
            if pending.tool == "run_tests":
                route = next(
                    route
                    for route in self._authority.test_routes
                    if route.test_id == pending.arguments["test_id"]
                )
                if pending.effect.action is None:
                    raise ValueError("original prepared test action unavailable")
                test_scope = {
                    "test_id": route.test_id,
                    "selectors": list(route.selectors),
                    "project_root": str(route.project_root),
                    "snapshot": dict(pending.effect.action.parameters["host_test_snapshot"]),
                    "runtime_digest": route.runtime.digest,
                    "interpreter_digest": route.runtime.interpreter_digest,
                    "output_trust": "untrusted_test_diagnostic",
                    "test_correctness_verified": False,
                }
            return _result(
                "completed",
                data={
                    "request": current,
                    "expected_binding": binding,
                    "expires_at": pending.request.expires_at,
                    "proposal": {
                        "actor": pending.actor,
                        "tool": pending.tool,
                        "target_name": pending.arguments.get("name"),
                        "route_id": pending.arguments.get("route_id"),
                        "test_id": pending.arguments.get("test_id"),
                        "test_scope": test_scope,
                        "content_bytes": len(content.encode("utf-8"))
                        if type(content) is str
                        else None,
                        "content_sha256": (
                            hashlib.sha256(content.encode("utf-8")).hexdigest()
                            if type(content) is str
                            else None
                        ),
                        "expected_version": pending.arguments.get("expected_version"),
                        "expected_digest": pending.arguments.get("expected_digest"),
                        **({"content": content} if parameters["include_content"] else {}),
                        **(
                            {"arguments": pending.arguments}
                            if parameters["include_content"]
                            else {}
                        ),
                    },
                },
            )
        if parameters["expected_binding"] != binding:
            return _result("denied", ("host.approval_binding_changed",))
        if operation == "resolve":
            choice, key = parameters["choice"], parameters["idempotency_key"]
            if (
                type(choice) is not str
                or choice not in {"approve", "deny"}
                or type(key) is not str
                or not 1 <= len(key) <= 128
            ):
                return _result("denied", ("host.operator_resolution_invalid",))
            service.resolve(human, reference, choice, idempotency_key=key)
            return _result("completed", data={"request": service.get_request(human, reference)})
        workload = self.require_client(pending.client)
        with self._lock:
            if pending.result is not None:
                return _result("completed", data={"fulfillment": pending.result})
            if pending.fulfilling or workload.busy:
                return _result("denied", ("host.fulfillment_or_workload_busy",))
            pending.fulfilling = workload.busy = True
        try:
            self._authority.maintenance()
            self._authority.refresh_factory()
            dispatched = service.fulfill(human, reference)
            if dispatched.status != "host_completed":
                result = _result("unknown", ("host.approved_effect_uncertain",), forwarded=None)
            else:
                # Public metadata is not a physical receipt. Recover only the
                # original verified native object through the protected service.
                native = service.fulfillment_result(human, reference)
                effect = HostDispatch(
                    "completed",
                    (),
                    native.forwarded,
                    native.physical_enforcement,
                    result=native,
                    action=pending.effect.action,
                )
                result = self._completed(
                    pending.actor, pending.tool, pending.arguments, effect, pending.custody
                )
        except (ValueError, OSError, RuntimeError):
            result = _result("unknown", ("host.approved_effect_unavailable",), forwarded=None)
        finally:
            if pending.custody is not None:
                self._lineage.uncertain(pending.custody)
            with self._lock:
                workload.busy = False
        with self._lock:
            pending.result = result
        return _result("completed", data={"fulfillment": result})

    @_host_control
    def status(self, client: HostClient) -> dict:
        row = self.require_client(client)
        current = self._authority.coordinator.status(
            self._authority.scope, control=self._authority.control
        )
        value = {
            "schema_version": STATUS_VERSION,
            "online": bool(current.get("online")) and not self.shutdown_requested.is_set(),
            "profile_digest": self.profile.digest,
            "policy_epoch": current.get("policy_epoch"),
            "owner_fence": current.get("owner_fence"),
            "actor": row.actor,
            "execution_boundary": "managed_owned_tools",
            "client_process_confinement": "not_established",
            "unmediated_tools": "uncovered",
            "max_tool_data_bytes": MAX_DATA_BYTES,
            "current_task_expires_at": self._authority.expires_at,
            "retained_data": self._lineage.status(row.actor) if row.actor is not None else {},
            "execution_authority": False,
        }
        if validate_named_schema("swarm_tool_host_status", value):
            raise ValueError("invalid bounded managed host status")
        return value

    def maintenance(self) -> None:
        if self._closed or self.shutdown_requested.is_set():
            return
        try:
            with self._authority.control_phase(blocking=False) as acquired:
                if not acquired:
                    return  # Busy is not permission to extend any original lease.
                self._authority.maintenance()
                with self._lock:
                    candidates = tuple(
                        pending
                        for pending in self._approvals.values()
                        if pending.result is None and not pending.fulfilling
                    )
                for pending in candidates:
                    current_time = self._authority.clock()
                    with self._lock:
                        if (
                            pending.result is None
                            and not pending.fulfilling
                            and current_time >= pending.request.expires_at
                        ):
                            pending.result = _result("denied", ("host.approval_expired",))
                            if pending.custody is not None:
                                self._lineage.cancel(pending.custody)
                self._authority.coordinator.checkpoint(
                    self._authority.scope, control=self._authority.control
                )
        except ValueError:
            if not self._closed and not self.shutdown_requested.is_set():
                raise

    def request_shutdown(self, *, operator: object) -> None:
        """Preemptive local capability, never a caller-supplied wire identity."""
        if operator is not self._operator:
            raise ValueError("original managed shutdown operator required")
        with self._lock:
            self._closed = True
            self.shutdown_requested.set()
        self._authority.request_stop()

    def close(self) -> None:
        with self._close_lock:
            if self._cleanup_complete:
                return
            with self._lock:
                self._closed = True
                self.shutdown_requested.set()
                clients = tuple(self._clients)
            error = None
            try:
                if hasattr(self._authority, "auth"):
                    self._authority.auth.fence(operator=self._operator)
            except BaseException as failure:
                error = failure
            try:
                if hasattr(self._authority, "broker"):
                    for authorization in tuple(self._authority.broker._pending):
                        try:
                            self._authority.broker.request_stop(authorization)
                        except (ValueError, OSError, RuntimeError):
                            pass
            except BaseException as failure:
                error = error or failure
            for client in clients:
                try:
                    self.close_client(client)
                except BaseException as failure:
                    error = error or failure
            try:
                self._authority.close()
            except BaseException as failure:
                error = error or failure
            if error is not None:
                raise _HostCleanupIncomplete(self) from error
            try:
                with self._lock:
                    if self._clients:
                        raise RuntimeError("original managed clients remain open")
                if self._lock_fd is not None:
                    os.close(self._lock_fd)
                    self._lock_fd = None
            except BaseException as error:
                raise _HostCleanupIncomplete(self) from error
            self._cleanup_complete = True


__all__ = ["HostClient", "ManagedToolHost"]
