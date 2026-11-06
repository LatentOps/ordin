"""Minimal protected host SDK. Framework/model fields never enroll a principal."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import inspect
import json
import math
from threading import RLock
from typing import Any, Callable, Mapping
from uuid import uuid4

from ordin import ToolCallAdapter
from ordin.action import ActionEnvelope
from ordin._runtime_json import digest
from ordin.swarm import SwarmContext, SwarmGate, SwarmToolGateway
from ._reports import checked

MAX_BYTES = 65536


def bounded_json(value: Any) -> Any:
    pending = [(value, 0)]
    nodes, size = 1, 0
    while pending:
        item, depth = pending.pop()
        if depth > 12:
            raise ValueError("framework JSON nesting exceeds its bound")
        if type(item) is str:
            if len(item) > MAX_BYTES:
                raise ValueError("framework JSON string exceeds its bound")
            size += len(item.encode("utf-8"))
        elif type(item) in {dict, list, tuple}:
            children = list(item.items()) if type(item) is dict and len(item) <= 4096 else item
            count = len(item) * 2 if type(item) is dict else len(item)
            if nodes + count > 4096:
                raise ValueError("framework JSON item count exceeds its bound")
            nodes += count
            if type(item) is dict:
                for key, child in children:
                    if type(key) is not str:
                        raise ValueError("framework JSON object keys must be strings")
                    pending.extend(((key, depth + 1), (child, depth + 1)))
            else:
                pending.extend((child, depth + 1) for child in item)
        elif type(item) is int:
            if abs(item) > 9007199254740991:
                raise ValueError("framework JSON integer exceeds exact interoperable range")
        elif type(item) is float:
            if not math.isfinite(item):
                raise ValueError("framework JSON number must be finite")
        elif item is not None and type(item) is not bool:
            raise ValueError("framework arguments require JSON data")
        if size > MAX_BYTES:
            raise ValueError("framework JSON data exceeds its bound")
    try:
        raw = json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        if len(raw.encode()) > MAX_BYTES:
            raise ValueError("framework request exceeds bounded JSON size")
        return json.loads(raw)
    except (TypeError, RecursionError, UnicodeError):
        raise ValueError("framework requests require bounded JSON data") from None


def callback_binding(callback: Callable) -> tuple:
    function = getattr(callback, "__func__", callback)
    return (
        id(callback),
        id(function),
        id(getattr(function, "__code__", None)),
        id(getattr(callback, "__self__", None)),
        id(getattr(function, "__defaults__", None)),
        id(getattr(function, "__kwdefaults__", None)),
    )


@dataclass(frozen=True, eq=False, slots=True)
class FrameworkSession:
    binding_id: str


@dataclass(frozen=True, eq=False, slots=True)
class FrameworkTool:
    binding_id: str


@dataclass(frozen=True, eq=False, slots=True)
class FrameworkCall:
    call_id: str


class SwarmToolRefused(RuntimeError):
    def __init__(self, disposition: str, reason_codes: tuple[str, ...]):
        self.disposition, self.reason_codes = disposition, reason_codes
        super().__init__("Ordin " + disposition + ": " + ",".join(reason_codes))


@dataclass(frozen=True, slots=True)
class FrameworkPreparation:
    disposition: str
    action_digest: str
    reason_codes: tuple[str, ...]
    call: FrameworkCall | None = field(default=None, repr=False)

    def as_dict(self):
        return checked(
            {
                "schema_version": "ordin.swarm_framework_preparation.v1",
                "disposition": self.disposition,
                "action_digest": self.action_digest,
                "reason_codes": list(self.reason_codes),
                "call_digest": digest(self.call.call_id) if self.call else None,
                "execution_authority": False,
            }
        )


@dataclass(frozen=True, eq=False, slots=True)
class FrameworkResult:
    status: str
    action_digest: str
    call_digest: str
    journal_gap: bool
    physical_enforcement: bool
    value: Any = field(default=None, repr=False)

    def as_dict(self):
        return checked(
            {
                "schema_version": "ordin.swarm_framework_result.v1",
                "status": self.status,
                "action_digest": self.action_digest,
                "call_digest": self.call_digest,
                "journal_gap": self.journal_gap,
                "physical_enforcement": self.physical_enforcement,
                "execution_authority": False,
            }
        )


@dataclass
class _Session:
    runtime: object
    identify: Callable
    context: SwarmContext
    channel: Any
    adapter: object
    actor: Any
    gateway: Any
    broker: Any = None
    coordinator: Any = None
    attachment: Any = None
    tools: dict[str, FrameworkTool] = field(default_factory=dict)
    requests: set[str] = field(default_factory=set)
    closed: bool = False
    lock: Any = field(default_factory=RLock)


@dataclass(frozen=True)
class _Tool:
    session: FrameworkSession
    name: str
    runtime: str
    callback: Callable
    callback_key: tuple
    guard: Callable
    action_builder: Callable | None
    route: str


@dataclass
class _Call:
    session: FrameworkSession
    tool: FrameworkTool
    arguments: dict[str, Any]
    argument_digest: str
    authorization: Any
    state: str = "prepared"


class SwarmSDK:
    """Original handles over the maintained gateway; no independent safety engine.

    Operator code owns runtime/identify callbacks, enrollment, exact tool objects
    and dispatchers. Unwrapped Python, background work and provider transports
    remain outside this interception boundary.
    """

    def __init__(self, *, operator: object, max_sessions=256, max_tools=256, max_calls=4096):
        if type(operator) is not object or any(
            type(v) is not int or not 1 <= v <= 16384 for v in (max_sessions, max_tools, max_calls)
        ):
            raise ValueError("protected SDK operator and bounded capacities required")
        self._operator = operator
        self._limits = max_sessions, max_tools, max_calls
        self._sessions: dict[FrameworkSession, _Session] = {}
        self._tools: dict[FrameworkTool, _Tool] = {}
        self._calls: dict[FrameworkCall, _Call] = {}
        self._results: dict[FrameworkResult, tuple[FrameworkCall, str]] = {}
        self._lock = RLock()

    def bind(
        self,
        runtime: object,
        context: SwarmContext,
        gate: SwarmGate,
        channel,
        adapter: object,
        *,
        gateway: SwarmToolGateway,
        identify: Callable,
        operator: object,
        assessment_provider=None,
        broker=None,
        broker_binding=None,
    ) -> FrameworkSession:
        if (
            operator is not self._operator
            or type(gateway) is not SwarmToolGateway
            or type(gate) is not SwarmGate
            or not callable(identify)
        ):
            raise ValueError("original host gateway, gate and lifecycle binding required")
        if identify() is not runtime:
            raise ValueError("host runtime identity unavailable")
        gate._registry.authenticate(context, channel, adapter)
        with self._lock:
            if len(self._sessions) >= self._limits[0] or any(
                v.runtime is runtime and v.context is context and not v.closed
                for v in self._sessions.values()
            ):
                raise ValueError("SDK session capacity or duplicate runtime")
            if broker is None:
                if broker_binding is not None:
                    raise ValueError("broker binding requires its original broker")
                actor = gateway.bind_agent(
                    context,
                    gate,
                    channel,
                    adapter,
                    routes=frozenset({"sdk", "file", "http", "mcp", "shell", "database"}),
                    assessment_provider=assessment_provider,
                )
            else:
                from ordin.swarm.broker import SwarmExecutionBroker

                if (
                    type(broker) is not SwarmExecutionBroker
                    or broker.gateway_scope(broker_binding)[2] is not context
                    or broker._gate is not gate
                ):
                    raise ValueError("original broker route differs from SDK context")
                actor = gateway.bind_broker_agent(
                    broker, broker_binding, routes=frozenset({"sdk", "file"})
                )
            handle = FrameworkSession(uuid4().hex)
            self._sessions[handle] = _Session(
                runtime, identify, context, channel, adapter, actor, gateway, broker
            )
            return handle

    def _session(self, handle: FrameworkSession) -> _Session:
        row = self._sessions.get(handle) if type(handle) is FrameworkSession else None
        if row is None or row.closed or row.identify() is not row.runtime:
            raise ValueError("original current framework session required")
        if row.coordinator is not None:
            service, scope, channel, broker_channel, lease, grant = row.coordinator
            current, enrollment, _ = service._subject(scope, channel)
            service.admission_context(scope, channel, lease)
            if (
                enrollment.context is not row.context
                or current.brokers.get(enrollment.host_id) is not row.broker
            ):
                raise ValueError("coordinator framework enrollment or broker changed")
            return row
        actor = row.gateway._actor(row.actor)
        if actor.context is not row.context:
            raise ValueError("framework actor enrollment changed")
        return row

    def _operation(self, row):
        return row.gateway._operation_lock if row.gateway is not None else self._lock

    def bind_attached(self, manager, handle, *, operator: object):
        from ordin.swarm import SwarmAttachManager

        if operator is not self._operator or type(manager) is not SwarmAttachManager:
            raise ValueError("original SDK operator and attach manager required")
        with manager._gateway._operation_lock, self._lock:
            attached = manager._row(handle)
            manager._check_live(attached)
            if (
                attached.gateway_actor is None
                or attached.context is None
                or len(self._sessions) >= self._limits[0]
                or any(
                    v.context is attached.context and not v.closed for v in self._sessions.values()
                )
            ):
                raise ValueError("verified original live gateway context required")
            endpoint = attached.endpoint
            session = FrameworkSession(uuid4().hex)
            self._sessions[session] = _Session(
                endpoint.identity,
                endpoint.current,
                attached.context,
                endpoint.channel,
                endpoint.adapter,
                attached.gateway_actor,
                manager._gateway,
                attachment=(manager, handle),
            )
            return session

    def bind_coordinator(
        self,
        runtime,
        *,
        coordinator,
        scope,
        workload_channel,
        broker_channel,
        lease,
        grant_ref,
        identify,
        operator: object,
    ):
        """A remote/durable route uses the original registered enforcing broker.

        No framework callback is transmitted or used as a physical executor.
        Every reference is reauthenticated online by the native coordinator.
        """
        from ordin.swarm.coordinator import SwarmCoordinator, CoordinatorRecord
        from ordin.swarm.broker import SwarmExecutionBroker

        if (
            operator is not self._operator
            or type(coordinator) is not SwarmCoordinator
            or type(lease) is not CoordinatorRecord
            or lease.kind != "lease"
            or lease.reference is None
            or not callable(identify)
            or identify() is not runtime
        ):
            raise ValueError("original protected coordinator lease and host runtime required")
        configured, enrollment, _ = coordinator._subject(scope, workload_channel)
        coordinator.admission_context(scope, workload_channel, lease.reference)
        broker = configured.brokers.get(enrollment.host_id)
        if (
            type(broker) is not SwarmExecutionBroker
            or configured.broker_channels.get(enrollment.host_id) is not broker_channel
        ):
            raise ValueError("original same-host enforcing coordinator route required")
        with self._lock:
            if len(self._sessions) >= self._limits[0] or any(
                v.context is enrollment.context and not v.closed for v in self._sessions.values()
            ):
                raise ValueError("SDK session capacity or duplicate context")
            handle = FrameworkSession(uuid4().hex)
            self._sessions[handle] = _Session(
                runtime,
                identify,
                enrollment.context,
                enrollment.registry_channel,
                enrollment.adapter,
                None,
                None,
                broker,
                (coordinator, scope, workload_channel, broker_channel, lease.reference, grant_ref),
            )
            return handle

    def context(self, handle: FrameworkSession) -> SwarmContext:
        return self._session(handle).context

    def register_tool(
        self,
        session: FrameworkSession,
        *,
        name: str,
        runtime: str,
        callback: Callable,
        guard: Callable,
        route="sdk",
        action_builder=None,
        operator: object,
    ) -> FrameworkTool:
        from ordin.swarm.models import identifier

        identifier(name, "tool_name")
        identifier(runtime, "tool_runtime")
        if (
            operator is not self._operator
            or not callable(callback)
            or not callable(guard)
            or inspect.iscoroutinefunction(callback)
            or (action_builder is not None and not callable(action_builder))
        ):
            raise ValueError("original synchronous host tool and current-object guard required")
        if route not in {"sdk", "file", "http", "mcp", "shell", "database"}:
            raise ValueError("unsupported framework forwarding route")
        row = self._session(session)
        with self._operation(row), self._lock, row.lock:
            if name in row.tools or len(self._tools) >= self._limits[1]:
                raise ValueError("SDK tool capacity or duplicate native name")
            guard()
            handle = FrameworkTool(uuid4().hex)
            self._tools[handle] = _Tool(
                session,
                name,
                runtime,
                callback,
                callback_binding(callback),
                guard,
                action_builder,
                route,
            )
            row.tools[name] = handle
            return handle

    def tool(self, session: FrameworkSession, name: str) -> FrameworkTool:
        row = self._session(session)
        if type(name) is not str or name not in row.tools:
            raise ValueError("tool is not in this original host dispatch table")
        return row.tools[name]

    def prepare(
        self,
        session: FrameworkSession,
        tool: FrameworkTool,
        arguments: Mapping[str, Any],
        *,
        request_id: str,
    ) -> FrameworkPreparation:
        row = self._session(session)
        bound = self._tools.get(tool) if type(tool) is FrameworkTool else None
        if (
            bound is None
            or bound.session is not session
            or type(request_id) is not str
            or not 1 <= len(request_id) <= 256
            or not isinstance(arguments, Mapping)
        ):
            raise ValueError("exact session/tool binding and bounded request ID required")
        captured = bounded_json(dict(arguments))
        with self._operation(row), self._lock, row.lock:
            if len(self._calls) >= self._limits[2] or len(row.requests) >= self._limits[2]:
                raise ValueError("SDK replay history capacity reached")
            key = digest(request_id)
            if key in row.requests:
                raise ValueError("native framework request already attempted")
            row.requests.add(key)
            bound.guard()
            if callback_binding(bound.callback) != bound.callback_key:
                raise ValueError("protected tool callback changed")
            action = (
                ToolCallAdapter(bound.runtime).adapt(
                    bound.name, captured, action_id="framework-" + uuid4().hex
                )
                if bound.action_builder is None
                else bound.action_builder(bounded_json(captured))
            )
            if type(action) is not ActionEnvelope:
                raise ValueError("host tool adapter did not produce an exact action")
            action = replace(action, action_id="framework-" + uuid4().hex)
            if row.coordinator is not None:
                service, scope, channel, broker_channel, lease, grant = row.coordinator
                request_key = "framework-" + digest([session.binding_id, key])
                evaluation = service.evaluate(
                    scope, channel, lease, grant, action, idempotency_key=request_key
                )
                if evaluation.status != "execute":
                    return FrameworkPreparation(
                        evaluation.status,
                        digest(action.as_dict()),
                        ("framework.coordinator_restricted",),
                    )
                authorization = service.reserve(
                    scope, channel, lease, evaluation.reference, action, idempotency_key=request_key
                )
                if authorization.status != "reserved" or authorization.action_digest is None:
                    return FrameworkPreparation(
                        "deny", digest(action.as_dict()), ("framework.coordinator_not_reserved",)
                    )
                handle = FrameworkCall(uuid4().hex)
                self._calls[handle] = _Call(
                    session, tool, captured, digest(captured), authorization
                )
                return FrameworkPreparation("execute", authorization.action_digest, (), handle)
            authorization = row.gateway.prepare(
                row.actor,
                action,
                route=bound.route,
                budget_idempotency_key="framework-" + digest([session.binding_id, key]),
            )
            reasons = authorization.decision.reason_codes if authorization.decision else ()
            if authorization.ticket is None:
                return FrameworkPreparation(
                    authorization.disposition,
                    authorization.action_digest,
                    reasons or ("framework.review_restricted",),
                )
            handle = FrameworkCall(uuid4().hex)
            self._calls[handle] = _Call(session, tool, captured, digest(captured), authorization)
            return FrameworkPreparation("execute", authorization.action_digest, (), handle)

    def forward(
        self, session: FrameworkSession, call: FrameworkCall, *, arguments=None
    ) -> FrameworkResult:
        row = self._session(session)
        with self._operation(row), self._lock, row.lock:
            pending = self._calls.get(call) if type(call) is FrameworkCall else None
            if pending is None or pending.session is not session or pending.state != "prepared":
                raise ValueError("unknown, foreign or consumed framework authorization")
            pending.state = "checking"
        bound = self._tools[pending.tool]
        try:
            with self._operation(row), row.lock:
                self._session(session)
                bound.guard()
                if callback_binding(bound.callback) != bound.callback_key or (
                    arguments is not None
                    and digest(bounded_json(arguments)) != pending.argument_digest
                ):
                    raise ValueError("exact framework callback or arguments changed")

                def execute(_action):
                    bound.guard()
                    if callback_binding(bound.callback) != bound.callback_key:
                        raise ValueError("framework callback changed before effect")
                    value = bound.callback(bounded_json(pending.arguments))
                    if inspect.isawaitable(value):
                        if inspect.iscoroutine(value):
                            value.close()
                        raise ValueError(
                            "async tool execution requires an explicit verified adapter"
                        )
                    return value

                pending.state = "forwarding"
                if row.coordinator is not None:
                    service, scope, channel, broker_channel, lease, grant = row.coordinator
                    original = service._prepared.get(pending.authorization.reference)
                    if original is None or original.broker is not row.broker:
                        raise ValueError("original coordinator broker authorization unavailable")
                    outcome = service.guarded_dispatch(
                        scope, broker_channel, pending.authorization.reference
                    )
                    native = row.broker._pending[original.authorization].result
                    if native is not None and not row.broker.verify_result(
                        native, original.authorization
                    ):
                        raise ValueError("coordinator acquired an unverified broker result")
                    status = "completed" if outcome.status == "host_completed" else "unknown"
                    if status == "completed" and (native is None or native.status != "completed"):
                        raise ValueError("original completed broker evidence required")
                    pending.state = status
                    report = FrameworkResult(
                        status,
                        pending.authorization.action_digest,
                        digest(call.call_id),
                        status != "completed",
                        bool(native and native.physical_enforcement),
                        outcome.value if status == "completed" else None,
                    )
                    self._results[report] = (call, digest(report.as_dict()))
                    return report
                native_auth = (
                    row.gateway._pending[pending.authorization.ticket].broker_authorization
                    if row.broker
                    else None
                )
                result = row.gateway.forward(
                    row.actor,
                    pending.authorization.ticket,
                    None if row.broker is not None else execute,
                )
                pending.state = result.status
                physical = False
                if row.broker is not None:
                    # The gateway has already verified the original broker
                    # result. This report still does not become authority.
                    native = row.broker._pending[native_auth].result
                    if native is None or not row.broker.verify_result(native, native_auth):
                        raise ValueError("original broker result unavailable")
                    physical = native.physical_enforcement
                report = FrameworkResult(
                    result.status,
                    pending.authorization.action_digest,
                    digest(call.call_id),
                    result.journal_gap,
                    physical,
                    result.value,
                )
                self._results[report] = (call, digest(report.as_dict()))
                return report
        except BaseException:
            pending.state = "failed"
            try:
                if row.coordinator is not None:
                    service, scope, channel, _, lease, _ = row.coordinator
                    service.cancel(scope, channel, lease, pending.authorization.reference)
                else:
                    row.gateway.cancel(row.actor, pending.authorization.ticket)
            except ValueError:
                pass
            raise

    def invoke(self, session, tool, arguments, *, request_id):
        prepared = self.prepare(session, tool, arguments, request_id=request_id)
        if prepared.call is None:
            raise SwarmToolRefused(prepared.disposition, prepared.reason_codes)
        result = self.forward(session, prepared.call)
        if result.status != "completed":
            raise SwarmToolRefused("deny", ("framework.effect_" + result.status,))
        return result.value

    def cancel(self, session, call):
        row = self._session(session)
        with self._operation(row), self._lock, row.lock:
            pending = self._calls.get(call) if type(call) is FrameworkCall else None
            if pending is None or pending.session is not session or pending.state != "prepared":
                raise ValueError("original queued framework call required")
            pending.state = "canceled"
            if row.coordinator is not None:
                service, scope, channel, _, lease, _ = row.coordinator
                service.cancel(scope, channel, lease, pending.authorization.reference)
            else:
                row.gateway.cancel(row.actor, pending.authorization.ticket)

    def verify_result(self, result, call):
        with self._lock:
            return type(result) is FrameworkResult and self._results.get(result) == (
                call,
                digest(result.as_dict()),
            )

    def close(self, session):
        with self._lock:
            row = self._sessions.get(session) if type(session) is FrameworkSession else None
            if row is None:
                raise ValueError("original framework session required")
            if row.closed:
                return
            row.closed = True
        if row.attachment is not None:
            row.attachment[0].detach(row.attachment[1])
        elif row.coordinator is not None:
            service, scope, channel, _, lease, _ = row.coordinator
            service.revoke_lease(scope, channel, lease)
        else:
            row.gateway.revoke_agent(row.actor)

    def status(self, session):
        row = self._session(session)
        return checked(
            {
                "schema_version": "ordin.swarm_framework_session.v1",
                "context_digest": digest(row.context.as_dict()),
                "tool_names": sorted(row.tools),
                "state": "connected",
                "mode": "coordinator"
                if row.coordinator
                else "broker"
                if row.broker
                else "intercept",
                "physical_enforcement": False,
                "execution_authority": False,
                "uncovered": [
                    "unwrapped_direct_calls",
                    "background_workers",
                    "provider_transport",
                    "native_messages_without_gateway",
                    "native_artifacts_without_gateway",
                ],
            }
        )


__all__ = [
    "SwarmSDK",
    "FrameworkSession",
    "FrameworkTool",
    "FrameworkCall",
    "FrameworkPreparation",
    "FrameworkResult",
    "SwarmToolRefused",
]
