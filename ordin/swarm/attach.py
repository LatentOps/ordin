"""Explicit host attach to existing sessions; never process injection or discovery by name."""

from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from typing import Any, Callable
from uuid import uuid4

from ordin._runtime_json import digest
from ordin.runtime_observation import RuntimeEvidenceSource, RuntimeObservation

from .coverage import AttachCoverage
from .events import SwarmEvent
from .gate import SwarmGate
from .gateway import GatewayAgent, SwarmToolGateway
from .identity import HostChannel
from .ingest import HostEventSource, SwarmEventIngestor
from .models import SwarmContext, identifier
from .registry import InMemoryAgentRegistry


@dataclass(frozen=True, eq=False, slots=True)
class RunningSessionIdentity:
    """Host connector's original session handle, never an agent-supplied process name."""

    agent_id: str
    session_id: str

    def __post_init__(self) -> None:
        identifier(self.agent_id, "agent_id")
        identifier(self.session_id, "session_id")


class HostSessionEndpoint:
    """Protected connector hooks into an existing host dispatch table.

    identify must return the same original handle while that process/session is
    alive, and None after disconnect. Route accessors operate on the host's
    actual future-call dispatch entry. These callbacks are host integration
    code, not configuration or code loaded from agents or JSON.
    """

    def __init__(
        self,
        channel: HostChannel,
        adapter: object,
        *,
        identify: Callable[[], RunningSessionIdentity | None],
        get_router: Callable[[], object],
        set_router: Callable[[object], None] | None = None,
        coverage: AttachCoverage = AttachCoverage("observe"),
        collector: RuntimeEvidenceSource | None = None,
    ) -> None:
        if (
            type(channel) is not HostChannel
            or not callable(identify)
            or not callable(get_router)
            or (set_router is not None and not callable(set_router))
            or type(coverage) is not AttachCoverage
            or (collector is not None and type(collector) is not RuntimeEvidenceSource)
        ):
            raise ValueError("protected host endpoint callbacks required")
        coverage.__post_init__()
        identity = identify()
        if type(identity) is not RunningSessionIdentity:
            raise ValueError("authenticated integration has no live original session")
        identity.__post_init__()
        self.channel, self.adapter = channel, adapter
        self.identify, self.get_router, self.set_router = identify, get_router, set_router
        self.coverage, self.identity = coverage, identity
        self.collector = collector
        self._identity_digest = digest([identity.agent_id, identity.session_id])

    def current(self) -> RunningSessionIdentity:
        try:
            valid = (
                self.identify() is self.identity
                and digest([self.identity.agent_id, self.identity.session_id])
                == self._identity_digest
            )
        except Exception:
            valid = False
        if not valid:
            raise ValueError("host session disconnected or was replaced")
        return self.identity


@dataclass(frozen=True, eq=False, slots=True)
class AttachedSession:
    binding_id: str


class MediatedSessionRouter:
    """Host dispatch target; executors and route selection remain host owned."""

    def __init__(
        self, gateway: SwarmToolGateway, actor: GatewayAgent, guard: Callable[[], None]
    ) -> None:
        self._gateway, self._actor = gateway, actor
        self._guard = guard

    def call(self, route: str, action, executor: Callable):
        with self._gateway._operation_lock:
            self._guard()
            authorization = self._gateway.prepare(self._actor, action, route=route)
            if authorization.ticket is None:
                return authorization
            return self._gateway.forward(self._actor, authorization.ticket, executor)


@dataclass
class _Attachment:
    endpoint: HostSessionEndpoint
    endpoint_digest: str
    original_binding: tuple[object, ...]
    context: SwarmContext | None = None
    source: HostEventSource | None = None
    gateway_actor: GatewayAgent | None = None
    router: MediatedSessionRouter | None = None
    previous_router: object = None
    active: bool = False
    attempts: int = 0
    sequence: int = 0
    continuity: bool = False
    reason: str = "not_attached"


class SwarmAttachManager:
    def __init__(
        self,
        registry: InMemoryAgentRegistry,
        *,
        events: SwarmEventIngestor,
        gateway: SwarmToolGateway,
        gate: SwarmGate,
        max_sessions: int = 256,
        assessment_provider: Callable[..., tuple] | None = None,
    ) -> None:
        if (
            type(registry) is not InMemoryAgentRegistry
            or type(events) is not SwarmEventIngestor
            or events._registry is not registry
            or type(gateway) is not SwarmToolGateway
            or gateway._events is not events
            or type(gate) is not SwarmGate
            or gate._registry is not registry
            or gate._events is not events
            or type(max_sessions) is not int
            or not 1 <= max_sessions <= 4096
            or (assessment_provider is not None and not callable(assessment_provider))
        ):
            raise ValueError("attach requires shared protected enrollment/gateway evidence")
        self._registry, self._events, self._gateway, self._gate = registry, events, gateway, gate
        self._limit = max_sessions
        self._assessment_provider = assessment_provider
        self._sessions: dict[AttachedSession, _Attachment] = {}
        self._lock = RLock()

    def register(self, endpoint: HostSessionEndpoint) -> AttachedSession:
        """Host-only registration after its authenticated connector discovered a session."""
        if type(endpoint) is not HostSessionEndpoint:
            raise ValueError("attach requires an original protected host endpoint")
        with self._lock:
            endpoint.current()
            self._registry._channel(endpoint.channel, endpoint.adapter)
            for handle, row in self._sessions.items():
                if row.endpoint is endpoint:
                    return handle
                if row.endpoint.identity is endpoint.identity:
                    raise ValueError("session already bound to another endpoint")
            if len(self._sessions) >= self._limit:
                raise ValueError("attach session capacity reached")
            handle = AttachedSession(uuid4().hex)
            self._sessions[handle] = _Attachment(
                endpoint, self._endpoint_digest(endpoint), self._binding(endpoint)
            )
            return handle

    @staticmethod
    def _binding(endpoint: HostSessionEndpoint) -> tuple[object, ...]:
        return (
            endpoint.identify,
            endpoint.get_router,
            endpoint.set_router,
            endpoint.channel,
            endpoint.adapter,
            endpoint.coverage,
            endpoint.collector,
        )

    def _endpoint_digest(self, endpoint: HostSessionEndpoint) -> str:
        return digest(
            {
                "identity": [endpoint.identity.agent_id, endpoint.identity.session_id],
                "coverage": [
                    endpoint.coverage.mode,
                    sorted(endpoint.coverage.routes),
                    endpoint.coverage.telemetry,
                    sorted(endpoint.coverage.restart_required),
                    sorted(endpoint.coverage.observed_pathways),
                ],
                "collector": endpoint.collector.key if endpoint.collector else None,
                "callbacks": [
                    id(endpoint.identify),
                    id(endpoint.get_router),
                    id(endpoint.set_router),
                ],
                "channel": id(endpoint.channel),
                "adapter": id(endpoint.adapter),
            }
        )

    def _row(self, handle: AttachedSession) -> _Attachment:
        if type(handle) is not AttachedSession or handle not in self._sessions:
            raise ValueError("unknown original attached-session handle")
        row = self._sessions[handle]
        if any(
            current is not original
            for current, original in zip(self._binding(row.endpoint), row.original_binding)
        ) or row.endpoint_digest != self._endpoint_digest(row.endpoint):
            raise ValueError("protected host endpoint configuration changed")
        return row

    def plan(self, handle: AttachedSession) -> dict[str, Any]:
        with self._lock:
            row = self._row(handle)
            endpoint = row.endpoint
            endpoint.current()
            supported = endpoint.coverage.mode != "enforce" and (
                endpoint.coverage.mode != "intercept"
                or (endpoint.set_router is not None and bool(endpoint.coverage.enabled_routes))
            )
            return {
                "schema_version": "ordin.swarm_attach_plan.v1",
                "supported": supported,
                "dry_run": True,
                "mode": endpoint.coverage.mode,
                "pre_attach_history": "unknown",
                "execution_authority": False,
                "pathways": endpoint.coverage.diagnostics(live=True),
                "required": [] if supported else ["verified_live_route_or_constrained_restart"],
            }

    def attach(self, handle: AttachedSession, *, dry_run: bool = False) -> dict[str, Any]:
        if type(dry_run) is not bool:
            raise ValueError("invalid attach dry-run flag")
        with self._gateway._operation_lock, self._lock:
            row = self._row(handle)
            plan = self.plan(handle)
            if dry_run:
                return plan
            if not plan["supported"]:
                raise ValueError("required live coverage unavailable; constrained restart required")
            endpoint = row.endpoint
            if row.active:
                self._check_live(row)
                return self.status(handle)
            if row.context is not None:
                self._registry.forget_ended(row.context, endpoint.channel, endpoint.adapter)
                row.context = None
            identity = endpoint.current()
            context = self._registry.enroll(
                endpoint.channel,
                endpoint.adapter,
                agent_id=identity.agent_id,
                session_id=identity.session_id,
                coverage=endpoint.coverage.manifest(handle.binding_id),
            )
            row.context = context
            row.active = True
            row.attempts += 1
            row.sequence, row.continuity = 0, False
            row.reason = "attached"
            try:
                row.source = self._events.bind_source(
                    context,
                    endpoint.channel,
                    endpoint.adapter,
                    source_id="attach-" + uuid4().hex,
                    role="collector" if endpoint.collector else "gateway",
                    collector=endpoint.collector,
                )
                if endpoint.coverage.mode == "intercept":
                    if endpoint.set_router is None:
                        raise ValueError("live host routing installer unavailable")
                    row.previous_router = endpoint.get_router()
                    row.gateway_actor = self._gateway.bind_agent(
                        context,
                        self._gate,
                        endpoint.channel,
                        endpoint.adapter,
                        routes=endpoint.coverage.enabled_routes,
                        assessment_provider=self._assessment_provider,
                    )

                    def guard() -> None:
                        self._row(handle)
                        self._check_live(row)

                    row.router = MediatedSessionRouter(self._gateway, row.gateway_actor, guard)
                    endpoint.set_router(row.router)
                    if endpoint.get_router() is not row.router:
                        raise ValueError("future-call routing was not installed")
                self._check_live(row)
            except Exception:
                self._detach(row, "attach_failed")
                raise ValueError(
                    "attach failed; enrollment fenced and coverage remains unknown"
                ) from None
            return self.status(handle)

    def _check_live(self, row: _Attachment) -> None:
        endpoint = row.endpoint
        endpoint.current()
        if row.context is None or not row.active:
            raise ValueError("session is not attached")
        self._registry.authenticate(row.context, endpoint.channel, endpoint.adapter)
        if endpoint.coverage.mode == "intercept" and endpoint.get_router() is not row.router:
            raise ValueError("protected future-call route was disconnected")
        if endpoint.coverage.mode == "intercept":
            if (
                row.gateway_actor is None
                or self._gateway._actor(row.gateway_actor).context is not row.context
            ):
                raise ValueError("protected gateway enrollment was revoked")

    def _detach(self, row: _Attachment, reason: str) -> None:
        if not row.active:
            return
        endpoint = row.endpoint
        # The caller holds the gateway operation lock: no forward starts after
        # revocation, and an in-flight host callback finishes before detach returns.
        if row.context is not None:
            try:
                self._registry.end(row.context, endpoint.channel, endpoint.adapter)
            except ValueError:
                # Closed/replaced channels already fence this original context.
                pass
        if row.gateway_actor is not None:
            try:
                self._gateway.revoke_agent(row.gateway_actor)
            except ValueError:
                pass  # An independently revoked gateway actor is already fenced.
            row.gateway_actor = None
        row.active, row.continuity, row.reason = False, False, reason
        if row.router is not None and endpoint.set_router is not None:
            try:
                if endpoint.get_router() is row.router:
                    endpoint.set_router(row.previous_router)
            except Exception:
                row.reason = "routing_restore_failed"
        row.router = None

    def detach(self, handle: AttachedSession) -> dict[str, Any]:
        with self._gateway._operation_lock, self._lock:
            row = self._row(handle)
            self._detach(row, "detached")
            return self.status(handle)

    def ingest(
        self,
        handle: AttachedSession,
        event: SwarmEvent,
        *,
        observation: RuntimeObservation | None = None,
    ):
        with self._gateway._operation_lock, self._lock:
            row = self._row(handle)
            self._check_live(row)
            if row.source is None:
                raise ValueError("attached event source unavailable")
            if (
                type(event) is not SwarmEvent
                or row.context is None
                or event.timestamp < row.context.enrolled_at
            ):
                raise ValueError("pre-attach history cannot authenticate as a current event")
            receipt = self._events.ingest(row.source, event, observation=observation)
            if not receipt.duplicate:
                if event.source_sequence != row.sequence + 1 or receipt.gaps:
                    row.continuity = False
                    row.reason = "event_continuity_gap"
                elif row.reason != "event_continuity_gap":
                    row.continuity = True
                row.sequence = max(row.sequence, event.source_sequence)
            return receipt

    def context(self, handle: AttachedSession) -> tuple[SwarmContext, HostEventSource]:
        with self._lock:
            row = self._row(handle)
            self._check_live(row)
            if row.context is None or row.source is None:
                raise ValueError("attached session context unavailable")
            return row.context, row.source

    def status(self, handle: AttachedSession) -> dict[str, Any]:
        with self._gateway._operation_lock, self._lock:
            row = self._row(handle)
            if row.active:
                try:
                    self._check_live(row)
                except Exception:
                    self._detach(row, "disconnected_or_stale")
            identity = row.endpoint.identity
            return {
                "schema_version": "ordin.swarm_attach_status.v1",
                "session_digest": digest([identity.agent_id, identity.session_id]),
                "state": "attached" if row.active else "detached",
                "mode": row.endpoint.coverage.mode,
                "generation": row.context.identity.generation if row.context else 0,
                "attachment_count": row.attempts,
                "reason_code": row.reason,
                "pre_attach_history": "unknown",
                "current_window": "continuous_since_attach"
                if row.active and row.continuity
                else "unknown",
                "pathways": row.endpoint.coverage.diagnostics(
                    routing_verified=row.active and row.router is not None,
                    live=row.active,
                ),
                "execution_authority": False,
                "physical_enforcement": False,
            }

    def doctor(self, handle: AttachedSession) -> dict[str, Any]:
        report = self.status(handle)
        report["diagnostics"] = [
            "pre_attach_history_unknown",
            *[
                "path_" + v["pathway"] + "_" + v["state"]
                for v in report["pathways"]
                if v["state"] != "covered"
            ],
        ]
        return report
