"""Explicit host-owned tool forwarding with isolated existing review sessions."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from threading import RLock
import time
from typing import Any, Callable, Mapping
from uuid import uuid4

from ordin.action import ActionEnvelope
from ordin.agent import AgentDecision, AgentGate
from ordin.api import Ordin
from ordin.assurance.delegating_gate import DelegatingAssuranceGate
from ordin._runtime_json import digest
from ordin.session import IntegrationSession, SessionIdentity

from .events import EventRef, SwarmEvent
from .facts import SwarmAssessment
from .gate import SwarmDecision, SwarmGate
from .identity import HostChannel
from .ingest import HostEventSource, SwarmEventIngestor
from .models import SwarmContext, identifier, timestamp

ROUTES = frozenset({"shell", "mcp", "file", "database", "http", "sdk"})


@dataclass(frozen=True, eq=False, slots=True)
class GatewayAgent:
    binding_id: str


@dataclass(frozen=True, eq=False, slots=True)
class ForwardTicket:
    ticket_id: str


@dataclass(frozen=True, slots=True)
class GatewayAuthorization:
    disposition: str
    action_id: str
    action_digest: str
    decision: SwarmDecision
    ticket: ForwardTicket | None = None


@dataclass(frozen=True, slots=True)
class GatewayResult:
    action_id: str
    status: str
    value: Any = field(repr=False, compare=False)
    journal_gap: bool = False


@dataclass(frozen=True, slots=True)
class GatewayOutcome:
    value: Any = field(repr=False, compare=False)
    status: str = "completed"

    def __post_init__(self) -> None:
        if type(self.status) is not str or self.status not in {"completed", "failed", "pending"}:
            raise ValueError("unknown host forwarding outcome")


@dataclass
class _Actor:
    context: SwarmContext
    channel: HostChannel
    adapter: object
    gate: SwarmGate
    routes: frozenset[str]
    approval_ui: bool
    event_source: HostEventSource | None
    session: IntegrationSession | None = None
    active: ForwardTicket | None = None
    captured: tuple[SwarmDecision, dict[str, Any]] | None = None
    assessments: tuple[SwarmAssessment, ...] = ()
    source_sequence: int = 0
    journal_gap: bool = False
    active_route: str | None = None
    assessment_provider: Any = None
    lock: Any = field(default_factory=RLock)


@dataclass(frozen=True)
class _GatewayReviewGate(AgentGate):
    owner: Any = field(default=None, repr=False, compare=False)
    actor: Any = field(default=None, repr=False, compare=False)

    @property
    def session_configuration_binding(self):
        return {
            "namespace": "ordin.swarm.gateway.v1",
            "configuration_digest": self.actor.gate.configuration_digest,
            "source_digest": digest(self.actor.context.as_dict()),
        }

    def evaluate_action(self, action, **kwargs) -> AgentDecision:
        assessments = self.actor.assessments
        if self.actor.assessment_provider is not None:
            provider_options = dict(kwargs)
            if self.actor.gate._events is not None:
                provider_options["event_source"] = self.actor.event_source
            assessments = self.actor.assessment_provider(
                self.actor.context, action, self.actor.gate, provider_options
            )
        decision = self.actor.gate.evaluate_action(
            self.actor.context,
            action,
            channel=self.actor.channel,
            adapter=self.actor.adapter,
            event_source=self.actor.event_source if self.actor.gate._events is not None else None,
            assessments=assessments,
            **kwargs,
        )
        self.actor.captured = (decision, dict(kwargs))
        disposition = decision.disposition
        route = self.actor.active_route or (
            action.kind if action.kind in ROUTES else "http" if action.kind == "network" else "sdk"
        )
        if self.actor.journal_gap or (
            self.actor.context.coverage.mode not in {"intercept", "enforce"}
            or route not in self.actor.routes
        ):
            disposition = "deny"
        if decision.requires_approval and not self.actor.approval_ui:
            disposition = "deny"
        return AgentDecision(disposition, decision.review)


@dataclass
class _Pending:
    actor: GatewayAgent
    action: ActionEnvelope
    decision: SwarmDecision
    options: dict[str, Any]
    session_digest: str
    expires_at: float
    route: str


class SwarmToolGateway:
    """A protected mediator, not a sandbox for paths routed around it.

    Callers keep handles, channels and executors outside agent control. The
    executor is an explicit host-owned forwarding operation, never policy code.
    """

    def __init__(
        self,
        *,
        events: SwarmEventIngestor | None = None,
        max_agents: int = 256,
        max_pending: int = 256,
        ticket_lifetime: float = 30,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        for value in (max_agents, max_pending):
            if type(value) is not int or not 1 <= value <= 4096:
                raise ValueError("invalid bounded gateway capacity")
        if not 0 < timestamp(ticket_lifetime) <= 300 or not callable(clock):
            raise ValueError("invalid gateway ticket lifetime")
        if events is not None and type(events) is not SwarmEventIngestor:
            raise ValueError("gateway journal must be a protected event ingestor")
        self._events, self._limit, self._pending_limit = events, max_agents, max_pending
        self._lifetime, self._clock, self._last_now = float(ticket_lifetime), clock, 0.0
        self._actors: dict[GatewayAgent, _Actor] = {}
        self._pending: dict[ForwardTicket, _Pending] = {}
        self._lock = RLock()
        self._operation_lock = RLock()

    def _now(self) -> float:
        now = timestamp(self._clock())
        if now < self._last_now:
            raise ValueError("gateway clock moved backward")
        self._last_now = now
        return now

    def bind_agent(
        self,
        context: SwarmContext,
        gate: SwarmGate,
        channel: HostChannel,
        adapter: object,
        *,
        routes: frozenset[str],
        approval_ui: bool = False,
        assessment_provider: Callable[..., tuple[SwarmAssessment, ...]] | None = None,
    ) -> GatewayAgent:
        if type(gate) is not SwarmGate or type(approval_ui) is not bool:
            raise ValueError("gateway requires a protected gate and explicit approval capability")
        if assessment_provider is not None and not callable(assessment_provider):
            raise ValueError("assessment provider must be a protected host callable")
        if type(routes) is not frozenset or not routes <= ROUTES:
            raise ValueError("unknown gateway route")
        gate._registry.authenticate(context, channel, adapter)
        if isinstance(gate._baseline, DelegatingAssuranceGate):
            raise ValueError("delegated execution requires its action-bound broker integration")
        with self._lock:
            if len(self._actors) >= self._limit:
                raise ValueError("gateway agent capacity reached")
            if any(actor.context is context for actor in self._actors.values()):
                raise ValueError("duplicate gateway enrollment")
            if gate._events is not None and gate._events is not self._events:
                raise ValueError("gateway and decision evidence must share the protected ingestor")
            source = None
            if self._events is not None:
                source = self._events.bind_source(
                    context, channel, adapter, source_id="gateway-" + uuid4().hex
                )
            actor = _Actor(context, channel, adapter, gate, routes, approval_ui, source)
            actor.assessment_provider = assessment_provider
            baseline = gate._baseline
            ordin = baseline.ordin
            facade = _GatewayReviewGate(ordin=ordin, owner=self, actor=actor)
            handle = GatewayAgent(uuid4().hex)
            actor.session = IntegrationSession(
                SessionIdentity(
                    "ordin-swarm-gateway", context.identity.session_id, context.identity.runtime_id
                ),
                facade,
            )
            self._actors[handle] = actor
            return handle

    def _actor(self, handle: GatewayAgent, *, authenticate: bool = True) -> _Actor:
        if type(handle) is not GatewayAgent:
            raise ValueError("unknown protected gateway agent")
        actor = self._actors.get(handle)
        if actor is None:
            raise ValueError("unknown protected gateway agent")
        if authenticate:
            actor.gate._registry.authenticate(actor.context, actor.channel, actor.adapter)
        return actor

    def review_gate(self, handle: GatewayAgent) -> AgentGate:
        """Host adapter hook; returned gate retains actor/session binding."""
        actor = self._actor(handle)
        if actor.session is None:
            raise ValueError("uninitialized gateway session")
        return actor.session.gate

    def prepare(
        self,
        handle: GatewayAgent,
        action: ActionEnvelope | Mapping[str, Any],
        *,
        route: str = "sdk",
        assessments: tuple[SwarmAssessment, ...] = (),
    ) -> GatewayAuthorization:
        actor = self._actor(handle)
        if route not in ROUTES:
            raise ValueError("unknown forwarding route")
        normalized = ActionEnvelope.from_dict(
            action.as_dict() if isinstance(action, ActionEnvelope) else action
        )
        normalized = replace(normalized, action_id="swarm-" + uuid4().hex)
        with self._operation_lock, actor.lock:
            if actor.active is not None:
                raise ValueError("gateway actor already has an active forwarding attempt")
            if actor.session is None:
                raise ValueError("uninitialized gateway session")
            actor.assessments = assessments
            actor.active_route = route
            actor.captured = None
            try:
                baseline = actor.session.evaluate(normalized, approval_supported=actor.approval_ui)
            finally:
                actor.assessments = ()
                actor.active_route = None
            if actor.captured is None:
                raise ValueError("gateway did not capture its protected decision")
            decision, options = actor.captured
            disposition = baseline.disposition
            mediated = (
                actor.context.coverage.mode in {"intercept", "enforce"} and route in actor.routes
            )
            if not mediated or actor.journal_gap:
                disposition = "deny"
            ticket = None
            if disposition == "execute":
                with self._lock:
                    if len(self._pending) >= self._pending_limit:
                        raise ValueError("gateway forwarding capacity reached")
                    ticket = ForwardTicket(uuid4().hex)
                    self._pending[ticket] = _Pending(
                        handle,
                        normalized,
                        decision,
                        options,
                        digest(actor.session.snapshot()),
                        timestamp(self._now() + self._lifetime),
                        route,
                    )
                    actor.active = ticket
            if disposition != "execute":
                self._journal(
                    actor,
                    _Pending(
                        handle,
                        normalized,
                        decision,
                        options,
                        digest(actor.session.snapshot()),
                        self._now(),
                        route,
                    ),
                    "denied",
                    forwarded=False,
                )
            return GatewayAuthorization(
                disposition, normalized.action_id, digest(normalized.as_dict()), decision, ticket
            )

    def forward(
        self,
        handle: GatewayAgent,
        ticket: ForwardTicket,
        executor: Callable[[ActionEnvelope], Any],
        *,
        action: ActionEnvelope | None = None,
    ) -> GatewayResult:
        actor = self._actor(handle, authenticate=False)
        if not callable(executor):
            raise ValueError("forwarding requires an explicit host executor")
        with self._operation_lock, actor.lock:
            with self._lock:
                pending = self._pending.get(ticket) if type(ticket) is ForwardTicket else None
                if pending is None or pending.actor is not handle:
                    raise ValueError("unknown, foreign or consumed forwarding ticket")
                del self._pending[ticket]
            try:
                actor.gate._registry.authenticate(actor.context, actor.channel, actor.adapter)
                if actor.session is None or actor.active is not ticket:
                    raise ValueError("changed forwarding session")
                if self._now() >= pending.expires_at:
                    raise ValueError("expired forwarding ticket")
                selected = action if action is not None else pending.action
                if digest(selected.as_dict()) != pending.decision.action_digest:
                    raise ValueError("forwarding action changed")
                if digest(actor.session.snapshot()) != pending.session_digest:
                    raise ValueError("forwarding history changed")
                if not actor.gate.binding_matches(
                    pending.decision,
                    actor.context,
                    selected,
                    channel=actor.channel,
                    adapter=actor.adapter,
                    event_source=actor.event_source if actor.gate._events is not None else None,
                    **pending.options,
                ):
                    raise ValueError("stale forwarding decision")
                detached = ActionEnvelope.from_dict(selected.as_dict())
                if detached.action_id is None:
                    raise ValueError("forwarding requires its host action ID")
                try:
                    value = executor(detached)
                except Exception:
                    self._journal(actor, pending, "failed")
                    raise
                outcome = value.status if type(value) is GatewayOutcome else "completed"
                payload = value.value if type(value) is GatewayOutcome else value
                self._journal(actor, pending, outcome)
                return GatewayResult(detached.action_id, outcome, payload, actor.journal_gap)
            finally:
                actor.active = None

    def _journal(
        self, actor: _Actor, pending: _Pending, outcome: str, *, forwarded: bool = True
    ) -> None:
        if self._events is None or actor.event_source is None:
            return
        action_id = pending.action.action_id
        if action_id is None:
            raise ValueError("journaled forwarding requires a host action ID")
        previous: str | None = None
        review: str | None = None
        stages = (
            ("proposed", "reviewed", "reserved", "committed", "forwarded")
            if forwarded
            else ("proposed", "reviewed")
        )
        if outcome != "pending":
            stages = (*stages, outcome)
        for kind in stages:
            event_id = kind + "-" + action_id
            parents: tuple[str, ...] = () if previous is None else (previous,)
            if kind not in {"proposed", "reviewed"}:
                if review is None:
                    raise ValueError("journaled result lacks its reviewed anchor")
                parents = tuple(dict.fromkeys((review, *parents)))
            actor.source_sequence += 1
            try:
                self._events.ingest(
                    actor.event_source,
                    SwarmEvent(
                        event_id,
                        kind,
                        actor.context.registry_id,
                        actor.context.identity,
                        actor.event_source.source_id,
                        actor.source_sequence,
                        self._now(),
                        evidence_class="host_authenticated",
                        action_id=pending.action.action_id,
                        action_digest=pending.decision.action_digest,
                        review_event_id=review if kind not in {"proposed", "reviewed"} else None,
                        parent_event_ids=tuple(
                            EventRef(
                                actor.context.identity.tenant_id, actor.context.identity.swarm_id, p
                            )
                            for p in parents
                        ),
                    ),
                )
            except (ValueError, OSError):
                actor.journal_gap = True
                return
            if kind == "reviewed":
                review = event_id
            previous = event_id

    def status(self, handle: GatewayAgent) -> dict[str, Any]:
        actor = self._actor(handle)
        return {
            "schema_version": "ordin.swarm_gateway_status.v1",
            "identity": actor.context.identity.as_dict(),
            "mode": actor.context.coverage.mode,
            "routes": {
                route: (
                    "mediated"
                    if route in actor.routes
                    and actor.context.coverage.mode in {"intercept", "enforce"}
                    else "coverage_gap"
                )
                for route in sorted(ROUTES)
            },
            "active_attempt": actor.active is not None,
            "journal_gap": actor.journal_gap,
        }
