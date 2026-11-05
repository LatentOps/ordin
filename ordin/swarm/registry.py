"""Bounded, explicitly scoped in-memory enrollment; no discovery or background IO.

The owner is a trusted host, not agent code. This is an API trust boundary, not
protection from hostile code sharing the host's memory. Each registry owns one
tenant/swarm scope. Serialized contexts never authenticate, even after restart.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from threading import RLock
import time
from typing import Callable, Protocol, TYPE_CHECKING
from uuid import uuid4

from .identity import HostChannel
from .models import CoverageManifest, SwarmContext, SwarmIdentity, counter, identifier, timestamp

if TYPE_CHECKING:
    from ordin.assurance.delegation import DelegationIssuer, IssuedDelegation
    from ordin.assurance.host import HostEvidenceSource


class AgentRegistry(Protocol):
    def bind_channel(self, adapter: object, *, runtime_id: str) -> HostChannel: ...

    def enroll(
        self,
        channel: HostChannel,
        adapter: object,
        *,
        agent_id: str,
        session_id: str,
        task_id: str | None = None,
        parent_agent_id: str | None = None,
        delegation_id: str | None = None,
        coverage: CoverageManifest = CoverageManifest(),
    ) -> SwarmContext: ...

    def authenticate(
        self,
        context: SwarmContext,
        channel: HostChannel,
        adapter: object,
    ) -> SwarmContext: ...

    def heartbeat(self, context: SwarmContext, channel: HostChannel, adapter: object) -> None: ...

    def state(self, context: SwarmContext, channel: HostChannel, adapter: object) -> str: ...

    def pause(self, context: SwarmContext, channel: HostChannel, adapter: object) -> None: ...

    def end(self, context: SwarmContext, channel: HostChannel, adapter: object) -> None: ...

    def restart(
        self,
        context: SwarmContext,
        channel: HostChannel,
        adapter: object,
        *,
        new_channel: HostChannel,
        new_adapter: object,
        session_id: str,
        coverage: CoverageManifest = CoverageManifest(),
    ) -> SwarmContext: ...

    def advance_policy_epoch(self, epoch: int) -> None: ...

    def rebind_delegation(
        self,
        context: SwarmContext,
        channel: HostChannel,
        adapter: object,
        *,
        parent_context: SwarmContext,
        parent_channel: HostChannel,
        parent_adapter: object,
        issuer: DelegationIssuer,
        grant: IssuedDelegation,
        parent_source: HostEvidenceSource,
        child_source: HostEvidenceSource,
    ) -> SwarmContext: ...

    def forget_ended(
        self, context: SwarmContext, channel: HostChannel, adapter: object
    ) -> None: ...

    def close_channel(self, channel: HostChannel, adapter: object) -> None: ...


@dataclass
class _Agent:
    context: SwarmContext
    channel: HostChannel
    digest: str
    last_heartbeat: float
    phase: str = "active"


def _digest(context: SwarmContext) -> str:
    return hashlib.sha256(context._validated_bytes()).hexdigest()


class InMemoryAgentRegistry:
    def __init__(
        self,
        tenant_id: str,
        swarm_id: str,
        *,
        policy_epoch: int = 0,
        max_agents: int = 256,
        max_channels: int = 256,
        max_parent_depth: int = 16,
        heartbeat_timeout: float = 30,
        clock: Callable[[], float] = time.monotonic,
        registry_id: str | None = None,
    ) -> None:
        self._tenant = identifier(tenant_id, "tenant_id")
        self._swarm = identifier(swarm_id, "swarm_id")
        self._registry_id = identifier(
            uuid4().hex if registry_id is None else registry_id, "registry_id"
        )
        self._policy_epoch = counter(policy_epoch, "policy_epoch")
        for name, value, maximum in (
            ("max_agents", max_agents, 4096),
            ("max_channels", max_channels, 4096),
            ("max_parent_depth", max_parent_depth, 32),
        ):
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError(f"invalid {name}")
        if not 0 < timestamp(heartbeat_timeout) <= 3600 or not callable(clock):
            raise ValueError("invalid heartbeat configuration")
        self._max_agents, self._max_channels = max_agents, max_channels
        self._max_parent_depth = max_parent_depth
        self._timeout = float(heartbeat_timeout)
        self._clock = clock
        self._last_clock = 0.0
        self._generation = 0
        self._channels: dict[HostChannel, tuple[object, str]] = {}
        self._agents: dict[str, _Agent] = {}
        self._lock = RLock()
        self._policy_execution_barrier = RLock()

    def _now(self) -> float:
        now = timestamp(self._clock())
        if now < self._last_clock:
            raise ValueError("host clock moved backwards")
        self._last_clock = now
        return now

    def _channel(self, channel: HostChannel, adapter: object) -> str:
        if type(channel) is not HostChannel:
            raise ValueError("unknown protected host channel")
        binding = self._channels.get(channel)
        if (
            binding is None
            or binding[0] is not adapter
            or (channel.tenant_id, channel.swarm_id, channel.runtime_id)
            != (self._tenant, self._swarm, binding[1])
        ):
            raise ValueError("unknown, changed or cross-scope host channel")
        return binding[1]

    def bind_channel(self, adapter: object, *, runtime_id: str) -> HostChannel:
        """Host-only: bind an already verified adapter instance, not a claimed PID/ID."""
        identifier(runtime_id, "runtime_id")
        if adapter is None or isinstance(
            adapter, (str, bytes, int, float, bool, dict, list, tuple, set)
        ):
            raise ValueError("adapter must be a protected instance, not serialized identity")
        with self._lock:
            if len(self._channels) >= self._max_channels:
                raise ValueError("host channel limit reached")
            channel = HostChannel(self._tenant, self._swarm, runtime_id)
            self._channels[channel] = (adapter, runtime_id)
            return channel

    def _phase(self, record: _Agent, now: float) -> str:
        if record.phase == "active" and now - record.last_heartbeat >= self._timeout:
            return "stale"
        return record.phase

    def _parents(self, identity: SwarmIdentity, now: float) -> None:
        seen = {identity.agent_id}
        current = identity
        for _ in range(self._max_parent_depth):
            if current.parent_agent_id is None:
                return
            parent = self._agents.get(current.parent_agent_id)
            binding = self._channels.get(parent.channel) if parent is not None else None
            if (
                parent is None
                or binding is None
                or current.parent_agent_id in seen
                or self._phase(parent, now) != "active"
                or parent.context.identity.generation != current.parent_generation
                or parent.context.identity.policy_epoch != self._policy_epoch
                or _digest(parent.context) != parent.digest
            ):
                raise ValueError("missing, stale or changed parent identity")
            self._channel(parent.channel, binding[0])
            seen.add(current.parent_agent_id)
            current = parent.context.identity
        if current.parent_agent_id is not None:
            raise ValueError("parent depth limit reached")

    def _issue(
        self,
        channel: HostChannel,
        runtime: str,
        *,
        agent_id: str,
        session_id: str,
        task_id: str | None,
        parent_agent_id: str | None,
        delegation_id: str | None,
        coverage: CoverageManifest,
        now: float,
    ) -> SwarmContext:
        if type(coverage) is not CoverageManifest:
            raise ValueError("coverage requires an immutable host manifest")
        coverage.__post_init__()
        if any(entry.state == "physically_enforced" for entry in coverage.entries):
            raise ValueError(
                "enrollment alone cannot attest physical enforcement; broker receipt required"
            )
        if parent_agent_id is not None:
            identifier(parent_agent_id, "parent_agent_id")
        parent = self._agents.get(parent_agent_id) if parent_agent_id is not None else None
        identity = SwarmIdentity(
            self._tenant,
            self._swarm,
            agent_id,
            runtime,
            session_id,
            counter(self._generation + 1, "generation"),
            self._policy_epoch,
            parent_agent_id,
            parent.context.identity.generation if parent else None,
            task_id,
            delegation_id,
        )
        self._parents(identity, now)
        context = SwarmContext(self._registry_id, identity, coverage, now)
        record = _Agent(context, channel, _digest(context), now)
        self._generation = identity.generation
        self._agents[agent_id] = record
        return context

    def enroll(
        self,
        channel: HostChannel,
        adapter: object,
        *,
        agent_id: str,
        session_id: str,
        task_id: str | None = None,
        parent_agent_id: str | None = None,
        delegation_id: str | None = None,
        coverage: CoverageManifest = CoverageManifest(),
    ) -> SwarmContext:
        with self._lock:
            runtime = self._channel(channel, adapter)
            now = self._now()
            identifier(agent_id, "agent_id")
            if agent_id in self._agents:
                raise ValueError("duplicate principal; use explicit restart")
            if len(self._agents) >= self._max_agents:
                raise ValueError("principal limit reached")
            return self._issue(
                channel,
                runtime,
                agent_id=agent_id,
                session_id=session_id,
                task_id=task_id,
                parent_agent_id=parent_agent_id,
                delegation_id=delegation_id,
                coverage=coverage,
                now=now,
            )

    def _record(self, context: SwarmContext, channel: HostChannel, adapter: object) -> _Agent:
        self._channel(channel, adapter)
        if type(context) is not SwarmContext or type(context.identity) is not SwarmIdentity:
            raise ValueError("unknown principal context")
        record = self._agents.get(context.identity.agent_id)
        if record is None or record.context is not context or record.channel is not channel:
            raise ValueError("unknown, serialized, replaced or cross-channel principal")
        if _digest(context) != record.digest:
            raise ValueError("principal context was changed")
        return record

    def _live(
        self, context: SwarmContext, channel: HostChannel, adapter: object, now: float
    ) -> _Agent:
        record = self._record(context, channel, adapter)
        if (
            self._phase(record, now) != "active"
            or context.identity.policy_epoch != self._policy_epoch
        ):
            raise ValueError("principal is paused, ended, expired or from a stale policy epoch")
        self._parents(context.identity, now)
        return record

    def authenticate(
        self, context: SwarmContext, channel: HostChannel, adapter: object
    ) -> SwarmContext:
        with self._lock:
            self._live(context, channel, adapter, self._now())
            return context

    def heartbeat(self, context: SwarmContext, channel: HostChannel, adapter: object) -> None:
        with self._lock:
            now = self._now()
            record = self._live(context, channel, adapter, now)
            record.last_heartbeat = now

    def state(self, context: SwarmContext, channel: HostChannel, adapter: object) -> str:
        with self._lock:
            record = self._record(context, channel, adapter)
            now = self._now()
            phase = self._phase(record, now)
            if phase != "active":
                return phase
            if context.identity.policy_epoch != self._policy_epoch:
                return "stale"
            try:
                self._parents(context.identity, now)
            except ValueError:
                return "stale"
            return phase

    def pause(self, context: SwarmContext, channel: HostChannel, adapter: object) -> None:
        with self._lock:
            self._live(context, channel, adapter, self._now()).phase = "paused"

    def end(self, context: SwarmContext, channel: HostChannel, adapter: object) -> None:
        with self._lock:
            self._record(context, channel, adapter).phase = "ended"

    def restart(
        self,
        context: SwarmContext,
        channel: HostChannel,
        adapter: object,
        *,
        new_channel: HostChannel,
        new_adapter: object,
        session_id: str,
        coverage: CoverageManifest = CoverageManifest(),
    ) -> SwarmContext:
        with self._lock:
            self._record(context, channel, adapter)
            runtime = self._channel(new_channel, new_adapter)
            if session_id == context.identity.session_id:
                raise ValueError("restart requires a new session identity")
            identity = context.identity
            return self._issue(
                new_channel,
                runtime,
                agent_id=identity.agent_id,
                session_id=session_id,
                task_id=identity.task_id,
                parent_agent_id=identity.parent_agent_id,
                delegation_id=identity.delegation_id,
                coverage=coverage,
                now=self._now(),
            )

    def advance_policy_epoch(self, epoch: int) -> None:
        """Host-only fencing. Existing contexts stay stale until explicitly reissued."""
        counter(epoch, "policy_epoch")
        with self._lock:
            if epoch <= self._policy_epoch:
                raise ValueError("policy epoch must increase monotonically")
            self._policy_epoch = epoch

    def refresh_policy_context(
        self,
        context: SwarmContext,
        channel: HostChannel,
        adapter: object,
        *,
        coverage: CoverageManifest = CoverageManifest(),
    ) -> SwarmContext:
        """Host-only re-enrollment after fencing, preserving the physical session.

        Refresh live parents before children. Coverage requires fresh host
        verification and defaults to uncovered. This renews no delegated grant.
        """
        with self._lock:
            record = self._record(context, channel, adapter)
            now = self._now()
            if (
                self._phase(record, now) != "active"
                or context.identity.policy_epoch >= self._policy_epoch
            ):
                raise ValueError("only a live stale-policy context can be refreshed")
            identity = context.identity
            return self._issue(
                channel,
                self._channel(channel, adapter),
                agent_id=identity.agent_id,
                session_id=identity.session_id,
                task_id=identity.task_id,
                parent_agent_id=identity.parent_agent_id,
                delegation_id=identity.delegation_id,
                coverage=coverage,
                now=now,
            )

    def rebind_delegation(
        self,
        context: SwarmContext,
        channel: HostChannel,
        adapter: object,
        *,
        parent_context: SwarmContext,
        parent_channel: HostChannel,
        parent_adapter: object,
        issuer: DelegationIssuer,
        grant: IssuedDelegation,
        parent_source: HostEvidenceSource,
        child_source: HostEvidenceSource,
    ) -> SwarmContext:
        """Host-only current private grant binding, preserving the physical session.

        This increments the authorization generation and fences older contexts
        and descendant parent-generation references. It neither restarts the
        process nor turns a serialized grant ID into authority.
        """
        from ordin.assurance.delegation import DelegationIssuer, IssuedDelegation
        from ordin.assurance.delegated_paths import verify_current_delegation_relationship
        from ordin.assurance.host import HostEvidenceSource

        if (
            type(issuer) is not DelegationIssuer
            or type(grant) is not IssuedDelegation
            or type(parent_source) is not HostEvidenceSource
            or type(child_source) is not HostEvidenceSource
        ):
            raise ValueError("delegation rebind requires original protected issuer/source objects")
        with issuer._lock, self._lock:
            verify_current_delegation_relationship(issuer, grant, parent_source, child_source)
            now = self._now()
            child = self._record(context, channel, adapter)
            parent = self._live(parent_context, parent_channel, parent_adapter, now)
            identity = context.identity
            if (
                self._phase(child, now) != "active"
                or identity.policy_epoch != self._policy_epoch
                or identity.agent_id != grant.record.child_principal
                or parent.context.identity.agent_id != grant.record.parent_principal
                or child_source.epoch != identity.policy_epoch
                or (identity.tenant_id, identity.swarm_id, identity.task_id)
                != (
                    parent_context.identity.tenant_id,
                    parent_context.identity.swarm_id,
                    parent_context.identity.task_id,
                )
            ):
                raise ValueError("delegation rebind differs from live parent/child workload scope")
            if (
                identity.delegation_id == grant.record.grant_id
                and identity.parent_agent_id == parent_context.identity.agent_id
                and identity.parent_generation == parent_context.identity.generation
            ):
                return context
            return self._issue(
                channel,
                self._channel(channel, adapter),
                agent_id=identity.agent_id,
                session_id=identity.session_id,
                task_id=identity.task_id,
                parent_agent_id=parent_context.identity.agent_id,
                delegation_id=grant.record.grant_id,
                coverage=context.coverage,
                now=now,
            )

    def forget_ended(self, context: SwarmContext, channel: HostChannel, adapter: object) -> None:
        with self._lock:
            record = self._record(context, channel, adapter)
            if record.phase != "ended":
                raise ValueError("only ended principals can be forgotten")
            del self._agents[context.identity.agent_id]

    def close_channel(self, channel: HostChannel, adapter: object) -> None:
        """Fence all channel principals; retain the monotonic incarnation counter."""
        with self._lock:
            self._channel(channel, adapter)
            self._agents = {
                key: value for key, value in self._agents.items() if value.channel is not channel
            }
            del self._channels[channel]
