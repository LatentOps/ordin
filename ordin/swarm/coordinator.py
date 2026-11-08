"""Optional durable online authority for independently authenticated agent hosts.

Database state controls admissions and accounting. Original native grants,
decisions and broker authorizations stay private/live; stored JSON is historical
metadata and can never recreate those objects after restart.
"""

from __future__ import annotations

from contextlib import nullcontext
from dataclasses import dataclass, field
import json
import ssl
import struct
import time
from threading import RLock
from typing import TYPE_CHECKING, Any, Callable, Mapping
from uuid import uuid4

from ordin.action import ActionEnvelope
from ordin._runtime_json import digest

from .budgets import (
    BudgetCost,
    BudgetError,
    BudgetObservationSource,
    BudgetPolicy,
    _resolve_budget_costs,
    _select_budget_buckets,
)
from .coordinator_store import (
    CoordinatorClock,
    CoordinatorRejected,
    CoordinatorTransaction,
    CoordinatorUnavailable,
    PostgresCoordinatorStore,
    SQLiteCoordinatorStore,
    _active_transaction,
)
from .delegation import SwarmDelegationService
from .events import REVIEW_BOUND_STAGES, SwarmEvent, _hex
from .models import counter, identifier, timestamp
from .registry import InMemoryAgentRegistry
from .workload_auth import AuthorityChannel, WorkloadAuthenticator

if TYPE_CHECKING:
    from .broker import SwarmExecutionBroker
    from .ingest import HostEventSource
    from .memory import ArtifactAddress, ArtifactGrant, SwarmArtifact, SwarmArtifactGateway
    from .policy_runtime import SwarmPolicyRuntime
    from .source_flow import LineageHandle
    from .temporal import SwarmTemporalEngine


def _action_fence_key(action_digest: str, actor_digest: str | None = None) -> str:
    return (
        action_digest
        if actor_digest is None
        else digest(["ordin.swarm.actor_action_fence.v1", actor_digest, action_digest])
    )


@dataclass(frozen=True, eq=False, slots=True)
class CoordinatorControlSource:
    source_id: str


@dataclass(frozen=True, eq=False, slots=True)
class CoordinatorScope:
    scope_key: str


@dataclass(frozen=True, eq=False, slots=True)
class CoordinatorFenceReceipt:
    scope_digest: str
    revocation_epoch: int
    intent_digest: str
    policy_epoch: int
    owner_fence: int

    def as_dict(self):
        return {
            "schema_version": "ordin.swarm_coordinator_fence.v1",
            "scope_digest": self.scope_digest,
            "revocation_epoch": self.revocation_epoch,
            "intent_digest": self.intent_digest,
            "policy_epoch": self.policy_epoch,
            "owner_fence": self.owner_fence,
            "execution_authority": False,
            "physical_enforcement": False,
        }


@dataclass(frozen=True, slots=True)
class CoordinatorRecord:
    kind: str
    reference: str | None = field(repr=False)
    scope_digest: str
    subject_digest: str | None
    policy_epoch: int
    owner_fence: int
    expires_at: float | None
    status: str
    action_digest: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "ordin.swarm_coordinator_record.v1",
            "kind": self.kind,
            "reference_digest": digest(self.reference) if self.reference else None,
            "scope_digest": self.scope_digest,
            "subject_digest": self.subject_digest,
            "policy_epoch": self.policy_epoch,
            "owner_fence": self.owner_fence,
            "expires_at": self.expires_at,
            "status": self.status,
            "action_digest": self.action_digest,
            "requires_online_authority": True,
            "execution_authority": False,
        }

    def to_wire(self) -> dict[str, Any]:
        return {**self.as_dict(), "reference": self.reference}


@dataclass(frozen=True, slots=True)
class CoordinatorDispatch:
    status: str
    reservation_digest: str
    action_digest: str
    reason_code: str
    value: Any = field(default=None, repr=False, compare=False)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "ordin.swarm_coordinator_dispatch.v1",
            "status": self.status,
            "reservation_digest": self.reservation_digest,
            "action_digest": self.action_digest,
            "reason_code": self.reason_code,
            "physical_enforcement": False,
            "runtime_evidence": "separate_broker_boundary",
            "execution_authority": False,
        }


@dataclass
class _Scope:
    native: SwarmDelegationService
    budget: BudgetPolicy
    tenant_id: str
    swarm_id: str
    broker_channels: dict[str, AuthorityChannel]
    runtime: Any = None
    brokers: dict[str, Any] = field(default_factory=dict)
    artifacts: Any = None
    temporal: Any = None

    @property
    def authenticator(self) -> WorkloadAuthenticator:
        return self.native.authenticator


@dataclass(frozen=True)
class _Prepared:
    scope: CoordinatorScope
    subject: str
    action_digest: str
    native_id: str | None
    broker: Any = field(repr=False)
    authorization: Any = field(repr=False)
    action: ActionEnvelope = field(repr=False)


@dataclass(frozen=True, eq=False, slots=True)
class CoordinatorBudgetView:
    """Original read-only DB budget binding; never a reservation or executor."""

    _coordinator: Any = field(repr=False)
    _handle: CoordinatorScope = field(repr=False)

    @property
    def authority_binding_digest(self):
        scope = self._coordinator._scope(self._handle)
        return digest(
            [self._coordinator.store.identity, self._handle.scope_key, scope.budget.digest]
        )

    @property
    def admission_available(self):
        coordinator, handle = self._coordinator, self._handle

        def read(transaction):
            coordinator._owner(transaction, handle)
            return True

        try:
            active = _active_transaction.get()
            if active is not None:
                return active[0] is coordinator.store and read(active[2])
            with coordinator.store.transaction() as transaction:
                return read(transaction)
        except ValueError:
            return False

    def snapshot_digest(self, context, *, channel, adapter):
        coordinator, handle = self._coordinator, self._handle
        scope = coordinator._scope(handle)
        if (
            self not in coordinator._budget_views
            or scope.runtime is None
            or scope.runtime._registry is not scope.authenticator._registry
        ):
            raise CoordinatorRejected("coordinator.original_budget_view_required")
        scope.authenticator._registry.authenticate(context, channel, adapter)

        def read(transaction):
            state = transaction.scope(handle.scope_key)
            if (
                state["owner"]["id"] != coordinator._instance
                or transaction.now >= state["owner"]["expires_at"]
            ):
                raise CoordinatorRejected("coordinator.budget_authority_unavailable")
            matches = [
                row
                for row in scope.authenticator._enrollments.values()
                if row.context is context and row.role == "workload"
            ]
            if len(matches) != 1:
                raise CoordinatorRejected("coordinator.original_budget_context_required")
            return digest(coordinator._budget_report(transaction, scope, state, matches[0]))

        active = _active_transaction.get()
        if active is not None:
            if active[0] is not coordinator.store:
                raise CoordinatorRejected("coordinator.budget_store_mismatch")
            return read(active[2])
        with coordinator.store.transaction() as transaction:
            return read(transaction)


def _new_scope(key, tenant, swarm, epoch, selection, binding, budget):
    return {
        "version": 1,
        "scope_key": key,
        "tenant_digest": digest(tenant),
        "swarm_digest": digest(swarm),
        "policy_epoch": epoch,
        "policy_digest": selection,
        "runtime_binding": binding,
        "budget_digest": budget.digest,
        "owner": {"id": None, "fence": 0, "expires_at": 0},
        "subjects": {},
        "grants": {},
        "evaluations": {},
        "reservations": {},
        "events": {},
        "streams": {},
        "artifact_floors": {},
        "artifact_pending": [],
        "temporal_projection": None,
        "sequence": 0,
        "journal_head": "0" * 64,
        "checkpoint_sequence": 0,
        "checkpoint_digest": None,
        "incomplete": False,
        "event_incomplete": False,
        "prehistory": "unknown",
        "revocation_epoch": 0,
        "fences": {},
        "blocked_actions": [],
    }


def _bucket_checksum(row: Mapping[str, Any]) -> str:
    return digest(
        [
            row[key]
            for key in (
                "bucket",
                "tenant_digest",
                "metric",
                "maximum",
                "held",
                "consumed",
                "observed",
                "blocked_epoch",
            )
        ]
    )


def _bucket(connection, key):
    row = connection.execute("SELECT * FROM coordinator_buckets WHERE bucket=?", (key,)).fetchone()
    if row is not None and (
        any(
            type(row[name]) is not int or not 0 <= row[name] <= 10**15
            for name in ("maximum", "held", "consumed", "observed")
        )
        or row["checksum"] != _bucket_checksum(row)
    ):
        raise CoordinatorUnavailable("coordinator budget history changed")
    return row


def _save_bucket(connection, row):
    connection.execute(
        "UPDATE coordinator_buckets SET maximum=?,held=?,consumed=?,observed=?,blocked_epoch=?,checksum=? WHERE bucket=?",
        (
            row["maximum"],
            row["held"],
            row["consumed"],
            row["observed"],
            row["blocked_epoch"],
            _bucket_checksum(row),
            row["bucket"],
        ),
    )


def _barrier_checksum(key, epoch, state, intent):
    return digest([key, epoch, state, intent])


def _barrier(connection, key):
    row = connection.execute(
        "SELECT * FROM coordinator_barriers WHERE realm_key=?", (key,)
    ).fetchone()
    if row is not None:
        if (
            type(row["epoch"]) is not int
            or not 0 < row["epoch"] < 2**53
            or row["state"] not in {"blocked", "reconciled"}
            or row["checksum"]
            != _barrier_checksum(key, row["epoch"], row["state"], row["intent_digest"])
        ):
            raise CoordinatorUnavailable("coordinator containment barrier history changed")
        _hex(row["intent_digest"], "coordinator containment intent")
    return row


class SwarmCoordinator:
    """Host-owned optional coordinator; local locks never grant hard authority."""

    def __init__(
        self,
        store: SQLiteCoordinatorStore | PostgresCoordinatorStore,
        *,
        operator: object,
        clock: CoordinatorClock | None = None,
        lease_lifetime: float = 10,
        owner_lifetime: float = 30,
        max_records: int = 4096,
        max_events: int = 2048,
        max_journal_lag: int = 128,
        settlements: BudgetObservationSource | None = None,
    ) -> None:
        if (
            type(store) not in {SQLiteCoordinatorStore, PostgresCoordinatorStore}
            or type(operator) is not object
        ):
            raise ValueError("original protected coordinator database and operator required")
        if (
            not 1 <= timestamp(lease_lifetime) <= 30
            or not lease_lifetime <= timestamp(owner_lifetime) <= 60
        ):
            raise ValueError("invalid bounded coordinator leases")
        if any(
            type(value) is not int or not 1 <= value <= maximum
            for value, maximum in (
                (max_records, 16384),
                (max_events, 4096),
                (max_journal_lag, 4096),
            )
        ):
            raise ValueError("invalid bounded coordinator history")
        if settlements is not None and type(settlements) is not BudgetObservationSource:
            raise ValueError("original protected settlement source required")
        if clock is not None and (type(clock) is not CoordinatorClock or clock._store is not store):
            raise ValueError("coordinator clock must be its original DB clock")
        self.store, self.clock = store, clock or CoordinatorClock(store)
        self._operator, self._control = operator, CoordinatorControlSource(uuid4().hex)
        self._instance = uuid4().hex + uuid4().hex
        self._lease_lifetime, self._owner_lifetime = lease_lifetime, owner_lifetime
        self._limit, self._event_limit, self._lag_limit = max_records, max_events, max_journal_lag
        self._settlements = settlements
        self._scopes: dict[CoordinatorScope, _Scope] = {}
        self._prepared: dict[str, _Prepared] = {}
        self._audit_sources: dict[CoordinatorScope, Any] = {}
        self._retired_prepared: dict[str, _Prepared] = {}
        # Each entry corresponds to an existing bounded durable reservation;
        # these original objects are never reconstructed from checkpoint JSON.
        self._completed_prepared: dict[str, _Prepared] = {}
        self._fence_receipts: dict[CoordinatorFenceReceipt, str] = {}
        self._recovery_verifiers: dict[CoordinatorScope, Any] = {}
        self._budget_views: set[CoordinatorBudgetView] = set()
        self._available, self._lock = True, RLock()

    def control_source(self, *, operator: object) -> CoordinatorControlSource:
        if operator is not self._operator:
            raise ValueError("original protected operator required")
        return self._control

    def _control_check(self, source):
        if source is not self._control:
            raise ValueError("original coordinator server control source required")

    def bind_audit(
        self, handle: CoordinatorScope, source, *, control: CoordinatorControlSource
    ) -> None:
        from .diagnostics import SwarmAuditSource

        self._control_check(control)
        self._scope(handle)
        if (
            type(source) is not SwarmAuditSource
            or source._coordinator is not self
            or source._scope is not handle
        ):
            raise ValueError("original coordinator audit binding required")
        self._audit_sources[handle] = source

    def _emit_audit(self, handle, record):
        source = self._audit_sources.get(handle)
        if source is not None:
            try:
                source.record_coordinator(self, handle, record)
            except (ValueError, OSError, RuntimeError):
                source._fault = True

    def _scope(self, handle: CoordinatorScope) -> _Scope:
        if type(handle) is not CoordinatorScope or handle not in self._scopes:
            raise ValueError("unknown original coordinator scope")
        return self._scopes[handle]

    def register_scope(
        self,
        native: SwarmDelegationService,
        budget: BudgetPolicy,
        *,
        control: CoordinatorControlSource,
        broker_channels: tuple[AuthorityChannel, ...],
        runtime: SwarmPolicyRuntime | None = None,
        brokers: tuple[tuple[str, SwarmExecutionBroker], ...] = (),
        artifacts: SwarmArtifactGateway | None = None,
        temporal: SwarmTemporalEngine | None = None,
    ) -> CoordinatorScope:
        self._control_check(control)
        if (
            type(native) is not SwarmDelegationService
            or type(budget) is not BudgetPolicy
            or type(broker_channels) is not tuple
            or not 1 <= len(broker_channels) <= 64
        ):
            raise ValueError("original native authority, budget and broker channels required")
        auth = native.authenticator
        registry = auth._registry
        if type(registry) is not InMemoryAgentRegistry:
            raise ValueError("original coordinator registry required")
        if (
            auth._clock is not self.clock
            or registry._clock is not self.clock
            or native.issuer._clock is not self.clock
        ):
            raise ValueError(
                "registry, issuer and workload authentication must share the original DB clock"
            )
        if (
            native._operator is not self._operator
            or auth._operator is not self._operator
            or auth._scope is None
        ):
            raise ValueError("coordinator native scope/operator is not bound")
        if runtime is not None:
            from .policy_runtime import SwarmPolicyRuntime

            if (
                type(runtime) is not SwarmPolicyRuntime
                or runtime._clock is not self.clock
                or runtime.facts_source._clock is not self.clock
            ):
                raise ValueError("original policy runtime and same DB clock required")
            required = (
                runtime._active.budget_limits
                if runtime._active and runtime._active.budget_limits
                else runtime._budget.policy.limits
                if runtime._budget
                else runtime.maximum.budget_limits
            )
            selected_limits = {
                (limit.scope, limit.metric, limit.subject): limit for limit in budget.limits
            }
            for limit in required:
                candidate = selected_limits.get((limit.scope, limit.metric, limit.subject))
                if (
                    candidate is None
                    or candidate.maximum > limit.maximum
                    or candidate.unknown_ceiling != limit.unknown_ceiling
                    or limit.unknown_effects
                    and (
                        not candidate.unknown_effects
                        or not set(candidate.unknown_effects) <= set(limit.unknown_effects)
                    )
                ):
                    raise ValueError("coordinator budget exceeds or omits approved policy limits")
        if artifacts is not None:
            from .memory import SwarmArtifactGateway

            if (
                type(artifacts) is not SwarmArtifactGateway
                or artifacts._clock is not self.clock
                or artifacts._ingest._registry is not registry
            ):
                raise ValueError("original artifact gateway and same DB clock required")
        if temporal is not None:
            from .temporal import SwarmTemporalEngine

            if (
                type(temporal) is not SwarmTemporalEngine
                or temporal._clock is not self.clock
                or temporal._graph._ingestor._registry is not registry
            ):
                raise ValueError("original temporal engine and same DB clock required")
        tenant, swarm, _ = auth._scope
        if budget.policy_epoch != registry._policy_epoch:
            raise ValueError("coordinator budget/current registry epoch mismatch")
        pins = {}
        for channel in broker_channels:
            enrollment = auth.require(channel, role="broker")
            if enrollment.host_id in pins:
                raise ValueError("duplicate coordinator broker host")
            pins[enrollment.host_id] = channel
        configured = {}
        if brokers:
            from .broker import SwarmExecutionBroker

            for host, broker in brokers:
                if (
                    type(host) is not str
                    or host not in pins
                    or type(broker) is not SwarmExecutionBroker
                    or host in configured
                ):
                    raise ValueError("original enforcing broker required")
                configured[host] = broker
        with self._lock:
            key = digest(["ordin.coordinator.scope.v1", tenant, swarm, auth._scope[2]])
            if len(self._scopes) >= 64 or any(item.scope_key == key for item in self._scopes):
                raise ValueError("duplicate coordinator scope or capacity reached")
            handle = CoordinatorScope(key)
            self._scopes[handle] = _Scope(
                native, budget, tenant, swarm, pins, runtime, configured, artifacts, temporal
            )
            return handle

    @staticmethod
    def _policy(scope):
        if scope.runtime is None:
            selected = digest(
                [
                    scope.native.assurance.approved_profile.digest,
                    scope.native.assurance.configuration_digest,
                    scope.budget.digest,
                ]
            )
            return scope.budget.policy_epoch, selected, selected
        epoch, selected, binding = (
            scope.runtime.epoch,
            scope.runtime.selection_digest,
            scope.runtime.binding_digest,
        )
        if selected is None or scope.runtime.active_policy_digest is None:
            raise CoordinatorRejected("coordinator.policy_unavailable")
        return epoch, selected, binding

    def initialize_scope(
        self, handle: CoordinatorScope, *, control: CoordinatorControlSource
    ) -> None:
        self._control_check(control)
        scope = self._scope(handle)
        epoch, selected, binding = self._policy(scope)
        with self.store.transaction() as transaction:
            transaction.create_scope(
                handle.scope_key,
                _new_scope(
                    handle.scope_key,
                    scope.tenant_id,
                    scope.swarm_id,
                    epoch,
                    selected,
                    binding,
                    scope.budget,
                ),
            )

    @staticmethod
    def _realms(scope):
        return (
            digest(["tenant", scope.tenant_id]),
            digest(["swarm", scope.tenant_id, scope.swarm_id]),
            digest(["task", scope.tenant_id, scope.swarm_id, scope.authenticator._scope[2]]),
        )

    def _owner(
        self, transaction, handle, *, allow_incomplete=False, allow_contained=False, expire=True
    ):
        if not self._available:
            raise CoordinatorUnavailable("coordinator requires online recovery")
        scope = self._scope(handle)
        state = transaction.scope(handle.scope_key)
        transaction.verify_journal_head(handle.scope_key)
        if not allow_contained:
            for realm in self._realms(scope):
                barrier = _barrier(transaction.connection, realm)
                if barrier is not None and barrier["state"] == "blocked":
                    raise CoordinatorRejected("coordinator.scope_contained")
        epoch, selected, binding = self._policy(scope)
        if (
            state["owner"]["id"] != self._instance
            or transaction.now >= state["owner"]["expires_at"]
        ):
            raise CoordinatorRejected("coordinator.owner_lease_fenced_or_expired")
        if (
            state["policy_epoch"],
            state["policy_digest"],
            state["runtime_binding"],
            state["budget_digest"],
        ) != (epoch, selected, binding, scope.budget.digest):
            raise CoordinatorRejected("coordinator.policy_snapshot_stale")
        if not allow_incomplete and (
            state["incomplete"]
            or state["event_incomplete"]
            or state["artifact_pending"]
            or state["sequence"] - state["checkpoint_sequence"] > self._lag_limit
        ):
            raise CoordinatorRejected("coordinator.history_incomplete_or_projection_lag")
        if not allow_incomplete:
            self._check_artifacts(scope, state)
            self._check_temporal(scope, state)
        if expire:
            self._expire(transaction, state)
        return scope, state

    @staticmethod
    def _release(transaction, state, reservation, status):
        for item in transaction.connection.execute(
            "SELECT * FROM coordinator_items WHERE scope_key=? AND reservation_id=?",
            (state["scope_key"], reservation["id"]),
        ).fetchall():
            row = _bucket(transaction.connection, item["bucket"])
            if row is None or row["held"] < item["amount"]:
                raise CoordinatorUnavailable("coordinator budget hold history missing")
            updated = dict(row)
            updated["held"] -= item["amount"]
            _save_bucket(transaction.connection, updated)
        reservation["status"] = status

    def _expire(self, transaction, state):
        for reservation in state["reservations"].values():
            if transaction.now >= reservation["expires_at"]:
                if reservation["status"] in {"preparing", "reserved"}:
                    self._release(transaction, state, reservation, "expired")
                elif reservation["status"] == "forwarding":
                    reservation["status"] = "uncertain"

    def start(
        self, handle: CoordinatorScope, *, control: CoordinatorControlSource, takeover: bool = False
    ) -> dict[str, Any]:
        self._control_check(control)
        if type(takeover) is not bool:
            raise ValueError("invalid coordinator takeover flag")
        scope = self._scope(handle)
        if scope.runtime is not None:
            view = scope.runtime._coordinator_budget
            if view not in self._budget_views or view._handle is not handle:
                raise CoordinatorRejected("coordinator.current_protected_budget_view_required")
        with self.store.transaction() as transaction:
            state = transaction.scope(handle.scope_key)
            epoch, selected, binding = self._policy(scope)
            transaction.verify_journal_head(handle.scope_key)
            if epoch < state["policy_epoch"] or (
                epoch == state["policy_epoch"] and selected != state["policy_digest"]
            ):
                raise CoordinatorRejected("coordinator.recovery_policy_mismatch")
            owner = state["owner"]
            if (
                owner["id"] == self._instance
                and transaction.now < owner["expires_at"]
                and self._available
                and not takeover
            ):
                return self._status(transaction, handle, state)
            if owner["id"] is not None and transaction.now < owner["expires_at"] and not takeover:
                raise CoordinatorRejected("coordinator.active_owner_exists")
            owner["id"], owner["fence"], owner["expires_at"] = (
                self._instance,
                counter(owner["fence"] + 1, "coordinator fence"),
                transaction.now + self._owner_lifetime,
            )
            state["policy_epoch"], state["policy_digest"], state["runtime_binding"] = (
                epoch,
                selected,
                binding,
            )
            state["budget_digest"] = scope.budget.digest
            for subject in state["subjects"].values():
                subject["lease_expires_at"] = 0
            for grant in state["grants"].values():
                if grant["status"] != "revoked":
                    grant["status"] = "requires_revalidation"
            for evaluation in state["evaluations"].values():
                evaluation["status"] = "stale"
            for reservation in state["reservations"].values():
                if reservation["status"] in {"preparing", "reserved"}:
                    self._release(transaction, state, reservation, "canceled")
                elif reservation["status"] == "forwarding":
                    reservation["status"] = "uncertain"
            transaction.append(
                handle.scope_key,
                "owner_started",
                self._instance,
                {"owner_fence": owner["fence"], "policy_epoch": epoch},
                maximum=self._limit,
            )
            result = self._status(transaction, handle, state)
        with self._lock:
            for key, prepared in tuple(self._completed_prepared.items()):
                if prepared.scope is handle:
                    del self._completed_prepared[key]
            for key, prepared in tuple(self._prepared.items()):
                if prepared.scope is handle:
                    if prepared.broker is not None and state["reservations"].get(key, {}).get(
                        "status"
                    ) in {"uncertain", "forwarding"}:
                        self._retired_prepared[key] = prepared
                    del self._prepared[key]
        self._available = True
        return result

    def heartbeat(
        self, handle: CoordinatorScope, *, control: CoordinatorControlSource
    ) -> dict[str, Any]:
        self._control_check(control)
        with self.store.transaction() as transaction:
            _, state = self._owner(transaction, handle, allow_incomplete=True, allow_contained=True)
            state["owner"]["expires_at"] = transaction.now + self._owner_lifetime
            transaction.append(
                handle.scope_key,
                "owner_renewed",
                self._instance,
                {"owner_fence": state["owner"]["fence"]},
                maximum=self._limit,
            )
            return self._status(transaction, handle, state)

    def refresh_broker_channel(
        self,
        handle: CoordinatorScope,
        channel: AuthorityChannel,
        *,
        control: CoordinatorControlSource,
        operator: object,
        expected_owner_fence: int,
    ) -> None:
        """Refresh original broker transport without renewing workload or approval authority."""
        from .broker import SwarmExecutionBroker

        self._control_check(control)
        if (
            operator is not self._operator
            or type(expected_owner_fence) is not int
            or expected_owner_fence < 1
        ):
            raise CoordinatorRejected("original broker refresh owner control required")
        scope = self._scope(handle)
        enrolled = scope.authenticator.require(channel, role="broker")
        broker = scope.brokers.get(enrolled.host_id)
        if (
            type(broker) is not SwarmExecutionBroker
            or broker._operator is not operator
            or broker._service is not scope.native
        ):
            raise CoordinatorRejected("original registered broker refresh required")
        with self._containment_barrier(scope), broker._barrier(), broker._execution_lock:
            with broker._state_lock:
                if any(
                    row.state in {"prepared", "checking", "forwarding"}
                    for row in broker._pending.values()
                ):
                    raise CoordinatorRejected("broker transport refresh requires no pending work")
            with self.store.transaction() as transaction:
                _, state = self._owner(transaction, handle)
                current = scope.authenticator.require(channel, role="broker")
                if (
                    state["owner"]["fence"] != expected_owner_fence
                    or current is not enrolled
                    or current is not broker._broker_enrollment
                    or scope.authenticator.enrollment(current.enrollment_id) is not current
                    or scope.broker_channels.get(current.host_id) is not broker._broker_channel
                ):
                    raise CoordinatorRejected("broker refresh identity, pin or owner fence changed")
                transaction.append(
                    handle.scope_key,
                    "broker_transport_refreshed",
                    digest(current.enrollment_id),
                    {"host_digest": digest(current.host_id), "owner_fence": expected_owner_fence},
                    maximum=self._limit,
                )
            # Both live transport pins move together only after durable ACK.
            broker.refresh_broker_channel(channel, operator=operator)
            scope.broker_channels[current.host_id] = channel

    def _subject(self, handle, channel):
        scope = self._scope(handle)
        enrollment = scope.authenticator.require(channel, role="workload")
        context = enrollment.context
        if context is None or (context.identity.tenant_id, context.identity.swarm_id) != (
            scope.tenant_id,
            scope.swarm_id,
        ):
            raise CoordinatorRejected("coordinator.workload_scope_mismatch")
        return (
            scope,
            enrollment,
            digest([scope.tenant_id, scope.swarm_id, context.identity.agent_id]),
        )

    def admit(self, handle: CoordinatorScope, channel: AuthorityChannel) -> CoordinatorRecord:
        scope, enrollment, subject_key = self._subject(handle, channel)
        context = enrollment.context
        with self.store.transaction() as transaction:
            _, state = self._owner(transaction, handle)
            subjects = state["subjects"]
            old = subjects.get(subject_key)
            if old is not None and old["revoked"]:
                raise CoordinatorRejected("coordinator.workload_revoked")
            context_digest = digest(context.as_dict())
            if old is None:
                if len(subjects) >= 4096:
                    raise CoordinatorRejected("coordinator.workload_capacity")
                old = subjects[subject_key] = {
                    "generation": 0,
                    "revoked": False,
                    "context_digest": None,
                }
            if (
                old["context_digest"] != context_digest
                or transaction.now >= old.get("lease_expires_at", 0)
                or old.get("owner_fence") != state["owner"]["fence"]
            ):
                old.update(
                    generation=counter(old["generation"] + 1, "workload generation"),
                    lease_id=uuid4().hex + uuid4().hex,
                    context_digest=context_digest,
                    certificate_digest=enrollment.certificate_digest,
                    host_id=enrollment.host_id,
                    owner_fence=state["owner"]["fence"],
                    policy_epoch=state["policy_epoch"],
                    producer=digest([subject_key, context_digest, enrollment.certificate_digest]),
                    event_source="coordinator-"
                    + digest([subject_key, context_digest, enrollment.certificate_digest])[:32],
                    continuity="unknown",
                    parent_subject=digest(
                        [scope.tenant_id, scope.swarm_id, context.identity.parent_agent_id]
                    )
                    if context.identity.parent_agent_id
                    else None,
                    task_digest=digest(context.identity.task_id),
                )
            old["lease_expires_at"] = min(
                transaction.now + self._lease_lifetime, state["owner"]["expires_at"]
            )
            transaction.append(
                handle.scope_key,
                "workload_admitted",
                subject_key,
                {"subject_digest": subject_key, "generation": old["generation"]},
                maximum=self._limit,
            )
            return self._record(
                "lease",
                old["lease_id"],
                handle,
                subject_key,
                state,
                old["lease_expires_at"],
                "current",
            )

    @staticmethod
    def _record(kind, reference, handle, subject, state, expires, status, action=None):
        return CoordinatorRecord(
            kind,
            reference,
            handle.scope_key,
            subject,
            state["policy_epoch"],
            state["owner"]["fence"],
            expires,
            status,
            action,
        )

    def _lease(self, transaction, handle, channel, lease_id, *, allow_incomplete=False):
        scope, enrollment, subject_key = self._subject(handle, channel)
        _, state = self._owner(transaction, handle, allow_incomplete=allow_incomplete)
        row = state["subjects"].get(subject_key)
        if (
            row is None
            or row["revoked"]
            or row.get("lease_id") != lease_id
            or row["context_digest"] != digest(enrollment.context.as_dict())
            or row["certificate_digest"] != enrollment.certificate_digest
            or row["host_id"] != enrollment.host_id
            or row["policy_epoch"] != state["policy_epoch"]
            or row["owner_fence"] != state["owner"]["fence"]
            or transaction.now >= row["lease_expires_at"]
        ):
            raise CoordinatorRejected("coordinator.workload_lease_stale_or_foreign")
        return scope, state, enrollment, subject_key, row

    def bind_grant(
        self,
        handle: CoordinatorScope,
        channel: AuthorityChannel,
        lease_id: str,
        native_reference: str,
    ) -> CoordinatorRecord:
        scope, _, _ = self._subject(handle, channel)
        metadata = scope.native.require_current(channel, native_reference)
        with self.store.transaction() as transaction:
            _, state, enrollment, subject, lease = self._lease(
                transaction, handle, channel, lease_id
            )
            key = digest(native_reference)
            previous = state["grants"].get(key)
            if previous is not None and previous["status"] == "revoked":
                raise CoordinatorRejected("coordinator.grant_revoked")
            if previous is None and len(state["grants"]) >= self._limit:
                raise CoordinatorRejected("coordinator.grant_history_capacity")
            remaining = metadata.expires_at - scope.native.issuer._now()
            if remaining <= 0 or metadata.policy_epoch != state["policy_epoch"]:
                raise CoordinatorRejected("coordinator.native_grant_stale")
            original = scope.native._grants[native_reference]
            if (
                original.parent_ref is not None
                and enrollment.context.identity.delegation_id != original.handle.record.grant_id
            ):
                raise CoordinatorRejected("coordinator.delegation_context_binding_required")
            state["grants"][key] = {
                "native_reference": native_reference,
                "subject": subject,
                "subject_generation": lease["generation"],
                "authority_digest": metadata.authority_digest,
                "parent_digest": digest(original.parent_ref) if original.parent_ref else None,
                "policy_epoch": state["policy_epoch"],
                "owner_fence": state["owner"]["fence"],
                "expires_at": transaction.now + remaining,
                "status": "current",
            }
            transaction.append(
                handle.scope_key,
                "grant_bound",
                key,
                {"subject_digest": subject, "authority_digest": metadata.authority_digest},
                maximum=self._limit,
            )
            return self._record(
                "grant", key, handle, subject, state, transaction.now + remaining, "current"
            )

    def _grant(self, state, subject, lease, reference, now):
        key = digest(reference)
        row = state["grants"].get(key)
        if (
            row is None
            or row["status"] != "current"
            or row["subject"] != subject
            or row["subject_generation"] != lease["generation"]
            or row["owner_fence"] != state["owner"]["fence"]
            or row["policy_epoch"] != state["policy_epoch"]
            or now >= row["expires_at"]
        ):
            raise CoordinatorRejected("coordinator.current_native_grant_required")
        current = row
        seen: set[str] = set()
        while current is not None:
            key = current["parent_digest"]
            owner = state["subjects"].get(current["subject"])
            if (
                owner is None
                or owner["revoked"]
                or now >= owner["lease_expires_at"]
                or owner["generation"] != current["subject_generation"]
                or current["status"] != "current"
                or current["owner_fence"] != state["owner"]["fence"]
                or now >= current["expires_at"]
            ):
                raise CoordinatorRejected("coordinator.grant_ancestry_stale")
            if key is None:
                break
            if key in seen or len(seen) >= 16:
                raise CoordinatorUnavailable("coordinator grant ancestry corrupt")
            seen.add(key)
            current = state["grants"].get(key)
            if current is None:
                raise CoordinatorRejected("coordinator.parent_grant_revalidation_required")
        return row

    def policy_snapshot(
        self, handle: CoordinatorScope, channel: AuthorityChannel, lease_id: str
    ) -> dict[str, Any]:
        with self.store.transaction() as transaction:
            _, state, _, _, _ = self._lease(
                transaction, handle, channel, lease_id, allow_incomplete=True
            )
            return {
                "schema_version": "ordin.swarm_coordinator_policy.v1",
                "scope_digest": handle.scope_key,
                "policy_epoch": state["policy_epoch"],
                "policy_digest": state["policy_digest"],
                "runtime_binding": state["runtime_binding"],
                "owner_fence": state["owner"]["fence"],
                "prehistory": "unknown",
                "execution_authority": False,
            }

    def evaluate(
        self,
        handle: CoordinatorScope,
        channel: AuthorityChannel,
        lease_id: str,
        native_reference: str,
        action: ActionEnvelope,
        *,
        idempotency_key: str,
        governance_context=None,
    ) -> CoordinatorRecord:
        """Non-authorizing preview; reserve/dispatch recheck original live authority."""
        identifier(idempotency_key, "idempotency_key")
        if type(action) is not ActionEnvelope or action.action_id is None:
            raise ValueError("exact host-correlated action required")
        captured = ActionEnvelope.from_dict(action.as_dict())
        action_hash = digest(captured.as_dict())
        scope = self._scope(handle)
        with self._containment_barrier(scope), self.store.transaction() as transaction:
            scope, state, enrollment, subject, lease = self._lease(
                transaction, handle, channel, lease_id
            )
            self._grant(state, subject, lease, native_reference, transaction.now)
            key = digest([subject, lease["generation"], idempotency_key])
            request_hash = digest(
                [native_reference, action_hash, state["policy_epoch"], state["owner"]["fence"]]
            )
            existing = transaction.request(handle.scope_key, "evaluate", key, request_hash)
            if existing is not None:
                row = state["evaluations"].get(existing["reference"])
                if (
                    row is None
                    or row["status"] != "previewed"
                    or row["channel_digest"] != digest(channel.channel_id)
                    or transaction.now >= row["expires_at"]
                ):
                    raise CoordinatorRejected("coordinator.evaluation_stale_or_consumed")
                return self._record(
                    "evaluation",
                    row["id"],
                    handle,
                    subject,
                    state,
                    row["expires_at"],
                    row["disposition"],
                    action_hash,
                )
            if len(state["evaluations"]) >= self._limit:
                raise CoordinatorRejected("coordinator.evaluation_history_capacity")
            original, native_subject = scope.native._grant(channel, native_reference)
            if native_subject.context is not enrollment.context or native_subject.source is None:
                raise CoordinatorRejected("coordinator.native_scope_changed")
            preview_context = native_subject.source.context()
            approval_options = {}
            if scope.native._governance is not None:
                preview_context, approval_options = scope.native._governance.native_options(
                    governance_context, channel, native_reference, captured, preview_context
                )
            elif governance_context is not None:
                raise CoordinatorRejected("coordinator.unconfigured_governance")
            preview = original.gate.preview_action(
                captured, host_context=preview_context, **approval_options
            )
            reference = uuid4().hex + uuid4().hex
            expires = min(lease["lease_expires_at"], transaction.now + scope.native._lifetime)
            state["evaluations"][reference] = {
                "id": reference,
                "subject": subject,
                "subject_generation": lease["generation"],
                "action_digest": action_hash,
                "grant_reference": native_reference,
                "channel_digest": digest(channel.channel_id),
                "owner_fence": state["owner"]["fence"],
                "policy_epoch": state["policy_epoch"],
                "runtime_binding": state["runtime_binding"],
                "expires_at": expires,
                "status": "previewed",
                "disposition": preview.disposition,
            }
            transaction.append(
                handle.scope_key,
                "action_evaluated",
                reference,
                {"action_digest": action_hash, "disposition": preview.disposition},
                maximum=self._limit,
            )
            result = self._record(
                "evaluation",
                reference,
                handle,
                subject,
                state,
                expires,
                preview.disposition,
                action_hash,
            )
            transaction.record_request(
                handle.scope_key,
                "evaluate",
                key,
                request_hash,
                result.to_wire(),
                maximum=self._limit,
            )
            if digest(action.as_dict()) != action_hash:
                raise ValueError("action changed during coordinator evaluation")
        self._emit_audit(handle, result)
        return result

    @staticmethod
    def _scopes_for(scope, enrollment):
        registry, context = scope.authenticator._registry, enrollment.context
        with registry._lock:
            registry.authenticate(context, enrollment.registry_channel, enrollment.adapter)
            identity = context.identity
            agents, tasks = (
                [identity.agent_id],
                [] if identity.task_id is None else [identity.task_id],
            )
            current = identity
            for _ in range(registry._max_parent_depth):
                if current.parent_agent_id is None:
                    break
                current = registry._agents[current.parent_agent_id].context.identity
                agents.append(current.agent_id)
                if current.task_id is not None:
                    tasks.append(current.task_id)
            return {
                "tenant": (identity.tenant_id,),
                "swarm": (identity.swarm_id,),
                "agent": tuple(agents),
                "task": tuple(dict.fromkeys(tasks)),
            }

    @staticmethod
    def _known_costs(action, effects):
        values = {
            "requests": 1,
            "concurrency": 1,
            "tool_calls": int(action.kind in {"tool", "mcp"}),
            "external_operations": int(action.kind == "network"),
            "child_spawns": 0,
            "destructive_actions": int(
                any(
                    effect in {"filesystem.delete", "filesystem.recursive_delete"}
                    for effect in effects
                )
            ),
            "processes": int(
                any(effect in {"code.execute", "code.remote_execute"} for effect in effects)
            ),
        }
        return tuple(BudgetCost(metric, amount) for metric, amount in values.items())

    def _prepare(self, scope, channel, native_reference, action, key, governance_context=None):
        enrollment = scope.authenticator.require(channel, role="workload")
        broker = scope.brokers.get(enrollment.host_id)
        if broker is not None:
            result = broker.prepare(
                channel,
                native_reference,
                action,
                idempotency_key=key,
                governance_context=governance_context,
            )
            if result.authorization is None:
                raise CoordinatorRejected("coordinator.broker_preparation_restricted")
            try:
                original = broker.authorization_scope(result.authorization)
                if (
                    original.context is not enrollment.context
                    or type(original.action) is not ActionEnvelope
                ):
                    raise CoordinatorRejected("coordinator.original_broker_scope_mismatch")
            except Exception:
                broker.cancel(result.authorization)
                raise
            return broker, result.authorization, None, original.action
        if scope.runtime is not None:
            raise CoordinatorRejected("coordinator.current_policy_broker_required")
        if governance_context is not None:
            raise CoordinatorRejected("coordinator.governance_requires_owned_broker")
        review = scope.native.review(channel, native_reference, action)
        if review.admission_id is None or review.disposition != "execute":
            raise CoordinatorRejected("coordinator.native_review_restricted")
        broker_channel = scope.broker_channels.get(enrollment.host_id)
        try:
            if broker_channel is None:
                raise CoordinatorRejected("coordinator.bound_broker_host_unavailable")
            original = scope.native.admission_scope(broker_channel, review.admission_id)
        except Exception:
            scope.native.cancel(channel, review.admission_id)
            raise
        return None, None, review.admission_id, original.action

    @staticmethod
    def _containment_barrier(scope):
        # Native review/commit may query this same DB when containment is
        # enabled. Take its admission barrier before DB and issuer locks on
        # every preparation route; the incident control path never takes it.
        return (
            scope.native._policy_barrier()
            if scope.native._containment is not None
            else nullcontext()
        )

    @staticmethod
    def _cancel_prepared(scope, channel, prepared):
        try:
            if prepared.broker is not None:
                prepared.broker.cancel(prepared.authorization)
            elif prepared.native_id is not None:
                scope.native.cancel(channel, prepared.native_id)
        except Exception:
            pass

    def _charge(self, transaction, state, scope, enrollment, action, reference):
        effects = tuple(scope.native.assurance.ordin.review_action(action).effects)
        buckets = _select_budget_buckets(
            scope.budget, enrollment.context, self._scopes_for(scope, enrollment)
        )
        try:
            broker = scope.brokers.get(enrollment.host_id)
            costs = (
                broker._default_costs()
                if broker is not None
                else self._known_costs(action, effects)
            )
            _, resolved = _resolve_budget_costs(buckets, costs, effects)
        except BudgetError as error:
            raise CoordinatorRejected(error.reason_code) from None
        charges = []
        for selected in buckets:
            metric, amount = selected.limits[0].metric, resolved[selected.limits[0].metric]
            row = _bucket(transaction.connection, selected.key)
            if row is None:
                row = {
                    "bucket": selected.key,
                    "tenant_digest": digest(scope.tenant_id),
                    "metric": metric,
                    "maximum": selected.maximum,
                    "held": 0,
                    "consumed": 0,
                    "observed": 0,
                    "blocked_epoch": -1,
                }
                transaction.connection.execute(
                    "INSERT INTO coordinator_buckets VALUES(?,?,?,?,?,?,?,?,?)",
                    tuple(
                        row[name]
                        for name in (
                            "bucket",
                            "tenant_digest",
                            "metric",
                            "maximum",
                            "held",
                            "consumed",
                            "observed",
                            "blocked_epoch",
                        )
                    )
                    + (_bucket_checksum(row),),
                )
            if row["tenant_digest"] != digest(scope.tenant_id) or row["metric"] != metric:
                raise CoordinatorUnavailable("coordinator budget scope changed")
            maximum = min(selected.maximum, row["maximum"])
            if (
                row["blocked_epoch"] >= state["policy_epoch"]
                or row["held"] + row["consumed"] + amount > maximum
            ):
                raise CoordinatorRejected("coordinator.budget_limit_exceeded")
            charges.append((row, amount, maximum))
        for row, amount, maximum in charges:
            updated = dict(row)
            updated["held"] += amount
            updated["maximum"] = maximum
            _save_bucket(transaction.connection, updated)
            transaction.connection.execute(
                "INSERT INTO coordinator_items VALUES(?,?,?,?,?)",
                (state["scope_key"], reference, row["bucket"], row["metric"], amount),
            )
        return effects

    def reserve(
        self,
        handle: CoordinatorScope,
        channel: AuthorityChannel,
        lease_id: str,
        evaluation_id: str,
        action: ActionEnvelope,
        *,
        idempotency_key: str,
        governance_context=None,
    ) -> CoordinatorRecord:
        identifier(idempotency_key, "idempotency_key")
        _hex(evaluation_id, "coordinator evaluation reference")
        if type(action) is not ActionEnvelope:
            raise ValueError("exact current reservation action required")
        captured = ActionEnvelope.from_dict(action.as_dict())
        caller_hash = digest(captured.as_dict())
        scope, enrollment, _ = self._subject(handle, channel)
        staged = None
        guard = (
            scope.runtime.execution_guard(
                enrollment.context, broker=scope.brokers.get(enrollment.host_id)
            )
            if scope.runtime
            else nullcontext()
        )
        try:
            with self._containment_barrier(scope), guard, self.store.transaction() as transaction:
                scope, state, enrollment, subject, lease = self._lease(
                    transaction, handle, channel, lease_id
                )
                evaluation = state["evaluations"].get(evaluation_id)
                if (
                    evaluation is None
                    or evaluation["subject"] != subject
                    or evaluation["subject_generation"] != lease["generation"]
                    or evaluation["action_digest"] != caller_hash
                    or evaluation["owner_fence"] != state["owner"]["fence"]
                    or evaluation["channel_digest"] != digest(channel.channel_id)
                    or transaction.now >= evaluation["expires_at"]
                ):
                    raise CoordinatorRejected("coordinator.exact_current_evaluation_required")
                self._grant(state, subject, lease, evaluation["grant_reference"], transaction.now)
                key = digest([subject, lease["generation"], idempotency_key])
                request_hash = digest([evaluation_id, caller_hash, state["owner"]["fence"]])
                existing = transaction.request(handle.scope_key, "reserve", key, request_hash)
                if existing is not None:
                    row = state["reservations"].get(existing["reference"])
                    if (
                        row is None
                        or row["status"] != "reserved"
                        or row["id"] not in self._prepared
                    ):
                        raise CoordinatorRejected("coordinator.reservation_stale_or_consumed")
                    return self._record(
                        "reservation",
                        row["id"],
                        handle,
                        subject,
                        state,
                        row["expires_at"],
                        row["status"],
                        row["action_digest"],
                    )
                if evaluation["status"] != "previewed" or len(state["reservations"]) >= self._limit:
                    raise CoordinatorRejected("coordinator.evaluation_consumed_or_capacity")
                if scope.budget.require_physical_enforcement:
                    raise CoordinatorRejected("coordinator.physical_budget_receipt_unavailable")
                reference = uuid4().hex + uuid4().hex
                effects = self._charge(transaction, state, scope, enrollment, captured, reference)
                expires = min(
                    evaluation["expires_at"],
                    lease["lease_expires_at"],
                    transaction.now + scope.budget.reservation_lifetime,
                )
                reservation = state["reservations"][reference] = {
                    "id": reference,
                    "subject": subject,
                    "subject_generation": lease["generation"],
                    "action_digest": caller_hash,
                    "caller_digest": caller_hash,
                    "evaluation": evaluation_id,
                    "owner_fence": state["owner"]["fence"],
                    "policy_epoch": state["policy_epoch"],
                    "runtime_binding": state["runtime_binding"],
                    "expires_at": expires,
                    "status": "preparing",
                    "host_id": enrollment.host_id,
                    "context_digest": digest(enrollment.context.as_dict()),
                    "native_reference": None,
                    "settlement_digest": None,
                }
                try:
                    broker, authorization, native_id, canonical = self._prepare(
                        scope,
                        channel,
                        evaluation["grant_reference"],
                        captured,
                        reference,
                        governance_context,
                    )
                    staged = (
                        reference,
                        _Prepared(
                            handle,
                            subject,
                            digest(canonical.as_dict()),
                            native_id,
                            broker,
                            authorization,
                            canonical,
                        ),
                    )
                    canonical_effects = tuple(
                        scope.native.assurance.ordin.review_action(canonical).effects
                    )
                    if (
                        canonical.kind != captured.kind
                        or canonical.operation != captured.operation
                        or set(canonical_effects) != set(effects)
                    ):
                        raise CoordinatorRejected("coordinator.canonical_cost_plan_changed")
                except CoordinatorRejected:
                    self._release(transaction, state, reservation, "denied")
                    if staged is not None:
                        self._cancel_prepared(scope, channel, staged[1])
                        staged = None
                    transaction.append(
                        handle.scope_key,
                        "preparation_denied",
                        reference,
                        {"action_digest": caller_hash},
                        maximum=self._limit,
                    )
                    raise
                reservation["status"] = "reserved"
                reservation["action_digest"] = staged[1].action_digest
                if (
                    reservation["action_digest"] in state["blocked_actions"]
                    or _action_fence_key(reservation["action_digest"], subject)
                    in state["blocked_actions"]
                ):
                    self._release(transaction, state, reservation, "denied")
                    self._cancel_prepared(scope, channel, staged[1])
                    staged = None
                    raise CoordinatorRejected("coordinator.action_fenced")
                reservation["native_reference"] = native_id
                evaluation["status"] = "reserved"
                transaction.append(
                    handle.scope_key,
                    "budget_reserved",
                    reference,
                    {"action_digest": reservation["action_digest"], "subject_digest": subject},
                    maximum=self._limit,
                )
                result = self._record(
                    "reservation",
                    reference,
                    handle,
                    subject,
                    state,
                    expires,
                    "reserved",
                    reservation["action_digest"],
                )
                transaction.record_request(
                    handle.scope_key,
                    "reserve",
                    key,
                    request_hash,
                    result.to_wire(),
                    maximum=self._limit,
                )
                if digest(action.as_dict()) != caller_hash:
                    raise ValueError("reservation action changed")
        except Exception:
            if staged is not None:
                self._cancel_prepared(scope, channel, staged[1])
            raise
        if staged is not None:
            with self._lock:
                self._prepared[staged[0]] = staged[1]
        self._emit_audit(handle, result)
        return result

    def _broker_reservation(self, transaction, handle, channel, reference, *, statuses):
        _hex(reference, "coordinator reservation reference")
        scope = self._scope(handle)
        broker = scope.authenticator.require(channel, role="broker")
        _, state = self._owner(transaction, handle)
        reservation = state["reservations"].get(reference)
        subject = state["subjects"].get(reservation["subject"]) if reservation else None
        if (
            reservation is None
            or reservation["status"] not in statuses
            or subject is None
            or subject["revoked"]
            or broker.host_id != reservation["host_id"]
            or subject["generation"] != reservation["subject_generation"]
            or transaction.now >= subject["lease_expires_at"]
            or reservation["owner_fence"] != state["owner"]["fence"]
            or reservation["policy_epoch"] != state["policy_epoch"]
        ):
            raise CoordinatorRejected("coordinator.current_broker_reservation_required")
        evaluation = state["evaluations"].get(reservation["evaluation"])
        if evaluation is None:
            raise CoordinatorUnavailable("coordinator original evaluation history missing")
        self._grant(
            state, reservation["subject"], subject, evaluation["grant_reference"], transaction.now
        )
        return scope, state, reservation

    def begin_forward(
        self, handle: CoordinatorScope, broker_channel: AuthorityChannel, reservation_id: str
    ) -> CoordinatorRecord:
        """Durably consume before any broker effect. ACK loss is never retried."""
        scope = self._scope(handle)
        with self._containment_barrier(scope), self.store.transaction() as transaction:
            scope, state, reservation = self._broker_reservation(
                transaction, handle, broker_channel, reservation_id, statuses={"reserved"}
            )
            prepared = self._prepared.get(reservation_id)
            if (
                prepared is None
                or prepared.scope is not handle
                or prepared.action_digest != reservation["action_digest"]
                or transaction.now >= reservation["expires_at"]
            ):
                raise CoordinatorRejected("coordinator.original_live_preparation_required")
            if prepared.broker is not None:
                original = prepared.broker.authorization_scope(prepared.authorization)
            else:
                original = scope.native.admission_scope(broker_channel, prepared.native_id)
            if (
                digest(original.action.as_dict()) != reservation["action_digest"]
                or digest(original.context.as_dict()) != reservation["context_digest"]
            ):
                raise CoordinatorRejected("coordinator.prepared_scope_changed")
            if prepared.broker is not None and prepared.broker._governance is not None:
                prepared.broker._governance.consume_in_transaction(
                    transaction,
                    prepared.broker._governance_contexts.get(prepared.authorization),
                    prepared.broker,
                    prepared.authorization,
                    reservation_id,
                )
            reservation["status"] = "forwarding"
            transaction.append(
                handle.scope_key,
                "forwarding_started",
                reservation_id,
                {"action_digest": reservation["action_digest"]},
                maximum=self._limit,
            )
            result = self._record(
                "dispatch",
                reservation_id,
                handle,
                reservation["subject"],
                state,
                reservation["expires_at"],
                "forwarding",
                reservation["action_digest"],
            )
        self._emit_audit(handle, result)
        return result

    def cancel(
        self,
        handle: CoordinatorScope,
        channel: AuthorityChannel,
        lease_id: str,
        reservation_id: str,
    ) -> bool:
        with self.store.transaction() as transaction:
            scope, state, _, subject, lease = self._lease(
                transaction, handle, channel, lease_id, allow_incomplete=True
            )
            reservation = state["reservations"].get(reservation_id)
            if (
                reservation is None
                or reservation["subject"] != subject
                or reservation["subject_generation"] != lease["generation"]
            ):
                raise CoordinatorRejected("coordinator.foreign_reservation")
            if reservation["status"] in {"canceled", "expired", "denied"}:
                return False
            if reservation["status"] not in {"preparing", "reserved"}:
                raise CoordinatorRejected("coordinator.uncertain_effect_cannot_refund")
            self._release(transaction, state, reservation, "canceled")
            transaction.append(
                handle.scope_key, "reservation_canceled", reservation_id, {}, maximum=self._limit
            )
        prepared = self._prepared.pop(reservation_id, None)
        if prepared is not None:
            self._cancel_prepared(scope, channel, prepared)
        return True

    def uncertain(
        self, handle: CoordinatorScope, broker_channel: AuthorityChannel, reservation_id: str
    ) -> CoordinatorRecord:
        with self.store.transaction() as transaction:
            _, state, reservation = self._broker_reservation(
                transaction,
                handle,
                broker_channel,
                reservation_id,
                statuses={"forwarding", "uncertain"},
            )
            reservation["status"] = "uncertain"
            transaction.append(
                handle.scope_key,
                "forwarding_uncertain",
                reservation_id,
                {"action_digest": reservation["action_digest"]},
                maximum=self._limit,
            )
            result = self._record(
                "dispatch",
                reservation_id,
                handle,
                reservation["subject"],
                state,
                reservation["expires_at"],
                "uncertain",
                reservation["action_digest"],
            )
        self._emit_audit(handle, result)
        return result

    def commit(
        self, handle: CoordinatorScope, broker_channel: AuthorityChannel, reservation_id: str
    ) -> CoordinatorRecord:
        """Broker-reported completion charges full bounds; no wire refund claims."""
        with self.store.transaction() as transaction:
            _, state, reservation = self._broker_reservation(
                transaction,
                handle,
                broker_channel,
                reservation_id,
                statuses={"forwarding", "uncertain", "committed"},
            )
            if reservation["status"] == "committed":
                return self._record(
                    "dispatch",
                    reservation_id,
                    handle,
                    reservation["subject"],
                    state,
                    reservation["expires_at"],
                    "committed",
                    reservation["action_digest"],
                )
            for item in transaction.connection.execute(
                "SELECT * FROM coordinator_items WHERE scope_key=? AND reservation_id=?",
                (handle.scope_key, reservation_id),
            ).fetchall():
                row = _bucket(transaction.connection, item["bucket"])
                if row is None or row["held"] < item["amount"]:
                    raise CoordinatorUnavailable("coordinator held-budget history missing")
                updated = dict(row)
                updated["held"] -= item["amount"]
                updated["consumed"] += 0 if item["metric"] == "concurrency" else item["amount"]
                _save_bucket(transaction.connection, updated)
            reservation["status"] = "committed"
            transaction.append(
                handle.scope_key,
                "forwarding_completed",
                reservation_id,
                {
                    "action_digest": reservation["action_digest"],
                    "evidence": "authenticated_broker_report",
                },
                maximum=self._limit,
            )
            result = self._record(
                "dispatch",
                reservation_id,
                handle,
                reservation["subject"],
                state,
                reservation["expires_at"],
                "committed",
                reservation["action_digest"],
            )
        with self._lock:
            prepared = self._prepared.pop(reservation_id, None)
            if prepared is not None and prepared.broker is not None:
                self._completed_prepared[reservation_id] = prepared
        self._emit_audit(handle, result)
        return result

    def broker_result(
        self, handle: CoordinatorScope, broker_channel: AuthorityChannel, reservation_id: str
    ):
        """Retrieve one original committed physical outcome under current protected scope."""
        scope = self._scope(handle)
        with self._containment_barrier(scope), self._lock, self.store.transaction() as transaction:
            _, _, reservation = self._broker_reservation(
                transaction, handle, broker_channel, reservation_id, statuses={"committed"}
            )
            enrollment = scope.authenticator.require(broker_channel, role="broker")
            prepared = self._completed_prepared.get(reservation_id)
            if (
                prepared is None
                or prepared.scope is not handle
                or prepared.broker is None
                or prepared.authorization is None
                or prepared.broker is not scope.brokers.get(enrollment.host_id)
                or scope.broker_channels.get(enrollment.host_id) is not broker_channel
                or prepared.broker._service is not scope.native
                or prepared.action_digest != reservation["action_digest"]
                or digest(prepared.action.as_dict()) != prepared.action_digest
            ):
                raise CoordinatorRejected("coordinator.original_completed_broker_binding_required")
            broker = prepared.broker
            with broker._state_lock:
                authorized = broker._pending_row(prepared.authorization)
                result = authorized.result
                if (
                    result is None
                    or result.status != "completed"
                    or not result.physical_enforcement
                    or result.action_digest != prepared.action_digest
                    or not broker.verify_result(result, prepared.authorization)
                    or result.executor_outcome is None
                    or not broker._executor.verify_outcome(
                        result.executor_outcome, authorized.scope.plan
                    )
                ):
                    raise CoordinatorRejected("coordinator.original_actual_broker_outcome_required")
                return result

    def guarded_dispatch(
        self,
        handle: CoordinatorScope,
        broker_channel: AuthorityChannel,
        reservation_id: str,
        *,
        forward: Callable[[ActionEnvelope], Any] | None = None,
    ) -> CoordinatorDispatch:
        """One online DB admission then one original broker dispatch, never an ACK retry."""
        self.begin_forward(handle, broker_channel, reservation_id)
        prepared = self._prepared.get(reservation_id)
        if prepared is None:
            raise CoordinatorRejected("coordinator.original_live_preparation_required")
        scope = self._scope(handle)
        try:
            if prepared.broker is not None:
                if forward is not None:
                    raise ValueError("registered enforcing broker owns its executor")
                result = prepared.broker.dispatch(prepared.authorization, action=prepared.action)
                if not prepared.broker.verify_result(result, prepared.authorization):
                    raise ValueError("original broker result unavailable")
            else:
                if (
                    forward is None
                    or not callable(forward)
                    or scope.runtime is not None
                    or prepared.native_id is None
                ):
                    raise ValueError("protected host mediator unavailable")
                result = scope.native.guarded_dispatch(
                    broker_channel, prepared.native_id, prepared.action, forward
                )
            if result.status not in {"completed", "host_completed"}:
                raise ValueError("broker result uncertain")
        except Exception:
            try:
                self.uncertain(handle, broker_channel, reservation_id)
            except (ValueError, CoordinatorUnavailable):
                self._available = False
            return CoordinatorDispatch(
                "unknown",
                digest(reservation_id),
                prepared.action_digest,
                "coordinator.effect_uncertain",
            )
        try:
            self.commit(handle, broker_channel, reservation_id)
        except (ValueError, CoordinatorUnavailable):
            self._available = False
            return CoordinatorDispatch(
                "unknown",
                digest(reservation_id),
                prepared.action_digest,
                "coordinator.completion_ack_uncertain",
            )
        return CoordinatorDispatch(
            "host_completed",
            digest(reservation_id),
            prepared.action_digest,
            "coordinator.host_completed",
            result.value,
        )

    def budget_report(
        self, handle: CoordinatorScope, channel: AuthorityChannel, lease_id: str
    ) -> dict[str, Any]:
        with self.store.transaction() as transaction:
            scope, state, enrollment, _, _ = self._lease(
                transaction, handle, channel, lease_id, allow_incomplete=True
            )
            return self._budget_report(transaction, scope, state, enrollment)

    def _budget_report(self, transaction, scope, state, enrollment):
        result = []
        for selected in _select_budget_buckets(
            scope.budget, enrollment.context, self._scopes_for(scope, enrollment)
        ):
            row = _bucket(transaction.connection, selected.key)
            maximum = selected.maximum if row is None else min(selected.maximum, row["maximum"])
            held, consumed = (0, 0) if row is None else (row["held"], row["consumed"])
            result.append(
                {
                    "bucket_digest": selected.key,
                    "scope": selected.limits[0].scope,
                    "metric": selected.limits[0].metric,
                    "maximum": maximum,
                    "reserved": held,
                    "consumed": consumed,
                    "observed": None if row is None else row["observed"],
                    "remaining": max(0, maximum - held - consumed),
                    "blocked": row is not None and row["blocked_epoch"] >= state["policy_epoch"],
                }
            )
        return {
            "schema_version": "ordin.swarm_budget.v1",
            "policy_digest": scope.budget.digest,
            "policy_epoch": state["policy_epoch"],
            "limits": result,
            "execution_authority": False,
            "enforcement": "admission_accounting",
            "physical_enforcement": False,
        }

    def _status(self, transaction, handle, state):
        statuses: dict[str, int] = {}
        for row in state["reservations"].values():
            statuses[row["status"]] = statuses.get(row["status"], 0) + 1
        return {
            "schema_version": "ordin.swarm_coordinator_status.v1",
            "scope_digest": handle.scope_key,
            "database_digest": digest(self.store.identity),
            "backend": self.store.backend,
            "mode": "multi_host_postgresql" if self.store.multi_host else "single_host_dev",
            "online": self._available
            and state["owner"]["id"] == self._instance
            and transaction.now < state["owner"]["expires_at"],
            "policy_epoch": state["policy_epoch"],
            "policy_digest": state["policy_digest"],
            "owner_fence": state["owner"]["fence"],
            "journal_sequence": state["sequence"],
            "checkpoint_sequence": state["checkpoint_sequence"],
            "journal_incomplete": state["incomplete"]
            or state["event_incomplete"]
            or bool(state["artifact_pending"]),
            "projection_lag": state["sequence"] - state["checkpoint_sequence"],
            "prehistory": "unknown",
            "workload_count": len(state["subjects"]),
            "grant_count": len(state["grants"]),
            "reservations": statuses,
            "unmediated_execution": "uncovered",
            "physical_enforcement": False,
            "execution_authority": False,
        }

    def status(
        self, handle: CoordinatorScope, *, control: CoordinatorControlSource
    ) -> dict[str, Any]:
        self._control_check(control)
        self._scope(handle)
        try:
            with self.store.transaction() as transaction:
                state = transaction.scope(handle.scope_key)
                transaction.verify_journal_head(handle.scope_key)
                return self._status(transaction, handle, state)
        except CoordinatorUnavailable:
            return {
                "schema_version": "ordin.swarm_coordinator_offline.v1",
                "scope_digest": handle.scope_key,
                "online": False,
                "coverage": "unknown",
                "requires_online_authority": True,
                "physical_enforcement": False,
                "execution_authority": False,
            }

    def _fence_state(self, transaction, state, kind, target, actor_digest=None):
        epoch = counter(state["revocation_epoch"] + 1, "revocation epoch")
        targets = {
            key
            for key, row in state["subjects"].items()
            if kind in {"swarm", "tenant"}
            or kind == "task"
            and row["task_digest"] == target
            or kind in {"agent", "subtree"}
            and key == target
        }
        if kind == "subtree":
            for _ in range(32):
                added = {
                    key
                    for key, row in state["subjects"].items()
                    if row["parent_subject"] in targets
                }
                if added <= targets:
                    break
                targets.update(added)
            else:
                raise CoordinatorUnavailable("coordinator workload tree exceeded bound")
        for key in targets:
            state["subjects"][key]["revoked"] = True
            state["subjects"][key]["lease_expires_at"] = 0
        for grant in state["grants"].values():
            if grant["subject"] in targets:
                grant["status"] = "revoked"
        affected = []
        for reference, row in state["reservations"].items():
            if row["subject"] in targets or (
                kind == "action"
                and row["action_digest"] == target
                and (actor_digest is None or row["subject"] == actor_digest)
            ):
                affected.append(reference)
                if row["status"] in {"preparing", "reserved"}:
                    self._release(transaction, state, row, "canceled")
                elif row["status"] == "forwarding":
                    row["status"] = "uncertain"
        if kind == "action":
            blocked = _action_fence_key(target, actor_digest)
            if blocked not in state["blocked_actions"]:
                state["blocked_actions"].append(blocked)
        intent = {
            "kind": kind,
            "target_digest": target,
            "subjects": sorted(targets),
            "reservations": sorted(affected),
            "policy_epoch": state["policy_epoch"],
            "owner_fence": state["owner"]["fence"],
            "reconciled": False,
        }
        if actor_digest is not None:
            intent["actor_digest"] = actor_digest
        state["fences"][str(epoch)] = intent
        state["revocation_epoch"] = epoch
        transaction.append(
            state["scope_key"],
            "revocation_intent",
            digest(intent),
            {"revocation_epoch": epoch, "kind": kind, "affected": len(affected)},
            maximum=self._limit,
        )
        return epoch, intent

    def record_fence(
        self,
        handle: CoordinatorScope,
        *,
        control: CoordinatorControlSource,
        kind: str,
        subject_digest: str | None = None,
        expected_epoch: int | None = None,
        actor_digest: str | None = None,
    ) -> CoordinatorFenceReceipt:
        self._control_check(control)
        scope = self._scope(handle)
        if type(kind) is not str or kind not in {
            "action",
            "agent",
            "subtree",
            "task",
            "swarm",
            "tenant",
        }:
            raise ValueError("unknown bounded coordinator fence scope")
        if kind in {"action", "agent", "subtree", "task"}:
            if subject_digest is None:
                raise ValueError("exact coordinator fence target required")
            _hex(subject_digest, "coordinator fence target")
        if actor_digest is not None:
            if kind != "action":
                raise ValueError("actor-specific target applies only to an action fence")
            _hex(actor_digest, "coordinator action actor")
        with self.store.transaction() as transaction:
            primary = transaction.scope(handle.scope_key)
            transaction.verify_journal_head(handle.scope_key)
            if expected_epoch is not None and expected_epoch != primary["revocation_epoch"]:
                raise CoordinatorRejected("coordinator.revocation_epoch_changed")
            realm = None
            if kind in {"tenant", "swarm", "task"}:
                auth_scope = scope.authenticator._scope
                if auth_scope is None:
                    raise CoordinatorRejected("coordinator.original_task_scope_required")
                if kind == "task" and subject_digest != digest(auth_scope[2]):
                    raise CoordinatorRejected("coordinator.foreign_task_fence")
                realm = self._realms(scope)[{"tenant": 0, "swarm": 1, "task": 2}[kind]]
                old = _barrier(transaction.connection, realm)
                realm_epoch = counter((old["epoch"] if old else 0) + 1, "realm revocation epoch")
                initial = _barrier_checksum(realm, realm_epoch, "blocked", "0" * 64)
                if old is None:
                    transaction.connection.execute(
                        "INSERT INTO coordinator_barriers VALUES(?,?,'blocked',?,?)",
                        (realm, realm_epoch, "0" * 64, initial),
                    )
                    transaction.register_barrier(realm)
                else:
                    transaction.connection.execute(
                        "UPDATE coordinator_barriers SET epoch=?,state='blocked',intent_digest=?,checksum=? WHERE realm_key=?",
                        (realm_epoch, "0" * 64, initial, realm),
                    )
            members = {}
            for key in tuple(transaction._scopes):
                state = transaction.scope(key)
                selected = (
                    key == handle.scope_key
                    or kind == "tenant"
                    and state["tenant_digest"] == digest(scope.tenant_id)
                    or kind == "swarm"
                    and (state["tenant_digest"], state["swarm_digest"])
                    == (digest(scope.tenant_id), digest(scope.swarm_id))
                )
                if selected:
                    epoch, _ = self._fence_state(
                        transaction, state, kind, subject_digest, actor_digest
                    )
                    members[key] = epoch
            intent = primary["fences"][str(primary["revocation_epoch"])]
            intent["members"] = members
            intent["realm"] = {"key": realm, "epoch": realm_epoch} if realm else None
            checksum = digest(intent)
            if realm:
                transaction.connection.execute(
                    "UPDATE coordinator_barriers SET intent_digest=?,checksum=? WHERE realm_key=?",
                    (checksum, _barrier_checksum(realm, realm_epoch, "blocked", checksum), realm),
                )
            transaction.append(
                handle.scope_key,
                "revocation_group",
                checksum,
                {
                    "members_digest": digest(members),
                    "revocation_epoch": primary["revocation_epoch"],
                },
                maximum=self._limit,
            )
            receipt = CoordinatorFenceReceipt(
                handle.scope_key,
                primary["revocation_epoch"],
                checksum,
                primary["policy_epoch"],
                primary["owner"]["fence"],
            )
        self._fence_receipts[receipt] = checksum
        return receipt

    def bind_recovery_verifier(
        self, handle: CoordinatorScope, verifier: object, *, control: CoordinatorControlSource
    ) -> None:
        self._control_check(control)
        self._scope(handle)
        if type(verifier) in {dict, list, tuple, str, bytes, int, bool} or not callable(
            getattr(verifier, "verify_resume_receipt", None)
        ):
            raise ValueError("original protected recovery controller required")
        self._recovery_verifiers[handle] = verifier

    def recover_fence(
        self, handle: CoordinatorScope, revocation_epoch: int, *, control: CoordinatorControlSource
    ) -> CoordinatorFenceReceipt:
        """Recover an intent reference; never recreate a resumed permission."""
        self._control_check(control)
        self._scope(handle)
        with self.store.transaction() as transaction:
            state = transaction.scope(handle.scope_key)
            intent = state["fences"].get(str(revocation_epoch))
            if (
                intent is None
                or intent["reconciled"]
                or state["revocation_epoch"] != revocation_epoch
            ):
                raise CoordinatorRejected("coordinator.current_pending_intent_required")
            receipt = CoordinatorFenceReceipt(
                handle.scope_key,
                revocation_epoch,
                digest(intent),
                intent["policy_epoch"],
                intent["owner_fence"],
            )
        self._fence_receipts[receipt] = receipt.intent_digest
        return receipt

    def _pending_intent(self, transaction, handle, receipt):
        _, state = self._owner(transaction, handle, allow_incomplete=True, allow_contained=True)
        intent = state["fences"].get(str(receipt.revocation_epoch))
        if (
            state["revocation_epoch"] != receipt.revocation_epoch
            or intent is None
            or digest(intent) != self._fence_receipts[receipt]
            or intent["reconciled"]
        ):
            raise CoordinatorRejected("coordinator.recovery_intent_changed")
        return state, intent

    @staticmethod
    def _require_incident_outcomes(state, intent, epoch):
        for reference in intent["reservations"]:
            row = state["reservations"].get(reference)
            if row is None:
                raise CoordinatorUnavailable("coordinator incident reservation history missing")
            if row["status"] in {"forwarding", "uncertain"}:
                outcome = row.get("incident_outcome")
                if (
                    outcome is None
                    or outcome["revocation_epoch"] != epoch
                    or outcome["status"] not in {"completed", "canceled"}
                ):
                    raise CoordinatorRejected("coordinator.incident_outcomes_unresolved")

    def reconcile_broker_outcome(
        self,
        handle: CoordinatorScope,
        reservation_id: str,
        original_receipt: object,
        *,
        control: CoordinatorControlSource,
        revocation_epoch: int,
    ) -> CoordinatorRecord:
        """Record a known original broker outcome without refunding uncertain holds."""
        from .authorization import BrokerControlReceipt, BrokerResult

        self._control_check(control)
        self._scope(handle)
        counter(revocation_epoch, "revocation epoch")
        prepared = self._prepared.get(reservation_id) or self._retired_prepared.get(reservation_id)
        if prepared is None or prepared.scope is not handle or prepared.broker is None:
            raise CoordinatorRejected("coordinator.original_incident_preparation_required")
        broker, authorization = prepared.broker, prepared.authorization
        # Verification may acquire broker/runtime locks; do it outside DB locks.
        if type(original_receipt) is BrokerControlReceipt:
            verified = broker.verify_control_receipt(original_receipt, authorization)
        elif type(original_receipt) is BrokerResult:
            verified = broker.verify_result(original_receipt, authorization)
        else:
            raise CoordinatorRejected("coordinator.original_known_broker_outcome_required")
        if not verified or getattr(original_receipt, "status", None) not in {
            "completed",
            "canceled",
        }:
            raise CoordinatorRejected("coordinator.original_known_broker_outcome_required")
        receipt_digest = digest(original_receipt.as_dict())
        with self.store.transaction() as transaction:
            state = transaction.scope(handle.scope_key)
            transaction.verify_journal_head(handle.scope_key)
            intent = state["fences"].get(str(revocation_epoch))
            reservation = state["reservations"].get(reservation_id)
            current = self._prepared.get(reservation_id) or self._retired_prepared.get(
                reservation_id
            )
            if (
                state["revocation_epoch"] != revocation_epoch
                or intent is None
                or intent["reconciled"]
                or reservation_id not in intent["reservations"]
                or reservation is None
                or current is not prepared
                or reservation["action_digest"] != prepared.action_digest
            ):
                raise CoordinatorRejected("coordinator.current_incident_outcome_binding_required")
            outcome = {
                "status": original_receipt.status,
                "receipt_digest": receipt_digest,
                "revocation_epoch": revocation_epoch,
                "action_digest": prepared.action_digest,
            }
            previous = reservation.get("incident_outcome")
            if previous is not None:
                if (
                    any(previous[key] != outcome[key] for key in ("status", "action_digest"))
                    or previous["revocation_epoch"] > revocation_epoch
                ):
                    raise CoordinatorRejected("coordinator.incident_outcome_conflict")
                if previous["revocation_epoch"] == revocation_epoch:
                    receipt_digest = previous["receipt_digest"]
            if previous is None or previous["revocation_epoch"] < revocation_epoch:
                reservation["incident_outcome"] = outcome
                transaction.append(
                    handle.scope_key,
                    "broker_incident_reconciled",
                    receipt_digest,
                    {
                        "reservation_digest": digest(reservation_id),
                        "revocation_epoch": revocation_epoch,
                        "status": original_receipt.status,
                    },
                    maximum=self._limit,
                )
            # No held/consumed counters or reservation phase are changed here.
            return self._record(
                "reconciliation",
                receipt_digest,
                handle,
                reservation["subject"],
                state,
                None,
                original_receipt.status + "_holds_retained",
                prepared.action_digest,
            )

    def reconcile_fence(
        self,
        handle: CoordinatorScope,
        receipt: CoordinatorFenceReceipt,
        original_resume_receipt: object,
        *,
        control: CoordinatorControlSource,
    ) -> CoordinatorRecord:
        self._control_check(control)
        self._scope(handle)
        verifier = self._recovery_verifiers.get(handle)
        if (
            type(receipt) is not CoordinatorFenceReceipt
            or receipt not in self._fence_receipts
            or receipt.scope_digest != handle.scope_key
            or type(original_resume_receipt) in {dict, list, tuple, str, bytes, int, bool}
            or verifier is None
        ):
            raise CoordinatorRejected("coordinator.original_recovery_receipts_required")
        with self.store.transaction() as transaction:
            state, intent = self._pending_intent(transaction, handle, receipt)
            self._require_incident_outcomes(state, intent, receipt.revocation_epoch)
            policy, owner = state["policy_epoch"], state["owner"]["fence"]
            if policy <= receipt.policy_epoch and owner <= receipt.owner_fence:
                raise CoordinatorRejected("coordinator.fresh_policy_or_owner_fence_required")
        # Never wait for a backend verifier while holding DB/control locks.
        if (
            verifier.verify_resume_receipt(
                original_resume_receipt,
                scope_digest=handle.scope_key,
                revocation_epoch=receipt.revocation_epoch,
                policy_epoch=policy,
                owner_fence=owner,
            )
            is not True
        ):
            raise CoordinatorRejected("coordinator.backend_reconciliation_unverified")
        with self.store.transaction() as transaction:
            state, intent = self._pending_intent(transaction, handle, receipt)
            self._require_incident_outcomes(state, intent, receipt.revocation_epoch)
            if (state["policy_epoch"], state["owner"]["fence"]) != (policy, owner):
                raise CoordinatorRejected("coordinator.reconciliation_state_changed")
            for key, epoch in intent.get(
                "members", {handle.scope_key: receipt.revocation_epoch}
            ).items():
                member = transaction.scope(key)
                if (
                    member["revocation_epoch"] != epoch
                    or key != handle.scope_key
                    and not member["fences"][str(epoch)]["reconciled"]
                ):
                    raise CoordinatorRejected("coordinator.member_reconciliation_required")
            realm = intent.get("realm")
            if realm:
                row = _barrier(transaction.connection, realm["key"])
                if (
                    row is None
                    or row["epoch"] != realm["epoch"]
                    or row["intent_digest"] != receipt.intent_digest
                ):
                    raise CoordinatorRejected("coordinator.realm_fence_changed")
                transaction.connection.execute(
                    "UPDATE coordinator_barriers SET state='reconciled',checksum=? WHERE realm_key=?",
                    (
                        _barrier_checksum(
                            realm["key"], row["epoch"], "reconciled", row["intent_digest"]
                        ),
                        realm["key"],
                    ),
                )
            for subject in intent["subjects"]:
                row = state["subjects"][subject]
                row["revoked"], row["lease_expires_at"] = False, 0
                row["generation"] = counter(row["generation"] + 1, "recovered workload generation")
            if intent["kind"] == "action":
                blocked = _action_fence_key(intent["target_digest"], intent.get("actor_digest"))
                if blocked in state["blocked_actions"]:
                    state["blocked_actions"].remove(blocked)
            intent["reconciled"] = True
            intent["reconciliation_digest"] = digest([receipt.intent_digest, policy, owner])
            transaction.append(
                handle.scope_key,
                "revocation_reconciled",
                intent["reconciliation_digest"],
                {"revocation_epoch": receipt.revocation_epoch},
                maximum=self._limit,
            )
            return self._record(
                "reconciliation",
                intent["reconciliation_digest"],
                handle,
                None,
                state,
                None,
                "fresh_admission_required",
            )

    def admission_context(
        self, handle: CoordinatorScope, channel: AuthorityChannel, lease_id: str
    ) -> dict[str, Any]:
        """Data describing this verified producer; it is never an enrollment."""
        with self.store.transaction() as transaction:
            scope, state, enrollment, _, row = self._lease(
                transaction, handle, channel, lease_id, allow_incomplete=True
            )
            stream = state["streams"].get(row["producer"], {})
            return {
                "schema_version": "ordin.swarm_coordinator_producer.v1",
                "registry_id": enrollment.context.registry_id,
                "identity": enrollment.context.identity.as_dict(),
                "source_id": row["event_source"],
                "next_sequence": stream.get("contiguous", 0) + 1,
                "prehistory": "unknown",
                "execution_authority": False,
            }

    @staticmethod
    def _event_alias(handle, event_id):
        return "e-" + digest([handle.scope_key, event_id])

    @staticmethod
    def _event_gaps(events, streams):
        # Validate the prospective bounded DAG before publishing any mutation.
        colors: dict[str, int] = {}

        def visit(key, depth):
            if depth > 128 or colors.get(key) == 1:
                raise CoordinatorRejected("coordinator.event_cycle_or_depth")
            if colors.get(key) == 2 or key not in events:
                return
            colors[key] = 1
            for parent in events[key]["parents"]:
                visit(parent, depth + 1)
            colors[key] = 2

        for key in events:
            visit(key, 0)
        return any(row["highest"] != row["contiguous"] for row in streams.values()) or any(
            parent not in events for row in events.values() for parent in row["parents"]
        )

    def ingest_event(
        self, handle: CoordinatorScope, channel: AuthorityChannel, lease_id: str, event: SwarmEvent
    ) -> dict[str, Any]:
        if type(event) is not SwarmEvent:
            raise CoordinatorRejected("coordinator.typed_event_required")
        event = SwarmEvent.from_dict(event.as_dict())
        if event.evidence_class not in {"caller_asserted", "host_authenticated"}:
            raise CoordinatorRejected("coordinator.protected_backend_receipt_required")
        if event.evidence_class == "host_authenticated" and event.event_kind == "observed":
            raise CoordinatorRejected("coordinator.protected_backend_receipt_required")
        with self.store.transaction() as transaction:
            scope, state, enrollment, subject, lease = self._lease(
                transaction, handle, channel, lease_id, allow_incomplete=True
            )
            if (
                event.identity != enrollment.context.identity
                or event.registry_id != enrollment.context.registry_id
                or event.source_id != lease["event_source"]
            ):
                raise CoordinatorRejected("coordinator.event_producer_mismatch")
            alias = self._event_alias(handle, event.event_id)
            previous = state["events"].get(alias)
            if previous is not None:
                if previous["submitted_digest"] != event.digest:
                    raise CoordinatorRejected("coordinator.event_id_conflict")
                return {
                    "event_digest": digest(alias),
                    "status": "duplicate",
                    "execution_authority": False,
                }
            if len(state["events"]) >= self._event_limit:
                raise CoordinatorRejected("coordinator.event_capacity")
            events = dict(state["events"])
            streams = {
                key: {**row, "sequences": dict(row["sequences"])}
                for key, row in state["streams"].items()
            }
            stream = streams.setdefault(
                lease["producer"], {"contiguous": 0, "highest": 0, "sequences": {}}
            )
            if event.source_sequence > stream["contiguous"] + 128:
                raise CoordinatorRejected("coordinator.event_receive_window")
            seq = str(event.source_sequence)
            if seq in stream["sequences"]:
                raise CoordinatorRejected("coordinator.event_sequence_conflict")
            review = (
                self._event_alias(handle, event.review_event_id) if event.review_event_id else None
            )
            if event.event_kind in REVIEW_BOUND_STAGES:
                anchor = events.get(review)
                if anchor is None or (
                    anchor["kind"],
                    anchor["subject"],
                    anchor["context_digest"],
                    anchor["action_id_digest"],
                    anchor["action_digest"],
                ) != (
                    "reviewed",
                    subject,
                    lease["context_digest"],
                    digest(event.action_id),
                    event.action_digest,
                ):
                    raise CoordinatorRejected("coordinator.review_anchor_missing_or_foreign")
            if event.action_id is not None and any(
                row["context_digest"] == lease["context_digest"]
                and row["action_id_digest"] == digest(event.action_id)
                and row["action_digest"] != event.action_digest
                for row in events.values()
            ):
                raise CoordinatorRejected("coordinator.action_identity_digest_conflict")
            events[alias] = {
                "kind": event.event_kind,
                "subject": subject,
                "context_digest": lease["context_digest"],
                "producer": lease["producer"],
                "sequence": event.source_sequence,
                "parents": [
                    self._event_alias(handle, parent.event_id) for parent in event.parent_event_ids
                ],
                "review": review,
                "action_digest": event.action_digest,
                "action_id_digest": digest(event.action_id) if event.action_id else None,
                "resources": list(event.resource_digests),
                "evidence_class": event.evidence_class,
                "admitted_at": transaction.now,
                "submitted_digest": event.digest,
            }
            stream["sequences"][seq] = alias
            stream["highest"] = max(stream["highest"], event.source_sequence)
            while str(stream["contiguous"] + 1) in stream["sequences"]:
                stream["contiguous"] += 1
            incomplete = self._event_gaps(events, streams)
            state["events"], state["streams"], state["event_incomplete"] = (
                events,
                streams,
                incomplete,
            )
            transaction.append(
                handle.scope_key,
                "event_ingested",
                event.digest,
                {"event_digest": digest(alias), "incomplete": incomplete},
                maximum=self._limit,
            )
            return {
                "event_digest": digest(alias),
                "status": "accepted",
                "incomplete": incomplete,
                "execution_authority": False,
            }

    @staticmethod
    def _artifact_snapshot(scope):
        gateway = scope.artifacts
        if gateway is None:
            return {}
        with gateway._lock:
            return {
                digest(address.as_dict()): {
                    "version": resource.highwater,
                    "labels": list(resource.labels.labels),
                    "deleted": resource.deleted,
                    "last_digest": resource.last_digest,
                }
                for address, resource in gateway._resources.items()
            }

    @classmethod
    def _check_artifacts(cls, scope, state, *, deleting=False):
        current = cls._artifact_snapshot(scope)
        for key, floor in state["artifact_floors"].items():
            row = current.get(key)
            if (
                row is None
                or row["version"] < floor["version"]
                or not set(floor["labels"]) <= set(row["labels"])
            ):
                raise CoordinatorRejected("coordinator.artifact_history_requires_reconciliation")
            if (
                row["version"] == floor["version"]
                and row != floor
                and not (deleting and row == {**floor, "deleted": True})
            ):
                raise CoordinatorRejected("coordinator.artifact_version_or_tombstone_changed")

    def checkpoint(
        self, handle: CoordinatorScope, *, control: CoordinatorControlSource
    ) -> dict[str, Any]:
        self._control_check(control)
        scope = self._scope(handle)
        with self.store.transaction() as transaction:
            _, state = self._owner(transaction, handle, allow_incomplete=True, allow_contained=True)
            self._check_artifacts(scope, state)
            artifacts = self._artifact_snapshot(scope)
            temporal = self._temporal_snapshot(scope)
            projection = {
                "events": state["events"],
                "streams": state["streams"],
                "artifacts": artifacts,
                "temporal": temporal,
                "prehistory": "unknown",
                "live_authority": False,
            }
            projection_digest = digest(projection)
            if state.get("projection_digest") != projection_digest:
                transaction.append(
                    handle.scope_key,
                    "projection_materialized",
                    projection_digest,
                    {"projection_digest": projection_digest},
                    maximum=self._limit,
                )
            state["artifact_floors"], state["temporal_projection"], state["projection_digest"] = (
                artifacts,
                temporal,
                projection_digest,
            )
            return transaction.checkpoint(handle.scope_key, projection)

    @staticmethod
    def _temporal_snapshot(scope):
        engine = scope.temporal
        if engine is None:
            return None
        with engine._lock:
            return {
                "binding_digest": engine.binding_digest,
                "policy_digest": engine.policy_digest,
                "configuration_digest": engine.configuration_digest,
                "historical_only": True,
                "facts": {
                    digest(key): {
                        "fingerprint": row.fingerprint,
                        "event_digest": row.event_digest,
                        "actor_digest": digest(row.identity.as_dict()),
                        "admitted_at": row.observed_at,
                        "signals": sorted(row.semantics.signals),
                        "operation_digest": digest(row.semantics.operation),
                        "labels": sorted(row.labels),
                        "origins": sorted(row.origins),
                        "lineage_complete": row.lineage_complete,
                        "observation_digest": row.observation.digest if row.observation else None,
                    }
                    for key, row in engine._facts.items()
                },
                "coverage": [
                    {
                        "source_digest": digest(source.source_id),
                        "context_digest": digest(row[0].as_dict()),
                        "complete_from": row[1],
                    }
                    for source, row in engine._coverage.items()
                ],
            }

    @classmethod
    def _check_temporal(cls, scope, state):
        prior = state["temporal_projection"]
        if prior is None:
            return
        current = cls._temporal_snapshot(scope)
        if current is None or any(
            current["facts"].get(key, {}).get("fingerprint") != row["fingerprint"]
            for key, row in prior["facts"].items()
        ):
            raise CoordinatorRejected("coordinator.temporal_history_requires_reconciliation")

    def history(
        self, handle: CoordinatorScope, *, control: CoordinatorControlSource
    ) -> dict[str, Any]:
        self._control_check(control)
        self._scope(handle)
        with self.store.transaction() as transaction:
            state = transaction.scope(handle.scope_key)
            row = transaction.connection.execute(
                "SELECT state_json,state_digest FROM coordinator_checkpoints WHERE scope_key=? ORDER BY sequence DESC",
                (handle.scope_key,),
            ).fetchone()
            if row is None:
                if state["checkpoint_digest"] is not None:
                    raise CoordinatorUnavailable("coordinator checkpoint history missing")
                return {"prehistory": "unknown", "live_authority": False, "projection": None}
            from .coordinator_store import decode

            snapshot = decode(row["state_json"])
            if (
                digest(snapshot) != row["state_digest"]
                or row["state_digest"] != state["checkpoint_digest"]
            ):
                raise CoordinatorUnavailable("coordinator checkpoint history changed")
            return snapshot

    def artifact_write(
        self,
        handle: CoordinatorScope,
        source: HostEventSource,
        address: ArtifactAddress,
        value: str,
        *,
        expected_version: int,
        inputs: tuple[LineageHandle, ...] = (),
        grant: ArtifactGrant | None = None,
    ) -> SwarmArtifact:
        return self._artifact_transition(
            handle,
            "write",
            source,
            address,
            value=value,
            expected_version=expected_version,
            inputs=inputs,
            grant=grant,
        )

    def budget_view(
        self, handle: CoordinatorScope, *, control: CoordinatorControlSource
    ) -> CoordinatorBudgetView:
        self._control_check(control)
        scope = self._scope(handle)
        if scope.runtime is None:
            raise ValueError("coordinator budget view requires its original policy runtime")
        for view in self._budget_views:
            if view._handle is handle:
                return view
        view = CoordinatorBudgetView(self, handle)
        self._budget_views.add(view)
        scope.runtime.bind_coordinator_budget(view, operator=self._operator)
        return view

    def artifact_delete(
        self,
        handle: CoordinatorScope,
        source: HostEventSource,
        address: ArtifactAddress,
        *,
        expected_version: int,
        grant: ArtifactGrant | None = None,
    ) -> None:
        return self._artifact_transition(
            handle, "delete", source, address, expected_version=expected_version, grant=grant
        )

    def _artifact_transition(self, handle, operation, source, address, **arguments):
        scope = self._scope(handle)
        if scope.artifacts is None:
            raise CoordinatorRejected("coordinator.managed_artifact_gateway_required")
        gateway, reference = scope.artifacts, uuid4().hex
        # Authenticate the original host source and scope before journaling an intent.
        context = gateway._actor(source, address).context
        auth_scope = scope.authenticator._scope
        if auth_scope is None:
            raise CoordinatorRejected("coordinator.original_task_scope_required")
        if (context.identity.tenant_id, context.identity.swarm_id, context.identity.task_id) != (
            scope.tenant_id,
            scope.swarm_id,
            auth_scope[2],
        ):
            raise CoordinatorRejected("coordinator.artifact_scope_mismatch")
        with self.store.transaction() as transaction:
            _, state = self._owner(transaction, handle)
            before = self._artifact_snapshot(scope)
            state["artifact_pending"].append(reference)
            transaction.append(
                handle.scope_key,
                "artifact_intent",
                reference,
                {"operation": operation, "address_digest": digest(address.as_dict())},
                maximum=self._limit,
            )
        try:
            result = getattr(gateway, operation)(source, address, **arguments)
            with self.store.transaction() as transaction:
                _, state = self._owner(transaction, handle, allow_incomplete=True)
                self._check_artifacts(scope, state, deleting=operation == "delete")
                state["artifact_floors"] = self._artifact_snapshot(scope)
                state["artifact_pending"].remove(reference)
                transaction.append(
                    handle.scope_key,
                    "artifact_committed",
                    reference,
                    {"snapshot_digest": digest(state["artifact_floors"])},
                    maximum=self._limit,
                )
            return result
        except BaseException:
            # The gateway marks any partial backing-store effect faulted. A
            # known validation denial may clear its intent only when the same
            # original gateway remains healthy and its full metadata is unchanged.
            if not gateway._fault and self._artifact_snapshot(scope) == before:
                try:
                    with self.store.transaction() as transaction:
                        _, state = self._owner(transaction, handle, allow_incomplete=True)
                        if reference in state["artifact_pending"]:
                            state["artifact_pending"].remove(reference)
                            transaction.append(
                                handle.scope_key,
                                "artifact_rejected_no_effect",
                                reference,
                                {},
                                maximum=self._limit,
                            )
                except (CoordinatorUnavailable, CoordinatorRejected):
                    pass
            # Partial/unknown effects or acknowledgements retain the durable hold.
            raise

    def revoke_lease(
        self, handle: CoordinatorScope, channel: AuthorityChannel, lease_id: str
    ) -> dict[str, Any]:
        with self.store.transaction() as transaction:
            _, state, _, subject, _ = self._lease(
                transaction, handle, channel, lease_id, allow_incomplete=True
            )
            epoch, _ = self._fence_state(transaction, state, "agent", subject)
            return {
                "schema_version": "ordin.swarm_coordinator_revocation.v1",
                "scope_digest": handle.scope_key,
                "revocation_epoch": epoch,
                "status": "revoked",
                "execution_authority": False,
            }

    def workload_status(
        self, handle: CoordinatorScope, channel: AuthorityChannel, lease_id: str
    ) -> dict[str, Any]:
        with self.store.transaction() as transaction:
            _, state, _, _, _ = self._lease(
                transaction, handle, channel, lease_id, allow_incomplete=True
            )
            return self._status(transaction, handle, state)

    def artifact_sweep(
        self,
        handle: CoordinatorScope,
        *,
        control: CoordinatorControlSource,
        maximum_resources: int = 256,
    ) -> dict[str, Any]:
        self._control_check(control)
        if type(maximum_resources) is not int or not 1 <= maximum_resources <= 4096:
            raise ValueError("bounded artifact retention batch required")
        scope = self._scope(handle)
        gateway = scope.artifacts
        if gateway is None or scope.authenticator._scope is None:
            raise CoordinatorRejected("coordinator.managed_artifact_gateway_required")
        reference = uuid4().hex
        with self.store.transaction() as transaction:
            _, state = self._owner(transaction, handle)
            state["artifact_pending"].append(reference)
            transaction.append(
                handle.scope_key, "artifact_sweep_intent", reference, {}, maximum=self._limit
            )
        result = gateway.sweep(
            operator=self._operator,
            tenant_id=scope.tenant_id,
            swarm_id=scope.swarm_id,
            task_id=scope.authenticator._scope[2],
            maximum_resources=maximum_resources,
        )
        with self.store.transaction() as transaction:
            _, state = self._owner(transaction, handle, allow_incomplete=True)
            self._check_artifacts(scope, state, deleting=True)
            state["artifact_floors"] = self._artifact_snapshot(scope)
            state["artifact_pending"].remove(reference)
            transaction.append(
                handle.scope_key,
                "artifact_sweep_completed",
                reference,
                {
                    "versions_removed": result["versions_removed"],
                    "tombstones_retained": result["tombstones_retained"],
                },
                maximum=self._limit,
            )
        return result
