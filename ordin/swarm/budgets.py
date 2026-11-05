"""Host-owned atomic quotas and exact-action reservations, never execution permits."""

from __future__ import annotations

from dataclasses import dataclass, field
from contextlib import contextmanager
import sqlite3
from threading import RLock
import time
from typing import Any, Callable, Iterator
from uuid import uuid4

from ordin.action import ActionEnvelope
from ordin._runtime_json import digest

from .budget_store import BudgetRejected, InMemoryBudgetStore, SQLiteBudgetStore
from .identity import HostChannel
from .models import SwarmContext, counter, identifier, timestamp
from .registry import InMemoryAgentRegistry


METRICS = frozenset(
    {
        "dollar_micros",
        "tokens",
        "external_operations",
        "child_spawns",
        "requests",
        "concurrency",
        "output_bytes",
        "destructive_actions",
        "tool_calls",
        "processes",
    }
)
MAX_UNITS = 10**12
_ACTIVE = {"reserved", "forwarding", "uncertain"}


def _amount(value: int, *, maximum: int = MAX_UNITS) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("invalid bounded budget quantity")
    return value


@dataclass(frozen=True, slots=True)
class BudgetCost:
    metric: str
    amount: int | None

    def __post_init__(self) -> None:
        if type(self.metric) is not str or self.metric not in METRICS:
            raise ValueError("unknown budget metric")
        if self.amount is not None:
            _amount(self.amount)


@dataclass(frozen=True, slots=True)
class BudgetLimit:
    scope: str
    metric: str
    maximum: int
    subject: str | None = None
    unknown_ceiling: int | None = None
    unknown_effects: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if type(self.scope) is not str or self.scope not in {"tenant", "swarm", "task", "agent"}:
            raise ValueError("unknown budget scope")
        BudgetCost(self.metric, 0)
        _amount(self.maximum, maximum=10**15)
        if self.subject is not None:
            identifier(self.subject, "budget_subject")
        if self.scope in {"tenant", "swarm"} and self.subject is not None:
            raise ValueError("tenant/swarm budgets derive identity from the protected registry")
        if self.unknown_ceiling is not None:
            _amount(self.unknown_ceiling)
            if self.unknown_ceiling == 0 or self.unknown_ceiling > self.maximum:
                raise ValueError("unknown cost ceiling exceeds operator maximum")
        if (
            type(self.unknown_effects) is not tuple
            or len(self.unknown_effects) > 64
            or any(type(v) is not str for v in self.unknown_effects)
            or len(set(self.unknown_effects)) != len(self.unknown_effects)
        ):
            raise ValueError("bounded immutable unknown-cost effects required")
        for effect in self.unknown_effects:
            identifier(effect, "unknown_effect")

    def as_dict(self) -> dict[str, Any]:
        return {
            name: getattr(self, name)
            for name in (
                "scope",
                "metric",
                "maximum",
                "subject",
                "unknown_ceiling",
                "unknown_effects",
            )
        }


@dataclass(frozen=True, slots=True)
class BudgetPolicy:
    policy_epoch: int
    limits: tuple[BudgetLimit, ...]
    reservation_lifetime: float = 30
    max_reservations: int = 4096
    require_physical_enforcement: bool = False

    def __post_init__(self) -> None:
        counter(self.policy_epoch, "budget_policy_epoch")
        if (
            type(self.limits) is not tuple
            or not 1 <= len(self.limits) <= 64
            or any(type(v) is not BudgetLimit for v in self.limits)
        ):
            raise ValueError("bounded protected budget limits required")
        for limit in self.limits:
            limit.__post_init__()
        if len({(v.scope, v.metric, v.subject) for v in self.limits}) != len(self.limits):
            raise ValueError("duplicate budget limit selector")
        if (
            not 0 < timestamp(self.reservation_lifetime) <= 3600
            or type(self.max_reservations) is not int
            or not 1 <= self.max_reservations <= 16384
        ):
            raise ValueError("invalid bounded budget reservation policy")
        if type(self.require_physical_enforcement) is not bool:
            raise ValueError("physical budget requirement must be protected configuration")

    @property
    def digest(self) -> str:
        self.__post_init__()
        return digest(
            {
                "epoch": self.policy_epoch,
                "limits": [v.as_dict() for v in self.limits],
                "lifetime": self.reservation_lifetime,
                "capacity": self.max_reservations,
                "require_physical_enforcement": self.require_physical_enforcement,
            }
        )


class BudgetError(BudgetRejected):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, eq=False, slots=True)
class BudgetTicket:
    reservation_id: str

    @classmethod
    def from_dict(cls, value):
        raise ValueError("JSON cannot issue a budget ticket")


@dataclass(frozen=True, eq=False, slots=True)
class BudgetObservation:
    reservation_id: str
    action_digest: str
    context_digest: str
    outcome: str
    costs: tuple[BudgetCost, ...]


class BudgetObservationSource:
    """Protected settlement channel; model text/dicts cannot issue refunds."""

    def __init__(self, *, max_receipts: int = 4096) -> None:
        if type(max_receipts) is not int or not 1 <= max_receipts <= 16384:
            raise ValueError("invalid observation receipt capacity")
        self._limit = max_receipts
        self._issued: dict[BudgetObservation, str] = {}
        self._lock = RLock()

    def record(
        self,
        reservation_id: str,
        action: ActionEnvelope,
        context: SwarmContext,
        *,
        outcome: str,
        costs: tuple[BudgetCost, ...],
    ) -> BudgetObservation:
        identifier(reservation_id, "reservation_id")
        if (
            type(action) is not ActionEnvelope
            or type(context) is not SwarmContext
            or type(outcome) is not str
            or outcome not in {"completed", "no_effect"}
        ):
            raise ValueError("typed exact settlement scope required")
        _costs(costs, observed=True)
        if outcome == "no_effect" and any(v.amount != 0 for v in costs):
            raise ValueError("no-effect settlement must attest zero expenditure")
        with self._lock:
            if len(self._issued) >= self._limit:
                raise ValueError("budget observation capacity reached")
            receipt = BudgetObservation(
                reservation_id, digest(action.as_dict()), digest(context.as_dict()), outcome, costs
            )
            self._issued[receipt] = _observation_digest(receipt)
            return receipt

    def verify(self, receipt: BudgetObservation) -> bool:
        with self._lock:
            if type(receipt) is not BudgetObservation:
                return False
            expected = self._issued.get(receipt)
            return expected is not None and expected == _observation_digest(receipt)


def _observation_digest(receipt: BudgetObservation) -> str:
    return digest(
        {
            "id": receipt.reservation_id,
            "action": receipt.action_digest,
            "context": receipt.context_digest,
            "outcome": receipt.outcome,
            "costs": [(v.metric, v.amount) for v in receipt.costs],
        }
    )


def _costs(values: tuple[BudgetCost, ...], *, observed: bool = False) -> dict[str, int | None]:
    if (
        type(values) is not tuple
        or len(values) > len(METRICS)
        or any(type(v) is not BudgetCost for v in values)
    ):
        raise ValueError("bounded protected budget costs required")
    for value in values:
        value.__post_init__()
    if (
        len({v.metric for v in values}) != len(values)
        or observed
        and any(v.amount is None for v in values)
    ):
        raise ValueError("duplicate or unknown observed budget metric")
    return {v.metric: v.amount for v in values}


@dataclass(frozen=True)
class _Binding:
    ticket: BudgetTicket
    registry: InMemoryAgentRegistry
    context_digest: str
    action_digest: str
    generation: int
    executor: Any = None
    executor_proof: Any = None
    physical_costs: tuple = ()


@dataclass(frozen=True)
class _Bucket:
    key: str
    limits: tuple[BudgetLimit, ...]

    @property
    def maximum(self) -> int:
        return min(v.maximum for v in self.limits)


class BudgetLedger:
    def __init__(
        self,
        registry: InMemoryAgentRegistry,
        policy: BudgetPolicy,
        *,
        store: InMemoryBudgetStore | SQLiteBudgetStore | None = None,
        clock: Callable[[], float] = time.time,
        operator: object,
        observations: BudgetObservationSource | None = None,
    ) -> None:
        if (
            type(registry) is not InMemoryAgentRegistry
            or type(policy) is not BudgetPolicy
            or not callable(clock)
            or type(operator) is not object
        ):
            raise ValueError("protected registry/policy/clock/operator required")
        if observations is not None and type(observations) is not BudgetObservationSource:
            raise ValueError("protected budget observation source required")
        if policy.policy_epoch != registry._policy_epoch:
            raise ValueError("budget policy epoch differs from the registry")
        self._registry, self.policy, self._clock, self._operator = registry, policy, clock, operator
        self._store = InMemoryBudgetStore() if store is None else store
        if type(self._store) not in {InMemoryBudgetStore, SQLiteBudgetStore}:
            raise ValueError("unsupported nontransactional budget backend")
        self._observations = observations
        self._issued: dict[str, _Binding] = {}
        self._executors: set = set()
        self._lock = RLock()
        self._nonce = uuid4().hex
        now = timestamp(clock())
        self._clock_state = [now]
        with self._store.transaction() as connection:
            meta = connection.execute("SELECT * FROM budget_meta WHERE singleton=1").fetchone()
            if meta is not None:
                if (
                    now < meta["last_now"]
                    or policy.policy_epoch < meta["epoch"]
                    or policy.policy_epoch == meta["epoch"]
                    and policy.digest != meta["policy_digest"]
                ):
                    raise BudgetError("budget.recovery_policy_or_clock_mismatch")
                self._generation = counter(meta["generation"] + 1, "budget_generation")
                # Reserved tickets were never handed to an executor. The new
                # generation fences every older begin_forward before releasing.
                for row in connection.execute(
                    "SELECT reservation_id FROM budget_reservations WHERE status='reserved'"
                ).fetchall():
                    self._release(connection, row[0], "canceled")
                connection.execute(
                    "UPDATE budget_reservations SET status='uncertain' WHERE status='forwarding'"
                )
            else:
                self._generation = 1
            connection.execute(
                "INSERT OR REPLACE INTO budget_meta VALUES(1,?,?,?,?,?)",
                (policy.digest, policy.policy_epoch, self._generation, self._nonce, now),
            )

    def bind_executor(self, executor, *, operator: object) -> None:
        from .broker import SwarmExecutionBroker

        if (
            operator is not self._operator
            or type(executor) is not SwarmExecutionBroker
            or executor._budget is not self
        ):
            raise BudgetError("budget.protected_original_executor_required")
        with self._lock:
            self._executors.add(executor)

    def for_registry(self, registry: InMemoryAgentRegistry) -> BudgetLedger:
        """Protected same-coordinator view; tenant counters aggregate across swarms."""
        if (
            type(registry) is not InMemoryAgentRegistry
            or registry._policy_epoch != self.policy.policy_epoch
        ):
            raise ValueError("invalid registry view for current budget authority")
        result = object.__new__(BudgetLedger)
        result.__dict__.update(self.__dict__)
        result._registry = registry
        return result

    def _meta(self, connection: sqlite3.Connection) -> float:
        meta = connection.execute("SELECT * FROM budget_meta WHERE singleton=1").fetchone()
        if (
            meta is None
            or meta["generation"] != self._generation
            or meta["nonce"] != self._nonce
            or meta["policy_digest"] != self.policy.digest
        ):
            raise BudgetError("budget.coordinator_fenced")
        now = timestamp(self._clock())
        if now < max(meta["last_now"], self._clock_state[0]):
            raise BudgetError("budget.clock_moved_backward")
        self._clock_state[0] = now
        connection.execute("UPDATE budget_meta SET last_now=? WHERE singleton=1", (now,))
        return now

    def _scopes(
        self, context: SwarmContext, channel: HostChannel, adapter: object
    ) -> dict[str, tuple[str, ...]]:
        with self._registry._lock:
            self._registry.authenticate(context, channel, adapter)
            if context.identity.policy_epoch != self.policy.policy_epoch:
                raise BudgetError("budget.stale_policy_epoch")
            identity = context.identity
            agents, tasks = (
                [identity.agent_id],
                ([] if identity.task_id is None else [identity.task_id]),
            )
            current = identity
            for _ in range(self._registry._max_parent_depth):
                if current.parent_agent_id is None:
                    break
                parent = self._registry._agents[current.parent_agent_id].context.identity
                agents.append(parent.agent_id)
                if parent.task_id is not None:
                    tasks.append(parent.task_id)
                current = parent
            return {
                "tenant": (identity.tenant_id,),
                "swarm": (identity.swarm_id,),
                "task": tuple(dict.fromkeys(tasks)),
                "agent": tuple(agents),
            }

    def _buckets(self, context: SwarmContext, scopes: dict[str, tuple[str, ...]]) -> list[_Bucket]:
        result: dict[str, list[BudgetLimit]] = {}
        for limit in self.policy.limits:
            if limit.scope == "task" and not scopes["task"]:
                raise BudgetError("budget.missing_task_identity")
            for subject in scopes[limit.scope]:
                if limit.subject is not None and limit.subject != subject:
                    continue
                identity = context.identity
                parts = [
                    "ordin.swarm.budget.bucket.v1",
                    limit.scope,
                    limit.metric,
                    identity.tenant_id,
                ]
                if limit.scope != "tenant":
                    parts.append(identity.swarm_id)
                if limit.scope in {"agent", "task"}:
                    parts.append(subject)
                result.setdefault(digest(parts), []).append(limit)
        if not result or len(result) > 128:
            raise BudgetError("budget.missing_or_oversized_scope")
        return [_Bucket(key, tuple(limits)) for key, limits in result.items()]

    @staticmethod
    def _release(connection: sqlite3.Connection, reservation_id: str, status: str) -> None:
        for item in connection.execute(
            "SELECT * FROM budget_items WHERE reservation_id=?", (reservation_id,)
        ).fetchall():
            connection.execute(
                "UPDATE budget_buckets SET held=held-? WHERE bucket=?",
                (item["amount"], item["bucket"]),
            )
        connection.execute(
            "UPDATE budget_reservations SET status=? WHERE reservation_id=?",
            (status, reservation_id),
        )

    def _expire(self, connection: sqlite3.Connection, now: float) -> int:
        rows = connection.execute(
            "SELECT reservation_id FROM budget_reservations WHERE status='reserved' AND expires_at<=?",
            (now,),
        ).fetchall()
        for row in rows:
            self._release(connection, row[0], "expired")
        return len(rows)

    @staticmethod
    def default_costs() -> tuple[BudgetCost, ...]:
        return (BudgetCost("requests", 1), BudgetCost("concurrency", 1))

    @contextmanager
    def _admission_transaction(self) -> Iterator[tuple[sqlite3.Connection, list[_Binding]]]:
        with self._lock:
            staged: list[_Binding] = []
            with self._store.transaction() as connection:
                yield connection, staged
            # The store context must confirm durable commit before any original
            # live ticket is published. Rollback or lost ACK publishes nothing.
            for binding in staged:
                self._issued[binding.ticket.reservation_id] = binding

    def reserve(
        self,
        context: SwarmContext,
        action: ActionEnvelope,
        *,
        channel: HostChannel,
        adapter: object,
        idempotency_key: str,
        costs: tuple[BudgetCost, ...] = (),
        effects: tuple[str, ...] = (),
        executor=None,
        executor_proof=None,
    ) -> BudgetTicket:
        identifier(idempotency_key, "idempotency_key")
        if type(action) is not ActionEnvelope or action.action_id is None:
            raise ValueError("budget reservation requires an exact host-correlated action")
        if type(effects) is not tuple or len(effects) > 64:
            raise ValueError("bounded protected action effects required")
        for effect in effects:
            identifier(effect, "effect")
        values = _costs(costs)
        # A reservation always covers at least one possible forwarding call.
        # These local counts cannot be reduced by provider/model cost fields.
        for metric in ("requests", "concurrency"):
            value = values.get(metric)
            values[metric] = 1 if value is None else max(1, value)
        scopes = self._scopes(context, channel, adapter)
        buckets = self._buckets(context, scopes)
        resolved = dict(values)
        for metric in {bucket.limits[0].metric for bucket in buckets}:
            if resolved.get(metric) is None:
                selected_limits = [
                    limit for bucket in buckets for limit in bucket.limits if limit.metric == metric
                ]
                if any(
                    limit.unknown_ceiling is None
                    or limit.unknown_effects
                    and not set(limit.unknown_effects).intersection(effects)
                    for limit in selected_limits
                ):
                    raise BudgetError("budget.unknown_cost")
                resolved[metric] = max(limit.unknown_ceiling or 0 for limit in selected_limits)
        physical_costs = tuple(
            BudgetCost(metric, resolved[metric])
            for metric in sorted({bucket.limits[0].metric for bucket in buckets})
        )
        if self.policy.require_physical_enforcement and (
            executor not in self._executors
            or not executor.verify_budget_proof(executor_proof, context, action, physical_costs)
        ):
            raise BudgetError("budget.physical_enforcement_unavailable")
        action_digest, context_digest = digest(action.as_dict()), digest(context.as_dict())
        key = digest([context.identity.tenant_id, idempotency_key])
        cost_digest = digest({"costs": values, "effects": effects})
        with self._admission_transaction() as (connection, staged):
            now = self._meta(connection)
            self._expire(connection, now)
            previous = connection.execute(
                "SELECT * FROM budget_reservations WHERE idempotency_digest=?", (key,)
            ).fetchone()
            if previous is not None:
                binding = self._issued.get(previous["reservation_id"])
                if (
                    previous["status"] != "reserved"
                    or binding is None
                    or previous["context_digest"] != context_digest
                    or previous["action_digest"] != action_digest
                    or previous["costs_digest"] != cost_digest
                ):
                    raise BudgetError("budget.idempotency_conflict_or_consumed")
                return binding.ticket
            if (
                connection.execute("SELECT count(*) FROM budget_reservations").fetchone()[0]
                >= self.policy.max_reservations
            ):
                raise BudgetError("budget.history_capacity_reached")
            charges = []
            for selected in buckets:
                bucket, limit = selected.key, selected.limits[0]
                amount = resolved[limit.metric]
                if amount is None:
                    raise AssertionError("resolved budget cost missing")
                state = connection.execute(
                    "SELECT * FROM budget_buckets WHERE bucket=?", (bucket,)
                ).fetchone()
                held, consumed = (0, 0) if state is None else (state["held"], state["consumed"])
                if state is not None and state["blocked_epoch"] >= self.policy.policy_epoch:
                    raise BudgetError("budget.observed_cost_exceeded_bound")
                if held + consumed + amount > selected.maximum:
                    raise BudgetError("budget.limit_exceeded")
                charges.append((bucket, limit.metric, amount))
            reservation_id = uuid4().hex
            connection.execute(
                "INSERT INTO budget_reservations VALUES(?,?,?,?,?,?,?,?,?,NULL)",
                (
                    reservation_id,
                    key,
                    context_digest,
                    action_digest,
                    cost_digest,
                    self.policy.policy_epoch,
                    self._generation,
                    "reserved",
                    now + self.policy.reservation_lifetime,
                ),
            )
            for bucket, metric, amount in charges:
                connection.execute(
                    "INSERT OR IGNORE INTO budget_buckets VALUES(?,?,0,0,0,0,-1)", (bucket, metric)
                )
                connection.execute(
                    "UPDATE budget_buckets SET held=held+? WHERE bucket=?", (amount, bucket)
                )
                connection.execute(
                    "INSERT INTO budget_items VALUES(?,?,?,?)",
                    (reservation_id, bucket, metric, amount),
                )
            ticket = BudgetTicket(reservation_id)
            staged.append(
                _Binding(
                    ticket,
                    self._registry,
                    context_digest,
                    action_digest,
                    self._generation,
                    executor if self.policy.require_physical_enforcement else None,
                    executor_proof,
                    physical_costs,
                )
            )
            return ticket

    def _ticket(self, connection: sqlite3.Connection, ticket: BudgetTicket):
        if type(ticket) is not BudgetTicket:
            raise BudgetError("budget.original_ticket_required")
        binding = self._issued.get(ticket.reservation_id)
        if (
            binding is None
            or binding.ticket is not ticket
            or binding.registry is not self._registry
        ):
            raise BudgetError("budget.original_ticket_required")
        row = connection.execute(
            "SELECT * FROM budget_reservations WHERE reservation_id=?", (ticket.reservation_id,)
        ).fetchone()
        if (
            row is None
            or row["generation"] != self._generation
            or row["action_digest"] != binding.action_digest
            or row["context_digest"] != binding.context_digest
        ):
            raise BudgetError("budget.stale_ticket")
        return row

    def begin_forward(
        self,
        ticket: BudgetTicket,
        context: SwarmContext,
        action: ActionEnvelope,
        *,
        channel: HostChannel,
        adapter: object,
    ) -> None:
        self._scopes(context, channel, adapter)
        binding = self._issued.get(ticket.reservation_id) if type(ticket) is BudgetTicket else None
        if self.policy.require_physical_enforcement and (
            binding is None
            or binding.executor not in self._executors
            or not binding.executor.verify_budget_proof(
                binding.executor_proof, context, action, binding.physical_costs
            )
        ):
            raise BudgetError("budget.physical_enforcement_unavailable")
        with self._lock, self._store.transaction() as connection:
            now = self._meta(connection)
            self._expire(connection, now)
            row = self._ticket(connection, ticket)
            if (
                row["status"] != "reserved"
                or row["expires_at"] <= now
                or row["context_digest"] != digest(context.as_dict())
                or row["action_digest"] != digest(action.as_dict())
                or context.identity.policy_epoch != self.policy.policy_epoch
            ):
                raise BudgetError("budget.forward_binding_or_state_invalid")
            connection.execute(
                "UPDATE budget_reservations SET status='forwarding' WHERE reservation_id=?",
                (ticket.reservation_id,),
            )

    def cancel(self, ticket: BudgetTicket) -> None:
        with self._lock, self._store.transaction() as connection:
            self._meta(connection)
            row = self._ticket(connection, ticket)
            if row["status"] in {"canceled", "expired"}:
                return
            if row["status"] != "reserved":
                raise BudgetError("budget.forwarded_reservation_requires_reconciliation")
            self._release(connection, ticket.reservation_id, "canceled")

    def expire(self) -> int:
        with self._lock, self._store.transaction() as connection:
            return self._expire(connection, self._meta(connection))

    def uncertain(self, ticket: BudgetTicket) -> None:
        with self._lock, self._store.transaction() as connection:
            self._meta(connection)
            row = self._ticket(connection, ticket)
            if row["status"] == "uncertain":
                return
            if row["status"] != "forwarding":
                raise BudgetError("budget.uncertain_requires_forwarding")
            connection.execute(
                "UPDATE budget_reservations SET status='uncertain' WHERE reservation_id=?",
                (ticket.reservation_id,),
            )

    def _settle(
        self, connection: sqlite3.Connection, row, observation: BudgetObservation | None
    ) -> str:
        observed: dict[str, int | None] = {}
        settlement_digest = None
        if observation is not None:
            if (
                self._observations is None
                or not self._observations.verify(observation)
                or (
                    observation.reservation_id,
                    observation.action_digest,
                    observation.context_digest,
                )
                != (row["reservation_id"], row["action_digest"], row["context_digest"])
            ):
                raise BudgetError("budget.original_bound_settlement_required")
            observed = _costs(observation.costs, observed=True)
            settlement_digest = _observation_digest(observation)
        items = connection.execute(
            "SELECT * FROM budget_items WHERE reservation_id=?", (row["reservation_id"],)
        ).fetchall()
        metrics = {item["metric"] for item in items}
        if observation is not None and set(observed) != metrics:
            raise BudgetError("budget.settlement_metric_coverage_mismatch")
        late_settlement = (
            row["status"] == "committed"
            and row["settlement_digest"] is None
            and observation is not None
        )
        if row["status"] in {"committed", "released", "overrun"} and not late_settlement:
            if observation is not None and row["settlement_digest"] != settlement_digest:
                raise BudgetError("budget.conflicting_settlement")
            return row["status"]
        if row["status"] not in {"forwarding", "uncertain"} and not late_settlement:
            raise BudgetError("budget.settlement_requires_forwarding")
        status = (
            "released"
            if observation is not None and observation.outcome == "no_effect"
            else "committed"
        )
        for item in items:
            value = observed.get(item["metric"])
            charge = (
                0
                if item["metric"] == "concurrency" or status == "released"
                else item["amount"]
                if value is None
                else value
            )
            if value is not None and value > item["amount"]:
                status = "overrun"
                connection.execute(
                    "UPDATE budget_buckets SET blocked_epoch=? WHERE bucket=?",
                    (self.policy.policy_epoch, item["bucket"]),
                )
            connection.execute(
                "UPDATE budget_buckets SET held=held-?, consumed=consumed+?, observed=observed+?, observations=observations+? WHERE bucket=?",
                (
                    0 if late_settlement else item["amount"],
                    charge - (0 if item["metric"] == "concurrency" else item["amount"])
                    if late_settlement
                    else charge,
                    0 if value is None or item["metric"] == "concurrency" else value,
                    int(value is not None),
                    item["bucket"],
                ),
            )
        connection.execute(
            "UPDATE budget_reservations SET status=?,settlement_digest=? WHERE reservation_id=?",
            (status, settlement_digest, row["reservation_id"]),
        )
        return status

    def commit(self, ticket: BudgetTicket, *, observation: BudgetObservation | None = None) -> str:
        """Host callback completed; without settlement charge the full reserved bound."""
        with self._lock, self._store.transaction() as connection:
            self._meta(connection)
            return self._settle(connection, self._ticket(connection, ticket), observation)

    def reconcile(
        self, reservation_id: str, *, operator: object, observation: BudgetObservation
    ) -> str:
        if operator is not self._operator:
            raise BudgetError("budget.protected_operator_required")
        identifier(reservation_id, "reservation_id")
        with self._lock, self._store.transaction() as connection:
            self._meta(connection)
            row = connection.execute(
                "SELECT * FROM budget_reservations WHERE reservation_id=?", (reservation_id,)
            ).fetchone()
            if row is None:
                raise BudgetError("budget.unknown_reservation")
            return self._settle(connection, row, observation)

    def report(
        self, context: SwarmContext, *, channel: HostChannel, adapter: object
    ) -> dict[str, Any]:
        scopes = self._scopes(context, channel, adapter)
        with self._lock, self._store.transaction() as connection:
            now = self._meta(connection)
            self._expire(connection, now)
            limits = []
            for selected in self._buckets(context, scopes):
                bucket, limit = selected.key, selected.limits[0]
                state = connection.execute(
                    "SELECT * FROM budget_buckets WHERE bucket=?", (bucket,)
                ).fetchone()
                held, consumed, observed, count = (
                    (0, 0, 0, 0)
                    if state is None
                    else (
                        state["held"],
                        state["consumed"],
                        state["observed"],
                        state["observations"],
                    )
                )
                limits.append(
                    {
                        "bucket_digest": bucket,
                        "scope": limit.scope,
                        "metric": limit.metric,
                        "maximum": selected.maximum,
                        "reserved": held,
                        "consumed": consumed,
                        "observed": observed if count else None,
                        "remaining": max(0, selected.maximum - held - consumed),
                        "blocked": state is not None
                        and state["blocked_epoch"] >= self.policy.policy_epoch,
                    }
                )
            return {
                "schema_version": "ordin.swarm_budget.v1",
                "policy_digest": self.policy.digest,
                "policy_epoch": self.policy.policy_epoch,
                "limits": limits,
                "execution_authority": False,
                "enforcement": "unsupported"
                if self.policy.require_physical_enforcement
                else "admission_accounting",
                "physical_enforcement": False,
            }

    def reservation_status(self, ticket: BudgetTicket) -> dict[str, Any]:
        with self._lock, self._store.transaction() as connection:
            self._expire(connection, self._meta(connection))
            row = self._ticket(connection, ticket)
            return {
                "schema_version": "ordin.swarm_budget_reservation.v1",
                "reservation_id": row["reservation_id"],
                "action_digest": row["action_digest"],
                "status": row["status"],
                "execution_authority": False,
            }

    def audit(self, *, operator: object, offset: int = 0, limit: int = 128) -> dict[str, Any]:
        if operator is not self._operator:
            raise BudgetError("budget.protected_operator_required")
        if (
            type(offset) is not int
            or not 0 <= offset <= 16384
            or type(limit) is not int
            or not 1 <= limit <= 256
        ):
            raise ValueError("invalid bounded budget audit page")
        with self._lock, self._store.transaction() as connection:
            self._expire(connection, self._meta(connection))
            rows = connection.execute(
                "SELECT reservation_id,action_digest,context_digest,epoch,status,expires_at FROM budget_reservations ORDER BY rowid LIMIT ? OFFSET ?",
                (limit + 1, offset),
            ).fetchall()
            return {
                "schema_version": "ordin.swarm_budget_audit.v1",
                "reservations": [
                    {
                        "reservation_id": row["reservation_id"],
                        "action_digest": row["action_digest"],
                        "context_digest": row["context_digest"],
                        "policy_epoch": row["epoch"],
                        "status": row["status"],
                        "expires_at": row["expires_at"],
                    }
                    for row in rows[:limit]
                ],
                "next_offset": offset + limit if len(rows) > limit else None,
                "execution_authority": False,
            }
