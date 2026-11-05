"""Original protected policy facts; data and serialized receipts are not authority."""

from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
import time
from typing import Any, Callable
from uuid import uuid4

from ordin.action import ActionEnvelope
from ordin._runtime_json import digest

from .events import _hex
from .labels import LABELS
from .models import SwarmContext, counter, identifier, timestamp
from .policy_set import MESSAGE_CLASSES, SwarmBudgetCondition, _strings, _typed


@dataclass(frozen=True, slots=True)
class SwarmBudgetFact:
    scope: str
    metric: str
    remaining: int

    def __post_init__(self) -> None:
        SwarmBudgetCondition(self.scope, self.metric, self.remaining)

    def as_dict(self) -> dict[str, Any]:
        return {"scope": self.scope, "metric": self.metric, "remaining": self.remaining}


@dataclass(frozen=True, eq=False, slots=True)
class SwarmPolicyFacts:
    fact_id: str
    generation: int
    action_digest: str
    context_digest: str
    policy_digest: str
    snapshot_digest: str
    expires_at: float
    data_labels: tuple[str, ...] | None
    message_classes: tuple[str, ...] | None
    temporal_categories: tuple[str, ...] | None
    budgets: tuple[SwarmBudgetFact, ...] | None
    checks: tuple[tuple[str, str], ...]

    def _payload(self) -> dict[str, Any]:
        identifier(self.fact_id, "fact_id")
        counter(self.generation, "fact_generation")
        for name in ("action_digest", "context_digest", "policy_digest", "snapshot_digest"):
            _hex(getattr(self, name), name)
        timestamp(self.expires_at)
        for name, allowed in (
            ("data_labels", LABELS),
            ("message_classes", MESSAGE_CLASSES),
            ("temporal_categories", None),
        ):
            value = getattr(self, name)
            if value is not None:
                _strings(value, allowed=allowed)
        if self.budgets is not None:
            _typed(self.budgets, SwarmBudgetFact, maximum=64)
            if len({(v.scope, v.metric) for v in self.budgets}) != len(self.budgets):
                raise ValueError("ambiguous protected budget facts")
        if type(self.checks) is not tuple or len(self.checks) > 64:
            raise ValueError("invalid bounded protected policy checks")
        for pair in self.checks:
            if type(pair) is not tuple or len(pair) != 2:
                raise ValueError("invalid protected policy check")
            identifier(pair[0], "check_id")
            if pair[1] not in {"satisfied", "violated", "unknown"}:
                raise ValueError("invalid protected check status")
        if len({v[0] for v in self.checks}) != len(self.checks):
            raise ValueError("ambiguous protected policy checks")
        return {
            "fact_id": self.fact_id,
            "generation": self.generation,
            "action_digest": self.action_digest,
            "context_digest": self.context_digest,
            "policy_digest": self.policy_digest,
            "snapshot_digest": self.snapshot_digest,
            "expires_at": self.expires_at,
            "data_labels": None if self.data_labels is None else list(self.data_labels),
            "message_classes": None if self.message_classes is None else list(self.message_classes),
            "temporal_categories": None
            if self.temporal_categories is None
            else list(self.temporal_categories),
            "budgets": None if self.budgets is None else [v.as_dict() for v in self.budgets],
            "checks": [{"check_id": key, "status": value} for key, value in self.checks],
        }

    @property
    def digest(self) -> str:
        return digest(self._payload())

    @classmethod
    def from_dict(cls, value):
        raise ValueError("JSON cannot authenticate policy facts")


class SwarmPolicyFactsSource:
    """Host-only fact issuer; collectors validate actual inputs before issuing.

    This authenticates host declarations, not their independent physical truth.
    Models/callback payloads must never receive access to this issuing API.
    """

    def __init__(
        self, *, clock: Callable[[], float] = time.monotonic, max_facts: int = 4096
    ) -> None:
        if not callable(clock) or type(max_facts) is not int or not 1 <= max_facts <= 16384:
            raise ValueError("invalid bounded policy fact source")
        self._clock, self._limit = clock, max_facts
        self._now_last, self._generation = 0.0, 0
        self._nonce = uuid4().hex
        self._issued: dict[SwarmPolicyFacts, str] = {}
        self._lock = RLock()

    def _now(self) -> float:
        value = timestamp(self._clock())
        if value < self._now_last:
            raise ValueError("policy fact clock moved backward")
        self._now_last = value
        return value

    @property
    def binding_digest(self) -> str:
        with self._lock:
            return digest([self._nonce, self._generation])

    def issue(
        self,
        context: SwarmContext,
        action: ActionEnvelope,
        *,
        policy_digest: str,
        snapshot_digest: str,
        data_labels: tuple[str, ...] | None = None,
        message_classes: tuple[str, ...] | None = None,
        temporal_categories: tuple[str, ...] | None = None,
        budgets: tuple[SwarmBudgetFact, ...] | None = None,
        checks: tuple[tuple[str, str], ...] = (),
        lifetime: float = 30,
    ) -> SwarmPolicyFacts:
        if (
            type(context) is not SwarmContext
            or type(action) is not ActionEnvelope
            or not 0 < timestamp(lifetime) <= 300
        ):
            raise ValueError("exact typed policy fact scope and lifetime required")
        with self._lock:
            if len(self._issued) >= self._limit:
                raise ValueError("policy fact capacity reached")
            receipt = SwarmPolicyFacts(
                uuid4().hex,
                self._generation,
                digest(action.as_dict()),
                digest(context.as_dict()),
                policy_digest,
                snapshot_digest,
                self._now() + lifetime,
                data_labels,
                message_classes,
                temporal_categories,
                budgets,
                checks,
            )
            self._issued[receipt] = receipt.digest
            return receipt

    def verify(
        self,
        receipt: SwarmPolicyFacts,
        context: SwarmContext,
        action: ActionEnvelope,
        *,
        policy_digest: str,
        snapshot_digest: str,
    ) -> bool:
        with self._lock:
            if type(receipt) is not SwarmPolicyFacts:
                return False
            expected = self._issued.get(receipt)
            if expected is None:
                return False
            try:
                return (
                    expected == receipt.digest
                    and receipt.generation == self._generation
                    and self._now() < receipt.expires_at
                    and (
                        receipt.action_digest,
                        receipt.context_digest,
                        receipt.policy_digest,
                        receipt.snapshot_digest,
                    )
                    == (
                        digest(action.as_dict()),
                        digest(context.as_dict()),
                        policy_digest,
                        snapshot_digest,
                    )
                )
            except (ValueError, TypeError, AttributeError):
                return False

    def fence(self) -> None:
        with self._lock:
            self._generation = counter(self._generation + 1, "policy_fact_generation")
            self._issued.clear()
