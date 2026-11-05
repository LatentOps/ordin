"""Action/snapshot-bound host assessments, never model-authored approval."""

from dataclasses import dataclass, field
from threading import RLock
import time
from typing import Any, Callable
from uuid import uuid4

from ordin._runtime_json import digest

from .events import _hex
from .models import counter, identifier, timestamp


@dataclass(frozen=True, slots=True)
class _AssessmentSeal:
    owner: object
    digest: str


@dataclass(frozen=True, slots=True)
class SwarmAssessment:
    receipt_id: str
    source_id: str
    generation: int
    check_id: str
    status: str
    action_digest: str
    context_digest: str
    policy_digest: str
    snapshot_digest: str
    expires_at: float
    reason_code: str
    _seal: _AssessmentSeal | None = field(default=None, repr=False, compare=False, kw_only=True)

    def _payload(self) -> dict:
        for name in ("receipt_id", "source_id", "check_id", "reason_code"):
            identifier(getattr(self, name), name)
        counter(self.generation, "assessment_generation")
        if type(self.status) is not str or self.status not in {"satisfied", "violated", "unknown"}:
            raise ValueError("invalid host swarm assessment")
        for name in ("action_digest", "context_digest", "policy_digest", "snapshot_digest"):
            _hex(getattr(self, name), name)
        timestamp(self.expires_at)
        return {
            name: getattr(self, name)
            for name in (
                "receipt_id",
                "source_id",
                "generation",
                "check_id",
                "status",
                "action_digest",
                "context_digest",
                "policy_digest",
                "snapshot_digest",
                "expires_at",
                "reason_code",
            )
        }

    def __post_init__(self) -> None:
        if type(self._seal) is not _AssessmentSeal or self._seal.digest != digest(self._payload()):
            raise ValueError("swarm assessment requires a protected host source")

    @classmethod
    def from_dict(cls, value):
        raise ValueError("JSON cannot issue swarm assessments")


class SwarmAssessmentSource:
    """Host-only provider; concrete budget/lineage authorities supply its facts.

    This object and its issuing API must remain outside agent control. An
    assessment is not an execution permit or an approval override.
    """

    def __init__(
        self,
        source_id: str,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_receipts: int = 4096,
    ) -> None:
        self.source_id = identifier(source_id, "source_id")
        if type(max_receipts) is not int or not 1 <= max_receipts <= 16384 or not callable(clock):
            raise ValueError("invalid bounded assessment source")
        self._clock, self._last_now = clock, 0.0
        self._limit = max_receipts
        self._generation = 0
        self._counter = 0
        self._key = object()
        self._binding_nonce = uuid4().hex
        self._issued: dict[str, SwarmAssessment] = {}
        self._lock = RLock()

    def _now(self) -> float:
        now = timestamp(self._clock())
        if now < self._last_now:
            raise ValueError("assessment clock moved backward")
        self._last_now = now
        return now

    @property
    def binding_digest(self) -> str:
        with self._lock:
            return digest(
                {
                    "source_id": self.source_id,
                    "generation": self._generation,
                    "incarnation": self._binding_nonce,
                }
            )

    def issue(
        self,
        *,
        check_id: str,
        status: str,
        action_digest: str,
        context_digest: str,
        policy_digest: str,
        snapshot_digest: str,
        lifetime: float = 30,
        reason_code: str = "host.assessment",
    ) -> SwarmAssessment:
        if not 0 < timestamp(lifetime) <= 3600:
            raise ValueError("invalid assessment lifetime")
        with self._lock:
            if len(self._issued) >= self._limit:
                raise ValueError("assessment receipt capacity reached")
            now = self._now()
            values: dict[str, Any] = dict(
                receipt_id=f"assessment-{self._generation}-{self._counter + 1}",
                source_id=self.source_id,
                generation=self._generation,
                check_id=check_id,
                status=status,
                action_digest=action_digest,
                context_digest=context_digest,
                policy_digest=policy_digest,
                snapshot_digest=snapshot_digest,
                expires_at=timestamp(now + lifetime),
                reason_code=reason_code,
            )
            preview = object.__new__(SwarmAssessment)
            for key, value in values.items():
                object.__setattr__(preview, key, value)
            receipt = SwarmAssessment(
                **values, _seal=_AssessmentSeal(self._key, digest(preview._payload()))
            )
            self._counter += 1
            self._issued[receipt.receipt_id] = receipt
            return receipt

    def verify(
        self,
        receipt: SwarmAssessment,
        *,
        action_digest: str,
        context_digest: str,
        policy_digest: str,
        snapshot_digest: str,
    ) -> bool:
        with self._lock:
            if (
                type(receipt) is not SwarmAssessment
                or self._issued.get(receipt.receipt_id) is not receipt
            ):
                return False
            try:
                receipt.__post_init__()
                return (
                    type(receipt._seal) is _AssessmentSeal
                    and receipt._seal.owner is self._key
                    and receipt.source_id == self.source_id
                    and receipt.generation == self._generation
                    and self._now() < receipt.expires_at
                    and (
                        receipt.action_digest,
                        receipt.context_digest,
                        receipt.policy_digest,
                        receipt.snapshot_digest,
                    )
                    == (action_digest, context_digest, policy_digest, snapshot_digest)
                )
            except (ValueError, AttributeError):
                return False

    def fence(self) -> None:
        with self._lock:
            self._generation = counter(self._generation + 1, "assessment_generation")
            self._issued.clear()
