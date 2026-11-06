"""Optional original human-approval fulfillment, separate from review and execution.

Serialized data never satisfies an approval obligation. The protected integration
owns issuance, durable one-use admission and the concrete execution boundary.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import math
from threading import RLock
import time
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from ._runtime_json import digest

if TYPE_CHECKING:
    from .action import ActionEnvelope, ActionReview


def _hex(value: Any) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(v not in "0123456789abcdef" for v in value)
    ):
        raise ValueError("exact approval binding digest required")


@dataclass(frozen=True, slots=True, eq=False)
class ApprovalScope:
    context_digest: str
    policy_digest: str
    policy_epoch: int
    scope_digest: str
    operator_maximum_digest: str
    owner_fence: int
    revocation_epoch: int
    budget_digest: str
    delegation_digest: str
    capabilities_digest: str

    def __post_init__(self):
        for name in (
            "context_digest",
            "policy_digest",
            "scope_digest",
            "operator_maximum_digest",
            "budget_digest",
            "delegation_digest",
            "capabilities_digest",
        ):
            _hex(getattr(self, name))
        for name in ("policy_epoch", "owner_fence", "revocation_epoch"):
            value = getattr(self, name)
            if type(value) is not int or not 0 <= value <= 2**63 - 1:
                raise ValueError("invalid bounded approval epoch or ownership fence")

    def as_dict(self):
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @property
    def digest(self) -> str:
        return digest(self.as_dict())


@dataclass(frozen=True, slots=True, eq=False)
class ApprovalSatisfaction:
    """Original host fulfillment of one operator-review obligation, not a permit."""

    satisfaction_id: str
    _source: Any = field(default=None, repr=False, compare=False, kw_only=True)

    def as_dict(self):
        if type(self._source) is not ApprovalSource:
            raise ValueError("original protected approval satisfaction required")
        return self._source.describe(self)

    @property
    def digest(self) -> str:
        return digest(self.as_dict())

    def fulfilled(
        self,
        action: ActionEnvelope,
        review: ActionReview,
        configuration_digest: str,
        scope: ApprovalScope | None,
    ) -> bool:
        return type(self._source) is ApprovalSource and self._source.verify(
            self, action, review, configuration_digest, scope
        )

    @classmethod
    def from_dict(cls, value):
        raise ValueError("JSON cannot fulfill a human approval obligation")


@dataclass(frozen=True, slots=True, eq=False)
class ApprovalExecutionLease:
    """Private exact-job lease, reserved and consumed only by the trusted broker."""

    lease_id: str
    _source: Any = field(default=None, repr=False, compare=False, kw_only=True)

    def as_dict(self):
        if type(self._source) is not ApprovalSource:
            raise ValueError("original protected approval execution lease required")
        return self._source.describe_lease(self)

    @property
    def digest(self) -> str:
        return digest(self.as_dict())

    @classmethod
    def from_dict(cls, value):
        raise ValueError("JSON cannot restore a human approval execution lease")


@dataclass(frozen=True)
class _Satisfaction:
    scope: ApprovalScope
    action_digest: str
    review_digest: str
    configuration_digest: str
    approval: Any
    expires_at: float
    generation: int
    payload: dict[str, Any]


@dataclass
class _Execution:
    satisfaction: ApprovalSatisfaction
    base_contract_digest: str
    broker: object
    payload: dict[str, Any]
    executor: object | None = None
    job: object | None = None
    state: str = "reserved"


class _AdmissionLock:
    """Normal approval work follows admission-barrier -> issuer -> optional DB clock."""

    def __init__(self, barrier):
        self._barrier, self._lock = barrier, RLock()

    def __enter__(self):
        self._barrier.acquire()
        try:
            self._lock.acquire()
        except BaseException:
            self._barrier.release()
            raise
        return self

    def __exit__(self, *error):
        self._lock.release()
        self._barrier.release()


class ApprovalSource:
    """Protected original host approval issuer; never expose its mutators to a model.

    The caller authenticates humans and owns durable one-use admission. Issuance
    alone does not allow execution: a concrete broker must bind and commit the
    original exact-job lease, and its actual executor must verify it at use.
    """

    def __init__(
        self,
        host,
        profile,
        maximum,
        *,
        operator: object,
        clock=time.monotonic,
        verifier=None,
        maximum_receipts: int = 4096,
        admission_barrier=None,
    ):
        from .assurance.host import HostEvidenceSource
        from .assurance.models import ApprovedSecurityProfile
        from .assurance.delegation import DelegationAuthority

        if (
            type(host) is not HostEvidenceSource
            or type(profile) is not ApprovedSecurityProfile
            or type(maximum) is not DelegationAuthority
            or type(operator) is not object
            or not callable(clock)
        ):
            raise ValueError(
                "original host, approved profile, operator maximum and capability required"
            )
        if not callable(verifier):
            raise ValueError("protected approval lifecycle verifier must be callable")
        if type(maximum_receipts) is not int or not 1 <= maximum_receipts <= 4096:
            raise ValueError("invalid bounded approval issuer capacity")
        host._check_profile(profile)
        self.host, self.profile, self.maximum = host, profile, maximum
        self._operator, self._clock, self._verifier = operator, clock, verifier
        self._maximum_digest, self._host_digest = maximum.digest, digest(host.as_dict())
        self._profile_digest, self._nonce = profile.digest, uuid4().hex
        self._limit, self._generation, self._last_now = maximum_receipts, 0, 0.0
        self._scopes: dict[ApprovalScope, str] = {}
        self._issued: dict[ApprovalSatisfaction, _Satisfaction] = {}
        self._leases: dict[ApprovalExecutionLease, _Execution] = {}
        self._used: set[ApprovalSatisfaction] = set()
        self._admission_barrier = admission_barrier if admission_barrier is not None else RLock()
        if not callable(getattr(self._admission_barrier, "acquire", None)) or not callable(
            getattr(self._admission_barrier, "release", None)
        ):
            raise ValueError("original protected admission barrier required")
        self._lock = _AdmissionLock(self._admission_barrier)

    def _configuration(self):
        if (
            self.maximum.digest != self._maximum_digest
            or self.profile.digest != self._profile_digest
            or digest(self.host.as_dict()) != self._host_digest
        ):
            raise ValueError("protected approval configuration changed")
        self.host._check_profile(self.profile)

    def _now(self):
        now = self._clock()
        if type(now) not in {int, float} or not math.isfinite(now) or now < self._last_now:
            raise ValueError("approval clock unavailable or moved backward")
        self._last_now = float(now)
        return float(now)

    def _operator_check(self, operator):
        if operator is not self._operator:
            raise ValueError("original protected approval operator capability required")

    @property
    def binding_digest(self):
        with self._lock:
            self._configuration()
            return digest(
                [
                    self._nonce,
                    self._generation,
                    self._host_digest,
                    self._profile_digest,
                    self._maximum_digest,
                ]
            )

    def create_scope(self, *, operator: object, **bindings) -> ApprovalScope:
        self._operator_check(operator)
        with self._lock:
            self._configuration()
            if len(self._scopes) >= self._limit:
                raise ValueError("approval scope capacity reached")
            scope = ApprovalScope(**bindings)
            if (
                scope.policy_epoch != self.host.epoch
                or scope.operator_maximum_digest != self._maximum_digest
            ):
                raise ValueError("approval scope exceeds current host epoch or operator maximum")
            self._scopes[scope] = scope.digest
            return scope

    @staticmethod
    def _base_contract(action, review):
        from .action import ActionEnvelope, ActionReview
        from .runtime_contract import derive_runtime_capability_contract

        if (
            type(action) is not ActionEnvelope
            or type(review) is not ActionReview
            or digest(action.as_dict()) != digest(review.action.as_dict())
        ):
            raise ValueError("approval requires the exact original normalized review")
        contract = derive_runtime_capability_contract(review)
        if review.decision == "block" or contract.unknowns or contract.grant_state == "diagnostic":
            raise ValueError("approval cannot satisfy a block or missing action semantics")
        return contract

    def _lifecycle(self, satisfaction_id, scope, stage):
        if self._verifier is None:
            return False
        try:
            return self._verifier(satisfaction_id, scope, stage) is True
        except Exception:
            return False

    def issue(
        self,
        action,
        review,
        configuration_digest: str,
        scope: ApprovalScope,
        *,
        satisfaction_id: str,
        lifetime: float,
        operator: object,
    ) -> ApprovalSatisfaction:
        """Call only after authenticated human resolution is durably committed."""
        self._operator_check(operator)
        _hex(configuration_digest)
        if (
            type(satisfaction_id) is not str
            or not 1 <= len(satisfaction_id) <= 64
            or any(
                v not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
                for v in satisfaction_id
            )
        ):
            raise ValueError("bounded original human resolution identity required")
        if (
            type(lifetime) not in {int, float}
            or not math.isfinite(lifetime)
            or not 0 < lifetime <= 300
        ):
            raise ValueError("approval lifetime must be at most 300 seconds")
        contract = self._base_contract(action, review)
        from .assurance.delegation import _verify_operation_authority
        from .runtime_requests_v2 import derive_runtime_request_contract_v2
        from .assurance.rest import derive_rest_request_contract

        request = derive_runtime_request_contract_v2(review)
        complete = (
            derive_rest_request_contract(review, capability=contract)
            if review.adapter == "network.rest"
            else request
            if request.requests
            or any(value.protocol in {"graphql", "mcp", "json-rpc"} for value in contract.network)
            else contract
        )
        if not _verify_operation_authority(complete, self.maximum).ok:
            raise ValueError("approved action exceeds actual operator maximum or verifier coverage")
        with self._lock:
            self._configuration()
            if (
                type(scope) is not ApprovalScope
                or self._scopes.get(scope) != scope.digest
                or scope.capabilities_digest != contract.digest
            ):
                raise ValueError("original exact approval capability scope required")
            generation = self._generation
            if len(self._issued) >= self._limit or any(
                value.satisfaction_id == satisfaction_id for value in self._issued
            ):
                raise ValueError("approval receipt identity reused or capacity reached")
        # Durable/controller checks happen outside issuer locks. Recheck issuance
        # generation afterward; an unavailable or uncertain resolution stays closed.
        if not self._lifecycle(satisfaction_id, scope, "issue"):
            raise ValueError("original committed human resolution is unavailable")
        with self._lock:
            self._configuration()
            if (
                generation != self._generation
                or len(self._issued) >= self._limit
                or any(value.satisfaction_id == satisfaction_id for value in self._issued)
            ):
                raise ValueError("approval issuer changed or receipt identity raced")
            if (
                self._base_contract(action, review).digest != contract.digest
                or self._scopes.get(scope) != scope.digest
            ):
                raise ValueError("action, review or scope changed during human approval issuance")
            proof = ApprovalSatisfaction(satisfaction_id, _source=self)
            native = self.host.record_approval(
                action, self.profile, receipt_id="human:" + satisfaction_id
            )
            expiry = self._now() + lifetime
            payload = {
                "schema_version": "ordin.approval_satisfaction.v1",
                "satisfaction_id": satisfaction_id,
                "action_digest": digest(action.as_dict()),
                "review_digest": digest(review.as_dict()),
                "configuration_digest": configuration_digest,
                "scope": scope.as_dict(),
                "source_binding": self.binding_digest,
                "host_approval_digest": native.digest,
                "expires_at": expiry,
                "fulfilled_obligation": "operator_review",
                "execution_authority": False,
            }
            self._issued[proof] = _Satisfaction(
                scope,
                digest(action.as_dict()),
                digest(review.as_dict()),
                configuration_digest,
                native,
                expiry,
                generation,
                payload,
            )
            object.__setattr__(native, "_governance_satisfaction", proof)
            return proof

    def scope_for(self, proof) -> ApprovalScope:
        with self._lock:
            row = self._issued.get(proof) if type(proof) is ApprovalSatisfaction else None
            if row is None or proof._source is not self or not self._alive(proof, row):
                raise ValueError("original current approval scope required")
            return row.scope

    def describe(self, proof):
        from ._runtime_json import freeze, thaw

        with self._lock:
            row = self._issued.get(proof) if type(proof) is ApprovalSatisfaction else None
            if row is None or proof._source is not self:
                raise ValueError("original protected approval satisfaction required")
            return thaw(freeze(row.payload))

    def host_approval(self, proof):
        with self._lock:
            row = self._issued.get(proof) if type(proof) is ApprovalSatisfaction else None
            if row is None or proof._source is not self:
                raise ValueError("original protected host approval required")
            native = row.approval
        if not self.host_receipt_current(native, proof):
            raise ValueError("human approval expired, consumed or changed")
        return native

    def _alive(self, proof, row):
        self._configuration()
        return (
            proof._source is self
            and proof.satisfaction_id == row.payload["satisfaction_id"]
            and row.generation == self._generation
            and self._now() < row.expires_at
            and self._scopes.get(row.scope) == row.scope.digest
            and (
                proof not in self._used
                or any(
                    value.satisfaction is proof and value.state == "forwarding"
                    for value in self._leases.values()
                )
            )
        )

    def verify(self, proof, action, review, configuration_digest, scope):
        try:
            with self._lock:
                row = self._issued.get(proof) if type(proof) is ApprovalSatisfaction else None
                if row is None or scope is not row.scope or not self._alive(proof, row):
                    return False
                if (
                    digest(action.as_dict()),
                    digest(review.as_dict()),
                    configuration_digest,
                    self._base_contract(action, review).digest,
                ) != (
                    row.action_digest,
                    row.review_digest,
                    row.configuration_digest,
                    row.scope.capabilities_digest,
                ):
                    return False
                stage = "execution" if proof in self._used else "review"
            if not self._lifecycle(proof.satisfaction_id, scope, stage):
                return False
            with self._lock:
                return self._issued.get(proof) is row and self._alive(proof, row)
        except (ValueError, TypeError, AttributeError):
            return False

    def host_receipt_current(self, native, proof):
        try:
            with self._lock:
                row = self._issued.get(proof) if type(proof) is ApprovalSatisfaction else None
                if (
                    row is None
                    or row.approval is not native
                    or native.digest != row.payload["host_approval_digest"]
                    or not self._alive(proof, row)
                ):
                    return False
                stage = "execution" if proof in self._used else "review"
            if not self._lifecycle(proof.satisfaction_id, row.scope, stage):
                return False
            with self._lock:
                return self._issued.get(proof) is row and self._alive(proof, row)
        except (ValueError, TypeError, AttributeError):
            return False

    def reserve_lease(
        self, proof, contract, broker: object, *, operator: object
    ) -> ApprovalExecutionLease:
        """Call only after one durable approval hold bound to this actual broker."""
        self._operator_check(operator)
        with self._lock:
            row = self._issued.get(proof) if type(proof) is ApprovalSatisfaction else None
            if row is None or not self._alive(proof, row) or proof in self._used:
                raise ValueError("original current unused human approval required")
            if (
                contract.digest != row.scope.capabilities_digest
                or contract.unknowns
                or contract.decision == "block"
            ):
                raise ValueError(
                    "approval lease cannot change capability requirements or waive unknowns"
                )
            if len(self._leases) >= self._limit or any(
                value.satisfaction is proof for value in self._leases.values()
            ):
                raise ValueError("approval already has a broker lease or lease capacity reached")
        if not self._lifecycle(proof.satisfaction_id, row.scope, "reserve"):
            raise ValueError("original durable approval hold unavailable")
        with self._lock:
            if (
                not self._alive(proof, row)
                or proof in self._used
                or len(self._leases) >= self._limit
                or any(value.satisfaction is proof for value in self._leases.values())
            ):
                raise ValueError("approval lease admission changed or raced")
            lease = ApprovalExecutionLease(uuid4().hex, _source=self)
            payload = {
                "schema_version": "ordin.approval_execution_lease.v1",
                "lease_id": lease.lease_id,
                "satisfaction_digest": proof.digest,
                "base_contract_digest": contract.digest,
                "scope_digest": row.scope.digest,
                "expires_at": row.expires_at,
                "execution_authority": False,
            }
            self._leases[lease] = _Execution(proof, contract.digest, broker, payload)
            return lease

    def describe_lease(self, lease):
        from ._runtime_json import freeze, thaw

        with self._lock:
            row = self._leases.get(lease) if type(lease) is ApprovalExecutionLease else None
            if (
                row is None
                or lease._source is not self
                or row.payload["lease_id"] != lease.lease_id
            ):
                raise ValueError("original approval execution lease required")
            return thaw(freeze(row.payload))

    def witnessed(self, lease, base_contract_digest: str) -> bool:
        """Immutable historical fulfillment only; actual execution needs a live job check."""
        with self._lock:
            row = self._leases.get(lease) if type(lease) is ApprovalExecutionLease else None
            return (
                row is not None
                and lease._source is self
                and lease.lease_id == row.payload["lease_id"]
                and row.base_contract_digest == base_contract_digest
            )

    def lease_matches(self, lease, proof) -> bool:
        with self._lock:
            row = self._leases.get(lease) if type(lease) is ApprovalExecutionLease else None
            return (
                row is not None
                and row.satisfaction is proof
                and lease._source is self
                and lease.lease_id == row.payload["lease_id"]
            )

    def bind_job(self, lease, broker, executor, job, *, operator: object):
        self._operator_check(operator)
        with self._lock:
            row = self._leases.get(lease) if type(lease) is ApprovalExecutionLease else None
            if (
                row is None
                or lease._source is not self
                or lease.lease_id != row.payload["lease_id"]
                or row.broker is not broker
                or row.state != "reserved"
                or row.job is not None
            ):
                raise ValueError("original unused exact-broker approval lease required")
            if not self._alive(row.satisfaction, self._issued[row.satisfaction]):
                raise ValueError("approval changed before owned job binding")
            row.executor, row.job = executor, job

    def begin(self, lease, broker, executor, job, *, operator: object):
        """Call after durable one-use consumption commits, immediately before effect."""
        self._operator_check(operator)
        with self._lock:
            row = self._leases.get(lease) if type(lease) is ApprovalExecutionLease else None
            if (
                row is None
                or lease._source is not self
                or lease.lease_id != row.payload["lease_id"]
                or row.broker is not broker
                or row.executor is not executor
                or row.job is not job
                or row.state != "reserved"
                or row.satisfaction in self._used
            ):
                raise ValueError("approval lease was copied, used or bound to another owned job")
            proof = self._issued[row.satisfaction]
            if not self._alive(row.satisfaction, proof):
                raise ValueError("approval changed before actual forwarding")
        if not self._lifecycle(row.satisfaction.satisfaction_id, proof.scope, "begin"):
            raise ValueError("original committed approval consumption unavailable")
        with self._lock:
            if (
                row.state != "reserved"
                or row.satisfaction in self._used
                or not self._alive(row.satisfaction, proof)
            ):
                raise ValueError("approval forwarding raced or changed")
            self._used.add(row.satisfaction)
            row.state = "forwarding"

    def verify_execution(self, lease, executor, job) -> bool:
        try:
            with self._lock:
                row = self._leases.get(lease) if type(lease) is ApprovalExecutionLease else None
                if (
                    row is None
                    or lease._source is not self
                    or row.payload["lease_id"] != lease.lease_id
                    or row.executor is not executor
                    or row.job is not job
                    or row.state != "forwarding"
                ):
                    return False
                proof = self._issued[row.satisfaction]
                if not self._alive(row.satisfaction, proof):
                    return False
            if not self._lifecycle(row.satisfaction.satisfaction_id, proof.scope, "execution"):
                return False
            with self._lock:
                return row.state == "forwarding" and self._alive(row.satisfaction, proof)
        except (ValueError, TypeError, AttributeError):
            return False

    def finish(self, lease, *, operator: object):
        self._operator_check(operator)
        with self._lock:
            row = self._leases.get(lease) if type(lease) is ApprovalExecutionLease else None
            if row is None or lease._source is not self:
                raise ValueError("original approval lease required")
            row.state = "settled" if row.state == "forwarding" else "canceled"

    def fence(self, *, operator: object):
        self._operator_check(operator)
        with self._lock:
            self._generation += 1
            for lease in self._leases.values():
                if lease.state != "settled":
                    lease.state = "fenced"


class ApprovalAuthority:
    """Protected finite enrollment of per-workload original approval sources."""

    def __init__(
        self, maximum, *, operator: object, maximum_sources: int = 256, admission_barrier=None
    ):
        from .assurance.delegation import DelegationAuthority

        if (
            type(maximum) is not DelegationAuthority
            or type(operator) is not object
            or type(maximum_sources) is not int
            or not 1 <= maximum_sources <= 256
        ):
            raise ValueError("original finite approval authority and operator required")
        self.maximum, self._operator, self._limit = maximum, operator, maximum_sources
        self._maximum_digest = maximum.digest
        self._nonce, self._generation = uuid4().hex, 0
        self._sources: dict[str, ApprovalSource] = {}
        self._admission_barrier = admission_barrier if admission_barrier is not None else RLock()
        if not callable(getattr(self._admission_barrier, "acquire", None)) or not callable(
            getattr(self._admission_barrier, "release", None)
        ):
            raise ValueError("original protected admission barrier required")
        self._lock = _AdmissionLock(self._admission_barrier)

    @property
    def binding_digest(self):
        with self._lock:
            if self.maximum.digest != self._maximum_digest:
                raise ValueError("approval operator maximum changed")
            return digest(
                [
                    self._nonce,
                    self._generation,
                    self._maximum_digest,
                    sorted((key, value.binding_digest) for key, value in self._sources.items()),
                ]
            )

    def enroll(self, source: ApprovalSource, *, operator: object) -> None:
        if (
            operator is not self._operator
            or type(source) is not ApprovalSource
            or source._operator is not operator
            or source._admission_barrier is not self._admission_barrier
        ):
            raise ValueError("original protected approval authority enrollment required")
        with self._lock:
            self.binding_digest
            if (
                source.maximum.digest != self._maximum_digest
                or source.host.key in self._sources
                or len(self._sources) >= self._limit
            ):
                raise ValueError("approval source maximum, identity or capacity mismatch")
            for existing in self._sources.values():
                existing.fence(operator=operator)
            source.fence(operator=operator)
            self._sources[source.host.key] = source
            self._generation += 1

    def accepts(self, proof) -> bool:
        try:
            with self._lock:
                self.binding_digest
                return (
                    type(proof) is ApprovalSatisfaction
                    and type(proof._source) is ApprovalSource
                    and self._sources.get(proof._source.host.key) is proof._source
                )
        except (ValueError, TypeError, AttributeError):
            return False
