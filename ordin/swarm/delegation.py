"""Online cross-host delegation over independently authenticated workload channels.

Serialized core grants are never restored. The authority retains the original
DelegationIssuer, issued handles, selected maxima and per-child review sessions.
Only an enrolled broker on the subject host can consume a one-use admission.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import secrets
import ssl
import struct
import time
from threading import RLock
from typing import Any, Callable, Mapping
from uuid import uuid4

from ordin.action import ActionEnvelope
from ordin._runtime_json import digest
from ordin.assurance import (
    AssuranceGate,
    DelegationAuthority,
    DelegationIssuer,
    DelegatingAssuranceGate,
    HostEvidenceSource,
    IssuedDelegation,
)
from ordin.assurance.delegating_gate import DelegatedDecision
from ordin.schema import validate_named_schema
from ordin import AgentGate
from ordin.session import IntegrationSession

from .events import _hex
from .models import identifier
from .models import SwarmContext
from .workload_auth import AuthorityChannel, WorkloadAuthenticator, WorkloadEnrollment


def _checked(name: str, value: dict[str, Any]) -> dict[str, Any]:
    if validate_named_schema(name, value):
        raise ValueError("invalid redacted authority record")
    return value


@dataclass(frozen=True, slots=True)
class RemoteDelegation:
    grant_id: str = field(repr=False)
    subject_digest: str
    host_digest: str
    authority_digest: str
    parent_digest: str | None
    policy_epoch: int
    issuer_generation: int
    expires_at: int
    depth: int
    maximum_depth: int
    limits: tuple[int, int, int]
    task_digest: str
    issuer_digest: str

    def as_dict(self) -> dict[str, Any]:
        return _checked(
            "swarm_remote_delegation",
            {
                "schema_version": "ordin.swarm_remote_delegation.v1",
                "grant_digest": digest(self.grant_id),
                "subject_digest": self.subject_digest,
                "host_digest": self.host_digest,
                "authority_digest": self.authority_digest,
                "parent_digest": self.parent_digest,
                "policy_epoch": self.policy_epoch,
                "issuer_generation": self.issuer_generation,
                "expires_at": self.expires_at,
                "depth": self.depth,
                "maximum_depth": self.maximum_depth,
                "limits": {
                    "active_children": self.limits[0],
                    "in_flight_operations": self.limits[1],
                    "actions_per_grant": self.limits[2],
                },
                "task_digest": self.task_digest,
                "issuer_digest": self.issuer_digest,
                "requires_online_authority": True,
                "execution_authority": False,
            },
        )

    def to_wire(self) -> dict[str, Any]:
        """Control reference for an authenticated TLS response, never public audit."""
        return _checked("swarm_remote_delegation", {**self.as_dict(), "grant_id": self.grant_id})


@dataclass(frozen=True, slots=True)
class RemoteReview:
    admission_id: str | None = field(repr=False)
    disposition: str
    action_digest: str
    grant_digest: str
    issuer_generation: int
    expires_at: int
    reason_codes: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return _checked(
            "swarm_remote_review",
            {
                "schema_version": "ordin.swarm_remote_review.v1",
                "admission_digest": digest(self.admission_id) if self.admission_id else None,
                "disposition": self.disposition,
                "action_digest": self.action_digest,
                "grant_digest": self.grant_digest,
                "issuer_generation": self.issuer_generation,
                "expires_at": self.expires_at,
                "reason_codes": list(self.reason_codes),
                "requires_online_authority": True,
                "execution_authority": False,
            },
        )

    def to_wire(self) -> dict[str, Any]:
        return _checked(
            "swarm_remote_review", {**self.as_dict(), "admission_id": self.admission_id}
        )


@dataclass(frozen=True, slots=True)
class DelegationDispatch:
    status: str
    admission_digest: str
    action_digest: str
    reason_code: str
    value: Any = field(default=None, repr=False, compare=False)

    def as_dict(self) -> dict[str, Any]:
        return _checked(
            "swarm_delegation_dispatch",
            {
                "schema_version": "ordin.swarm_delegation_dispatch.v1",
                "status": self.status,
                "admission_digest": self.admission_digest,
                "action_digest": self.action_digest,
                "reason_code": self.reason_code,
                "physical_enforcement": False,
                "receiver_execution": "unknown",
                "execution_authority": False,
            },
        )


@dataclass(frozen=True, slots=True)
class BrokerAdmissionScope:
    admission_digest: str
    action_digest: str
    grant_digest: str
    subject_digest: str
    host_digest: str
    issuer_generation: int
    expires_at: int
    ancestry_digest: str
    authority: DelegationAuthority = field(repr=False)
    action: ActionEnvelope = field(repr=False)
    context: SwarmContext = field(repr=False)
    source: HostEvidenceSource = field(repr=False)
    delegating_gate: DelegatingAssuranceGate = field(repr=False)
    delegated_decision: DelegatedDecision = field(repr=False)

    @property
    def review_context(self):
        return self.delegated_decision._context

    @property
    def review_history(self):
        return self.delegated_decision._history

    def as_dict(self) -> dict[str, Any]:
        return _checked(
            "swarm_broker_admission_scope",
            {
                "schema_version": "ordin.swarm_broker_admission_scope.v1",
                "admission_digest": self.admission_digest,
                "action_digest": self.action_digest,
                "grant_digest": self.grant_digest,
                "subject_digest": self.subject_digest,
                "host_digest": self.host_digest,
                "issuer_generation": self.issuer_generation,
                "expires_at": self.expires_at,
                "ancestry_digest": self.ancestry_digest,
                "authority_digest": self.authority.digest,
                "requires_online_authority": True,
                "execution_authority": False,
            },
        )

    def to_wire(self) -> dict[str, Any]:
        """Private authenticated broker data, never a restorable issuer/gate handle."""
        return _checked(
            "swarm_broker_admission_scope",
            {
                **self.as_dict(),
                "authority_data": self.authority.as_dict(),
                "action_data": self.action.as_dict(),
                "context_data": self.context.as_dict(),
            },
        )

    @classmethod
    def from_dict(cls, value):
        raise ValueError("JSON cannot restore current broker admission authority")


@dataclass(frozen=True)
class _Grant:
    enrollment_id: str
    handle: IssuedDelegation
    gate: DelegatingAssuranceGate
    parent_ref: str | None


@dataclass
class _Admission:
    admission_id: str
    owner_channel: AuthorityChannel
    grant_ref: str
    decision: DelegatedDecision
    action: ActionEnvelope
    action_digest: str
    expires_at: int
    service_generation: int
    ancestry_digest: str
    state: str = "pending"


class SwarmDelegationService:
    """Protected bounded authority service; no offline grants or automatic network IO.

    Transport adapters must close AuthorityChannels on EOF. All live operations
    recheck the issuer and TLS workload scope. A software callback boundary is
    not kernel containment of a workload's preexisting privileges.
    """

    def __init__(
        self,
        issuer: DelegationIssuer,
        assurance: AssuranceGate,
        authenticator: WorkloadAuthenticator,
        *,
        operator: object,
        admission_lifetime: int = 10,
        max_admissions: int = 4096,
    ) -> None:
        if (
            type(issuer) is not DelegationIssuer
            or type(assurance) is not AssuranceGate
            or type(authenticator) is not WorkloadAuthenticator
            or type(operator) is not object
            or assurance.approved_profile != issuer.profile
            or authenticator._operator is not operator
        ):
            raise ValueError(
                "protected current issuer, profile, workload authentication and operator required"
            )
        if (
            type(admission_lifetime) is not int
            or not 1 <= admission_lifetime <= 30
            or type(max_admissions) is not int
            or not 1 <= max_admissions <= 16384
        ):
            raise ValueError("invalid bounded remote admission configuration")
        self.issuer, self.assurance, self.authenticator = issuer, assurance, authenticator
        self._instances = (issuer, assurance, authenticator)
        self._assurance_digest = assurance.configuration_digest
        self._operator, self._lifetime, self._limit = operator, admission_lifetime, max_admissions
        self._grants: dict[str, _Grant] = {}
        self._grant_ids: dict[str, str] = {}
        self._requests: dict[tuple[str, str], tuple[str, str]] = {}
        self._admissions: dict[str, _Admission] = {}
        self._pending: dict[str, _Admission] = {}
        self._generation = 0
        self._available = True
        self._audit: list[dict[str, Any]] = []
        self._audit_limit = max_admissions * 3 + issuer.limits.maximum_grants * 3
        self._audit_full = False
        self._lock = RLock()

    def _operator_check(self, operator: object) -> None:
        if operator is not self._operator:
            raise ValueError("protected authority operator capability required")

    def _online(self) -> None:
        if not self._available or self._audit_full:
            raise ValueError("online delegation authority unavailable")
        if (
            any(
                current is not original
                for current, original in zip(
                    (self.issuer, self.assurance, self.authenticator), self._instances
                )
            )
            or self.assurance.configuration_digest != self._assurance_digest
        ):
            raise ValueError("protected remote authority configuration changed")
        self.issuer._require_configuration()

    def _audit_event(self, kind: str, reference: str, **metadata: Any) -> None:
        if len(self._audit) >= self._audit_limit:
            self._audit_full = True
            return
        self._audit.append(
            _checked(
                "swarm_authority_audit",
                {
                    "schema_version": "ordin.swarm_authority_audit.v1",
                    "kind": kind,
                    "reference_digest": digest(reference),
                    "execution_authority": False,
                    **metadata,
                },
            )
        )

    def _subject(self, channel: AuthorityChannel) -> WorkloadEnrollment:
        self._online()
        subject = self.authenticator.require(channel, role="workload")
        if subject.source is None or subject.context is None:
            raise ValueError("authority workload scope unavailable")
        subject.source._check_profile(self.issuer.profile)
        if (
            subject.source.repository != self.issuer.source.repository
            or subject.source.runtime_policy_digest != self.issuer.source.runtime_policy_digest
            or subject.source.epoch != self.issuer.source.epoch
        ):
            raise ValueError("workload source belongs to another protected issuer scope")
        return subject

    def _grant(
        self, channel: AuthorityChannel, reference: str
    ) -> tuple[_Grant, WorkloadEnrollment]:
        _hex(reference, "remote grant reference")
        subject = self._subject(channel)
        row = self._grants.get(reference)
        if row is None or row.enrollment_id != subject.enrollment_id or subject.source is None:
            raise ValueError("grant is not owned by the authenticated workload")
        self._ancestry_digest(row)
        self.issuer.require_current(row.handle, subject.source)
        return row, subject

    def _ancestry_digest(self, row: _Grant) -> str:
        ancestor = row
        seen: set[str] = set()
        chain = []
        while True:
            if (
                ancestor.handle.record.grant_id in seen
                or len(seen) >= self.issuer.limits.maximum_grants
            ):
                raise ValueError("remote ancestry is cyclic or exceeds its bound")
            seen.add(ancestor.handle.record.grant_id)
            enrolled = self.authenticator.enrollment(ancestor.enrollment_id)
            if enrolled.context is None or enrolled.source is None:
                raise ValueError("ancestor workload scope unavailable")
            if enrolled.context.identity.delegation_id not in {
                None,
                ancestor.handle.record.grant_id,
            }:
                raise ValueError("workload context names another issued authority")
            chain.append(
                [
                    ancestor.handle.digest,
                    enrolled.context.as_dict(),
                    enrolled.source_key,
                    enrolled.host_id,
                    enrolled.certificate_digest,
                ]
            )
            if ancestor.parent_ref is None:
                break
            parent = self._grants.get(ancestor.parent_ref)
            if parent is None:
                raise ValueError("remote ancestry is incomplete")
            ancestor = parent
        return digest(chain)

    def _metadata(self, reference: str, row: _Grant) -> RemoteDelegation:
        subject = self.authenticator.enrollment(row.enrollment_id)
        if subject.context is None:
            raise ValueError("workload metadata unavailable")
        return RemoteDelegation(
            reference,
            digest(subject.context.as_dict()),
            digest([subject.host_id, subject.certificate_digest]),
            row.handle.authority.digest,
            digest(row.parent_ref) if row.parent_ref else None,
            subject.context.identity.policy_epoch,
            self.issuer._generation,
            row.handle.record.expires_at,
            row.handle.record.depth,
            row.handle.record.maximum_delegation_depth,
            (
                self.issuer.limits.active_children,
                self.issuer.limits.in_flight_operations,
                self.issuer.limits.actions_per_grant,
            ),
            digest(
                [
                    subject.context.identity.tenant_id,
                    subject.context.identity.swarm_id,
                    subject.context.identity.task_id,
                ]
            ),
            digest(self.issuer._issuer_key),
        )

    def _planned_identity(self, enrollment: WorkloadEnrollment):
        identity = enrollment.runtime_identity
        if identity is not None:
            if (
                enrollment.source is None
                or IntegrationSession(
                    identity, AgentGate(self.assurance.ordin)
                ).runtime_session_digest
                != enrollment.source.session_digest
            ):
                raise ValueError(
                    "workload planned runtime session differs from its original host source"
                )
        return identity

    def publish_root(
        self, enrollment_id: str, root: IssuedDelegation, *, operator: object
    ) -> RemoteDelegation:
        self._operator_check(operator)
        with self._lock, self.issuer._lock:
            self._online()
            subject = self.authenticator.enrollment(enrollment_id)
            if (
                subject.role != "workload"
                or subject.source is None
                or subject.source.key != self.issuer.source.key
                or root.record.parent_grant_id is not None
            ):
                raise ValueError(
                    "root requires the issuer's independently authenticated workload scope"
                )
            self.issuer.require_current(root, subject.source)
            existing = self._grant_ids.get(root.record.grant_id)
            if existing:
                return self._metadata(existing, self._grants[existing])
            reference = secrets.token_hex(32)
            gate = DelegatingAssuranceGate(
                self.assurance,
                self.issuer,
                root,
                subject.source,
                identity=self._planned_identity(subject),
            )
            row = _Grant(enrollment_id, root, gate, None)
            self._grants[reference], self._grant_ids[root.record.grant_id] = row, reference
            self._audit_event("root_published", reference, authority_digest=root.authority.digest)
            return self._metadata(reference, row)

    def issue_child(
        self,
        channel: AuthorityChannel,
        parent_ref: str,
        target_enrollment: str,
        authority: DelegationAuthority,
        *,
        request_id: str,
        lifetime: int = 30,
        maximum_depth: int | None = None,
    ) -> RemoteDelegation:
        identifier(request_id, "request_id")
        identifier(target_enrollment, "target enrollment")
        if (
            type(authority) is not DelegationAuthority
            or type(lifetime) is not int
            or not 1 <= lifetime <= 600
        ):
            raise ValueError("typed bounded child authority proposal required")
        with self._lock, self.issuer._lock:
            parent, owner = self._grant(channel, parent_ref)
            target = self.authenticator.enrollment(target_enrollment)
            if (
                target.role != "workload"
                or target.source is None
                or target.context is None
                or owner.context is None
            ):
                raise ValueError("child target must be an enrolled current workload")
            if (
                target.context.identity.tenant_id,
                target.context.identity.swarm_id,
                target.context.identity.task_id,
            ) != (
                owner.context.identity.tenant_id,
                owner.context.identity.swarm_id,
                owner.context.identity.task_id,
            ):
                raise ValueError("child crosses tenant, swarm or task scope")
            material = digest(
                [parent_ref, target_enrollment, authority.as_dict(), lifetime, maximum_depth]
            )
            key = (owner.enrollment_id, request_id)
            if key in self._requests:
                old_material, reference = self._requests[key]
                if old_material != material:
                    raise ValueError("conflicting delegation request ID")
                row = self._grants[reference]
                self.issuer.require_current(row.handle, target.source)
                return self._metadata(reference, row)
            now = self.issuer._now()
            identity = self._planned_identity(target)
            handle = self.issuer.issue_child(
                parent.handle,
                target.source,
                authority,
                grant_id="remote-" + uuid4().hex,
                expires_at=now + lifetime,
                maximum_delegation_depth=maximum_depth,
            )
            reference = secrets.token_hex(32)
            gate = DelegatingAssuranceGate(
                self.assurance, self.issuer, handle, target.source, identity=identity
            )
            row = _Grant(target_enrollment, handle, gate, parent_ref)
            self._grants[reference], self._grant_ids[handle.record.grant_id] = row, reference
            self._requests[key] = (material, reference)
            self._audit_event(
                "child_issued",
                reference,
                parent_digest=digest(parent_ref),
                authority_digest=authority.digest,
            )
            return self._metadata(reference, row)

    def require_current(self, channel: AuthorityChannel, reference: str) -> RemoteDelegation:
        with self._lock, self.issuer._lock:
            row, _ = self._grant(channel, reference)
            return self._metadata(reference, row)

    def bind_delegation_context(self, reference: str, *, operator: object) -> SwarmContext:
        """Bind original issued child authority without inventing a process restart."""
        self._operator_check(operator)
        with self._lock, self.issuer._lock, self.authenticator._lock:
            self._online()
            row = self._grants.get(_hex(reference, "grant reference"))
            if row is None or row.parent_ref is None:
                raise ValueError("context binding requires an original issued child relationship")
            parent = self._grants.get(row.parent_ref)
            child = self.authenticator._enrollments.get(row.enrollment_id)
            if (
                parent is None
                or child is None
                or child.enrollment_id in self.authenticator._revoked
            ):
                raise ValueError("current protected parent and child enrollment required")
            owner = self.authenticator.enrollment(parent.enrollment_id)
            if (
                child.context is None
                or child.registry_channel is None
                or child.source is None
                or owner.context is None
                or owner.registry_channel is None
                or owner.source is None
                or row.handle.host_source_key != child.source.key
            ):
                raise ValueError("current original delegation sources are unavailable")
            rebound = self.authenticator._registry.rebind_delegation(
                child.context,
                child.registry_channel,
                child.adapter,
                parent_context=owner.context,
                parent_channel=owner.registry_channel,
                parent_adapter=owner.adapter,
                issuer=self.issuer,
                grant=row.handle,
                parent_source=owner.source,
                child_source=child.source,
            )
            self.authenticator.rebind_workload(child.enrollment_id, rebound, operator=operator)
            self._expire_admissions()
            return rebound

    def admission_scope(
        self, broker_channel: AuthorityChannel, admission_id: str
    ) -> BrokerAdmissionScope:
        """Current exact scope data for compilation; guarded_dispatch is still mandatory."""
        _hex(admission_id, "admission reference")
        with self._lock, self.issuer._lock:
            self._online()
            broker = self.authenticator.require(broker_channel, role="broker")
            admission = self._admissions.get(admission_id)
            if admission is None or admission.state != "pending":
                raise ValueError("unknown or consumed remote admission")
            row, subject = self._grant(admission.owner_channel, admission.grant_ref)
            expected = (
                row.handle.record.grant_id,
                admission.action_digest,
                admission.decision.contract_digest,
                self.issuer._generation,
            )
            if (
                broker.host_id != subject.host_id
                or self._ancestry_digest(row) != admission.ancestry_digest
                or subject.context is None
                or subject.source is None
                or self.issuer._now() >= admission.expires_at
                or admission.service_generation != self._generation
                or admission.decision._ticket is None
                or self.issuer._pending.get(admission.decision._ticket) != expected
                or not row.gate.binding_matches(admission.decision, admission.action)
            ):
                raise ValueError("current exact broker scope unavailable")
            return BrokerAdmissionScope(
                digest(admission_id),
                admission.action_digest,
                digest(admission.grant_ref),
                digest(subject.context.as_dict()),
                digest([subject.host_id, subject.certificate_digest]),
                self.issuer._generation,
                admission.expires_at,
                admission.ancestry_digest,
                row.handle.authority,
                ActionEnvelope.from_dict(admission.action.as_dict()),
                subject.context,
                subject.source,
                row.gate,
                admission.decision,
            )

    def review(
        self,
        channel: AuthorityChannel,
        reference: str,
        action: ActionEnvelope,
        *,
        credential_uses: tuple = (),
    ) -> RemoteReview:
        if type(action) is not ActionEnvelope or type(credential_uses) is not tuple:
            raise ValueError("typed exact action and protected credential receipts required")
        with self._lock, self.issuer._lock:
            row, subject = self._grant(channel, reference)
            self._expire_admissions()
            if len(self._admissions) >= self._limit:
                raise ValueError("remote admission history capacity reached")
            if subject.source is None:
                raise ValueError("workload host source unavailable")
            captured = ActionEnvelope.from_dict(action.as_dict())
            context = subject.source.context(credential_uses=credential_uses)
            decision = row.gate.evaluate_action(captured, host_context=context)
            try:
                ancestry = self._ancestry_digest(row)
            except ValueError:
                if decision._ticket:
                    self.issuer.cancel_operation(decision._ticket)
                raise
            admission = None
            expires = min(row.handle.record.expires_at, self.issuer._now() + self._lifetime)
            if decision.may_execute:
                admission = secrets.token_hex(32)
                issued = _Admission(
                    admission,
                    channel,
                    reference,
                    decision,
                    captured,
                    digest(captured.as_dict()),
                    expires,
                    self._generation,
                    ancestry,
                )
                self._admissions[admission] = self._pending[admission] = issued
            self._audit_event(
                "action_reviewed",
                admission or secrets.token_hex(32),
                action_digest=digest(captured.as_dict()),
                disposition=decision.disposition,
            )
            return RemoteReview(
                admission,
                decision.disposition,
                digest(captured.as_dict()),
                digest(reference),
                self.issuer._generation,
                expires,
                decision.reason_codes,
            )

    def _cancel(self, admission: _Admission, state: str) -> None:
        if admission.state == "pending":
            if admission.decision._ticket:
                self.issuer.cancel_operation(admission.decision._ticket)
            admission.state = state
            self._pending.pop(admission.admission_id, None)

    def _expire_admissions(self) -> None:
        now = self.issuer._now()
        for admission in tuple(self._pending.values()):
            invalid = (
                now >= admission.expires_at
                or admission.decision.issuer_generation != self.issuer._generation
            )
            if not invalid:
                try:
                    self.authenticator.require(admission.owner_channel, role="workload")
                    current = self._grants.get(admission.grant_ref)
                    invalid = (
                        current is None
                        or self._ancestry_digest(current) != admission.ancestry_digest
                    )
                except ValueError:
                    invalid = True
            if invalid:
                self._cancel(admission, "expired_or_fenced")

    def cancel(self, channel: AuthorityChannel, admission_id: str) -> bool:
        _hex(admission_id, "admission reference")
        with self._lock, self.issuer._lock:
            self._subject(channel)
            admission = self._admissions.get(admission_id)
            if (
                admission is None
                or admission.owner_channel is not channel
                or admission.state != "pending"
            ):
                return False
            self._cancel(admission, "canceled")
            return True

    def guarded_dispatch(
        self,
        broker_channel: AuthorityChannel,
        admission_id: str,
        action: ActionEnvelope,
        forward: Callable[[ActionEnvelope], Any],
    ) -> DelegationDispatch:
        """Trusted broker callback under current issuer fence; never return a cached permit.

        Core commit and callback invocation are serialized with issuer revocation.
        The broker must constrain actual effects and forward only these captured
        bytes. Callback completion is a host result, not physical enforcement.
        """
        _hex(admission_id, "admission reference")
        if type(action) is not ActionEnvelope or not callable(forward):
            raise ValueError("exact action and protected broker forwarder required")
        with self._lock, self.issuer._lock:
            self._online()
            broker = self.authenticator.require(broker_channel, role="broker")
            admission = self._admissions.get(admission_id)
            if admission is None or admission.state != "pending":
                raise ValueError("unknown or consumed remote admission")
            # Consume before any potentially failing validation/callback. A stale
            # ticket cannot be retried after an uncertain broker effect.
            admission.state = "consuming"
            self._pending.pop(admission_id, None)
            try:
                row, subject = self._grant(admission.owner_channel, admission.grant_ref)
                captured = ActionEnvelope.from_dict(admission.action.as_dict())
                if (
                    broker.host_id != subject.host_id
                    or self._ancestry_digest(row) != admission.ancestry_digest
                    or admission.service_generation != self._generation
                    or self.issuer._now() >= admission.expires_at
                    or digest(action.as_dict()) != admission.action_digest
                    or digest(captured.as_dict()) != admission.action_digest
                    or not row.gate.commit_use(admission.decision, captured)
                ):
                    raise ValueError(
                        "remote admission is stale, changed or belongs to another broker host"
                    )
            except Exception:
                admission.state = "denied"
                if admission.decision._ticket:
                    self.issuer.cancel_operation(admission.decision._ticket)
                raise ValueError("current exact remote admission refused") from None
            admission.state = "committed"
            try:
                value = forward(captured)
            except Exception:
                admission.state = "uncertain"
                self._audit_event(
                    "dispatch_uncertain", admission_id, action_digest=admission.action_digest
                )
                return DelegationDispatch(
                    "unknown",
                    digest(admission_id),
                    admission.action_digest,
                    "delegation.forward_uncertain",
                )
            admission.state = "completed"
            self._audit_event(
                "dispatch_completed", admission_id, action_digest=admission.action_digest
            )
            return DelegationDispatch(
                "host_completed",
                digest(admission_id),
                admission.action_digest,
                "delegation.host_forward_completed",
                value,
            )

    def commit(
        self,
        broker_channel: AuthorityChannel,
        admission_id: str,
        action: ActionEnvelope,
        forward: Callable[[ActionEnvelope], Any],
    ) -> DelegationDispatch:
        """Alias requiring an immediate broker callback, never a reusable boolean lease."""
        return self.guarded_dispatch(broker_channel, admission_id, action, forward)

    def revoke(
        self, channel: AuthorityChannel, parent_ref: str, target_ref: str
    ) -> tuple[str, ...]:
        with self._lock, self.issuer._lock:
            parent, _ = self._grant(channel, parent_ref)
            target = self._grants.get(_hex(target_ref, "target grant reference"))
            current = target
            while current is not None and current is not parent:
                current = self._grants.get(current.parent_ref) if current.parent_ref else None
            if target is None or current is not parent:
                raise ValueError("workload cannot revoke a sibling or unrelated grant")
            return self._revoke(target_ref, target)

    def operator_revoke(self, reference: str, *, operator: object) -> tuple[str, ...]:
        self._operator_check(operator)
        with self._lock, self.issuer._lock:
            row = self._grants.get(_hex(reference, "grant reference"))
            if row is None:
                raise ValueError("unknown issued remote grant")
            return self._revoke(reference, row)

    def _revoke(self, reference: str, row: _Grant) -> tuple[str, ...]:
        revoked = self.issuer.revoke(row.handle)
        for admission in self._admissions.values():
            self._cancel(admission, "fenced")
        self._audit_event(
            "grant_revoked",
            reference,
            affected=len(revoked),
            issuer_generation=self.issuer._generation,
        )
        return tuple(digest(self._grant_ids[v]) for v in revoked if v in self._grant_ids)

    def set_available(self, available: bool, *, operator: object) -> None:
        self._operator_check(operator)
        if type(available) is not bool:
            raise ValueError("invalid authority availability flag")
        with self._lock, self.issuer._lock:
            if available != self._available:
                self._generation += 1
                for admission in self._admissions.values():
                    self._cancel(admission, "partition_fenced")
                self._available = available

    def fence_policy(self, *, operator: object) -> None:
        self._operator_check(operator)
        with self._lock, self.issuer._lock:
            self.issuer.invalidate_policy()
            self.authenticator.fence(operator=operator)
            self._generation += 1
            for admission in self._admissions.values():
                self._cancel(admission, "policy_fenced")

    def audit(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            return tuple(dict(v) for v in self._audit)

    def handle_request(
        self, channel: AuthorityChannel, request: Mapping[str, Any]
    ) -> dict[str, Any]:
        """Bounded remote authority protocol. No wire method accepts executable callbacks."""
        try:
            if type(request) is not dict or len(json.dumps(request).encode()) > 65536:
                raise ValueError("invalid request")
            operation = request.get("operation")
            if operation == "current" and set(request) == {"operation", "grant_id"}:
                return self.require_current(channel, request["grant_id"]).to_wire()
            if operation == "issue" and set(request) == {
                "operation",
                "parent_id",
                "target_id",
                "authority",
                "request_id",
                "lifetime",
                "maximum_depth",
            }:
                return self.issue_child(
                    channel,
                    request["parent_id"],
                    request["target_id"],
                    DelegationAuthority.from_dict(request["authority"]),
                    request_id=request["request_id"],
                    lifetime=request["lifetime"],
                    maximum_depth=request["maximum_depth"],
                ).to_wire()
            if operation == "review" and set(request) == {"operation", "grant_id", "action"}:
                return self.review(
                    channel, request["grant_id"], ActionEnvelope.from_dict(request["action"])
                ).to_wire()
            if operation == "cancel" and set(request) == {"operation", "admission_id"}:
                return {"canceled": self.cancel(channel, request["admission_id"])}
            if operation == "scope" and set(request) == {"operation", "admission_id"}:
                return self.admission_scope(channel, request["admission_id"]).to_wire()
            if operation == "revoke" and set(request) == {"operation", "parent_id", "target_id"}:
                return {
                    "revoked_digests": list(
                        self.revoke(channel, request["parent_id"], request["target_id"])
                    )
                }
            raise ValueError("unsupported authority protocol operation")
        except (ValueError, TypeError, KeyError, RecursionError, OverflowError):
            raise ValueError("authority protocol request refused") from None

    def serve_one(self, connection: ssl.SSLSocket) -> None:
        """Process one length-prefixed JSON request on an existing verified TLS socket."""
        channel = self.authenticator.authenticate(connection)
        deadline = time.monotonic() + 10
        previous_timeout = connection.gettimeout()
        try:

            def read_exact(size: int) -> bytes:
                result = bytearray()
                while len(result) < size:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ValueError("authority request deadline exceeded")
                    connection.settimeout(min(remaining, previous_timeout or 10))
                    packet = connection.recv(size - len(result))
                    if not packet:
                        raise ValueError("authority transport disconnected")
                    result.extend(packet)
                return bytes(result)

            (length,) = struct.unpack("!I", read_exact(4))
            if not 1 <= length <= 65536:
                raise ValueError("authority frame limit exceeded")

            def unique(pairs):
                data = {}
                for key, value in pairs:
                    if key in data:
                        raise ValueError("duplicate authority protocol key")
                    data[key] = value
                return data

            request = json.loads(read_exact(length), object_pairs_hook=unique)
            response = self.handle_request(channel, request)
            encoded = json.dumps(response, sort_keys=True, allow_nan=False).encode()
            if len(encoded) > 65536:
                raise ValueError("authority response frame limit exceeded")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError("authority request deadline exceeded")
            connection.settimeout(min(remaining, previous_timeout or 10))
            connection.sendall(struct.pack("!I", len(encoded)) + encoded)
        except Exception:
            try:
                self.authenticator.close(channel)
            except ValueError:
                pass
            connection.close()
            raise ValueError("authority transport request failed") from None
        finally:
            if connection.fileno() >= 0:
                connection.settimeout(previous_timeout)
