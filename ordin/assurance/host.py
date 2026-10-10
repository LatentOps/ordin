"""Host-owned facts and action-bound receipts; JSON never authenticates them.

The host protects this source and its approval/assessment channel. Like
RuntimeEvidenceSource, this is an API boundary, not an in-process security
boundary or independent proof of backend enforcement. Assessments describe
authenticated host results, never scanner/model hypotheses or raw observations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import cached_property
from typing import Any, Mapping

from ordin.action import ActionEnvelope, ActionHistory
from ordin._runtime_json import digest as core_digest
from ordin.runtime_boundary import RuntimeCapabilityBoundary
from ordin.runtime_contract import CredentialBinding
from ordin.runtime_requests_v2 import RuntimeRequestBoundaryV2

from ._json import digest, validate
from .models import ApprovedSecurityProfile, JsonRecord, RepositoryScope, _unique


@dataclass(frozen=True)
class _ReceiptAuthority:
    source_key: str
    payload_digest: str


@dataclass(frozen=True)
class HostApproval(JsonRecord):
    SCHEMA = "assurance_host_approval"
    receipt_id: str
    source_key: str
    action_digest: str
    profile_digest: str
    contract_id: str | None = None
    _authority: _ReceiptAuthority | None = field(
        default=None, repr=False, compare=False, kw_only=True
    )

    def __post_init__(self) -> None:
        super().__post_init__()
        if (
            not isinstance(self._authority, _ReceiptAuthority)
            or self._authority.source_key != self.source_key
            or (self._authority.payload_digest != self.digest)
        ):
            raise ValueError("approval requires a protected host channel")


@dataclass(frozen=True)
class HostConstraintAssessment(JsonRecord):
    SCHEMA = "assurance_host_assessment"
    assessment_id: str
    source_key: str
    action_digest: str
    profile_digest: str
    invariant_id: str
    kind: str
    status: str
    contract_id: str | None = None
    proof_gaps: tuple[str, ...] = ()
    origin: str = "host_authenticated_assessment"
    _authority: _ReceiptAuthority | None = field(
        default=None, repr=False, compare=False, kw_only=True
    )

    def __post_init__(self) -> None:
        super().__post_init__()
        if (
            not isinstance(self._authority, _ReceiptAuthority)
            or self._authority.source_key != self.source_key
            or (self._authority.payload_digest != self.digest)
        ):
            raise ValueError("assessment requires a protected host channel")
        if self.status in {"satisfied", "violated"} and self.proof_gaps:
            raise ValueError("unresolved host assessment cannot declare a conclusive result")


@dataclass(frozen=True)
class HostCapabilityAuthority:
    authority_id: str
    boundary: RuntimeCapabilityBoundary

    def __post_init__(self) -> None:
        if not isinstance(self.boundary, RuntimeCapabilityBoundary):
            raise ValueError("capability authority requires an operator-owned boundary")
        validate("assurance_authority_ref", self.as_dict())

    def as_dict(self) -> dict:
        return {"authority_id": self.authority_id, "boundary_digest": self.boundary.digest}


@dataclass(frozen=True)
class HostCredentialUse(JsonRecord):
    SCHEMA = "assurance_host_credential_use"
    receipt_id: str
    source_key: str
    action_digest: str
    profile_digest: str
    binding: str
    host: str
    port: int
    _authority: _ReceiptAuthority | None = field(
        default=None, repr=False, compare=False, kw_only=True
    )

    def __post_init__(self) -> None:
        super().__post_init__()
        CredentialBinding(self.binding, self.host, self.port)
        if (
            not isinstance(self._authority, _ReceiptAuthority)
            or self._authority.source_key != self.source_key
            or (self._authority.payload_digest != self.digest)
        ):
            raise ValueError("credential routing requires a protected host channel")


@dataclass(frozen=True)
class HostRequestAuthority:
    authority_id: str
    boundary: RuntimeRequestBoundaryV2

    def __post_init__(self) -> None:
        if not isinstance(self.boundary, RuntimeRequestBoundaryV2):
            raise ValueError("request authority requires an exact operator-owned v2 boundary")
        validate("assurance_authority_ref", self.as_dict())

    def as_dict(self) -> dict:
        return {"authority_id": self.authority_id, "boundary_digest": self.boundary.digest}


@dataclass(frozen=True)
class _ContextAuthority:
    source_key: str
    payload_digest: str


@dataclass(frozen=True)
class AssuranceHostContext:
    source: HostEvidenceSource
    capability_authorities: tuple[HostCapabilityAuthority, ...] = ()
    request_authorities: tuple[HostRequestAuthority, ...] = ()
    approvals: tuple[HostApproval, ...] = ()
    assessments: tuple[HostConstraintAssessment, ...] = ()
    credential_uses: tuple[HostCredentialUse, ...] = ()
    history_digest: str | None = None
    _authority: _ContextAuthority | None = field(
        default=None, repr=False, compare=False, kw_only=True
    )

    def __post_init__(self) -> None:
        if not isinstance(self.source, HostEvidenceSource):
            raise ValueError("host context requires a protected evidence source")
        for name, model, key in (
            ("capability_authorities", HostCapabilityAuthority, "authority_id"),
            ("request_authorities", HostRequestAuthority, "authority_id"),
            ("approvals", HostApproval, "receipt_id"),
            ("assessments", HostConstraintAssessment, "assessment_id"),
            ("credential_uses", HostCredentialUse, "receipt_id"),
        ):
            value = getattr(self, name)
            if (
                not isinstance(value, (list, tuple))
                or len(value) > 128
                or any(not isinstance(item, model) for item in value)
            ):
                raise ValueError("host context requires bounded typed records")
            object.__setattr__(self, name, tuple(value))
            _unique(tuple(value), key)
        if any(receipt.source_key != self.source.key for receipt in self.approvals) or any(
            receipt.source_key != self.source.key for receipt in self.assessments
        ):
            raise ValueError("host receipt belongs to another principal, policy, session or epoch")
        if any(receipt.source_key != self.source.key for receipt in self.credential_uses):
            raise ValueError("credential routing belongs to another host scope")
        validate("assurance_host_context", self.as_dict())
        if (
            not isinstance(self._authority, _ContextAuthority)
            or self._authority.source_key != self.source.key
            or (self._authority.payload_digest != self.digest)
        ):
            raise ValueError("host context cannot be activated from ordinary data")

    def as_dict(self) -> dict:
        return {
            "schema_version": "ordin.assurance_host_context.v1",
            "scope": self.source.as_dict(),
            "source_key": self.source.key,
            "capability_authorities": [item.as_dict() for item in self.capability_authorities],
            "request_authorities": [item.as_dict() for item in self.request_authorities],
            "approval_digests": [item.digest for item in self.approvals],
            "assessment_digests": [item.digest for item in self.assessments],
            "credential_use_digests": [item.digest for item in self.credential_uses],
            "history_digest": self.history_digest,
        }

    @cached_property
    def digest(self) -> str:
        return digest("host_context", self.as_dict())

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> AssuranceHostContext:
        raise ValueError("JSON cannot authenticate host context")


@dataclass(frozen=True)
class HostEvidenceSource:
    """Protected host principal/session/policy channel, not agent-supplied data.

    record_approval is called only after actual host-authorized approval.
    record_assessment is called only after authenticated, conclusive domain
    verification. It does not infer causal flow or validate grant lifecycle.
    M6/M7 verifier integrations must supply those real results; absence remains
    inconclusive. This source issues neither credentials nor execution grants.
    """

    principal: str
    repository: RepositoryScope
    session_digest: str
    epoch: int
    runtime_policy_digest: str
    selection_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.repository, RepositoryScope):
            raise ValueError("host source requires repository scope")
        validate("assurance_host_scope", self.as_dict())

    def as_dict(self) -> dict:
        return {
            "principal": self.principal,
            "repository": self.repository.as_dict(),
            "session_digest": self.session_digest,
            "epoch": self.epoch,
            "runtime_policy_digest": self.runtime_policy_digest,
            "selection_digest": self.selection_digest,
        }

    @cached_property
    def key(self) -> str:
        return digest("host_evidence_source", self.as_dict())

    def _check_profile(self, profile: ApprovedSecurityProfile) -> None:
        if (
            not isinstance(profile, ApprovedSecurityProfile)
            or profile.profile.repository != self.repository
            or (
                profile.selection_digest != self.selection_digest
                or profile.runtime_policy_digest != self.runtime_policy_digest
            )
        ):
            raise ValueError("host evidence source does not match selected profile")

    def record_approval(
        self,
        action: ActionEnvelope,
        profile: ApprovedSecurityProfile,
        *,
        receipt_id: str,
        contract_id: str | None = None,
    ) -> HostApproval:
        self._check_profile(profile)
        if not isinstance(action, ActionEnvelope):
            raise ValueError("host approval requires the exact normalized action")
        values: dict[str, Any] = dict(
            receipt_id=receipt_id,
            source_key=self.key,
            action_digest=core_digest(action.as_dict()),
            profile_digest=profile.digest,
            contract_id=contract_id,
        )
        packet = {"schema_version": "ordin.assurance_host_approval.v1", **values}
        validate("assurance_host_approval", packet)
        authority = _ReceiptAuthority(self.key, digest("assurance_host_approval", packet))
        return HostApproval(**values, _authority=authority)

    def record_assessment(
        self,
        action: ActionEnvelope,
        profile: ApprovedSecurityProfile,
        *,
        assessment_id: str,
        invariant_id: str,
        kind: str,
        status: str,
        contract_id: str | None = None,
        proof_gaps: tuple[str, ...] = (),
    ) -> HostConstraintAssessment:
        self._check_profile(profile)
        if not isinstance(action, ActionEnvelope):
            raise ValueError("host assessment requires the exact normalized action")
        values: dict[str, Any] = dict(
            assessment_id=assessment_id,
            source_key=self.key,
            action_digest=core_digest(action.as_dict()),
            profile_digest=profile.digest,
            invariant_id=invariant_id,
            kind=kind,
            status=status,
            contract_id=contract_id,
            proof_gaps=list(proof_gaps),
            origin="host_authenticated_assessment",
        )
        packet = {"schema_version": "ordin.assurance_host_assessment.v1", **values}
        validate("assurance_host_assessment", packet)
        authority = _ReceiptAuthority(self.key, digest("assurance_host_assessment", packet))
        return HostConstraintAssessment(**values, _authority=authority)

    def context(
        self,
        *,
        capability_authorities: tuple[HostCapabilityAuthority, ...] = (),
        request_authorities: tuple[HostRequestAuthority, ...] = (),
        approvals: tuple[HostApproval, ...] = (),
        assessments: tuple[HostConstraintAssessment, ...] = (),
        credential_uses: tuple[HostCredentialUse, ...] = (),
        history: ActionHistory | None = None,
    ) -> AssuranceHostContext:
        if history is not None and not isinstance(history, ActionHistory):
            raise ValueError("host history requires an exact typed ActionHistory")
        history_hash = core_digest(history.as_dict()) if history is not None else None
        values: dict[str, Any] = dict(
            source=self,
            capability_authorities=capability_authorities,
            request_authorities=request_authorities,
            approvals=approvals,
            assessments=assessments,
            credential_uses=credential_uses,
            history_digest=history_hash,
        )
        # Form the same bounded audit packet without creating an unauthenticated
        # context instance. The instance constructor then verifies this seal.
        packet = {
            "schema_version": "ordin.assurance_host_context.v1",
            "scope": self.as_dict(),
            "source_key": self.key,
            "capability_authorities": [item.as_dict() for item in capability_authorities],
            "request_authorities": [item.as_dict() for item in request_authorities],
            "approval_digests": [item.digest for item in approvals],
            "assessment_digests": [item.digest for item in assessments],
            "credential_use_digests": [item.digest for item in credential_uses],
            "history_digest": history_hash,
        }
        validate("assurance_host_context", packet)
        return AssuranceHostContext(
            **values, _authority=_ContextAuthority(self.key, digest("host_context", packet))
        )

    def record_credential_use(
        self,
        action: ActionEnvelope,
        profile: ApprovedSecurityProfile,
        *,
        receipt_id: str,
        binding: CredentialBinding,
    ) -> HostCredentialUse:
        """Record host-controlled opaque routing, never a secret or permission grant."""
        self._check_profile(profile)
        if not isinstance(action, ActionEnvelope) or not isinstance(binding, CredentialBinding):
            raise ValueError("credential routing requires typed action and opaque binding")
        values: dict[str, Any] = dict(
            receipt_id=receipt_id,
            source_key=self.key,
            action_digest=core_digest(action.as_dict()),
            profile_digest=profile.digest,
            **binding.as_dict(),
        )
        packet = {"schema_version": "ordin.assurance_host_credential_use.v1", **values}
        validate("assurance_host_credential_use", packet)
        authority = _ReceiptAuthority(self.key, digest("assurance_host_credential_use", packet))
        return HostCredentialUse(**values, _authority=authority)
