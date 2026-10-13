"""Per-child review sessions with current issued grants and exact use binding."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Mapping
import threading

from ordin.action import ActionEnvelope, ActionHistory, ActionReview
from ordin.agent import AgentDecision, AgentGate
from ordin._runtime_json import digest as core_digest
from ordin.execution import ActionObservation
from ordin.runtime_contract import (
    CredentialBinding,
    RuntimeCapabilityContract,
    derive_runtime_capability_contract,
)
from ordin.runtime_observation import RuntimeEvidenceSource, RuntimeObservation
from ordin.runtime_requests_v2 import RuntimeRequestContractV2, derive_runtime_request_contract_v2
from ordin.session import IntegrationSession, SessionIdentity

from ._json import digest, validate
from .delegation import DelegationIssuer, DelegationVerification, IssuedDelegation, DOMAINS
from .gate import AssuranceDecision, AssuranceGate, DISPOSITION_ORDER
from .host import AssuranceHostContext, HostEvidenceSource


@dataclass(frozen=True)
class _DelegatedSeal:
    issuer_key: str
    payload_digest: str


@dataclass(frozen=True)
class DelegatedDecision:
    assurance: AssuranceDecision
    disposition: str
    grant_digest: str
    action_digest: str
    contract_digest: str | None
    issuer_generation: int
    verification: DelegationVerification | None
    reason_codes: tuple[str, ...]
    _context: AssuranceHostContext = field(repr=False, compare=False)
    _history: ActionHistory = field(repr=False, compare=False)
    _ticket: str | None = field(default=None, repr=False, compare=False)
    _seal: _DelegatedSeal | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.assurance, AssuranceDecision)
            or self.disposition not in DISPOSITION_ORDER
            or DISPOSITION_ORDER[self.disposition] < DISPOSITION_ORDER[self.assurance.disposition]
        ):
            raise ValueError("delegation cannot weaken the underlying assurance decision")
        validate("assurance_delegated_decision", self.as_dict())
        if not isinstance(self._seal, _DelegatedSeal) or self._seal.payload_digest != self.digest:
            raise ValueError("delegated decision requires a current gate-issued seal")

    def as_dict(self) -> dict:
        return {
            "schema_version": "ordin.assurance_delegated_decision.v1",
            "disposition": self.disposition,
            "baseline_disposition": self.assurance.disposition,
            "assurance_digest": self.assurance.evidence_digest,
            "grant_digest": self.grant_digest,
            "action_digest": self.action_digest,
            "contract_digest": self.contract_digest,
            "issuer_generation": self.issuer_generation,
            "verification": self.verification.as_dict() if self.verification else None,
            "reason_codes": list(self.reason_codes),
        }

    @property
    def digest(self) -> str:
        return digest("delegated_decision", self.as_dict())

    @property
    def may_execute(self) -> bool:
        return self.disposition == "execute"

    @property
    def denied(self) -> bool:
        return self.disposition == "deny"

    @property
    def requires_approval(self) -> bool:
        return self.disposition == "escalate"

    @classmethod
    def from_dict(cls, payload: Mapping) -> DelegatedDecision:
        raise ValueError("JSON decisions cannot authorize delegated use")


@dataclass(frozen=True)
class _ChildSessionGate(AgentGate):
    owner: Any = None

    def evaluate_action(self, action, **kwargs) -> AgentDecision:
        decision = self.owner._review(action, **kwargs)
        self.owner._captured.append(decision)
        return AgentDecision(decision.disposition, decision.assurance.review)


class DelegatingAssuranceGate:
    """Optional host wrapper; it reviews and binds operations without executing them.

    Each child owns an independent existing IntegrationSession. A host must bind
    the identity to the real process and enforce the effective rights in the OS
    broker. commit_use proves the binding was current at that check; it is not an
    atomic kernel execution or credential grant.
    """

    def __init__(
        self,
        assurance: AssuranceGate,
        issuer: DelegationIssuer,
        grant: IssuedDelegation,
        source: HostEvidenceSource,
        *,
        identity: SessionIdentity | None = None,
    ):
        if (
            not isinstance(assurance, AssuranceGate)
            or not isinstance(issuer, DelegationIssuer)
            or not isinstance(grant, IssuedDelegation)
            or not isinstance(source, HostEvidenceSource)
        ):
            raise ValueError("delegating gate requires protected typed host configuration")
        if assurance.approved_profile != issuer.profile:
            raise ValueError("delegating gate must use the current issuer profile")
        issuer.require_current(grant, source)
        self.assurance, self.issuer, self.grant, self.source = assurance, issuer, grant, source
        self._captured: list[DelegatedDecision] = []
        self._next_context: AssuranceHostContext | None = None
        self._lock = threading.RLock()
        session_identity = identity or SessionIdentity(
            "ordin-assurance-child", grant.record.grant_id
        )
        self._session = IntegrationSession(
            session_identity, _ChildSessionGate(assurance.ordin, self)
        )

    def _review(
        self, action: ActionEnvelope, *, history: ActionHistory, **kwargs
    ) -> DelegatedDecision:
        context = self._next_context or self.source.context(history=history)
        if context.source.key != self.source.key:
            raise ValueError("child review context belongs to another host identity")
        underlying = self.assurance.evaluate_action(
            action, host_context=context, history=history, **kwargs
        )
        assert isinstance(underlying.review, ActionReview)
        final = underlying.disposition
        reasons = []
        verified = None
        contract: RuntimeCapabilityContract | RuntimeRequestContractV2 | None = None
        ticket = None
        if underlying.baseline.denied:
            reasons.append("delegation.core_denied")
        else:
            try:
                self.issuer.require_current(self.grant, self.source)
                capability = derive_runtime_capability_contract(underlying.review)
                credentials = tuple(
                    CredentialBinding(use.binding, use.host, use.port)
                    for use in context.credential_uses
                    if use.action_digest == underlying.action_digest
                    and use.profile_digest == self.issuer.profile.digest
                )
                if credentials:
                    capability = replace(
                        capability,
                        credentials=tuple(dict.fromkeys((*capability.credentials, *credentials))),
                        contract_id="",
                    )
                request = derive_runtime_request_contract_v2(underlying.review)
                contract = (
                    replace(request, capability=capability, request_contract_id="")
                    if request.requests
                    or any(n.protocol in {"graphql", "mcp", "json-rpc"} for n in capability.network)
                    else capability
                )
                checked = self.issuer._check_operation(contract, self.grant)
                coverage = {**dict.fromkeys(DOMAINS, True), **dict(checked.coverage)}
                verified = DelegationVerification(
                    checked.result,
                    (checked.reason_code,),
                    self.grant.authority.digest,
                    self.grant.authority.digest,
                    self.issuer.operator_maximum.digest,
                    self.issuer.task_maximum.digest,
                    coverage,
                    () if checked.ok else tuple(checked.unsupported_fields)[:32],
                )
                # Profile delegation rows receive a current exact-action host
                # assessment, then a fresh review. The old result is not reused.
                receipts = tuple(
                    self.source.record_assessment(
                        underlying.review.action,
                        self.issuer.profile,
                        assessment_id="delegated:"
                        + self.grant.digest[:20]
                        + ":"
                        + rule.digest[:12],
                        invariant_id=rule.invariant_id,
                        kind="delegated_authority_subset",
                        status="satisfied"
                        if checked.ok
                        else "violated"
                        if checked.result == "exceeds_boundary"
                        else "unsupported",
                        proof_gaps=()
                        if checked.result in {"within_boundary", "exceeds_boundary"}
                        else ("Current operation requirements cannot be completely represented.",),
                    )
                    for rule in self.issuer.profile.profile.invariants
                    if rule.kind == "delegated_authority_subset"
                )
                if receipts:
                    context = self.source.context(
                        capability_authorities=context.capability_authorities,
                        request_authorities=context.request_authorities,
                        approvals=context.approvals,
                        assessments=tuple(
                            a for a in context.assessments if a.kind != "delegated_authority_subset"
                        )
                        + receipts,
                        credential_uses=context.credential_uses,
                        history=history,
                    )
                    underlying = self.assurance.evaluate_action(
                        underlying.review.action, host_context=context, history=history, **kwargs
                    )
                    final = underlying.disposition
                if not checked.ok:
                    final = (
                        "deny"
                        if checked.result == "exceeds_boundary"
                        else "escalate"
                        if final == "execute"
                        else final
                    )
                    reasons.append("delegation.operation_" + checked.result)
                if self.grant.authority.requires_approval and not any(
                    a.action_digest == underlying.action_digest for a in context.approvals
                ):
                    if final == "execute":
                        final = "escalate"
                    reasons.append("delegation.grant_approval_required")
                if final == "execute":
                    ticket = self.issuer._reserve_operation(
                        self.grant, self.source, underlying.action_digest, contract
                    )
            except ValueError:
                final = "deny"
                reasons.append("delegation.current_grant_or_quota_invalid")
        values: dict[str, Any] = dict(
            assurance=underlying,
            disposition=final,
            grant_digest=self.grant.digest,
            action_digest=underlying.action_digest,
            contract_digest=contract.digest if contract else None,
            issuer_generation=self.issuer._generation,
            verification=verified,
            reason_codes=tuple(reasons),
            _context=context,
            _history=history,
            _ticket=ticket,
        )
        preview = object.__new__(DelegatedDecision)
        for key, value in values.items():
            object.__setattr__(preview, key, value)
        return DelegatedDecision(
            **values, _seal=_DelegatedSeal(self.issuer._issuer_key, preview.digest)
        )

    def evaluate_action(
        self,
        action: ActionEnvelope,
        *,
        host_context: AssuranceHostContext | None = None,
        contract_check=None,
    ) -> DelegatedDecision:
        if not isinstance(action, ActionEnvelope):
            raise ValueError("delegated review requires a normalized typed action")
        if host_context is not None and (
            not isinstance(host_context, AssuranceHostContext)
            or host_context.source.key != self.source.key
        ):
            raise ValueError("agent JSON cannot supply a child host context")
        with self._lock:
            self._next_context = host_context
            try:
                self._session.evaluate(
                    action, contract_check=contract_check, approval_supported=False
                )
                return self._captured.pop()
            finally:
                self._next_context = None

    def binding_matches(self, decision: DelegatedDecision, action: ActionEnvelope) -> bool:
        if (
            not isinstance(decision, DelegatedDecision)
            or not isinstance(action, ActionEnvelope)
            or decision._seal is None
            or decision._seal.issuer_key != self.issuer._issuer_key
            or decision._seal.payload_digest != decision.digest
            or decision.grant_digest != self.grant.digest
            or decision.issuer_generation != self.issuer._generation
        ):
            return False
        try:
            self.issuer.require_current(self.grant, self.source)
        except ValueError:
            return False
        return self.assurance.binding_matches(
            decision.assurance, action, host_context=decision._context, history=decision._history
        )

    def commit_use(self, decision: DelegatedDecision, action: ActionEnvelope) -> bool:
        if (
            not isinstance(decision, DelegatedDecision)
            or not decision.may_execute
            or decision._ticket is None
            or decision.contract_digest is None
            or not self.binding_matches(decision, action)
        ):
            if isinstance(decision, DelegatedDecision) and decision._ticket:
                self.issuer.cancel_operation(decision._ticket)
            return False
        return self.issuer._commit_operation(
            self.grant,
            self.source,
            decision._ticket,
            decision.action_digest,
            decision.contract_digest,
            binding_check=lambda: self.assurance.binding_matches(
                decision.assurance,
                action,
                host_context=decision._context,
                history=decision._history,
            ),
        )

    def observe(self, observation: ActionObservation) -> None:
        self._session.observe(observation)  # Existing caller-asserted correlation only.

    def bind_runtime_source(self, source: RuntimeEvidenceSource) -> None:
        if (
            not isinstance(source, RuntimeEvidenceSource)
            or source.session_digest != self.source.session_digest
            or source.policy_digest != self.source.runtime_policy_digest
        ):
            raise ValueError("child collector differs from the host-issued scope")
        self._session.bind_runtime_source(source)

    def observe_runtime(self, observation: RuntimeObservation) -> None:
        self.issuer.require_current(self.grant, self.source)
        self._session.observe_runtime(observation)

    def snapshot(self) -> dict:
        return self._session.snapshot()

    @property
    def runtime_session_digest(self) -> str:
        return self._session.runtime_session_digest

    def reset(self) -> None:
        self.issuer.revoke(self.grant)
        self._session.reset()
