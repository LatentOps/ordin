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
from .host import AssuranceHostContext, HostCredentialUse, HostEvidenceSource
from .rest import RestRequestContract, derive_rest_request_contract


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
    _approval_satisfaction: Any = field(default=None, repr=False, compare=False, kw_only=True)

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
        packet = {
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
        if self._approval_satisfaction is not None:
            packet["approval_satisfaction_digest"] = self._approval_satisfaction.digest
        return packet

    @property
    def review(self) -> ActionReview:
        review = self.assurance.review
        if not isinstance(review, ActionReview):
            raise ValueError("delegated decision requires a generic action review")
        return review

    @property
    def digest(self) -> str:
        return digest("delegated_decision", self.as_dict())

    @property
    def may_execute(self) -> bool:
        return self.disposition == "execute" or self.approval_fulfilled

    @property
    def approval_fulfilled(self) -> bool:
        return (
            self.disposition != "deny"
            and self._approval_satisfaction is not None
            and self._approval_satisfaction is self.assurance._approval_satisfaction
            and self.assurance.approval_fulfilled
        )

    @property
    def approval_execution_lease(self):
        return self.assurance.approval_execution_lease if self.approval_fulfilled else None

    @property
    def execution_eligibility(self) -> str:
        return (
            "approved"
            if self.approval_fulfilled
            else "eligible"
            if self.disposition == "execute"
            else "denied"
            if self.disposition == "deny"
            else "approval_required"
        )

    @property
    def denied(self) -> bool:
        return self.disposition == "deny"

    @property
    def requires_approval(self) -> bool:
        return self.disposition == "escalate" and not self.approval_fulfilled

    @classmethod
    def from_dict(cls, payload: Mapping) -> DelegatedDecision:
        raise ValueError("JSON decisions cannot authorize delegated use")


@dataclass(frozen=True)
class _ChildSessionGate(AgentGate):
    owner: Any = None

    def evaluate_action(self, action, **kwargs) -> AgentDecision:
        decision = self.owner._review(action, **kwargs)
        self.owner._captured.append(decision)
        baseline = decision.assurance.baseline
        result = AgentDecision(
            decision.disposition,
            decision.assurance.review,
            _approval_satisfaction=baseline._approval_satisfaction
            if decision.approval_fulfilled
            else None,
            _approval_scope=baseline._approval_scope if decision.approval_fulfilled else None,
            _approval_configuration=baseline._approval_configuration
            if decision.approval_fulfilled
            else None,
            _approval_execution_lease=baseline._approval_execution_lease
            if decision.approval_fulfilled
            else None,
        )
        contract = (
            self.owner._review_contract(decision.assurance, decision._context)
            if self.owner._session._runtime_active
            and not decision.denied
            and decision.contract_digest is not None
            else None
        )
        self.owner._session_runtime_binding = (result, decision, contract)
        return result

    def _runtime_credential_bindings(
        self, decision: AgentDecision
    ) -> tuple[CredentialBinding, ...]:
        binding = self.owner._session_runtime_binding
        if (
            binding is None
            or binding[0] is not decision
            or not self.owner._captured
            or self.owner._captured[-1] is not binding[1]
            or decision.review is not binding[1].assurance.review
        ):
            raise ValueError("original immediate delegated session decision required")
        original, contract = binding[1], binding[2]
        # Denied proposals still belong in history. They acquire no credential
        # correlation or execution rights from an invalid/expired grant.
        if original.denied or contract is None:
            return ()
        context = original._context
        if (
            not self.owner.binding_matches(original, original.assurance.review.action)
            or context._authority is None
            or context._authority.source_key != self.owner.source.key
            or context._authority.payload_digest != digest("host_context", context.as_dict())
            or original.contract_digest != contract.digest
        ):
            raise ValueError("original current delegated credential context required")
        for use in context.credential_uses:
            if (
                type(use) is not HostCredentialUse
                or use._authority is None
                or use.source_key != self.owner.source.key
                or use._authority.source_key != use.source_key
                or use._authority.payload_digest
                != digest("assurance_host_credential_use", use.as_dict())
            ):
                raise ValueError("original sealed credential routing receipt required")
        capability = (
            contract if type(contract) is RuntimeCapabilityContract else contract.capability
        )
        baseline = derive_runtime_capability_contract(
            decision.review, approval_execution_lease=decision.approval_execution_lease
        )
        if (
            capability != replace(baseline, credentials=capability.credentials, contract_id="")
            or capability._approval_lease is not baseline._approval_lease
        ):
            raise ValueError("delegated correlation may add only original credential routing")
        return capability.credentials


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
        self._issued_inputs: dict[str, tuple[DelegatedDecision, dict[str, Any]]] = {}
        self._next_context: AssuranceHostContext | None = None
        self._next_approval_options: dict[str, Any] = {}
        self._session_runtime_binding: tuple[AgentDecision, DelegatedDecision, Any] | None = None
        self._lock = threading.RLock()
        session_identity = identity or SessionIdentity(
            "ordin-assurance-child", grant.record.grant_id
        )
        self._session = IntegrationSession(
            session_identity, _ChildSessionGate(assurance.ordin, self)
        )

    def _review_contract(self, underlying: AssuranceDecision, context: AssuranceHostContext):
        capability = derive_runtime_capability_contract(
            underlying.review, approval_execution_lease=underlying.approval_execution_lease
        )
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
        return (
            derive_rest_request_contract(underlying.review, capability=capability)
            if underlying.review.adapter == "network.rest"
            else (
                replace(request, capability=capability, request_contract_id="")
                if request.requests
                or any(n.protocol in {"graphql", "mcp", "json-rpc"} for n in capability.network)
                else capability
            )
        )

    def _review(
        self,
        action: ActionEnvelope,
        *,
        history: ActionHistory,
        _reserve: bool = True,
        _assurance: AssuranceGate | None = None,
        _host_context: AssuranceHostContext | None = None,
        **kwargs,
    ) -> DelegatedDecision:
        for name, value in self._next_approval_options.items():
            if name in kwargs and kwargs[name] is not value:
                raise ValueError("approval inputs changed during delegated review")
        kwargs = {**kwargs, **self._next_approval_options}
        assurance = _assurance if _assurance is not None else self.assurance
        context = _host_context or self._next_context or self.source.context(history=history)
        if context.source.key != self.source.key:
            raise ValueError("child review context belongs to another host identity")
        underlying = assurance.evaluate_action(
            action, host_context=context, history=history, **kwargs
        )
        assert isinstance(underlying.review, ActionReview)
        final = underlying.disposition
        approval_blocked = underlying.denied
        reasons = []
        verified = None
        contract: (
            RuntimeCapabilityContract | RuntimeRequestContractV2 | RestRequestContract | None
        ) = None
        ticket = None
        if underlying.baseline.denied:
            reasons.append("delegation.core_denied")
        else:
            try:
                self.issuer.require_current(self.grant, self.source)
                contract = self._review_contract(underlying, context)
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
                    underlying = assurance.evaluate_action(
                        underlying.review.action, host_context=context, history=history, **kwargs
                    )
                    final = underlying.disposition
                if not checked.ok:
                    approval_blocked = True
                    final = (
                        "deny"
                        if checked.result == "exceeds_boundary"
                        else "escalate"
                        if final == "execute"
                        else final
                    )
                    reasons.append("delegation.operation_" + checked.result)
                if self.grant.authority.requires_approval and not any(
                    a.action_digest == underlying.action_digest and a.current
                    for a in context.approvals
                ):
                    approval_blocked = True
                    if final == "execute":
                        final = "escalate"
                    reasons.append("delegation.grant_approval_required")
                if (
                    final == "execute"
                    or underlying.approval_fulfilled
                    and not approval_blocked
                    and final != "deny"
                ):
                    if _reserve:
                        ticket = self.issuer._reserve_operation(
                            self.grant, self.source, underlying.action_digest, contract
                        )
                    else:
                        self.issuer._preview_operation(self.grant, self.source, contract)
            except ValueError:
                approval_blocked = True
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
            _approval_satisfaction=underlying._approval_satisfaction
            if underlying.approval_fulfilled and not approval_blocked and final != "deny"
            else None,
        )
        preview = object.__new__(DelegatedDecision)
        for key, value in values.items():
            object.__setattr__(preview, key, value)
        decision = DelegatedDecision(
            **values, _seal=_DelegatedSeal(self.issuer._issuer_key, preview.digest)
        )
        if ticket is not None:
            with self.issuer._lock:
                self._issued_inputs = {
                    key: value
                    for key, value in self._issued_inputs.items()
                    if key in self.issuer._pending
                }
                self._issued_inputs[ticket] = (decision, dict(kwargs))
        return decision

    def original_review_inputs(self, decision: DelegatedDecision) -> dict[str, Any]:
        """Exact original protected inputs for a still-pending original decision.

        This does not append history, reserve again or accept an arbitrary
        retained decision. Used by a broker composing fresh global checks.
        """
        with self.issuer._lock:
            record = (
                self._issued_inputs.get(decision._ticket)
                if isinstance(decision, DelegatedDecision) and decision._ticket
                else None
            )
            expected = (
                (
                    self.grant.record.grant_id,
                    decision.action_digest,
                    decision.contract_digest,
                    self.issuer._generation,
                )
                if record
                else None
            )
            if (
                record is None
                or record[0] is not decision
                or self.issuer._pending.get(decision._ticket or "") != expected
                or not self.binding_matches(decision, decision.assurance.review.action)
            ):
                raise ValueError("original current delegated review inputs unavailable")
            return dict(record[1])

    @property
    def preview_binding_digest(self) -> str:
        """Read-only fingerprint of the exact child history and quota state."""
        with self._lock, self._session._lock, self.issuer._lock:
            return core_digest(
                {
                    "assurance": self.assurance.configuration_digest,
                    "grant": self.grant.digest,
                    "source": self.source.key,
                    "issuer_generation": self.issuer._generation,
                    "history": self._session.snapshot(),
                    "runtime": self._session.runtime_snapshot(),
                    "used": dict(self.issuer._used),
                    "pending": sorted(self.issuer._pending.values()),
                }
            )

    def preview_action(
        self,
        action: ActionEnvelope,
        *,
        host_context: AssuranceHostContext | None = None,
        contract_check=None,
        approval_satisfaction=None,
        approval_scope=None,
        approval_execution_lease=None,
    ) -> DelegatedDecision:
        """Read-only review: no audit emission, session append, ticket or credential."""
        if not isinstance(action, ActionEnvelope):
            raise ValueError("delegated preview requires a normalized typed action")
        if host_context is not None and (
            not isinstance(host_context, AssuranceHostContext)
            or host_context.source.key != self.source.key
        ):
            raise ValueError("agent JSON cannot supply a child host context")
        with self._lock, self._session._lock:
            proposed, history, observations, extra = self._session._review_inputs(
                action, contract_check
            )
            baseline = replace(
                self.assurance.baseline_gate,
                ordin=replace(self.assurance.ordin, audit=None),
            )
            assurance = replace(self.assurance, baseline_gate=baseline)
            approval_options = (
                {
                    "approval_satisfaction": approval_satisfaction,
                    "approval_scope": approval_scope,
                    "approval_execution_lease": approval_execution_lease,
                }
                if any(
                    value is not None
                    for value in (approval_satisfaction, approval_scope, approval_execution_lease)
                )
                else {}
            )
            return self._review(
                proposed,
                history=history,
                observations=observations,
                _reserve=False,
                _assurance=assurance,
                _host_context=host_context,
                **approval_options,
                **extra,
            )

    def evaluate_action(
        self,
        action: ActionEnvelope,
        *,
        host_context: AssuranceHostContext | None = None,
        contract_check=None,
        approval_satisfaction=None,
        approval_scope=None,
        approval_execution_lease=None,
    ) -> DelegatedDecision:
        if not isinstance(action, ActionEnvelope):
            raise ValueError("delegated review requires a normalized typed action")
        if host_context is not None and (
            not isinstance(host_context, AssuranceHostContext)
            or host_context.source.key != self.source.key
        ):
            raise ValueError("agent JSON cannot supply a child host context")
        with self._lock:
            captured_count = len(self._captured)
            self._next_context = host_context
            self._next_approval_options = (
                {
                    "approval_satisfaction": approval_satisfaction,
                    "approval_scope": approval_scope,
                    "approval_execution_lease": approval_execution_lease,
                }
                if any(
                    value is not None
                    for value in (approval_satisfaction, approval_scope, approval_execution_lease)
                )
                else {}
            )
            try:
                self._session.evaluate(
                    action, contract_check=contract_check, approval_supported=False
                )
                return self._captured.pop()
            except BaseException:
                # A failed initial append never returned a usable review and
                # cannot have forwarded. Release only its original pending use.
                for captured in self._captured[captured_count:]:
                    if captured._ticket is not None:
                        self.issuer.cancel_operation(captured._ticket)
                        self._issued_inputs.pop(captured._ticket, None)
                raise
            finally:
                del self._captured[captured_count:]
                self._session_runtime_binding = None
                self._next_context = None
                self._next_approval_options = {}

    def is_original_decision(self, decision: DelegatedDecision, action: ActionEnvelope) -> bool:
        """Protected composition of an existing reservation without a second review."""
        if type(decision) is not DelegatedDecision:
            return False
        with self._lock, self.issuer._lock:
            try:
                self.original_review_inputs(decision)
                return self.binding_matches(decision, action)
            except ValueError:
                return False

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
