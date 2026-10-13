"""Conservative composition with AgentGate; no execution, model or network calls."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from ordin.action import ActionEnvelope, ActionHistory, ActionReview
from ordin.adapters import MCPAdapter, ToolCallAdapter
from ordin.agent import AgentDecision, AgentDisposition, AgentGate
from ordin._runtime_json import digest as core_digest
from ordin.context import ExecutionContext
from ordin.data import load_effect_catalog
from ordin.execution import ObservationHistory
from ordin.mcp_contracts import MCPContractCheck
from ordin.runtime_observation import RuntimeObservationHistory, RuntimeReviewBinding
from ordin.session import configuration_digest

from ._json import digest, validate
from .host import AssuranceHostContext
from .invariants import evaluate_approved_invariants, profile_scope_error
from .models import ApprovedSecurityProfile, InvariantEvaluation, ModelRiskEvidence
from .profiles import CompiledSecurityProfile, compile_approved_profile

DISPOSITION_ORDER = {"execute": 0, "escalate": 1, "deny": 2}


@dataclass(frozen=True)
class _DecisionAuthority:
    payload_digest: str
    review_digest: str


@dataclass(frozen=True)
class AssuranceDecision:
    baseline: AgentDecision
    disposition: AgentDisposition
    action_digest: str
    baseline_configuration_digest: str
    assurance_configuration_digest: str
    invariant_evaluations: tuple[InvariantEvaluation, ...] = ()
    model_evidence: tuple[ModelRiskEvidence, ...] = ()
    contract_id: str | None = None
    profile_digest: str | None = None
    host_context_digest: str | None = None
    history_digest: str | None = None
    reason_codes: tuple[str, ...] = ()
    _effect_catalog: frozenset[str] = field(
        default_factory=frozenset, repr=False, compare=False, kw_only=True
    )
    _authority: _DecisionAuthority | None = field(
        default=None, repr=False, compare=False, kw_only=True
    )

    def __post_init__(self) -> None:
        if (
            not isinstance(self.baseline, AgentDecision)
            or self.disposition not in DISPOSITION_ORDER
            or (
                self.baseline.disposition not in DISPOSITION_ORDER
                or DISPOSITION_ORDER[self.disposition]
                < DISPOSITION_ORDER[self.baseline.disposition]
            )
        ):
            raise ValueError("assurance disposition cannot downgrade the baseline")
        for name, model, maximum in (
            ("invariant_evaluations", InvariantEvaluation, 256),
            ("model_evidence", ModelRiskEvidence, 32),
        ):
            value = getattr(self, name)
            if (
                not isinstance(value, (tuple, list))
                or len(value) > maximum
                or any(not isinstance(item, model) for item in value)
            ):
                raise ValueError("assurance decision requires bounded typed evidence")
            object.__setattr__(self, name, tuple(value))
        object.__setattr__(self, "reason_codes", tuple(self.reason_codes))
        validate("assurance_decision", self.as_dict())
        if (
            not isinstance(self._authority, _DecisionAuthority)
            or self._authority.payload_digest != self.evidence_digest
            or (self._authority.review_digest != core_digest(self.baseline.review.as_dict()))
        ):
            raise ValueError("assurance decision requires a current gate-issued result")

    @property
    def review(self):
        return self.baseline.review

    @property
    def may_execute(self) -> bool:
        return self.disposition == "execute"

    @property
    def denied(self) -> bool:
        return self.disposition == "deny"

    @property
    def requires_approval(self) -> bool:
        return self.disposition == "escalate"

    def _packet(self) -> dict:
        effects = getattr(self.baseline.review, "effects", ())
        catalog = self._effect_catalog
        retained = tuple(effect for effect in effects if effect in catalog)[:64]
        return {
            "schema_version": "ordin.assurance_decision.v1",
            "baseline": {
                "disposition": self.baseline.disposition,
                "decision": self.baseline.review.decision,
                "risk": self.baseline.review.risk,
                "effects": list(retained),
                "omitted_effects": len(effects) - len(retained),
            },
            "disposition": self.disposition,
            "action_digest": self.action_digest,
            "contract_id": self.contract_id,
            "profile_digest": self.profile_digest,
            "baseline_configuration_digest": self.baseline_configuration_digest,
            "assurance_configuration_digest": self.assurance_configuration_digest,
            "host_context_digest": self.host_context_digest,
            "history_digest": self.history_digest,
            "invariant_evaluations": [item.as_dict() for item in self.invariant_evaluations],
            "model_evidence": [item.as_dict() for item in self.model_evidence],
            "reason_codes": list(self.reason_codes),
        }

    @property
    def evidence_digest(self) -> str:
        return digest("assurance_decision", self._packet())

    def as_dict(self) -> dict:
        return {**self._packet(), "evidence_digest": self.evidence_digest}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> AssuranceDecision:
        raise ValueError("JSON decisions are advisory data, not gate-issued execution permission")


@dataclass(frozen=True)
class AssuranceGate:
    baseline_gate: AgentGate = field(default_factory=AgentGate)
    approved_profile: ApprovedSecurityProfile | None = None
    require_profile: bool = False
    required_profile_digest: str | None = None
    _compiled: CompiledSecurityProfile | None = field(
        default=None, init=False, repr=False, compare=False
    )
    _effect_catalog: frozenset[str] = field(
        default_factory=frozenset, init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        if not isinstance(self.baseline_gate, AgentGate) or type(self.require_profile) is not bool:
            raise ValueError(
                "assurance gate requires an existing AgentGate and protected configuration"
            )
        # Immutable redaction whitelist only; unknown/new labels stay omitted.
        object.__setattr__(self, "_effect_catalog", frozenset(load_effect_catalog()))
        if self.approved_profile is not None:
            if not isinstance(self.approved_profile, ApprovedSecurityProfile):
                raise ValueError("unapproved JSON/draft cannot activate an assurance gate")
            object.__setattr__(self, "_compiled", compile_approved_profile(self.approved_profile))
        if self.required_profile_digest is not None:
            validate(
                "assurance_authority_ref",
                {
                    "authority_id": "required-profile",
                    "boundary_digest": self.required_profile_digest,
                },
            )

    @property
    def ordin(self):
        return self.baseline_gate.ordin

    @property
    def configuration_digest(self) -> str:
        return digest(
            "assurance_gate_configuration",
            {
                "baseline": configuration_digest(self.baseline_gate),
                "profile": self.approved_profile.digest if self.approved_profile else None,
                "selection": self.approved_profile.selection_digest
                if self.approved_profile
                else None,
                "required": self.require_profile,
                "required_profile_digest": self.required_profile_digest,
            },
        )

    def evaluate_action(
        self,
        action: ActionEnvelope | Mapping[str, Any],
        *,
        host_context: AssuranceHostContext | None = None,
        history: ActionHistory | Mapping[str, Any] | None = None,
        observations: ObservationHistory | Mapping[str, Any] | None = None,
        contract_check: MCPContractCheck | None = None,
        runtime_observations: RuntimeObservationHistory | Mapping[str, Any] | None = None,
        runtime_binding: RuntimeReviewBinding | None = None,
    ) -> AssuranceDecision:
        normalized = ActionEnvelope.from_dict(
            action.as_dict() if isinstance(action, ActionEnvelope) else action
        )
        typed_history = (
            ActionHistory.from_dict(
                history.as_dict() if isinstance(history, ActionHistory) else history
            )
            if history is not None
            else None
        )
        initial_hash = core_digest(normalized.as_dict())
        initial_configuration = configuration_digest(self.baseline_gate)
        initial_assurance_configuration = self.configuration_digest
        baseline = self.baseline_gate.evaluate_action(
            normalized,
            history=typed_history,
            observations=observations,
            contract_check=contract_check,
            runtime_observations=runtime_observations,
            runtime_binding=runtime_binding,
        )
        assert isinstance(baseline.review, ActionReview)
        final = baseline.disposition
        reasons: list[str] = []
        checks: tuple[InvariantEvaluation, ...] = ()
        profile = self.approved_profile
        host = host_context if isinstance(host_context, AssuranceHostContext) else None
        if baseline.denied:
            reasons.append("assurance.baseline_denied")
        elif profile is None:
            if self.require_profile or self.required_profile_digest is not None:
                final = "escalate"
                reasons.append("assurance.required_profile_missing")
        else:
            if (
                self.required_profile_digest is not None
                and self.required_profile_digest != profile.digest
            ):
                final = "escalate"
                reasons.append("assurance.required_profile_changed")
            error = profile_scope_error(profile, host)
            if error:
                final = "escalate"
                reasons.append(
                    "assurance.host_context_untrusted"
                    if host_context is not None and host is None
                    else error
                )
            checks = evaluate_approved_invariants(
                baseline.review, profile, host_context=host, history=typed_history
            )
            by_id = {rule.invariant_id: rule for rule in profile.profile.invariants}
            for check in checks:
                rule = by_id[check.invariant_id]
                if check.status == "violated":
                    candidate: AgentDisposition = (
                        "deny" if rule.on_violation == "block" else "escalate"
                    )
                    if DISPOSITION_ORDER[candidate] > DISPOSITION_ORDER[final]:
                        final = candidate
                    reasons.append(check.reason_code)
                elif rule.mandatory and check.status in {"unsupported", "inconclusive"}:
                    if final == "execute":
                        final = "escalate"
                    reasons.append(check.reason_code)
            if baseline.review.decision in {"ask", "warn"} and final == "execute":
                final = "escalate"
                reasons.append("assurance.baseline_attention_required")
        if core_digest(normalized.as_dict()) != initial_hash:
            final = "deny"
            reasons.append("assurance.action_changed_during_review")
        if configuration_digest(self.baseline_gate) != initial_configuration:
            final = "deny"
            reasons.append("assurance.baseline_configuration_changed_during_review")
        values: dict[str, Any] = dict(
            baseline=baseline,
            disposition=final,
            action_digest=core_digest(baseline.review.action.as_dict()),
            baseline_configuration_digest=initial_configuration,
            assurance_configuration_digest=initial_assurance_configuration,
            invariant_evaluations=checks,
            contract_id=next((check.contract_id for check in checks if check.contract_id), None),
            profile_digest=profile.digest if profile else None,
            host_context_digest=host.digest if host else None,
            history_digest=core_digest(typed_history.as_dict()) if typed_history else None,
            reason_codes=tuple(dict.fromkeys(reasons)),
            _effect_catalog=self._effect_catalog,
        )
        # Construct the audit packet with the same method, but do not accept an
        # unsealed public decision. The seal binds both outcome and core review.
        preview = object.__new__(AssuranceDecision)
        for key, value in {**values, "model_evidence": ()}.items():
            object.__setattr__(preview, key, value)
        authority = _DecisionAuthority(
            preview.evidence_digest, core_digest(baseline.review.as_dict())
        )
        return AssuranceDecision(**values, _authority=authority)

    def evaluate_tool(
        self,
        adapter: ToolCallAdapter,
        tool: str,
        arguments: Mapping[str, Any] | None = None,
        *,
        intent: str | None = None,
        context: ExecutionContext | None = None,
        action_id: str | None = None,
        **review_context: Any,
    ) -> AssuranceDecision:
        return self.evaluate_action(
            adapter.adapt(tool, arguments, intent=intent, context=context, action_id=action_id),
            **review_context,
        )

    def evaluate_mcp(
        self,
        adapter: MCPAdapter,
        tool: str,
        arguments: Mapping[str, Any] | None = None,
        *,
        intent: str | None = None,
        context: ExecutionContext | None = None,
        action_id: str | None = None,
        **review_context: Any,
    ) -> AssuranceDecision:
        return self.evaluate_action(
            adapter.adapt(tool, arguments, intent=intent, context=context, action_id=action_id),
            **review_context,
        )

    def binding_matches(
        self,
        decision: AssuranceDecision,
        action: ActionEnvelope,
        *,
        host_context: AssuranceHostContext | None = None,
        history: ActionHistory | None = None,
    ) -> bool:
        if not isinstance(decision, AssuranceDecision) or not isinstance(action, ActionEnvelope):
            return False
        if (host_context is not None and not isinstance(host_context, AssuranceHostContext)) or (
            history is not None and not isinstance(history, ActionHistory)
        ):
            return False
        if (
            decision._authority is None
            or decision._authority.payload_digest != decision.evidence_digest
            or (
                decision._authority.review_digest != core_digest(decision.baseline.review.as_dict())
            )
        ):
            return False
        return (
            decision.action_digest == core_digest(action.as_dict())
            and (decision.baseline_configuration_digest == configuration_digest(self.baseline_gate))
            and decision.assurance_configuration_digest == self.configuration_digest
            and decision.profile_digest
            == (self.approved_profile.digest if self.approved_profile else None)
            and (
                decision.host_context_digest
                == (host_context.digest if isinstance(host_context, AssuranceHostContext) else None)
            )
            and decision.history_digest == (core_digest(history.as_dict()) if history else None)
        )
