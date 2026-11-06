"""Pure swarm review composition. Decisions never reserve, commit or execute."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from threading import RLock
from typing import TYPE_CHECKING, Any, Mapping

from ordin.action import ActionEnvelope, ActionHistory, ActionReview
from ordin.agent import AgentDecision, AgentGate
from ordin.assurance.gate import AssuranceDecision, AssuranceGate
from ordin.assurance.delegating_gate import DelegatedDecision, DelegatingAssuranceGate
from ordin.assurance.host import AssuranceHostContext
from ordin.execution import ObservationHistory
from ordin.mcp_contracts import MCPContractCheck
from ordin.runtime_observation import RuntimeObservationHistory, RuntimeReviewBinding
from ordin._runtime_json import digest, freeze, thaw
from ordin.session import configuration_digest

from .events import _hex
from .facts import SwarmAssessment, SwarmAssessmentSource
from .identity import HostChannel
from .ingest import HostEventSource, SwarmEventIngestor
from .models import SwarmContext, SwarmIdentity, identifier
from .policy import DISPOSITIONS, SwarmPolicy
from .registry import AgentRegistry

if TYPE_CHECKING:
    from .policy_runtime import SwarmPolicyRuntime
    from .policy_facts import SwarmPolicyFacts

BaseDecision = AgentDecision | AssuranceDecision | DelegatedDecision
BaseGate = AgentGate | AssuranceGate | DelegatingAssuranceGate


def _options_digest(options: Mapping[str, Any]) -> str:
    from ordin.approval import ApprovalSatisfaction, ApprovalScope, ApprovalExecutionLease

    allowed = {
        "host_context",
        "history",
        "observations",
        "contract_check",
        "runtime_observations",
        "runtime_binding",
        "approval_satisfaction",
        "approval_scope",
        "approval_execution_lease",
    }
    if set(options) - allowed:
        raise ValueError("unsupported swarm baseline options")
    payload: dict[str, Any] = {}
    models = (
        AssuranceHostContext,
        ActionHistory,
        ObservationHistory,
        MCPContractCheck,
        RuntimeObservationHistory,
        RuntimeReviewBinding,
        ApprovalSatisfaction,
        ApprovalScope,
        ApprovalExecutionLease,
    )
    for key, value in options.items():
        if value is None:
            payload[key] = None
        elif isinstance(value, Mapping):
            payload[key] = thaw(freeze(value))
        elif type(value) in models:
            payload[key] = value.as_dict()
        else:
            raise ValueError("baseline options require bounded typed host inputs")
    return digest(payload)


@dataclass(frozen=True, slots=True)
class _DecisionSeal:
    owner: object
    payload_digest: str
    review_digest: str


@dataclass(frozen=True, slots=True)
class SwarmDecision:
    baseline: BaseDecision
    disposition: str
    action_digest: str
    registry_id: str
    identity: SwarmIdentity
    context_digest: str
    configuration_digest: str
    policy_digest: str
    evidence_snapshot_digest: str
    reason_codes: tuple[str, ...] = ()
    matched_rules: tuple[str, ...] = ()
    check_results: tuple[tuple[str, str], ...] = ()
    _seal: _DecisionSeal | None = field(default=None, repr=False, compare=False, kw_only=True)
    _assessments: tuple[SwarmAssessment, ...] = field(
        default=(), repr=False, compare=False, kw_only=True
    )
    _policy_facts: SwarmPolicyFacts | None = field(
        default=None, repr=False, compare=False, kw_only=True
    )
    _approval_satisfaction: Any = field(default=None, repr=False, compare=False, kw_only=True)

    def __post_init__(self) -> None:
        if type(self.disposition) is not str or self.disposition not in DISPOSITIONS:
            raise ValueError("invalid swarm disposition")
        if not isinstance(self.baseline, (AgentDecision, AssuranceDecision, DelegatedDecision)):
            raise ValueError("swarm decision requires its original baseline result")
        if (
            type(self.baseline.disposition) is not str
            or self.baseline.disposition not in DISPOSITIONS
            or DISPOSITIONS[self.disposition] < DISPOSITIONS[self.baseline.disposition]
        ):
            raise ValueError("swarm decision cannot weaken its baseline")
        if not isinstance(self.review, ActionReview):
            raise ValueError("swarm decision requires a generic action review")
        if type(self.review.decision) is not str or self.review.decision not in {
            "allow",
            "warn",
            "ask",
            "block",
        }:
            raise ValueError("invalid underlying core decision")
        if self.review.decision == "block" and self.disposition != "deny":
            raise ValueError("core block cannot be weakened")
        if self.review.decision in {"warn", "ask"} and self.disposition == "execute":
            raise ValueError("core warning or approval requirement cannot be bypassed")
        identifier(self.registry_id, "registry_id")
        if type(self.identity) is not SwarmIdentity:
            raise ValueError("swarm decision requires immutable host identity")
        self.identity.__post_init__()
        for name in (
            "action_digest",
            "context_digest",
            "configuration_digest",
            "policy_digest",
            "evidence_snapshot_digest",
        ):
            _hex(getattr(self, name), name)
        for name, maximum in (("reason_codes", 128), ("matched_rules", 128), ("check_results", 64)):
            value = getattr(self, name)
            if type(value) is not tuple or len(value) > maximum:
                raise ValueError("invalid bounded swarm decision evidence")
        if type(self._assessments) is not tuple or len(self._assessments) > 64:
            raise ValueError("invalid bounded decision assessments")
        for receipt in self._assessments:
            if type(receipt) is not SwarmAssessment:
                raise ValueError("decision assessments require protected host receipts")
            receipt.__post_init__()
        for code in self.reason_codes:
            identifier(code, "reason_code")
        for rule in self.matched_rules:
            identifier(rule, "rule_id")
        for check in self.check_results:
            if type(check) is not tuple or len(check) != 2:
                raise ValueError("invalid swarm check result")
            identifier(check[0], "check_id")
            if check[1] not in {"satisfied", "violated", "unknown"}:
                raise ValueError("invalid swarm check status")
        if (
            type(self._seal) is not _DecisionSeal
            or self._seal.payload_digest != digest(self.as_dict())
            or self._seal.review_digest != digest(self.review.as_dict())
        ):
            raise ValueError("swarm decision requires a current gate-issued binding")

    @property
    def review(self) -> ActionReview:
        review = self.baseline.review
        if not isinstance(review, ActionReview):
            raise ValueError("swarm decision requires a generic action review")
        return review

    @property
    def may_execute(self) -> bool:
        """A review disposition only; no ticket or execution side effect."""
        return self.disposition == "execute" or self.approval_fulfilled

    @property
    def approval_fulfilled(self) -> bool:
        return (
            self.disposition != "deny"
            and self._approval_satisfaction is not None
            and self._approval_satisfaction
            is getattr(self.baseline, "_approval_satisfaction", None)
            and self.baseline.approval_fulfilled
        )

    @property
    def approval_execution_lease(self):
        return self.baseline.approval_execution_lease if self.approval_fulfilled else None

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

    def as_dict(self) -> dict[str, Any]:
        result = {
            "schema_version": "ordin.swarm_decision.v1",
            "disposition": self.disposition,
            "baseline_disposition": self.baseline.disposition,
            "core_decision": self.review.decision,
            "action_digest": self.action_digest,
            "registry_id": self.registry_id,
            "identity": self.identity.as_dict(),
            "context_digest": self.context_digest,
            "configuration_digest": self.configuration_digest,
            "policy_digest": self.policy_digest,
            "evidence_snapshot_digest": self.evidence_snapshot_digest,
            "assessment_digests": [digest(receipt._payload()) for receipt in self._assessments],
            "reason_codes": list(self.reason_codes),
            "matched_rules": list(self.matched_rules),
            "check_results": [
                {"check_id": key, "status": status} for key, status in self.check_results
            ],
        }
        if self._policy_facts is not None:
            result["policy_facts_digest"] = self._policy_facts.digest
        if self._approval_satisfaction is not None:
            result["approval_satisfaction_digest"] = self._approval_satisfaction.digest
        return result

    @classmethod
    def from_dict(cls, value):
        raise ValueError("JSON decisions cannot authorize swarm use")


class SwarmGate:
    def __init__(
        self,
        registry: AgentRegistry,
        baseline: BaseGate | None = None,
        *,
        policy: SwarmPolicy | None = None,
        assessment_source: SwarmAssessmentSource | None = None,
        events: SwarmEventIngestor | None = None,
        delegation_context: SwarmContext | None = None,
        policy_runtime: SwarmPolicyRuntime | None = None,
    ) -> None:
        selected = baseline if baseline is not None else AgentGate()
        if type(selected) not in {AgentGate, AssuranceGate, DelegatingAssuranceGate}:
            raise ValueError("swarm review requires an existing protected Ordin gate")
        if policy is not None:
            if type(policy) is not SwarmPolicy:
                raise ValueError("agent JSON cannot configure swarm policy")
            policy.__post_init__()
        if assessment_source is not None and type(assessment_source) is not SwarmAssessmentSource:
            raise ValueError("swarm assessments require an operator-owned source")
        if events is not None and type(events) is not SwarmEventIngestor:
            raise ValueError("swarm evidence requires an authenticated event ingestor")
        if policy_runtime is not None:
            from .policy_runtime import SwarmPolicyRuntime

            if (
                type(policy_runtime) is not SwarmPolicyRuntime
                or policy_runtime._registry is not registry
            ):
                raise ValueError("compiled policy requires its original protected registry runtime")
            policy_runtime.register_gate(policy)
        if isinstance(selected, DelegatingAssuranceGate):
            if type(delegation_context) is not SwarmContext:
                raise ValueError("delegation requires an explicit host principal/session binding")
            delegation_context.__post_init__()
            if (
                delegation_context.identity.agent_id != selected.source.principal
                or delegation_context.identity.delegation_id != selected.grant.record.grant_id
            ):
                raise ValueError("delegation context does not identify the issued child grant")
        elif delegation_context is not None:
            raise ValueError("unexpected delegation context")
        self._delegation_context_digest = (
            digest(delegation_context.as_dict()) if delegation_context else None
        )
        self._registry, self._baseline, self._policy = registry, selected, policy
        self._assessment_source, self._events = assessment_source, events
        self._policy_runtime = policy_runtime
        self._key = object()
        self._lock = RLock()

    @property
    def policy_digest(self) -> str:
        legacy = self._policy.digest if self._policy else digest({"swarm_policy": None})
        return (
            legacy
            if self._policy_runtime is None
            else digest([legacy, self._policy_runtime.binding_digest])
        )

    @property
    def configuration_digest(self) -> str:
        baseline = self._baseline
        base_digest = (
            configuration_digest(baseline)
            if isinstance(baseline, AgentGate)
            else baseline.configuration_digest
            if isinstance(baseline, AssuranceGate)
            else digest(
                {
                    "assurance": baseline.assurance.configuration_digest,
                    "grant": baseline.grant.digest,
                    "source": baseline.source.key,
                }
            )
        )
        payload = {
            "baseline": base_digest,
            "kind": type(baseline).__name__,
            "policy": self.policy_digest,
            "assessment_source": self._assessment_source.binding_digest
            if self._assessment_source
            else None,
            "events_configured": self._events is not None,
            "delegation_context": self._delegation_context_digest,
        }
        return digest(payload)

    def evidence_snapshot_digest(
        self,
        context: SwarmContext,
        *,
        event_source: HostEventSource | None = None,
        **baseline_options: Any,
    ) -> str:
        events = None
        if self._events is not None:
            if event_source is None:
                raise ValueError("configured event evidence requires its protected sender")
            events = self._events.snapshot_binding(event_source, context)
        elif event_source is not None:
            raise ValueError("unexpected event source")
        delegation = (
            self._baseline.preview_binding_digest
            if type(self._baseline) is DelegatingAssuranceGate
            else None
        )
        payload = {
            "events": events,
            "delegation": delegation,
            "review_inputs": _options_digest(baseline_options),
            "assessment_source": self._assessment_source.binding_digest
            if self._assessment_source
            else None,
        }
        if self._policy_runtime is not None:
            payload["compiled_policy_evidence"] = self._policy_runtime.evidence_digest(context)
        return digest(payload)

    def _review(self, action: ActionEnvelope, kwargs: dict[str, Any]) -> BaseDecision:
        baseline = self._baseline
        if isinstance(baseline, DelegatingAssuranceGate):
            if set(kwargs) - {"host_context", "contract_check"}:
                raise ValueError("delegation preview owns its protected child history")
            return baseline.preview_action(action, **kwargs)
        quiet: AgentGate | AssuranceGate
        if isinstance(baseline, AssuranceGate):
            quiet = replace(
                baseline,
                baseline_gate=replace(
                    baseline.baseline_gate, ordin=replace(baseline.ordin, audit=None)
                ),
            )
        else:
            quiet = replace(baseline, ordin=replace(baseline.ordin, audit=None))
        return quiet.evaluate_action(action, **kwargs)

    def evaluate_action(
        self,
        context: SwarmContext,
        action: ActionEnvelope | Mapping[str, Any],
        *,
        channel: HostChannel,
        adapter: object,
        event_source: HostEventSource | None = None,
        assessments: tuple[SwarmAssessment, ...] = (),
        policy_facts: SwarmPolicyFacts | None = None,
        delegated_baseline: DelegatedDecision | None = None,
        **baseline_options: Any,
    ) -> SwarmDecision:
        """Evaluate only: caller separately owns approval, reservation and execution."""
        if type(context) is not SwarmContext:
            raise ValueError("swarm review requires an immutable host context")
        context.__post_init__()
        if type(assessments) is not tuple or len(assessments) > 64:
            raise ValueError("invalid bounded host assessments")
        original = action.as_dict() if isinstance(action, ActionEnvelope) else action
        normalized = ActionEnvelope.from_dict(original)
        action_hash = digest(normalized.as_dict())
        context_hash = digest(context.as_dict())
        if (
            self._delegation_context_digest is not None
            and context_hash != self._delegation_context_digest
        ):
            raise ValueError("delegation belongs to a different current principal/session")
        with self._lock:
            initial_config = self.configuration_digest
            reasons: list[str] = []
            try:
                self._registry.authenticate(context, channel, adapter)
                initial_snapshot = self.evidence_snapshot_digest(
                    context, event_source=event_source, **baseline_options
                )
                identity_valid = True
            except ValueError:
                identity_valid = False
                initial_snapshot = digest({"swarm_snapshot": "unverified"})
                reasons.append("swarm.identity_or_evidence_unverified")
            if delegated_baseline is None:
                underlying = self._review(normalized, dict(baseline_options))
            else:
                if (
                    type(self._baseline) is not DelegatingAssuranceGate
                    or type(delegated_baseline) is not DelegatedDecision
                    or not self._baseline.is_original_decision(delegated_baseline, normalized)
                ):
                    raise ValueError("original current delegated baseline from this gate required")
                underlying = delegated_baseline
            if not isinstance(underlying.review, ActionReview):
                raise ValueError("swarm baseline did not produce a generic action review")
            final = underlying.disposition
            approval_blocked = not identity_valid or underlying.review.decision == "block"
            proof = getattr(underlying, "_approval_satisfaction", None)
            if proof is not None and underlying.approval_fulfilled:
                try:
                    scope = proof._source.scope_for(proof)
                    if (
                        scope.context_digest != context_hash
                        or scope.policy_epoch != context.identity.policy_epoch
                    ):
                        raise ValueError("human approval belongs to another current workload")
                except (ValueError, TypeError, AttributeError):
                    approval_blocked = True
                    final = "deny"
                    reasons.append("swarm.human_approval_scope_unverified")
            if not identity_valid or underlying.review.decision == "block":
                final = "deny"
            elif underlying.review.decision in {"warn", "ask"} and final == "execute":
                final = "escalate"
                reasons.append("swarm.core_escalation_required")
            matched: list[str] = []
            policy = self._policy
            if policy is not None:
                for rule in policy.rules:
                    if (
                        (not rule.agent_ids or context.identity.agent_id in rule.agent_ids)
                        and (not rule.task_ids or context.identity.task_id in rule.task_ids)
                        and (not rule.action_kinds or normalized.kind in rule.action_kinds)
                        and (
                            not rule.effects
                            or bool(set(rule.effects).intersection(underlying.review.effects))
                        )
                    ):
                        matched.append(rule.rule_id)
                        if rule.disposition != "execute":
                            approval_blocked = True
                        final = max((final, rule.disposition), key=DISPOSITIONS.__getitem__)
                if matched:
                    reasons.append("swarm.policy_constraints")
            checks = {}
            valid_assessments = []
            valid_policy_facts = None
            for assessment in assessments:
                if self._assessment_source is None or not self._assessment_source.verify(
                    assessment,
                    action_digest=action_hash,
                    context_digest=context_hash,
                    policy_digest=self.policy_digest,
                    snapshot_digest=initial_snapshot,
                ):
                    final = "deny"
                    reasons.append("swarm.assessment_unverified")
                    continue
                allowed_checks = set(policy.required_checks if policy else ()) | set(
                    self._policy_runtime.required_checks if self._policy_runtime else ()
                )
                if assessment.check_id not in allowed_checks:
                    final = "deny"
                    reasons.append("swarm.assessment_unexpected")
                    continue
                valid_assessments.append(assessment)
                if assessment.check_id in checks:
                    final = "deny"
                    reasons.append("swarm.assessment_ambiguous")
                checks[assessment.check_id] = assessment.status
            if policy is not None:
                for check in policy.required_checks:
                    status = checks.get(check, "unknown")
                    checks[check] = status
                    if status == "violated":
                        approval_blocked = True
                        final = "deny"
                        reasons.append("swarm.mandatory_check_violated")
                    elif status != "satisfied":
                        approval_blocked = True
                        final = max(
                            (final, policy.unknown_disposition), key=DISPOSITIONS.__getitem__
                        )
                        reasons.append("swarm.mandatory_check_unknown")
            if self._policy_runtime is not None:
                projection = self._policy_runtime._evaluate(
                    context,
                    normalized,
                    underlying,
                    facts=policy_facts,
                    policy_digest=self.policy_digest,
                    snapshot_digest=initial_snapshot,
                    checks=checks,
                    delegation_gate=self._baseline
                    if type(self._baseline) is DelegatingAssuranceGate
                    else None,
                )
                if not projection.may_execute:
                    approval_blocked = True
                final = max((final, projection.disposition), key=DISPOSITIONS.__getitem__)
                reasons.extend(projection.reason_codes)
                matched.extend(projection.matched_rules)
                checks.update(projection.check_results)
                if policy_facts is not None:
                    if self._policy_runtime.facts_source.verify(
                        policy_facts,
                        context,
                        normalized,
                        policy_digest=self.policy_digest,
                        snapshot_digest=initial_snapshot,
                    ):
                        valid_policy_facts = policy_facts
                    else:
                        final = "deny"
                        reasons.append("policy.facts_changed")
            elif policy_facts is not None:
                final = "deny"
                reasons.append("policy.unexpected_facts")
            try:
                current_action = action.as_dict() if isinstance(action, ActionEnvelope) else action
                if digest(ActionEnvelope.from_dict(current_action).as_dict()) != action_hash:
                    raise ValueError("changed action")
                self._registry.authenticate(context, channel, adapter)
                if (
                    digest(context.as_dict()) != context_hash
                    or self.configuration_digest != initial_config
                    or self.evidence_snapshot_digest(
                        context, event_source=event_source, **baseline_options
                    )
                    != initial_snapshot
                    or digest(underlying.review.action.as_dict()) != action_hash
                ):
                    raise ValueError("changed swarm review binding")
            except ValueError:
                final = "deny"
                reasons.append("swarm.review_binding_changed")
            for assessment in valid_assessments:
                if self._assessment_source is None or not self._assessment_source.verify(
                    assessment,
                    action_digest=action_hash,
                    context_digest=context_hash,
                    policy_digest=self.policy_digest,
                    snapshot_digest=initial_snapshot,
                ):
                    final = "deny"
                    reasons.append("swarm.assessment_changed")
            if (
                valid_policy_facts is not None
                and self._policy_runtime is not None
                and not self._policy_runtime.facts_source.verify(
                    valid_policy_facts,
                    context,
                    normalized,
                    policy_digest=self.policy_digest,
                    snapshot_digest=initial_snapshot,
                )
            ):
                final = "deny"
                reasons.append("policy.facts_changed")
            values: dict[str, Any] = dict(
                baseline=underlying,
                disposition=final,
                action_digest=action_hash,
                registry_id=context.registry_id,
                identity=context.identity,
                context_digest=context_hash,
                configuration_digest=initial_config,
                policy_digest=self.policy_digest,
                evidence_snapshot_digest=initial_snapshot,
                reason_codes=tuple(dict.fromkeys(reasons)),
                matched_rules=tuple(matched),
                check_results=tuple(sorted(checks.items())),
                _assessments=tuple(valid_assessments),
                _policy_facts=valid_policy_facts,
                _approval_satisfaction=proof
                if underlying.approval_fulfilled and not approval_blocked and final != "deny"
                else None,
            )
            preview = object.__new__(SwarmDecision)
            for key, value in values.items():
                object.__setattr__(preview, key, value)
            return SwarmDecision(
                **values,
                _seal=_DecisionSeal(
                    self._key,
                    digest(preview.as_dict()),
                    digest(underlying.review.as_dict()),
                ),
            )

    def binding_matches(
        self,
        decision: SwarmDecision,
        context: SwarmContext,
        action: ActionEnvelope | Mapping[str, Any],
        *,
        channel: HostChannel,
        adapter: object,
        event_source: HostEventSource | None = None,
        **baseline_options: Any,
    ) -> bool:
        """Fresh binding check only; a broker must still reserve and recheck at use."""
        if type(decision) is not SwarmDecision:
            return False
        try:
            decision.__post_init__()
            if type(decision._seal) is not _DecisionSeal or decision._seal.owner is not self._key:
                return False
            self._registry.authenticate(context, channel, adapter)
            normalized = ActionEnvelope.from_dict(
                action.as_dict() if isinstance(action, ActionEnvelope) else action
            )
            if decision._approval_satisfaction is not None:
                if not decision.approval_fulfilled:
                    return False
                scope = decision._approval_satisfaction._source.scope_for(
                    decision._approval_satisfaction
                )
                if (
                    scope.context_digest != digest(context.as_dict())
                    or scope.policy_epoch != context.identity.policy_epoch
                ):
                    return False
            for assessment in decision._assessments:
                if self._assessment_source is None or not self._assessment_source.verify(
                    assessment,
                    action_digest=decision.action_digest,
                    context_digest=decision.context_digest,
                    policy_digest=decision.policy_digest,
                    snapshot_digest=decision.evidence_snapshot_digest,
                ):
                    return False
            if decision._policy_facts is not None:
                if self._policy_runtime is None or not self._policy_runtime.facts_source.verify(
                    decision._policy_facts,
                    context,
                    normalized,
                    policy_digest=decision.policy_digest,
                    snapshot_digest=decision.evidence_snapshot_digest,
                ):
                    return False
            return (
                digest(normalized.as_dict()) == decision.action_digest
                and digest(context.as_dict()) == decision.context_digest
                and context.identity == decision.identity
                and self.configuration_digest == decision.configuration_digest
                and self.policy_digest == decision.policy_digest
                and self.evidence_snapshot_digest(
                    context, event_source=event_source, **baseline_options
                )
                == decision.evidence_snapshot_digest
            )
        except (ValueError, AttributeError, TypeError):
            return False
