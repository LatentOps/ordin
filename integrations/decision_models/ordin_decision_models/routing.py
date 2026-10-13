"""Risk routing and bounded inference. Default mode is disabled."""

from __future__ import annotations

import asyncio
import threading
import time
from dataclasses import dataclass
from typing import Any

from ordin.assurance import AssuranceGate, AssuranceDecision
from ordin.assurance._json import canonical_json, digest
from ordin.assurance.models import JsonRecord

from .fusion import SemanticDecision, issue_semantic_decision
from .protocol import (
    QUESTION_IDS,
    ProviderDescriptor,
    SanitizedDecisionState,
    SecurityQuestionSet,
    check_evidence,
    evidence,
)
from .privacy import sanitize_decision_state


@dataclass(frozen=True)
class RoutingPolicy(JsonRecord):
    """Host-owned selection, not provider/caller-supplied policy."""

    SCHEMA = "assurance_semantic_policy"
    mode: str = "disabled"
    enabled_question_ids: tuple[str, ...] = QUESTION_IDS
    mandatory_action_kinds: tuple[str, ...] = ()
    mandatory_effects: tuple[str, ...] = ()
    required_question_ids: tuple[str, ...] = ()
    escalation_threshold: float = 0.8
    uncertainty_margin: float = 0.1
    deadline_ms: int = 250
    max_total_calls: int = 32
    max_concurrency: int = 2
    max_input_bytes: int = 12_288

    def __post_init__(self):
        super().__post_init__()
        for values in (
            self.enabled_question_ids,
            self.required_question_ids,
            self.mandatory_action_kinds,
            self.mandatory_effects,
        ):
            if len(set(values)) != len(values):
                raise ValueError("duplicate semantic routing selector")
        if set(self.required_question_ids) - set(self.enabled_question_ids):
            raise ValueError("mandatory question is not enabled")
        if (
            self.mandatory_action_kinds or self.mandatory_effects
        ) and not self.required_question_ids:
            raise ValueError("mandatory semantic class requires an explicit question set")


class _Budget:
    def __init__(self, policy):
        self.policy = policy
        self.lock = threading.Lock()
        self.calls = self.inflight = self.canceled = self.timeouts = 0

    def reserve(self):
        with self.lock:
            if (
                self.calls >= self.policy.max_total_calls
                or self.inflight >= self.policy.max_concurrency
            ):
                return False
            self.calls += 1
            self.inflight += 1
            return True

    def release(self):
        with self.lock:
            self.inflight -= 1

    def snapshot(self):
        with self.lock:
            return {
                "calls": self.calls,
                "inflight": self.inflight,
                "canceled": self.canceled,
                "timeouts": self.timeouts,
            }


class SemanticInspectionRouter:
    def __init__(
        self,
        gate: AssuranceGate | None = None,
        *,
        policy: RoutingPolicy | None = None,
        provider=None,
    ):
        self.gate = gate or AssuranceGate()
        self.policy = policy or RoutingPolicy()
        if not isinstance(self.gate, AssuranceGate) or not isinstance(self.policy, RoutingPolicy):
            raise ValueError("semantic routing requires protected typed configuration")
        if provider is not None and not isinstance(provider.descriptor, ProviderDescriptor):
            raise ValueError("semantic provider needs a typed stable descriptor")
        self.provider = provider
        self._budget = _Budget(self.policy)

    @property
    def configuration_digest(self):
        return digest(
            "semantic_router",
            {
                "gate": self.gate.configuration_digest,
                "policy": self.policy.digest,
                "provider": self.provider.descriptor.digest if self.provider is not None else None,
            },
        )

    def questions_for_state(self, state: SanitizedDecisionState):
        if not isinstance(state, SanitizedDecisionState):
            raise ValueError("routing state must be issued by the privacy builder")
        signals = set(state.signals)
        available = set()
        if "task_alignment_question" in signals:
            available.add("material_intent_mismatch")
        if "network_effect" in signals:
            available.add("possible_secret_egress")
        if "authority_change_candidate" in signals:
            available.add("suspicious_permission_expansion")
        if "untrusted_instruction_context" in signals and state.authorized_task:
            available.add("untrusted_instruction_following")
        if "delegation_candidate" in signals and state.authorized_task:
            available.add("suspicious_delegation")
        mandatory = state.action_kind in self.policy.mandatory_action_kinds or any(
            effect in self.policy.mandatory_effects for effect in state.effects
        )
        selected = tuple(key for key in self.policy.enabled_question_ids if key in available)
        missing = (
            tuple(key for key in self.policy.required_question_ids if key not in selected)
            if mandatory
            else ()
        )
        return SecurityQuestionSet(selected) if selected else None, mandatory, missing

    def _prepare(self, action, state, kwargs):
        started = time.monotonic()
        configuration = self.configuration_digest
        baseline = self.gate.evaluate_action(action, **kwargs)
        if self.policy.mode == "disabled" or baseline.denied:
            return baseline, None, None, False, (), started, configuration
        if state is None:
            state = sanitize_decision_state(
                self.gate,
                baseline,
                host_context=kwargs.get("host_context"),
                history=kwargs.get("history"),
            )
        if (
            not isinstance(state, SanitizedDecisionState)
            or state.action_digest != baseline.action_digest
            or state.baseline_evidence_digest != baseline.evidence_digest
            or state.gate_configuration_digest != self.gate.configuration_digest
            or state.host_context_digest != baseline.host_context_digest
        ):
            raise ValueError("semantic input is stale or belongs to another action/context")
        questions, mandatory, missing = self.questions_for_state(state)
        return baseline, state, questions, mandatory, missing, started, configuration

    def _skip_reason(self, state, questions, missing):
        if missing:
            return "semantic.required_context_missing"
        if questions is None:
            return "semantic.no_question"
        if self.provider is None:
            return "semantic.provider_unavailable"
        if self.provider.descriptor.locality == "hosted" and not state.remote_eligible:
            return "semantic.hosted_content_refused"
        if len(canonical_json(state.as_dict()).encode()) > self.policy.max_input_bytes:
            return "semantic.input_budget_exceeded"
        return None

    def _finish(self, prepared, model=None, *, invoked=False, reason=None, kwargs=None):
        baseline, state, questions, mandatory, missing, started, configuration = prepared
        final = baseline.disposition
        reasons = []
        uncertain = ()
        if self.policy.mode == "disabled":
            reasons.append("semantic.disabled")
        elif baseline.denied:
            reasons.append("semantic.deterministic_denial")
        elif reason:
            reasons.append(reason)
        if model is not None and self.provider is not None:
            model = check_evidence(model, self.provider.descriptor, state, questions)
            if model.error_class != "none" or model.supportedness != "supported":
                reasons.append("semantic.provider_" + model.error_class)
            else:
                uncertain = tuple(
                    a.question_id
                    for a in model.answers
                    if abs(a.p_yes - 0.5) <= self.policy.uncertainty_margin
                )
                if any(a.p_yes >= self.policy.escalation_threshold for a in model.answers):
                    reasons.append("semantic.risk_threshold_crossed")
                    if self.policy.mode == "enforced-escalation" and final == "execute":
                        final = "escalate"
                if uncertain:
                    reasons.append("semantic.prediction_uncertain")
        failed_inspection = (
            reason is not None
            or model is None
            or model.error_class != "none"
            or model.supportedness != "supported"
            or bool(uncertain)
        )
        if self.policy.mode == "enforced-escalation" and not baseline.denied:
            if (mandatory and failed_inspection) or baseline.review.decision == "ask":
                if final == "execute":
                    final = "escalate"
                reasons.append("semantic.mandatory_attention_required")
        if configuration != self.configuration_digest or not self.gate.binding_matches(
            baseline,
            baseline.review.action,
            host_context=(kwargs or {}).get("host_context"),
            history=(kwargs or {}).get("history"),
        ):
            # A changed binding cannot produce an executable result. Shadow also
            # refuses stale reviews at use time while preserving its sampled parity.
            reasons.append("semantic.configuration_changed")
            if self.policy.mode == "enforced-escalation":
                final = "deny"
        return issue_semantic_decision(
            baseline,
            decision_id="semantic:"
            + digest("semantic_decision_id", [baseline.evidence_digest, configuration])[:24],
            mode=self.policy.mode,
            disposition=final,
            baseline_disposition=baseline.disposition,
            baseline_evidence_digest=baseline.evidence_digest,
            router_configuration_digest=configuration,
            state_digest=state.digest if state else None,
            question_set_digest=questions.digest if questions else None,
            model_evidence=model,
            model_invoked=invoked,
            mandatory=mandatory,
            uncertain_question_ids=uncertain,
            reason_codes=tuple(dict.fromkeys(reasons)),
            elapsed_ms=round((time.monotonic() - started) * 1000, 6),
        )

    def evaluate_action(self, action, *, state=None, **kwargs) -> SemanticDecision:
        prepared = self._prepare(action, state, kwargs)
        baseline, state, questions, mandatory, missing, started, configuration = prepared
        if self.policy.mode == "disabled" or baseline.denied:
            return self._finish(prepared, kwargs=kwargs)
        reason = self._skip_reason(state, questions, missing)
        if reason:
            return self._finish(prepared, reason=reason, kwargs=kwargs)
        if not callable(getattr(self.provider, "evaluate", None)):
            return self._finish(
                prepared, reason="semantic.async_provider_requires_async", kwargs=kwargs
            )
        if not self._budget.reserve():
            return self._finish(prepared, reason="semantic.call_budget_exceeded", kwargs=kwargs)
        descriptor = self.provider.descriptor
        done = threading.Event()
        output: list[Any] = []

        def work():
            try:
                output.append(
                    self.provider.evaluate(state, questions, deadline_ms=self.policy.deadline_ms)
                )
            except Exception:
                output.append(evidence(descriptor, state, questions, error_class="transport"))
            finally:
                self._budget.release()
                done.set()

        threading.Thread(target=work, daemon=True, name="ordin-semantic-evaluation").start()
        if not done.wait(self.policy.deadline_ms / 1000):
            with self._budget.lock:
                self._budget.timeouts += 1
            model = evidence(descriptor, state, questions, error_class="timeout")
        else:
            model = output[0]
        return self._finish(prepared, model, invoked=True, kwargs=kwargs)

    async def evaluate_action_async(self, action, *, state=None, **kwargs) -> SemanticDecision:
        prepared = self._prepare(action, state, kwargs)
        baseline, state, questions, mandatory, missing, started, configuration = prepared
        if self.policy.mode == "disabled" or baseline.denied:
            return self._finish(prepared, kwargs=kwargs)
        reason = self._skip_reason(state, questions, missing)
        if reason:
            return self._finish(prepared, reason=reason, kwargs=kwargs)
        if not callable(getattr(self.provider, "evaluate_async", None)):
            # The synchronous path already bounds workers and retains leases
            # until actual completion. It is never a hidden synchronous hosted call.
            if self.provider.descriptor.locality == "hosted":
                return self._finish(
                    prepared, reason="semantic.async_provider_unavailable", kwargs=kwargs
                )
            return await asyncio.to_thread(self.evaluate_action, action, state=state, **kwargs)
        if not self._budget.reserve():
            return self._finish(prepared, reason="semantic.call_budget_exceeded", kwargs=kwargs)
        descriptor = self.provider.descriptor
        try:
            model = await asyncio.wait_for(
                self.provider.evaluate_async(state, questions, deadline_ms=self.policy.deadline_ms),
                self.policy.deadline_ms / 1000,
            )
        except asyncio.TimeoutError:
            with self._budget.lock:
                self._budget.timeouts += 1
            model = evidence(descriptor, state, questions, error_class="timeout")
        except asyncio.CancelledError:
            with self._budget.lock:
                self._budget.canceled += 1
            raise
        except Exception:
            model = evidence(descriptor, state, questions, error_class="transport")
        finally:
            self._budget.release()
        return self._finish(prepared, model, invoked=True, kwargs=kwargs)

    def binding_matches(self, result: SemanticDecision, action, *, state=None, **kwargs):
        if (
            not isinstance(result, SemanticDecision)
            or result._seal is None
            or result._seal.payload_digest != result.digest
            or result.router_configuration_digest != self.configuration_digest
        ):
            return False
        if result._baseline is None or not self.gate.binding_matches(
            result._baseline, action, **kwargs
        ):
            return False
        return (
            result.state_digest is None
            or isinstance(state, SanitizedDecisionState)
            and state.digest == result.state_digest
            and state.action_digest == result._baseline.action_digest
        )
