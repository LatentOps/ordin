from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal, Mapping, TypeAlias

from .action import ActionEnvelope, ActionHistory, ActionReview
from .adapters import MCPAdapter, ToolCallAdapter
from .api import Ordin
from .context import ExecutionContext
from .execution import ObservationHistory
from .mcp_contracts import MCPContractCheck
from .review import CommandReview
from .trace import ActionTrace

if TYPE_CHECKING:
    from .runtime_contract import CredentialBinding
    from .runtime_observation import RuntimeObservationHistory, RuntimeReviewBinding
    from .approval import (
        ApprovalSource,
        ApprovalAuthority,
        ApprovalSatisfaction,
        ApprovalScope,
        ApprovalExecutionLease,
    )


AgentDisposition: TypeAlias = Literal["execute", "escalate", "deny"]
AgentReview: TypeAlias = CommandReview | ActionReview


@dataclass(frozen=True)
class AgentDecision:
    """Caller-facing disposition for a proposed agent action."""

    disposition: AgentDisposition
    review: AgentReview
    _approval_satisfaction: ApprovalSatisfaction | None = field(
        default=None, repr=False, compare=False, kw_only=True
    )
    _approval_scope: ApprovalScope | None = field(
        default=None, repr=False, compare=False, kw_only=True
    )
    _approval_configuration: str | None = field(
        default=None, repr=False, compare=False, kw_only=True
    )
    _approval_execution_lease: ApprovalExecutionLease | None = field(
        default=None, repr=False, compare=False, kw_only=True
    )

    @property
    def approval_fulfilled(self) -> bool:
        from .approval import ApprovalSatisfaction

        return (
            self.disposition != "deny"
            and type(self._approval_satisfaction) is ApprovalSatisfaction
            and isinstance(self.review, ActionReview)
            and self._approval_configuration is not None
            and self._approval_satisfaction.fulfilled(
                self.review.action, self.review, self._approval_configuration, self._approval_scope
            )
        )

    @property
    def approval_execution_lease(self):
        proof = self._approval_satisfaction
        lease = self._approval_execution_lease
        return (
            lease
            if self.approval_fulfilled
            and proof is not None
            and proof._source.lease_matches(lease, proof)
            else None
        )

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
    def may_execute(self) -> bool:
        return self.disposition == "execute" or self.approval_fulfilled

    @property
    def requires_approval(self) -> bool:
        return self.disposition == "escalate" and not self.approval_fulfilled

    @property
    def denied(self) -> bool:
        return self.disposition == "deny"


@dataclass(frozen=True)
class AgentGate:
    """Translate Ordin reviews into runtime dispositions without executing actions.

    Explicit blocks are always denied. Other decisions are evaluated with the
    `ReviewPolicy` configured on the wrapped `Ordin` instance. A policy failure
    becomes `escalate`, leaving approval, sandboxing, execution, retries, and
    history persistence to the caller.
    """

    ordin: Ordin = field(default_factory=Ordin)
    approval_source: ApprovalSource | ApprovalAuthority | None = field(
        default=None, repr=False, compare=False, kw_only=True
    )

    def __post_init__(self):
        if self.approval_source is not None:
            from .approval import ApprovalSource, ApprovalAuthority

            if type(self.approval_source) not in {ApprovalSource, ApprovalAuthority}:
                raise ValueError("core approval requires its original protected host source")

    def _runtime_credential_bindings(
        self, decision: AgentDecision
    ) -> tuple[CredentialBinding, ...]:
        """Host composition for initial observation correlation; grants no authority."""
        return ()

    def evaluate(
        self,
        command: str,
        *,
        intent: str | None = None,
        context: ExecutionContext | None = None,
        trace: ActionTrace | None = None,
    ) -> AgentDecision:
        """Backward-compatible shell-command entry point."""

        review = self.ordin.review(
            command,
            intent=intent,
            context=context,
            trace=trace,
        )
        return AgentDecision(
            disposition=self._disposition(review),
            review=review,
        )

    def evaluate_action(
        self,
        action: ActionEnvelope | Mapping[str, Any],
        *,
        history: ActionHistory | Mapping[str, Any] | None = None,
        observations: ObservationHistory | Mapping[str, Any] | None = None,
        contract_check: MCPContractCheck | None = None,
        runtime_observations: "RuntimeObservationHistory | Mapping[str, Any] | None" = None,
        runtime_binding: "RuntimeReviewBinding | None" = None,
        approval_satisfaction: ApprovalSatisfaction | None = None,
        approval_scope: ApprovalScope | None = None,
        approval_execution_lease: ApprovalExecutionLease | None = None,
    ) -> AgentDecision:
        """Review a generic action through the same Ordin policy boundary."""

        review = self.ordin.review_action(
            action,
            history=history,
            observations=observations,
            contract_check=contract_check,
            runtime_observations=runtime_observations,
            runtime_binding=runtime_binding,
        )
        from .session import configuration_digest

        proof = approval_satisfaction
        from .approval import ApprovalAuthority

        accepted = (
            self.approval_source.accepts(proof)
            if type(self.approval_source) is ApprovalAuthority
            else self.approval_source is not None
            and getattr(proof, "_source", None) is self.approval_source
        )
        if not accepted:
            proof = None
        return AgentDecision(
            disposition=self._disposition(review),
            review=review,
            _approval_satisfaction=proof,
            _approval_scope=approval_scope if proof is not None else None,
            _approval_configuration=configuration_digest(self) if proof is not None else None,
            _approval_execution_lease=approval_execution_lease if proof is not None else None,
        )

    def evaluate_tool(
        self,
        adapter: ToolCallAdapter,
        tool: str,
        arguments: Mapping[str, Any] | None = None,
        *,
        intent: str | None = None,
        context: ExecutionContext | None = None,
        action_id: str | None = None,
        history: ActionHistory | Mapping[str, Any] | None = None,
        observations: ObservationHistory | Mapping[str, Any] | None = None,
    ) -> AgentDecision:
        action = adapter.adapt(
            tool,
            arguments,
            intent=intent,
            context=context,
            action_id=action_id,
        )
        return self.evaluate_action(
            action,
            history=history,
            observations=observations,
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
        history: ActionHistory | Mapping[str, Any] | None = None,
        observations: ObservationHistory | Mapping[str, Any] | None = None,
    ) -> AgentDecision:
        action = adapter.adapt(
            tool,
            arguments,
            intent=intent,
            context=context,
            action_id=action_id,
        )
        return self.evaluate_action(
            action,
            history=history,
            observations=observations,
        )

    def _disposition(self, review: AgentReview) -> AgentDisposition:
        if review.blocked:
            return "deny"
        if self.ordin.allows(review):
            return "execute"
        return "escalate"
