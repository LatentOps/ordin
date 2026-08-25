from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, TypeAlias

from .api import Ordin
from .context import ExecutionContext
from .review import CommandReview
from .trace import ActionTrace


AgentDisposition: TypeAlias = Literal["execute", "escalate", "deny"]


@dataclass(frozen=True)
class AgentDecision:
    """Caller-facing disposition for a proposed agent shell action."""

    disposition: AgentDisposition
    review: CommandReview

    @property
    def may_execute(self) -> bool:
        return self.disposition == "execute"

    @property
    def requires_approval(self) -> bool:
        return self.disposition == "escalate"

    @property
    def denied(self) -> bool:
        return self.disposition == "deny"


@dataclass(frozen=True)
class AgentGate:
    """Translate Ordin reviews into runtime dispositions without executing actions.

    Explicit blocks are always denied. Other decisions are evaluated with the
    `ReviewPolicy` configured on the wrapped `Ordin` instance. A policy failure
    becomes `escalate`, leaving approval and execution to the caller.
    """

    ordin: Ordin = field(default_factory=Ordin)

    def evaluate(
        self,
        command: str,
        *,
        intent: str | None = None,
        context: ExecutionContext | None = None,
        trace: ActionTrace | None = None,
    ) -> AgentDecision:
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

    def _disposition(self, review: CommandReview) -> AgentDisposition:
        if review.blocked:
            return "deny"
        if self.ordin.allows(review):
            return "execute"
        return "escalate"
