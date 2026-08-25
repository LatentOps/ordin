from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from .action import ActionEnvelope, ActionReview, review_action
from .action_policy import ActionPolicySet, CompiledActionPolicySet
from .context import ExecutionContext, ReviewRequest
from .policy import ReviewPolicy
from .review import CommandReview, review_command
from .risk import RiskReview, check_command
from .schema import validate_named_schema
from .search import SearchResult, search
from .trace import ActionTrace


@dataclass(frozen=True)
class Ordin:
    """Stable library entry point for command discovery and pre-execution review.

    Ordin is intentionally side-effect free: these methods search and review
    actions but never execute shell commands or generic actions.
    """

    context: ExecutionContext | None = None
    trace: ActionTrace | None = None
    policy: ReviewPolicy = field(default_factory=ReviewPolicy)
    action_policy: ActionPolicySet | CompiledActionPolicySet | None = None

    def __post_init__(self) -> None:
        if isinstance(self.action_policy, ActionPolicySet):
            object.__setattr__(self, "action_policy", self.action_policy.compile())
        elif self.action_policy is not None and not isinstance(
            self.action_policy, CompiledActionPolicySet
        ):
            raise ValueError("action_policy must be an ActionPolicySet, compiled policy, or null")

    def search(self, query: str, *, limit: int = 5) -> list[SearchResult]:
        if not isinstance(query, str) or not query.strip():
            raise ValueError("search query must be non-empty text")
        if limit < 1:
            raise ValueError("search limit must be at least 1")
        return search(query, limit=limit)

    def check(
        self,
        command: str,
        *,
        context: ExecutionContext | None = None,
    ) -> RiskReview:
        return check_command(command, context=context if context is not None else self.context)

    def review(
        self,
        command: str,
        *,
        intent: str | None = None,
        context: ExecutionContext | None = None,
        trace: ActionTrace | None = None,
    ) -> CommandReview:
        return review_command(
            command,
            intent=intent,
            context=context if context is not None else self.context,
            trace=trace if trace is not None else self.trace,
        )

    def review_request(
        self,
        request: ReviewRequest | Mapping[str, Any],
    ) -> CommandReview:
        parsed = self._parse_request(request)
        return review_command(
            parsed.command,
            intent=parsed.intent,
            context=parsed.context if parsed.context is not None else self.context,
            trace=parsed.trace if parsed.trace is not None else self.trace,
        )

    def review_action(
        self,
        action: ActionEnvelope | Mapping[str, Any],
    ) -> ActionReview:
        parsed = self._parse_action(action)
        if parsed.context is None and self.context is not None:
            parsed = ActionEnvelope(
                kind=parsed.kind,
                operation=parsed.operation,
                parameters=parsed.parameters,
                intent=parsed.intent,
                context=self.context,
                action_id=parsed.action_id,
            )
        result = review_action(parsed)
        compiled_policy = self.action_policy
        if isinstance(compiled_policy, CompiledActionPolicySet):
            result = compiled_policy.apply(result)
        return result

    def allows(self, review: RiskReview | CommandReview | ActionReview) -> bool:
        return self.policy.allows(review)

    def _parse_request(self, request: ReviewRequest | Mapping[str, Any]) -> ReviewRequest:
        if isinstance(request, ReviewRequest):
            return request
        if not isinstance(request, Mapping):
            raise ValueError("review request must be a ReviewRequest or mapping")
        payload = dict(request)
        errors = validate_named_schema("review_request", payload)
        if errors:
            raise ValueError("review request schema validation failed: " + "; ".join(errors))
        return ReviewRequest.from_dict(payload)

    def _parse_action(self, action: ActionEnvelope | Mapping[str, Any]) -> ActionEnvelope:
        if isinstance(action, ActionEnvelope):
            return action
        if not isinstance(action, Mapping):
            raise ValueError("action must be an ActionEnvelope or mapping")
        payload = dict(action)
        errors = validate_named_schema("action_envelope", payload)
        if errors:
            raise ValueError("action envelope schema validation failed: " + "; ".join(errors))
        return ActionEnvelope.from_dict(payload)
