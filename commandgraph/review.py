from __future__ import annotations

from dataclasses import dataclass

from . import REVIEW_SCHEMA_VERSION
from .context import ExecutionContext
from .risk import check_command
from .search import SearchResult, search
from .shell import executable_name


@dataclass(frozen=True)
class CommandReview:
    intent: str | None
    command: str
    decision: str
    risk: str
    reasons: list[str]
    safer_next_step: str | None
    related_commands: list[str]
    intent_alignment: str
    context: ExecutionContext | None = None

    def as_dict(self) -> dict:
        return {
            "schema_version": REVIEW_SCHEMA_VERSION,
            "intent": self.intent,
            "command": self.command,
            "decision": self.decision,
            "risk": self.risk,
            "reasons": self.reasons,
            "safer_next_step": self.safer_next_step,
            "related_commands": self.related_commands,
            "intent_alignment": self.intent_alignment,
            "context": self.context.as_dict() if self.context else None,
        }


def warn_for_intent_mismatch(
    command: str,
    intent: str | None,
    related: list[SearchResult],
) -> tuple[str, list[str]]:
    if not intent:
        return "not_provided", []

    executable = executable_name(command)
    if not executable:
        return "unknown", ["could not identify the command executable"]

    if not related:
        return (
            "unknown",
            [f'no command graph match found for intent "{intent}"'],
        )

    top_score = related[0].score
    executable_result = next(
        (item for item in related if item.command == executable),
        None,
    )
    if executable_result and (
        executable_result.command == related[0].command
        or executable_result.score >= top_score * 0.75
    ):
        return "matched", []

    return (
        "mismatch",
        [
            (
                f'command "{executable}" is not one of the top command matches '
                f'for intent "{intent}"'
            )
        ],
    )


def review_command(
    command: str,
    intent: str | None = None,
    context: ExecutionContext | None = None,
) -> CommandReview:
    risk = check_command(command, context=context)
    related = search(intent or command, limit=3)
    related_commands = [item.command for item in related]
    intent_alignment, alignment_reasons = warn_for_intent_mismatch(
        command,
        intent,
        related,
    )
    decision = risk.decision
    review_risk = risk.risk
    reasons = list(risk.reasons)

    if intent_alignment == "mismatch":
        reasons.extend(alignment_reasons)
        if decision in {"allow", "ask"}:
            decision = "warn"
            review_risk = "medium"

    return CommandReview(
        intent=intent,
        command=command,
        decision=decision,
        risk=review_risk,
        reasons=reasons,
        safer_next_step=risk.safer_next_step,
        related_commands=related_commands,
        intent_alignment=intent_alignment,
        context=context,
    )
