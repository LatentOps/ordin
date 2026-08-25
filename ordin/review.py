from __future__ import annotations

from dataclasses import dataclass

from . import REVIEW_SCHEMA_VERSION
from .context import ExecutionContext
from .policy import DECISION_ORDER, Decision, DecisionResultMixin
from .risk import check_command, decision_for_risk, max_risk
from .search import SearchResult, search
from .shell import executable_name
from .trace import ActionTrace
from .trajectory import evaluate_trajectory


@dataclass(frozen=True)
class CommandReview(DecisionResultMixin):
    intent: str | None
    command: str
    decision: Decision
    risk: str
    reasons: list[str]
    safer_next_step: str | None
    related_commands: list[str]
    intent_alignment: str
    context: ExecutionContext | None = None
    trace: ActionTrace | None = None
    trace_length: int = 0
    trajectory_categories: list[str] | None = None

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
            "trace": self.trace.as_dict() if self.trace else None,
            "trace_length": self.trace_length,
            "trajectory_categories": self.trajectory_categories or [],
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
        [(f'command "{executable}" is not one of the top command matches for intent "{intent}"')],
    )


def _stronger_decision(current: Decision, candidate: Decision) -> Decision:
    return candidate if DECISION_ORDER[candidate] > DECISION_ORDER[current] else current


def review_command(
    command: str,
    intent: str | None = None,
    context: ExecutionContext | None = None,
    trace: ActionTrace | None = None,
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
    safer_next_step = risk.safer_next_step

    trajectory = evaluate_trajectory(
        trace,
        command,
        context=context,
        current_review=risk,
    )
    if trajectory.risk is not None:
        prior_risk = review_risk
        review_risk = max_risk(review_risk, trajectory.risk)
        decision = _stronger_decision(
            decision,
            decision_for_risk(trajectory.risk),
        )
        for finding in trajectory.findings:
            if finding.reason not in reasons:
                reasons.append(finding.reason)
        if review_risk != prior_risk:
            first_step = next(
                (
                    finding.safer_next_step
                    for finding in trajectory.findings
                    if finding.safer_next_step
                ),
                None,
            )
            if first_step:
                safer_next_step = first_step

    if intent_alignment == "mismatch":
        reasons.extend(reason for reason in alignment_reasons if reason not in reasons)
        if decision in {"allow", "ask"}:
            decision = "warn"
            review_risk = max_risk(review_risk, "medium")

    return CommandReview(
        intent=intent,
        command=command,
        decision=decision,
        risk=review_risk,
        reasons=reasons,
        safer_next_step=safer_next_step,
        related_commands=related_commands,
        intent_alignment=intent_alignment,
        context=context,
        trace=trace,
        trace_length=trajectory.trace_length,
        trajectory_categories=trajectory.categories,
    )
