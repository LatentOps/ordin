from __future__ import annotations

from dataclasses import dataclass

from .context import ExecutionContext
from .risk import RISK_ORDER, RiskReview, check_command
from .semantics import semantic_evidence_for_command
from .temporal import default_temporal_policy, temporal_evidence_for_command
from .trace import ActionTrace


@dataclass(frozen=True)
class ObservedAction:
    """Compatibility view of locally re-evaluated command semantics."""

    command: str
    effects: frozenset[str]
    categories: frozenset[str]
    risk: str


@dataclass(frozen=True)
class TrajectoryFinding:
    risk: str
    category: str
    reason: str
    safer_next_step: str | None = None


@dataclass(frozen=True)
class TrajectoryEvaluation:
    trace_length: int
    findings: tuple[TrajectoryFinding, ...]

    @property
    def risk(self) -> str | None:
        if not self.findings:
            return None
        return max(
            (finding.risk for finding in self.findings),
            key=lambda value: RISK_ORDER[value],
        )

    @property
    def categories(self) -> list[str]:
        return sorted({finding.category for finding in self.findings})


def observe_action(
    command: str,
    *,
    context: ExecutionContext | None = None,
    review: RiskReview | None = None,
) -> ObservedAction:
    risk_review = review or check_command(command, context=context)
    semantics = semantic_evidence_for_command(command, context=context)
    return ObservedAction(
        command=command,
        effects=frozenset(semantics.effects),
        categories=frozenset(risk_review.risk_categories or []),
        risk=risk_review.risk,
    )


def evaluate_trajectory(
    trace: ActionTrace | None,
    current_command: str,
    *,
    context: ExecutionContext | None = None,
    current_review: RiskReview | None = None,
) -> TrajectoryEvaluation:
    """Compatibility adapter over the generic bounded temporal policy engine."""

    if trace is None or not trace.actions:
        return TrajectoryEvaluation(trace_length=0, findings=())

    prior = tuple(
        temporal_evidence_for_command(action.command, context=context)
        for action in trace.actions
    )
    current = temporal_evidence_for_command(
        current_command,
        context=context,
        review=current_review,
    )
    evaluation = default_temporal_policy().evaluate(prior, current)
    return TrajectoryEvaluation(
        trace_length=len(trace.actions),
        findings=tuple(
            TrajectoryFinding(
                risk=match.risk,
                category=match.category,
                reason=match.reason,
                safer_next_step=match.safer_next_step,
            )
            for match in evaluation.matches
        ),
    )
