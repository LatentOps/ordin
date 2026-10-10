"""Real-provider API recipes with explicit opt-in and externally supplied scope."""

from __future__ import annotations

from .protocol import SanitizedDecisionState, SecurityQuestionSet


def local_prediction_example(
    *,
    enabled=False,
    runtime=None,
    checkpoint=None,
    scope=None,
    state: SanitizedDecisionState | None = None,
    questions: SecurityQuestionSet | None = None,
    deadline_ms=250,
):
    """The caller obtains actual broker approval before setting enabled=True."""
    if enabled is not True:
        return {"skipped": True, "reason": "local inference requires explicit setup opt-in"}
    if state is None or questions is None:
        raise ValueError("local example requires exact protected sanitized state/questions")
    from .laya import LayaDecisionModel

    with LayaDecisionModel(runtime, checkpoint) as provider:
        provider.initialize(scope)
        result = provider.evaluate(state, questions, deadline_ms=deadline_ms)
        return {
            "skipped": False,
            "evidence": result.as_dict(),
            "metrics": provider.public_metrics(),
            "limitation": "One prediction is not a security effectiveness or calibration evaluation.",
        }


async def hosted_prediction_example(
    *, enabled=False, provider=None, state=None, questions=None, deadline_ms=250
):
    """An actual discovered/pinned/consented TypeSafe provider is host supplied."""
    if enabled is not True:
        return {"skipped": True, "reason": "hosted inference requires explicit disclosure opt-in"}
    from .typesafe import TypeSafeDecisionModel

    if not isinstance(provider, TypeSafeDecisionModel) or state is None or questions is None:
        raise ValueError("hosted example needs actual selected provider and protected inputs")
    result = await provider.evaluate_async(state, questions, deadline_ms=deadline_ms)
    return {
        "skipped": False,
        "evidence": result.as_dict(),
        "metrics": provider.metrics,
        "limitation": "One prediction is not a security effectiveness or calibration evaluation.",
    }
