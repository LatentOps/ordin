"""Synthetic offline model plumbing; predetermined predictions are not evals."""

from __future__ import annotations

from ordin import ActionEnvelope
from ordin.assurance import AssuranceGate, HostEvidenceSource, RepositoryScope
from ordin.assurance._json import canonical_json
from ordin.assurance.origins import register_instruction_origin, correlate_source_use

from . import (
    MockDecisionModel,
    RoutingPolicy,
    SelectedSnippet,
    SemanticInspectionRouter,
    request_semantic_inspection,
    sanitize_decision_state,
)


def main() -> int:
    gate = AssuranceGate()
    action = ActionEnvelope.shell("git status --short", action_id="synthetic-semantic-demo")
    source = HostEvidenceSource(
        "fixture", RepositoryScope("fixture/demo", "fixture-v1"), "a" * 64, 1, "b" * 64, "c" * 64
    )
    host = source.context()
    baseline = gate.evaluate_action(action, host_context=host)
    task = "Inspect synthetic repository status"
    command = "git status --short"
    origin = register_instruction_origin(
        source, origin_id="task", kind="authorized_user", classification="public", content=task
    )
    selected = register_instruction_origin(
        source,
        origin_id="snippet",
        kind="authorized_user",
        classification="public",
        content=command,
    )
    use = correlate_source_use(
        source, selected, action, use_id="selected-use", argument_path=("parameters", "command")
    )
    state = sanitize_decision_state(
        gate,
        baseline,
        host_context=host,
        task_origin=origin,
        task_text=task,
        snippets=(SelectedSnippet(selected, use, command),),
        inspection=request_semantic_inspection(
            source, action, reasons=("ambiguous_task_alignment",)
        ),
    )
    results = []
    for mode in ("disabled", "shadow", "enforced-escalation"):
        provider = MockDecisionModel({"material_intent_mismatch": 0.95})
        router = SemanticInspectionRouter(gate, policy=RoutingPolicy(mode=mode), provider=provider)
        result = router.evaluate_action(action, state=state, host_context=host)
        results.append(
            {
                "mode": mode,
                "provider_calls": provider.calls,
                "result": result.as_dict(),
                "binding_matches": router.binding_matches(
                    result, action, state=state, host_context=host
                ),
            }
        )
    print(
        canonical_json(
            {
                "synthetic_only": True,
                "model_effectiveness_evaluated": False,
                "actions_executed": False,
                "state": state.public_dict(),
                "results": results,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
