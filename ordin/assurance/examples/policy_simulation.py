"""Offline policy-change example. No fixture commands are executed."""

import json

from ordin import ActionEnvelope, Ordin, ReviewPolicy
from ordin.assurance import FrozenCase, FrozenCorpus, SimulationPolicy, simulate_policy_change


def main() -> None:
    corpus = FrozenCorpus.synthetic(
        (
            FrozenCase(
                "unknown-tool",
                ActionEnvelope(
                    "mcp", "call", {"server": "fixture", "tool": "unknown", "arguments": {}}
                ),
                expected="escalate",
                label="adversarial",
                critical=True,
            ),
        )
    )
    report = simulate_policy_change(
        SimulationPolicy(),
        SimulationPolicy(Ordin(policy=ReviewPolicy("block"))),
        corpus,
        baseline_revision="fixture-v1",
        candidate_revision="fixture-v2",
    )
    assert report.newly_executable == ("unknown-tool",)
    assert not report.activation_safe
    print(
        json.dumps(
            {
                "newly_executable": report.newly_executable,
                "activation_safe": report.activation_safe,
                "authority_delta": report.policy_authority_delta,
                "coverage": report.coverage,
            }
        )
    )


if __name__ == "__main__":
    main()
