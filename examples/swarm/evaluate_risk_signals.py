"""Explicit synthetic local calibration, separate from deterministic authorization tests."""

import argparse
import json
from pathlib import Path
import platform

from ordin import ActionEnvelope
from ordin.swarm import InMemoryAgentRegistry
from ordin.swarm.risk_signals import (
    SwarmRiskBudget,
    SwarmRiskCalibrationCase,
    SwarmRiskInput,
    SwarmRiskScorer,
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    payload = options.corpus.read_bytes()
    if len(payload) > 65536:
        raise ValueError("explicit synthetic calibration corpus exceeds 64 KiB")
    corpus = json.loads(payload)
    if (
        type(corpus) is not dict
        or set(corpus) != {"schema_version", "cases"}
        or corpus["schema_version"] != "ordin.swarm_risk_corpus.v1"
        or type(corpus["cases"]) is not list
    ):
        raise ValueError("closed synthetic calibration corpus required")
    cases = []
    for row in corpus["cases"]:
        if type(row) is not dict or set(row) != {"case_id", "kind", "text", "expected_class"}:
            raise ValueError("closed synthetic calibration case required")
        cases.append(
            SwarmRiskCalibrationCase(
                row["case_id"], (SwarmRiskInput(row["kind"], row["text"]),), row["expected_class"]
            )
        )
    registry = InMemoryAgentRegistry("risk-calibration", "synthetic")
    adapter = object()
    channel = registry.bind_channel(adapter, runtime_id="synthetic-evaluator")
    context = registry.enroll(channel, adapter, agent_id="synthetic", session_id="calibration")
    scorer = SwarmRiskScorer(enabled=True, operator=object())
    report = scorer.calibrate(
        tuple(cases),
        budget=SwarmRiskBudget(1000),
        context=context,
        action=ActionEnvelope.shell("git status"),
    )
    artifact = {
        "report": report.as_dict(),
        "provider_id": scorer.status()["provider_id"],
        "python": platform.python_version(),
        "platform": platform.system(),
        "authorization_suite_included": False,
        "promotion_configured": False,
    }
    options.output.write_text(
        json.dumps(artifact, indent=2, allow_nan=False) + "\n", encoding="utf-8"
    )
    print(json.dumps(artifact, allow_nan=False))


if __name__ == "__main__":
    main()
