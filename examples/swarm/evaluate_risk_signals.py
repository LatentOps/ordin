"""Explicit synthetic local calibration, separate from deterministic authorization tests."""

import argparse
import hashlib
import json
from pathlib import Path
import platform
from time import perf_counter_ns
import ordin.swarm.risk_signals as risk_module

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
    with options.corpus.open("rb") as stream:
        payload = stream.read(65537)
    if len(payload) > 65536:
        raise ValueError("explicit synthetic calibration corpus exceeds 64 KiB")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate calibration corpus field")
            result[key] = value
        return result

    def reject_constant(value):
        raise ValueError("nonfinite calibration corpus field")

    corpus = json.loads(payload, object_pairs_hook=unique, parse_constant=reject_constant)
    if (
        type(corpus) is not dict
        or set(corpus) != {"schema_version", "cases"}
        or corpus["schema_version"] != "ordin.swarm_risk_corpus.v1"
        or type(corpus["cases"]) is not list
        or not 12 <= len(corpus["cases"]) <= 256
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
    start = perf_counter_ns()
    report = scorer.calibrate(
        tuple(cases),
        budget=SwarmRiskBudget(1000),
        context=context,
        action=ActionEnvelope.shell("git status"),
    )
    wall_ms = (perf_counter_ns() - start) / 1000000
    artifact = {
        "report": report.as_dict(),
        "provider_id": scorer.status()["provider_id"],
        "python": platform.python_version(),
        "platform": platform.system(),
        "authorization_suite_included": False,
        "promotion_configured": False,
        "performance": {
            "calibration_method_wall_ms": wall_ms,
            "per_case_method_wall_ms": wall_ms / len(cases),
            "scope": "validation_capture_worker_scheduling_and_reporting",
            "file_read_provider_setup_and_network_included": False,
            "active_workers_after": scorer.status()["active_workers"],
            "reserved_cost_micros": scorer.status()["reserved_cost_micros"],
            "physical_provider_billing_enforced": False,
        },
        "provenance": {
            "provider_scope": "packaged_local_rules_only",
            "source_module": risk_module.__name__,
            "source_file_sha256": hashlib.sha256(
                Path(risk_module.__file__).read_bytes()
            ).hexdigest(),
            "explicit_synthetic_corpus_file_sha256": hashlib.sha256(payload).hexdigest(),
            "runtime_dataset_digest": "private_scorer_hmac",
            "calibration_relationship": "caller_declared_synthetic_held_out_cases_not_training_attestation",
            "binary_score_rule": "confidence_for_positive_class_else_one_minus_confidence",
            "external_models_or_provider_billing": "not_exercised",
        },
    }
    options.output.write_text(
        json.dumps(artifact, indent=2, allow_nan=False) + "\n", encoding="utf-8"
    )
    print(json.dumps(artifact, allow_nan=False))


if __name__ == "__main__":
    main()
