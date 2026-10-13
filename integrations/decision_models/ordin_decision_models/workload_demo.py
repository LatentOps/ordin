"""Offline frozen-workload plumbing with predetermined mock outputs only."""

from __future__ import annotations

import argparse
import asyncio
import json
from dataclasses import replace
from pathlib import Path

from ordin.assurance import AssuranceGate, HostEvidenceSource, RepositoryScope
from ordin.assurance._json import thaw

from .evaluation import (
    collect_development,
    collect_development_async,
    evaluate_corpus,
    evaluate_corpus_async,
    fit_measured_threshold,
)
from .mock import MockDecisionModel
from .routing import RoutingPolicy, SemanticInspectionRouter
from .workloads import load_frozen_workload


def run_workload(root: Path, manifest_sha256: str, *, asynchronous=False):
    manifest, corpora = load_frozen_workload(root, expected_manifest_sha256=manifest_sha256)
    by_partition = {corpus.partition: corpus for corpus in corpora}
    development = by_partition["development"]
    gate = AssuranceGate()
    source = HostEvidenceSource(
        "semantic-synthetic-harness",
        RepositoryScope("fixture/semantic", "fixture-v1"),
        "a" * 64,
        1,
        "b" * 64,
        "c" * 64,
    )
    host = source.context()
    provider = MockDecisionModel()  # Fixed values; labels never select scores.
    policy = RoutingPolicy(mode="shadow")
    shadow = SemanticInspectionRouter(gate, policy=policy, provider=provider)
    if asynchronous:
        measurements = asyncio.run(collect_development_async(development, shadow, host))
    else:
        measurements = collect_development(development, shadow, host)
    threshold = fit_measured_threshold(development, measurements)
    reports = []
    for partition in ("held_out", "adversarial_shift"):
        for mode in ("disabled", "shadow", "enforced-escalation"):
            router = SemanticInspectionRouter(
                gate,
                policy=replace(policy, mode=mode, escalation_threshold=threshold.threshold),
                provider=provider,
            )
            kwargs = {"threshold": threshold, "development": development}
            if asynchronous:
                report = asyncio.run(
                    evaluate_corpus_async(by_partition[partition], router, host, **kwargs)
                )
            else:
                report = evaluate_corpus(by_partition[partition], router, host, **kwargs)
            reports.append({"mode": mode, "report": thaw(report)})
    return {
        "schema_version": "ordin.semantic_mock_workload_demo.v1",
        "manifest_sha256": manifest_sha256,
        "synthetic_only": True,
        "provisional": True,
        "actions_executed": False,
        "independent_adjudication": manifest["label_protocol"]["independent_adjudication"],
        "acceptance_eligible": False,
        "model_effectiveness_evaluated": False,
        "driver": "async" if asynchronous else "sync",
        "development_measurements": measurements.as_dict(),
        "frozen_threshold": threshold.as_dict(),
        "threshold_digest": threshold.digest,
        "provider_calls": provider.calls,
        "reports": reports,
        "limitations": [
            "Predetermined outputs verify measurement/routing plumbing only.",
            "Labels are provisional; this sample does not satisfy the full independent protection corpus.",
            "No actual provider/hardware/cost/effectiveness acceptance has been established.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workload", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--async", dest="asynchronous", action="store_true")
    args = parser.parse_args()
    result = run_workload(args.workload, args.manifest_sha256, asynchronous=args.asynchronous)
    with args.output.open("x", encoding="utf-8") as output:
        json.dump(result, output, indent=2, sort_keys=True)
        output.write("\n")
    print(
        json.dumps(
            {
                "provider": "mock",
                "driver": result["driver"],
                "provider_calls": result["provider_calls"],
                "actions_executed": False,
                "model_effectiveness_evaluated": False,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
