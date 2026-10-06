"""Measure review, additive contract derivation, and boundary checks without execution."""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
from pathlib import Path
from time import perf_counter_ns

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ordin import (
    ActionEnvelope,
    Ordin,
    RuntimeCapabilityBoundary,
    derive_runtime_capability_contract,
    verify_runtime_capability,
)
from ordin.runtime_contract import FilesystemCapability
from ordin.runtime_requirements import RuntimeRequirementProfile


def percentile(values, fraction):
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def run(repetitions=30):
    if type(repetitions) is not int or repetitions < 3:
        raise ValueError("benchmark needs at least three repetitions")
    engine = Ordin()
    profile = RuntimeRequirementProfile(
        "benchmark-toolchain",
        filesystem=(
            FilesystemCapability("read", "/usr", "prefix"),
            FilesystemCapability("execute", "/usr", "prefix"),
        ),
        executable_bindings={"git": "/usr/bin/git", "curl": "/usr/bin/curl", "rm": "/usr/bin/rm"},
        spawn_children=True,
    )
    workload = (
        "git status --short",
        "curl --disable --request GET https://api.github.com/rate_limit",
        "rm /repo/scratch.txt",
        "mystery-command",
    )
    actions = tuple(
        ActionEnvelope.shell(command, action_id="benchmark-" + str(index))
        for index, command in enumerate(workload)
    )
    prepared = []
    for action in actions:
        review = profile.declare(engine.review_action(action))
        contract = derive_runtime_capability_contract(review)
        boundary = RuntimeCapabilityBoundary(
            "benchmark",
            filesystem=contract.filesystem,
            network=contract.network,
            tools=contract.tools,
            process=contract.process,
            privilege=contract.privilege,
            credentials=contract.credentials,
            filesystem_semantics="lexical_prefix",
            runtime_filesystem_guarantees=True,
        )
        prepared.append((action, contract, boundary))
    samples = {name: [] for name in ("review_only", "review_and_contract", "boundary_verification")}
    outcomes = {
        name: 0 for name in ("within_boundary", "exceeds_boundary", "unsupported", "inconclusive")
    }
    for _ in range(3):
        for action, contract, boundary in prepared:
            profile.declare(engine.review_action(action))
            derive_runtime_capability_contract(profile.declare(engine.review_action(action)))
            verify_runtime_capability(contract, boundary)
    for _ in range(repetitions):
        for action, contract, boundary in prepared:
            begin = perf_counter_ns()
            profile.declare(engine.review_action(action))
            samples["review_only"].append((perf_counter_ns() - begin) / 1_000_000)
            begin = perf_counter_ns()
            derive_runtime_capability_contract(profile.declare(engine.review_action(action)))
            samples["review_and_contract"].append((perf_counter_ns() - begin) / 1_000_000)
            begin = perf_counter_ns()
            result = verify_runtime_capability(contract, boundary)
            samples["boundary_verification"].append((perf_counter_ns() - begin) / 1_000_000)
            outcomes[result.result] += 1
    summary = {
        name: {
            "samples": len(values),
            "median_ms": statistics.median(values),
            "p95_ms": percentile(values, 0.95),
            "p99_ms": percentile(values, 0.99),
        }
        for name, values in samples.items()
    }
    return {
        "schema_version": "ordin.runtime_capability_benchmark.v1",
        "workload": list(workload),
        "repetitions": repetitions,
        "warmup_per_workload": 3,
        "environment": {"python": platform.python_version(), "platform": platform.platform()},
        "latency": summary,
        "boundary_outcomes": outcomes,
        "scope": "Local review/declared context, contract derivation and intended-boundary checking. No action execution, network requests, or backend enforcement included.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repetitions", type=int, default=30)
    parser.add_argument("--json-out")
    args = parser.parse_args()
    report = run(args.repetitions)
    text = json.dumps(report, indent=2)
    if args.json_out:
        Path(args.json_out).write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
