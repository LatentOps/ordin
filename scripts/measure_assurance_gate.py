"""Measure matched core/profile gate timings on predeclared synthetic controls.

Uses fixed synthetic actions, an approved fixture profile and a synthetic host
channel. No reviewed action is executed. This is not production effectiveness.
"""

import argparse
import hashlib
import json
import platform
import time
from pathlib import Path

from ordin import ActionEnvelope, AgentGate
from ordin._runtime_json import digest as core_digest
from ordin.assurance import (
    AssuranceGate,
    HostEvidenceSource,
    InvariantSelectors,
    ProtectedAsset,
    ProtectedProfileSelection,
    RepositoryScope,
    SecurityInvariant,
    SecurityProfile,
    load_approved_profile,
)
from ordin.runtime_boundary import RuntimeCapabilityBoundary
from ordin.runtime_contract import FilesystemCapability
from ordin.runtime_observation import RuntimeEvidenceSource


def percentiles(samples):
    ordered = sorted(samples)

    def value(quantile):
        return ordered[round((len(ordered) - 1) * quantile)]

    return {
        "p50_ms": value(0.50),
        "p95_ms": value(0.95),
        "p99_ms": value(0.99),
        "samples": len(samples),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=100)
    parser.add_argument("--revision", required=True)
    args = parser.parse_args()
    if not 20 <= args.samples <= 1000:
        raise ValueError("bounded sample count required")
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    repository = RepositoryScope("fixture/benchmark", "fixture-v1")
    profile = SecurityProfile(
        "benchmark",
        "1",
        repository,
        (ProtectedAsset("policy", "policy", "/fixture/.github/workflows/deploy.yml"),),
        invariants=(
            SecurityInvariant(
                "policy-write",
                "protected_policy_mutation",
                InvariantSelectors(resource_ref="policy"),
            ),
        ),
    )
    path = args.output / "profile.json"
    path.write_text(json.dumps(profile.as_dict()), encoding="utf-8")
    path.chmod(0o600)
    policy_digest = "a" * 64
    selection = ProtectedProfileSelection(
        args.output.resolve(),
        "profile.json",
        "/operator/profile.json",
        repository,
        profile.digest,
        hashlib.sha256(path.read_bytes()).hexdigest(),
        "1",
        "synthetic-operator",
        RuntimeCapabilityBoundary(
            "agent",
            filesystem=(FilesystemCapability("write", "/fixture", "prefix"),),
            filesystem_semantics="lexical_prefix",
            runtime_filesystem_guarantees=True,
        ),
        RuntimeEvidenceSource("fixture", "b" * 64, "sandbox", policy_digest),
    )
    approved = load_approved_profile(
        selection, current_repository=repository, active_runtime_policy_digest=policy_digest
    )
    host = HostEvidenceSource(
        "agent", repository, "b" * 64, 1, policy_digest, selection.digest
    ).context()
    baseline = AgentGate()
    gate = AssuranceGate(baseline, approved)
    disabled = AssuranceGate(baseline)
    cases = [
        ActionEnvelope.shell("git status --short"),
        ActionEnvelope.shell("git log -1 --oneline"),
        ActionEnvelope.shell("rm -rf /"),
        ActionEnvelope("file", "write", {"path": "/fixture/file"}),
    ]
    for _ in range(10):
        for action in cases:
            baseline.evaluate_action(action)
            gate.evaluate_action(action, host_context=host)
            disabled.evaluate_action(action)
    core, assured, unused, overhead = [], [], [], []
    mismatches = []
    for repetition in range(args.samples):
        for index, action in enumerate(cases):
            # Alternate timing order to reduce simple cache/order bias.
            entries = [
                ("core", lambda: baseline.evaluate_action(action)),
                ("assured", lambda: gate.evaluate_action(action, host_context=host)),
                ("disabled", lambda: disabled.evaluate_action(action)),
            ]
            if repetition % 2:
                entries.reverse()
            timings = {}
            outcomes = {}
            for label, call in entries:
                start = time.perf_counter_ns()
                outcome = call()
                timings[label] = (time.perf_counter_ns() - start) / 1_000_000
                outcomes[label] = outcome.disposition
            core.append(timings["core"])
            assured.append(timings["assured"])
            unused.append(timings["disabled"])
            overhead.append(max(0, timings["assured"] - timings["core"]))
            if (
                outcomes["core"] != outcomes["disabled"]
                or {"execute": 0, "escalate": 1, "deny": 2}[outcomes["assured"]]
                < {"execute": 0, "escalate": 1, "deny": 2}[outcomes["core"]]
            ):
                mismatches.append({"case": index, "outcomes": outcomes})
    report = {
        "schema_version": "ordin.assurance_gate_measurement.v1",
        "revision": args.revision,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "warmup_rounds": 10,
        "repetitions": args.samples,
        "case_count": len(cases),
        "core": percentiles(core),
        "with_profile": percentiles(assured),
        "disabled_wrapper": percentiles(unused),
        "added_profile_overhead": percentiles(overhead),
        "declared_p95_overhead_budget_ms": 5,
        "mismatches": mismatches,
        "limitations": [
            "Synthetic fixture measurements, not real-world security effectiveness.",
            "Host contention influences tail latency; no scanner/model/enforcement timing included.",
            "Counterexample/delegation/provider and complete release gates remain separate.",
        ],
    }
    # Measure the additional layer directly as well. This uses authentic frozen
    # core outcomes and clearly does not replace the end-to-end paired result.
    # It distinguishes JSON/check overhead from noisy repeated core I/O.
    reviewed = {core_digest(action.as_dict()): baseline.evaluate_action(action) for action in cases}

    class ReviewedFixtureGate(AgentGate):
        def evaluate_action(self, action, **kwargs):
            return reviewed[core_digest(action.as_dict())]

    fixture_gate = AssuranceGate(ReviewedFixtureGate(baseline.ordin), approved)
    intrinsic = []
    for _ in range(args.samples):
        for action in cases:
            start = time.perf_counter_ns()
            fixture_gate.evaluate_action(action, host_context=host)
            intrinsic.append((time.perf_counter_ns() - start) / 1_000_000)
    report["intrinsic_profile_layer"] = percentiles(intrinsic)
    report["intrinsic_layer_meets_budget"] = report["intrinsic_profile_layer"]["p95_ms"] <= 5
    report["ok"] = not mismatches and report["added_profile_overhead"]["p95_ms"] <= 5
    (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
