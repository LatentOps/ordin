"""Seeded multi-property discovery and concrete replay over fixed trusted fixtures."""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from time import perf_counter
from typing import Sequence

from ._environment import environment_label
from ._json import canonical_json, digest, loads, validate
from ._property_challenges import SCENARIOS, VERSION, fixture_packet, outcome
from .challenge import ChallengeRun, challenge_authority_subset
from .models import CounterexampleRecord, JsonRecord

REQUIRED_PROPERTIES = (
    "authority_subset",
    "monotonicity",
    "exact_request_commitment",
    "protocol_separation",
    "tool_identity",
    "history_observations",
    "delegation_subset",
    "trust_origin",
    "optional_failure_mode",
    "review_to_use_binding",
)


def _capture(packet, result):
    return {
        "fixture": packet,
        "action_digest": result.action_digest,
        "policy_digest": result.policy_digest,
    }


def _recheck(capture):
    if not isinstance(capture, dict) or set(capture) != {
        "fixture",
        "action_digest",
        "policy_digest",
    }:
        raise ValueError("invalid bounded property capture")
    checked = outcome(capture["fixture"])
    if (
        capture["action_digest"] != checked.action_digest
        or capture["policy_digest"] != checked.policy_digest
    ):
        raise ValueError("property action or policy binding differs")
    return checked


def replay_property_counterexample(record: CounterexampleRecord, *, expected_revision: str) -> str:
    if (
        not isinstance(record, CounterexampleRecord)
        or record.revision != expected_revision
        or record.generator_version != VERSION
        or record.mutation != "property_preserving_shrink"
    ):
        raise ValueError("property replay requires the exact revision and generator")
    initial, minimized = loads(record.initial_input), loads(record.minimized_input)
    before, after = _recheck(initial), _recheck(minimized)
    for key in ("property_id", "scenario", "variant", "assumptions_digest"):
        if initial["fixture"][key] != minimized["fixture"][key]:
            raise ValueError("shrink changed the declared property or assumptions")
    if (
        record.claimed_property != initial["fixture"]["property_id"]
        or before.action_digest != after.action_digest
        or before.policy_digest != after.policy_digest
        or len(record.minimized_input) > len(record.initial_input)
    ):
        raise ValueError("shrink changed the failing action or maximum")
    if not before.assessable or not after.assessable:
        return "inconclusive"
    if (
        (before.expected, before.actual) != (after.expected, after.actual)
        or before.expected == before.actual
        or record.baseline_result != before.expected
        or record.candidate_result != before.actual
    ):
        return "not_reproduced"
    return "verified_failure"


def _minimize(packet, checked):
    # The closed schema defines noise as decorative, and outcome() rejects any
    # other spelling/content. Concrete replay below still checks both captures.
    result = {k: v for k, v in packet.items() if k != "noise"}
    candidates = []
    if packet["value"] and packet["property_id"] in {"tool_identity", "monotonicity", "protocol_separation"}:
        candidates.append({**result, "value": 0})
    for candidate in candidates:
        new = outcome(candidate)
        if new.assessable and (new.expected, new.actual, new.action_digest, new.policy_digest) == (
            checked.expected,
            checked.actual,
            checked.action_digest,
            checked.policy_digest,
        ):
            result = candidate
    return result


def challenge_property(
    *,
    property_id: str,
    seed: int,
    revision: str,
    trials: int = 32,
    variant: str = "actual",
    time_budget_ms: float = 10_000,
) -> ChallengeRun:
    if (
        not isinstance(property_id, str)
        or property_id not in SCENARIOS
        or type(seed) is not int
        or not 0 <= seed < 2**63
        or type(trials) is not int
        or not 1 <= trials <= 256
        or not isinstance(variant, str)
        or variant not in {"actual", "seeded_unsafe_checker"}
    ):
        raise ValueError("bounded known property, seed, variant and trials required")
    if (
        isinstance(time_budget_ms, bool)
        or not isinstance(time_budget_ms, (float, int))
        or not math.isfinite(time_budget_ms)
        or not 0 < time_budget_ms <= 30_000
    ):
        raise ValueError("invalid property time budget")
    validate("assurance_authority_ref", {"authority_id": revision, "boundary_digest": "0" * 64})
    started = perf_counter()
    generator = random.Random(seed)
    scenarios = SCENARIOS[property_id]
    samples, manifest, records = [], [], []
    signatures = set()
    evaluated = failures = unresolved = controls = 0
    for index in range(trials):
        if (perf_counter() - started) * 1000 >= time_budget_ms:
            unresolved += trials - index
            break
        scenario = scenarios[index % len(scenarios)]
        packet = fixture_packet(property_id, scenario, generator.randrange(1000), variant)
        checked = outcome(packet)
        capture = _capture(packet, checked)
        input_digest = digest("property_generated_input", capture)
        manifest.append(input_digest)
        samples.append(
            {
                "case_id": f"{property_id}:{index}",
                "scenario": scenario,
                "input_digest": input_digest,
                "action_digest": checked.action_digest,
                "policy_digest": checked.policy_digest,
                "expected": checked.expected,
                "actual": checked.actual,
                "assessable": checked.assessable,
                "reason_code": checked.reason_code,
                "relation": checked.relation,
                "benign": checked.benign,
                "comparison": checked.comparison,
                "legacy_actual": checked.legacy_actual,
            }
        )
        if not checked.assessable:
            unresolved += 1
            continue
        evaluated += 1
        if checked.expected == checked.actual:
            controls += checked.benign
            continue
        failures += 1
        signature = (scenario, checked.expected, checked.actual)
        if signature in signatures:
            continue
        signatures.add(signature)
        minimized_packet = _minimize(packet, checked)
        minimized = _capture(minimized_packet, checked)
        initial_text, minimized_text = canonical_json(capture), canonical_json(minimized)
        record = CounterexampleRecord(
            "counterexample:" + digest("property_counterexample", [seed, index, capture])[:24],
            property_id,
            seed,
            VERSION,
            "property_preserving_shrink",
            initial_text,
            minimized_text,
            digest("counterexample_input", initial_text),
            digest("counterexample_input", minimized_text),
            checked.expected,
            checked.actual,
            "verified_failure",
            revision,
            environment_label(),
            proof_gaps=(
                "Closed synthetic property fixture only; no live host boundary was exercised.",
            ),
        )
        if replay_property_counterexample(record, expected_revision=revision) != "verified_failure":
            raise ValueError("property shrink lost the original reproduced failure")
        records.append(record)
    missing_scenarios = tuple(v for v in scenarios if v not in {s["scenario"] for s in samples})
    return ChallengeRun(
        seed,
        revision,
        variant,
        len(manifest),
        evaluated,
        unresolved,
        failures,
        controls,
        tuple(records),
        digest("property_manifest", manifest),
        round((perf_counter() - started) * 1000, 6),
        "failing" if failures else "inconclusive" if unresolved or missing_scenarios else "passed",
        requested_trials=trials,
        property_id=property_id,
        generator_version=VERSION,
        samples=tuple(samples),
        missing_scenarios=missing_scenarios,
        limitations=(
            "Fixed synthetic property fixtures; no network, target execution, host grant, or real runtime enforcement.",
        ),
    )


@dataclass(frozen=True)
class ChallengeSuite(JsonRecord):
    SCHEMA = "assurance_challenge_suite"
    MANY = {"runs": ChallengeRun}
    seed: int
    revision: str
    runs: tuple[ChallengeRun, ...]
    status: str
    elapsed_ms: float
    required_properties: tuple[str, ...] = REQUIRED_PROPERTIES
    missing_properties: tuple[str, ...] = ()
    unresolved_properties: tuple[str, ...] = ()
    failures: int = 0
    host_boundary_exercised: bool = False

    def __post_init__(self):
        super().__post_init__()
        properties = [v.property_id for v in self.runs]
        missing = tuple(p for p in self.required_properties if p not in properties)
        unresolved = tuple(v.property_id for v in self.runs if v.unresolved or v.missing_scenarios)
        failures = sum(v.failures for v in self.runs)
        expected = "failing" if failures else "inconclusive" if missing or unresolved else "passed"
        if (
            len(properties) != len(set(properties))
            or self.required_properties != REQUIRED_PROPERTIES
            or missing != self.missing_properties
            or unresolved != self.unresolved_properties
            or failures != self.failures
            or self.status != expected
            or any(v.seed != self.seed or v.revision != self.revision for v in self.runs)
        ):
            raise ValueError("property suite must retain required coverage and exact run identity")


def challenge_security_properties(
    *,
    seed: int,
    revision: str,
    trials_per_property: int = 32,
    variant: str = "actual",
    properties: Sequence[str] = REQUIRED_PROPERTIES,
    time_budget_ms: float = 30_000,
) -> ChallengeSuite:
    if (
        not isinstance(properties, (list, tuple))
        or len(properties) > 10
        or any(not isinstance(v, str) for v in properties)
        or len(set(properties)) != len(properties)
        or any(v not in REQUIRED_PROPERTIES for v in properties)
        or type(trials_per_property) is not int
        or not 1 <= trials_per_property <= 32
        or not isinstance(variant, str)
        or variant not in {"actual", "seeded_unsafe_checker"}
    ):
        raise ValueError("invalid bounded suite selection")
    if (
        isinstance(time_budget_ms, bool)
        or not isinstance(time_budget_ms, (int, float))
        or not math.isfinite(time_budget_ms)
        or not 0 < time_budget_ms <= 30_000
    ):
        raise ValueError("invalid suite budget")
    started = perf_counter()
    runs = []
    for prop in properties:
        remaining = max(0.000001, time_budget_ms - (perf_counter() - started) * 1000)
        if prop == "authority_subset":
            runs.append(
                challenge_authority_subset(
                    seed=seed,
                    revision=revision,
                    trials=trials_per_property,
                    variant="actual" if variant == "actual" else "seeded_prefix_bug",
                    time_budget_ms=remaining,
                )
            )
        else:
            runs.append(
                challenge_property(
                    property_id=prop,
                    seed=seed,
                    revision=revision,
                    trials=trials_per_property,
                    variant=variant,
                    time_budget_ms=remaining,
                )
            )
    missing = tuple(p for p in REQUIRED_PROPERTIES if p not in properties)
    unresolved = tuple(v.property_id for v in runs if v.unresolved or v.missing_scenarios)
    failures = sum(v.failures for v in runs)
    return ChallengeSuite(
        seed,
        revision,
        tuple(runs),
        "failing" if failures else "inconclusive" if missing or unresolved else "passed",
        round((perf_counter() - started) * 1000, 6),
        missing_properties=missing,
        unresolved_properties=unresolved,
        failures=failures,
    )
