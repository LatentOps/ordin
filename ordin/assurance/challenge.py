"""Deterministic finite challengers. Inputs are data; no target code is executed."""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from time import perf_counter
from typing import Mapping

from ordin.runtime_boundary import RuntimeCapabilityBoundary, verify_runtime_capability
from ordin.runtime_contract import FilesystemCapability, RuntimeCapabilityContract

from ._json import canonical_json, digest, loads, validate
from ._environment import environment_label
from .models import CounterexampleRecord, JsonRecord

GENERATOR_VERSION = "authority-paths-v1"
INPUT_VERSION = "ordin.assurance_challenge_input.v1"
PROPERTY = "authority_subset"
MAX_TRIALS = 256


def _input(path: str, variant: str) -> dict:
    return {
        "schema_version": INPUT_VERSION,
        "property_id": PROPERTY,
        "generator_version": GENERATOR_VERSION,
        "boundary_path": "/fixture",
        "boundary_access": "read",
        "boundary_scope": "prefix",
        "filesystem_semantics": "lexical_prefix",
        "runtime_filesystem_guarantees": True,
        "request_path": path,
        "request_access": "read",
        "request_scope": "exact",
        "variant": variant,
    }


def _outcome(packet: Mapping) -> tuple[str, str, str]:
    required = set(_input("/fixture/file", "actual"))
    if not isinstance(packet, Mapping) or set(packet) != required:
        raise ValueError("challenge input differs from the declared finite property")
    path, variant = packet["request_path"], packet["variant"]
    if (
        not isinstance(path, str)
        or not isinstance(variant, str)
        or variant not in {"actual", "seeded_prefix_bug"}
        or len(path) > 256
        or not path.startswith("/")
    ):
        raise ValueError("unsupported finite challenge input")
    if packet != _input(path, variant):
        raise ValueError("challenge input differs from the declared finite property")
    # The oracle's preconditions are explicit; ambiguous/encoded paths do not
    # become counterexamples in an abstraction that does not model them.
    parts = path.split("/")[1:]
    if not parts or any(
        not part
        or part in {".", ".."}
        or not all(c.isascii() and (c.isalnum() or c in "-_") for c in part)
        for part in parts
    ):
        return "unsupported", "unsupported", "precondition_not_met"
    boundary = RuntimeCapabilityBoundary(
        "finite-fixture",
        filesystem=(FilesystemCapability("read", "/fixture", "prefix"),),
        filesystem_semantics="lexical_prefix",
        runtime_filesystem_guarantees=True,
    )
    contract = RuntimeCapabilityContract(
        "finite-proposal",
        digest("finite_action", {"path": path}),
        "allow",
        "low",
        filesystem=(FilesystemCapability("read", path, "exact"),),
        source={
            "kind": "fixture",
            "operation": "read",
            "adapter": None,
            "effects": [],
            "provenance_digest": None,
        },
    )
    actual = verify_runtime_capability(contract, boundary).result
    # Independent, faithful oracle for this exact finite filesystem domain.
    expected = (
        "within_boundary"
        if path == "/fixture" or path.startswith("/fixture/")
        else "exceeds_boundary"
    )
    if variant == "seeded_prefix_bug":
        actual = "within_boundary" if path.startswith("/fixture") else "exceeds_boundary"
    return expected, actual, "evaluated"


def _same_failure(packet: dict, signature: tuple[str, str]) -> bool:
    expected, actual, status = _outcome(packet)
    return status == "evaluated" and (expected, actual) == signature and expected != actual


def _minimize(packet: dict, signature: tuple[str, str]) -> dict:
    """Bounded deletion shrinking; retain this property and this exact mismatch."""
    current = dict(packet)
    attempts = 0
    while attempts < 512:
        changed = False
        path = current["request_path"]
        for index in range(len(path) - 1, 0, -1):
            attempts += 1
            candidate = {**current, "request_path": path[:index] + path[index + 1 :]}
            if _same_failure(candidate, signature):
                current = candidate
                changed = True
                break
            if attempts >= 512:
                break
        if not changed:
            break
    return current


@dataclass(frozen=True)
class ChallengeRun(JsonRecord):
    SCHEMA = "assurance_challenge_run"
    MANY = {"counterexamples": CounterexampleRecord}
    seed: int
    revision: str
    variant: str
    generated: int
    evaluated: int
    unresolved: int
    failures: int
    benign_controls: int
    counterexamples: tuple[CounterexampleRecord, ...]
    input_manifest_digest: str
    elapsed_ms: float
    status: str
    requested_trials: int = 0
    property_id: str = PROPERTY
    generator_version: str = GENERATOR_VERSION
    host_boundary_exercised: bool = False
    limitations: tuple[str, ...] = (
        "Finite synthetic path/read rights only; no claim about symlinks, other domains, live enforcement or untested invariants.",
    )
    samples: tuple[Mapping, ...] = ()
    missing_scenarios: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        super().__post_init__()
        expected_status = (
            "failing"
            if self.failures
            else "inconclusive"
            if self.unresolved or self.missing_scenarios
            else "passed"
        )
        if (
            not 1 <= self.requested_trials <= MAX_TRIALS
            or self.evaluated + self.unresolved != self.requested_trials
            or not self.evaluated <= self.generated <= self.requested_trials
            or self.failures + self.benign_controls > self.evaluated
            or len(self.counterexamples) > self.failures
            or bool(self.failures) != bool(self.counterexamples)
            or self.status != expected_status
        ):
            raise ValueError("challenger summary must account for failures, coverage and limits")
        if self.generator_version == "security-properties-v1":
            from ._property_challenges import SCENARIOS

            expected_missing = tuple(
                v
                for v in SCENARIOS[self.property_id]
                if v not in {s["scenario"] for s in self.samples}
            )
            if (
                expected_missing != self.missing_scenarios
                or len({v["case_id"] for v in self.samples}) != self.generated
                or any(v["scenario"] not in SCENARIOS[self.property_id] for v in self.samples)
                or len(self.samples) != self.generated
                or sum(v["assessable"] for v in self.samples) != self.evaluated
                or sum(v["assessable"] and v["expected"] != v["actual"] for v in self.samples)
                != self.failures
            ):
                raise ValueError("property samples must agree with run counts")
        elif (
            self.property_id != PROPERTY
            or self.variant == "seeded_unsafe_checker"
            or self.samples
            or self.missing_scenarios
        ):
            raise ValueError("finite path generator cannot represent another property")


def replay_counterexample(record: CounterexampleRecord, *, expected_revision: str) -> str:
    """Recheck both captures; a forged status/digest cannot establish reproduction."""
    if not isinstance(record, CounterexampleRecord) or record.revision != expected_revision:
        raise ValueError("counterexample replay requires the exact pinned revision")
    if record.generator_version == "security-properties-v1":
        from .property_challenge import replay_property_counterexample

        return replay_property_counterexample(record, expected_revision=expected_revision)
    if (
        record.claimed_property != PROPERTY
        or record.generator_version != GENERATOR_VERSION
        or record.mutation != "filesystem_path_deletion_shrink"
    ):
        raise ValueError("unsupported counterexample property or generator")
    initial, minimized = loads(record.initial_input), loads(record.minimized_input)
    before = _outcome(initial)
    after = _outcome(minimized)
    if initial["variant"] != minimized["variant"] or len(record.minimized_input) > len(
        record.initial_input
    ):
        raise ValueError("counterexample shrink changed the property variant")
    if before[2] != "evaluated" or after[2] != "evaluated":
        return "inconclusive"
    if before[:2] != after[:2] or before[0] == before[1]:
        return "not_reproduced"
    if record.baseline_result != before[0] or record.candidate_result != before[1]:
        return "not_reproduced"
    return "verified_failure"


def challenge_authority_subset(
    *,
    seed: int,
    revision: str,
    trials: int = 64,
    variant: str = "actual",
    time_budget_ms: float = 10_000,
) -> ChallengeRun:
    """Compare core subset checking to a finite oracle; optionally seed a fixture bug.

    The fixture mutant is selected by a closed enum, never imported from a target
    checkout. Unsupported preconditions and timeouts are partial, not passes.
    """
    if (
        type(seed) is not int
        or not 0 <= seed < 2**63
        or type(trials) is not int
        or not 1 <= trials <= MAX_TRIALS
    ):
        raise ValueError("bounded nonnegative seed and trial count required")
    if (
        not isinstance(variant, str)
        or variant not in {"actual", "seeded_prefix_bug"}
        or isinstance(time_budget_ms, bool)
        or not isinstance(time_budget_ms, (int, float))
        or not math.isfinite(time_budget_ms)
        or not 0 < time_budget_ms <= 30_000
    ):
        raise ValueError("unsupported challenger or time budget")
    validate("assurance_authority_ref", {"authority_id": revision, "boundary_digest": "0" * 64})
    generator = random.Random(seed)
    started = perf_counter()
    variants = (
        "/fixture/{word}",
        "/fixture/{word}/leaf",
        "/fixture2/{word}/noise/leaf",
        "/fixture-{word}/noise/leaf",
        "/other/{word}",
        "/fixture/../outside",
        "/fixture//leaf",
        "/fixture/%2e%2e",
    )
    manifest: list[str] = []
    records: list[CounterexampleRecord] = []
    signatures: set[tuple[str, str, str]] = set()
    evaluated = failures = unresolved = controls = 0
    for index in range(trials):
        if (perf_counter() - started) * 1000 >= time_budget_ms:
            unresolved += trials - index
            break
        word = f"case{generator.randrange(1000)}"
        packet = _input(variants[index % len(variants)].format(word=word), variant)
        manifest.append(digest("challenge_generated_input", packet))
        expected, actual, status = _outcome(packet)
        if status != "evaluated" or actual in {"unsupported", "inconclusive"}:
            unresolved += 1
            continue
        evaluated += 1
        if expected == actual:
            controls += expected == "within_boundary"
            continue
        failures += 1
        minimized = _minimize(packet, (expected, actual))
        signature = (expected, actual, minimized["request_path"])
        if signature in signatures:
            continue
        signatures.add(signature)
        initial_text, minimized_text = canonical_json(packet), canonical_json(minimized)
        record = CounterexampleRecord(
            "counterexample:" + digest("challenge_case", [seed, index, packet])[:24],
            PROPERTY,
            seed,
            GENERATOR_VERSION,
            "filesystem_path_deletion_shrink",
            initial_text,
            minimized_text,
            digest("counterexample_input", initial_text),
            digest("counterexample_input", minimized_text),
            expected,
            actual,
            "verified_failure",
            revision,
            environment_label(),
            proof_gaps=("Synthetic finite checker only; no host boundary was exercised.",),
        )
        if replay_counterexample(record, expected_revision=revision) != "verified_failure":
            raise ValueError("minimized counterexample lost its original property failure")
        records.append(record)
    elapsed = round((perf_counter() - started) * 1000, 6)
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
        digest("challenge_manifest", manifest),
        elapsed,
        "failing" if failures else "inconclusive" if unresolved else "passed",
        requested_trials=trials,
    )
