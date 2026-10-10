"""Seeded synthetic defect discovery, property-preserving shrink and replay."""

from dataclasses import replace

import pytest

from ordin.assurance._json import canonical_json, digest, loads
from ordin.assurance.challenge import (
    ChallengeRun,
    challenge_authority_subset,
    replay_counterexample,
)
from ordin.assurance.models import CounterexampleRecord


def run(**kwargs):
    return challenge_authority_subset(seed=14, revision="fixture-v1", trials=16, **kwargs)


def test_seeded_defect_is_found_minimized_and_replayed_with_benign_controls(monkeypatch):
    import socket
    import subprocess

    def forbidden(*args, **kwargs):
        pytest.fail("finite challenger attempted external execution or network")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    result = run(variant="seeded_prefix_bug")
    assert result.status == "failing" and result.failures == 4
    assert result.evaluated == 10 and result.unresolved == 6 and result.benign_controls == 4
    assert result.as_dict()["host_boundary_exercised"] is False
    assert len(result.counterexamples) == 2
    assert ChallengeRun.from_json(canonical_json(result.as_dict())) == result
    for record in result.counterexamples:
        assert len(record.minimized_input) < len(record.initial_input)
        assert (
            record.replay_outcome
            == replay_counterexample(record, expected_revision="fixture-v1")
            == "verified_failure"
        )
        assert CounterexampleRecord.from_json(canonical_json(record.as_dict())) == record
        original, minimized = loads(record.initial_input), loads(record.minimized_input)
        assert {k: v for k, v in original.items() if k != "request_path"} == {
            k: v for k, v in minimized.items() if k != "request_path"
        }
        assert minimized["request_path"] in {"/fixture2", "/fixture-"}


def test_actual_verifier_disagrees_with_no_supported_fixture_but_unknown_stays_partial():
    result = run()
    assert result.failures == 0 and result.counterexamples == ()
    assert result.unresolved == 6 and result.status == "inconclusive"
    assert result.generated == result.evaluated + result.unresolved == 16


def test_seed_and_generator_manifest_are_reproducible():
    first, second = run(variant="seeded_prefix_bug"), run(variant="seeded_prefix_bug")
    assert first.input_manifest_digest == second.input_manifest_digest
    assert first.counterexamples == second.counterexamples
    other = challenge_authority_subset(
        seed=15, revision="fixture-v1", trials=16, variant="seeded_prefix_bug"
    )
    assert other.input_manifest_digest != first.input_manifest_digest


def test_replay_requires_same_revision_and_does_not_trust_claimed_failure():
    record = run(variant="seeded_prefix_bug").counterexamples[0]
    with pytest.raises(ValueError, match="exact pinned revision"):
        replay_counterexample(record, expected_revision="fixture-v2")
    assert (
        replay_counterexample(
            replace(record, candidate_result="exceeds_boundary"), expected_revision="fixture-v1"
        )
        == "not_reproduced"
    )
    minimized = loads(record.minimized_input)
    minimized["request_path"] = "/fixture/safe"
    changed = canonical_json(minimized)
    forged = replace(
        record, minimized_input=changed, minimized_digest=digest("counterexample_input", changed)
    )
    assert replay_counterexample(forged, expected_revision="fixture-v1") == "not_reproduced"


def test_shrink_cannot_change_the_property_preconditions_or_variant():
    record = run(variant="seeded_prefix_bug").counterexamples[0]
    minimized = loads(record.minimized_input)
    minimized["request_access"] = "delete"
    changed = canonical_json(minimized)
    forged = replace(
        record, minimized_input=changed, minimized_digest=digest("counterexample_input", changed)
    )
    with pytest.raises(ValueError, match="declared finite property"):
        replay_counterexample(forged, expected_revision="fixture-v1")
    minimized = loads(record.minimized_input)
    minimized["variant"] = "actual"
    changed = canonical_json(minimized)
    forged = replace(
        record, minimized_input=changed, minimized_digest=digest("counterexample_input", changed)
    )
    with pytest.raises(ValueError, match="property variant"):
        replay_counterexample(forged, expected_revision="fixture-v1")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"seed": True},
        {"seed": -1},
        {"trials": 0},
        {"trials": 257},
        {"variant": "target_plugin"},
        {"time_budget_ms": float("nan")},
        {"time_budget_ms": True},
    ],
)
def test_hostile_configuration_is_refused(kwargs):
    parameters = {"seed": 14, "revision": "fixture-v1", "trials": 16, **kwargs}
    with pytest.raises(ValueError):
        challenge_authority_subset(**parameters)


def test_timeout_is_partial_not_a_security_pass():
    result = run(time_budget_ms=0.000001)
    assert result.status == "inconclusive" and result.unresolved == 16 and result.generated == 0


def test_serialized_run_cannot_promote_unknown_coverage_or_host_enforcement():
    packet = run().as_dict()
    packet["status"] = "passed"
    with pytest.raises(ValueError, match="summary must account"):
        ChallengeRun.from_dict(packet)
    packet = run().as_dict()
    packet["host_boundary_exercised"] = True
    with pytest.raises(ValueError):
        ChallengeRun.from_dict(packet)


def test_cli_seeded_run_and_pinned_replay(tmp_path, capsys):
    import json
    from ordin.assurance.cli import main

    assert (
        main(
            [
                "challenge",
                "run",
                "--seed",
                "14",
                "--trials",
                "16",
                "--revision",
                "fixture-v1",
                "--variant",
                "seeded_prefix_bug",
            ]
        )
        == 1
    )
    packet = json.loads(capsys.readouterr().out)
    assert packet["failures"] == 4 and packet["status"] == "failing"
    path = tmp_path / "counterexample.json"
    path.write_text(json.dumps(packet["counterexamples"][0]), encoding="utf-8")
    assert main(["challenge", "replay", str(path), "--revision", "fixture-v1"]) == 0
    assert json.loads(capsys.readouterr().out)["replay_outcome"] == "verified_failure"
    assert main(["challenge", "replay", str(path), "--revision", "fixture-v2"]) == 2
    assert json.loads(capsys.readouterr().err)["coverage"] == "unknown"
