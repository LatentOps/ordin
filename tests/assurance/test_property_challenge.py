"""Actual generative APIs, seeded defects, strict commitments and missing coverage."""

from dataclasses import replace

import pytest

from ordin.assurance import (
    ChallengeRun,
    ChallengeSuite,
    challenge_property,
    challenge_security_properties,
    replay_counterexample,
)
from ordin.assurance._json import canonical_json, digest, loads
from ordin.assurance._property_challenges import SCENARIOS


@pytest.fixture(scope="module")
def actual_suite():
    return challenge_security_properties(seed=14, revision="fixture-v1", trials_per_property=32)


@pytest.fixture(scope="module")
def seeded_suite():
    return challenge_security_properties(
        seed=14, revision="fixture-v1", trials_per_property=32, variant="seeded_unsafe_checker"
    )


def test_actual_suite_accounts_for_all_required_properties_and_uncertainty(actual_suite):
    assert len(actual_suite.runs) == 10 and actual_suite.missing_properties == ()
    assert actual_suite.status == "inconclusive" and actual_suite.failures == 0
    assert actual_suite.unresolved_properties == (
        "authority_subset",
        "optional_failure_mode",
    )
    assert sum(v.generated for v in actual_suite.runs) == 320
    assert sum(v.evaluated for v in actual_suite.runs) == 276
    assert ChallengeSuite.from_json(canonical_json(actual_suite.as_dict())) == actual_suite
    for run in actual_suite.runs:
        assert ChallengeRun.from_json(canonical_json(run.as_dict())) == run
        if run.property_id not in actual_suite.unresolved_properties:
            assert run.status == "passed" and run.missing_scenarios == ()
            assert run.benign_controls > 0


def test_seeded_defects_shrink_replay_and_preserve_action_and_policy(seeded_suite):
    assert seeded_suite.status == "failing" and seeded_suite.failures > 0
    for run in seeded_suite.runs:
        if run.property_id == "optional_failure_mode":
            assert run.unresolved == 32 and run.failures == 0
            continue
        assert run.failures and run.benign_controls and run.counterexamples
        for record in run.counterexamples:
            assert (
                replay_counterexample(record, expected_revision="fixture-v1") == "verified_failure"
            )
            assert len(record.minimized_input) < len(record.initial_input)
            if run.property_id != "authority_subset":
                first, minimal = loads(record.initial_input), loads(record.minimized_input)
                assert first["action_digest"] == minimal["action_digest"]
                assert first["policy_digest"] == minimal["policy_digest"]
                for key in ("property_id", "scenario", "variant", "assumptions_digest"):
                    assert first["fixture"][key] == minimal["fixture"][key]


def test_protocol_compatibility_difference_is_recorded_without_changing_legacy(actual_suite):
    run = next(v for v in actual_suite.runs if v.property_id == "protocol_separation")
    row = next(v for v in run.samples if v["scenario"] == "tcp_to_rest")
    assert row["legacy_actual"] == "accepted" and row["actual"] == "rejected"
    assert row["comparison"] == "expected_policy_difference"


def test_missing_or_short_property_selection_cannot_report_complete():
    suite = challenge_security_properties(
        seed=14, revision="fixture-v1", trials_per_property=1, properties=("trust_origin",)
    )
    assert suite.status == "inconclusive" and len(suite.missing_properties) == 9
    assert suite.runs[0].status == "inconclusive" and len(suite.runs[0].missing_scenarios) == 9
    packet = suite.as_dict()
    packet["status"] = "passed"
    with pytest.raises(ValueError):
        ChallengeSuite.from_dict(packet)
    packet = suite.runs[0].as_dict()
    packet["missing_scenarios"] = []
    packet["status"] = "passed"
    with pytest.raises(ValueError, match="samples"):
        ChallengeRun.from_dict(packet)


def test_replay_rejects_mutated_context_and_failure_claim(seeded_suite):
    run = next(v for v in seeded_suite.runs if v.property_id == "exact_request_commitment")
    record = run.counterexamples[0]
    assert (
        replay_counterexample(
            replace(record, candidate_result="rejected"), expected_revision="fixture-v1"
        )
        == "not_reproduced"
    )
    payload = loads(record.minimized_input)
    payload["policy_digest"] = "0" * 64
    text = canonical_json(payload)
    with pytest.raises(ValueError, match="binding differs"):
        replay_counterexample(
            replace(
                record, minimized_input=text, minimized_digest=digest("counterexample_input", text)
            ),
            expected_revision="fixture-v1",
        )
    payload = loads(record.minimized_input)
    payload["fixture"]["scenario"] = "graphql_same"
    text = canonical_json(payload)
    with pytest.raises(ValueError):
        replay_counterexample(
            replace(
                record, minimized_input=text, minimized_digest=digest("counterexample_input", text)
            ),
            expected_revision="fixture-v1",
        )


def test_fixture_suite_performs_no_subprocess_network_or_fixture_file_reads(monkeypatch):
    import builtins
    import socket
    import subprocess

    original_open = builtins.open

    def forbidden(*args, **kwargs):
        pytest.fail("property runner attempted external work")

    def scoped_open(file, *args, **kwargs):
        if str(file).startswith(("/fixture", "/other")):
            pytest.fail("property runner attempted a fixture filesystem operation")
        return original_open(file, *args, **kwargs)

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(builtins, "open", scoped_open)
    result = challenge_security_properties(seed=15, revision="fixture-v1", trials_per_property=32)
    assert result.failures == 0 and result.status == "inconclusive"


@pytest.mark.parametrize("property_id", [v for v in SCENARIOS if v != "optional_failure_mode"])
def test_generators_preserve_every_declared_scenario_and_seed_digest(property_id):
    first = challenge_property(
        property_id=property_id,
        seed=14,
        revision="fixture-v1",
        trials=max(16, len(SCENARIOS[property_id])),
    )
    second = challenge_property(
        property_id=property_id,
        seed=14,
        revision="fixture-v1",
        trials=max(16, len(SCENARIOS[property_id])),
    )
    assert (
        first.input_manifest_digest == second.input_manifest_digest
        and first.samples == second.samples
    )
    assert set(v["scenario"] for v in first.samples) == set(SCENARIOS[property_id])


def test_cli_property_selection_and_general_counterexample_replay(tmp_path, capsys, seeded_suite):
    import json
    from ordin.assurance.cli import main

    assert (
        main(
            [
                "challenge",
                "run",
                "--seed",
                "14",
                "--revision",
                "fixture-v1",
                "--trials",
                "32",
                "--property",
                "tool_identity",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["failures"] == 0
    record = next(v for v in seeded_suite.runs if v.property_id == "tool_identity").counterexamples[
        0
    ]
    path = tmp_path / "record.json"
    path.write_text(json.dumps(record.as_dict()), encoding="utf-8")
    assert main(["challenge", "replay", str(path), "--revision", "fixture-v1"]) == 0
    assert json.loads(capsys.readouterr().out)["replay_outcome"] == "verified_failure"


def test_suite_time_budget_never_turns_skipped_work_into_success():
    suite = challenge_security_properties(seed=14, revision="fixture-v1", time_budget_ms=0.000001)
    assert suite.status == "inconclusive" and suite.failures == 0
    assert all(v.status == "inconclusive" for v in suite.runs)
    assert all(v.generated == 0 for v in suite.runs)
