"""Real offline routing/refusal work, unavailable controls and exact replay."""

from dataclasses import replace
from pathlib import Path

import pytest

from ordin.assurance import (
    ChallengeRun,
    challenge_property,
    challenge_security_properties,
    replay_counterexample,
)
from ordin.assurance import _optional_challenges as optional
from ordin.assurance._json import canonical_json, digest, loads


@pytest.fixture
def sdk(monkeypatch):
    # This selects the project's optional SDK source, never a target provider.
    monkeypatch.syspath_prepend(
        str(Path(__file__).resolve().parents[2] / "integrations/decision_models")
    )
    import ordin_decision_models

    return ordin_decision_models


def run(**kwargs):
    return challenge_property(
        property_id=optional.PROPERTY, seed=14, revision="fixture-v1", trials=32, **kwargs
    )


def test_actual_optional_property_has_complete_failure_coverage_and_benign_controls(sdk):
    result = run()
    assert result.generator_version == optional.VERSION
    assert result.status == "passed" and result.failures == result.unresolved == 0
    assert result.generated == result.evaluated == 32 and result.benign_controls == 6
    assert result.missing_scenarios == () and not result.host_boundary_exercised
    assert {r["scenario"] for r in result.samples} == set(optional.SCENARIOS)
    assert ChallengeRun.from_json(canonical_json(result.as_dict())) == result


def test_seeded_unsafe_consumer_shrinks_replays_and_keeps_original_action_policy(sdk):
    result = run(variant="seeded_unsafe_checker")
    assert result.status == "failing" and result.failures == 24
    assert result.benign_controls == 6 and result.generated == result.evaluated == 32
    assert len(result.counterexamples) == 18
    for record in result.counterexamples:
        assert replay_counterexample(record, expected_revision="fixture-v1") == "verified_failure"
        original, minimal = loads(record.initial_input), loads(record.minimized_input)
        assert len(record.minimized_input) < len(record.initial_input)
        assert original["action_digest"] == minimal["action_digest"]
        assert original["policy_digest"] == minimal["policy_digest"]
        assert (
            original["fixture"]["generator_version"]
            == minimal["fixture"]["generator_version"]
            == optional.VERSION
        )


def test_missing_sdk_is_explicit_and_core_refusal_apis_still_run(monkeypatch):
    def absent(name):
        assert name == "ordin_decision_models"
        raise ModuleNotFoundError("owned unavailable fixture", name=name)

    monkeypatch.setattr(optional.importlib, "import_module", absent)
    result = run()
    assert result.status == "inconclusive" and result.failures == 0
    assert result.generated == 32 and result.evaluated == 4 and result.unresolved == 28
    assert result.missing_scenarios == ()
    assert all(
        row["reason_code"] == "assurance.challenge.optional_sdk_unavailable"
        for row in result.samples
        if not row["assessable"]
    )


def test_default_suite_uses_actual_optional_generator_and_legacy_remains_readable(sdk):
    current = challenge_security_properties(
        seed=14, revision="fixture-v1", properties=(optional.PROPERTY,), trials_per_property=32
    )
    assert current.runs[0].generator_version == optional.VERSION
    assert current.runs[0].status == "passed" and current.missing_properties
    assert current.status == "inconclusive"  # Other required properties were not selected.
    legacy = run(generator_version="security-properties-v1")
    assert legacy.generator_version == "security-properties-v1"
    assert legacy.evaluated == 0 and legacy.unresolved == legacy.generated == 32
    assert ChallengeRun.from_json(canonical_json(legacy.as_dict())) == legacy


def test_short_or_exhausted_run_never_claims_complete_optional_coverage(sdk):
    short = challenge_property(
        property_id=optional.PROPERTY, seed=14, revision="fixture-v1", trials=1
    )
    assert short.status == "inconclusive" and len(short.missing_scenarios) == 21
    timed = run(time_budget_ms=0.000001)
    assert timed.status == "inconclusive" and timed.generated == 0 and timed.unresolved == 32
    with pytest.raises(ValueError):
        ChallengeRun.from_dict({**timed.as_dict(), "status": "passed"})


@pytest.mark.parametrize(
    "field,value",
    [
        ("scenario", "benign_supported"),
        ("generator_version", "security-properties-v1"),
        ("variant", "actual"),
        ("assumptions_digest", "0" * 64),
    ],
)
def test_counterexample_cannot_change_property_assumptions_or_generation(sdk, field, value):
    record = run(variant="seeded_unsafe_checker").counterexamples[0]
    packet = loads(record.minimized_input)
    packet["fixture"][field] = value
    text = canonical_json(packet)
    with pytest.raises(ValueError):
        replay_counterexample(
            replace(
                record, minimized_input=text, minimized_digest=digest("counterexample_input", text)
            ),
            expected_revision="fixture-v1",
        )


def test_offline_failure_fixtures_never_launch_or_connect(sdk, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("closed challenge attempted process/network work")

    monkeypatch.setattr("subprocess.Popen", forbidden)
    monkeypatch.setattr("socket.create_connection", forbidden)
    monkeypatch.setattr("socket.getaddrinfo", forbidden)
    result = run()
    assert result.status == "passed" and result.failures == 0


def test_cli_defaults_to_current_generator_and_exposes_frozen_legacy(sdk, capsys):
    import json
    from ordin.assurance.cli import main

    args = [
        "challenge",
        "run",
        "--property",
        optional.PROPERTY,
        "--seed",
        "14",
        "--revision",
        "fixture-v1",
        "--trials",
        "32",
    ]
    assert main(args) == 0
    assert json.loads(capsys.readouterr().out)["generator_version"] == optional.VERSION
    assert main(args + ["--legacy-optional-failures"]) == 2
    assert json.loads(capsys.readouterr().out)["generator_version"] == "security-properties-v1"


@pytest.mark.parametrize("version", [False, "", "unknown", "authority-paths-v1"])
def test_unrecognized_generation_is_not_coerced_to_a_default(version):
    with pytest.raises(ValueError):
        run(generator_version=version)
