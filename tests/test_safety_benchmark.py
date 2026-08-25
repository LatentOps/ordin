from pathlib import Path

import pytest

from ordin.safety_benchmark import (
    DEFAULT_FUZZ_SEED,
    SafetyFixture,
    SafetyThresholds,
    adversarial_equivalence_errors,
    evaluate_safety,
    generate_adversarial_equivalence_cases,
    load_safety_fixtures,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "benchmarks" / "safety.jsonl"


def test_repository_safety_fixtures_have_zero_false_allows_and_critical_misses():
    report = evaluate_safety(load_safety_fixtures(FIXTURES))

    assert report.case_count >= 16
    assert report.false_allows == 0
    assert report.critical_misses == 0
    assert report.false_blocks == 0
    assert report.regression_errors(SafetyThresholds()) == []
    assert report.percentile_ms(0.50) >= 0
    assert report.percentile_ms(0.95) >= report.percentile_ms(0.50)
    assert report.percentile_ms(0.99) >= report.percentile_ms(0.95)


def test_trajectory_cases_are_explicitly_measured():
    report = evaluate_safety(load_safety_fixtures(FIXTURES))

    assert len(report.trajectory_cases) >= 3
    assert report.trajectory_detection_rate == 1.0


def test_fuzz_generation_is_deterministic_for_recorded_seed():
    first = generate_adversarial_equivalence_cases(seed=DEFAULT_FUZZ_SEED)
    second = generate_adversarial_equivalence_cases(seed=DEFAULT_FUZZ_SEED)

    assert first == second
    assert first
    assert all(case.variants for case in first)


def test_adversarial_dangerous_forms_do_not_weaken_decisions():
    assert adversarial_equivalence_errors(seed=DEFAULT_FUZZ_SEED) == []


def test_fixture_loader_rejects_duplicate_ids(tmp_path):
    path = tmp_path / "fixtures.jsonl"
    path.write_text(
        '{"id":"same","type":"shell","command":"git status","expected":"allow"}\n'
        '{"id":"same","type":"shell","command":"git status","expected":"allow"}\n',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="duplicate safety fixture id"):
        load_safety_fixtures(path)


def test_fixture_validation_is_fail_closed():
    with pytest.raises(ValueError, match="requires runtime"):
        SafetyFixture.from_dict(
            {
                "id": "bad-tool",
                "type": "tool",
                "tool": "read",
                "expected": "ask",
            }
        )

    with pytest.raises(ValueError, match="expected decision"):
        SafetyFixture.from_dict(
            {
                "id": "bad-decision",
                "type": "shell",
                "command": "git status",
                "expected": 1,
            }
        )


def test_report_exposes_machine_readable_metrics():
    report = evaluate_safety(
        [
            SafetyFixture(
                id="safe",
                type="shell",
                command="git status --short",
                expected="allow",
            ),
            SafetyFixture(
                id="unknown",
                type="tool",
                runtime="agent",
                tool="unknown",
                expected="ask",
            ),
        ]
    )

    payload = report.as_dict()
    assert payload["cases"] == 2
    assert payload["false_allows"] == 0
    assert payload["critical_misses"] == 0
    assert payload["false_blocks"] == 0
    assert payload["asks"] == 1
    assert set(payload["latency_ms"]) == {"p50", "p95", "p99"}
