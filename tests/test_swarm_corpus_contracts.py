"""Strict report shapes, private output files, and predeclared benchmark limits."""

from copy import deepcopy
import json
import os

import pytest

from ordin.schema import validate_named_schema
from ordin.safety_benchmark import SafetyThresholds
from ordin.swarm.benchmark_cli import _write, main, render_markdown
from ordin.swarm.overhead_benchmark import measure
from tests.swarm_corpus_contract_samples import corpus_contract_samples


@pytest.fixture(scope="module")
def samples():
    return corpus_contract_samples()


def test_all_published_corpus_reports_validate_and_keep_no_authority(samples):
    for name, value in samples.items():
        assert not validate_named_schema(name, value)
    for name in ("swarm_corpus_report", "swarm_overhead_report"):
        value = samples[name]
        assert not value["execution_authority"]
        assert value["revision"] in render_markdown(value)
        assert "Limitations" in render_markdown(value)


@pytest.mark.parametrize("field,value", (("revision", "HEAD"), ("execution_authority", True)))
def test_report_contract_refuses_unpinned_or_authoritative_claim(samples, field, value):
    report = deepcopy(samples["swarm_corpus_report"])
    report[field] = value
    assert validate_named_schema("swarm_corpus_report", report)


def test_unchanged_threshold_contract_cannot_hide_a_relaxed_budget(samples):
    value = deepcopy(samples["swarm_overhead_report"])
    thresholds = SafetyThresholds()
    assert value["thresholds"]["p95_ms"] == thresholds.max_p95_ms == 250
    assert value["thresholds"]["p99_ms"] == thresholds.max_p99_ms == 500
    value["thresholds"]["p95_ms"] = 10000
    assert validate_named_schema("swarm_overhead_report", value)


@pytest.mark.parametrize(
    "configuration",
    ({"samples": 7}, {"samples": 257}, {"long_actions": 63}, {"long_actions": 1025}),
)
def test_benchmark_work_is_bounded_before_measuring(configuration):
    with pytest.raises(ValueError):
        measure(revision="a" * 40, **configuration)


def test_cli_writes_validated_private_output_and_refuses_overwrite(tmp_path, monkeypatch, samples):
    report = samples["swarm_corpus_report"]
    monkeypatch.setattr("ordin.swarm.benchmark_cli.evaluate", lambda *args, **kwargs: report)
    output, markdown = tmp_path / "report.json", tmp_path / "report.md"
    assert (
        main(
            ["corpus", "--revision", "a" * 40, "--output", str(output), "--markdown", str(markdown)]
        )
        == 0
    )
    assert json.loads(output.read_text())["result_sha256"] == report["result_sha256"]
    if os.name != "nt":
        assert output.stat().st_mode & 0o077 == 0
    with pytest.raises(FileExistsError):
        _write(output, "changed")
    assert json.loads(output.read_text())["result_sha256"] == report["result_sha256"]


def test_cli_invalid_schema_does_not_create_output(tmp_path, monkeypatch, samples):
    report = deepcopy(samples["swarm_corpus_report"])
    report["execution_authority"] = True
    monkeypatch.setattr("ordin.swarm.benchmark_cli.evaluate", lambda *args, **kwargs: report)
    output = tmp_path / "invalid.json"
    assert main(["corpus", "--revision", "a" * 40, "--output", str(output)]) == 2
    assert not output.exists()
