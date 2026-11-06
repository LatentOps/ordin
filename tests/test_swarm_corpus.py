"""Corpus provenance, reproducibility and explicit unknown/false-positive metrics."""

from copy import deepcopy
import json
from pathlib import Path

import pytest

from ordin.swarm._corpus_world import CANARY
from ordin.swarm.benchmark import evaluate, load_corpus
from ordin.swarm.corpus_controls import CONTROLS, outcome
from ordin.schema import validate_named_schema

MANIFEST = Path(__file__).resolve().parents[1] / "benchmarks/swarm/v1/manifest.json"


def test_complete_offline_stateful_corpus_and_reproducible_judgments():
    first = evaluate(MANIFEST, revision="a" * 40, seed=276)
    second = evaluate(MANIFEST, revision="a" * 40, seed=276)
    assert first["ok"], first["errors"]
    assert first["result_sha256"] == second["result_sha256"]
    assert first["metrics"]["critical_misses"] == first["metrics"]["false_allows"] == 0
    assert first["metrics"]["false_blocks"] == first["metrics"]["unnecessary_approvals"] == 0
    assert first["metrics"]["unknowns"] >= 6 and first["metrics"]["kernel_not_run"] > 0
    assert first["metrics"]["authenticated_kernel_completions"] == 0
    encoded = json.dumps(first)
    assert CANARY not in encoded and "rm -rf" not in encoded
    assert not first["execution_authority"]
    assert not validate_named_schema("swarm_corpus_report", first)
    assert (
        first["scope"]["cases"]
        == first["scope"]["evaluated"]
        + first["metrics"]["kernel_not_run"]
        + first["metrics"]["optional_not_evaluated"]
    )
    assert first["scope"]["critical_not_run"] > 0


def test_required_critical_unknown_is_a_miss_not_a_synthetic_pass(monkeypatch):
    monkeypatch.setitem(
        CONTROLS,
        "mass-deletion",
        lambda *args: outcome("unknown", {"unknown_is_not_completion": True}, backend="unknown"),
    )
    result = evaluate(MANIFEST, revision="b" * 40)
    assert not result["ok"] and result["metrics"]["critical_misses"] == 1
    assert any("mass-deletion" in value for value in result["errors"])


def test_benign_false_blocks_and_unnecessary_approvals_are_published(monkeypatch):
    monkeypatch.setitem(
        CONTROLS,
        "parallel-reads",
        lambda *args: outcome(
            "deny",
            {"fixture": True},
            core={"decision": "allow", "disposition": "escalate", "effects": []},
        ),
    )
    result = evaluate(MANIFEST, revision="c" * 40)
    assert not result["ok"] and result["metrics"]["false_blocks"] == 1
    assert result["metrics"]["unnecessary_approvals"] == 1


@pytest.mark.parametrize(
    "change", ("captured", "missing", "unknown", "duplicate", "raw-private", "relabel")
)
def test_unreviewed_capture_incomplete_or_unknown_fixture_is_refused(tmp_path, change):
    value = deepcopy(json.loads(MANIFEST.read_text()))
    if change == "captured":
        value["cases"][0]["provenance"]["kind"] = "captured"
    elif change == "missing":
        value["cases"].pop()
    elif change == "unknown":
        value["cases"][0]["scenario"] = "run_arbitrary_callback"
    elif change == "duplicate":
        value["cases"].append(value["cases"][0])
    elif change == "relabel":
        value["cases"][0].update(label="benign", expected="execute", critical=False)
    else:
        value["sanitization"]["private_traces_included"] = True
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError):
        load_corpus(path)


@pytest.mark.parametrize("revision", ("main", "HEAD", "a" * 39, "g" * 40))
def test_report_requires_exact_revision(revision):
    with pytest.raises(ValueError):
        evaluate(MANIFEST, revision=revision)


def test_absent_optional_risk_retains_unknown_rows_without_claiming_enforcement(monkeypatch):
    monkeypatch.setattr("ordin.swarm.benchmark.optional_risk_available", lambda: False)
    report = evaluate(MANIFEST, revision="d" * 40)
    assert report["ok"], report["errors"]
    rows = [value for value in report["results"] if value["status"] == "not_evaluated"]
    assert len(rows) == report["metrics"]["optional_not_evaluated"] == 5
    assert report["scope"]["critical_not_evaluated"] == 3
    assert all(value["actual"] == "unknown" and value["matched"] is None for value in rows)
    assert all(not value["backend_facts"]["physical_enforcement"] for value in rows)
