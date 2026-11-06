"""Public calibration examples keep a bounded registered data-only contract."""

from copy import deepcopy
import json
from pathlib import Path

import pytest

from ordin.schema import validate_named_schema
from ordin.swarm.risk_signals import SwarmRiskInput
from tests.swarm_risk_contract_samples import swarm_risk_contract_samples


ROOT = Path(__file__).resolve().parents[1]


def test_both_public_risk_corpora_use_the_registered_contract():
    for name in ("risk-calibration-corpus.json", "risk-review-holdout-corpus.json"):
        payload = json.loads((ROOT / "examples/swarm" / name).read_text())
        assert not validate_named_schema("swarm_risk_corpus", payload)


@pytest.mark.parametrize(
    "field,value",
    (
        ("case_id", ""),
        ("case_id", "x" * 129),
        ("kind", "authenticated_host_fact"),
        ("text", "x" * 16385),
        ("expected_class", "unknown"),
        ("expected_class", "approved"),
        ("execution_authority", True),
    ),
)
def test_risk_corpus_rejects_unbounded_or_authoritative_case_claims(field, value):
    payload = swarm_risk_contract_samples()["swarm_risk_corpus"]
    payload["cases"][0][field] = value
    assert validate_named_schema("swarm_risk_corpus", payload)


def test_risk_corpus_rejects_top_level_authority_and_duplicate_rows():
    payload = swarm_risk_contract_samples()["swarm_risk_corpus"]
    payload["execution_authority"] = True
    assert validate_named_schema("swarm_risk_corpus", payload)
    del payload["execution_authority"]
    payload["cases"][1] = deepcopy(payload["cases"][0])
    assert validate_named_schema("swarm_risk_corpus", payload)


@pytest.mark.parametrize("count", (11, 257))
def test_risk_corpus_retains_the_calibration_case_count_bounds(count):
    payload = swarm_risk_contract_samples()["swarm_risk_corpus"]
    row = payload["cases"][0]
    payload["cases"] = [{**row, "case_id": f"case-{index}"} for index in range(count)]
    assert validate_named_schema("swarm_risk_corpus", payload)


def test_runtime_keeps_the_stricter_utf8_byte_bound():
    with pytest.raises(ValueError, match="bounded"):
        SwarmRiskInput("untrusted_message", "\U0001f642" * 4097)
