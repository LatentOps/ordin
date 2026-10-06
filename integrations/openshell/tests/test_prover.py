import json
import os
import shutil

import pytest

from ordin_openshell.prover import MODELED_DOMAINS, parse_prover_json, verify_with_openshell_prover
from test_compiler import compile


def response(result="within_boundary", **kwargs):
    return {
        "schema_version": 1,
        "prover_version": "0.1.2",
        "check": "boundary",
        "coverage": {"domains": sorted(MODELED_DOMAINS)},
        "result": result,
        "exit_code": {
            "within_boundary": 0,
            "exceeds_boundary": 1,
            "error": 2,
            "unsupported": 3,
            "inconclusive": 3,
        }[result],
        "inputs": {"candidate": "candidate.policy", "boundary": "boundary.policy"},
        "counterexample": None,
        "reason_code": None,
        "reason": None,
        **kwargs,
    }


@pytest.mark.parametrize(
    "state", ["within_boundary", "exceeds_boundary", "unsupported", "inconclusive", "error"]
)
def test_all_prover_states_and_exit_codes_are_preserved(state):
    payload = response(state)
    result = parse_prover_json(json.dumps(payload), returncode=payload["exit_code"])
    assert result.result == state
    assert result.ok == (state == "within_boundary")
    assert set(result.coverage["domains"]) == MODELED_DOMAINS


def test_unsupported_coverage_and_counterexample_never_disappear():
    payload = response(
        "exceeds_boundary",
        counterexample={"domain": "network", "method": "POST", "path": "/issues"},
    )
    result = parse_prover_json(json.dumps(payload), returncode=1)
    assert result.counterexample["method"] == "POST"
    result = parse_prover_json(
        json.dumps(response(coverage={"domains": ["network_rest"]})), returncode=0
    )
    assert result.result == "unsupported" and result.unsupported_domains
    assert not result.ok


@pytest.mark.parametrize(
    "overrides",
    [
        {"schema_version": 2},
        {"prover_version": "0.1.3"},
        {"exit_code": 1},
        {"coverage": {"domains": "all"}},
        {"extra_unknown_field": True},
    ],
)
def test_incompatible_or_malformed_prover_results_fail_closed(overrides):
    result = parse_prover_json(json.dumps(response(**overrides)), returncode=0)
    assert not result.ok and result.result == "error"


def test_invalid_json_duplicate_fields_and_missing_binary_are_typed_errors(tmp_path):
    assert (
        parse_prover_json('{"result":"within_boundary","result":"error"}', returncode=0).result
        == "error"
    )
    assert parse_prover_json("not json", returncode=0).result == "error"
    assert (
        verify_with_openshell_prover(
            tmp_path / "c", tmp_path / "b", executable="definitely-missing-ordin-prover"
        ).reason_code
        == "openshell_prover_missing"
    )


def test_real_prover_policy_fixture(tmp_path):
    executable = os.environ.get("ORDIN_OPENSHELL_PROVER", "openshell-prover")
    if shutil.which(executable) is None:
        pytest.skip("standalone OpenShell prover is not installed")
    policy = compile().plan.as_dict()["policy"]
    candidate, boundary = tmp_path / "candidate.json", tmp_path / "boundary.json"
    candidate.write_text(json.dumps(policy))
    boundary.write_text(json.dumps(policy))
    within = verify_with_openshell_prover(candidate, boundary, executable=executable)
    assert within.ok, within.as_dict()
    network = next(iter(policy["network_policies"].values()))
    network["endpoints"][0]["rules"][0]["allow"]["method"] = "POST"
    candidate.write_text(json.dumps(policy))
    exceeds = verify_with_openshell_prover(candidate, boundary, executable=executable)
    assert exceeds.result == "exceeds_boundary", exceeds.as_dict()
    assert exceeds.counterexample
