"""Report integrity is deliberately weaker than authenticated runtime authority."""

from copy import deepcopy
import hashlib
import json

import pytest

from ordin.schema import validate_named_schema
from tests.swarm_release_contract_samples import manifest_sample, RAW
from ordin_swarm.release_evidence import (
    artifact_errors,
    canonical_bytes,
    evidence_sha256,
    validate_manifest,
)


def reseal(value):
    value["manifest_sha256"] = evidence_sha256(
        {key: item for key, item in value.items() if key != "manifest_sha256"}
    )
    return value


def test_closed_unmeasured_manifest_is_schema_valid_but_never_authority():
    value = manifest_sample()
    assert not validate_named_schema("swarm_release_manifest", value)
    assert not validate_manifest(value)
    assert len(value["checks"]) == 16
    assert all(row["status"] == "not_evaluated" for row in value["checks"])
    assert not value["local_gate_passed"] and not value["complete_conformance"]
    assert not value["origin_authenticated_by_json"]
    assert value["dependency_security_clearance"] == "not_established"
    assert not value["execution_authority"] and not value["production_rollout_authorized"]


@pytest.mark.parametrize(
    "change",
    (
        "physical",
        "windows_physical",
        "omitted",
        "external_pass",
        "no_artifact",
        "budget",
        "denominator",
        "authority",
        "origin",
        "dirty",
    ),
)
def test_self_consistent_rehashed_claims_cannot_widen_declared_evidence(change):
    value = manifest_sample()
    row = next(row for row in value["checks"] if row["id"] == "mcp")
    if change == "physical":
        row.update(
            status="passed",
            producer="fixed_installed_helper",
            artifact="example.json",
            passed=1,
            observed_boundary="owned_linux_read_worker",
            physical_enforcement=True,
        )
    elif change == "windows_physical":
        value["environment"]["platform"] = "win32"
        next(row for row in value["checks"] if row["id"] == "owned_linux_worker").update(
            status="passed",
            producer="fixed_installed_helper",
            artifact="example.json",
            passed=1,
            observed_boundary="owned_linux_read_worker",
            physical_enforcement=True,
        )
    elif change == "omitted":
        value["checks"].pop()
    elif change == "external_pass":
        next(row for row in value["checks"] if row["id"] == "langgraph").update(
            status="passed", producer="fixed_installed_helper", artifact="example.json", passed=1
        )
    elif change == "no_artifact":
        row.update(status="passed", producer="fixed_installed_helper", passed=1)
    elif change == "budget":
        value["benchmarks"]["p95_budget_ms"] = 10000
    elif change == "denominator":
        value["benchmarks"]["cases"] = 1
    elif change == "authority":
        value["execution_authority"] = True
    elif change == "origin":
        value["origin_authenticated_by_json"] = True
    else:
        value["source"]["clean"] = False
    assert validate_manifest(reseal(value))


def test_manifest_and_owned_artifact_changes_are_detected(tmp_path):
    value = manifest_sample()
    path = tmp_path / "example.json"
    path.write_bytes(RAW)
    assert artifact_errors(value, tmp_path) == []
    path.write_bytes(RAW + b"changed")
    assert artifact_errors(value, tmp_path)
    value["source"]["tree"] = "f" * 40
    assert "release.manifest_digest_mismatch" in validate_manifest(value)


def test_byte_consistency_does_not_authenticate_an_imported_json_producer(tmp_path):
    value = manifest_sample()
    raw = b'{"physical_enforcement":true,"execution_authority":true}'
    (tmp_path / "example.json").write_bytes(raw)
    value["artifacts"][0].update(sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw))
    assert artifact_errors(reseal(value), tmp_path) == []
    assert not value["origin_authenticated_by_json"] and not value["execution_authority"]
    assert not value["local_gate_passed"]


def test_json_data_only_does_not_execute_python_serialization_hooks():
    called = []

    class Untrusted:
        def __deepcopy__(self, memo):
            called.append(True)
            raise AssertionError("untrusted Python callback")

    with pytest.raises(ValueError):
        canonical_bytes({"value": Untrusted()})
    assert not called
    for value in ([0] * 1025, {"value": "x" * 4097}, {"nan": float("nan")}):
        with pytest.raises(ValueError):
            canonical_bytes(value)


def test_optional_plugin_and_unmeasured_cases_are_not_dropped():
    value = manifest_sample()
    value["benchmarks"].update(
        cases=44, evaluated=39, optional_not_evaluated=5, unknowns=7, uncovered_paths=2
    )
    assert not validate_manifest(reseal(value))
    assert {row["id"] for row in value["checks"]} >= {"legacy_autogen", "postgres", "openshell"}


def test_quarantined_crewai_stays_explicit_without_an_active_sdk_lock_or_pass():
    value = manifest_sample()
    assert len(value["locks"]) == 4
    assert "requirements/swarm-crewai.txt" not in {row["name"] for row in value["locks"]}
    row = next(row for row in value["checks"] if row["id"] == "crewai")
    reference = next(
        row for row in value["external_gate_references"] if row["checks"] == ["crewai"]
    )
    assert row["status"] == "not_evaluated"
    assert row["reason_code"] == "security_blocked_unpatched_chromadb"
    assert reference["availability"] == "security_blocked"
    assert reference["observed_status"] == "not_evaluated"
    assert reference["required_lock_sha256"] is None
    assert len(reference["security_advisories"]) == 4
    assert all(row["first_patched_version"] is None for row in reference["security_advisories"])


@pytest.mark.parametrize(
    "change", ("enabled", "omit_advisory", "claim_sdk", "old_lock", "foreign_block")
)
def test_rehashed_quarantine_relabeling_cannot_manufacture_sdk_conformance(change):
    value = manifest_sample()
    reference = next(
        row for row in value["external_gate_references"] if row["checks"] == ["crewai"]
    )
    if change == "enabled":
        reference["availability"] = "enabled"
    elif change == "omit_advisory":
        reference["security_advisories"].pop()
    elif change == "claim_sdk":
        next(row for row in value["checks"] if row["id"] == "crewai")["reason_code"] = "sdk_passed"
    elif change == "old_lock":
        value["locks"][-1]["name"] = "requirements/swarm-crewai.txt"
    else:
        next(row for row in value["external_gate_references"] if row["checks"] == ["langgraph"])[
            "availability"
        ] = "security_blocked"
    assert validate_manifest(reseal(value))
