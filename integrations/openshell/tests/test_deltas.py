import hashlib
from dataclasses import replace

import pytest

from ordin import ActionEnvelope, Ordin, RuntimeEvidenceSource, derive_runtime_capability_contract
from ordin.runtime_contract import FilesystemCapability
from ordin.runtime_requirements import RuntimeRequirementProfile
from ordin_openshell.compiler import OpenShellBackend
from ordin_openshell.deltas import propose_openshell_delta
from ordin_openshell.prover import MODELED_DOMAINS, OpenShellProverResult
from test_apply import boundary_for


def fixture():
    review = Ordin().review_action(
        ActionEnvelope.shell(
            "curl --disable --request GET https://api.github.com/rate_limit",
            action_id="read-rate-limit",
        )
    )
    profile = RuntimeRequirementProfile(
        "fixture-bootstrap",
        filesystem=(
            FilesystemCapability("read", "/usr", "prefix"),
            FilesystemCapability("execute", "/usr", "prefix"),
        ),
        executable_bindings={"curl": "/usr/bin/curl"},
        spawn_children=True,
    )
    review = profile.declare(review)
    contract = derive_runtime_capability_contract(review)
    source = RuntimeEvidenceSource("openshell", "a" * 64, "sandbox", "b" * 64)
    denial = source.observe(
        contract,
        observation_id="rate-limit-denied",
        trust="backend_enforced",
        enforcement_point="network",
        outcome="denied",
        operation="http.request",
        reason_code="policy_denied",
        metadata={
            "host": "api.github.com",
            "port": 443,
            "method": "GET",
            "path": "/rate_limit",
            "binary": "/usr/bin/curl",
        },
    )
    return review, contract, denial, boundary_for(contract), OpenShellBackend((1000, 1000))


def test_delta_is_narrow_but_backend_candidate_keeps_reviewed_startup_requirements():
    review, contract, denial, boundary, backend = fixture()
    result = propose_openshell_delta(review, contract, denial, boundary, backend=backend)
    assert result.proposal.status == "requires_approval"
    assert result.proposal.requires_human_approval
    assert result.proposal.requested_delta.filesystem == ()
    assert (
        result.candidate is not None and result.candidate.contract.filesystem == contract.filesystem
    )
    assert result.candidate.contract.network == result.proposal.requested_delta.network
    assert result.candidate.contract.decision == review.decision
    assert [s["step"] for s in result.proposal.verification] == [
        "capability_boundary",
        "candidate_capability_boundary",
        "openshell_compile",
        "openshell_validation",
    ]


@pytest.mark.parametrize("state", ["unsupported", "inconclusive", "exceeds_boundary", "error"])
def test_prover_non_success_rejects_candidate_and_preserves_coverage(monkeypatch, state):
    import ordin_openshell.deltas as module

    review, contract, denial, boundary, backend = fixture()
    monkeypatch.setattr(
        module,
        "verify_with_openshell_prover",
        lambda *a, **k: OpenShellProverResult(state, "fixture", {"domains": ["network_rest"]}),
    )
    result = propose_openshell_delta(
        review,
        contract,
        denial,
        boundary,
        backend=backend,
        backend_boundary_policy=backend.compile(contract).plan.policy,
    )
    assert result.candidate is None and result.proposal.status == "rejected"
    assert result.proposal.verification[-1]["details"]["coverage"]["domains"] == ("network_rest",)


def test_real_snapshot_binding_and_proof_step_are_retained_but_never_auto_approve(monkeypatch):
    import ordin_openshell.deltas as module

    review, contract, denial, boundary, backend = fixture()

    def proof(candidate, maximum, **kwargs):
        return OpenShellProverResult(
            "within_boundary",
            "fixture",
            {"domains": sorted(MODELED_DOMAINS)},
            candidate_digest=hashlib.sha256(candidate.read_bytes()).hexdigest(),
            boundary_digest=hashlib.sha256(maximum.read_bytes()).hexdigest(),
            prover_version="0.1.2",
        )

    monkeypatch.setattr(module, "verify_with_openshell_prover", proof)
    result = propose_openshell_delta(
        review,
        contract,
        denial,
        boundary,
        backend=backend,
        backend_boundary_policy=backend.compile(contract).plan.policy,
    )
    assert result.candidate is not None and result.proposal.status == "requires_approval"
    assert result.proposal.verification[-1]["result"] == "within_boundary"
    assert result.proposal.verification[-1]["details"]["candidate_digest"]


def test_unmodeled_delete_or_foreign_action_never_expands_backend_authority():
    review, contract, denial, boundary, backend = fixture()
    source = RuntimeEvidenceSource("openshell", "a" * 64, "sandbox", "b" * 64)
    bad = source.observe(
        contract,
        observation_id="bad",
        trust="backend_enforced",
        enforcement_point="network",
        outcome="denied",
        operation="http.request",
        reason_code="policy_denied",
        metadata={
            "host": "api.github.com",
            "port": 443,
            "method": "DELETE",
            "path": "/rate_limit",
            "binary": "/usr/bin/curl",
        },
    )
    result = propose_openshell_delta(review, contract, bad, boundary, backend=backend)
    assert result.candidate is None and result.proposal.requested_delta is None
    assert result.proposal.reason_code == "runtime_delta_unmodeled_requirement"
