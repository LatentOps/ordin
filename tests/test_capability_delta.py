import json
from dataclasses import replace

import pytest

from ordin import ActionEnvelope, ActionResource, ActionReview
from ordin.runtime_contract import (
    FilesystemCapability,
    NetworkCapability,
    ProcessCapability,
    derive_runtime_capability_contract,
)
from ordin.runtime_observation import RuntimeEvidenceSource, RuntimeObservation, ObservedResource
from ordin.runtime_boundary import RuntimeCapabilityBoundary
from ordin.capability_delta import CapabilityDeltaProposal, propose_capability_delta
from ordin.enforcement_backend import CompilationResult
from ordin.schema import load_schema, resource_parity_errors, validate_named_schema
from ordin._runtime_schemas import SCHEMAS


def read_review():
    return ActionReview(
        ActionEnvelope(
            kind="file", operation="read", action_id="read", parameters={"path": "/repo/a"}
        ),
        "allow",
        "low",
        [],
        None,
        ["filesystem.read"],
        [ActionResource("path", "/repo/a")],
        "trusted-fixture",
    )


def source():
    return RuntimeEvidenceSource("openshell", "a" * 64, "sandbox", "b" * 64)


def deny(contract, *, point="filesystem", operation="filesystem.read", resources=(), metadata=None):
    return source().observe(
        contract,
        observation_id="denial",
        trust="backend_enforced",
        enforcement_point=point,
        outcome="denied",
        operation=operation,
        resources=resources,
        reason_code="policy_denied",
        metadata=metadata,
    )


def test_predicted_exact_filesystem_requirement_proposes_one_narrow_permission():
    review = read_review()
    contract = derive_runtime_capability_contract(review)
    denial = deny(contract, resources=(ObservedResource("path", "/repo/a"),))
    boundary = RuntimeCapabilityBoundary(
        "repo", filesystem=(FilesystemCapability("read", "/repo/a"),)
    )
    proposal = propose_capability_delta(review, contract, denial, boundary)
    assert proposal.status == "requires_approval" and proposal.requires_human_approval
    assert proposal.requested_delta.filesystem == (FilesystemCapability("read", "/repo/a"),)
    assert proposal.requested_delta.network == ()
    assert proposal.verification[0]["result"] == "within_boundary"
    assert proposal.contract_id == contract.contract_id


def test_trusted_network_denial_can_narrow_known_host_prediction_to_method_and_path():
    review = replace(
        read_review(),
        action=ActionEnvelope(kind="network", operation="request", action_id="request"),
        effects=["network.upload"],
        resources=[ActionResource("host", "api.example.com")],
    )
    contract = derive_runtime_capability_contract(review)
    assert contract.unknowns
    denial = deny(
        contract,
        point="network",
        operation="http.request",
        metadata={"host": "api.example.com", "port": 443, "method": "POST", "path": "/issues"},
    )
    boundary = RuntimeCapabilityBoundary(
        "api",
        network=(
            NetworkCapability("api.example.com", 443, "rest", "write", ("POST",), ("/issues",)),
        ),
    )
    proposal = propose_capability_delta(review, contract, denial, boundary)
    assert proposal.status == "requires_approval"
    assert proposal.requested_delta.network == boundary.network
    assert proposal.requested_delta.unknowns == ()
    assert proposal.requires_human_approval


def test_unmodeled_runtime_requirement_never_proposes_new_authority():
    review = read_review()
    contract = derive_runtime_capability_contract(review)
    denial = deny(
        contract,
        point="network",
        operation="http.request",
        metadata={"host": "api.example.com", "port": 443, "method": "POST", "path": "/upload"},
    )
    proposal = propose_capability_delta(
        review, contract, denial, RuntimeCapabilityBoundary("empty")
    )
    assert proposal.status == "rejected"
    assert proposal.reason_code == "runtime_delta_unmodeled_requirement"
    assert proposal.requested_delta is None


def test_wrong_action_digest_contract_and_blocked_decision_are_rejected():
    review = read_review()
    contract = derive_runtime_capability_contract(review)
    denial = deny(contract, resources=(ObservedResource("path", "/repo/a"),))
    changed = replace(review, action=replace(review.action, parameters={"path": "/other"}))
    assert (
        propose_capability_delta(
            changed, contract, denial, RuntimeCapabilityBoundary("empty")
        ).status
        == "rejected"
    )
    payload = denial.as_dict()
    payload["action_digest"] = "0" * 64
    mismatched = source().restore_trusted(payload)
    assert (
        propose_capability_delta(
            review, contract, mismatched, RuntimeCapabilityBoundary("empty")
        ).status
        == "rejected"
    )
    blocked = replace(review, decision="block", risk="critical")
    blocked_contract = derive_runtime_capability_contract(blocked)
    result = propose_capability_delta(
        blocked, blocked_contract, deny(blocked_contract), RuntimeCapabilityBoundary("empty")
    )
    assert result.reason_code == "runtime_delta_blocked_action"


def test_caller_asserted_denial_cannot_expand_runtime_authority():
    review = read_review()
    contract = derive_runtime_capability_contract(review)
    denial = RuntimeObservation(
        "weak",
        "read",
        contract.action_digest,
        contract.contract_id,
        outcome="denied",
        enforcement_point="filesystem",
        operation="filesystem.read",
    )
    assert (
        propose_capability_delta(
            review, contract, denial, RuntimeCapabilityBoundary("empty")
        ).reason_code
        == "runtime_delta_untrusted_denial"
    )


def test_boundary_exceedance_and_backend_unsupported_are_preserved():
    review = read_review()
    contract = derive_runtime_capability_contract(review)
    denial = deny(contract, resources=(ObservedResource("path", "/repo/a"),))
    excluded = propose_capability_delta(
        review, contract, denial, RuntimeCapabilityBoundary("empty")
    )
    assert (
        excluded.status == "rejected" and excluded.verification[0]["result"] == "exceeds_boundary"
    )

    class UnsupportedBackend:
        name = "fixture"

        def compile(self, contract):
            return CompilationResult(
                "unsupported",
                self.name,
                "filesystem_unsupported",
                unsupported_fields=("filesystem.scope",),
            )

        def validate(self, plan):
            raise AssertionError("unsupported policy must never be validated or applied")

    boundary = RuntimeCapabilityBoundary(
        "read", filesystem=(FilesystemCapability("read", "/repo/a"),)
    )
    rejected = propose_capability_delta(
        review, contract, denial, boundary, backend=UnsupportedBackend()
    )
    assert rejected.status == "rejected"
    assert rejected.verification[-1]["details"]["unsupported_fields"] == ("filesystem.scope",)


def test_proposal_schema_round_trip_and_identity_tampering():
    review = read_review()
    contract = derive_runtime_capability_contract(review)
    proposal = propose_capability_delta(
        review,
        contract,
        deny(contract, resources=(ObservedResource("path", "/repo/a"),)),
        RuntimeCapabilityBoundary("read", filesystem=(FilesystemCapability("read", "/repo/a"),)),
    )
    assert validate_named_schema("capability_delta_proposal", proposal.as_dict()) == []
    assert CapabilityDeltaProposal.from_dict(json.loads(json.dumps(proposal.as_dict()))) == proposal
    payload = proposal.as_dict()
    payload["requires_human_approval"] = False
    with pytest.raises(ValueError):
        CapabilityDeltaProposal.from_dict(payload)
    assert load_schema("capability_delta_proposal") == SCHEMAS["capability_delta_proposal"]
    assert resource_parity_errors() == []


def test_core_proposal_never_approves_applies_retries_or_runs_action(monkeypatch):
    import subprocess
    import socket

    review = read_review()
    contract = derive_runtime_capability_contract(review)
    denial = deny(contract, resources=(ObservedResource("path", "/repo/a"),))

    def forbidden(*args, **kwargs):
        raise AssertionError("core proposal attempted execution or network")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    result = propose_capability_delta(
        review,
        contract,
        denial,
        RuntimeCapabilityBoundary("read", filesystem=(FilesystemCapability("read", "/repo/a"),)),
    )
    assert result.status not in {"approved", "applied"}
