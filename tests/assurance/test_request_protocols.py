"""Strict Assurance protocol maxima preserve the deliberately broader legacy API."""

from dataclasses import replace

from ordin import ActionEnvelope, Ordin
from ordin.assurance import verify_assurance_request_authority
from ordin.assurance import verify_assurance_capability
from ordin.runtime_requirements import RuntimeRequirementProfile
from ordin.runtime_boundary import RuntimeCapabilityBoundary
from ordin.runtime_contract import NetworkCapability, CredentialBinding
from ordin.runtime_requests_v2 import (
    RuntimeRequestBoundaryV2,
    derive_runtime_request_contract_v2,
    verify_runtime_request_authority,
)


def test_raw_tcp_does_not_supply_rest_authority_to_assurance():
    review = Ordin(
        runtime_requirements=RuntimeRequirementProfile(
            "fixture", executable_bindings={"curl": "/fixture/bin/curl"}, spawn_children=False
        )
    ).review_action(
        ActionEnvelope.shell("curl --disable --request GET https://fixture.invalid/api")
    )
    contract = derive_runtime_request_contract_v2(review)
    assert contract.capability.network and contract.capability.network[0].protocol == "rest"
    tcp = NetworkCapability("fixture.invalid", 443, protocol="tcp", access="write")
    boundary = RuntimeRequestBoundaryV2(
        RuntimeCapabilityBoundary(
            "fixture",
            network=(tcp,),
            filesystem=contract.capability.filesystem,
            process=contract.capability.process,
            privilege=contract.capability.privilege,
        ),
        (),
    )
    assert verify_runtime_request_authority(contract, boundary).ok
    strict = verify_assurance_request_authority(contract, boundary)
    assert not strict.ok and strict.result == "exceeds_boundary"
    assert strict.reason_code == "assurance.request_protocol_exceeds_boundary"
    assert not verify_assurance_capability(contract.capability, boundary.boundary).ok
    explicit = replace(
        boundary, boundary=replace(boundary.boundary, network=(tcp, *contract.capability.network))
    )
    assert verify_assurance_request_authority(contract, explicit).ok


def test_strict_projection_cannot_hide_another_domain_or_body_violation():
    review = Ordin().review_action(
        ActionEnvelope(
            "network",
            "jsonrpc.request",
            {
                "url": "https://fixture.invalid/api",
                "body": {"jsonrpc": "2.0", "id": 1, "method": "lookup", "params": {"id": "a"}},
            },
        )
    )
    contract = derive_runtime_request_contract_v2(review)
    boundary = RuntimeRequestBoundaryV2(
        RuntimeCapabilityBoundary("fixture", network=contract.capability.network), contract.requests
    )
    assert verify_assurance_request_authority(contract, boundary).ok
    altered_capability = replace(
        contract.capability,
        contract_id="",
        credentials=(CredentialBinding("fixture-credential", "outside.invalid", 443),),
    )
    changed = replace(contract, capability=altered_capability, request_contract_id="")
    assert not verify_assurance_request_authority(changed, boundary).ok
    changed = replace(
        contract,
        request_contract_id="",
        requests=(replace(contract.requests[0], commitment="0" * 64),),
    )
    assert not verify_assurance_request_authority(changed, boundary).ok
