"""REST proposal checks retain original non-network domains and all maxima."""

from dataclasses import replace

import pytest

from ordin.assurance import DelegationAuthority, IssuedDelegation, verify_delegation_subset
from ordin.assurance.delegation import _network_boundary
from ordin.assurance.rest import RestRequestAuthority, verify_assurance_capability
from ordin.runtime_boundary import RuntimeCapabilityBoundary
from ordin.runtime_contract import (
    CredentialBinding,
    FilesystemCapability,
    NetworkCapability,
    PrivilegeCapability,
    ProcessCapability,
    RuntimeCapabilityContract,
    ToolCapability,
)


def authority(*, parameters=None, uid=65534):
    parameters = parameters or {
        "url": "https://fixture.invalid:9443/reference",
        "method": "GET",
        "headers": {"Accept": "text/plain"},
    }
    request = RestRequestAuthority.from_parameters(parameters)
    capability = RuntimeCapabilityBoundary(
        "original",
        filesystem=(FilesystemCapability("read", "/project/source", "exact"),),
        network=(
            NetworkCapability(
                request.host,
                request.port,
                "rest",
                request.access,
                (request.method,),
                (request.path,),
            ),
        ),
        tools=(ToolCapability("managed", None, "read_file"),),
        process=ProcessCapability(False, (), False),
        privilege=PrivilegeCapability(False, uid),
        credentials=(CredentialBinding("original-binding", request.host, request.port),),
        filesystem_semantics="lexical_prefix",
        runtime_filesystem_guarantees=True,
    )
    return DelegationAuthority(capability, rest_requests=(request,))


def test_original_network_only_projection_loses_uid_but_complete_proposal_is_contained():
    original = authority()
    request = original.rest_requests[0]
    network = NetworkCapability(
        request.host, request.port, "rest", request.access, (request.method,), (request.path,)
    )
    network_only = RuntimeCapabilityContract(
        "old-projection",
        original.digest,
        "allow",
        "low",
        network=(network,),
        source={
            "kind": "delegation",
            "operation": "subset",
            "adapter": None,
            "effects": [],
            "provenance_digest": None,
        },
    )
    before = verify_assurance_capability(network_only, _network_boundary(original, (network,)))
    assert not before.ok and before.reason_code == "runtime_boundary_uid_unproven"
    after = verify_delegation_subset(original, original, original, original)
    assert after.ok and all(after.coverage.values())
    assert original.capability.privilege.required_euid == 65534
    legacy = authority(uid=None)
    assert verify_delegation_subset(legacy, legacy, legacy, legacy).ok
    with pytest.raises(ValueError, match="JSON"):
        IssuedDelegation.from_dict(after.as_dict())


@pytest.mark.parametrize(
    "domain,changes",
    [
        ("privilege", {"privilege": PrivilegeCapability(False, 1000)}),
        ("privilege", {"privilege": PrivilegeCapability(True, 65534)}),
        ("process", {"process": ProcessCapability(True, ("/bin/python",), False)}),
        ("filesystem", {"filesystem": (FilesystemCapability("write", "/outside/file", "exact"),)}),
        ("tools", {"tools": (ToolCapability("managed", None, "other_tool"),)}),
        (
            "credentials",
            {"credentials": (CredentialBinding("foreign-binding", "fixture.invalid", 9443),)},
        ),
    ],
)
@pytest.mark.parametrize("maximum_index", [0, 1, 2])
def test_every_original_nonnetwork_domain_remains_inside_every_maximum(
    domain, changes, maximum_index
):
    maximum = authority()
    child = replace(maximum, capability=replace(maximum.capability, **changes))
    maxima = [child, child, child]
    maxima[maximum_index] = maximum
    result = verify_delegation_subset(child, *maxima)
    assert not result.ok and result.result == "exceeds_boundary"
    role = ("parent", "operator", "task")[maximum_index]
    assert "delegation." + role + "_exceeds_boundary" in result.reason_codes
    assert result.coverage[domain] is True  # Supported and definitively denied.


@pytest.mark.parametrize(
    "parameters",
    [
        {"url": "https://foreign.invalid:9443/reference", "method": "GET"},
        {"url": "https://fixture.invalid:9444/reference", "method": "GET"},
        {"url": "https://fixture.invalid:9443/outside", "method": "GET"},
        {"url": "https://fixture.invalid:9443/reference", "method": "POST", "body": "changed"},
    ],
)
def test_exact_request_outside_child_network_capability_stays_rejected(parameters):
    original = authority()
    child = replace(original, rest_requests=(RestRequestAuthority.from_parameters(parameters),))
    result = verify_delegation_subset(child, child, child, child)
    assert not result.ok and not result.coverage["requests"]
    assert "delegation.rest_request_outside_child_capability" in result.reason_codes


@pytest.mark.parametrize(
    "parameters,changed",
    [
        (
            {
                "url": "https://fixture.invalid:9443/reference",
                "method": "GET",
                "headers": {"Accept": "text/plain"},
            },
            {
                "url": "http://fixture.invalid:9443/reference",
                "method": "GET",
                "headers": {"Accept": "text/plain"},
            },
        ),
        (
            {
                "url": "https://fixture.invalid:9443/reference",
                "method": "GET",
                "headers": {"Accept": "text/plain"},
            },
            {
                "url": "https://fixture.invalid:9443/reference",
                "method": "GET",
                "headers": {"Accept": "application/json"},
            },
        ),
        (
            {
                "url": "https://fixture.invalid:9443/reference",
                "method": "POST",
                "body": {"value": 1},
            },
            {
                "url": "https://fixture.invalid:9443/reference",
                "method": "POST",
                "body": {"value": True},
            },
        ),
    ],
)
@pytest.mark.parametrize("maximum_index", [0, 1, 2])
def test_full_request_commitment_cannot_change_when_network_scope_still_matches(
    parameters, changed, maximum_index
):
    maximum = authority(parameters=parameters)
    child = replace(maximum, rest_requests=(RestRequestAuthority.from_parameters(changed),))
    assert child.rest_requests[0].commitment != maximum.rest_requests[0].commitment
    maxima = [child, child, child]
    maxima[maximum_index] = maximum
    result = verify_delegation_subset(child, *maxima)
    assert result.result == "exceeds_boundary" and not result.coverage["requests"]
    role = ("parent", "operator", "task")[maximum_index]
    assert "delegation." + role + "_rest_request_commitment_exceeds" in result.reason_codes


def test_unsupported_filesystem_process_or_removed_approval_are_not_erased():
    original = authority()
    unsupported = (
        replace(original, capability=replace(original.capability, allow_any_executable=True)),
        replace(
            original,
            capability=replace(
                original.capability,
                filesystem=(FilesystemCapability("read", "/project", "prefix"),),
                runtime_filesystem_guarantees=False,
            ),
        ),
    )
    for child in unsupported:
        assert not verify_delegation_subset(child, child, child, child).ok
    required = replace(original, requires_approval=True)
    assert not verify_delegation_subset(original, required, required, required).ok
