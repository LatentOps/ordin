"""Additional protocol isolation for Assurance; legacy transport rules stay intact."""

from dataclasses import replace

from ordin._runtime_host import host_matches
from ordin.runtime_boundary import (
    CapabilityVerificationResult,
    RuntimeCapabilityBoundary,
    verify_runtime_capability,
)
from ordin.runtime_contract import NetworkCapability, RuntimeCapabilityContract
from ordin.runtime_requests import RequestVerificationResult
from ordin.runtime_requests_v2 import (
    RuntimeRequestBoundaryV2,
    RuntimeRequestContractV2,
    verify_runtime_request_authority,
)


def verify_assurance_request_authority(
    contract: RuntimeRequestContractV2,
    boundary: RuntimeRequestBoundaryV2,
) -> RequestVerificationResult:
    """Verify every legacy constraint, then require a separate exact protocol grant.

    The internal network-only projection adds a restriction after full six-domain
    and exact-request validation. It is never returned as an execution grant or
    asserted to be a full contract. A raw TCP maximum cannot supply HTTP, GraphQL,
    MCP or JSON-RPC authority in an approved Assurance request profile.
    """
    checked = verify_runtime_request_authority(contract, boundary)
    if not checked.ok:
        return checked
    for network in contract.capability.network:
        if network.protocol == "tcp":
            continue
        maxima = [n for n in boundary.boundary.network if n.protocol == network.protocol]
        maxima.extend(
            NetworkCapability(
                network.host, grant.port, grant.protocol, grant.access, grant.methods, grant.paths
            )
            for grant in boundary.network_grants
            if grant.protocol == network.protocol
            and grant.port == network.port
            and host_matches(grant.host_pattern, network.host)
        )

        def projected(n):
            return (
                replace(n, protocol="rest") if n.protocol in {"graphql", "mcp", "json-rpc"} else n
            )

        question = RuntimeCapabilityContract(
            contract.capability.action_id,
            contract.capability.action_digest,
            "allow",
            "low",
            network=(projected(network),),
            source=contract.capability.source,
        )
        comparison = verify_runtime_capability(
            question,
            RuntimeCapabilityBoundary(
                "assurance-protocol-projection",
                network=tuple(projected(n) for n in maxima),
            ),
        )
        if not comparison.ok:
            return RequestVerificationResult(
                comparison.result,
                "assurance.request_protocol_exceeds_boundary"
                if comparison.result == "exceeds_boundary"
                else "assurance.request_protocol_unsupported",
                contract.digest,
                boundary.digest,
                {**dict(checked.coverage), "network": comparison.coverage["network"]},
                counterexample={"protocol": network.protocol},
                unsupported_fields=comparison.unsupported_fields,
            )
    return checked


def verify_assurance_capability(
    contract: RuntimeCapabilityContract,
    boundary: RuntimeCapabilityBoundary,
) -> CapabilityVerificationResult:
    """Full core containment plus protocol separation for basic profile maxima."""
    checked = verify_runtime_capability(contract, boundary)
    if not checked.ok:
        return checked
    # Core v1 supports REST and TCP here. Higher-level protocols remain
    # unsupported until an exact v2 request authority is separately supplied.
    for network in contract.network:
        if network.protocol == "tcp":
            continue
        question = RuntimeCapabilityContract(
            contract.action_id,
            contract.action_digest,
            "allow",
            "low",
            network=(network,),
            source=contract.source,
        )
        comparison = verify_runtime_capability(
            question,
            RuntimeCapabilityBoundary(
                "assurance-basic-protocol-projection",
                network=tuple(n for n in boundary.network if n.protocol == network.protocol),
            ),
        )
        if not comparison.ok:
            return CapabilityVerificationResult(
                comparison.result,
                "assurance.request_protocol_exceeds_boundary"
                if comparison.result == "exceeds_boundary"
                else "assurance.request_protocol_unsupported",
                contract.digest,
                boundary.digest,
                {**dict(checked.coverage), "network": comparison.coverage["network"]},
                counterexample={"protocol": network.protocol},
                unsupported_fields=comparison.unsupported_fields,
            )
    return checked
