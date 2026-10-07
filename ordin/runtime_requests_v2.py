"""Exact request authority, with no persisted payload or argument values."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Mapping

from ._graphql_authority import graphql_authorities
from ._request_commitment import (
    REQUEST_COMMITMENT_ALGORITHM,
    request_commitment,
    rpc_body_commitment,
)
from ._runtime_json import digest, freeze, model_tuple, thaw, validate
from ._runtime_host import host_matches, identity_matches
from .runtime_boundary import DOMAINS, RuntimeCapabilityBoundary, verify_runtime_capability
from .runtime_contract import (
    NetworkCapability,
    RuntimeCapabilityContract,
    derive_runtime_capability_contract,
)
from .runtime_requests import (
    MCP_VERSIONS,
    RequestVerificationResult,
    _mcp_protocol_version,
    request_endpoint,
)

REQUEST_SCHEMA_VERSION = "ordin.runtime_request_contract.v2"
BOUNDARY_SCHEMA_VERSION = "ordin.runtime_request_boundary.v2"


@dataclass(frozen=True)
class NetworkAuthorityGrant:
    host_pattern: str
    port: int
    protocol: str
    access: str
    methods: tuple[str, ...] = ()
    paths: tuple[str, ...] = ()

    def __post_init__(self):
        object.__setattr__(self, "methods", tuple(self.methods))
        object.__setattr__(self, "paths", tuple(self.paths))
        validate("network_authority_grant", self.as_dict())
        if "*" in self.host_pattern and not self.host_pattern.startswith(("*.", "**.")):
            raise ValueError("runtime_network_grant_invalid")
        probe = self.host_pattern.replace("**.", "probe.", 1).replace("*.", "probe.", 1)
        if not host_matches(self.host_pattern, probe):
            raise ValueError("runtime_network_grant_invalid")
        if self.protocol == "tcp" and (self.access != "write" or self.methods or self.paths):
            raise ValueError("runtime_network_grant_invalid")
        if self.protocol != "tcp" and (not self.methods or not self.paths):
            raise ValueError("runtime_network_grant_invalid")

    def as_dict(self):
        return {
            "host_pattern": self.host_pattern,
            "port": self.port,
            "protocol": self.protocol,
            "access": self.access,
            "methods": list(self.methods),
            "paths": list(self.paths),
        }


@dataclass(frozen=True)
class RequestAuthority:
    protocol: str
    host: str
    port: int
    path: str
    commitment: str
    algorithm: str = REQUEST_COMMITMENT_ALGORITHM
    server: str | None = None
    versions: tuple[str, ...] = ()
    operations: tuple[Any, ...] = ()
    calls: tuple[Any, ...] = ()

    def __post_init__(self):
        object.__setattr__(self, "versions", tuple(self.versions))
        object.__setattr__(
            self, "operations", tuple(freeze(v, max_items=4096) for v in self.operations)
        )
        object.__setattr__(self, "calls", tuple(freeze(v) for v in self.calls))
        validate("request_authority", self.as_dict())
        authority_host = f"[{self.host}]" if ":" in self.host else self.host
        if request_endpoint(f"https://{authority_host}:{self.port}{self.path}") != (
            self.host,
            self.port,
            self.path,
        ):
            raise ValueError("runtime_request_authority_invalid")
        if self.protocol == "graphql":
            if not self.operations or self.calls or self.server is not None or self.versions:
                raise ValueError("runtime_request_authority_invalid")
        elif not self.calls or self.operations:
            raise ValueError("runtime_request_authority_invalid")
        if self.protocol == "mcp":
            if (
                not self.server
                or len(self.versions) != 1
                or not set(self.versions).issubset(MCP_VERSIONS)
            ):
                raise ValueError("runtime_request_authority_invalid")
        elif self.server is not None or self.versions:
            raise ValueError("runtime_request_authority_invalid")

    def as_dict(self):
        return {
            "protocol": self.protocol,
            "host": self.host,
            "port": self.port,
            "path": self.path,
            "commitment": self.commitment,
            "algorithm": self.algorithm,
            "server": self.server,
            "versions": list(self.versions),
            "operations": thaw(self.operations),
            "calls": thaw(self.calls),
        }

    @classmethod
    def from_body(cls, protocol: str, url: str, body: Any, *, server=None, versions=()):
        endpoint = request_endpoint(url)
        if endpoint is None or "?" in url or "#" in url:
            raise ValueError("runtime_request_authority_invalid")
        if protocol == "graphql":
            return cls(
                protocol, *endpoint, request_commitment(body), operations=graphql_authorities(body)
            )
        if protocol not in {"mcp", "json-rpc"}:
            raise ValueError("runtime_request_authority_invalid")
        commitment = rpc_body_commitment(body)
        messages = body if isinstance(body, (list, tuple)) else (body,)
        calls = []
        for message in messages:
            params = message.get("params")
            tool = (
                params.get("name")
                if protocol == "mcp"
                and message["method"] == "tools/call"
                and isinstance(params, Mapping)
                else None
            )
            calls.append(
                {
                    "method": message["method"],
                    "tool": tool,
                    "kind": "request" if "id" in message else "notification",
                }
            )
        return cls(
            protocol, *endpoint, commitment, server=server, versions=versions, calls=tuple(calls)
        )


@dataclass(frozen=True)
class RuntimeRequestContractV2:
    capability: RuntimeCapabilityContract
    requests: tuple[RequestAuthority, ...]
    request_contract_id: str = ""

    def __post_init__(self):
        if not isinstance(self.capability, RuntimeCapabilityContract):
            raise ValueError("runtime_request_authority_invalid")
        object.__setattr__(self, "requests", model_tuple(self.requests, RequestAuthority))
        expected = "rq:" + digest(self._material())
        if self.request_contract_id and expected != self.request_contract_id:
            raise ValueError("runtime_request_identity_mismatch")
        object.__setattr__(self, "request_contract_id", expected)
        validate("runtime_request_contract_v2", self.as_dict())

    def _material(self):
        return {
            "schema_version": REQUEST_SCHEMA_VERSION,
            "capability": self.capability.as_dict(),
            "requests": [request.as_dict() for request in self.requests],
        }

    def as_dict(self):
        return {**self._material(), "request_contract_id": self.request_contract_id}

    @property
    def digest(self):
        return digest(self.as_dict())

    @classmethod
    def from_dict(cls, value):
        validate("runtime_request_contract_v2", value)
        return cls(
            RuntimeCapabilityContract.from_dict(value["capability"]),
            tuple(RequestAuthority(**request) for request in value["requests"]),
            value["request_contract_id"],
        )


@dataclass(frozen=True)
class RuntimeRequestBoundaryV2:
    boundary: RuntimeCapabilityBoundary
    requests: tuple[RequestAuthority, ...]
    network_grants: tuple[NetworkAuthorityGrant, ...] = ()

    def __post_init__(self):
        if not isinstance(self.boundary, RuntimeCapabilityBoundary):
            raise ValueError("runtime_request_authority_invalid")
        object.__setattr__(self, "requests", model_tuple(self.requests, RequestAuthority))
        object.__setattr__(
            self, "network_grants", model_tuple(self.network_grants, NetworkAuthorityGrant)
        )
        validate("runtime_request_boundary_v2", self.as_dict())

    def as_dict(self):
        return {
            "schema_version": BOUNDARY_SCHEMA_VERSION,
            "boundary": self.boundary.as_dict(),
            "requests": [request.as_dict() for request in self.requests],
            "network_grants": [grant.as_dict() for grant in self.network_grants],
        }

    @property
    def digest(self):
        return digest(self.as_dict())

    @classmethod
    def from_dict(cls, value):
        validate("runtime_request_boundary_v2", value)
        return cls(
            RuntimeCapabilityBoundary.from_dict(value["boundary"]),
            tuple(RequestAuthority(**request) for request in value["requests"]),
            tuple(NetworkAuthorityGrant(**grant) for grant in value["network_grants"]),
        )


def request_authority_errors(contract: RuntimeRequestContractV2) -> tuple[str, ...]:
    errors = set()
    for request in contract.requests:
        matches = [
            n
            for n in contract.capability.network
            if (n.protocol, n.host, n.port, n.paths, n.methods, n.tool_identity)
            == (request.protocol, request.host, request.port, (request.path,), ("POST",), None)
        ]
        if not matches:
            errors.add("requests.endpoint_contract_mismatch")
        if (
            request.protocol == "graphql"
            and matches
            and any(
                n.access
                != (
                    "read"
                    if all(
                        o["operation_type"] in {"query", "subscription"} for o in request.operations
                    )
                    else "write"
                )
                for n in matches
            )
        ):
            errors.add("requests.graphql_access_mismatch")
    for network in contract.capability.network:
        if network.protocol == "json-rpc" and network.access != "write":
            errors.add("requests.jsonrpc_access_mismatch")
        if network.protocol in {"graphql", "mcp", "json-rpc"}:
            if (
                network.tool_identity is not None
                or network.methods != ("POST",)
                or len(network.paths) != 1
                or network.access not in {"read", "write"}
            ):
                errors.add("requests.network_scope_unrepresentable")
            if not any(
                (r.protocol, r.host, r.port, (r.path,))
                == (network.protocol, network.host, network.port, network.paths)
                for r in contract.requests
            ):
                errors.add("requests.missing_restrictions")
    for tool in contract.capability.tools:
        if not any(
            r.protocol == tool.runtime == "mcp"
            and r.server == tool.server
            and any(c["method"] == "tools/call" and c["tool"] == tool.tool for c in r.calls)
            for r in contract.requests
        ):
            errors.add("requests.tool_contract_mismatch")
    return tuple(sorted(errors))


def verify_runtime_request_authority(
    contract: RuntimeRequestContractV2, boundary: RuntimeRequestBoundaryV2
):
    if not isinstance(contract, RuntimeRequestContractV2) or not isinstance(
        boundary, RuntimeRequestBoundaryV2
    ):
        raise ValueError("runtime_request_authority_invalid")
    errors = request_authority_errors(contract)
    if errors:
        return RequestVerificationResult(
            "unsupported",
            "runtime_request_unsupported",
            contract.digest,
            boundary.digest,
            {**dict.fromkeys(DOMAINS, False), "requests": False},
            unsupported_fields=errors,
        )

    def transport(network):
        return (
            replace(network, protocol="rest")
            if network.protocol in {"graphql", "mcp", "json-rpc"}
            else network
        )

    maxima = list(boundary.boundary.network)
    for network in contract.capability.network:
        for grant in boundary.network_grants:
            if host_matches(grant.host_pattern, network.host) and grant.port == network.port:
                maxima.append(
                    NetworkCapability(
                        network.host,
                        grant.port,
                        grant.protocol,
                        grant.access,
                        grant.methods,
                        grant.paths,
                    )
                )
    tools = tuple(
        tool
        for tool in contract.capability.tools
        if any(
            maximum.runtime == tool.runtime
            and maximum.operation == tool.operation
            and identity_matches(maximum.server, tool.server)
            and identity_matches(maximum.tool, tool.tool)
            for maximum in boundary.boundary.tools
        )
    )
    candidate = replace(
        contract.capability,
        contract_id="",
        network=tuple(map(transport, contract.capability.network)),
    )
    maximum = replace(boundary.boundary, network=tuple(map(transport, maxima)), tools=tools)
    core = verify_runtime_capability(candidate, maximum)
    if core.ok:
        for protocol in {n.protocol for n in contract.capability.network}:
            core = verify_runtime_capability(
                replace(
                    candidate,
                    contract_id="",
                    network=tuple(
                        transport(n) for n in contract.capability.network if n.protocol == protocol
                    ),
                ),
                replace(
                    maximum,
                    network=tuple(transport(n) for n in maxima if n.protocol in {protocol, "tcp"}),
                ),
            )
            if not core.ok:
                break
    if not core.ok:
        return RequestVerificationResult(
            core.result,
            core.reason_code,
            contract.digest,
            boundary.digest,
            {**dict(core.coverage), "requests": False},
            core.counterexample,
            core.unsupported_fields,
        )
    for request in contract.requests:
        if request not in boundary.requests:
            return RequestVerificationResult(
                "exceeds_boundary",
                "runtime_request_exceeds_boundary",
                contract.digest,
                boundary.digest,
                {**dict(core.coverage), "requests": True},
                counterexample={"request_digest": digest(request.as_dict())},
            )
    return RequestVerificationResult(
        "within_boundary",
        "runtime_request_within",
        contract.digest,
        boundary.digest,
        {**dict(core.coverage), "requests": True},
    )


def derive_runtime_request_contract_v2(review):
    capability = derive_runtime_capability_contract(review)
    params = review.action.parameters
    requests = []
    if review.adapter == "network.graphql":
        body = params.get("body")
        if body is None:
            body = {
                "query": params.get("query"),
                **{k: params[k] for k in ("variables", "operationName") if k in params},
            }
        requests.append(RequestAuthority.from_body("graphql", params.get("url"), body))
    elif review.adapter == "network.jsonrpc":
        requests.append(
            RequestAuthority.from_body("json-rpc", params.get("url"), params.get("body"))
        )
    elif review.action.kind == "mcp" and review.adapter:
        method = params.get("method") if review.adapter == "mcp.protocol" else "tools/call"
        if not isinstance(method, str):
            return RuntimeRequestContractV2(capability, ())
        body = {"jsonrpc": "2.0", "method": method}
        if not method.startswith("notifications/"):
            body["id"] = 1
        if review.adapter == "mcp.protocol":
            if "params" in params:
                body["params"] = params["params"]
        else:
            body["params"] = {"name": params.get("tool"), "arguments": params.get("arguments", {})}
        version = _mcp_protocol_version(review)
        for network in capability.network:
            if (
                network.protocol == "mcp"
                and len(network.paths) == 1
                and version
                and isinstance(network.host, str)
            ):
                host = f"[{network.host}]" if ":" in network.host else network.host
                requests.append(
                    RequestAuthority.from_body(
                        "mcp",
                        f"https://{host}:{network.port}{network.paths[0]}",
                        body,
                        server=params.get("server"),
                        versions=(version,),
                    )
                )
    return RuntimeRequestContractV2(capability, tuple(requests))


def request_contract_from_dict(value):
    if value.get("schema_version") == REQUEST_SCHEMA_VERSION:
        return RuntimeRequestContractV2.from_dict(value)
    from .runtime_requests import RuntimeRequestContract

    return RuntimeRequestContract.from_dict(value)


def request_boundary_from_dict(value):
    if value.get("schema_version") == BOUNDARY_SCHEMA_VERSION:
        return RuntimeRequestBoundaryV2.from_dict(value)
    from .runtime_requests import RuntimeRequestBoundary

    return RuntimeRequestBoundary.from_dict(value)


def verify_request_contract(contract, boundary):
    if isinstance(contract, RuntimeRequestContractV2):
        return verify_runtime_request_authority(contract, boundary)
    from .runtime_requests import verify_runtime_request_capability

    return verify_runtime_request_capability(contract, boundary)
