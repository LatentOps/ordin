"""Action-bound request restrictions beside the unchanged capability v1 format.

The supported model describes GraphQL operation/root-field permissions and MCP
method/tool/version permissions. Argument, variable and nested-field constraints
remain explicit unsupported requirements, never discarded during compilation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from typing import Any
from urllib.parse import urlsplit
from ._runtime_url import has_unsafe_authority_characters

from ._runtime_json import digest, freeze, thaw, model_tuple, text_tuple, validate
from .action import ActionReview
from .runtime_boundary import (
    CapabilityVerificationResult,
    RuntimeCapabilityBoundary,
    verify_runtime_capability,
    DOMAINS,
)
from .runtime_contract import (
    NetworkCapability,
    RuntimeCapabilityContract,
    _safe_path,
    derive_runtime_capability_contract,
)

REQUEST_SCHEMA_VERSION = "ordin.runtime_request_contract.v1"
REQUEST_BOUNDARY_SCHEMA_VERSION = "ordin.runtime_request_boundary.v1"
MCP_VERSIONS = frozenset({"2025-03-26", "2025-06-18", "2025-11-25"})
MCP_METHODS = frozenset(
    {"initialize", "notifications/initialized", "ping", "tools/list", "tools/call"}
)
NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
TOOL_NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")


class _GraphQLScopeParser:
    """Bounded syntax whose exact root fields the pinned backend enforces."""

    def __init__(self, query: str) -> None:
        self.tokens: list[str] = []
        position = 0
        while position < len(query):
            if query[position] in " \t\r\n,":
                position += 1
                continue
            comment = re.match(r"#[^\r\n]*", query[position:])
            if comment:
                position += len(comment[0])
                continue
            token = re.match(r"\.\.\.|[A-Za-z_][A-Za-z0-9_]*|[{}:]", query[position:])
            if token is None or len(token[0]) > 128 or len(self.tokens) >= 512:
                raise ValueError("graphql_scope_unsupported")
            self.tokens.append(token[0])
            position += len(token[0])
        self.position = 0

    def take(self, expected: str | None = None) -> str:
        value = self.tokens[self.position]
        self.position += 1
        if expected is not None and value != expected:
            raise ValueError("graphql_scope_unsupported")
        return value

    def peek(self) -> str | None:
        return self.tokens[self.position] if self.position < len(self.tokens) else None

    def name(self) -> str:
        value = self.take()
        if not NAME.fullmatch(value):
            raise ValueError("graphql_scope_unsupported")
        return value

    def selections(self, depth: int = 0) -> list[tuple[str, str, str]]:
        if depth > 16:
            raise ValueError("graphql_scope_unsupported")
        self.take("{")
        result: list[tuple[str, str, str]] = []
        while self.peek() != "}":
            if self.peek() == "...":
                self.take()
                fragment = self.name()
                if fragment == "on":
                    self.name()  # Type conditions reduce execution, never add fields.
                    result.extend(self.selections(depth + 1))
                else:
                    result.append(("spread", fragment, ""))
            else:
                response_name = field_name = self.name()
                if self.peek() == ":":
                    self.take()
                    field_name = self.name()
                result.append(("field", field_name, response_name))
        self.take("}")
        if not result:
            raise ValueError("graphql_scope_unsupported")
        return result

    def operation(self) -> tuple[str, str, tuple[str, ...]]:
        operation = None
        fragments: dict[str, list[tuple[str, str, str]]] = {}
        while self.peek() is not None:
            kind = self.take()
            if kind in {"query", "mutation"} and operation is None:
                operation = (kind, self.name(), self.selections())
            elif kind == "fragment":
                name = self.name()
                if name == "on" or name in fragments or len(fragments) >= 128:
                    raise ValueError("graphql_scope_unsupported")
                self.take("on")
                self.name()
                fragments[name] = self.selections()
            else:
                raise ValueError("graphql_scope_unsupported")
        if operation is None:
            raise ValueError("graphql_scope_unsupported")
        fields: set[str] = set()
        responses: dict[str, str] = {}
        visited: set[str] = set()

        def expand(nodes, active: frozenset[str] = frozenset()) -> None:
            if len(active) > 16:
                raise ValueError("graphql_scope_unsupported")
            for kind, value, response in nodes:
                if kind == "field":
                    if response in responses and responses[response] != value:
                        raise ValueError("graphql_scope_unsupported")
                    responses[response] = value
                    fields.add(value)
                else:
                    if value in active or value not in fragments:
                        raise ValueError("graphql_scope_unsupported")
                    if value not in visited:
                        expand(fragments[value], active | {value})
                        visited.add(value)

        expand(operation[2])
        if not fields or len(fields) > 128 or visited != set(fragments):
            raise ValueError("graphql_scope_unsupported")
        return operation[0], operation[1], tuple(sorted(fields))


def graphql_operation(query: Any) -> tuple[str, str, tuple[str, ...]] | None:
    """Parse one named operation with flat aliases/fragments; never argument values."""
    if not isinstance(query, str) or len(query) > 4096:
        return None
    try:
        return _GraphQLScopeParser(query).operation()
    except (ValueError, IndexError, RecursionError):
        return None


def _mcp_protocol_version(review: ActionReview) -> str | None:
    version = review.action.parameters.get("protocol_version", "2025-11-25")
    if not isinstance(version, str) or version not in MCP_VERSIONS:
        return None
    declarations = (
        [
            r.metadata.get("versions")
            for r in review.provenance.records
            if r.source == "context"
            and r.code == "runtime.requirement.mcp_versions"
            and r.metadata.get("profile_digest")
            and r.metadata.get("server") == review.action.parameters.get("server")
        ]
        if review.provenance
        else []
    )
    if declarations:
        scopes = []
        for value in declarations:
            if not isinstance(value, str):
                return None
            entries = value.split(",")
            if len(set(entries)) != len(entries) or not set(entries).issubset(MCP_VERSIONS):
                return None
            scopes.append(set(entries))
        return version if all(version in scope for scope in scopes) else None
    return version if version == "2025-11-25" else None


def request_endpoint(url: Any) -> tuple[str, int, str] | None:
    if not isinstance(url, str) or has_unsafe_authority_characters(url):
        return None
    try:
        parsed = urlsplit(url)
        host, port, path = (
            parsed.hostname,
            parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80),
            parsed.path or "/",
        )
        if (
            parsed.scheme not in {"http", "https"}
            or not host
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            return None
        if (
            not 1 <= port <= 65535
            or not _safe_path(path)
            or any(c in path for c in "%?#")
            or "//" in path
        ):
            return None
        NetworkCapability(host, port, "rest", "read", ("POST",), (path,))
        return host, port, path
    except (ValueError, TypeError):
        return None


@dataclass(frozen=True)
class ProtocolRequestCapability:
    protocol: str
    host: str
    port: int
    path: str
    operation_type: str | None = None
    operation_name: str | None = None
    fields: tuple[str, ...] = ()
    server: str | None = None
    method: str | None = None
    tool: str | None = None
    versions: tuple[str, ...] = ()
    requires_argument_constraints: bool = False

    def __post_init__(self) -> None:
        for name in ("fields", "versions"):
            object.__setattr__(self, name, tuple(sorted(text_tuple(getattr(self, name)))))
        validate("protocol_request", self.as_dict())
        if not _safe_path(self.path) or any(c in self.path for c in "%?#") or "//" in self.path:
            raise ValueError("runtime_request_path_unsupported")
        if self.protocol == "graphql":
            if (
                self.operation_type not in {"query", "mutation"}
                or not isinstance(self.operation_name, str)
                or not NAME.fullmatch(self.operation_name)
                or not self.fields
                or any(not NAME.fullmatch(v) for v in self.fields)
            ):
                raise ValueError("runtime_request_graphql_scope_invalid")
            if (
                self.server is not None
                or self.method is not None
                or self.tool is not None
                or self.versions
            ):
                raise ValueError("runtime_request_mixed_protocol_fields")
        else:
            if (
                self.method not in MCP_METHODS
                or not self.server
                or not self.versions
                or not set(self.versions).issubset(MCP_VERSIONS)
            ):
                raise ValueError("runtime_request_mcp_scope_invalid")
            if self.method == "tools/call" and (
                not isinstance(self.tool, str) or not TOOL_NAME.fullmatch(self.tool)
            ):
                raise ValueError("runtime_request_mcp_tool_invalid")
            if self.method != "tools/call" and self.tool is not None:
                raise ValueError("runtime_request_mcp_tool_invalid")
            if self.operation_type is not None or self.operation_name is not None or self.fields:
                raise ValueError("runtime_request_mixed_protocol_fields")
        if len(set(self.fields)) != len(self.fields) or len(set(self.versions)) != len(
            self.versions
        ):
            raise ValueError("runtime_request_duplicate_scope")

    def as_dict(self) -> dict[str, Any]:
        return {
            "protocol": self.protocol,
            "host": self.host,
            "port": self.port,
            "path": self.path,
            "operation_type": self.operation_type,
            "operation_name": self.operation_name,
            "fields": list(self.fields),
            "server": self.server,
            "method": self.method,
            "tool": self.tool,
            "versions": list(self.versions),
            "requires_argument_constraints": self.requires_argument_constraints,
        }


@dataclass(frozen=True)
class RuntimeRequestContract:
    capability: RuntimeCapabilityContract
    requests: tuple[ProtocolRequestCapability, ...]
    request_contract_id: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.capability, RuntimeCapabilityContract):
            raise ValueError("runtime_request_capability_invalid")
        object.__setattr__(self, "requests", model_tuple(self.requests, ProtocolRequestCapability))
        expected = "rq:" + digest(self._material())
        if self.request_contract_id and self.request_contract_id != expected:
            raise ValueError("runtime_request_identity_mismatch")
        object.__setattr__(self, "request_contract_id", expected)
        validate("runtime_request_contract", self.as_dict())

    def _material(self) -> dict:
        return {
            "schema_version": REQUEST_SCHEMA_VERSION,
            "capability": self.capability.as_dict(),
            "requests": [r.as_dict() for r in self.requests],
        }

    def as_dict(self) -> dict:
        return {**self._material(), "request_contract_id": self.request_contract_id}

    @property
    def digest(self) -> str:
        return digest(self.as_dict())

    @classmethod
    def from_dict(cls, value: dict) -> RuntimeRequestContract:
        validate("runtime_request_contract", value)
        return cls(
            RuntimeCapabilityContract.from_dict(value["capability"]),
            tuple(ProtocolRequestCapability(**r) for r in value["requests"]),
            value["request_contract_id"],
        )


@dataclass(frozen=True)
class RuntimeRequestBoundary:
    boundary: RuntimeCapabilityBoundary
    requests: tuple[ProtocolRequestCapability, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.boundary, RuntimeCapabilityBoundary):
            raise ValueError("runtime_request_boundary_invalid")
        object.__setattr__(self, "requests", model_tuple(self.requests, ProtocolRequestCapability))
        validate("runtime_request_boundary", self.as_dict())

    def as_dict(self) -> dict:
        return {
            "schema_version": REQUEST_BOUNDARY_SCHEMA_VERSION,
            "boundary": self.boundary.as_dict(),
            "requests": [r.as_dict() for r in self.requests],
        }

    @property
    def digest(self) -> str:
        return digest(self.as_dict())

    @classmethod
    def from_dict(cls, value: dict) -> RuntimeRequestBoundary:
        validate("runtime_request_boundary", value)
        return cls(
            RuntimeCapabilityBoundary.from_dict(value["boundary"]),
            tuple(ProtocolRequestCapability(**r) for r in value["requests"]),
        )


@dataclass(frozen=True)
class RequestVerificationResult:
    result: str
    reason_code: str
    contract_digest: str
    boundary_digest: str
    coverage: Any
    counterexample: Any = None
    unsupported_fields: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if set(self.coverage) != set(DOMAINS) | {"requests"} or any(
            type(v) is not bool for v in self.coverage.values()
        ):
            raise ValueError("runtime_request_coverage_invalid")
        CapabilityVerificationResult(
            self.result,
            self.reason_code,
            self.contract_digest,
            self.boundary_digest,
            {d: self.coverage[d] for d in DOMAINS},
            self.counterexample,
            self.unsupported_fields,
        )
        object.__setattr__(self, "coverage", freeze(self.coverage))
        object.__setattr__(self, "counterexample", freeze(self.counterexample))
        object.__setattr__(self, "unsupported_fields", text_tuple(self.unsupported_fields))

    @property
    def ok(self) -> bool:
        return self.result == "within_boundary"

    def as_dict(self) -> dict:
        return {
            "result": self.result,
            "reason_code": self.reason_code,
            "contract_digest": self.contract_digest,
            "boundary_digest": self.boundary_digest,
            "coverage": thaw(self.coverage),
            "counterexample": thaw(self.counterexample),
            "unsupported_fields": list(self.unsupported_fields),
        }


def derive_runtime_request_contract(review: ActionReview) -> RuntimeRequestContract:
    capability = derive_runtime_capability_contract(review)
    requests = []
    if review.adapter == "network.graphql":
        parsed = graphql_operation(review.action.parameters.get("query"))
        if parsed is not None:
            for net in capability.network:
                if net.protocol == "graphql" and net.host and net.port and len(net.paths) == 1:
                    requests.append(
                        ProtocolRequestCapability(
                            "graphql", net.host, net.port, net.paths[0], *parsed
                        )
                    )
    if review.action.kind == "mcp" and review.adapter and review.effects:
        server, tool = review.action.parameters.get("server"), review.action.parameters.get("tool")
        version = _mcp_protocol_version(review)
        method = (
            review.action.parameters.get("method")
            if review.adapter == "mcp.protocol"
            else "tools/call"
        )
        for net in capability.network:
            if (
                net.protocol == "mcp"
                and net.host
                and net.port
                and len(net.paths) == 1
                and isinstance(server, str)
                and version is not None
                and (review.adapter == "mcp.protocol" or isinstance(tool, str))
            ):
                requests.append(
                    ProtocolRequestCapability(
                        "mcp",
                        net.host,
                        net.port,
                        net.paths[0],
                        server=server,
                        method=method,
                        tool=tool,
                        versions=(version,),
                        requires_argument_constraints=bool(
                            review.action.parameters.get("arguments")
                            or review.action.parameters.get("params")
                        ),
                    )
                )
    return RuntimeRequestContract(capability, tuple(requests))


def request_contract_errors(contract: RuntimeRequestContract) -> tuple[str, ...]:
    errors = []
    mapped_tools = set()
    for request in contract.requests:
        if request.requires_argument_constraints:
            errors.append("requests.argument_constraints_unrepresentable")
        matches = [
            n
            for n in contract.capability.network
            if n.protocol == request.protocol
            and n.host == request.host
            and n.port == request.port
            and n.paths == (request.path,)
            and n.methods == ("POST",)
        ]
        if not matches:
            errors.append("requests.endpoint_contract_mismatch")
        if request.protocol == "graphql" and any(
            n.access != ("read" if request.operation_type == "query" else "write") for n in matches
        ):
            errors.append("requests.graphql_access_mismatch")
        if request.protocol == "mcp" and request.method == "tools/call":
            mapped_tools.add(("mcp", request.server, request.tool, "call"))
    for net in contract.capability.network:
        if net.protocol in {"mcp", "graphql"} and net.tool_identity is not None:
            errors.append("requests.opaque_tool_identity_unrepresentable")
        if net.protocol in {"mcp", "graphql"} and not any(
            r.protocol == net.protocol
            and r.host == net.host
            and r.port == net.port
            and net.paths == (r.path,)
            for r in contract.requests
        ):
            errors.append("requests.missing_restrictions")
    if any(
        (t.runtime, t.server, t.tool, t.operation) not in mapped_tools
        for t in contract.capability.tools
    ):
        errors.append("requests.tool_contract_mismatch")
    return tuple(sorted(set(errors)))


def verify_runtime_request_capability(
    contract: RuntimeRequestContract, boundary: RuntimeRequestBoundary
) -> RequestVerificationResult:
    if not isinstance(contract, RuntimeRequestContract) or not isinstance(
        boundary, RuntimeRequestBoundary
    ):
        raise ValueError("runtime_request_verification_input_invalid")
    errors = request_contract_errors(contract)
    if any(
        n.protocol in {"graphql", "mcp"} and n.tool_identity is not None
        for n in boundary.boundary.network
    ):
        errors += ("requests.boundary_opaque_tool_identity_unrepresentable",)
    for allowed in boundary.requests:
        if not any(
            n.protocol == allowed.protocol
            and n.host == allowed.host
            and n.port == allowed.port
            and "POST" in n.methods
            and any(
                allowed.path == p or p.endswith("/**") and allowed.path.startswith(p[:-2])
                for p in n.paths
            )
            for n in boundary.boundary.network
        ):
            errors += ("requests.boundary_transport_mismatch",)
    if errors:
        return RequestVerificationResult(
            "unsupported",
            "runtime_request_unsupported",
            contract.digest,
            boundary.digest,
            {**{d: False for d in DOMAINS}, "requests": False},
            unsupported_fields=errors,
        )

    # Core verifies every existing domain and the exact transport. The additional
    # request model independently checks high-level method/name/field authority.
    def transport(net):
        return (
            replace(net, protocol="rest", tool_identity=None)
            if net.protocol in {"mcp", "graphql"}
            else net
        )

    candidate = replace(
        contract.capability,
        contract_id="",
        network=tuple(transport(n) for n in contract.capability.network),
    )
    maximum = replace(
        boundary.boundary, network=tuple(transport(n) for n in boundary.boundary.network)
    )
    core = verify_runtime_capability(candidate, maximum)
    if core.ok:
        # Projection preserves request transport but erases protocol identity.
        # Verify each original protocol against its own grants before accepting
        # the aggregate result, so raw HTTP cannot borrow GraphQL/MCP authority.
        for protocol in sorted({n.protocol for n in contract.capability.network}):
            scoped = verify_runtime_capability(
                replace(
                    candidate,
                    contract_id="",
                    network=tuple(
                        transport(n) for n in contract.capability.network if n.protocol == protocol
                    ),
                ),
                replace(
                    maximum,
                    network=tuple(
                        transport(n)
                        for n in boundary.boundary.network
                        if n.protocol in {protocol, "tcp"}
                    ),
                ),
            )
            if not scoped.ok:
                core = scoped
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
        within = any(
            (request.protocol, request.host, request.port, request.path)
            == (allowed.protocol, allowed.host, allowed.port, allowed.path)
            and not allowed.requires_argument_constraints
            and (
                request.operation_type == allowed.operation_type
                and request.operation_name == allowed.operation_name
                and set(request.fields).issubset(allowed.fields)
                if request.protocol == "graphql"
                else request.server == allowed.server
                and request.method == allowed.method
                and request.tool == allowed.tool
                and set(request.versions).issubset(allowed.versions)
            )
            for allowed in boundary.requests
        )
        if not within:
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
