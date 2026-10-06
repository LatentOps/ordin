"""Conservative capability subset checks, never a kernel-enforcement proof."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from ._runtime_json import digest, freeze, model_tuple, text_tuple, thaw, validate
from .runtime_contract import (
    CredentialBinding,
    FilesystemCapability,
    NetworkCapability,
    PrivilegeCapability,
    ProcessCapability,
    RuntimeCapabilityContract,
    ToolCapability,
    _safe_path,
)

RUNTIME_CAPABILITY_BOUNDARY_SCHEMA_VERSION = "ordin.runtime_capability_boundary.v1"
DOMAINS = ("filesystem", "network", "tools", "process", "privilege", "credentials")
# Access is atomic. Read also includes metadata lookup; write does not implicitly
# grant read, delete, or execution. These are semantic rights, not kernel flags.
FILESYSTEM_RIGHTS = {
    "read": frozenset({"read", "metadata"}),
    "metadata": frozenset({"metadata"}),
    "write": frozenset({"write"}),
    "delete": frozenset({"delete"}),
    "execute": frozenset({"execute"}),
}
NETWORK_RIGHTS = {"read": frozenset({"read"}), "write": frozenset({"read", "write"})}


@dataclass(frozen=True)
class RuntimeCapabilityBoundary:
    boundary_id: str
    filesystem: tuple[FilesystemCapability, ...] = ()
    network: tuple[NetworkCapability, ...] = ()
    tools: tuple[ToolCapability, ...] = ()
    process: ProcessCapability = field(default_factory=ProcessCapability)
    privilege: PrivilegeCapability = field(default_factory=PrivilegeCapability)
    credentials: tuple[CredentialBinding, ...] = ()
    filesystem_semantics: str = "exact"
    runtime_filesystem_guarantees: bool = False
    allow_any_executable: bool = False

    def __post_init__(self) -> None:
        for name, model in (
            ("filesystem", FilesystemCapability),
            ("network", NetworkCapability),
            ("tools", ToolCapability),
            ("credentials", CredentialBinding),
        ):
            object.__setattr__(self, name, model_tuple(getattr(self, name), model))
        if not isinstance(self.process, ProcessCapability) or not isinstance(
            self.privilege, PrivilegeCapability
        ):
            raise ValueError("boundary requires typed process and privilege capabilities")
        validate("runtime_capability_boundary", self.as_dict())

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": RUNTIME_CAPABILITY_BOUNDARY_SCHEMA_VERSION,
            "boundary_id": self.boundary_id,
            "filesystem": [v.as_dict() for v in self.filesystem],
            "network": [v.as_dict() for v in self.network],
            "tools": [v.as_dict() for v in self.tools],
            "process": self.process.as_dict(),
            "privilege": self.privilege.as_dict(),
            "credentials": [v.as_dict() for v in self.credentials],
            "filesystem_semantics": self.filesystem_semantics,
            "runtime_filesystem_guarantees": self.runtime_filesystem_guarantees,
            "allow_any_executable": self.allow_any_executable,
        }

    @property
    def digest(self) -> str:
        return digest(self.as_dict())

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> RuntimeCapabilityBoundary:
        validate("runtime_capability_boundary", payload)
        return cls(
            boundary_id=payload["boundary_id"],
            filesystem=tuple(FilesystemCapability(**v) for v in payload["filesystem"]),
            network=tuple(NetworkCapability(**v) for v in payload["network"]),
            tools=tuple(ToolCapability(**v) for v in payload["tools"]),
            process=ProcessCapability(**payload["process"]),
            privilege=PrivilegeCapability(**payload["privilege"]),
            credentials=tuple(CredentialBinding(**v) for v in payload["credentials"]),
            filesystem_semantics=payload["filesystem_semantics"],
            runtime_filesystem_guarantees=payload["runtime_filesystem_guarantees"],
            allow_any_executable=payload["allow_any_executable"],
        )


@dataclass(frozen=True)
class CapabilityVerificationResult:
    result: str
    reason_code: str
    contract_digest: str
    boundary_digest: str
    coverage: Mapping[str, bool]
    counterexample: Mapping[str, Any] | None = None
    unsupported_fields: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.result not in {
            "within_boundary",
            "exceeds_boundary",
            "unsupported",
            "inconclusive",
        }:
            raise ValueError("invalid boundary verification state")
        if set(self.coverage) != set(DOMAINS) or any(
            type(v) is not bool for v in self.coverage.values()
        ):
            raise ValueError("boundary verification requires complete domain coverage flags")
        object.__setattr__(self, "coverage", freeze(self.coverage))
        if self.counterexample is not None:
            object.__setattr__(self, "counterexample", freeze(self.counterexample))
        object.__setattr__(self, "unsupported_fields", text_tuple(self.unsupported_fields))
        if self.result == "within_boundary" and (
            not all(self.coverage.values()) or self.unsupported_fields
        ):
            raise ValueError(
                "within_boundary requires complete coverage without unsupported fields"
            )

    @property
    def ok(self) -> bool:
        return self.result == "within_boundary"

    def as_dict(self) -> dict[str, Any]:
        return {
            "result": self.result,
            "reason_code": self.reason_code,
            "contract_digest": self.contract_digest,
            "boundary_digest": self.boundary_digest,
            "coverage": thaw(self.coverage),
            "counterexample": thaw(self.counterexample),
            "unsupported_fields": list(self.unsupported_fields),
        }


def _request_path(path: str, *, pattern: bool = False) -> bool:
    if not _safe_path(path.replace("/**", "/placeholder") if pattern else path):
        return False
    if "%" in path or "#" in path or "?" in path or "//" in path:
        return False
    return "*" not in path or (pattern and path.endswith("/**") and path.count("*") == 2)


def _rest_path_within(candidate: str, boundary: str) -> bool:
    return candidate == boundary or (
        boundary.endswith("/**") and candidate.startswith(boundary[:-2])
    )


def verify_runtime_capability(
    contract: RuntimeCapabilityContract,
    boundary: RuntimeCapabilityBoundary,
) -> CapabilityVerificationResult:
    """Verify an intended capability subset without filesystem/DNS/runtime access."""
    if not isinstance(contract, RuntimeCapabilityContract) or not isinstance(
        boundary, RuntimeCapabilityBoundary
    ):
        raise ValueError("boundary verification requires typed contract and boundary")
    coverage = {domain: True for domain in DOMAINS}
    findings: list[tuple[str, str, dict[str, Any]]] = []
    unsupported: set[str] = set()

    def fail(state: str, code: str, domain: str, value: Any = None) -> None:
        findings.append((state, code, {"domain": domain, "value": value}))
        if state in {"unsupported", "inconclusive"}:
            coverage[domain] = False
            unsupported.add(code)

    if contract.decision == "block":
        fail("exceeds_boundary", "runtime_boundary_blocked_decision", "process")
    for unknown in contract.unknowns:
        domains = (
            DOMAINS
            if unknown.domain == "semantics"
            else (
                "credentials"
                if unknown.domain == "credential"
                else "tools"
                if unknown.domain == "tool"
                else unknown.domain,
            )
        )
        for domain in domains:
            fail("unsupported", unknown.reason_code, domain)

    for capability in contract.filesystem:
        if (
            capability.access not in FILESYSTEM_RIGHTS
            or capability.path is None
            or not _safe_path(capability.path)
            or capability.scope == "unknown"
        ):
            fail("unsupported", "runtime_boundary_filesystem_scope_unsupported", "filesystem")
            continue
        matches = []
        unresolved = False
        for maximum in boundary.filesystem:
            if (
                maximum.access not in FILESYSTEM_RIGHTS
                or maximum.path is None
                or not _safe_path(maximum.path)
                or maximum.scope == "unknown"
            ):
                unresolved = True
                continue
            if not FILESYSTEM_RIGHTS[capability.access].issubset(FILESYSTEM_RIGHTS[maximum.access]):
                continue
            if maximum.path == capability.path and (
                maximum.scope == "prefix" or capability.scope == "exact"
            ):
                matches.append(maximum)
            elif maximum.scope == "prefix" and capability.path.startswith(
                maximum.path.rstrip("/") + "/"
            ):
                if (
                    boundary.filesystem_semantics == "lexical_prefix"
                    and boundary.runtime_filesystem_guarantees
                ):
                    matches.append(maximum)
                else:
                    unresolved = True
        if not matches:
            fail(
                "unsupported" if unresolved else "exceeds_boundary",
                "runtime_boundary_filesystem_prefix_unproven"
                if unresolved
                else "filesystem_access_exceeds_boundary",
                "filesystem",
                capability.as_dict(),
            )

    for network_capability in contract.network:
        if (
            network_capability.host is None
            or network_capability.port is None
            or network_capability.protocol == "unknown"
            or network_capability.access not in NETWORK_RIGHTS
        ):
            fail("inconclusive", "runtime_boundary_network_unknown", "network")
            continue
        if network_capability.protocol not in {"rest", "tcp"}:
            fail(
                "unsupported",
                "runtime_boundary_protocol_unsupported",
                "network",
                network_capability.protocol,
            )
            continue
        if network_capability.protocol == "tcp" and (
            network_capability.methods
            or network_capability.paths
            or network_capability.tool_identity
        ):
            fail("unsupported", "runtime_boundary_tcp_request_restriction", "network")
            continue
        if network_capability.protocol == "rest" and (
            not network_capability.methods
            or not network_capability.paths
            or any(not _request_path(p) for p in network_capability.paths)
        ):
            fail("unsupported", "runtime_boundary_request_scope_unsupported", "network")
            continue
        maxima = [
            m
            for m in boundary.network
            if m.host == network_capability.host and m.port == network_capability.port
        ]
        if not maxima:
            fail(
                "exceeds_boundary",
                "network_endpoint_exceeds_boundary",
                "network",
                network_capability.as_dict(),
            )
            continue
        # A TCP boundary is explicitly broader than request-level access. The
        # reverse cannot pass. Candidate REST never compiles to TCP here.
        matched = False
        unmodeled = False
        rest_maxima = []
        for network_maximum in maxima:
            if (
                network_maximum.access not in NETWORK_RIGHTS
                or network_maximum.protocol == "unknown"
            ):
                unmodeled = True
                continue
            if not NETWORK_RIGHTS[network_capability.access].issubset(
                NETWORK_RIGHTS[network_maximum.access]
            ):
                continue
            if network_capability.tool_identity != network_maximum.tool_identity:
                continue
            if network_maximum.protocol == "tcp":
                if not network_maximum.methods and not network_maximum.paths:
                    matched = True
            elif network_capability.protocol == network_maximum.protocol == "rest":
                if any(not _request_path(p, pattern=True) for p in network_maximum.paths):
                    unmodeled = True
                    continue
                rest_maxima.append(network_maximum)
        if not matched and network_capability.protocol == "rest":
            comparisons = 0
            all_pairs = True
            exhausted = False
            for method in set(network_capability.methods):
                for path in set(network_capability.paths):
                    covered = False
                    for network_maximum in rest_maxima:
                        if method not in network_maximum.methods:
                            continue
                        for allowed in set(network_maximum.paths):
                            comparisons += 1
                            if comparisons > 50_000:
                                exhausted = True
                                break
                            if _rest_path_within(path, allowed):
                                covered = True
                                break
                        if covered or exhausted:
                            break
                    if not covered:
                        all_pairs = False
                    if exhausted:
                        break
                if exhausted:
                    break
            if exhausted:
                fail("inconclusive", "runtime_boundary_resource_limit", "network")
                continue
            matched = all_pairs
        if not matched:
            fail(
                "unsupported" if unmodeled else "exceeds_boundary",
                "runtime_boundary_network_scope_unsupported"
                if unmodeled
                else "network_request_exceeds_boundary",
                "network",
                network_capability.as_dict(),
            )

    for tool in contract.tools:
        if tool not in boundary.tools:
            fail("exceeds_boundary", "tool_identity_exceeds_boundary", "tools", tool.as_dict())

    process = contract.process
    maximum_process = boundary.process
    if process.execution is None:
        fail("inconclusive", "runtime_boundary_process_unknown", "process")
    elif process.execution:
        if maximum_process.execution is False:
            fail("exceeds_boundary", "process_execution_exceeds_boundary", "process")
        elif maximum_process.execution is None:
            fail("inconclusive", "runtime_boundary_process_unknown", "process")
        if not process.executables or any(not _safe_path(p) for p in process.executables):
            fail("unsupported", "runtime_boundary_binary_identity_missing", "process")
        elif not boundary.allow_any_executable and not set(process.executables).issubset(
            maximum_process.executables
        ):
            fail(
                "exceeds_boundary",
                "process_binary_exceeds_boundary",
                "process",
                list(process.executables),
            )
        if process.spawn_children is None and maximum_process.spawn_children is not True:
            fail("inconclusive", "runtime_boundary_child_process_unknown", "process")
        elif process.spawn_children is True and maximum_process.spawn_children is not True:
            fail("exceeds_boundary", "process_children_exceeds_boundary", "process")

    privilege = contract.privilege
    maximum_privilege = boundary.privilege
    if privilege.escalation is None:
        fail("inconclusive", "runtime_boundary_privilege_unknown", "privilege")
    elif privilege.escalation and maximum_privilege.escalation is not True:
        fail("exceeds_boundary", "privilege_escalation_exceeds_boundary", "privilege")
    if (
        maximum_privilege.required_euid is not None
        and privilege.required_euid != maximum_privilege.required_euid
    ):
        fail(
            "inconclusive" if privilege.required_euid is None else "exceeds_boundary",
            "runtime_boundary_uid_unproven",
            "privilege",
        )
    for credential in contract.credentials:
        if credential not in boundary.credentials:
            fail(
                "exceeds_boundary",
                "credential_binding_exceeds_boundary",
                "credentials",
                credential.as_dict(),
            )

    if findings:
        priority = {"exceeds_boundary": 3, "unsupported": 2, "inconclusive": 1}
        state, code, counterexample = max(findings, key=lambda v: priority[v[0]])
    else:
        state, code, counterexample = "within_boundary", "runtime_boundary_within", None
    return CapabilityVerificationResult(
        state,
        code,
        contract.digest,
        boundary.digest,
        coverage,
        counterexample,
        tuple(sorted(unsupported)),
    )
