"""Pure minimal denial proposals. Core never approves, applies, or retries."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Mapping

from ._runtime_json import digest, freeze, thaw, validate
from .action import ActionHistory, ActionReview
from .enforcement_backend import EnforcementBackend
from .runtime_boundary import RuntimeCapabilityBoundary, verify_runtime_capability
from .runtime_contract import (
    CredentialBinding,
    FilesystemCapability,
    NetworkCapability,
    ProcessCapability,
    RuntimeCapabilityContract,
    ToolCapability,
    _safe_path,
    derive_runtime_capability_contract,
)
from .runtime_observation import RuntimeObservation, RuntimeObservationHistory

CAPABILITY_DELTA_PROPOSAL_SCHEMA_VERSION = "ordin.capability_delta_proposal.v1"


@dataclass(frozen=True)
class CapabilityDeltaProposal:
    action_id: str
    action_digest: str
    contract_id: str
    denial_observation_id: str
    requested_delta: RuntimeCapabilityContract | None
    reason_code: str
    verification: tuple[Mapping[str, Any], ...] = ()
    requires_human_approval: bool = True
    status: str = "requires_approval"
    proposal_id: str = ""

    def __post_init__(self) -> None:
        if self.requested_delta is not None and not isinstance(
            self.requested_delta, RuntimeCapabilityContract
        ):
            raise ValueError("proposal requires a typed requested capability state")
        object.__setattr__(self, "verification", freeze(self.verification))
        expected = "dp:" + digest(self._material())
        if self.proposal_id and self.proposal_id != expected:
            raise ValueError("proposal identity does not match content")
        object.__setattr__(self, "proposal_id", expected)
        validate("capability_delta_proposal", self.as_dict())
        if self.status != "rejected" and not self.requires_human_approval:
            raise ValueError("initial capability proposals require human approval")

    def _material(self) -> dict[str, Any]:
        return {
            "schema_version": CAPABILITY_DELTA_PROPOSAL_SCHEMA_VERSION,
            "action_id": self.action_id,
            "action_digest": self.action_digest,
            "contract_id": self.contract_id,
            "denial_observation_id": self.denial_observation_id,
            "requested_delta": self.requested_delta.as_dict() if self.requested_delta else None,
            "reason_code": self.reason_code,
            "verification": thaw(self.verification),
            "requires_human_approval": self.requires_human_approval,
            "status": self.status,
        }

    def as_dict(self) -> dict[str, Any]:
        return {**self._material(), "proposal_id": self.proposal_id}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> CapabilityDeltaProposal:
        validate("capability_delta_proposal", payload)
        return cls(
            action_id=payload["action_id"],
            action_digest=payload["action_digest"],
            contract_id=payload["contract_id"],
            denial_observation_id=payload["denial_observation_id"],
            requested_delta=RuntimeCapabilityContract.from_dict(payload["requested_delta"])
            if payload["requested_delta"]
            else None,
            reason_code=payload["reason_code"],
            verification=tuple(payload["verification"]),
            requires_human_approval=payload["requires_human_approval"],
            status=payload["status"],
            proposal_id=payload["proposal_id"],
        )


def propose_capability_delta(
    review: ActionReview,
    contract: RuntimeCapabilityContract,
    denial: RuntimeObservation,
    boundary: RuntimeCapabilityBoundary,
    *,
    backend: EnforcementBackend | None = None,
) -> CapabilityDeltaProposal:
    """Propose only an already-predicted requirement, narrowed by trusted denial.

    The boundary is the operator's maximum, not proof of the currently active
    policy. Backend verification is explicit when a backend is supplied. Every
    proposal requires human approval; no core state becomes approved/applied.
    """
    action_id = review.action.action_id
    if action_id is None:
        raise ValueError("capability proposal requires a reviewed action ID")

    def rejected(
        code: str, verification: tuple[Mapping[str, Any], ...] = ()
    ) -> CapabilityDeltaProposal:
        return CapabilityDeltaProposal(
            action_id,
            contract.action_digest,
            contract.contract_id,
            denial.observation_id,
            None,
            code,
            verification,
            True,
            "rejected",
        )

    if derive_runtime_capability_contract(review) != contract:
        return rejected("runtime_observation_contract_mismatch")
    try:
        RuntimeObservationHistory((denial,), (contract,)).correlate(ActionHistory((review.action,)))
    except ValueError:
        return rejected("runtime_observation_action_mismatch")
    if review.provenance is not None:
        scopes = [
            r.metadata.get("session_digest")
            for r in review.provenance.records
            if r.code == "runtime.session.review"
        ]
        if scopes and denial.session_digest != scopes[-1]:
            return rejected("runtime_observation_session_mismatch")
    if denial.trust != "backend_enforced" or denial.outcome != "denied":
        return rejected("runtime_delta_untrusted_denial")
    if review.decision == "block":
        return rejected("runtime_delta_blocked_action")
    fs: tuple[FilesystemCapability, ...] = ()
    net: tuple[NetworkCapability, ...] = ()
    tools: tuple[ToolCapability, ...] = ()
    credentials: tuple[CredentialBinding, ...] = ()
    process = ProcessCapability(False)
    domain = denial.enforcement_point

    if domain == "filesystem":
        paths = [r.value for r in denial.resources if r.type in {"path", "file", "directory"}]
        operations = {
            "filesystem.read": "read",
            "filesystem.metadata_read": "metadata",
            "filesystem.write": "write",
            "filesystem.delete": "delete",
            "filesystem.execute": "execute",
        }
        access = operations.get(denial.operation)
        if len(paths) != 1 or access is None or not _safe_path(paths[0]):
            return rejected("runtime_delta_unmodeled_requirement")
        path = paths[0]
        predicted = [
            c
            for c in contract.filesystem
            if c.access == access
            and (
                c.path is None
                or c.path == path
                or c.scope == "prefix"
                and path.startswith(c.path.rstrip("/") + "/")
            )
        ]
        if not predicted:
            return rejected("runtime_delta_unmodeled_requirement")
        fs = (FilesystemCapability(access, path, "exact"),)
    elif domain == "network":
        host, port = denial.metadata.get("host"), denial.metadata.get("port")
        method, network_path = denial.metadata.get("method"), denial.metadata.get("path")
        if (
            not isinstance(host, str)
            or type(port) is not int
            or not isinstance(method, str)
            or not isinstance(network_path, str)
        ):
            return rejected("runtime_delta_unmodeled_requirement")
        access = "read" if method in {"GET", "HEAD", "OPTIONS"} else "write"
        predicted_network = [
            c
            for c in contract.network
            if c.host == host
            and c.port in {None, port}
            and c.protocol in {"unknown", "rest"}
            and (c.access == access or c.access == "write" and access == "read")
            and (not c.methods or method in c.methods)
            and (not c.paths or network_path in c.paths)
        ]
        if not predicted_network:
            return rejected("runtime_delta_unmodeled_requirement")
        net = (NetworkCapability(host, port, "rest", access, (method,), (network_path,)),)
        binary = denial.metadata.get("binary")
        if contract.process.execution:
            if (
                not isinstance(binary, str)
                or binary not in contract.process.executables
                or not _safe_path(binary)
            ):
                return rejected("runtime_delta_unmodeled_requirement")
            process = ProcessCapability(True, (binary,), contract.process.spawn_children)
    elif domain == "tool":
        identities = [r.value for r in denial.resources if r.type == "tool"]
        matches = [
            t for t in contract.tools if identities == [f"{t.runtime}:{t.server or ''}:{t.tool}"]
        ]
        if len(matches) != 1:
            return rejected("runtime_delta_unmodeled_requirement")
        tools = (matches[0],)
    elif domain == "credential":
        bindings = [r.value for r in denial.resources if r.type == "credential"]
        matching_credentials = [
            c
            for c in contract.credentials
            if bindings == [c.binding]
            and denial.metadata.get("host") == c.host
            and denial.metadata.get("port") == c.port
        ]
        if len(matching_credentials) != 1:
            return rejected("runtime_delta_unmodeled_requirement")
        credentials = (matching_credentials[0],)
    else:
        return rejected("runtime_delta_unmodeled_requirement")
    # Keep uncertainty in unrelated semantic domains. Narrowing one denial must
    # not erase unresolved facts or the original decision/policy requirement.
    related = "credential" if domain == "credential" else domain
    refinable = {
        "runtime_contract_missing_resource",
        "runtime_contract_malformed_resource",
        "runtime_contract_unknown_protocol",
    }
    unknowns = tuple(
        u for u in contract.unknowns if u.domain != related or u.reason_code not in refinable
    )
    requested = replace(
        contract,
        contract_id="",
        filesystem=fs,
        network=net,
        tools=tools,
        credentials=credentials,
        process=process,
        unknowns=unknowns,
    )
    verification = verify_runtime_capability(requested, boundary)
    steps: list[Mapping[str, Any]] = [
        {
            "step": "capability_boundary",
            "result": verification.result,
            "reason_code": verification.reason_code,
            "details": verification.as_dict(),
        }
    ]
    if not verification.ok:
        return rejected("runtime_delta_boundary_rejected", tuple(steps))
    if backend is not None:
        compiled = backend.compile(requested)
        steps.append(
            {
                "step": "backend_compile",
                "result": compiled.status,
                "reason_code": compiled.reason_code,
                "details": {"unsupported_fields": list(compiled.unsupported_fields)},
            }
        )
        if compiled.status != "success" or compiled.plan is None:
            return rejected("runtime_delta_backend_rejected", tuple(steps))
        validated = backend.validate(compiled.plan)
        steps.append(
            {
                "step": "backend_validation",
                "result": validated.status,
                "reason_code": validated.reason_code,
                "details": validated.as_dict(),
            }
        )
        if not validated.ok or validated.policy_digest != compiled.plan.policy_digest:
            return rejected("runtime_delta_backend_rejected", tuple(steps))
    return CapabilityDeltaProposal(
        action_id,
        contract.action_digest,
        contract.contract_id,
        denial.observation_id,
        requested,
        "runtime_delta_requires_approval",
        tuple(steps),
        True,
        "requires_approval",
    )
