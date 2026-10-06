"""Verified backend candidates for core denial proposals; no approval/apply/retry."""

from __future__ import annotations

import hashlib
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Mapping

from ordin._runtime_json import MAX_RUNTIME_BYTES, canonical_json, digest
from ordin.action import ActionReview
from ordin.capability_delta import CapabilityDeltaProposal, propose_capability_delta
from ordin.enforcement_backend import EnforcementPlan
from ordin.runtime_boundary import RuntimeCapabilityBoundary, verify_runtime_capability
from ordin.runtime_contract import RuntimeCapabilityContract
from ordin.runtime_observation import RuntimeObservation

from .apply import policy_bytes
from .compiler import OpenShellBackend
from .prover import MODELED_DOMAINS, verify_with_openshell_prover


@dataclass(frozen=True)
class OpenShellDeltaResult:
    proposal: CapabilityDeltaProposal
    candidate: EnforcementPlan | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "proposal": self.proposal.as_dict(),
            "candidate": self.candidate.as_dict() if self.candidate else None,
        }


def propose_openshell_delta(
    review: ActionReview,
    contract: RuntimeCapabilityContract,
    denial: RuntimeObservation,
    boundary: RuntimeCapabilityBoundary,
    *,
    backend: OpenShellBackend,
    backend_boundary_policy: Mapping[str, Any] | None = None,
    prover_executable: str = "openshell-prover",
) -> OpenShellDeltaResult:
    proposal = propose_capability_delta(review, contract, denial, boundary)
    if proposal.status == "rejected" or proposal.requested_delta is None:
        return OpenShellDeltaResult(proposal)
    requested = proposal.requested_delta
    # A delta is not a whole runtime policy: retain reviewed deployment/startup
    # requirements when constructing the would-be backend policy. The proposed
    # permission itself remains the original narrow core artifact.
    changes: dict[str, Any] = {"contract_id": "", "unknowns": requested.unknowns}
    for name in ("filesystem", "network", "tools", "credentials"):
        narrowed = getattr(requested, name)
        if narrowed:
            changes[name] = narrowed
    if requested.process.executables:
        changes["process"] = requested.process
    candidate_contract = replace(contract, **changes)
    steps = list(proposal.verification)

    def reject(code: str) -> OpenShellDeltaResult:
        return OpenShellDeltaResult(
            replace(
                proposal,
                requested_delta=None,
                reason_code=code,
                status="rejected",
                verification=tuple(steps),
                proposal_id="",
            )
        )

    full = verify_runtime_capability(candidate_contract, boundary)
    steps.append(
        {
            "step": "candidate_capability_boundary",
            "result": full.result,
            "reason_code": full.reason_code,
            "details": {
                "contract_digest": full.contract_digest,
                "boundary_digest": full.boundary_digest,
                "coverage": dict(full.coverage),
                "unsupported_fields": list(full.unsupported_fields),
            },
        }
    )
    if not full.ok:
        return reject("runtime_delta_boundary_rejected")
    compiled = backend.compile(candidate_contract)
    steps.append(
        {
            "step": "openshell_compile",
            "result": compiled.status,
            "reason_code": compiled.reason_code,
            "details": {"unsupported_fields": list(compiled.unsupported_fields)},
        }
    )
    if compiled.status != "success" or compiled.plan is None:
        return reject("runtime_delta_backend_rejected")
    plan = compiled.plan
    validated = backend.validate(plan)
    steps.append(
        {
            "step": "openshell_validation",
            "result": validated.status,
            "reason_code": validated.reason_code,
            "details": validated.as_dict(),
        }
    )
    if not validated.ok:
        return reject("runtime_delta_backend_rejected")
    if backend_boundary_policy is not None:
        boundary_bytes = (canonical_json(backend_boundary_policy) + "\n").encode()
        if len(boundary_bytes) > MAX_RUNTIME_BYTES:
            return reject("runtime_delta_backend_boundary_invalid")
        with tempfile.TemporaryDirectory(prefix="ordin-delta-proof-") as directory:
            candidate_path, boundary_path = (
                Path(directory) / "candidate.json",
                Path(directory) / "boundary.json",
            )
            candidate_path.write_bytes(policy_bytes(plan))
            boundary_path.write_bytes(boundary_bytes)
            candidate_path.chmod(0o600)
            boundary_path.chmod(0o600)
            required = MODELED_DOMAINS | ({"credentials"} if plan.contract.credentials else set())
            proof = verify_with_openshell_prover(
                candidate_path,
                boundary_path,
                executable=prover_executable,
                required_domains=frozenset(required),
            )
        report = proof.as_dict()
        counterexample = report.pop("counterexample")
        report["counterexample_digest"] = (
            digest(counterexample) if counterexample is not None else None
        )
        steps.append(
            {
                "step": "openshell_prover",
                "result": proof.result,
                "reason_code": proof.reason_code,
                "details": report,
            }
        )
        if (
            not proof.ok
            or proof.candidate_digest != hashlib.sha256(policy_bytes(plan)).hexdigest()
            or proof.boundary_digest != hashlib.sha256(boundary_bytes).hexdigest()
        ):
            return reject("runtime_delta_backend_proof_rejected")
    return OpenShellDeltaResult(replace(proposal, verification=tuple(steps), proposal_id=""), plan)
