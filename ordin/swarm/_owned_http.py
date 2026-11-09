"""Closed full-REST plans and bounded HTTP framing; no authority projection."""

from dataclasses import dataclass
from typing import Any, Mapping

from ordin._runtime_json import digest, freeze, thaw
from ordin.assurance.rest import EXACT_REQUIREMENT, RestRequestContract


@dataclass(frozen=True, eq=False)
class OwnedRequestPlan:
    backend: str
    complete: RestRequestContract
    policy: Mapping[str, Any]
    mode: str = "enforce"

    def __post_init__(self):
        if (
            type(self.complete) is not RestRequestContract
            or self.backend != "linux-owned-tools-v1"
            or self.mode != "enforce"
        ):
            raise ValueError("closed original complete REST plan required")
        capability = self.complete.capability
        if (
            capability.decision != "allow"
            or capability._approval_lease is not None
            or len(capability.unknowns) != 1
            or capability.unknowns[0].domain != "network"
            or capability.unknowns[0].reason_code != EXACT_REQUIREMENT
        ):
            raise ValueError("unresolved REST authority cannot form an owned plan")
        object.__setattr__(self, "policy", freeze(self.policy))

    @property
    def contract(self):
        # Preserve the original diagnostic capability for session correlation.
        # Full authority is always carried by complete, never this projection.
        return self.complete.capability

    @property
    def policy_digest(self):
        return digest(self.policy)

    @property
    def plan_id(self):
        return "owned-rest:" + digest(
            [self.backend, self.complete.digest, self.policy_digest, self.mode]
        )

    @property
    def requires_human_approval(self):
        return False

    def as_dict(self):
        return {
            "backend": self.backend,
            "complete": self.complete.as_dict(),
            "policy": thaw(self.policy),
            "policy_digest": self.policy_digest,
            "plan_id": self.plan_id,
            "mode": self.mode,
            "execution_authority": False,
        }


@dataclass(frozen=True)
class OwnedRequestCompilation:
    status: str
    backend: str
    reason_code: str
    plan: OwnedRequestPlan | None = None
    unsupported_fields: tuple[str, ...] = ()

    @property
    def enforceable(self):
        return self.status == "success" and type(self.plan) is OwnedRequestPlan

    def as_dict(self):
        return {
            "status": self.status,
            "backend": self.backend,
            "reason_code": self.reason_code,
            "plan": self.plan.as_dict() if self.plan else None,
            "unsupported_fields": list(self.unsupported_fields),
            "enforceable": self.enforceable,
        }
