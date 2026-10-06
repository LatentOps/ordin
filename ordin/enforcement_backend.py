"""Backend-neutral compile/validate interfaces. Core never applies or executes."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol, runtime_checkable

from ._runtime_json import digest, freeze, text_tuple, thaw
from .runtime_contract import RuntimeCapabilityContract


def _identifier(value: Any, name: str) -> None:
    from ._runtime_schemas import IDENTIFIER
    from .schema import validate_instance

    if validate_instance(value, IDENTIFIER):
        raise ValueError(f"invalid backend {name}")


@dataclass(frozen=True)
class EnforcementPlan:
    backend: str
    contract: RuntimeCapabilityContract
    policy: Mapping[str, Any]
    mode: str = "enforce"
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _identifier(self.backend, "identity")
        if not isinstance(self.contract, RuntimeCapabilityContract):
            raise ValueError("enforcement plan requires a capability contract")
        if self.mode not in {"shadow", "enforce"}:
            raise ValueError("enforcement plan mode must be shadow or enforce")
        if not isinstance(self.policy, Mapping) or not isinstance(self.metadata, Mapping):
            raise ValueError("enforcement policy and metadata require objects")
        object.__setattr__(self, "policy", freeze(self.policy))
        object.__setattr__(self, "metadata", freeze(self.metadata))
        if self.mode == "enforce" and self.contract.grant_state == "diagnostic":
            raise ValueError("blocked or uncertain contracts cannot form enforceable plans")

    @property
    def policy_digest(self) -> str:
        return digest(self.policy)

    @property
    def plan_id(self) -> str:
        return "ep:" + digest(
            {
                "backend": self.backend,
                "contract_digest": self.contract.digest,
                "policy_digest": self.policy_digest,
                "mode": self.mode,
                "metadata": thaw(self.metadata),
            }
        )

    @property
    def requires_human_approval(self) -> bool:
        return self.contract.decision in {"warn", "ask"}

    def as_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "backend": self.backend,
            "mode": self.mode,
            "contract": self.contract.as_dict(),
            "policy": thaw(self.policy),
            "policy_digest": self.policy_digest,
            "requires_human_approval": self.requires_human_approval,
            "metadata": thaw(self.metadata),
        }


@dataclass(frozen=True)
class CompilationResult:
    status: str
    backend: str
    reason_code: str
    reasons: tuple[str, ...] = ()
    unsupported_fields: tuple[str, ...] = ()
    plan: EnforcementPlan | None = None

    def __post_init__(self) -> None:
        _identifier(self.backend, "identity")
        _identifier(self.reason_code, "reason code")
        if self.status not in {"success", "unsupported", "inconclusive"}:
            raise ValueError("invalid compilation status")
        object.__setattr__(self, "reasons", text_tuple(self.reasons))
        object.__setattr__(self, "unsupported_fields", text_tuple(self.unsupported_fields))
        if self.plan is not None and (
            not isinstance(self.plan, EnforcementPlan) or self.plan.backend != self.backend
        ):
            raise ValueError("compilation plan backend mismatch")
        if self.status == "success" and (self.plan is None or self.unsupported_fields):
            raise ValueError("successful compilation requires a complete plan")
        if self.status != "success" and self.plan is not None and self.plan.mode != "shadow":
            raise ValueError("non-success compilation cannot provide an enforcement plan")

    @property
    def enforceable(self) -> bool:
        return self.status == "success" and self.plan is not None and self.plan.mode == "enforce"

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "backend": self.backend,
            "reason_code": self.reason_code,
            "reasons": list(self.reasons),
            "unsupported_fields": list(self.unsupported_fields),
            "enforceable": self.enforceable,
            "plan": self.plan.as_dict() if self.plan else None,
        }


@dataclass(frozen=True)
class BackendValidationResult:
    status: str
    backend: str
    policy_digest: str
    reason_code: str
    reasons: tuple[str, ...] = ()
    unsupported_fields: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        from ._runtime_schemas import DIGEST
        from .schema import validate_instance

        _identifier(self.backend, "identity")
        _identifier(self.reason_code, "reason code")
        if self.status not in {"success", "invalid", "unsupported", "inconclusive"}:
            raise ValueError("invalid backend validation status")
        if validate_instance(self.policy_digest, DIGEST):
            raise ValueError("invalid backend policy digest")
        object.__setattr__(self, "reasons", text_tuple(self.reasons))
        object.__setattr__(self, "unsupported_fields", text_tuple(self.unsupported_fields))
        if self.status == "success" and self.unsupported_fields:
            raise ValueError("successful validation cannot omit unsupported fields")

    @property
    def ok(self) -> bool:
        return self.status == "success"

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "backend": self.backend,
            "policy_digest": self.policy_digest,
            "reason_code": self.reason_code,
            "reasons": list(self.reasons),
            "unsupported_fields": list(self.unsupported_fields),
        }


@runtime_checkable
class EnforcementBackend(Protocol):
    @property
    def name(self) -> str: ...

    def compile(self, contract: RuntimeCapabilityContract) -> CompilationResult: ...

    def validate(self, plan: EnforcementPlan) -> BackendValidationResult: ...
