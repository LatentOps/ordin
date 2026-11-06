"""Bounded governance records. Data is never an authenticated human approval."""

from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Any

from ordin._runtime_json import digest
from ordin.data import load_effect_catalog

from .events import _hex
from .models import identifier

REASONS = frozenset({"incident_response", "safety_recovery", "availability", "data_preservation"})


def _names(values, maximum):
    if (
        type(values) is not tuple
        or not 1 <= len(values) <= maximum
        or any(type(value) is not str for value in values)
        or len(set(values)) != len(values)
    ):
        raise ValueError("finite distinct governance roles required")
    for value in values:
        identifier(value, "governance_role")
        if "*" in value:
            raise ValueError("governance roles cannot contain wildcards")


def _duration(value, maximum):
    if type(value) not in {int, float} or not math.isfinite(value) or not 0 < value <= maximum:
        raise ValueError("invalid bounded governance lifetime")


@dataclass(frozen=True, slots=True)
class SwarmApprovalPolicy:
    policy_id: str
    revision: int = 1
    required_roles: tuple[str, ...] = ("approve",)
    two_person_effects: tuple[str, ...] = ()
    high_risk_quorum: int = 2
    lifetime: float = 30
    maximum_lifetime: float = 300
    max_requests: int = 512
    break_glass: bool = False
    break_glass_roles: tuple[str, ...] = ("break_glass",)
    break_glass_quorum: int = 2
    break_glass_lifetime: float = 30
    recovery_roles: tuple[str, ...] = ("recover",)
    recovery_quorum: int = 2

    def __post_init__(self):
        identifier(self.policy_id, "approval_policy_id")
        if type(self.revision) is not int or not 1 <= self.revision <= 2**31 - 1:
            raise ValueError("invalid governance policy revision")
        for roles in (self.required_roles, self.break_glass_roles, self.recovery_roles):
            _names(roles, 16)
        if (
            type(self.two_person_effects) is not tuple
            or len(self.two_person_effects) > 64
            or any(type(value) is not str for value in self.two_person_effects)
            or len(set(self.two_person_effects)) != len(self.two_person_effects)
            or not set(self.two_person_effects) <= set(load_effect_catalog())
        ):
            raise ValueError("configured high-impact effects must use the known effect vocabulary")
        _duration(self.maximum_lifetime, 300)
        _duration(self.lifetime, self.maximum_lifetime)
        _duration(self.break_glass_lifetime, min(60, self.maximum_lifetime))
        if type(self.max_requests) is not int or not 1 <= self.max_requests <= 1024:
            raise ValueError("invalid bounded governance queue capacity")
        if type(self.break_glass) is not bool or any(
            type(value) is not int or not 2 <= value <= 8
            for value in (self.high_risk_quorum, self.break_glass_quorum, self.recovery_quorum)
        ):
            raise ValueError("high-impact governance requires at least two distinct operators")

    @property
    def digest(self):
        return digest(self.as_dict())

    def as_dict(self):
        return {
            "schema_version": "ordin.swarm_approval_policy.v1",
            **{
                name: list(value) if type(value) is tuple else value
                for name in self.__dataclass_fields__
                for value in (getattr(self, name),)
            },
            "execution_authority": False,
        }

    @classmethod
    def from_dict(cls, value):
        if (
            type(value) is not dict
            or value.get("schema_version") != "ordin.swarm_approval_policy.v1"
            or value.get("execution_authority", False) is not False
            or set(value)
            - set(cls.__dataclass_fields__)
            - {"schema_version", "execution_authority"}
        ):
            raise ValueError("invalid bounded governance policy data")
        fields = {key: item for key, item in value.items() if key in cls.__dataclass_fields__}
        for key in ("required_roles", "two_person_effects", "break_glass_roles", "recovery_roles"):
            if key in fields:
                if type(fields[key]) is not list:
                    raise ValueError("finite governance arrays required")
                fields[key] = tuple(fields[key])
        return cls(**fields)


@dataclass(frozen=True, slots=True)
class SwarmApprovalBinding:
    scope_digest: str
    principal_digest: str
    session_digest: str
    context_digest: str
    action_digest: str
    review_digest: str
    gate_digest: str
    policy_digest: str
    evidence_digest: str
    delegation_digest: str
    budget_digest: str
    capabilities_digest: str
    operator_maximum_digest: str
    directory_digest: str
    policy_epoch: int
    revocation_epoch: int
    owner_fence: int

    def __post_init__(self):
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            if name in {"policy_epoch", "revocation_epoch", "owner_fence"}:
                if type(value) is not int or not 0 <= value <= 2**63 - 1:
                    raise ValueError("invalid governance epoch or owner fence")
            else:
                _hex(value, name)

    def as_dict(self):
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @property
    def digest(self):
        return digest(self.as_dict())


@dataclass(frozen=True, slots=True)
class SwarmApprovalRequest:
    request_id: str
    binding: SwarmApprovalBinding
    approval_policy_digest: str
    disposition: str
    risk: str
    effects: tuple[str, ...]
    required_roles: tuple[str, ...]
    quorum: int
    expires_at: float
    mode: str = "standard"
    reason_code: str | None = None

    def __post_init__(self):
        identifier(self.request_id, "approval_request_id")
        if type(self.binding) is not SwarmApprovalBinding:
            raise ValueError("exact typed governance binding required")
        self.binding.__post_init__()
        _hex(self.approval_policy_digest, "approval_policy_digest")
        _names(self.required_roles, 16)
        if (
            self.disposition not in {"execute", "escalate", "deny"}
            or self.risk not in {"low", "medium", "high", "critical", "unknown"}
            or self.mode not in {"standard", "break_glass", "recovery"}
        ):
            raise ValueError("invalid finite governance request state")
        if (self.mode == "standard" and self.reason_code is not None) or (
            self.mode != "standard" and self.reason_code not in REASONS
        ):
            raise ValueError("bounded governance reason code required")
        if (
            type(self.effects) is not tuple
            or len(self.effects) > 64
            or any(type(value) is not str for value in self.effects)
            or not set(self.effects) <= set(load_effect_catalog())
        ):
            raise ValueError("governance effects must come from actual known semantics")
        if (
            type(self.quorum) is not int
            or not 1 <= self.quorum <= 8
            or type(self.expires_at) not in {int, float}
            or not math.isfinite(self.expires_at)
            or self.expires_at < 0
        ):
            raise ValueError("invalid bounded governance quorum or expiry")

    @property
    def digest(self):
        return digest(self.as_dict())

    def as_dict(self):
        return {
            "schema_version": "ordin.swarm_approval_request.v1",
            "request_id": self.request_id,
            "binding": self.binding.as_dict(),
            "binding_digest": self.binding.digest,
            "approval_policy_digest": self.approval_policy_digest,
            "disposition": self.disposition,
            "risk": self.risk,
            "effects": list(self.effects),
            "required_roles": list(self.required_roles),
            "quorum": self.quorum,
            "expires_at": self.expires_at,
            "mode": self.mode,
            "reason_code": self.reason_code,
            "execution_authority": False,
        }


@dataclass(frozen=True, slots=True, eq=False)
class SwarmApprovalReceipt:
    receipt_id: str

    @classmethod
    def from_dict(cls, value: Any):
        raise ValueError("JSON cannot authenticate or consume a human approval")


@dataclass(frozen=True, slots=True, eq=False)
class SwarmRecoveryApproval:
    approval_id: str

    @classmethod
    def from_dict(cls, value: Any):
        raise ValueError("JSON cannot approve recovery or resume old permits")


@dataclass(frozen=True, slots=True)
class SwarmRecoveryRequest:
    request_id: str
    binding_digest: str
    incident_digest: str
    scope_digest: str
    policy_epoch: int
    revocation_epoch: int
    owner_fence: int
    required_roles: tuple[str, ...]
    quorum: int
    expires_at: float
    reason_code: str

    def __post_init__(self):
        identifier(self.request_id, "recovery_request_id")
        for name in ("binding_digest", "incident_digest", "scope_digest"):
            _hex(getattr(self, name), name)
        for name in ("policy_epoch", "revocation_epoch", "owner_fence"):
            value = getattr(self, name)
            if type(value) is not int or not 0 <= value <= 2**63 - 1:
                raise ValueError("invalid recovery epoch or fence")
        _names(self.required_roles, 16)
        if type(self.quorum) is not int or not 2 <= self.quorum <= 8:
            raise ValueError("recovery requires distinct human quorum")
        if self.reason_code not in REASONS:
            raise ValueError("bounded recovery reason code required")
        if (
            type(self.expires_at) not in {int, float}
            or not math.isfinite(self.expires_at)
            or self.expires_at < 0
        ):
            raise ValueError("invalid recovery expiry")

    def as_dict(self):
        return {
            "schema_version": "ordin.swarm_recovery_request.v1",
            **{
                name: list(value) if type(value) is tuple else value
                for name in self.__dataclass_fields__
                for value in (getattr(self, name),)
            },
            "execution_authority": False,
        }

    @property
    def digest(self):
        return digest(self.as_dict())
