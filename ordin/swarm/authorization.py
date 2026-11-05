"""Inspectible broker reports and opaque controls; JSON never authorizes effects."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ordin._runtime_json import digest
from ordin.action import ActionEnvelope
from ordin.enforcement_backend import EnforcementPlan

from .budgets import BudgetTicket
from .delegation import BrokerAdmissionScope
from .gate import SwarmDecision
from .models import SwarmContext


@dataclass(frozen=True, eq=False, slots=True)
class BrokerAuthorization:
    authorization_id: str

    @classmethod
    def from_dict(cls, value):
        raise ValueError("JSON cannot issue or restore broker authorization")


@dataclass(frozen=True, eq=False, slots=True)
class BrokerGatewayBinding:
    binding_id: str


@dataclass(frozen=True, eq=False, slots=True)
class BrokerActivationProof:
    proof_id: str


@dataclass(frozen=True, eq=False, slots=True)
class BrokerBudgetProof:
    proof_id: str


@dataclass(frozen=True, slots=True)
class BrokerPreparation:
    disposition: str
    reason_codes: tuple[str, ...]
    action_digest: str | None
    caller_digest: str
    policy_digest: str
    authorization: BrokerAuthorization | None = field(default=None, repr=False)
    decision: SwarmDecision | None = field(default=None, repr=False)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "ordin.swarm_broker_preparation.v1",
            "disposition": self.disposition,
            "reason_codes": list(self.reason_codes),
            "action_digest": self.action_digest,
            "caller_digest": self.caller_digest,
            "policy_digest": self.policy_digest,
            "authorization_digest": digest(self.authorization.authorization_id)
            if self.authorization
            else None,
            "execution_authority": False,
        }


@dataclass(frozen=True, slots=True)
class BrokerAuthorizationScope:
    action: ActionEnvelope = field(repr=False)
    context: SwarmContext = field(repr=False)
    plan: EnforcementPlan = field(repr=False)
    decision: SwarmDecision = field(repr=False)
    delegation_scope: BrokerAdmissionScope = field(repr=False)
    budget_ticket: BudgetTicket = field(repr=False)
    caller_digest: str
    authorization_digest: str
    expires_at: int
    policy_digest: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "ordin.swarm_broker_scope.v1",
            "action_digest": digest(self.action.as_dict()),
            "context_digest": digest(self.context.as_dict()),
            "plan_digest": digest(self.plan.as_dict()),
            "caller_digest": self.caller_digest,
            "authorization_digest": self.authorization_digest,
            "expires_at": self.expires_at,
            "policy_digest": self.policy_digest,
            "budget_reservation_digest": digest(self.budget_ticket.reservation_id),
            "delegation_admission_digest": self.delegation_scope.admission_digest,
            "execution_authority": False,
        }


@dataclass(frozen=True, eq=False, slots=True)
class BrokerResult:
    status: str
    reason_code: str
    action_digest: str
    caller_digest: str
    authorization_digest: str
    physical_enforcement: bool
    forwarded: bool
    budget_status: str
    observation_digest: str | None = None
    executor_outcome: Any = field(default=None, repr=False)
    value: Any = field(default=None, repr=False)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "ordin.swarm_broker_result.v1",
            "status": self.status,
            "reason_code": self.reason_code,
            "action_digest": self.action_digest,
            "caller_digest": self.caller_digest,
            "authorization_digest": self.authorization_digest,
            "physical_enforcement": self.physical_enforcement,
            "forwarded": self.forwarded,
            "budget_status": self.budget_status,
            "observation_digest": self.observation_digest,
            "execution_authority": False,
        }


@dataclass(frozen=True, eq=False, slots=True)
class BrokerControlReceipt:
    authorization_digest: str
    status: str
    reason_code: str
    state: str
    action_digest: str
    context_digest: str
    policy_epoch: int
    owned_job_digest: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "ordin.swarm_broker_control.v1",
            "authorization_digest": self.authorization_digest,
            "status": self.status,
            "reason_code": self.reason_code,
            "state": self.state,
            "action_digest": self.action_digest,
            "context_digest": self.context_digest,
            "policy_epoch": self.policy_epoch,
            "owned_job_digest": self.owned_job_digest,
            "rollback_claim": False,
            "execution_authority": False,
        }
