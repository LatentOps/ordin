"""Redacted public reports; these examples are never execution authority."""

from ordin.swarm.authorization import BrokerPreparation, BrokerResult, BrokerControlReceipt
from ordin.swarm.linux_backend import ExecutorOutcome


def broker_contract_samples():
    h = "a" * 64
    return {
        "swarm_broker_preparation": BrokerPreparation(
            "deny", ("broker.unsupported",), h, h, h
        ).as_dict(),
        "swarm_broker_result": BrokerResult(
            "denied", "broker.unsupported", h, h, h, False, False, "canceled"
        ).as_dict(),
        "swarm_broker_control": BrokerControlReceipt(
            h, "unknown", "broker.owned_status", "checking", h, h, 0, h
        ).as_dict(),
        "swarm_executor_outcome": ExecutorOutcome(
            "unsupported", "broker.kernel_unavailable", h, h, h, False, None, 0, 0, None
        ).as_dict(),
        "swarm_broker_scope": {
            "schema_version": "ordin.swarm_broker_scope.v1",
            "action_digest": h,
            "context_digest": h,
            "plan_digest": h,
            "caller_digest": h,
            "authorization_digest": h,
            "expires_at": 100,
            "policy_digest": h,
            "budget_reservation_digest": h,
            "delegation_admission_digest": h,
            "execution_authority": False,
        },
    }
