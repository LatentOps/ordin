"""Bounded host-configured swarm constraints; selectors never execute code."""

from dataclasses import dataclass
from typing import Any

from ordin._runtime_json import digest

from .models import identifier

DISPOSITIONS = {"execute": 0, "escalate": 1, "deny": 2}


@dataclass(frozen=True, slots=True)
class SwarmRule:
    rule_id: str
    disposition: str
    agent_ids: tuple[str, ...] = ()
    task_ids: tuple[str, ...] = ()
    action_kinds: tuple[str, ...] = ()
    effects: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        identifier(self.rule_id, "rule_id")
        if type(self.disposition) is not str or self.disposition not in DISPOSITIONS:
            raise ValueError("unknown swarm rule disposition")
        for name in ("agent_ids", "task_ids", "action_kinds", "effects"):
            values = getattr(self, name)
            if type(values) is not tuple or len(values) > 64:
                raise ValueError("swarm selectors require bounded immutable collections")
            for value in values:
                identifier(value, name)
            if len(set(values)) != len(values):
                raise ValueError("duplicate swarm selector")

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "disposition": self.disposition,
            **{
                name: list(getattr(self, name))
                for name in ("agent_ids", "task_ids", "action_kinds", "effects")
            },
        }


@dataclass(frozen=True, slots=True)
class SwarmPolicy:
    policy_id: str
    revision: str
    rules: tuple[SwarmRule, ...] = ()
    required_checks: tuple[str, ...] = ()
    unknown_disposition: str = "deny"

    def __post_init__(self) -> None:
        identifier(self.policy_id, "policy_id")
        identifier(self.revision, "revision")
        if type(self.rules) is not tuple or len(self.rules) > 128:
            raise ValueError("invalid bounded swarm rules")
        if any(type(rule) is not SwarmRule for rule in self.rules):
            raise ValueError("swarm rules must be immutable host configuration")
        for rule in self.rules:
            rule.__post_init__()
        if len({rule.rule_id for rule in self.rules}) != len(self.rules):
            raise ValueError("duplicate swarm rule ID")
        if type(self.required_checks) is not tuple or len(self.required_checks) > 64:
            raise ValueError("invalid bounded mandatory swarm checks")
        for check in self.required_checks:
            identifier(check, "check_id")
        if len(set(self.required_checks)) != len(self.required_checks):
            raise ValueError("duplicate mandatory swarm check")
        if type(self.unknown_disposition) is not str or self.unknown_disposition not in {
            "escalate",
            "deny",
        }:
            raise ValueError("unknown mandatory checks cannot authorize execution")

    def as_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "revision": self.revision,
            "rules": [rule.as_dict() for rule in self.rules],
            "required_checks": list(self.required_checks),
            "unknown_disposition": self.unknown_disposition,
        }

    @property
    def digest(self) -> str:
        self.__post_init__()
        return digest(self.as_dict())


# The legacy host-programmatic policy remains unchanged. The new data document
# has its own exact schema and still needs a protected approved runtime to deploy.
from .policy_set import (  # noqa: E402
    SwarmPolicySet,
    SwarmPolicyRule,
    SwarmPolicySelector,
    SwarmPolicyPermissions,
    SwarmPolicyTool,
    SwarmPolicyResource,
    SwarmBudgetConstraint,
    SwarmBudgetCondition,
    load_swarm_policy_set,
)
