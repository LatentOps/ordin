"""Finite policy compilation and monotonic review joins, never execution authority."""

from __future__ import annotations

from dataclasses import dataclass, field, fields
import json
from pathlib import Path
from typing import Any

from ordin.action import ActionEnvelope, ActionReview
from ordin._runtime_json import digest
from ordin.tool_calls import _action_identity
from ordin.schema import validate_named_schema

from .budgets import BudgetLimit
from .events import _hex
from .models import SwarmContext, identifier
from .policy import DISPOSITIONS
from .policy_facts import SwarmPolicyFacts
from .policy_set import (
    CAPABILITIES,
    SwarmPolicyPermissions,
    SwarmPolicyResource,
    SwarmPolicyRule,
    SwarmPolicySet,
    SwarmPolicyTool,
    _strings,
    _typed,
)


@dataclass(frozen=True, slots=True)
class SwarmRoleBinding:
    agent_id: str
    role_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        identifier(self.agent_id, "role_agent_id")
        _strings(self.role_ids)


@dataclass(frozen=True, slots=True)
class SwarmPolicyMaximum:
    tenant_id: str
    swarm_id: str
    permissions: SwarmPolicyPermissions
    role_bindings: tuple[SwarmRoleBinding, ...] = ()
    agent_ids: tuple[str, ...] | None = None
    required_checks: tuple[str, ...] = ()
    required_capabilities: tuple[str, ...] = ("identity",)
    budget_limits: tuple[BudgetLimit, ...] = ()
    delegation_maximum_digest: str | None = None

    def __post_init__(self) -> None:
        identifier(self.tenant_id, "tenant_id")
        identifier(self.swarm_id, "swarm_id")
        if type(self.permissions) is not SwarmPolicyPermissions:
            raise ValueError("operator maximum requires typed permissions")
        self.permissions.__post_init__()
        if self.permissions.action_kinds is None or not self.permissions.action_kinds:
            raise ValueError("operator maximum requires explicit finite action kinds")
        _typed(self.role_bindings, SwarmRoleBinding, maximum=128)
        if len({v.agent_id for v in self.role_bindings}) != len(self.role_bindings):
            raise ValueError("ambiguous operator role bindings")
        if self.agent_ids is not None:
            _strings(self.agent_ids, maximum=128)
        _strings(self.required_checks, maximum=64)
        _strings(self.required_capabilities, allowed=CAPABILITIES)
        _typed(self.budget_limits, BudgetLimit, maximum=64)
        if len({(v.scope, v.metric, v.subject) for v in self.budget_limits}) != len(
            self.budget_limits
        ):
            raise ValueError("duplicate operator budget maximum")
        if self.delegation_maximum_digest is not None:
            _hex(self.delegation_maximum_digest, "delegation maximum")

    @property
    def digest(self) -> str:
        self.__post_init__()
        return digest(self.as_dict())

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "ordin.swarm_policy_maximum.v1",
            "tenant_id": self.tenant_id,
            "swarm_id": self.swarm_id,
            "permissions": self.permissions.as_dict(),
            "role_bindings": [
                {"agent_id": v.agent_id, "role_ids": list(v.role_ids)} for v in self.role_bindings
            ],
            "agent_ids": None if self.agent_ids is None else list(self.agent_ids),
            "required_checks": list(self.required_checks),
            "required_capabilities": list(self.required_capabilities),
            "budget_limits": [
                v.as_dict() | {"unknown_effects": list(v.unknown_effects)}
                for v in self.budget_limits
            ],
            "delegation_maximum_digest": self.delegation_maximum_digest,
        }

    @classmethod
    def from_dict(cls, value: dict) -> SwarmPolicyMaximum:
        """Static data only; parsing a maximum does not authorize a deployment."""
        try:
            if (
                type(value) is not dict
                or len(json.dumps(value).encode()) > 65536
                or validate_named_schema("swarm_policy_maximum", value)
            ):
                raise ValueError("invalid maximum")
            return cls(
                value["tenant_id"],
                value["swarm_id"],
                SwarmPolicyPermissions.from_dict(value["permissions"]),
                tuple(
                    SwarmRoleBinding(v["agent_id"], tuple(v["role_ids"]))
                    for v in value["role_bindings"]
                ),
                None if value["agent_ids"] is None else tuple(value["agent_ids"]),
                tuple(value["required_checks"]),
                tuple(value["required_capabilities"]),
                tuple(
                    BudgetLimit(**(v | {"unknown_effects": tuple(v["unknown_effects"])}))
                    for v in value["budget_limits"]
                ),
                value["delegation_maximum_digest"],
            )
        except (ValueError, KeyError, TypeError, UnicodeError, RecursionError, OverflowError):
            raise ValueError("invalid bounded policy maximum data") from None


@dataclass(frozen=True, slots=True)
class SwarmPolicyResult:
    disposition: str
    reason_codes: tuple[str, ...]
    matched_rules: tuple[str, ...]
    check_results: tuple[tuple[str, str], ...] = ()
    _constraints_disposition: str = field(default="deny", repr=False, compare=False, kw_only=True)
    _approval_satisfaction: Any = field(default=None, repr=False, compare=False, kw_only=True)
    _approval_baseline: Any = field(default=None, repr=False, compare=False, kw_only=True)

    @property
    def approval_fulfilled(self) -> bool:
        return (
            self.disposition != "deny"
            and self._constraints_disposition == "execute"
            and self._approval_satisfaction is not None
            and self._approval_satisfaction
            is getattr(self._approval_baseline, "_approval_satisfaction", None)
            and self._approval_baseline.approval_fulfilled
        )

    @property
    def may_execute(self) -> bool:
        return self.disposition == "execute" or self.approval_fulfilled

    def as_dict(self) -> dict[str, Any]:
        packet = {
            "disposition": self.disposition,
            "reason_codes": list(self.reason_codes),
            "matched_rules": list(self.matched_rules),
            "check_results": [
                {"check_id": key, "status": value} for key, value in self.check_results
            ],
            "execution_authority": False,
        }
        if self._approval_satisfaction is not None:
            packet["approval_satisfaction_digest"] = self._approval_satisfaction.digest
        return packet


def _stronger(*values: str) -> str:
    return max(values, key=DISPOSITIONS.__getitem__)


def _permissions(
    policy: SwarmPolicyPermissions, maximum: SwarmPolicyPermissions
) -> SwarmPolicyPermissions:
    result: dict[str, Any] = {}
    for field in fields(policy):
        candidate, allowed = getattr(policy, field.name), getattr(maximum, field.name)
        if candidate is None:
            result[field.name] = allowed
        else:
            if allowed is not None and not set(candidate) <= set(allowed):
                raise ValueError("policy permission exceeds operator maximum")
            result[field.name] = candidate
    return SwarmPolicyPermissions(**result)


def _budgets(policy: SwarmPolicySet, maximum: SwarmPolicyMaximum) -> tuple[BudgetLimit, ...]:
    selected = {(v.scope, v.metric, v.subject): v for v in maximum.budget_limits}
    for value in policy.budgets:
        key = value.scope, value.metric, value.subject
        root = selected.get(key)
        aggregate = [
            v.maximum
            for v in maximum.budget_limits
            if v.metric == value.metric
            and (
                v.scope in {"tenant", "swarm"}
                or v.scope == value.scope
                and (v.subject is None or value.subject is None or v.subject == value.subject)
            )
        ]
        if root is None and not aggregate:
            raise ValueError("policy budget has no operator aggregate maximum")
        ceiling = min(([root.maximum] if root else []) + aggregate)
        if value.maximum > ceiling:
            raise ValueError("policy budget exceeds operator maximum")
        selected[key] = BudgetLimit(
            value.scope,
            value.metric,
            value.maximum,
            value.subject,
            root.unknown_ceiling if root else None,
            root.unknown_effects if root else (),
        )
    return tuple(selected.values())


@dataclass(frozen=True, slots=True)
class CompiledSwarmPolicy:
    """Pure restriction plan; only an approved runtime can install this selection."""

    policy: SwarmPolicySet
    maximum: SwarmPolicyMaximum
    permissions: SwarmPolicyPermissions
    budget_limits: tuple[BudgetLimit, ...]
    required_checks: tuple[str, ...]
    required_capabilities: tuple[str, ...]
    policy_digest: str
    maximum_digest: str

    def validate(self) -> None:
        if self.policy.digest != self.policy_digest or self.maximum.digest != self.maximum_digest:
            raise ValueError("compiled policy data changed")

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "ordin.swarm_policy_compilation.v1",
            "policy_digest": self.policy_digest,
            "maximum_digest": self.maximum_digest,
            "compilation_digest": self.digest,
            "scope_digest": digest([self.policy.tenant_id, self.policy.swarm_id]),
            "required_checks": list(self.required_checks),
            "required_capabilities": list(self.required_capabilities),
            "rule_count": len(self.policy.rules),
            "execution_authority": False,
            "live_capabilities_verified": False,
            "deployment_authorized": False,
        }

    @property
    def digest(self) -> str:
        self.validate()
        return digest(
            {
                "schema_version": "ordin.swarm_policy_compilation.v1",
                "policy": self.policy_digest,
                "maximum": self.maximum_digest,
                "permissions": self.permissions.as_dict(),
                "budgets": [v.as_dict() for v in self.budget_limits],
                "checks": self.required_checks,
                "capabilities": self.required_capabilities,
            }
        )

    def roles(self, agent_id: str) -> frozenset[str]:
        return frozenset(
            next((v.role_ids for v in self.maximum.role_bindings if v.agent_id == agent_id), ())
        )

    @staticmethod
    def _destinations(review: ActionReview) -> frozenset[str]:
        return frozenset(
            v.value
            for v in review.resources
            if v.type in {"url", "host", "destination", "endpoint"}
        )

    def _rule(
        self,
        rule: SwarmPolicyRule,
        context: SwarmContext,
        action: ActionEnvelope,
        review: ActionReview,
        facts: SwarmPolicyFacts | None,
    ) -> bool | None:
        selected, identity = rule.match, context.identity
        for values, value in (
            (selected.tenant_ids, identity.tenant_id),
            (selected.swarm_ids, identity.swarm_id),
            (selected.task_ids, identity.task_id),
            (selected.agent_ids, identity.agent_id),
            (selected.action_kinds, action.kind),
            (selected.operations, action.operation),
        ):
            if values and value not in values:
                return False
        if selected.role_ids and not set(selected.role_ids).intersection(
            self.roles(identity.agent_id)
        ):
            return False
        if (
            selected.effects_any
            and not set(selected.effects_any).intersection(review.effects)
            or not set(selected.effects_all) <= set(review.effects)
        ):
            return False
        if selected.tools_any:
            tool = _action_identity(action)
            if tool is None or tool not in {(v.kind, v.scope, v.name) for v in selected.tools_any}:
                return False
        if selected.resources_any and not {
            (v.type, v.value) for v in selected.resources_any
        }.intersection((v.type, v.value) for v in review.resources):
            return False
        unknown = False
        if selected.destinations_any:
            destinations = self._destinations(review)
            if not destinations:
                unknown = True
            elif not destinations.intersection(selected.destinations_any):
                return False
        for values, name in (
            (selected.data_labels_any, "data_labels"),
            (selected.message_classes_any, "message_classes"),
            (selected.temporal_categories_any, "temporal_categories"),
        ):
            if values:
                fact_values = getattr(facts, name) if facts is not None else None
                if fact_values is None:
                    unknown = True
                elif not set(values).intersection(fact_values):
                    return False
        for condition in selected.budgets:
            remaining = (
                next(
                    (
                        v.remaining
                        for v in facts.budgets
                        if (v.scope, v.metric) == (condition.scope, condition.metric)
                    ),
                    None,
                )
                if facts is not None and facts.budgets is not None
                else None
            )
            if remaining is None:
                unknown = True
            elif remaining > condition.remaining_lte:
                return False
        return None if unknown else True

    def evaluate(
        self,
        context: SwarmContext,
        action: ActionEnvelope,
        review: ActionReview,
        baseline_disposition: str,
        *,
        facts: SwarmPolicyFacts | None = None,
        checks: dict[str, str] | None = None,
    ) -> SwarmPolicyResult:
        self.validate()
        reasons, matches, unknown_rules = [], [], False
        if (context.identity.tenant_id, context.identity.swarm_id) != (
            self.policy.tenant_id,
            self.policy.swarm_id,
        ):
            return SwarmPolicyResult("deny", ("policy.scope_mismatch",), ())
        if (
            self.maximum.agent_ids is not None
            and context.identity.agent_id not in self.maximum.agent_ids
        ):
            return SwarmPolicyResult("deny", ("policy.agent_outside_maximum",), ())
        if baseline_disposition not in DISPOSITIONS:
            raise ValueError("invalid protected baseline disposition")
        for rule in self.policy.rules:
            result = self._rule(rule, context, action, review, facts)
            if result is True:
                matches.append(rule)
            elif result is None:
                unknown_rules = True
        requested = (
            _stronger(*(v.disposition for v in matches))
            if matches
            else self.policy.default_disposition
        )
        constraints = requested
        final = _stronger(baseline_disposition, requested)
        if review.decision == "block":
            final = constraints = "deny"
        elif review.decision in {"warn", "ask"}:
            final = _stronger(final, "escalate")
        permissions = self.permissions
        if permissions.action_kinds is not None and action.kind not in permissions.action_kinds:
            final = constraints = "deny"
            reasons.append("policy.action_kind_outside_maximum")
        if permissions.effects is not None and not set(review.effects) <= set(permissions.effects):
            final = constraints = "deny"
            reasons.append("policy.effect_not_allowed")
        if permissions.resources is not None and not {
            (v.type, v.value) for v in review.resources
        } <= {(v.type, v.value) for v in permissions.resources}:
            final = constraints = "deny"
            reasons.append("policy.resource_not_allowed")
        if action.kind in {"tool", "mcp"} and permissions.tools is not None:
            tool = _action_identity(action)
            if tool is None or tool not in {(v.kind, v.scope, v.name) for v in permissions.tools}:
                final = constraints = "deny"
                reasons.append("policy.tool_not_allowed")
        unknown = unknown_rules
        if permissions.destinations is not None:
            actual = self._destinations(review)
            if not actual and (
                action.kind == "network" or any(v.startswith("network.") for v in review.effects)
            ):
                unknown = True
                reasons.append("policy.destination_unknown")
            elif not actual <= set(permissions.destinations):
                final = constraints = "deny"
                reasons.append("policy.destination_not_allowed")
        for allowed, name in (
            (permissions.data_labels, "data_labels"),
            (permissions.message_classes, "message_classes"),
        ):
            if allowed is not None:
                fact_values = getattr(facts, name) if facts is not None else None
                if fact_values is None:
                    unknown = True
                    reasons.append("policy.protected_fact_missing")
                elif not set(fact_values).difference({"unclassified"}) <= set(allowed):
                    final = constraints = "deny"
                    reasons.append("policy.protected_value_not_allowed")
        if (
            facts is not None
            and facts.data_labels is not None
            and "unclassified" in facts.data_labels
        ):
            unknown = True
            reasons.append("policy.data_classification_unknown")
        statuses = dict(checks or {})
        if facts is not None:
            for check, status in facts.checks:
                if check in statuses:
                    statuses[check] = max(
                        (statuses[check], status),
                        key={"satisfied": 0, "unknown": 1, "violated": 2}.__getitem__,
                    )
                else:
                    statuses[check] = status
        for check in self.required_checks:
            status = statuses.setdefault(check, "unknown")
            if status == "violated":
                final = constraints = "deny"
                reasons.append("policy.mandatory_check_violated")
            elif status != "satisfied":
                unknown = True
                reasons.append("policy.mandatory_check_unknown")
        if unknown:
            final = _stronger(final, self.policy.unknown_disposition)
            constraints = _stronger(constraints, self.policy.unknown_disposition)
            reasons.append("policy.required_fact_unknown")
        return SwarmPolicyResult(
            final,
            tuple(dict.fromkeys(reasons)),
            tuple(v.rule_id for v in matches),
            tuple(sorted((key, statuses[key]) for key in self.required_checks)),
            _constraints_disposition=constraints,
        )


def compile_swarm_policy_set(
    policy: SwarmPolicySet, maximum: SwarmPolicyMaximum
) -> CompiledSwarmPolicy:
    if type(policy) is not SwarmPolicySet or type(maximum) is not SwarmPolicyMaximum:
        raise ValueError("typed declarative policy and protected maximum required")
    policy.__post_init__()
    maximum.__post_init__()
    if (policy.tenant_id, policy.swarm_id) != (maximum.tenant_id, maximum.swarm_id):
        raise ValueError("policy scope exceeds operator maximum")
    for rule in policy.rules:
        if any(value != maximum.tenant_id for value in rule.match.tenant_ids) or any(
            value != maximum.swarm_id for value in rule.match.swarm_ids
        ):
            raise ValueError("policy selector exceeds exact tenant/swarm scope")
    if (
        policy.delegation_maximum_digest is not None
        and policy.delegation_maximum_digest != maximum.delegation_maximum_digest
    ):
        raise ValueError("policy delegation maximum differs from protected authority")
    if len(set(policy.required_checks) | set(maximum.required_checks)) > 64:
        raise ValueError("policy mandatory-check composition capacity exceeded")
    return CompiledSwarmPolicy(
        policy,
        maximum,
        _permissions(policy.permissions, maximum.permissions),
        _budgets(policy, maximum),
        tuple(sorted(set(policy.required_checks) | set(maximum.required_checks))),
        tuple(sorted(set(policy.required_capabilities) | set(maximum.required_capabilities))),
        policy.digest,
        maximum.digest,
    )


def load_swarm_policy_maximum(path: str | Path) -> SwarmPolicyMaximum:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate maximum key")
            result[key] = value
        return result

    try:
        with Path(path).open("rb") as stream:
            raw = stream.read(65537)
        if len(raw) > 65536:
            raise ValueError("maximum file too large")
        return SwarmPolicyMaximum.from_dict(json.loads(raw, object_pairs_hook=unique))
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
        raise ValueError("invalid explicit policy maximum file") from None


def diff_swarm_policies(before: SwarmPolicySet, after: SwarmPolicySet) -> dict[str, Any]:
    if (
        type(before) is not SwarmPolicySet
        or type(after) is not SwarmPolicySet
        or (before.tenant_id, before.swarm_id) != (after.tenant_id, after.swarm_id)
    ):
        raise ValueError("policy diff requires one exact tenant/swarm scope")
    old, new = before.as_dict(), after.as_dict()
    return {
        "schema_version": "ordin.swarm_policy_diff.v1",
        "before_digest": before.digest,
        "after_digest": after.digest,
        "scope_digest": digest([before.tenant_id, before.swarm_id]),
        "changed_fields": sorted(key for key in old if old[key] != new[key]),
        "added_rules": sorted({v.rule_id for v in after.rules} - {v.rule_id for v in before.rules}),
        "removed_rules": sorted(
            {v.rule_id for v in before.rules} - {v.rule_id for v in after.rules}
        ),
        "maximum_checked": False,
        "execution_authority": False,
    }


def policy_relaxes(before: CompiledSwarmPolicy, after: CompiledSwarmPolicy) -> bool:
    """Conservative structural review; samples alone cannot prove no widening."""
    for item in fields(before.permissions):
        old, new = getattr(before.permissions, item.name), getattr(after.permissions, item.name)
        if old is not None and (new is None or not set(new) <= set(old)):
            return True
    rank = {"execute": 0, "escalate": 1, "deny": 2}
    if (
        rank[after.policy.default_disposition] < rank[before.policy.default_disposition]
        or rank[after.policy.unknown_disposition] < rank[before.policy.unknown_disposition]
        or not set(before.required_checks) <= set(after.required_checks)
        or not set(before.required_capabilities) <= set(after.required_capabilities)
    ):
        return True
    previous = {v.rule_id: v for v in before.policy.rules}
    following = {v.rule_id: v for v in after.policy.rules}
    for key, old in previous.items():
        new = following.get(key)
        if new is None and old.disposition != "execute":
            return True
        if new is not None and (
            new.match != old.match or rank[new.disposition] < rank[old.disposition]
        ):
            return True
    if any(
        key not in previous and rank[new.disposition] < rank[before.policy.default_disposition]
        for key, new in following.items()
    ):
        return True
    limits = {(v.scope, v.metric, v.subject): v.maximum for v in after.budget_limits}
    return any(
        (new := limits.get((v.scope, v.metric, v.subject))) is None or new > v.maximum
        for v in before.budget_limits
    )
