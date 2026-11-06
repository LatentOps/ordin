"""Protected incident intent and scoped monotonic containment; no rollback claims."""

from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from typing import Any
from uuid import uuid4

from ordin._runtime_json import digest

from .events import _hex
from .models import counter, identifier

SCOPES = frozenset({"action", "agent", "delegation_subtree", "task", "swarm", "tenant"})
SEVERITIES = {"medium": 0, "high": 1, "critical": 2}
RESULTS = frozenset({"canceled", "completed", "unable_to_stop", "unknown"})


@dataclass(frozen=True, slots=True)
class IncidentScope:
    kind: str
    tenant_id: str
    swarm_id: str | None = None
    agent_id: str | None = None
    task_id: str | None = None
    action_digest: str | None = None

    def __post_init__(self) -> None:
        if type(self.kind) is not str or self.kind not in SCOPES:
            raise ValueError("unknown incident scope")
        identifier(self.tenant_id, "tenant_id")
        for name in ("swarm_id", "agent_id", "task_id"):
            value = getattr(self, name)
            if value is not None:
                identifier(value, name)
        expected = {
            "tenant": (False, False, False, False),
            "swarm": (True, False, False, False),
            "agent": (True, True, False, False),
            "delegation_subtree": (True, True, False, False),
            "task": (True, False, True, False),
            "action": (True, True, False, True),
        }[self.kind]
        if (
            tuple(
                value is not None
                for value in (self.swarm_id, self.agent_id, self.task_id, self.action_digest)
            )
            != expected
        ):
            raise ValueError("incident scope fields do not match its exact kind")
        if self.action_digest is not None:
            _hex(self.action_digest, "incident action digest")

    def as_dict(self) -> dict[str, Any]:
        return {
            name: getattr(self, name)
            for name in ("kind", "tenant_id", "swarm_id", "agent_id", "task_id", "action_digest")
        }

    @property
    def digest(self) -> str:
        self.__post_init__()
        return digest(self.as_dict())


@dataclass(frozen=True, slots=True)
class IncidentRule:
    rule_id: str
    minimum_severity: str
    automatic_scope: str = "agent"
    max_affected: int = 1

    def __post_init__(self) -> None:
        identifier(self.rule_id, "incident_rule_id")
        if type(self.minimum_severity) is not str or self.minimum_severity not in SEVERITIES:
            raise ValueError("unknown incident severity")
        if type(self.automatic_scope) is not str or self.automatic_scope not in {
            "action",
            "agent",
            "delegation_subtree",
        }:
            raise ValueError("automatic containment must be explicitly narrow")
        if type(self.max_affected) is not int or not 1 <= self.max_affected <= 32:
            raise ValueError("invalid automatic containment blast radius")


@dataclass(frozen=True, slots=True)
class IncidentPolicy:
    policy_id: str
    revision: int
    automatic_rules: tuple[IncidentRule, ...] = ()
    max_affected: int = 256

    def __post_init__(self) -> None:
        identifier(self.policy_id, "incident_policy_id")
        counter(self.revision, "incident_policy_revision")
        if (
            type(self.automatic_rules) is not tuple
            or len(self.automatic_rules) > 64
            or any(type(value) is not IncidentRule for value in self.automatic_rules)
            or len({value.rule_id for value in self.automatic_rules}) != len(self.automatic_rules)
            or type(self.max_affected) is not int
            or not 1 <= self.max_affected <= 4096
        ):
            raise ValueError("invalid bounded incident policy")
        for rule in self.automatic_rules:
            rule.__post_init__()

    @property
    def digest(self) -> str:
        self.__post_init__()
        return digest(
            {
                "policy_id": self.policy_id,
                "revision": self.revision,
                "automatic_rules": [
                    (rule.rule_id, rule.minimum_severity, rule.automatic_scope, rule.max_affected)
                    for rule in self.automatic_rules
                ],
                "max_affected": self.max_affected,
            }
        )


@dataclass(frozen=True, eq=False, slots=True)
class IncidentSignal:
    signal_id: str


@dataclass(frozen=True)
class _Signal:
    handle: IncidentSignal
    scope: IncidentScope
    severity: str
    rule_id: str | None
    proof_digest: str
    operator_owned: bool


class IncidentSignalSource:
    """Host-only original findings. JSON/text cannot issue a containment signal.

    Operator signals require the exact protected capability. Automatic signals
    must be captured by the controller from a configured original rule engine;
    no generic public method accepts caller-claimed risk or severity.
    """

    def __init__(self, *, operator: object, max_signals: int = 4096) -> None:
        if (
            type(operator) is not object
            or type(max_signals) is not int
            or not 1 <= max_signals <= 16384
        ):
            raise ValueError("protected bounded incident signal source required")
        self._operator, self._limit = operator, max_signals
        self._signals: dict[IncidentSignal, _Signal] = {}
        self._lock = RLock()

    def operator_signal(
        self, scope: IncidentScope, *, severity: str, operator: object
    ) -> IncidentSignal:
        if operator is not self._operator or type(scope) is not IncidentScope:
            raise ValueError("protected incident operator required")
        return self._capture(scope, severity, None, digest(["operator", scope.as_dict()]), True)

    def _capture(
        self,
        scope: IncidentScope,
        severity: str,
        rule_id: str | None,
        proof_digest: str,
        operator_owned: bool,
    ) -> IncidentSignal:
        if (
            type(scope) is not IncidentScope
            or type(severity) is not str
            or severity not in SEVERITIES
        ):
            raise ValueError("typed incident scope and severity required")
        scope.__post_init__()
        _hex(proof_digest, "incident evidence digest")
        if rule_id is not None:
            identifier(rule_id, "incident_rule_id")
        with self._lock:
            if len(self._signals) >= self._limit:
                raise ValueError("incident signal capacity reached")
            handle = IncidentSignal(uuid4().hex)
            self._signals[handle] = _Signal(
                handle, scope, severity, rule_id, proof_digest, operator_owned
            )
            return handle

    def _original(self, handle: IncidentSignal) -> _Signal:
        if type(handle) is not IncidentSignal or handle not in self._signals:
            raise ValueError("unknown original incident signal")
        return self._signals[handle]


# Imported last so the controller can use the data-only scope definitions.
from .containment import SwarmContainmentController, IncidentReceipt, IncidentResumeReceipt  # noqa: E402
from .incident_rules import incident_temporal_policy, cascade_incident_rules  # noqa: E402

__all__ = [
    "IncidentScope",
    "IncidentRule",
    "IncidentPolicy",
    "IncidentSignal",
    "IncidentSignalSource",
    "SwarmContainmentController",
    "IncidentReceipt",
    "IncidentResumeReceipt",
    "incident_temporal_policy",
    "cascade_incident_rules",
]
