"""Operator-approved local policy epochs with atomic execution-barrier cutover."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field, fields, replace
from threading import RLock
import time
from typing import Any, Callable, Iterator
from uuid import uuid4

from ordin.action import ActionEnvelope, ActionReview
from ordin.agent import AgentGate
from ordin.api import Ordin
from ordin.assurance.delegating_gate import DelegatingAssuranceGate
from ordin.assurance.delegation import DelegationIssuer
from ordin._runtime_json import digest

from .budgets import BudgetLedger, BudgetPolicy
from .budget_store import SQLiteBudgetStore
from .delegation import SwarmDelegationService
from .models import SwarmContext, counter, identifier, timestamp
from .policy import SwarmPolicy
from .policy_compiler import (
    CompiledSwarmPolicy,
    SwarmPolicyMaximum,
    SwarmPolicyResult,
    _stronger,
    compile_swarm_policy_set,
    policy_relaxes,
)
from .policy_facts import SwarmPolicyFacts, SwarmPolicyFactsSource
from .policy_set import SwarmPolicyPermissions, SwarmPolicySet
from .registry import InMemoryAgentRegistry
from .source_flow import SwarmSourceFlow
from .temporal import SwarmTemporalEngine


@dataclass(frozen=True, eq=False, slots=True)
class SwarmPolicyDeployment:
    deployment_id: str
    compilation_digest: str
    base_binding_digest: str
    target_epoch: int
    expires_at: float


@dataclass(frozen=True, eq=False, slots=True)
class SwarmPolicyApproval:
    approval_id: str
    deployment_id: str
    simulation_digest: str
    compilation_digest: str
    target_epoch: int
    base_binding_digest: str
    expires_at: float


@dataclass(frozen=True, slots=True)
class SwarmPolicyReplayCase:
    case_id: str
    context: SwarmContext
    action: ActionEnvelope
    expected: str = "unspecified"
    facts: SwarmPolicyFacts | None = None

    def __post_init__(self) -> None:
        identifier(self.case_id, "case_id")
        if (
            type(self.context) is not SwarmContext
            or type(self.action) is not ActionEnvelope
            or self.expected not in {"benign", "unsafe", "unspecified"}
        ):
            raise ValueError("invalid bounded policy replay case")
        if self.facts is not None:
            if type(self.facts) is not SwarmPolicyFacts:
                raise ValueError("typed hypothetical facts required")
            self.facts._payload()


@dataclass(frozen=True, eq=False, slots=True)
class SwarmPolicySimulation:
    deployment_id: str
    compilation_digest: str
    base_binding_digest: str
    cases_digest: str
    outcomes: tuple[tuple[str, str, str, str], ...]
    structural_relaxation: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "ordin.swarm_policy_simulation.v1",
            "compilation_digest": self.compilation_digest,
            "base_binding_digest": self.base_binding_digest,
            "cases_digest": self.cases_digest,
            "outcomes": [
                {"case_id": key, "before": old, "after": new, "expected": expected}
                for key, old, new, expected in self.outcomes
            ],
            "relaxations": sum(
                old != "execute" and new == "execute" for _, old, new, _ in self.outcomes
            ),
            "benign_restricted": sum(
                expected == "benign" and new != "execute" for _, _, new, expected in self.outcomes
            ),
            "unsafe_executable": sum(
                expected == "unsafe" and new == "execute" for _, _, new, expected in self.outcomes
            ),
            "structural_relaxation": self.structural_relaxation,
            "evidence_class": "offline_simulation",
            "execution_authority": False,
        }

    @property
    def digest(self) -> str:
        return digest(self.as_dict())


@dataclass(frozen=True, slots=True)
class SwarmPolicyActivation:
    policy_digest: str
    compilation_digest: str
    epoch: int
    state: str
    reason_codes: tuple[str, ...]
    budget_ledger: BudgetLedger | None = field(default=None, repr=False, compare=False)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "ordin.swarm_policy_activation.v1",
            "policy_digest": self.policy_digest,
            "compilation_digest": self.compilation_digest,
            "epoch": self.epoch,
            "state": self.state,
            "reason_codes": list(self.reason_codes),
            "execution_authority": False,
            "physical_enforcement": False,
        }


class SwarmPolicyRuntime:
    """One protected local coordinator; distributed linearization belongs to its coordinator.

    All guarded dispatchers share execution_barrier. An in-flight synchronous
    callback finishes before activation can cut over; this is not kernel cancel.
    """

    def __init__(
        self,
        registry: InMemoryAgentRegistry,
        maximum: SwarmPolicyMaximum,
        *,
        operator: object,
        clock: Callable[[], float] = time.monotonic,
        facts_source: SwarmPolicyFactsSource | None = None,
        budget_ledger: BudgetLedger | None = None,
        flow: SwarmSourceFlow | None = None,
        temporal_engine: SwarmTemporalEngine | None = None,
        delegation_service: SwarmDelegationService | None = None,
        delegation_operator: object | None = None,
        delegation_issuer: DelegationIssuer | None = None,
        max_deployments: int = 64,
    ) -> None:
        if (
            type(registry) is not InMemoryAgentRegistry
            or type(maximum) is not SwarmPolicyMaximum
            or type(operator) is not object
            or not callable(clock)
        ):
            raise ValueError("protected policy registry, maximum and operator required")
        if (registry._tenant, registry._swarm) != (maximum.tenant_id, maximum.swarm_id):
            raise ValueError("policy maximum differs from the actual registry scope")
        if facts_source is not None and type(facts_source) is not SwarmPolicyFactsSource:
            raise ValueError("original protected policy fact source required")
        if budget_ledger is not None and (
            type(budget_ledger) is not BudgetLedger or budget_ledger._registry is not registry
        ):
            raise ValueError("policy budget must share its original registry")
        if flow is not None and (
            type(flow) is not SwarmSourceFlow or flow._graph._ingestor._registry is not registry
        ):
            raise ValueError("policy flow must share its original registry")
        if temporal_engine is not None and (
            type(temporal_engine) is not SwarmTemporalEngine
            or temporal_engine._graph._ingestor._registry is not registry
        ):
            raise ValueError("policy temporal engine must share its original registry")
        if delegation_service is not None:
            if (
                type(delegation_service) is not SwarmDelegationService
                or delegation_service.authenticator._registry is not registry
            ):
                raise ValueError("policy delegation must share its original registry")
            delegation_service._operator_check(delegation_operator)
            if delegation_issuer is not None and delegation_issuer is not delegation_service.issuer:
                raise ValueError("ambiguous policy delegation issuer")
            delegation_issuer = delegation_service.issuer
            if (
                maximum.delegation_maximum_digest
                != delegation_service.issuer.operator_maximum.digest
            ):
                raise ValueError("policy delegation maximum differs from original issuer")
        if delegation_issuer is not None:
            if (
                type(delegation_issuer) is not DelegationIssuer
                or delegation_issuer.operator_maximum.digest != maximum.delegation_maximum_digest
            ):
                raise ValueError("policy delegation issuer differs from operator maximum")
            delegation_issuer._require_configuration()
        elif maximum.delegation_maximum_digest is not None:
            raise ValueError("policy delegation maximum requires its actual issuer")
        if type(max_deployments) is not int or not 1 <= max_deployments <= 256:
            raise ValueError("invalid policy deployment capacity")
        self._registry, self.maximum, self._operator = registry, maximum, operator
        self._maximum_digest = maximum.digest
        self._clock, self._last_now = clock, 0.0
        self.facts_source = facts_source or SwarmPolicyFactsSource(clock=clock)
        self._budget, self._flow, self._temporal = budget_ledger, flow, temporal_engine
        self._delegation, self._delegation_operator = delegation_service, delegation_operator
        self._issuer = delegation_issuer
        self._task_maximum_digest = (
            delegation_issuer.task_maximum.digest if delegation_issuer else None
        )
        self._epoch, self._generation, self._source_generation = registry._policy_epoch, 0, 0
        self._nonce, self._limit = uuid4().hex, max_deployments
        self._active: CompiledSwarmPolicy | None = None
        self._approval_digest: str | None = None
        self._available = False
        self._deployments: dict[SwarmPolicyDeployment, CompiledSwarmPolicy] = {}
        self._simulations: dict[SwarmPolicySimulation, str] = {}
        self._approvals: dict[SwarmPolicyApproval, tuple[SwarmPolicyDeployment, str]] = {}
        self._used: set[SwarmPolicyApproval] = set()
        self._gate_limits: set[tuple[int, frozenset[str], frozenset[str]]] = set()
        self._enforcement: dict[str, tuple[Any, Any]] = {}
        self._lock, self._execution_barrier = RLock(), registry._policy_execution_barrier

    def _now(self) -> float:
        now = timestamp(self._clock())
        if now < self._last_now:
            raise ValueError("policy coordinator clock moved backward")
        self._last_now = now
        return now

    def _configuration(self) -> None:
        if (
            self.maximum.digest != self._maximum_digest
            or self._registry._policy_epoch != self._epoch
        ):
            raise ValueError("policy coordinator configuration or epoch changed")

    @property
    def epoch(self) -> int:
        with self._lock:
            return self._epoch

    @property
    def selection_digest(self) -> str | None:
        with self._lock:
            self._configuration()
            return self._active.digest if self._active else None

    @property
    def active_policy_digest(self) -> str | None:
        with self._lock:
            self._configuration()
            return self._active.policy_digest if self._active else None

    @property
    def execution_barrier(self):
        return self._execution_barrier

    @property
    def binding_digest(self) -> str:
        with self._lock:
            self._configuration()
            return digest(
                [
                    self._nonce,
                    self._generation,
                    self._epoch,
                    self._source_generation,
                    self._active.digest if self._active else None,
                    self._approval_digest,
                    self._maximum_digest,
                    self.facts_source.binding_digest,
                    self._available,
                    self._budget_binding(),
                    self._delegation_binding(),
                    self._enforcement_binding(self._active.policy if self._active else None),
                ]
            )

    def _budget_binding(self) -> str | None:
        if self._budget is None:
            return None
        try:
            return self._budget.authority_binding_digest
        except ValueError:
            return "unavailable"

    def _delegation_binding(self) -> str | None:
        if self._issuer is None:
            return None
        try:
            self._issuer._require_configuration()
            return digest(
                [
                    self._issuer._issuer_key,
                    self._issuer._generation,
                    self._issuer.operator_maximum.digest,
                    self._issuer.task_maximum.digest,
                    self._issuer.source.key,
                    self._delegation._generation if self._delegation else None,
                    self._delegation._available if self._delegation else None,
                    self._delegation.authenticator._generation if self._delegation else None,
                    self._delegation.authenticator._configuration()
                    == self._delegation.authenticator._tls_binding
                    if self._delegation
                    else None,
                ]
            )
        except ValueError:
            return "unavailable"

    def rebind_sources(
        self,
        *,
        operator: object,
        flow: SwarmSourceFlow | None = None,
        temporal_engine: SwarmTemporalEngine | None = None,
        budget_ledger: BudgetLedger | None = None,
        delegation_service: SwarmDelegationService | None = None,
        delegation_operator: object | None = None,
        delegation_issuer: DelegationIssuer | None = None,
    ) -> None:
        """Protected current-epoch collector refresh; never revives old tickets.

        A successful policy epoch requires fresh live contexts/sources. Source
        replacement is checked against the same immutable operator maximum.
        """
        if operator is not self._operator:
            raise ValueError("original policy operator required")
        with self._execution_barrier, self._lock:
            self._configuration()
            if flow is not None:
                if (
                    type(flow) is not SwarmSourceFlow
                    or flow._graph._ingestor._registry is not self._registry
                    or flow._graph._context.identity.policy_epoch != self._epoch
                ):
                    raise ValueError("current original flow source required")
                flow._graph.build()
            if temporal_engine is not None:
                if (
                    type(temporal_engine) is not SwarmTemporalEngine
                    or temporal_engine._graph._ingestor._registry is not self._registry
                    or temporal_engine._graph._context.identity.policy_epoch != self._epoch
                ):
                    raise ValueError("current original temporal source required")
                temporal_engine.binding_digest
            if budget_ledger is not None:
                if (
                    type(budget_ledger) is not BudgetLedger
                    or budget_ledger._registry is not self._registry
                    or budget_ledger.policy.policy_epoch != self._epoch
                ):
                    raise ValueError("current original budget authority required")
                budget_ledger.authority_binding_digest
                if self._budget is not None:
                    old_store, new_store = self._budget._store, budget_ledger._store
                    same_domain = old_store is new_store or (
                        isinstance(old_store, SQLiteBudgetStore)
                        and isinstance(new_store, SQLiteBudgetStore)
                        and old_store.path == new_store.path
                        and old_store._identity == new_store._identity
                    )
                    if not same_domain:
                        raise ValueError("budget source refresh cannot reset accounting history")
                required_limits = (
                    self._active.budget_limits
                    if self._active and self._active.budget_limits
                    else self._budget.policy.limits
                    if self._budget
                    else self.maximum.budget_limits
                )
                selected = {(v.scope, v.metric, v.subject): v for v in budget_ledger.policy.limits}
                for limit in required_limits:
                    candidate = selected.get((limit.scope, limit.metric, limit.subject))
                    if (
                        candidate is None
                        or candidate.maximum > limit.maximum
                        or limit.unknown_ceiling is None
                        and candidate.unknown_ceiling is not None
                        or limit.unknown_ceiling is not None
                        and candidate.unknown_ceiling != limit.unknown_ceiling
                        or limit.unknown_effects
                        and (
                            not candidate.unknown_effects
                            or not set(candidate.unknown_effects) <= set(limit.unknown_effects)
                        )
                    ):
                        raise ValueError("budget source refresh exceeds approved maximum")
            if delegation_service is not None:
                if (
                    type(delegation_service) is not SwarmDelegationService
                    or delegation_service.authenticator._registry is not self._registry
                    or delegation_service.issuer.source.epoch != self._epoch
                    or delegation_service.issuer.operator_maximum.digest
                    != self.maximum.delegation_maximum_digest
                ):
                    raise ValueError("current original delegated authority required")
                delegation_service._operator_check(delegation_operator)
                delegation_service._online()
                if (
                    delegation_issuer is not None
                    and delegation_issuer is not delegation_service.issuer
                ):
                    raise ValueError("ambiguous policy delegation issuer")
                delegation_issuer = delegation_service.issuer
            if delegation_issuer is not None:
                if (
                    type(delegation_issuer) is not DelegationIssuer
                    or delegation_issuer.source.epoch != self._epoch
                    or delegation_issuer.operator_maximum.digest
                    != self.maximum.delegation_maximum_digest
                    or delegation_issuer.task_maximum.digest != self._task_maximum_digest
                ):
                    raise ValueError("current original policy delegation issuer required")
                delegation_issuer._require_configuration()
            if delegation_service is not None:
                delegation_service.bind_policy_runtime(
                    self,
                    operator=delegation_operator,
                    facts_provider=delegation_service._policy_facts_provider,
                )
            self.facts_source.fence()
            self._source_generation += 1
            if flow is not None:
                self._flow = flow
            if temporal_engine is not None:
                self._temporal = temporal_engine
            if budget_ledger is not None:
                self._budget = budget_ledger
            if delegation_service is not None:
                self._delegation, self._delegation_operator = (
                    delegation_service,
                    delegation_operator,
                )
            if delegation_issuer is not None:
                self._issuer = delegation_issuer

    @property
    def required_checks(self) -> tuple[str, ...]:
        with self._lock:
            return self._active.required_checks if self._active else self.maximum.required_checks

    def register_gate(self, legacy: SwarmPolicy | None) -> None:
        value = (
            (0, frozenset(), frozenset())
            if legacy is None
            else (
                len(legacy.rules),
                frozenset(v.rule_id for v in legacy.rules),
                frozenset(legacy.required_checks),
            )
        )
        with self._lock:
            if self._active:
                self._compatible(self._active, (value,))
            if value not in self._gate_limits and len(self._gate_limits) >= 256:
                raise ValueError("policy gate registration capacity reached")
            self._gate_limits.add(value)

    def _compatible(self, plan: CompiledSwarmPolicy, constraints=None) -> None:
        if len(plan.required_checks) > 64:
            raise ValueError("policy check composition capacity exceeded")
        for count, rules, checks in self._gate_limits if constraints is None else constraints:
            if (
                count + len(plan.policy.rules) > 128
                or rules.intersection(v.rule_id for v in plan.policy.rules)
                or len(checks | set(plan.required_checks)) > 64
            ):
                raise ValueError("policy and legacy composition is ambiguous or oversized")

    def _context(self, context: SwarmContext):
        if type(context) is not SwarmContext:
            raise ValueError("original policy context required")
        row = self._registry._agents.get(context.identity.agent_id)
        if row is None or row.context is not context:
            raise ValueError("original current policy context required")
        adapter = self._registry._channels.get(row.channel)
        if adapter is None:
            raise ValueError("policy context channel unavailable")
        self._registry.authenticate(context, row.channel, adapter[0])
        return row.channel, adapter[0]

    def evidence_digest(self, context: SwarmContext) -> str:
        with self._lock:
            channel, adapter = self._context(context)
            flow = None
            if self._flow is not None:
                try:
                    flow = self._flow.binding_digest
                except ValueError:
                    flow = "unavailable"
            temporal = None
            if self._temporal is not None:
                try:
                    temporal = self._temporal.binding_digest
                except ValueError:
                    temporal = "unavailable"
            budget = None
            if self._budget is not None:
                try:
                    budget = self._budget.snapshot_digest(context, channel=channel, adapter=adapter)
                except ValueError:
                    budget = "unavailable"
            return digest([self.binding_digest, flow, temporal, budget])

    def _capabilities(self, policy: SwarmPolicySet | None = None) -> frozenset[str]:
        values = {"identity", "protected_facts"}
        if self._flow is not None:
            try:
                self._flow._graph.build()
                values.add("source_flow")
            except ValueError:
                pass
        if self._temporal is not None:
            try:
                self._temporal.binding_digest
                values.add("temporal")
            except ValueError:
                pass
        if (
            self._budget is not None
            and self._budget.policy.policy_epoch == self._epoch
            and not self._budget.policy.require_physical_enforcement
            and self._budget_binding() != "unavailable"
        ):
            values.add("budget.admission")
        if self._delegation is not None:
            try:
                self._delegation._online()
                if (
                    self._delegation.issuer.source.epoch == self._epoch
                    and self._delegation.authenticator._configuration()
                    == self._delegation.authenticator._tls_binding
                ):
                    values.add("delegation.online")
            except ValueError:
                pass
        # Physical capabilities are deliberately absent. A flag/plan/estimate
        # does not prove a live enforcing filesystem/process/broker boundary.
        if policy is not None and self._enforcement_binding(policy) not in {None, "unavailable"}:
            values.add("broker.enforce")
        return frozenset(values)

    def _enforcement_binding(self, policy: SwarmPolicySet | None) -> str | None:
        if policy is None or policy.digest not in self._enforcement:
            return None
        broker, proof = self._enforcement[policy.digest]
        try:
            if not broker.verify_activation(proof, policy_digest=policy.digest):
                return "unavailable"
            description = broker.describe_activation(proof)
            return digest(description)
        except (ValueError, AttributeError, TypeError):
            return "unavailable"

    def bind_enforcement(self, policy: SwarmPolicySet, broker, proof, *, operator: object) -> None:
        """Bind only an original verified broker-owned factory, never a flag/plan."""
        if operator is not self._operator or type(policy) is not SwarmPolicySet:
            raise ValueError("protected exact policy factory binding required")
        try:
            from .broker import SwarmExecutionBroker
        except ImportError:
            raise ValueError("verified enforcing broker bridge unavailable") from None
        with self._execution_barrier, self._lock:
            if (
                type(broker) is not SwarmExecutionBroker
                or policy.enforcement_scope != "broker_owned_fresh_worker_route"
            ):
                raise ValueError("unsupported policy enforcement boundary")
            plan = compile_swarm_policy_set(policy, self.maximum)
            permissions = plan.permissions
            if (
                permissions.action_kinds is None
                or not set(permissions.action_kinds) <= {"tool"}
                or permissions.effects is None
                or not set(permissions.effects) <= {"filesystem.read"}
                or not permissions.tools
                or any(v.kind != "tool" for v in permissions.tools)
                or not permissions.resources
                or any(v.type != "path" for v in permissions.resources)
            ):
                raise ValueError("policy exceeds supported exact read-worker route")
            from ordin.assurance.delegation import DelegationAuthority
            from ordin.runtime_boundary import RuntimeCapabilityBoundary
            from ordin.runtime_contract import (
                FilesystemCapability,
                ToolCapability,
                ProcessCapability,
            )

            authority = DelegationAuthority(
                RuntimeCapabilityBoundary(
                    "policy-" + policy.digest[:16],
                    filesystem=tuple(
                        FilesystemCapability("read", v.value) for v in permissions.resources
                    ),
                    tools=tuple(ToolCapability(v.scope, None, v.name) for v in permissions.tools),
                    process=ProcessCapability(execution=False, spawn_children=False),
                )
            )
            if not broker.verify_activation(
                proof, policy_digest=policy.digest
            ) or not broker.policy_fits(proof, authority, policy_digest=policy.digest):
                raise ValueError("actual broker factory does not cover exact policy authority")
            description = broker.describe_activation(proof)
            if (
                description.get("scope") != "broker_owned_fresh_worker_route"
                or description.get("physical_policy_applied") is not False
                or description.get("requires_action_admission") is not True
            ):
                raise ValueError(
                    "broker proof does not describe its actual limited factory boundary"
                )
            if policy.digest not in self._enforcement and len(self._enforcement) >= self._limit:
                raise ValueError("policy factory binding capacity reached")
            self._enforcement[policy.digest] = (broker, proof)
            self._source_generation += 1
            self.facts_source.fence()

    def prepare(self, policy: SwarmPolicySet, *, lifetime: float = 300) -> SwarmPolicyDeployment:
        if not 0 < timestamp(lifetime) <= 3600:
            raise ValueError("invalid deployment lifetime")
        with self._lock:
            self._configuration()
            plan = compile_swarm_policy_set(policy, self.maximum)
            self._compatible(plan)
            self._require_supported(plan)
            if len(self._deployments) >= self._limit:
                raise ValueError("policy deployment history capacity reached")
            proposal = SwarmPolicyDeployment(
                uuid4().hex,
                plan.digest,
                self.binding_digest,
                counter(self._epoch + 1, "policy_epoch"),
                self._now() + lifetime,
            )
            self._deployments[proposal] = plan
            return proposal

    def _require_supported(self, plan: CompiledSwarmPolicy) -> None:
        policy = plan.policy
        needed = set(plan.required_capabilities)
        if (
            policy.enforcement_scope == "all_agent_paths"
            or "broker.enforce" in needed
            and policy.enforcement_scope != "broker_owned_fresh_worker_route"
        ):
            raise ValueError("required live/all-path enforcement is unsupported")
        if policy.enforcement_scope == "broker_owned_fresh_worker_route":
            needed.add("broker.enforce")
        if plan.budget_limits or self._budget is not None:
            needed.add("budget.admission")
        if not needed <= self._capabilities(policy):
            raise ValueError(
                "required policy capability unavailable; verified re-enrollment or restart required"
            )

    def _proposal(self, proposal: SwarmPolicyDeployment) -> CompiledSwarmPolicy:
        if type(proposal) is not SwarmPolicyDeployment or proposal not in self._deployments:
            raise ValueError("original policy deployment required")
        plan = self._deployments[proposal]
        if (
            proposal.compilation_digest != plan.digest
            or proposal.base_binding_digest != self.binding_digest
            or proposal.target_epoch != self._epoch + 1
            or self._now() >= proposal.expires_at
        ):
            raise ValueError("stale policy deployment")
        return plan

    def simulate(
        self,
        proposal: SwarmPolicyDeployment,
        cases: tuple[SwarmPolicyReplayCase, ...],
        *,
        ordin: Ordin | None = None,
    ) -> SwarmPolicySimulation:
        if (
            type(cases) is not tuple
            or not 1 <= len(cases) <= 256
            or any(type(v) is not SwarmPolicyReplayCase for v in cases)
            or len({v.case_id for v in cases}) != len(cases)
        ):
            raise ValueError("bounded explicit replay cases required")
        with self._lock:
            plan = self._proposal(proposal)
            self._require_supported(plan)
            if len(self._simulations) >= self._limit * 4:
                raise ValueError("policy simulation history capacity reached")
            baseline = AgentGate(replace(ordin or Ordin(), audit=None))
            before_plan = self._active or compile_swarm_policy_set(
                SwarmPolicySet(
                    "operator-maximum",
                    1,
                    self.maximum.tenant_id,
                    self.maximum.swarm_id,
                    default_disposition="execute",
                ),
                self.maximum,
            )
            outcomes, fingerprints, size = [], [], 0
            for case in cases:
                case.__post_init__()
                action = ActionEnvelope.from_dict(case.action.as_dict())
                size += len(str(action.as_dict()).encode())
                if size > 1048576:
                    raise ValueError("policy replay corpus limit exceeded")
                result = baseline.evaluate_action(action)
                if not isinstance(result.review, ActionReview):
                    raise ValueError("policy replay requires an action review")
                before: str
                before = before_plan.evaluate(
                    case.context, action, result.review, result.disposition, facts=case.facts
                ).disposition
                after = plan.evaluate(
                    case.context, action, result.review, result.disposition, facts=case.facts
                ).disposition
                outcomes.append((case.case_id, before, after, case.expected))
                fingerprints.append(
                    [
                        case.case_id,
                        digest(case.context.as_dict()),
                        digest(action.as_dict()),
                        case.expected,
                        case.facts.digest if case.facts else None,
                    ]
                )
            simulation = SwarmPolicySimulation(
                proposal.deployment_id,
                plan.digest,
                self.binding_digest,
                digest(fingerprints),
                tuple(outcomes),
                self._relaxes(plan),
            )
            self._simulations[simulation] = simulation.digest
            return simulation

    def approve(
        self,
        proposal: SwarmPolicyDeployment,
        simulation: SwarmPolicySimulation,
        *,
        operator: object,
        allow_relaxation: bool = False,
    ) -> SwarmPolicyApproval:
        if operator is not self._operator or type(allow_relaxation) is not bool:
            raise ValueError("original protected operator approval required")
        with self._lock:
            plan = self._proposal(proposal)
            if len(self._approvals) >= self._limit * 4:
                raise ValueError("policy approval history capacity reached")
            self._require_supported(plan)
            if (
                type(simulation) is not SwarmPolicySimulation
                or self._simulations.get(simulation) != simulation.digest
                or simulation.deployment_id != proposal.deployment_id
                or simulation.compilation_digest != plan.digest
                or simulation.base_binding_digest != self.binding_digest
            ):
                raise ValueError("original exact policy simulation required")
            result = simulation.as_dict()
            if (
                result["unsafe_executable"]
                or (result["relaxations"] or result["structural_relaxation"])
                and not allow_relaxation
            ):
                raise ValueError(
                    "policy simulation requires explicit relaxation approval or rejects unsafe cases"
                )
            approval = SwarmPolicyApproval(
                uuid4().hex,
                proposal.deployment_id,
                simulation.digest,
                plan.digest,
                proposal.target_epoch,
                self.binding_digest,
                proposal.expires_at,
            )
            self._approvals[approval] = (
                proposal,
                digest(
                    [
                        approval.approval_id,
                        approval.simulation_digest,
                        approval.compilation_digest,
                        approval.target_epoch,
                        approval.base_binding_digest,
                        approval.expires_at,
                    ]
                ),
            )
            return approval

    def activate(self, approval: SwarmPolicyApproval, *, operator: object) -> SwarmPolicyActivation:
        if operator is not self._operator:
            raise ValueError("original protected operator activation required")
        with self._execution_barrier, self._lock:
            original = (
                self._approvals.get(approval) if type(approval) is SwarmPolicyApproval else None
            )
            if (
                original is None
                or approval in self._used
                or original[1]
                != digest(
                    [
                        approval.approval_id,
                        approval.simulation_digest,
                        approval.compilation_digest,
                        approval.target_epoch,
                        approval.base_binding_digest,
                        approval.expires_at,
                    ]
                )
            ):
                raise ValueError("original unused exact policy approval required")
            plan = self._proposal(original[0])
            self._compatible(plan)
            self._require_supported(plan)
            if (
                approval.target_epoch != self._epoch + 1
                or approval.base_binding_digest != self.binding_digest
            ):
                raise ValueError("stale policy activation")
            self._used.add(approval)
            next_epoch = approval.target_epoch
            self._available = False
            # Once fencing starts, failure cannot resurrect an older epoch. No
            # guarded callback can run while this shared barrier is held.
            self._registry.advance_policy_epoch(next_epoch)
            self._epoch = next_epoch
            self._generation += 1
            try:
                self.facts_source.fence()
                if self._delegation is not None:
                    self._delegation.fence_policy(operator=self._delegation_operator)
                    self._delegation.bind_policy_runtime(
                        self,
                        operator=self._delegation_operator,
                        facts_provider=self._delegation._policy_facts_provider,
                    )
                elif self._issuer is not None:
                    self._issuer.invalidate_policy()
                if self._temporal is not None:
                    policy = self._temporal._policy.policy
                    from .temporal_policy import SwarmTemporalPolicySet

                    self._temporal.upgrade_policy(
                        SwarmTemporalPolicySet(policy.policy_id, policy.revision + 1, policy.rules)
                    )
                if self._budget is not None:
                    current = self._budget
                    limits = plan.budget_limits or current.policy.limits
                    self._budget = BudgetLedger(
                        self._registry,
                        BudgetPolicy(
                            next_epoch,
                            limits,
                            current.policy.reservation_lifetime,
                            current.policy.max_reservations,
                            current.policy.require_physical_enforcement,
                        ),
                        store=current._store,
                        clock=current._clock,
                        operator=current._operator,
                        observations=current._observations,
                    )
                elif plan.budget_limits:
                    raise ValueError("budget history unavailable")
                self._active, self._approval_digest = (
                    plan,
                    digest(
                        [
                            approval.approval_id,
                            approval.simulation_digest,
                            approval.compilation_digest,
                            next_epoch,
                        ]
                    ),
                )
                self._available = True
            except Exception:
                self._active = None
                self._approval_digest = None
                return SwarmPolicyActivation(
                    plan.policy_digest,
                    plan.digest,
                    next_epoch,
                    "failed_closed",
                    ("policy.activation_incomplete",),
                    self._budget,
                )
            return SwarmPolicyActivation(
                plan.policy_digest,
                plan.digest,
                next_epoch,
                "active_requires_reenrollment",
                ("policy.old_authorizations_fenced", "policy.fresh_contexts_and_sources_required"),
                self._budget,
            )

    @contextmanager
    def execution_guard(self, context: SwarmContext, *, broker=None) -> Iterator[None]:
        with self._execution_barrier:
            with self._lock:
                self._configuration()
                self._context(context)
                if (
                    not self._available
                    or self._active is None
                    or context.identity.policy_epoch != self._epoch
                ):
                    raise ValueError("active current policy execution scope unavailable")
                if (
                    self._active.policy.enforcement_scope == "broker_owned_fresh_worker_route"
                    or "broker.enforce" in self._active.required_capabilities
                ):
                    binding = self._enforcement.get(self._active.policy_digest)
                    if (
                        binding is None
                        or broker is not binding[0]
                        or self._enforcement_binding(self._active.policy) in {None, "unavailable"}
                    ):
                        raise ValueError(
                            "policy requires its original verified enforcing broker route"
                        )
            yield

    def _evaluate(
        self,
        context: SwarmContext,
        action: ActionEnvelope,
        baseline,
        *,
        facts: SwarmPolicyFacts | None,
        policy_digest: str,
        snapshot_digest: str,
        checks: dict[str, str] | None = None,
        delegation_gate: DelegatingAssuranceGate | None = None,
    ) -> SwarmPolicyResult:
        with self._lock:
            try:
                self._configuration()
                self._context(context)
                if (
                    not self._available
                    or self._active is None
                    or context.identity.policy_epoch != self._epoch
                ):
                    raise ValueError("inactive policy")
                needed = set(self._active.required_capabilities) | (
                    {"budget.admission"} if self._budget is not None else set()
                )
                if self._active.policy.enforcement_scope == "broker_owned_fresh_worker_route":
                    needed.add("broker.enforce")
                if not needed <= self._capabilities(self._active.policy):
                    return SwarmPolicyResult(
                        "deny", ("policy.required_capability_unavailable",), ()
                    )
                if context.identity.delegation_id is not None:
                    if (
                        type(delegation_gate) is not DelegatingAssuranceGate
                        or delegation_gate.issuer is not self._issuer
                        or self.maximum.delegation_maximum_digest is None
                        or delegation_gate.issuer.operator_maximum.digest
                        != self.maximum.delegation_maximum_digest
                        or delegation_gate.grant.record.grant_id != context.identity.delegation_id
                        or delegation_gate.source.principal != context.identity.agent_id
                        or delegation_gate.source.epoch != context.identity.policy_epoch
                    ):
                        return SwarmPolicyResult("deny", ("policy.delegation_unverified",), ())
                    delegation_gate.issuer.require_current(
                        delegation_gate.grant, delegation_gate.source
                    )
                if facts is not None and not self.facts_source.verify(
                    facts,
                    context,
                    action,
                    policy_digest=policy_digest,
                    snapshot_digest=snapshot_digest,
                ):
                    return SwarmPolicyResult("deny", ("policy.facts_unverified",), ())
                review: ActionReview = baseline.review
                return self._active.evaluate(
                    context, action, review, baseline.disposition, facts=facts, checks=checks
                )
            except ValueError:
                return SwarmPolicyResult("deny", ("policy.current_scope_unverified",), ())

    def evaluate_baseline(
        self,
        context: SwarmContext,
        action: ActionEnvelope,
        baseline,
        *,
        facts: SwarmPolicyFacts | None = None,
        delegation_gate: DelegatingAssuranceGate | None = None,
    ) -> SwarmPolicyResult:
        return self._evaluate(
            context,
            action,
            baseline,
            facts=facts,
            policy_digest=self.binding_digest,
            snapshot_digest=self.evidence_digest(context),
            delegation_gate=delegation_gate,
        )

    def _relaxes(self, candidate: CompiledSwarmPolicy) -> bool:
        if self._active is not None and policy_relaxes(self._active, candidate):
            return True
        actual = self._budget.policy.limits if self._budget else ()
        effective = candidate.budget_limits or actual
        selected = {(v.scope, v.metric, v.subject): v.maximum for v in effective}
        return any(
            (maximum := selected.get((v.scope, v.metric, v.subject))) is None or maximum > v.maximum
            for v in actual
        )
