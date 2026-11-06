"""Exact action-bound execution bridge over original authority and real executors."""

from __future__ import annotations

from contextlib import nullcontext
from dataclasses import dataclass, field, replace
import hashlib
import tempfile
from pathlib import Path
from threading import Event, RLock
from typing import Any, Callable
from uuid import uuid4

from ordin import (
    AgentGate,
    Ordin,
    ToolCallAdapter,
    ToolResourceBinding,
    ToolSemanticRule,
    ToolSemanticsRegistry,
)
from ordin.action import ActionEnvelope
from ordin._runtime_json import digest
from ordin.assurance import AssuranceGate, DelegationAuthority
from ordin.assurance.rest import derive_rest_request_contract
from ordin.runtime_boundary import RuntimeCapabilityBoundary
from ordin.runtime_contract import (
    CredentialBinding,
    FilesystemCapability,
    ProcessCapability,
    PrivilegeCapability,
    ToolCapability,
    derive_runtime_capability_contract,
)
from ordin.runtime_requests_v2 import derive_runtime_request_contract_v2

from .authorization import (
    BrokerActivationProof,
    BrokerAuthorization,
    BrokerAuthorizationScope,
    BrokerBudgetProof,
    BrokerControlReceipt,
    BrokerGatewayBinding,
    BrokerPreparation,
    BrokerResult,
)
from .budgets import BudgetCost, BudgetError, BudgetLedger, BudgetObservationSource
from .delegation import BrokerAdmissionScope, SwarmDelegationService
from .events import _hex
from .gate import SwarmGate
from .linux_backend import ExecutorOutcome, LinuxFileReadBackend
from .models import SwarmContext
from .workload_auth import AuthorityChannel


@dataclass
class _Pending:
    scope: BrokerAuthorizationScope
    caller_action: ActionEnvelope
    workload_channel: AuthorityChannel
    admission_id: str
    registry_channel: Any
    adapter: object
    event_source: Any
    options: dict[str, Any]
    configuration_digest: str
    runtime_digest: str | None
    owned_job: Any
    reporting_source: Any
    delegation_binding_digest: str
    runtime_evidence_digest: str | None = None
    state: str = "prepared"
    stop: Event = field(default_factory=Event)
    forwarded: bool = False
    result: BrokerResult | None = None


@dataclass(frozen=True)
class _Activation:
    policy_digest: str
    factory_digest: str
    expires_at: int
    evidence_digest: str
    description: dict[str, Any]
    probe_executor: LinuxFileReadBackend = field(repr=False)
    probe_outcome: ExecutorOutcome = field(repr=False)
    probe_plan: Any = field(repr=False)


class SwarmExecutionBroker:
    """Protected typed broker, not an arbitrary executor callback or cached permit.

    Workload identity, source enrollment, budget providers and policy runtime are
    host-owned. Its physical claim is confined to supported owned executor
    routes; raw host/agent access outside them remains uncovered.
    """

    def __init__(
        self,
        service: SwarmDelegationService,
        broker_channel: AuthorityChannel,
        global_gate: SwarmGate,
        budget: BudgetLedger,
        executor: LinuxFileReadBackend,
        *,
        operator: object,
        assessment_provider: Callable | None = None,
        cost_provider: Callable | None = None,
        policy_runtime: Any = None,
        max_authorizations: int = 4096,
    ) -> None:
        if (
            type(service) is not SwarmDelegationService
            or type(global_gate) is not SwarmGate
            or type(budget) is not BudgetLedger
            or type(executor) is not LinuxFileReadBackend
            or operator is not service._operator
            or operator is not executor._operator
            or global_gate._registry is not service.authenticator._registry
            or budget._registry is not global_gate._registry
            or type(global_gate._baseline) is not AssuranceGate
            or global_gate._baseline.configuration_digest != service.assurance.configuration_digest
            or type(max_authorizations) is not int
            or not 1 <= max_authorizations <= 16384
            or (assessment_provider is not None and not callable(assessment_provider))
            or (cost_provider is not None and not callable(cost_provider))
        ):
            raise ValueError(
                "broker requires shared original authority, global checks, ledger and owned executor"
            )
        service.authenticator.require(broker_channel, role="broker")
        self._service, self._broker_channel, self._gate, self._budget, self._executor = (
            service,
            broker_channel,
            global_gate,
            budget,
            executor,
        )
        self._operator, self._assessments, self._costs = (
            operator,
            assessment_provider,
            cost_provider,
        )
        self._runtime, self._limit = policy_runtime, max_authorizations
        self._registry = global_gate._registry
        self._nonce = uuid4().hex
        self._execution_lock = RLock()
        self._state_lock = RLock()
        self._pending: dict[BrokerAuthorization, _Pending] = {}
        self._results: dict[BrokerResult, tuple[BrokerAuthorization, str]] = {}
        self._controls: dict[BrokerControlReceipt, tuple[BrokerAuthorization, str]] = {}
        self._proofs: dict[BrokerActivationProof, _Activation] = {}
        self._budget_proofs: dict[BrokerBudgetProof, tuple] = {}
        self._gateway_bindings: dict[BrokerGatewayBinding, tuple] = {}
        budget.bind_executor(self, operator=operator)

    def _guard(self, context: SwarmContext):
        return (
            nullcontext()
            if self._runtime is None
            else self._runtime.execution_guard(context, broker=self)
        )

    def _barrier(self):
        if self._runtime is not None:
            return self._runtime.execution_barrier
        if self._service._containment is not None:
            return self._service._policy_barrier()
        return self._execution_lock

    @property
    def factory_configuration_digest(self) -> str:
        return digest(
            [
                self._nonce,
                self._executor.configuration_digest,
                hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            ]
        )

    @property
    def configuration_digest(self) -> str:
        return digest(
            [
                self.factory_configuration_digest,
                self._service.issuer._issuer_key,
                self._gate.configuration_digest,
                self._budget.policy.digest,
                self._runtime.binding_digest if self._runtime is not None else None,
            ]
        )

    def _runtime_digest(self):
        return self._runtime.binding_digest if self._runtime is not None else None

    def _pending_row(self, authorization: BrokerAuthorization) -> _Pending:
        if type(authorization) is not BrokerAuthorization or authorization not in self._pending:
            raise ValueError("unknown original broker authorization")
        return self._pending[authorization]

    def _contract(self, scope: BrokerAdmissionScope, review):
        capability = derive_runtime_capability_contract(review)
        credentials = tuple(
            CredentialBinding(v.binding, v.host, v.port)
            for v in scope.review_context.credential_uses
            if v.action_digest == scope.action_digest
            and v.profile_digest == self._service.issuer.profile.digest
        )
        if credentials:
            from dataclasses import replace

            capability = replace(
                capability,
                credentials=tuple(dict.fromkeys((*capability.credentials, *credentials))),
                contract_id="",
            )
        if review.adapter == "network.rest":
            complete = derive_rest_request_contract(review, capability=capability)
        else:
            request = derive_runtime_request_contract_v2(review)
            if request.requests or any(
                n.protocol in {"graphql", "mcp", "json-rpc"} for n in capability.network
            ):
                from dataclasses import replace

                complete = replace(request, capability=capability, request_contract_id="")
            else:
                complete = capability
        if complete.digest != scope.delegated_decision.contract_digest:
            raise ValueError("broker original delegated requirements changed")
        return complete, capability

    def _default_costs(self) -> tuple[BudgetCost, ...]:
        return tuple(
            BudgetCost(metric, value)
            for metric, value in (
                ("requests", 1),
                ("concurrency", 1),
                ("tool_calls", 1),
                ("external_operations", 1),
                ("processes", 1),
                ("child_spawns", 1),
                ("destructive_actions", 0),
                ("output_bytes", self._executor.max_stdout_bytes),
                ("tokens", None),
                ("dollar_micros", None),
            )
        )

    def _budget_proof(self, scope, channel, grant_ref):
        complete, capability = self._contract(scope, scope.delegated_decision.assurance.review)
        if complete.digest != capability.digest:
            raise ValueError("owned executor cannot enforce the complete request domain")
        compiled = self._executor.compile(capability)
        if (
            not compiled.enforceable
            or compiled.plan is None
            or not self._executor.validate(compiled.plan).ok
        ):
            raise ValueError("physical budget executor requirements unsupported")
        with self._state_lock:
            candidates = tuple(self._proofs)
        factory = next(
            (
                v
                for v in candidates
                if self.verify_activation(v, policy_digest=self._gate.policy_digest)
            ),
            None,
        )
        if factory is None:
            factory = self.activation_proof(self._gate.policy_digest, operator=self._operator)
        limits = dict((v.metric, v.amount) for v in self._default_costs() if v.amount is not None)
        proof = BrokerBudgetProof(uuid4().hex)
        with self._state_lock:
            if len(self._budget_proofs) >= self._limit:
                raise ValueError("broker budget proof capacity reached")
            self._budget_proofs[proof] = (
                scope,
                channel,
                grant_ref,
                factory,
                compiled.plan,
                self.configuration_digest,
                limits,
            )
        return proof

    def verify_budget_proof(self, proof, context, action, costs) -> bool:
        with self._state_lock:
            row = self._budget_proofs.get(proof) if type(proof) is BrokerBudgetProof else None
        if row is None or type(context) is not SwarmContext or type(action) is not ActionEnvelope:
            return False
        scope, channel, grant_ref, factory, plan, config, limits = row
        try:
            with self._service._lock, self._service.issuer._lock:
                grant, subject = self._service._grant(channel, grant_ref)
                return (
                    subject.context is context
                    and context is scope.context
                    and digest(action.as_dict()) == scope.action_digest
                    and digest(grant_ref) == scope.grant_digest
                    and grant.gate is scope.delegating_gate
                    and grant.handle is scope.delegating_gate.grant
                    and self._service.issuer._now() < scope.expires_at
                    and self.configuration_digest == config
                    and self.verify_activation(
                        factory, policy_digest=self._gate.policy_digest, context=context
                    )
                    and self._executor.validate(plan).ok
                    and type(costs) is tuple
                    and all(
                        type(v) is BudgetCost
                        and v.metric in limits
                        and type(v.amount) is int
                        and v.amount >= limits[v.metric]
                        for v in costs
                    )
                )
        except (ValueError, OSError, RuntimeError):
            return False

    def supports_budget_policy(self, policy) -> bool:
        """Current original factory readiness; every action still needs its proof."""
        if policy is not self._budget.policy:
            return False
        bounds = {v.metric: v.amount for v in self._default_costs() if v.amount is not None}
        with self._state_lock:
            proofs = tuple(self._proofs.items())
        return all(
            v.metric in bounds and v.maximum >= bounds[v.metric] for v in policy.limits
        ) and any(
            self.verify_activation(proof, policy_digest=row.policy_digest) for proof, row in proofs
        )

    def _cancel_admission(self, reference: str) -> None:
        with self._service._lock, self._service.issuer._lock:
            row = self._service._admissions.get(reference)
            if row is not None:
                self._service._cancel(row, "broker_canceled")

    def bind_gateway(self, workload_channel, grant_ref: str, *, operator: object):
        """Bind an original host route; a JSON grant name alone cannot enroll it."""
        if operator is not self._operator:
            raise ValueError("protected broker operator required")
        with self._service._lock, self._service.issuer._lock:
            _, subject = self._service._grant(workload_channel, grant_ref)
            if subject.context is None or subject.context.coverage.mode not in {
                "intercept",
                "enforce",
            }:
                raise ValueError("current mediated workload required")
            binding = BrokerGatewayBinding(uuid4().hex)
            with self._state_lock:
                if len(self._gateway_bindings) >= self._limit:
                    raise ValueError("broker gateway binding capacity reached")
                self._gateway_bindings[binding] = (
                    workload_channel,
                    grant_ref,
                    subject.context,
                    subject.registry_channel,
                    subject.adapter,
                )
            return binding

    def gateway_scope(self, binding: BrokerGatewayBinding):
        with self._state_lock:
            row = (
                self._gateway_bindings.get(binding)
                if type(binding) is BrokerGatewayBinding
                else None
            )
        if row is None:
            raise ValueError("original broker gateway binding required")
        channel, grant_ref, context, registry_channel, adapter = row
        if type(context) is not SwarmContext:
            raise ValueError("broker gateway original context required")
        with self._service._lock, self._service.issuer._lock:
            _, current = self._service._grant(channel, grant_ref)
            if current.context is not context:
                raise ValueError("broker gateway context changed")
        self._registry.authenticate(context, registry_channel, adapter)
        return row

    def _policy_review(self, scope, decision, registry_channel, adapter):
        if self._runtime is None:
            return None
        from importlib import import_module

        SwarmBudgetFact = getattr(import_module("ordin.swarm.policy_facts"), "SwarmBudgetFact")

        report = self._budget.report(scope.context, channel=registry_channel, adapter=adapter)
        snapshot = self._runtime.evidence_digest(scope.context)
        facts = self._runtime.facts_source.issue(
            scope.context,
            scope.action,
            policy_digest=self._runtime.binding_digest,
            snapshot_digest=snapshot,
            budgets=tuple(
                SwarmBudgetFact(v["scope"], v["metric"], v["remaining"]) for v in report["limits"]
            ),
        )
        result = self._runtime.evaluate_baseline(
            scope.context,
            scope.action,
            decision.baseline,
            facts=facts,
            delegation_gate=scope.delegating_gate,
        )
        if result.disposition != "execute":
            raise ValueError("current compiled policy restricts broker execution")
        return snapshot

    def prepare(
        self,
        workload_channel: AuthorityChannel,
        grant_ref: str,
        action: ActionEnvelope,
        *,
        idempotency_key: str,
        event_source=None,
        gateway_binding: BrokerGatewayBinding | None = None,
    ) -> BrokerPreparation:
        if type(action) is not ActionEnvelope:
            raise ValueError("typed exact broker action required")
        caller = ActionEnvelope.from_dict(action.as_dict())
        caller_digest = digest(caller.as_dict())
        reviewed_action = caller
        if gateway_binding is not None:
            bound = self.gateway_scope(gateway_binding)
            if bound[:2] != (workload_channel, grant_ref):
                raise ValueError("foreign broker gateway binding")
            reviewed_action = replace(caller, action_id="swarm-" + uuid4().hex)
        admission_id = None
        budget_ticket = None
        canonical_digest = None
        decision = None
        try:
            with self._service._lock, self._service.issuer._lock:
                grant, subject = self._service._grant(workload_channel, grant_ref)
                if (
                    subject.context is None
                    or subject.source is None
                    or subject.registry_channel is None
                ):
                    raise ValueError("broker workload scope unavailable")
                context = subject.context
                if context.coverage.mode not in {"intercept", "enforce"}:
                    raise ValueError("broker workload route is not mediated")
                if (
                    grant.parent_ref is not None
                    and context.identity.delegation_id != grant.handle.record.grant_id
                ):
                    raise ValueError("broker requires a verified current delegation context rebind")
                if grant.gate.runtime_session_digest != subject.source.session_digest:
                    raise ValueError("broker requires the original planned runtime session mapping")
                source = self._executor.evidence_source(
                    session_digest=subject.source.session_digest,
                    policy_digest=subject.source.runtime_policy_digest,
                    context_digest=digest([subject.source.key, context.registry_id]),
                )
                grant.gate.bind_runtime_source(source)
            with self._barrier(), self._guard(context), self._execution_lock:
                reviewed = self._service.review(workload_channel, grant_ref, reviewed_action)
                admission_id = reviewed.admission_id
                canonical_digest = reviewed.action_digest
                if reviewed.disposition != "execute" or admission_id is None:
                    return BrokerPreparation(
                        reviewed.disposition,
                        reviewed.reason_codes or ("broker.delegation_refused",),
                        canonical_digest,
                        caller_digest,
                        self._gate.policy_digest,
                    )
                scope = self._service.admission_scope(self._broker_channel, admission_id)
                if scope.action_digest != digest(reviewed_action.as_dict()):
                    raise ValueError(
                        "broker canonical caller action requires an explicit protected binding"
                    )
                costs = (
                    self._default_costs()
                    if self._costs is None
                    else self._costs(scope.context, scope.action, scope)
                )
                executor_proof = (
                    self._budget_proof(scope, workload_channel, grant_ref)
                    if self._budget.policy.require_physical_enforcement
                    else None
                )
                budget_ticket = self._budget.reserve(
                    scope.context,
                    scope.action,
                    channel=subject.registry_channel,
                    adapter=subject.adapter,
                    idempotency_key=idempotency_key,
                    costs=costs,
                    effects=tuple(scope.delegated_decision.assurance.review.effects),
                    executor=self,
                    executor_proof=executor_proof,
                )
                options = scope.review_options
                provider_options = (
                    {**options, "event_source": event_source}
                    if self._gate._events is not None
                    else options
                )
                assessments = (
                    ()
                    if self._assessments is None
                    else self._assessments(
                        scope.context, scope.action, self._gate, provider_options, budget_ticket
                    )
                )
                decision = self._gate.evaluate_action(
                    scope.context,
                    scope.action,
                    channel=subject.registry_channel,
                    adapter=subject.adapter,
                    event_source=event_source,
                    assessments=assessments,
                    **options,
                )
                if not decision.may_execute:
                    self._budget.cancel(budget_ticket)
                    budget_ticket = None
                    self._cancel_admission(admission_id)
                    return BrokerPreparation(
                        decision.disposition,
                        decision.reason_codes or ("broker.global_refused",),
                        canonical_digest,
                        caller_digest,
                        self._gate.policy_digest,
                        decision=decision,
                    )
                runtime_evidence = self._policy_review(
                    scope, decision, subject.registry_channel, subject.adapter
                )
                complete, capability = self._contract(scope, decision.review)
                if getattr(complete, "requests", ()) or decision.review.adapter == "network.rest":
                    raise ValueError(
                        "selected owned executor cannot enforce this complete request domain"
                    )
                compiled = self._executor.compile(capability)
                if (
                    not compiled.enforceable
                    or compiled.plan is None
                    or not self._executor.validate(compiled.plan).ok
                ):
                    raise ValueError(
                        "broker executor compilation or required runtime support failed"
                    )
                current = self._service.admission_scope(self._broker_channel, admission_id)
                if current.ancestry_digest != scope.ancestry_digest:
                    raise ValueError("broker delegation changed during preparation")
                authorization = BrokerAuthorization(uuid4().hex)
                owned_job = self._executor.create_job(compiled.plan, operator=self._operator)
                prepared = BrokerAuthorizationScope(
                    scope.action,
                    scope.context,
                    compiled.plan,
                    decision,
                    scope,
                    budget_ticket,
                    caller_digest,
                    digest(authorization.authorization_id),
                    scope.expires_at,
                    self._gate.policy_digest,
                )
                row = _Pending(
                    prepared,
                    caller,
                    workload_channel,
                    admission_id,
                    subject.registry_channel,
                    subject.adapter,
                    event_source,
                    options,
                    self.configuration_digest,
                    self._runtime_digest(),
                    owned_job,
                    source,
                    scope.delegating_gate.preview_binding_digest,
                    runtime_evidence,
                )
                with self._state_lock:
                    if len(self._pending) >= self._limit:
                        raise ValueError("broker authorization capacity reached")
                    self._pending[authorization] = row
                return BrokerPreparation(
                    "execute",
                    (),
                    canonical_digest,
                    caller_digest,
                    self._gate.policy_digest,
                    authorization,
                    decision,
                )
        except (ValueError, BudgetError, OSError, RuntimeError):
            if admission_id is not None:
                self._cancel_admission(admission_id)
            if budget_ticket is not None:
                try:
                    self._budget.cancel(budget_ticket)
                except (ValueError, OSError, RuntimeError):
                    pass
            return BrokerPreparation(
                "deny",
                ("broker.preparation_incomplete",),
                canonical_digest,
                caller_digest,
                self._gate.policy_digest,
                decision=decision,
            )

    def authorization_scope(self, authorization: BrokerAuthorization) -> BrokerAuthorizationScope:
        with self._state_lock:
            return self._pending_row(authorization).scope

    def _finish(self, authorization, row, status, reason, budget_status, outcome=None):
        actual = (
            outcome
            if type(outcome) is ExecutorOutcome
            and self._executor.verify_outcome(outcome, row.scope.plan)
            else None
        )
        result = BrokerResult(
            status,
            reason,
            digest(row.scope.action.as_dict()),
            row.scope.caller_digest,
            row.scope.authorization_digest,
            bool(actual and actual.physical_enforcement),
            row.forwarded,
            budget_status,
            actual.observation.digest if actual and actual.observation else None,
            actual,
            actual.value if actual and status == "completed" else None,
        )
        with self._state_lock:
            row.state, row.result = status, result
            self._results[result] = (authorization, digest(result.as_dict()))
        return result

    def verify_result(self, result: BrokerResult, authorization: BrokerAuthorization) -> bool:
        with self._state_lock:
            return (
                type(result) is BrokerResult
                and authorization in self._pending
                and self._results.get(result) == (authorization, digest(result.as_dict()))
            )

    def dispatch(
        self, authorization: BrokerAuthorization, *, action: ActionEnvelope | None = None
    ) -> BrokerResult:
        with self._state_lock:
            row = self._pending_row(authorization)
            if row.state != "prepared":
                raise ValueError("broker authorization already consumed or fenced")
            row.state = "checking"
        budget_started = False
        try:
            with self._barrier(), self._guard(row.scope.context), self._execution_lock:
                selected = row.caller_action if action is None else action
                if (
                    row.stop.is_set()
                    or type(selected) is not ActionEnvelope
                    or digest(selected.as_dict()) != row.scope.caller_digest
                    or digest(row.scope.action.as_dict()) != row.scope.decision.action_digest
                ):
                    raise ValueError("broker action or cancellation binding changed")
                self._registry.authenticate(row.scope.context, row.registry_channel, row.adapter)
                if (
                    self.configuration_digest != row.configuration_digest
                    or self._runtime_digest() != row.runtime_digest
                ):
                    raise ValueError("broker policy or configuration changed")
                if self._service.issuer._now() >= row.scope.expires_at:
                    raise ValueError("broker authorization expired")
                if (
                    self._runtime is not None
                    and self._runtime.evidence_digest(row.scope.context)
                    != row.runtime_evidence_digest
                ):
                    raise ValueError("broker compiled policy evidence changed")
                current = self._service.admission_scope(self._broker_channel, row.admission_id)
                if current.ancestry_digest != row.scope.delegation_scope.ancestry_digest:
                    raise ValueError("broker current delegation binding changed")
                if current.delegating_gate.preview_binding_digest != row.delegation_binding_digest:
                    raise ValueError("broker retained runtime/history inputs changed")
                if not self._gate.binding_matches(
                    row.scope.decision,
                    row.scope.context,
                    row.scope.action,
                    channel=row.registry_channel,
                    adapter=row.adapter,
                    event_source=row.event_source,
                    **row.options,
                ):
                    raise ValueError("broker global facts changed")
                if (
                    self._budget.reservation_status(row.scope.budget_ticket)["status"] != "reserved"
                    or not self._executor.validate(row.scope.plan).ok
                ):
                    raise ValueError("broker budget or executor binding changed")
                captured = ActionEnvelope.from_dict(row.scope.action.as_dict())

                def forward(bound):
                    nonlocal budget_started
                    if row.stop.is_set() or digest(bound.as_dict()) != digest(captured.as_dict()):
                        raise ValueError("broker final effect binding changed")
                    self._registry.authenticate(
                        row.scope.context, row.registry_channel, row.adapter
                    )
                    budget_started = True
                    self._budget.begin_forward(
                        row.scope.budget_ticket,
                        row.scope.context,
                        bound,
                        channel=row.registry_channel,
                        adapter=row.adapter,
                    )
                    with self._state_lock:
                        row.state, row.forwarded = "forwarding", True
                    return self._executor.execute(
                        row.scope.plan,
                        bound,
                        row.reporting_source,
                        operator=self._operator,
                        job=row.owned_job,
                    )

                dispatch = self._service.guarded_dispatch(
                    self._broker_channel,
                    row.admission_id,
                    captured,
                    forward,
                    policy_broker=self,
                )
                outcome = dispatch.value
                if (
                    dispatch.status != "host_completed"
                    or type(outcome) is not ExecutorOutcome
                    or not self._executor.verify_outcome(outcome, row.scope.plan)
                ):
                    raise ValueError("broker did not acquire an original executor outcome")
                if (
                    outcome.status not in {"completed", "denied"}
                    or not outcome.physical_enforcement
                    or outcome.observation is None
                ):
                    self._budget.uncertain(row.scope.budget_ticket)
                    return self._finish(
                        authorization,
                        row,
                        "canceled" if outcome.status == "canceled" else "unknown",
                        outcome.reason_code,
                        "uncertain",
                        outcome,
                    )
                row.scope.delegation_scope.delegating_gate.observe_runtime(outcome.observation)
                settled = self._budget.commit(row.scope.budget_ticket)
                return self._finish(
                    authorization, row, outcome.status, outcome.reason_code, settled, outcome
                )
        except (ValueError, BudgetError, OSError, RuntimeError):
            self._cancel_admission(row.admission_id)
            state = "uncertain" if budget_started else "canceled"
            try:
                if budget_started:
                    self._budget.uncertain(row.scope.budget_ticket)
                else:
                    self._budget.cancel(row.scope.budget_ticket)
            except (ValueError, OSError, RuntimeError):
                state = "uncertain"
            return self._finish(
                authorization,
                row,
                "unknown" if budget_started else "canceled" if row.stop.is_set() else "denied",
                "broker.effect_refused_or_uncertain",
                state,
            )

    def cancel(self, authorization: BrokerAuthorization) -> BrokerControlReceipt:
        with self._state_lock:
            row = self._pending_row(authorization)
            if row.state != "prepared":
                return self.request_stop(authorization)
            row.stop.set()
            row.state = "canceled"
        with self._barrier(), self._execution_lock:
            self._cancel_admission(row.admission_id)
            try:
                self._budget.cancel(row.scope.budget_ticket)
                reason = "broker.queued_canceled"
            except (ValueError, OSError, RuntimeError):
                reason = "broker.queued_fenced_budget_uncertain"
        return self._control(authorization, row, "canceled", reason)

    def _control(self, authorization, row, status, reason):
        receipt = BrokerControlReceipt(
            row.scope.authorization_digest,
            status,
            reason,
            row.state,
            digest(row.scope.action.as_dict()),
            digest(row.scope.context.as_dict()),
            row.scope.context.identity.policy_epoch,
            digest(row.owned_job.job_id),
        )
        with self._state_lock:
            # Control operations remain available when the report history is
            # full. Evicted reports cease to be current protected evidence.
            while len(self._controls) >= self._limit * 4:
                self._controls.pop(next(iter(self._controls)))
            self._controls[receipt] = (authorization, digest(receipt.as_dict()))
        return receipt

    def verify_control_receipt(
        self, receipt: BrokerControlReceipt, authorization: BrokerAuthorization
    ) -> bool:
        with self._state_lock:
            row = self._pending.get(authorization)
            return (
                type(receipt) is BrokerControlReceipt
                and row is not None
                and self._controls.get(receipt) == (authorization, digest(receipt.as_dict()))
                and receipt.authorization_digest == row.scope.authorization_digest
                and receipt.action_digest == digest(row.scope.action.as_dict())
                and receipt.context_digest == digest(row.scope.context.as_dict())
                and receipt.policy_epoch == row.scope.context.identity.policy_epoch
                and receipt.owned_job_digest == digest(row.owned_job.job_id)
            )

    def request_stop(self, authorization: BrokerAuthorization) -> BrokerControlReceipt:
        with self._state_lock:
            row = self._pending_row(authorization)
            row.stop.set()
            status = self._executor.request_stop(row.owned_job, operator=self._operator)
            if row.state == "prepared":
                row.state, status = "canceled", "canceled"
            return self._control(authorization, row, status, "broker.owned_stop_requested")

    def status(self, authorization: BrokerAuthorization) -> BrokerControlReceipt:
        with self._state_lock:
            row = self._pending_row(authorization)
            job = self._executor.job_status(row.owned_job, operator=self._operator)
            status = (
                "canceled"
                if row.state == "canceled" or job == "canceled"
                else "completed"
                if row.result is not None and row.result.status in {"completed", "denied"}
                else "unable_to_stop"
                if job == "unable_to_stop"
                else "unknown"
            )
            return self._control(authorization, row, status, "broker.owned_status")

    def active_authorizations(self, context: SwarmContext) -> tuple[BrokerAuthorization, ...]:
        with self._state_lock:
            return tuple(
                auth
                for auth, row in self._pending.items()
                if row.scope.context is context
                and row.state in {"prepared", "checking", "forwarding"}
            )

    def activation_proof(self, policy_digest: str, *, operator: object) -> BrokerActivationProof:
        """Explicit owned kernel probe of the fresh-worker FACTORY, not a cohort grant."""
        _hex(policy_digest, "activation policy digest")
        if operator is not self._operator:
            raise ValueError("protected broker operator required")
        with self._barrier(), self._execution_lock:
            self._executor._verify_install()
            with tempfile.TemporaryDirectory(prefix="ordin-owned-factory-probe-") as directory:
                root = Path(directory).resolve()
                workspace, install = root / "workspace", root / "install"
                workspace.mkdir(mode=0o700)
                install.mkdir(mode=0o700)
                target = workspace / "probe.txt"
                target.write_bytes(b"owned-factory-probe\n")
                target.chmod(0o600)
                native = LinuxFileReadBackend(
                    workspace,
                    ("probe.txt",),
                    install,
                    operator=operator,
                    tool_runtime=self._executor.tool_runtime,
                    tool_name=self._executor.tool_name,
                    path_argument=self._executor.path_argument,
                    max_payload_bytes=self._executor.max_payload_bytes,
                    timeout_ms=self._executor.timeout_ms,
                    memory_mib=self._executor.memory_mib,
                    cpu_seconds=self._executor.cpu_seconds,
                )
                try:
                    semantics = ToolSemanticsRegistry(
                        "owned-factory-probe",
                        "1",
                        (
                            ToolSemanticRule(
                                "read",
                                "tool",
                                native.tool_name,
                                ("filesystem.read",),
                                runtime=native.tool_runtime,
                                resources=(ToolResourceBinding(native.path_argument, "path"),),
                            ),
                        ),
                    )
                    action = ToolCallAdapter(native.tool_runtime).adapt(
                        native.tool_name,
                        {native.path_argument: str(target)},
                        action_id="factory-" + uuid4().hex,
                    )
                    contract = derive_runtime_capability_contract(
                        Ordin(tool_semantics=semantics).review_action(action)
                    )
                    compiled = native.compile(contract)
                    if not compiled.enforceable or compiled.plan is None:
                        raise ValueError("owned factory cannot compile its complete probe")
                    source = native.evidence_source(
                        session_digest=digest([self._nonce, policy_digest]),
                        policy_digest=compiled.plan.policy_digest,
                        context_digest=digest(self._nonce),
                    )
                    outcome = native.execute(compiled.plan, action, source, operator=operator)
                    if (
                        outcome.status != "completed"
                        or not outcome.physical_enforcement
                        or outcome.value != b"owned-factory-probe\n"
                        or not native.verify_outcome(outcome, compiled.plan)
                    ):
                        raise ValueError("owned factory kernel probe did not complete")
                    evidence = native.evidence_record(outcome, operator=operator)
                    description = {
                        "scope": "broker_owned_fresh_worker_route",
                        "capabilities": ["broker.enforce"],
                        "factory": True,
                        "requires_action_admission": True,
                        "physical_policy_applied": False,
                        "supported_action_kinds": ["tool"],
                        "operations": ["call"],
                        "effects": ["filesystem.read"],
                        "tool_runtime": self._executor.tool_runtime,
                        "tool_name": self._executor.tool_name,
                        "path_argument": self._executor.path_argument,
                        "files": [
                            str(self._executor.workspace / name)
                            for name in self._executor.allowed_files
                        ],
                        "limits": {
                            "uid": self._executor.uid,
                            "gid": self._executor.gid,
                            "memory_bytes": self._executor.memory_mib * 1048576,
                            "cpu_seconds": self._executor.cpu_seconds,
                            "processes": 1,
                            "payload_bytes": self._executor.max_payload_bytes,
                            "combined_output_frame_bytes": self._executor.max_stdout_bytes,
                        },
                        "evidence_digest": digest(evidence),
                        "execution_authority": False,
                    }
                    proof = BrokerActivationProof(uuid4().hex)
                    with self._state_lock:
                        if len(self._proofs) >= 64:
                            raise ValueError("broker activation proof capacity reached")
                        self._proofs[proof] = _Activation(
                            policy_digest,
                            self.factory_configuration_digest,
                            self._service.issuer._now() + 30,
                            digest(evidence),
                            description,
                            native,
                            outcome,
                            compiled.plan,
                        )
                    return proof
                finally:
                    native.close()

    def verify_activation(
        self,
        proof: BrokerActivationProof,
        *,
        policy_digest: str,
        context: SwarmContext | None = None,
    ) -> bool:
        with self._state_lock:
            row = self._proofs.get(proof) if type(proof) is BrokerActivationProof else None
        if row is None:
            return False
        try:
            self._executor._verify_install()
            if (
                row.policy_digest != policy_digest
                or row.factory_digest != self.factory_configuration_digest
                or self._service.issuer._now() >= row.expires_at
                or not row.probe_executor.verify_outcome(row.probe_outcome, row.probe_plan)
            ):
                return False
            if context is not None:
                matched = next(
                    (
                        v
                        for v in self._service.authenticator._enrollments.values()
                        if v.context is context
                    ),
                    None,
                )
                if matched is None:
                    return False
                self._service.authenticator.enrollment(matched.enrollment_id)
            return True
        except (ValueError, OSError, RuntimeError):
            return False

    def describe_activation(self, proof: BrokerActivationProof) -> dict[str, Any]:
        with self._state_lock:
            row = self._proofs.get(proof) if type(proof) is BrokerActivationProof else None
        if row is None or not self.verify_activation(proof, policy_digest=row.policy_digest):
            raise ValueError("original current broker factory proof unavailable")
        from ordin._runtime_json import freeze, thaw

        return thaw(
            freeze(
                {
                    **row.description,
                    "policy_digest": row.policy_digest,
                    "expires_at": row.expires_at,
                }
            )
        )

    def policy_fits(
        self, proof: BrokerActivationProof, permissions: DelegationAuthority, *, policy_digest: str
    ) -> bool:
        if type(permissions) is not DelegationAuthority or not self.verify_activation(
            proof, policy_digest=policy_digest
        ):
            return False
        maximum = permissions.capability
        paths = {str(self._executor.workspace / name) for name in self._executor.allowed_files}
        return (
            not maximum.network
            and not maximum.credentials
            and not permissions.requests
            and not permissions.network_grants
            and not permissions.rest_requests
            and not maximum.allow_any_executable
            and maximum.process.execution is False
            and not maximum.process.executables
            and maximum.process.spawn_children in {None, False}
            and maximum.privilege.escalation is False
            and maximum.privilege.required_euid in {None, self._executor.uid}
            and all(
                v.access == "read" and v.scope == "exact" and v.path in paths
                for v in maximum.filesystem
            )
            and all(
                (v.runtime, v.server, v.tool, v.operation)
                == (self._executor.tool_runtime, None, self._executor.tool_name, "call")
                for v in maximum.tools
            )
        )
