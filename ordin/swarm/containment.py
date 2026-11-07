"""Durable logical fencing followed by bounded, verifiable backend reconciliation.

This controller is a protected host API. Its exported receipts are reports; only
the original in-memory objects can participate in a recovery ceremony.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from threading import Event, RLock, Thread
from typing import Any, TYPE_CHECKING
from uuid import uuid4

from ordin._runtime_json import digest

from .broker import SwarmExecutionBroker
from .coordinator import SwarmCoordinator, CoordinatorScope, _action_fence_key
from .credential_broker import SwarmCredentialBroker, CredentialRoute
from .models import SwarmContext
from .coordinator_store import _active_transaction, CoordinatorRejected
from .coordinator_store import CoordinatorUnavailable

if TYPE_CHECKING:
    from .incident import IncidentPolicy, IncidentScope, IncidentSignal, IncidentSignalSource


@dataclass(frozen=True, eq=False, slots=True)
class IncidentReceipt:
    incident_id: str
    scope_digest: str
    revocation_epoch: int
    intent_digest: str
    operation: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "ordin.swarm_incident.v1",
            "incident_id": self.incident_id,
            "scope_digest": self.scope_digest,
            "revocation_epoch": self.revocation_epoch,
            "intent_digest": self.intent_digest,
            "operation": self.operation,
            "execution_authority": False,
        }


@dataclass(frozen=True, eq=False, slots=True)
class IncidentResumeReceipt:
    receipt_id: str


@dataclass
class _Incident:
    receipt: IncidentReceipt
    checksum: str
    scope: Any
    fence: Any
    affected: tuple[Any, ...]
    jobs: tuple[Any, ...]
    credentials: tuple[Any, ...]
    previous_digest: str
    chain_digest: str
    done: Event = field(default_factory=Event)
    errors: set[str] = field(default_factory=set)
    controls: dict[Any, Any] = field(default_factory=dict)
    resumed: bool = False


@dataclass(frozen=True)
class _Resume:
    handle_id: str
    incident: IncidentReceipt
    scope_digest: str
    revocation_epoch: int
    policy_epoch: int
    owner_fence: int
    evidence_digest: str
    expires_at: float


class SwarmContainmentController:
    """Contain current protected routes without claiming atomic physical undo.

    The DB fence commits before any broker notification. Long issuer/credential
    locks run on one bounded daemon per incident, outside controller/DB locks.
    While reconciliation is incomplete the durable fence remains effective.
    A new controller never reconstructs executable permissions from reports.
    """

    def __init__(
        self,
        coordinator: SwarmCoordinator,
        scope: CoordinatorScope,
        *,
        control: Any,
        operator: object,
        policy: IncidentPolicy,
        signals: IncidentSignalSource,
        credentials: tuple[tuple[SwarmCredentialBroker, CredentialRoute, IncidentScope], ...] = (),
        max_incidents: int = 128,
    ) -> None:
        from .incident import IncidentPolicy, IncidentScope, IncidentSignalSource

        if (
            type(coordinator) is not SwarmCoordinator
            or operator is not coordinator._operator
            or type(policy) is not IncidentPolicy
            or type(signals) is not IncidentSignalSource
            or signals._operator is not operator
            or type(max_incidents) is not int
            or not 1 <= max_incidents <= 1024
            or type(credentials) is not tuple
            or len(credentials) > 1024
        ):
            raise ValueError("original protected containment configuration required")
        coordinator._control_check(control)
        native = coordinator._scope(scope)
        policy.__post_init__()
        for vault, route, selected in credentials:
            if (
                type(vault) is not SwarmCredentialBroker
                or vault._operator is not operator
                or vault._service is not native.native
                or type(route) is not CredentialRoute
                or route not in vault._routes
                or type(selected) is not IncidentScope
                or (selected.tenant_id, selected.swarm_id) != (native.tenant_id, native.swarm_id)
            ):
                raise ValueError("original scoped credential route required")
        self._coordinator, self._scope, self._control = coordinator, scope, control
        self._operator, self._policy, self._signals = operator, policy, signals
        self._policy_digest = policy.digest
        self._credentials, self._limit = credentials, max_incidents
        self._incidents: dict[IncidentReceipt, _Incident] = {}
        self._resumes: dict[IncidentResumeReceipt, _Resume] = {}
        self._recovery_bundles: dict[IncidentResumeReceipt, tuple[Any, ...]] = {}
        self._signals_used: set[IncidentSignal] = set()
        self._pending_signals: set[IncidentSignal] = set()
        self._automatic_proofs: dict[IncidentSignal, tuple[Any, str]] = {}
        self._head = "0" * 64
        self._lock = RLock()
        self._audit_source: Any = None
        for handle, native_scope in coordinator._scopes.items():
            coordinator.bind_recovery_verifier(handle, self, control=control)
            native_scope.native.bind_containment(self, operator=operator)

    def bind_audit(self, source, *, operator: object) -> None:
        from .diagnostics import SwarmAuditSource

        self._operator_check(operator)
        if (
            type(source) is not SwarmAuditSource
            or source._containment is not self
            or source._coordinator is not self._coordinator
            or source._scope is not self._scope
        ):
            raise ValueError("original scoped containment audit source required")
        self._audit_source = source

    def _emit_audit(self, receipt):
        if self._audit_source is not None:
            try:
                self._audit_source.record_incident(self, receipt)
            except (ValueError, OSError, RuntimeError):
                self._audit_source._fault = True

    def require_current(self, context, action):
        """Recheck DB fences at native review/commit, including cached direct routes."""
        if type(context) is not SwarmContext:
            raise ValueError("original current containment context required")
        handles = [
            handle
            for handle, scope in self._coordinator._scopes.items()
            if scope.authenticator._scope is not None
            and (scope.tenant_id, scope.swarm_id, scope.authenticator._scope[2])
            == (context.identity.tenant_id, context.identity.swarm_id, context.identity.task_id)
        ]
        if len(handles) != 1:
            raise ValueError("current unique containment scope required")
        handle = handles[0]
        subject = digest(
            [context.identity.tenant_id, context.identity.swarm_id, context.identity.agent_id]
        )

        def check(transaction):
            _, state = self._coordinator._owner(transaction, handle)
            row = state["subjects"].get(subject)
            action_hash = digest(action.as_dict())
            if (
                row is None
                or row["revoked"]
                or action_hash in state["blocked_actions"]
                or _action_fence_key(action_hash, subject) in state["blocked_actions"]
            ):
                raise CoordinatorRejected("containment.current_route_fenced")

        active = _active_transaction.get()
        if active is not None:
            if active[0] is not self._coordinator.store:
                raise ValueError("foreign active containment transaction")
            check(active[2])
        else:
            with self._coordinator.store.transaction() as transaction:
                check(transaction)

    def _operator_check(self, operator: object) -> None:
        if operator is not self._operator or self._policy.digest != self._policy_digest:
            raise ValueError("original operator and unchanged incident policy required")

    def _execution_barrier(self, native):
        """Keep admission locks before DB/issuer/broker locks on every bound route.

        Containment itself never takes this barrier: an in-flight callback must
        not delay publishing its durable fence or requesting an owned stop.
        """
        from .registry import InMemoryAgentRegistry

        matches = [scope for scope in self._coordinator._scopes.values() if scope.native is native]
        if len(matches) != 1:
            raise ValueError("original unique native containment route required")
        registry = matches[0].authenticator._registry
        if type(registry) is not InMemoryAgentRegistry:
            raise ValueError("original containment registry required")
        return registry._policy_execution_barrier

    def temporal_signal(self, engine, context, source, action, *, parent_event_ids, uses=()):
        """Compute a configured finding from the original engine, never accept one as JSON.

        Rules may cover repeated denials, lateral relays, escalation fanout,
        deletion and child-spawning using the bounded temporal policy language.
        Their thresholds and maximum scope belong to the protected policy.
        """
        from .incident import IncidentScope, SEVERITIES
        from .temporal import SwarmTemporalEngine

        native = self._coordinator._scope(self._scope)
        if (
            type(engine) is not SwarmTemporalEngine
            or engine is not native.temporal
            or type(context) is not SwarmContext
            or (context.identity.tenant_id, context.identity.swarm_id)
            != (native.tenant_id, native.swarm_id)
        ):
            raise ValueError("original scope-bound temporal engine required")
        result = engine.evaluate(
            context, source, action, parent_event_ids=parent_event_ids, uses=uses
        )
        configured = {rule.rule_id: rule for rule in self._policy.automatic_rules}
        eligible = [
            (finding, configured[finding.rule_id])
            for finding in result.findings
            if finding.rule_id in configured
            and finding.severity in SEVERITIES
            and SEVERITIES[finding.severity]
            >= SEVERITIES[configured[finding.rule_id].minimum_severity]
        ]
        if not eligible:
            raise ValueError("no configured original automatic containment finding")
        finding, rule = max(eligible, key=lambda row: SEVERITIES[row[0].severity])
        identity = context.identity
        selected = IncidentScope(
            rule.automatic_scope,
            identity.tenant_id,
            identity.swarm_id,
            identity.agent_id,
            action_digest=result.action_digest if rule.automatic_scope == "action" else None,
        )
        signal = self._signals._capture(
            selected, finding.severity, rule.rule_id, digest(result.as_dict()), False
        )
        self._automatic_proofs[signal] = (engine, engine.binding_digest)
        return signal

    @staticmethod
    def _contains(outer, inner) -> bool:
        if outer.tenant_id != inner.tenant_id:
            return False
        if outer.kind == "tenant":
            return True
        if outer.swarm_id != inner.swarm_id:
            return False
        if outer.kind == "swarm":
            return True
        if outer.kind == "task":
            return outer.task_id == inner.task_id
        if outer.agent_id != inner.agent_id:
            return False
        return outer.kind != "action" or outer.action_digest == inner.action_digest

    def _targets(self, selected):
        native = self._coordinator._scope(self._scope)
        if selected.tenant_id != native.tenant_id or (
            selected.kind != "tenant" and selected.swarm_id != native.swarm_id
        ):
            raise ValueError("containment signal outside original coordinator scope")
        members: list[Any] = []
        for handle, scope in tuple(self._coordinator._scopes.items()):
            if scope.tenant_id != selected.tenant_id or (
                selected.kind != "tenant" and scope.swarm_id != selected.swarm_id
            ):
                continue
            auth = scope.authenticator
            with auth._lock:
                enrollments: tuple[Any, ...] = tuple(
                    row for row in auth._enrollments.values() if row.context is not None
                )
            wanted = {
                row.context.identity.agent_id
                for row in enrollments
                if selected.kind in {"tenant", "swarm"}
                or selected.kind == "task"
                and row.context.identity.task_id == selected.task_id
                or selected.kind in {"agent", "delegation_subtree", "action"}
                and row.context.identity.agent_id == selected.agent_id
            }
            # Parent revocation always invalidates descendants. Include them in
            # blast-radius accounting even for the single-agent public scope.
            if selected.kind != "action":
                for _ in range(32):
                    children = {
                        row.context.identity.agent_id
                        for row in enrollments
                        if row.context.identity.parent_agent_id in wanted
                    }
                    if children <= wanted:
                        break
                    wanted.update(children)
                else:
                    raise ValueError("containment ancestry exceeds bound")
            members.extend(
                (handle, scope, row)
                for row in enrollments
                if row.context.identity.agent_id in wanted
            )
        if not members or len(members) > self._policy.max_affected:
            raise ValueError("empty or excessive containment blast radius")
        return tuple(
            sorted(members, key=lambda value: value[2].context.identity.generation, reverse=True)
        )

    def contain(self, signal: IncidentSignal, *, operation: str = "quarantine", operator=None):
        from .incident import SEVERITIES

        if type(operation) is not str or operation not in {"pause", "revoke", "quarantine"}:
            raise ValueError("unknown incident operation")
        protected = self._signals._original(signal)
        if protected.operator_owned:
            self._operator_check(operator)
        else:
            rule = next(
                (r for r in self._policy.automatic_rules if r.rule_id == protected.rule_id), None
            )
            proof = self._automatic_proofs.get(signal)
            if (
                rule is None
                or proof is None
                or proof[0].binding_digest != proof[1]
                or protected.scope.kind != rule.automatic_scope
                or SEVERITIES[protected.severity] < SEVERITIES[rule.minimum_severity]
                or operation != "quarantine"
                or self._policy.digest != self._policy_digest
            ):
                raise ValueError("current original configured automatic finding required")
        targets = self._targets(protected.scope)
        if not protected.operator_owned and (rule is None or len(targets) > rule.max_affected):
            raise ValueError("automatic containment exceeds configured narrow blast radius")
        with self._admission(signal):
            return self._contain(protected, targets, operation, signal)

    @contextmanager
    def _admission(self, signal):
        admitted = False
        try:
            with self._lock:
                if signal in self._signals_used or (
                    len(self._incidents) + len(self._pending_signals) >= self._limit
                ):
                    raise ValueError("incident signal already used or capacity reached")
                admitted = True
                # Consume before attempting durable commit: an ambiguous ACK must
                # not cause an automatic second incident or re-enable anything.
                self._signals_used.add(signal)
                self._pending_signals.add(signal)
            yield
        finally:
            if admitted:
                with self._lock:
                    self._pending_signals.discard(signal)

    def _contain(self, protected, targets, operation, signal):
        selected = protected.scope
        kind = "subtree" if selected.kind in {"agent", "delegation_subtree"} else selected.kind
        subject = (
            digest([selected.tenant_id, selected.swarm_id, selected.agent_id])
            if kind == "subtree"
            else digest(selected.task_id)
            if kind == "task"
            else selected.action_digest
            if kind == "action"
            else None
        )
        try:
            fence = self._coordinator.record_fence(
                self._scope,
                control=self._control,
                kind=kind,
                subject_digest=subject,
                actor_digest=digest([selected.tenant_id, selected.swarm_id, selected.agent_id])
                if kind == "action"
                else None,
            )
        except (ValueError, CoordinatorUnavailable, OSError):
            # Commit acknowledgement may have been lost. Never infer an open
            # route from that uncertainty; native guards still require DB
            # authority and local stop requests are safe without a new grant.
            for _, scope, row in targets:
                if selected.kind != "action":
                    try:
                        registry = scope.authenticator._registry
                        if (
                            registry.state(row.context, row.registry_channel, row.adapter)
                            == "active"
                        ):
                            registry.pause(row.context, row.registry_channel, row.adapter)
                    except (ValueError, RuntimeError, OSError):
                        pass
                for broker in scope.brokers.values():
                    for auth in broker.active_authorizations(row.context):
                        bound = broker.authorization_scope(auth)
                        if (
                            selected.kind != "action"
                            or digest(bound.action.as_dict()) == selected.action_digest
                        ):
                            broker.request_stop(auth)
            raise
        jobs = []
        for _, scope, row in targets:
            for broker in scope.brokers.values():
                if type(broker) is not SwarmExecutionBroker:
                    raise ValueError("original enforcing broker configuration changed")
                for auth in broker.active_authorizations(row.context):
                    binding = broker.authorization_scope(auth)
                    if (
                        selected.kind != "action"
                        or digest(binding.action.as_dict()) == selected.action_digest
                    ):
                        jobs.append((broker, auth))
        credentials = tuple(
            (vault, route)
            for vault, route, binding in self._credentials
            if self._contains(selected, binding)
            or selected.kind != "action"
            and any(binding.agent_id == row.context.identity.agent_id for _, _, row in targets)
        )
        receipt = IncidentReceipt(
            uuid4().hex, fence.scope_digest, fence.revocation_epoch, fence.intent_digest, operation
        )
        with self._lock:
            checksum = digest(receipt.as_dict())
            chain = digest([self._head, checksum, protected.proof_digest, self._policy_digest])
            incident = _Incident(
                receipt,
                checksum,
                selected,
                fence,
                targets,
                tuple(jobs),
                credentials,
                self._head,
                chain,
            )
            self._incidents[receipt] = incident
            self._pending_signals.discard(signal)
            self._head = chain
        # Registry pause does not wait on the issuer's execution barrier. This
        # closes cached native authorization paths as the durable fence closes
        # new coordinator admissions, before asynchronous cleanup starts.
        if selected.kind != "action":
            for _, scope, row in targets:
                try:
                    registry = scope.authenticator._registry
                    if registry.state(row.context, row.registry_channel, row.adapter) == "active":
                        registry.pause(row.context, row.registry_channel, row.adapter)
                except (ValueError, RuntimeError, OSError):
                    self._error(incident, "registry_fence_unknown")
        for broker, auth in jobs:
            try:
                control = broker.request_stop(auth)
                if not broker.verify_control_receipt(control, auth):
                    raise ValueError("unverified owned stop")
                incident.controls[(broker, auth)] = control
            except (ValueError, RuntimeError, OSError):
                self._error(incident, "broker_stop_unknown")
        Thread(
            target=self._cleanup, args=(incident,), name="ordin-containment", daemon=True
        ).start()
        self._emit_audit(receipt)
        return receipt

    def pause(self, signal, *, operator):
        return self.contain(signal, operation="pause", operator=operator)

    def revoke(self, signal, *, operator):
        return self.contain(signal, operation="revoke", operator=operator)

    def quarantine(self, signal, *, operator=None):
        return self.contain(signal, operation="quarantine", operator=operator)

    def _cleanup(self, incident):
        try:
            if incident.scope.kind != "action":
                seen = set()
                for _, scope, row in incident.affected:
                    for reference, grant in tuple(scope.native._grants.items()):
                        if (
                            grant.enrollment_id == row.enrollment_id
                            and (scope.native, reference) not in seen
                        ):
                            seen.add((scope.native, reference))
                            try:
                                scope.native.operator_revoke(reference, operator=self._operator)
                            except (ValueError, RuntimeError, OSError):
                                self._error(incident, "delegation_revocation_unknown")
            for vault, route in incident.credentials:
                try:
                    vault.revoke(route, operator=self._operator)
                except (ValueError, RuntimeError, OSError):
                    self._error(incident, "credential_revocation_unknown")
            for broker, auth in incident.jobs:
                try:
                    control = broker.cancel(auth)
                    if not broker.verify_control_receipt(control, auth):
                        raise ValueError("unverified cancellation")
                    incident.controls[(broker, auth)] = control
                except (ValueError, RuntimeError, OSError):
                    self._error(incident, "broker_cancellation_unknown")
        except Exception:
            # No exception details can reveal actions/credentials. The fence is
            # already durable and remains closed even if host cleanup fails.
            self._error(incident, "host_cleanup_unknown")
        finally:
            incident.done.set()

    def _original(self, receipt):
        if type(receipt) is not IncidentReceipt or receipt not in self._incidents:
            raise ValueError("original incident receipt required")
        incident = self._incidents[receipt]
        if digest(receipt.as_dict()) != incident.checksum:
            raise ValueError("changed original incident receipt")
        return incident

    def _durable_outcomes(self, incident):
        outcomes = []
        with self._coordinator.store.transaction() as transaction:
            state = transaction.scope(self._scope.scope_key)
            intent = state["fences"].get(str(incident.receipt.revocation_epoch))
            if intent is None:
                return [{"status": "unknown"}]
            for key, epoch in intent.get(
                "members", {self._scope.scope_key: incident.receipt.revocation_epoch}
            ).items():
                member = transaction.scope(key)
                selected = member["fences"].get(str(epoch))
                if selected is None:
                    outcomes.append({"status": "unknown"})
                    continue
                for reference in selected["reservations"]:
                    row = member["reservations"].get(reference)
                    recorded = row.get("incident_outcome", {}) if row else {}
                    if recorded.get("revocation_epoch") != epoch:
                        recorded = {}
                    status = (
                        "canceled"
                        if row and row["status"] == "canceled"
                        else "completed"
                        if row and row["status"] == "committed"
                        else recorded.get("status", "unknown")
                    )
                    outcomes.append({"reservation_digest": digest(reference), "status": status})
        return outcomes

    def _error(self, incident, code):
        with self._lock:
            incident.errors.add(code)

    def status(self, receipt: IncidentReceipt, *, operator: object):
        self._operator_check(operator)
        incident = self._original(receipt)
        outcomes = []
        for broker, auth in incident.jobs:
            try:
                result = broker.status(auth)
                if not broker.verify_control_receipt(result, auth):
                    raise ValueError("unverified owned status")
                outcomes.append(result.as_dict())
            except (ValueError, RuntimeError, OSError):
                outcomes.append({"status": "unknown"})
        status = self._coordinator.status(self._scope, control=self._control)
        try:
            durable = self._durable_outcomes(incident)
        except (ValueError, CoordinatorUnavailable, OSError):
            durable = [{"status": "unknown"}]
        with self._lock:
            errors = sorted(incident.errors)
        return {
            **receipt.as_dict(),
            "affected_agents": len(incident.affected),
            "backend_outcomes": outcomes,
            "durable_outcomes": durable,
            "notifications_complete": incident.done.is_set(),
            "proof_gaps": errors,
            "coordinator_online": status.get("online", True),
            "resumed": incident.resumed,
            "previous_digest": incident.previous_digest,
            "chain_digest": incident.chain_digest,
            "unmediated_paths": "uncovered",
            "completed_effects_undone": False,
        }

    def _reconciled(self, incident):
        with self._lock:
            incomplete = bool(incident.errors) or not incident.done.is_set()
        if incomplete:
            return None
        report = self.status(incident.receipt, operator=self._operator)
        if not report["coordinator_online"] or any(
            item["status"] not in {"canceled", "completed"}
            for item in report["backend_outcomes"] + report["durable_outcomes"]
        ):
            return None
        return digest(report)

    def reconcile_job(
        self, receipt, reservation_id, original_outcome, *, operator, member_scope=None
    ):
        """Record an original owned outcome while preserving every uncertain hold."""
        self._operator_check(operator)
        incident = self._original(receipt)
        handle = self._scope if member_scope is None else member_scope
        self._coordinator._scope(handle)
        with self._coordinator.store.transaction() as transaction:
            state = transaction.scope(self._scope.scope_key)
            intent = state["fences"][str(receipt.revocation_epoch)]
            members = intent.get("members", {self._scope.scope_key: receipt.revocation_epoch})
            epoch = members.get(handle.scope_key)
        if epoch is None or incident.resumed:
            raise ValueError("original affected incident member required")
        return self._coordinator.reconcile_broker_outcome(
            handle,
            reservation_id,
            original_outcome,
            control=self._control,
            revocation_epoch=epoch,
        )

    def approve_resume(self, receipt, *, operator, lifetime=30):
        """Approve reconciled state; a fresh owner/policy fence is still mandatory.

        Revoked native grants, old TLS enrollment and old registry contexts are
        never restored. Workloads must enroll/review/reserve again afterward.
        """
        self._operator_check(operator)
        if type(lifetime) not in {int, float} or not 0 < lifetime <= 60:
            raise ValueError("bounded recovery approval lifetime required")
        incident = self._original(receipt)
        evidence = self._reconciled(incident)
        if evidence is None or incident.resumed:
            raise ValueError("current original backend reconciliation required")
        members = []
        with self._coordinator.store.transaction() as transaction:
            state = transaction.scope(self._scope.scope_key)
            intent = state["fences"][str(receipt.revocation_epoch)]
            for key, epoch in intent.get(
                "members", {self._scope.scope_key: receipt.revocation_epoch}
            ).items():
                handles = [
                    handle for handle in self._coordinator._scopes if handle.scope_key == key
                ]
                if len(handles) != 1:
                    raise CoordinatorRejected("containment.original_member_recovery_required")
                member_state = transaction.scope(key)
                old = member_state["fences"].get(str(epoch))
                if old is None or old["reconciled"] or member_state["revocation_epoch"] != epoch:
                    raise CoordinatorRejected("containment.current_member_intent_required")
                policy, owner = member_state["policy_epoch"], member_state["owner"]["fence"]
                if policy <= old["policy_epoch"] and owner <= old["owner_fence"]:
                    raise CoordinatorRejected(
                        "new policy epoch or owner fence required before resume"
                    )
                members.append((handles[0], epoch, policy, owner))
            now = transaction.now
        bundle = []
        with self._lock:
            if len(self._resumes) + len(members) > self._limit * 64:
                raise ValueError("recovery receipt capacity reached")
        for member, epoch, policy, owner in members:
            fence = (
                incident.fence
                if member is self._scope
                else self._coordinator.recover_fence(
                    member,
                    epoch,
                    control=self._control,
                )
            )
            handle = IncidentResumeReceipt(uuid4().hex)
            with self._lock:
                self._resumes[handle] = _Resume(
                    handle.receipt_id,
                    receipt,
                    member.scope_key,
                    epoch,
                    policy,
                    owner,
                    evidence,
                    now + lifetime,
                )
            bundle.append((member, fence, handle))
        primary = next(item[2] for item in bundle if item[0] is self._scope)
        with self._lock:
            self._recovery_bundles[primary] = tuple(
                sorted(bundle, key=lambda item: item[0] is self._scope)
            )
        return primary

    def verify_resume_receipt(
        self, receipt, *, scope_digest, revocation_epoch, policy_epoch, owner_fence
    ):
        if type(receipt) is not IncidentResumeReceipt:
            return False
        with self._lock:
            proof = self._resumes.get(receipt)
        if (
            proof is None
            or receipt.receipt_id != proof.handle_id
            or (
                proof.scope_digest,
                proof.revocation_epoch,
                proof.policy_epoch,
                proof.owner_fence,
            )
            != (scope_digest, revocation_epoch, policy_epoch, owner_fence)
        ):
            return False
        incident = self._original(proof.incident)
        return (
            not incident.resumed
            and self._coordinator.clock() < proof.expires_at
            and self._reconciled(incident) == proof.evidence_digest
        )

    def resume(self, receipt, approval, *, operator):
        self._operator_check(operator)
        incident = self._original(receipt)
        proof = self._resumes.get(approval)
        bundle = self._recovery_bundles.get(approval)
        if proof is None or proof.incident is not receipt or bundle is None:
            raise ValueError("original exact incident recovery approval required")
        for member, fence, selected in bundle:
            proof = self._resumes[selected]
            # A partial group acknowledgement can be retried with the original
            # bundle, but only the exact recorded reconciliation may be skipped.
            with self._coordinator.store.transaction() as transaction:
                state = transaction.scope(member.scope_key)
                intent = state["fences"].get(str(fence.revocation_epoch), {})
                already = intent.get("reconciled") is True
                if already and (
                    intent.get("reconciliation_digest")
                    != digest([fence.intent_digest, proof.policy_epoch, proof.owner_fence])
                    or (state["policy_epoch"], state["owner"]["fence"])
                    != (proof.policy_epoch, proof.owner_fence)
                ):
                    raise CoordinatorRejected("containment.group_reconciliation_changed")
            if not already:
                self._coordinator.reconcile_fence(member, fence, selected, control=self._control)
        with self._lock:
            for _, _, selected in bundle:
                self._resumes.pop(selected, None)
            self._recovery_bundles.pop(approval, None)
            incident.resumed = True
        self._emit_audit(receipt)
        return self.status(receipt, operator=operator)
