"""Protected durable human governance, composed with the original coordinator."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, replace
from threading import RLock
from typing import Any
from uuid import uuid4

from ordin import ActionEnvelope
from ordin._runtime_json import digest
from ordin.approval import ApprovalAuthority, ApprovalSource
from ordin.assurance.host import HostEvidenceSource
from ordin.runtime_contract import CredentialBinding, derive_runtime_capability_contract
from ordin.session import configuration_digest

from .approval import (
    SwarmApprovalPolicy,
    SwarmApprovalBinding,
    SwarmApprovalRequest,
    SwarmApprovalReceipt,
    SwarmRecoveryApproval,
    SwarmRecoveryRequest,
    REASONS,
)
from .coordinator import SwarmCoordinator, CoordinatorScope
from .coordinator_store import CoordinatorRejected, CoordinatorUnavailable, _active_transaction
from .operator_auth import SwarmOperatorDirectory
from .registry import InMemoryAgentRegistry


class _Lifecycle:
    def __init__(self, operator):
        self._operator, self._service = operator, None

    def bind(self, service, *, operator):
        if operator is self._operator and self._service is service:
            return
        if (
            operator is not self._operator
            or type(service) is not SwarmApprovalService
            or self._service is not None
        ):
            raise ValueError("original one-time governance lifecycle binding required")
        self._service = service

    def __call__(self, identity, scope, stage):
        return self._service is not None and self._service._verify_core_lifecycle(
            identity, scope, stage
        )


class SwarmApprovalBootstrap:
    """Create finite original sources before the native assurance configuration seals."""

    def __init__(
        self,
        registry: InMemoryAgentRegistry,
        hosts: tuple[HostEvidenceSource, ...],
        profile,
        maximum,
        *,
        operator: object,
        clock,
    ):
        if (
            type(registry) is not InMemoryAgentRegistry
            or type(hosts) is not tuple
            or not 1 <= len(hosts) <= 256
            or any(type(host) is not HostEvidenceSource for host in hosts)
            or len({host.key for host in hosts}) != len(hosts)
            or registry._clock is not clock
        ):
            raise ValueError("original bounded host sources and same coordinator clock required")
        self.registry, self._operator, self.clock = registry, operator, clock
        self._lifecycle = _Lifecycle(operator)
        self.authority = ApprovalAuthority(
            maximum, operator=operator, admission_barrier=registry._policy_execution_barrier
        )
        self.sources = {}
        for host in hosts:
            source = ApprovalSource(
                host,
                profile,
                maximum,
                operator=operator,
                clock=clock,
                verifier=self._lifecycle,
                admission_barrier=registry._policy_execution_barrier,
            )
            self.authority.enroll(source, operator=operator)
            self.sources[host.key] = source


@dataclass
class _OriginalRequest:
    request: SwarmApprovalRequest
    action: ActionEnvelope
    caller_digest: str
    preview: Any
    source: ApprovalSource
    workload_channel: Any
    lease_id: str
    native_reference: str
    subject_digest: str
    broker: Any
    costs_digest: str
    task_id: str
    caller_action: ActionEnvelope


@dataclass
class _Approved:
    original: _OriginalRequest
    receipt: SwarmApprovalReceipt
    receipt_id: str
    satisfaction: Any = None
    scope: Any = None
    execution_lease: Any = None
    authorization: Any = None
    reservation_id: str | None = None
    context: Any = None
    context_id: str | None = None


@dataclass(frozen=True, slots=True, eq=False)
class _Preparation:
    preparation_id: str


@dataclass(frozen=True)
class _OrdinaryJob:
    broker: Any
    executor: Any
    job: Any
    admission_id: str
    admission: Any
    workload_context: Any
    gate: Any
    review_inputs: dict[str, Any]
    session_digest: str
    runtime_digest: str


class SwarmApprovalService:
    """One current protected governance controller, using the coordinator's DB locks.

    No listener, execution or recovery is started by construction. Operator
    transport owns real TLS sockets; callers cannot resolve votes with JSON roles.
    """

    def __init__(
        self,
        coordinator: SwarmCoordinator,
        scope: CoordinatorScope,
        directory: SwarmOperatorDirectory,
        bootstrap: SwarmApprovalBootstrap,
        policy: SwarmApprovalPolicy,
        *,
        control,
        operator: object,
        factory_proofs: dict[str, Any] | None = None,
    ):
        if (
            type(coordinator) is not SwarmCoordinator
            or type(directory) is not SwarmOperatorDirectory
            or type(bootstrap) is not SwarmApprovalBootstrap
            or type(policy) is not SwarmApprovalPolicy
        ):
            raise ValueError("original protected governance components required")
        coordinator._control_check(control)
        native_scope = coordinator._scope(scope)
        if (
            bootstrap._operator is not operator
            or directory._operator is not operator
            or coordinator._operator is not operator
            or native_scope.authenticator is not directory.authenticator
            or bootstrap.registry is not directory.authenticator._registry
            or bootstrap.clock is not coordinator.clock
            or native_scope.native.assurance.baseline_gate.approval_source
            is not bootstrap.authority
        ):
            raise ValueError(
                "governance components must share their original current scope and authority"
            )
        policy.__post_init__()
        self.coordinator, self.scope, self.directory, self.bootstrap, self.policy = (
            coordinator,
            scope,
            directory,
            bootstrap,
            policy,
        )
        self._control, self._operator, self._policy_digest = control, operator, policy.digest
        self._instance = uuid4().hex
        self._barrier = bootstrap.registry._policy_execution_barrier
        self._originals: dict[str, _OriginalRequest] = {}
        self._receipts: dict[SwarmApprovalReceipt, _Approved] = {}
        self._receipt_by_request: dict[str, SwarmApprovalReceipt] = {}
        self._preparing: dict[object, _Approved] = {}
        self._ordinary_jobs: dict[object, _OrdinaryJob] = {}
        self._recoveries: dict[SwarmRecoveryApproval, Any] = {}
        self._recovery_ids: dict[SwarmRecoveryApproval, str] = {}
        self._recovery_requests: dict[str, Any] = {}
        self._lock = RLock()
        if factory_proofs is not None and (
            type(factory_proofs) is not dict or len(factory_proofs) > 64
        ):
            raise ValueError("finite original owned-factory proofs required")
        self._factory_proofs = dict(factory_proofs or {})
        self._factory_configurations = {
            host: broker.factory_configuration_digest
            for host, broker in native_scope.brokers.items()
        }

    def _configuration(self):
        self.coordinator._control_check(self._control)
        if (
            self.policy.digest != self._policy_digest
            or self.coordinator._scope(self.scope).native.assurance.baseline_gate.approval_source
            is not self.bootstrap.authority
        ):
            raise CoordinatorUnavailable("governance configuration changed")

    @contextmanager
    def _transaction(self):
        active = _active_transaction.get()
        if active is not None:
            if active[0] is not self.coordinator.store:
                raise CoordinatorUnavailable("governance transaction belongs to another authority")
            yield active[2]
        else:
            with self.coordinator.store.transaction() as transaction:
                yield transaction

    def _namespace(self, transaction, *, contained=False):
        self._configuration()
        native_scope, state = self.coordinator._owner(
            transaction, self.scope, allow_contained=contained, expire=False
        )
        namespace = state.get("governance")
        if (
            state.get("governance_manifest")
            != digest(["ordin.swarm_governance.v1", self._policy_digest])
            or type(namespace) is not dict
            or namespace.get("version") != 1
            or namespace.get("policy_digest") != self._policy_digest
            or type(namespace.get("requests")) is not dict
            or type(namespace.get("recoveries")) is not dict
            or type(namespace.get("keys")) is not dict
            or len(namespace["requests"]) + len(namespace["recoveries"]) > self.policy.max_requests
        ):
            raise CoordinatorUnavailable("initialized governance history missing or changed")
        if namespace.get("instance") != self._instance:
            raise CoordinatorRejected(
                "governance original controller was replaced or needs recovery"
            )
        return native_scope, state, namespace

    def initialize(self, *, operator: object, recover: bool = False):
        if operator is not self._operator:
            raise ValueError("original governance installation control required")
        if type(recover) is not bool:
            raise ValueError("explicit installation recovery flag required")
        with self._barrier, self._lock, self._transaction() as transaction:
            _, state = self.coordinator._owner(transaction, self.scope)
            if "governance_manifest" in state or "governance" in state:
                namespace = state.get("governance")
                if (
                    not recover
                    or state.get("governance_manifest")
                    != digest(["ordin.swarm_governance.v1", self._policy_digest])
                    or type(namespace) is not dict
                    or namespace.get("version") != 1
                    or namespace.get("policy_digest") != self._policy_digest
                    or type(namespace.get("requests")) is not dict
                    or type(namespace.get("recoveries")) is not dict
                    or type(namespace.get("keys")) is not dict
                ):
                    raise CoordinatorRejected("governance history cannot be reset or reconstructed")
                if namespace["instance"] != self._instance:
                    if state["owner"]["fence"] <= namespace["owner_fence"]:
                        raise CoordinatorRejected(
                            "fresh owner fence required for governance takeover"
                        )
                    for row in (*namespace["requests"].values(), *namespace["recoveries"].values()):
                        if row["status"] in {"pending", "approved", "held"}:
                            row["status"] = "canceled"
                        elif row["status"] == "consumed":
                            row["status"] = "uncertain"
                    namespace["instance"] = self._instance
                    namespace["owner_fence"] = state["owner"]["fence"]
            else:
                if recover:
                    raise CoordinatorRejected("missing initialized governance history")
                state["governance_manifest"] = digest(
                    ["ordin.swarm_governance.v1", self._policy_digest]
                )
                state["governance"] = {
                    "version": 1,
                    "policy_digest": self._policy_digest,
                    "instance": self._instance,
                    "owner_fence": state["owner"]["fence"],
                    "requests": {},
                    "recoveries": {},
                    "keys": {},
                }
            transaction.append(
                self.scope.scope_key,
                "governance_initialized",
                self._instance,
                {"policy_digest": self._policy_digest},
                maximum=self.coordinator._limit,
            )
        # Publish the live issuer/controller relationship only after durable ACK.
        self.bootstrap._lifecycle.bind(self, operator=operator)
        native_scope = self.coordinator._scope(self.scope)
        native_scope.native.bind_governance(self, operator=operator)
        for broker in native_scope.brokers.values():
            broker.bind_governance(self, operator=operator)

    @property
    def binding_digest(self):
        with self._barrier, self._lock:
            self._configuration()
            return digest(
                [
                    self._instance,
                    self.scope.scope_key,
                    self._policy_digest,
                    self.directory.binding_digest,
                    self.bootstrap.authority.binding_digest,
                ]
            )

    def _verify_core_lifecycle(self, identity, scope, stage):
        with self._barrier, self._lock, self._transaction() as transaction:
            _, state, namespace = self._namespace(transaction)
            row = namespace["requests"].get(identity)
            original = self._originals.get(identity)
            if (
                row is None
                or original is None
                or row["binding_digest"] != original.request.binding.digest
                or row["request"] != original.request.as_dict()
                or scope.context_digest != original.request.binding.context_digest
                or scope.policy_digest != state["policy_digest"]
                or scope.policy_epoch != state["policy_epoch"]
                or scope.owner_fence != state["owner"]["fence"]
                or scope.revocation_epoch != state["revocation_epoch"]
                or transaction.now >= row["expires_at"]
                or row["directory_digest"] != self.directory.binding_digest
            ):
                return False
            allowed = {
                "issue": {"approved", "held"},
                "reserve": {"held"},
                "review": {"approved", "held", "consumed"},
                "begin": {"consumed"},
                "execution": {"consumed"},
            }
            return (
                row["status"] in allowed.get(stage, set())
                and self._current_votes(row) >= original.request.quorum
            )

    def _capture(self, transaction, channel, lease_id, reference, action):
        from ordin.swarm.broker import SwarmExecutionBroker

        native_scope, state, enrollment, subject, lease = self.coordinator._lease(
            transaction, self.scope, channel, lease_id
        )
        if enrollment.context is None or enrollment.source is None:
            raise CoordinatorRejected("governance original workload context unavailable")
        broker = native_scope.brokers.get(enrollment.host_id)
        factory = self._factory_proofs.get(enrollment.host_id)
        if (
            type(broker) is not SwarmExecutionBroker
            or broker.factory_configuration_digest
            != self._factory_configurations.get(enrollment.host_id)
            or factory is None
            or not broker.verify_activation(factory, policy_digest=state["policy_digest"])
        ):
            raise CoordinatorRejected("governance current actual enforcing factory unavailable")
        with native_scope.native._lock, native_scope.native.issuer._lock:
            grant, original = native_scope.native._grant(channel, reference)
            if original is not enrollment:
                raise CoordinatorRejected("governance delegated workload identity changed")
            runtime_source = broker._executor.evidence_source(
                session_digest=enrollment.source.session_digest,
                policy_digest=enrollment.source.runtime_policy_digest,
                context_digest=digest([enrollment.source.key, enrollment.context.registry_id]),
            )
            grant.gate.bind_runtime_source(runtime_source)
            credential_uses = broker.review_credential_uses(enrollment.source, action)
            if not broker.verify_credential_uses(enrollment.source, action, credential_uses):
                raise CoordinatorRejected("governance original credential routing unavailable")
            preview = grant.gate.preview_action(
                action,
                host_context=enrollment.source.context(credential_uses=credential_uses),
            )
            review = preview.review
            contract = ApprovalSource._base_contract(review.action, review)
            native_scope.native.issuer._preview_operation(grant.handle, enrollment.source, contract)
        allowed_missing_approval = {
            rule.invariant_id
            for rule in native_scope.native.issuer.profile.profile.invariants
            if rule.kind == "require_approval"
        }
        for check in preview.assurance.invariant_evaluations:
            if check.status != "satisfied" and check.invariant_id not in allowed_missing_approval:
                raise CoordinatorRejected("governance mandatory assurance requirement unresolved")
        if (
            preview.verification is None
            or not preview.verification.ok
            or preview.assurance.baseline.denied
        ):
            raise CoordinatorRejected("governance underlying rights or core review denies approval")
        if native_scope.runtime is not None:
            provider = native_scope.native._policy_facts_provider
            facts = (
                provider(enrollment.context, action, native_scope.runtime, preview)
                if provider is not None
                else None
            )
            projection = native_scope.runtime.evaluate_baseline(
                enrollment.context, action, preview, facts=facts, delegation_gate=grant.gate
            )
            if projection._constraints_disposition != "execute":
                raise CoordinatorRejected(
                    "governance independent policy/mandatory requirement blocks approval"
                )
        source = self.bootstrap.sources.get(enrollment.source.key)
        if source is None or source.host is not enrollment.source:
            raise CoordinatorRejected("governance original workload approval source unavailable")
        broker._executor.validate_action_requirements(review.action, contract)
        if broker._costs is not None:
            raise CoordinatorRejected(
                "governance requires the represented fixed-worker cost planner"
            )
        costs = broker._default_costs()
        costs_digest = digest([(value.metric, value.amount) for value in costs])
        evidence = (
            native_scope.runtime.evidence_digest(enrollment.context)
            if native_scope.runtime is not None
            else grant.gate.preview_binding_digest
        )
        binding = SwarmApprovalBinding(
            self.scope.scope_key,
            subject,
            enrollment.source.session_digest,
            digest(enrollment.context.as_dict()),
            digest(review.action.as_dict()),
            digest(review.as_dict()),
            native_scope.native.assurance.configuration_digest,
            state["policy_digest"],
            evidence,
            digest([grant.handle.digest, native_scope.native.issuer._generation]),
            digest([native_scope.budget.digest, broker._budget.policy.digest, costs_digest]),
            contract.digest,
            native_scope.native.issuer.operator_maximum.digest,
            self.directory.binding_digest,
            state["policy_epoch"],
            state["revocation_epoch"],
            state["owner"]["fence"],
        )
        return binding, preview, source, broker, costs_digest, enrollment, lease

    def refresh_factory_proof(
        self, host_id: str, proof, *, operator: object, expected_owner_fence: int
    ):
        """Refresh only a proven original factory; existing request deadlines stay fixed."""
        from .broker import SwarmExecutionBroker

        if (
            operator is not self._operator
            or type(host_id) is not str
            or type(expected_owner_fence) is not int
            or expected_owner_fence < 1
            or _active_transaction.get() is not None
        ):
            raise CoordinatorRejected("original factory refresh control required")
        with self._barrier, self._lock:
            with self._transaction() as transaction:
                native_scope, state, _ = self._namespace(transaction)
                broker = native_scope.brokers.get(host_id)
                if (
                    state["owner"]["fence"] != expected_owner_fence
                    or type(broker) is not SwarmExecutionBroker
                    or broker._operator is not operator
                    or broker._service is not native_scope.native
                    or broker.factory_configuration_digest
                    != self._factory_configurations.get(host_id)
                    or not broker.verify_activation(proof, policy_digest=state["policy_digest"])
                ):
                    raise CoordinatorRejected("original current same-factory proof required")
                description = broker.describe_activation(proof)
                transaction.append(
                    self.scope.scope_key,
                    "approval_factory_refreshed",
                    digest(host_id),
                    {
                        "factory_digest": broker.factory_configuration_digest,
                        "proof_digest": digest(description),
                    },
                    maximum=self.coordinator._limit,
                )
            # Publish under the same barriers, only after the durable acknowledgement.
            self._factory_proofs[host_id] = proof

    def request(
        self,
        channel,
        lease_id: str,
        native_reference: str,
        action: ActionEnvelope,
        *,
        idempotency_key: str,
    ) -> SwarmApprovalRequest:
        return self._request(
            channel, lease_id, native_reference, action, idempotency_key=idempotency_key
        )

    def break_glass(
        self,
        operator_channel,
        channel,
        lease_id,
        native_reference,
        action,
        *,
        reason_code: str,
        idempotency_key: str,
    ):
        if not self.policy.break_glass or reason_code not in REASONS:
            raise CoordinatorRejected(
                "explicit enabled break-glass profile and finite reason required"
            )
        _, enrollment, _ = self.coordinator._subject(self.scope, channel)
        if enrollment.context is None:
            raise CoordinatorRejected("original workload task required")
        actor = self.directory.require(
            operator_channel,
            task_id=enrollment.context.identity.task_id or "swarm-control",
            roles=self.policy.break_glass_roles,
        )
        return self._request(
            channel,
            lease_id,
            native_reference,
            action,
            idempotency_key=idempotency_key,
            mode="break_glass",
            initiator=actor,
            reason_code=reason_code,
        )

    def _request(
        self,
        channel,
        lease_id,
        native_reference,
        action,
        *,
        idempotency_key,
        mode="standard",
        initiator=None,
        reason_code=None,
    ):
        if (
            type(action) is not ActionEnvelope
            or type(idempotency_key) is not str
            or not 1 <= len(idempotency_key) <= 128
        ):
            raise ValueError("exact typed action and bounded governance idempotency key required")
        caller = ActionEnvelope.from_dict(action.as_dict())
        caller_digest = digest(caller.as_dict())
        request_id = uuid4().hex
        captured = ActionEnvelope.from_dict(caller.as_dict() | {"action_id": "human-" + request_id})
        with self._barrier, self._lock, self._transaction() as transaction:
            _, _, namespace = self._namespace(transaction)
            _, _, subject = self.coordinator._subject(self.scope, channel)
            key = digest(
                [
                    subject,
                    native_reference,
                    mode,
                    reason_code,
                    initiator.digest if initiator is not None else None,
                    idempotency_key,
                ]
            )
            old = namespace["keys"].get(key)
            if old is not None:
                if old["caller_digest"] != caller_digest:
                    raise CoordinatorRejected("governance idempotency conflict")
                original = self._originals.get(old["request_id"])
                if original is None:
                    raise CoordinatorRejected(
                        "governance original request requires fresh recovery review"
                    )
                return original.request
            if (
                len(namespace["requests"]) + len(namespace["recoveries"])
                >= self.policy.max_requests
            ):
                raise CoordinatorRejected("governance bounded request history exhausted")
            binding, preview, source, broker, costs_digest, enrollment, lease = self._capture(
                transaction, channel, lease_id, native_reference, captured
            )
            quorum = (
                self.policy.high_risk_quorum
                if preview.review.risk in {"high", "critical"}
                or set(preview.review.effects).intersection(self.policy.two_person_effects)
                else 1
            )
            roles = self.policy.required_roles
            lifetime = self.policy.lifetime
            if mode == "break_glass":
                self.directory.member(
                    initiator.enrollment_id,
                    task_id=enrollment.context.identity.task_id or "swarm-control",
                    roles=self.policy.break_glass_roles,
                )
                quorum = self.policy.break_glass_quorum
                roles, lifetime = self.policy.break_glass_roles, self.policy.break_glass_lifetime
            expiry = min(transaction.now + lifetime, lease["lease_expires_at"])
            request = SwarmApprovalRequest(
                request_id,
                binding,
                self._policy_digest,
                preview.disposition,
                preview.review.risk,
                tuple(preview.review.effects),
                roles,
                quorum,
                expiry,
                mode,
                reason_code,
            )
            namespace["requests"][request_id] = {
                "request": request.as_dict(),
                "binding_digest": binding.digest,
                "directory_digest": self.directory.binding_digest,
                "status": "pending",
                "expires_at": expiry,
                "task_id": enrollment.context.identity.task_id or "swarm-control",
                "votes": {},
                "resolutions": {},
                "subject": subject,
                "lease_id": lease_id,
                "native_reference_digest": digest(native_reference),
            }
            namespace["keys"][key] = {"caller_digest": caller_digest, "request_id": request_id}
            transaction.append(
                self.scope.scope_key,
                "approval_requested",
                request_id,
                {
                    "binding_digest": binding.digest,
                    "quorum": quorum,
                    "mode": mode,
                    "reason_code": reason_code,
                    "actor_digest": initiator.digest if initiator is not None else None,
                },
                maximum=self.coordinator._limit,
            )
            original = _OriginalRequest(
                request,
                captured,
                caller_digest,
                preview,
                source,
                channel,
                lease_id,
                native_reference,
                subject,
                broker,
                costs_digest,
                enrollment.context.identity.task_id or "swarm-control",
                caller,
            )
        # Rollback/lost ACK must never publish a live request binding.
        with self._lock:
            self._originals[request_id] = original
        return request

    def _current_votes(self, row):
        members, certificates = set(), set()
        for principal, vote in row["votes"].items():
            if vote["choice"] != "approve":
                continue
            try:
                member = self.directory.member(
                    vote["enrollment_id"],
                    task_id=row["task_id"],
                    roles=tuple(row["request"]["required_roles"]),
                )
            except ValueError:
                continue
            if (
                member.principal_id != principal
                or member.digest != vote["actor_digest"]
                or member.certificate_digest in certificates
            ):
                raise CoordinatorRejected(
                    "governance human authority changed or quorum aliases a credential"
                )
            members.add(principal)
            certificates.add(member.certificate_digest)
        return len(members)

    def _publish_receipt(self, original):
        request_id = original.request.request_id
        receipt = self._receipt_by_request.get(request_id)
        if receipt is None:
            receipt = SwarmApprovalReceipt(uuid4().hex)
            self._receipt_by_request[request_id] = receipt
            self._receipts[receipt] = _Approved(original, receipt, receipt.receipt_id)
        else:
            self._approved(receipt)
        return receipt

    def _approved(self, receipt):
        approved = self._receipts.get(receipt) if type(receipt) is SwarmApprovalReceipt else None
        if (
            approved is None
            or approved.receipt is not receipt
            or receipt.receipt_id != approved.receipt_id
        ):
            raise CoordinatorRejected("governance original current approval receipt required")
        return approved

    def _expire_row(self, transaction, row, request_id):
        if (
            row["status"] in {"pending", "approved", "held"}
            and transaction.now >= row["expires_at"]
        ):
            row["status"] = "expired"
            transaction.append(
                self.scope.scope_key,
                "approval_expired",
                request_id,
                {"binding_digest": row["binding_digest"]},
                maximum=self.coordinator._limit,
            )

    def _close_request(self, request_id):
        receipt = self._receipt_by_request.get(request_id)
        value = self._receipts.get(receipt) if receipt is not None else None
        if value is None or value.execution_lease is None:
            return
        value.original.source.finish(value.execution_lease, operator=self._operator)
        if value.reservation_id is not None:
            try:
                self.coordinator.cancel(
                    self.scope,
                    value.original.workload_channel,
                    value.original.lease_id,
                    value.reservation_id,
                )
            except (CoordinatorRejected, CoordinatorUnavailable):
                # A stale owner/lease or uncertain effect cannot be refunded here.
                pass

    def _terminal(self, operator_channel, request_id, choice, idempotency_key):
        from .models import identifier

        identifier(request_id, "approval_request_id")
        if type(idempotency_key) is not str or not 1 <= len(idempotency_key) <= 128:
            raise ValueError("bounded governance idempotency key required")
        with self._barrier, self._lock, self._transaction() as transaction:
            _, _, namespace = self._namespace(transaction, contained=True)
            row = namespace["requests"].get(request_id) or namespace["recoveries"].get(request_id)
            if row is None:
                raise CoordinatorRejected("governance request unavailable")
            actor = self.directory.require(
                operator_channel,
                task_id=row["task_id"],
                roles=tuple(row["request"]["required_roles"]),
            )
            self._expire_row(transaction, row, request_id)
            if choice == "cancel" and row["status"] in {"pending", "approved", "held"}:
                row["status"] = "canceled"
                transaction.append(
                    self.scope.scope_key,
                    "approval_canceled",
                    request_id,
                    {
                        "actor_digest": actor.digest,
                        "binding_digest": row["binding_digest"],
                        "idempotency_digest": digest(idempotency_key),
                    },
                    maximum=self.coordinator._limit,
                )
            elif choice == "expire" and row["status"] in {"pending", "approved", "held"}:
                raise CoordinatorRejected("governance approval has not expired")
            elif row["status"] in {"consumed", "uncertain", "completed"}:
                raise CoordinatorRejected(
                    "consumed approval requires reconciliation, never cancellation"
                )
            result = {
                "schema_version": "ordin.swarm_approval_resolution.v1",
                "request_id": request_id,
                "status": row["status"],
                "votes": self._current_votes(row),
                "quorum": row["request"]["quorum"],
                "execution_authority": False,
            }
        self._close_request(request_id)
        return result

    def cancel(self, operator_channel, request_id, *, idempotency_key):
        return self._terminal(operator_channel, request_id, "cancel", idempotency_key)

    def expire(self, operator_channel, request_id, *, idempotency_key):
        return self._terminal(operator_channel, request_id, "expire", idempotency_key)

    def prepare(
        self, receipt: SwarmApprovalReceipt, channel, lease_id: str, action: ActionEnvelope
    ):
        with self._barrier, self._lock:
            approved = self._approved(receipt)
            original = approved.original
            if (
                digest(action.as_dict()) != original.caller_digest
                or channel is not original.workload_channel
                or lease_id != original.lease_id
                or approved.context is not None
            ):
                raise CoordinatorRejected(
                    "governance approval is changed, foreign or already prepared"
                )
            with self._transaction() as transaction:
                _, _, namespace = self._namespace(transaction)
                row = namespace["requests"].get(original.request.request_id)
                if (
                    row is None
                    or row["request"] != original.request.as_dict()
                    or row["status"] != "approved"
                    or transaction.now >= row["expires_at"]
                    or self._current_votes(row) < original.request.quorum
                ):
                    raise CoordinatorRejected("governance unresolved, expired or consumed approval")
                current = self._capture(
                    transaction, channel, lease_id, original.native_reference, original.action
                )[0]
                if current.digest != original.request.binding.digest:
                    raise CoordinatorRejected("governance context changed before reservation")
                row["status"] = "held"
                transaction.append(
                    self.scope.scope_key,
                    "approval_held",
                    original.request.request_id,
                    {"binding_digest": row["binding_digest"]},
                    maximum=self.coordinator._limit,
                )
                remaining = row["expires_at"] - transaction.now
            # The durable hold commits before publishing a live exact-job lease.
            binding = original.request.binding
            source = original.source
            core_scope = source.create_scope(
                operator=self._operator,
                context_digest=binding.context_digest,
                policy_digest=binding.policy_digest,
                policy_epoch=binding.policy_epoch,
                scope_digest=binding.scope_digest,
                operator_maximum_digest=binding.operator_maximum_digest,
                owner_fence=binding.owner_fence,
                revocation_epoch=binding.revocation_epoch,
                budget_digest=binding.budget_digest,
                delegation_digest=binding.delegation_digest,
                capabilities_digest=binding.capabilities_digest,
            )
            baseline = self.coordinator._scope(self.scope).native.assurance.baseline_gate
            proof = source.issue(
                original.action,
                original.preview.review,
                configuration_digest(baseline),
                core_scope,
                satisfaction_id=original.request.request_id,
                lifetime=remaining,
                operator=self._operator,
            )
            lease = source.reserve_lease(
                proof,
                derive_runtime_capability_contract(original.preview.review),
                original.broker,
                operator=self._operator,
            )
            context = _Preparation(uuid4().hex)
            approved.satisfaction, approved.scope, approved.execution_lease, approved.context = (
                proof,
                core_scope,
                lease,
                context,
            )
            approved.context_id = context.preparation_id
            self._preparing[context] = approved
            try:
                evaluation = self.coordinator.evaluate(
                    self.scope,
                    channel,
                    lease_id,
                    original.native_reference,
                    original.action,
                    idempotency_key="approval-eval-" + original.request.request_id,
                    governance_context=context,
                )
                if evaluation.reference is None:
                    raise CoordinatorRejected(
                        "governance original evaluation reference unavailable"
                    )
                reservation = self.coordinator.reserve(
                    self.scope,
                    channel,
                    lease_id,
                    evaluation.reference,
                    original.action,
                    idempotency_key="approval-reserve-" + original.request.request_id,
                    governance_context=context,
                )
                if reservation.reference is None:
                    raise CoordinatorRejected(
                        "governance original reservation reference unavailable"
                    )
                prepared = self.coordinator._prepared[reservation.reference]
                approved.reservation_id, approved.authorization = (
                    reservation.reference,
                    prepared.authorization,
                )
                return reservation
            except Exception:
                with self._transaction() as transaction:
                    _, _, namespace = self._namespace(transaction)
                    row = namespace["requests"][original.request.request_id]
                    if row["status"] == "held":
                        row["status"] = "canceled"
                        transaction.append(
                            self.scope.scope_key,
                            "approval_preparation_canceled",
                            original.request.request_id,
                            {"binding_digest": row["binding_digest"]},
                            maximum=self.coordinator._limit,
                        )
                source.finish(lease, operator=self._operator)
                raise

    def _preparation(self, context):
        value = self._preparing.get(context) if type(context) is _Preparation else None
        if value is None or context.preparation_id != value.context_id:
            raise CoordinatorRejected("governance original exact preparation required")
        return value

    def _ordinary_allow(
        self,
        channel,
        reference,
        action,
        *,
        broker=None,
        context=None,
        host_context=None,
        original_job=None,
    ):
        """Additional fresh core filter; ordinary authority/policy/budget checks still apply."""
        from .broker import SwarmExecutionBroker

        if type(action) is not ActionEnvelope:
            raise CoordinatorRejected("governance exact ordinary action required")
        with self._barrier, self._lock, self._transaction() as transaction:
            native_scope, _, _ = self._namespace(transaction)
            native = native_scope.native
            with native._lock, native.issuer._lock:
                grant, subject = native._grant(channel, reference)
                original = native_scope.brokers.get(subject.host_id)
                if (
                    type(original) is not SwarmExecutionBroker
                    or broker is not None
                    and broker is not original
                    or original._service is not native
                    or subject.source is None
                    or subject.context is None
                    or context is not None
                    and context is not subject.context
                ):
                    raise CoordinatorRejected("governance original ordinary broker scope required")
                supplied = host_context
                if supplied is None:
                    credential_uses = original.review_credential_uses(subject.source, action)
                    supplied = subject.source.context(credential_uses=credential_uses)
                if supplied.source is not subject.source:
                    raise CoordinatorRejected("governance original ordinary host required")
                if not original.verify_credential_uses(
                    subject.source, action, supplied.credential_uses
                ):
                    raise CoordinatorRejected(
                        "governance original ordinary credentials unavailable"
                    )
                runtime_source = original._executor.evidence_source(
                    session_digest=subject.source.session_digest,
                    policy_digest=subject.source.runtime_policy_digest,
                    context_digest=digest([subject.source.key, subject.context.registry_id]),
                )
                grant.gate.bind_runtime_source(runtime_source)
                if original_job is None:
                    preview = grant.gate.preview_action(action, host_context=supplied)
                else:
                    if (
                        type(original_job) is not _OrdinaryJob
                        or self._ordinary_jobs.get(original_job.job) is not original_job
                        or original_job.broker is not original
                        or original_job.gate is not grant.gate
                        or original_job.admission.owner_channel is not channel
                        or original_job.admission.grant_ref != reference
                        or original_job.admission.action_digest != digest(action.as_dict())
                    ):
                        raise CoordinatorRejected("governance original ordinary recheck required")
                    gate = original_job.gate
                    with gate._lock, gate._session._lock:
                        if (
                            digest(gate._session.snapshot()) != original_job.session_digest
                            or digest(gate._session.runtime_snapshot())
                            != original_job.runtime_digest
                            or not gate.binding_matches(original_job.admission.decision, action)
                        ):
                            raise CoordinatorRejected(
                                "governance ordinary history or binding changed"
                            )
                        baseline = replace(
                            gate.assurance.baseline_gate,
                            ordin=replace(gate.assurance.ordin, audit=None),
                        )
                        current_assurance = replace(gate.assurance, baseline_gate=baseline)
                        preview = gate._review(
                            action,
                            _reserve=False,
                            _assurance=current_assurance,
                            _host_context=supplied,
                            **original_job.review_inputs,
                        )
                contract = self._ordinary_contract(preview, native.issuer.profile.digest)
                if (
                    preview.review.decision != "allow"
                    or preview.assurance.baseline.denied
                    or preview.verification is None
                    or not preview.verification.ok
                    or any(
                        check.status != "satisfied"
                        for check in preview.assurance.invariant_evaluations
                    )
                ):
                    raise CoordinatorRejected(
                        "governance original human preparation or resolved requirements required"
                    )
                if original_job is None:
                    native.issuer._preview_operation(grant.handle, subject.source, contract)
                elif not native.issuer._check_operation(contract, grant.handle).ok:
                    raise CoordinatorRejected("governance current ordinary rights unavailable")
            if native_scope.runtime is not None:
                provider = native._policy_facts_provider
                facts = (
                    provider(subject.context, action, native_scope.runtime, preview)
                    if provider is not None
                    else None
                )
                projection = native_scope.runtime.evaluate_baseline(
                    subject.context, action, preview, facts=facts, delegation_gate=grant.gate
                )
                if projection._constraints_disposition != "execute":
                    raise CoordinatorRejected(
                        "governance independent ordinary policy denies execution"
                    )

    @staticmethod
    def _ordinary_contract(preview, profile_digest):
        """Keep exact REST commitment requirements in their complete typed contract."""
        from ordin.assurance.rest import (
            EXACT_REQUIREMENT,
            RestRequestContract,
            derive_rest_request_contract,
        )
        from ordin.runtime_contract import RuntimeCapabilityContract

        capability = derive_runtime_capability_contract(preview.review)
        complete: RuntimeCapabilityContract | RestRequestContract
        credentials = tuple(
            CredentialBinding(use.binding, use.host, use.port)
            for use in preview._context.credential_uses
            if use.action_digest == preview.action_digest and use.profile_digest == profile_digest
        )
        if credentials:
            capability = replace(
                capability,
                credentials=tuple(dict.fromkeys((*capability.credentials, *credentials))),
                contract_id="",
            )
        if preview.review.adapter == "network.rest":
            complete = derive_rest_request_contract(preview.review, capability=capability)
            if any(
                unknown.domain != "network" or unknown.reason_code != EXACT_REQUIREMENT
                for unknown in capability.unknowns
            ):
                raise CoordinatorRejected("governance unresolved REST requirements")
        else:
            complete = capability
            if capability.unknowns:
                raise CoordinatorRejected("governance unresolved ordinary requirements")
        if complete.digest != preview.contract_digest:
            raise CoordinatorRejected("governance complete delegated requirements changed")
        return complete

    def _ordinary_pending(
        self, broker, *, authorization=None, executor=None, job=None, admission_id=None
    ):
        """Resolve only an original protected authorization/job, never a caller allow flag."""
        from .broker import SwarmExecutionBroker

        native_scope = self.coordinator._scope(self.scope)
        if type(broker) is not SwarmExecutionBroker or not any(
            value is broker for value in native_scope.brokers.values()
        ):
            raise CoordinatorRejected("governance original ordinary broker required")
        with broker._state_lock:
            if authorization is not None:
                pending = broker._pending_row(authorization)
            else:
                matches = [
                    row
                    for row in broker._pending.values()
                    if (admission_id is not None and row.admission_id == admission_id)
                    or (job is not None and row.owned_job is job)
                ]
                if len(matches) != 1:
                    raise CoordinatorRejected("governance original ordinary owned job required")
                pending = matches[0]
            if (
                pending.scope.decision.review.decision != "allow"
                or pending.scope.decision.approval_fulfilled
                or pending.state not in {"prepared", "checking", "forwarding"}
                or executor is not None
                and executor is not broker._executor
                or job is not None
                and pending.owned_job is not job
            ):
                raise CoordinatorRejected("governance ordinary route cannot fulfill a warning")
            admission = broker._service._admissions.get(pending.admission_id)
            original_job = self._ordinary_jobs.get(pending.owned_job)
            if (
                admission is None
                or original_job is None
                or original_job.admission is not admission
                or original_job.admission_id != pending.admission_id
                or original_job.broker is not broker
                or original_job.executor is not broker._executor
                or original_job.job is not pending.owned_job
                or original_job.workload_context is not pending.scope.context
                or admission.owner_channel is not pending.workload_channel
                or digest(admission.action.as_dict()) != digest(pending.scope.action.as_dict())
            ):
                raise CoordinatorRejected("governance ordinary admission binding changed")
        self._ordinary_allow(
            pending.workload_channel,
            admission.grant_ref,
            pending.scope.action,
            broker=broker,
            context=pending.scope.context,
            host_context=pending.scope.delegation_scope.review_context,
            original_job=original_job,
        )
        return original_job

    def require_preparation(
        self, context, broker, channel, reference, action, *, host_context=None
    ):
        if context is None:
            self._ordinary_allow(
                channel, reference, action, broker=broker, host_context=host_context
            )
            return
        value = self._preparation(context)
        original = value.original
        if (
            original.broker is not broker
            or original.workload_channel is not channel
            or original.native_reference != reference
            or digest(action.as_dict()) != original.request.binding.action_digest
        ):
            raise CoordinatorRejected("governance broker/action/workload binding changed")
        if not original.source.verify(
            value.satisfaction,
            action,
            original.preview.review,
            configuration_digest(
                self.coordinator._scope(self.scope).native.assurance.baseline_gate
            ),
            value.scope,
        ):
            raise CoordinatorRejected("governance original human fulfillment no longer current")
        expected = original.preview._context
        if host_context is not None and (
            host_context.source is not expected.source
            or len(host_context.credential_uses) != len(expected.credential_uses)
            or any(
                actual is not retained
                for actual, retained in zip(host_context.credential_uses, expected.credential_uses)
            )
        ):
            raise CoordinatorRejected("governance original credential routing changed")
        if not broker.verify_credential_uses(expected.source, action, expected.credential_uses):
            raise CoordinatorRejected("governance original credential routing unavailable")

    def native_options(self, context, channel, reference, action, host_context):
        if context is None:
            self._ordinary_allow(channel, reference, action, host_context=host_context)
            return host_context, {}
        value = self._preparation(context)
        self.require_preparation(
            context,
            value.original.broker,
            channel,
            reference,
            action,
            host_context=host_context,
        )
        native = value.original.source.host_approval(value.satisfaction)
        if host_context.source is not value.original.source.host:
            raise CoordinatorRejected("governance protected host identity changed")
        supplied = host_context.source.context(
            capability_authorities=host_context.capability_authorities,
            request_authorities=host_context.request_authorities,
            approvals=tuple(
                receipt
                for receipt in host_context.approvals
                if receipt.receipt_id != native.receipt_id
            )
            + (native,),
            assessments=host_context.assessments,
            credential_uses=host_context.credential_uses,
        )
        return supplied, {
            "approval_satisfaction": value.satisfaction,
            "approval_scope": value.scope,
            "approval_execution_lease": value.execution_lease,
        }

    def require_native_dispatch(
        self,
        context,
        workload_context,
        action,
        broker,
        *,
        channel=None,
        reference=None,
        host_context=None,
        admission_id=None,
    ):
        if context is None:
            original_job = self._ordinary_pending(broker, admission_id=admission_id)
            if (
                original_job.admission.owner_channel is not channel
                or original_job.workload_context is not workload_context
                or original_job.admission.grant_ref != reference
                or original_job.admission.action_digest != digest(action.as_dict())
                or host_context is not original_job.admission.decision._context
            ):
                raise CoordinatorRejected("governance original native ordinary admission required")
            return
        value = self._preparation(context)
        if (
            broker is not value.original.broker
            or digest(workload_context.as_dict()) != value.original.request.binding.context_digest
            or digest(action.as_dict()) != value.original.request.binding.action_digest
        ):
            raise CoordinatorRejected("governance requires the original owned broker route")
        self.require_preparation(
            context,
            broker,
            value.original.workload_channel,
            value.original.native_reference,
            action,
            host_context=host_context,
        )

    def bind_owned_job(self, context, broker, executor, job):
        if context is None:
            self._bind_ordinary_job(broker, executor, job)
            return
        value = self._preparation(context)
        if broker is not value.original.broker:
            raise CoordinatorRejected("governance job belongs to another broker")
        value.original.source.bind_job(
            value.execution_lease, broker, executor, job, operator=self._operator
        )

    def _bind_ordinary_job(self, broker, executor, job):
        """Capture recheck inputs only from a live native ticket and original owned job."""
        from .broker import SwarmExecutionBroker

        native_scope = self.coordinator._scope(self.scope)
        if (
            type(broker) is not SwarmExecutionBroker
            or broker not in native_scope.brokers.values()
            or broker._service is not native_scope.native
            or executor is not broker._executor
        ):
            raise CoordinatorRejected("governance original ordinary producer required")
        native = native_scope.native
        with self._barrier, self._lock, native._lock, native.issuer._lock, executor._jobs_lock:
            state = executor._job(job)
            if state.state != "queued" or job in self._ordinary_jobs:
                raise CoordinatorRejected("governance original fresh ordinary job required")
            if (
                sum(value.broker is broker for value in self._ordinary_jobs.values())
                >= broker._limit
            ):
                raise CoordinatorRejected("governance ordinary witness history exhausted")
            candidates = []
            for key, admission in native._admissions.items():
                if (
                    admission.state != "pending"
                    or admission.action_digest != state.binding[1]
                    or admission.decision.contract_digest != state.binding[2]
                ):
                    continue
                try:
                    grant, subject = native._grant(admission.owner_channel, admission.grant_ref)
                except ValueError:
                    continue
                if subject.host_id == broker._broker_enrollment.host_id:
                    candidates.append((key, admission, grant, subject.context))
            if len(candidates) != 1:
                raise CoordinatorRejected(
                    "governance unique original native job admission required"
                )
            key, admission, grant, workload_context = candidates[0]
            if (
                admission.decision.review.decision != "allow"
                or admission.decision.approval_fulfilled
            ):
                raise CoordinatorRejected("governance ordinary job cannot fulfill a warning")
            gate = grant.gate
            with gate._lock, gate._session._lock:
                inputs = gate.original_review_inputs(admission.decision)
                self._ordinary_jobs[job] = _OrdinaryJob(
                    broker,
                    executor,
                    job,
                    key,
                    admission,
                    workload_context,
                    gate,
                    {"history": admission.decision._history, **inputs},
                    digest(gate._session.snapshot()),
                    digest(gate._session.runtime_snapshot()),
                )

    def consume_in_transaction(self, transaction, context, broker, authorization, reservation_id):
        if context is None:
            prepared = self.coordinator._prepared.get(reservation_id)
            if (
                prepared is None
                or prepared.broker is not broker
                or prepared.authorization is not authorization
            ):
                raise CoordinatorRejected("governance original ordinary reservation required")
            self._ordinary_pending(broker, authorization=authorization)
            return
        value = self._preparation(context)
        original = value.original
        if (
            broker is not original.broker
            or value.authorization is not authorization
            or value.reservation_id != reservation_id
        ):
            raise CoordinatorRejected("governance original reservation/authorization required")
        _, state, namespace = self._namespace(transaction)
        row = namespace["requests"].get(original.request.request_id)
        if (
            row is None
            or row["request"] != original.request.as_dict()
            or row["binding_digest"] != original.request.binding.digest
            or row["status"] != "held"
            or transaction.now >= row["expires_at"]
            or self._current_votes(row) < original.request.quorum
            or row["directory_digest"] != self.directory.binding_digest
        ):
            raise CoordinatorRejected("governance approval unavailable at actual consumption")
        binding = original.request.binding
        if (
            state["policy_epoch"],
            state["revocation_epoch"],
            state["owner"]["fence"],
            state["policy_digest"],
        ) != (
            binding.policy_epoch,
            binding.revocation_epoch,
            binding.owner_fence,
            binding.policy_digest,
        ):
            raise CoordinatorRejected("governance epoch/owner/policy changed at consumption")
        row["status"], row["reservation_digest"] = "consumed", digest(reservation_id)
        transaction.append(
            self.scope.scope_key,
            "approval_consumed",
            original.request.request_id,
            {"binding_digest": row["binding_digest"], "reservation_digest": digest(reservation_id)},
            maximum=self.coordinator._limit,
        )

    def begin_owned_effect(self, context, broker, executor, job):
        if context is None:
            self._ordinary_pending(broker, executor=executor, job=job)
            return
        value = self._preparation(context)
        value.original.source.begin(
            value.execution_lease, broker, executor, job, operator=self._operator
        )

    def fulfill(self, operator_channel, request_id: str):
        """Execute one approved request using only retained original host inputs."""
        if type(request_id) is not str or not 1 <= len(request_id) <= 64:
            raise CoordinatorRejected("governance bounded original request required")
        with self._lock:
            original = self._originals.get(request_id)
        if original is None:
            raise CoordinatorRejected("governance original current request required")
        self.directory.require(
            operator_channel, task_id=original.task_id, roles=original.request.required_roles
        )
        with self._barrier, self._lock:
            self._configuration()
            if self._originals.get(request_id) is not original:
                raise CoordinatorRejected("governance original request changed")
            self.directory.require(
                operator_channel, task_id=original.task_id, roles=original.request.required_roles
            )
            receipt = self._receipt_by_request.get(request_id)
            if receipt is None or self._approved(receipt).original is not original:
                raise CoordinatorRejected("governance original approved receipt unavailable")
            self.prepare(
                receipt, original.workload_channel, original.lease_id, original.caller_action
            )
            return self.dispatch(receipt)

    def fulfillment_result(self, operator_channel, request_id: str):
        """Return the retained original completed broker outcome, never a wire report."""
        if type(request_id) is not str or not 1 <= len(request_id) <= 64:
            raise CoordinatorRejected("governance bounded original request required")
        with self._barrier, self._lock, self._transaction() as transaction:
            _, _, namespace = self._namespace(transaction, contained=True)
            original = self._originals.get(request_id)
            if original is None:
                raise CoordinatorRejected("governance original completed request required")
            self.directory.require(
                operator_channel, task_id=original.task_id, roles=original.request.required_roles
            )
            receipt = self._receipt_by_request.get(request_id)
            if receipt is None:
                raise CoordinatorRejected("governance retained original receipt unavailable")
            value = self._approved(receipt)
            row = namespace["requests"].get(request_id)
            if (
                value.original is not original
                or value.authorization is None
                or row is None
                or row["status"] != "completed"
                or row["request"] != original.request.as_dict()
                or row["binding_digest"] != original.request.binding.digest
            ):
                raise CoordinatorRejected("governance original completed outcome unavailable")
            broker = original.broker
            with broker._state_lock:
                pending = broker._pending_row(value.authorization)
                result = pending.result
                if (
                    result is None
                    or result.status != "completed"
                    or not result.physical_enforcement
                    or not broker.verify_result(result, value.authorization)
                    or result.action_digest != original.request.binding.action_digest
                    or result.executor_outcome is None
                    or not broker._executor.verify_outcome(
                        result.executor_outcome, pending.scope.plan
                    )
                ):
                    raise CoordinatorRejected(
                        "governance original actual broker outcome unavailable"
                    )
                return result

    def dispatch(self, receipt: SwarmApprovalReceipt):
        with self._barrier, self._lock:
            value = self._approved(receipt)
            if value.reservation_id is None or value.authorization is None:
                raise CoordinatorRejected("governance original prepared operation required")
            broker = value.original.broker
            with self._transaction() as transaction:
                _, _, namespace = self._namespace(transaction)
                if namespace["requests"][value.original.request.request_id]["status"] != "held":
                    raise CoordinatorRejected("governance approval already used or terminal")
            try:
                result = self.coordinator.guarded_dispatch(
                    self.scope, broker._broker_channel, value.reservation_id
                )
            except Exception:
                with self._transaction() as transaction:
                    _, _, namespace = self._namespace(transaction, contained=True)
                    row = namespace["requests"][value.original.request.request_id]
                    if row["status"] in {"held", "consumed"}:
                        row["status"] = "uncertain"
                        transaction.append(
                            self.scope.scope_key,
                            "approval_outcome",
                            value.original.request.request_id,
                            {"status": "uncertain", "binding_digest": row["binding_digest"]},
                            maximum=self.coordinator._limit,
                        )
                raise
            finally:
                # Exceptions and ambiguous DB acknowledgements must also close the live lease.
                value.original.source.finish(value.execution_lease, operator=self._operator)
            with self._transaction() as transaction:
                _, _, namespace = self._namespace(transaction, contained=True)
                row = namespace["requests"][value.original.request.request_id]
                row["status"] = "completed" if result.status == "host_completed" else "uncertain"
                transaction.append(
                    self.scope.scope_key,
                    "approval_outcome",
                    value.original.request.request_id,
                    {"status": row["status"], "binding_digest": row["binding_digest"]},
                    maximum=self.coordinator._limit,
                )
            return result

    def resolve(self, operator_channel, request_id: str, choice: str, *, idempotency_key: str):
        if (
            choice not in {"approve", "deny"}
            or type(idempotency_key) is not str
            or not 1 <= len(idempotency_key) <= 128
        ):
            raise ValueError("closed human resolution and bounded idempotency key required")
        with self._lock:
            original = self._originals.get(request_id)
        if original is None:
            raise CoordinatorRejected("governance original current request required")
        actor = self.directory.require(
            operator_channel, task_id=original.task_id, roles=original.request.required_roles
        )
        key = digest([actor.enrollment_id, idempotency_key])
        with self._barrier, self._lock, self._transaction() as transaction:
            _, _, namespace = self._namespace(transaction)
            row = namespace["requests"].get(request_id)
            if (
                row is None
                or row["binding_digest"] != original.request.binding.digest
                or row["request"] != original.request.as_dict()
            ):
                raise CoordinatorUnavailable("governance request history missing or changed")
            self.directory.member(
                actor.enrollment_id, task_id=original.task_id, roles=original.request.required_roles
            )
            self._expire_row(transaction, row, request_id)
            fingerprint = digest([choice, actor.digest, original.request.digest])
            previous = row["resolutions"].get(key)
            if previous is not None:
                if previous["fingerprint"] != fingerprint:
                    raise CoordinatorRejected("governance resolution idempotency conflict")
            elif row["status"] in {"pending", "approved"}:
                if (
                    row["status"] not in {"pending", "approved"}
                    or transaction.now >= row["expires_at"]
                ):
                    raise CoordinatorRejected(
                        "governance request expired, denied, canceled or already consumed"
                    )
                current = self._capture(
                    transaction,
                    original.workload_channel,
                    original.lease_id,
                    original.native_reference,
                    original.action,
                )[0]
                if current.digest != original.request.binding.digest:
                    raise CoordinatorRejected(
                        "governance exact review context changed; fresh review required"
                    )
                old_vote = row["votes"].get(actor.principal_id)
                if old_vote is not None and old_vote["choice"] != choice:
                    raise CoordinatorRejected(
                        "governance conflicting resolution requires a new request"
                    )
                if old_vote is None:
                    if len(row["votes"]) >= 16:
                        raise CoordinatorRejected("bounded governance voter history exhausted")
                    row["votes"][actor.principal_id] = {
                        "enrollment_id": actor.enrollment_id,
                        "actor_digest": actor.digest,
                        "certificate_digest": actor.certificate_digest,
                        "choice": choice,
                    }
                votes = self._current_votes(row)
                row["status"] = (
                    "denied"
                    if choice == "deny"
                    else "approved"
                    if votes >= original.request.quorum
                    else "pending"
                )
                if len(row["resolutions"]) >= 32:
                    raise CoordinatorRejected("bounded governance resolution history exhausted")
                row["resolutions"][key] = {"fingerprint": fingerprint}
                transaction.append(
                    self.scope.scope_key,
                    "approval_resolved",
                    request_id,
                    {
                        "binding_digest": row["binding_digest"],
                        "actor_digest": actor.digest,
                        "choice": choice,
                        "status": row["status"],
                    },
                    maximum=self.coordinator._limit,
                )
            result = {
                "schema_version": "ordin.swarm_approval_resolution.v1",
                "request_id": request_id,
                "status": row["status"],
                "votes": self._current_votes(row),
                "quorum": original.request.quorum,
                "execution_authority": False,
            }
        # Failed or ambiguous commit must not expose a live approval handle.
        if result["status"] == "approved":
            with self._lock:
                result["receipt"] = self._publish_receipt(original)
        elif result["status"] in {"denied", "canceled", "expired"}:
            self._close_request(request_id)
        return result

    def snapshot(self, operator_channel, *, task_id: str):
        self.directory.require(operator_channel, task_id=task_id, roles=("observe",))
        with self._barrier, self._lock, self._transaction() as transaction:
            _, state, namespace = self._namespace(transaction, contained=True)
            requests = [
                {
                    "request": row["request"],
                    "status": row["status"],
                    "vote_count": self._current_votes(row),
                }
                for row in namespace["requests"].values()
                if row["task_id"] == task_id
            ]
            return {
                "schema_version": "ordin.swarm_approval_queue.v1",
                "scope_digest": self.scope.scope_key,
                "policy_epoch": state["policy_epoch"],
                "owner_fence": state["owner"]["fence"],
                "requests": requests,
                "recoveries": [
                    {
                        "request": row["request"],
                        "status": row["status"],
                        "vote_count": self._current_votes(row),
                    }
                    for row in namespace["recoveries"].values()
                    if row["task_id"] == task_id
                ],
                "execution_authority": False,
            }

    def get_request(self, operator_channel, request_id):
        """Look up a redacted report after RBAC; never reconstruct a live receipt."""
        with self._barrier, self._lock, self._transaction() as transaction:
            _, _, namespace = self._namespace(transaction, contained=True)
            row = namespace["requests"].get(request_id) or namespace["recoveries"].get(request_id)
            if row is None:
                raise CoordinatorRejected("governance request unavailable")
            self.directory.require(operator_channel, task_id=row["task_id"], roles=("observe",))
            status = (
                "expired"
                if (
                    row["status"] in {"pending", "approved", "held"}
                    and transaction.now >= row["expires_at"]
                )
                else row["status"]
            )
            return {
                "request": row["request"],
                "status": status,
                "vote_count": self._current_votes(row),
            }

    def describe_receipt(self, receipt):
        """A receipt report has no restoration or execution authority."""
        with self._barrier, self._lock, self._transaction() as transaction:
            value = self._approved(receipt)
            _, _, namespace = self._namespace(transaction, contained=True)
            request = value.original.request
            row = namespace["requests"].get(request.request_id)
            if row is None or row["request"] != request.as_dict():
                raise CoordinatorUnavailable("original approval history changed")
            return {
                "schema_version": "ordin.swarm_approval_receipt.v1",
                "receipt_id": receipt.receipt_id,
                "request_id": request.request_id,
                "request_digest": request.digest,
                "binding_digest": request.binding.digest,
                "expires_at": row["expires_at"],
                "status": row["status"],
                "execution_authority": False,
            }

    def audit(self, operator_channel, *, task_id):
        """Bounded scoped vote/outcome projection of the protected durable history."""
        self.directory.require(operator_channel, task_id=task_id, roles=("observe",))
        with self._barrier, self._lock, self._transaction() as transaction:
            _, state, namespace = self._namespace(transaction, contained=True)
            records = []
            for mode, rows in (
                ("action", namespace["requests"]),
                ("recovery", namespace["recoveries"]),
            ):
                for request_id, row in rows.items():
                    if row["task_id"] == task_id:
                        records.append(
                            {
                                "request_id": request_id,
                                "kind": mode,
                                "binding_digest": row["binding_digest"],
                                "status": row["status"],
                                "expires_at": row["expires_at"],
                                "votes": [
                                    {"actor_digest": vote["actor_digest"], "choice": vote["choice"]}
                                    for vote in row["votes"].values()
                                ],
                            }
                        )
            return {
                "schema_version": "ordin.swarm_approval_audit.v1",
                "scope_digest": self.scope.scope_key,
                "journal_head": state["journal_head"],
                "records": records,
                "execution_authority": False,
            }

    def _recovery_evidence(self, controller, receipt, task_id):
        from .containment import SwarmContainmentController

        if (
            type(controller) is not SwarmContainmentController
            or controller._coordinator is not self.coordinator
            or controller._scope is not self.scope
            or self.coordinator._scope(self.scope).native._containment is not controller
        ):
            raise CoordinatorRejected("original same-scope containment controller required")
        incident = controller._original(receipt)
        if incident.resumed or any(
            handle is not self.scope
            or enrollment.context is None
            or (enrollment.context.identity.task_id or "swarm-control") != task_id
            for handle, _, enrollment in incident.affected
        ):
            raise CoordinatorRejected("recovery requires original bounded single-task scope")
        evidence = controller._reconciled(incident)
        if evidence is None:
            raise CoordinatorRejected("unknown inflight execution cannot authorize recovery")
        return evidence

    def _recovery_binding(self, transaction, controller, receipt, evidence):
        _, state, namespace = self._namespace(transaction, contained=True)
        intent = state["fences"].get(str(receipt.revocation_epoch))
        if (
            intent is None
            or intent["reconciled"]
            or receipt.revocation_epoch != state["revocation_epoch"]
            or len(intent.get("members", {self.scope.scope_key: receipt.revocation_epoch})) != 1
            or state["policy_epoch"] <= intent["policy_epoch"]
            and state["owner"]["fence"] <= intent["owner_fence"]
        ):
            raise CoordinatorRejected("fresh owner/policy and original current incident required")
        binding = digest(
            [
                self.scope.scope_key,
                receipt.as_dict(),
                evidence,
                state["policy_digest"],
                state["policy_epoch"],
                state["owner"]["fence"],
                state["revocation_epoch"],
                self._policy_digest,
                self.directory.binding_digest,
                controller._policy.digest,
            ]
        )
        return binding, state, namespace

    def request_recovery(
        self,
        operator_channel,
        controller,
        incident_receipt,
        *,
        task_id,
        reason_code,
        idempotency_key,
    ):
        if (
            reason_code not in REASONS
            or type(idempotency_key) is not str
            or not 1 <= len(idempotency_key) <= 128
        ):
            raise ValueError("bounded recovery reason and idempotency key required")
        actor = self.directory.require(
            operator_channel, task_id=task_id, roles=self.policy.recovery_roles
        )
        with self._barrier, self._lock:
            evidence = self._recovery_evidence(controller, incident_receipt, task_id)
            with self._transaction() as transaction:
                binding, state, namespace = self._recovery_binding(
                    transaction, controller, incident_receipt, evidence
                )
                self.directory.member(
                    actor.enrollment_id, task_id=task_id, roles=self.policy.recovery_roles
                )
                key = digest(["recovery", actor.digest, idempotency_key])
                previous = namespace["keys"].get(key)
                fingerprint = digest([binding, reason_code, task_id])
                if previous is not None:
                    if (
                        previous.get("fingerprint") != fingerprint
                        or previous["request_id"] not in self._recovery_requests
                    ):
                        raise CoordinatorRejected(
                            "recovery idempotency changed or original request lost"
                        )
                    return self._recovery_requests[previous["request_id"]][0]
                if (
                    len(namespace["requests"]) + len(namespace["recoveries"])
                    >= self.policy.max_requests
                ):
                    raise CoordinatorRejected("bounded governance request history exhausted")
                request = SwarmRecoveryRequest(
                    uuid4().hex,
                    binding,
                    digest(incident_receipt.as_dict()),
                    self.scope.scope_key,
                    state["policy_epoch"],
                    state["revocation_epoch"],
                    state["owner"]["fence"],
                    self.policy.recovery_roles,
                    self.policy.recovery_quorum,
                    min(
                        transaction.now + min(60, self.policy.lifetime),
                        state["owner"]["expires_at"],
                    ),
                    reason_code,
                )
                namespace["recoveries"][request.request_id] = {
                    "request": request.as_dict(),
                    "binding_digest": binding,
                    "directory_digest": self.directory.binding_digest,
                    "task_id": task_id,
                    "expires_at": request.expires_at,
                    "status": "pending",
                    "votes": {},
                    "resolutions": {},
                }
                namespace["keys"][key] = {
                    "fingerprint": fingerprint,
                    "request_id": request.request_id,
                }
                transaction.append(
                    self.scope.scope_key,
                    "recovery_requested",
                    request.request_id,
                    {
                        "actor_digest": actor.digest,
                        "binding_digest": binding,
                        "reason_code": reason_code,
                    },
                    maximum=self.coordinator._limit,
                )
            self._recovery_requests[request.request_id] = (
                request,
                controller,
                incident_receipt,
                task_id,
            )
            return request

    def resolve_recovery(self, operator_channel, request_id, choice, *, idempotency_key):
        if (
            choice not in {"approve", "deny"}
            or type(idempotency_key) is not str
            or not 1 <= len(idempotency_key) <= 128
        ):
            raise ValueError("finite recovery choice and bounded idempotency key required")
        with self._barrier, self._lock:
            original = self._recovery_requests.get(request_id)
            if original is None:
                raise CoordinatorRejected("original current recovery request required")
            request, controller, incident, task_id = original
            actor = self.directory.require(
                operator_channel, task_id=task_id, roles=request.required_roles
            )
            evidence = self._recovery_evidence(controller, incident, task_id)
            with self._transaction() as transaction:
                binding, _, namespace = self._recovery_binding(
                    transaction, controller, incident, evidence
                )
                row = namespace["recoveries"].get(request_id)
                if (
                    row is None
                    or binding != request.binding_digest
                    or row["binding_digest"] != binding
                ):
                    raise CoordinatorRejected("recovery evidence, scope or authority changed")
                self._expire_row(transaction, row, request_id)
                key = digest([actor.enrollment_id, idempotency_key])
                fingerprint = digest([choice, actor.digest, request.digest])
                old = row["resolutions"].get(key)
                if old is not None and old["fingerprint"] != fingerprint:
                    raise CoordinatorRejected("recovery resolution idempotency conflict")
                if old is None and row["status"] in {"pending", "approved"}:
                    vote = row["votes"].get(actor.principal_id)
                    if vote is not None and vote["choice"] != choice:
                        raise CoordinatorRejected(
                            "conflicting recovery resolution requires new review"
                        )
                    if len(row["resolutions"]) >= 32 or vote is None and len(row["votes"]) >= 16:
                        raise CoordinatorRejected("bounded recovery vote history exhausted")
                    row["votes"][actor.principal_id] = {
                        "enrollment_id": actor.enrollment_id,
                        "actor_digest": actor.digest,
                        "certificate_digest": actor.certificate_digest,
                        "choice": choice,
                    }
                    row["status"] = (
                        "denied"
                        if choice == "deny"
                        else (
                            "approved" if self._current_votes(row) >= request.quorum else "pending"
                        )
                    )
                    row["resolutions"][key] = {"fingerprint": fingerprint}
                    transaction.append(
                        self.scope.scope_key,
                        "recovery_resolved",
                        request_id,
                        {
                            "actor_digest": actor.digest,
                            "choice": choice,
                            "binding_digest": binding,
                            "status": row["status"],
                        },
                        maximum=self.coordinator._limit,
                    )
                result = {
                    "schema_version": "ordin.swarm_approval_resolution.v1",
                    "request_id": request_id,
                    "status": row["status"],
                    "votes": self._current_votes(row),
                    "quorum": request.quorum,
                    "execution_authority": False,
                }
            if result["status"] == "approved":
                handle = next(
                    (handle for handle, value in self._recoveries.items() if value is original),
                    None,
                )
                if handle is None:
                    handle = SwarmRecoveryApproval(uuid4().hex)
                    self._recoveries[handle] = original
                    self._recovery_ids[handle] = handle.approval_id
                elif self._recovery_ids.get(handle) != handle.approval_id:
                    raise CoordinatorRejected("mutated original recovery handle")
                result["approval"] = handle
            return result

    def resume(self, operator_channel, approval):
        with self._barrier, self._lock:
            original = (
                self._recoveries.get(approval) if type(approval) is SwarmRecoveryApproval else None
            )
            if original is None or self._recovery_ids.get(approval) != approval.approval_id:
                raise CoordinatorRejected("original one-use human recovery approval required")
            request, controller, incident, task_id = original
            actor = self.directory.require(
                operator_channel, task_id=task_id, roles=request.required_roles
            )
            evidence = self._recovery_evidence(controller, incident, task_id)
            with self._transaction() as transaction:
                binding, _, namespace = self._recovery_binding(
                    transaction, controller, incident, evidence
                )
                row = namespace["recoveries"].get(request.request_id)
                if (
                    row is None
                    or row["status"] != "approved"
                    or transaction.now >= row["expires_at"]
                    or binding != request.binding_digest
                    or row["binding_digest"] != binding
                    or self._current_votes(row) < request.quorum
                ):
                    raise CoordinatorRejected("recovery quorum expired, consumed or changed")
                row["status"] = "consumed"
                remaining = min(60, row["expires_at"] - transaction.now)
                transaction.append(
                    self.scope.scope_key,
                    "recovery_consumed",
                    request.request_id,
                    {"actor_digest": actor.digest, "binding_digest": binding},
                    maximum=self.coordinator._limit,
                )
            # Only a durable confirmed human quorum reaches the original low-level controller.
            try:
                low_level = controller.approve_resume(
                    incident, operator=self._operator, lifetime=remaining
                )
                if not controller.verify_resume_receipt(
                    low_level,
                    scope_digest=self.scope.scope_key,
                    revocation_epoch=request.revocation_epoch,
                    policy_epoch=request.policy_epoch,
                    owner_fence=request.owner_fence,
                ):
                    raise CoordinatorRejected("original recovery evidence changed before resume")
                result = controller.resume(incident, low_level, operator=self._operator)
            except Exception:
                self._record_recovery_outcome(request, "uncertain")
                raise
            self._record_recovery_outcome(request, "completed")
            return result

    def _record_recovery_outcome(self, request, status):
        with self._transaction() as transaction:
            _, _, namespace = self._namespace(transaction, contained=True)
            row = namespace["recoveries"][request.request_id]
            if row["status"] != "consumed":
                raise CoordinatorRejected("recovery terminal transition is invalid")
            row["status"] = status
            transaction.append(
                self.scope.scope_key,
                "recovery_outcome",
                request.request_id,
                {"status": status, "binding_digest": request.binding_digest},
                maximum=self.coordinator._limit,
            )
