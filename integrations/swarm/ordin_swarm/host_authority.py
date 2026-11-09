"""Original host authority assembled from existing Ordin safety components."""

from __future__ import annotations

from contextlib import ExitStack, contextmanager
from functools import wraps
from dataclasses import dataclass, field
import hashlib
import json
import os
import tempfile
from pathlib import Path
import time
from typing import Mapping, Any, Callable, Concatenate, ParamSpec, TypeVar
from threading import RLock
from urllib.parse import urlsplit
from uuid import uuid4

from ordin import AgentGate, Ordin, ToolResourceBinding, ToolSemanticRule, ToolSemanticsRegistry
from ordin.action import ActionEnvelope
from ordin.assurance import (
    AssuranceGate,
    DelegationAuthority,
    DelegationIssuer,
    HostEvidenceSource,
    ProtectedProfileSelection,
    RepositoryScope,
    SecurityProfile,
    load_approved_profile,
)
from ordin.assurance._files import read_scoped_file
from ordin.assurance.rest import RestRequestAuthority, RestSemantics
from ordin.runtime_boundary import RuntimeCapabilityBoundary
from ordin.runtime_contract import (
    CredentialBinding,
    FilesystemCapability,
    NetworkCapability,
    PrivilegeCapability,
    ProcessCapability,
    ToolCapability,
)
from ordin.runtime_observation import RuntimeEvidenceSource
from ordin.runtime_requirements import RuntimeRequirementProfile, ToolRuntimeRequirement
from ordin.session import IntegrationSession, SessionIdentity
from ordin.swarm import CoverageManifest, InMemoryAgentRegistry, SwarmGate
from ordin.swarm.budget_store import SQLiteBudgetStore
from ordin.swarm.budgets import BudgetLedger, BudgetLimit, BudgetPolicy
from ordin.swarm.broker import SwarmExecutionBroker
from ordin.swarm.approval import SwarmApprovalPolicy, SwarmApprovalRequest
from ordin.swarm.authorization import BrokerResult
from ordin.swarm.approval_service import SwarmApprovalBootstrap, SwarmApprovalService
from ordin.swarm.coordinator import SwarmCoordinator
from ordin.swarm.coordinator_store import CoordinatorClock, SQLiteCoordinatorStore
from ordin.swarm.delegation import SwarmDelegationService
from ordin.swarm.operator_auth import SwarmOperatorDirectory
from ordin.swarm.workload_auth import WorkloadAuthenticator

from .host_pki import PrivateHostPKI, _new_file
from .host_profiles import HOST_TOOL_DATA_BYTES, ToolHostProfile, check_private_directory


RUNTIME = "ordin-owned"


class _HostCleanupIncomplete(RuntimeError):
    """Private original cleanup capability, never reconstructed from data."""

    def __init__(self, owner):
        super().__init__("managed host cleanup remains incomplete")
        self.__owner = owner

    @property
    def cleanup_owner(self):
        return self.__owner

    def retry_cleanup(self):
        self.__owner.close()


_ControlP = ParamSpec("_ControlP")
_ControlR = TypeVar("_ControlR")


def _authority_control(
    method: Callable[Concatenate[Any, _ControlP], _ControlR],
) -> Callable[Concatenate[Any, _ControlP], _ControlR]:
    @wraps(method)
    def controlled(self: Any, *args: _ControlP.args, **kwargs: _ControlP.kwargs) -> _ControlR:
        with self.control_phase():
            return method(self, *args, **kwargs)

    return controlled


def _budget_policy(profile, policy_epoch):
    return BudgetPolicy(
        policy_epoch,
        (
            BudgetLimit("swarm", "requests", profile.limits.requests),
            BudgetLimit("swarm", "concurrency", profile.limits.concurrency),
            BudgetLimit("swarm", "output_bytes", profile.limits.output_bytes),
        ),
    )


@dataclass(frozen=True, slots=True)
class HostDispatch:
    status: str
    reason_codes: tuple[str, ...]
    forwarded: bool | None
    physical_enforcement: bool
    result: BrokerResult | None = field(default=None, repr=False)
    approval: SwarmApprovalRequest | None = field(default=None, repr=False)
    action: ActionEnvelope | None = field(default=None, repr=False)
    lease_id: str | None = field(default=None, repr=False)


def host_core(test_routes=(), *, required_euid=None) -> Ordin:
    return Ordin(
        rest_semantics=RestSemantics(),
        runtime_requirements=(
            RuntimeRequirementProfile(
                "managed-fixed-tests" if test_routes else "managed-owned-tools",
                required_euid=required_euid,
                tool_requirements=tuple(
                    ToolRuntimeRequirement(
                        RUNTIME,
                        None,
                        "run_tests",
                        "call",
                        route.test_id,
                        filesystem=(
                            FilesystemCapability("read", str(route.project_root), "prefix"),
                            FilesystemCapability("read", str(route.runtime.root), "prefix"),
                        ),
                        client_executables=(str(route.runtime.interpreter),),
                        spawn_children=False,
                    )
                    for route in test_routes
                ),
            )
            if test_routes or required_euid is not None
            else None
        ),
        tool_semantics=ToolSemanticsRegistry(
            "managed-host-tools",
            "1",
            (
                ToolSemanticRule(
                    "managed-read",
                    "tool",
                    "read_file",
                    ("filesystem.read",),
                    runtime=RUNTIME,
                    resources=(ToolResourceBinding("path", "path"),),
                ),
                *(
                    (
                        ToolSemanticRule(
                            "managed-tests", "tool", "run_tests", ("code.execute",), runtime=RUNTIME
                        ),
                    )
                    if test_routes
                    else ()
                ),
                ToolSemanticRule(
                    "managed-write",
                    "tool",
                    "write_artifact",
                    ("filesystem.write",),
                    runtime=RUNTIME,
                    resources=(ToolResourceBinding("path", "path"),),
                ),
            ),
        ),
    )


def host_test_routes(profile: ToolHostProfile, *, operator: object):
    if not profile.test_routes:
        return ()
    from ordin.swarm.confined_tests import TestRoute, load_python_runtime_catalog

    runtime = load_python_runtime_catalog(
        profile.configuration_root / "state" / "test-runtime", operator=operator
    )
    return tuple(
        TestRoute(route.test_id, profile.workspace, route.selectors, runtime)
        for route in profile.test_routes
    )


def make_backend(profile: ToolHostProfile, *, operator: object, initialize: bool, test_routes=None):
    # This import remains optional: inspecting a core action starts no host.
    from ordin.swarm.owned_tools import LinuxOwnedToolsBackend

    routes = []
    for selected in profile.http_routes:
        from ordin.swarm.owned_tools import OwnedHTTPRoute

        parsed = urlsplit(selected.url)
        if parsed.hostname is None:
            raise ValueError("managed route hostname unavailable")
        credential = (
            None
            if selected.credential_file is None
            else read_scoped_file(
                profile.configuration_root,
                selected.credential_file,
                maximum=4096,
                private=True,
            )
        )
        ca_file = None
        if selected.ca_file is not None:
            read_scoped_file(
                profile.configuration_root, selected.ca_file, maximum=16384, private=True
            )
            ca_file = profile.configuration_root / selected.ca_file
        routes.append(
            OwnedHTTPRoute(
                selected.route_id,
                selected.url,
                selected.addresses,
                max_response_bytes=min(selected.response_limit_bytes, HOST_TOOL_DATA_BYTES),
                ca_file=ca_file,
                credential_binding=(
                    None
                    if credential is None
                    else CredentialBinding(
                        "managed-" + selected.route_id,
                        parsed.hostname,
                        parsed.port or 443,
                    )
                ),
                credential=credential,
                allow_private=selected.allow_private_network,
                allow_http=selected.allow_http,
            )
        )
    installations = profile.configuration_root / "state" / "workers"
    check_private_directory(installations)
    with os.scandir(installations) as entries:
        for number, _ in enumerate(entries):
            if number >= 63:
                raise ValueError(
                    "managed worker installation history requires operator maintenance"
                )
    installation = Path(tempfile.mkdtemp(prefix="worker-", dir=installations))
    return LinuxOwnedToolsBackend(
        profile.workspace,
        tuple(file.name for file in profile.files),
        installation,
        operator=operator,
        tool_runtime=RUNTIME,
        http_routes=tuple(routes),
        max_payload_bytes=HOST_TOOL_DATA_BYTES,
        max_write_bytes=HOST_TOOL_DATA_BYTES,
        initialize=initialize,
        **(
            {
                "test_routes": host_test_routes(profile, operator=operator)
                if test_routes is None
                else test_routes
            }
            if profile.test_routes
            else {}
        ),
    )


def _authority(profile, actor, uid, test_routes=()) -> DelegationAuthority:
    reads = (
        {name for principal in profile.actors for name in principal.read_files}
        if actor is None
        else set(actor.read_files)
    )
    writes = (
        {name for principal in profile.actors for name in principal.write_files}
        if actor is None
        else set(actor.write_files)
    )
    selected_routes = (
        profile.http_routes
        if actor is None
        else tuple(route for route in profile.http_routes if route.route_id in actor.http_routes)
    )
    selected_tests = tuple(
        route for route in test_routes if actor is None or route.test_id in actor.test_ids
    )
    filesystem = tuple(
        FilesystemCapability(access, str(profile.workspace / name), "exact")
        for access, names in (("read", reads), ("write", writes))
        for name in sorted(names)
    )
    filesystem += tuple(
        dict.fromkeys(
            FilesystemCapability("read", str(path), "prefix")
            for route in selected_tests
            for path in (route.project_root, route.runtime.root)
        )
    )
    network, credentials, requests = [], [], []
    for route in selected_routes:
        authority = RestRequestAuthority.from_parameters({"url": route.url, "method": "GET"})
        requests.append(authority)
        network.append(
            NetworkCapability(
                authority.host,
                authority.port,
                "rest",
                "read",
                ("GET",),
                (authority.path,),
            )
        )
        if route.credential_file is not None:
            credentials.append(
                CredentialBinding("managed-" + route.route_id, authority.host, authority.port)
            )
    return DelegationAuthority(
        RuntimeCapabilityBoundary(
            "managed-root" if actor is None else "managed-" + actor.agent_id,
            filesystem=filesystem,
            network=tuple(network),
            tools=tuple(
                ToolCapability(RUNTIME, None, tool)
                for tool, enabled in (
                    ("read_file", bool(reads)),
                    ("write_artifact", bool(writes)),
                    ("run_tests", bool(selected_tests)),
                )
                if enabled
            ),
            process=ProcessCapability(
                bool(selected_tests),
                tuple(sorted({str(route.runtime.interpreter) for route in selected_tests})),
                False,
            ),
            privilege=PrivilegeCapability(False, uid),
            credentials=tuple(credentials),
            filesystem_semantics="lexical_prefix",
            runtime_filesystem_guarantees=True,
        ),
        rest_requests=tuple(requests),
    )


class HostAuthority:
    """Per-installation native authority; retained handles are never JSON-restored."""

    def __init__(
        self,
        profile: ToolHostProfile,
        *,
        operator: object,
        clock=time.time,
        policy_epoch: int = 0,
        initialize_scope: bool = False,
        takeover: bool = False,
    ):
        if type(profile) is not ToolHostProfile or type(operator) is not object:
            raise ValueError("original operator profile and capability required")
        if (
            type(policy_epoch) is not int
            or not 0 <= policy_epoch < 2**63
            or type(initialize_scope) is not bool
            or type(takeover) is not bool
            or initialize_scope
            and takeover
        ):
            raise ValueError("explicit valid initial scope or protected takeover required")
        profile.require_unchanged()
        check_private_directory(profile.configuration_root)
        check_private_directory(profile.configuration_root / "state")
        self.stack = ExitStack()
        self._close_lock = RLock()
        self._control_lock = RLock()
        self._closing = self._cleanup_complete = False
        try:
            self.profile, self.operator = profile, operator
            self.store = SQLiteCoordinatorStore(
                profile.configuration_root / "state" / "coordinator.sqlite",
                create=False,
                clock=clock,
            )
            clock = self.clock = CoordinatorClock(self.store)
            self.pki = PrivateHostPKI(profile)
            self.test_routes = host_test_routes(profile, operator=operator)
            self.backend = make_backend(
                profile, operator=operator, initialize=False, test_routes=self.test_routes
            )
            self.core = host_core(self.test_routes, required_euid=self.backend.uid)
            self.started_at = clock()
            self.expires_at = self.started_at + min(profile.limits.lifetime_seconds, 600)
            self.incarnation = uuid4().hex
            maximum = _authority(profile, None, self.backend.uid, self.test_routes)
            scope = RepositoryScope("managed/" + profile.profile_id, profile.digest)
            content = SecurityProfile("managed-" + profile.profile_id, "1", scope)
            assurance_path = profile.configuration_root / "assurance.json"
            if not assurance_path.exists():
                raise ValueError("managed host security profile has not been initialized")
            raw = read_scoped_file(
                profile.configuration_root, "assurance.json", maximum=65536, private=True
            )
            if json.loads(raw) != content.as_dict():
                raise ValueError("managed host security profile differs from operator selection")
            selection = ProtectedProfileSelection(
                config_root=profile.configuration_root,
                relative_path="assurance.json",
                protected_runtime_path=str(assurance_path),
                repository=scope,
                expected_profile_digest=content.digest,
                expected_file_digest=hashlib.sha256(raw).hexdigest(),
                expected_version="1",
                operator_identity="managed-host-operator",
                agent_boundary=maximum.capability,
                runtime_source=RuntimeEvidenceSource(
                    "managed-host", profile.digest, "host-" + self.incarnation, profile.digest
                ),
            )
            self.approved = load_approved_profile(
                selection,
                current_repository=scope,
                active_runtime_policy_digest=profile.digest,
            )
            names = ("authority-root", *(actor.agent_id for actor in profile.actors))
            self.identities = {
                name: SessionIdentity("managed-" + name, "session-" + uuid4().hex) for name in names
            }
            self.sources = {
                name: HostEvidenceSource(
                    name,
                    scope,
                    IntegrationSession(identity, AgentGate(self.core)).runtime_session_digest,
                    policy_epoch,
                    profile.digest,
                    self.approved.selection_digest,
                )
                for name, identity in self.identities.items()
            }
            self.issuer = DelegationIssuer(
                self.sources["authority-root"], self.approved, maximum, maximum, clock=clock
            )
            root = self.issuer.authorize_root(
                maximum, grant_id="root-" + self.incarnation, expires_at=self.expires_at
            )
            self.registry = InMemoryAgentRegistry(
                profile.tenant_id, profile.swarm_id, clock=clock, heartbeat_timeout=3600
            )
            if policy_epoch:
                self.registry.advance_policy_epoch(policy_epoch)
            self.auth = WorkloadAuthenticator(
                self.registry,
                self.pki.server_context,
                operator=operator,
                clock=clock,
                channel_lifetime=60,
            )
            self.bootstrap = SwarmApprovalBootstrap(
                self.registry,
                tuple(self.sources.values()),
                self.approved,
                maximum,
                operator=operator,
                clock=clock,
            )
            self.assurance = AssuranceGate(
                AgentGate(self.core, approval_source=self.bootstrap.authority), self.approved
            )
            self.directory = SwarmOperatorDirectory(
                self.auth,
                operator=operator,
                roles=("observe", "approve", "deny", "recover", "policy_admin"),
            )
            self.directory.enroll(
                principal_id="managed-host-operator",
                certificate_digest=self.pki.fingerprint("operator"),
                roles=("observe", "approve", "deny", "recover", "policy_admin"),
                task_ids=(profile.task_id,),
                operator=operator,
            )
            self.service = SwarmDelegationService(
                self.issuer, self.assurance, self.auth, operator=operator
            )
            self.contexts, self.adapters, self.registry_channels, self.enrollments = {}, {}, {}, {}
            for name in names:
                adapter = object()
                channel = self.registry.bind_channel(adapter, runtime_id="managed-" + name)
                context = self.registry.enroll(
                    channel,
                    adapter,
                    agent_id=name,
                    session_id=self.identities[name].session_id,
                    task_id=profile.task_id,
                    coverage=CoverageManifest("intercept"),
                )
                self.enrollments[name] = self.auth.enroll_workload(
                    host_id="managed-host",
                    certificate_digest=self.pki.fingerprint(name),
                    context=context,
                    source=self.sources[name],
                    channel=channel,
                    adapter=adapter,
                    operator=operator,
                    runtime_identity=self.identities[name],
                )
                self.contexts[name], self.adapters[name], self.registry_channels[name] = (
                    context,
                    adapter,
                    channel,
                )
            self.root_socket, _ = self.stack.enter_context(self.pki.pair("authority-root"))
            root_channel = self.auth.authenticate(self.root_socket)
            root_ref = self.service.publish_root(
                self.enrollments["authority-root"], root, operator=operator
            )
            self.root_grant = root_ref.grant_id
            self.grants = {}
            for actor in profile.actors:
                grant = self.service.issue_child(
                    root_channel,
                    root_ref.grant_id,
                    self.enrollments[actor.agent_id],
                    _authority(profile, actor, self.backend.uid, self.test_routes),
                    request_id="enroll-" + actor.agent_id,
                    lifetime=max(1, min(600, int(self.expires_at - clock()) - 1)),
                )
                self.grants[actor.agent_id] = grant.grant_id
                self.contexts[actor.agent_id] = self.service.bind_delegation_context(
                    grant.grant_id, operator=operator
                )
            self.auth.enroll_broker(
                host_id="managed-host",
                certificate_digest=self.pki.fingerprint("broker"),
                operator=operator,
            )
            self.broker_socket, _ = self.stack.enter_context(self.pki.pair("broker"))
            broker_channel = self.auth.authenticate(self.broker_socket)
            self.ledger = BudgetLedger(
                self.registry,
                _budget_policy(profile, policy_epoch),
                store=SQLiteBudgetStore(
                    profile.configuration_root / "state" / "budget.sqlite", create=False
                ),
                clock=clock,
                operator=operator,
            )
            self.gate = SwarmGate(self.registry, self.assurance)
            self.broker = SwarmExecutionBroker(
                self.service,
                broker_channel,
                self.gate,
                self.ledger,
                self.backend,
                operator=operator,
            )
            self.coordinator = SwarmCoordinator(
                self.store,
                operator=operator,
                clock=clock,
                lease_lifetime=30,
                owner_lifetime=60,
            )
            self.control = self.coordinator.control_source(operator=operator)
            self.scope = self.coordinator.register_scope(
                self.service,
                self.ledger.policy,
                control=self.control,
                broker_channels=(broker_channel,),
                brokers=(("managed-host", self.broker),),
            )
            if initialize_scope:
                self.coordinator.initialize_scope(self.scope, control=self.control)
            self.owner = self.coordinator.start(self.scope, control=self.control, takeover=takeover)
            root_lease = self.coordinator.admit(self.scope, root_channel)
            if root_lease.reference is None:
                raise ValueError("managed host root lease is unavailable")
            self.coordinator.bind_grant(
                self.scope, root_channel, root_lease.reference, self.root_grant
            )
            proof = self.broker.activation_proof(self.owner["policy_digest"], operator=operator)
            self.governance = SwarmApprovalService(
                self.coordinator,
                self.scope,
                self.directory,
                self.bootstrap,
                SwarmApprovalPolicy(
                    "managed-write", max_requests=min(1024, profile.limits.requests)
                ),
                control=self.control,
                operator=operator,
                factory_proofs={"managed-host": proof},
            )
            self.governance.initialize(operator=operator, recover=takeover)
            self.factory_proof = proof
        except BaseException as construction_error:
            try:
                self.close()
            except BaseException:
                raise _HostCleanupIncomplete(self) from construction_error
            raise

    @contextmanager
    def control_phase(self, *, blocking=True, allow_closing=False):
        """Serialize original synchronous auth/clock/metadata and job phases.

        Waiting never renews a deadline. Admission fencing and original stop
        requests do not acquire this guard, so cleanup remains preemptive.
        """
        acquired = self._control_lock.acquire(blocking=blocking)
        if not acquired:
            yield False
            return
        try:
            if self._closing and not allow_closing:
                raise ValueError("managed authority is draining")
            yield True
        finally:
            self._control_lock.release()

    @_authority_control
    def refresh_broker_channel(self) -> None:
        # Reauthenticate actual live TLS, without extending a task/grant lifetime.
        self.coordinator.refresh_broker_channel(
            self.scope,
            self.auth.authenticate(self.broker_socket),
            control=self.control,
            operator=self.operator,
            expected_owner_fence=self.owner["owner_fence"],
        )

    @_authority_control
    def maintenance(self) -> dict:
        """Renew online ownership, never a caller's approval or delegated lifetime."""
        if self._closing:
            raise ValueError("managed authority is draining")
        self.profile.require_unchanged()
        if self.clock() >= self.expires_at:
            raise ValueError("managed task lifetime ended; fresh operator startup required")
        for name, context in self.contexts.items():
            self.registry.heartbeat(context, self.registry_channels[name], self.adapters[name])
        self.owner = self.coordinator.heartbeat(self.scope, control=self.control)
        self.refresh_broker_channel()
        channel = self.auth.authenticate(self.root_socket)
        lease = self.coordinator.admit(self.scope, channel)
        if lease.reference is None:
            raise ValueError("managed parent lease is unavailable")
        self.coordinator.bind_grant(self.scope, channel, lease.reference, self.root_grant)
        return self.owner

    @_authority_control
    def refresh_factory(self) -> None:
        policy_digest = self.owner["policy_digest"]
        current = None
        if self.broker.verify_activation(self.factory_proof, policy_digest=policy_digest):
            current = self.broker.describe_activation(self.factory_proof)
        if current is None or current["expires_at"] - self.clock() < 5:
            proof = self.broker.activation_proof(policy_digest, operator=self.operator)
            self.governance.refresh_factory_proof(
                "managed-host",
                proof,
                operator=self.operator,
                expected_owner_fence=self.owner["owner_fence"],
            )
            self.factory_proof = proof

    @_authority_control
    def dispatch(
        self, actor: str, channel, action: ActionEnvelope, *, request_id: str
    ) -> HostDispatch:
        """Use original coordinator/native/broker paths; no callback substitution."""
        self.maintenance()
        self.refresh_factory()
        self.profile.actor(actor)
        enrollment = self.auth.require(channel, role="workload")
        if enrollment.enrollment_id != self.enrollments[actor]:
            raise ValueError("managed transport actor changed")
        lease = self.coordinator.admit(self.scope, channel)
        if lease.reference is None:
            return HostDispatch("denied", ("host.lease_unavailable",), False, False)
        if action.kind == "tool" and action.parameters.get("tool") == "run_tests":
            arguments = action.parameters.get("arguments")
            if (
                not isinstance(arguments, Mapping)
                or set(arguments) != {"test_id"}
                or type(arguments["test_id"]) is not str
                or arguments["test_id"] not in self.profile.actor(actor).test_ids
            ):
                return HostDispatch("denied", ("host.test_route_not_authorized",), False, False)
            action = self.backend.prepare_action(action, operator=self.operator)
        reference = self.grants[actor]
        self.coordinator.bind_grant(self.scope, channel, lease.reference, reference)
        # Intrinsic WARN/ASK actions enter the original human queue before the
        # ordinary coordinator guard, which intentionally rejects preparation
        # without a human receipt. request() independently captures/rechecks all
        # current scope, history, requirements, factory and credential bindings.
        baseline = self.assurance.baseline_gate.evaluate_action(action)
        if baseline.denied:
            return HostDispatch("denied", ("host.core_review_denied",), False, False)
        if baseline.requires_approval:
            try:
                approval = self.governance.request(
                    channel, lease.reference, reference, action, idempotency_key=request_id
                )
            except (ValueError, OSError, RuntimeError):
                return HostDispatch(
                    "denied",
                    ("host.independent_requirement_or_approval_unavailable",),
                    False,
                    False,
                )
            return HostDispatch(
                "requires_approval",
                ("host.exact_operator_approval_required",),
                False,
                False,
                approval=approval,
                action=action,
                lease_id=lease.reference,
            )
        evaluation = self.coordinator.evaluate(
            self.scope,
            channel,
            lease.reference,
            reference,
            action,
            idempotency_key=request_id,
        )
        if evaluation.status != "execute":
            return HostDispatch("denied", ("host.current_admission_refused",), False, False)
        if evaluation.reference is None:
            return HostDispatch("denied", ("host.evaluation_unavailable",), False, False)
        reserved = self.coordinator.reserve(
            self.scope,
            channel,
            lease.reference,
            evaluation.reference,
            action,
            idempotency_key=request_id,
        )
        if reserved.status != "reserved" or reserved.reference is None:
            return HostDispatch("denied", ("host.reservation_refused",), False, False)
        broker_channel = self.auth.authenticate(self.broker_socket)
        dispatched = self.coordinator.guarded_dispatch(
            self.scope, broker_channel, reserved.reference
        )
        if dispatched.status != "host_completed":
            return HostDispatch("unknown", ("host.original_dispatch_uncertain",), None, False)
        try:
            native = self.coordinator.broker_result(self.scope, broker_channel, reserved.reference)
        except (ValueError, OSError, RuntimeError):
            return HostDispatch("unknown", ("host.original_outcome_unavailable",), None, False)
        return HostDispatch(
            "completed",
            (),
            native.forwarded,
            native.physical_enforcement,
            result=native,
            action=action,
        )

    def request_stop(self) -> None:
        """Original local operator path: fence and signal without a DB/phase wait."""
        self._closing = True
        if hasattr(self, "auth"):
            self.auth.fence(operator=self.operator)
        if hasattr(self, "broker"):
            with self.broker._state_lock:
                authorizations = tuple(self.broker._pending)
            for authorization in authorizations:
                try:
                    self.broker.request_stop(authorization)
                except (ValueError, OSError, RuntimeError):
                    pass  # Original close still verifies actual child termination.

    def close(self) -> None:
        with self._close_lock:
            if self._cleanup_complete:
                return
            try:
                self.request_stop()
                with self.control_phase(blocking=False, allow_closing=True) as acquired:
                    if not acquired:
                        raise _HostCleanupIncomplete(self)
                    if hasattr(self, "backend"):
                        # Control/storage/TLS custody remains intact until an
                        # in-flight phase leaves and original children stop.
                        self.backend.close()
                    self.stack.close()
            except BaseException as error:
                raise _HostCleanupIncomplete(self) from error
            self._cleanup_complete = True


def initialize_host_authority_files(profile: ToolHostProfile, *, operator: object) -> None:
    """Only for the newly created installation, before any caller is attached."""
    profile.require_unchanged()
    content = SecurityProfile(
        "managed-" + profile.profile_id,
        "1",
        RepositoryScope("managed/" + profile.profile_id, profile.digest),
    )
    _new_file(
        profile.configuration_root / "assurance.json",
        json.dumps(content.as_dict(), sort_keys=True).encode("utf-8"),
    )
    _new_file(profile.configuration_root / "state" / "host.lock", b"")
    backend = make_backend(profile, operator=operator, initialize=True)
    backend.close()
    store = SQLiteCoordinatorStore(
        profile.configuration_root / "state" / "coordinator.sqlite", create=True
    )
    clock = CoordinatorClock(store)
    registry = InMemoryAgentRegistry(profile.tenant_id, profile.swarm_id, clock=clock)
    # Store creation alone creates a schema. Only its original one-time handle
    # may initialize ledger meta/history; startup must subsequently attach with
    # create=False, which correctly rejects absent or incomplete accounting.
    BudgetLedger(
        registry,
        _budget_policy(profile, 0),
        store=SQLiteBudgetStore(
            profile.configuration_root / "state" / "budget.sqlite", create=True
        ),
        clock=clock,
        operator=operator,
    )


__all__ = [
    "HostAuthority",
    "HostDispatch",
    "RUNTIME",
    "host_core",
    "initialize_host_authority_files",
]
