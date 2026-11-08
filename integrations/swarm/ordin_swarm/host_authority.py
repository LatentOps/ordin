"""Original host authority assembled from existing Ordin safety components."""

from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass, field
import hashlib
import json
import os
import tempfile
from pathlib import Path
import time
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
from ordin.session import IntegrationSession, SessionIdentity
from ordin.swarm import CoverageManifest, InMemoryAgentRegistry, SwarmGate
from ordin.swarm.budget_store import SQLiteBudgetStore
from ordin.swarm.budgets import BudgetLedger, BudgetLimit, BudgetPolicy
from ordin.swarm.broker import SwarmExecutionBroker
from ordin.swarm.approval import SwarmApprovalPolicy
from ordin.swarm.approval_service import SwarmApprovalBootstrap, SwarmApprovalService
from ordin.swarm.coordinator import SwarmCoordinator
from ordin.swarm.coordinator_store import CoordinatorClock, SQLiteCoordinatorStore
from ordin.swarm.delegation import SwarmDelegationService
from ordin.swarm.operator_auth import SwarmOperatorDirectory
from ordin.swarm.workload_auth import WorkloadAuthenticator

from .host_pki import PrivateHostPKI, _new_file
from .host_profiles import HOST_TOOL_DATA_BYTES, ToolHostProfile, check_private_directory


RUNTIME = "ordin-owned"


@dataclass(frozen=True, slots=True)
class HostDispatch:
    status: str
    reason_codes: tuple[str, ...]
    forwarded: bool | None
    physical_enforcement: bool
    result: object = field(default=None, repr=False)
    approval: object = field(default=None, repr=False)
    action: ActionEnvelope | None = field(default=None, repr=False)
    lease_id: str | None = field(default=None, repr=False)


def host_core() -> Ordin:
    return Ordin(
        rest_semantics=RestSemantics(),
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


def make_backend(profile: ToolHostProfile, *, operator: object, initialize: bool):
    # This import remains optional: inspecting a core action starts no host.
    from ordin.swarm.owned_tools import LinuxOwnedToolsBackend, OwnedHTTPRoute

    routes = []
    for selected in profile.http_routes:
        parsed = urlsplit(selected.url)
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
    )


def _authority(profile, actor, uid) -> DelegationAuthority:
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
    filesystem = tuple(
        FilesystemCapability(access, str(profile.workspace / name), "exact")
        for access, names in (("read", reads), ("write", writes))
        for name in sorted(names)
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
                for tool, enabled in (("read_file", bool(reads)), ("write_artifact", bool(writes)))
                if enabled
            ),
            process=ProcessCapability(False, (), False),
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
        try:
            self.profile, self.operator = profile, operator
            self.store = SQLiteCoordinatorStore(
                profile.configuration_root / "state" / "coordinator.sqlite",
                create=False,
                clock=clock,
            )
            clock = self.clock = CoordinatorClock(self.store)
            self.pki = PrivateHostPKI(profile)
            self.backend = make_backend(profile, operator=operator, initialize=False)
            self.stack.callback(self.backend.close)
            self.core = host_core()
            self.started_at = clock()
            self.expires_at = self.started_at + min(profile.limits.lifetime_seconds, 600)
            self.incarnation = uuid4().hex
            maximum = _authority(profile, None, self.backend.uid)
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
                    _authority(profile, actor, self.backend.uid),
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
                BudgetPolicy(
                    policy_epoch,
                    (
                        BudgetLimit("swarm", "requests", profile.limits.requests),
                        BudgetLimit("swarm", "concurrency", profile.limits.concurrency),
                        BudgetLimit("swarm", "output_bytes", profile.limits.output_bytes),
                    ),
                ),
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
        except BaseException:
            self.stack.close()
            raise

    def refresh_broker_channel(self) -> None:
        # Reauthenticate actual live TLS, without extending a task/grant lifetime.
        self.coordinator.refresh_broker_channel(
            self.scope,
            self.auth.authenticate(self.broker_socket),
            control=self.control,
            operator=self.operator,
            expected_owner_fence=self.owner["owner_fence"],
        )

    def maintenance(self) -> dict:
        """Renew online ownership, never a caller's approval or delegated lifetime."""
        self.profile.require_unchanged()
        if self.clock() >= self.expires_at:
            raise ValueError("managed task lifetime ended; fresh operator startup required")
        self.owner = self.coordinator.heartbeat(self.scope, control=self.control)
        self.refresh_broker_channel()
        channel = self.auth.authenticate(self.root_socket)
        lease = self.coordinator.admit(self.scope, channel)
        if lease.reference is None:
            raise ValueError("managed parent lease is unavailable")
        self.coordinator.bind_grant(self.scope, channel, lease.reference, self.root_grant)
        return self.owner

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
        reference = self.grants[actor]
        self.coordinator.bind_grant(self.scope, channel, lease.reference, reference)
        evaluation = self.coordinator.evaluate(
            self.scope,
            channel,
            lease.reference,
            reference,
            action,
            idempotency_key=request_id,
        )
        if evaluation.status != "execute":
            baseline = self.assurance.baseline_gate.evaluate_action(action)
            if baseline.requires_approval:
                try:
                    approval = self.governance.request(
                        channel,
                        lease.reference,
                        reference,
                        action,
                        idempotency_key=request_id,
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
            return HostDispatch("denied", ("host.current_admission_refused",), False, False)
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
        # These are original protected objects, not imported record JSON. The SDK
        # uses the same custody boundary to recover the broker's verified result.
        original = self.coordinator._prepared.get(reserved.reference)
        if original is None or original.broker is not self.broker:
            raise ValueError("managed original broker reservation unavailable")
        dispatched = self.coordinator.guarded_dispatch(
            self.scope, self.auth.authenticate(self.broker_socket), reserved.reference
        )
        pending = self.broker._pending.get(original.authorization)
        native = pending.result if pending is not None else None
        if native is None or not self.broker.verify_result(native, original.authorization):
            return HostDispatch("unknown", ("host.original_outcome_unavailable",), None, False)
        if dispatched.status != "host_completed" or native.status != "completed":
            return HostDispatch(
                "denied" if native.status == "denied" else "unknown",
                (native.reason_code,),
                native.forwarded,
                native.physical_enforcement,
                result=native,
                action=action,
            )
        return HostDispatch(
            "completed",
            (),
            native.forwarded,
            native.physical_enforcement,
            result=native,
            action=action,
        )

    def close(self) -> None:
        self.auth.fence(operator=self.operator)
        self.stack.close()


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
    SQLiteBudgetStore(profile.configuration_root / "state" / "budget.sqlite", create=True)
    SQLiteCoordinatorStore(profile.configuration_root / "state" / "coordinator.sqlite", create=True)


__all__ = [
    "HostAuthority",
    "HostDispatch",
    "RUNTIME",
    "host_core",
    "initialize_host_authority_files",
]
