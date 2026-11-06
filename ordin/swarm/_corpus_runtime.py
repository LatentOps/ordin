"""Original mTLS authority and owned backend used only by explicit local evaluation."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
import hashlib
from pathlib import Path
import socket
import ssl
import sys
import tempfile
from typing import Any

from ordin import (
    AgentGate,
    Ordin,
    ToolCallAdapter,
    ToolResourceBinding,
    ToolSemanticRule,
    ToolSemanticsRegistry,
)
from ordin.assurance import AssuranceGate, DelegationAuthority
from ordin.runtime_boundary import RuntimeCapabilityBoundary
from ordin.runtime_contract import FilesystemCapability, ToolCapability
from ordin.session import IntegrationSession, SessionIdentity

from ._corpus_delegation import Delegations
from .budgets import BudgetLedger, BudgetPolicy, BudgetLimit
from .coordinator_store import CoordinatorClock, SQLiteCoordinatorStore
from .coordinator import SwarmCoordinator
from .delegation import SwarmDelegationService
from .workload_auth import WorkloadAuthenticator
from .models import CoverageManifest
from .registry import InMemoryAgentRegistry
from .gate import SwarmGate
from .broker import SwarmExecutionBroker
from .linux_backend import LinuxFileReadBackend

CERTS = Path(__file__).resolve().parents[1] / "resources/swarm/tls"


def _fingerprint(name):
    return hashlib.sha256(
        ssl.PEM_cert_to_DER_cert((CERTS / (name + ".pem")).read_text())
    ).hexdigest()


@contextmanager
def _tls(context, name):
    left, right = socket.socketpair()
    with ExitStack() as stack:
        stack.callback(left.close)
        stack.callback(right.close)
        left.settimeout(10)
        right.settimeout(10)
        client_context = ssl.create_default_context(
            ssl.Purpose.SERVER_AUTH, cafile=str(CERTS / "ca.pem")
        )
        client_context.minimum_version = ssl.TLSVersion.TLSv1_2
        client_context.load_cert_chain(
            str(CERTS / (name + ".pem")), str(CERTS / (name + "-key.pem"))
        )
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(context.wrap_socket, left, server_side=True)
            client = client_context.wrap_socket(right, server_hostname="localhost")
            stack.callback(client.close)
            server = pending.result(timeout=10)
            stack.callback(server.close)
        yield server, client


class OwnedRuntime:
    def __init__(self, workspace: Path, stack: ExitStack, *, kernel=True):
        self.operator = object()
        self.store = SQLiteCoordinatorStore(
            workspace / "authority.sqlite", create=True, clock=lambda: 100
        )
        self.clock = CoordinatorClock(self.store)
        target_root = workspace / "files"
        target_root.mkdir(mode=0o700)
        self.target = target_root / "canary.txt"
        self.target.write_bytes(b"SYNTHETIC_OWNED_KERNEL_CANARY\n")
        self.target.chmod(0o600)
        self.path = str(self.target) if sys.platform == "linux" else "/fixture/canary.txt"
        self.core = Ordin(
            tool_semantics=ToolSemanticsRegistry(
                "corpus-owned-read",
                "1",
                (
                    ToolSemanticRule(
                        "read",
                        "tool",
                        "read_file",
                        ("filesystem.read",),
                        runtime="fixture",
                        resources=(ToolResourceBinding("path", "path"),),
                    ),
                ),
            )
        )
        self.names = ("parent", "child", "sibling")
        self.identities = tuple(
            SessionIdentity("corpus-" + name, "session-" + name) for name in self.names
        )
        self.maximum = DelegationAuthority(
            RuntimeCapabilityBoundary(
                "corpus-owned-maximum",
                filesystem=(FilesystemCapability("read", self.path, "exact"),),
                tools=(ToolCapability("fixture", None, "read_file"),),
                filesystem_semantics="lexical_prefix",
                runtime_filesystem_guarantees=True,
            )
        )
        self.native = Delegations(
            workspace / "profile",
            agents=3,
            clock=self.clock,
            maximum=self.maximum,
            principals=self.names,
            session_digests=tuple(
                IntegrationSession(identity, AgentGate(self.core)).runtime_session_digest
                for identity in self.identities
            ),
        )
        self.registry = InMemoryAgentRegistry(
            "corpus-tenant", "corpus-swarm", clock=self.clock, heartbeat_timeout=3600
        )
        self._enroll(workspace, stack, kernel)

    def _enroll(self, workspace, stack, kernel):
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.minimum_version = ssl.TLSVersion.TLSv1_2
        tls.verify_mode = ssl.CERT_REQUIRED
        tls.load_verify_locations(cafile=str(CERTS / "ca.pem"))
        tls.load_cert_chain(str(CERTS / "server.pem"), str(CERTS / "server-key.pem"))
        self.auth = WorkloadAuthenticator(
            self.registry, tls, operator=self.operator, clock=self.clock
        )
        self.service = SwarmDelegationService(
            self.native.issuer,
            AssuranceGate(AgentGate(self.core), self.native.profile),
            self.auth,
            operator=self.operator,
        )
        self.channels: dict[str, Any] = {}
        self.contexts: dict[str, Any] = {}
        self.enrollments = {}
        self.sockets = {}
        for index, name in enumerate(self.names):
            adapter = object()
            channel = self.registry.bind_channel(adapter, runtime_id="corpus-" + name)
            context = self.registry.enroll(
                channel,
                adapter,
                agent_id=name,
                session_id="session-" + name,
                task_id="corpus-task",
                coverage=CoverageManifest("intercept"),
            )
            enrollment = self.auth.enroll_workload(
                host_id="host-a" if index == 0 else "host-b",
                certificate_digest=_fingerprint(name),
                context=context,
                source=self.native.sources[index],
                channel=channel,
                adapter=adapter,
                operator=self.operator,
                runtime_identity=self.identities[index],
            )
            server, client = stack.enter_context(_tls(tls, name))
            self.channels[name] = self.auth.authenticate(server)
            self.contexts[name] = context
            self.enrollments[name] = enrollment
            self.sockets[name] = (server, client)
        self.auth.enroll_broker(
            host_id="host-b", certificate_digest=_fingerprint("broker-b"), operator=self.operator
        )
        server, client = stack.enter_context(_tls(tls, "broker-b"))
        self.broker_channel = self.auth.authenticate(server)
        root = self.service.publish_root(
            self.enrollments["parent"], self.native.root, operator=self.operator
        )
        self.parent_grant = root.grant_id
        child = self.service.issue_child(
            self.channels["parent"],
            root.grant_id,
            self.enrollments["child"],
            self.maximum,
            request_id="corpus-child",
            lifetime=60,
        )
        self.grant = child.grant_id
        self.contexts["child"] = self.service.bind_delegation_context(
            child.grant_id, operator=self.operator
        )
        self.channels["child"] = self.auth.authenticate(self.sockets["child"][0])
        sibling = self.service.issue_child(
            self.channels["parent"],
            root.grant_id,
            self.enrollments["sibling"],
            self.maximum,
            request_id="corpus-sibling",
            lifetime=60,
        )
        self.sibling_grant = sibling.grant_id
        self.contexts["sibling"] = self.service.bind_delegation_context(
            sibling.grant_id, operator=self.operator
        )
        self.channels["sibling"] = self.auth.authenticate(self.sockets["sibling"][0])
        self.ledger = BudgetLedger(
            self.registry,
            BudgetPolicy(
                0,
                (
                    BudgetLimit("swarm", "requests", 32),
                    BudgetLimit("swarm", "concurrency", 1),
                    BudgetLimit("swarm", "output_bytes", 1000000),
                ),
            ),
            clock=self.clock,
            operator=self.operator,
        )
        self.backend: Any = None
        self.broker: Any = None
        if kernel:
            install = Path(
                stack.enter_context(tempfile.TemporaryDirectory(prefix="ordin-corpus-worker-"))
            )
            self.backend = LinuxFileReadBackend(
                self.target.parent, ("canary.txt",), install, operator=self.operator
            )
            stack.callback(self.backend.close)
            self.broker = SwarmExecutionBroker(
                self.service,
                self.broker_channel,
                SwarmGate(self.registry, self.service.assurance),
                self.ledger,
                self.backend,
                operator=self.operator,
            )
        self.action = ToolCallAdapter("fixture").adapt(
            "read_file", {"path": self.path}, action_id="corpus-kernel-read"
        )

    def coordinate(self):
        coordinator = SwarmCoordinator(self.store, clock=self.clock, operator=self.operator)
        control = coordinator.control_source(operator=self.operator)
        scope = coordinator.register_scope(
            self.service,
            BudgetPolicy(0, (BudgetLimit("swarm", "requests", 32),)),
            control=control,
            broker_channels=(self.broker_channel,),
            brokers=(("host-b", self.broker),) if self.broker is not None else (),
        )
        coordinator.initialize_scope(scope, control=control)
        coordinator.start(scope, control=control)
        parent = coordinator.admit(scope, self.channels["parent"])
        child = coordinator.admit(scope, self.channels["child"])
        sibling = coordinator.admit(scope, self.channels["sibling"])
        if parent.reference is None or child.reference is None:
            raise ValueError("original corpus leases unavailable")
        coordinator.bind_grant(scope, self.channels["parent"], parent.reference, self.parent_grant)
        coordinator.bind_grant(scope, self.channels["child"], child.reference, self.grant)
        if sibling.reference is None:
            raise ValueError("original sibling lease unavailable")
        coordinator.bind_grant(
            scope, self.channels["sibling"], sibling.reference, self.sibling_grant
        )
        self.leases = {"parent": parent, "child": child, "sibling": sibling}
        return coordinator, scope, control, child


@contextmanager
def owned_runtime(workspace: Path, *, kernel=True):
    workspace.mkdir(parents=True, exist_ok=False)
    with ExitStack() as stack:
        yield OwnedRuntime(workspace, stack, kernel=kernel)
