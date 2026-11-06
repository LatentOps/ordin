"""Owned synthetic actors and real stateful primitives for offline evaluations."""

from dataclasses import dataclass
import hashlib

from ordin import ActionEnvelope, AgentGate, Ordin
from ordin.assurance import HostEvidenceSource, RepositoryScope, register_instruction_origin

from .registry import InMemoryAgentRegistry
from .models import CoverageManifest, SwarmContext
from .identity import HostChannel
from .events import SwarmEvent
from .ingest import SwarmEventIngestor, HostEventSource
from .causal_graph import SwarmCausalGraph
from .source_flow import EgressSink, SwarmSourceFlow, LineageUse
from .labels import Sensitivity
from .messages import SwarmMessageGateway, DESTINATION_PATH, PrivateMessage
from .memory import SwarmArtifactGateway, ArtifactAddress
from .artifact_store import MemoryArtifactStore
from .gate import SwarmGate
from .gateway import SwarmToolGateway
from .budgets import BudgetLedger, BudgetPolicy, BudgetLimit

CANARY = "SYNTHETIC_SWARM_CANARY_V1_NO_REAL_SECRET"
REPOSITORY = RepositoryScope("ordin/swarm-corpus", "synthetic-v1")


@dataclass(frozen=True)
class Actor:
    context: SwarmContext
    channel: HostChannel
    adapter: object
    source: HostEventSource
    host: HostEvidenceSource


class World:
    """Nothing outside this owned synthetic tenant is discovered or enrolled."""

    def __init__(self, agents=3, *, tenant="corpus-tenant", maximum=100, store=None):
        if type(agents) is not int or not 2 <= agents <= 10:
            raise ValueError("corpus schedules support two to ten actors")
        self.operator = object()
        self.now = [100.0]
        self.registry = InMemoryAgentRegistry(
            tenant, "corpus-swarm", clock=lambda: self.now[0], heartbeat_timeout=3600
        )
        self.events = SwarmEventIngestor(self.registry)
        self.actors = []
        for index in range(agents):
            adapter = object()
            channel = self.registry.bind_channel(adapter, runtime_id="corpus-runtime-" + str(index))
            context = self.registry.enroll(
                channel,
                adapter,
                agent_id="actor-" + str(index),
                session_id="session-" + str(index),
                task_id="corpus-task",
                coverage=CoverageManifest("intercept"),
            )
            source = self.events.bind_source(
                context, channel, adapter, source_id="collector-" + str(index)
            )
            host = HostEvidenceSource(
                context.identity.agent_id,
                REPOSITORY,
                hashlib.sha256(str(index).encode()).hexdigest(),
                0,
                "c" * 64,
                "d" * 64,
            )
            self.actors.append(Actor(context, channel, adapter, source, host))
        first = self.actors[0]
        self.graph = SwarmCausalGraph(self.events, first.source, first.context)
        sinks = [
            EgressSink(
                "external",
                "network",
                "network",
                "jsonrpc.request",
                ("parameters", "url"),
                "https://fixture.invalid/rpc",
                ("public",),
            )
        ]
        sinks.extend(
            EgressSink(
                "internal-" + str(i),
                "message",
                "tool",
                "call",
                DESTINATION_PATH,
                "actor-" + str(i),
                ("public", "secret", "private_code", "pii"),
            )
            for i in range(agents)
        )
        self.flow = SwarmSourceFlow(
            self.graph, operator=self.operator, sinks=tuple(sinks), max_records=16384
        )
        for actor in self.actors:
            self.flow.bind_actor(actor.source, actor.context, actor.host)
        self.artifacts = SwarmArtifactGateway(
            self.flow,
            backend=MemoryArtifactStore(),
            operator=self.operator,
            workspaces=("fixture",),
            clock=lambda: self.now[0],
        )
        self.messages = SwarmMessageGateway(self.flow, clock=lambda: self.now[0])
        self.inboxes: list[list[PrivateMessage]] = [[] for _ in self.actors]
        self.peers = [
            self.messages.register(
                actor.context, actor.source, actor.channel, actor.adapter, self.inboxes[i].append
            )
            for i, actor in enumerate(self.actors)
        ]
        self.ledger = BudgetLedger(
            self.registry,
            BudgetPolicy(0, (BudgetLimit("swarm", "requests", maximum),)),
            store=store,
            clock=lambda: self.now[0],
            operator=self.operator,
        )
        self.gate = SwarmGate(self.registry, AgentGate(Ordin()), events=self.events)
        self.gateway = SwarmToolGateway(events=self.events, clock=lambda: self.now[0])
        self.handles = [
            self.gateway.bind_agent(
                actor.context,
                self.gate,
                actor.channel,
                actor.adapter,
                routes=frozenset({"sdk", "shell", "file", "http"}),
            )
            for actor in self.actors
        ]
        self.effects: list[str | None] = []

    def emit(self, index, kind, *, value=CANARY, parents=(), name=None):
        actor = self.actors[index]
        source = self.events._source(actor.source)
        identity = name or "event-" + str(len(self.events.snapshot()) + 1)
        event = SwarmEvent(
            identity,
            kind,
            actor.context.registry_id,
            actor.context.identity,
            actor.source.source_id,
            source.contiguous + 1,
            self.now[0],
            evidence_class="host_authenticated",
            resource_digests=(hashlib.sha256(value.encode()).hexdigest(),),
            parent_event_ids=parents,
        )
        self.events.ingest(actor.source, event)
        return identity

    def collect(self, index=0, *, value=CANARY, labels=("secret",)):
        actor = self.actors[index]
        event = self.emit(index, "artifact_read", value=value)
        origin = register_instruction_origin(
            actor.host,
            origin_id=event,
            kind="repository_file",
            classification="sensitive" if labels != ("public",) else "public",
            content=value,
        )
        return self.flow.register(
            actor.source, event_id=event, origin=origin, sensitivity=Sensitivity(labels)
        )

    def share(self, sender, recipient, handle, *, value=CANARY):
        channel = self.messages.grant(
            self.peers[sender], self.peers[recipient], sink_id="internal-" + str(recipient)
        )
        outcome = self.messages.send(self.peers[sender], channel, value, inputs=(handle,))
        if outcome.status != "delivered" or outcome.recipient_lineage is None:
            raise ValueError("corpus handoff was not authenticated")
        return outcome.recipient_lineage

    def address(self, key="artifact"):
        identity = self.actors[0].context.identity
        return ArtifactAddress(identity.tenant_id, identity.swarm_id, "fixture", "artifacts", key)

    @staticmethod
    def upload(value=CANARY):
        return ActionEnvelope(
            "network",
            "jsonrpc.request",
            {
                "url": "https://fixture.invalid/rpc",
                "body": {"jsonrpc": "2.0", "id": 1, "method": "send", "params": {"value": value}},
            },
            action_id="corpus-upload",
        )

    def assess_upload(self, index, handle, *, value=CANARY):
        return self.flow.assess(
            self.actors[index].source,
            self.upload(value),
            sink_id="external",
            uses=(LineageUse(handle, ("parameters", "body", "params", "value")),),
            complete=True,
        )

    def local_effect(self, action):
        # This does not execute a shell or a network request. The callback is
        # an explicit owned fixture effect used only to measure interception.
        self.effects.append(action.action_id)
        return "owned-fixture-completed"
