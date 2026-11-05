"""Explicit, local host enrollment. Importing this package starts no services."""

from .identity import HostChannel
from .models import CoverageEntry, CoverageManifest, SwarmContext, SwarmIdentity
from .registry import AgentRegistry, InMemoryAgentRegistry
from .events import EventRef, SwarmEvent
from .ingest import ActionEventState, HostEventSource, IngestReceipt, SwarmEventIngestor
from .journal import EventJournal, JournalRecord
from .gate import SwarmDecision, SwarmGate
from .policy import SwarmPolicy, SwarmRule
from .facts import SwarmAssessment, SwarmAssessmentSource
from .gateway import (
    ForwardTicket,
    GatewayAgent,
    GatewayAuthorization,
    GatewayOutcome,
    GatewayResult,
    SwarmToolGateway,
)
from .mcp_gateway import SwarmMCPAdapter
from .hooks_gateway import SwarmHookAdapter
from .causal_graph import SwarmCausalGraph, SwarmGraphView
from .lineage import SwarmDelegationLink
from .labels import Sensitivity
from .source_flow import EgressSink, LineageHandle, LineageUse, SourceFlowResult, SwarmSourceFlow
from .attach import (
    AttachedSession,
    HostSessionEndpoint,
    MediatedSessionRouter,
    RunningSessionIdentity,
    SwarmAttachManager,
)
from .coverage import AttachCoverage
from .messages import (
    MessageChannel,
    MessageOutcome,
    MessagePeer,
    PrivateMessage,
    SwarmMessageEnvelope,
    SwarmMessageGateway,
)
from .message_adapters import (
    CallbackMessageInbox,
    QueueMessageInbox,
    RPCMessageInbox,
    SwarmMessageAdapter,
)
from .artifact_store import ArtifactBlobStore, FilesystemArtifactStore, MemoryArtifactStore
from .memory import (
    ArtifactAddress,
    ArtifactGrant,
    PrivateArtifactRead,
    SwarmArtifact,
    SwarmArtifactGateway,
)
from .artifact_adapters import (
    ArtifactAdapter,
    GuardedVectorPointAPI,
    SharedMemoryAdapter,
    VectorPointArtifactAdapter,
    WorkspaceArtifactAdapter,
)

from .temporal import (
    CompiledSwarmTemporalPolicy,
    SwarmTemporalEngine,
    SwarmTemporalEvaluation,
    SwarmTemporalFinding,
    SwarmTemporalPolicySet,
    SwarmTemporalPredicate,
    SwarmTemporalRule,
    default_swarm_temporal_policy,
    load_swarm_temporal_policy,
)

__all__ = [
    "ArtifactBlobStore",
    "FilesystemArtifactStore",
    "MemoryArtifactStore",
    "ArtifactAddress",
    "ArtifactGrant",
    "PrivateArtifactRead",
    "SwarmArtifact",
    "SwarmArtifactGateway",
    "ArtifactAdapter",
    "GuardedVectorPointAPI",
    "SharedMemoryAdapter",
    "VectorPointArtifactAdapter",
    "WorkspaceArtifactAdapter",
    "CompiledSwarmTemporalPolicy",
    "SwarmTemporalEngine",
    "SwarmTemporalEvaluation",
    "SwarmTemporalFinding",
    "SwarmTemporalPolicySet",
    "SwarmTemporalPredicate",
    "SwarmTemporalRule",
    "default_swarm_temporal_policy",
    "load_swarm_temporal_policy",
    "MessageChannel",
    "MessageOutcome",
    "MessagePeer",
    "PrivateMessage",
    "SwarmMessageEnvelope",
    "SwarmMessageGateway",
    "CallbackMessageInbox",
    "QueueMessageInbox",
    "RPCMessageInbox",
    "SwarmMessageAdapter",
    "Sensitivity",
    "EgressSink",
    "LineageHandle",
    "LineageUse",
    "SourceFlowResult",
    "SwarmSourceFlow",
    "AttachedSession",
    "HostSessionEndpoint",
    "MediatedSessionRouter",
    "RunningSessionIdentity",
    "SwarmAttachManager",
    "AttachCoverage",
    "SwarmCausalGraph",
    "SwarmGraphView",
    "SwarmDelegationLink",
    "ForwardTicket",
    "GatewayAgent",
    "GatewayAuthorization",
    "GatewayOutcome",
    "GatewayResult",
    "SwarmToolGateway",
    "SwarmMCPAdapter",
    "SwarmHookAdapter",
    "SwarmAssessment",
    "SwarmAssessmentSource",
    "SwarmDecision",
    "SwarmGate",
    "SwarmPolicy",
    "SwarmRule",
    "ActionEventState",
    "EventJournal",
    "EventRef",
    "HostEventSource",
    "IngestReceipt",
    "JournalRecord",
    "SwarmEvent",
    "SwarmEventIngestor",
    "AgentRegistry",
    "CoverageEntry",
    "CoverageManifest",
    "HostChannel",
    "InMemoryAgentRegistry",
    "SwarmContext",
    "SwarmIdentity",
]
