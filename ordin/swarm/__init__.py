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

__all__ = [
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
