"""Explicit, local host enrollment. Importing this package starts no services."""

from .identity import HostChannel
from .models import CoverageEntry, CoverageManifest, SwarmContext, SwarmIdentity
from .registry import AgentRegistry, InMemoryAgentRegistry
from .events import EventRef, SwarmEvent
from .ingest import ActionEventState, HostEventSource, IngestReceipt, SwarmEventIngestor
from .journal import EventJournal, JournalRecord

__all__ = [
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
