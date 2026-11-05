"""Explicit, local host enrollment. Importing this package starts no services."""

from .identity import HostChannel
from .models import CoverageEntry, CoverageManifest, SwarmContext, SwarmIdentity
from .registry import AgentRegistry, InMemoryAgentRegistry

__all__ = [
    "AgentRegistry",
    "CoverageEntry",
    "CoverageManifest",
    "HostChannel",
    "InMemoryAgentRegistry",
    "SwarmContext",
    "SwarmIdentity",
]
