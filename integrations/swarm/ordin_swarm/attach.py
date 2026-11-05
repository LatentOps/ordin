"""Maintained host attach API; callbacks must be protected integration code."""

from ordin.swarm.attach import (
    AttachedSession,
    HostSessionEndpoint,
    MediatedSessionRouter,
    RunningSessionIdentity,
    SwarmAttachManager,
)

__all__ = [
    "AttachedSession",
    "HostSessionEndpoint",
    "MediatedSessionRouter",
    "RunningSessionIdentity",
    "SwarmAttachManager",
]
