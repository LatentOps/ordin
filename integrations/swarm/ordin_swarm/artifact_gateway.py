"""Maintained guarded artifact/workspace/shared-memory integration."""

from ordin.swarm.artifact_store import (
    ArtifactBlobStore,
    FilesystemArtifactStore,
    MemoryArtifactStore,
)
from ordin.swarm.memory import (
    ArtifactAddress,
    ArtifactGrant,
    PrivateArtifactRead,
    SwarmArtifact,
    SwarmArtifactGateway,
)
from ordin.swarm.artifact_adapters import (
    ArtifactAdapter,
    GuardedVectorPointAPI,
    SharedMemoryAdapter,
    VectorPointArtifactAdapter,
    WorkspaceArtifactAdapter,
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
]
