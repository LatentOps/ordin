"""Explicit host-managed workspace/KV/vector-point adapters; no raw path interception."""

from typing import Protocol

from ordin.action import ActionEnvelope

from .ingest import HostEventSource
from .memory import (
    ArtifactAddress,
    ArtifactGrant,
    PrivateArtifactRead,
    SwarmArtifact,
    SwarmArtifactGateway,
)
from .models import identifier
from .source_flow import LineageHandle


class GuardedVectorPointAPI(Protocol):
    """A provider must enforce subject/tenant/versions at its actual host boundary.

    No arbitrary nearest-neighbor/query API is inferred from this point-access
    contract. Returned records remain data; provider JSON cannot issue grants.
    """

    def get(
        self, key: str, *, version: int | None = None, grant: ArtifactGrant | None = None
    ) -> PrivateArtifactRead: ...
    def put(
        self,
        key: str,
        value: str,
        *,
        expected_version: int,
        inputs: tuple[LineageHandle, ...],
        grant: ArtifactGrant | None = None,
    ) -> SwarmArtifact: ...


class ArtifactAdapter:
    def __init__(
        self,
        gateway: SwarmArtifactGateway,
        source: HostEventSource,
        *,
        workspace_id: str,
        namespace: str,
        kind: str = "artifact",
    ) -> None:
        if type(gateway) is not SwarmArtifactGateway:
            raise ValueError("protected artifact gateway required")
        identifier(workspace_id, "workspace_id")
        identifier(namespace, "namespace")
        actor = gateway._flow._actor(source)
        probe = ArtifactAddress(
            actor.context.identity.tenant_id,
            actor.context.identity.swarm_id,
            workspace_id,
            namespace,
            "probe",
            kind,
        )
        with gateway._lock:
            gateway._actor(source, probe)
        self._gateway, self._source = gateway, source
        self._scope = probe

    def address(self, key: str) -> ArtifactAddress:
        return ArtifactAddress(
            self._scope.tenant_id,
            self._scope.swarm_id,
            self._scope.workspace_id,
            self._scope.namespace,
            key,
            self._scope.kind,
        )

    def put(
        self,
        key: str,
        value: str,
        *,
        expected_version: int,
        inputs: tuple[LineageHandle, ...],
        grant: ArtifactGrant | None = None,
        ttl: float = 300,
    ) -> SwarmArtifact:
        return self._gateway.write(
            self._source,
            self.address(key),
            value,
            expected_version=expected_version,
            inputs=inputs,
            grant=grant,
            ttl=ttl,
        )

    def get(
        self, key: str, *, version: int | None = None, grant: ArtifactGrant | None = None
    ) -> PrivateArtifactRead:
        return self._gateway.read(self._source, self.address(key), version=version, grant=grant)

    def delete(
        self, key: str, *, expected_version: int, grant: ArtifactGrant | None = None
    ) -> None:
        self._gateway.delete(
            self._source, self.address(key), expected_version=expected_version, grant=grant
        )

    def prepare_export(
        self,
        key: str,
        action: ActionEnvelope,
        *,
        argument_path: tuple[str, ...],
        sink_id: str,
        version: int | None = None,
        grant: ArtifactGrant | None = None,
    ) -> PrivateArtifactRead:
        return self._gateway.prepare_export(
            self._source,
            self.address(key),
            action,
            argument_path=argument_path,
            sink_id=sink_id,
            version=version,
            grant=grant,
        )


class WorkspaceArtifactAdapter(ArtifactAdapter):
    """Managed logical workspace keys, never user-supplied arbitrary filesystem paths."""

    def __init__(
        self, gateway: SwarmArtifactGateway, source: HostEventSource, *, workspace_id: str
    ) -> None:
        super().__init__(
            gateway, source, workspace_id=workspace_id, namespace="workspace", kind="workspace"
        )


class SharedMemoryAdapter(ArtifactAdapter):
    def __init__(
        self, gateway: SwarmArtifactGateway, source: HostEventSource, *, workspace_id: str
    ) -> None:
        super().__init__(gateway, source, workspace_id=workspace_id, namespace="kv", kind="kv")


class VectorPointArtifactAdapter(ArtifactAdapter):
    """Guarded exact record operations; arbitrary vector search remains unsupported."""

    def __init__(
        self, gateway: SwarmArtifactGateway, source: HostEventSource, *, workspace_id: str
    ) -> None:
        super().__init__(
            gateway, source, workspace_id=workspace_id, namespace="vector", kind="vector_entry"
        )

    def search(self, *args, **kwargs):
        raise ValueError("opaque vector queries require an explicitly enforced provider API")
