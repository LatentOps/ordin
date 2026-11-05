"""Versioned protected data resources with exact-agent ACLs and conservative lineage."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from threading import RLock
import time
from typing import Any, Callable
from uuid import uuid4

from ordin.action import ActionEnvelope
from ordin._runtime_json import digest
from ordin.assurance.origins import InstructionOrigin, register_instruction_origin
from ordin.schema import validate_named_schema

from .artifact_store import ArtifactStoreCapacityError, FilesystemArtifactStore, MemoryArtifactStore
from .events import EventRef, SwarmEvent, _hex
from .ingest import HostEventSource
from .labels import Sensitivity
from .models import SwarmContext, counter, identifier, timestamp
from .source_flow import LineageHandle, LineageUse, SwarmSourceFlow

PERMISSIONS = frozenset({"read", "write", "delete", "export"})
RESERVED = frozenset({"system", "system_prompt", "policy", "policies", "credentials"})


@dataclass(frozen=True, slots=True)
class ArtifactAddress:
    tenant_id: str
    swarm_id: str
    workspace_id: str
    namespace: str
    key: str
    kind: str = "artifact"

    def __post_init__(self) -> None:
        for name in ("tenant_id", "swarm_id", "workspace_id", "namespace", "key"):
            identifier(getattr(self, name), name)
        if (
            self.namespace.casefold() in RESERVED
            or type(self.kind) is not str
            or self.kind
            not in {
                "artifact",
                "workspace",
                "kv",
                "vector_entry",
            }
        ):
            raise ValueError("protected or unsupported artifact namespace/kind")

    def as_dict(self) -> dict[str, str]:
        return {
            name: getattr(self, name)
            for name in ("tenant_id", "swarm_id", "workspace_id", "namespace", "key", "kind")
        }


@dataclass(frozen=True, slots=True)
class SwarmArtifact:
    address: ArtifactAddress
    owner_digest: str
    version: int
    content_digest: str
    byte_length: int
    labels: tuple[str, ...]
    expires_at: float
    write_event: EventRef
    source_lineage: tuple[str, ...]
    proof_gaps: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if type(self.address) is not ArtifactAddress or type(self.write_event) is not EventRef:
            raise ValueError("typed artifact address/event required")
        self.address.__post_init__()
        self.write_event.__post_init__()
        if (self.address.tenant_id, self.address.swarm_id) != (
            self.write_event.tenant_id,
            self.write_event.swarm_id,
        ):
            raise ValueError("cross-scope artifact event")
        for name in ("owner_digest", "content_digest"):
            _hex(getattr(self, name), name)
        counter(self.version, "artifact_version")
        if self.version == 0:
            raise ValueError("artifact versions start at one")
        timestamp(self.expires_at)
        if (
            type(self.byte_length) is not int
            or not 0 <= self.byte_length <= 1048576
            or type(self.proof_gaps) is not tuple
            or len(self.proof_gaps) > 64
        ):
            raise ValueError("invalid bounded artifact size/gaps")
        for gap in self.proof_gaps:
            identifier(gap, "artifact_gap")
        Sensitivity(self.labels)
        if type(self.source_lineage) is not tuple or not 1 <= len(self.source_lineage) <= 9:
            raise ValueError("bounded artifact lineage required")
        for value in self.source_lineage:
            _hex(value, "artifact lineage digest")
        if validate_named_schema("swarm_artifact", self.as_dict()):
            raise ValueError("invalid bounded artifact metadata")

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "ordin.swarm_artifact.v1",
            "address": self.address.as_dict(),
            "owner_digest": self.owner_digest,
            "version": self.version,
            "content_digest": self.content_digest,
            "byte_length": self.byte_length,
            "labels": list(self.labels),
            "expires_at": self.expires_at,
            "write_event": self.write_event.as_dict(),
            "source_lineage": list(self.source_lineage),
            "proof_gaps": list(self.proof_gaps),
            "instruction_authority": "data",
            "execution_authority": False,
        }

    @property
    def digest(self) -> str:
        self.__post_init__()
        return digest(self.as_dict())


@dataclass(frozen=True, slots=True)
class PrivateArtifactRead:
    artifact: SwarmArtifact
    value: str = field(repr=False)
    read_event: EventRef
    origin: InstructionOrigin = field(repr=False)
    lineage: LineageHandle | None = field(default=None, repr=False)
    proof_gaps: tuple[str, ...] = ()

    @property
    def instruction_authority(self) -> str:
        return "data"


@dataclass(frozen=True, eq=False, slots=True)
class ArtifactGrant:
    grant_id: str


@dataclass(frozen=True)
class _Grant:
    address: ArtifactAddress
    subject: HostEventSource
    context: SwarmContext
    permissions: frozenset[str]
    version: int
    allowed_labels: frozenset[str]
    expires_at: float


@dataclass(frozen=True)
class _Version:
    metadata: SwarmArtifact
    lineage: LineageHandle
    writer: HostEventSource


@dataclass
class _Resource:
    owner: SwarmContext
    highwater: int = 0
    versions: dict[int, _Version] = field(default_factory=dict)
    labels: Sensitivity = Sensitivity(("public",))
    deleted: bool = False
    last_digest: str | None = None


class SwarmArtifactGateway:
    """Host-only managed UTF-8 artifacts. Raw backing-store access remains uncovered.

    The original source is the caller capability, not a claimed agent ID. All
    access passes current enrollment plus owner or exact-version operator grant.
    """

    def __init__(
        self,
        flow: SwarmSourceFlow,
        *,
        backend: MemoryArtifactStore | FilesystemArtifactStore,
        operator: object,
        workspaces: tuple[str, ...],
        namespaces: tuple[str, ...] = ("shared", "artifacts", "workspace", "kv", "vector"),
        max_resources: int = 256,
        max_versions: int = 8,
        max_grants: int = 1024,
        max_value_bytes: int = 65536,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if (
            type(flow) is not SwarmSourceFlow
            or type(backend) not in {MemoryArtifactStore, FilesystemArtifactStore}
            or type(operator) is not object
            or not callable(clock)
        ):
            raise ValueError("protected artifact flow/backend/operator required")
        for values in (workspaces, namespaces):
            if (
                type(values) is not tuple
                or not 1 <= len(values) <= 64
                or len(set(values)) != len(values)
            ):
                raise ValueError("bounded explicit artifact scopes required")
            for value in values:
                identifier(value, "artifact_scope")
        if any(v.casefold() in RESERVED for v in namespaces):
            raise ValueError("agent storage cannot include protected policy namespaces")
        for limit_value, maximum in (
            (max_resources, 4096),
            (max_versions, 64),
            (max_grants, 16384),
            (max_value_bytes, 1048576),
        ):
            if type(limit_value) is not int or not 1 <= limit_value <= maximum:
                raise ValueError("invalid bounded artifact gateway capacity")
        self._flow, self._backend, self._operator = flow, backend, operator
        self._graph, self._ingest = flow._graph, flow._graph._ingestor
        self._workspaces, self._namespaces = frozenset(workspaces), frozenset(namespaces)
        self._resource_limit, self._version_limit = max_resources, max_versions
        self._grant_limit, self._value_limit = max_grants, max_value_bytes
        self._clock, self._last_now = clock, 0.0
        self._resources: dict[ArtifactAddress, _Resource] = {}
        self._grants: dict[ArtifactGrant, _Grant] = {}
        self._references: dict[str, int] = {}
        self._audit: list[dict[str, Any]] = []
        self._fault = False
        self._lock = RLock()

    def _now(self) -> float:
        now = timestamp(self._clock())
        if now < self._last_now:
            raise ValueError("artifact clock moved backward")
        self._last_now = now
        return now

    def _actor(self, source: HostEventSource, address: ArtifactAddress):
        if self._fault:
            raise ValueError("artifact backing/journal state requires host reconciliation")
        if len(self._audit) >= 16384:
            raise ValueError("artifact audit capacity reached")
        if type(address) is not ArtifactAddress:
            raise ValueError("typed artifact address required")
        address.__post_init__()
        actor = self._flow._actor(source)
        identity = actor.context.identity
        if (
            (address.tenant_id, address.swarm_id) != (identity.tenant_id, identity.swarm_id)
            or address.workspace_id not in self._workspaces
            or address.namespace not in self._namespaces
            or self._ingest._source(source).role != "gateway"
        ):
            raise ValueError("artifact scope or protected source not authorized")
        return actor

    def _authorize(
        self,
        source: HostEventSource,
        address: ArtifactAddress,
        permission: str,
        version: int,
        grant: ArtifactGrant | None,
    ):
        actor = self._actor(source, address)
        resource = self._resources.get(address)
        if resource is None:
            raise ValueError("artifact unavailable or not authorized")
        if actor.context is resource.owner:
            return actor, resource
        row = self._grants.get(grant) if type(grant) is ArtifactGrant else None
        if (
            row is None
            or row.address != address
            or row.subject is not source
            or row.context is not actor.context
            or permission not in row.permissions
            or row.version != version
            or self._now() >= row.expires_at
        ):
            raise ValueError("artifact permission missing, stale or version mismatched")
        record = resource.versions.get(version)
        labels = record.metadata.labels if record else resource.labels.labels
        if not set(labels) <= row.allowed_labels:
            raise ValueError("artifact classification exceeds granted access")
        return actor, resource

    def grant(
        self,
        address: ArtifactAddress,
        subject: HostEventSource,
        *,
        permissions: frozenset[str],
        expected_version: int,
        operator: object,
        allowed_labels: frozenset[str] = frozenset({"public"}),
        lifetime: float = 60,
    ) -> ArtifactGrant:
        if (
            operator is not self._operator
            or type(permissions) is not frozenset
            or not permissions
            or not permissions <= PERMISSIONS
            or type(allowed_labels) is not frozenset
            or not allowed_labels
            or not allowed_labels <= {"public", "secret", "pii", "private_code"}
            or not 0 < timestamp(lifetime) <= 600
        ):
            raise ValueError("current protected operator artifact grant required")
        counter(expected_version, "expected_version")
        with self._lock, self._flow._lock, self._graph._lock, self._ingest._lock:
            actor = self._actor(subject, address)
            resource = self._resources.get(address)
            if resource is None or resource.deleted or expected_version not in resource.versions:
                raise ValueError("artifact version unavailable for sharing")
            if len(self._grants) >= self._grant_limit:
                raise ValueError("artifact grant capacity reached")
            handle = ArtifactGrant(uuid4().hex)
            self._grants[handle] = _Grant(
                address,
                subject,
                actor.context,
                permissions,
                expected_version,
                allowed_labels,
                self._now() + lifetime,
            )
            return handle

    def revoke(self, grant: ArtifactGrant, *, operator: object) -> None:
        with self._lock:
            if (
                operator is not self._operator
                or type(grant) is not ArtifactGrant
                or grant not in self._grants
            ):
                raise ValueError("original protected artifact grant required")
            del self._grants[grant]

    def _event(
        self, source: HostEventSource, kind: str, content_digest: str, parents: tuple[EventRef, ...]
    ) -> EventRef:
        actor = self._flow._actor(source)
        binding = self._ingest._source(source)
        if binding.contiguous != max(binding.sequences, default=0):
            raise ValueError("artifact source event continuity incomplete")
        event_id = "artifact-" + uuid4().hex
        event = SwarmEvent(
            event_id,
            kind,
            actor.context.registry_id,
            actor.context.identity,
            source.source_id,
            binding.contiguous + 1,
            self._now(),
            evidence_class="host_authenticated",
            parent_event_ids=parents,
            resource_digests=(content_digest,),
        )
        receipt = self._ingest.ingest(source, event)
        if receipt.gaps:
            raise ValueError("artifact event ancestry incomplete")
        return EventRef(actor.context.identity.tenant_id, actor.context.identity.swarm_id, event_id)

    def _drop(self, version: _Version) -> None:
        key = version.metadata.content_digest
        count = self._references[key]
        if count == 1:
            self._backend.remove(key)
            del self._references[key]
        else:
            self._references[key] = count - 1

    def _purge(self, resource: _Resource) -> None:
        now = self._now()
        for version, record in tuple(resource.versions.items()):
            if now >= record.metadata.expires_at:
                self._drop(record)
                del resource.versions[version]
        if resource.highwater not in resource.versions:
            resource.deleted = True

    def write(
        self,
        source: HostEventSource,
        address: ArtifactAddress,
        value: str,
        *,
        expected_version: int,
        inputs: tuple[LineageHandle, ...],
        ttl: float = 300,
        grant: ArtifactGrant | None = None,
    ) -> SwarmArtifact:
        counter(expected_version, "expected_version")
        if (
            type(value) is not str
            or len(value) > self._value_limit
            or not 0 < timestamp(ttl) <= 86400
        ):
            raise ValueError("bounded UTF-8 artifact value/lifetime required")
        try:
            raw = value.encode("utf-8")
        except UnicodeError:
            raise ValueError("invalid artifact encoding") from None
        if (
            len(raw) > self._value_limit
            or type(inputs) is not tuple
            or not 1 <= len(inputs) <= 8
            or len(set(inputs)) != len(inputs)
        ):
            raise ValueError("bounded exact artifact lineage inputs required")
        with self._lock, self._flow._lock, self._graph._lock, self._ingest._lock:
            actor = self._actor(source, address)
            resource = self._resources.get(address)
            if resource is None:
                if expected_version != 0 or len(self._resources) >= self._resource_limit:
                    raise ValueError("artifact create conflict or resource capacity reached")
                resource = _Resource(actor.context)
            else:
                self._authorize(source, address, "write", resource.highwater, grant)
            if expected_version != resource.highwater:
                raise ValueError("artifact conditional version conflict")
            content_digest = hashlib.sha256(raw).hexdigest()
            rows = [self._flow._record(handle) for handle in inputs]
            if any(
                row.actor.context is not actor.context
                or row.actor.source is not source
                or row.content_digest != content_digest
                or row.byte_length != len(raw)
                or not row.complete
                or not row.sensitivity.known
                for row in rows
            ):
                raise ValueError("artifact write requires current complete exact-byte lineage")
            labels = resource.labels.join(*(row.sensitivity for row in rows))
            if actor.context is not resource.owner:
                permission = self._grants.get(grant) if type(grant) is ArtifactGrant else None
                if permission is None or not set(labels.labels) <= permission.allowed_labels:
                    raise ValueError("artifact output classification exceeds write grant")
            parents = tuple(
                EventRef(address.tenant_id, address.swarm_id, key)
                for key in sorted({r.event_id for r in rows})
            )
            next_version = counter(resource.highwater + 1, "artifact_version")
            lineage = tuple(sorted(self._flow._digest(row) for row in rows))
            if resource.last_digest is not None:
                lineage += (resource.last_digest,)
            try:
                if self._backend.put(raw) != content_digest:
                    raise ValueError("backing content digest mismatch")
                event = self._event(source, "artifact_write", content_digest, parents)
                input_labels = rows[0].sensitivity.join(*(row.sensitivity for row in rows[1:]))
                if labels == input_labels:
                    # This is an actual exact-byte data transfer. Preserve the
                    # original handles so temporal attribution can follow it.
                    handle = self._flow.derive(
                        source,
                        event_id=event.event_id,
                        content=raw,
                        parents=inputs,
                        complete=True,
                    )
                else:
                    # Retained resource classification can be stricter than new
                    # replacement bytes. It is a protected classification root,
                    # not proof that overwritten old bytes caused the output.
                    origin = register_instruction_origin(
                        actor.host,
                        origin_id="artifact-" + uuid4().hex,
                        kind="repository_file",
                        classification="sensitive" if labels.sensitive else "public",
                        content=raw,
                        parent_action_digest=digest([address.as_dict(), next_version]),
                    )
                    handle = self._flow.register(
                        source, event_id=event.event_id, origin=origin, sensitivity=labels
                    )
                gaps = self._flow._record(handle).gaps
                metadata = SwarmArtifact(
                    address,
                    digest(resource.owner.as_dict()),
                    next_version,
                    content_digest,
                    len(raw),
                    labels.labels,
                    self._now() + ttl,
                    event,
                    lineage,
                    gaps,
                )
                # No metadata version is visible until bytes, journal and protected
                # classification all commit. A partial failure fences this service.
                self._references[content_digest] = self._references.get(content_digest, 0) + 1
                resource.versions[next_version] = _Version(metadata, handle, source)
                resource.highwater, resource.labels, resource.deleted = next_version, labels, False
                resource.last_digest = metadata.digest
                self._resources[address] = resource
                while len(resource.versions) > self._version_limit:
                    oldest = min(resource.versions)
                    self._drop(resource.versions[oldest])
                    del resource.versions[oldest]
                self._purge(resource)
            except ArtifactStoreCapacityError:
                raise ValueError("artifact backing capacity reached") from None
            except Exception:
                self._fault = True
                raise ValueError(
                    "artifact write incomplete; host reconciliation required"
                ) from None
            self._audit_event(metadata, "write")
            return metadata

    def _read(
        self,
        source: HostEventSource,
        address: ArtifactAddress,
        version: int | None,
        grant: ArtifactGrant | None,
        permission: str,
    ) -> PrivateArtifactRead:
        resource = self._resources.get(address)
        if resource is None:
            raise ValueError("artifact unavailable or not authorized")
        selected = resource.highwater if version is None else counter(version, "artifact_version")
        actor, resource = self._authorize(source, address, permission, selected, grant)
        try:
            self._purge(resource)
        except Exception:
            self._fault = True
            raise ValueError(
                "artifact retention cleanup failed; host reconciliation required"
            ) from None
        record = resource.versions.get(selected)
        if record is None:
            raise ValueError("artifact expired, deleted or outside retention")
        try:
            raw = self._backend.read(record.metadata.content_digest, record.metadata.byte_length)
            value = raw.decode("utf-8")
            event = self._event(
                source,
                "artifact_read",
                record.metadata.content_digest,
                (record.metadata.write_event,),
            )
            origin = register_instruction_origin(
                actor.host,
                origin_id="artifact-read-" + uuid4().hex,
                kind="repository_file",
                classification="sensitive"
                if Sensitivity(record.metadata.labels).sensitive
                else "public",
                content=raw,
                parent_action_digest=record.metadata.digest,
            )
        except ValueError:
            self._fault = True
            raise ValueError(
                "artifact read boundary changed; host reconciliation required"
            ) from None
        except Exception:
            self._fault = True
            raise ValueError("artifact read failed; host reconciliation required") from None
        lineage_handle = None
        gaps = record.metadata.proof_gaps
        try:
            lineage_handle = self._flow.derive(
                source,
                event_id=event.event_id,
                content=raw,
                parents=(record.lineage,),
                complete=True,
            )
            gaps = tuple(sorted(set(gaps) | set(self._flow._record(lineage_handle).gaps)))
        except ValueError:
            gaps = tuple(sorted(set(gaps) | {"historical_lineage_unavailable"}))
        self._audit_event(record.metadata, permission)
        return PrivateArtifactRead(record.metadata, value, event, origin, lineage_handle, gaps)

    def read(
        self,
        source: HostEventSource,
        address: ArtifactAddress,
        *,
        version: int | None = None,
        grant: ArtifactGrant | None = None,
    ) -> PrivateArtifactRead:
        with self._lock, self._flow._lock, self._graph._lock, self._ingest._lock:
            return self._read(source, address, version, grant, "read")

    def prepare_export(
        self,
        source: HostEventSource,
        address: ArtifactAddress,
        action: ActionEnvelope,
        *,
        argument_path: tuple[str, ...],
        sink_id: str,
        version: int | None = None,
        grant: ArtifactGrant | None = None,
    ) -> PrivateArtifactRead:
        """Authorize exact data for a mediated proposal; never execute or weaken its action gate."""
        with self._lock, self._flow._lock, self._graph._lock, self._ingest._lock:
            result = self._read(source, address, version, grant, "export")
            if result.lineage is None or result.proof_gaps:
                raise ValueError("artifact export provenance incomplete")
            facts = self._flow.assess(
                source,
                action,
                sink_id=sink_id,
                uses=(LineageUse(result.lineage, argument_path),),
                complete=True,
            )
            if facts.status != "satisfied":
                raise ValueError("artifact export source-flow restricted")
            return result

    def delete(
        self,
        source: HostEventSource,
        address: ArtifactAddress,
        *,
        expected_version: int,
        grant: ArtifactGrant | None = None,
    ) -> None:
        counter(expected_version, "expected_version")
        with self._lock, self._flow._lock, self._graph._lock, self._ingest._lock:
            _, resource = self._authorize(source, address, "delete", expected_version, grant)
            if resource.highwater != expected_version:
                raise ValueError("artifact delete version conflict")
            if resource.deleted and not resource.versions:
                return
            record = resource.versions.get(expected_version)
            try:
                # A revocation event records the protected deletion operation;
                # no cross-agent data-flow edge is inferred from it.
                if record is not None:
                    self._event(source, "revoked", record.metadata.content_digest, ())
                for version in tuple(resource.versions.values()):
                    self._drop(version)
                resource.versions.clear()
                resource.deleted = True
            except Exception:
                self._fault = True
                raise ValueError(
                    "artifact deletion incomplete; host reconciliation required"
                ) from None
            if record is not None:
                self._audit_event(record.metadata, "delete")

    def _audit_event(self, metadata: SwarmArtifact, operation: str) -> None:
        if len(self._audit) >= 16384:
            raise ValueError("artifact audit capacity reached")
        self._audit.append(
            {
                "artifact_digest": metadata.digest,
                "operation": operation,
                "version": metadata.version,
                "labels": list(metadata.labels),
            }
        )

    def audit(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            return tuple({**row, "labels": list(row["labels"])} for row in self._audit)

    def diagnostics(self) -> dict[str, Any]:
        with self._lock:
            return {
                "schema_version": "ordin.swarm_artifact_diagnostics.v1",
                "managed_api": "mediated",
                "raw_backing_access": "uncovered",
                "opaque_vector_queries": "unsupported",
                "healthy": not self._fault,
                "physical_enforcement": False,
                "resource_count": len(self._resources),
                "grant_count": len(self._grants),
            }
