"""Explicit host-reviewed runtime requirements, kept separate from action effects.

The host knows its deployment's loader/working paths and binary bindings. These
facts are supplied as context evidence, never discovered from the environment
or granted by agent arguments. They do not rewrite the original semantic review.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Mapping

from ._runtime_json import digest, freeze, model_tuple, thaw
from .action import ActionReview
from .provenance import ProvenanceRecord, ProvenanceResource
from .runtime_contract import FilesystemCapability, _safe_path


@dataclass(frozen=True)
class RuntimeRequirementProfile:
    profile_id: str
    filesystem: tuple[FilesystemCapability, ...] = ()
    executable_bindings: Mapping[str, str] = field(default_factory=dict)
    spawn_children: bool | None = None
    client_executables: tuple[str, ...] = ()
    mcp_endpoints: Mapping[str, str] = field(default_factory=dict)
    mcp_versions: Mapping[str, tuple[str, ...]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.profile_id, str) or not 1 <= len(self.profile_id) <= 128:
            raise ValueError("runtime_requirement_profile_identity_invalid")
        object.__setattr__(self, "filesystem", model_tuple(self.filesystem, FilesystemCapability))
        bindings = self.executable_bindings if self.executable_bindings is not None else {}
        if not isinstance(bindings, Mapping):
            raise ValueError("runtime_requirement_bindings_invalid")
        if any(
            not isinstance(k, str) or not k or not isinstance(v, str) or not _safe_path(v)
            for k, v in bindings.items()
        ):
            raise ValueError("runtime_requirement_bindings_invalid")
        object.__setattr__(self, "executable_bindings", freeze(bindings))
        if self.spawn_children is not None and type(self.spawn_children) is not bool:
            raise ValueError("runtime_requirement_children_invalid")
        from ._runtime_json import text_tuple
        from .runtime_requests import request_endpoint, MCP_VERSIONS

        object.__setattr__(self, "client_executables", text_tuple(self.client_executables))
        if any(not _safe_path(path) for path in self.client_executables):
            raise ValueError("runtime_requirement_client_invalid")
        if not isinstance(self.mcp_endpoints, Mapping) or any(
            not isinstance(server, str) or not server or request_endpoint(url) is None
            for server, url in self.mcp_endpoints.items()
        ):
            raise ValueError("runtime_requirement_mcp_endpoint_invalid")
        object.__setattr__(self, "mcp_endpoints", freeze(self.mcp_endpoints))
        if not isinstance(self.mcp_versions, Mapping) or any(
            server not in self.mcp_endpoints
            or not isinstance(versions, (tuple, list))
            or not versions
            or any(not isinstance(v, str) or v not in MCP_VERSIONS for v in versions)
            or len(set(versions)) != len(versions)
            for server, versions in self.mcp_versions.items()
        ):
            raise ValueError("runtime_requirement_mcp_versions_invalid")
        object.__setattr__(
            self, "mcp_versions", freeze({k: sorted(v) for k, v in self.mcp_versions.items()})
        )
        if any(
            f.path is None
            or not _safe_path(f.path)
            or f.access == "unknown"
            or f.scope == "unknown"
            for f in self.filesystem
        ):
            raise ValueError("runtime_requirement_filesystem_invalid")
        freeze(self.as_dict())

    def as_dict(self) -> dict:
        result = {
            "profile_id": self.profile_id,
            "filesystem": [f.as_dict() for f in self.filesystem],
            "executable_bindings": thaw(self.executable_bindings),
            "spawn_children": self.spawn_children,
        }
        if self.client_executables:
            result["client_executables"] = list(self.client_executables)
        if self.mcp_endpoints:
            result["mcp_endpoints"] = thaw(self.mcp_endpoints)
        if self.mcp_versions:
            result["mcp_versions"] = thaw(self.mcp_versions)
        return result

    @property
    def digest(self) -> str:
        return digest(self.as_dict())

    def declare(self, review: ActionReview) -> ActionReview:
        """Host API: attach reviewed deployment facts, preserving decision/effects.

        Protect the profile and original review. This is local context authority,
        not measurement, authentication, or a way to bypass unknown action semantics.
        """
        if not isinstance(review, ActionReview) or review.provenance is None:
            raise ValueError("runtime_requirement_review_invalid")
        records = []
        for capability in self.filesystem:
            assert capability.path is not None
            records.append(
                ProvenanceRecord(
                    source="context",
                    kind="resource",
                    code="runtime.requirement.filesystem",
                    resource=ProvenanceResource("path", capability.path),
                    metadata={
                        "access": capability.access,
                        "scope": capability.scope,
                        "profile_digest": self.digest,
                    },
                )
            )
        for logical, path in sorted(self.executable_bindings.items()):
            records.append(
                ProvenanceRecord(
                    source="context",
                    kind="resource",
                    code="runtime.requirement.executable",
                    resource=ProvenanceResource("executable", path),
                    metadata={"logical_executable": logical, "profile_digest": self.digest},
                )
            )
        if self.spawn_children is not None:
            records.append(
                ProvenanceRecord(
                    source="context",
                    kind="finding",
                    code="runtime.requirement.children",
                    metadata={"spawn_children": self.spawn_children, "profile_digest": self.digest},
                )
            )
        if review.action.kind != "shell":
            for path in self.client_executables:
                records.append(
                    ProvenanceRecord(
                        source="context",
                        kind="resource",
                        code="runtime.requirement.client",
                        resource=ProvenanceResource("executable", path),
                        metadata={"profile_digest": self.digest},
                    )
                )
        if review.action.kind == "mcp":
            server = review.action.parameters.get("server")
            if isinstance(server, str) and server in self.mcp_versions:
                records.append(
                    ProvenanceRecord(
                        source="context",
                        kind="finding",
                        code="runtime.requirement.mcp_versions",
                        metadata={
                            "server": server,
                            "versions": ",".join(self.mcp_versions[server]),
                            "profile_digest": self.digest,
                        },
                    )
                )
            if isinstance(server, str) and server in self.mcp_endpoints:
                records.append(
                    ProvenanceRecord(
                        source="context",
                        kind="resource",
                        code="runtime.requirement.mcp_endpoint",
                        resource=ProvenanceResource("url", self.mcp_endpoints[server]),
                        metadata={"server": server, "profile_digest": self.digest},
                    )
                )
        return replace(review, provenance=review.provenance.append(*records))
