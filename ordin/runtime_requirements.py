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
from ._runtime_host import identity_matches


@dataclass(frozen=True)
class ToolRuntimeRequirement:
    """Host-selected requirements for one exact fixed-tool catalogue entry.

    Matching caller data selects requirements, not permission. The original
    semantic decision/effects and all capability-maximum checks still apply.
    """

    runtime: str
    server: str | None
    tool: str
    operation: str
    test_id: str
    filesystem: tuple[FilesystemCapability, ...] = ()
    client_executables: tuple[str, ...] = ()
    spawn_children: bool | None = False

    def __post_init__(self) -> None:
        import re

        for value in (self.runtime, self.tool, self.operation, self.test_id):
            if (
                type(value) is not str
                or not 1 <= len(value) <= 128
                or re.fullmatch(r"[A-Za-z0-9_.:/-]+", value) is None
            ):
                raise ValueError("runtime_requirement_tool_selector_invalid")
        if self.server is not None and (
            type(self.server) is not str
            or not 1 <= len(self.server) <= 128
            or re.fullmatch(r"[A-Za-z0-9_.:/-]+", self.server) is None
        ):
            raise ValueError("runtime_requirement_tool_selector_invalid")
        checked = RuntimeRequirementProfile(
            "checked-tool-requirements",
            filesystem=self.filesystem,
            client_executables=self.client_executables,
            spawn_children=self.spawn_children,
        )
        if len(checked.filesystem) > 8 or len(checked.client_executables) > 4:
            raise ValueError("runtime_requirement_tool_capacity")
        object.__setattr__(self, "filesystem", checked.filesystem)
        object.__setattr__(self, "client_executables", checked.client_executables)

    @property
    def selector(self) -> tuple[str, str | None, str, str, str]:
        return self.runtime, self.server, self.tool, self.operation, self.test_id

    def as_dict(self) -> dict:
        return {
            "runtime": self.runtime,
            "server": self.server,
            "tool": self.tool,
            "operation": self.operation,
            "test_id": self.test_id,
            "filesystem": [item.as_dict() for item in self.filesystem],
            "client_executables": list(self.client_executables),
            "spawn_children": self.spawn_children,
        }

    def matches(self, review: ActionReview) -> bool:
        parameters = review.action.parameters
        arguments = parameters.get("arguments")
        return (
            review.action.kind in {"tool", "mcp"}
            and review.action.operation == self.operation
            and parameters.get("runtime") == self.runtime
            and parameters.get("server") == self.server
            and parameters.get("tool") == self.tool
            and isinstance(arguments, Mapping)
            and set(arguments) == {"test_id"}
            and type(arguments["test_id"]) is str
            and arguments["test_id"] == self.test_id
        )

    def declaration(self) -> RuntimeRequirementProfile:
        return RuntimeRequirementProfile(
            "conditional-tool-" + digest(self.as_dict()),
            filesystem=self.filesystem,
            client_executables=self.client_executables,
            spawn_children=self.spawn_children,
        )


@dataclass(frozen=True)
class RuntimeRequirementProfile:
    profile_id: str
    filesystem: tuple[FilesystemCapability, ...] = ()
    executable_bindings: Mapping[str, str] = field(default_factory=dict)
    spawn_children: bool | None = None
    client_executables: tuple[str, ...] = ()
    mcp_endpoints: Mapping[str, str] = field(default_factory=dict)
    mcp_versions: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    tool_requirements: tuple[ToolRuntimeRequirement, ...] = ()

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
        object.__setattr__(
            self, "tool_requirements", model_tuple(self.tool_requirements, ToolRuntimeRequirement)
        )
        if len(self.tool_requirements) > 16 or len(
            {item.selector for item in self.tool_requirements}
        ) != len(self.tool_requirements):
            raise ValueError("runtime_requirement_tool_capacity_or_duplicate")
        # The existing per-container bound is unchanged; the optional field is
        # omitted when empty, preserving old profile bytes and digests exactly.
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
        if self.tool_requirements:
            result["tool_requirements"] = [item.as_dict() for item in self.tool_requirements]
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
            matching = sorted(
                key
                for key in self.mcp_endpoints
                if isinstance(server, str) and identity_matches(key, server)
            )
            if len({self.mcp_endpoints[key] for key in matching}) > 1:
                raise ValueError("runtime_requirement_mcp_endpoint_conflict")
            for key in matching:
                if key not in self.mcp_versions:
                    continue
                records.append(
                    ProvenanceRecord(
                        source="context",
                        kind="finding",
                        code="runtime.requirement.mcp_versions",
                        metadata={
                            "server": server,
                            "versions": ",".join(self.mcp_versions[key]),
                            "profile_digest": self.digest,
                        },
                    )
                )
            if matching:
                records.append(
                    ProvenanceRecord(
                        source="context",
                        kind="resource",
                        code="runtime.requirement.mcp_endpoint",
                        resource=ProvenanceResource("url", self.mcp_endpoints[matching[0]]),
                        metadata={"server": server, "profile_digest": self.digest},
                    )
                )
        declared = replace(review, provenance=review.provenance.append(*records))
        for requirement in self.tool_requirements:
            if requirement.matches(review):
                declared = requirement.declaration().declare(declared)
        return declared
