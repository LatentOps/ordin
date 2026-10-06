"""Pure derivation of action-bound minimum runtime capability requirements.

These contracts describe requirements, never grants. Unknowns prevent enforce
compilation. A blocked decision is diagnostic and an ask/warn requires approval.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Mapping
from urllib.parse import urlsplit

from ._runtime_json import digest, freeze, model_tuple, text_tuple, thaw, validate
from .action import ActionReview
from .audit import action_digest
from .shell import split_shell_segments

RUNTIME_CAPABILITY_SCHEMA_VERSION = "ordin.runtime_capability.v1"


@dataclass(frozen=True)
class FilesystemCapability:
    access: str
    path: str | None
    scope: str = "exact"

    def __post_init__(self) -> None:
        validate("filesystem", self.as_dict())

    def as_dict(self) -> dict[str, Any]:
        return {"access": self.access, "path": self.path, "scope": self.scope}


@dataclass(frozen=True)
class NetworkCapability:
    host: str | None
    port: int | None
    protocol: str = "unknown"
    access: str = "unknown"
    methods: tuple[str, ...] = ()
    paths: tuple[str, ...] = ()
    tool_identity: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "methods", text_tuple(self.methods))
        object.__setattr__(self, "paths", text_tuple(self.paths))
        validate("network", self.as_dict())

    def as_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "access": self.access,
            "methods": list(self.methods),
            "paths": list(self.paths),
            "tool_identity": self.tool_identity,
        }


@dataclass(frozen=True)
class ToolCapability:
    runtime: str
    server: str | None
    tool: str
    operation: str = "call"

    def __post_init__(self) -> None:
        validate("tool", self.as_dict())

    def as_dict(self) -> dict[str, Any]:
        return {
            "runtime": self.runtime,
            "server": self.server,
            "tool": self.tool,
            "operation": self.operation,
        }


@dataclass(frozen=True)
class ProcessCapability:
    execution: bool | None = False
    executables: tuple[str, ...] = ()
    spawn_children: bool | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "executables", text_tuple(self.executables))
        validate("process", self.as_dict())

    def as_dict(self) -> dict[str, Any]:
        return {
            "execution": self.execution,
            "executables": list(self.executables),
            "spawn_children": self.spawn_children,
        }


@dataclass(frozen=True)
class PrivilegeCapability:
    escalation: bool | None = False
    required_euid: int | None = None

    def __post_init__(self) -> None:
        validate("privilege", self.as_dict())

    def as_dict(self) -> dict[str, Any]:
        return {"escalation": self.escalation, "required_euid": self.required_euid}


@dataclass(frozen=True)
class CredentialBinding:
    binding: str
    host: str
    port: int

    def __post_init__(self) -> None:
        validate("credential", self.as_dict())

    def as_dict(self) -> dict[str, Any]:
        return {"binding": self.binding, "host": self.host, "port": self.port}


@dataclass(frozen=True)
class CapabilityUnknown:
    domain: str
    reason_code: str
    reason: str

    def __post_init__(self) -> None:
        validate("unknown", self.as_dict())

    def as_dict(self) -> dict[str, str]:
        return {"domain": self.domain, "reason_code": self.reason_code, "reason": self.reason}


@dataclass(frozen=True)
class RuntimeCapabilityContract:
    action_id: str | None
    action_digest: str
    decision: str
    risk: str
    filesystem: tuple[FilesystemCapability, ...] = ()
    network: tuple[NetworkCapability, ...] = ()
    tools: tuple[ToolCapability, ...] = ()
    process: ProcessCapability = field(default_factory=ProcessCapability)
    privilege: PrivilegeCapability = field(default_factory=PrivilegeCapability)
    credentials: tuple[CredentialBinding, ...] = ()
    unknowns: tuple[CapabilityUnknown, ...] = ()
    source: Mapping[str, Any] = field(default_factory=dict)
    contract_id: str = ""

    def __post_init__(self) -> None:
        for name, model in (
            ("filesystem", FilesystemCapability),
            ("network", NetworkCapability),
            ("tools", ToolCapability),
            ("credentials", CredentialBinding),
            ("unknowns", CapabilityUnknown),
        ):
            object.__setattr__(self, name, model_tuple(getattr(self, name), model))
        if not isinstance(self.process, ProcessCapability) or not isinstance(
            self.privilege, PrivilegeCapability
        ):
            raise ValueError("runtime contract requires typed process/privilege capabilities")
        if not isinstance(self.source, Mapping):
            raise ValueError("runtime contract source must be an object")
        object.__setattr__(self, "source", freeze(self.source))
        expected = "rc:" + digest(self._material())
        if self.contract_id and self.contract_id != expected:
            raise ValueError("runtime contract identity does not match its content")
        object.__setattr__(self, "contract_id", expected)
        validate("runtime_capability", self.as_dict())

    @property
    def grant_state(self) -> str:
        if self.decision == "block" or self.unknowns:
            return "diagnostic"
        if self.decision in {"ask", "warn"}:
            return "requires_approval"
        return "eligible"

    def _material(self) -> dict[str, Any]:
        return {
            "schema_version": RUNTIME_CAPABILITY_SCHEMA_VERSION,
            "action_id": self.action_id,
            "action_digest": self.action_digest,
            "decision": self.decision,
            "risk": self.risk,
            "grant_state": self.grant_state,
            "filesystem": [v.as_dict() for v in self.filesystem],
            "network": [v.as_dict() for v in self.network],
            "tools": [v.as_dict() for v in self.tools],
            "process": self.process.as_dict(),
            "privilege": self.privilege.as_dict(),
            "credentials": [v.as_dict() for v in self.credentials],
            "unknowns": [v.as_dict() for v in self.unknowns],
            "source": thaw(self.source),
        }

    def as_dict(self) -> dict[str, Any]:
        return {**self._material(), "contract_id": self.contract_id}

    @property
    def digest(self) -> str:
        return digest(self.as_dict())

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> RuntimeCapabilityContract:
        validate("runtime_capability", payload)
        result = cls(
            action_id=payload["action_id"],
            action_digest=payload["action_digest"],
            decision=payload["decision"],
            risk=payload["risk"],
            filesystem=tuple(FilesystemCapability(**v) for v in payload["filesystem"]),
            network=tuple(NetworkCapability(**v) for v in payload["network"]),
            tools=tuple(ToolCapability(**v) for v in payload["tools"]),
            process=ProcessCapability(**payload["process"]),
            privilege=PrivilegeCapability(**payload["privilege"]),
            credentials=tuple(CredentialBinding(**v) for v in payload["credentials"]),
            unknowns=tuple(CapabilityUnknown(**v) for v in payload["unknowns"]),
            source=payload["source"],
            contract_id=payload["contract_id"],
        )
        if result.grant_state != payload["grant_state"]:
            raise ValueError("runtime contract grant state disagrees with decision/unknowns")
        return result


_FILESYSTEM_EFFECTS = {
    "filesystem.read": "read",
    "filesystem.metadata_read": "metadata",
    "filesystem.write": "write",
    "filesystem.delete": "delete",
    "filesystem.recursive_delete": "delete",
    "filesystem.execute": "execute",
}
_NETWORK_EFFECTS = {
    "network.connect": "read",
    "network.download": "read",
    "network.upload": "write",
}


def _safe_path(path: str) -> bool:
    # This is syntax validation, never a symlink or filesystem-security proof.
    return (
        path.startswith("/")
        and not path.startswith("//")
        and all(part not in {".", ".."} for part in path.split("/"))
        and not any(ord(c) < 32 or c in "*?$`\\" for c in path)
    )


def derive_runtime_capability_contract(review: ActionReview) -> RuntimeCapabilityContract:
    """Derive only from supplied reviewed evidence; never execute or inspect a host."""
    if not isinstance(review, ActionReview):
        raise ValueError("runtime derivation requires an ActionReview")
    effects = set(review.effects)
    unknowns: set[CapabilityUnknown] = set()
    filesystem: set[FilesystemCapability] = set()
    network: set[NetworkCapability] = set()
    tools: list[ToolCapability] = []

    def unknown(domain: str, code: str, reason: str) -> None:
        unknowns.add(CapabilityUnknown(domain, code, reason))

    if review.adapter is None or review.risk == "unknown":
        unknown(
            "semantics",
            "runtime_contract_unknown_semantics",
            "Reviewed action has unknown deterministic semantics.",
        )
    fs_effects = {v for v in effects if v.startswith("filesystem.")}
    paths = [v for v in review.resources if v.type in {"path", "file", "directory"}]
    if len(paths) > 1 and len({_FILESYSTEM_EFFECTS.get(e) for e in fs_effects}) > 1:
        unknown(
            "filesystem",
            "runtime_contract_ambiguous_resource",
            "Effects cannot be precisely associated with individual resource targets.",
        )
    for effect in sorted(fs_effects):
        access = _FILESYSTEM_EFFECTS.get(effect, "unknown")
        if access == "unknown":
            unknown(
                "filesystem",
                "runtime_contract_unknown_semantics",
                "Filesystem effect has no precise access mapping.",
            )
        if not paths:
            filesystem.add(FilesystemCapability(access, None, "unknown"))
            unknown(
                "filesystem",
                "runtime_contract_missing_resource",
                "Filesystem effect has no established resource target.",
            )
        for resource in paths:
            if not _safe_path(resource.value):
                filesystem.add(FilesystemCapability(access, None, "unknown"))
                unknown(
                    "filesystem",
                    "runtime_contract_malformed_resource",
                    "Filesystem target is not an unambiguous absolute POSIX path.",
                )
            else:
                scope = "prefix" if effect == "filesystem.recursive_delete" else "exact"
                filesystem.add(FilesystemCapability(access, resource.value, scope))
    net_effects = {v for v in effects if v.startswith("network.")}
    net_resources = [v for v in review.resources if v.type in {"host", "url", "endpoint"}]
    if net_effects:
        access = "write" if "network.upload" in effects else "read"
        if not net_effects.issubset(_NETWORK_EFFECTS):
            access = "unknown"
            unknown(
                "network",
                "runtime_contract_unknown_semantics",
                "Network effect has no precise access mapping.",
            )
        if not net_resources:
            network.add(NetworkCapability(None, None, access=access))
            unknown(
                "network",
                "runtime_contract_missing_resource",
                "Network effect has no established endpoint.",
            )
        for resource in net_resources:
            host, port = None, None
            try:
                if resource.type == "host":
                    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", resource.value):
                        host = resource.value
                else:
                    url = urlsplit(resource.value)
                    # Query/userinfo can contain credentials. Never retain them.
                    if (
                        url.scheme in {"http", "https"}
                        and not any(ord(c) < 32 for c in resource.value)
                        and not (url.username or url.password or url.query or url.fragment)
                    ):
                        parsed_port = (
                            url.port
                            if url.port is not None
                            else (443 if url.scheme == "https" else 80)
                        )
                        parsed_host = url.hostname
                        if (
                            1 <= parsed_port <= 65535
                            and parsed_host
                            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:-]{0,252}", parsed_host)
                        ):
                            host, port = parsed_host, parsed_port
            except ValueError:
                host, port = None, None
            if host is None:
                unknown(
                    "network",
                    "runtime_contract_malformed_resource",
                    "Endpoint is malformed, ambiguous, or includes sensitive URL components.",
                )
            # Host/URL evidence alone does not establish REST or an HTTP method.
            network.add(NetworkCapability(host, port, access=access))
            unknown(
                "network",
                "runtime_contract_unknown_protocol",
                "Endpoint evidence does not establish request protocol and method.",
            )
    params = review.action.parameters
    if review.action.kind in {"mcp", "tool"}:
        runtime = "mcp" if review.action.kind == "mcp" else params.get("runtime")
        server = params.get("server") if runtime == "mcp" else None
        tool = params.get("tool")
        if (
            review.adapter is not None
            and effects
            and isinstance(runtime, str)
            and isinstance(tool, str)
        ):
            if runtime != "mcp" or isinstance(server, str):
                tools.append(ToolCapability(runtime, server, tool))
            else:
                unknown("tool", "runtime_contract_missing_resource", "Exact MCP server is missing.")
        else:
            unknown(
                "tool",
                "runtime_contract_unknown_semantics",
                "Tool identity has no trusted deterministic semantic binding.",
            )
    process_execution = review.action.kind == "shell" or any(
        e.startswith(("process.", "code.")) for e in effects
    )
    executables: tuple[str, ...] = ()
    escalation: bool | None = any(e.startswith("privilege.") for e in effects)
    if review.action.kind == "shell":
        command = params.get("command")
        try:
            segments, operators = (
                split_shell_segments(command) if isinstance(command, str) else ([], [])
            )
            if len(segments) == 1 and not operators and segments[0]:
                token = segments[0][0]
                if re.fullmatch(r"[A-Za-z0-9_./+-]+", token):
                    executables = (token,)
                if token.rsplit("/", 1)[-1] in {"sudo", "su", "doas"}:
                    escalation = True
                if any(v in {"<", ">", ">>", "(", ")"} for v in segments[0]):
                    unknown(
                        "process",
                        "runtime_contract_unknown_semantics",
                        "Shell redirections or nested execution require additional scope.",
                    )
            else:
                unknown(
                    "process",
                    "runtime_contract_unknown_semantics",
                    "Compound shell execution has no single established executable scope.",
                )
        except ValueError:
            unknown("process", "runtime_contract_unknown_semantics", "Shell syntax is ambiguous.")
        if not executables:
            unknown(
                "process", "runtime_contract_missing_resource", "Executable identity is unknown."
            )
    if review.adapter is None:
        escalation = None
    return RuntimeCapabilityContract(
        action_id=review.action.action_id,
        action_digest=action_digest(review),
        decision=review.decision,
        risk=review.risk,
        filesystem=tuple(sorted(filesystem, key=lambda v: (v.access, v.path or "", v.scope))),
        network=tuple(sorted(network, key=lambda v: (v.host or "", v.port or 0, v.access))),
        tools=tuple(tools),
        process=ProcessCapability(
            process_execution if review.adapter is not None else None, executables, None
        ),
        privilege=PrivilegeCapability(escalation),
        unknowns=tuple(sorted(unknowns, key=lambda v: (v.domain, v.reason_code, v.reason))),
        source={
            "kind": review.action.kind,
            "operation": review.action.operation,
            "adapter": review.adapter,
            "effects": sorted(effects),
            "provenance_digest": review.provenance.digest if review.provenance else None,
        },
    )
