"""Executable schema definitions; checked JSON copies are shipped with Ordin.

Runtime model validation uses these in-memory definitions, never filesystem I/O.
The root and packaged JSON copies must match them (tested by doctor and tests).
"""

from __future__ import annotations

from typing import Any


def text(maximum: int = 4096, *, nullable: bool = False, pattern: str | None = None) -> dict:
    result: dict[str, Any] = {
        "type": ["string", "null"] if nullable else "string",
        "minLength": 1,
        "maxLength": maximum,
    }
    if pattern:
        result["pattern"] = pattern
    return result


def array(item: dict, maximum: int = 128) -> dict:
    return {"type": "array", "maxItems": maximum, "items": item}


def obj(properties: dict, *, required: list[str] | None = None) -> dict:
    return {
        "type": "object",
        "properties": properties,
        "required": list(properties) if required is None else required,
        "additionalProperties": False,
    }


def enum(*values: str) -> dict:
    return {"type": "string", "enum": list(values)}


DIGEST = text(64, pattern="^[a-f0-9]{64}$")
IDENTIFIER = text(128, pattern="^[A-Za-z0-9][A-Za-z0-9_.:/@-]*$")
HOST = text(253, nullable=True, pattern="^[A-Za-z0-9][A-Za-z0-9.:-]*$")
PORT = {"type": ["integer", "null"], "minimum": 1, "maximum": 65535}
BOOL = {"type": ["boolean", "null"]}
FILESYSTEM = obj(
    {
        "access": enum("read", "write", "delete", "metadata", "execute", "unknown"),
        "path": text(nullable=True),
        "scope": enum("exact", "prefix", "unknown"),
    }
)
NETWORK = obj(
    {
        "host": HOST,
        "port": PORT,
        "protocol": enum("rest", "mcp", "json-rpc", "graphql", "websocket", "tcp", "unknown"),
        "access": enum("read", "write", "unknown"),
        "methods": array(
            enum("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE"), 32
        ),
        "paths": array(text(), 128),
        "tool_identity": text(256, nullable=True),
    }
)
TOOL = obj(
    {
        "runtime": text(128),
        "server": text(256, nullable=True),
        "tool": text(256),
        "operation": {"const": "call", "type": "string"},
    }
)
PROCESS = obj({"execution": BOOL, "executables": array(text()), "spawn_children": BOOL})
PRIVILEGE = obj({"escalation": BOOL, "required_euid": {"type": ["integer", "null"], "minimum": 0}})
CREDENTIAL = obj(
    {"binding": IDENTIFIER, "host": {**HOST, "type": "string"}, "port": {**PORT, "type": "integer"}}
)
UNKNOWN = obj(
    {
        "domain": enum(
            "filesystem", "network", "process", "privilege", "credential", "tool", "semantics"
        ),
        "reason_code": IDENTIFIER,
        "reason": text(),
    }
)
SOURCE = obj(
    {
        "kind": text(64),
        "operation": text(128),
        "adapter": text(128, nullable=True),
        "effects": array(text(256, pattern="^[a-z][a-z0-9_.-]*$")),
        "provenance_digest": {**DIGEST, "type": ["string", "null"]},
    }
)
CAPABILITY = obj(
    {
        "schema_version": {"const": "ordin.runtime_capability.v1"},
        "contract_id": text(67, pattern="^rc:[a-f0-9]{64}$"),
        "action_id": text(128, nullable=True),
        "action_digest": DIGEST,
        "decision": enum("allow", "warn", "ask", "block"),
        "risk": enum("low", "medium", "high", "critical", "unknown"),
        "grant_state": enum("eligible", "requires_approval", "diagnostic"),
        "filesystem": array(FILESYSTEM),
        "network": array(NETWORK),
        "tools": array(TOOL),
        "process": PROCESS,
        "privilege": PRIVILEGE,
        "credentials": array(CREDENTIAL),
        "unknowns": array(UNKNOWN),
        "source": SOURCE,
    }
)
SCHEMAS = {
    "runtime_capability": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://latentops.space/ordin/schemas/runtime-capability.v1.schema.json",
        "title": "Ordin runtime capability contract v1",
        **CAPABILITY,
    }
}
SHAPES = {
    "filesystem": FILESYSTEM,
    "network": NETWORK,
    "tool": TOOL,
    "process": PROCESS,
    "privilege": PRIVILEGE,
    "credential": CREDENTIAL,
    "unknown": UNKNOWN,
}
