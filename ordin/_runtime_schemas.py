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

RESOURCE = obj({"type": text(64, pattern="^[a-z][a-z0-9_.-]*$"), "value": text()})
SOURCE_CONTEXT = obj(
    {
        "backend": IDENTIFIER,
        "session_digest": DIGEST,
        "sandbox_id": IDENTIFIER,
        "policy_digest": DIGEST,
    }
)
OBSERVATION_METADATA = obj(
    {
        "event_digest": DIGEST,
        "source_schema_version": text(64),
        "method": enum(
            "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE"
        ),
        "host": {**HOST, "type": "string"},
        "port": {**PORT, "type": "integer"},
        "path": text(),
        "binary": text(),
        "process_id": {"type": "integer", "minimum": 0},
        "request_id_digest": DIGEST,
    },
    required=[],
)
OBSERVATION = obj(
    {
        "schema_version": {"const": "ordin.runtime_observation.v1"},
        "observation_id": IDENTIFIER,
        "action_id": text(128),
        "action_digest": {**DIGEST, "type": ["string", "null"]},
        "contract_id": text(67, nullable=True, pattern="^rc:[a-f0-9]{64}$"),
        "backend": IDENTIFIER,
        "trust": enum("caller_asserted", "backend_observed", "backend_enforced"),
        "enforcement_point": enum(
            "filesystem", "network", "process", "credential", "tool", "sandbox", "unknown"
        ),
        "outcome": enum("allowed", "denied", "failed", "completed", "unknown"),
        "operation": text(128, pattern="^[a-z][a-z0-9_.-]*$"),
        "effects": array(text(256, pattern="^[a-z][a-z0-9_.-]*$")),
        "resources": array(RESOURCE),
        "reason_code": IDENTIFIER,
        "metadata": OBSERVATION_METADATA,
        "session_digest": {**DIGEST, "type": ["string", "null"]},
        "sandbox_id": {**IDENTIFIER, "type": ["string", "null"]},
        "policy_digest": {**DIGEST, "type": ["string", "null"]},
    }
)
OBSERVATION_HISTORY = obj(
    {
        "schema_version": {"const": "ordin.runtime_observation_history.v1"},
        "observations": array(OBSERVATION),
        "contracts": array(CAPABILITY, 32),
    }
)
SCHEMAS.update(
    {
        "runtime_observation": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "https://latentops.space/ordin/schemas/runtime-observation.v1.schema.json",
            "title": "Ordin runtime observation v1",
            **OBSERVATION,
        },
        "runtime_observation_history": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "https://latentops.space/ordin/schemas/runtime-observation-history.v1.schema.json",
            "title": "Ordin runtime observation history v1",
            **OBSERVATION_HISTORY,
        },
    }
)
SHAPES["runtime_source_context"] = SOURCE_CONTEXT
SHAPES["runtime_review_binding"] = obj(
    {
        "session_digest": DIGEST,
        "sequence": {"type": "integer", "minimum": 1},
        "epoch": {"type": "integer", "minimum": 0},
    }
)
RUNTIME_SESSION = obj(
    {
        "schema_version": {"const": "ordin.runtime_session.v1"},
        "identity_key": DIGEST,
        "configuration_digest": DIGEST,
        "sequence": {"type": "integer", "minimum": 0},
        "epoch": {"type": "integer", "minimum": 0},
        "sources": array(SOURCE_CONTEXT),
        "current_source": {**DIGEST, "type": ["string", "null"]},
        "bindings": array(
            obj(
                {"contract_id": text(67, pattern="^rc:[a-f0-9]{64}$"), "source_keys": array(DIGEST)}
            ),
            32,
        ),
        "history": OBSERVATION_HISTORY,
    }
)
SCHEMAS["runtime_session"] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://latentops.space/ordin/schemas/runtime-session.v1.schema.json",
    "title": "Ordin runtime session evidence sidecar v1",
    **RUNTIME_SESSION,
}
BOUNDARY = obj(
    {
        "schema_version": {"const": "ordin.runtime_capability_boundary.v1"},
        "boundary_id": IDENTIFIER,
        "filesystem": array(FILESYSTEM),
        "network": array(NETWORK),
        "tools": array(TOOL),
        "process": PROCESS,
        "privilege": PRIVILEGE,
        "credentials": array(CREDENTIAL),
        "filesystem_semantics": enum("exact", "lexical_prefix"),
        "runtime_filesystem_guarantees": {"type": "boolean"},
        "allow_any_executable": {"type": "boolean"},
    }
)
SCHEMAS["runtime_capability_boundary"] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://latentops.space/ordin/schemas/runtime-capability-boundary.v1.schema.json",
    "title": "Ordin runtime capability boundary v1",
    **BOUNDARY,
}
DELTA_VERIFICATION = obj(
    {
        "step": IDENTIFIER,
        "result": text(64),
        "reason_code": IDENTIFIER,
        "details": {"type": "object", "maxProperties": 32, "additionalProperties": True},
    }
)
DELTA = obj(
    {
        "schema_version": {"const": "ordin.capability_delta_proposal.v1"},
        "proposal_id": text(67, pattern="^dp:[a-f0-9]{64}$"),
        "action_id": text(128),
        "action_digest": DIGEST,
        "contract_id": text(67, pattern="^rc:[a-f0-9]{64}$"),
        "denial_observation_id": IDENTIFIER,
        "requested_delta": {"anyOf": [CAPABILITY, {"type": "null"}]},
        "reason_code": IDENTIFIER,
        "verification": array(DELTA_VERIFICATION, 8),
        "requires_human_approval": {"type": "boolean"},
        "status": enum("draft", "verified", "requires_approval", "rejected", "approved", "applied"),
    }
)
SCHEMAS["capability_delta_proposal"] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://latentops.space/ordin/schemas/capability-delta-proposal.v1.schema.json",
    "title": "Ordin capability delta proposal v1",
    **DELTA,
}

SHADOW_METRICS = obj(
    {
        name: {"type": "integer", "minimum": 0}
        for name in (
            "actions_reviewed",
            "contracts_generated",
            "contracts_fully_representable",
            "contracts_unsupported",
            "runtime_events_correlated",
            "correlation_mismatches",
            "observed_but_unpredicted_capabilities",
            "predicted_but_unused_capabilities",
            "would_deny_events",
            "compiler_widening_failures",
        )
    }
)
SHADOW_OUTCOMES = obj(
    {
        name: {"type": "integer", "minimum": 0}
        for name in (
            "within_boundary",
            "exceeds_boundary",
            "unsupported",
            "inconclusive",
        )
    }
)
SHADOW_EVENT = obj(
    {
        "observation_digest": DIGEST,
        "event_digest": {**DIGEST, "type": ["string", "null"]},
        "outcome": enum("allowed", "denied", "failed", "completed", "unknown"),
        "prediction": enum("predicted", "unpredicted", "inconclusive"),
        "policy_match": enum("within_policy", "outside_policy", "inconclusive"),
        "reason_code": IDENTIFIER,
    }
)
SHADOW_ACTION = obj(
    {
        "action_digest": DIGEST,
        "contract_id": text(67, pattern="^rc:[a-f0-9]{64}$"),
        "contract_digest": DIGEST,
        "review_decision": enum("allow", "warn", "ask", "block"),
        "risk": enum("low", "medium", "high", "critical", "unknown"),
        "policy_digest": {**DIGEST, "type": ["string", "null"]},
        "compilation_status": enum("success", "unsupported", "inconclusive"),
        "unsupported_fields": array(text(128)),
        "boundary_result": enum(
            "within_boundary", "exceeds_boundary", "unsupported", "inconclusive"
        ),
        "boundary_digest": DIGEST,
        "boundary_coverage": obj(
            {
                name: {"type": "boolean"}
                for name in (
                    "filesystem",
                    "network",
                    "tools",
                    "process",
                    "privilege",
                    "credentials",
                )
            }
        ),
        "mismatches": array(
            enum(
                "predicted_but_not_observed",
                "observed_but_not_predicted",
                "compiler_widening_detected",
                "runtime_denial_expected",
                "runtime_denial_unexpected",
                "unrepresentable_capability",
                "action_correlation_mismatch",
                "runtime_event_inconclusive",
            ),
            8,
        ),
        "events": array(SHADOW_EVENT),
    }
)
SCHEMAS["runtime_shadow_report"] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://latentops.space/ordin/schemas/runtime-shadow-report.v1.schema.json",
    "title": "Ordin runtime shadow report v1",
    **obj(
        {
            "schema_version": {"const": "ordin.runtime_shadow_report.v1"},
            "backend": IDENTIFIER,
            "mode": {"const": "shadow"},
            "metrics": SHADOW_METRICS,
            "boundary_outcomes": SHADOW_OUTCOMES,
            "actions": array(SHADOW_ACTION),
        }
    ),
}
