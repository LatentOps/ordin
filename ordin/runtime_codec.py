"""Bounded data-only loading for runtime CLI artifacts; no action is re-reviewed."""

from __future__ import annotations

import json
import math
import os
import stat
from pathlib import Path
from typing import Any, Mapping

from ._json_contracts import load_configuration
from ._runtime_json import MAX_RUNTIME_BYTES
from .action import ActionEnvelope, ActionResource, ActionReview
from .execution import ExecutionCapabilityProfile
from .policy import validate_decision
from .provenance import DecisionProvenance, ProvenanceRecord, ProvenanceResource
from .schema import validate_named_schema


def read_runtime_json(path: str | Path) -> dict[str, Any]:
    """Read an explicit local artifact. Errors never echo rejected private input."""
    try:
        return load_configuration(path, label="runtime input", maximum=MAX_RUNTIME_BYTES)
    except (ValueError, TypeError, OSError):
        raise ValueError("runtime_input_invalid") from None


def read_private_runtime_json(path: str | Path) -> dict[str, Any]:
    """Explicit host-owned reporting configuration/evidence; never agent input.

    Owner-only POSIX permissions and a protected directory are local trust
    controls, not authentication against a compromised owner or host process.
    """
    target = Path(path).absolute()
    parent = target.parent.stat()
    if os.name == "posix" and (parent.st_uid != os.geteuid() or parent.st_mode & 0o022):
        raise ValueError("runtime_private_input_directory")
    descriptor = os.open(
        target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    )
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or target.is_symlink()
            or info.st_size > MAX_RUNTIME_BYTES
        ):
            raise ValueError("runtime_private_input_invalid")
        if os.name == "posix" and (info.st_uid != os.geteuid() or info.st_mode & 0o077):
            raise ValueError("runtime_private_input_permissions")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(MAX_RUNTIME_BYTES + 1)
        if len(raw) > MAX_RUNTIME_BYTES:
            raise ValueError("runtime_private_input_size")

        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("runtime_private_input_duplicate_key")
                result[key] = value
            return result

        packet = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
        pending = [(packet, 0)]
        while pending:
            value, depth = pending.pop()
            if isinstance(value, float) and not math.isfinite(value):
                raise ValueError("runtime_private_input_nonfinite")
            if isinstance(value, (dict, list)):
                if depth > 32:
                    raise ValueError("runtime_private_input_depth")
                pending.extend(
                    (item, depth + 1)
                    for item in (value.values() if isinstance(value, dict) else value)
                )
        if not isinstance(packet, dict):
            raise ValueError("runtime_private_input_object_required")
        return packet
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ValueError("runtime_private_input_invalid") from None
    finally:
        os.close(descriptor)


def action_review_from_dict(payload: Mapping[str, Any]) -> ActionReview:
    """Decode the existing v1 review without changing its wire contract or semantics.

    This validates shape, not authenticity. Hosts must protect reviewed artifacts.
    Runtime capability derivation consumes the resulting review directly; it does
    not rerun adapters with potentially different policy, history, or context.
    """
    if not isinstance(payload, Mapping) or validate_named_schema("action_review", payload):
        raise ValueError("runtime_review_invalid")
    graphql_fields = 0
    if payload.get("adapter") == "network.graphql":
        from ._graphql_authority import MAX_GRAPHQL_NODES

        graphql_fields = sum(r["type"] == "graphql_field" for r in payload["resources"])
        if graphql_fields > MAX_GRAPHQL_NODES:
            raise ValueError("runtime_review_collection_size")
    for name, maximum in (
        ("reasons", 512),
        ("effects", 128),
        ("resources", 128 + graphql_fields),
        ("trajectory_categories", 128),
        ("policy_matches", 256),
    ):
        if len(payload.get(name, ())) > maximum:
            raise ValueError("runtime_review_collection_size")
    provenance = None
    material = payload.get("provenance")
    if material is not None:
        records = []
        for row in material["records"]:
            arguments = {k: v for k, v in row.items() if k != "resource"}
            arguments["matched_indices"] = tuple(row["matched_indices"])
            arguments["resource"] = (
                ProvenanceResource(**row["resource"]) if row["resource"] else None
            )
            records.append(ProvenanceRecord(**arguments))
        provenance = DecisionProvenance(
            tuple(records),
            validate_decision(material["final_decision"]),
            material["final_risk"],
            material["schema_version"],
        )
        if (
            provenance.final_decision != payload["decision"]
            or provenance.final_risk != payload["risk"]
        ):
            raise ValueError("runtime_review_provenance_mismatch")
    return ActionReview(
        action=ActionEnvelope.from_dict(payload["action"]),
        decision=validate_decision(payload["decision"]),
        risk=payload["risk"],
        reasons=list(payload["reasons"]),
        safer_next_step=payload["safer_next_step"],
        effects=list(payload["effects"]),
        resources=[ActionResource(**r) for r in payload["resources"]],
        adapter=payload["adapter"],
        capabilities=ExecutionCapabilityProfile.from_dict(payload["capabilities"])
        if payload["capabilities"] is not None
        else None,
        provenance=provenance,
        intent_alignment=payload["intent_alignment"],
        trajectory_categories=list(payload["trajectory_categories"]),
        policy=dict(payload["policy"]) if payload.get("policy") else None,
        policy_matches=[dict(item) for item in payload.get("policy_matches", ())],
    )
