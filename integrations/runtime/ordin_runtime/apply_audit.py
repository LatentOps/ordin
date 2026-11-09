"""Private hash-chained operator receipts beside Ordin's unchanged decision audit."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ordin._audit_storage import MAX_AUDIT_BYTES, locked_audit, load_audit_line
from ordin._runtime_json import MAX_RUNTIME_BYTES, canonical_json, digest

from .apply import PolicyApplyPreparation, PolicyApplyResult

MAX_APPLY_RECEIPTS = 4096


def with_apply_provenance(review, result: PolicyApplyResult):
    """Add digest linkage to the existing review/audit plane without weakening it."""
    from dataclasses import replace
    from ordin.audit import action_digest
    from ordin.provenance import ProvenanceRecord

    contract = result.preparation.plan.contract
    if (
        review.provenance is None
        or action_digest(review) != contract.action_digest
        or review.decision != contract.decision
        or review.risk != contract.risk
        or review.provenance.digest != contract.source.get("provenance_digest")
    ):
        raise ValueError("runtime_apply_review_mismatch")
    packet = result.preparation.as_dict()
    record = ProvenanceRecord(
        source="decision",
        kind="finding",
        code="runtime.policy." + result.status,
        action_id=review.action.action_id,
        metadata={
            "action_digest": contract.action_digest,
            "contract_id": contract.contract_id,
            "contract_digest": contract.digest,
            "plan_id": packet["plan_id"],
            "policy_digest": packet["policy_digest"],
            "request_id": packet["request_id"],
            "verification_digest": digest(packet["verification"]),
            "active_policy_digest": result.current.policy_digest if result.current else None,
            "mutation_attempted": result.mutation_attempted,
        },
    )
    return replace(review, provenance=review.provenance.append(record))


def _read_receipts(fd: int) -> list[dict[str, Any]]:
    records, previous = [], None
    with os.fdopen(os.dup(fd), "rb") as stream:
        stream.seek(0)
        while raw := stream.readline(MAX_RUNTIME_BYTES + 1):
            if len(raw) > MAX_RUNTIME_BYTES or not raw.endswith(b"\n"):
                raise ValueError("openshell_apply_audit_incomplete")
            record = load_audit_line(raw)
            material = {k: v for k, v in record.items() if k != "event_hash"}
            if (
                record.get("schema_version") != "ordin.openshell_apply_audit.v1"
                or record.get("previous_hash") != previous
                or record.get("event_hash") != digest(material)
            ):
                raise ValueError("openshell_apply_audit_corrupt")
            previous = record["event_hash"]
            records.append(record)
            if len(records) > MAX_APPLY_RECEIPTS:
                raise ValueError("openshell_apply_audit_capacity")
    return records


class PolicyApplyAudit:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def record(
        self,
        preparation: PolicyApplyPreparation,
        status: str,
        *,
        result: PolicyApplyResult | None = None,
    ) -> dict[str, Any]:
        if status not in {"attempted", "applied", "inconclusive", "unsupported"}:
            raise ValueError("openshell_apply_audit_status_invalid")
        packet = {
            "schema_version": "ordin.openshell_apply_audit.v1",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "code": "runtime.policy." + status,
            **preparation.as_dict(),
            "outcome": status,
            "mutation_attempted": result.mutation_attempted if result else None,
            "active_policy_digest": result.current.policy_digest
            if result and result.current
            else None,
        }
        with locked_audit(self.path) as fd:
            records = _read_receipts(fd)
            if len(records) >= MAX_APPLY_RECEIPTS:
                raise ValueError("openshell_apply_audit_capacity")
            packet["previous_hash"] = records[-1]["event_hash"] if records else None
            packet["event_hash"] = digest(packet)
            data = (canonical_json(packet) + "\n").encode()
            if len(data) > MAX_RUNTIME_BYTES or os.fstat(fd).st_size + len(data) > MAX_AUDIT_BYTES:
                raise ValueError("openshell_apply_audit_size")
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError("openshell_apply_audit_write_failed")
                view = view[written:]
            os.fsync(fd)
        return packet

    def verify(self, *, expected_last_hash: str | None = None) -> dict[str, Any]:
        with locked_audit(self.path) as fd:
            records = _read_receipts(fd)
        last_hash = records[-1]["event_hash"] if records else None
        if expected_last_hash is not None and last_hash != expected_last_hash:
            raise ValueError("openshell_apply_audit_checkpoint_mismatch")
        return {"ok": True, "events": len(records), "last_hash": last_hash}
