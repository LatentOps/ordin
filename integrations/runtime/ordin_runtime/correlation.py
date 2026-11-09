"""Private, bounded event bindings owned by the trusted local collector.

Bindings are explicit, never guessed from an event's destination, process name,
numeric OCSF action_id, or timestamp. Checksums detect corruption, not tampering
by the owner. The collector must establish action attribution before registering.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ordin._private_storage import private_database
from ordin._runtime_json import canonical_json, digest, freeze
from ordin._runtime_schemas import DIGEST, IDENTIFIER
from ordin.runtime_contract import RuntimeCapabilityContract
from ordin.runtime_observation import RuntimeCorrelationError, RuntimeEvidenceSource
from ordin.schema import validate_instance

MAX_BINDINGS = 128
MAX_BINDING_BYTES = 4096
MAX_BINDING_LIFETIME_MS = 86_400_000


@dataclass(frozen=True)
class CorrelationBinding:
    action_id: str
    action_digest: str
    contract_id: str
    source: RuntimeEvidenceSource
    event_id_digest: str
    event_digest: str
    created_ms: int
    expires_ms: int

    def __post_init__(self) -> None:
        if not isinstance(self.source, RuntimeEvidenceSource) or self.source.backend != "openshell":
            raise ValueError("openshell_correlation_source_invalid")
        freeze(self.as_dict())
        if not isinstance(self.action_id, str) or not 1 <= len(self.action_id) <= 128:
            raise ValueError("openshell_correlation_action_invalid")
        if any(
            validate_instance(v, DIGEST)
            for v in (self.action_digest, self.event_id_digest, self.event_digest)
        ) or validate_instance(self.contract_id, IDENTIFIER):
            raise ValueError("openshell_correlation_digest_invalid")
        if not self.contract_id.startswith("rc:") or validate_instance(
            self.contract_id[3:], DIGEST
        ):
            raise ValueError("openshell_correlation_contract_invalid")
        if (
            type(self.created_ms) is not int
            or type(self.expires_ms) is not int
            or self.created_ms < 0
            or not 0 < self.expires_ms - self.created_ms <= MAX_BINDING_LIFETIME_MS
        ):
            raise ValueError("openshell_correlation_lifetime_invalid")

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "ordin.openshell_correlation.v1",
            "action_id": self.action_id,
            "action_digest": self.action_digest,
            "contract_id": self.contract_id,
            "source": self.source.as_dict(),
            "event_id_digest": self.event_id_digest,
            "event_digest": self.event_digest,
            "created_ms": self.created_ms,
            "expires_ms": self.expires_ms,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CorrelationBinding:
        if set(data) != {
            "schema_version",
            "action_id",
            "action_digest",
            "contract_id",
            "source",
            "event_id_digest",
            "event_digest",
            "created_ms",
            "expires_ms",
        } or (data["schema_version"] != "ordin.openshell_correlation.v1"):
            raise ValueError("openshell_correlation_record_invalid")
        return cls(
            **{k: v for k, v in data.items() if k not in {"schema_version", "source"}},
            source=RuntimeEvidenceSource(**data["source"]),
        )

    def require_match(
        self,
        contract: RuntimeCapabilityContract,
        source: RuntimeEvidenceSource,
        *,
        event_digest: str,
        event_time_ms: int,
        now_ms: int,
    ) -> None:
        if self.action_id != contract.action_id or self.action_digest != contract.action_digest:
            raise RuntimeCorrelationError("runtime_observation_action_mismatch")
        if self.contract_id != contract.contract_id:
            raise RuntimeCorrelationError("runtime_observation_contract_mismatch")
        if self.source.session_digest != source.session_digest:
            raise RuntimeCorrelationError("runtime_observation_session_mismatch")
        if self.source != source:
            raise RuntimeCorrelationError("runtime_observation_source_mismatch")
        if self.event_digest != event_digest:
            raise RuntimeCorrelationError("openshell_correlation_event_mismatch")
        if (
            type(now_ms) is not int
            or type(event_time_ms) is not int
            or not self.created_ms <= event_time_ms <= now_ms <= self.expires_ms
        ):
            raise RuntimeCorrelationError("openshell_correlation_stale")


class CorrelationStore:
    """Atomic SQLite writes with owner-only POSIX permissions and replay rejection."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def register(self, binding: CorrelationBinding) -> None:
        if not isinstance(binding, CorrelationBinding):
            raise ValueError("openshell_correlation_record_invalid")
        with private_database(self.path, "runtime") as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS event_bindings (event_id TEXT PRIMARY KEY, "
                "payload TEXT NOT NULL, checksum TEXT NOT NULL, consumed INTEGER NOT NULL)"
            )
            if db.execute(
                "SELECT 1 FROM event_bindings WHERE event_id=?", (binding.event_id_digest,)
            ).fetchone():
                raise RuntimeCorrelationError("runtime_observation_duplicate")
            if db.execute("SELECT COUNT(*) FROM event_bindings").fetchone()[0] >= MAX_BINDINGS:
                raise ValueError("openshell_correlation_capacity")
            packet = binding.as_dict()
            payload = canonical_json(packet)
            if len(payload.encode()) > MAX_BINDING_BYTES:
                raise ValueError("openshell_correlation_record_size")
            db.execute(
                "INSERT INTO event_bindings VALUES (?, ?, ?, 0)",
                (binding.event_id_digest, payload, digest(packet)),
            )

    def lookup(self, event_id_digest: str) -> CorrelationBinding | None:
        if validate_instance(event_id_digest, DIGEST):
            raise ValueError("openshell_correlation_digest_invalid")
        with private_database(self.path, "runtime", readonly=True) as db:
            row = db.execute(
                "SELECT payload, checksum, consumed FROM event_bindings WHERE event_id=?",
                (event_id_digest,),
            ).fetchone()
        if row is None:
            return None
        payload, checksum, consumed = row
        if (
            not isinstance(payload, str)
            or len(payload.encode()) > MAX_BINDING_BYTES
            or type(consumed) is not int
            or consumed not in {0, 1}
        ):
            raise ValueError("openshell_correlation_corrupt")
        try:
            packet = json.loads(payload)
            if digest(packet) != checksum:
                raise ValueError("openshell_correlation_corrupt")
            binding = CorrelationBinding.from_dict(packet)
        except (ValueError, TypeError, KeyError):
            raise ValueError("openshell_correlation_corrupt") from None
        if binding.event_id_digest != event_id_digest:
            raise ValueError("openshell_correlation_corrupt")
        if consumed:
            raise RuntimeCorrelationError("runtime_observation_duplicate")
        return binding

    def consume(self, binding: CorrelationBinding) -> None:
        with private_database(self.path, "runtime") as db:
            cursor = db.execute(
                "UPDATE event_bindings SET consumed=1 WHERE event_id=? "
                "AND checksum=? AND payload=? AND consumed=0",
                (
                    binding.event_id_digest,
                    digest(binding.as_dict()),
                    canonical_json(binding.as_dict()),
                ),
            )
            if cursor.rowcount != 1:
                raise RuntimeCorrelationError("runtime_observation_duplicate")
