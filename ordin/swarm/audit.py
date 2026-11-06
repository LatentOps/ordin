"""Bounded privacy-first diagnostics. Audit data never grants execution authority."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import time
from typing import Any, Callable
from uuid import uuid4

from ordin._private_storage import private_database
from ordin._runtime_json import digest

from .coordinator_store import decode, encode
from .events import _hex
from .models import identifier, timestamp

ZERO = "0" * 64
KINDS = frozenset(
    {
        "decision",
        "admission",
        "broker_result",
        "incident",
        "risk_signal",
        "retention",
        "legacy_review",
        "legacy_observation",
    }
)
EVIDENCE = frozenset({"intent", "reported", "observed", "unknown", "diagnostic"})
STATES = frozenset(
    {
        "reviewed",
        "reserved",
        "forwarded",
        "completed",
        "denied",
        "canceled",
        "unknown",
        "paused",
        "revoked",
        "quarantined",
        "resumed",
        "swept",
        "risk_reported",
    }
)
SCHEMA = (
    "CREATE TABLE audit_meta (singleton INTEGER PRIMARY KEY CHECK(singleton=1), data TEXT NOT NULL, checksum TEXT NOT NULL)",
    "CREATE TABLE audit_events (sequence INTEGER PRIMARY KEY CHECK(sequence>0), admitted_at REAL NOT NULL, payload TEXT NOT NULL, event_hash TEXT NOT NULL UNIQUE)",
)


@dataclass(frozen=True, slots=True)
class SwarmAuditPolicy:
    maximum_events: int = 256
    retention_seconds: float = 3600
    maximum_entities: int = 256

    def __post_init__(self):
        if (
            type(self.maximum_events) is not int
            or not 1 <= self.maximum_events <= 4096
            or type(self.maximum_entities) is not int
            or not 1 <= self.maximum_entities <= 4096
            or not 1 <= timestamp(self.retention_seconds) <= 365 * 86400
        ):
            raise ValueError("bounded tenant audit retention required")

    @property
    def digest(self):
        self.__post_init__()
        return digest([self.maximum_events, self.retention_seconds, self.maximum_entities])


class TenantRedactor:
    """Protected secret key prevents dictionary attacks on common paths/URLs."""

    def __init__(self, key: bytes, tenant_id: str):
        if type(key) is not bytes or not 32 <= len(key) <= 64:
            raise ValueError("protected 256-bit or stronger privacy key required")
        identifier(tenant_id, "tenant_id")
        self._key = hmac.digest(key, b"ordin.swarm.privacy.v1\0" + tenant_id.encode(), "sha256")
        self.tenant_ref = self.ref("tenant", tenant_id)
        self.key_ref = self.ref("privacy_key", "version-1")

    def ref(self, domain: str, value: Any) -> str:
        identifier(domain, "privacy_domain")
        raw = encode({"value": value}, 65536).encode("utf-8")
        return (
            "hmac:" + hmac.new(self._key, domain.encode() + b"\0" + raw, hashlib.sha256).hexdigest()
        )

    def seal(self, value: Any) -> str:
        return hmac.new(
            self._key, b"audit_meta\0" + encode(value).encode(), hashlib.sha256
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class SwarmAuditVerification:
    valid: bool
    first_sequence: int
    tail_sequence: int
    tail_hash: str
    checkpoint_status: str
    proof_gaps: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "ordin.swarm_audit_verification.v1",
            "valid": self.valid,
            "first_sequence": self.first_sequence,
            "tail_sequence": self.tail_sequence,
            "tail_hash": self.tail_hash,
            "checkpoint_status": self.checkpoint_status,
            "proof_gaps": list(self.proof_gaps),
            "owner_rewrite_possible": True,
            "execution_authority": False,
        }


def verify_swarm_audit(
    bundle: dict[str, Any], checkpoint: dict[str, Any] | None = None
) -> SwarmAuditVerification:
    """Verify bounded data, not identity or runtime evidence; anchor trust is external."""
    errors = []
    try:
        from ordin.schema import validate_named_schema

        if validate_named_schema("swarm_audit_bundle", bundle):
            raise ValueError("audit.bundle_shape")
        encode(bundle, 8 * 1024 * 1024)
        first, tail, head = bundle["first_sequence"], bundle["tail_sequence"], bundle["base_hash"]
        records = bundle["events"]
        if len(records) != tail - first + 1:
            raise ValueError("audit.sequence_gap")
        hashes = {first - 1: head}
        for sequence, event in enumerate(records, first):
            material = {key: value for key, value in event.items() if key != "event_hash"}
            if (
                bundle["scope_ref"] is not None
                and event["refs"].get("scope") != bundle["scope_ref"]
            ):
                raise ValueError("audit.foreign_scope_event")
            if (
                event["sequence"] != sequence
                or event["previous_hash"] != head
                or digest(material) != event["event_hash"]
            ):
                raise ValueError("audit.chain_mismatch")
            head = hashes[sequence] = event["event_hash"]
        if head != bundle["tail_hash"]:
            raise ValueError("audit.tail_mismatch")
        status = "not_supplied"
        if checkpoint is not None:
            if (
                validate_named_schema("swarm_audit_checkpoint", checkpoint)
                or checkpoint["journal_ref"] != bundle["journal_ref"]
                or checkpoint["tenant_ref"] != bundle["tenant_ref"]
                or checkpoint["scope_ref"] != bundle["scope_ref"]
            ):
                raise ValueError("audit.checkpoint_domain_mismatch")
            anchor = checkpoint["tail_sequence"]
            if anchor > tail:
                raise ValueError("audit.truncated_before_checkpoint")
            if anchor < first - 1:
                status = "outside_retention_unknown"
                errors.append("audit.checkpoint_outside_retention")
            elif hashes.get(anchor) != checkpoint["tail_hash"]:
                raise ValueError("audit.checkpoint_mismatch")
            else:
                status = "matches_supplied_anchor"
        gaps = ["audit.owner_can_rewrite_unanchored_history"]
        if first > 1:
            gaps.append("audit.retained_prefix_unavailable")
        return SwarmAuditVerification(
            not errors, first, tail, head, status, tuple([*errors, *gaps])
        )
    except (ValueError, KeyError, TypeError, RecursionError):
        return SwarmAuditVerification(
            False, 0, 0, ZERO, "invalid", ("audit.invalid_or_corrupt_export",)
        )


class SwarmAuditJournal:
    """A private tenant journal with explicit initialization and bounded retention."""

    def __init__(
        self,
        path: str | Path,
        *,
        key: bytes,
        tenant_id: str,
        operator: object,
        policy: SwarmAuditPolicy = SwarmAuditPolicy(),
        clock: Callable[[], float] = time.time,
        create: bool = False,
    ):
        if (
            type(operator) is not object
            or type(policy) is not SwarmAuditPolicy
            or not callable(clock)
            or type(create) is not bool
        ):
            raise ValueError("protected tenant audit configuration required")
        self.path, self.redactor = Path(path).absolute(), TenantRedactor(key, tenant_id)
        self._operator, self.policy, self._clock = operator, policy, clock
        self._policy_digest = policy.digest
        if create:
            descriptor = os.open(
                self.path, os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600
            )
            os.close(descriptor)
            with private_database(self.path, "swarm_audit", create=False) as connection:
                for statement in SCHEMA:
                    connection.execute(statement)
                meta = {
                    "version": 1,
                    "tenant_ref": self.redactor.tenant_ref,
                    "key_ref": self.redactor.key_ref,
                    "journal_ref": self.redactor.ref("journal", uuid4().hex),
                    "scope_ref": None,
                    "policy_digest": policy.digest,
                    "first_sequence": 1,
                    "tail_sequence": 0,
                    "base_hash": ZERO,
                    "tail_hash": ZERO,
                    "last_now": timestamp(clock()),
                    "entities": [],
                }
                connection.execute(
                    "INSERT INTO audit_meta VALUES(1,?,?)", (encode(meta), self.redactor.seal(meta))
                )
        self._identity = self.path.stat().st_dev, self.path.stat().st_ino
        with private_database(self.path, "swarm_audit", create=False) as connection:
            self._read(connection)

    def _check(self, operator):
        if operator is not self._operator or self.policy.digest != self._policy_digest:
            raise ValueError("original tenant audit operator required")

    def _read(self, connection):
        if (self.path.stat().st_dev, self.path.stat().st_ino) != self._identity:
            raise ValueError("audit.file_identity_changed")
        actual = {
            row[0]: " ".join(row[1].lower().split())
            for row in connection.execute(
                "SELECT name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' AND type='table'"
            )
        }
        if actual != {
            statement.split()[2]: " ".join(statement.lower().split()) for statement in SCHEMA
        }:
            raise ValueError("audit.schema_changed")
        rows = connection.execute("SELECT data,checksum FROM audit_meta").fetchall()
        if len(rows) != 1:
            raise ValueError("audit.meta_missing")
        meta = decode(rows[0][0])
        if (
            not hmac.compare_digest(self.redactor.seal(meta), rows[0][1])
            or meta["tenant_ref"] != self.redactor.tenant_ref
            or meta["key_ref"] != self.redactor.key_ref
            or meta["policy_digest"] != self._policy_digest
            or meta["version"] != 1
        ):
            raise ValueError("audit.integrity_or_key_mismatch")
        if (
            connection.execute("SELECT count(*) FROM audit_events").fetchone()[0]
            > self.policy.maximum_events
        ):
            raise ValueError("audit.history_capacity_changed")
        events = []
        for sequence, admitted, raw, checksum in connection.execute(
            "SELECT sequence,admitted_at,payload,event_hash FROM audit_events ORDER BY sequence"
        ):
            event = decode(raw, 65536)
            if (event.get("sequence"), event.get("admitted_at"), event.get("event_hash")) != (
                sequence,
                admitted,
                checksum,
            ):
                raise ValueError("audit.index_changed")
            events.append(event)
        bundle = self._bundle(meta, events)
        if not verify_swarm_audit(bundle).valid:
            raise ValueError("audit.history_invalid")
        return meta, events

    @staticmethod
    def _bundle(meta, events):
        return {
            "schema_version": "ordin.swarm_audit_bundle.v1",
            **{
                key: meta[key]
                for key in (
                    "tenant_ref",
                    "journal_ref",
                    "scope_ref",
                    "first_sequence",
                    "tail_sequence",
                    "base_hash",
                    "tail_hash",
                )
            },
            "events": events,
            "privacy": "tenant_keyed_hmac_metadata",
            "execution_authority": False,
        }

    def bind_scope(self, scope_key: str, *, operator: object):
        self._check(operator)
        selected = self.redactor.ref("scope", scope_key)
        with private_database(self.path, "swarm_audit", create=False) as connection:
            meta, _ = self._read(connection)
            if meta["scope_ref"] != selected:
                if meta["scope_ref"] is not None or meta["tail_sequence"] != 0:
                    raise ValueError("audit.scope_rebinding_forbidden")
                meta["scope_ref"] = selected
                self._save(connection, meta)

    def _save(self, connection, meta):
        connection.execute(
            "UPDATE audit_meta SET data=?,checksum=? WHERE singleton=1",
            (encode(meta), self.redactor.seal(meta)),
        )

    def _append(
        self,
        *,
        kind: str,
        state: str,
        evidence: str,
        refs: dict[str, Any],
        facts: dict[str, Any],
        operator: object,
    ):
        self._check(operator)
        if kind not in KINDS or state not in STATES or evidence not in EVIDENCE:
            raise ValueError("audit.closed_event_vocabulary")
        refs, facts = decode(encode(refs, 65536), 65536), decode(encode(facts, 65536), 65536)
        with private_database(self.path, "swarm_audit", create=False) as connection:
            now = timestamp(self._clock())
            meta, events = self._read(connection)
            if now < meta["last_now"]:
                raise ValueError("audit.clock_rollback")
            pseudonyms = {name: self.redactor.ref(name, value) for name, value in refs.items()}
            if meta["scope_ref"] is not None and pseudonyms.get("scope") != meta["scope_ref"]:
                raise ValueError("audit.scoped_producer_required")
            if len(set(pseudonyms.values())) > self.policy.maximum_entities:
                raise ValueError("audit.entity_cardinality_limit")
            sequence = meta["tail_sequence"] + 1
            event = {
                "schema_version": "ordin.swarm_audit_event.v1",
                "sequence": sequence,
                "admitted_at": now,
                "kind": kind,
                "state": state,
                "evidence": evidence,
                "refs": pseudonyms,
                "facts": facts,
                "previous_hash": meta["tail_hash"],
                "execution_authority": False,
            }
            event["event_hash"] = digest(event)
            from ordin.schema import validate_named_schema

            if validate_named_schema("swarm_audit_event", event):
                raise ValueError("audit.invalid_event")
            connection.execute(
                "INSERT INTO audit_events VALUES(?,?,?,?)",
                (sequence, now, encode(event, 65536), event["event_hash"]),
            )
            if sequence > 2**53 - 1:
                raise ValueError("audit.sequence_limit")
            meta.update(tail_sequence=sequence, tail_hash=event["event_hash"], last_now=now)
            self._trim(connection, meta, [*events, event], now)
            self._save(connection, meta)
            return event

    def _trim(self, connection, meta, events, now):
        remove = [
            row
            for index, row in enumerate(events)
            if row["admitted_at"] < now - self.policy.retention_seconds
            or index < len(events) - self.policy.maximum_events
        ]
        cut = len(remove)
        while (
            cut < len(events)
            and len({value for row in events[cut:] for value in row["refs"].values()})
            > self.policy.maximum_entities
        ):
            cut += 1
        remove = events[:cut]
        if remove:
            last = remove[-1]
            connection.execute("DELETE FROM audit_events WHERE sequence<=?", (last["sequence"],))
            meta["first_sequence"], meta["base_hash"] = last["sequence"] + 1, last["event_hash"]
        remaining = events[cut:]
        meta["entities"] = sorted({value for row in remaining for value in row["refs"].values()})

    def export(self, *, operator: object):
        return self.sweep(operator=operator)

    def checkpoint(self, *, operator: object):
        bundle = self.export(operator=operator)
        return {
            "schema_version": "ordin.swarm_audit_checkpoint.v1",
            **{
                key: bundle[key]
                for key in ("tenant_ref", "journal_ref", "scope_ref", "tail_sequence", "tail_hash")
            },
            "execution_authority": False,
        }

    def sweep(self, *, operator: object):
        self._check(operator)
        with private_database(self.path, "swarm_audit", create=False) as connection:
            now = timestamp(self._clock())
            meta, events = self._read(connection)
            if now < meta["last_now"]:
                raise ValueError("audit.clock_rollback")
            self._trim(connection, meta, events, now)
            meta["last_now"] = now
            self._save(connection, meta)
            return self._bundle(
                meta, [row for row in events if row["sequence"] >= meta["first_sequence"]]
            )
