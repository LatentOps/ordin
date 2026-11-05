"""Bounded swarm event data; neither event hashes nor JSON authenticate a sender."""

from __future__ import annotations

from dataclasses import dataclass, fields
import hashlib
import json
import math
import re
from typing import Any, Mapping

from .models import SwarmIdentity, counter, identifier, timestamp

EVENT_KINDS = frozenset(
    {
        "proposed",
        "reviewed",
        "reserved",
        "committed",
        "forwarded",
        "completed",
        "observed",
        "failed",
        "denied",
        "canceled",
        "delegated",
        "message_sent",
        "message_received",
        "artifact_read",
        "artifact_write",
        "revoked",
    }
)
EVIDENCE_CLASSES = frozenset(
    {
        "caller_asserted",
        "host_authenticated",
        "backend_observed",
        "backend_enforced",
    }
)
ACTION_STAGES = frozenset(
    {
        "proposed",
        "reviewed",
        "reserved",
        "committed",
        "forwarded",
        "completed",
        "observed",
        "failed",
        "denied",
        "canceled",
    }
)
REVIEW_BOUND_STAGES = ACTION_STAGES - {"proposed", "reviewed"}
MAX_EVENT_BYTES = 65536
_HEX = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_IDENTITY_FIELDS = frozenset(field.name for field in fields(SwarmIdentity))


def _text(value: str, name: str, limit: int = 128) -> str:
    if type(value) is not str or not 1 <= len(value) <= limit or any(ord(c) < 32 for c in value):
        raise ValueError(f"invalid bounded {name}")
    return value


def _hex(value: str, name: str) -> str:
    if type(value) is not str or len(value) != 64 or _HEX.fullmatch(value) is None:
        raise ValueError(f"invalid {name}")
    return value


def _keys(value: Any, expected: frozenset[str]) -> dict[str, Any]:
    if type(value) is not dict or len(value) != len(expected):
        raise ValueError("invalid swarm event object shape")
    if any(type(key) is not str or len(key) > 128 for key in value):
        raise ValueError("invalid swarm event keys")
    if frozenset(value) != expected:
        raise ValueError("unknown or missing swarm event fields")
    return value


@dataclass(frozen=True, slots=True)
class EventRef:
    tenant_id: str
    swarm_id: str
    event_id: str

    def __post_init__(self) -> None:
        for name in ("tenant_id", "swarm_id", "event_id"):
            identifier(getattr(self, name), name)

    def as_dict(self) -> dict[str, str]:
        return {"tenant_id": self.tenant_id, "swarm_id": self.swarm_id, "event_id": self.event_id}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> EventRef:
        return cls(**_keys(value, frozenset({"tenant_id", "swarm_id", "event_id"})))


@dataclass(frozen=True, slots=True)
class SwarmEvent:
    event_id: str
    event_kind: str
    registry_id: str
    identity: SwarmIdentity
    source_id: str
    source_sequence: int
    timestamp: float
    evidence_class: str = "caller_asserted"
    confidence: float = 0.0
    action_id: str | None = None
    action_digest: str | None = None
    review_event_id: str | None = None
    parent_event_ids: tuple[EventRef, ...] = ()
    resource_digests: tuple[str, ...] = ()
    observation_digest: str | None = None
    observed_outcome: str | None = None

    def __post_init__(self) -> None:
        self._validated_bytes()

    def _validated_bytes(self) -> bytes:
        for name in ("event_id", "registry_id", "source_id"):
            identifier(getattr(self, name), name)
        if type(self.event_kind) is not str or self.event_kind not in EVENT_KINDS:
            raise ValueError("unknown swarm event kind")
        if type(self.evidence_class) is not str or self.evidence_class not in EVIDENCE_CLASSES:
            raise ValueError("unknown swarm evidence class")
        if type(self.identity) is not SwarmIdentity:
            raise ValueError("swarm event requires immutable identity data")
        self.identity.__post_init__()
        counter(self.source_sequence, "source_sequence")
        if self.source_sequence == 0:
            raise ValueError("source sequence must be positive")
        timestamp(self.timestamp)
        if (
            type(self.confidence) not in {int, float}
            or not 0 <= self.confidence <= 1
            or not math.isfinite(self.confidence)
        ):
            raise ValueError("invalid bounded event confidence")
        if (self.action_id is None) != (self.action_digest is None):
            raise ValueError("action identity requires its exact digest")
        if self.action_id is not None:
            _text(self.action_id, "action_id")
            if self.action_digest is None:
                raise ValueError("action identity requires its exact digest")
            _hex(self.action_digest, "action_digest")
        elif self.event_kind in ACTION_STAGES:
            raise ValueError("action stage requires action identity")
        if self.review_event_id is not None:
            identifier(self.review_event_id, "review_event_id")
        if self.event_kind in REVIEW_BOUND_STAGES and self.review_event_id is None:
            raise ValueError("action stage requires an exact reviewed-event reference")
        if self.event_kind not in REVIEW_BOUND_STAGES and self.review_event_id is not None:
            raise ValueError("unexpected reviewed-event reference")
        if type(self.parent_event_ids) is not tuple or len(self.parent_event_ids) > 8:
            raise ValueError("invalid bounded parent event collection")
        seen = set()
        for parent in self.parent_event_ids:
            if type(parent) is not EventRef:
                raise ValueError("parent references must be immutable scoped IDs")
            parent.__post_init__()
            if (parent.tenant_id, parent.swarm_id) != (
                self.identity.tenant_id,
                self.identity.swarm_id,
            ):
                raise ValueError("cross-tenant or cross-swarm parent reference")
            if parent.event_id == self.event_id or parent.event_id in seen:
                raise ValueError("self or duplicate parent event reference")
            seen.add(parent.event_id)
        if self.review_event_id is not None and self.review_event_id not in seen:
            raise ValueError("review reference must be an explicit causal parent")
        if type(self.resource_digests) is not tuple or len(self.resource_digests) > 64:
            raise ValueError("invalid bounded resource digest collection")
        for digest in self.resource_digests:
            _hex(digest, "resource_digest")
        if len(set(self.resource_digests)) != len(self.resource_digests):
            raise ValueError("duplicate resource digest")
        if self.evidence_class in {"backend_observed", "backend_enforced"}:
            if self.event_kind != "observed" or self.observation_digest is None:
                raise ValueError("runtime event requires an exact observed-receipt digest")
            _hex(self.observation_digest, "observation_digest")
            if type(self.observed_outcome) is not str or self.observed_outcome not in {
                "allowed",
                "denied",
                "failed",
                "completed",
                "unknown",
            }:
                raise ValueError("runtime event requires its exact reported outcome")
        elif self.observation_digest is not None or self.observed_outcome is not None:
            raise ValueError("unexpected runtime observation digest")
        try:
            raw = json.dumps(
                self.as_dict(),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        except UnicodeError:
            raise ValueError("swarm events require valid UTF-8") from None
        if len(raw) > MAX_EVENT_BYTES:
            raise ValueError("swarm event byte limit exceeded")
        return raw

    @property
    def digest(self) -> str:
        return hashlib.sha256(b"ordin.swarm_event.v1\0" + self._validated_bytes()).hexdigest()

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "ordin.swarm_event.v1",
            "event_id": self.event_id,
            "event_kind": self.event_kind,
            "registry_id": self.registry_id,
            "identity": self.identity.as_dict(),
            "source_id": self.source_id,
            "source_sequence": self.source_sequence,
            "timestamp": self.timestamp,
            "evidence_class": self.evidence_class,
            "confidence": self.confidence,
            "action_id": self.action_id,
            "action_digest": self.action_digest,
            "review_event_id": self.review_event_id,
            "parent_event_ids": [parent.as_dict() for parent in self.parent_event_ids],
            "resource_digests": list(self.resource_digests),
            "observation_digest": self.observation_digest,
            "observed_outcome": self.observed_outcome,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> SwarmEvent:
        expected = frozenset(field.name for field in fields(cls)) | {"schema_version"}
        value = _keys(value, expected)
        if (
            type(value["schema_version"]) is not str
            or value["schema_version"] != "ordin.swarm_event.v1"
        ):
            raise ValueError("unsupported swarm event version")
        identity = SwarmIdentity(**_keys(value["identity"], _IDENTITY_FIELDS))
        parents = value["parent_event_ids"]
        resources = value["resource_digests"]
        if (
            type(parents) is not list
            or len(parents) > 8
            or type(resources) is not list
            or len(resources) > 64
        ):
            raise ValueError("invalid bounded swarm event collections")
        return cls(
            **{
                key: item
                for key, item in value.items()
                if key not in {"schema_version", "identity", "parent_event_ids", "resource_digests"}
            },
            identity=identity,
            parent_event_ids=tuple(EventRef.from_dict(parent) for parent in parents),
            resource_digests=tuple(resources),
        )

    @classmethod
    def from_json(cls, raw: str | bytes) -> SwarmEvent:
        if type(raw) not in {str, bytes} or len(raw) > MAX_EVENT_BYTES:
            raise ValueError("invalid bounded swarm event JSON")
        try:
            encoded = raw.encode("utf-8") if isinstance(raw, str) else raw
            if len(encoded) > MAX_EVENT_BYTES:
                raise ValueError("swarm event byte limit exceeded")
            text = encoded.decode("utf-8")

            def pairs(items):
                if len(items) > 32:
                    raise ValueError("swarm event object property limit exceeded")
                result = {}
                for key, value in items:
                    if key in result:
                        raise ValueError("duplicate swarm event JSON key")
                    result[key] = value
                return result

            def constant(_):
                raise ValueError("non-finite swarm event JSON number")

            value = json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
        except (UnicodeError, ValueError, RecursionError):
            raise ValueError("invalid bounded swarm event JSON") from None
        return cls.from_dict(value)
