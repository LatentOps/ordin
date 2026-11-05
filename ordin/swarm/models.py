"""Immutable enrollment data. JSON is inspectable data, never identity authority."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import math
import re
from typing import Any, Mapping

from ordin.schema import validate_named_schema

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}\Z", re.ASCII)
_STATES = frozenset(
    {"observe_only", "mediated", "physically_enforced", "unsupported", "coverage_gap"}
)
_MODES = frozenset({"observe", "intercept", "enforce", "uncovered"})


def identifier(value: str, name: str) -> str:
    if type(value) is not str or len(value) > 128 or _ID.fullmatch(value) is None:
        raise ValueError(f"{name} must be a bounded host identifier")
    return value


def counter(value: int, name: str) -> int:
    if type(value) is not int or not 0 <= value < 2**63:
        raise ValueError(f"{name} must be a nonnegative bounded integer")
    return value


def timestamp(value: float) -> float:
    if type(value) not in {int, float} or not 0 <= value <= 1e18 or not math.isfinite(value):
        raise ValueError("host clock must provide finite nonnegative monotonic seconds")
    return float(value)


@dataclass(frozen=True, slots=True)
class SwarmIdentity:
    tenant_id: str
    swarm_id: str
    agent_id: str
    runtime_id: str
    session_id: str
    generation: int
    policy_epoch: int
    parent_agent_id: str | None = None
    parent_generation: int | None = None
    task_id: str | None = None
    delegation_id: str | None = None

    def __post_init__(self) -> None:
        for name in ("tenant_id", "swarm_id", "agent_id", "runtime_id", "session_id"):
            identifier(getattr(self, name), name)
        for name in ("parent_agent_id", "task_id", "delegation_id"):
            value = getattr(self, name)
            if value is not None:
                identifier(value, name)
        counter(self.generation, "generation")
        counter(self.policy_epoch, "policy_epoch")
        if self.generation == 0:
            raise ValueError("generation must be positive")
        if (self.parent_agent_id is None) != (self.parent_generation is None):
            raise ValueError("parent identity requires an exact parent generation")
        if self.parent_generation is not None:
            counter(self.parent_generation, "parent_generation")
            if self.parent_generation == 0 or self.parent_agent_id == self.agent_id:
                raise ValueError("invalid parent identity")
        if self.delegation_id is not None and self.parent_agent_id is None:
            raise ValueError("delegation identity requires a parent")

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class CoverageEntry:
    capability: str
    route: str
    resource: str
    boundary_id: str
    state: str

    def __post_init__(self) -> None:
        for name in ("capability", "route", "boundary_id"):
            identifier(getattr(self, name), name)
        if (
            type(self.resource) is not str
            or not 1 <= len(self.resource) <= 512
            or any(ord(c) < 32 or ord(c) == 127 for c in self.resource)
        ):
            raise ValueError("resource must be bounded, explicit and free of control characters")
        if type(self.state) is not str or self.state not in _STATES:
            raise ValueError("unknown capability coverage state")

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class CoverageManifest:
    mode: str = "uncovered"
    entries: tuple[CoverageEntry, ...] = ()

    def __post_init__(self) -> None:
        if (
            type(self.mode) is not str
            or self.mode not in _MODES
            or type(self.entries) is not tuple
            or len(self.entries) > 64
        ):
            raise ValueError("invalid or oversized coverage manifest")
        seen = set()
        for entry in self.entries:
            if type(entry) is not CoverageEntry:
                raise ValueError("coverage entries must be immutable values")
            entry.__post_init__()
            key = (entry.capability, entry.route, entry.resource)
            if key in seen:
                raise ValueError("duplicate capability coverage")
            seen.add(key)
            if self.mode == "uncovered" and entry.state not in {"unsupported", "coverage_gap"}:
                raise ValueError("uncovered enrollment cannot claim mediation")
            if self.mode == "observe" and entry.state in {"mediated", "physically_enforced"}:
                raise ValueError("observation cannot claim interception")
            if self.mode == "intercept" and entry.state == "physically_enforced":
                raise ValueError("interception cannot claim physical enforcement")

    def as_dict(self) -> dict[str, Any]:
        return {"mode": self.mode, "entries": [entry.as_dict() for entry in self.entries]}


@dataclass(frozen=True, slots=True)
class SwarmContext:
    registry_id: str
    identity: SwarmIdentity
    coverage: CoverageManifest
    enrolled_at: float

    def __post_init__(self) -> None:
        self._validated_bytes()

    def _validated_bytes(self) -> bytes:
        identifier(self.registry_id, "registry_id")
        if type(self.identity) is not SwarmIdentity or type(self.coverage) is not CoverageManifest:
            raise ValueError("context requires immutable identity and coverage")
        self.identity.__post_init__()
        self.coverage.__post_init__()
        timestamp(self.enrolled_at)
        try:
            raw = json.dumps(
                self.as_dict(),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        except UnicodeError:
            raise ValueError("swarm context must be valid UTF-8") from None
        if len(raw) > 65536:
            raise ValueError("swarm context exceeds the 64 KiB encoded limit")
        return raw

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "ordin.swarm_context.v1",
            "registry_id": self.registry_id,
            "identity": self.identity.as_dict(),
            "coverage": self.coverage.as_dict(),
            "enrolled_at": self.enrolled_at,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> SwarmContext:
        if type(value) is not dict or len(value) != 5:
            raise ValueError("swarm context must be a JSON object")
        identity = value.get("identity")
        manifest = value.get("coverage")
        if (
            type(identity) is not dict
            or len(identity) > 11
            or type(manifest) is not dict
            or len(manifest) > 2
        ):
            raise ValueError("invalid bounded identity or coverage")
        entries = manifest.get("entries")
        if type(entries) is not list or len(entries) > 64:
            raise ValueError("invalid bounded coverage entries")
        if any(type(entry) is not dict or len(entry) != 5 for entry in entries):
            raise ValueError("invalid bounded coverage entry")
        for container in (value, identity, manifest, *entries):
            if any(type(item) is str and len(item) > 512 for item in container.values()):
                raise ValueError("oversized swarm context field")
        errors = validate_named_schema("swarm_context", value)
        if errors:
            raise ValueError("invalid swarm context")
        return cls(
            registry_id=value["registry_id"],
            identity=SwarmIdentity(**value["identity"]),
            coverage=CoverageManifest(
                manifest["mode"], tuple(CoverageEntry(**entry) for entry in manifest["entries"])
            ),
            enrolled_at=value["enrolled_at"],
        )
