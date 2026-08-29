from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Literal, Mapping, get_args

from . import PROVENANCE_SCHEMA_VERSION
from .policy import Decision, validate_decision


ProvenanceSource = Literal[
    "adapter",
    "semantic",
    "risk_rule",
    "context",
    "intent",
    "observation",
    "temporal_policy",
    "action_policy",
    "decision",
]
ProvenanceKind = Literal["finding", "effect", "resource", "rule", "observation", "merge"]
MAX_PROVENANCE_RECORDS = 512
MAX_PROVENANCE_TEXT = 32768
MAX_PROVENANCE_CODE = 256
MAX_PROVENANCE_METADATA = 64
MAX_PROVENANCE_INDICES = 32
VALID_RISKS = frozenset(("unknown", "low", "medium", "high", "critical"))
VALID_PROVENANCE_SOURCES = frozenset(get_args(ProvenanceSource))
VALID_PROVENANCE_KINDS = frozenset(get_args(ProvenanceKind))
RESOURCE_TYPE_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]*$")


@dataclass(frozen=True)
class ProvenanceResource:
    type: str
    value: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.type, str)
            or not self.type
            or len(self.type) > 64
            or RESOURCE_TYPE_PATTERN.fullmatch(self.type) is None
        ):
            raise ValueError(
                "provenance resource type must be a valid 1 to 64 character identifier"
            )
        if not isinstance(self.value, str) or not self.value:
            raise ValueError("provenance resource value must be non-empty text")
        if len(self.value) > MAX_PROVENANCE_TEXT:
            raise ValueError("provenance resource value is too long")

    def as_dict(self) -> dict[str, str]:
        return {"type": self.type, "value": self.value}

    def redacted(self) -> "ProvenanceResource":
        digest = hashlib.sha256(self.value.encode("utf-8")).hexdigest()
        return ProvenanceResource(type=self.type, value=f"sha256:{digest}")


@dataclass(frozen=True)
class ProvenanceRecord:
    source: ProvenanceSource
    kind: ProvenanceKind
    code: str
    summary: str | None = None
    decision: Decision | None = None
    risk: str | None = None
    effect: str | None = None
    resource: ProvenanceResource | None = None
    rule_id: str | None = None
    action_id: str | None = None
    category: str | None = None
    matched_indices: tuple[int, ...] = ()
    metadata: Mapping[str, str | int | bool | None] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.source not in VALID_PROVENANCE_SOURCES:
            raise ValueError(f"unsupported provenance source: {self.source!r}")
        if self.kind not in VALID_PROVENANCE_KINDS:
            raise ValueError(f"unsupported provenance kind: {self.kind!r}")
        if self.decision is not None:
            validate_decision(self.decision)
        if not self.code or len(self.code) > MAX_PROVENANCE_CODE:
            raise ValueError(f"provenance code must contain 1 to {MAX_PROVENANCE_CODE} characters")
        for name, text_value in (
            ("summary", self.summary),
            ("effect", self.effect),
            ("rule_id", self.rule_id),
            ("action_id", self.action_id),
            ("category", self.category),
        ):
            if text_value is not None and (
                not isinstance(text_value, str) or len(text_value) > MAX_PROVENANCE_TEXT
            ):
                raise ValueError(f"provenance {name} is invalid or too long")
        if self.risk is not None and self.risk not in VALID_RISKS:
            raise ValueError(f"unsupported provenance risk: {self.risk!r}")
        if len(self.matched_indices) > MAX_PROVENANCE_INDICES:
            raise ValueError("provenance matched_indices is too large")
        if any(
            not isinstance(index, int) or isinstance(index, bool) or index < 0
            for index in self.matched_indices
        ):
            raise ValueError("provenance matched_indices must contain non-negative integers")
        if not isinstance(self.metadata, Mapping) or len(self.metadata) > MAX_PROVENANCE_METADATA:
            raise ValueError("provenance metadata must be a bounded mapping")
        copied: dict[str, str | int | bool | None] = {}
        for key, metadata_value in self.metadata.items():
            if not isinstance(key, str) or not key or len(key) > 128:
                raise ValueError("provenance metadata keys must contain 1 to 128 characters")
            if metadata_value is not None and not isinstance(metadata_value, (str, int, bool)):
                raise ValueError("provenance metadata values must be JSON scalar values")
            if isinstance(metadata_value, str) and len(metadata_value) > MAX_PROVENANCE_TEXT:
                raise ValueError("provenance metadata string is too long")
            copied[key] = metadata_value
        object.__setattr__(self, "metadata", copied)

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "kind": self.kind,
            "code": self.code,
            "summary": self.summary,
            "decision": self.decision,
            "risk": self.risk,
            "effect": self.effect,
            "resource": self.resource.as_dict() if self.resource else None,
            "rule_id": self.rule_id,
            "action_id": self.action_id,
            "category": self.category,
            "matched_indices": list(self.matched_indices),
            "metadata": dict(self.metadata),
        }

    def for_audit(
        self,
        *,
        include_resource_values: bool = False,
        include_summaries: bool = False,
        include_action_ids: bool = False,
    ) -> "ProvenanceRecord":
        resource = self.resource
        if resource is not None and not include_resource_values:
            resource = resource.redacted()
        return ProvenanceRecord(
            source=self.source,
            kind=self.kind,
            code=self.code,
            summary=self.summary if include_summaries else None,
            decision=self.decision,
            risk=self.risk,
            effect=self.effect,
            resource=resource,
            rule_id=self.rule_id,
            action_id=self.action_id if include_action_ids else None,
            category=self.category,
            matched_indices=self.matched_indices,
            metadata=self.metadata,
        )


@dataclass(frozen=True)
class DecisionProvenance:
    records: tuple[ProvenanceRecord, ...]
    final_decision: Decision
    final_risk: str
    schema_version: str = PROVENANCE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != PROVENANCE_SCHEMA_VERSION:
            raise ValueError(f"unsupported provenance schema: {self.schema_version!r}")
        validate_decision(self.final_decision)
        if self.final_risk not in VALID_RISKS:
            raise ValueError(f"unsupported provenance final_risk: {self.final_risk!r}")
        if len(self.records) > MAX_PROVENANCE_RECORDS:
            raise ValueError(f"provenance supports at most {MAX_PROVENANCE_RECORDS} records")
        if any(not isinstance(record, ProvenanceRecord) for record in self.records):
            raise ValueError("provenance records must be ProvenanceRecord values")

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "records": [record.as_dict() for record in self.records],
            "final_decision": self.final_decision,
            "final_risk": self.final_risk,
        }

    def append(
        self,
        *records: ProvenanceRecord,
        final_decision: Decision | None = None,
        final_risk: str | None = None,
    ) -> "DecisionProvenance":
        return DecisionProvenance(
            records=(*self.records, *records),
            final_decision=final_decision or self.final_decision,
            final_risk=final_risk or self.final_risk,
        )

    def for_audit(
        self,
        *,
        include_resource_values: bool = False,
        include_summaries: bool = False,
        include_action_ids: bool = False,
    ) -> "DecisionProvenance":
        return DecisionProvenance(
            records=tuple(
                record.for_audit(
                    include_resource_values=include_resource_values,
                    include_summaries=include_summaries,
                    include_action_ids=include_action_ids,
                )
                for record in self.records
            ),
            final_decision=self.final_decision,
            final_risk=self.final_risk,
        )

    @property
    def digest(self) -> str:
        canonical = json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
