"""Immutable imported claims; ordinary JSON cannot confirm a finding or grant rights."""

import hashlib
from dataclasses import dataclass

from ordin.assurance.models import JsonRecord, RepositoryScope, SecurityFinding, SourceReference

from ._validation import loads


@dataclass(frozen=True)
class ImportedLocation(JsonRecord):
    SCHEMA = "imported_location"
    NESTED = {"source": SourceReference}
    path: str
    start_line: int
    end_line: int | None = None
    role: str | None = None
    status: str = "reported"
    source: SourceReference | None = None

    def __post_init__(self):
        super().__post_init__()
        from ordin.assurance._files import relative_parts

        relative_parts(self.path)
        if (
            self.end_line is not None
            and self.end_line < self.start_line
            or self.status == "verified"
            and self.source is None
        ):
            raise ValueError("imported location range/verification inconsistent")


@dataclass(frozen=True)
class ImportedFinding(JsonRecord):
    SCHEMA = "assurance_imported_finding"
    NESTED = {"finding": SecurityFinding}
    MANY = {"locations": ImportedLocation}
    record_id: str
    finding: SecurityFinding
    vendor_finding_id: str
    occurrence_id: str
    rule_id: str
    reported_severity: str
    reported_confidence: str
    reported_score: float | None
    locations: tuple[ImportedLocation, ...]
    reported_payload_parts: tuple[str, ...]
    payload_digest: str
    duplicate_index: int = 0

    def __post_init__(self):
        super().__post_init__()
        raw = "".join(self.reported_payload_parts)
        if (
            hashlib.sha256(raw.encode()).hexdigest() != self.payload_digest
            or self.finding.origin != "imported_claim"
            or self.finding.status != "imported"
            or self.finding.verification_method != "none"
        ):
            raise ValueError("imported vendor finding cannot promote validation or alter capture")
        original = loads(raw)
        if "findingId" in original:
            if (
                original["findingId"] != self.vendor_finding_id
                or original["occurrenceId"] != self.occurrence_id
                or original["ruleId"] != self.rule_id
                or original["severity"]["level"] != self.reported_severity
                or original["confidence"]["level"] != self.reported_confidence
                or original["severity"].get("score") != self.reported_score
            ):
                raise ValueError("reported finding summary differs from original vendor claims")
        elif "ruleId" in original:
            props = original.get("properties", {})
            if (
                original["ruleId"] != self.rule_id
                or props.get("severity", "unknown") != self.reported_severity
                or props.get("confidence", "unknown") != self.reported_confidence
            ):
                raise ValueError("reported SARIF summary differs from original claims")

    def reported_details(self) -> dict:
        """Sensitive vendor material; use only in a private operator view/export."""
        return loads("".join(self.reported_payload_parts))

    def public_dict(self) -> dict:
        return {
            "record_id": self.record_id,
            "finding_digest": self.finding.digest,
            "payload_digest": self.payload_digest,
            "status": "imported",
            "origin": "imported_claim",
            "reported_severity": self.reported_severity,
            "reported_confidence": self.reported_confidence,
            "reported_score": self.reported_score,
            "locations": len(self.locations),
            "verified_locations": sum(v.status == "verified" for v in self.locations),
            "duplicate_index": self.duplicate_index,
        }


@dataclass(frozen=True)
class ScannerImportReport(JsonRecord):
    SCHEMA = "assurance_scan_import"
    NESTED = {"repository": RepositoryScope}
    MANY = {"findings": ImportedFinding}
    report_id: str
    repository: RepositoryScope
    artifact_digest: str
    format: str
    adapter_revision: str
    scanner_name: str | None
    scanner_version: str | None
    scan_id: str | None
    scan_status: str
    reported_completeness: str
    completeness: str
    integrity: str
    scope_match: str
    included_paths: tuple[str, ...]
    excluded_paths: tuple[str, ...]
    findings: tuple[ImportedFinding, ...]
    metadata_parts: tuple[str, ...]
    metadata_digest: str
    threat_model_digest: str | None = None
    proof_gaps: tuple[str, ...] = ()
    origin: str = "imported_claim"

    def __post_init__(self):
        super().__post_init__()
        raw = "".join(self.metadata_parts)
        if hashlib.sha256(raw.encode()).hexdigest() != self.metadata_digest or len(
            {v.record_id for v in self.findings}
        ) != len(self.findings):
            raise ValueError("scanner import capture/record identity inconsistent")
        original = loads(raw)
        if self.format == "codex_json":
            manifest = original.get("manifest")
            coverage = original.get("coverage")
            scan = manifest["scan"] if manifest is not None else {}
            if (
                scan.get("status", "unknown") != self.scan_status
                or (coverage["completeness"] if coverage is not None else "unknown")
                != self.reported_completeness
            ):
                raise ValueError("scan status/coverage differs from imported metadata")
        if self.completeness == "complete" and (
            self.scan_status != "completed"
            or self.reported_completeness != "complete"
            or self.scope_match != "matched"
            or self.integrity != "matched"
        ):
            raise ValueError("incomplete or unverified import cannot declare complete coverage")

    @property
    def conclusive_import(self) -> bool:
        return self.completeness == "complete"

    def reported_metadata(self) -> dict:
        return loads("".join(self.metadata_parts))

    def public_dict(self) -> dict:
        """Redacted routine JSON; as_dict() contains sensitive reported material."""
        return {
            "schema_version": "ordin.assurance_scan_import_summary.v1",
            "report_id": self.report_id,
            "repository_digest": self.repository.digest,
            "artifact_digest": self.artifact_digest,
            "format": self.format,
            "adapter_revision": self.adapter_revision,
            "scan_status": self.scan_status,
            "reported_completeness": self.reported_completeness,
            "completeness": self.completeness,
            "integrity": self.integrity,
            "scope_match": self.scope_match,
            "finding_count": len(self.findings),
            "findings": [v.public_dict() for v in self.findings],
            "metadata_digest": self.metadata_digest,
            "threat_model_digest": self.threat_model_digest,
            "proof_gaps": list(self.proof_gaps),
            "origin": "imported_claim",
            "finding_confirmation": "not_performed",
        }
