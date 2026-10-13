"""Read-only import of pinned Codex Security JSON and bounded SARIF claim data."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from ordin.assurance._files import (
    ScopedFileError,
    directory_entries,
    read_scoped_file,
    relative_parts,
)
from ordin.assurance._json import digest
from ordin.assurance.inventory import AuthorizedRepository, verify_source_reference
from ordin.assurance.models import (
    EvidenceLink,
    RepositoryScope,
    SecurityFinding,
    SourceReference,
    SecurityProfileDraft,
    SecurityInvariant,
    InvariantSelectors,
)

from ._validation import MAX_BYTES, canonical, check_links, freeze, loads, validate_document
from .models import ImportedFinding, ImportedLocation, ScannerImportReport

UPSTREAM_REVISION = "6f4c62875baa310c6f18608035309e77bc8e808b"


@dataclass(frozen=True)
class ImportScope:
    artifact_root: Path
    repository: RepositoryScope
    source_repository: AuthorizedRepository | None = None
    expected_target_id: str | None = None
    expected_plugin_version: str | None = None

    def __post_init__(self):
        if (
            not isinstance(self.artifact_root, Path)
            or not self.artifact_root.is_absolute()
            or not isinstance(self.repository, RepositoryScope)
        ):
            raise ValueError(
                "import requires an absolute authorized output root and repository scope"
            )
        if self.source_repository is not None and (
            not isinstance(self.source_repository, AuthorizedRepository)
            or self.source_repository.repository != self.repository
        ):
            raise ValueError("import source repository scope differs")
        directory_entries(self.artifact_root, maximum=256)


def _parts(packet) -> tuple[tuple[str, ...], str]:
    # ASCII JSON escapes preserve multiline/private vendor material losslessly,
    # while each string meets the independent public contract text bounds.
    raw = json.dumps(
        packet, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )
    return tuple(raw[i : i + 4000] for i in range(0, len(raw), 4000)), hashlib.sha256(
        raw.encode()
    ).hexdigest()


def _scope_path(value: str) -> None:
    if value == ".":
        return
    if (
        not isinstance(value, str)
        or len(value) > 1024
        or value.startswith("/")
        or "\\" in value
        or ":" in value
        or "%" in value
        or not re.fullmatch(r"[A-Za-z0-9_./*-]+", value)
        or any(p in {"", ".", ".."} for p in value.split("/"))
    ):
        raise ValueError("scanner scope path unsupported")


def _optional(scope: ImportScope, path: str) -> bytes | None:
    components = relative_parts(path)
    parent = "/".join(components[:-1])
    entries = directory_entries(scope.artifact_root, parent, maximum=256)
    entry = next((e for e in entries if e.name == components[-1]), None)
    if entry is None:
        return None
    if entry.kind != "file":
        raise ValueError("scanner artifact must be regular and unlinked")
    return read_scoped_file(scope.artifact_root, path, maximum=MAX_BYTES)


def _references(value, *, key="", artifacts=None):
    if isinstance(value, Mapping):
        for name, child in value.items():
            _references(child, key=name, artifacts=artifacts)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _references(child, key=key, artifacts=artifacts)
    elif isinstance(value, str):
        if key in {"path", "reportPath"}:
            relative_parts(value)
        if key in {"receiptRefs", "evidenceRefs", "evidence_refs"} and value.startswith(
            "artifacts/"
        ):
            relative_parts(value)
            if artifacts is not None and value not in artifacts:
                raise ValueError(
                    "scanner supporting reference is not declared in sealed artifact set"
                )


def _location(scope, item, matched, gaps):
    path = item["path"]
    relative_parts(path)
    start, end = item["startLine"], item.get("endLine")
    if end is not None and end < start:
        raise ValueError("scanner location range invalid")
    role = item.get("role")
    if role is not None and (len(role) > 128 or any(ord(c) < 32 for c in role)):
        raise ValueError("scanner location role unsupported")
    status, source = "reported", None
    if matched is False:
        status = "revision_mismatch"
    elif matched is True and scope.source_repository is not None:
        try:
            raw = read_scoped_file(scope.source_repository.root, path, maximum=MAX_BYTES)
        except ScopedFileError as error:
            if error.code != "source_unavailable":
                raise
            gaps.append(
                "A reported source location is missing/unavailable in the selected repository."
            )
            return ImportedLocation(path, start, end, role, "missing")
        source = SourceReference(
            path, start, scope.repository.revision, hashlib.sha256(raw).hexdigest()
        )
        if not verify_source_reference(scope.source_repository, source):
            raise ValueError("scanner source line is outside selected repository content")
        if end is not None and end > len(raw.splitlines()):
            raise ValueError("scanner source end line is outside selected repository content")
        status = "verified"
    return ImportedLocation(path, start, end, role, status, source)


def _finding(
    scope, record, index, artifact_digest, matched, duplicate_index, gaps, *, reported_packet=None
):
    locations = tuple(_location(scope, item, matched, gaps) for item in record["locations"])
    refs = tuple(v.source for v in locations if v.source is not None)
    raw_parts, payload_digest = _parts(record if reported_packet is None else reported_packet)
    identifier = (
        "imported:"
        + digest(
            "scanner_occurrence",
            [artifact_digest, index, record["findingId"], record["occurrenceId"]],
        )[:24]
    )
    link = EvidenceLink(
        "vendor:" + payload_digest[:24],
        "imported_claim",
        proof_gaps=(
            "Scanner validation/reachability are reported claims, not independently reproduced evidence.",
        ),
    )
    finding = SecurityFinding(
        identifier,
        "scanner_claim",
        scope.repository,
        digest(
            "scanner_root_cause",
            [
                scope.repository.as_dict(),
                record["ruleId"],
                record["identity"],
                record["fingerprints"]["primary"],
            ],
        ),
        affected_sources=refs,
        evidence=(link,),
        status="imported",
        origin="imported_claim",
        occurrence_ids=(record["occurrenceId"],),
        proof_gaps=("Runtime validation and exploitability are unverified.",),
    )
    return ImportedFinding(
        identifier,
        finding,
        record["findingId"],
        record["occurrenceId"],
        record["ruleId"],
        record["severity"]["level"],
        record["confidence"]["level"],
        record["severity"].get("score"),
        locations,
        raw_parts,
        payload_digest,
        duplicate_index,
    )


def import_codex_json(
    scope: ImportScope,
    *,
    findings_path="findings.json",
    manifest_path="scan-manifest.json",
    coverage_path="coverage.json",
    threat_model_path: str | None = None,
) -> ScannerImportReport:
    """Import claims only. Missing metadata or incomplete scans never imply clean.

    Integrity means matched content hashes under the authorized output directory,
    not scanner identity authentication or runtime reproduction. No artifact,
    reference, code snippet, Markdown instruction or remediation is executed.
    """
    if not isinstance(scope, ImportScope):
        raise ValueError("typed authorized import scope required")
    raw_findings = _optional(scope, findings_path)
    if raw_findings is None:
        raise ValueError("scanner findings artifact absent")
    document = loads(raw_findings)
    validate_document("findings", document)
    if len(document["findings"]) > 256:
        raise ValueError("scanner finding limit")
    raw_manifest = _optional(scope, manifest_path)
    raw_coverage = _optional(scope, coverage_path)
    manifest = loads(raw_manifest) if raw_manifest is not None else None
    coverage = loads(raw_coverage) if raw_coverage is not None else None
    gaps = []
    if manifest is not None:
        validate_document("scan-manifest", manifest)
    else:
        gaps.append("Scan manifest is absent; scope, producer and completion are unknown.")
    if coverage is not None:
        validate_document("coverage", coverage)
    else:
        gaps.append(
            "Coverage artifact is absent; zero imported findings does not establish complete review."
        )
    for packet in (manifest, coverage):
        if packet is not None:
            _references(packet)
    scan = manifest["scan"] if manifest is not None else {}
    if scan and scan["sealedAt"] != scan["completedAt"]:
        raise ValueError("scanner terminal seal timestamp differs from completion")
    if (
        manifest is not None
        and scan["id"] != document["scanId"]
        or coverage is not None
        and coverage["scanId"] != document["scanId"]
    ):
        raise ValueError("scanner artifact identities conflict")
    target = scan.get("target", {})
    revision = target.get("headRevision") or target.get("revision")
    scope_match = "unknown"
    if target:
        scope_match = (
            "matched"
            if target.get("displayName") == scope.repository.id
            and revision == scope.repository.revision
            else "mismatch"
            if revision is not None
            else "unknown"
        )
        if (
            scope.expected_target_id is not None
            and target.get("targetId") != scope.expected_target_id
        ):
            scope_match = "mismatch"
    if scope_match != "matched":
        gaps.append("Scanner target/revision is not matched to the selected repository scope.")
    producer = scan.get("producer", {})
    if (
        scope.expected_plugin_version is not None
        and producer.get("version") != scope.expected_plugin_version
    ):
        raise ValueError("scanner plugin version differs from protected selection")
    included = tuple(
        coverage.get("includePaths", [])
        if coverage
        else scan.get("scope", {}).get("includePaths", [])
    )
    excluded = tuple(
        coverage.get("excludePaths", [])
        if coverage
        else scan.get("scope", {}).get("excludePaths", [])
    )
    for value in (*included, *excluded):
        _scope_path(value)
    if manifest is not None:
        for value in (*scan["scope"]["includePaths"], *scan["scope"]["excludePaths"]):
            _scope_path(value)
    declared = {}
    raw_packets = {findings_path: raw_findings, coverage_path: raw_coverage}
    integrity = "missing" if manifest is None or coverage is None else "matched"
    if manifest is not None:
        total_artifact_bytes = 0
        if len(scan["artifacts"]) > 128:
            raise ValueError("scanner sealed artifact count limit")
        for artifact in scan["artifacts"]:
            path = artifact["path"]
            relative_parts(path)
            if path in declared:
                raise ValueError("duplicate sealed scanner artifact path")
            declared[path] = artifact
            raw = raw_packets.get(path)
            if raw is None:
                raw = _optional(scope, path)
            if raw is None or hashlib.sha256(raw).hexdigest() != artifact["sha256"]:
                raise ValueError("scanner artifact absent or changed after sealing")
            total_artifact_bytes += len(raw)
            if total_artifact_bytes > 8_388_608:
                raise ValueError("scanner sealed artifact total byte limit")
        if findings_path not in declared or coverage_path not in declared:
            raise ValueError("selected scanner documents are not declared by manifest")
    _references(document, artifacts=declared if manifest is not None else None)
    if coverage is not None:
        _references(coverage, artifacts=declared if manifest is not None else None)
    reported = coverage["completeness"] if coverage is not None else "unknown"
    status = scan.get("status", "unknown")
    if (
        coverage is not None
        and tuple(scan.get("scope", {}).get("includePaths", included)) != included
    ):
        gaps.append("Manifest and coverage selected scopes differ.")
        scope_match = "mismatch"
    if reported != "complete":
        gaps.append("Scanner coverage is partial or unknown; unresolved review remains explicit.")
    if status != "completed":
        gaps.append("Scanner terminal status does not establish a completed scan.")
    threat_digest = None
    threat = None
    if threat_model_path is not None:
        raw = _optional(scope, threat_model_path)
        if raw is None:
            raise ValueError("selected threat-model artifact absent")
        if len(raw) > 65_536:
            raise ValueError("threat-model text limit")
        try:
            threat = raw.decode("utf-8")
        except UnicodeError:
            raise ValueError("threat-model encoding invalid") from None
        freeze(threat)
        check_links({"text": threat})
        threat_digest = hashlib.sha256(raw).hexdigest()
    elif manifest is not None and "threatModel" in scan:
        threat = scan["threatModel"]
        check_links({"text": threat.get("content", "") if isinstance(threat, dict) else threat})
        threat_digest = hashlib.sha256(canonical(threat).encode()).hexdigest()
    bundle_digest = digest(
        "scanner_artifact_bundle",
        {
            "findings": hashlib.sha256(raw_findings).hexdigest(),
            "manifest": hashlib.sha256(raw_manifest).hexdigest() if raw_manifest else None,
            "coverage": hashlib.sha256(raw_coverage).hexdigest() if raw_coverage else None,
            "threat": threat_digest,
        },
    )
    duplicates: dict[str, int] = {}
    records = []
    for index, record in enumerate(document["findings"]):
        key = record["occurrenceId"]
        duplicate_index = duplicates.get(key, 0)
        duplicates[key] = duplicate_index + 1
        records.append(
            _finding(
                scope,
                record,
                index,
                bundle_digest,
                True if scope_match == "matched" else False if scope_match == "mismatch" else None,
                duplicate_index,
                gaps,
            )
        )
    metadata = {"manifest": manifest, "coverage": coverage, "threat_model": threat}
    metadata_parts, metadata_digest = _parts(metadata)
    complete = (
        reported == "complete"
        and status == "completed"
        and integrity == "matched"
        and scope_match == "matched"
        and not any(v.status == "missing" for record in records for v in record.locations)
    )
    return ScannerImportReport(
        "scan-import:" + bundle_digest[:24],
        scope.repository,
        bundle_digest,
        "codex_json",
        UPSTREAM_REVISION,
        producer.get("name"),
        producer.get("version"),
        document["scanId"],
        status,
        reported,
        "complete" if complete else "partial" if reported == "partial" else "unknown",
        integrity,
        scope_match,
        included,
        excluded,
        tuple(records),
        metadata_parts,
        metadata_digest,
        threat_model_digest=threat_digest,
        proof_gaps=tuple(
            dict.fromkeys(
                gaps
                + (["Imported scanner claims have not been independently reproduced or confirmed."])
            )
        ),
    )


def propose_imported_profile(
    report: ScannerImportReport, *, source_repository: AuthorizedRepository | None = None
) -> SecurityProfileDraft:
    """Untrusted narrative produces a source-backed proposal, never active policy."""
    if not isinstance(report, ScannerImportReport):
        raise ValueError("typed scanner import required")
    refs = tuple(
        dict.fromkeys(s for item in report.findings for s in item.finding.affected_sources)
    )
    suggestions = []
    verified_refs: tuple[SourceReference, ...] = ()
    if source_repository is not None:
        if (
            not isinstance(source_repository, AuthorizedRepository)
            or source_repository.repository != report.repository
        ):
            raise ValueError("proposal source repository differs from imported scope")
        if any(not verify_source_reference(source_repository, ref) for ref in refs):
            raise ValueError("proposal source evidence is stale or unverified")
        verified_refs = refs
        for index, item in enumerate(report.findings):
            if not item.finding.affected_sources:
                continue
            detail = item.reported_details()
            category = str(detail.get("taxonomy", {}).get("category", "unknown")).lower()
            if any(word in category for word in ("credential", "secret", "exfil", "network")):
                suggestions.append(
                    SecurityInvariant(
                        f"scanner-egress-{index}",
                        "source_flow_guard",
                        InvariantSelectors(effects=("network.upload",)),
                        on_violation="escalate",
                    )
                )
            else:
                suggestions.append(
                    SecurityInvariant(
                        f"scanner-boundary-{index}",
                        "resource_subset",
                        InvariantSelectors(),
                        authority_ref="operator-reviewed-maximum",
                        on_violation="escalate",
                    )
                )
    return SecurityProfileDraft(
        "scan-draft:" + report.digest[:24],
        report.repository,
        "codex_security_import",
        source_evidence=verified_refs,
        invariant_suggestions=tuple(suggestions),
        risk_hypotheses=(
            "Imported vulnerability claims need independent source/reachability validation before restriction proposals.",
        ),
        unresolved_facts=tuple(
            dict.fromkeys(
                (
                    *report.proof_gaps,
                    "Scanner/threat-model prose is untrusted context and cannot select operator policy.",
                )
            )
        ),
        scan_digest=report.artifact_digest,
        completeness="partial" if report.completeness == "complete" else report.completeness,
    )
