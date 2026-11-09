"""Offline saved workflow claims. No scanner, exploit, patch or verdict is executed."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from ordin.assurance._files import directory_entries, read_scoped_file, relative_parts
from ordin.assurance._json import digest, validate
from ordin.assurance.models import JsonRecord, RepositoryScope

from ._validation import MAX_BYTES, loads, check_links, validate_document
from .importer import _parts

ADAPTER_REVISION = "6f4c62875baa310c6f18608035309e77bc8e808b"
WORKFLOWS = {"validate", "patch", "verify_fix", "patch_risk"}


@dataclass(frozen=True)
class WorkflowCapture(JsonRecord):
    """Operator-saved capture metadata; its assertions do not authenticate a runtime."""

    SCHEMA = "assurance_workflow_capture"
    NESTED = {"repository": RepositoryScope}
    workflow: str
    repository: RepositoryScope
    source_tool: dict
    scan_id: str | None
    native_repository: str | None
    expected_identifiers: tuple[str, ...]
    artifact_sha256: str
    reported_exit_code: int | None
    reported_status: str
    patch_sha256: str | None

    def __post_init__(self):
        super().__post_init__()
        if len(set(self.expected_identifiers)) != len(self.expected_identifiers):
            raise ValueError("workflow capture identifiers must be unique")


@dataclass(frozen=True)
class ImportedWorkflowClaim(JsonRecord):
    SCHEMA = "assurance_workflow_claim"
    record_id: str
    workflow: str
    identifier_digest: str | None
    reported_verdict: str
    payload_parts: tuple[str, ...]
    payload_digest: str
    origin: str = "imported_claim"
    status: str = "imported"
    verification_method: str = "none"

    def __post_init__(self):
        super().__post_init__()
        raw = "".join(self.payload_parts)
        if hashlib.sha256(raw.encode()).hexdigest() != self.payload_digest:
            raise ValueError("workflow claim capture was altered")
        payload = loads(raw)
        observed = (
            payload.get("disposition", "unknown")
            if self.workflow == "validate"
            else payload.get("recommendation")
            if self.workflow == "patch_risk"
            else payload.get("status", "changes_reported" if "applied" in payload else "unknown")
        )
        identifier = payload.get("id", payload.get("occurrenceId"))
        if observed != self.reported_verdict or self.identifier_digest != (
            digest("vendor_workflow_id", identifier) if identifier else None
        ):
            raise ValueError("workflow summary differs from original reported claims")

    def reported_details(self):
        """Explicit private access to vendor code, evidence, paths and instructions."""
        return loads("".join(self.payload_parts))

    def public_dict(self):
        return {
            "record_id": self.record_id,
            "workflow": self.workflow,
            "identifier_digest": self.identifier_digest,
            "reported_verdict": self.reported_verdict,
            "payload_digest": self.payload_digest,
            "origin": self.origin,
            "status": self.status,
            "verification_method": "none",
        }


@dataclass(frozen=True)
class WorkflowImportReport(JsonRecord):
    SCHEMA = "assurance_workflow_import"
    NESTED = {"repository": RepositoryScope}
    MANY = {"claims": ImportedWorkflowClaim}
    repository: RepositoryScope
    workflow: str
    artifact_digest: str
    capture_digest: str | None
    adapter_revision: str
    reported_tool_version: str | None
    scan_id_digest: str | None
    integrity: str
    scope_match: str
    completeness: str
    native_format: str
    claims: tuple[ImportedWorkflowClaim, ...]
    metadata_parts: tuple[str, ...]
    metadata_digest: str
    proof_gaps: tuple[str, ...]
    closure: str = "not_performed"
    authority_change: str = "none"
    origin: str = "imported_claim"

    def __post_init__(self):
        super().__post_init__()
        if (
            hashlib.sha256("".join(self.metadata_parts).encode()).hexdigest()
            != self.metadata_digest
        ):
            raise ValueError("workflow metadata capture was altered")
        original = loads("".join(self.metadata_parts))
        if set(original) != {"capture", "native_report"}:
            raise ValueError("workflow metadata envelope differs from capture")
        native = original["native_report"]
        expected_payloads = (
            native.get("results")
            if self.workflow == "verify_fix"
            else native.get("patches", [native])
            if self.workflow == "patch"
            else [native]
        )
        if expected_payloads != [claim.reported_details() for claim in self.claims]:
            raise ValueError("workflow occurrences differ from native capture")
        captured = (
            WorkflowCapture.from_dict(original["capture"])
            if original["capture"] is not None
            else None
        )
        if captured is not None and (
            captured.workflow != self.workflow
            or captured.source_tool["version"] != self.reported_tool_version
            or (digest("vendor_scan_id", captured.scan_id) if captured.scan_id else None)
            != self.scan_id_digest
            or (self.integrity == "matched" and captured.artifact_sha256 != self.artifact_digest)
            or (self.scope_match == "matched" and captured.repository != self.repository)
        ):
            raise ValueError("workflow metadata summary differs from reported capture")
        if len({claim.record_id for claim in self.claims}) != len(self.claims) or any(
            claim.workflow != self.workflow for claim in self.claims
        ):
            raise ValueError("workflow claim identity/type mismatch")
        if self.completeness == "complete" and (
            self.proof_gaps
            or self.integrity != "matched"
            or self.scope_match != "matched"
            or not self.capture_digest
        ):
            raise ValueError("partial workflow import cannot claim complete capture")
        if self.completeness == "complete":
            accepted_exit = {0, 1}
            if self.workflow == "verify_fix":
                verdicts = {claim.reported_verdict for claim in self.claims}
                accepted_exit = {
                    2 if "inconclusive" in verdicts else 1 if "still_vulnerable" in verdicts else 0
                }
            if (
                captured is None
                or captured.reported_status != "completed"
                or captured.source_tool["version"] != "0.2.0"
                or captured.reported_exit_code not in accepted_exit
            ):
                raise ValueError("complete workflow capture contradicts recorded source/completion")

    def reported_metadata(self):
        return loads("".join(self.metadata_parts))

    def public_dict(self):
        return {
            "schema_version": "ordin.assurance_workflow_import_summary.v1",
            "report_digest": self.digest,
            "repository_digest": self.repository.digest,
            "workflow": self.workflow,
            "artifact_digest": self.artifact_digest,
            "capture_digest": self.capture_digest,
            "adapter_revision": self.adapter_revision,
            "reported_tool_version_digest": digest(
                "workflow_tool_version", self.reported_tool_version
            )
            if self.reported_tool_version
            else None,
            "scan_id_digest": self.scan_id_digest,
            "integrity": self.integrity,
            "scope_match": self.scope_match,
            "completeness": self.completeness,
            "native_format": self.native_format,
            "claims": [claim.public_dict() for claim in self.claims],
            "metadata_digest": self.metadata_digest,
            "proof_gaps": list(self.proof_gaps),
            "closure": "not_performed",
            "authority_change": "none",
            "origin": "imported_claim",
        }


@dataclass(frozen=True)
class WorkflowImportScope:
    artifact_root: Path
    repository: RepositoryScope
    workflow: str
    expected_tool_version: str = "0.2.0"
    expected_scan_id: str | None = None
    expected_identifiers: tuple[str, ...] = ()
    expected_patch_digest: str | None = None
    artifact_format: str = "json"

    def __post_init__(self):
        if (
            self.artifact_format not in {"json", "text"}
            or self.artifact_format == "text"
            and self.workflow != "validate"
        ):
            raise ValueError("plain saved report support is limited to CLI validation prose")
        if (
            not isinstance(self.artifact_root, Path)
            or not self.artifact_root.is_absolute()
            or not isinstance(self.repository, RepositoryScope)
            or self.workflow not in WORKFLOWS
        ):
            raise ValueError(
                "workflow import requires an explicit authorized root, repository and operation"
            )
        if (
            not isinstance(self.expected_tool_version, str)
            or not 1 <= len(self.expected_tool_version) <= 128
            or not isinstance(self.expected_identifiers, tuple)
            or len(self.expected_identifiers) > 128
            or any(
                not isinstance(item, str) or not 1 <= len(item) <= 256
                for item in self.expected_identifiers
            )
            or len(set(self.expected_identifiers)) != len(self.expected_identifiers)
        ):
            raise ValueError("declared workflow identity selection is malformed")
        if self.expected_patch_digest is not None:
            validate(
                "assurance_authority_ref",
                {"authority_id": "workflow-patch", "boundary_digest": self.expected_patch_digest},
            )
        directory_entries(self.artifact_root, maximum=256)


def _closed(packet, required, optional=()):
    if (
        not isinstance(packet, dict)
        or not set(required) <= set(packet)
        or set(packet) - set(required) - set(optional)
    ):
        raise ValueError("unsupported pinned workflow object")


def _text(value, maximum=65536):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValueError("workflow text field is malformed")


def _files(values):
    if (
        not isinstance(values, list)
        or len(values) > 128
        or any(not isinstance(value, str) for value in values)
        or len(set(values)) != len(values)
    ):
        raise ValueError("workflow file list is malformed")
    for value in values:
        _text(value, 1024)
        relative_parts(value)


def _risk_from_report(value):
    # CLI patchRisk.report keeps marked-summary JSON as inert report text.
    _closed(value, {"report"}, {"summary"})
    _text(value["report"])
    text = value["report"].strip()
    if text.startswith("{"):
        payload = loads(text)
    else:
        marker = "<!-- codex-security:patch-risk-summary:end -->"
        if text.count(marker) != 1:
            return None
        tail = text.split(marker, 1)[1].strip()
        if not tail.startswith("{"):
            return None
        payload = loads(tail)
    validate_document("patch-risk-assessment", payload)
    return payload


def _native(scope, payload):
    records, identifiers, gaps = [], [], []
    native_repo = native_scan = patch_digest = None
    if scope.workflow == "validate":
        _closed(payload, {"disposition", "report"}, {"outputDir", "threadId"})
        if payload["disposition"] not in {"reportable", "suppressed", "not_applicable", "deferred"}:
            raise ValueError("unknown validation disposition")
        _text(payload["report"])
        if "outputDir" in payload:
            _text(payload["outputDir"], 1024)
        if payload.get("threadId") is not None:
            _text(payload["threadId"], 256)
        records = [payload]
        format_name = "sdk_validation"
    elif scope.workflow == "verify_fix":
        _closed(payload, {"repository", "results"}, {"scanId"})
        _text(payload["repository"], 1024)
        native_repo, native_scan = payload["repository"], payload.get("scanId")
        if not isinstance(payload["results"], list) or len(payload["results"]) > 128:
            raise ValueError("verification result collection malformed")
        for record in payload["results"]:
            _closed(record, {"id", "status", "evidence"})
            _text(record["id"], 256)
            _text(record["evidence"])
            if record["status"] not in {"fixed", "still_vulnerable", "inconclusive"}:
                raise ValueError("unknown external verification status")
            records.append(record)
            identifiers.append(record["id"])
        format_name = "cli_verify_fix"
    elif scope.workflow == "patch":
        _closed(
            payload,
            {"repository", "applied", "filesChanged", "files"},
            {"scanId", "patches", "patchRisk", "pullRequest", "error"},
        )
        _text(payload["repository"], 1024)
        _files(payload["files"])
        if (
            type(payload["applied"]) is not bool
            or type(payload["filesChanged"]) is not int
            or payload["filesChanged"] != len(payload["files"])
            or payload["applied"] != bool(payload["files"])
        ):
            raise ValueError("reported patch file/application counts differ")
        native_repo, native_scan = payload["repository"], payload.get("scanId")
        if "patches" in payload:
            if not isinstance(payload["patches"], list) or len(payload["patches"]) > 128:
                raise ValueError("patch result collection malformed")
            for record in payload["patches"]:
                _closed(record, {"occurrenceId", "status", "files"}, {"verification", "reason"})
                _text(record["occurrenceId"], 256)
                _files(record["files"])
                if record["status"] not in {"verified", "no_change", "blocked", "failed"}:
                    raise ValueError("unknown external patch status")
                if record["status"] in {"verified", "no_change"}:
                    _text(record.get("verification"))
                else:
                    _text(record.get("reason"))
                records.append(record)
                identifiers.append(record["occurrenceId"])
            format_name = "cli_saved_patch"
        else:
            records = [payload]
            format_name = "cli_supplied_patch"
            gaps.append("Supplied-issue patch output has no per-finding verification verdict.")
        if "patchRisk" in payload:
            risk = _risk_from_report(payload["patchRisk"])
            if risk is None:
                gaps.append(
                    "Embedded patch-risk prose has no supported structured assessment capture."
                )
        if "pullRequest" in payload:
            _closed(payload["pullRequest"], {"branch", "url"})
            _text(payload["pullRequest"]["branch"], 256)
    else:
        validate_document("patch-risk-assessment", payload)
        records = [payload]
        native_repo, patch_digest = payload["patch"]["repository"], payload["patch"]["sha256"]
        _files(payload["patch"]["changedFiles"])
        format_name = "patch_risk_assessment"
    if native_scan is not None:
        _text(native_scan, 256)
    check_links(payload)
    return records, identifiers, native_repo, native_scan, patch_digest, format_name, gaps


def import_workflow_claims(
    scope: WorkflowImportScope,
    *,
    artifact_path="workflow.json",
    capture_path="workflow-capture.json",
):
    if not isinstance(scope, WorkflowImportScope):
        raise ValueError("workflow import requires typed scope")
    raw = read_scoped_file(scope.artifact_root, artifact_path, maximum=MAX_BYTES)
    artifact_digest = hashlib.sha256(raw).hexdigest()
    if scope.artifact_format == "text":
        text = raw.decode("utf-8")
        _text(text)
        payload = {"report": text}
        _parts(payload)
        check_links(payload)
        records, identifiers, native_repo, native_scan, native_patch = (
            [payload],
            [],
            None,
            None,
            None,
        )
        format_name = "cli_validation_text"
        gaps = [
            "CLI validation prose is captured without inferring a typed disposition or runtime proof."
        ]
    else:
        payload = loads(raw)
        records, identifiers, native_repo, native_scan, native_patch, format_name, gaps = _native(
            scope, payload
        )
    capture = capture_digest = None
    entries = {
        entry.name: entry.kind for entry in directory_entries(scope.artifact_root, maximum=256)
    }
    if len(relative_parts(capture_path)) != 1:
        raise ValueError("workflow capture must be an explicit leaf file within its root")
    if capture_path not in entries:
        capture_raw = None
    elif entries[capture_path] != "file":
        raise ValueError("workflow capture is not a regular safe file")
    else:
        capture_raw = read_scoped_file(scope.artifact_root, capture_path, maximum=65536)
    if capture_raw is not None:
        capture = WorkflowCapture.from_dict(loads(capture_raw))
        capture_digest = hashlib.sha256(capture_raw).hexdigest()
    integrity, scope_match = "unknown", "unknown"
    if capture is None:
        gaps.append(
            "Capture manifest is absent; source/version/revision/expected coverage are unverified."
        )
    else:
        if capture.workflow != scope.workflow:
            raise ValueError("capture workflow differs from selected operation")
        integrity = "matched" if capture.artifact_sha256 == artifact_digest else "mismatched"
        scope_match = "matched" if capture.repository == scope.repository else "mismatched"
        if integrity != "matched":
            gaps.append("Workflow artifact bytes differ from the saved capture hash.")
        if (
            scope_match != "matched"
            or native_repo is not None
            and capture.native_repository != native_repo
        ):
            scope_match = "mismatched"
            gaps.append("Reported repository/revision mapping differs from selected capture scope.")
        if (
            capture.source_tool["version"] != scope.expected_tool_version
            or capture.source_tool["version"] != "0.2.0"
        ):
            gaps.append(
                "Captured external tool version differs from the selected contract version."
            )
        accepted_exits = {0, 1}
        if scope.workflow == "verify_fix":
            statuses = {record["status"] for record in records}
            expected_exit = (
                2 if "inconclusive" in statuses else 1 if "still_vulnerable" in statuses else 0
            )
            accepted_exits = {expected_exit}
        if (
            capture.reported_status != "completed"
            or capture.reported_exit_code not in accepted_exits
        ):
            gaps.append(
                "External workflow completion/exit is partial, failed, canceled or unknown."
            )
        if (
            scope.expected_scan_id is not None
            and capture.scan_id != scope.expected_scan_id
            or native_scan is not None
            and capture.scan_id != native_scan
        ):
            gaps.append("External workflow scan identity is mismatched.")
        if scope.workflow in {"patch", "verify_fix"}:
            expected = scope.expected_identifiers or capture.expected_identifiers
            if (
                not expected
                or tuple(identifiers) != expected
                or capture.expected_identifiers != expected
            ):
                gaps.append(
                    "Expected finding/occurrence coverage is absent, duplicated, reordered or incomplete."
                )
        if scope.workflow == "patch_risk":
            if scope.expected_patch_digest is None:
                gaps.append("The independently selected patch artifact digest is absent.")
            elif (
                native_patch != scope.expected_patch_digest
                or capture.patch_sha256 != scope.expected_patch_digest
            ):
                gaps.append(
                    "Reported patch-risk artifact differs from the selected exact patch bytes."
                )
        if scope.workflow == "validate" and (
            len(capture.expected_identifiers) != 1
            or scope.expected_identifiers
            and scope.expected_identifiers != capture.expected_identifiers
        ):
            gaps.append("SDK validation lacks a unique matching captured finding identity.")
    if len(set(identifiers)) != len(identifiers):
        gaps.append("Repeated external result identifiers retain separate unverified occurrences.")
    claims = []
    for index, record in enumerate(records):
        identifier = record.get("id", record.get("occurrenceId"))
        if (
            scope.workflow == "validate"
            and capture is not None
            and len(capture.expected_identifiers) == 1
        ):
            # Identity stays capture metadata; never fabricate it in the native record.
            identifier = None
        verdict = (
            record.get("disposition", "unknown")
            if scope.workflow == "validate"
            else record.get("recommendation")
            if scope.workflow == "patch_risk"
            else record.get("status", "changes_reported" if "applied" in record else "unknown")
        )
        parts, payload_digest = _parts(record)
        assert isinstance(verdict, str)
        claims.append(
            ImportedWorkflowClaim(
                "workflow:" + digest("workflow_occurrence", [artifact_digest, index])[:24],
                scope.workflow,
                digest("vendor_workflow_id", identifier) if identifier else None,
                verdict,
                parts,
                payload_digest,
            )
        )
    metadata_parts, metadata_digest = _parts(
        {"capture": capture.as_dict() if capture else None, "native_report": payload}
    )
    return WorkflowImportReport(
        scope.repository,
        scope.workflow,
        artifact_digest,
        capture_digest,
        ADAPTER_REVISION,
        capture.source_tool["version"] if capture else None,
        digest("vendor_scan_id", capture.scan_id) if capture and capture.scan_id else None,
        integrity,
        scope_match,
        "complete" if not gaps else "partial" if capture else "unknown",
        format_name,
        tuple(claims),
        metadata_parts,
        metadata_digest,
        tuple(dict.fromkeys(gaps)),
    )
