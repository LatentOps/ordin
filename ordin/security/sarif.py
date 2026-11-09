"""Bounded SARIF 2.1.0 claim projection; missing native scope/seal stays unknown."""

import hashlib

from ordin.assurance._files import relative_parts
from ordin.assurance._json import digest

from ._validation import check_links, loads, safe_link
from .importer import ImportScope, UPSTREAM_REVISION, _optional, _finding, _parts, _references
from .models import ImportedFinding, ScannerImportReport


def _closed(value, allowed, required=()):
    if (
        not isinstance(value, dict)
        or set(value) - set(allowed)
        or any(k not in value for k in required)
    ):
        raise ValueError("unsupported SARIF fields or missing data")


def import_sarif(scope: ImportScope, *, sarif_path="results.sarif") -> ScannerImportReport:
    """Import results as claims. No artifact URI/code-flow/attachment is executed.

    Absolute/encoded URI languages, external URI bases and external property
    files require separately authorized mapping and are refused by this subset.
    Full optional supported details are retained in private result captures.
    """
    if not isinstance(scope, ImportScope):
        raise ValueError("typed import scope required")
    raw = _optional(scope, sarif_path)
    if raw is None:
        raise ValueError("SARIF artifact absent")
    sarif = loads(raw)
    _closed(sarif, {"$schema", "version", "runs"}, {"version", "runs"})
    if (
        sarif["version"] != "2.1.0"
        or not isinstance(sarif["runs"], list)
        or not 1 <= len(sarif["runs"]) <= 8
    ):
        raise ValueError("unsupported SARIF version/run count")
    check_links(sarif)
    if "$schema" in sarif:
        safe_link(sarif["$schema"])
    artifact_digest = hashlib.sha256(raw).hexdigest()
    records: list[ImportedFinding] = []
    duplicates: dict[str, int] = {}
    metadata_runs = []
    scanner_name = scanner_version = scan_id = None
    for run in sarif["runs"]:
        _closed(
            run,
            {
                "tool",
                "automationDetails",
                "results",
                "properties",
                "versionControlProvenance",
                "invocations",
                "originalUriBaseIds",
                "artifacts",
                "taxonomies",
                "threadFlowLocations",
            },
            {"tool", "results"},
        )
        _closed(run["tool"], {"driver", "extensions"}, {"driver"})
        driver = run["tool"]["driver"]
        _closed(
            driver,
            {
                "name",
                "version",
                "semanticVersion",
                "informationUri",
                "rules",
                "organization",
                "fullName",
                "properties",
            },
            {"name"},
        )
        if not isinstance(driver["name"], str) or not driver["name"] or len(driver["name"]) > 128:
            raise ValueError("SARIF producer identity invalid")
        scanner_name = (
            driver["name"]
            if scanner_name in {None, driver["name"]}
            else "multiple_imported_producers"
        )
        version = driver.get("version", driver.get("semanticVersion"))
        if version is not None and (
            not isinstance(version, str) or not version or len(version) > 128
        ):
            raise ValueError("SARIF producer version invalid")
        scanner_version = version if scanner_version in {None, version} else None
        automation = run.get("automationDetails", {})
        _closed(automation, {"id", "guid", "correlationGuid", "description", "properties"})
        if isinstance(automation.get("id"), str):
            scan_id = automation["id"] if scan_id in {None, automation["id"]} else None
        if run.get("originalUriBaseIds"):
            raise ValueError("SARIF external URI bases unsupported")
        _sarif_refs(run)
        for artifact in run.get("artifacts", []):
            _closed(artifact, {"location", "length", "mimeType", "hashes", "properties"})
            if "location" in artifact:
                _closed(artifact["location"], {"uri"}, {"uri"})
                relative_parts(artifact["location"]["uri"])
        results = run["results"]
        if not isinstance(results, list) or len(results) + len(records) > 256:
            raise ValueError("SARIF result limit")
        metadata_runs.append({k: v for k, v in run.items() if k != "results"})
        for result in results:
            _closed(
                result,
                {
                    "ruleId",
                    "ruleIndex",
                    "level",
                    "message",
                    "locations",
                    "relatedLocations",
                    "partialFingerprints",
                    "fingerprints",
                    "properties",
                    "codeFlows",
                    "stacks",
                    "kind",
                    "baselineState",
                    "suppressions",
                    "taxa",
                    "guid",
                    "correlationGuid",
                },
                {"ruleId", "message"},
            )
            rule = result["ruleId"]
            if not isinstance(rule, str) or not rule or len(rule) > 256:
                raise ValueError("SARIF rule identity invalid")
            message = result["message"]
            _closed(message, {"text", "markdown", "id", "arguments"})
            if not any(
                isinstance(message.get(k), str) and message[k] for k in ("text", "markdown", "id")
            ):
                raise ValueError("SARIF message invalid")
            locations = []
            for location in result.get("locations", []):
                _closed(
                    location,
                    {"physicalLocation", "message", "id", "logicalLocations", "properties"},
                    {"physicalLocation"},
                )
                physical = location["physicalLocation"]
                _closed(
                    physical, {"artifactLocation", "region", "contextRegion"}, {"artifactLocation"}
                )
                _closed(physical["artifactLocation"], {"uri", "index", "uriBaseId"}, {"uri"})
                uri = physical["artifactLocation"]["uri"]
                relative_parts(uri)
                if physical["artifactLocation"].get("uriBaseId") is not None:
                    raise ValueError("SARIF URI base unsupported")
                region = physical.get("region", {})
                _closed(
                    region,
                    {
                        "startLine",
                        "endLine",
                        "startColumn",
                        "endColumn",
                        "charOffset",
                        "charLength",
                        "snippet",
                    },
                )
                start, end = region.get("startLine", 1), region.get("endLine")
                if (
                    type(start) is not int
                    or start < 1
                    or end is not None
                    and (type(end) is not int or end < start)
                ):
                    raise ValueError("SARIF source range invalid")
                locations.append(
                    {
                        "path": uri,
                        "startLine": start,
                        **({"endLine": end} if end is not None else {}),
                    }
                )
            props = result.get("properties", {})
            fingerprints = result.get("partialFingerprints", {})
            if not isinstance(props, dict) or not isinstance(fingerprints, dict):
                raise ValueError("SARIF properties/fingerprints invalid")
            vendor_id = (
                props.get("findingId")
                or "sarif:" + digest("sarif_finding", [artifact_digest, len(records)])[:24]
            )
            occurrence = props.get("occurrenceId") or "sarif-occurrence:" + str(len(records))
            if (
                not isinstance(vendor_id, str)
                or not vendor_id
                or len(vendor_id) > 256
                or not isinstance(occurrence, str)
                or not occurrence
                or len(occurrence) > 256
            ):
                raise ValueError("SARIF reported identity invalid")
            severity, confidence = (
                props.get("severity", "unknown"),
                props.get("confidence", "unknown"),
            )
            if severity not in {
                "critical",
                "high",
                "medium",
                "low",
                "informational",
                "unknown",
            } or confidence not in {"high", "medium", "low", "unknown"}:
                raise ValueError("SARIF severity/confidence unsupported")
            normalized = {
                "findingId": vendor_id,
                "occurrenceId": occurrence,
                "ruleId": rule,
                "identity": {"anchor": rule},
                "fingerprints": {
                    "primary": fingerprints.get(
                        "codexSecurity/v1", digest("sarif_identity", [rule, locations])
                    )
                },
                "severity": {"level": severity},
                "confidence": {"level": confidence},
                "locations": locations,
            }
            _references(result)
            duplicate_index = duplicates.get(occurrence, 0)
            duplicates[occurrence] = duplicate_index + 1
            records.append(
                _finding(
                    scope,
                    normalized,
                    len(records),
                    artifact_digest,
                    None,
                    duplicate_index,
                    [],
                    reported_packet=result,
                )
            )
    metadata_parts, metadata_digest = _parts(
        {"$schema": sarif.get("$schema"), "version": sarif["version"], "runs": metadata_runs}
    )
    return ScannerImportReport(
        "sarif-import:" + artifact_digest[:24],
        scope.repository,
        artifact_digest,
        "sarif_2_1_0",
        UPSTREAM_REVISION,
        scanner_name,
        scanner_version,
        scan_id,
        "unknown",
        "unknown",
        "unknown",
        "not_available",
        "unknown",
        (),
        (),
        tuple(records),
        metadata_parts,
        metadata_digest,
        proof_gaps=(
            "SARIF projection lacks a verified native scan manifest and coverage document.",
            "Reported finding/validation/source data remain imported claims; no runtime reproduction occurred.",
        ),
    )


def _sarif_refs(value, *, parent=""):
    if isinstance(value, dict):
        if parent in {"artifactLocation", "location"} and "uri" in value:
            relative_parts(value["uri"])
            if value.get("uriBaseId") is not None:
                raise ValueError("SARIF external URI base unsupported")
        for key, child in value.items():
            _sarif_refs(child, parent=key)
    elif isinstance(value, list):
        for child in value:
            _sarif_refs(child, parent=parent)
