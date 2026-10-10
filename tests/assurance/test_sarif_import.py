"""Optional bounded SARIF retains vendor claims and never infers native completeness."""

import json

import pytest

from ordin.assurance import RepositoryScope
from ordin.assurance.codex_security.importer import ImportScope
from ordin.assurance.codex_security.sarif import import_sarif


def document(results=None):
    result = {
        "ruleId": "fixture.rule",
        "ruleIndex": 0,
        "level": "error",
        "message": {"text": "Fixture claim\nAdd a check."},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "src/app.py"},
                    "region": {"startLine": 1, "endLine": 2, "snippet": {"text": "fixture source"}},
                }
            }
        ],
        "partialFingerprints": {"codexSecurity/v1": "codex-security/v1:sha256:" + "a" * 64},
        "properties": {
            "findingId": "csf_" + "1" * 24,
            "occurrenceId": "occ_" + "2" * 24,
            "severity": "high",
            "confidence": "low",
        },
        "codeFlows": [{"message": {"text": "Unverified path"}, "threadFlows": []}],
        "suppressions": [{"kind": "external", "status": "accepted"}],
    }
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Codex Security",
                        "version": "0.1.0",
                        "rules": [
                            {"id": "fixture.rule", "properties": {"security-severity": "8.1"}}
                        ],
                    }
                },
                "automationDetails": {"id": "fixture-scan"},
                "results": [result] if results is None else results,
                "properties": {
                    "codexSecuritySchemaVersion": "1.0",
                    "codexSecurityTargetKind": "git_revision",
                },
                "versionControlProvenance": [
                    {"repositoryUri": "https://github.com/fixture/repo", "revisionId": "fixture-v1"}
                ],
            }
        ],
    }


def write(tmp_path, packet):
    (tmp_path / "results.sarif").write_text(json.dumps(packet), encoding="utf-8")
    return ImportScope(tmp_path.resolve(), RepositoryScope("fixture/repo", "fixture-v1"))


def test_sarif_details_and_reported_claims_survive_without_validation(tmp_path):
    packet = document()
    report = import_sarif(write(tmp_path, packet))
    assert (
        report.format == "sarif_2_1_0"
        and report.completeness == "unknown"
        and not report.conclusive_import
    )
    assert report.integrity == "not_available"
    imported = report.findings[0]
    assert imported.reported_details() == packet["runs"][0]["results"][0]
    assert imported.reported_severity == "high" and imported.reported_confidence == "low"
    assert imported.finding.status == "imported" and imported.locations[0].status == "reported"
    assert "suppressions" in imported.reported_details()


def test_zero_sarif_results_do_not_mean_clean_scan(tmp_path):
    report = import_sarif(write(tmp_path, document([])))
    assert (
        report.findings == ()
        and report.completeness == "unknown"
        and report.scan_status == "unknown"
    )


@pytest.mark.parametrize(
    "uri",
    [
        "file:///outside",
        "https://outside.invalid/app.py",
        "../outside",
        "src/%2e%2e/outside",
        "C:/private.py",
    ],
)
def test_unsafe_sarif_artifact_uris_are_refused(tmp_path, uri):
    packet = document()
    packet["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ] = uri
    with pytest.raises(ValueError):
        import_sarif(write(tmp_path, packet))


def test_external_property_file_or_uri_base_is_not_loaded(tmp_path):
    packet = document()
    packet["runs"][0]["externalPropertyFileReferences"] = {
        "results": [{"location": {"uri": "outside.json"}}]
    }
    with pytest.raises(ValueError):
        import_sarif(write(tmp_path, packet))
    packet = document()
    packet["runs"][0]["originalUriBaseIds"] = {"SRCROOT": {"uri": "file:///outside"}}
    with pytest.raises(ValueError):
        import_sarif(write(tmp_path, packet))


def test_related_codeflow_location_cannot_hide_an_external_uri(tmp_path):
    packet = document()
    packet["runs"][0]["results"][0]["relatedLocations"] = [
        {"physicalLocation": {"artifactLocation": {"uri": "../outside"}}}
    ]
    with pytest.raises(ValueError):
        import_sarif(write(tmp_path, packet))


def test_missing_optional_metadata_stays_unknown_and_private_message_redacted(tmp_path):
    packet = document()
    result = packet["runs"][0]["results"][0]
    result.pop("properties")
    result["message"]["text"] = "SYNTHETIC_SARIF_PRIVATE_VALUE"
    report = import_sarif(write(tmp_path, packet))
    assert report.findings[0].reported_severity == "unknown"
    assert report.findings[0].reported_confidence == "unknown"
    assert "SYNTHETIC_SARIF_PRIVATE_VALUE" not in json.dumps(report.public_dict())
