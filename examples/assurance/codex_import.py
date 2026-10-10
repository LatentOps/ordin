"""Create and import a synthetic native scan bundle; no scanner/provider executes."""

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from ordin.assurance import RepositoryScope
from ordin.assurance.codex_security import ImportScope, import_codex_json


def fixture(directory: Path, *, completeness="partial"):
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    repository = RepositoryScope("fixture/codex-import", "fixture-v1")
    findings = {
        "documentType": "codex-security.findings",
        "schemaVersion": "1.0",
        "scanId": "fixture-scan",
        "findings": [],
    }
    coverage = {
        "documentType": "codex-security.coverage",
        "schemaVersion": "1.0",
        "scanId": "fixture-scan",
        "mode": "repository",
        "completeness": completeness,
        "inventoryStrategy": "repository",
        "includePaths": ["."],
        "excludePaths": [],
        "surfaces": [],
        "explicitExclusions": [],
        "deferred": [{"id": "fixture-pending", "reason": "Synthetic unresolved review."}]
        if completeness == "partial"
        else [],
    }
    manifest: dict[str, Any] = {
        "documentType": "codex-security.scan-manifest",
        "schemaVersion": "1.0",
        "scan": {
            "id": "fixture-scan",
            "producer": {"name": "codex-security-plugin", "version": "0.1.0"},
            "status": "completed",
            "startedAt": "2026-10-10T00:00:00Z",
            "completedAt": "2026-10-10T00:01:00Z",
            "sealedAt": "2026-10-10T00:01:00Z",
            "target": {
                "kind": "git_revision",
                "targetId": "fixture-target",
                "displayName": repository.id,
                "revision": repository.revision,
            },
            "scope": {"includePaths": ["."], "excludePaths": []},
            "coverageRef": "coverage.json",
            "findingsRef": "findings.json",
            "artifacts": [],
        },
    }
    for name, packet in (("findings.json", findings), ("coverage.json", coverage)):
        raw = (json.dumps(packet, indent=2) + "\n").encode()
        (directory / name).write_bytes(raw)
        manifest["scan"]["artifacts"].append(
            {
                "path": name,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "mediaType": "application/json",
            }
        )
    (directory / "scan-manifest.json").write_bytes((json.dumps(manifest, indent=2) + "\n").encode())
    return ImportScope(directory.resolve(), repository)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = import_codex_json(fixture(args.output))
    assert (
        report.findings == () and report.completeness == "partial" and not report.conclusive_import
    )
    print(json.dumps(report.public_dict()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
