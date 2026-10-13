"""Record pinned zero-finding partial/full import and SARIF unknown coverage."""

import argparse
import json
import subprocess
from pathlib import Path

from ordin.assurance.codex_security import import_codex_json, import_sarif
from examples.assurance.codex_import import fixture

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--fixture-dir", type=Path, required=True)
    args = parser.parse_args()
    pinned = subprocess.run(
        [
            "rtk",
            "proxy",
            "git",
            "diff",
            "--quiet",
            args.revision,
            "--",
            "ordin",
            "data/codex_security",
            "schemas",
            "pyproject.toml",
        ],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    if pinned.returncode:
        raise ValueError("offline importer differs from pinned source")
    args.fixture_dir.mkdir(parents=True, exist_ok=False)
    partial = import_codex_json(fixture(args.fixture_dir / "partial"))
    complete_scope = fixture(args.fixture_dir / "complete", completeness="complete")
    complete = import_codex_json(complete_scope)
    (complete_scope.artifact_root / "results.sarif").write_bytes(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [{"tool": {"driver": {"name": "Codex Security"}}, "results": []}],
            }
        ).encode()
    )
    sarif = import_sarif(complete_scope)
    assert (
        not partial.conclusive_import and complete.conclusive_import and not sarif.conclusive_import
    )
    report = {
        "schema_version": "ordin.assurance_m8_offline_import_evidence.v1",
        "implemented_revision": args.revision,
        "partial": partial.public_dict(),
        "complete_imported_scope": complete.public_dict(),
        "sarif": sarif.public_dict(),
        "limitations": [
            "Synthetic saved artifacts only; no actual security scan, finding reproduction, scanner/provider or credential used."
        ],
    }
    (ROOT / "docs/assurance/evidence/m8-offline-import.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "revision": args.revision,
                "partial": partial.completeness,
                "complete_imported_scope": complete.completeness,
                "sarif": sarif.completeness,
                "confirms_findings": False,
                "scanner_invoked": False,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
