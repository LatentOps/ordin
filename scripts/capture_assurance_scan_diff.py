"""Capture pinned offline M8 evidence without raw source or machine metadata."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

from ordin.assurance import AuthorizedRepository, RepositoryScope
from ordin.assurance.codex_security.scanner import mock_scanner_run
from ordin.assurance.diff_triage import triage_source_diff

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--fixture-dir", type=Path, required=True)
    parser.add_argument("--junit", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
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
            "schemas",
            "pyproject.toml",
            "integrations/codex_security",
            "tests/assurance",
        ],
        cwd=ROOT,
        capture_output=True,
        check=False,
        timeout=30,
    )
    if pinned.returncode:
        raise ValueError("scanner/diff package or tests differ from pinned source")
    raw = args.junit.read_bytes()
    if len(raw) > 1_048_576 or b"<!DOCTYPE" in raw or b"<!ENTITY" in raw:
        raise ValueError("test evidence outside bounded trusted JUnit contract")
    xml = ET.fromstring(raw)
    cases = [
        {
            "class": case.attrib.get("classname"),
            "name": case.attrib.get("name"),
            "outcome": "failed"
            if case.find("failure") is not None or case.find("error") is not None
            else "skipped"
            if case.find("skipped") is not None
            else "passed",
        }
        for case in xml.iter("testcase")
    ]
    if not cases or any(case["outcome"] == "failed" for case in cases):
        raise ValueError("pinned M8 source gate failed or lacks cases")
    args.fixture_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    before, after = args.fixture_dir / "before", args.fixture_dir / "after"
    before.mkdir()
    after.mkdir()
    (before / "README.md").write_text("Synthetic old documentation\n", encoding="utf-8")
    (after / "README.md").write_text("Synthetic updated documentation\n", encoding="utf-8")
    (after / "app.py").write_text(
        "import subprocess\nsubprocess.run(['synthetic-only'])\n", encoding="utf-8"
    )
    triage = triage_source_diff(
        AuthorizedRepository(
            before.absolute(), RepositoryScope("fixture/diff", "before"), "/fixture"
        ),
        AuthorizedRepository(
            after.absolute(), RepositoryScope("fixture/diff", "after"), "/fixture"
        ),
    )
    report = {
        "schema_version": "ordin.assurance_m8_scanner_diff_evidence.v1",
        "implemented_revision": args.revision,
        "source_gate": {
            "junit_sha256": hashlib.sha256(raw).hexdigest(),
            "passed": sum(case["outcome"] == "passed" for case in cases),
            "skipped": sum(case["outcome"] == "skipped" for case in cases),
            "cases": cases,
        },
        "mock_states": [mock_scanner_run(exit_code=code).as_dict() for code in (0, 1, 2, 130, 143)],
        "offline_source_triage": triage.public_dict(),
        "limitations": [
            "Built-in mocks and actual local synthetic fake-process tests only; no real scanner, model, credential, source upload or CI runner.",
            "Host-deployed isolation, POSIX process behavior and full release gates remain unverified.",
        ],
    }
    with args.output.open("x", encoding="utf-8") as output:
        json.dump(report, output, indent=2, sort_keys=True)
        output.write("\n")
    print(
        json.dumps(
            {
                "revision": args.revision,
                "passed": report["source_gate"]["passed"],
                "skipped": report["source_gate"]["skipped"],
                "review_required": triage.review_required,
                "real_scanner_invoked": False,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
