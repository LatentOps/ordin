"""Source-pinned optional provider checks; no real model/inference claim."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--junit", type=Path, required=True)
    parser.add_argument("--adapter-check", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--slice", choices=("protocol_typesafe", "laya_evaluation"), default="protocol_typesafe"
    )
    args = parser.parse_args()
    result = subprocess.run(
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
            "integrations/decision_models",
            "tests/assurance",
            "pyproject.toml",
        ],
        cwd=ROOT,
        capture_output=True,
        timeout=30,
    )
    if result.returncode:
        raise ValueError("provider source/tests differ from pinned implementation")
    raw = args.junit.read_bytes()
    if len(raw) > 1_048_576 or b"<!DOCTYPE" in raw or b"<!ENTITY" in raw:
        raise ValueError("trusted test evidence outside bounded JUnit contract")
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
        raise ValueError("provider source gate failed or has no cases")
    checked = args.adapter_check.read_bytes()
    if len(checked) > 65536:
        raise ValueError("adapter check byte budget exceeded")
    adapter = json.loads(checked)
    if (
        not adapter["smoke"]["network_process_calls_rejected"]
        or adapter["smoke"]["heavy_model_packages_loaded"]
    ):
        raise ValueError("optional wheel smoke lacks default-path evidence")
    report = {
        "schema_version": "ordin.assurance_m9_" + args.slice + "_evidence.v1",
        "implemented_revision": args.revision,
        "source_gate": {
            "junit_sha256": hashlib.sha256(raw).hexdigest(),
            "passed": sum(case["outcome"] == "passed" for case in cases),
            "skipped": sum(case["outcome"] == "skipped" for case in cases),
            "cases": cases,
        },
        "optional_wheel_check": adapter,
        "limitations": [
            "Offline mocks, fake transports and simulated HTTP streams only; no real TypeSafe account/TLS API or Laya checkpoint loaded.",
            "Actual local/hosted model, independently labeled frozen workloads, effectiveness/friction/latency acceptance and full release gates remain unverified.",
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
                "real_model_evaluated": False,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
