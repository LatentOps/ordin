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
    parser.add_argument("--workload-sync", type=Path)
    parser.add_argument("--workload-async", type=Path)
    parser.add_argument(
        "--slice",
        choices=("protocol_typesafe", "laya_evaluation", "frozen_evaluation"),
        default="protocol_typesafe",
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
            "benchmarks/assurance/v1/semantic",
            "scripts/freeze_assurance_semantic_workload.py",
            "scripts/check_decision_models_wheel.py",
            "scripts/capture_assurance_decision_models.py",
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
    if args.slice == "frozen_evaluation":
        if args.workload_sync is None or args.workload_async is None:
            raise ValueError("frozen evaluation capture requires both actual mock driver runs")
        manifest_path = ROOT / "benchmarks/assurance/v1/semantic/manifest.json"
        manifest_raw = manifest_path.read_bytes()
        manifest = json.loads(manifest_raw)
        if (
            manifest["acceptance_eligible"] is not False
            or manifest["label_protocol"]["independent_adjudication"] is not False
        ):
            raise ValueError("provisional workload cannot attest acceptance")
        runs = {}
        for driver, path in (("sync", args.workload_sync), ("async", args.workload_async)):
            raw = path.read_bytes()
            if len(raw) > 1_048_576:
                raise ValueError("mock workload evidence byte limit exceeded")
            packet = json.loads(raw)
            if (
                packet["schema_version"] != "ordin.semantic_mock_workload_demo.v1"
                or packet["driver"] != driver
                or packet["manifest_sha256"] != hashlib.sha256(manifest_raw).hexdigest()
                or packet["actions_executed"] is not False
                or packet["model_effectiveness_evaluated"] is not False
                or packet["acceptance_eligible"] is not False
                or len(packet["reports"]) != 6
            ):
                raise ValueError("mock workload evidence lacks required scope/manifest binding")
            expected_arms = {
                (partition, mode)
                for partition in ("held_out", "adversarial_shift")
                for mode in ("disabled", "shadow", "enforced-escalation")
            }
            actual_arms = {(arm["report"]["partition"], arm["mode"]) for arm in packet["reports"]}
            if actual_arms != expected_arms:
                raise ValueError("mock workload arms are incomplete")
            runs[driver] = {"sha256": hashlib.sha256(raw).hexdigest(), "result": packet}
        dispositions = lambda run: [
            [case["final"] for case in arm["report"]["cases"]] for arm in run["result"]["reports"]
        ]
        if dispositions(runs["sync"]) != dispositions(runs["async"]):
            raise ValueError("mock sync/async dispositions differ")
        report["provisional_workload"] = {
            "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
            "manifest": manifest,
            "mock_runs": runs,
            "sync_async_disposition_parity": True,
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
