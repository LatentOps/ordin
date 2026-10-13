"""Pin trusted offline CLI/quickstart and affected host regression evidence."""

import argparse
import hashlib
import json
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def junit(path):
    raw = path.read_bytes()
    if len(raw) > 1048576 or b"<!DOCTYPE" in raw or b"<!ENTITY" in raw:
        raise ValueError("trusted test evidence exceeds the bounded contract")
    result = ET.fromstring(raw)
    cases = []
    for case in result.iter("testcase"):
        name = case.get("name", "")
        if "[" in name:
            name = (
                name.split("[", 1)[0]
                + "[parameter:"
                + hashlib.sha256(name.encode()).hexdigest()[:16]
                + "]"
            )
        cases.append(
            {
                "class": case.get("classname"),
                "name": name,
                "outcome": "failed"
                if case.find("failure") is not None or case.find("error") is not None
                else "skipped"
                if case.find("skipped") is not None
                else "passed",
            }
        )
    if not cases:
        raise ValueError("test evidence contains no cases")
    return {
        "sha256": hashlib.sha256(raw).hexdigest(),
        "passed": sum(c["outcome"] == "passed" for c in cases),
        "failed": sum(c["outcome"] == "failed" for c in cases),
        "skipped": sum(c["outcome"] == "skipped" for c in cases),
        "cases": cases,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--source-junit", type=Path, required=True)
    parser.add_argument("--host-junit", type=Path, required=True)
    parser.add_argument("--openshell-junit", type=Path, required=True)
    parser.add_argument("--wheel-check", type=Path, required=True)
    parser.add_argument("--installed-runtime", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    checked = subprocess.run(
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
            "tests/assurance",
            "integrations/decision_models",
            "examples/assurance",
            "scripts/check_assurance_wheel.py",
            "scripts/capture_assurance_developer_experience.py",
        ],
        cwd=ROOT,
        capture_output=True,
        timeout=30,
    )
    if checked.returncode:
        raise ValueError("developer experience source/tests differ from pinned revision")
    source, host, openshell = (
        junit(args.source_junit),
        junit(args.host_junit),
        junit(args.openshell_junit),
    )
    if source["failed"] or openshell["failed"]:
        raise ValueError("mandatory source/OpenShell gate failed")
    raw = args.wheel_check.read_bytes()
    if len(raw) > 131072:
        raise ValueError("wheel check exceeds bounded evidence contract")
    wheel = json.loads(raw)
    smoke = wheel["smoke"]
    quickstart = smoke.get("offline_quickstart", {})
    if (
        not smoke.get("ok")
        or quickstart.get("actions_executed") is not False
        or quickstart.get("model_or_scanner_called") is not False
        or quickstart.get("offline_finding_import", {}).get("finding_confirmation")
        != "not_performed"
    ):
        raise ValueError("wheel does not prove the inert installed quickstart")
    runtime_raw = args.installed_runtime.read_bytes()
    if len(runtime_raw) > 131072:
        raise ValueError("runtime check exceeds bounded evidence contract")
    runtime = json.loads(runtime_raw)
    if (
        runtime.get("schema_version") != "ordin.runtime_integration_evaluation.v1"
        or runtime.get("revision") != args.revision
        or runtime.get("scope", {}).get("cases") != 17
        or runtime.get("pass_count") != 17
        or runtime.get("failure_count") != 0
        or runtime.get("errors") != []
        or runtime.get("configuration", {}).get("model_inference_used") is not False
    ):
        raise ValueError("installed runtime evidence is incomplete or mismatched")
    report = {
        "schema_version": "ordin.assurance_m11_developer_experience_evidence.v1",
        "implemented_revision": args.revision,
        "source_gate": source,
        "host_source_environment_gate": host,
        "openshell_gate": openshell,
        "installed_wheel_check": wheel,
        "installed_runtime_check": runtime,
        "installed_runtime_check_sha256": hashlib.sha256(runtime_raw).hexdigest(),
        "limitations": [
            "Owned synthetic fixtures/local Windows Python only; no live host, provider, scanner or OS grant acceptance.",
            "Source host gate retains the isolated-subprocess environment failure; installed candidate evaluation verifies the 17 protocol cases separately.",
            "Whole-objective effectiveness, corpus/CI and original release/performance gates remain open.",
        ],
    }
    with args.output.open("x", encoding="utf-8") as output:
        json.dump(report, output, indent=2, sort_keys=True)
        output.write("\n")
    print(
        json.dumps(
            {
                "revision": args.revision,
                "source_passed": source["passed"],
                "host_source_failed": host["failed"],
                "openshell_passed": openshell["passed"],
                "actions_executed": False,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
