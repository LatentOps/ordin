"""Pin trusted local finding/replay test and installed-wheel evidence."""

import argparse
import hashlib
import json
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--junit", type=Path, required=True)
    parser.add_argument("--wheel-check", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--slice",
        choices=("validation_replay", "vetted_source", "workflow_claims"),
        default="validation_replay",
    )
    args = parser.parse_args()
    quiet = subprocess.run(
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
            "integrations/codex_security",
            "pyproject.toml",
            "scripts/check_assurance_wheel.py",
            "scripts/capture_assurance_validation.py",
        ],
        cwd=ROOT,
        capture_output=True,
        timeout=30,
    )
    if quiet.returncode:
        raise ValueError("validation source/tests differ from the pinned implementation")
    raw = args.junit.read_bytes()
    if len(raw) > 1_048_576 or b"<!DOCTYPE" in raw or b"<!ENTITY" in raw:
        raise ValueError("trusted JUnit evidence exceeds the bounded contract")
    xml = ET.fromstring(raw)
    cases = [
        {
            "class": case.get("classname"),
            "name": case.get("name"),
            "outcome": "failed"
            if case.find("failure") is not None or case.find("error") is not None
            else "skipped"
            if case.find("skipped") is not None
            else "passed",
        }
        for case in xml.iter("testcase")
    ]
    if not cases or any(case["outcome"] == "failed" for case in cases):
        raise ValueError("source gate failed or contains no cases")
    wheel_raw = args.wheel_check.read_bytes()
    if len(wheel_raw) > 131072:
        raise ValueError("wheel evidence exceeds the bounded contract")
    wheel = json.loads(wheel_raw)
    from ordin.assurance._schemas import SCHEMAS
    from ordin.schema import SCHEMA_FILES

    smoke = wheel.get("smoke", {})
    demo = smoke.get("finding_validation_demo", {})
    if (
        wheel.get("schema_version") != "ordin.assurance_wheel_check.v1"
        or smoke.get("ok") is not True
        or smoke.get("schemas") != len(SCHEMA_FILES)
        or smoke.get("assurance_schemas") != len(SCHEMAS)
        or demo.get("synthetic_only") is not True
        or demo.get("actions_executed") is not False
        or demo.get("target_code_executed") is not False
        or demo.get("patch_applied") is not False
        or demo.get("validation", {}).get("tested_scope") != "gate_authority_subset"
        or demo.get("fix", {}).get("result") != "fixed-verified"
        or demo.get("fix", {}).get("integrated") is not False
    ):
        raise ValueError(
            "installed wheel evidence lacks current schemas or the inert scoped validation example"
        )
    report = {
        "schema_version": "ordin.assurance_m10_" + args.slice + "_evidence.v1",
        "implemented_revision": args.revision,
        "source_gate": {
            "junit_sha256": hashlib.sha256(raw).hexdigest(),
            "passed": sum(case["outcome"] == "passed" for case in cases),
            "skipped": sum(case["outcome"] == "skipped" for case in cases),
            "cases": cases,
        },
        "installed_wheel_check": wheel,
        "limitations": [
            "Synthetic source, pure gate/policy replay and protected SDK receipt tests only; no live exploit or target-code execution.",
            "Physical host grant/sandbox enforcement is not independently exercised; protected host channels must report actual facts.",
            "Current finding predicates are limited to gate/contract authority subset; other vulnerability classes remain inconclusive.",
            "Sandboxed target-code tests, external Codex validation/fix reports, full CLI lifecycle, broader acceptance and release gates remain open.",
        ],
    }
    if args.slice == "workflow_claims":
        if smoke.get("offline_workflow_claims") is not True:
            raise ValueError("installed wheel lacks the offline workflow import check")
        report["limitations"] = [
            "Saved synthetic external validation/patch/fix/risk artifacts were imported offline; no external workflow, model, upload or real target operation ran.",
            "Native verdicts and capture metadata remain imported claims, never Ordin confirmation, grant, merge or patch authority.",
            "Physical broker and real-model acceptance, broader predicates, integrated CLI/corpus/CI and existing full release/performance gates remain open.",
        ]
    if args.slice in {"vetted_source", "workflow_claims"}:
        if smoke.get("vetted_test_no_execution") is not True:
            raise ValueError("installed wheel lacks the default no-execution vetted-test check")
        if args.slice == "vetted_source":
            report["limitations"] = [
                "Vetted synthetic pure source ran through a fake approved broker; no real target exploitation or private assets were exercised.",
                "Physical isolation/CPU/memory/egress/credential enforcement remains a protected host obligation and is not independently proved by local fake-broker tests.",
                "Source fix verdicts cover the closed canonical lexical predicate and unchanged fixtures only; generic source-code remediation is unverified.",
                "External Codex workflow claim reports, integrated CLI, full corpus/CI and original release/performance gates remain open.",
            ]
        # Pytest may derive parameter IDs from source text. Keep correlation
        # through a digest while preserving the public test function identity.
        for case in report["source_gate"]["cases"]:
            name = case["name"] or ""
            if "[" in name:
                function = name.split("[", 1)[0]
                case["name"] = (
                    function + "[parameter:" + hashlib.sha256(name.encode()).hexdigest()[:16] + "]"
                )
    with args.output.open("x", encoding="utf-8") as output:
        json.dump(report, output, indent=2, sort_keys=True)
        output.write("\n")
    print(
        json.dumps(
            {
                "revision": args.revision,
                "passed": report["source_gate"]["passed"],
                "skipped": report["source_gate"]["skipped"],
                "capture_slice": args.slice,
                "live_external_workflow_executed": False,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
