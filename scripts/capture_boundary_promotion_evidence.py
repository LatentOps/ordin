"""Compact evidence for reviewed fixture adoption; no broad release claim."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

from capture_assurance_developer_experience import junit

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / ".assurance-work"


def read(path):
    raw = path.read_bytes()
    if len(raw) > 16 * 1024 * 1024:
        raise ValueError("verification evidence exceeds its byte budget")
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def summary(path):
    result = junit(path)
    result["cases"] = [case for case in result["cases"] if case["outcome"] != "passed"]
    result["passed_case_ids_omitted"] = True
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[a-f0-9]{40}", args.revision):
        raise ValueError("exact implementation revision required")
    if subprocess.run(
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
            "tests",
            "integrations",
            "scripts/check_assurance_wheel.py",
        ],
        cwd=ROOT,
        capture_output=True,
        timeout=30,
    ).returncode:
        raise ValueError("verified code/tests differ from pinned candidate")
    wheel, wheel_pin = read(WORK / "boundary-promotion-wheel.json")
    minimum, minimum_pin = read(WORK / "boundary-promotion-minimum/report.json")
    source = summary(WORK / "boundary-promotion-full-focus.xml")
    focus = summary(WORK / "boundary-promotion-cli.xml")
    example = summary(WORK / "boundary-promotion-demo.xml")
    installed = summary(WORK / "boundary-promotion-installed-focus.xml")
    demo = wheel["smoke"]["boundary_regression_demo"]
    if (
        any(v["failed"] for v in (source, focus, example, installed))
        or not wheel["smoke"]["ok"]
        or len(wheel["source_files_compared"]) != 347
        or len(wheel["smoke"]["assurance_modules_imported"]) != 62
        or wheel["smoke"]["schemas"] != 100
        or not demo["synthetic_review_only"]
        or not demo["failure_and_benign_replayed"]
        or not demo["duplicate_refused"]
        or minimum["revision"] != args.revision
        or minimum["pytest_exit_code"]
        or minimum["fixture_pass_count"] != 35
        or minimum["observation_errors"]
        or minimum["partial_coverage_cases"] != ["AT-26", "AT-28"]
    ):
        raise ValueError("required corpus/wheel/minimum verification is incomplete")
    for relative, pin in wheel["source_files_compared"].items():
        if hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() != pin:
            raise ValueError("installed wheel source differs from current bytes")
    report = {
        "schema_version": "ordin.assurance_boundary_promotion_verification.v1",
        "revision": args.revision,
        "overall_acceptance": "incomplete",
        "source_focus_before_demo_addition": source,
        "promotion_cli_compatibility": focus,
        "runnable_demo_and_examples": example,
        "installed_promotion_schema_focus": installed,
        "historical_benign_control_failure": summary(WORK / "boundary-promotion-first.xml"),
        "wheel": {
            "report_sha256": wheel_pin,
            "wheel_sha256": wheel["wheel_sha256"],
            "source_files": 347,
            "modules": 62,
            "schemas": 100,
            "existing_examples": wheel["smoke"]["standalone_examples"],
            "promotion_demo": demo,
        },
        "minimum": {
            "sha256": minimum_pin,
            "passed": 35,
            "observer_errors": [],
            "partial": minimum["partial_coverage_cases"],
        },
        "limitations": [
            "Owned synthetic review/corpus fixtures; no real human review or live corpus/policy installation claimed.",
            "Dedicated closed fixture regressions preserve scoped evidence and cannot issue host execution authority.",
            "All old core-only trace promotion contracts remain separate and unchanged.",
            "Current native/full original regression and paired latency remain separate release gates.",
            "Broader M10 physical isolation/predicates, real providers and independent effectiveness labels remain open.",
        ],
    }
    rendered = json.dumps(report, sort_keys=True, indent=2)
    for marker in (
        "sk-synthetic-private-comment",
        "SYNTHETIC_PRIVATE_VENDOR_VALUE",
        "fixture-secret-never-export",
    ):
        if marker in rendered:
            raise ValueError("private fixture value in public evidence")
    with args.output.open("x", encoding="utf-8") as output:
        output.write(rendered + "\n")
    print(
        json.dumps(
            {
                "source_passed": source["passed"],
                "installed_passed": installed["passed"],
                "minimum_passed": 35,
                "schemas": 100,
            }
        )
    )


if __name__ == "__main__":
    main()
