"""Pin concrete optional failures and confirmed cleanup without broad claims."""

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
        raise ValueError("bounded verification evidence required")
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
    changed = subprocess.run(
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
            "pyproject.toml",
        ],
        cwd=ROOT,
        capture_output=True,
        timeout=30,
    )
    if changed.returncode:
        raise ValueError("current library/tests differ from verified candidate")
    wheel, wheel_pin = read(WORK / "optional-failure-wheel.json")
    installed, installed_pin = read(WORK / "optional-failure-installed.json")
    minimum, minimum_pin = read(WORK / "optional-failure-minimum/report.json")
    source = summary(WORK / "optional-failure-final-focus.xml")
    lifecycle = summary(WORK / "job-cleanup-retained.xml")
    controls = summary(WORK / "job-cleanup-negative.xml")
    installed_tests = summary(WORK / "optional-failure-installed-focus.xml")
    if any(v["failed"] for v in (source, lifecycle, controls, installed_tests)):
        raise ValueError("required current functional verification failed")
    optional, seeded, suite = (installed[name] for name in ("optional", "seeded", "suite"))
    if (
        installed["revision"] != args.revision
        or minimum["revision"] != args.revision
        or minimum["fixture_pass_count"] != 35
        or minimum["pytest_exit_code"]
        or minimum["observation_errors"]
        or minimum["partial_coverage_cases"] != ["AT-26", "AT-28"]
        or len(wheel["source_files_compared"]) != 344
        or len(wheel["smoke"]["assurance_modules_imported"]) != 60
        or not wheel["smoke"]["ok"]
        or optional["status"] != "passed"
        or optional["evaluated"] != 32
        or seeded["failures"] != 24
        or seeded["benign_controls"] != 6
        or len(seeded["counterexamples"]) != 18
        or set(installed["replay_outcomes"]) != {"verified_failure"}
        or suite["unresolved_properties"] != ["authority_subset"]
        or sum(v["generated"] for v in suite["runs"]) != 320
    ):
        raise ValueError("complete offline/minimum evidence is mismatched")
    for relative, pin in wheel["source_files_compared"].items():
        if hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() != pin:
            raise ValueError("wheel differs from current package bytes")
    report = {
        "schema_version": "ordin.assurance_optional_failure_verification.v1",
        "revision": args.revision,
        "overall_acceptance": "incomplete",
        "source_focus": source,
        "lifecycle_focus": lifecycle,
        "cleanup_failure_controls": controls,
        "installed_focus": installed_tests,
        "historical_cleanup_failure": summary(WORK / "optional-failure-full-focus.xml"),
        "historical_zero_wait_cleanup_failure": summary(WORK / "job-cleanup-controls.xml"),
        "wheel": {
            "report_sha256": wheel_pin,
            "wheel_sha256": wheel["wheel_sha256"],
            "source_files": 344,
            "modules": 60,
            "schemas": wheel["smoke"]["schemas"],
            "examples": wheel["smoke"]["standalone_examples"],
            "optional_solver": wheel["smoke"]["optional_solver_unavailable"]["solver_result"],
        },
        "installed_generator": {
            "sha256": installed_pin,
            "generated": 320,
            "assessed": sum(v["evaluated"] for v in suite["runs"]),
            "elapsed_ms": suite["elapsed_ms"],
            "optional_evaluated": 32,
            "seeded_failures": 24,
            "benign_controls": 6,
            "minimized_records": 18,
            "replay_outcomes": installed["replay_outcomes"],
            "spies_active": installed["network_process_spies_active"],
            "source_independent_imports": installed["source_independent_imports"],
        },
        "minimum": {
            "sha256": minimum_pin,
            "passed": 35,
            "observer_errors": [],
            "partial": minimum["partial_coverage_cases"],
        },
        "limitations": [
            "Owned mock/refusal fixtures only; no real model/scanner or physical host security boundary.",
            "Seeded failures belong to a deliberately unsafe fixture consumer, not a production vulnerability claim.",
            "Windows/Python 3.13 verification; current native-platform/full-release/paired timing gates remain separate.",
            "Safe promotion, independent effectiveness labels, broader M10 validation and physical isolation remain open.",
        ],
    }
    rendered = json.dumps(report, sort_keys=True, indent=2)
    for marker in (
        "sk-synthetic-private-comment",
        "SYNTHETIC_PRIVATE_VENDOR_VALUE",
        "fixture-secret-never-export",
    ):
        if marker in rendered:
            raise ValueError("private fixture data in public evidence")
    with args.output.open("x", encoding="utf-8") as output:
        output.write(rendered + "\n")
    print(
        json.dumps(
            {
                "source_passed": source["passed"],
                "installed_passed": installed_tests["passed"],
                "optional_assessed": 32,
                "replayed": 18,
                "minimum_passed": 35,
            }
        )
    )


if __name__ == "__main__":
    main()
