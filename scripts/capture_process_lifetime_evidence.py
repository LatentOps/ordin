"""Capture bounded local verification while retaining failed and partial gates."""

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
        raise ValueError("verification exceeds its evidence size limit")
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def wheel_summary(path):
    report, pin = read(path)
    smoke = report["smoke"]
    if (
        not smoke["ok"]
        or len(report["source_files_compared"]) != 343
        or len(smoke["assurance_modules_imported"]) != 59
        or smoke["standalone_examples"]["example_count"] != 8
        or not smoke["standalone_examples"]["all_passed"]
        or smoke["schemas"] != 99
        or smoke["optional_solver_unavailable"]["solver_result"] != "unavailable"
    ):
        raise ValueError("complete offline distribution verification is missing")
    return {
        "report_sha256": pin,
        "wheel_sha256": report["wheel_sha256"],
        "environment": report["environment"],
        "source_file_count": len(report["source_files_compared"]),
        "module_count": len(smoke["assurance_modules_imported"]),
        "schemas": smoke["schemas"],
        "examples": smoke["standalone_examples"],
        "solver_result": smoke["optional_solver_unavailable"]["solver_result"],
        "console_entrypoint": report["console_entrypoint"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--attempt", choices=("historical", "corrected"), default="historical")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[a-f0-9]{40}", args.revision):
        raise ValueError("exact library revision required")
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
            "integrations",
            "pyproject.toml",
        ],
        cwd=ROOT,
        capture_output=True,
        timeout=30,
    )
    if checked.returncode not in {0, 1}:
        raise ValueError("current/historical library comparison failed")
    prefix = "managed-launch" if args.attempt == "corrected" else "detached-json"
    full_state, full_pin = read(WORK / (prefix + "-installed-all-suite/state.json"))
    if full_state["status"] != "completed" or full_state["revision"] != args.revision:
        raise ValueError("complete current-library regression is not terminal")
    full = junit(WORK / (prefix + "-installed-all-suite/junit.xml"))
    if bool(full_state["returncode"]) != bool(full["failed"]):
        raise ValueError("regression status and JUnit outcomes disagree")
    native, native_pin = read(WORK / ("linux-current-" + args.revision[:7] + "-state.json"))
    if (
        native["source_revision"] != args.revision
        or native["code_overlays"]
        or native["wheel-check"]["returncode"]
        or native["status"] not in {"completed", "failed"}
    ):
        raise ValueError("exact native build/wheel/source evidence is not terminal")
    native_output = WORK / Path(native["output"]).name
    native_tests = junit(native_output / "source-focus.xml")
    fixture, fixture_pin = read(WORK / "linux-fixture-exclusion-focus.json")
    if (
        fixture["source_revision"] != "eb7e32f8418ea45725cdc2013d3cebdb548870bf"
        or fixture["returncode"]
        or fixture["production_code_changed"]
        or fixture["fixture_deadlines_changed"]
        or fixture["production_exclusion_check_changed"]
    ):
        raise ValueError("stricter owned fixture recheck is incomplete")
    diagnostic, diagnostic_pin = read(WORK / "linux-detached-json-diagnostic.json")
    diagnostic_result = json.loads(diagnostic["stdout"])
    report = {
        "schema_version": "ordin.assurance_process_validation_evidence.v1",
        "library_revision": args.revision,
        "current_library_matches_revision": checked.returncode == 0,
        "scope": "Recorded verification for the named library revision; subsequent corrections require their own checks.",
        "overall_acceptance": "incomplete",
        "attempt": args.attempt,
        "windows_wheel": wheel_summary(WORK / (prefix + "-wheel.json")),
        "windows_contract_focus": junit(WORK / "detached-json-validation-final.xml"),
        "windows_core_focus": junit(WORK / "detached-json-core.xml"),
        "windows_resolver_launcher_focus": junit(WORK / "native-startup-and-path.xml"),
        "windows_full_regression": {"state": full_state, "state_sha256": full_pin, "junit": full},
        "historical_windows_combined_failure": junit(WORK / "primary-thread-final-focus.xml"),
        "native_build": {
            "state_sha256": native_pin,
            "source_revision": native["source_revision"],
            "source_archive_sha256": native["source_archive_sha256"],
            "environment": {k: native[k] for k in ("python_version", "path", "uid")},
            "code_overlays": native["code_overlays"],
            "candidate_wheels": native["candidate_wheels"],
            "development_wheels": native["development_wheels"],
            "source_tests": native_tests,
            "wheel": wheel_summary(native_output / "linux-wheel.json"),
        },
        "stricter_native_fixture_recheck": {
            "result": fixture,
            "sha256": fixture_pin,
            "junit": junit(WORK / "linux-fixture-exclusion-focus.xml"),
        },
        "private_native_overlay_diagnostic": {
            "sha256": diagnostic_pin,
            "scope": diagnostic["scope"],
            "overlays": diagnostic["overlays"],
            "path": diagnostic["path"],
            "result": diagnostic_result,
        },
        "historical_native_source_timeout": {
            "timeout_seconds": 900,
            "completed_suite_result": False,
            "partial_log_sha256": hashlib.sha256(
                (WORK / "linux-live-source-focus.txt").read_bytes()
            ).hexdigest(),
        },
        "limitations": [
            "Native source outcomes retain every failed test; the earlier stricter fixture diagnostic is separately identified as a test overlay.",
            "All original process deadlines, byte limits, schema meanings and test assertions are retained.",
            "A private overlay diagnostic is not a fresh wheel, paired latency acceptance or physical isolation proof.",
            "Original 5 ms added-p95 and supported-platform release/CI gates remain open.",
            "Broader M10 predicates/broker, dependent provider generation/promotion and real effectiveness/provider exercises remain unverified.",
        ],
    }
    if args.attempt == "corrected":
        if checked.returncode:
            raise ValueError("corrected verification requires the current library bytes")
        report["corrected_launch_focus"] = junit(WORK / "managed-model-fixture-focus.xml")
        model, model_pin = read(WORK / "managed-launch-model-wheel.json")
        report["optional_model_wheel"] = {"sha256": model_pin, "result": model}
        measured, measured_pin = read(WORK / "managed-launch-overhead-1/report.json")
        if (
            measured["revision"] != args.revision
            or measured["declared_p95_overhead_budget_ms"] != 5
            or measured["case_count"] != 4
            or measured["repetitions"] != 100
            or measured["warmup_rounds"] != 10
        ):
            raise ValueError("paired acceptance workload or threshold differs")
        report["paired_overhead"] = {"sha256": measured_pin, "result": measured}
        report["historical_attempt_sha256"] = hashlib.sha256(
            (ROOT / "docs/assurance/evidence/process-lifetime-verification.json").read_bytes()
        ).hexdigest()
        minimum, minimum_pin = read(WORK / "managed-launch-minimum/report.json")
        if (
            minimum["revision"] != args.revision
            or minimum["fixture_pass_count"] != 35
            or minimum["pytest_exit_code"]
            or minimum["observation_errors"]
            or minimum["partial_coverage_cases"] != ["AT-26", "AT-28"]
        ):
            raise ValueError("minimum contractual audit is incomplete or mismatched")
        report["minimum_acceptance"] = {
            "sha256": minimum_pin,
            "revision": minimum["revision"],
            "fixture_pass_count": minimum["fixture_pass_count"],
            "pytest_exit_code": minimum["pytest_exit_code"],
            "observation_errors": minimum["observation_errors"],
            "partial_coverage_cases": minimum["partial_coverage_cases"],
        }
    rendered = json.dumps(report, sort_keys=True, indent=2)
    for token in (
        "sk-synthetic-private-comment",
        "SYNTHETIC_PRIVATE_VENDOR_VALUE",
        "fixture-secret-never-export",
    ):
        if token in rendered:
            raise ValueError("public evidence contains a private fixture value")
    with args.output.open("x", encoding="utf-8") as output:
        output.write(rendered + "\n")
    print(
        json.dumps(
            {
                "revision": args.revision,
                "full_passed": full["passed"],
                "full_failed": full["failed"],
                "native_failed": native_tests["failed"],
            }
        )
    )


if __name__ == "__main__":
    main()
