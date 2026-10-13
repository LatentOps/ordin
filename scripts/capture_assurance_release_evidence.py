"""Retain exact-candidate fixture, regression and failed performance evidence."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

from capture_assurance_developer_experience import junit

ROOT = Path(__file__).resolve().parents[1]
WORK = Path(".assurance-work")


def read(name):
    raw = (WORK / name).read_bytes()
    if len(raw) > 1048576:
        raise ValueError("trusted release evidence exceeds bounded contract")
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if Path.cwd().resolve() != ROOT:
        raise ValueError("release capture must run from the checked workspace")
    if not re.fullmatch(r"[a-f0-9]{40}", args.revision):
        raise ValueError("release evidence requires an exact candidate")
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
            "examples",
            "benchmarks",
            "scripts/run_assurance_full_regression.py",
            "scripts/measure_assurance_gate.py",
        ],
        cwd=ROOT,
        capture_output=True,
        timeout=30,
    ).returncode:
        raise ValueError("release source/test/measurement files differ from candidate")
    fixture, fixture_sha = read("m12-acceptance-candidate/report.json")
    wheel, wheel_sha = read("m12-acceptance-wheel-check.json")
    runtime, runtime_sha = read("m12-runtime-evaluation.json")
    integration, integration_sha = read("m12-integration-evaluation.json")
    safety, safety_sha = read("m12-safety-benchmark.json")
    trajectory, trajectory_sha = read("m12-trajectory.json")
    replay, replay_sha = read("m12-regression-replay.json")
    try:
        corpus, corpus_sha = read("m12-agent-corpus/report.json")
        corpus_access = "raw report read and hashed"
    except PermissionError:
        observed = json.loads(
            (ROOT / "docs/assurance/evidence/m12-observed-tool-results.json").read_text(
                encoding="utf-8"
            )
        )
        if observed["revision"] != args.revision or observed["agent_corpus"]["returncode"] != 0:
            raise ValueError("observed corpus command did not complete on this candidate")
        corpus = {
            "revision": observed["revision"],
            "ok": observed["agent_corpus"]["ok"],
            "scope": {"cases": observed["agent_corpus"]["cases"]},
            "errors": observed["agent_corpus"]["errors"],
        }
        corpus_sha = None
        corpus_access = "Actual completed tool stdout; raw report PermissionError, no hash claimed"
    measurements = []
    for index in range(1, 4):
        raw = (ROOT / f"docs/assurance/evidence/m12-overhead-{index}.json").read_bytes()
        if len(raw) > 65536:
            raise ValueError("copied overhead evidence exceeds bounded contract")
        result, result_sha = json.loads(raw), hashlib.sha256(raw).hexdigest()
        if result["revision"] != args.revision or result["declared_p95_overhead_budget_ms"] != 5:
            raise ValueError("measurement revision/budget differs from declared candidate")
        measurements.append({"sha256": result_sha, "result": result})
    history = []
    for name in (
        "m12-candidate-full-regression",
        "m12-installed-all-suite",
        "m12-installed-final-all-suite",
    ):
        state, state_sha = read(name + "/state.json")
        if state["status"] != "completed":
            raise ValueError("full regression is not terminal")
        history.append(
            {"state": state, "state_sha256": state_sha, "junit": junit(WORK / name / "junit.xml")}
        )
    if history[-1]["state"]["revision"] != args.revision:
        raise ValueError("latest full regression is not the selected candidate")
    if (
        runtime["revision"] != args.revision
        or integration["revision"] != args.revision
        or corpus["revision"] != args.revision
    ):
        raise ValueError("evaluation reports refer to another revision")
    if fixture["wheel_sha256"] != wheel["wheel_sha256"] or not wheel["smoke"]["ok"]:
        raise ValueError("fixture and fresh-wheel evidence differ")
    # The first acceptance report is retained under its actual earlier SHA.
    # Library bytes were unchanged through the test/example-only follow-ups.
    for relative, expected in fixture["installed_core_sources"].items():
        if hashlib.sha256((ROOT / "ordin" / relative).read_bytes()).hexdigest() != expected:
            raise ValueError("fixture-tested core differs from selected candidate")
    report = {
        "schema_version": "ordin.assurance_m12_release_evidence.v1",
        "candidate_revision": args.revision,
        "release_acceptance": "failed_open_gates",
        "fixture_report": fixture,
        "fixture_report_sha256": fixture_sha,
        "fresh_wheel_check": wheel,
        "fresh_wheel_check_sha256": wheel_sha,
        "full_regression_history": history,
        "overhead_measurements": measurements,
        "safety": {"sha256": safety_sha, "result": safety},
        "integration": {
            "sha256": integration_sha,
            "result": {key: value for key, value in integration.items() if key != "workloads"},
        },
        "runtime": {"sha256": runtime_sha, "result": runtime},
        "trajectory": {"sha256": trajectory_sha, "result": trajectory},
        "regression_replay": {
            "sha256": replay_sha,
            "result": {key: value for key, value in replay.items() if key != "results"},
        },
        "agent_corpus": {
            "sha256": corpus_sha,
            "evidence_access": corpus_access,
            "revision": corpus["revision"],
            "ok": corpus["ok"],
            "scope": corpus["scope"],
            "errors": corpus["errors"],
        },
        "test_environment": {
            "tooling_from_system_site_packages": True,
            "pytest": fixture["environment"]["pytest"],
            "core_import": "installed workspace wheel; no editable source import",
        },
        "limitations": [
            "Local Windows/Python 3.13 only; authored CI is not a remote CI result.",
            "Fixture report retains its actual earlier source SHA; exact core bytes are matched to this candidate.",
            "Earlier full failures remain historical; selected candidate still fails the original safety latency gate.",
            "All three declared 5 ms added-p95 overhead measurements fail; intrinsic timing does not replace paired acceptance.",
            "No independent effectiveness labels, real inference/scanner, physical broker, uploads or publication.",
        ],
    }
    rendered = json.dumps(report, indent=2, sort_keys=True)
    for token in (
        "fixture-secret-never-export",
        "sk-synthetic-raw",
        "SYNTHETIC_PRIVATE_VENDOR_VALUE",
    ):
        if token in rendered:
            raise ValueError("public evidence contains a private fixture marker")
    with args.output.open("x", encoding="utf-8") as stream:
        stream.write(rendered + "\n")
    print(
        json.dumps(
            {
                "candidate": args.revision,
                "fixtures_passed": fixture["fixture_pass_count"],
                "full_passed": history[-1]["junit"]["passed"],
                "full_failed": history[-1]["junit"]["failed"],
                "acceptance": "failed_open_gates",
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
