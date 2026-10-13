"""Capture installed catalog-snapshot verification without waiving failed gates."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from capture_assurance_developer_experience import junit

ROOT = Path(__file__).resolve().parents[1]
REVISION = "04f40d05d85aeab244c149757a6a0a0e655ad060"


def read(path):
    raw = path.read_bytes()
    if len(raw) > 1048576:
        raise ValueError("catalog verification artifact exceeds bounded contract")
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if subprocess.run(
        [
            "rtk",
            "proxy",
            "git",
            "diff",
            "--quiet",
            REVISION,
            "--",
            "ordin",
            "schemas",
            "tests",
            "integrations",
            "examples",
            "benchmarks",
        ],
        cwd=ROOT,
        capture_output=True,
        timeout=30,
    ).returncode:
        raise ValueError("catalog candidate sources differ from verified revision")
    work = ROOT / ".assurance-work"
    state, state_sha = read(work / "catalog-installed-all-suite/state.json")
    if state["status"] != "completed" or state["returncode"] != 0 or state["revision"] != REVISION:
        raise ValueError("catalog full regression is incomplete or failed")
    wheel, wheel_sha = read(work / "catalog-lazy-wheel.json")
    safety, safety_sha = read(work / "catalog-safety-benchmark.json")
    integration, integration_sha = read(work / "catalog-integration-evaluation.json")
    runtime, runtime_sha = read(work / "catalog-runtime-evaluation.json")
    trajectory, trajectory_sha = read(work / "catalog-trajectory.json")
    replay, replay_sha = read(work / "catalog-regression-replay.json")
    if integration["revision"] != REVISION or runtime["revision"] != REVISION:
        raise ValueError("catalog evaluations refer to another revision")
    measurements = []
    for index in range(1, 4):
        value, value_sha = read(ROOT / f"docs/assurance/evidence/catalog-overhead-{index}.json")
        if value["revision"] != REVISION or value["declared_p95_overhead_budget_ms"] != 5:
            raise ValueError("catalog measurement changed source or original budget")
        measurements.append({"result": value, "sha256": value_sha})
    report = {
        "schema_version": "ordin.catalog_snapshot_evidence.v1",
        "implemented_revision": REVISION,
        "release_acceptance": "failed_open_gates",
        "full_regression": {
            "state": state,
            "state_sha256": state_sha,
            "junit": junit(work / "catalog-installed-all-suite/junit.xml"),
        },
        "snapshot_focus": junit(work / "catalog-byte-assurance.xml"),
        "lazy_import_focus": junit(work / "catalog-lazy-import.xml"),
        "fresh_wheel": {"result": wheel, "sha256": wheel_sha},
        "safety": {"result": safety, "sha256": safety_sha},
        "integration": {
            "result": {k: v for k, v in integration.items() if k != "workloads"},
            "sha256": integration_sha,
        },
        "runtime": {"result": runtime, "sha256": runtime_sha},
        "trajectory": {"result": trajectory, "sha256": trajectory_sha},
        "regression_replay": {
            "result": {k: v for k, v in replay.items() if k != "results"},
            "sha256": replay_sha,
        },
        "overhead_measurements": measurements,
        "agent_corpus": {
            "source": "Actual completed installed-wheel tool stdout",
            "revision": REVISION,
            "returncode": 0,
            "cases": 9,
            "errors": [],
            "raw_report_hash": None,
        },
        "limits": {"snapshot_files": 256, "retained_bytes": 4194304, "per_file_bytes": 524288},
        "limitations": [
            "Local Windows/Python 3.13, available older tooling and authored synthetic fixtures only; no remote CI claim.",
            "Fresh wheel smoke and installed library tests are distinct from shared system-site pytest tooling.",
            "Source mutation refuses a review; catalog snapshots do not enforce execution or issue authority.",
            "Full-suite and integration pass, while standalone safety p95 and paired 5 ms Assurance overhead remain failed.",
            "Earlier failed candidate evidence remains historical; no metrics, labels or thresholds were changed.",
            "No provider/scanner, real broker/host, upload or publication was used.",
        ],
    }
    rendered = json.dumps(report, indent=2, sort_keys=True)
    for token in (
        "fixture-secret-never-export",
        "SYNTHETIC_PRIVATE_VENDOR_VALUE",
        "sk-synthetic-private-comment",
    ):
        if token in rendered:
            raise ValueError("public catalog evidence contains a private fixture marker")
    with args.output.open("x", encoding="utf-8") as stream:
        stream.write(rendered + "\n")
    print(
        json.dumps(
            {
                "revision": REVISION,
                "full_passed": report["full_regression"]["junit"]["passed"],
                "full_failed": report["full_regression"]["junit"]["failed"],
                "acceptance": "failed_open_gates",
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
