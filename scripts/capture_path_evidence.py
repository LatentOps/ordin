"""Pin installed PATH batching evidence without replacing original failed gates."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from capture_catalog_evidence import read
from capture_assurance_developer_experience import junit

ROOT = Path(__file__).resolve().parents[1]
REVISION = "6120e15731ce414465dbecb72fe6cb577f2d2c81"


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
        raise ValueError("PATH candidate source differs from measured revision")
    work = ROOT / ".assurance-work"
    state, state_sha = read(work / "path-installed-all-suite/state.json")
    if state["revision"] != REVISION or state["status"] != "completed" or state["returncode"] != 0:
        raise ValueError("PATH full suite is incomplete or failed")
    report = {
        "schema_version": "ordin.path_lookup_evidence.v1",
        "implemented_revision": REVISION,
        "release_acceptance": "failed_open_gates",
        "full_regression": {
            "state": state,
            "state_sha256": state_sha,
            "junit": junit(work / "path-installed-all-suite/junit.xml"),
        },
        "assurance_search_focus": junit(work / "path-assurance.xml"),
        "privacy_fallback_focus": junit(work / "path-privacy.xml"),
        "directory_limits": {"path_entries": 128, "names_per_directory": 1024},
        "agent_corpus": {
            "source": "Actual completed installed-wheel command stdout",
            "revision": REVISION,
            "returncode": 0,
            "cases": 9,
            "errors": [],
            "raw_report_hash": None,
        },
        "limitations": [
            "Local Windows/Python 3.13 and available older tooling; no remote CI result.",
            "Availability remains a ranking hint; stdlib which resolves actual candidates and no result survives a search.",
            "Source membership/environment changes refuse return; unknown/large/inaccessible/remote/device namespaces retain original probing.",
            "Full, safety, integration and functional gates pass while the original paired 5 ms added-p95 gate remains failed.",
            "No real model/scanner, physical broker/host, upload, patch/policy installation or publication.",
        ],
    }
    for name, filename, omit in (
        ("wheel", "path-privacy-wheel.json", ()),
        ("safety_first", "path-safety-benchmark.json", ()),
        ("safety_second", "path-safety-benchmark-2.json", ()),
        ("integration", "path-integration-evaluation.json", ("workloads",)),
        ("runtime", "path-runtime-evaluation.json", ()),
        ("trajectory", "path-trajectory.json", ()),
        ("regression", "path-regression-replay.json", ("results",)),
    ):
        value, digest = read(work / filename)
        if "revision" in value and value["revision"] != REVISION:
            raise ValueError("PATH report refers to another source revision")
        report[name] = {
            "result": {k: v for k, v in value.items() if k not in omit},
            "sha256": digest,
        }
    measurements = []
    for index in range(1, 4):
        value, digest = read(ROOT / f"docs/assurance/evidence/path-overhead-{index}.json")
        if value["revision"] != REVISION or value["declared_p95_overhead_budget_ms"] != 5:
            raise ValueError("PATH overhead source/budget differs from declared candidate")
        measurements.append({"result": value, "sha256": digest})
    report["overhead_measurements"] = measurements
    rendered = json.dumps(report, indent=2, sort_keys=True)
    for marker in (
        "fixture-secret-never-export",
        "SYNTHETIC_PRIVATE_VENDOR_VALUE",
        "sk-synthetic-private-comment",
    ):
        if marker in rendered:
            raise ValueError("public PATH evidence contains private fixture data")
    with args.output.open("x", encoding="utf-8") as stream:
        stream.write(rendered + "\n")
    print(
        json.dumps(
            {
                "revision": REVISION,
                "full_passed": report["full_regression"]["junit"]["passed"],
                "full_failed": report["full_regression"]["junit"]["failed"],
                "evidence_sha256": hashlib.sha256(rendered.encode()).hexdigest(),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
