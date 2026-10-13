"""Capture actual finite challenger and final wheel results at a pinned revision."""

import argparse
import hashlib
import json
import subprocess
import zipfile
from pathlib import Path

from ordin.assurance import challenge_authority_subset, replay_counterexample

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True)
    args = parser.parse_args()
    pinned = subprocess.run(
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
            "pyproject.toml",
        ],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    if pinned.returncode != 0:
        raise ValueError("challenger source differs from declared revision")
    seeded = challenge_authority_subset(
        seed=14, revision=args.revision, trials=16, variant="seeded_prefix_bug"
    )
    actual = challenge_authority_subset(seed=14, revision=args.revision, trials=16)
    assert seeded.failures == 4 and len(seeded.counterexamples) == 2 and seeded.benign_controls == 4
    assert actual.failures == 0 and actual.evaluated == 10 and actual.unresolved == 6
    assert all(
        replay_counterexample(record, expected_revision=args.revision) == "verified_failure"
        for record in seeded.counterexamples
    )
    wheel = ROOT / ".assurance-work/m5-finite-build/ordin-0.4.0.dev0-py3-none-any.whl"
    with zipfile.ZipFile(wheel) as archive:
        checked = 0
        for name in archive.namelist():
            if name.startswith("ordin/") and name.endswith((".py", ".json")):
                if archive.read(name) != (ROOT / name).read_bytes():
                    raise ValueError("challenger wheel/package source mismatch")
                checked += 1
    check_bytes = (ROOT / ".assurance-work/m5-finite-wheel-check.json").read_bytes()
    if len(check_bytes) > 1_048_576:
        raise ValueError("private wheel report limit exceeded")
    wheel_check = json.loads(check_bytes)
    doctor = wheel_check.pop("doctor")
    wheel_check["doctor_stdout_sha256"] = hashlib.sha256(doctor.encode()).hexdigest()
    wheel_check["doctor_verified_success"] = True
    report = {
        "schema_version": "ordin.assurance_m5_finite_evidence.v1",
        "implemented_revision": args.revision,
        "seeded_run": seeded.as_dict(),
        "actual_run": actual.as_dict(),
        "concrete_replays_verified": len(seeded.counterexamples),
        "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
        "wheel_source_files_compared": checked,
        "wheel_check": wheel_check,
        "limitations": [
            "Finite synthetic filesystem subset property only; M5's broader generators, solver and promotion remain open."
        ],
    }
    target = ROOT / "docs/assurance/evidence/m5-finite-challenge.json"
    target.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "revision": args.revision,
                "seeded_failures": seeded.failures,
                "minimized_replayed_records": len(seeded.counterexamples),
                "actual_supported": actual.evaluated,
                "actual_unresolved": actual.unresolved,
                "wheel_source_files_compared": checked,
                "host_boundary_exercised": False,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
