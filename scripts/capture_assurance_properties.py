"""Capture pinned expanded properties, CLI parity and the source-matched wheel."""

import argparse
import hashlib
import json
import subprocess
import sys
import zipfile
from pathlib import Path

from ordin.assurance import challenge_security_properties

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True)
    args = parser.parse_args()
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
            "pyproject.toml",
        ],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    if changed.returncode:
        raise ValueError("property source differs from declared revision")
    actual = challenge_security_properties(seed=14, revision=args.revision, trials_per_property=32)
    seeded = challenge_security_properties(
        seed=14, revision=args.revision, trials_per_property=32, variant="seeded_unsafe_checker"
    )
    assert actual.failures == 0 and sum(v.evaluated for v in actual.runs) == 244
    assert seeded.failures > 0 and all(v.generated == 32 for v in seeded.runs)
    cli = subprocess.run(
        [
            sys.executable,
            "-m",
            "ordin.assurance.cli",
            "challenge",
            "run",
            "--suite",
            "--seed",
            "14",
            "--revision",
            args.revision,
            "--trials",
            "32",
            "--time-budget-ms",
            "30000",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    parsed = json.loads(cli.stdout)
    assert cli.returncode == 2 and parsed["status"] == "inconclusive"
    assert [
        (v["input_manifest_digest"], v["generated"], v["failures"]) for v in parsed["runs"]
    ] == [(v.input_manifest_digest, v.generated, v.failures) for v in actual.runs]
    wheel = ROOT / ".assurance-work/m5-expanded-build/ordin-0.4.0.dev0-py3-none-any.whl"
    with zipfile.ZipFile(wheel) as archive:
        count = 0
        for name in archive.namelist():
            if name.startswith("ordin/") and name.endswith((".py", ".json")):
                assert archive.read(name) == (ROOT / name).read_bytes()
                count += 1
    raw_check = (ROOT / ".assurance-work/m5-expanded-wheel-check.json").read_bytes()
    if len(raw_check) > 1_048_576:
        raise ValueError("wheel report byte limit")
    check = json.loads(raw_check)
    check["doctor_stdout_sha256"] = hashlib.sha256(check.pop("doctor").encode()).hexdigest()
    check["doctor_verified_success"] = True
    report = {
        "schema_version": "ordin.assurance_m5_properties_evidence.v1",
        "implemented_revision": args.revision,
        "actual_suite": actual.as_dict(),
        "seeded_suite": seeded.as_dict(),
        "cli_exit_code": cli.returncode,
        "sdk_cli_manifest_parity": True,
        "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
        "wheel_source_files_compared": count,
        "wheel_check": check,
        "limitations": [
            "Synthetic local fixtures; no real host enforcement, remote CI, optional solver, scanner or model invocation."
        ],
    }
    (ROOT / "docs/assurance/evidence/m5-expanded-properties.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "revision": args.revision,
                "actual_generated": sum(v.generated for v in actual.runs),
                "actual_assessed": sum(v.evaluated for v in actual.runs),
                "actual_unresolved": sum(v.unresolved for v in actual.runs),
                "seeded_failures": seeded.failures,
                "replayed_minimized_records": sum(len(v.counterexamples) for v in seeded.runs),
                "cli_exit_code": cli.returncode,
                "wheel_source_files_compared": count,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
