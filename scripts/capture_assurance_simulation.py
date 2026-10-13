"""Capture pinned SDK/CLI replay and local wheel evidence without source output."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import zipfile
from pathlib import Path

from ordin.assurance._json import loads
from ordin.assurance.cli import simulation_exit_code
from ordin.assurance.simulation import simulate_policy_change
from scripts.freeze_assurance_simulation import DESTINATION, inputs

ROOT = Path(__file__).resolve().parents[1]
REVISION = "3d757a3d1f2a389d526f921c3a45ab3827e4202d"


def main() -> int:
    status = subprocess.run(
        [
            "rtk",
            "proxy",
            "git",
            "status",
            "--porcelain",
            "--untracked-files=no",
            "--",
            "ordin",
            "schemas",
            "pyproject.toml",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    if status.stdout.strip():
        raise ValueError("pinned simulation capture requires unchanged package source")
    pinned = subprocess.run(
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
            "pyproject.toml",
        ],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    if pinned.returncode != 0:
        raise ValueError("package source differs from the declared pinned simulator revision")
    old, new, corpus = inputs()
    report = simulate_policy_change(
        old, new, corpus, baseline_revision=REVISION, candidate_revision=REVISION
    )
    arguments = [
        sys.executable,
        "-m",
        "ordin.assurance.cli",
        "policy",
        "simulate",
        "--baseline",
        str(DESTINATION / "simulation-baseline.json"),
        "--candidate",
        str(DESTINATION / "simulation-candidate.json"),
        "--corpus",
        str(DESTINATION / "simulation-corpus.json"),
        "--baseline-revision",
        REVISION,
        "--candidate-revision",
        REVISION,
    ]
    cli = subprocess.run(arguments, cwd=ROOT, capture_output=True, text=True, timeout=120)
    packet = loads(cli.stdout)
    if cli.returncode != simulation_exit_code(report):
        raise ValueError("SDK/CLI security result mismatch")
    fields = (
        "baseline_core",
        "candidate_core",
        "baseline_final",
        "candidate_final",
        "change",
        "reason_codes",
        "assessable",
        "baseline_effects",
        "candidate_effects",
    )
    if [[a[k] for k in fields] for a in report.as_dict()["cases"]] != [
        [a[k] for k in fields] for a in packet["cases"]
    ]:
        raise ValueError("SDK/CLI replay mismatch")
    wheel = ROOT / ".assurance-work/m4-final-build/ordin-0.4.0.dev0-py3-none-any.whl"
    with zipfile.ZipFile(wheel) as archive:
        checked = 0
        for name in archive.namelist():
            if name.startswith("ordin/") and name.endswith((".py", ".json")):
                if archive.read(name) != (ROOT / name).read_bytes():
                    raise ValueError("final wheel/package source mismatch")
                checked += 1
    wheel_bytes = (ROOT / ".assurance-work/m4-final-wheel-check.json").read_bytes()
    if len(wheel_bytes) > 1_048_576:
        raise ValueError("wheel check report byte limit exceeded")
    # This private helper output contains the doctor's multiline stdout, not an
    # Assurance contract. Keep its digest, without loosening public JSON rules.
    wheel_check = json.loads(wheel_bytes)
    doctor = wheel_check.pop("doctor")
    wheel_check["doctor_stdout_sha256"] = hashlib.sha256(doctor.encode()).hexdigest()
    wheel_check["doctor_verified_success"] = True  # helper uses check=True before writing.
    envelope = {
        "schema_version": "ordin.assurance_m4_evidence.v1",
        "implemented_revision": REVISION,
        "report": report.as_dict(),
        "cli_exit_code": cli.returncode,
        "sdk_cli_decision_parity": True,
        "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
        "wheel_source_files_compared": checked,
        "wheel_check": wheel_check,
        "limitations": [
            "Synthetic offline evidence on Windows/Python 3.13 only; no OS enforcement or optional provider/scanner exercise."
        ],
    }
    target = ROOT / "docs/assurance/evidence/m4-simulation.json"
    target.write_text(json.dumps(envelope, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "implemented_revision": REVISION,
                "cases": len(report.cases),
                "cli_exit_code": cli.returncode,
                "newly_denied": report.newly_denied,
                "critical_misses": report.critical_misses,
                "critical_caught": report.critical_caught,
                "coverage": report.coverage,
                "benign_false_escalations": report.benign_false_escalations,
                "wheel_source_files_compared": checked,
                "sdk_cli_decision_parity": True,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
