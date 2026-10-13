"""Recheck original failed tests against the installed frozen baseline wheel."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CASES = [
    "tests/test_integration_evaluation.py::test_real_agent_evaluation_passes_all_owned_gates",
    "tests/test_integration_evaluation.py::test_real_agent_evaluation_reports_required_scope_and_metrics",
    "tests/test_integration_examples.py::test_python_quickstart_reviews_executes_and_records_observation",
    "tests/test_integration_examples.py::test_json_subprocess_example_uses_versioned_cli_boundary",
    "tests/test_integration_examples.py::test_ci_gate_allows_safe_command_and_rejects_blocked_command",
    "tests/test_mcp_proxy.py::test_stdio_proxy_exits_when_upstream_stops_with_client_input_open[import time; print('invalid-json', flush=True); time.sleep(30)-1]",
    "tests/test_regression_promotion.py::test_committed_promoted_regressions_replay_cleanly",
    "tests/test_runtime_evaluation.py::test_runtime_integration_evaluation_exercises_process_boundaries",
    "tests/test_safety_benchmark.py::test_repository_safety_fixtures_have_zero_false_allows_and_critical_misses",
    "tests/test_session.py::test_concurrent_store_updates_are_serialized_without_cross_session_state",
    "tests/test_setup.py::test_preview_apply_idempotence_smoke_and_removal_preserve_unrelated_files[claude]",
    "tests/test_setup.py::test_preview_apply_idempotence_smoke_and_removal_preserve_unrelated_files[codex]",
    "tests/test_setup.py::test_preview_apply_idempotence_smoke_and_removal_preserve_unrelated_files[cursor]",
    "tests/test_setup.py::test_opt_in_evidence_and_launcher_configuration_are_explicit[claude]",
    "tests/test_setup.py::test_opt_in_evidence_and_launcher_configuration_are_explicit[codex]",
    "tests/test_setup.py::test_opt_in_evidence_and_launcher_configuration_are_explicit[cursor]",
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    interpreter = args.python.resolve(strict=True)
    if not interpreter.is_relative_to(ROOT / ".assurance-work"):
        raise ValueError("recheck requires the workspace baseline venv")
    inventory = json.loads((ROOT / "docs/assurance/evidence/baseline-inventory.json").read_text())
    for case in CASES:
        filename = case.split("::")[0]
        if (
            hashlib.sha256((ROOT / filename).read_bytes()).hexdigest()
            != (inventory["source_inventory"][filename]["sha256"])
        ):
            raise ValueError("baseline test bytes changed")
    output = args.output.absolute()
    if not output.is_relative_to(ROOT / ".assurance-work") or output.exists():
        raise ValueError("recheck output must be a fresh workspace evidence directory")
    output.mkdir(parents=True)
    env = os.environ.copy()
    env["PATH"] = str(interpreter.parent) + os.pathsep + env.get("PATH", "")
    script = (
        "import sys,ordin,ordin.schema; from pathlib import Path; "
        "assert '.assurance-work' in ordin.__file__; "
        "assert len(ordin.schema.SCHEMA_FILES)==40; "
        "import pytest; raise SystemExit(pytest.main(sys.argv[1:]))"
    )
    command = [
        str(interpreter),
        "-I",
        "-c",
        script,
        "-q",
        "-ra",
        "-p",
        "no:cacheprovider",
        "--basetemp=" + str(output / "tmp"),
        "--junitxml=" + str(output / "junit.xml"),
        *CASES,
    ]
    started = datetime.now(timezone.utc).isoformat()
    result = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True, timeout=600)
    (output / "output.txt").write_text(result.stdout + result.stderr, encoding="utf-8")
    report = {
        "schema_version": "ordin.assurance_baseline_recheck.v1",
        "baseline_revision": inventory["revision"],
        "started_at": started,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "returncode": result.returncode,
        "cases": CASES,
        "output_sha256": hashlib.sha256((result.stdout + result.stderr).encode()).hexdigest(),
        "limitations": ["Focused recheck of original failures, not a full suite rerun."],
    }
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(result.stdout[-10000:])
    print(json.dumps(report))
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
