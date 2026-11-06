"""Explicit unmeasured data example; it does not assert a test run occurred."""

import hashlib
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "integrations/swarm"))
from ordin_swarm.release_evidence import CHECKS, build_manifest, not_evaluated

RAW = b'{"schema_version":"synthetic.release.example.v1"}\n'
LOCKS = (
    "requirements/dev-baseline.txt",
    "requirements/coordinator-postgres.txt",
    "requirements/swarm-langgraph.txt",
    "requirements/swarm-crewai.txt",
    "requirements/swarm-autogen.txt",
)


def manifest_sample():
    return build_manifest(
        source={
            "commit": "a" * 40,
            "tree": "b" * 40,
            "clean": True,
            "source_bytes_verified": True,
            "git_hooks_executed": False,
            "code_resource_sha256": "c" * 64,
        },
        wheels=[
            {
                "name": name,
                "filename": filename,
                "sha256": "d" * 64,
                "bytes": 1,
                "requires_dist": [],
            }
            for name, filename in (
                ("ordin", "ordin-example.whl"),
                ("ordin-swarm", "ordin_swarm-example.whl"),
            )
        ],
        locks=[
            {"name": name, "sha256": "e" * 64, "pin_format": "pip_require_hashes"} for name in LOCKS
        ],
        environment={
            "python": "3.12.3",
            "implementation": "CPython",
            "platform": "linux",
            "kernel_release": "synthetic_schema_example",
            "machine": "x86_64",
            "logical_cpu_count": 2,
            "package_origin": "isolated_wheels",
            "optional_risk_module_installed": False,
            "optional_risk_configured": False,
            "hosted_model_providers_installed": False,
            "llm_inference_exercised": False,
        },
        artifacts=[
            {
                "name": "example.json",
                "sha256": hashlib.sha256(RAW).hexdigest(),
                "bytes": len(RAW),
                "kind": "data_report",
                "schema_version": "synthetic.release.example.v1",
            }
        ],
        checks=[not_evaluated(name, "synthetic_schema_example") for name in CHECKS],
        benchmarks={
            "corpus_artifact": "example.json",
            "corpus_result_sha256": "f" * 64,
            "cases": 0,
            "evaluated": 0,
            "kernel_not_run": 0,
            "optional_not_evaluated": 0,
            "critical_misses": 0,
            "false_allows": 0,
            "false_blocks": 0,
            "unnecessary_approvals": 0,
            "unknowns": 0,
            "uncovered_paths": 0,
            "overhead_artifact": None,
            "p95_budget_ms": 250.0,
            "p99_budget_ms": 500.0,
            "samples_per_shape": 0,
            "requested_long_actions": 0,
            "completed_long_actions": 0,
            "retained_state_bounded": None,
        },
        references=[
            {
                "checks": [name],
                "workflow": workflow,
                "workflow_sha256": "0" * 64,
                "observed_status": "not_evaluated",
                "required_lock_sha256": None,
                "observed_artifact_sha256": None,
                "reason_code": "dedicated_gate_not_run_in_this_collection",
            }
            for name, workflow in (
                ("langgraph", ".github/workflows/swarm-frameworks.yml"),
                ("crewai", ".github/workflows/swarm-frameworks.yml"),
                ("legacy_autogen", ".github/workflows/swarm-frameworks.yml"),
                ("postgres", ".github/workflows/coordinator.yml"),
                ("openshell", ".github/workflows/runtime-extension.yml"),
            )
        ],
    )
