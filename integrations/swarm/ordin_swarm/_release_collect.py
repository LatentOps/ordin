"""Transcribe fixed installed helper outputs; report bytes are never authority."""

import hashlib
import json
from pathlib import Path
import sys


def collect(inputs_path: Path, directory: Path):
    from ordin.schema import validate_named_schema
    from ordin_swarm.release_evidence import CHECKS, build_manifest, not_evaluated, artifact_errors

    def load(name, schema=None):
        path = directory / name
        if path.is_symlink() or path.stat().st_size > 8388608:
            raise ValueError("collector requires bounded owned artifacts")
        report = json.loads(path.read_text())
        if schema and validate_named_schema(schema, report):
            raise ValueError("fixed helper report violated its published contract")
        return report

    inputs = json.loads(inputs_path.read_text())
    checks = {
        name: not_evaluated(name, "dedicated_gate_not_run_in_this_collection") for name in CHECKS
    }

    def passed(name, artifact, boundary, count=1, skipped=0, physical=False):
        checks[name] = {
            "id": name,
            "status": "passed",
            "producer": "fixed_installed_helper",
            "observed_boundary": boundary,
            "physical_enforcement": physical,
            "artifact": artifact,
            "passed": count,
            "failed": 0,
            "skipped": skipped,
            "reason_code": "fixed_owned_checks_passed",
        }

    core = load("core-compatibility.json")
    if core["failed"] or not core["v0_3_surface_preserved"] or core["source_overlay"]:
        raise ValueError("core-only compatibility probe failed")
    passed("core_compatibility", "core-compatibility.json", "review_only", core["passed"])
    quick = load("quickstart.json", "swarm_quickstart")
    if (
        quick["physical_enforcement"]
        or quick["observe_only"]["callbacks_invoked"]
        or quick["shadow"]["execution_performed"]
        or quick["shadow"]["disposition_changes"]
    ):
        raise ValueError("quickstart blurred review and physical execution")
    mediated = quick["mediated"]
    if not (
        mediated["allowed_read_completed"]
        and mediated["private_handoff_delivered"]
        and mediated["source_flow_violated"]
        and mediated["denied_reviews"] >= 2
        and not mediated["egress_callbacks"]
        and not mediated["child_callbacks"]
    ):
        raise ValueError("two-agent callback fixture failed")
    passed("two_agent_quickstart", "quickstart.json", "host_owned_callbacks")
    passed("custom_sdk", "quickstart.json", "host_owned_callbacks")
    owned = load("owned-demo.json", "swarm_owned_demo")
    if sys.platform == "linux":
        if not (
            owned["status"] == "completed"
            and owned["physical_enforcement"]
            and owned["allowed_read_completed"]
            and not owned["whole_host_enforced"]
            and owned["authorization_replay"] == "refused"
            and owned["stale_epoch_authorization"] == "refused"
            and owned["mediated_out_of_scope_request"] == "denied_before_worker"
            and owned["raw_host_bypass"] == "uncovered_success"
        ):
            raise ValueError("required owned Linux evidence was not established")
        passed("owned_linux_worker", "owned-demo.json", "owned_linux_read_worker", physical=True)
    else:
        if owned["status"] != "unsupported" or owned["physical_enforcement"] is not False:
            raise ValueError("Windows must preserve the unsupported Linux boundary")
        checks["owned_linux_worker"] = {
            "id": "owned_linux_worker",
            "status": "unsupported",
            "producer": "fixed_installed_helper",
            "observed_boundary": "unsupported",
            "physical_enforcement": False,
            "artifact": "owned-demo.json",
            "passed": 0,
            "failed": 0,
            "skipped": 1,
            "reason_code": "owned_linux_worker_unsupported_on_windows",
        }
        passed("windows_unsupported_control", "owned-demo.json", "unsupported")
    groups = ("mcp", "hooks", "coordinator_restart", "multi_host_epochs")
    for group in groups:
        filename = group.replace("_", "-") + ".json"
        report = load(filename)
        if (
            report["exit_code"]
            or report["failed"]
            or report["passed"] < 1
            or report["source_overlay"]
        ):
            raise ValueError("required installed conformance group failed")
        boundary = (
            "host_owned_callbacks" if group in {"mcp", "hooks"} else "real_mtls_sqlite_admission"
        )
        passed(group, filename, boundary, report["passed"], report["skipped"])
        checks[group]["producer"] = "fixed_installed_regression"
    corpus = load("corpus.json", "swarm_corpus_report")
    if (
        not corpus["ok"]
        or corpus["revision"] != inputs["source"]["commit"]
        or (sys.platform == "linux" and not corpus["scope"]["kernel_requested"])
    ):
        raise ValueError("corpus did not establish its declared lane")
    passed(
        "corpus",
        "corpus.json",
        "review_only",
        corpus["scope"]["evaluated"],
        corpus["metrics"]["kernel_not_run"] + corpus["metrics"]["optional_not_evaluated"],
    )
    overhead = None
    if sys.platform == "linux":
        overhead = load("overhead.json", "swarm_overhead_report")
        if not overhead["ok"] or overhead["revision"] != inputs["source"]["commit"]:
            raise ValueError("predeclared overhead gate failed")
        passed("overhead", "overhead.json", "host_owned_callbacks", overhead["samples_per_shape"])
    environment_report = load("environment.json")
    environment_report.pop("schema_version")
    names = [
        "test-fixtures.json",
        "core-compatibility.json",
        "quickstart.json",
        "owned-demo.json",
        "environment.json",
        *(name.replace("_", "-") + ".json" for name in groups),
        "corpus.json",
    ]
    if overhead:
        names.append("overhead.json")
    artifacts = []
    for name in names:
        raw = (directory / name).read_bytes()
        item = json.loads(raw)
        artifacts.append(
            {
                "name": name,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "bytes": len(raw),
                "kind": "benchmark" if name in {"corpus.json", "overhead.json"} else "data_report",
                "schema_version": item["schema_version"],
            }
        )
    return finish(inputs, environment_report, artifacts, checks, corpus, overhead, directory)


def finish(inputs, environment_report, artifacts, checks, corpus, overhead, directory):
    from ordin_swarm.release_evidence import CHECKS, build_manifest, artifact_errors

    locks = {item["name"]: item["sha256"] for item in inputs["locks"]}
    references = []
    for name, workflow, lock in (
        ("langgraph", ".github/workflows/swarm-frameworks.yml", "requirements/swarm-langgraph.txt"),
        ("crewai", ".github/workflows/swarm-frameworks.yml", "requirements/swarm-crewai.txt"),
        (
            "legacy_autogen",
            ".github/workflows/swarm-frameworks.yml",
            "requirements/swarm-autogen.txt",
        ),
        ("postgres", ".github/workflows/coordinator.yml", "requirements/coordinator-postgres.txt"),
        ("openshell", ".github/workflows/runtime-extension.yml", None),
    ):
        references.append(
            {
                "checks": [name],
                "workflow": workflow,
                "workflow_sha256": inputs["workflow_hashes"][workflow],
                "observed_status": "not_evaluated",
                "required_lock_sha256": locks[lock] if lock else None,
                "observed_artifact_sha256": None,
                "reason_code": "dedicated_gate_not_run_in_this_collection",
            }
        )
    metrics = corpus["metrics"]
    benchmarks = {
        "corpus_artifact": "corpus.json",
        "corpus_result_sha256": corpus["result_sha256"],
        "cases": corpus["scope"]["cases"],
        "evaluated": corpus["scope"]["evaluated"],
        **{
            key: metrics[key]
            for key in (
                "kernel_not_run",
                "optional_not_evaluated",
                "critical_misses",
                "false_allows",
                "false_blocks",
                "unnecessary_approvals",
                "unknowns",
                "uncovered_paths",
            )
        },
        "overhead_artifact": "overhead.json" if overhead else None,
        "p95_budget_ms": 250.0,
        "p99_budget_ms": 500.0,
        "samples_per_shape": overhead["samples_per_shape"] if overhead else 0,
        "requested_long_actions": overhead["long_session"]["requested_actions"] if overhead else 0,
        "completed_long_actions": overhead["long_session"]["completed_actions"] if overhead else 0,
        "retained_state_bounded": overhead["long_session"]["bounded"] if overhead else None,
    }
    result = build_manifest(
        source=inputs["source"],
        wheels=inputs["wheels"],
        locks=inputs["locks"],
        environment=environment_report,
        artifacts=artifacts,
        checks=[checks[name] for name in CHECKS],
        benchmarks=benchmarks,
        references=references,
    )
    if artifact_errors(result, directory):
        raise ValueError("collected artifact bytes changed")
    return result
