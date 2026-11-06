"""Bounded release-accounting data. No manifest is a live runtime proof or permit."""

from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
from typing import Any

from ordin.schema import validate_named_schema

VERSION = "ordin.swarm_release_manifest.v1"
MAX_BYTES = 1048576
CHECKS = (
    "core_compatibility",
    "two_agent_quickstart",
    "custom_sdk",
    "owned_linux_worker",
    "windows_unsupported_control",
    "mcp",
    "hooks",
    "coordinator_restart",
    "multi_host_epochs",
    "corpus",
    "overhead",
    "langgraph",
    "crewai",
    "legacy_autogen",
    "postgres",
    "openshell",
)
EXTERNAL = frozenset({"langgraph", "crewai", "legacy_autogen", "postgres", "openshell"})
COMMON_REQUIRED = frozenset(
    {
        "core_compatibility",
        "two_agent_quickstart",
        "custom_sdk",
        "mcp",
        "hooks",
        "coordinator_restart",
        "multi_host_epochs",
        "corpus",
    }
)
BOUNDARIES = (
    "review_only",
    "host_owned_callbacks",
    "owned_linux_read_worker",
    "real_mtls_sqlite_admission",
    "unsupported",
    "not_evaluated",
    "unknown",
)
LIMITATIONS = (
    "Synthetic fixtures and data-only manifests are not deployment prevalence or runtime authority.",
    "Only the separately observed owned Linux read worker establishes physical enforcement in this gate.",
    "Raw host tools, network, credentials, existing processes and unwrapped routes remain uncovered.",
    "SQLite host-protocol checks do not establish PostgreSQL consensus or production multi-host availability.",
    "External SDK, PostgreSQL and OpenShell checks remain not_evaluated until their actual dedicated gates run.",
    "Local rules and synthetic diagnostics are not LLM inference; no hosted provider is exercised.",
)


def canonical_bytes(value: Any) -> bytes:
    def bounded(item, depth=0):
        if depth > 16:
            raise ValueError("release evidence nesting exceeds its bound")
        if type(item) is dict:
            if len(item) > 512 or any(type(key) is not str for key in item):
                raise ValueError("release evidence object is not bounded JSON")
            for key, child in item.items():
                bounded(key, depth + 1)
                bounded(child, depth + 1)
        elif type(item) is list:
            if len(item) > 1024:
                raise ValueError("release evidence array exceeds its bound")
            for child in item:
                bounded(child, depth + 1)
        elif type(item) is str:
            if len(item) > 4096:
                raise ValueError("release evidence string exceeds its bound")
        elif type(item) is float:
            if not math.isfinite(item):
                raise ValueError("nonfinite release evidence")
        elif type(item) not in {int, bool, type(None)}:
            raise ValueError("release evidence accepts JSON data only")

    bounded(value)
    try:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    except (TypeError, ValueError, RecursionError) as error:
        raise ValueError("release evidence must be bounded finite JSON") from error
    if len(raw) > MAX_BYTES:
        raise ValueError("release evidence exceeds its byte bound")
    return raw


def evidence_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def required_checks(platform: str) -> frozenset[str]:
    if platform not in {"linux", "win32"}:
        raise ValueError("the release gate supports explicit Linux and Windows lanes")
    return COMMON_REQUIRED | (
        frozenset({"owned_linux_worker", "overhead"})
        if platform == "linux"
        else frozenset({"windows_unsupported_control"})
    )


def not_evaluated(check_id: str, reason: str) -> dict[str, Any]:
    if check_id not in CHECKS or not re.fullmatch(r"[a-z][a-z0-9_]{0,95}", reason):
        raise ValueError("closed check identity and finite reason code required")
    return {
        "id": check_id,
        "status": "not_evaluated",
        "producer": "not_run",
        "observed_boundary": "not_evaluated",
        "physical_enforcement": None,
        "artifact": None,
        "passed": 0,
        "failed": 0,
        "skipped": 0,
        "reason_code": reason,
    }


def validate_manifest(value: Any) -> list[str]:
    """Validate report data only; success does not authenticate a producer."""
    try:
        canonical_bytes(value)
        errors = validate_named_schema("swarm_release_manifest", value)
        if errors:
            return errors
        rows = value["checks"]
        by_id = {row["id"]: row for row in rows}
        if len(by_id) != len(rows) or set(by_id) != set(CHECKS):
            errors.append("release.check_inventory_mismatch")
            return errors
        names = {row["name"] for row in value["artifacts"]}
        if len(names) != len(value["artifacts"]):
            errors.append("release.duplicate_artifact")
        for row in rows:
            if row["artifact"] is not None and row["artifact"] not in names:
                errors.append("release.missing_check_artifact")
            if row["status"] == "passed" and (
                row["producer"] not in {"fixed_installed_helper", "fixed_installed_regression"}
                or row["artifact"] is None
                or row["failed"]
                or row["passed"] < 1
            ):
                errors.append("release.passed_check_lacks_owned_observation")
            if row["id"] in EXTERNAL and row["status"] == "passed":
                errors.append("release.external_claim_not_observed_by_this_producer")
            if (
                row["id"] == "owned_linux_worker"
                and row["status"] == "passed"
                and (
                    row["physical_enforcement"] is not True
                    or row["observed_boundary"] != "owned_linux_read_worker"
                    or value["environment"]["platform"] != "linux"
                )
            ):
                errors.append("release.required_linux_boundary_not_observed")
            if (
                row["id"] == "windows_unsupported_control"
                and row["status"] == "passed"
                and (
                    value["environment"]["platform"] != "win32"
                    or row["observed_boundary"] != "unsupported"
                    or row["physical_enforcement"] is not False
                )
            ):
                errors.append("release.windows_unsupported_control_mismatch")
            if row["physical_enforcement"] is True and (
                row["id"] != "owned_linux_worker"
                or row["status"] != "passed"
                or row["observed_boundary"] != "owned_linux_read_worker"
                or value["environment"]["platform"] != "linux"
            ):
                errors.append("release.physical_claim_outside_owned_linux_lane")
            if (
                row["status"] in {"unsupported", "not_evaluated"}
                and row["physical_enforcement"] is True
            ):
                errors.append("release.unmeasured_physical_claim")
        expected_pass = all(
            by_id[name]["status"] == "passed"
            for name in required_checks(value["environment"]["platform"])
        )
        if value["local_gate_passed"] != expected_pass:
            errors.append("release.local_gate_result_mismatch")
        if value["complete_conformance"] != all(row["status"] == "passed" for row in rows):
            errors.append("release.complete_conformance_mismatch")
        if {row["name"] for row in value["wheels"]} != {"ordin", "ordin-swarm"} or len(
            value["wheels"]
        ) != 2:
            errors.append("release.wheel_inventory_mismatch")
        if len({row["name"] for row in value["locks"]}) != len(value["locks"]):
            errors.append("release.duplicate_lock")
        benchmarks = value["benchmarks"]
        if benchmarks["cases"] != sum(
            benchmarks[key] for key in ("evaluated", "kernel_not_run", "optional_not_evaluated")
        ):
            errors.append("release.corpus_denominator_mismatch")
        if benchmarks["corpus_artifact"] not in names or (
            benchmarks["overhead_artifact"] is not None
            and benchmarks["overhead_artifact"] not in names
        ):
            errors.append("release.missing_benchmark_artifact")
        if by_id["corpus"]["status"] == "passed" and any(
            benchmarks[key]
            for key in ("critical_misses", "false_allows", "false_blocks", "unnecessary_approvals")
        ):
            errors.append("release.failed_corpus_cannot_pass")
        if by_id["overhead"]["status"] == "passed" and (
            benchmarks["overhead_artifact"] is None
            or benchmarks["retained_state_bounded"] is not True
        ):
            errors.append("release.failed_overhead_cannot_pass")
        referenced = {name for row in value["external_gate_references"] for name in row["checks"]}
        if referenced != set(EXTERNAL):
            errors.append("release.external_inventory_mismatch")
        material = {key: item for key, item in value.items() if key != "manifest_sha256"}
        if value["manifest_sha256"] != evidence_sha256(material):
            errors.append("release.manifest_digest_mismatch")
        return errors
    except (KeyError, TypeError, ValueError, RecursionError):
        return ["release.invalid_report_data"]


def build_manifest(
    *, source, wheels, locks, environment, artifacts, checks, benchmarks, references
):
    """Serialize fixed-producer observations; never restore executable authority."""

    def copy_data(value):
        return json.loads(canonical_bytes(value))

    rows = copy_data(checks)
    environment = copy_data(environment)
    by_id = {row["id"]: row for row in rows}
    value = {
        "schema_version": VERSION,
        "source": copy_data(source),
        "wheels": copy_data(wheels),
        "locks": copy_data(locks),
        "environment": environment,
        "artifacts": copy_data(artifacts),
        "checks": rows,
        "benchmarks": copy_data(benchmarks),
        "external_gate_references": copy_data(references),
        "expected_boundaries": ["review_only", "host_owned_callbacks", "owned_linux_read_worker"],
        "uncovered_paths": [
            "raw_host_tools",
            "raw_host_network",
            "existing_credentials",
            "unwrapped_processes",
        ],
        "local_gate_passed": all(
            by_id.get(name, {}).get("status") == "passed"
            for name in required_checks(environment["platform"])
        ),
        "complete_conformance": all(
            by_id.get(name, {}).get("status") == "passed" for name in CHECKS
        ),
        "fixture_operator_control": "explicit_owned_fixture_flag",
        "production_rollout_authorized": False,
        "publication_authorized": False,
        "origin_authenticated_by_json": False,
        "execution_authority": False,
        "limitations": list(LIMITATIONS),
    }
    value["manifest_sha256"] = evidence_sha256(value)
    errors = validate_manifest(value)
    if errors:
        raise ValueError("invalid release evidence: " + "; ".join(errors))
    return value


def artifact_errors(manifest: dict[str, Any], directory: Path) -> list[str]:
    """Compare bytes only. Matching hashes do not attest runtime observations."""
    errors = validate_manifest(manifest)
    if errors:
        return errors
    root = directory.resolve(strict=True)
    for item in manifest["artifacts"]:
        path = root / item["name"]
        try:
            if path.is_symlink() or not path.resolve(strict=True).is_relative_to(root):
                raise ValueError("unowned artifact")
            descriptor = os.open(
                path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
            )
            with os.fdopen(descriptor, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size != item["bytes"]:
                    raise ValueError("unexpected artifact type or size")
                raw = stream.read(item["bytes"] + 1)
            if len(raw) != item["bytes"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
                errors.append("release.artifact_bytes_changed")
        except (OSError, ValueError):
            errors.append("release.artifact_unavailable")
    return errors
