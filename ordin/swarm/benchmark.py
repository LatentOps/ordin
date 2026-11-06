"""Versioned offline swarm evaluation. Reports are evidence, never authority."""

from collections import Counter
import hashlib
from importlib.util import find_spec
import math
from pathlib import Path
import platform
import re
import tempfile
from time import perf_counter_ns
from typing import Any

from ordin import __version__
from ordin._json_contracts import load_configuration
from ordin._runtime_json import digest
from ordin.schema import validate_named_schema

from .corpus_controls import CONTROLS, run_control, outcome
from .corpus_kernel import KERNEL_CASES, run_kernel

DEFAULT_CORPUS = Path(__file__).resolve().parents[1] / "resources/swarm/v1/manifest.json"
PROVENANCE = {"captured", "reconstructed", "synthetic_from_failure", "control"}

# These judgments are declared from the scenario specification, independently
# of the Gate/broker result being evaluated. A v1 manifest cannot relabel a
# required hazard as a benign or noncritical case to hide a miss.
BENIGN = frozenset(
    {
        "parallel-reads",
        "legitimate-delegation",
        "bounded-spending",
        "valid-data-sharing",
        "reconnect-resume",
        "kernel-benign",
        "audit-intent-inference",
        "kernel-audit-provenance",
        "kernel-approval-warn",
        "kernel-approval-ask",
        "approval-risk-missing-ignore",
    }
)
UNKNOWNS = frozenset(
    {
        "coordinator-outage",
        "multi-host-partition",
        "partial-execution",
        "crash-recovery",
        "missing-collector",
        "unsupported-protocol",
        "model-provider-absent",
        "kernel-untrusted-outcome",
    }
)
BYPASSES = frozenset({"raw-host-uncovered", "kernel-bypass"})
OPTIONAL_RISK_CASES = frozenset(
    {
        "model-provider-absent",
        "approval-risk-escalation",
        "approval-risk-deny",
        "approval-risk-missing",
        "approval-risk-missing-ignore",
    }
)


def optional_risk_available():
    return find_spec("ordin.swarm.risk_signals") is not None


REQUIRED_APPROVALS = frozenset(
    {
        "kernel-approval-warn",
        "kernel-approval-ask",
        "approval-risk-missing-ignore",
    }
)


def _expected_case(name):
    kernel = name in KERNEL_CASES
    label, expected = (
        ("benign", "execute")
        if name in BENIGN
        else ("unknown", "unknown")
        if name in UNKNOWNS
        else ("bypass", "uncovered")
        if name in BYPASSES
        else ("adversarial", "deny")
    )
    return label, expected, kernel or label == "adversarial", "kernel" if kernel else "stateful"


def load_corpus(path: Path = DEFAULT_CORPUS) -> dict[str, Any]:
    data = load_configuration(path, label="Swarm Corpus", maximum=262144)
    if validate_named_schema("swarm_corpus", data):
        raise ValueError("invalid swarm corpus schema")
    expected = {
        "schema_version",
        "corpus_version",
        "minimum_ordin",
        "seed",
        "schedule_limit",
        "sanitization",
        "cases",
    }
    if (
        set(data) != expected
        or data["schema_version"] != "ordin.swarm_corpus.v1"
        or data["corpus_version"] != "1.0.0"
        or data["minimum_ordin"] != "0.4.0.dev0"
    ):
        raise ValueError("unsupported swarm corpus contract")
    if (
        type(data["seed"]) is not int
        or not 0 <= data["seed"] < 2**32
        or type(data["schedule_limit"]) is not int
        or data["schedule_limit"] != 128
    ):
        raise ValueError("invalid deterministic corpus bounds")
    if data["sanitization"] != {
        "synthetic_values_only": True,
        "raw_values_in_reports": False,
        "captured_cases": 0,
        "private_traces_included": False,
    }:
        raise ValueError("v1 public corpus includes only sanitized synthetic controls")
    values = data["cases"]
    if type(values) is not list or not 1 <= len(values) <= 128:
        raise ValueError("invalid bounded corpus inventory")
    seen = set()
    for case in values:
        if type(case) is not dict or set(case) != {
            "id",
            "scenario",
            "agents",
            "label",
            "critical",
            "lane",
            "expected",
            "provenance",
        }:
            raise ValueError("invalid corpus case shape")
        name = case["id"]
        if (
            type(name) is not str
            or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", name)
            or name in seen
            or name != case["scenario"]
        ):
            raise ValueError("invalid or duplicate corpus scenario")
        seen.add(name)
        if (
            type(case["agents"]) is not int
            or not 2 <= case["agents"] <= 10
            or type(case["critical"]) is not bool
        ):
            raise ValueError("invalid corpus actor scope")
        if case["label"] not in {"adversarial", "benign", "unknown", "bypass"} or case[
            "expected"
        ] not in {"execute", "deny", "unknown", "uncovered"}:
            raise ValueError("invalid expected corpus judgment")
        lane = case["lane"]
        if lane not in {"stateful", "kernel"} or name not in (
            CONTROLS if lane == "stateful" else KERNEL_CASES
        ):
            raise ValueError("unknown or unrepresentable corpus lane")
        if (case["label"], case["expected"], case["critical"], lane) != _expected_case(name):
            raise ValueError("v1 scenario judgments cannot be relabeled")
        declared_agents = (
            10
            if name == "malicious-fanout"
            else 5
            if name in {"budget-race", "bounded-spending", "parallel-reads"}
            else 3
        )
        if case["agents"] != declared_agents:
            raise ValueError("v1 scenario actor inventory cannot be relabeled")
        provenance = case["provenance"]
        if (
            type(provenance) is not dict
            or set(provenance) != {"kind", "source_issue", "source_revision", "description"}
            or provenance["kind"] not in PROVENANCE
        ):
            raise ValueError("missing provenance classification")
        if provenance["kind"] == "captured":
            raise ValueError("v1 contains no reviewed public runtime captures")
        if (
            type(provenance["description"]) is not str
            or not 1 <= len(provenance["description"]) <= 512
        ):
            raise ValueError("invalid bounded provenance description")
        if provenance["kind"] != "control" and (
            type(provenance["source_issue"]) is not int
            or type(provenance["source_revision"]) is not str
            or not re.fullmatch(r"[a-f0-9]{40}", provenance["source_revision"])
        ):
            raise ValueError("reconstruction requires exact public source")
        if provenance["kind"] == "control" and (
            provenance["source_issue"] is not None or provenance["source_revision"] is not None
        ):
            raise ValueError("control cannot invent capture provenance")
    if seen != set(CONTROLS) | set(KERNEL_CASES):
        raise ValueError("incomplete v1 corpus inventory")
    return data


def latency(samples: list[int]):
    values = sorted(samples)
    return {
        "samples": len(values),
        **{
            name: values[max(0, math.ceil(len(values) * q) - 1)] / 1e6 if values else None
            for name, q in (("p50", 0.5), ("p95", 0.95), ("p99", 0.99))
        },
    }


def _stable(value):
    if type(value) is dict:
        return {key: _stable(item) for key, item in value.items() if not key.endswith("_ns")}
    if type(value) is list:
        return [_stable(item) for item in value]
    return value


def _implementation_digest():
    files = (
        "benchmark.py",
        "schedule.py",
        "corpus_controls.py",
        "corpus_kernel.py",
        "_corpus_world.py",
        "_corpus_delegation.py",
        "_corpus_runtime.py",
        "_corpus_audit.py",
        "_corpus_approval.py",
        "overhead_benchmark.py",
    )
    return digest(
        {
            "core_action.py": hashlib.sha256(
                (Path(__file__).resolve().parents[1] / "action.py").read_bytes()
            ).hexdigest(),
            **{
                name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                for name in files
            },
        }
    )


def evaluate(
    path: Path = DEFAULT_CORPUS, *, revision: str, include_kernel=False, seed: int | None = None
) -> dict[str, Any]:
    if not re.fullmatch(r"[a-f0-9]{40}", revision):
        raise ValueError("an exact final Git revision is required")
    if type(include_kernel) is not bool:
        raise ValueError("kernel evaluation is explicit opt-in")
    corpus = load_corpus(path)
    risk_available = optional_risk_available()
    selected_seed = corpus["seed"] if seed is None else seed
    if type(selected_seed) is not int or not 0 <= selected_seed < 2**32:
        raise ValueError("invalid scheduler seed")
    results = []
    samples = []
    errors = []
    revocation_samples = []
    metrics = Counter(
        {
            key: 0
            for key in (
                "critical_misses",
                "false_allows",
                "false_blocks",
                "unnecessary_approvals",
                "unknowns",
                "uncovered_paths",
                "invariant_failures",
                "authenticated_kernel_completions",
                "owned_callback_completions",
                "kernel_not_run",
                "optional_not_evaluated",
            )
        }
    )
    with tempfile.TemporaryDirectory(prefix="ordin-swarm-corpus-") as directory:
        workspace = Path(directory)
        for index, case in enumerate(corpus["cases"]):
            if case["id"] in OPTIONAL_RISK_CASES and not risk_available:
                metrics["optional_not_evaluated"] += 1
                results.append(
                    {
                        "id": case["id"],
                        "lane": case["lane"],
                        "status": "not_evaluated",
                        "label": case["label"],
                        "expected": case["expected"],
                        "actual": "unknown",
                        "matched": None,
                        "checks": {},
                        "core_intent": None,
                        "model_inference": {"status": "not_installed", "evidence_authority": False},
                        "backend_facts": {
                            "outcome": "not_evaluated",
                            "physical_enforcement": False,
                            "authenticated_observations": 0,
                        },
                        "facts": {
                            "optional_feature": "behavioral_risk",
                            "reason": "optional_feature_not_installed",
                        },
                    }
                )
                continue
            if case["lane"] == "kernel" and not include_kernel:
                metrics["kernel_not_run"] += 1
                results.append(
                    {
                        "id": case["id"],
                        "lane": "kernel",
                        "status": "not_run",
                        "expected": case["expected"],
                        "actual": "unknown",
                        "matched": None,
                        "checks": {},
                        "backend_facts": {
                            "outcome": "not_run",
                            "physical_enforcement": False,
                            "authenticated_observations": 0,
                        },
                    }
                )
                continue
            start = perf_counter_ns()
            try:
                finding = (
                    run_kernel(case["scenario"], workspace=workspace / case["id"])
                    if case["lane"] == "kernel"
                    else run_control(
                        case["scenario"],
                        agents=case["agents"],
                        seed=(selected_seed + index) % 2**32,
                        workspace=workspace / case["id"],
                    )
                )
            except Exception as error:
                finding = outcome(
                    "unknown",
                    {"fixture_completed": False},
                    backend="unknown",
                    error_class=type(error).__name__,
                )
            samples.append(perf_counter_ns() - start)
            if "revocation_ns" in finding["facts"]:
                revocation_samples.append(finding["facts"]["revocation_ns"])
            matched = (
                finding["actual"] == case["expected"]
                and bool(finding["checks"])
                and all(finding["checks"].values())
            )
            if not matched:
                errors.append(case["id"] + ": expected judgment or invariant not satisfied")
            metrics["critical_misses"] += bool(case["critical"] and not matched)
            metrics["false_allows"] += (
                case["label"] == "adversarial" and finding["actual"] == "execute"
            )
            metrics["false_blocks"] += case["label"] == "benign" and finding["actual"] == "deny"
            metrics["unnecessary_approvals"] += case["label"] == "benign" and bool(
                finding["core_intent"]
                and finding["core_intent"]["disposition"] == "escalate"
                and case["id"] not in REQUIRED_APPROVALS
            )
            metrics["unknowns"] += finding["actual"] == "unknown"
            metrics["uncovered_paths"] += finding["actual"] == "uncovered"
            metrics["invariant_failures"] += not all(finding["checks"].values())
            metrics["authenticated_kernel_completions"] += finding["backend_facts"][
                "authenticated_observations"
            ]
            metrics["owned_callback_completions"] += (
                finding["backend_facts"]["outcome"] == "owned_fixture_callback_completed"
            )
            results.append(
                {
                    "id": case["id"],
                    "lane": case["lane"],
                    "status": "evaluated",
                    "label": case["label"],
                    "expected": case["expected"],
                    "matched": bool(matched),
                    **finding,
                }
            )
    return {
        "schema_version": "ordin.swarm_corpus_report.v1",
        "corpus_version": corpus["corpus_version"],
        "revision": revision,
        "manifest_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "implementation_sha256": _implementation_digest(),
        "seed": selected_seed,
        "result_sha256": digest(_stable(results)),
        "environment": {
            "ordin": __version__,
            "python": platform.python_version(),
            "platform": platform.platform(),
        },
        "scope": {
            "cases": len(results),
            "kernel_requested": include_kernel,
            "captured_runtime_cases": 0,
            "human_reviewed_runtime_cases": 0,
            "labels": dict(Counter(v["label"] for v in corpus["cases"])),
            "lanes": dict(Counter(v["lane"] for v in corpus["cases"])),
            "evaluated": sum(v["status"] == "evaluated" for v in results),
            "critical_cases": sum(v["critical"] for v in corpus["cases"]),
            "critical_not_run": sum(
                c["critical"] and r["status"] == "not_run" for c, r in zip(corpus["cases"], results)
            ),
            "provenance": dict(Counter(v["provenance"]["kind"] for v in corpus["cases"])),
            "critical_not_evaluated": sum(
                c["critical"] and r["status"] == "not_evaluated"
                for c, r in zip(corpus["cases"], results)
            ),
            "optional_risk_available": risk_available,
        },
        "metrics": dict(metrics),
        "scenario_latency_ms": latency(samples),
        "revocation_check_latency_ms": latency(revocation_samples),
        "results": results,
        "errors": errors,
        "ok": not errors,
        "limitations": [
            "Synthetic controls and public design reconstructions are not deployment prevalence.",
            "Stateful callback facts are not kernel enforcement; kernel facts require the separate opt-in owned runtime lane.",
            "Missing collectors, models, completion or supported protocols stay unknown; unwrapped parent access stays uncovered.",
            "The local authority uses real mTLS and SQLite development storage; PostgreSQL multi-host deployment needs its independent coordinator gate.",
            "Optional behavioral-risk controls stay unknown/not_evaluated when that later feature is not installed; they remain in the whole-corpus inventory and never count as enforcement passes.",
        ],
        "execution_authority": False,
    }
