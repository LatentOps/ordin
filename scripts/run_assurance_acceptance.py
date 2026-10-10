"""Run the fixed AT-01..AT-35 fixture plan against an installed candidate wheel.

This is a source-pinned contractual fixture report, not independent effectiveness
or physical host acceptance. Full test output stays in workspace scratch storage.
"""

from __future__ import annotations

import argparse
from contextlib import redirect_stderr, redirect_stdout
from functools import wraps
import hashlib
import importlib
import json
from pathlib import Path
import platform
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PLAN = ROOT / "benchmarks/assurance/v1/acceptance-plan.json"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def safe_node(node):
    path, _, function = node.partition("::")
    if not re.fullmatch(r"(?:tests|integrations/decision_models/tests)/[A-Za-z0-9_/]+\.py", path):
        raise ValueError("acceptance plan contains an unsupported test path")
    if function and not re.fullmatch(r"test_[a-z0-9_]+", function):
        raise ValueError("acceptance plan contains an unsupported test selector")
    target = (ROOT / path).resolve(strict=True)
    if not target.is_relative_to(ROOT):
        raise ValueError("acceptance test source escapes workspace")
    return path


def matched(node, selection):
    return (
        node == selection or node.startswith(selection + "[") or node.startswith(selection + "::")
    )


class Observer:
    """Observe actual return values; never add reviews, grant rights or change results."""

    def __init__(self):
        self.current = None
        self.events = {}
        self.outcomes = {}
        self.patches = []
        self.observation_errors = []

    def install(self):
        for module, owner, name, operation in (
            ("ordin.agent", "AgentGate", "evaluate_action", "baseline_review"),
            ("ordin.assurance.gate", "AssuranceGate", "evaluate_action", "assurance_review"),
            (
                "ordin.assurance.delegating_gate",
                "DelegatingAssuranceGate",
                "evaluate_action",
                "delegated_review",
            ),
            (
                "ordin.assurance.delegating_gate",
                "DelegatingAssuranceGate",
                "commit_use",
                "grant_use_commit",
            ),
            (
                "ordin_decision_models.routing",
                "SemanticInspectionRouter",
                "evaluate_action",
                "semantic_review",
            ),
        ):
            target = getattr(importlib.import_module(module), owner)
            original = getattr(target, name)

            def observe_call(original, operation):
                @wraps(original)
                def call(gate, *args, **kwargs):
                    result = original(gate, *args, **kwargs)
                    if self.current is not None:
                        try:
                            self.record(gate, result, kwargs, operation)
                        except Exception as error:
                            # An observation failure must not alter library behavior,
                            # and it makes the evidence incomplete instead of passing.
                            self.observation_errors.append(type(error).__name__)
                    return result

                return call

            setattr(target, name, observe_call(original, operation))
            self.patches.append((target, name, original))
        for module, name in (
            ("ordin.assurance.codex_security.importer", "import_codex_json"),
            ("ordin.assurance.validation", "validate_finding_replay"),
            ("ordin.assurance.validation", "validate_finding_host_observation"),
            ("ordin.assurance.remediation", "verify_fix"),
            ("ordin.assurance.delegation", "verify_delegation_subset"),
            ("ordin.assurance.simulation", "simulate_policy_change"),
            ("ordin.assurance.challenge", "challenge_authority_subset"),
            ("ordin.assurance.challenge", "replay_counterexample"),
        ):
            target = importlib.import_module(module)
            original = getattr(target, name)

            def observe_function(original, name):
                @wraps(original)
                def call(*args, **kwargs):
                    result = original(*args, **kwargs)
                    if self.current is not None:
                        if len(self.events.get(self.current, ())) >= 256:
                            self.observation_errors.append("EventBudgetExceeded")
                            return result
                        values = {
                            key: getattr(result, key, None)
                            for key in (
                                "result",
                                "status",
                                "tested_scope",
                                "completeness",
                                "critical_misses",
                                "benign_regressions",
                                "authority_delta",
                                "failures",
                                "generated",
                                "evaluated",
                                "unresolved",
                                "baseline_configuration_digest",
                                "candidate_configuration_digest",
                            )
                        }
                        if isinstance(result, str):
                            values["result"] = result
                        values["operation"] = name
                        self.events.setdefault(self.current, []).append(values)
                    return result

                return call

            wrapped = observe_function(original, name)
            setattr(target, name, wrapped)
            self.patches.append((target, name, original))
            for facade in ("ordin.assurance", "ordin.assurance.codex_security"):
                exports = importlib.import_module(facade)
                if getattr(exports, name, None) is original:
                    setattr(exports, name, wrapped)
                    self.patches.append((exports, name, original))

    def record(self, gate, result, kwargs, operation):
        from ordin._runtime_json import digest as action_digest
        from ordin.agent import AgentGate
        from ordin.session import configuration_digest

        events = self.events.setdefault(self.current, [])
        if len(events) >= 256:
            self.observation_errors.append("EventBudgetExceeded")
            return
        wrapped = getattr(result, "assurance", result)
        review = getattr(wrapped, "review", None)
        baseline = getattr(wrapped, "baseline", None)
        verification = getattr(result, "verification", None)
        context = kwargs.get("host_context")
        event = {
            "operation": operation,
            "action_digest": None if review is None else action_digest(review.action.as_dict()),
            "context_digest": getattr(wrapped, "host_context_digest", None)
            or getattr(context, "digest", None),
            "configuration_digest": configuration_digest(gate)
            if isinstance(gate, AgentGate)
            else getattr(gate, "configuration_digest", None),
            "profile_digest": getattr(wrapped, "profile_digest", None),
            "baseline_disposition": getattr(result, "baseline_disposition", None)
            or getattr(baseline, "disposition", None)
            or (getattr(result, "disposition", None) if operation == "baseline_review" else None),
            "final_disposition": getattr(result, "disposition", None),
            "reason_codes": list(getattr(result, "reason_codes", ())),
            "authority_result": getattr(verification, "result", None),
            "authority_ok": getattr(verification, "ok", None),
            "use_committed": result if operation == "grant_use_commit" else None,
            "invariant_results": [
                {
                    "invariant_digest": sha(item.invariant_id.encode()),
                    "status": item.status,
                    "reason_code": item.reason_code,
                }
                for item in getattr(wrapped, "invariant_evaluations", ())
            ],
        }
        # Names, action arguments, source content and exception messages stay private.
        events.append(event)

    def pytest_runtest_setup(self, item):
        self.current = item.nodeid

    def pytest_runtest_logreport(self, report):
        if report.when == "call" or report.failed or report.skipped:
            self.outcomes.setdefault(report.nodeid, []).append(
                {"phase": report.when, "outcome": report.outcome}
            )

    def pytest_runtest_teardown(self, item):
        self.current = None

    def restore(self):
        for target, name, original in reversed(self.patches):
            setattr(target, name, original)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--wheel-check", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[a-f0-9]{40}", args.revision):
        raise ValueError("acceptance revision must be an exact source commit")
    actual = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout.strip()
    if actual != args.revision:
        raise ValueError("acceptance revision differs from current checkout")
    if subprocess.run(
        [
            "git",
            "diff",
            "--quiet",
            args.revision,
            "--",
            "ordin",
            "tests",
            "integrations/decision_models",
            "benchmarks/assurance",
            "scripts/run_assurance_acceptance.py",
        ],
        cwd=ROOT,
        capture_output=True,
        timeout=30,
    ).returncode:
        raise ValueError("acceptance sources differ from pinned revision")
    import ordin
    import ordin.assurance
    import ordin_decision_models
    import pytest

    if Path(ordin.__file__).resolve().is_relative_to(ROOT / "ordin"):
        raise ValueError("acceptance must import an installed core wheel")
    if Path(ordin_decision_models.__file__).resolve().is_relative_to(ROOT / "integrations"):
        raise ValueError("acceptance must import the installed optional protocol wheel")
    installed_root = Path(ordin.__file__).resolve().parent
    package_files = {}
    for source in (ROOT / "ordin").rglob("*"):
        if source.suffix not in {".py", ".json"}:
            continue
        relative = source.relative_to(ROOT / "ordin")
        expected = sha(source.read_bytes())
        if sha((installed_root / relative).read_bytes()) != expected:
            raise ValueError("installed core source differs from acceptance candidate")
        package_files[relative.as_posix()] = expected
    optional_root = ROOT / "integrations/decision_models/ordin_decision_models"
    installed_optional = Path(ordin_decision_models.__file__).resolve().parent
    optional_files = {}
    for source in optional_root.rglob("*"):
        if source.suffix not in {".py", ".json"}:
            continue
        relative = source.relative_to(optional_root)
        expected = sha(source.read_bytes())
        if sha((installed_optional / relative).read_bytes()) != expected:
            raise ValueError("installed optional protocol source differs from acceptance candidate")
        optional_files[relative.as_posix()] = expected
    raw = PLAN.read_bytes()
    if len(raw) > 65536:
        raise ValueError("acceptance plan exceeds bounded contract")
    plan = json.loads(raw)
    cases = plan["cases"]
    if [case["id"] for case in cases] != [f"AT-{index:02}" for index in range(1, 36)]:
        raise ValueError("acceptance plan does not retain the 35 required scenarios")
    nodes = list(dict.fromkeys(node for case in cases for node in case["test_nodes"]))
    sources = {safe_node(node): sha((ROOT / safe_node(node)).read_bytes()) for node in nodes}
    wheel_raw = args.wheel_check.read_bytes()
    if len(wheel_raw) > 131072:
        raise ValueError("wheel evidence exceeds bounded contract")
    wheel = json.loads(wheel_raw)
    if not wheel.get("smoke", {}).get("ok"):
        raise ValueError("supplied fresh-wheel check did not pass")
    output = args.output.resolve()
    if not output.is_relative_to(ROOT / ".assurance-work"):
        raise ValueError("acceptance private output must stay in workspace scratch storage")
    output.mkdir(parents=True, exist_ok=False)
    observer = Observer()
    observer.install()
    try:
        with (output / "pytest-private.txt").open("x", encoding="utf-8") as log:
            with redirect_stdout(log), redirect_stderr(log):
                exit_code = pytest.main(
                    [
                        "-q",
                        "-ra",
                        "-p",
                        "no:cacheprovider",
                        *nodes,
                        "--basetemp=" + str(output / "tmp"),
                        "--junitxml=" + str(output / "junit.xml"),
                    ],
                    plugins=[observer],
                )
    finally:
        observer.restore()
    results = []
    for case in cases:
        selected = [
            node for node in observer.outcomes if any(matched(node, s) for s in case["test_nodes"])
        ]
        missing = [s for s in case["test_nodes"] if not any(matched(n, s) for n in selected)]
        passed = (
            bool(selected)
            and not missing
            and all(
                all(row["outcome"] == "passed" for row in observer.outcomes[node])
                for node in selected
            )
        )
        events = [event for node in selected for event in observer.events.get(node, ())]
        results.append(
            {
                **case,
                "fixture_outcome": "passed" if passed else "not_passed",
                "missing_test_nodes": missing,
                "executed_test_count": len(selected),
                "test_outcomes": [
                    {"node_digest": sha(node.encode()), "phases": observer.outcomes[node]}
                    for node in selected
                ],
                "reviews": events,
                "review_scope": "actual observed fixture calls"
                if events
                else "artifact/containment/assertion fixture; no gate review observed",
            }
        )
    report = {
        "schema_version": "ordin.assurance_acceptance_fixture_evidence.v1",
        "revision": args.revision,
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "pytest": pytest.__version__,
        },
        "plan_sha256": sha(raw),
        "installed_core_sources": package_files,
        "installed_optional_protocol_sources": optional_files,
        "test_sources": sources,
        "wheel_check_sha256": sha(wheel_raw),
        "wheel_sha256": wheel["wheel_sha256"],
        "pytest_exit_code": int(exit_code),
        "observation_errors": observer.observation_errors,
        "cases": results,
        "fixture_pass_count": sum(row["fixture_outcome"] == "passed" for row in results),
        "partial_coverage_cases": [row["id"] for row in results if row["coverage"] == "partial"],
        "overall_acceptance": "incomplete",
        "effectiveness_acceptance_eligible": False,
        "limitations": [
            "Existing authored synthetic assertions are exercised without modifying verdicts; this is not independently adjudicated effectiveness evidence.",
            "Gate/action/context/configuration digests are observed when available; artifact-only and typed-containment cases do not invent runtime decisions.",
            "Optional models are mocks and scanner processes are fake fixtures; no actual provider, real scanner or physical sandbox is exercised.",
            "Full suite, original latency budgets, external enforcement, platform CI and the explicitly partial scenario requirements remain separate open gates.",
        ],
    }
    with (output / "report.json").open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(
        json.dumps(
            {
                "fixture_passed": report["fixture_pass_count"],
                "scenarios": 35,
                "partial_coverage": report["partial_coverage_cases"],
                "pytest_exit_code": int(exit_code),
                "overall_acceptance": "incomplete",
            }
        )
    )
    return (
        1 if exit_code or observer.observation_errors or report["fixture_pass_count"] != 35 else 0
    )


if __name__ == "__main__":
    raise SystemExit(main())
