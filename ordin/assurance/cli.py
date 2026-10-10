"""Separate local Assurance CLI. Ordinary Ordin commands retain their behavior."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Sequence

from ._files import _directory, read_scoped_file, relative_parts
from ._json import canonical_json, loads
from .models import CounterexampleRecord, PolicySimulationReport, SecurityProfile
from .challenge import ChallengeRun, challenge_authority_subset, replay_counterexample
from .property_challenge import (
    ChallengeSuite,
    REQUIRED_PROPERTIES,
    challenge_property,
    challenge_security_properties,
)
from .simulation import FrozenCorpus, SimulationPolicy, simulate_policy_change

PASS = 0
SECURITY_REGRESSION = 1
PARTIAL_OR_MALFORMED = 2


def _read(path: str) -> dict:
    if path == "-":
        stream = getattr(sys.stdin, "buffer", sys.stdin)
        return loads(stream.read(1_048_577))
    local = Path(path).absolute()
    return loads(read_scoped_file(local.parent, local.name, maximum=1_048_576))


def _write_report(path: str, packet: dict) -> None:
    """Explicit output only; refuse overwrite and hold validated parent directories."""
    local = Path(path).absolute()
    relative_parts(local.name)
    content = canonical_json(packet) + "\n"
    with _directory(local.parent) as (directory, _):
        if isinstance(directory, int):
            fd = os.open(
                local.name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=directory,
            )
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as output:
                output.write(content)
        else:
            # Windows ancestor handles prevent rename/reparse substitution.
            with local.open("x", encoding="utf-8", newline="\n") as output:
                output.write(content)


def simulation_exit_code(report: PolicySimulationReport) -> int:
    if (
        report.critical_misses
        or report.newly_executable
        or report.policy_authority_delta == "widened"
        or any("assurance.simulation_critical_downgrade" in v.reason_codes for v in report.cases)
    ):
        return SECURITY_REGRESSION
    return PASS if report.activation_safe else PARTIAL_OR_MALFORMED


def _diff(before: PolicySimulationReport, after: PolicySimulationReport) -> tuple[dict, int]:
    if before.corpus_digest != after.corpus_digest or [v.case_id for v in before.cases] != [
        v.case_id for v in after.cases
    ]:
        raise ValueError("simulation diff requires the same frozen corpus and ordering")
    changed = [
        {
            "case_id": a.case_id,
            "before": a.candidate_final,
            "after": b.candidate_final,
            "effects_changed": a.candidate_effects != b.candidate_effects,
            "temporal_changed": a.candidate_temporal != b.candidate_temporal,
            "capability_changed": a.candidate_capability_digest != b.candidate_capability_digest,
        }
        for a, b in zip(before.cases, after.cases)
        if (
            a.candidate_final,
            a.candidate_effects,
            a.candidate_temporal,
            a.candidate_capability_digest,
        )
        != (
            b.candidate_final,
            b.candidate_effects,
            b.candidate_temporal,
            b.candidate_capability_digest,
        )
    ]
    return {
        "schema_version": "ordin.assurance_simulation_diff.v1",
        "corpus_digest": after.corpus_digest,
        "baseline_report_digest": before.digest,
        "candidate_report_digest": after.digest,
        "changes": changed,
        "advisory_only": True,
    }, simulation_exit_code(after)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ordin-assure", description="Local, read-only security assurance"
    )
    groups = parser.add_subparsers(dest="group", required=True)
    profile = groups.add_parser("profile").add_subparsers(dest="command", required=True)
    validate = profile.add_parser("validate", help="validate content without approving it")
    validate.add_argument("path")
    inspect = profile.add_parser("inspect", help="inspect validated content without approving it")
    inspect.add_argument("path")
    inspect.add_argument("--include-details", action="store_true")
    inspect.add_argument("--report")
    invariants = groups.add_parser("invariants").add_subparsers(dest="command", required=True)
    check = invariants.add_parser(
        "check", help="data-only preview; host-dependent checks remain inconclusive"
    )
    check.add_argument("--profile", required=True)
    check.add_argument("--action", required=True)
    check.add_argument("--report")
    attack = groups.add_parser("attack-path").add_subparsers(dest="command", required=True)
    graph = attack.add_parser(
        "analyze",
        aliases=["inspect"],
        help="inspect imported graph/source references without authenticating runtime claims",
    )
    graph.add_argument("--evidence", required=True)
    graph.add_argument("--source-root")
    graph.add_argument("--repository")
    graph.add_argument("--revision")
    graph.add_argument("--report")
    delegation = groups.add_parser("delegation").add_subparsers(dest="command", required=True)
    subset = delegation.add_parser(
        "verify", help="compare declared maxima without issuing or restoring a grant"
    )
    subset.add_argument("--parent", required=True)
    subset.add_argument("--child", required=True)
    subset.add_argument("--operator")
    subset.add_argument("--task")
    subset.add_argument("--report")
    finding = groups.add_parser("finding").add_subparsers(dest="command", required=True)
    static = finding.add_parser(
        "validate", help="static source review; runtime closure requires protected SDK evidence"
    )
    static.add_argument("--input", required=True, help="candidate/rubric JSON bundle")
    static.add_argument("--mode", choices=("static",), default="static")
    static.add_argument("--source-root", required=True)
    static.add_argument("--repository", required=True)
    static.add_argument("--revision", required=True)
    static.add_argument("--report")
    report = groups.add_parser("report").add_subparsers(dest="command", required=True)
    compare = report.add_parser(
        "compare", help="compare policy simulation reports with the same frozen corpus"
    )
    compare.add_argument("--before", required=True)
    compare.add_argument("--after", required=True)
    compare.add_argument("--report")
    cases = groups.add_parser("counterexample").add_subparsers(dest="command", required=True)
    counter = cases.add_parser(
        "replay", help="replay a saved finite counterexample; never execute a proposed action"
    )
    counter.add_argument("path")
    counter.add_argument("--revision", required=True)
    counter.add_argument("--report")
    policy = groups.add_parser("policy").add_subparsers(dest="command", required=True)
    simulate = policy.add_parser(
        "simulate", help="replay independent baseline and candidate sessions"
    )
    simulate.add_argument("--baseline", required=True)
    simulate.add_argument("--candidate", required=True)
    simulate.add_argument("--corpus", required=True)
    simulate.add_argument("--baseline-revision", default="unspecified")
    simulate.add_argument("--candidate-revision", default="unspecified")
    simulate.add_argument("--expected-corpus-digest")
    simulate.add_argument("--report", help="explicit new output file; existing files are refused")
    diff = policy.add_parser("diff", help="compare reports for the same corpus")
    diff.add_argument("--baseline", required=True)
    diff.add_argument("--candidate", required=True)
    diff.add_argument("--report")
    challenge = groups.add_parser("challenge").add_subparsers(dest="command", required=True)
    challenge.add_parser("list", help="list the bounded property catalog and proof limits")
    run = challenge.add_parser("run", help="bounded synthetic authority-subset challenger")
    run.add_argument("--seed", type=int, required=True)
    run.add_argument("--revision", required=True)
    run.add_argument("--trials", type=int)
    run.add_argument(
        "--variant",
        choices=("actual", "seeded_prefix_bug", "seeded_unsafe_checker"),
        default="actual",
    )
    selection = run.add_mutually_exclusive_group()
    selection.add_argument("--property", choices=REQUIRED_PROPERTIES, default="authority_subset")
    selection.add_argument(
        "--suite",
        action="store_true",
        help="retain all ten required properties and incomplete integrations",
    )
    run.add_argument("--time-budget-ms", type=float, default=10_000)
    run.add_argument("--report")
    replay = challenge.add_parser(
        "replay", help="recheck both captures for the exact property failure"
    )
    replay.add_argument("path")
    replay.add_argument("--revision", required=True)
    replay.add_argument("--report")
    codex = groups.add_parser("codex").add_subparsers(dest="command", required=True)
    imported = codex.add_parser(
        "import", help="read saved scanner artifacts without credentials or scanner execution"
    )
    imported.add_argument("--artifact-root", required=True)
    imported.add_argument("--repository", required=True)
    imported.add_argument("--revision", required=True)
    imported.add_argument("--format", choices=("json", "sarif"), default="json")
    imported.add_argument("--findings-path", default="findings.json")
    imported.add_argument("--sarif-path", default="results.sarif")
    imported.add_argument("--threat-model-path")
    imported.add_argument("--expected-plugin-version")
    imported.add_argument("--expected-target-id")
    imported.add_argument("--fail-on-severity", choices=("critical", "high", "medium", "low"))
    imported.add_argument(
        "--include-details",
        action="store_true",
        help="explicit sensitive vendor capture; keep output private",
    )
    imported.add_argument("--report")
    workflow = codex.add_parser(
        "import-workflow",
        help="import saved external validation/patch/fix claims without executing a workflow",
    )
    workflow.add_argument("--artifact-root", required=True)
    workflow.add_argument("--repository", required=True)
    workflow.add_argument("--revision", required=True)
    workflow.add_argument(
        "--workflow", choices=("validate", "patch", "verify_fix", "patch_risk"), required=True
    )
    workflow.add_argument("--artifact-path", default="workflow.json")
    workflow.add_argument("--format", choices=("json", "text"), default="json")
    workflow.add_argument("--capture-path", default="workflow-capture.json")
    workflow.add_argument("--expected-tool-version", default="0.2.0")
    workflow.add_argument("--expected-scan-id")
    workflow.add_argument("--expected-identifier", action="append", default=[])
    workflow.add_argument("--expected-patch-digest")
    workflow.add_argument(
        "--include-details",
        action="store_true",
        help="explicit private reported payload; never upload or log by default",
    )
    workflow.add_argument("--report")
    mock = codex.add_parser(
        "mock", help="offline synthetic scanner state; no executable or credentials"
    )
    mock.add_argument("--exit-code", type=int, choices=(0, 1, 2, 130, 143), default=0)
    mock.add_argument(
        "--completeness", choices=("complete", "partial", "unknown"), default="complete"
    )
    mock.add_argument("--report")
    source = groups.add_parser("source").add_subparsers(dest="command", required=True)
    triage = source.add_parser(
        "diff", help="read-only snapshot heuristics and deterministic authority deltas"
    )
    triage.add_argument("--baseline-root", required=True)
    triage.add_argument("--candidate-root", required=True)
    triage.add_argument("--repository", required=True)
    triage.add_argument("--baseline-revision", required=True)
    triage.add_argument("--candidate-revision", required=True)
    triage.add_argument("--virtual-root", required=True)
    triage.add_argument("--baseline-policy")
    triage.add_argument("--candidate-policy")
    triage.add_argument("--baseline-profile")
    triage.add_argument("--candidate-profile")
    triage.add_argument("--include-details", action="store_true")
    triage.add_argument("--report")
    visited = set()

    def formats(current):
        if id(current) in visited:
            return
        visited.add(id(current))
        current.add_argument(
            "--json", action="store_true", help="JSON is the deterministic default output"
        )
        if any(action.dest == "report" for action in current._actions):
            current.add_argument(
                "--output", dest="report", help="alias for explicit new report file"
            )
        for action in current._actions:
            if isinstance(action, argparse._SubParsersAction):
                for child in action.choices.values():
                    formats(child)

    formats(parser)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    packet: dict
    result: ChallengeRun | ChallengeSuite
    try:
        if args.group == "profile":
            profile = SecurityProfile.from_dict(_read(args.path))
            packet = {
                "valid": True,
                "profile_digest": profile.digest,
                "approved": False,
                "reason_code": "assurance.profile_content_valid",
            }
            if args.command == "inspect":
                from .offline import inspect_profile_content

                packet = inspect_profile_content(profile, include_details=args.include_details)
            code = PASS
        elif args.group == "invariants":
            from ordin import ActionEnvelope
            from .offline import preview_invariants

            packet = preview_invariants(
                SecurityProfile.from_dict(_read(args.profile)),
                ActionEnvelope.from_dict(_read(args.action)),
            )
            code = (
                SECURITY_REGRESSION
                if packet["baseline_disposition"] == "deny"
                or any(row["status"] == "violated" for row in packet["evaluations"])
                else PARTIAL_OR_MALFORMED
                if any(
                    row["status"] in {"inconclusive", "unsupported"}
                    for row in packet["evaluations"]
                )
                else PASS
            )
        elif args.group == "attack-path":
            from .offline import inspect_attack_path
            from .inventory import AuthorizedRepository
            from .models import RepositoryScope

            selected_source = None
            if args.source_root:
                if not args.repository or not args.revision:
                    raise ValueError(
                        "source graph references require explicit repository/revision mapping"
                    )
                selected_source = AuthorizedRepository(
                    Path(args.source_root).absolute(),
                    RepositoryScope(args.repository, args.revision),
                    "/offline/source",
                )
            packet = inspect_attack_path(_read(args.evidence), source_scope=selected_source)
            code = PARTIAL_OR_MALFORMED
        elif args.group == "delegation":
            from .offline import compare_delegation_data
            from .delegation import DelegationAuthority

            packet = compare_delegation_data(
                DelegationAuthority.from_dict(_read(args.child)),
                DelegationAuthority.from_dict(_read(args.parent)),
                operator=DelegationAuthority.from_dict(_read(args.operator))
                if args.operator
                else None,
                task=DelegationAuthority.from_dict(_read(args.task)) if args.task else None,
            )
            code = (
                PASS
                if packet["result"] == "within_boundary"
                else SECURITY_REGRESSION
                if packet["result"] == "exceeds_boundary"
                else PARTIAL_OR_MALFORMED
            )
        elif args.group == "finding":
            from .offline import review_static_candidate
            from .inventory import AuthorizedRepository
            from .models import RepositoryScope, SecurityFinding
            from .validation_models import FindingRubric

            candidate_input = _read(args.input)
            if set(candidate_input) != {"candidate", "rubric"}:
                raise ValueError("static review bundle requires exact candidate/rubric data")
            candidate_scope = AuthorizedRepository(
                Path(args.source_root).absolute(),
                RepositoryScope(args.repository, args.revision),
                "/offline/source",
            )
            packet = review_static_candidate(
                candidate_scope,
                SecurityFinding.from_dict(candidate_input["candidate"]),
                FindingRubric.from_dict(candidate_input["rubric"]),
            )
            code = PARTIAL_OR_MALFORMED
        elif args.group == "report":
            packet, code = _diff(
                PolicySimulationReport.from_dict(_read(args.before)),
                PolicySimulationReport.from_dict(_read(args.after)),
            )
        elif args.group == "counterexample":
            record = CounterexampleRecord.from_dict(_read(args.path))
            outcome = replay_counterexample(record, expected_revision=args.revision)
            packet = {
                "record_digest": record.digest,
                "replay_outcome": outcome,
                "host_boundary_exercised": False,
            }
            code = (
                PASS
                if outcome == "verified_failure"
                else SECURITY_REGRESSION
                if outcome == "not_reproduced"
                else PARTIAL_OR_MALFORMED
            )
        elif args.group == "source":
            from .diff_triage import triage_source_diff
            from .inventory import AuthorizedRepository
            from .models import RepositoryScope

            triaged = triage_source_diff(
                AuthorizedRepository(
                    Path(args.baseline_root).absolute(),
                    RepositoryScope(args.repository, args.baseline_revision),
                    args.virtual_root,
                ),
                AuthorizedRepository(
                    Path(args.candidate_root).absolute(),
                    RepositoryScope(args.repository, args.candidate_revision),
                    args.virtual_root,
                ),
                baseline_policy=SimulationPolicy.from_dict(_read(args.baseline_policy))
                if args.baseline_policy
                else None,
                candidate_policy=SimulationPolicy.from_dict(_read(args.candidate_policy))
                if args.candidate_policy
                else None,
                baseline_profile=SecurityProfile.from_dict(_read(args.baseline_profile))
                if args.baseline_profile
                else None,
                candidate_profile=SecurityProfile.from_dict(_read(args.candidate_profile))
                if args.candidate_profile
                else None,
            )
            packet = triaged.as_dict() if args.include_details else triaged.public_dict()
            code = (
                SECURITY_REGRESSION
                if triaged.policy_authority_delta == "widened"
                else PARTIAL_OR_MALFORMED
                if triaged.completeness != "complete"
                else PASS
            )
        elif args.group == "codex" and args.command == "mock":
            from .codex_security.scanner import mock_scanner_run

            mocked = mock_scanner_run(exit_code=args.exit_code, completeness=args.completeness)
            packet = mocked.as_dict()
            code = (
                args.exit_code
                if args.exit_code in {130, 143}
                else PASS
                if mocked.status == "completed"
                else SECURITY_REGRESSION
                if mocked.status == "severity_violation"
                else PARTIAL_OR_MALFORMED
            )
        elif args.group == "codex" and args.command == "import-workflow":
            from .codex_security.workflow import WorkflowImportScope, import_workflow_claims
            from .models import RepositoryScope

            workflow_scope = WorkflowImportScope(
                Path(args.artifact_root).absolute(),
                RepositoryScope(args.repository, args.revision),
                args.workflow,
                expected_tool_version=args.expected_tool_version,
                expected_scan_id=args.expected_scan_id,
                expected_identifiers=tuple(args.expected_identifier),
                expected_patch_digest=args.expected_patch_digest,
                artifact_format=args.format,
            )
            imported = import_workflow_claims(
                workflow_scope, artifact_path=args.artifact_path, capture_path=args.capture_path
            )
            packet = imported.as_dict() if args.include_details else imported.public_dict()
            code = PASS if imported.completeness == "complete" else PARTIAL_OR_MALFORMED
        elif args.group == "codex":
            from .codex_security import ImportScope, import_codex_json, import_sarif
            from .models import RepositoryScope

            scope = ImportScope(
                Path(args.artifact_root).absolute(),
                RepositoryScope(args.repository, args.revision),
                expected_target_id=args.expected_target_id,
                expected_plugin_version=args.expected_plugin_version,
            )
            imported_report = (
                import_codex_json(
                    scope,
                    findings_path=args.findings_path,
                    threat_model_path=args.threat_model_path,
                )
                if args.format == "json"
                else import_sarif(scope, sarif_path=args.sarif_path)
            )
            packet = (
                imported_report.as_dict() if args.include_details else imported_report.public_dict()
            )
            code = PASS if imported_report.conclusive_import else PARTIAL_OR_MALFORMED
            if code == PASS and args.fail_on_severity:
                ranks = {
                    "critical": 4,
                    "high": 3,
                    "medium": 2,
                    "low": 1,
                    "informational": 0,
                    "unknown": -1,
                }
                if any(
                    ranks[v.reported_severity] >= ranks[args.fail_on_severity]
                    for v in imported_report.findings
                ):
                    code = SECURITY_REGRESSION
        elif args.group == "challenge":
            if args.command == "list":
                packet = {
                    "schema_version": "ordin.assurance_challenge_catalog.v1",
                    "properties": list(REQUIRED_PROPERTIES),
                    "execution": "bounded_synthetic_only",
                    "proof_scope": "finite_tested_inputs",
                    "optional_providers": "not_called",
                }
                code = PASS
            elif args.command == "run":
                if args.suite:
                    result = challenge_security_properties(
                        seed=args.seed,
                        revision=args.revision,
                        trials_per_property=args.trials if args.trials is not None else 32,
                        variant=args.variant,
                        time_budget_ms=args.time_budget_ms,
                    )
                elif args.property == "authority_subset":
                    result = challenge_authority_subset(
                        seed=args.seed,
                        revision=args.revision,
                        trials=args.trials if args.trials is not None else 64,
                        variant=args.variant,
                        time_budget_ms=args.time_budget_ms,
                    )
                else:
                    result = challenge_property(
                        property_id=args.property,
                        seed=args.seed,
                        revision=args.revision,
                        trials=args.trials if args.trials is not None else 32,
                        variant=args.variant,
                        time_budget_ms=args.time_budget_ms,
                    )
                packet = result.as_dict()
                code = (
                    SECURITY_REGRESSION
                    if result.failures
                    else PARTIAL_OR_MALFORMED
                    if result.status == "inconclusive"
                    else PASS
                )
            else:
                record = CounterexampleRecord.from_dict(_read(args.path))
                outcome = replay_counterexample(record, expected_revision=args.revision)
                packet = {
                    "record_digest": record.digest,
                    "replay_outcome": outcome,
                    "host_boundary_exercised": False,
                }
                code = (
                    PASS
                    if outcome == "verified_failure"
                    else SECURITY_REGRESSION
                    if outcome == "not_reproduced"
                    else PARTIAL_OR_MALFORMED
                )
        elif args.command == "simulate":
            report = simulate_policy_change(
                SimulationPolicy.from_dict(_read(args.baseline)),
                SimulationPolicy.from_dict(_read(args.candidate)),
                FrozenCorpus.from_dict(_read(args.corpus)),
                baseline_revision=args.baseline_revision,
                candidate_revision=args.candidate_revision,
                expected_corpus_digest=args.expected_corpus_digest,
            )
            packet, code = report.as_dict(), simulation_exit_code(report)
        else:
            packet, code = _diff(
                PolicySimulationReport.from_dict(_read(args.baseline)),
                PolicySimulationReport.from_dict(_read(args.candidate)),
            )
        if getattr(args, "report", None):
            _write_report(args.report, packet)
        print(json.dumps(packet, sort_keys=True, allow_nan=False))
        return code
    except (ValueError, OSError, KeyError, TypeError):
        # Rejected values, paths, source text and exception messages may contain secrets.
        print(
            '{"error":"assurance_input_or_output_invalid","coverage":"unknown","activation_safe":false}',
            file=sys.stderr,
        )
        return PARTIAL_OR_MALFORMED


if __name__ == "__main__":
    raise SystemExit(main())
