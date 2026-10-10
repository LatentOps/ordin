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
            code = PASS
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
            if args.command == "run":
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
