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
from .models import PolicySimulationReport, SecurityProfile
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
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    packet: dict
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
