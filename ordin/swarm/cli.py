"""Offline attach planning and explicit report diagnostics; no implicit discovery."""

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from ordin.schema import validate_named_schema

from .coverage import AttachCoverage, PATHWAYS


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate report key")
        result[key] = value
    return result


def main(argv: Sequence[str] | None = None) -> int:
    raw_args = list(sys.argv[1:] if argv is None else argv)
    if raw_args and raw_args[0] == "approval":
        from .approval_cli import main as approval_main

        return approval_main(raw_args[1:])
    if (
        raw_args
        and raw_args[0] == "policy"
        and len(raw_args) > 1
        and raw_args[1] in {"validate", "explain", "diff", "simulate"}
    ):
        from .policy_cli import main as policy_main

        return policy_main(raw_args[1:])
    raw = list(sys.argv[1:] if argv is None else argv)
    if raw and raw[0] == "temporal":
        from .temporal_cli import main as temporal_main

        return temporal_main(raw[1:])
    if raw:
        from .operator_cli import COMMANDS, _load, main as operator_main

        legacy_attach = False
        if raw[0] == "status" and "--report" in raw:
            try:
                path = raw[raw.index("--report") + 1]
                legacy_attach = _load(path).get("schema_version") == "ordin.swarm_attach_status.v1"
            except (ValueError, OSError, IndexError):
                legacy_attach = True
        if raw[0] in COMMANDS and not legacy_attach:
            return operator_main(raw)
    parser = argparse.ArgumentParser(
        prog="ordin swarm",
        description="Plan host attach and inspect explicit offline coverage reports.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("policy", help="Validate, explain, diff and simulate explicit policy data")
    commands.add_parser("temporal", help="Validate an explicit bounded swarm temporal policy")
    commands.add_parser(
        "approval", help="Governance policy validation and protected operator commands"
    )
    attach = commands.add_parser(
        "attach", help="Preview required host routing; live attach uses the protected SDK"
    )
    attach.add_argument("--dry-run", action="store_true")
    attach.add_argument("--mode", choices=("observe", "intercept", "enforce"), default="observe")
    attach.add_argument(
        "--route",
        action="append",
        default=[],
        choices=("shell", "mcp", "sdk", "file", "database", "http"),
    )
    attach.add_argument("--json", action="store_true")
    for command in ("status", "doctor"):
        child = commands.add_parser(
            command, help="Inspect an explicitly supplied report; never restore live authority"
        )
        child.add_argument("--report", required=True)
        child.add_argument("--json", action="store_true")
    args = parser.parse_args(raw)
    try:
        if args.command == "attach":
            if not args.dry_run:
                raise ValueError(
                    "live attach requires an authenticated host endpoint through SwarmAttachManager; use --dry-run to plan"
                )
            coverage = AttachCoverage(args.mode, frozenset(args.route))
            result = {
                "schema_version": "ordin.swarm_attach_plan.v1",
                "supported": False,
                "dry_run": True,
                "mode": args.mode,
                "pre_attach_history": "unknown",
                "execution_authority": False,
                "pathways": coverage.diagnostics(live=False),
                "required": ["authenticated_host_endpoint"]
                + (["constrained_restart"] if args.mode == "enforce" else []),
            }
        else:
            try:
                with Path(args.report).open("rb") as stream:
                    data = stream.read(65537)
                if len(data) > 65536:
                    raise ValueError("report too large")
                result = json.loads(data, object_pairs_hook=_unique)
                if validate_named_schema("swarm_attach_status", result):
                    raise ValueError("invalid report")
                if {v["pathway"] for v in result["pathways"]} != set(PATHWAYS):
                    raise ValueError("incomplete pathway inventory")
            except (OSError, UnicodeError, ValueError, RecursionError):
                raise ValueError("invalid bounded swarm attach report") from None
            result["report_source"], result["verified_live"] = "untrusted_file", False
            if args.command == "doctor":
                result["diagnostics"] = [
                    "offline_report_not_live_verification",
                    "pre_attach_history_unknown",
                ] + [
                    "path_" + v["pathway"] + "_" + v["state"]
                    for v in result["pathways"]
                    if v["state"] != "covered"
                ]
        print(json.dumps(result, sort_keys=True) if args.json else json.dumps(result, indent=2))
        return 0
    except ValueError as exc:
        print(json.dumps({"error": str(exc)}))
        return 2
