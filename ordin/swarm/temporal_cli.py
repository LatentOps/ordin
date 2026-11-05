"""Explicit offline validation of bounded swarm temporal policy files."""

import argparse
import json
from typing import Sequence

from .temporal_policy import load_swarm_temporal_policy


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ordin swarm temporal")
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser(
        "validate", help="Validate an explicitly supplied temporal policy without executing actions"
    )
    validate.add_argument("--policy", required=True)
    validate.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        policy = load_swarm_temporal_policy(args.policy).policy
    except (OSError, ValueError, TypeError, RecursionError):
        print(json.dumps({"error": "invalid_swarm_temporal_policy"}))
        return 2
    result = {
        "schema_version": "ordin.swarm_temporal_validation.v1",
        "valid": True,
        "policy_digest": policy.digest,
        "rule_count": len(policy.rules),
        "execution_authority": False,
    }
    print(json.dumps(result, sort_keys=True) if args.json else json.dumps(result, indent=2))
    return 0
