"""Explicit integration commands. Compilation and validation are read-only."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from ordin._runtime_json import MAX_RUNTIME_BYTES
from ordin.runtime_contract import RuntimeCapabilityContract

from .compiler import compile_openshell_policy
from .model import parse_policy, serialize_policy


def read_text(path: str) -> str:
    with Path(path).open("rb") as stream:
        content = stream.read(MAX_RUNTIME_BYTES + 1)
    if len(content) > MAX_RUNTIME_BYTES:
        raise ValueError("openshell_input_size")
    return content.decode("utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ordin-openshell", description="Explicit Ordin OpenShell policy integration"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    compile_parser = commands.add_parser("compile-contract")
    compile_parser.add_argument("--contract", required=True)
    compile_parser.add_argument("--output")
    compile_parser.add_argument("--format", choices=("json", "yaml"), default="json")
    compile_parser.add_argument("--uid", type=int, required=True)
    compile_parser.add_argument("--gid", type=int, required=True)
    compile_parser.add_argument("--shadow", action="store_true")
    validate = commands.add_parser("validate")
    validate.add_argument("--policy", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "validate":
            parse_policy(read_text(args.policy))
            print(json.dumps({"status": "success", "reason_code": "openshell_policy_valid"}))
            return 0
        payload = json.loads(read_text(args.contract))
        contract = RuntimeCapabilityContract.from_dict(payload)
        result = compile_openshell_policy(
            contract,
            process_identity=(args.uid, args.gid),
            mode="shadow" if args.shadow else "enforce",
        )
        if result.status != "success" or result.plan is None:
            print(json.dumps(result.as_dict()))
            return 2
        if args.output:
            Path(args.output).write_text(
                serialize_policy(result.plan.policy, format=args.format), encoding="utf-8"
            )
        print(json.dumps(result.as_dict()))
        return 0
    except (ValueError, OSError, UnicodeError, TypeError):
        print(json.dumps({"status": "unsupported", "reason_code": "openshell_input_invalid"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
