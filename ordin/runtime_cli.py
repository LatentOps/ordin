"""Read-only capability and observation commands for the zero-dependency core."""

from __future__ import annotations

import argparse
import json
from typing import Sequence

from .capability_delta import propose_capability_delta
from .runtime_boundary import RuntimeCapabilityBoundary, verify_runtime_capability
from .runtime_codec import action_review_from_dict, read_runtime_json, read_private_runtime_json
from .runtime_contract import RuntimeCapabilityContract, derive_runtime_capability_contract
from .runtime_observation import RuntimeObservation, RuntimeEvidenceSource


def main(argv: Sequence[str] | None = None, *, observations: bool = False) -> int:
    parser = argparse.ArgumentParser(
        prog="ordin runtime-observation" if observations else "ordin capability"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate")
    validate.add_argument("path")
    validate.add_argument("--json", action="store_true")
    if observations:
        validate.add_argument(
            "--trusted-source", help="Explicit private host-owned source context JSON"
        )
    if not observations:
        derive = commands.add_parser("derive")
        derive.add_argument("--review", required=True)
        derive.add_argument("--json", action="store_true")
        verify = commands.add_parser("verify")
        verify.add_argument("contract")
        verify.add_argument("--boundary", required=True)
        verify.add_argument("--json", action="store_true")
        propose = commands.add_parser("propose")
        for name in ("review", "contract", "denial", "boundary"):
            propose.add_argument("--" + name, required=True)
        propose.add_argument("--json", action="store_true")
        propose.add_argument(
            "--trusted-source", help="Explicit private host-owned source context JSON"
        )
    args = parser.parse_args(argv)
    try:
        if args.command == "validate":
            data = read_runtime_json(args.path)
            if observations:
                # Strong labels cannot be blessed by normal CLI/agent JSON.
                if args.trusted_source:
                    source = RuntimeEvidenceSource(**read_private_runtime_json(args.trusted_source))
                    source.restore_trusted(read_private_runtime_json(args.path))
                else:
                    RuntimeObservation.from_dict(data)
            else:
                RuntimeCapabilityContract.from_dict(data)
            output, code = {"status": "success", "reason_code": "runtime_artifact_valid"}, 0
        elif args.command == "derive":
            review = action_review_from_dict(read_runtime_json(args.review))
            output, code = derive_runtime_capability_contract(review).as_dict(), 0
        elif args.command == "verify":
            contract = RuntimeCapabilityContract.from_dict(read_runtime_json(args.contract))
            boundary = RuntimeCapabilityBoundary.from_dict(read_runtime_json(args.boundary))
            result = verify_runtime_capability(contract, boundary)
            output, code = result.as_dict(), 0 if result.ok else 1
        else:
            review = action_review_from_dict(read_runtime_json(args.review))
            contract = RuntimeCapabilityContract.from_dict(read_runtime_json(args.contract))
            boundary = RuntimeCapabilityBoundary.from_dict(read_runtime_json(args.boundary))
            # A core command has no authorization to manufacture backend trust.
            if args.trusted_source:
                source = RuntimeEvidenceSource(**read_private_runtime_json(args.trusted_source))
                denial = source.restore_trusted(read_private_runtime_json(args.denial))
            else:
                denial = RuntimeObservation.from_dict(read_runtime_json(args.denial))
            proposal = propose_capability_delta(review, contract, denial, boundary)
            output, code = proposal.as_dict(), 0 if proposal.status == "requires_approval" else 1
    except (ValueError, TypeError, KeyError, OSError):
        print(
            json.dumps({"error": "invalid_runtime_input", "reason_code": "runtime_input_invalid"})
        )
        return 2
    print(json.dumps(output, indent=2))  # Machine JSON is available on every path.
    return code
