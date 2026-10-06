"""Explicit compile/proof/evidence diagnostics and approved named-sandbox policy apply."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Sequence

from ordin._runtime_json import MAX_RUNTIME_BYTES, digest
from ordin.runtime_boundary import RuntimeCapabilityBoundary
from ordin.runtime_codec import (
    action_review_from_dict,
    read_runtime_json,
    read_private_runtime_json,
)
from ordin.runtime_contract import RuntimeCapabilityContract, derive_runtime_capability_contract
from ordin.runtime_observation import RuntimeEvidenceSource

from .apply import apply_openshell_policy
from .apply_audit import PolicyApplyAudit
from .backend_cli import OpenShellCLI
from .compiler import OpenShellBackend
from .correlation import CorrelationStore
from .doctor import openshell_doctor
from .model import parse_policy, serialize_policy
from .observations import ingest_openshell_event
from .prover import verify_with_openshell_prover
from .shadow import ShadowCase, build_shadow_report


def read_text(path: str) -> str:
    with Path(path).open("rb") as stream:
        content = stream.read(MAX_RUNTIME_BYTES + 1)
    if len(content) > MAX_RUNTIME_BYTES:
        raise ValueError("openshell_input_size")
    return content.decode("utf-8")


def _backend(args, *, mode="enforce") -> OpenShellBackend:
    config = read_private_runtime_json(args.operator_config) if args.operator_config else {}
    if set(config) - {"resource_kinds", "credential_providers"}:
        raise ValueError("openshell_operator_configuration_invalid")
    return OpenShellBackend(
        (args.uid, args.gid),
        config.get("resource_kinds", {}),
        config.get("credential_providers", {}),
        mode=mode,
    )


def _contract(args) -> RuntimeCapabilityContract:
    if getattr(args, "review", None):
        return derive_runtime_capability_contract(
            action_review_from_dict(read_runtime_json(args.review))
        )
    return RuntimeCapabilityContract.from_dict(read_runtime_json(args.contract))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ordin-openshell", description="Explicit Ordin OpenShell integration"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    for command, input_kind in (("compile", "review"), ("compile-contract", "contract")):
        compile_parser = commands.add_parser(command)
        compile_parser.add_argument("--" + input_kind, required=True)
        compile_parser.add_argument("--output")
        compile_parser.add_argument("--format", choices=("json", "yaml"), default="json")
        compile_parser.add_argument("--uid", type=int, required=True)
        compile_parser.add_argument("--gid", type=int, required=True)
        compile_parser.add_argument("--operator-config")
        compile_parser.add_argument("--shadow", action="store_true")
    validate = commands.add_parser("validate")
    validate.add_argument("--policy", required=True)
    prove = commands.add_parser("prove")
    prove.add_argument("--policy", required=True)
    prove.add_argument("--boundary", required=True)
    prove.add_argument("--prover", default="openshell-prover")
    prove.add_argument("--timeout", type=float, default=15)
    doctor = commands.add_parser("doctor")
    doctor.add_argument("--openshell", default="openshell")
    doctor.add_argument("--prover", default="openshell-prover")
    ingest = commands.add_parser("ingest-event")
    ingest.add_argument("--event", required=True)
    ingest.add_argument("--contract")
    ingest.add_argument("--source-context")
    ingest.add_argument("--correlation-db")
    ingest.add_argument("--now-ms", type=int)
    shadow = commands.add_parser("shadow-report")
    shadow.add_argument("--cases", required=True, help="Private host-owned shadow cases JSON")
    apply = commands.add_parser("apply")
    for name in ("contract", "policy", "sandbox"):
        apply.add_argument("--" + name, required=True)
    apply.add_argument("--uid", type=int, required=True)
    apply.add_argument("--gid", type=int, required=True)
    apply.add_argument("--operator-config")
    apply.add_argument("--capability-boundary")
    apply.add_argument("--require-verified-boundary")
    apply.add_argument(
        "--approve-request", help="Exact digest-bound request ID approved by the operator"
    )
    apply.add_argument("--openshell", default="openshell")
    apply.add_argument("--prover", default="openshell-prover")
    apply.add_argument("--gateway")
    apply.add_argument("--gateway-endpoint")
    apply.add_argument("--workspace", default="default")
    apply.add_argument("--timeout", type=float, default=30)
    apply.add_argument("--audit", help="Explicit private hash-chained operator receipt file")
    args = parser.parse_args(argv)
    try:
        if args.command == "validate":
            policy = parse_policy(read_text(args.policy))
            output = {
                "status": "success",
                "reason_code": "openshell_policy_valid",
                "policy_digest": digest(policy),
            }
            code = 0
        elif args.command == "doctor":
            output = openshell_doctor(cli_executable=args.openshell, prover_executable=args.prover)
            code = 0 if output["status"] == "success" else 2
        elif args.command == "prove":
            proof = verify_with_openshell_prover(
                args.policy, args.boundary, executable=args.prover, timeout=args.timeout
            )
            output, code = proof.as_dict(), 0 if proof.ok else 2
        elif args.command == "ingest-event":
            contract = _contract(args) if args.contract else None
            source = (
                RuntimeEvidenceSource(**read_private_runtime_json(args.source_context))
                if args.source_context
                else None
            )
            store = CorrelationStore(args.correlation_db) if args.correlation_db else None
            # Attribution comes only from the protected, exact event digest binding.
            ingestion = ingest_openshell_event(
                read_text(args.event),
                contract=contract,
                source=source,
                store=store,
                now_ms=args.now_ms,
            )
            output, code = ingestion.as_dict(), 0 if ingestion.status == "accepted" else 2
        elif args.command == "shadow-report":
            data = read_private_runtime_json(args.cases)
            if (
                set(data) != {"cases"}
                or not isinstance(data["cases"], list)
                or len(data["cases"]) > 128
            ):
                raise ValueError("openshell_shadow_input_invalid")
            cases = []
            for case in data["cases"]:
                if not isinstance(case, dict) or set(case) != {
                    "contract",
                    "boundary",
                    "observations",
                    "source",
                    "operator",
                }:
                    raise ValueError("openshell_shadow_input_invalid")
                source = RuntimeEvidenceSource(**case["source"])
                operator = case["operator"]
                if set(operator) != {"uid", "gid", "resource_kinds", "credential_providers"}:
                    raise ValueError("openshell_shadow_input_invalid")
                backend = OpenShellBackend(
                    (operator["uid"], operator["gid"]),
                    operator["resource_kinds"],
                    operator["credential_providers"],
                    mode="shadow",
                )
                cases.append(
                    ShadowCase(
                        RuntimeCapabilityContract.from_dict(case["contract"]),
                        RuntimeCapabilityBoundary.from_dict(case["boundary"]),
                        tuple(source.restore_trusted(o) for o in case["observations"]),
                        source,
                        backend,
                    )
                )
            output, code = build_shadow_report(tuple(cases)).as_dict(), 0
        else:
            contract = _contract(args)
            backend = _backend(args, mode="shadow" if getattr(args, "shadow", False) else "enforce")
            compiled = backend.compile(contract)
            if compiled.status != "success" or compiled.plan is None:
                output, code = compiled.as_dict(), 2
            elif args.command == "apply":
                raw_policy = read_text(args.policy)
                if digest(parse_policy(raw_policy)) != compiled.plan.policy_digest:
                    raise ValueError("openshell_policy_contract_mismatch")
                boundary = (
                    RuntimeCapabilityBoundary.from_dict(read_runtime_json(args.capability_boundary))
                    if args.capability_boundary
                    else None
                )
                # The prover is the schema authority for its boundary document, which may
                # deliberately be broader than this compiler's supported candidate subset.
                backend_boundary = (
                    read_runtime_json(args.require_verified_boundary)
                    if args.require_verified_boundary
                    else None
                )
                applied = apply_openshell_policy(
                    compiled.plan,
                    backend=backend,
                    sandbox=args.sandbox,
                    approval_request_id=args.approve_request,
                    cli=OpenShellCLI(
                        args.openshell, args.gateway, args.workspace, args.gateway_endpoint
                    ),
                    capability_boundary=boundary,
                    backend_boundary_policy=backend_boundary,
                    prover_executable=args.prover,
                    timeout=args.timeout,
                    audit=PolicyApplyAudit(args.audit) if args.audit else None,
                )
                output = {
                    **applied.as_dict(),
                    "sandbox": args.sandbox,
                    "input_policy_bytes_digest": hashlib.sha256(raw_policy.encode()).hexdigest(),
                }
                code = 0 if applied.status == "applied" else 2
            else:
                if args.output:
                    Path(args.output).write_text(
                        serialize_policy(compiled.plan.policy, format=args.format), encoding="utf-8"
                    )
                output, code = compiled.as_dict(), 0
        print(json.dumps(output, indent=2))
        return code
    except (ValueError, OSError, UnicodeError, TypeError, KeyError):
        print(json.dumps({"status": "unsupported", "reason_code": "openshell_input_invalid"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
