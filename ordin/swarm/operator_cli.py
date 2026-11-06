"""Explicit authenticated operator queries, or clearly unverified offline reports."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socket
import ssl

from ordin.schema import validate_named_schema
from .audit import verify_swarm_audit
from .coordinator_store import decode
from .dashboard import render_swarm_dashboard
from .operator_api import SwarmOperatorClient

COMMANDS = frozenset(
    {
        "list",
        "status",
        "graph",
        "explain",
        "incidents",
        "policy",
        "coverage",
        "pause",
        "revoke",
        "approve",
        "deny",
        "sweep",
        "export",
        "dashboard",
        "audit",
    }
)


def _load(path, maximum=1024 * 1024):
    with Path(path).open("rb") as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError("operator.report_limit")
    return decode(data.decode("utf-8"), maximum)


def _save(path, data):
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(data)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="ordin swarm",
        description="Explicit mTLS operator diagnostics; importing or inspecting data starts no service.",
    )
    parser.add_argument("command", choices=sorted(COMMANDS))
    parser.add_argument("audit_action", nargs="?", choices=("verify",))
    parser.add_argument("--host")
    parser.add_argument("--port", type=int)
    parser.add_argument("--ca")
    parser.add_argument("--cert")
    parser.add_argument("--key")
    parser.add_argument("--scope-ref")
    parser.add_argument("--report")
    parser.add_argument("--checkpoint")
    parser.add_argument("--action-ref")
    parser.add_argument("--actor-ref")
    parser.add_argument("--scope-kind", choices=("agent", "task", "swarm"), default="agent")
    parser.add_argument("--request-ref")
    parser.add_argument("--idempotency-key")
    parser.add_argument("--maximum-resources", type=int, default=256)
    parser.add_argument("--output")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "audit":
            if args.audit_action != "verify" or not args.report:
                raise ValueError("operator.audit_input_required")
            result = verify_swarm_audit(
                _load(args.report, 8 * 1024 * 1024),
                _load(args.checkpoint) if args.checkpoint else None,
            ).as_dict()
        elif args.report:
            if args.command not in {
                "list",
                "status",
                "graph",
                "explain",
                "incidents",
                "policy",
                "coverage",
                "dashboard",
                "export",
            }:
                raise ValueError("operator.offline_control_forbidden")
            result = _load(args.report)
            if validate_named_schema("swarm_operator_snapshot", result):
                raise ValueError("operator.snapshot_required")
            result["verified_live_source"] = False
            result["coordinator_online"] = False
            result["proof_gaps"] = sorted(
                set(result["proof_gaps"]) | {"offline_report_not_live_verification"}
            )
            if args.command in {"graph", "incidents", "policy", "coverage"}:
                result = {
                    "schema_version": "ordin.swarm_operator_view.v1",
                    "scope_ref": result["scope_ref"],
                    "view": args.command,
                    "data": result[args.command],
                    "proof_gaps": result["proof_gaps"],
                    "execution_authority": False,
                }
        elif not args.host:
            if args.command in {
                "pause",
                "revoke",
                "approve",
                "deny",
                "sweep",
                "export",
                "dashboard",
            }:
                raise ValueError("operator.authenticated_endpoint_required")
            result = {
                "schema_version": "ordin.swarm_operator_unconfigured.v1",
                "configured": False,
                "verified_live_source": False,
                "coverage": "unknown",
                "prehistory": "unknown",
                "execution_authority": False,
            }
        else:
            if (
                not args.port
                or not 1 <= args.port <= 65535
                or not all((args.ca, args.cert, args.key))
            ):
                raise ValueError("operator.explicit_tls_configuration_required")
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=args.ca)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(args.cert, args.key)
            operation = "status" if args.command == "dashboard" else args.command
            arguments = {}
            if operation == "explain":
                arguments = {"action_ref": args.action_ref}
            if operation in {"pause", "revoke"}:
                arguments = {"scope_kind": args.scope_kind, "actor_ref": args.actor_ref}
            if operation in {"approve", "deny"}:
                arguments = {
                    "request_ref": args.request_ref,
                    "idempotency_key": args.idempotency_key,
                }
            if operation == "sweep":
                arguments = {"maximum_resources": args.maximum_resources}
            with socket.create_connection((args.host, args.port), timeout=5) as raw:
                with context.wrap_socket(raw, server_hostname=args.host) as connection:
                    result = SwarmOperatorClient(connection).request(
                        operation, scope_ref=args.scope_ref, **arguments
                    )
        if args.command == "dashboard":
            if not args.output:
                raise ValueError("operator.dashboard_output_required")
            _save(args.output, render_swarm_dashboard(result))
        elif args.output:
            _save(args.output, json.dumps(result, sort_keys=True, allow_nan=False) + "\n")
        print(
            json.dumps(result, sort_keys=True, allow_nan=False)
            if args.json
            else json.dumps(result, indent=2, allow_nan=False)
        )
        return 0 if args.command != "audit" or result["valid"] else 2
    except (ValueError, OSError, TypeError, KeyError, RecursionError):
        print(json.dumps({"error": "operator.request_refused", "execution_authority": False}))
        return 2
