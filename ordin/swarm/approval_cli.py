"""Bounded operator commands over an original host-injected authenticated session."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from .approval import SwarmApprovalPolicy, SwarmApprovalReceipt, SwarmRecoveryApproval
from .approval_service import SwarmApprovalService
from .operator_auth import HumanOperatorChannel


class SwarmApprovalOperatorSession:
    """Host-owned live handles; files and command-line flags cannot restore these."""

    def __init__(self, service: SwarmApprovalService, channel: HumanOperatorChannel):
        if type(service) is not SwarmApprovalService or type(channel) is not HumanOperatorChannel:
            raise ValueError("original governance service and authenticated human channel required")
        self.service, self.channel = service, channel
        self._receipts: dict[str, SwarmApprovalReceipt] = {}
        self._recoveries: dict[str, SwarmRecoveryApproval] = {}

    def execute(
        self, command, *, request_id=None, task_id=None, idempotency_key=None, recovery=False
    ):
        service, channel = self.service, self.channel
        if command == "queue":
            return service.snapshot(channel, task_id=task_id)
        if command == "show":
            return service.get_request(channel, request_id)
        if command in {"approve", "deny"}:
            resolve = service.resolve_recovery if recovery else service.resolve
            result = resolve(channel, request_id, command, idempotency_key=idempotency_key)
            if "receipt" in result:
                self._receipts[request_id] = result["receipt"]
            if "approval" in result:
                self._recoveries[request_id] = result["approval"]
            return {
                key: value for key, value in result.items() if key not in {"receipt", "approval"}
            }
        if command == "cancel":
            return service.cancel(channel, request_id, idempotency_key=idempotency_key)
        if command == "expire":
            return service.expire(channel, request_id, idempotency_key=idempotency_key)
        if command == "resume":
            original = self._recoveries.get(request_id)
            if original is None:
                raise ValueError(
                    "original recovery approval must be retained in this live operator session"
                )
            return service.resume(channel, original)
        raise ValueError("unknown bounded governance command")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate governance policy field")
        result[key] = value
    return result


def main(argv: Sequence[str] | None = None, *, session: SwarmApprovalOperatorSession | None = None):
    parser = argparse.ArgumentParser(prog="ordin swarm approval")
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser(
        "validate", help="Validate an explicit offline governance policy"
    )
    validate.add_argument("policy")
    queue = commands.add_parser("queue", help="Inspect a protected live operator queue")
    queue.add_argument("--task", required=True)
    for name in ("show", "approve", "deny", "cancel", "expire", "resume"):
        child = commands.add_parser(name)
        child.add_argument("request_id")
        if name in {"approve", "deny", "cancel", "expire"}:
            child.add_argument("--idempotency-key", required=True)
        if name in {"approve", "deny"}:
            child.add_argument("--recovery", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "validate":
            with Path(args.policy).open("rb") as stream:
                raw = stream.read(32769)
            if len(raw) > 32768:
                raise ValueError("bounded governance policy required")
            result = SwarmApprovalPolicy.from_dict(
                json.loads(raw, object_pairs_hook=_unique)
            ).as_dict()
        else:
            if type(session) is not SwarmApprovalOperatorSession:
                raise ValueError(
                    "live governance requires a host-injected original authenticated operator session"
                )
            result = session.execute(
                args.command,
                request_id=getattr(args, "request_id", None),
                task_id=getattr(args, "task", None),
                idempotency_key=getattr(args, "idempotency_key", None),
                recovery=getattr(args, "recovery", False),
            )
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        # Never echo paths, arguments, credentials or unexpected backend messages.
        print(
            json.dumps(
                {
                    "error": "governance command rejected; original current bounded authority required"
                }
            )
        )
        return 2
