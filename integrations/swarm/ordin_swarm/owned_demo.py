"""Explicit isolated Linux broker canary with original runtime evidence."""

from __future__ import annotations

import argparse
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import platform
import sys
import tempfile
from typing import Any


def run() -> dict[str, Any]:
    if sys.platform != "linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        return {
            "schema_version": "ordin.swarm_owned_demo.v1",
            "status": "unsupported",
            "reason_code": "owned_demo.linux_x86_64_required",
            "physical_enforcement": False,
            "execution_authority": False,
        }
    from ordin import ToolCallAdapter
    from ordin.swarm._corpus_runtime import owned_runtime

    with tempfile.TemporaryDirectory(prefix="ordin-owned-swarm-demo-") as directory:
        root = Path(directory)
        with owned_runtime(root / "fixture", kernel=True) as fixture:
            broker = fixture.broker
            channel = fixture.channels["child"]
            expected = fixture.target.read_bytes()
            prepared = broker.prepare(
                channel, fixture.grant, fixture.action, idempotency_key="owned-demo-read"
            )
            if prepared.authorization is None:
                raise ValueError("owned broker refused its supported fixture request")
            authorization = prepared.authorization
            scope = broker.authorization_scope(authorization)
            result = broker.dispatch(authorization)
            if not (
                result.status == "completed"
                and result.physical_enforcement
                and result.value == expected
                and broker.verify_result(result, authorization)
                and result.executor_outcome is not None
                and fixture.backend.verify_outcome(result.executor_outcome, scope.plan)
            ):
                raise ValueError("original owned kernel completion was not verified")
            replay_refused = False
            try:
                broker.dispatch(authorization)
            except ValueError:
                replay_refused = True
            if not replay_refused:
                raise ValueError("owned broker authorization replay was accepted")
            outside = root / "outside-route.txt"
            outside.write_bytes(b"owned-host-bypass-canary\n")
            outside.chmod(0o600)
            forbidden = ToolCallAdapter("fixture").adapt(
                "read_file", {"path": str(outside)}, action_id="outside-route"
            )
            refused = broker.prepare(
                channel, fixture.grant, forbidden, idempotency_key="owned-demo-deny"
            )
            if refused.authorization is not None or refused.disposition == "execute":
                raise ValueError("out-of-scope mediated read received authorization")
            bypass_read = outside.read_bytes() == b"owned-host-bypass-canary\n"
            next_action = replace(fixture.action, action_id="old-epoch")
            stale = broker.prepare(
                channel, fixture.grant, next_action, idempotency_key="owned-demo-stale"
            )
            if stale.authorization is None:
                raise ValueError("stale-epoch control was not admitted before the fence")
            fixture.registry.advance_policy_epoch(1)
            fenced = broker.dispatch(stale.authorization)
            if fenced.status == "completed" or fenced.physical_enforcement:
                raise ValueError("old-epoch authorization survived its fence")
            outcome = result.executor_outcome
            report = {
                "schema_version": "ordin.swarm_owned_demo.v1",
                "status": "completed",
                "trust_boundary": "owned_loopback_fixture_with_public_test_pki",
                "environment": {
                    "python": platform.python_version(),
                    "kernel": platform.release(),
                    "machine": platform.machine(),
                },
                "execution_boundary": "fresh_owned_linux_read_worker",
                "policy_digest": scope.plan.policy_digest,
                "action_digest": result.action_digest,
                "verified_outcome_digest": hashlib.sha256(
                    json.dumps(outcome.as_dict(), sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest(),
                "payload_bytes": len(expected),
                "allowed_read_completed": True,
                "mediated_out_of_scope_request": "denied_before_worker",
                "authorization_replay": "refused",
                "stale_epoch_authorization": "refused",
                "raw_host_bypass": "uncovered_success" if bypass_read else "unknown",
                "budget_boundary": "local_admission_accounting",
                "coordinator_exercised": False,
                "physical_enforcement": True,
                "whole_host_enforced": False,
                "execution_authority": False,
            }
    from ordin.schema import validate_named_schema

    if validate_named_schema("swarm_owned_demo", report):
        raise ValueError("invalid owned runtime demonstration report")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run an isolated owned Linux broker fixture")
    parser.add_argument(
        "--owned-fixture",
        action="store_true",
        required=True,
        help="explicitly select the isolated fixture and its public test PKI",
    )
    parser.parse_args(argv)
    try:
        report = run()
    except (ImportError, ValueError, OSError, RuntimeError):
        print(
            json.dumps(
                {
                    "schema_version": "ordin.swarm_owned_demo.v1",
                    "status": "failed",
                    "reason_code": "owned_demo.fixture_failed",
                    "physical_enforcement": None,
                    "execution_authority": False,
                }
            )
        )
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
