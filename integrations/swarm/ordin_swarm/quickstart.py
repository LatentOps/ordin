"""Offline two-agent adoption fixture; never a production rollout or permit."""

from __future__ import annotations

import argparse
import json
import platform
import sys
from typing import Any


def run() -> dict[str, Any]:
    """Compare review modes, then exercise actual protected local callbacks.

    The maintained custom-runtime fixture uses two original enrolled actors,
    private artifact/message lineage, and denied egress/child callbacks. Its
    outcomes authenticate host mediation; they do not prove OS confinement.
    """
    from ordin import ActionEnvelope
    from ordin.swarm import CoverageManifest, InMemoryAgentRegistry, SwarmGate
    from .demo import run as framework_fixture

    comparisons = []
    for mode in ("observe", "intercept"):
        registry = InMemoryAgentRegistry("owned-fixture", "quickstart", clock=lambda: 100)
        gate = SwarmGate(registry)
        reviews = []
        for actor in ("planner", "worker"):
            adapter = object()
            channel = registry.bind_channel(adapter, runtime_id="quickstart")
            context = registry.enroll(
                channel,
                adapter,
                agent_id=actor,
                session_id="session-" + actor,
                coverage=CoverageManifest(mode),
            )
            for case_id, command in (("benign", "git status --short"), ("unsafe", "rm -rf /")):
                decision = gate.evaluate_action(
                    context,
                    ActionEnvelope.shell(command, action_id=actor + "-" + case_id),
                    channel=channel,
                    adapter=adapter,
                )
                reviews.append(
                    {"actor": actor, "case_id": case_id, "disposition": decision.disposition}
                )
        comparisons.append(reviews)
    mediated = framework_fixture("custom")
    if not (
        mediated["allowed_read_completed"]
        and mediated["private_handoff_delivered"]
        and mediated["source_flow_violated"]
        and not mediated["egress_callbacks"]
        and not mediated["child_callbacks"]
        and mediated["denied_reviews"] >= 2
        and mediated["physical_enforcement"] is False
    ):
        raise ValueError("owned two-agent fixture did not satisfy its declared controls")
    report = {
        "schema_version": "ordin.swarm_quickstart.v1",
        "fixture": "offline_two_agent_v1",
        "label_provenance": "synthetic_fixture_definition",
        "environment": {
            "python": platform.python_version(),
            "platform": sys.platform,
            "machine": platform.machine(),
        },
        "observe_only": {
            "reviews": comparisons[0],
            "callbacks_invoked": 0,
            "interception_active": False,
        },
        "shadow": {
            "reviews": comparisons[1],
            "disposition_changes": sum(
                a["disposition"] != b["disposition"] for a, b in zip(*comparisons)
            ),
            "execution_performed": False,
        },
        "mediated": mediated,
        "execution_boundary": "host_owned_callback_fixture",
        "runtime_enforcement": "not_evaluated",
        "physical_enforcement": False,
        "uncovered_paths": [
            "direct_host_tools",
            "raw_host_network",
            "existing_credentials",
            "unwrapped_processes",
        ],
        "runtime_network_guard": "disabled_connections_in_explicit_fixture",
        "hosted_model_calls": 0,
        "execution_authority": False,
    }
    from ordin.schema import validate_named_schema

    if validate_named_schema("swarm_quickstart", report):
        raise ValueError("invalid owned quickstart report")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the offline owned two-agent fixture")
    parser.parse_args(argv)
    try:
        report = run()
    except ImportError:
        print(
            json.dumps(
                {
                    "status": "failed",
                    "reason_code": "quickstart.incompatible_installation",
                    "execution_authority": False,
                }
            )
        )
        return 1
    except (ValueError, OSError, RuntimeError):
        print(
            json.dumps(
                {
                    "status": "failed",
                    "reason_code": "quickstart.fixture_failed",
                    "execution_authority": False,
                }
            )
        )
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
