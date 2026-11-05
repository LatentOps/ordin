"""Explicit read-only policy files, bounded offline diff and replay simulation."""

import argparse
from dataclasses import replace
import json
from pathlib import Path
from typing import Sequence

from ordin import ActionEnvelope, AgentGate, Ordin
from ordin.action import ActionReview
from ordin._runtime_json import digest

from .models import CoverageManifest, SwarmContext, SwarmIdentity
from .policy_compiler import (
    compile_swarm_policy_set,
    diff_swarm_policies,
    load_swarm_policy_maximum,
    policy_relaxes,
)
from .policy_facts import SwarmBudgetFact, SwarmPolicyFacts
from .policy_runtime import SwarmPolicyReplayCase, SwarmPolicySimulation
from .policy_set import SwarmPolicySet, load_swarm_policy_set


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate input key")
        result[key] = value
    return result


def _cases(path: str, policy_digest: str) -> tuple[SwarmPolicyReplayCase, ...]:
    try:
        with Path(path).open("rb") as stream:
            raw = stream.read(1048577)
        if len(raw) > 1048576:
            raise ValueError("corpus too large")
        values = json.loads(raw, object_pairs_hook=_unique)
        if (
            type(values) is not dict
            or set(values) != {"schema_version", "cases"}
            or values["schema_version"] != "ordin.swarm_policy_corpus.v1"
            or type(values["cases"]) is not list
            or not 1 <= len(values["cases"]) <= 256
        ):
            raise ValueError("invalid corpus")
        cases = []
        for value in values["cases"]:
            if (
                type(value) is not dict
                or set(value) - {"case_id", "identity", "action", "expected", "facts"}
                or not {"case_id", "identity", "action"} <= set(value)
            ):
                raise ValueError("invalid replay case")
            context = SwarmContext(
                "offline-simulation", SwarmIdentity(**value["identity"]), CoverageManifest(), 0
            )
            action = ActionEnvelope.from_dict(value["action"])
            facts = None
            if value.get("facts") is not None:
                data = value["facts"]
                if type(data) is not dict or set(data) - {
                    "data_labels",
                    "message_classes",
                    "temporal_categories",
                    "budgets",
                    "checks",
                }:
                    raise ValueError("invalid hypothetical facts")
                arrays = {}
                for name in (
                    "data_labels",
                    "message_classes",
                    "temporal_categories",
                    "budgets",
                    "checks",
                ):
                    item = data.get(name)
                    if item is not None and (type(item) is not list or len(item) > 64):
                        raise ValueError("invalid bounded hypothetical facts")
                    arrays[name] = item
                facts = SwarmPolicyFacts(
                    value["case_id"],
                    0,
                    digest(action.as_dict()),
                    digest(context.as_dict()),
                    policy_digest,
                    "0" * 64,
                    1,
                    None if arrays["data_labels"] is None else tuple(arrays["data_labels"]),
                    None if arrays["message_classes"] is None else tuple(arrays["message_classes"]),
                    None
                    if arrays["temporal_categories"] is None
                    else tuple(arrays["temporal_categories"]),
                    None
                    if arrays["budgets"] is None
                    else tuple(SwarmBudgetFact(**v) for v in arrays["budgets"]),
                    tuple((v["check_id"], v["status"]) for v in arrays["checks"] or ()),
                )
                facts._payload()
            cases.append(
                SwarmPolicyReplayCase(
                    value["case_id"], context, action, value.get("expected", "unspecified"), facts
                )
            )
        if len({v.case_id for v in cases}) != len(cases):
            raise ValueError("duplicate replay case IDs")
        return tuple(cases)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        raise ValueError("invalid explicit bounded offline policy corpus") from None


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ordin swarm policy",
        description="Read-only policy validation, explanation, diff and offline simulation.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("validate", "explain"):
        child = commands.add_parser(name)
        child.add_argument("policy")
        child.add_argument("--maximum")
        child.add_argument("--json", action="store_true")
    child = commands.add_parser("diff")
    child.add_argument("before")
    child.add_argument("after")
    child.add_argument("--json", action="store_true")
    child = commands.add_parser("simulate")
    child.add_argument("policy")
    child.add_argument("--maximum", required=True)
    child.add_argument("--corpus", required=True)
    child.add_argument("--before")
    child.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "diff":
            output = diff_swarm_policies(
                load_swarm_policy_set(args.before), load_swarm_policy_set(args.after)
            )
        else:
            policy = load_swarm_policy_set(args.policy)
            maximum = load_swarm_policy_maximum(args.maximum) if args.maximum else None
            plan = compile_swarm_policy_set(policy, maximum) if maximum else None
            if args.command == "simulate":
                assert plan is not None and maximum is not None
                before = (
                    compile_swarm_policy_set(load_swarm_policy_set(args.before), maximum)
                    if args.before
                    else compile_swarm_policy_set(
                        SwarmPolicySet(
                            "operator-maximum",
                            1,
                            maximum.tenant_id,
                            maximum.swarm_id,
                            default_disposition="execute",
                        ),
                        maximum,
                    )
                )
                outcomes, fingerprints = [], []
                baseline = AgentGate(replace(Ordin(), audit=None))
                for case in _cases(args.corpus, policy.digest):
                    result = baseline.evaluate_action(case.action)
                    if not isinstance(result.review, ActionReview):
                        raise ValueError("offline corpus requires action reviews")
                    previous = before.evaluate(
                        case.context,
                        case.action,
                        result.review,
                        result.disposition,
                        facts=case.facts,
                    )
                    following = plan.evaluate(
                        case.context,
                        case.action,
                        result.review,
                        result.disposition,
                        facts=case.facts,
                    )
                    outcomes.append(
                        (case.case_id, previous.disposition, following.disposition, case.expected)
                    )
                    fingerprints.append(
                        [
                            case.case_id,
                            digest(case.context.as_dict()),
                            digest(case.action.as_dict()),
                            case.facts.digest if case.facts else None,
                        ]
                    )
                output = SwarmPolicySimulation(
                    "offline",
                    plan.digest,
                    digest(["offline", before.digest]),
                    digest(fingerprints),
                    tuple(outcomes),
                    policy_relaxes(before, plan),
                ).as_dict()
            else:
                output = {
                    "schema_version": "ordin.swarm_policy_validation.v1",
                    "valid": True,
                    "policy_digest": policy.digest,
                    "scope_digest": digest([policy.tenant_id, policy.swarm_id]),
                    "maximum_checked": maximum is not None,
                    "compilation_digest": plan.digest if plan else None,
                    "explanation": policy.as_dict() if args.command == "explain" else None,
                    "live_capabilities_verified": False,
                    "deployment_authorized": False,
                    "execution_authority": False,
                }
        print(json.dumps(output, sort_keys=True) if args.json else json.dumps(output, indent=2))
        return 0
    except (ValueError, TypeError, KeyError) as exc:
        print(
            json.dumps(
                {
                    "error": "invalid_swarm_policy",
                    "message": str(exc)
                    if type(exc) is ValueError
                    else "invalid bounded policy input",
                }
            )
        )
        return 2
