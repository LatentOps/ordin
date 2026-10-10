"""Capture current host grant/revocation and cross-agent evidence at a pinned SHA."""

import argparse
import json
import subprocess
from pathlib import Path

from ordin import ToolCallAdapter
from ordin.assurance import ReviewedAction, build_delegated_attack_path, challenge_property
from examples.assurance.delegation import fixture

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--fixture-dir", type=Path, required=True)
    args = parser.parse_args()
    pinned = subprocess.run(
        [
            "rtk",
            "proxy",
            "git",
            "diff",
            "--quiet",
            args.revision,
            "--",
            "ordin",
            "schemas",
            "pyproject.toml",
        ],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    if pinned.returncode:
        raise ValueError("delegation package differs from declared revision")
    issuer, root, parent, child, grant, gate = fixture(args.fixture_dir, revision=args.revision)
    adapter = ToolCallAdapter("fixture")
    parent_context = parent.context()
    parent_decision = gate.assurance.evaluate_action(
        adapter.adapt("read_file", {"path": "/fixture/source"}, action_id="parent"),
        host_context=parent_context,
    )
    allowed = gate.evaluate_action(
        adapter.adapt("read_file", {"path": "/fixture/source"}, action_id="allowed")
    )
    denied = gate.evaluate_action(
        adapter.adapt("read_file", {"path": "/fixture/.env"}, action_id="denied")
    )
    path = build_delegated_attack_path(
        issuer,
        grant,
        parent,
        child,
        (ReviewedAction(parent_decision, parent_context),),
        (allowed, denied),
    )
    assert allowed.may_execute and denied.denied and path.reachability == "blocked"
    revoked = issuer.revoke(root)
    committed = gate.commit_use(allowed, allowed.assurance.review.action)
    assert not committed and set(revoked) == {"root", "child"}
    actual = challenge_property(
        property_id="delegation_subset", seed=14, revision=args.revision, trials=32
    )
    seeded = challenge_property(
        property_id="delegation_subset",
        seed=14,
        revision=args.revision,
        trials=32,
        variant="seeded_unsafe_checker",
    )
    assert actual.status == "passed" and actual.failures == 0 and seeded.failures == 24
    report = {
        "schema_version": "ordin.assurance_m7_evidence.v1",
        "implemented_revision": args.revision,
        "allowed_review": allowed.as_dict(),
        "denied_review": denied.as_dict(),
        "cross_agent_path": path.as_dict(),
        "revoked_grants": revoked,
        "pending_commit_after_revocation": committed,
        "actual_challenger": actual.as_dict(),
        "seeded_challenger": seeded.as_dict(),
        "limitations": [
            "Synthetic protected host fixtures; no real execution, credentials, OS permission grant or physical process isolation."
        ],
    }
    (ROOT / "docs/assurance/evidence/m7-delegation.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "revision": args.revision,
                "allowed": allowed.disposition,
                "env": denied.disposition,
                "cross_agent_reachability": path.reachability,
                "revoked": revoked,
                "pending_commit": committed,
                "assessed": actual.evaluated,
                "seeded_failures": seeded.failures,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
