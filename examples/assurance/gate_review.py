"""Synthetic host SDK review: conservative gate, receipts and binding recheck.

This example performs no tool execution and installs no real enforcement.
"""

import argparse
import hashlib
import json
from pathlib import Path

from ordin import (
    AgentGate,
    Ordin,
    ToolCallAdapter,
    ToolResourceBinding,
    ToolSemanticRule,
    ToolSemanticsRegistry,
)
from ordin.assurance import (
    AssuranceGate,
    HostEvidenceSource,
    InvariantSelectors,
    ProtectedAsset,
    ProtectedProfileSelection,
    RepositoryScope,
    SecurityInvariant,
    SecurityProfile,
    load_approved_profile,
)
from ordin.runtime_boundary import RuntimeCapabilityBoundary
from ordin.runtime_contract import FilesystemCapability
from ordin.runtime_observation import RuntimeEvidenceSource


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    repo = RepositoryScope("fixture/gate-example", "fixture-v1")
    profile = SecurityProfile(
        "fixture-gate",
        "1",
        repo,
        (ProtectedAsset("workflow", "policy", "/fixture/.github/workflows/deploy.yml"),),
        invariants=(
            SecurityInvariant(
                "protect-workflow",
                "protected_policy_mutation",
                InvariantSelectors(resource_ref="workflow"),
                on_violation="block",
            ),
            SecurityInvariant(
                "read-approval",
                "require_approval",
                InvariantSelectors(effects=("filesystem.read",)),
            ),
        ),
    )
    path = args.output / "profile.json"
    path.write_text(json.dumps(profile.as_dict()), encoding="utf-8")
    path.chmod(0o600)
    policy = "a" * 64
    selection = ProtectedProfileSelection(
        args.output.resolve(),
        "profile.json",
        "/operator/profile.json",
        repo,
        profile.digest,
        hashlib.sha256(path.read_bytes()).hexdigest(),
        "1",
        "fixture-operator",
        RuntimeCapabilityBoundary(
            "agent",
            filesystem=(FilesystemCapability("write", "/fixture", "prefix"),),
            filesystem_semantics="lexical_prefix",
            runtime_filesystem_guarantees=True,
        ),
        RuntimeEvidenceSource("synthetic-host-fixture", "b" * 64, "fixture-sandbox", policy),
    )
    approved = load_approved_profile(
        selection, current_repository=repo, active_runtime_policy_digest=policy
    )
    source = HostEvidenceSource("fixture-agent", repo, "b" * 64, 1, policy, selection.digest)
    semantics = ToolSemanticsRegistry(
        "fixture-tools",
        "1",
        (
            ToolSemanticRule(
                "read",
                "tool",
                "read_file",
                ("filesystem.read",),
                runtime="fixture",
                resources=(ToolResourceBinding("path", "path"),),
            ),
            ToolSemanticRule(
                "write",
                "tool",
                "write_file",
                ("filesystem.write",),
                runtime="fixture",
                resources=(ToolResourceBinding("path", "path"),),
            ),
        ),
    )
    gate = AssuranceGate(AgentGate(Ordin(tool_semantics=semantics)), approved)
    adapter = ToolCallAdapter("fixture")
    read = adapter.adapt("read_file", {"path": "/fixture/README.md"}, action_id="read")
    write = adapter.adapt(
        "write_file", {"path": "/fixture/.github/workflows/deploy.yml"}, action_id="write"
    )
    missing = gate.evaluate_action(read, host_context=source.context())
    receipt = source.record_approval(read, approved, receipt_id="fixture-human-approval")
    host = source.context(approvals=(receipt,))
    approved_read = gate.evaluate_action(read, host_context=host)
    denied_write = gate.evaluate_action(write, host_context=host)
    assert missing.requires_approval and approved_read.may_execute and denied_write.denied
    assert gate.binding_matches(approved_read, approved_read.review.action, host_context=host)
    reports = {
        "before_approval": missing.as_dict(),
        "after_approval": approved_read.as_dict(),
        "protected_mutation": denied_write.as_dict(),
    }
    (args.output / "decisions.json").write_text(
        json.dumps(reports, indent=2) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "before_approval": missing.disposition,
                "after_approval": approved_read.disposition,
                "protected_mutation": denied_write.disposition,
                "binding_matches": True,
                "executes_actions": False,
                "protection": "synthetic_host_fixture_only",
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
