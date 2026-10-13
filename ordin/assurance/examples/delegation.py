"""Offline parent/child grant fixture; no reviewed command or OS right executes."""

import argparse
import hashlib
import json
from dataclasses import replace
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
    DelegationAuthority,
    DelegationIssuer,
    DelegatingAssuranceGate,
    HostEvidenceSource,
    ProtectedProfileSelection,
    RepositoryScope,
    SecurityProfile,
    load_approved_profile,
)
from ordin.runtime_boundary import RuntimeCapabilityBoundary
from ordin.runtime_contract import FilesystemCapability, ToolCapability
from ordin.runtime_observation import RuntimeEvidenceSource


def fixture(directory: Path, *, revision="fixture-v1"):
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    repository = RepositoryScope("fixture/delegation", revision)
    profile = SecurityProfile("fixture-delegation", "1", repository)
    path = directory / "profile.json"
    path.write_text(json.dumps(profile.as_dict()), encoding="utf-8")
    path.chmod(0o600)
    policy = "a" * 64
    selection = ProtectedProfileSelection(
        directory.resolve(),
        "profile.json",
        "/operator/profile.json",
        repository,
        profile.digest,
        hashlib.sha256(path.read_bytes()).hexdigest(),
        "1",
        "fixture-operator",
        RuntimeCapabilityBoundary(
            "fixture-protection",
            filesystem=(FilesystemCapability("write", "/fixture", "prefix"),),
            filesystem_semantics="lexical_prefix",
            runtime_filesystem_guarantees=True,
        ),
        RuntimeEvidenceSource("synthetic-host-fixture", "b" * 64, "fixture-sandbox", policy),
    )
    approved = load_approved_profile(
        selection, current_repository=repository, active_runtime_policy_digest=policy
    )
    parent = HostEvidenceSource("parent", repository, "b" * 64, 0, policy, selection.digest)
    child = replace(parent, principal="child", session_digest="c" * 64)
    maximum = DelegationAuthority(
        RuntimeCapabilityBoundary(
            "parent-maximum",
            filesystem=(FilesystemCapability("read", "/fixture", "prefix"),),
            tools=(ToolCapability("fixture", None, "read_file"),),
            filesystem_semantics="lexical_prefix",
            runtime_filesystem_guarantees=True,
        )
    )
    narrowed = DelegationAuthority(
        replace(
            maximum.capability,
            boundary_id="child-maximum",
            filesystem=(FilesystemCapability("read", "/fixture/source", "exact"),),
        )
    )
    issuer = DelegationIssuer(parent, approved, maximum, maximum, clock=lambda: 100)
    root = issuer.authorize_root(maximum, grant_id="root", expires_at=200)
    grant = issuer.issue_child(root, child, narrowed, grant_id="child", expires_at=150)
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
        ),
    )
    gate = DelegatingAssuranceGate(
        AssuranceGate(AgentGate(Ordin(tool_semantics=semantics)), approved), issuer, grant, child
    )
    return issuer, root, parent, child, grant, gate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    issuer, root, parent, child, grant, gate = fixture(args.output)
    adapter = ToolCallAdapter("fixture")
    allowed = gate.evaluate_action(
        adapter.adapt("read_file", {"path": "/fixture/source"}, action_id="allowed")
    )
    denied = gate.evaluate_action(
        adapter.adapt("read_file", {"path": "/fixture/.env"}, action_id="denied")
    )
    assert allowed.may_execute and denied.denied
    issuer.revoke(root)
    assert not gate.commit_use(allowed, allowed.assurance.review.action)
    print(
        json.dumps(
            {
                "allowed_review": allowed.disposition,
                "env_review": denied.disposition,
                "pending_use_after_parent_revocation": False,
                "executes_actions": False,
                "enforcement": "synthetic_host_fixture_only",
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
