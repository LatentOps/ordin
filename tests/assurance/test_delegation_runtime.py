"""Exact MCP/runtime identity plus normal local review controls without execution."""

from dataclasses import replace

import pytest

from ordin import (
    ActionEnvelope,
    AgentGate,
    MCPAdapter,
    Ordin,
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
)
from ordin.runtime_contract import derive_runtime_capability_contract
from ordin.runtime_boundary import RuntimeCapabilityBoundary
from ordin.runtime_observation import RuntimeEvidenceSource, RuntimeObservation
from ordin.runtime_requests_v2 import derive_runtime_request_contract_v2
from ordin.runtime_requirements import RuntimeRequirementProfile
from ordin.session import IntegrationSession, SessionIdentity

from .test_profiles import REPO, POLICY_HASH, approve, selected, config_profile
from .test_invariants import SEMANTICS
from .test_delegation import child_max, maximum
from .test_delegating_gate import action


def test_exact_readonly_mcp_args_version_and_identity_remain_inside_child(tmp_path):
    profile = approve(selected(tmp_path, config_profile()))
    semantics = ToolSemanticsRegistry(
        "fixture-mcp",
        "1",
        (
            ToolSemanticRule(
                "read",
                "mcp",
                "read_file",
                ("filesystem.read",),
                server="fixture",
                resources=(ToolResourceBinding("path", "path"),),
            ),
        ),
    )
    requirements = RuntimeRequirementProfile(
        "fixture-mcp",
        client_executables=("/fixture/bin/mcp-client",),
        spawn_children=False,
        mcp_endpoints={"fixture": "https://fixture.invalid/mcp"},
        mcp_versions={"fixture": ("2025-11-25",)},
    )
    core = Ordin(tool_semantics=semantics, runtime_requirements=requirements)
    proposed = MCPAdapter("fixture").adapt(
        "read_file", {"path": "/fixture/source"}, action_id="read"
    )
    contract = derive_runtime_request_contract_v2(core.review_action(proposed))
    cap = contract.capability
    authority = DelegationAuthority(
        RuntimeCapabilityBoundary(
            "fixture-mcp",
            filesystem=cap.filesystem,
            network=cap.network,
            tools=cap.tools,
            process=cap.process,
            privilege=cap.privilege,
        ),
        contract.requests,
    )
    parent = HostEvidenceSource("parent", REPO, "a" * 64, 0, POLICY_HASH, profile.selection_digest)
    source = replace(parent, principal="child", session_digest="d" * 64)
    issuer = DelegationIssuer(parent, profile, authority, authority, clock=lambda: 100)
    root = issuer.authorize_root(authority, grant_id="root", expires_at=200)
    child = issuer.issue_child(root, source, authority, grant_id="child", expires_at=150)
    gate = DelegatingAssuranceGate(AssuranceGate(AgentGate(core), profile), issuer, child, source)
    allowed = gate.evaluate_action(proposed)
    assert allowed.may_execute and gate.commit_use(allowed, allowed.assurance.review.action)
    changed = MCPAdapter("fixture").adapt(
        "read_file", {"path": "/fixture/other"}, action_id="changed"
    )
    assert gate.evaluate_action(changed).denied
    unknown = MCPAdapter("fixture").adapt(
        "write_file", {"path": "/fixture/source"}, action_id="write"
    )
    assert not gate.evaluate_action(unknown).may_execute


def test_child_collector_cannot_accept_fabricated_or_sibling_observations(tmp_path):
    profile = approve(selected(tmp_path, config_profile()))
    core = Ordin(tool_semantics=SEMANTICS)
    identity = SessionIdentity("fixture-child", "child-runtime")
    planned = IntegrationSession(identity, AgentGate(core))
    parent = HostEvidenceSource("parent", REPO, "a" * 64, 0, POLICY_HASH, profile.selection_digest)
    source = replace(parent, principal="child", session_digest=planned.runtime_session_digest)
    issuer = DelegationIssuer(parent, profile, maximum(), maximum(), clock=lambda: 100)
    root = issuer.authorize_root(maximum(), grant_id="root", expires_at=200)
    child = issuer.issue_child(root, source, child_max(), grant_id="child", expires_at=150)
    gate = DelegatingAssuranceGate(
        AssuranceGate(AgentGate(core), profile), issuer, child, source, identity=identity
    )
    collector = RuntimeEvidenceSource(
        "fixture", source.session_digest, "fixture-sandbox", POLICY_HASH
    )
    assert gate.runtime_session_digest == source.session_digest
    gate.bind_runtime_source(collector)
    result = gate.evaluate_action(action())
    assert result.may_execute and gate.commit_use(result, result.assurance.review.action)
    contract = derive_runtime_capability_contract(result.assurance.review)
    observed = collector.observe(
        contract,
        observation_id="completed",
        trust="backend_observed",
        enforcement_point="filesystem",
        outcome="completed",
        operation="filesystem.read",
        effects=("filesystem.read",),
    )
    with pytest.raises(ValueError, match="untrusted_source"):
        RuntimeObservation.from_dict(observed.as_dict())
    with pytest.raises(ValueError):
        gate.observe_runtime(observed.as_dict())
    sibling = replace(collector, session_digest="e" * 64)
    injected = sibling.observe(
        contract,
        observation_id="sibling",
        trust="backend_observed",
        enforcement_point="filesystem",
        outcome="completed",
        operation="filesystem.read",
        effects=("filesystem.read",),
    )
    with pytest.raises(ValueError, match="source_mismatch"):
        gate.observe_runtime(injected)
    gate.observe_runtime(observed)


def test_normal_compile_test_review_is_not_unnecessarily_denied(tmp_path):
    profile = approve(selected(tmp_path, config_profile()))
    requirements = RuntimeRequirementProfile(
        "fixture-tests", executable_bindings={"python": "/fixture/bin/python"}, spawn_children=False
    )
    core = Ordin(runtime_requirements=requirements)
    sample = core.review_action(ActionEnvelope.shell("python -m pytest --collect-only"))
    cap = derive_runtime_capability_contract(sample)
    # The fixture's requirements are retained in full; unknown requirements
    # would refuse issuance rather than being deleted from this maximum.
    authority = DelegationAuthority(
        RuntimeCapabilityBoundary(
            "fixture-tests",
            filesystem=cap.filesystem,
            network=cap.network,
            tools=cap.tools,
            process=cap.process,
            privilege=cap.privilege,
        )
    )
    parent = HostEvidenceSource("parent", REPO, "a" * 64, 0, POLICY_HASH, profile.selection_digest)
    source = replace(parent, principal="child", session_digest="d" * 64)
    issuer = DelegationIssuer(parent, profile, authority, authority, clock=lambda: 100)
    root = issuer.authorize_root(authority, grant_id="root", expires_at=200)
    child = issuer.issue_child(root, source, authority, grant_id="child", expires_at=150)
    gate = DelegatingAssuranceGate(AssuranceGate(AgentGate(core), profile), issuer, child, source)
    result = gate.evaluate_action(
        ActionEnvelope.shell("python -m pytest --collect-only", action_id="test")
    )
    expected = AssuranceGate(AgentGate(core), profile).evaluate_action(
        result.assurance.review.action, host_context=source.context()
    )
    assert result.disposition == expected.disposition
    assert not result.denied
