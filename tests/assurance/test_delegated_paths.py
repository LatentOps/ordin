"""Current parent-child authority and byte provenance keep graph sessions distinct."""

from dataclasses import replace

import pytest

from ordin.assurance import (
    AssuranceGate,
    DelegatingAssuranceGate,
    ReviewedAction,
    build_delegated_attack_path,
    register_instruction_origin,
    correlate_source_use,
)

from .test_delegating_gate import configured, action


def inputs(tmp_path, *, child_path="/fixture/source"):
    issuer, root, child_source, grant, child_gate, clock = configured(tmp_path)
    parent_source = issuer.source
    parent_context = parent_source.context()
    parent_decision = child_gate.assurance.evaluate_action(
        action("parent-read"), host_context=parent_context
    )
    parent_rows = (ReviewedAction(parent_decision, parent_context),)
    child_decision = child_gate.evaluate_action(action("child-read", child_path))
    return (
        issuer,
        root,
        parent_source,
        child_source,
        grant,
        child_gate,
        clock,
        parent_rows,
        (child_decision,),
    )


def test_current_delegation_has_explicit_edge_and_distinct_scoped_nodes(tmp_path):
    issuer, root, parent, child, grant, gate, clock, parent_rows, child_rows = inputs(tmp_path)
    graph = build_delegated_attack_path(issuer, grant, parent, child, parent_rows, child_rows)
    assert len([n for n in graph.nodes if n.kind == "principal"]) == 2
    assert len([n for n in graph.nodes if n.kind == "action"]) == 2
    edge = next(e for e in graph.edges if e.kind == "delegated_to")
    assert edge.evidence.origin == "policy_verified"
    assert graph.session_digests == (parent.session_digest, child.session_digest)
    assert any("only by delegation" in gap for gap in graph.proof_gaps)


def test_child_denial_is_retained_as_counterevidence(tmp_path):
    issuer, root, parent, child, grant, gate, clock, parent_rows, child_rows = inputs(
        tmp_path, child_path="/fixture/.env"
    )
    assert child_rows[0].denied
    graph = build_delegated_attack_path(issuer, grant, parent, child, parent_rows, child_rows)
    assert graph.reachability == "blocked" and graph.permissions == "exceeds_boundary"
    assert any(n.category == "delegation_denied" for n in graph.nodes)


def test_sibling_forged_parent_and_revoked_relationship_are_rejected(tmp_path):
    issuer, root, parent, child, grant, gate, clock, parent_rows, child_rows = inputs(tmp_path)
    with pytest.raises(ValueError, match="scope changed|identity"):
        build_delegated_attack_path(
            issuer, grant, parent, replace(child, principal="sibling"), parent_rows, child_rows
        )
    with pytest.raises(ValueError, match="current parent"):
        build_delegated_attack_path(
            issuer, grant, replace(parent, principal="forged"), child, parent_rows, child_rows
        )
    with pytest.raises(ValueError, match="sealed delegated"):
        build_delegated_attack_path(
            issuer,
            grant,
            parent,
            child,
            parent_rows,
            (ReviewedAction(child_rows[0].assurance, child_rows[0]._context),),
        )
    issuer.revoke(root)
    with pytest.raises(ValueError, match="expired/revoked"):
        build_delegated_attack_path(issuer, grant, parent, child, parent_rows, child_rows)


def test_cross_action_source_lineage_requires_retained_parent_and_exact_child_bytes(tmp_path):
    issuer, root, parent, child, grant, gate, clock, parent_rows, child_rows = inputs(tmp_path)
    text = "/fixture/source"
    origin = register_instruction_origin(
        child,
        origin_id="parent-result",
        kind="mcp_result",
        classification="public",
        content=text,
        parent_action_digest=parent_rows[0].decision.action_digest,
    )
    use = correlate_source_use(
        child,
        origin,
        child_rows[0].assurance.review.action,
        use_id="use",
        argument_path=("parameters", "arguments", "path"),
    )
    graph = build_delegated_attack_path(
        issuer,
        grant,
        parent,
        child,
        parent_rows,
        child_rows,
        child_origins=(origin,),
        child_source_uses=(use,),
    )
    assert any(
        e.kind == "correlates_to" and e.evidence.origin == "host_authenticated_source"
        for e in graph.edges
    )
    bad = register_instruction_origin(
        child,
        origin_id="foreign",
        kind="mcp_result",
        classification="public",
        content=text,
        parent_action_digest="0" * 64,
    )
    with pytest.raises(ValueError, match="foreign parent"):
        build_delegated_attack_path(
            issuer, grant, parent, child, parent_rows, child_rows, child_origins=(bad,)
        )
