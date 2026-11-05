from dataclasses import replace
import json

import pytest

from ordin.swarm import InMemoryAgentRegistry, SwarmEventIngestor, SwarmEvent, EventRef
from ordin.swarm.causal_graph import SwarmCausalGraph
from ordin.swarm.lineage import SwarmDelegationLink
from tests.assurance.test_delegating_gate import configured


HASH = "f" * 64


def fixture(**budgets):
    now = [100.0]
    registry = InMemoryAgentRegistry("tenant", "swarm", clock=lambda: now[0], registry_id="fixture")
    ingestor = SwarmEventIngestor(registry)
    contexts, sources, channels, adapters = {}, {}, {}, {}
    for name in ("root", "a", "b", "c", "unrelated"):
        adapter = object()
        channel = registry.bind_channel(adapter, runtime_id="fixture")
        context = registry.enroll(
            channel,
            adapter,
            agent_id=name,
            session_id="session-" + name,
            parent_agent_id=None if name == "root" else "root",
        )
        source = ingestor.bind_source(context, channel, adapter, source_id=name)
        contexts[name], sources[name], channels[name], adapters[name] = (
            context,
            source,
            channel,
            adapter,
        )
    graph = SwarmCausalGraph(ingestor, sources["root"], contexts["root"], **budgets)
    return registry, ingestor, contexts, sources, channels, adapters, graph, now


def packet(context, source, event_id, kind, sequence, *, parents=(), resources=(), **options):
    return SwarmEvent(
        event_id,
        kind,
        context.registry_id,
        context.identity,
        source.source_id,
        sequence,
        100,
        evidence_class=options.pop("evidence_class", "host_authenticated"),
        parent_event_ids=tuple(EventRef("tenant", "swarm", parent) for parent in parents),
        resource_digests=resources,
        **options,
    )


def test_authenticated_sibling_handoff_connects_a_b_c_without_joining_unrelated_actions():
    _, ingest, contexts, sources, _, _, graph, _ = fixture()
    for actor, identity, kind, parents in (
        ("a", "send-a", "message_sent", ()),
        ("b", "receive-b", "message_received", ("send-a",)),
        ("b", "artifact-b", "artifact_write", ("receive-b",)),
        ("c", "read-c", "artifact_read", ("artifact-b",)),
        ("unrelated", "unrelated", "artifact_read", ()),
    ):
        sequence = 2 if identity == "artifact-b" else 1
        ingest.ingest(
            sources[actor],
            packet(
                contexts[actor],
                sources[actor],
                identity,
                kind,
                sequence,
                parents=parents,
                resources=(HASH,),
            ),
        )
    view = graph.build()
    assert view.reachable("send-a", "read-c")
    assert not view.reachable("send-a", "unrelated")
    assert {"message_sent/received", "artifact_written/read", "observed_data_flow"} <= {
        edge["kind"] for edge in view.edges
    }
    assert view.as_dict()["successful_exploitation"] == "unknown"
    assert view.as_dict()["execution_authority"] is False
    assert all(node["phase"] == "intended" for node in view.nodes)
    assert "session-a" not in json.dumps(view.as_dict())
    assert "session-a" not in view.mermaid()
    assert view.as_dict() == graph.build().as_dict()


def test_resource_digest_and_timestamp_equality_never_create_a_transfer_edge():
    _, ingest, contexts, sources, _, _, graph, _ = fixture()
    ingest.ingest(
        sources["a"], packet(contexts["a"], sources["a"], "a", "message_sent", 1, resources=(HASH,))
    )
    ingest.ingest(
        sources["b"],
        packet(contexts["b"], sources["b"], "b", "message_received", 1, resources=(HASH,)),
    )
    assert not graph.build().edges


def test_caller_claims_remain_weaker_hypotheses_and_cannot_become_observed_handoffs():
    registry, ingest, contexts, sources, channels, adapters, graph, _ = fixture()
    claims = ingest.bind_source(
        contexts["b"], channels["b"], adapters["b"], source_id="claims", role="asserted"
    )
    ingest.ingest(
        sources["a"], packet(contexts["a"], sources["a"], "a", "message_sent", 1, resources=(HASH,))
    )
    ingest.ingest(
        claims,
        packet(
            contexts["b"],
            claims,
            "b",
            "message_received",
            1,
            parents=("a",),
            resources=(HASH,),
            evidence_class="caller_asserted",
        ),
    )
    view = graph.build()
    assert not view.reachable("a", "b")
    assert view.reachable("a", "b", include_hypotheses=True)
    assert {edge["kind"] for edge in view.edges} == {"hypothesized_influence"}
    assert {edge["evidence_kind"] for edge in view.edges} == {"caller_asserted"}
    assert "caller_asserted_event" in view.proof_gaps


def test_missing_parents_sequence_gaps_and_stale_actor_records_remain_explicit():
    registry, ingest, contexts, sources, _, _, graph, _ = fixture()
    ingest.ingest(
        sources["a"],
        packet(contexts["a"], sources["a"], "a", "message_sent", 2, parents=("missing",)),
    )
    view = graph.build()
    assert {"unresolved_parent", "source_sequence_gap"} <= set(view.proof_gaps)
    actor = contexts["a"]
    registry.pause(actor, ingest._source_ids["a"].channel, ingest._source_ids["a"].adapter)
    view = graph.build()
    assert not view.nodes and "stale_principal_or_grant" in view.proof_gaps


def test_graph_budgets_report_truncation_without_claiming_complete_history():
    _, ingest, contexts, sources, _, _, graph, _ = fixture(max_nodes=2, max_edges=1, event_window=2)
    for i in range(1, 5):
        ingest.ingest(
            sources["a"],
            packet(
                contexts["a"],
                sources["a"],
                f"e{i}",
                "message_sent",
                i,
                parents=() if i == 1 else (f"e{i - 1}",),
            ),
        )
    view = graph.build()
    assert len(view.nodes) <= 2 and len(view.edges) <= 1
    assert view.truncated and "event_window_truncated" in view.proof_gaps


def test_forged_delegation_reference_cannot_create_an_authority_edge():
    _, ingest, contexts, sources, _, _, graph, _ = fixture()
    ingest.ingest(sources["a"], packet(contexts["a"], sources["a"], "delegate", "delegated", 1))
    ingest.ingest(
        sources["b"],
        packet(
            contexts["b"], sources["b"], "receive", "message_received", 1, parents=("delegate",)
        ),
    )
    view = graph.build()
    assert not view.edges and "unauthenticated_cross_agent_join" in view.proof_gaps


def test_current_host_issued_delegation_is_separate_from_data_causality(tmp_path):
    issuer, root, child_source, grant, gate, clock = configured(tmp_path)
    parent_source = issuer.source
    registry = InMemoryAgentRegistry("tenant", "swarm", clock=lambda: 100)
    adapter = object()
    channel = registry.bind_channel(adapter, runtime_id="fixture")
    parent = registry.enroll(
        channel, adapter, agent_id=parent_source.principal, session_id="parent"
    )
    child = registry.enroll(
        channel,
        adapter,
        agent_id=child_source.principal,
        session_id="child",
        parent_agent_id=parent.identity.agent_id,
        delegation_id=grant.record.grant_id,
    )
    ingest = SwarmEventIngestor(registry)
    ps = ingest.bind_source(parent, channel, adapter, source_id="parent")
    cs = ingest.bind_source(child, channel, adapter, source_id="child")
    graph = SwarmCausalGraph(ingest, ps, parent)
    link = SwarmDelegationLink(issuer, grant, parent_source, child_source, parent, child)
    graph.bind_delegation(link)
    ingest.ingest(ps, packet(parent, ps, "delegate", "delegated", 1))
    ingest.ingest(cs, packet(child, cs, "receive", "message_received", 1, parents=("delegate",)))
    view = graph.build()
    assert {edge["kind"] for edge in view.edges} == {"delegated_to"}
    assert not any(edge["kind"] == "observed_data_flow" for edge in view.edges)
    issuer.revoke(root)
    with pytest.raises(ValueError):
        graph.build()


def test_invalid_graph_scope_and_mutated_stored_event_are_rejected():
    _, ingest, contexts, sources, _, _, graph, _ = fixture()
    with pytest.raises(ValueError):
        SwarmCausalGraph(ingest, sources["a"], contexts["b"])
    event = packet(contexts["a"], sources["a"], "a", "message_sent", 1)
    ingest.ingest(sources["a"], event)
    object.__setattr__(event, "confidence", 0.5)
    with pytest.raises(ValueError, match="digest"):
        graph.build()


def test_cross_actor_handoff_edge_budget_is_reported_exactly():
    for limit in (1, 2):
        _, ingest, contexts, sources, _, _, graph, _ = fixture(max_edges=limit)
        ingest.ingest(
            sources["a"],
            packet(contexts["a"], sources["a"], "a", "message_sent", 1, resources=(HASH,)),
        )
        ingest.ingest(
            sources["b"],
            packet(
                contexts["b"],
                sources["b"],
                "b",
                "message_received",
                1,
                parents=("a",),
                resources=(HASH,),
            ),
        )
        view = graph.build()
        assert len(view.edges) == limit
        assert view.truncated is (limit == 1)


def test_out_of_order_projection_is_deterministic_after_authenticated_backfill():
    views = []
    for reversed_order in (False, True):
        _, ingest, contexts, sources, _, _, graph, _ = fixture()
        sent = packet(contexts["a"], sources["a"], "a", "message_sent", 1, resources=(HASH,))
        received = packet(
            contexts["b"],
            sources["b"],
            "b",
            "message_received",
            1,
            parents=("a",),
            resources=(HASH,),
        )
        rows = [(sources["a"], sent), (sources["b"], received)]
        for source, event in reversed(rows) if reversed_order else rows:
            ingest.ingest(source, event)
        views.append(graph.build())
    assert views[0].as_dict()["nodes"] == views[1].as_dict()["nodes"]
    assert views[0].as_dict()["edges"] == views[1].as_dict()["edges"]
    assert views[0].proof_gaps == views[1].proof_gaps


def test_stale_policy_epoch_and_cross_tenant_context_cannot_project_authority():
    registry, ingest, contexts, sources, _, _, graph, _ = fixture()
    ingest.ingest(sources["a"], packet(contexts["a"], sources["a"], "a", "message_sent", 1))
    registry.advance_policy_epoch(1)
    with pytest.raises(ValueError):
        graph.build()
    foreign = InMemoryAgentRegistry("other", "swarm", clock=lambda: 100)
    adapter = object()
    channel = foreign.bind_channel(adapter, runtime_id="fixture")
    context = foreign.enroll(channel, adapter, agent_id="root", session_id="session")
    with pytest.raises(ValueError):
        SwarmCausalGraph(ingest, sources["root"], context)


def test_time_window_uses_each_source_and_never_claims_truncated_history_complete():
    _, ingest, contexts, sources, _, _, graph, _ = fixture(source_time_window=10)
    ingest.ingest(sources["a"], packet(contexts["a"], sources["a"], "old", "message_sent", 1))
    newer = replace(packet(contexts["a"], sources["a"], "new", "message_sent", 2), timestamp=200)
    ingest.ingest(sources["a"], newer)
    view = graph.build()
    assert {node["event_id"] for node in view.nodes} == {"new"}
    assert view.truncated and "source_time_window_truncated" in view.proof_gaps
