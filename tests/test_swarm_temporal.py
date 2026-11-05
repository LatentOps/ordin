"""Causal cross-agent temporal policies use protected facts and exact current bytes."""

from dataclasses import replace
import json

import pytest

from ordin import ActionEnvelope, AgentGate, Ordin
from ordin.assurance import register_instruction_origin
from ordin.swarm import LineageUse, SwarmAssessmentSource, SwarmGate, SwarmPolicy, Sensitivity
from ordin.swarm.temporal import (
    SwarmTemporalEngine,
    SwarmTemporalPolicySet,
    SwarmTemporalPredicate as P,
    SwarmTemporalRule as R,
    default_swarm_temporal_policy,
    load_swarm_temporal_policy,
)
from tests.test_swarm_source_flow import configured, root, relay, upload, SECRET, PATH


def secret_policy(**options):
    return SwarmTemporalPolicySet(
        "fixture",
        1,
        (
            R(
                "relay",
                "critical",
                (
                    P(labels_any=("secret",), event_kinds=("artifact_read",)),
                    P(
                        event_kinds=("message_received",),
                        agent_relation="different",
                        transfer_edges=("message_sent/received",),
                    ),
                    P(
                        effects_any=("network.upload",),
                        labels_any=("secret",),
                        requires_lineage=True,
                        evidence_classes=("current_proposal",),
                    ),
                ),
                scope="swarm",
                **options,
            ),
        ),
    )


def captured(*, policy=None, public=False, ordin=None, **quotas):
    flow, operator, hosts, event, data = configured()
    _, ingest, contexts, sources, _, _, graph, now = data
    text = "Public report" if public else SECRET
    handle = root(
        flow,
        hosts,
        event,
        sources,
        labels=("public",) if public else ("secret",),
        classification="public" if public else "sensitive",
    )
    received = relay(flow, event, sources, handle, text)
    engine = SwarmTemporalEngine(
        graph, policy or secret_policy(), flow=flow, clock=lambda: now[0], ordin=ordin, **quotas
    )
    origin = register_instruction_origin(
        hosts["a"],
        origin_id="actual-source",
        kind="repository_file",
        classification="public" if public else "sensitive",
        content=SECRET,
    )
    by_event = {}
    for lineage, row in flow._records.items():
        by_event.setdefault(row.event_id, []).append(lineage)
    for row in ingest.snapshot():
        actor = row.event.identity.agent_id
        engine.record_event(
            sources[actor],
            row.event.event_id,
            lineage=tuple(by_event.get(row.event.event_id, ())),
            origins=(origin,) if row.event.event_id == "read" else (),
            observed_at=100,
        )
    return engine, flow, received, text, operator, hosts, event, data


def test_authenticated_a_b_c_sensitive_upload_matches_and_blocks_gate():
    engine, _, handle, text, _, _, _, data = captured()
    registry, ingest, contexts, sources, channels, adapters, _, now = data
    action = upload(text)
    result = engine.evaluate(
        contexts["c"],
        sources["c"],
        action,
        parent_event_ids=("receive-c",),
        uses=(LineageUse(handle, PATH),),
    )
    assert result.status == "violated" and len(result.findings) == 1
    assert result.findings[0].rule_id == "relay"
    assert {"read", "receive-b", "receive-c"} <= set(result.findings[0].path_event_ids)
    assert result.findings[0].current_action_digest == result.action_digest
    assert SECRET not in json.dumps(result.as_dict())
    authority = SwarmAssessmentSource("temporal", clock=lambda: now[0])
    gate = SwarmGate(
        registry,
        policy=SwarmPolicy("temporal", "1", required_checks=("temporal",)),
        assessment_source=authority,
        events=ingest,
    )
    receipt = engine.issue_assessment(
        contexts["c"],
        sources["c"],
        action,
        authority=authority,
        policy_digest=gate.policy_digest,
        snapshot_digest=gate.evidence_snapshot_digest(contexts["c"], event_source=sources["c"]),
        parent_event_ids=("receive-c",),
        uses=(LineageUse(handle, PATH),),
    )
    decision = gate.evaluate_action(
        contexts["c"],
        action,
        channel=channels["c"],
        adapter=adapters["c"],
        event_source=sources["c"],
        assessments=(receipt,),
    )
    assert decision.denied


def test_public_output_does_not_become_exfiltration_merely_from_secret_ancestor():
    engine, flow, handle, _, _, hosts, event, data = captured()
    # Explicit operator-controlled release produces a fresh public handle. Its
    # exact bytes remain correlated, without laundering labels through JSON.
    released = flow.declassify(
        handle,
        operator=flow._operator,
        policy_epoch=0,
        sensitivity=Sensitivity(("public",)),
        reason_code="operator.reviewed",
    )
    result = engine.evaluate(
        data[2]["c"],
        data[3]["c"],
        upload(SECRET),
        parent_event_ids=("receive-c",),
        uses=(LineageUse(released, PATH),),
    )
    assert result.status == "satisfied" and not result.findings
    with pytest.raises(ValueError, match="exact proposed"):
        engine.evaluate(
            data[2]["c"],
            data[3]["c"],
            upload("unrelated public data"),
            parent_event_ids=("receive-c",),
            uses=(LineageUse(handle, PATH),),
        )


def test_unrelated_current_parent_or_missing_byte_correlation_never_matches():
    engine, _, handle, _, _, _, _, data = captured()
    result = engine.evaluate(
        data[2]["c"],
        data[3]["c"],
        upload(SECRET),
        parent_event_ids=(),
        uses=(LineageUse(handle, PATH),),
    )
    assert result.status == "unknown" and not result.findings
    assert "current_source_use_not_causal" in result.proof_gaps
    result = engine.evaluate(
        data[2]["c"], data[3]["c"], upload(SECRET), parent_event_ids=("receive-c",)
    )
    assert result.status == "unknown" and "current_lineage_unavailable" in result.proof_gaps
    # A pointer to another principal is not a protected receive/handoff.
    result = engine.evaluate(
        data[2]["c"],
        data[3]["c"],
        upload(SECRET),
        parent_event_ids=("read",),
        uses=(LineageUse(handle, PATH),),
    )
    assert result.status == "unknown" and not result.findings


def test_complete_bounded_window_and_expiry_have_deterministic_meaning():
    engine, _, handle, _, _, _, _, data = captured(policy=secret_policy(within_seconds=10))
    now = data[7]
    # Capture time is the protected coordinator clock. Event JSON timestamps
    # cannot keep old evidence alive after this window.
    now[0] = 111
    for source in data[3].values():
        engine.cover(source, complete_from=100)
    result = engine.evaluate(
        data[2]["c"],
        data[3]["c"],
        upload(SECRET),
        parent_event_ids=("receive-c",),
        uses=(LineageUse(handle, PATH),),
    )
    assert result.status == "satisfied" and not result.findings
    fresh, *_ = captured(policy=secret_policy(within_seconds=10))
    with pytest.raises(ValueError, match="pre-attach"):
        fresh.cover(fresh._graph._source, complete_from=99)


def test_policy_parser_default_bundle_and_closed_schema(tmp_path):
    policy = default_swarm_temporal_policy()
    assert len(policy.policy.rules) == 7
    assert {rule.rule_id for rule in policy.policy.rules} >= {
        "sensitive_relay_upload",
        "delegation_fanout",
        "coordinated_api_misuse",
    }
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy.policy.as_dict()))
    assert load_swarm_temporal_policy(path).policy == policy.policy
    payload = policy.policy.as_dict()
    payload["rules"][0]["callback"] = "eval"
    with pytest.raises(ValueError):
        SwarmTemporalPolicySet.from_dict(payload)
    payload = policy.policy.as_dict()
    payload["rules"][0]["pattern"][-1]["evidence_classes"] = ["backend_observed"]
    with pytest.raises(ValueError, match="current proposal"):
        SwarmTemporalPolicySet.from_dict(payload)


def test_shuffled_authenticated_ingest_has_identical_causal_findings():
    original, _, _, _, _, _, _, original_data = captured()
    findings = []
    for reverse in (False, True):
        flow, _, hosts, _, data = configured()
        _, ingest, contexts, sources, _, _, graph, now = data
        rows = [row.event for row in original_data[1].snapshot()]
        for event in reversed(rows) if reverse else rows:
            ingest.ingest(sources[event.identity.agent_id], event)
        origin = register_instruction_origin(
            hosts["a"],
            origin_id="root",
            kind="repository_file",
            classification="sensitive",
            content=SECRET,
        )
        initial = flow.register(
            sources["a"], event_id="read", origin=origin, sensitivity=Sensitivity(("secret",))
        )
        received = flow.derive(
            sources["b"], event_id="receive-b", content=SECRET, parents=(initial,), complete=True
        )
        transformed = flow.derive(
            sources["b"], event_id="transform-b", content=SECRET, parents=(received,), complete=True
        )
        final = flow.derive(
            sources["c"],
            event_id="receive-c",
            content=SECRET,
            parents=(transformed,),
            complete=True,
        )
        engine = SwarmTemporalEngine(graph, secret_policy(), flow=flow, clock=lambda: now[0])
        by_event = {}
        for handle, row in flow._records.items():
            by_event.setdefault(row.event_id, []).append(handle)
        for event in rows:
            engine.record_event(
                sources[event.identity.agent_id],
                event.event_id,
                lineage=tuple(by_event.get(event.event_id, ())),
                observed_at=100,
            )
        result = engine.evaluate(
            contexts["c"],
            sources["c"],
            upload(SECRET),
            parent_event_ids=("receive-c",),
            uses=(LineageUse(final, PATH),),
        )
        assert result.status == "violated"
        findings.append([value.as_dict() for value in result.findings])
    assert findings[0] == findings[1]


def test_poisoning_requires_actual_current_code_bytes_and_preserves_core_denial():
    from ordin.tool_calls import ToolSemanticRule, ToolSemanticsRegistry

    semantics = ToolSemanticsRegistry(
        "fixture",
        "1",
        (ToolSemanticRule("run", "tool", "run_code", ("code.execute",), runtime="fixture"),),
    )
    policy = default_swarm_temporal_policy().policy
    poison = SwarmTemporalPolicySet(
        "poison",
        1,
        tuple(rule for rule in policy.rules if rule.rule_id == "untrusted_artifact_execution"),
    )
    engine, _, handle, _, _, _, _, data = captured(
        policy=poison, ordin=Ordin(tool_semantics=semantics)
    )
    action = ActionEnvelope(
        "tool",
        "call",
        {"runtime": "fixture", "tool": "run_code", "arguments": {"code": SECRET}},
        action_id="execute",
    )
    result = engine.evaluate(
        data[2]["c"],
        data[3]["c"],
        action,
        parent_event_ids=("receive-c",),
        uses=(LineageUse(handle, ("parameters", "arguments", "code")),),
    )
    assert (
        result.status == "violated" and result.findings[0].rule_id == "untrusted_artifact_execution"
    )
    unbound = engine.evaluate(
        data[2]["c"],
        data[3]["c"],
        ActionEnvelope.shell("python /fixture/opaque.py"),
        parent_event_ids=("receive-c",),
    )
    assert unbound.status == "unknown" and not unbound.findings
    # A temporal no-match is not permission to weaken a stronger baseline.
    baseline = AgentGate(Ordin()).evaluate_action(ActionEnvelope.shell("rm -rf /"))
    assert baseline.denied


def action_fixture(policy, *, tasks=None, **engine_options):
    from ordin.swarm import (
        InMemoryAgentRegistry,
        SwarmEventIngestor,
        SwarmCausalGraph,
        SwarmEvent,
        EventRef,
    )
    from ordin._runtime_json import digest

    now = [100.0]
    registry = InMemoryAgentRegistry(
        "tenant", "swarm", clock=lambda: now[0], registry_id="fixture", heartbeat_timeout=1000
    )
    ingest = SwarmEventIngestor(registry)
    contexts, sources, channels, adapters = {}, {}, {}, {}
    for name in ("root", "a", "b", "c"):
        adapter = object()
        channel = registry.bind_channel(adapter, runtime_id="fixture")
        context = registry.enroll(
            channel,
            adapter,
            agent_id=name,
            session_id=name,
            task_id=(tasks or {}).get(name, "task"),
            parent_agent_id=None if name == "root" else "root",
        )
        contexts[name], channels[name], adapters[name] = context, channel, adapter
        sources[name] = ingest.bind_source(context, channel, adapter, source_id=name)
    graph = SwarmCausalGraph(ingest, sources["root"], contexts["root"])
    engine = SwarmTemporalEngine(graph, policy, clock=lambda: now[0], **engine_options)
    sequences = {name: 0 for name in contexts}

    def emit(actor, event_id, kind, *, action=None, parents=(), review=None, resources=(), at=100):
        sequences[actor] += 1
        event = SwarmEvent(
            event_id,
            kind,
            contexts[actor].registry_id,
            contexts[actor].identity,
            sources[actor].source_id,
            sequences[actor],
            999999999999,
            evidence_class="host_authenticated",
            action_id=action.action_id if action else None,
            action_digest=digest(action.as_dict()) if action else None,
            parent_event_ids=tuple(EventRef("tenant", "swarm", value) for value in parents),
            review_event_id=review,
            resource_digests=resources,
        )
        ingest.ingest(sources[actor], event)
        engine.record_event(sources[actor], event_id, action=action, observed_at=at)
        return event

    return engine, emit, (registry, ingest, contexts, sources, channels, adapters, graph, now)


def retry_policy(**changes):
    values = dict(scope="swarm", aggregation="causal_ancestors", quota=2, count_by="actions")
    values.update(changes)
    return SwarmTemporalPolicySet(
        "retry",
        1,
        (
            R(
                "retry",
                "critical",
                (
                    P(
                        effects_any=("filesystem.delete",),
                        event_kinds=("failed",),
                        agent_relation="sibling",
                    ),
                    P(effects_any=("filesystem.delete",), evidence_classes=("current_proposal",)),
                ),
                **values,
            ),
        ),
    )


def retry_workflow(*, include_b=True, duplicate_a=False, policy=None):
    engine, emit, data = action_fixture(policy or retry_policy())
    resources = ("f" * 64,)
    for actor in ("a", "b"):
        action = ActionEnvelope.shell("rm -f /fixture/" + actor, action_id="attempt-" + actor)
        emit(actor, actor + "-review", "reviewed", action=action)
        emit(
            actor,
            actor + "-failed",
            "failed",
            action=action,
            parents=(actor + "-review",),
            review=actor + "-review",
        )
        if actor == "a" and duplicate_a:
            emit(
                actor,
                "a-failed-again",
                "failed",
                action=action,
                parents=("a-review", "a-failed"),
                review="a-review",
            )
        if actor == "a" or include_b:
            emit(
                actor,
                actor + "-send",
                "message_sent",
                parents=(actor + "-failed",),
                resources=resources,
            )
            emit(
                "c",
                actor + "-receive",
                "message_received",
                parents=(actor + "-send",) + (("a-receive",) if actor == "b" else ()),
                resources=resources,
            )
    return engine, data


def test_destructive_sibling_retries_count_only_causally_joined_distinct_actions():
    action = ActionEnvelope.shell("rm -f /fixture/c", action_id="attempt-c")
    engine, data = retry_workflow()
    result = engine.evaluate(data[2]["c"], data[3]["c"], action, parent_event_ids=("b-receive",))
    assert result.status == "violated"
    assert {item["event_id"] for item in result.findings[0].evidence} == {"a-failed", "b-failed"}
    engine, data = retry_workflow(include_b=False, duplicate_a=True)
    data[7][0] = 400
    for source in data[3].values():
        engine.cover(source, complete_from=100)
    result = engine.evaluate(data[2]["c"], data[3]["c"], action, parent_event_ids=("a-receive",))
    assert not result.findings and result.status == "satisfied"


def test_task_partition_privilege_path_and_recovery_loop():
    from ordin.tool_calls import ToolSemanticRule, ToolSemanticsRegistry

    semantics = ToolSemanticsRegistry(
        "fixture",
        "1",
        (
            ToolSemanticRule(
                "elevate", "tool", "elevate", ("privilege.escalate",), runtime="fixture"
            ),
        ),
    )
    elevate = ActionEnvelope(
        "tool",
        "call",
        {"runtime": "fixture", "tool": "elevate", "arguments": {}},
        action_id="elevate",
    )
    privilege = SwarmTemporalPolicySet(
        "privilege",
        1,
        (
            R(
                "privilege",
                "high",
                (
                    P(effects_any=("filesystem.permission_change",)),
                    P(effects_any=("privilege.escalate",), evidence_classes=("current_proposal",)),
                ),
            ),
        ),
    )
    engine, emit, data = action_fixture(privilege, ordin=Ordin(tool_semantics=semantics))
    chmod = ActionEnvelope.shell("chmod 777 /fixture/file", action_id="chmod")
    emit("c", "chmod", "reviewed", action=chmod)
    result = engine.evaluate(data[2]["c"], data[3]["c"], elevate, parent_event_ids=("chmod",))
    assert result.status == "violated"
    engine, emit, data = action_fixture(
        privilege, tasks={"a": "other"}, ordin=Ordin(tool_semantics=semantics)
    )
    emit("a", "chmod", "reviewed", action=chmod)
    emit("a", "send", "message_sent", parents=("chmod",), resources=("f" * 64,))
    emit("c", "receive", "message_received", parents=("send",), resources=("f" * 64,))
    data[7][0] = 400
    for source in data[3].values():
        engine.cover(source, complete_from=100)
    result = engine.evaluate(data[2]["c"], data[3]["c"], elevate, parent_event_ids=("receive",))
    assert result.status == "satisfied" and not result.findings


@pytest.mark.parametrize("outcome", ["allowed", "denied", "completed"])
def test_late_backend_observation_never_promotes_intention_to_completed_effect(outcome):
    from ordin import derive_runtime_capability_contract
    from ordin.runtime_observation import RuntimeEvidenceSource
    from ordin.swarm import SwarmEvent, EventRef
    from ordin.tool_calls import ToolSemanticRule, ToolSemanticsRegistry

    policy = SwarmTemporalPolicySet(
        "observed",
        1,
        (
            R(
                "observed",
                "high",
                (
                    P(
                        effects_any=("filesystem.read",),
                        effect_evidence="observed",
                        evidence_classes=("backend_observed",),
                    ),
                    P(effects_any=("code.execute",), evidence_classes=("current_proposal",)),
                ),
                scope="swarm",
            ),
        ),
    )
    semantics = ToolSemanticsRegistry(
        "fixture",
        "1",
        (ToolSemanticRule("run", "tool", "run_code", ("code.execute",), runtime="fixture"),),
    )
    engine, emit, data = action_fixture(policy, ordin=Ordin(tool_semantics=semantics))
    _, ingest, contexts, sources, channels, adapters, _, _ = data
    read = ActionEnvelope.shell("cat /fixture/file", action_id="read")
    reviewed = emit("c", "review", "reviewed", action=read)
    current = ActionEnvelope(
        "tool",
        "call",
        {"runtime": "fixture", "tool": "run_code", "arguments": {}},
        action_id="execute",
    )
    before = engine.evaluate(contexts["c"], sources["c"], current, parent_event_ids=("review",))
    assert before.status == "unknown" and not before.findings
    runtime = RuntimeEvidenceSource("fixture", "a" * 64, "sandbox", "b" * 64)
    collector = ingest.bind_source(
        contexts["c"],
        channels["c"],
        adapters["c"],
        source_id="collector",
        role="collector",
        collector=runtime,
    )
    contract = derive_runtime_capability_contract(Ordin().review_action(read))
    observation = runtime.observe(
        contract,
        observation_id="observation",
        trust="backend_observed",
        enforcement_point="filesystem",
        outcome=outcome,
        operation="read",
        effects=("filesystem.read",),
    )
    observed = SwarmEvent(
        "observation",
        "observed",
        contexts["c"].registry_id,
        contexts["c"].identity,
        "collector",
        1,
        9999999,
        evidence_class="backend_observed",
        action_id=read.action_id,
        action_digest=reviewed.action_digest,
        review_event_id="review",
        parent_event_ids=(EventRef("tenant", "swarm", "review"),),
        observation_digest=observation.digest,
        observed_outcome=outcome,
    )
    ingest.ingest(collector, observed, observation=observation)
    engine.record_event(
        collector, "observation", action=read, observation=observation, observed_at=100
    )
    after = engine.evaluate(contexts["c"], sources["c"], current, parent_event_ids=("observation",))
    assert bool(after.findings) is (outcome == "completed")
    if after.findings:
        assert after.findings[0].evidence[0]["effect_evidence"] == "observed"


def test_real_delegation_fanout_counts_original_current_grants_not_json(tmp_path):
    from tests.assurance.test_delegation import issuer_fixture, child_max
    from ordin.swarm import (
        InMemoryAgentRegistry,
        SwarmEventIngestor,
        SwarmCausalGraph,
        SwarmEvent,
        EventRef,
    )
    from ordin.swarm.lineage import SwarmDelegationLink
    from tests.assurance.test_invariants import SEMANTICS

    issuer, root_grant, parent_host, template, clock = issuer_fixture(tmp_path)
    registry = InMemoryAgentRegistry("tenant", "swarm", clock=lambda: clock[0])
    adapter = object()
    channel = registry.bind_channel(adapter, runtime_id="fixture")
    parent = registry.enroll(
        channel, adapter, agent_id="parent", session_id="parent", task_id="task"
    )
    ingest = SwarmEventIngestor(registry)
    sender = ingest.bind_source(parent, channel, adapter, source_id="parent")
    graph = SwarmCausalGraph(ingest, sender, parent)
    fanout = next(
        rule
        for rule in default_swarm_temporal_policy().policy.rules
        if rule.rule_id == "delegation_fanout"
    )
    engine = SwarmTemporalEngine(
        graph,
        SwarmTemporalPolicySet("fanout", 1, (fanout,)),
        ordin=Ordin(tool_semantics=SEMANTICS),
        clock=lambda: clock[0],
    )
    last_ack = None
    sequence = 0
    for index in range(3):
        child_host = replace(
            template, principal="child-" + str(index), session_digest=str(index + 2) * 64
        )
        grant = issuer.issue_child(
            root_grant, child_host, child_max(), grant_id="grant-" + str(index), expires_at=150
        )
        child = registry.enroll(
            channel,
            adapter,
            agent_id=child_host.principal,
            session_id="child-" + str(index),
            task_id="task",
            parent_agent_id="parent",
            delegation_id=grant.record.grant_id,
        )
        source = ingest.bind_source(child, channel, adapter, source_id=child_host.principal)
        graph.bind_delegation(
            SwarmDelegationLink(issuer, grant, parent_host, child_host, parent, child)
        )
        sequence += 1
        delegation = SwarmEvent(
            "delegate-" + str(index),
            "delegated",
            parent.registry_id,
            parent.identity,
            "parent",
            sequence,
            9999999,
            evidence_class="host_authenticated",
            parent_event_ids=() if last_ack is None else (EventRef("tenant", "swarm", last_ack),),
        )
        ingest.ingest(sender, delegation)
        engine.record_event(sender, delegation.event_id, observed_at=100)
        received = SwarmEvent(
            "child-receive-" + str(index),
            "message_received",
            child.registry_id,
            child.identity,
            source.source_id,
            1,
            9999999,
            evidence_class="host_authenticated",
            parent_event_ids=(EventRef("tenant", "swarm", delegation.event_id),),
        )
        ingest.ingest(source, received)
        engine.record_event(source, received.event_id, observed_at=100)
        sent = SwarmEvent(
            "child-send-" + str(index),
            "message_sent",
            child.registry_id,
            child.identity,
            source.source_id,
            2,
            9999999,
            evidence_class="host_authenticated",
            parent_event_ids=(EventRef("tenant", "swarm", received.event_id),),
            resource_digests=("f" * 64,),
        )
        ingest.ingest(source, sent)
        engine.record_event(source, sent.event_id, observed_at=100)
        sequence += 1
        ack = SwarmEvent(
            "parent-ack-" + str(index),
            "message_received",
            parent.registry_id,
            parent.identity,
            "parent",
            sequence,
            9999999,
            evidence_class="host_authenticated",
            parent_event_ids=(EventRef("tenant", "swarm", sent.event_id),),
            resource_digests=("f" * 64,),
        )
        ingest.ingest(sender, ack)
        engine.record_event(sender, ack.event_id, observed_at=100)
        last_ack = ack.event_id
    current = ActionEnvelope(
        "tool",
        "call",
        {"runtime": "fixture", "tool": "read_file", "arguments": {"path": "/fixture/source"}},
        action_id="read",
    )
    result = engine.evaluate(parent, sender, current, parent_event_ids=(last_ack,))
    assert result.status == "violated" and len(result.findings[0].evidence) == 3
    issuer.revoke(root_grant)
    with pytest.raises(ValueError):
        engine.evaluate(parent, sender, current, parent_event_ids=(last_ack,))


def test_coordinated_api_quota_requires_protected_same_sink_and_causal_join():
    from ordin._runtime_json import digest
    from ordin.swarm import SwarmEvent, EventRef

    flow, _, _, _, data = configured()
    policy = next(
        rule
        for rule in default_swarm_temporal_policy().policy.rules
        if rule.rule_id == "coordinated_api_misuse"
    )
    engine = SwarmTemporalEngine(
        data[6], SwarmTemporalPolicySet("api", 1, (policy,)), flow=flow, clock=lambda: data[7][0]
    )
    for index, actor in enumerate(("a", "b")):
        action = upload("public", identity="request-" + actor)
        reviewed = SwarmEvent(
            "review-" + actor,
            "reviewed",
            data[2][actor].registry_id,
            data[2][actor].identity,
            actor,
            1,
            9999999,
            evidence_class="host_authenticated",
            action_id=action.action_id,
            action_digest=digest(action.as_dict()),
        )
        data[1].ingest(data[3][actor], reviewed)
        engine.record_event(data[3][actor], reviewed.event_id, action=action, observed_at=100)
        sent = SwarmEvent(
            "send-" + actor,
            "message_sent",
            data[2][actor].registry_id,
            data[2][actor].identity,
            actor,
            2,
            9999999,
            evidence_class="host_authenticated",
            parent_event_ids=(EventRef("tenant", "swarm", reviewed.event_id),),
            resource_digests=("f" * 64,),
        )
        data[1].ingest(data[3][actor], sent)
        engine.record_event(data[3][actor], sent.event_id, observed_at=100)
        received = SwarmEvent(
            "receive-" + actor,
            "message_received",
            data[2]["c"].registry_id,
            data[2]["c"].identity,
            "c",
            index + 1,
            9999999,
            evidence_class="host_authenticated",
            parent_event_ids=(EventRef("tenant", "swarm", sent.event_id),)
            + ((EventRef("tenant", "swarm", "receive-a"),) if index else ()),
            resource_digests=("f" * 64,),
        )
        data[1].ingest(data[3]["c"], received)
        engine.record_event(data[3]["c"], received.event_id, observed_at=100)
    result = engine.evaluate(
        data[2]["c"],
        data[3]["c"],
        upload("public", identity="third"),
        parent_event_ids=("receive-b",),
    )
    assert result.status == "violated" and len(result.findings[0].evidence) == 2
    different = engine.evaluate(
        data[2]["c"],
        data[3]["c"],
        upload("public", destination="https://other.invalid/rpc"),
        parent_event_ids=("receive-b",),
    )
    assert different.status == "unknown" and not different.findings
    assert "protected_sink_identity_unavailable" in different.proof_gaps


def test_recovery_loop_uses_failed_attempts_and_current_exact_proposal():
    from ordin.tool_calls import ToolSemanticRule, ToolSemanticsRegistry

    rule = next(
        rule
        for rule in default_swarm_temporal_policy().policy.rules
        if rule.rule_id == "recovery_retry_loop"
    )
    semantics = ToolSemanticsRegistry(
        "fixture",
        "1",
        (ToolSemanticRule("run", "tool", "run", ("code.execute",), runtime="fixture"),),
    )
    engine, emit, data = action_fixture(
        SwarmTemporalPolicySet("recovery", 1, (rule,)), ordin=Ordin(tool_semantics=semantics)
    )
    previous = ()
    for index in range(3):
        action = ActionEnvelope(
            "tool",
            "call",
            {"runtime": "fixture", "tool": "run", "arguments": {}},
            action_id="run-" + str(index),
        )
        reviewed = "review-" + str(index)
        emit("c", reviewed, "reviewed", action=action, parents=previous)
        failed = "failed-" + str(index)
        emit("c", failed, "failed", action=action, parents=(reviewed,), review=reviewed)
        previous = (failed,)
    current = replace(action, action_id="next")
    result = engine.evaluate(data[2]["c"], data[3]["c"], current, parent_event_ids=previous)
    assert result.status == "violated" and len(result.findings[0].evidence) == 3


def test_machine_fact_and_policy_bounds_return_unknown_without_silent_allow():
    engine, _, handle, _, _, _, _, data = captured(max_transitions=1)
    result = engine.evaluate(
        data[2]["c"],
        data[3]["c"],
        upload(SECRET),
        parent_event_ids=("receive-c",),
        uses=(LineageUse(handle, PATH),),
    )
    assert result.status == "unknown" and "temporal_machine_quota_exhausted" in result.proof_gaps
    with pytest.raises(ValueError, match="capacity"):
        captured(max_facts=2)
    with pytest.raises(ValueError):
        SwarmTemporalPolicySet("too-many", 1, secret_policy().rules * 65)
    with pytest.raises(ValueError):
        replace(secret_policy().rules[0], within_events=129)


def test_policy_upgrade_and_label_change_fence_old_assessments_without_events():
    from ordin._runtime_json import digest

    engine, flow, handle, _, operator, _, _, data = captured(
        policy=secret_policy(within_seconds=10)
    )
    data[7][0] = 111
    for source in data[3].values():
        engine.cover(source, complete_from=100)
    authority = SwarmAssessmentSource("temporal", clock=lambda: data[7][0])
    action = upload(SECRET)
    bindings = dict(
        action_digest=digest(action.as_dict()),
        context_digest=digest(data[2]["c"].as_dict()),
        policy_digest="a" * 64,
        snapshot_digest="b" * 64,
    )
    receipt = engine.issue_assessment(
        data[2]["c"],
        data[3]["c"],
        action,
        authority=authority,
        policy_digest=bindings["policy_digest"],
        snapshot_digest=bindings["snapshot_digest"],
        parent_event_ids=("receive-c",),
        uses=(LineageUse(handle, PATH),),
    )
    assert receipt.status == "satisfied" and authority.verify(receipt, **bindings)
    engine.upgrade_policy(replace(engine._policy.policy, revision=2))
    assert not authority.verify(receipt, **bindings)
    result = engine.evaluate(
        data[2]["c"],
        data[3]["c"],
        action,
        parent_event_ids=("receive-c",),
        uses=(LineageUse(handle, PATH),),
    )
    assert (
        result.status == "unknown" and "complete_temporal_window_unavailable" in result.proof_gaps
    )
    public = flow.declassify(
        handle,
        operator=operator,
        policy_epoch=0,
        sensitivity=Sensitivity(("public",)),
        reason_code="operator.release",
    )
    receipt = engine.issue_assessment(
        data[2]["c"],
        data[3]["c"],
        action,
        authority=authority,
        policy_digest=bindings["policy_digest"],
        snapshot_digest=bindings["snapshot_digest"],
        parent_event_ids=("receive-c",),
        uses=(LineageUse(public, PATH),),
    )
    assert receipt.status == "satisfied" and authority.verify(receipt, **bindings)
    flow.declassify(
        public,
        operator=operator,
        policy_epoch=0,
        sensitivity=Sensitivity(("secret",)),
        reason_code="operator.reclassify",
    )
    assert not authority.verify(receipt, **bindings)


def test_restart_missing_edges_unknown_times_and_mutated_facts_fail_closed():
    engine, _, handle, _, _, _, _, data = captured()
    missing = engine.evaluate(
        data[2]["c"],
        data[3]["c"],
        upload(SECRET),
        parent_event_ids=("missing",),
        uses=(LineageUse(handle, PATH),),
    )
    assert missing.status == "unknown" and not missing.findings
    old = data[2]["b"]
    channel = data[0].bind_channel(data[5]["b"], runtime_id="fixture")
    data[0].restart(
        old,
        data[4]["b"],
        data[5]["b"],
        new_channel=channel,
        new_adapter=data[5]["b"],
        session_id="new-b",
    )
    # Historical provenance with an unavailable original sender cannot be minted
    # into a fresh conclusive sequence after restart.
    restarted = engine.evaluate(
        data[2]["c"],
        data[3]["c"],
        upload(SECRET),
        parent_event_ids=("receive-c",),
        uses=(LineageUse(handle, PATH),),
    )
    assert restarted.status == "unknown" and not restarted.findings
    assert "stale_principal_or_grant" in restarted.proof_gaps


def test_host_capture_time_ignores_agent_event_timestamp_and_unknown_semantics():
    from ordin.tool_calls import ToolSemanticRule, ToolSemanticsRegistry

    semantics = ToolSemanticsRegistry(
        "fixture",
        "1",
        (
            ToolSemanticRule(
                "elevate", "tool", "elevate", ("privilege.escalate",), runtime="fixture"
            ),
        ),
    )
    policy = SwarmTemporalPolicySet(
        "time",
        1,
        (
            R(
                "time",
                "high",
                (
                    P(effects_any=("filesystem.permission_change",)),
                    P(effects_any=("privilege.escalate",), evidence_classes=("current_proposal",)),
                ),
                within_seconds=10,
            ),
        ),
    )
    engine, emit, data = action_fixture(policy, ordin=Ordin(tool_semantics=semantics))
    event = emit(
        "c",
        "permissions",
        "reviewed",
        action=ActionEnvelope.shell("chmod 777 /fixture/file", action_id="permissions"),
    )
    assert event.timestamp == 999999999999
    data[7][0] = 111
    for source in data[3].values():
        engine.cover(source, complete_from=100)
    action = ActionEnvelope(
        "tool",
        "call",
        {"runtime": "fixture", "tool": "elevate", "arguments": {}},
        action_id="elevate",
    )
    result = engine.evaluate(data[2]["c"], data[3]["c"], action, parent_event_ids=("permissions",))
    assert result.status == "satisfied" and not result.findings
    unknown = engine.evaluate(
        data[2]["c"],
        data[3]["c"],
        ActionEnvelope.shell("unknown_unclassified_binary"),
        parent_event_ids=("permissions",),
    )
    assert unknown.status == "unknown" and "current_semantics_unavailable" in unknown.proof_gaps


def test_fact_capture_is_original_idempotent_bounded_and_never_mutable_json():
    engine, flow, handle, _, _, hosts, _, data = captured()
    engine.record_event(data[3]["c"], "receive-c", lineage=(handle,), observed_at=100)
    data[7][0] = 101
    with pytest.raises(ValueError, match="conflicts"):
        engine.record_event(data[3]["c"], "receive-c", lineage=(handle,), observed_at=101)
    with pytest.raises(ValueError, match="original authenticated"):
        engine.record_event(data[3]["a"], "receive-c", lineage=(handle,), observed_at=100)
    with pytest.raises(ValueError):
        engine.record_event(data[3]["c"], "receive-c", lineage=({"id": "forged"},), observed_at=100)
    result = engine.evaluate(
        data[2]["c"],
        data[3]["c"],
        upload(SECRET),
        parent_event_ids=("receive-c",),
        uses=(LineageUse(handle, PATH),),
    )
    exported = result.as_dict()
    exported["findings"][0]["evidence"][0]["event_id"] = "changed"
    assert result.as_dict()["findings"][0]["evidence"][0]["event_id"] != "changed"
    with pytest.raises(TypeError):
        result.findings[0].evidence[0]["event_id"] = "changed"


def test_cli_explicit_policy_validation_and_schema_reports(tmp_path, capsys):
    from ordin.entrypoint import main
    from ordin.schema import validate_named_schema

    path = tmp_path / "policy.json"
    path.write_text(json.dumps(default_swarm_temporal_policy().policy.as_dict()))
    assert main(["swarm", "temporal", "validate", "--policy", str(path), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert validate_named_schema("swarm_temporal_validation", report) == []
    assert report["valid"] and not report["execution_authority"]
    path.write_text('{"schema_version":"private malformed text"}')
    assert main(["swarm", "temporal", "validate", "--policy", str(path), "--json"]) == 2
    assert "private malformed text" not in capsys.readouterr().out
    engine, _, handle, _, _, _, _, data = captured()
    result = engine.evaluate(
        data[2]["c"],
        data[3]["c"],
        upload(SECRET),
        parent_event_ids=("receive-c",),
        uses=(LineageUse(handle, PATH),),
    )
    assert validate_named_schema("swarm_temporal_evaluation", result.as_dict()) == []


@pytest.mark.parametrize(
    "change",
    [
        {"effects_any": ["filesystem.read"]},
        {"agent_relation": "invented"},
        {"evidence_classes": ("caller_asserted",)},
        {"effect_evidence": []},
    ],
)
def test_invalid_predicate_configuration_fails_closed(change):
    with pytest.raises(ValueError):
        P(event_kinds=("artifact_read",), **change)


def test_mutable_action_changes_cannot_bind_safe_facts_to_another_proposal(monkeypatch):
    engine, _, handle, _, _, _, _, data = captured()
    action = upload(SECRET)
    changed = [False]

    def clock():
        if not changed[0]:
            action.parameters["body"]["params"]["value"] = "changed current bytes"
            changed[0] = True
        return data[7][0]

    monkeypatch.setattr(engine, "_clock", clock)
    with pytest.raises(ValueError, match="action changed"):
        engine.evaluate(
            data[2]["c"],
            data[3]["c"],
            action,
            parent_event_ids=("receive-c",),
            uses=(LineageUse(handle, PATH),),
        )

    engine, emit, data = action_fixture(retry_policy())
    prior = ActionEnvelope.shell("git status", action_id="prior")
    emit("a", "prior", "reviewed", action=prior)
    original = engine._semantics

    def semantics(normalized, observation=None):
        result = original(normalized, observation)
        prior.parameters["command"] = "rm -rf /"
        return result

    monkeypatch.setattr(engine, "_semantics", semantics)
    with pytest.raises(ValueError, match="action changed"):
        engine.record_event(data[3]["a"], "prior", action=prior, observed_at=100)


def test_missing_capture_and_idempotent_late_retry_do_not_retime_events():
    engine, _, handle, _, _, _, _, data = captured()
    data[7][0] = 101
    # A duplicate callback without a timestamp reuses the first protected capture.
    engine.record_event(data[3]["c"], "receive-c", lineage=(handle,))
    assert engine._facts["receive-c"].observed_at == 100
    del engine._facts["send-a"]  # Simulate collection that did not capture this node.
    result = engine.evaluate(
        data[2]["c"],
        data[3]["c"],
        upload(SECRET),
        parent_event_ids=("receive-c",),
        uses=(LineageUse(handle, PATH),),
    )
    assert result.status == "unknown" and not result.findings
    assert "host_observation_time_unavailable" in result.proof_gaps


def test_control_ancestry_is_not_counterfeit_data_origin_for_independent_secret():
    flow, _, hosts, event, data = configured()
    sources = data[3]
    first = root(flow, hosts, event, sources)
    event("a", "send-a", "message_sent", SECRET, parents=("read",))
    event("b", "receive-b", "message_received", SECRET, parents=("send-a",))
    received = flow.derive(
        sources["b"], event_id="receive-b", content=SECRET, parents=(first,), complete=True
    )
    # B independently reads another classified source after A's handoff. The
    # control dependency does not mean B's second source came from A's bytes.
    other = "INDEPENDENT_SYNTHETIC_SECRET"
    event("b", "independent", "artifact_read", other, parents=("receive-b",))
    origin = register_instruction_origin(
        hosts["b"],
        origin_id="independent",
        kind="repository_file",
        classification="sensitive",
        content=other,
    )
    independent = flow.register(
        sources["b"], event_id="independent", origin=origin, sensitivity=Sensitivity(("secret",))
    )
    engine = SwarmTemporalEngine(
        data[6], secret_policy(within_seconds=10), flow=flow, clock=lambda: data[7][0]
    )
    for actor, event_id, handles in (
        ("a", "read", (first,)),
        ("a", "send-a", ()),
        ("b", "receive-b", (received,)),
        ("b", "independent", (independent,)),
    ):
        engine.record_event(sources[actor], event_id, lineage=handles, observed_at=100)
    data[7][0] = 110
    for source in sources.values():
        engine.cover(source, complete_from=100)
    action = upload(other)
    result = engine.evaluate(
        data[2]["b"],
        sources["b"],
        action,
        parent_event_ids=("independent",),
        uses=(LineageUse(independent, PATH),),
    )
    assert result.status == "satisfied" and not result.findings
    # The ordinary source-flow guard still rejects this direct sensitive egress.
    assert (
        flow.assess(
            sources["b"],
            action,
            sink_id="external",
            uses=(LineageUse(independent, PATH),),
            complete=True,
        ).status
        == "violated"
    )


def test_runtime_binding_digest_is_pure_and_reflects_coverage_and_sender_lifecycle():
    engine, _, _, _, _, _, _, data = captured()
    before = engine.binding_digest
    state = (engine._generation, len(engine._facts), len(engine._coverage))
    assert engine.binding_digest == before
    assert (engine._generation, len(engine._facts), len(engine._coverage)) == state
    engine.cover(data[3]["a"], complete_from=100)
    covered = engine.binding_digest
    assert covered != before and engine.binding_digest == covered
    data[0].pause(data[2]["b"], data[4]["b"], data[5]["b"])
    assert engine.binding_digest != covered


def test_missing_prior_action_semantics_cannot_make_an_applicable_rule_safe():
    from ordin._runtime_json import digest
    from ordin.swarm import SwarmEvent
    from ordin.tool_calls import ToolSemanticRule, ToolSemanticsRegistry

    semantics = ToolSemanticsRegistry(
        "fixture",
        "1",
        (
            ToolSemanticRule(
                "elevate", "tool", "elevate", ("privilege.escalate",), runtime="fixture"
            ),
        ),
    )
    policy = SwarmTemporalPolicySet(
        "missing",
        1,
        (
            R(
                "missing",
                "high",
                (
                    P(effects_any=("filesystem.permission_change",)),
                    P(effects_any=("privilege.escalate",), evidence_classes=("current_proposal",)),
                ),
            ),
        ),
    )
    engine, _, data = action_fixture(policy, ordin=Ordin(tool_semantics=semantics))
    prior = ActionEnvelope.shell("chmod 777 /fixture/file", action_id="prior")
    event = SwarmEvent(
        "prior",
        "reviewed",
        data[2]["c"].registry_id,
        data[2]["c"].identity,
        "c",
        1,
        100,
        evidence_class="host_authenticated",
        action_id="prior",
        action_digest=digest(prior.as_dict()),
    )
    data[1].ingest(data[3]["c"], event)
    engine.record_event(data[3]["c"], "prior", observed_at=100)
    data[7][0] = 400
    for source in data[3].values():
        engine.cover(source, complete_from=100)
    current = ActionEnvelope(
        "tool",
        "call",
        {"runtime": "fixture", "tool": "elevate", "arguments": {}},
        action_id="current",
    )
    result = engine.evaluate(data[2]["c"], data[3]["c"], current, parent_event_ids=("prior",))
    assert result.status == "unknown" and not result.findings
    assert "prior_action_semantics_unavailable" in result.proof_gaps


def test_proposal_cannot_claim_completed_origin_or_transfer_metadata():
    final = secret_policy().rules[0].pattern[-1]
    with pytest.raises(ValueError, match="authenticated prior"):
        replace(
            secret_policy().rules[0],
            pattern=(
                P(event_kinds=("artifact_read",)),
                replace(final, transfer_edges=("observed_data_flow",)),
            ),
        )
    with pytest.raises(ValueError, match="authenticated prior"):
        replace(
            secret_policy().rules[0],
            pattern=(
                P(event_kinds=("artifact_read",)),
                replace(final, origins_any=("repository_file",)),
            ),
        )
