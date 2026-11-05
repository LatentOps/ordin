"""Actual host lineage, exact bytes, fail-closed gate and source-flow integration."""

import base64
from dataclasses import replace
import hashlib
import json

import pytest

from ordin import ActionEnvelope, AgentGate, Ordin
from ordin.assurance import (
    HostEvidenceSource,
    InstructionOrigin,
    ReviewedAction,
    assess_source_flow,
    register_instruction_origin,
    record_source_provenance,
)
from ordin.swarm import (
    EgressSink,
    LineageHandle,
    LineageUse,
    Sensitivity,
    SwarmGate,
    SwarmPolicy,
    SwarmAssessmentSource,
    SwarmSourceFlow,
    CoverageManifest,
    InMemoryAgentRegistry,
    SwarmEventIngestor,
    SwarmCausalGraph,
    SwarmToolGateway,
)
from tests.test_swarm_graph import fixture, packet
from tests.assurance.test_profiles import REPO, POLICY_HASH
from tests.assurance.test_source_flow import setup


SECRET = "SYNTHETIC_SECRET_WITH_NO_REAL_VALUE"
PATH = ("parameters", "body", "params", "value")


def upload(value, *, destination="https://fixture.invalid/rpc", identity="upload"):
    return ActionEnvelope(
        "network",
        "jsonrpc.request",
        {
            "url": destination,
            "body": {"jsonrpc": "2.0", "id": 1, "method": "send", "params": {"value": value}},
        },
        action_id=identity,
    )


def configured(*, allowed=("public",), **limits):
    registry, ingest, contexts, sources, channels, adapters, graph, now = fixture()
    operator = object()
    flow = SwarmSourceFlow(
        graph,
        operator=operator,
        sinks=(
            EgressSink(
                "external",
                "network",
                "network",
                "jsonrpc.request",
                ("parameters", "url"),
                "https://fixture.invalid/rpc",
                allowed,
            ),
        ),
        **limits,
    )
    hosts = {}
    for name in contexts:
        hosts[name] = HostEvidenceSource(name, REPO, "a" * 64, 1, POLICY_HASH, "b" * 64)
        flow.bind_actor(sources[name], contexts[name], hosts[name])
    sequences = {name: 0 for name in contexts}

    def event(actor, event_id, kind, text, *, parents=(), claimed=False):
        sequences[actor] += 1
        ingest.ingest(
            sources[actor],
            packet(
                contexts[actor],
                sources[actor],
                event_id,
                kind,
                sequences[actor],
                parents=parents,
                resources=(hashlib.sha256(text.encode()).hexdigest(),),
            ),
        )

    return (
        flow,
        operator,
        hosts,
        event,
        (registry, ingest, contexts, sources, channels, adapters, graph, now),
    )


def root(
    flow, hosts, event, sources, *, text=SECRET, labels=("secret",), classification="sensitive"
):
    event("a", "read", "artifact_read", text)
    origin = register_instruction_origin(
        hosts["a"],
        origin_id="actual-read",
        kind="repository_file",
        classification=classification,
        content=text,
    )
    return flow.register(
        sources["a"], event_id="read", origin=origin, sensitivity=Sensitivity(labels)
    )


def relay(flow, event, sources, handle, text, *, complete=True):
    event("a", "send-a", "message_sent", SECRET, parents=("read",))
    event("b", "receive-b", "message_received", SECRET, parents=("send-a",))
    received = flow.derive(
        sources["b"], event_id="receive-b", content=SECRET, parents=(handle,), complete=True
    )
    event("b", "transform-b", "artifact_write", text, parents=("receive-b",))
    transformed = flow.derive(
        sources["b"], event_id="transform-b", content=text, parents=(received,), complete=complete
    )
    event("b", "send-b", "message_sent", text, parents=("transform-b",))
    event("c", "receive-c", "message_received", text, parents=("send-b",))
    return flow.derive(
        sources["c"], event_id="receive-c", content=text, parents=(transformed,), complete=True
    )


@pytest.mark.parametrize(
    "transformed",
    [
        "A short summary with sensitive information",
        base64.b64encode(SECRET.encode()).decode(),
        SECRET,
    ],
)
def test_sensitive_a_transform_b_upload_c_is_blocked_without_claiming_exfiltration(transformed):
    flow, _, hosts, event, data = configured()
    sources = data[3]
    handle = root(flow, hosts, event, sources)
    output = relay(flow, event, sources, handle, transformed)
    result = flow.assess(
        sources["c"],
        upload(transformed),
        sink_id="external",
        uses=(LineageUse(output, PATH),),
        complete=True,
    )
    assert result.status == "violated" and result.labels == ("secret",)
    assert not result.proof_gaps
    report = result.as_dict()
    assert report["observed_exfiltration"] == "unknown" and report["execution_authority"] is False
    assert SECRET not in json.dumps(report) and transformed not in json.dumps(report)


def test_copy_to_file_and_delayed_upload_keep_private_code_and_pii():
    flow, _, hosts, event, data = configured()
    sources, now = data[3], data[7]
    handle = root(flow, hosts, event, sources, labels=("pii", "private_code"))
    output = relay(flow, event, sources, handle, "summarized private code")
    event("c", "file-copy", "artifact_write", "summarized private code", parents=("receive-c",))
    copied = flow.derive(
        sources["c"],
        event_id="file-copy",
        content="summarized private code",
        parents=(output,),
        complete=True,
    )
    now[0] += 5
    result = flow.assess(
        sources["c"],
        upload("summarized private code"),
        sink_id="external",
        uses=(LineageUse(copied, PATH),),
        complete=True,
    )
    assert result.status == "violated" and result.labels == ("pii", "private_code")


def test_benign_public_handoff_and_explicit_authorized_sensitive_sink():
    for labels, classification, allowed in (
        (("public",), "public", ("public",)),
        (("secret",), "sensitive", ("secret",)),
    ):
        flow, _, hosts, event, data = configured(allowed=allowed)
        sources = data[3]
        handle = root(flow, hosts, event, sources, labels=labels, classification=classification)
        output = relay(
            flow, event, sources, handle, "public report" if classification == "public" else SECRET
        )
        text = "public report" if classification == "public" else SECRET
        assert (
            flow.assess(
                sources["c"],
                upload(text),
                sink_id="external",
                uses=(LineageUse(output, PATH),),
                complete=True,
            ).status
            == "satisfied"
        )


def test_unobserved_cross_agent_transfer_is_unknown_without_counterfeit_violation():
    flow, _, hosts, event, data = configured()
    sources = data[3]
    handle = root(flow, hosts, event, sources)
    event("c", "unconnected", "artifact_read", SECRET)
    unverified = flow.derive(
        sources["c"], event_id="unconnected", content=SECRET, parents=(handle,), complete=True
    )
    result = flow.assess(
        sources["c"],
        upload(SECRET),
        sink_id="external",
        uses=(LineageUse(unverified, PATH),),
        complete=True,
    )
    assert result.status == "unknown" and "unverified_transfer" in result.proof_gaps
    assert "secret" in result.labels


def test_partial_transform_never_strips_sensitivity_and_unknown_origin_never_passes():
    flow, _, hosts, event, data = configured()
    sources = data[3]
    handle = root(flow, hosts, event, sources)
    output = relay(flow, event, sources, handle, "opaque summary", complete=False)
    result = flow.assess(
        sources["c"],
        upload("opaque summary"),
        sink_id="external",
        uses=(LineageUse(output, PATH),),
        complete=True,
    )
    assert result.status == "violated" and result.labels == ("secret", "unclassified")
    flow, _, hosts, event, data = configured()
    sources = data[3]
    unknown = root(flow, hosts, event, sources, labels=("unclassified",), classification="unknown")
    assert (
        flow.assess(
            sources["a"],
            upload(SECRET),
            sink_id="external",
            uses=(LineageUse(unknown, PATH),),
            complete=True,
        ).status
        == "unknown"
    )


def test_absence_unknown_sink_and_wrong_destination_require_restriction():
    flow, _, _, _, data = configured()
    source = data[3]["a"]
    assert flow.assess(source, upload("public"), sink_id="external", uses=()).status == "unknown"
    assert (
        flow.assess(source, upload("public"), sink_id="missing", uses=(), complete=True).status
        == "unknown"
    )
    assert (
        flow.assess(
            source,
            upload("public", destination="https://other.invalid"),
            sink_id="external",
            uses=(),
            complete=True,
        ).status
        == "unknown"
    )
    assert (
        flow.assess(source, upload("public"), sink_id="external", uses=(), complete=True).status
        == "satisfied"
    )


def test_declassification_requires_operator_and_current_epoch_and_is_audited():
    flow, operator, hosts, event, data = configured()
    registry, _, _, sources, *_ = data
    handle = root(flow, hosts, event, sources)
    for capability, epoch in ((object(), 0), (operator, 1)):
        with pytest.raises(ValueError, match="declassification"):
            flow.declassify(
                handle,
                operator=capability,
                policy_epoch=epoch,
                sensitivity=Sensitivity(("public",)),
                reason_code="approved.release",
            )
    released = flow.declassify(
        handle,
        operator=operator,
        policy_epoch=0,
        sensitivity=Sensitivity(("public",)),
        reason_code="approved.release",
    )
    assert (
        flow.assess(
            sources["a"],
            upload(SECRET),
            sink_id="external",
            uses=(LineageUse(released, PATH),),
            complete=True,
        ).status
        == "satisfied"
    )
    assert len(flow.audit()) == 1 and SECRET not in json.dumps(flow.audit())
    audit = flow.audit()
    audit[0]["labels"].append("secret")
    assert flow.audit()[0]["labels"] == ["public"]
    registry.advance_policy_epoch(1)
    with pytest.raises(ValueError):
        flow.assess(
            sources["a"],
            upload(SECRET),
            sink_id="external",
            uses=(LineageUse(released, PATH),),
            complete=True,
        )


def test_handles_bytes_actor_origin_and_record_budgets_are_checked():
    flow, _, hosts, event, data = configured(max_records=1)
    sources = data[3]
    handle = root(flow, hosts, event, sources)
    for use, actor, action in (
        (LineageUse(LineageHandle(handle.lineage_id), PATH), "a", upload(SECRET)),
        (LineageUse(handle, PATH), "c", upload(SECRET)),
        (LineageUse(handle, PATH), "a", upload("changed")),
    ):
        with pytest.raises(ValueError):
            flow.assess(sources[actor], action, sink_id="external", uses=(use,), complete=True)
    with pytest.raises(ValueError, match="capacity"):
        flow.derive(sources["a"], event_id="read", content=SECRET, parents=(handle,), complete=True)
    origin = register_instruction_origin(
        hosts["a"], origin_id="bad", kind="mcp_result", classification="sensitive", content=SECRET
    )
    with pytest.raises(ValueError, match="classification"):
        flow.register(
            sources["a"], event_id="read", origin=origin, sensitivity=Sensitivity(("public",))
        )
    with pytest.raises(ValueError):
        InstructionOrigin.from_dict(origin.as_dict())


def test_mandatory_swarm_gate_receipt_denies_and_is_bound_to_exact_action():
    flow, _, hosts, event, data = configured()
    registry, ingest, contexts, sources, channels, adapters, _, now = data
    handle = root(flow, hosts, event, sources)
    authority = SwarmAssessmentSource("lineage", clock=lambda: now[0])
    gate = SwarmGate(
        registry,
        AgentGate(Ordin()),
        policy=SwarmPolicy("egress", "1", required_checks=("source_flow",)),
        assessment_source=authority,
        events=ingest,
    )
    action = upload(SECRET)
    snapshot = gate.evidence_snapshot_digest(contexts["a"], event_source=sources["a"])
    receipt = flow.issue_assessment(
        sources["a"],
        action,
        authority=authority,
        policy_digest=gate.policy_digest,
        snapshot_digest=snapshot,
        sink_id="external",
        uses=(LineageUse(handle, PATH),),
        complete=True,
    )
    decision = gate.evaluate_action(
        contexts["a"],
        action,
        channel=channels["a"],
        adapter=adapters["a"],
        event_source=sources["a"],
        assessments=(receipt,),
    )
    assert decision.denied
    other = gate.evaluate_action(
        contexts["a"],
        upload("other", identity="other"),
        channel=channels["a"],
        adapter=adapters["a"],
        event_source=sources["a"],
        assessments=(receipt,),
    )
    assert other.denied


def test_assurance_guard_reuses_host_lineage_and_rejects_cross_action_receipt(tmp_path):
    flow, _, hosts, event, data = configured()
    sources = data[3]
    approved, template, gate, _ = setup(tmp_path, upload(SECRET))
    # Bind the same protected profile selection at actor enrollment.
    flow._actors.clear()
    for name, context in data[2].items():
        hosts[name] = replace(template, principal=name)
        flow.bind_actor(sources[name], context, hosts[name])
    handle = root(flow, hosts, event, sources)
    output = relay(flow, event, sources, handle, "summarized secret")
    action = upload("summarized secret")
    host = hosts["c"]
    context = host.context()
    reviewed = ReviewedAction(gate.evaluate_action(action, host_context=context), context)
    receipt = flow.assurance_assessment(
        sources["c"],
        action,
        approved,
        invariant_id="source-guard",
        sink_id="external",
        uses=(LineageUse(output, PATH),),
        complete=True,
    )
    provenance = record_source_provenance(host, action)
    combined = assess_source_flow(
        reviewed,
        approved,
        invariant_id="source-guard",
        provenance=provenance,
        lineage_assessment=receipt,
    )
    assert combined.status == "violated"
    assert gate.evaluate_action(action, host_context=host.context(assessments=(combined,))).denied
    stale = host.record_assessment(
        upload("other", identity="other"),
        approved,
        assessment_id="stale-lineage",
        invariant_id="source-guard",
        kind="source_flow_guard",
        status="satisfied",
    )
    with pytest.raises(ValueError, match="another action"):
        assess_source_flow(
            reviewed,
            approved,
            invariant_id="source-guard",
            provenance=provenance,
            lineage_assessment=stale,
        )


def test_sensitivity_join_retains_all_sensitive_categories_and_unknown():
    public = Sensitivity(("public",))
    secret = Sensitivity(("secret",))
    assert public.join(secret).labels == ("secret",)
    assert secret.join(Sensitivity(("pii", "private_code")), Sensitivity()).labels == (
        "pii",
        "private_code",
        "secret",
        "unclassified",
    )
    for labels in (("public", "secret"), ("secret", "pii"), ("safe",), ()):
        with pytest.raises(ValueError):
            Sensitivity(labels)


def test_gateway_never_forwards_sensitive_payload_after_lineage_violation():
    registry = InMemoryAgentRegistry("tenant", "swarm", clock=lambda: 100)
    adapter = object()
    channel = registry.bind_channel(adapter, runtime_id="fixture")
    context = registry.enroll(
        channel, adapter, agent_id="a", session_id="a", coverage=CoverageManifest("intercept")
    )
    ingest = SwarmEventIngestor(registry)
    sender = ingest.bind_source(context, channel, adapter, source_id="data-source")
    graph = SwarmCausalGraph(ingest, sender, context)
    flow = SwarmSourceFlow(
        graph,
        operator=object(),
        sinks=(
            EgressSink(
                "external",
                "network",
                "network",
                "jsonrpc.request",
                ("parameters", "url"),
                "https://fixture.invalid/rpc",
            ),
        ),
    )
    host = HostEvidenceSource("a", REPO, "a" * 64, 1, POLICY_HASH, "b" * 64)
    flow.bind_actor(sender, context, host)
    ingest.ingest(
        sender,
        packet(
            context,
            sender,
            "read",
            "artifact_read",
            1,
            resources=(hashlib.sha256(SECRET.encode()).hexdigest(),),
        ),
    )
    origin = register_instruction_origin(
        host, origin_id="read", kind="mcp_result", classification="sensitive", content=SECRET
    )
    handle = flow.register(
        sender, event_id="read", origin=origin, sensitivity=Sensitivity(("secret",))
    )
    authority = SwarmAssessmentSource("flow", clock=lambda: 100)
    gate = SwarmGate(
        registry,
        policy=SwarmPolicy("egress", "1", required_checks=("source_flow",)),
        assessment_source=authority,
        events=ingest,
    )

    def provider(context, action, gate, options):
        return (
            flow.issue_assessment(
                sender,
                action,
                authority=authority,
                policy_digest=gate.policy_digest,
                snapshot_digest=gate.evidence_snapshot_digest(context, **options),
                sink_id="external",
                uses=(LineageUse(handle, PATH),),
                complete=True,
            ),
        )

    gateway = SwarmToolGateway(events=ingest, clock=lambda: 100)
    actor = gateway.bind_agent(
        context, gate, channel, adapter, routes=frozenset({"http"}), assessment_provider=provider
    )
    denied = gateway.prepare(actor, upload(SECRET))
    assert denied.disposition == "deny" and denied.ticket is None
    calls = []
    with pytest.raises(ValueError):
        gateway.forward(actor, denied.ticket, lambda action: calls.append(action))
    assert not calls and "forwarded" not in {r.event.event_kind for r in ingest.snapshot()}


def test_label_changes_fence_old_swarm_assessments_without_journal_change():
    from ordin._runtime_json import digest

    flow, operator, hosts, event, data = configured()
    sources, contexts = data[3], data[2]
    handle = root(flow, hosts, event, sources)
    released = flow.declassify(
        handle,
        operator=operator,
        policy_epoch=0,
        sensitivity=Sensitivity(("public",)),
        reason_code="release",
    )
    authority = SwarmAssessmentSource("flow", clock=lambda: 100)
    action = upload(SECRET)
    bindings = dict(
        action_digest=digest(action.as_dict()),
        context_digest=digest(contexts["a"].as_dict()),
        policy_digest="a" * 64,
        snapshot_digest="b" * 64,
    )
    receipt = flow.issue_assessment(
        sources["a"],
        action,
        authority=authority,
        policy_digest=bindings["policy_digest"],
        snapshot_digest=bindings["snapshot_digest"],
        sink_id="external",
        uses=(LineageUse(released, PATH),),
        complete=True,
    )
    assert authority.verify(receipt, **bindings)
    flow.declassify(
        released,
        operator=operator,
        policy_epoch=0,
        sensitivity=Sensitivity(("secret",)),
        reason_code="reclassify",
    )
    assert not authority.verify(receipt, **bindings)
