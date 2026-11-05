from concurrent.futures import ThreadPoolExecutor
from copy import copy
from dataclasses import replace
import json
from threading import Barrier

import pytest

from ordin import ActionEnvelope, Ordin, derive_runtime_capability_contract
from ordin._runtime_json import digest as runtime_digest
from ordin.runtime_observation import RuntimeEvidenceSource, RuntimeObservation
from ordin.execution import ObservedResource
from ordin.schema import validate_named_schema
from ordin.swarm import InMemoryAgentRegistry
from ordin.swarm.events import EventRef, SwarmEvent
from ordin.swarm.ingest import HostEventSource, SwarmEventIngestor


DIGEST = "a" * 64


def fixture(*, registry_id=None, **options):
    now = [100.0]
    registry = InMemoryAgentRegistry(
        "tenant", "swarm", clock=lambda: now[0], registry_id=registry_id
    )
    adapter = object()
    channel = registry.bind_channel(adapter, runtime_id="fixture")
    context = registry.enroll(channel, adapter, agent_id="agent", session_id="session")
    ingest = SwarmEventIngestor(registry, **options)
    source = ingest.bind_source(context, channel, adapter, source_id="gateway")
    return registry, adapter, channel, context, ingest, source, now


def event(
    context, event_id, kind, sequence, *, source="gateway", parents=(), review=None, **options
):
    action = (
        {}
        if kind
        in {
            "message_sent",
            "message_received",
            "delegated",
            "artifact_read",
            "artifact_write",
            "revoked",
        }
        else {"action_id": "action", "action_digest": DIGEST}
    )
    return SwarmEvent(
        event_id,
        kind,
        context.registry_id,
        context.identity,
        source,
        sequence,
        100.0,
        evidence_class=options.pop("evidence_class", "host_authenticated"),
        parent_event_ids=tuple(EventRef("tenant", "swarm", parent) for parent in parents),
        review_event_id=review,
        **{**action, **options},
    )


def test_late_and_out_of_order_events_have_deterministic_conservative_projection():
    _, _, _, context, ingest, source, _ = fixture()
    review = event(context, "review", "reviewed", 2, parents=("proposal",))
    result = ingest.ingest(source, review)
    assert {"source_sequence_gap", "causal_parent_gap", "action_lifecycle_gap"} <= set(result.gaps)
    ingest.ingest(source, event(context, "proposal", "proposed", 1))
    for sequence, name, predecessor in (
        (3, "reserved", "review"),
        (4, "committed", "reserved"),
        (5, "forwarded", "committed"),
        (6, "completed", "forwarded"),
    ):
        parents = tuple(dict.fromkeys(("review", predecessor)))
        receipt = ingest.ingest(
            source, event(context, name, name, sequence, parents=parents, review="review")
        )
    state = ingest.action_state(source, action_id="action", action_digest=DIGEST)
    assert state.causally_complete and state.authenticated_completion
    assert (
        not state.missing_stages and not state.unresolved_parents and not state.sequence_incomplete
    )
    assert not receipt.gaps
    assert [r.event.event_id for r in ingest.snapshot()][:2] == ["review", "proposal"]
    assert [r.ingest_index for r in ingest.snapshot()] == list(range(1, 7))
    retry = ingest.ingest(source, review)
    assert retry.duplicate and retry.ingest_index == 1
    assert len(ingest.snapshot()) == 6


def test_completion_requires_exact_authenticated_review_and_never_invents_missing_stages():
    _, _, _, context, ingest, source, _ = fixture()
    completion = event(context, "done", "completed", 2, parents=("review",), review="review")
    with pytest.raises(ValueError, match="reviewed-action"):
        ingest.ingest(source, completion)
    assert ingest.snapshot() == ()
    ingest.ingest(source, event(context, "review", "reviewed", 1))
    ingest.ingest(source, completion)
    state = ingest.action_state(source, action_id="action", action_digest=DIGEST)
    assert state.authenticated_completion
    assert not state.causally_complete
    assert set(state.missing_stages) == {"proposed", "reserved", "committed", "forwarded"}
    with pytest.raises(ValueError):
        ingest.ingest(
            source,
            event(
                context,
                "changed",
                "completed",
                3,
                parents=("review",),
                review="review",
                action_digest="b" * 64,
            ),
        )
    with pytest.raises(ValueError):
        ingest.ingest(source, event(context, "second-review", "reviewed", 3))


def test_siblings_serialized_principals_and_constructed_sender_handles_cannot_forge():
    registry, adapter, channel, context, ingest, source, _ = fixture()
    review = event(context, "review", "reviewed", 1)
    for fake in (HostEventSource("gateway"), copy(source), {"source_id": "gateway"}):
        with pytest.raises(ValueError):
            ingest.ingest(fake, review)
    sibling_adapter = object()
    sibling_channel = registry.bind_channel(sibling_adapter, runtime_id="sibling")
    sibling = registry.enroll(
        sibling_channel, sibling_adapter, agent_id="sibling", session_id="other"
    )
    other = ingest.bind_source(sibling, sibling_channel, sibling_adapter, source_id="other")
    ingest.ingest(source, review)
    with pytest.raises(ValueError):
        ingest.ingest(other, review)
    forged = event(
        sibling, "forged", "completed", 1, source="other", parents=("review",), review="review"
    )
    with pytest.raises(ValueError, match="reviewed-action"):
        ingest.ingest(other, forged)
    assert len(ingest.snapshot()) == 1


def test_model_claims_and_confidence_cannot_become_trusted_runtime_facts():
    _, adapter, channel, context, ingest, source, _ = fixture()
    asserted = ingest.bind_source(context, channel, adapter, source_id="asserted", role="asserted")
    with pytest.raises(ValueError):
        ingest.ingest(
            asserted, event(context, "fake-host", "reviewed", 1, source="asserted", confidence=1)
        )
    ingest.ingest(source, event(context, "review", "reviewed", 1))
    claim = event(
        context,
        "claim",
        "completed",
        1,
        source="asserted",
        parents=("review",),
        review="review",
        confidence=1,
        evidence_class="caller_asserted",
    )
    assert "caller_asserted_event" in ingest.ingest(asserted, claim).gaps
    state = ingest.action_state(source, action_id="action", action_digest=DIGEST)
    assert not state.authenticated_completion and not state.authenticated_observation
    raw = claim.as_dict()
    raw["observed_effects"] = ["model-supplied-secret-export"]
    with pytest.raises(ValueError):
        SwarmEvent.from_dict(raw)
    with pytest.raises(ValueError):
        ingest.ingest(
            asserted,
            event(
                context,
                "fake-observed",
                "observed",
                2,
                source="asserted",
                parents=("review",),
                review="review",
                evidence_class="backend_enforced",
                observation_digest="b" * 64,
                observed_outcome="completed",
            ),
        )


def test_epoch_revocation_expiry_and_restart_reject_stale_senders():
    registry, adapter, channel, context, ingest, source, now = fixture()
    proposed = event(context, "proposal", "proposed", 1)
    now[0] = 130
    with pytest.raises(ValueError):
        ingest.ingest(source, proposed)
    now[0] = 131
    fresh = registry.restart(
        context, channel, adapter, new_channel=channel, new_adapter=adapter, session_id="new"
    )
    with pytest.raises(ValueError):
        ingest.ingest(source, proposed)
    new_source = ingest.bind_source(fresh, channel, adapter, source_id="new-source")
    registry.advance_policy_epoch(1)
    with pytest.raises(ValueError):
        ingest.ingest(new_source, event(fresh, "new", "proposed", 1, source="new-source"))


def test_duplicate_and_sequence_conflicts_are_bounded_without_discarding_deduplication():
    _, _, _, context, ingest, source, _ = fixture(max_events=1, sequence_window=4)
    with pytest.raises(ValueError, match="window"):
        ingest.ingest(source, event(context, "too-far", "proposed", 5))
    first = event(context, "one", "proposed", 4)
    ingest.ingest(source, first)
    assert ingest.ingest(source, first).duplicate
    with pytest.raises(ValueError, match="replay"):
        ingest.ingest(source, replace(first, confidence=0.5))
    with pytest.raises(ValueError, match="capacity"):
        ingest.ingest(source, event(context, "two", "proposed", 1))
    assert len(ingest.snapshot()) == 1


def test_late_parents_cannot_create_cycles_or_exceed_descendant_depth_bounds():
    _, _, _, context, ingest, source, _ = fixture(max_causal_depth=2)
    ingest.ingest(source, event(context, "a", "message_sent", 1, parents=("b",)))
    with pytest.raises(ValueError, match="cycle"):
        ingest.ingest(source, event(context, "b", "message_received", 2, parents=("a",)))
    ingest.ingest(source, event(context, "b", "message_received", 2, parents=("c",)))
    with pytest.raises(ValueError, match="depth"):
        ingest.ingest(source, event(context, "c", "message_sent", 3, parents=("d",)))
    assert len(ingest.snapshot()) == 2
    ingest.ingest(source, event(context, "c", "message_sent", 3))
    assert len(ingest.snapshot()) == 3


def test_cross_scope_parents_and_unbounded_inputs_are_rejected_without_echoing_payloads():
    _, _, _, context, _, _, _ = fixture()
    packet = event(context, "one", "proposed", 1)
    with pytest.raises(ValueError, match="cross-tenant"):
        replace(packet, parent_event_ids=(EventRef("other", "swarm", "parent"),))
    for changes in (
        {"source_sequence": True},
        {"source_sequence": 0},
        {"source_sequence": 2**63},
        {"confidence": float("nan")},
        {"timestamp": 10**1000},
        {"parent_event_ids": tuple(EventRef("tenant", "swarm", str(i)) for i in range(9))},
    ):
        with pytest.raises(ValueError):
            replace(packet, **changes)
    for raw in (
        '{"event_id":"a","event_id":"private-canary"}',
        '{"x":NaN}',
        b"\xff",
        "x" * 65537,
        "\U0001f642" * 20000,
        "[" * 1200 + "0" + "]" * 1200,
    ):
        with pytest.raises(ValueError) as failure:
            SwarmEvent.from_json(raw)
        assert "private-canary" not in str(failure.value)
    restored = SwarmEvent.from_json(json.dumps(packet.as_dict()))
    assert restored == packet and restored.digest == packet.digest


def test_append_failure_does_not_advance_sequence_or_admission_state():
    class FailingJournal:
        def __init__(self):
            self.fail = True
            self.indices = []

        def append(self, record, *, expected_index):
            self.indices.append(expected_index)
            if self.fail:
                raise OSError("fixture storage unavailable")

    storage = FailingJournal()
    _, _, _, context, ingest, source, _ = fixture(journal=storage)
    packet = event(context, "one", "proposed", 1)
    with pytest.raises(OSError):
        ingest.ingest(source, packet)
    assert ingest.snapshot() == ()
    storage.fail = False
    receipt = ingest.ingest(source, packet)
    assert receipt.ingest_index == 1 and not receipt.duplicate
    assert storage.indices == [0, 0]


def test_concurrent_retries_append_once():
    _, _, _, context, ingest, source, _ = fixture()
    packet = event(context, "one", "proposed", 1)
    barrier = Barrier(2)

    def submit(_):
        barrier.wait(timeout=10)
        return ingest.ingest(source, packet)

    with ThreadPoolExecutor(max_workers=2) as pool:
        receipts = list(pool.map(submit, range(2)))
    assert sum(receipt.duplicate for receipt in receipts) == 1
    assert len(ingest.snapshot()) == 1


def test_backend_observation_requires_original_receipt_source_action_and_resource_binding():
    _, adapter, channel, context, ingest, source, _ = fixture()
    action = ActionEnvelope.shell("git status --short", action_id="fixture-action")
    contract = derive_runtime_capability_contract(Ordin().review_action(action))
    runtime = RuntimeEvidenceSource("fixture-backend", "c" * 64, "sandbox", "d" * 64)
    collector = ingest.bind_source(
        context, channel, adapter, source_id="collector", role="collector", collector=runtime
    )
    review = event(
        context,
        "review",
        "reviewed",
        1,
        action_id=contract.action_id,
        action_digest=contract.action_digest,
    )
    ingest.ingest(source, review)
    observation = runtime.observe(
        contract,
        observation_id="observation",
        trust="backend_observed",
        enforcement_point="filesystem",
        outcome="completed",
        operation="read",
        resources=(ObservedResource("path", "/synthetic/report"),),
    )
    packet = event(
        context,
        "observed",
        "observed",
        1,
        source="collector",
        parents=("review",),
        review="review",
        evidence_class="backend_observed",
        observation_digest=observation.digest,
        observed_outcome=observation.outcome,
        resource_digests=tuple(
            sorted({runtime_digest(r.as_dict()) for r in observation.resources})
        ),
        action_id=contract.action_id,
        action_digest=contract.action_digest,
    )
    for supplied in (
        None,
        observation.as_dict(),
        RuntimeObservation("caller", "fixture-action", action_digest=contract.action_digest),
    ):
        with pytest.raises(ValueError):
            ingest.ingest(collector, packet, observation=supplied)
    with pytest.raises(ValueError):
        ingest.ingest(
            collector, replace(packet, resource_digests=("e" * 64,)), observation=observation
        )
    with pytest.raises(ValueError):
        ingest.ingest(
            collector, replace(packet, observation_digest="f" * 64), observation=observation
        )
    with pytest.raises(ValueError):
        ingest.ingest(
            collector, replace(packet, observed_outcome="denied"), observation=observation
        )
    foreign_source = RuntimeEvidenceSource("fixture-backend", "c" * 64, "other-sandbox", "d" * 64)
    foreign = foreign_source.observe(
        contract,
        observation_id="foreign",
        trust="backend_observed",
        enforcement_point="filesystem",
        outcome="completed",
        operation="read",
        resources=observation.resources,
    )
    with pytest.raises(ValueError):
        ingest.ingest(
            collector, replace(packet, observation_digest=foreign.digest), observation=foreign
        )
    ingest.ingest(collector, packet, observation=observation)
    state = ingest.action_state(
        collector, action_id=contract.action_id, action_digest=contract.action_digest
    )
    assert state.authenticated_observation and not state.authenticated_completion
    assert not state.causally_complete
    assert state.observed_outcomes == ("completed",)
    assert "/synthetic/report" not in json.dumps(packet.as_dict())
    assert ingest.ingest(collector, packet, observation=observation).duplicate


def test_untrusted_parent_claims_do_not_corrupt_a_trusted_lifecycle():
    _, adapter, channel, context, ingest, source, _ = fixture()
    previous = None
    for index, stage in enumerate(
        ("proposed", "reviewed", "reserved", "committed", "forwarded", "completed"), 1
    ):
        parents = () if previous is None else (previous,)
        review = None if stage in {"proposed", "reviewed"} else "reviewed"
        if review is not None:
            parents = tuple(dict.fromkeys((review, *parents)))
        ingest.ingest(source, event(context, stage, stage, index, parents=parents, review=review))
        previous = stage
    asserted = ingest.bind_source(context, channel, adapter, source_id="untrusted", role="asserted")
    ingest.ingest(
        asserted,
        event(
            context,
            "claim",
            "proposed",
            3,
            source="untrusted",
            evidence_class="caller_asserted",
            parents=("missing",),
        ),
    )
    assert ingest.action_state(source, action_id="action", action_digest=DIGEST).causally_complete


def test_fixture_replay_reproduces_causal_state_with_fresh_protected_sender_authority():
    _, _, _, context, ingest, source, _ = fixture(registry_id="offline-fixture")
    proposed = event(context, "proposal", "proposed", 1)
    reviewed = event(context, "review", "reviewed", 2, parents=("proposal",))
    ingest.ingest(source, reviewed)
    ingest.ingest(source, proposed)
    corpus = json.dumps([record.event.as_dict() for record in ingest.snapshot()])
    _, _, _, replay_context, replay, replay_source, _ = fixture(registry_id="offline-fixture")
    assert replay_context.as_dict() == context.as_dict()
    packets = [SwarmEvent.from_dict(raw) for raw in json.loads(corpus)]
    with pytest.raises(ValueError):
        replay.ingest(source, packets[0])
    for packet in reversed(packets):
        replay.ingest(replay_source, packet)
    assert replay.action_state(replay_source, action_id="action", action_digest=DIGEST) == (
        ingest.action_state(source, action_id="action", action_digest=DIGEST)
    )
    assert [r.event.event_id for r in replay.snapshot()] != [
        r.event.event_id for r in ingest.snapshot()
    ]


def test_published_schema_and_semantic_reader_reject_malformed_event_shapes():
    _, _, _, context, _, _, _ = fixture()
    packet = event(context, "proposal", "proposed", 1)
    assert validate_named_schema("swarm_event", packet.as_dict()) == []
    for mutate in (
        lambda raw: raw.update(unexpected="private-canary"),
        lambda raw: raw.update(policy_epoch=0),
        lambda raw: raw.update(source_sequence=True),
        lambda raw: raw.update(
            parent_event_ids=[{"event_id": "x", "tenant_id": "other", "swarm_id": "swarm"}]
        ),
        lambda raw: raw["identity"].update(policy_epoch=-1),
    ):
        raw = packet.as_dict()
        mutate(raw)
        with pytest.raises(ValueError):
            SwarmEvent.from_dict(raw)


def test_sender_capacity_and_distinct_event_sequence_reuse_fail_without_state_loss():
    _, adapter, channel, context, ingest, source, _ = fixture(max_sources=1)
    with pytest.raises(ValueError, match="capacity"):
        ingest.bind_source(context, channel, adapter, source_id="other")
    packet = event(context, "one", "proposed", 1)
    ingest.ingest(source, packet)
    with pytest.raises(ValueError, match="sequence replay"):
        ingest.ingest(source, event(context, "two", "proposed", 1))
    assert ingest.ingest(source, packet).duplicate
    assert len(ingest.snapshot()) == 1


def test_stage_presence_without_causal_links_cannot_complete_a_lifecycle():
    _, _, _, context, ingest, source, _ = fixture()
    ingest.ingest(source, event(context, "proposal", "proposed", 1))
    ingest.ingest(source, event(context, "review", "reviewed", 2, parents=("proposal",)))
    for sequence, kind in enumerate(("reserved", "committed", "forwarded", "completed"), 3):
        ingest.ingest(
            source, event(context, kind, kind, sequence, parents=("review",), review="review")
        )
    state = ingest.action_state(source, action_id="action", action_digest=DIGEST)
    assert state.authenticated_completion and not state.missing_stages
    assert not state.causally_complete


def complete_trace(context, ingest, source, *, start=1, proposal_parents=()):
    previous = None
    for sequence, kind in enumerate(
        ("proposed", "reviewed", "reserved", "committed", "forwarded", "completed"), start
    ):
        parents = proposal_parents if previous is None else (previous,)
        review = None if kind in {"proposed", "reviewed"} else "reviewed"
        if review is not None:
            parents = tuple(dict.fromkeys((review, *parents)))
        ingest.ingest(
            source,
            event(
                context,
                kind,
                kind,
                sequence,
                source=source.source_id,
                parents=parents,
                review=review,
            ),
        )
        previous = kind


def test_transitive_parent_gaps_resolve_only_with_authenticated_backfill():
    for asserted_parent in (False, True):
        _, adapter, channel, context, ingest, source, _ = fixture()
        ingest.ingest(source, event(context, "external", "message_sent", 1, parents=("missing",)))
        complete_trace(context, ingest, source, start=2, proposal_parents=("external",))
        state = ingest.action_state(source, action_id="action", action_digest=DIGEST)
        assert state.unresolved_parents == (EventRef("tenant", "swarm", "missing"),)
        assert not state.causally_complete
        if asserted_parent:
            claims = ingest.bind_source(
                context, channel, adapter, source_id="claims", role="asserted"
            )
            ingest.ingest(
                claims,
                event(
                    context,
                    "missing",
                    "message_received",
                    1,
                    source="claims",
                    evidence_class="caller_asserted",
                ),
            )
        else:
            ingest.ingest(source, event(context, "missing", "message_received", 8))
        state = ingest.action_state(source, action_id="action", action_digest=DIGEST)
        assert not state.unresolved_parents
        assert state.causally_complete is (not asserted_parent)
        assert bool(state.untrusted_parents) is asserted_parent


def test_ancestor_stream_sequence_gaps_remain_visible_to_dependent_actions():
    _, adapter, channel, context, ingest, source, _ = fixture()
    ingest.ingest(source, event(context, "external", "message_sent", 3))
    second = ingest.bind_source(context, channel, adapter, source_id="second")
    complete_trace(context, ingest, second, proposal_parents=("external",))
    state = ingest.action_state(second, action_id="action", action_digest=DIGEST)
    assert state.sequence_incomplete and not state.causally_complete
    ingest.ingest(source, event(context, "earlier-one", "message_sent", 1))
    ingest.ingest(source, event(context, "earlier-two", "message_sent", 2))
    state = ingest.action_state(second, action_id="action", action_digest=DIGEST)
    assert not state.sequence_incomplete and state.causally_complete
