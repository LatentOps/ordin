"""Generated bounded schedules over original production objects, not a permissive model."""

from copy import copy
from dataclasses import replace
from itertools import permutations
import random

import pytest

from ordin import ActionEnvelope
from ordin.swarm import SwarmGate, SwarmPolicy, SwarmRule
from ordin.swarm._corpus_world import World, CANARY
from ordin.swarm.corpus_controls import run_control
from ordin.swarm.schedule import ScheduledOperation, explore


def test_scheduler_exhaustive_small_inventory_and_seed_reproducibility():
    operations = tuple(ScheduledOperation("o" + str(i), i, "reserve") for i in range(3))
    first = explore(operations, agents=3, seed=276)
    assert {tuple(v.operation_id for v in row) for row in first.schedules} == set(
        permutations(("o0", "o1", "o2"))
    )
    assert first.digest == explore(operations, agents=3, seed=276).digest and not first.truncated
    limited = explore(operations, agents=3, seed=276, limit=2)
    assert limited.truncated and len(limited.schedules) == 2


@pytest.mark.parametrize("agents", range(2, 11))
def test_budget_no_overspend_across_seeded_actor_interleavings(tmp_path, agents):
    result = run_control(
        "budget-race", agents=agents, seed=agents * 276, workspace=tmp_path / "run"
    )
    assert result["actual"] == "deny" and all(result["checks"].values())
    assert result["facts"]["maximum_reserved"] <= 100
    if agents > 5:
        assert result["facts"]["truncated"]


@pytest.mark.parametrize("seed", range(8))
def test_no_decision_downgrade_under_generated_operator_constraints(seed):
    rng = random.Random(seed)
    world = World(2 + rng.randrange(9))
    rank = {"execute": 0, "escalate": 1, "deny": 2}
    baseline_rank = {"allow": 0, "warn": 1, "ask": 1, "block": 2}
    commands = (
        "git status --short",
        "rm -rf /fixture-owned/canaries",
        "future_opaque_tool --unknown",
    )
    for index in range(12):
        actor = world.actors[rng.randrange(len(world.actors))]
        restriction = rng.choice(tuple(rank))
        gate = SwarmGate(
            world.registry,
            policy=SwarmPolicy("generated", "1", rules=(SwarmRule("operator", restriction),)),
        )
        action = ActionEnvelope.shell(rng.choice(commands), action_id="property-" + str(index))
        result = gate.evaluate_action(
            actor.context, action, channel=actor.channel, adapter=actor.adapter
        )
        assert rank[result.disposition] >= max(
            rank[restriction], baseline_rank[result.review.decision]
        )


@pytest.mark.parametrize("agents", (2, 3, 5, 10))
def test_original_sender_and_per_tenant_context_cannot_be_substituted(agents):
    left, right = World(agents, tenant="left"), World(agents, tenant="right")
    left.emit(0, "message_sent")
    event = left.events.snapshot()[0].event
    before = left.events.snapshot()
    for sender, candidate in (
        (copy(left.actors[0].source), event),
        (right.actors[0].source, event),
        (left.actors[0].source, replace(event, identity=right.actors[0].context.identity)),
        (left.actors[1].source, event),
    ):
        with pytest.raises(ValueError):
            left.events.ingest(sender, candidate)
    assert left.events.snapshot() == before and not right.events.snapshot()


@pytest.mark.parametrize("kind", ("epoch", "end", "replacement"))
def test_no_stale_authority_can_forward_owned_effect(kind):
    world = World(3)
    actor = world.actors[0]
    prepared = world.gateway.prepare(world.handles[0], ActionEnvelope.shell("git status"))
    assert prepared.ticket is not None
    if kind == "epoch":
        world.registry.advance_policy_epoch(1)
    elif kind == "end":
        world.registry.end(actor.context, actor.channel, actor.adapter)
    else:
        adapter = object()
        channel = world.registry.bind_channel(adapter, runtime_id="corpus-runtime-0")
        world.registry.restart(
            actor.context,
            actor.channel,
            actor.adapter,
            new_channel=channel,
            new_adapter=adapter,
            session_id="new",
        )
    with pytest.raises(ValueError):
        world.gateway.forward(world.handles[0], prepared.ticket, world.local_effect)
    assert not world.effects


@pytest.mark.parametrize("seed", range(8))
def test_private_lineage_join_is_monotonic_across_generated_handoffs(seed):
    rng = random.Random(seed)
    world = World(2 + rng.randrange(9))
    labels = tuple(sorted(rng.sample(("secret", "private_code", "pii"), 1 + rng.randrange(3))))
    handle = world.collect(labels=labels)
    current = 0
    for _ in range(8):
        following = rng.choice([i for i in range(len(world.actors)) if i != current])
        handle = world.share(current, following, handle)
        assert set(labels) <= set(world.flow._record(handle).sensitivity.labels)
        current = following
    result = world.assess_upload(current, handle, value=CANARY)
    assert result.status == "violated" and result.as_dict()["observed_exfiltration"] == "unknown"


def test_bad_schedule_inventory_is_refused_before_exploration():
    for operations in (
        (ScheduledOperation("same", 0, "reserve"), ScheduledOperation("same", 1, "reserve")),
        (ScheduledOperation("cycle", 0, "reserve", ("cycle",)),),
        (ScheduledOperation("missing", 0, "reserve", ("unknown",)),),
    ):
        with pytest.raises(ValueError):
            explore(operations, agents=2)


@pytest.mark.parametrize("agents", (2, 5, 10))
def test_epoch_fence_and_commit_order_has_an_independent_state_oracle(agents):
    operations = (
        ScheduledOperation("prepare", 0, "prepare"),
        ScheduledOperation("fence", 1, "advance-epoch", ("prepare",)),
        ScheduledOperation("commit", 0, "commit", ("prepare",)),
    )
    schedules = explore(operations, agents=agents, seed=276)
    assert len(schedules.schedules) == 2 and not schedules.truncated
    for schedule in schedules.schedules:
        world = World(agents)
        ticket = None
        fenced = False
        for operation in schedule:
            if operation.kind == "prepare":
                ticket = world.gateway.prepare(
                    world.handles[0], ActionEnvelope.shell("git status")
                ).ticket
                assert ticket is not None
            elif operation.kind == "advance-epoch":
                world.registry.advance_policy_epoch(1)
                fenced = True
            elif fenced:
                with pytest.raises(ValueError):
                    world.gateway.forward(world.handles[0], ticket, world.local_effect)
                assert not world.effects
            else:
                result = world.gateway.forward(world.handles[0], ticket, world.local_effect)
                assert result.status == "completed" and len(world.effects) == 1


@pytest.mark.parametrize("agents", (2, 5, 10))
def test_tenant_bound_budget_and_lineage_objects_do_not_cross_boundaries(agents):
    from ordin.swarm.budgets import BudgetCost
    from ordin.swarm.source_flow import LineageUse

    left, right = World(agents, tenant="left"), World(agents, tenant="right")
    actor = left.actors[0]
    action = ActionEnvelope.shell("git status", action_id="same-id")
    ticket = left.ledger.reserve(
        actor.context,
        action,
        channel=actor.channel,
        adapter=actor.adapter,
        idempotency_key="same-id",
        costs=(BudgetCost("requests", 1),),
    )
    other = right.actors[0]
    with pytest.raises(ValueError):
        right.ledger.begin_forward(
            ticket, other.context, action, channel=other.channel, adapter=other.adapter
        )
    origin = left.collect()
    with pytest.raises(ValueError):
        right.flow.assess(
            other.source,
            right.upload(),
            sink_id="external",
            uses=(LineageUse(origin, ("parameters", "body", "params", "value")),),
            complete=True,
        )
    assert not left.effects and not right.effects
