"""Deterministic crash/retry/partition/order faults preserve conservative authority."""

from dataclasses import replace

import pytest

from ordin import ActionEnvelope
from ordin.swarm import SwarmGate, SwarmPolicy
from ordin.swarm._corpus_world import World
from ordin.swarm.corpus_controls import run_control


@pytest.mark.parametrize(
    "scenario",
    ("partial-execution", "crash-recovery", "coordinator-outage", "multi-host-partition"),
)
def test_faults_never_report_unobserved_as_completed_and_preserve_holds(tmp_path, scenario):
    result = run_control(scenario, agents=3, seed=276, workspace=tmp_path / scenario)
    assert result["actual"] == "unknown" and all(result["checks"].values())
    assert result["backend_facts"]["outcome"] == "unknown"
    assert not result["backend_facts"]["physical_enforcement"]


@pytest.mark.parametrize("agents", (2, 3, 5, 10))
def test_out_of_order_collector_frames_are_not_relabelled_continuous(agents):
    world = World(agents)
    world.emit(0, "message_sent")
    actor = world.actors[0]
    first = world.events.snapshot()[0].event
    third = replace(first, event_id="third", source_sequence=3)
    receipt = world.events.ingest(actor.source, third)
    assert receipt.gaps
    gate = SwarmGate(
        world.registry,
        events=world.events,
        policy=SwarmPolicy("complete-collection", "1", required_checks=("source_flow",)),
    )
    result = gate.evaluate_action(
        actor.context,
        ActionEnvelope.shell("git status"),
        channel=actor.channel,
        adapter=actor.adapter,
        event_source=actor.source,
    )
    assert not result.may_execute
    second = replace(first, event_id="second", source_sequence=2)
    world.events.ingest(actor.source, second)
    assert not gate.binding_matches(
        result,
        actor.context,
        ActionEnvelope.shell("git status"),
        channel=actor.channel,
        adapter=actor.adapter,
        event_source=actor.source,
    )


@pytest.mark.parametrize("seed", (0, 1, 42, 276))
def test_identical_cross_actor_action_bytes_keep_narrow_scope(tmp_path, seed):
    result = run_control(
        "narrow-action-collision", agents=3, seed=seed, workspace=tmp_path / "scope"
    )
    assert result["actual"] == "deny" and all(result["checks"].values())
    assert not result["backend_facts"]["physical_enforcement"]
