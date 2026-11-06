"""Bounded warm operation, input-size and retained-session measurements."""

import json
from pathlib import Path
import platform
import re
from time import perf_counter_ns

from ordin import ActionEnvelope, AgentGate
from ordin.action import MAX_ACTION_HISTORY, MAX_PARAMETER_STRING_LENGTH
from ordin.safety_benchmark import SafetyThresholds

from ._corpus_world import World
from .benchmark import latency, _implementation_digest


def _timed(operation):
    start = perf_counter_ns()
    value = operation()
    return perf_counter_ns() - start, value


def measure(*, revision: str, samples: int = 32, long_actions: int = 256):
    if (
        not re.fullmatch(r"[a-f0-9]{40}", revision)
        or type(samples) is not int
        or not 8 <= samples <= 256
        or type(long_actions) is not int
        or not 64 <= long_actions <= 1024
    ):
        raise ValueError("exact revision and bounded benchmark configuration required")
    thresholds = SafetyThresholds()
    results = []
    errors = []
    cold = []
    for count in (2, 5, 10):
        setup, world = _timed(lambda: World(count))
        cold.append({"agents": count, "world_setup_ms": setup / 1e6})
        actor = world.actors[0]
        baseline = AgentGate()
        action = ActionEnvelope.shell("git status --short")
        core = []
        swarm = []
        forward = []
        delta = []
        for index in range(samples + 8):
            plain, _ = _timed(lambda: baseline.evaluate_action(action))
            composed, decision = _timed(
                lambda: world.gate.evaluate_action(
                    actor.context,
                    action,
                    channel=actor.channel,
                    adapter=actor.adapter,
                    event_source=actor.source,
                )
            )

            def mediated():
                review = world.gateway.prepare(world.handles[index % count], action)
                if review.ticket is None:
                    raise ValueError("benign benchmark unexpectedly blocked")
                return world.gateway.forward(
                    world.handles[index % count], review.ticket, world.local_effect
                )

            elapsed, result = _timed(mediated)
            if not decision.may_execute or result.status != "completed":
                errors.append("benign-operation-blocked")
            if index >= 8:
                core.append(plain)
                swarm.append(composed)
                forward.append(elapsed)
                delta.append(composed - plain)
        result = {
            "agents": count,
            "core_review_ms": latency(core),
            "swarm_review_ms": latency(swarm),
            "owned_callback_forward_ms": latency(forward),
            "paired_review_overhead_ms": latency(delta),
            "difference_of_p95_ms": latency(swarm)["p95"] - latency(core)["p95"],
        }
        for label, values in (("core", core), ("swarm", swarm), ("forward", forward)):
            summary = latency(values)
            if summary["p95"] > thresholds.max_p95_ms or summary["p99"] > thresholds.max_p99_ms:
                errors.append(str(count) + "-actor-" + label + "-latency-threshold")
        results.append(result)
    sizes = []
    for length in (1024, 16384, MAX_PARAMETER_STRING_LENGTH):
        world = World(3)
        value = "SYNTHETIC_" + "x" * (length - 10)
        origin = world.collect(value=value)
        received = world.share(0, 1, origin, value=value)
        values = []
        for _ in range(samples):
            elapsed, result = _timed(lambda: world.assess_upload(1, received, value=value))
            values.append(elapsed)
            if result.status != "violated":
                errors.append("size-lineage-miss")
        summary = latency(values)
        if summary["p95"] > thresholds.max_p95_ms or summary["p99"] > thresholds.max_p99_ms:
            errors.append(str(length) + "-byte-lineage-latency-threshold")
        sizes.append({"input_bytes": len(value.encode()), "source_flow_ms": summary})
    oversized_refused = False
    try:
        ActionEnvelope("tool", "call", {"body": "x" * 65536})
    except ValueError:
        oversized_refused = True
    if not oversized_refused:
        errors.append("oversized-parameter-not-refused")
    world = World(2)
    timings = []
    capacity_reached = False
    capacity_refusal_no_effect = True
    for index in range(long_actions):

        def step():
            prepared = world.gateway.prepare(
                world.handles[index % 2], ActionEnvelope.shell("git status")
            )
            if prepared.ticket is None:
                raise ValueError("bounded benign session was blocked")
            return world.gateway.forward(
                world.handles[index % 2], prepared.ticket, world.local_effect
            )

        elapsed, result = _timed(step)
        if result.status != "completed":
            errors.append("long-session-unobserved-as-completed")
        timings.append(elapsed)
        if result.journal_gap:
            capacity_reached = True
            before = len(world.effects)
            refused = world.gateway.prepare(
                world.handles[index % 2], ActionEnvelope.shell("git status")
            )
            capacity_refusal_no_effect = refused.ticket is None and len(world.effects) == before
            break
    if capacity_reached and (
        len(world.events.snapshot()) != world.events._max_events or not capacity_refusal_no_effect
    ):
        errors.append("unsafe-event-capacity-refusal")
    sessions = [world.gateway._actors[handle].session for handle in world.handles]
    if any(value is None for value in sessions):
        raise ValueError("benchmark session unavailable")
    snapshots = [value.snapshot() for value in sessions if value is not None]
    retained = [len(value["history"]["actions"]) for value in snapshots]
    retained_bytes = sum(len(json.dumps(value, sort_keys=True).encode()) for value in snapshots)
    maximum = [MAX_ACTION_HISTORY for _ in world.handles]
    bounded = all(actual <= limit for actual, limit in zip(retained, maximum))
    if not bounded:
        errors.append("unbounded-retained-session")
    long_summary = latency(timings[-32:])
    if long_summary["p95"] > thresholds.max_p95_ms or long_summary["p99"] > thresholds.max_p99_ms:
        errors.append("long-session-latency-threshold")
    return {
        "schema_version": "ordin.swarm_overhead_report.v1",
        "revision": revision,
        "implementation_sha256": _implementation_digest(),
        "seed": 276,
        "environment": {"python": platform.python_version(), "platform": platform.platform()},
        "warmup_operations": 8,
        "samples_per_shape": samples,
        "cold_setup": cold,
        "thresholds": {
            "p95_ms": thresholds.max_p95_ms,
            "p99_ms": thresholds.max_p99_ms,
            "source": "unchanged_ordin_safety_benchmark_defaults",
        },
        "operation_shapes": results,
        "size_shapes": sizes,
        "capacity_bounds": {
            "max_parameter_string_characters": MAX_PARAMETER_STRING_LENGTH,
            "oversized_probe_characters": 65536,
            "oversized_probe_refused": oversized_refused,
        },
        "long_session": {
            "requested_actions": long_actions,
            "completed_actions": len(timings),
            "gateway_pending_capacity": world.gateway._pending_limit,
            "event_journal_capacity": world.events._max_events,
            "retained_event_count": len(world.events.snapshot()),
            "capacity_reached": capacity_reached,
            "capacity_refusal_no_effect": capacity_refusal_no_effect,
            "retained_actions": retained,
            "declared_history_limits": maximum,
            "retained_snapshot_bytes": retained_bytes,
            "bounded": bounded,
            "last_32_forward_ms": long_summary,
        },
        "errors": sorted(set(errors)),
        "ok": not errors,
        "execution_authority": False,
        "limitations": [
            "Warm owned callback operations, not arbitrary backend billing or physical kernel execution.",
            "Signed paired deltas retain timer noise; setup/cold startup is separate from per-operation overhead.",
            "Finite bounded samples and synthetic sizes are not production latency distributions.",
        ],
    }
