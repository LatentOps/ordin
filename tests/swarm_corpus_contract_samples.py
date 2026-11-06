"""Canonical corpus serialization and a data example of the timing contract."""

from ordin.swarm.benchmark import evaluate, load_corpus, latency


def corpus_contract_samples():
    timing = latency([1000000] * 8)
    overhead = {
        "schema_version": "ordin.swarm_overhead_report.v1",
        "revision": "a" * 40,
        "implementation_sha256": "b" * 64,
        "seed": 276,
        "environment": {"python": "3.12", "platform": "synthetic_schema_example"},
        "warmup_operations": 8,
        "samples_per_shape": 8,
        "cold_setup": [{"agents": n, "world_setup_ms": 1.0} for n in (2, 5, 10)],
        "thresholds": {
            "p95_ms": 250.0,
            "p99_ms": 500.0,
            "source": "unchanged_ordin_safety_benchmark_defaults",
        },
        "operation_shapes": [
            {
                "agents": n,
                "core_review_ms": timing,
                "swarm_review_ms": timing,
                "owned_callback_forward_ms": timing,
                "paired_review_overhead_ms": latency([0] * 8),
                "difference_of_p95_ms": 0.0,
            }
            for n in (2, 5, 10)
        ],
        "size_shapes": [{"input_bytes": n, "source_flow_ms": timing} for n in (1024, 16384, 32768)],
        "capacity_bounds": {
            "max_parameter_string_characters": 32768,
            "oversized_probe_characters": 65536,
            "oversized_probe_refused": True,
        },
        "long_session": {
            "requested_actions": 64,
            "completed_actions": 64,
            "gateway_pending_capacity": 256,
            "event_journal_capacity": 4096,
            "retained_event_count": 384,
            "capacity_reached": False,
            "capacity_refusal_no_effect": True,
            "retained_actions": [32, 32],
            "declared_history_limits": [32, 32],
            "retained_snapshot_bytes": 1024,
            "bounded": True,
            "last_32_forward_ms": timing,
        },
        "errors": [],
        "ok": True,
        "execution_authority": False,
        "limitations": ["Synthetic schema example; these numbers are not a performance result."],
    }
    return {
        "swarm_corpus": load_corpus(),
        "swarm_corpus_report": evaluate(revision="a" * 40),
        "swarm_overhead_report": overhead,
    }
