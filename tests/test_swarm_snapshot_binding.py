"""Specialized fingerprints retain the exact generic canonical digest."""

from copy import deepcopy
import pytest
from ordin._runtime_json import digest
import ordin.swarm.ingest as ingest_module
from ordin.swarm.ingest import _snapshot_binding_digest
from tests.test_swarm_events import fixture, event


@pytest.mark.parametrize("count", [0, 683, 4096])
@pytest.mark.parametrize("scope", [None, ("tenant", "swarm"), ("ténant", "群")])
def test_owned_primitive_fingerprint_matches_generic_digest_at_capacity(count, scope):
    roles = ("gateway", "collector", "asserted")
    events = [("event-" + str(i), format(i, "064x"), roles[i % 3]) for i in range(count)]
    streams = [
        ("source-" + str(i), roles[i % 3], "registry", "a" * 64, 2**53 - 1 - i) for i in range(10)
    ]
    assert _snapshot_binding_digest(scope, events, streams) == digest(
        {"scope": scope, "events": events, "streams": streams}
    )


def test_every_changed_scope_order_role_identity_generation_and_sequence_changes_binding():
    original = {
        "scope": ("tenant", "swarm"),
        "events": [("a", "a" * 64, "gateway"), ("b", "b" * 64, "asserted")],
        "streams": [
            ("a", "gateway", "registry", "c" * 64, 1),
            ("b", "asserted", "registry", "d" * 64, 2),
        ],
    }
    before = _snapshot_binding_digest(**original)
    variants = []
    for key, value in (
        ("scope", ("other", "swarm")),
        ("events", list(reversed(original["events"]))),
        ("streams", list(reversed(original["streams"]))),
        ("events", [("a", "a" * 64, "asserted"), original["events"][1]]),
        ("events", [("a", "f" * 64, "gateway"), original["events"][1]]),
        ("streams", [("a", "gateway", "registry", "e" * 64, 1), original["streams"][1]]),
        ("streams", [("a", "gateway", "registry", "c" * 64, 2), original["streams"][1]]),
    ):
        changed = deepcopy(original)
        changed[key] = value
        variants.append(changed)
    for changed in variants:
        assert _snapshot_binding_digest(**changed) == digest(changed)
        assert _snapshot_binding_digest(**changed) != before
    with pytest.raises(ValueError):
        _snapshot_binding_digest(None, [], [("x", "gateway", "r", "a" * 64, float("nan"))])


def test_real_snapshot_still_fingerprints_all_current_records_and_authenticates_scope(monkeypatch):
    registry, _, _, context, ingestor, source, _ = fixture()
    original = _snapshot_binding_digest
    calls = []

    def compare(scope, events, streams):
        assert type(scope) is tuple and all(type(v) is str for v in scope)
        assert all(
            type(row) is tuple and len(row) == 3 and all(type(v) is str for v in row)
            for row in events
        )
        assert all(
            type(row) is tuple
            and len(row) == 5
            and all(type(v) is str for v in row[:4])
            and type(row[4]) is int
            for row in streams
        )
        result = original(scope, events, streams)
        assert result == digest({"scope": scope, "events": events, "streams": streams})
        calls.append((len(events), len(streams)))
        return result

    monkeypatch.setattr(ingest_module, "_snapshot_binding_digest", compare)
    before = ingestor.snapshot_binding(source, context)
    ingestor.ingest(source, event(context, "first", "proposed", 1))
    assert ingestor.snapshot_binding(source, context) != before
    adapter = object()
    channel = registry.bind_channel(adapter, runtime_id="second")
    other = registry.enroll(channel, adapter, agent_id="other", session_id="other")
    ingestor.bind_source(other, channel, adapter, source_id="second", role="asserted")
    ingestor.snapshot_binding(source, context)
    assert calls == [(0, 1), (1, 1), (1, 2)]
    with pytest.raises(ValueError):
        ingestor.snapshot_binding(source, other)
    registry.advance_policy_epoch(1)
    with pytest.raises(ValueError):
        ingestor.snapshot_binding(source, context)
