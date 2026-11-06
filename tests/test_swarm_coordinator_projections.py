"""Protected artifact floors and temporal facts persist without live restoration."""

import hashlib
import json

import pytest

from ordin.assurance import register_instruction_origin
from ordin.swarm.artifact_store import MemoryArtifactStore
from ordin.swarm.causal_graph import SwarmCausalGraph
from ordin.swarm.coordinator_store import CoordinatorRejected
from ordin.swarm.events import SwarmEvent
from ordin.swarm.ingest import SwarmEventIngestor
from ordin.swarm.memory import ArtifactAddress, SwarmArtifactGateway
from ordin.swarm.source_flow import EgressSink, Sensitivity, SwarmSourceFlow
from ordin.swarm.temporal import SwarmTemporalEngine
from ordin.swarm.temporal_policy import default_swarm_temporal_policy
from tests.test_swarm_coordinator import configured


def protected_storage(data):
    enrollment = data["auth"].require(data["channels"]["child"], role="workload")
    context = enrollment.context
    ingest = SwarmEventIngestor(data["registry"])
    source = ingest.bind_source(
        context, enrollment.registry_channel, enrollment.adapter, source_id="artifact-child"
    )
    graph = SwarmCausalGraph(ingest, source, context)
    flow = SwarmSourceFlow(
        graph,
        sinks=(
            EgressSink(
                "external",
                "network",
                "network",
                "jsonrpc.request",
                ("parameters", "url"),
                "https://fixture.invalid/rpc",
                ("public",),
            ),
        ),
        operator=data["operator"],
    )
    flow.bind_actor(source, context, enrollment.source)
    gateway = SwarmArtifactGateway(
        flow,
        backend=MemoryArtifactStore(),
        operator=data["operator"],
        workspaces=("work",),
        clock=data["clock"],
    )
    temporal = SwarmTemporalEngine(
        graph, default_swarm_temporal_policy(), flow=flow, clock=data["clock"]
    )
    temporal.cover(source, complete_from=data["clock"]())
    # Protected host configuration, retaining actual objects rather than JSON.
    scope = data["coordinator"]._scope(data["scope"])
    scope.artifacts, scope.temporal = gateway, temporal
    address = ArtifactAddress("tenant", "swarm", "work", "artifacts", "report")

    def collect(text, labels=("secret",)):
        sequence = ingest._source(source).contiguous + 1
        key = "input-" + str(sequence)
        ingest.ingest(
            source,
            SwarmEvent(
                key,
                "artifact_read",
                context.registry_id,
                context.identity,
                source.source_id,
                sequence,
                data["clock"](),
                "host_authenticated",
                0,
                resource_digests=(hashlib.sha256(text.encode()).hexdigest(),),
            ),
        )
        origin = register_instruction_origin(
            enrollment.source,
            origin_id=key,
            kind="repository_file",
            classification="sensitive" if "secret" in labels else "public",
            content=text,
        )
        handle = flow.register(source, event_id=key, origin=origin, sensitivity=Sensitivity(labels))
        temporal.record_event(source, event_id=key, lineage=(handle,))
        return handle

    return gateway, temporal, source, address, collect


def test_artifact_write_delete_labels_and_temporal_projection_survive_reopen(tmp_path):
    with configured(tmp_path) as data:
        gateway, temporal, source, address, collect = protected_storage(data)
        coordinator, scope = data["coordinator"], data["scope"]
        text = "SYNTHETIC_SECRET_MUST_NOT_ENTER_DURABLE_JOURNAL"
        metadata = coordinator.artifact_write(
            scope, source, address, text, expected_version=0, inputs=(collect(text),)
        )
        assert metadata.version == 1
        coordinator.artifact_delete(scope, source, address, expected_version=1)
        checkpoint = coordinator.checkpoint(scope, control=data["control"])
        assert any(
            row["deleted"] and row["version"] == 1 and row["labels"] == ["secret"]
            for row in checkpoint["projection"]["artifacts"].values()
        )
        assert (
            checkpoint["projection"]["temporal"]["facts"]
            and checkpoint["projection"]["temporal"]["historical_only"]
        )
        assert (
            text not in json.dumps(checkpoint)
            and text.encode() not in data["store"].path.read_bytes()
        )
        assert coordinator.history(scope, control=data["control"]) == checkpoint
        # A blank gateway cannot replace the durable labels/version/tombstone.
        gateway._resources.clear()
        with pytest.raises(CoordinatorRejected, match="artifact_history"):
            coordinator.artifact_write(
                scope,
                source,
                address,
                "public",
                expected_version=0,
                inputs=(collect("public", ("public",)),),
            )
        assert coordinator.history(scope, control=data["control"]) == checkpoint


def test_partial_artifact_backing_failure_retains_unknown_intent(tmp_path, monkeypatch):
    with configured(tmp_path) as data:
        gateway, _, source, address, collect = protected_storage(data)
        text = "synthetic-private-input"
        handle = collect(text)

        def partial(*arguments, **keywords):
            raise OSError("simulated partial backing write")

        monkeypatch.setattr(gateway._backend, "write", partial, raising=False)
        # MemoryArtifactStore uses put, while the gateway catches partial effects.
        monkeypatch.setattr(gateway._backend, "put", partial)
        with pytest.raises(ValueError):
            data["coordinator"].artifact_write(
                data["scope"], source, address, text, expected_version=0, inputs=(handle,)
            )
        with data["store"].transaction() as transaction:
            assert transaction.scope(data["scope"].scope_key)["artifact_pending"]
        assert data["coordinator"].status(data["scope"], control=data["control"])[
            "journal_incomplete"
        ]


def test_restored_temporal_json_never_recreates_live_facts(tmp_path):
    with configured(tmp_path) as data:
        _, temporal, _, _, collect = protected_storage(data)
        collect("safe-public", ("public",))
        coordinator, scope = data["coordinator"], data["scope"]
        checkpoint = coordinator.checkpoint(scope, control=data["control"])
        temporal._facts.clear()
        with pytest.raises(CoordinatorRejected, match="temporal_history"):
            with data["store"].transaction() as transaction:
                coordinator._owner(transaction, scope)
        assert coordinator.history(scope, control=data["control"]) == checkpoint
