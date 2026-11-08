"""Bounded original byte custody and authenticated local agent handoffs."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from threading import RLock
from uuid import uuid4

from ordin.assurance import register_instruction_origin
from ordin.swarm import (
    EgressSink,
    Sensitivity,
    SwarmCausalGraph,
    SwarmEvent,
    SwarmEventIngestor,
    SwarmMessageGateway,
    SwarmSourceFlow,
)
from ordin.swarm.messages import DESTINATION_PATH


SENSITIVE_OUTPUT = ("pii", "private_code", "secret")


@dataclass(frozen=True, slots=True)
class HostResource:
    reference: str
    owner: str
    content: str = field(repr=False)
    labels: tuple[str, ...]
    lineage: object = field(repr=False)
    context: object = field(repr=False)


class HostLineage:
    """Host-retained resources; serialized labels and references issue no rights.

    Read classifications are explicit operator declarations. Agent-produced
    bytes are conservatively classified with every supported sensitive category.
    This records actual collected bytes and handoffs, not model understanding or
    complete taint tracking of a caller's unobserved environment.
    """

    def __init__(self, authority):
        self.authority = authority
        self.profile = authority.profile
        maximum = min(16384, max(64, self.profile.limits.requests * 4))
        self.events = SwarmEventIngestor(authority.registry, max_events=maximum)
        self.sources = {
            actor.agent_id: self.events.bind_source(
                authority.contexts[actor.agent_id],
                authority.registry_channels[actor.agent_id],
                authority.adapters[actor.agent_id],
                source_id="host-data-" + actor.agent_id,
            )
            for actor in self.profile.actors
        }
        first = self.profile.actors[0].agent_id
        graph = SwarmCausalGraph(self.events, self.sources[first], authority.contexts[first])
        self._routes = {}
        sinks = []
        for actor in self.profile.actors:
            for recipient in actor.peers:
                key = (actor.agent_id, recipient)
                sink_id = "handoff-" + hashlib.sha256(repr(key).encode()).hexdigest()[:32]
                self._routes[key] = sink_id
                sinks.append(
                    EgressSink(
                        sink_id,
                        "message",
                        "tool",
                        "call",
                        DESTINATION_PATH,
                        recipient,
                        ("pii", "private_code", "public", "secret"),
                    )
                )
        self.flow = SwarmSourceFlow(graph, operator=authority.operator, sinks=tuple(sinks))
        for actor in self.profile.actors:
            name = actor.agent_id
            self.flow.bind_actor(
                self.sources[name], authority.contexts[name], authority.sources[name]
            )
        self.messages = SwarmMessageGateway(self.flow, clock=authority.clock)
        self._lock = RLock()
        self._inboxes = {actor.agent_id: [] for actor in self.profile.actors}
        self._delivered = {}
        self._resources: dict[str, HostResource] = {}
        self._bytes = 0
        self._pending_bytes = 0
        self._pending_slots = 0
        self._maximum_resources = min(4096, self.profile.limits.requests)
        self._maximum_bytes = self.profile.limits.output_bytes
        self._peers = {
            actor.agent_id: self.messages.register(
                authority.contexts[actor.agent_id],
                self.sources[actor.agent_id],
                authority.registry_channels[actor.agent_id],
                authority.adapters[actor.agent_id],
                lambda message, name=actor.agent_id: self._enqueue(name, message),
            )
            for actor in self.profile.actors
        }
        self._channels = {
            key: self.messages.grant(
                self._peers[key[0]],
                self._peers[key[1]],
                sink_id=sink,
                lifetime=min(self.profile.limits.lifetime_seconds, 600),
            )
            for key, sink in self._routes.items()
        }

    def _capacity(self, content: str) -> int:
        if type(content) is not str:
            raise ValueError("managed resource requires UTF-8 text")
        count = len(content.encode("utf-8"))
        if (
            count > 65536
            or len(self._resources) + self._pending_slots >= self._maximum_resources
            or self._bytes + self._pending_bytes + count > self._maximum_bytes
        ):
            raise ValueError("managed byte custody capacity reached")
        return count

    def ensure_capacity(self, maximum: int = 65536) -> None:
        """Conservative admission before a tool effect that may return bytes."""
        with self._lock:
            if (
                type(maximum) is not int
                or not 0 <= maximum <= 65536
                or len(self._resources) + self._pending_slots >= self._maximum_resources
                or self._bytes + self._pending_bytes + maximum > self._maximum_bytes
            ):
                raise ValueError("managed byte custody capacity reached")

    def labels_for_file(self, name: str) -> tuple[str, ...]:
        # Writable data never becomes public after restart or a changed body.
        if any(name in actor.write_files for actor in self.profile.actors):
            return SENSITIVE_OUTPUT
        return (next(file.label for file in self.profile.files if file.name == name),)

    def capture(
        self, actor: str, content: str, labels: tuple[str, ...], *, kind="artifact_read"
    ) -> HostResource:
        with self._lock:
            count = self._capacity(content)
            source = self.sources[actor]
            context = self.authority.contexts[actor]
            host = self.authority.sources[actor]
            sensitivity = Sensitivity(tuple(sorted(labels)))
            event_id = "collected-" + uuid4().hex
            with self.events._lock:
                current = self.events._source(source)
                event = SwarmEvent(
                    event_id,
                    kind,
                    context.registry_id,
                    context.identity,
                    source.source_id,
                    current.contiguous + 1,
                    self.authority.clock(),
                    evidence_class="host_authenticated",
                    resource_digests=(hashlib.sha256(content.encode("utf-8")).hexdigest(),),
                )
                self.events.ingest(source, event)
            origin = register_instruction_origin(
                host,
                origin_id=event_id,
                kind="repository_file" if kind.startswith("artifact_") else "mcp_result",
                classification=(
                    "unknown"
                    if not sensitivity.known
                    else "sensitive"
                    if sensitivity.sensitive
                    else "public"
                ),
                content=content,
            )
            lineage = self.flow.register(
                source, event_id=event_id, origin=origin, sensitivity=sensitivity
            )
            result = HostResource(
                "resource-" + uuid4().hex, actor, content, sensitivity.labels, lineage, context
            )
            self._resources[result.reference] = result
            self._bytes += count
            return result

    def require(self, actor: str, reference: str) -> HostResource:
        if type(reference) is not str or len(reference) > 128:
            raise ValueError("invalid managed resource reference")
        with self._lock:
            value = self._resources.get(reference)
            if (
                value is None
                or value.owner != actor
                or value.context is not self.authority.contexts[actor]
            ):
                raise ValueError("foreign, stale or missing managed resource")
            self.events._source(self.sources[actor])
            self.flow._record(value.lineage)
            return value

    def _enqueue(self, actor, message):
        # Called only by the original message gateway after its admission checks.
        with self._lock:
            if len(self._inboxes[actor]) >= 64:
                raise ValueError("managed inbox capacity reached")
            self._inboxes[actor].append(message)

    def handoff(self, actor: str, reference: str, recipient: str) -> dict:
        with self._lock:
            value = self.require(actor, reference)
            key = (actor, recipient)
            if key not in self._channels:
                raise ValueError("unconfigured managed peer route")
            count = self._capacity(value.content)
            if len(self._inboxes[recipient]) >= 64:
                raise ValueError("managed inbox capacity reached")
            # Reserve before delivery. A lost acknowledgement retains the hold;
            # an ambiguous send cannot free space for another delivery.
            self._pending_bytes += count
            self._pending_slots += 1
            outcome = self.messages.send(
                self._peers[actor],
                self._channels[key],
                value.content,
                inputs=(value.lineage,),
            )
            if outcome.recipient_lineage is None:
                raise ValueError("managed handoff outcome is unresolved")
            self._delivered[outcome.envelope_digest] = (
                recipient,
                outcome.recipient_lineage,
                value.labels,
                count,
            )
            return {
                "status": "completed",
                "delivery": outcome.status,
                "receiver_execution": "unknown",
                "labels": list(value.labels),
            }

    def receive(self, actor: str) -> dict:
        with self._lock:
            inbox = self._inboxes[actor]
            if not inbox:
                return {"status": "completed", "messages": []}
            message = inbox[0]
            delivered = self._delivered.get(message.envelope.digest)
            if delivered is None or delivered[0] != actor:
                raise ValueError("managed message acknowledgement is unresolved")
            row = self.flow._record(delivered[1])
            count = len(message.body.encode("utf-8"))
            if (
                count != delivered[3]
                or count != row.byte_length
                or hashlib.sha256(message.body.encode("utf-8")).hexdigest() != row.content_digest
            ):
                raise ValueError("managed message bytes changed after acceptance")
            result = HostResource(
                "resource-" + uuid4().hex,
                actor,
                message.body,
                tuple(delivered[2]),
                delivered[1],
                self.authority.contexts[actor],
            )
            self._resources[result.reference] = result
            self._bytes += count
            self._pending_bytes -= count
            self._pending_slots -= 1
            inbox.pop(0)
            self._delivered.pop(message.envelope.digest)
            return {
                "status": "completed",
                "messages": [
                    {
                        "content": result.content,
                        "resource_ref": result.reference,
                        "labels": list(result.labels),
                        "instruction_authority": "data",
                    }
                ],
            }

    def status(self, actor: str) -> dict:
        with self._lock:
            return {
                "retained_resources": sum(
                    value.owner == actor for value in self._resources.values()
                ),
                "inbox_messages": len(self._inboxes[actor]),
                "retained_bytes_total": self._bytes + self._pending_bytes,
                "uncertain_handoff_holds": self._pending_slots - len(self._delivered),
                "capacity_bytes": self._maximum_bytes,
                "complete_taint_tracking": False,
            }


__all__ = ["HostLineage", "HostResource", "SENSITIVE_OUTPUT"]
