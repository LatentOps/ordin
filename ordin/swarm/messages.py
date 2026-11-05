"""Authenticated bounded inter-agent data delivery, not instruction/execution authority."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from threading import RLock
import time
from typing import Any, Callable, Mapping
from uuid import uuid4

from ordin.action import ActionEnvelope
from ordin._runtime_json import digest
from ordin.schema import validate_named_schema

from .events import EventRef, SwarmEvent, _hex
from .identity import HostChannel
from .ingest import HostEventSource
from .models import SwarmContext, SwarmIdentity, counter, identifier, timestamp
from .source_flow import LineageHandle, LineageUse, SwarmSourceFlow

BODY_PATH = ("parameters", "arguments", "body")
DESTINATION_PATH = ("parameters", "arguments", "destination")


@dataclass(frozen=True, slots=True)
class SwarmMessageEnvelope:
    message_id: str
    sender: SwarmIdentity
    destination: SwarmIdentity
    task_id: str | None
    sequence: int
    issued_at: float
    expires_at: float
    content_class: str
    content_digest: str
    byte_length: int
    parent_event_ids: tuple[EventRef, ...]
    source_lineage: tuple[str, ...]
    labels: tuple[str, ...]

    def __post_init__(self) -> None:
        identifier(self.message_id, "message_id")
        if type(self.sender) is not SwarmIdentity or type(self.destination) is not SwarmIdentity:
            raise ValueError("typed message identities required")
        self.sender.__post_init__()
        self.destination.__post_init__()
        if self.task_id is not None:
            identifier(self.task_id, "task_id")
        if self.task_id != self.sender.task_id:
            raise ValueError("message task must match its enrolled sender")
        if (self.sender.tenant_id, self.sender.swarm_id) != (
            self.destination.tenant_id,
            self.destination.swarm_id,
        ):
            raise ValueError("cross-scope message identity")
        counter(self.sequence, "message_sequence")
        if (
            self.sequence == 0
            or not 0 < timestamp(self.expires_at) - timestamp(self.issued_at) <= 600
        ):
            raise ValueError("invalid message sequence or lifetime")
        _hex(self.content_digest, "message content digest")
        if type(self.byte_length) is not int or not 0 <= self.byte_length <= 65536:
            raise ValueError("message size limit exceeded")
        if type(self.content_class) is not str or self.content_class not in {
            "data",
            "task_handoff",
            "tool_result",
        }:
            raise ValueError("message cannot confer instruction or policy authority")
        if (
            type(self.parent_event_ids) is not tuple
            or not 1 <= len(self.parent_event_ids) <= 8
            or any(type(v) is not EventRef for v in self.parent_event_ids)
            or len(set(self.parent_event_ids)) != len(self.parent_event_ids)
            or type(self.source_lineage) is not tuple
            or not 1 <= len(self.source_lineage) <= 8
            or type(self.labels) is not tuple
        ):
            raise ValueError("invalid bounded message lineage")
        for parent in self.parent_event_ids:
            parent.__post_init__()
            if (parent.tenant_id, parent.swarm_id) != (self.sender.tenant_id, self.sender.swarm_id):
                raise ValueError("cross-scope message parent")
        for value in self.source_lineage:
            _hex(value, "message lineage digest")
        if validate_named_schema("swarm_message", self.as_dict()):
            raise ValueError("invalid bounded swarm message envelope")

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "ordin.swarm_message.v1",
            "message_id": self.message_id,
            "sender": self.sender.as_dict(),
            "destination": self.destination.as_dict(),
            "task_id": self.task_id,
            "sequence": self.sequence,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "content_class": self.content_class,
            "content_digest": self.content_digest,
            "byte_length": self.byte_length,
            "parent_event_ids": [v.as_dict() for v in self.parent_event_ids],
            "source_lineage": list(self.source_lineage),
            "labels": list(self.labels),
            "instruction_authority": "data",
            "execution_authority": False,
        }

    @property
    def digest(self) -> str:
        self.__post_init__()
        return digest(self.as_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> SwarmMessageEnvelope:
        """Parse metadata only. Authentication still requires original peer/channel handles."""
        try:
            if type(value) is not dict or len(json.dumps(value).encode()) > 16384:
                raise ValueError("invalid message")
            if validate_named_schema("swarm_message", value):
                raise ValueError("invalid message")
            return cls(
                value["message_id"],
                SwarmIdentity(**value["sender"]),
                SwarmIdentity(**value["destination"]),
                value["task_id"],
                value["sequence"],
                value["issued_at"],
                value["expires_at"],
                value["content_class"],
                value["content_digest"],
                value["byte_length"],
                tuple(EventRef(**v) for v in value["parent_event_ids"]),
                tuple(value["source_lineage"]),
                tuple(value["labels"]),
            )
        except (KeyError, TypeError, ValueError, UnicodeError, RecursionError, OverflowError):
            raise ValueError("invalid bounded swarm message envelope") from None


@dataclass(frozen=True, eq=False, slots=True)
class MessagePeer:
    peer_id: str


@dataclass(frozen=True, eq=False, slots=True)
class MessageChannel:
    channel_id: str


@dataclass(frozen=True, slots=True)
class PrivateMessage:
    envelope: SwarmMessageEnvelope
    body: str = field(repr=False)

    @property
    def instruction_authority(self) -> str:
        return "data"


@dataclass(frozen=True, slots=True)
class MessageOutcome:
    status: str
    reason_code: str
    envelope_digest: str
    recipient_lineage: LineageHandle | None = field(default=None, repr=False, compare=False)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "ordin.swarm_message_outcome.v1",
            "status": self.status,
            "reason_code": self.reason_code,
            "envelope_digest": self.envelope_digest,
            "receiver_execution": "unknown",
            "execution_authority": False,
        }


@dataclass(frozen=True)
class _Peer:
    handle: MessagePeer
    context: SwarmContext
    source: HostEventSource
    channel: HostChannel
    adapter: object
    inbox: Callable[[PrivateMessage], Any]


@dataclass
class _Channel:
    sender: MessagePeer
    recipient: MessagePeer
    sink_id: str
    expires_at: float
    max_bytes: int
    rate_limit: int
    rate_window: float
    window_start: float
    attempts: int = 0
    sequence: int = 0
    revoked: bool = False
    delivery_lock: Any = field(default_factory=RLock)


@dataclass(frozen=True)
class _Work:
    sender: MessagePeer
    channel: MessageChannel
    envelope: SwarmMessageEnvelope
    inputs: tuple[LineageHandle, ...]
    sent_event_id: str


class SwarmMessageGateway:
    """Host-owned local ACL, replay and delivery boundary; no default message retention.

    Peer discovery, channel grants, inbox callbacks and lineage collection must
    remain outside agent control. Direct unmediated channels remain uncovered.
    """

    def __init__(
        self,
        flow: SwarmSourceFlow,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_peers: int = 256,
        max_channels: int = 512,
        max_messages: int = 4096,
        quarantine_on_violation: bool = True,
    ) -> None:
        if (
            type(flow) is not SwarmSourceFlow
            or not callable(clock)
            or type(quarantine_on_violation) is not bool
        ):
            raise ValueError("protected source-flow service and clock required")
        for value, maximum in ((max_peers, 4096), (max_channels, 8192), (max_messages, 16384)):
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError("invalid bounded message gateway capacity")
        self._flow, self._clock = flow, clock
        self._quarantine_on_violation = quarantine_on_violation
        self._graph, self._ingest = flow._graph, flow._graph._ingestor
        self._registry = self._ingest._registry
        self._peer_limit, self._channel_limit, self._message_limit = (
            max_peers,
            max_channels,
            max_messages,
        )
        self._peers: dict[MessagePeer, _Peer] = {}
        self._channels: dict[MessageChannel, _Channel] = {}
        self._drafts: dict[str, tuple[MessagePeer, MessageChannel, str, float]] = {}
        self._used: dict[str, MessageOutcome] = {}
        self._quarantined: dict[MessagePeer, str] = {}
        self._audit: list[dict[str, Any]] = []
        self._journal_gap = False
        self._last_now = 0.0
        self._lock = RLock()

    def _now(self) -> float:
        now = timestamp(self._clock())
        if now < self._last_now:
            raise ValueError("message clock moved backward")
        self._last_now = now
        return now

    def register(
        self,
        context: SwarmContext,
        source: HostEventSource,
        channel: HostChannel,
        adapter: object,
        inbox: Callable[[PrivateMessage], Any],
    ) -> MessagePeer:
        with self._lock, self._flow._lock, self._graph._lock, self._ingest._lock:
            actor = self._flow._actor(source)
            self._registry.authenticate(context, channel, adapter)
            if (
                actor.context is not context
                or not callable(inbox)
                or self._ingest._source(source).role != "gateway"
            ):
                raise ValueError("message peer requires original protected lineage context")
            if len(self._peers) >= self._peer_limit or any(
                v.context is context for v in self._peers.values()
            ):
                raise ValueError("message peer capacity or duplicate enrollment")
            handle = MessagePeer(uuid4().hex)
            self._peers[handle] = _Peer(handle, context, source, channel, adapter, inbox)
            return handle

    def _peer(self, handle: MessagePeer) -> _Peer:
        if type(handle) is not MessagePeer or handle not in self._peers:
            raise ValueError("unknown original message peer")
        if handle in self._quarantined:
            raise ValueError("message peer quarantined")
        peer = self._peers[handle]
        self._registry.authenticate(peer.context, peer.channel, peer.adapter)
        if self._flow._actor(peer.source).context is not peer.context:
            raise ValueError("message lineage context changed")
        return peer

    def grant(
        self,
        sender: MessagePeer,
        recipient: MessagePeer,
        *,
        sink_id: str,
        lifetime: float = 60,
        max_bytes: int = 65536,
        rate_limit: int = 64,
        rate_window: float = 60,
    ) -> MessageChannel:
        """Protected operator API: grant only this exact pair of enrolled generations."""
        if (
            not 0 < timestamp(lifetime) <= 600
            or not 0 < timestamp(rate_window) <= 600
            or type(max_bytes) is not int
            or not 1 <= max_bytes <= 65536
            or type(rate_limit) is not int
            or not 1 <= rate_limit <= 1024
        ):
            raise ValueError("invalid bounded message grant")
        identifier(sink_id, "sink_id")
        with self._lock:
            source, target = self._peer(sender), self._peer(recipient)
            if (source.context.identity.tenant_id, source.context.identity.swarm_id) != (
                target.context.identity.tenant_id,
                target.context.identity.swarm_id,
            ):
                raise ValueError("cross-scope message grant")
            sink = self._flow._sinks.get(sink_id)
            if (
                sink is None
                or sink.kind != "message"
                or sink.destination != target.context.identity.agent_id
            ):
                raise ValueError("message grant requires exact protected recipient sink policy")
            if len(self._channels) >= self._channel_limit:
                raise ValueError("message channel capacity reached")
            now = self._now()
            handle = MessageChannel(uuid4().hex)
            self._channels[handle] = _Channel(
                sender, recipient, sink_id, now + lifetime, max_bytes, rate_limit, rate_window, now
            )
            return handle

    def _channel(
        self, sender: MessagePeer, handle: MessageChannel
    ) -> tuple[_Channel, _Peer, _Peer]:
        if type(handle) is not MessageChannel or handle not in self._channels:
            raise ValueError("unknown original message channel")
        row = self._channels[handle]
        if row.sender is not sender or row.revoked or self._now() >= row.expires_at:
            raise ValueError("message channel sender, lifetime or revocation mismatch")
        return row, self._peer(row.sender), self._peer(row.recipient)

    @staticmethod
    def _body(body: str, maximum: int) -> bytes:
        if type(body) is not str or len(body) > maximum:
            raise ValueError("bounded private message text required")
        try:
            raw = body.encode("utf-8")
        except UnicodeError:
            raise ValueError("invalid message encoding") from None
        if len(raw) > maximum:
            raise ValueError("message byte limit exceeded")
        return raw

    @staticmethod
    def _action(recipient: _Peer, body: str) -> ActionEnvelope:
        # A source-use reference representation, never sent to a tool executor.
        return ActionEnvelope(
            "tool",
            "call",
            {
                "runtime": "ordin.swarm",
                "tool": "message.send",
                "arguments": {"destination": recipient.context.identity.agent_id, "body": body},
            },
        )

    def _facts(
        self,
        sender: _Peer,
        recipient: _Peer,
        channel: _Channel,
        body: str,
        inputs: tuple[LineageHandle, ...],
    ):
        if (
            type(inputs) is not tuple
            or not 1 <= len(inputs) <= 8
            or len(set(inputs)) != len(inputs)
        ):
            raise ValueError("original bounded message lineage inputs required")
        result = self._flow.assess(
            sender.source,
            self._action(recipient, body),
            sink_id=channel.sink_id,
            uses=tuple(LineageUse(v, BODY_PATH) for v in inputs),
            complete=True,
        )
        if result.status != "satisfied":
            if result.status == "violated" and self._quarantine_on_violation:
                self.quarantine(sender.handle, reason_code=result.reason_code)
            raise ValueError("message source flow is restricted: " + result.reason_code)
        parents = tuple(sorted({self._flow._record(v).event_id for v in inputs}))
        identity = sender.context.identity
        return result, tuple(
            EventRef(identity.tenant_id, identity.swarm_id, key) for key in parents
        )

    def _make(
        self,
        channel: _Channel,
        source: _Peer,
        target: _Peer,
        body: str,
        inputs: tuple[LineageHandle, ...],
        *,
        ttl: float,
        content_class: str,
    ) -> SwarmMessageEnvelope:
        raw = self._body(body, channel.max_bytes)
        if not 0 < timestamp(ttl) <= 600:
            raise ValueError("invalid message lifetime")
        facts, parents = self._facts(source, target, channel, body, inputs)
        now = self._now()
        return SwarmMessageEnvelope(
            uuid4().hex,
            source.context.identity,
            target.context.identity,
            source.context.identity.task_id,
            channel.sequence + 1,
            now,
            min(now + ttl, channel.expires_at),
            content_class,
            hashlib.sha256(raw).hexdigest(),
            len(raw),
            parents,
            facts.lineage_digests,
            facts.labels,
        )

    def prepare(
        self,
        sender: MessagePeer,
        channel: MessageChannel,
        body: str,
        *,
        inputs: tuple[LineageHandle, ...],
        ttl: float = 30,
        content_class: str = "data",
    ) -> SwarmMessageEnvelope:
        """Prepare metadata only; submit rechecks current facts before one delivery attempt."""
        with self._lock, self._flow._lock, self._graph._lock, self._ingest._lock:
            row, source, target = self._channel(sender, channel)
            now = self._now()
            self._drafts = {key: v for key, v in self._drafts.items() if v[3] > now}
            if len(self._drafts) >= self._message_limit:
                raise ValueError("message draft capacity reached")
            envelope = self._make(
                row, source, target, body, inputs, ttl=ttl, content_class=content_class
            )
            self._drafts[envelope.message_id] = (
                sender,
                channel,
                envelope.digest,
                envelope.expires_at,
            )
            return envelope

    def _event(
        self, peer: _Peer, kind: str, content_digest: str, parents: tuple[EventRef, ...]
    ) -> str:
        binding = self._ingest._source(peer.source)
        if binding.contiguous != max(binding.sequences, default=0):
            raise ValueError("message event source has a sequence gap")
        event_id = "message-" + uuid4().hex
        receipt = self._ingest.ingest(
            peer.source,
            SwarmEvent(
                event_id,
                kind,
                peer.context.registry_id,
                peer.context.identity,
                peer.source.source_id,
                binding.contiguous + 1,
                self._now(),
                evidence_class="host_authenticated",
                parent_event_ids=parents,
                resource_digests=(content_digest,),
            ),
        )
        if receipt.gaps:
            raise ValueError("message causal evidence is incomplete")
        return event_id

    def _record(self, envelope: SwarmMessageEnvelope, outcome: MessageOutcome) -> None:
        self._used[envelope.message_id] = outcome
        self._audit.append(
            {
                "envelope_digest": outcome.envelope_digest,
                "status": outcome.status,
                "reason_code": outcome.reason_code,
                "policy_epoch": envelope.sender.policy_epoch,
                "sender_digest": digest(envelope.sender.as_dict()),
                "recipient_digest": digest(envelope.destination.as_dict()),
            }
        )

    def _admit(
        self,
        sender: MessagePeer,
        channel: MessageChannel,
        body: str,
        inputs: tuple[LineageHandle, ...],
        envelope: SwarmMessageEnvelope | None,
        ttl: float,
        content_class: str,
    ) -> _Work:
        with self._lock, self._flow._lock, self._graph._lock, self._ingest._lock:
            row, source, target = self._channel(sender, channel)
            if self._journal_gap or len(self._used) >= self._message_limit:
                raise ValueError("message history unavailable or capacity reached")
            now = self._now()
            if now - row.window_start >= row.rate_window:
                row.window_start, row.attempts = now, 0
            if row.attempts >= row.rate_limit:
                raise ValueError("message rate limit reached")
            row.attempts += 1
            if envelope is None:
                envelope = self._make(
                    row, source, target, body, inputs, ttl=ttl, content_class=content_class
                )
            else:
                envelope.__post_init__()
                original = self._drafts.get(envelope.message_id)
                if (
                    original is None
                    or original[0] is not sender
                    or original[1] is not channel
                    or original[2] != envelope.digest
                ):
                    raise ValueError(
                        "message metadata was not issued for this original peer/channel"
                    )
                self._body(body, row.max_bytes)
                facts, parents = self._facts(source, target, row, body, inputs)
                if (facts.lineage_digests, facts.labels, parents) != (
                    envelope.source_lineage,
                    envelope.labels,
                    envelope.parent_event_ids,
                ):
                    raise ValueError("message lineage changed after preparation")
            if (
                envelope.sender != source.context.identity
                or envelope.destination != target.context.identity
                or envelope.sequence != row.sequence + 1
                or now >= envelope.expires_at
                or envelope.expires_at > row.expires_at
                or envelope.message_id in self._used
                or hashlib.sha256(self._body(body, row.max_bytes)).hexdigest()
                != envelope.content_digest
            ):
                raise ValueError("stale, replayed or changed message")
            self._drafts.pop(envelope.message_id, None)
            row.sequence += 1
            outcome = MessageOutcome("unknown", "message.delivery_pending", envelope.digest)
            self._record(envelope, outcome)
            try:
                sent = self._event(
                    source, "message_sent", envelope.content_digest, envelope.parent_event_ids
                )
            except Exception:
                self._journal_gap = True
                self._record(
                    envelope, MessageOutcome("unknown", "message.journal_gap", envelope.digest)
                )
                raise ValueError("message journal failed; delivery was not attempted") from None
            return _Work(sender, channel, envelope, inputs, sent)

    def _deliver(self, work: _Work, body: str) -> MessageOutcome:
        envelope = work.envelope
        try:
            with self._lock:
                _, _, target = self._channel(work.sender, work.channel)
                if self._now() >= envelope.expires_at:
                    raise ValueError("expired message")
            target.inbox(PrivateMessage(envelope, body))
        except Exception:
            outcome = MessageOutcome("unknown", "message.transport_uncertain", envelope.digest)
            with self._lock:
                self._channels[work.channel].revoked = True
                self._record(envelope, outcome)
            return outcome
        with self._lock, self._flow._lock, self._graph._lock, self._ingest._lock:
            try:
                _, _, target = self._channel(work.sender, work.channel)
                if self._now() >= envelope.expires_at:
                    raise ValueError("expired receipt")
                parent = EventRef(
                    envelope.sender.tenant_id, envelope.sender.swarm_id, work.sent_event_id
                )
                received = self._event(
                    target, "message_received", envelope.content_digest, (parent,)
                )
                lineage = self._flow.derive(
                    target.source,
                    event_id=received,
                    content=body,
                    parents=work.inputs,
                    complete=True,
                )
                if not self._flow._record(lineage).complete:
                    raise ValueError("incomplete received lineage")
                outcome = MessageOutcome(
                    "delivered", "message.delivered_as_data", envelope.digest, lineage
                )
            except Exception:
                self._journal_gap = True
                outcome = MessageOutcome("unknown", "message.receipt_uncertain", envelope.digest)
            self._record(envelope, outcome)
            return outcome

    def send(
        self,
        sender: MessagePeer,
        channel: MessageChannel,
        body: str,
        *,
        inputs: tuple[LineageHandle, ...],
        ttl: float = 30,
        content_class: str = "data",
    ) -> MessageOutcome:
        with self._lock:
            route, _, _ = self._channel(sender, channel)
        # Serialize admission and callback invocation per channel without holding
        # the global/lineage locks while the private transport runs.
        with route.delivery_lock:
            work = self._admit(sender, channel, body, inputs, None, ttl, content_class)
            return self._deliver(work, body)

    def submit(
        self,
        sender: MessagePeer,
        channel: MessageChannel,
        envelope: SwarmMessageEnvelope | Mapping[str, Any],
        body: str,
        *,
        inputs: tuple[LineageHandle, ...],
    ) -> MessageOutcome:
        if isinstance(envelope, Mapping):
            envelope = SwarmMessageEnvelope.from_dict(envelope)
        elif type(envelope) is not SwarmMessageEnvelope:
            raise ValueError("typed message metadata required")
        with self._lock:
            route, _, _ = self._channel(sender, channel)
        with route.delivery_lock:
            work = self._admit(sender, channel, body, inputs, envelope, 30, "data")
            return self._deliver(work, body)

    def quarantine(self, peer: MessagePeer, *, reason_code: str = "operator.quarantined") -> None:
        identifier(reason_code, "quarantine_reason")
        with self._lock:
            if type(peer) is not MessagePeer or peer not in self._peers:
                raise ValueError("unknown original message peer")
            self._quarantined[peer] = reason_code
            for channel in self._channels.values():
                if peer in {channel.sender, channel.recipient}:
                    channel.revoked = True

    def audit(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            return tuple(dict(row) for row in self._audit)

    def peer_status(self, peer: MessagePeer) -> dict[str, Any]:
        with self._lock:
            if type(peer) is not MessagePeer or peer not in self._peers:
                raise ValueError("unknown original message peer")
            row = self._peers[peer]
            state, reason = "active", "message.peer_active"
            try:
                self._peer(peer)
            except ValueError:
                state, reason = "stale", "message.peer_stale"
            if peer in self._quarantined:
                state, reason = "quarantined", self._quarantined[peer]
            return {
                "schema_version": "ordin.swarm_message_peer_status.v1",
                "peer_digest": digest(row.context.as_dict()),
                "state": state,
                "reason_code": reason,
                "journal_continuity": not self._journal_gap,
                "execution_authority": False,
            }
