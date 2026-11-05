"""Thin protected transports; all message authorization stays in one gateway."""

from queue import Queue
from typing import Any, Callable, Mapping

from ordin._runtime_json import digest

from .messages import (
    MessageChannel,
    MessagePeer,
    PrivateMessage,
    SwarmMessageEnvelope,
    SwarmMessageGateway,
)
from .models import SwarmContext
from .source_flow import LineageHandle


class CallbackMessageInbox:
    def __init__(self, callback: Callable[[PrivateMessage], Any]) -> None:
        if not callable(callback):
            raise ValueError("protected inbox callback required")
        self._callback = callback

    def __call__(self, message: PrivateMessage) -> None:
        if type(message) is not PrivateMessage:
            raise ValueError("typed private delivery required")
        self._callback(message)


class QueueMessageInbox:
    def __init__(self, queue: Queue) -> None:
        if (
            type(queue) is not Queue
            or type(queue.maxsize) is not int
            or not 1 <= queue.maxsize <= 4096
        ):
            raise ValueError("explicitly bounded private inbox queue required")
        self._queue = queue

    def __call__(self, message: PrivateMessage) -> None:
        if type(message) is not PrivateMessage:
            raise ValueError("typed private delivery required")
        self._queue.put_nowait(message)


class RPCMessageInbox:
    """Use an existing authenticated host connection, never identity from JSON.

    The host connector authenticates and binds the actual remote recipient before
    constructing this adapter. Its original opaque peer handle must stay current.
    transmit owns framing, TLS/authentication and private-body transport. A wire
    ACK correlates gateway acceptance, not receiver execution.
    """

    def __init__(
        self,
        recipient: SwarmContext,
        *,
        authenticated_peer: object,
        current_peer: Callable[[], object],
        transmit: Callable[[dict, str], Mapping[str, Any]],
    ) -> None:
        if (
            type(recipient) is not SwarmContext
            or type(authenticated_peer) is not object
            or not callable(current_peer)
            or not callable(transmit)
            or current_peer() is not authenticated_peer
        ):
            raise ValueError("original authenticated RPC recipient binding required")
        self._recipient, self._peer = recipient, authenticated_peer
        self._current, self._transmit = current_peer, transmit
        self._recipient_digest = digest(recipient.as_dict())

    def __call__(self, message: PrivateMessage) -> None:
        if (
            type(message) is not PrivateMessage
            or self._current() is not self._peer
            or digest(self._recipient.as_dict()) != self._recipient_digest
            or message.envelope.destination != self._recipient.identity
        ):
            raise ValueError("RPC recipient changed or disconnected")
        reply = self._transmit(message.envelope.as_dict(), message.body)
        expected = {
            "accepted": True,
            "message_id": message.envelope.message_id,
            "envelope_digest": message.envelope.digest,
            "recipient_digest": self._recipient_digest,
        }
        if (
            type(reply) is not dict
            or reply.get("accepted") is not True
            or any(
                type(reply.get(key)) is not str
                for key in ("message_id", "envelope_digest", "recipient_digest")
            )
            or reply != expected
            or self._current() is not self._peer
        ):
            raise ValueError("RPC acceptance was not correlated to its current recipient")


class SwarmMessageAdapter:
    """Host binds original peer and channel; transport payloads cannot replace them."""

    def __init__(
        self, gateway: SwarmMessageGateway, sender: MessagePeer, channel: MessageChannel
    ) -> None:
        if type(gateway) is not SwarmMessageGateway:
            raise ValueError("protected message gateway required")
        with gateway._lock:
            gateway._channel(sender, channel)
        self._gateway, self._sender, self._channel = gateway, sender, channel

    def send(
        self,
        body: str,
        *,
        inputs: tuple[LineageHandle, ...],
        ttl: float = 30,
        content_class: str = "data",
    ):
        return self._gateway.send(
            self._sender, self._channel, body, inputs=inputs, ttl=ttl, content_class=content_class
        )

    def submit(
        self,
        envelope: SwarmMessageEnvelope | Mapping[str, Any],
        body: str,
        *,
        inputs: tuple[LineageHandle, ...],
    ):
        return self._gateway.submit(self._sender, self._channel, envelope, body, inputs=inputs)
