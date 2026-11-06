"""Explicit typed message/artifact handoffs; native framework text stays data."""

from dataclasses import dataclass, field
import hashlib
from threading import RLock
from uuid import uuid4

from ordin.swarm import (
    LineageHandle,
    LineageUse,
    SwarmSourceFlow,
    SwarmMessageGateway,
    SwarmArtifactGateway,
)
from ordin_swarm.sdk import SwarmSDK, FrameworkSession


@dataclass(frozen=True, eq=False, slots=True)
class FrameworkData:
    data_id: str


@dataclass(frozen=True)
class _Data:
    session: FrameworkSession
    lineage: LineageHandle
    value: str = field(repr=False)


class FrameworkDataBridge:
    def __init__(self, sdk: SwarmSDK, flow: SwarmSourceFlow, *, operator: object, max_data=4096):
        if (
            type(sdk) is not SwarmSDK
            or type(flow) is not SwarmSourceFlow
            or operator is not sdk._operator
            or operator is not flow._operator
            or type(max_data) is not int
            or not 1 <= max_data <= 16384
        ):
            raise ValueError("shared original SDK/flow operator and bounded data required")
        self.sdk, self.flow, self._operator, self._limit = sdk, flow, operator, max_data
        self._actors: dict[FrameworkSession, tuple] = {}
        self._data: dict[FrameworkData, _Data] = {}
        self._lock = RLock()

    def bind(self, session, source, *, operator: object, messages=None, peer=None, artifacts=None):
        context = self.sdk.context(session)
        if operator is not self._operator or self.flow._actor(source).context is not context:
            raise ValueError("original current SDK lineage actor required")
        if messages is not None and (
            type(messages) is not SwarmMessageGateway
            or messages._flow is not self.flow
            or messages._peer(peer).context is not context
        ):
            raise ValueError("original same-context message peer required")
        if artifacts is not None and (
            type(artifacts) is not SwarmArtifactGateway or artifacts._flow is not self.flow
        ):
            raise ValueError("original shared artifact lineage service required")
        with self._lock:
            if session in self._actors:
                raise ValueError("framework data actor already bound")
            self._actors[session] = (source, messages, peer, artifacts)

    def _actor(self, session):
        current = self.sdk.context(session)
        row = self._actors.get(session)
        if row is None or self.flow._actor(row[0]).context is not current:
            raise ValueError("original live framework data actor required")
        return row

    def _capture(self, session, lineage, value):
        source, *_ = self._actor(session)
        record = self.flow._record(lineage)
        if (
            type(value) is not str
            or len(value.encode()) > 65536
            or record.actor.context is not self.sdk.context(session)
            or record.actor.source is not source
            or record.content_digest != hashlib.sha256(value.encode()).hexdigest()
            or not record.established
            or not record.complete
        ):
            raise ValueError("exact authenticated data and original lineage required")
        with self._lock:
            if len(self._data) >= self._limit:
                raise ValueError("framework data capacity reached")
            handle = FrameworkData(uuid4().hex)
            self._data[handle] = _Data(session, lineage, value)
            return handle

    def capture(self, session, lineage, value, *, operator: object):
        if operator is not self._operator:
            raise ValueError("protected data collector required")
        return self._capture(session, lineage, value)

    def _record(self, session, handle):
        self._actor(session)
        row = self._data.get(handle) if type(handle) is FrameworkData else None
        if row is None or row.session is not session:
            raise ValueError("original same-session framework data required")
        self.flow._record(row.lineage)
        return row

    def value(self, session, handle):
        return self._record(session, handle).value

    def use(self, session, handle, argument_path):
        row = self._record(session, handle)
        return LineageUse(row.lineage, argument_path)

    def read_artifact(self, session, address, *, grant=None, version=None):
        source, _, _, artifacts = self._actor(session)
        if artifacts is None:
            raise ValueError("original artifact route unavailable")
        result = artifacts.read(source, address, grant=grant, version=version)
        if result.lineage is None or result.proof_gaps:
            raise ValueError("artifact lineage incomplete")
        return self._capture(session, result.lineage, result.value)

    def send(self, sender, recipient, channel, data):
        source, messages, peer, _ = self._actor(sender)
        _, target_messages, target_peer, _ = self._actor(recipient)
        row = self._record(sender, data)
        if messages is None or messages is not target_messages:
            raise ValueError("shared original message route required")
        _, _, target = messages._channel(peer, channel)
        if target.handle is not target_peer or target.context is not self.sdk.context(recipient):
            raise ValueError("message route does not identify the original recipient")
        outcome = messages.send(
            peer, channel, row.value, inputs=(row.lineage,), content_class="task_handoff"
        )
        if (
            outcome.status != "delivered"
            or outcome.recipient_lineage is None
            or not any(v is outcome for v in messages._used.values())
        ):
            raise ValueError("original delivered message outcome required; receiver effect unknown")
        return self._capture(recipient, outcome.recipient_lineage, row.value)


__all__ = ["FrameworkData", "FrameworkDataBridge"]
