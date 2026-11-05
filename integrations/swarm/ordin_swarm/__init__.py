"""Optional host integration entry points; import starts no transports."""

from .mcp_adapter import SwarmMCPAdapter
from .hooks import SwarmHookAdapter
from .attach import HostSessionEndpoint, RunningSessionIdentity, SwarmAttachManager
from .coverage import AttachCoverage
from .message_gateway import (
    SwarmMessageGateway,
    SwarmMessageAdapter,
    CallbackMessageInbox,
    QueueMessageInbox,
    RPCMessageInbox,
)

__all__ = [
    "SwarmMCPAdapter",
    "SwarmHookAdapter",
    "HostSessionEndpoint",
    "RunningSessionIdentity",
    "SwarmAttachManager",
    "AttachCoverage",
    "SwarmMessageGateway",
    "SwarmMessageAdapter",
    "CallbackMessageInbox",
    "QueueMessageInbox",
    "RPCMessageInbox",
]
