"""Optional host integration entry points; import starts no transports."""

from .mcp_adapter import SwarmMCPAdapter
from .hooks import SwarmHookAdapter
from .attach import HostSessionEndpoint, RunningSessionIdentity, SwarmAttachManager
from .coverage import AttachCoverage
from .budget_store import (
    BudgetLedger,
    BudgetPolicy,
    BudgetLimit,
    BudgetCost,
    InMemoryBudgetStore,
    SQLiteBudgetStore,
)
from .message_gateway import (
    SwarmMessageGateway,
    SwarmMessageAdapter,
    CallbackMessageInbox,
    QueueMessageInbox,
    RPCMessageInbox,
)
from .artifact_gateway import (
    SwarmArtifactGateway,
    WorkspaceArtifactAdapter,
    SharedMemoryAdapter,
    VectorPointArtifactAdapter,
)

__all__ = [
    "SwarmArtifactGateway",
    "WorkspaceArtifactAdapter",
    "SharedMemoryAdapter",
    "VectorPointArtifactAdapter",
    "BudgetLedger",
    "BudgetPolicy",
    "BudgetLimit",
    "BudgetCost",
    "InMemoryBudgetStore",
    "SQLiteBudgetStore",
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
