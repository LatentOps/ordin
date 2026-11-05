"""Optional host integration entry points; import starts no transports."""

from .mcp_adapter import SwarmMCPAdapter
from .hooks import SwarmHookAdapter
from .delegation_service import SwarmDelegationService, WorkloadAuthenticator, AuthorityChannel
from .credential_broker import SwarmCredentialBroker
from .broker import SwarmExecutionBroker, LinuxFileReadBackend
from .attach import HostSessionEndpoint, RunningSessionIdentity, SwarmAttachManager
from .coverage import AttachCoverage
from .policy import SwarmPolicyRuntime, SwarmPolicySet, SwarmPolicyMaximum, compile_swarm_policy_set
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
    "SwarmExecutionBroker",
    "LinuxFileReadBackend",
    "SwarmPolicyRuntime",
    "SwarmPolicySet",
    "SwarmPolicyMaximum",
    "compile_swarm_policy_set",
    "BudgetLedger",
    "BudgetPolicy",
    "BudgetLimit",
    "BudgetCost",
    "InMemoryBudgetStore",
    "SQLiteBudgetStore",
    "SwarmDelegationService",
    "WorkloadAuthenticator",
    "AuthorityChannel",
    "SwarmCredentialBroker",
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
