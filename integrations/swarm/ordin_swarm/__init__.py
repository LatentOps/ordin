"""Optional host integration entry points; import starts no transports."""

from .sdk import (
    SwarmSDK,
    FrameworkSession,
    FrameworkTool,
    FrameworkCall,
    FrameworkPreparation,
    FrameworkResult,
    SwarmToolRefused,
)
from .data_bridge import FrameworkDataBridge, FrameworkData
from .protocol import FrameworkJSONClient

from .mcp_adapter import SwarmMCPAdapter
from .approval_service import (
    SwarmApprovalBootstrap,
    SwarmApprovalService,
    SwarmApprovalPolicy,
    SwarmApprovalBinding,
    SwarmApprovalRequest,
    SwarmApprovalReceipt,
    SwarmRecoveryRequest,
    SwarmRecoveryApproval,
    SwarmApprovalOperatorSession,
    HumanOperator,
    HumanOperatorChannel,
    SwarmOperatorDirectory,
)
from .operator_api import (
    SwarmAuditJournal,
    SwarmAuditPolicy,
    SwarmAuditSource,
    SwarmOperatorAPI,
    SwarmOperatorClient,
)
from .containment import (
    IncidentPolicy,
    IncidentRule,
    IncidentScope,
    IncidentSignal,
    IncidentSignalSource,
    IncidentReceipt,
    IncidentResumeReceipt,
    SwarmContainmentController,
)
from .coordinator import SwarmCoordinator, CoordinatorClock, CoordinatorEndpoint, CoordinatorClient
from .store_postgres import PostgresCoordinatorStore
from .store_sqlite import SQLiteCoordinatorStore
from .hooks import SwarmHookAdapter
from .delegation_service import SwarmDelegationService, WorkloadAuthenticator, AuthorityChannel
from .credential_broker import SwarmCredentialBroker
from .broker import SwarmExecutionBroker, LinuxFileReadBackend
from .attach import HostSessionEndpoint, RunningSessionIdentity, SwarmAttachManager
from .coverage import AttachCoverage
from .policy import SwarmPolicyRuntime, SwarmPolicySet, SwarmPolicyMaximum, compile_swarm_policy_set
from .semantic_signals import (
    SwarmRiskScorer,
    SwarmRiskSignalProvider,
    SwarmRiskInput,
    SwarmRiskPromotionPolicy,
)
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
    "SwarmApprovalBootstrap",
    "SwarmApprovalService",
    "SwarmApprovalPolicy",
    "SwarmApprovalBinding",
    "SwarmApprovalRequest",
    "SwarmApprovalReceipt",
    "SwarmRecoveryRequest",
    "SwarmRecoveryApproval",
    "SwarmApprovalOperatorSession",
    "HumanOperator",
    "HumanOperatorChannel",
    "SwarmOperatorDirectory",
    "SwarmAuditJournal",
    "SwarmAuditPolicy",
    "SwarmAuditSource",
    "SwarmOperatorAPI",
    "SwarmOperatorClient",
    "SwarmArtifactGateway",
    "WorkspaceArtifactAdapter",
    "SharedMemoryAdapter",
    "VectorPointArtifactAdapter",
    "IncidentPolicy",
    "IncidentRule",
    "IncidentScope",
    "IncidentSignal",
    "IncidentSignalSource",
    "IncidentReceipt",
    "IncidentResumeReceipt",
    "SwarmContainmentController",
    "SwarmSDK",
    "FrameworkSession",
    "FrameworkTool",
    "FrameworkCall",
    "FrameworkPreparation",
    "FrameworkResult",
    "SwarmToolRefused",
    "FrameworkDataBridge",
    "FrameworkData",
    "FrameworkJSONClient",
    "SwarmCoordinator",
    "CoordinatorClock",
    "CoordinatorEndpoint",
    "CoordinatorClient",
    "PostgresCoordinatorStore",
    "SQLiteCoordinatorStore",
    "SwarmExecutionBroker",
    "LinuxFileReadBackend",
    "SwarmRiskScorer",
    "SwarmRiskSignalProvider",
    "SwarmRiskInput",
    "SwarmRiskPromotionPolicy",
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
