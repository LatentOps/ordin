"""Explicit, local host enrollment. Importing this package starts no services."""

from .identity import HostChannel
from .approval import (
    SwarmApprovalBinding,
    SwarmApprovalPolicy,
    SwarmApprovalReceipt,
    SwarmApprovalRequest,
    SwarmRecoveryApproval,
    SwarmRecoveryRequest,
)
from .approval_service import SwarmApprovalBootstrap, SwarmApprovalService
from .operator_auth import HumanOperator, HumanOperatorChannel, SwarmOperatorDirectory
from .incident import (
    IncidentPolicy,
    IncidentRule,
    IncidentScope,
    IncidentSignal,
    IncidentSignalSource,
    IncidentReceipt,
    IncidentResumeReceipt,
    SwarmContainmentController,
)
from .coordinator import (
    SwarmCoordinator,
    CoordinatorBudgetView,
    CoordinatorControlSource,
    CoordinatorScope,
    CoordinatorFenceReceipt,
    CoordinatorRecord,
    CoordinatorDispatch,
)
from .coordinator_store import (
    CoordinatorClock,
    CoordinatorRejected,
    CoordinatorUnavailable,
    SQLiteCoordinatorStore,
    PostgresCoordinatorStore,
)
from .coordinator_rpc import CoordinatorEndpoint, CoordinatorClient
from .models import CoverageEntry, CoverageManifest, SwarmContext, SwarmIdentity
from .registry import AgentRegistry, InMemoryAgentRegistry
from .events import EventRef, SwarmEvent
from .ingest import ActionEventState, HostEventSource, IngestReceipt, SwarmEventIngestor
from .journal import EventJournal, JournalRecord
from .gate import SwarmDecision, SwarmGate
from .policy import SwarmPolicy, SwarmRule
from .facts import SwarmAssessment, SwarmAssessmentSource
from .budgets import (
    BudgetCost,
    BudgetError,
    BudgetLedger,
    BudgetLimit,
    BudgetObservation,
    BudgetObservationSource,
    BudgetPolicy,
    BudgetTicket,
)
from .budget_store import BudgetStore, InMemoryBudgetStore, SQLiteBudgetStore
from .policy_set import (
    SwarmBudgetCondition,
    SwarmBudgetConstraint,
    SwarmPolicyPermissions,
    SwarmPolicyResource,
    SwarmPolicyRule,
    SwarmPolicySelector,
    SwarmPolicySet,
    SwarmPolicyTool,
    load_swarm_policy_set,
)
from .policy_compiler import (
    CompiledSwarmPolicy,
    SwarmPolicyMaximum,
    SwarmPolicyResult,
    SwarmRoleBinding,
    compile_swarm_policy_set,
    diff_swarm_policies,
    load_swarm_policy_maximum,
)
from .policy_facts import SwarmBudgetFact, SwarmPolicyFacts, SwarmPolicyFactsSource
from .policy_runtime import (
    SwarmPolicyActivation,
    SwarmPolicyApproval,
    SwarmPolicyDeployment,
    SwarmPolicyReplayCase,
    SwarmPolicyRuntime,
    SwarmPolicySimulation,
)
from .gateway import (
    ForwardTicket,
    GatewayAgent,
    GatewayAuthorization,
    GatewayOutcome,
    GatewayResult,
    SwarmToolGateway,
)
from .mcp_gateway import SwarmMCPAdapter
from .hooks_gateway import SwarmHookAdapter
from .causal_graph import SwarmCausalGraph, SwarmGraphView
from .lineage import SwarmDelegationLink
from .delegation import (
    BrokerAdmissionScope,
    DelegationDispatch,
    RemoteDelegation,
    RemoteReview,
    SwarmDelegationService,
)
from .workload_auth import AuthorityChannel, WorkloadAuthenticator
from .broker import SwarmExecutionBroker
from .authorization import (
    BrokerActivationProof,
    BrokerAuthorization,
    BrokerAuthorizationScope,
    BrokerControlReceipt,
    BrokerGatewayBinding,
    BrokerPreparation,
    BrokerResult,
)
from .linux_backend import LinuxFileReadBackend, ExecutorOutcome
from .credential_broker import CredentialRoute, PrivateCredentialRequest, SwarmCredentialBroker
from .labels import Sensitivity
from .source_flow import EgressSink, LineageHandle, LineageUse, SourceFlowResult, SwarmSourceFlow
from .attach import (
    AttachedSession,
    HostSessionEndpoint,
    MediatedSessionRouter,
    RunningSessionIdentity,
    SwarmAttachManager,
)
from .coverage import AttachCoverage
from .messages import (
    MessageChannel,
    MessageOutcome,
    MessagePeer,
    PrivateMessage,
    SwarmMessageEnvelope,
    SwarmMessageGateway,
)
from .message_adapters import (
    CallbackMessageInbox,
    QueueMessageInbox,
    RPCMessageInbox,
    SwarmMessageAdapter,
)
from .artifact_store import ArtifactBlobStore, FilesystemArtifactStore, MemoryArtifactStore
from .memory import (
    ArtifactAddress,
    ArtifactGrant,
    PrivateArtifactRead,
    SwarmArtifact,
    SwarmArtifactGateway,
)
from .artifact_adapters import (
    ArtifactAdapter,
    GuardedVectorPointAPI,
    SharedMemoryAdapter,
    VectorPointArtifactAdapter,
    WorkspaceArtifactAdapter,
)

from .temporal import (
    CompiledSwarmTemporalPolicy,
    SwarmTemporalEngine,
    SwarmTemporalEvaluation,
    SwarmTemporalFinding,
    SwarmTemporalPolicySet,
    SwarmTemporalPredicate,
    SwarmTemporalRule,
    default_swarm_temporal_policy,
    load_swarm_temporal_policy,
)

from .audit import (
    SwarmAuditJournal,
    SwarmAuditPolicy,
    SwarmAuditVerification,
    TenantRedactor,
    verify_swarm_audit,
)
from .diagnostics import SwarmAuditSource
from .operator_api import SwarmOperatorAPI, SwarmOperatorClient

__all__ = [
    "SwarmApprovalBinding",
    "SwarmApprovalPolicy",
    "SwarmApprovalReceipt",
    "SwarmApprovalRequest",
    "SwarmRecoveryApproval",
    "SwarmRecoveryRequest",
    "SwarmApprovalBootstrap",
    "SwarmApprovalService",
    "HumanOperator",
    "HumanOperatorChannel",
    "SwarmOperatorDirectory",
    "SwarmAuditJournal",
    "SwarmAuditPolicy",
    "SwarmAuditVerification",
    "TenantRedactor",
    "verify_swarm_audit",
    "SwarmAuditSource",
    "SwarmOperatorAPI",
    "SwarmOperatorClient",
    "ArtifactBlobStore",
    "FilesystemArtifactStore",
    "MemoryArtifactStore",
    "ArtifactAddress",
    "ArtifactGrant",
    "PrivateArtifactRead",
    "SwarmArtifact",
    "SwarmArtifactGateway",
    "ArtifactAdapter",
    "GuardedVectorPointAPI",
    "SharedMemoryAdapter",
    "VectorPointArtifactAdapter",
    "WorkspaceArtifactAdapter",
    "CompiledSwarmTemporalPolicy",
    "SwarmTemporalEngine",
    "SwarmTemporalEvaluation",
    "SwarmTemporalFinding",
    "SwarmTemporalPolicySet",
    "SwarmTemporalPredicate",
    "SwarmTemporalRule",
    "default_swarm_temporal_policy",
    "load_swarm_temporal_policy",
    "IncidentPolicy",
    "IncidentRule",
    "IncidentScope",
    "IncidentSignal",
    "IncidentSignalSource",
    "IncidentReceipt",
    "IncidentResumeReceipt",
    "SwarmContainmentController",
    "SwarmCoordinator",
    "CoordinatorBudgetView",
    "CoordinatorControlSource",
    "CoordinatorScope",
    "CoordinatorFenceReceipt",
    "CoordinatorRecord",
    "CoordinatorDispatch",
    "CoordinatorClock",
    "CoordinatorRejected",
    "CoordinatorUnavailable",
    "SQLiteCoordinatorStore",
    "PostgresCoordinatorStore",
    "CoordinatorEndpoint",
    "CoordinatorClient",
    "SwarmExecutionBroker",
    "BrokerActivationProof",
    "BrokerAuthorization",
    "BrokerAuthorizationScope",
    "BrokerControlReceipt",
    "BrokerGatewayBinding",
    "BrokerPreparation",
    "BrokerResult",
    "LinuxFileReadBackend",
    "ExecutorOutcome",
    "SwarmBudgetCondition",
    "SwarmBudgetConstraint",
    "SwarmPolicyPermissions",
    "SwarmPolicyResource",
    "SwarmPolicyRule",
    "SwarmPolicySelector",
    "SwarmPolicySet",
    "SwarmPolicyTool",
    "load_swarm_policy_set",
    "CompiledSwarmPolicy",
    "SwarmPolicyMaximum",
    "SwarmPolicyResult",
    "SwarmRoleBinding",
    "compile_swarm_policy_set",
    "diff_swarm_policies",
    "load_swarm_policy_maximum",
    "SwarmBudgetFact",
    "SwarmPolicyFacts",
    "SwarmPolicyFactsSource",
    "SwarmPolicyActivation",
    "SwarmPolicyApproval",
    "SwarmPolicyDeployment",
    "SwarmPolicyReplayCase",
    "SwarmPolicyRuntime",
    "SwarmPolicySimulation",
    "BudgetCost",
    "BudgetError",
    "BudgetLedger",
    "BudgetLimit",
    "BudgetObservation",
    "BudgetObservationSource",
    "BudgetPolicy",
    "BudgetTicket",
    "BudgetStore",
    "InMemoryBudgetStore",
    "SQLiteBudgetStore",
    "AuthorityChannel",
    "WorkloadAuthenticator",
    "BrokerAdmissionScope",
    "DelegationDispatch",
    "RemoteDelegation",
    "RemoteReview",
    "SwarmDelegationService",
    "CredentialRoute",
    "PrivateCredentialRequest",
    "SwarmCredentialBroker",
    "MessageChannel",
    "MessageOutcome",
    "MessagePeer",
    "PrivateMessage",
    "SwarmMessageEnvelope",
    "SwarmMessageGateway",
    "CallbackMessageInbox",
    "QueueMessageInbox",
    "RPCMessageInbox",
    "SwarmMessageAdapter",
    "Sensitivity",
    "EgressSink",
    "LineageHandle",
    "LineageUse",
    "SourceFlowResult",
    "SwarmSourceFlow",
    "AttachedSession",
    "HostSessionEndpoint",
    "MediatedSessionRouter",
    "RunningSessionIdentity",
    "SwarmAttachManager",
    "AttachCoverage",
    "SwarmCausalGraph",
    "SwarmGraphView",
    "SwarmDelegationLink",
    "ForwardTicket",
    "GatewayAgent",
    "GatewayAuthorization",
    "GatewayOutcome",
    "GatewayResult",
    "SwarmToolGateway",
    "SwarmMCPAdapter",
    "SwarmHookAdapter",
    "SwarmAssessment",
    "SwarmAssessmentSource",
    "SwarmDecision",
    "SwarmGate",
    "SwarmPolicy",
    "SwarmRule",
    "ActionEventState",
    "EventJournal",
    "EventRef",
    "HostEventSource",
    "IngestReceipt",
    "JournalRecord",
    "SwarmEvent",
    "SwarmEventIngestor",
    "AgentRegistry",
    "CoverageEntry",
    "CoverageManifest",
    "HostChannel",
    "InMemoryAgentRegistry",
    "SwarmContext",
    "SwarmIdentity",
]
