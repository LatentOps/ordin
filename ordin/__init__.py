"""Ordin public API for command intelligence and pre-execution safety."""

__version__ = "0.2.0.dev0"

SEARCH_SCHEMA_VERSION = "ordin.search_result.v1"
RISK_SCHEMA_VERSION = "ordin.risk_review.v1"
REVIEW_SCHEMA_VERSION = "ordin.review.v1"
REVIEW_REQUEST_SCHEMA_VERSION = "ordin.review_request.v1"
ACTION_ENVELOPE_SCHEMA_VERSION = "ordin.action_envelope.v1"
ACTION_HISTORY_SCHEMA_VERSION = "ordin.action_history.v1"
ACTION_REVIEW_SCHEMA_VERSION = "ordin.action_review.v1"
ACTION_OBSERVATION_SCHEMA_VERSION = "ordin.action_observation.v1"
OBSERVATION_HISTORY_SCHEMA_VERSION = "ordin.observation_history.v1"
EXECUTION_CAPABILITIES_SCHEMA_VERSION = "ordin.execution_capabilities.v1"
ACTION_TRACE_SCHEMA_VERSION = "ordin.action_trace.v1"
POLICY_SET_SCHEMA_VERSION = "ordin.policy_set.v1"
TEMPORAL_POLICY_SET_SCHEMA_VERSION = "ordin.temporal_policy_set.v1"
TOOL_SEMANTICS_SCHEMA_VERSION = "ordin.tool_semantics.v1"
RISK_RULES_SCHEMA_VERSION = "ordin.risk_rules.v1"
MAN_INDEX_SCHEMA_VERSION = "ordin.man_index.v1"
EFFECT_CATALOG_SCHEMA_VERSION = "ordin.effect_catalog.v1"
EFFECT_GRAPH_SCHEMA_VERSION = "ordin.effect_graph.v1"
PACK_MANIFEST_SCHEMA_VERSION = "ordin.command_pack.v1"
PACK_LIST_SCHEMA_VERSION = "ordin.pack_list.v1"

from .action import ActionEnvelope, ActionHistory, ActionResource, ActionReview, review_action
from .action_policy import (
    ActionPolicyCondition,
    ActionPolicyRule,
    ActionPolicySet,
    CompiledActionPolicySet,
    PolicyEvaluation,
    PolicyMatch,
    PolicyResourceMatcher,
    load_action_policy,
)
from .adapters import MCPAdapter, ToolCallAdapter
from .agent import AgentDecision, AgentDisposition, AgentGate, AgentReview
from .api import Ordin
from .context import ExecutionContext, ReviewRequest
from .execution import (
    ActionObservation,
    ExecutionCapabilityProfile,
    ObservationHistory,
    ObservedResource,
    derive_capabilities,
)
from .policy import Decision, FailThreshold, ReviewPolicy
from .review import CommandReview
from .risk import RiskReview
from .search import SearchResult
from .temporal import (
    CompiledTemporalPolicySet,
    TemporalActionEvidence,
    TemporalPolicySet,
    TemporalPredicate,
    TemporalRule,
    default_temporal_policy,
    load_temporal_policy,
)
from .tool_calls import (
    CompiledToolSemanticsRegistry,
    ToolResourceBinding,
    ToolSemanticRule,
    ToolSemanticsRegistry,
    load_tool_semantics,
)
from .trace import ActionTrace, TraceAction

__all__ = [
    "ACTION_ENVELOPE_SCHEMA_VERSION",
    "ACTION_HISTORY_SCHEMA_VERSION",
    "ACTION_OBSERVATION_SCHEMA_VERSION",
    "ACTION_REVIEW_SCHEMA_VERSION",
    "ACTION_TRACE_SCHEMA_VERSION",
    "EXECUTION_CAPABILITIES_SCHEMA_VERSION",
    "OBSERVATION_HISTORY_SCHEMA_VERSION",
    "ActionEnvelope",
    "ActionHistory",
    "ActionObservation",
    "ActionPolicyCondition",
    "ActionPolicyRule",
    "ActionPolicySet",
    "ActionResource",
    "ActionReview",
    "ActionTrace",
    "AgentDecision",
    "AgentDisposition",
    "AgentGate",
    "AgentReview",
    "CommandReview",
    "CompiledActionPolicySet",
    "CompiledTemporalPolicySet",
    "CompiledToolSemanticsRegistry",
    "Decision",
    "EFFECT_CATALOG_SCHEMA_VERSION",
    "EFFECT_GRAPH_SCHEMA_VERSION",
    "ExecutionCapabilityProfile",
    "ExecutionContext",
    "FailThreshold",
    "MAN_INDEX_SCHEMA_VERSION",
    "MCPAdapter",
    "ObservationHistory",
    "ObservedResource",
    "Ordin",
    "PACK_LIST_SCHEMA_VERSION",
    "PACK_MANIFEST_SCHEMA_VERSION",
    "POLICY_SET_SCHEMA_VERSION",
    "PolicyEvaluation",
    "PolicyMatch",
    "PolicyResourceMatcher",
    "REVIEW_REQUEST_SCHEMA_VERSION",
    "REVIEW_SCHEMA_VERSION",
    "RISK_RULES_SCHEMA_VERSION",
    "RISK_SCHEMA_VERSION",
    "ReviewPolicy",
    "ReviewRequest",
    "RiskReview",
    "SEARCH_SCHEMA_VERSION",
    "SearchResult",
    "TEMPORAL_POLICY_SET_SCHEMA_VERSION",
    "TOOL_SEMANTICS_SCHEMA_VERSION",
    "TemporalActionEvidence",
    "TemporalPolicySet",
    "TemporalPredicate",
    "TemporalRule",
    "ToolCallAdapter",
    "ToolResourceBinding",
    "ToolSemanticRule",
    "ToolSemanticsRegistry",
    "TraceAction",
    "__version__",
    "default_temporal_policy",
    "derive_capabilities",
    "load_action_policy",
    "load_temporal_policy",
    "load_tool_semantics",
    "review_action",
]
