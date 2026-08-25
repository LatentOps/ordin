"""Ordin public API for command intelligence and pre-execution safety."""

__version__ = "0.2.0.dev0"

SEARCH_SCHEMA_VERSION = "ordin.search_result.v1"
RISK_SCHEMA_VERSION = "ordin.risk_review.v1"
REVIEW_SCHEMA_VERSION = "ordin.review.v1"
REVIEW_REQUEST_SCHEMA_VERSION = "ordin.review_request.v1"
ACTION_ENVELOPE_SCHEMA_VERSION = "ordin.action_envelope.v1"
ACTION_REVIEW_SCHEMA_VERSION = "ordin.action_review.v1"
ACTION_TRACE_SCHEMA_VERSION = "ordin.action_trace.v1"
POLICY_SET_SCHEMA_VERSION = "ordin.policy_set.v1"
RISK_RULES_SCHEMA_VERSION = "ordin.risk_rules.v1"
MAN_INDEX_SCHEMA_VERSION = "ordin.man_index.v1"
EFFECT_CATALOG_SCHEMA_VERSION = "ordin.effect_catalog.v1"
EFFECT_GRAPH_SCHEMA_VERSION = "ordin.effect_graph.v1"
PACK_MANIFEST_SCHEMA_VERSION = "ordin.command_pack.v1"
PACK_LIST_SCHEMA_VERSION = "ordin.pack_list.v1"

from .action import ActionEnvelope, ActionResource, ActionReview, review_action
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
from .agent import AgentDecision, AgentDisposition, AgentGate
from .api import Ordin
from .context import ExecutionContext, ReviewRequest
from .policy import Decision, FailThreshold, ReviewPolicy
from .review import CommandReview
from .risk import RiskReview
from .search import SearchResult
from .trace import ActionTrace, TraceAction

__all__ = [
    "ACTION_ENVELOPE_SCHEMA_VERSION",
    "ACTION_REVIEW_SCHEMA_VERSION",
    "ACTION_TRACE_SCHEMA_VERSION",
    "ActionEnvelope",
    "ActionPolicyCondition",
    "ActionPolicyRule",
    "ActionPolicySet",
    "ActionResource",
    "ActionReview",
    "ActionTrace",
    "AgentDecision",
    "AgentDisposition",
    "AgentGate",
    "CommandReview",
    "CompiledActionPolicySet",
    "Decision",
    "EFFECT_CATALOG_SCHEMA_VERSION",
    "EFFECT_GRAPH_SCHEMA_VERSION",
    "ExecutionContext",
    "FailThreshold",
    "MAN_INDEX_SCHEMA_VERSION",
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
    "TraceAction",
    "__version__",
    "load_action_policy",
    "review_action",
]
