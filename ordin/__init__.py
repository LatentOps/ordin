"""Ordin public API for command intelligence and pre-execution safety."""

__version__ = "0.1.0"

SEARCH_SCHEMA_VERSION = "ordin.search_result.v1"
RISK_SCHEMA_VERSION = "ordin.risk_review.v1"
REVIEW_SCHEMA_VERSION = "ordin.review.v1"
REVIEW_REQUEST_SCHEMA_VERSION = "ordin.review_request.v1"
ACTION_TRACE_SCHEMA_VERSION = "ordin.action_trace.v1"
RISK_RULES_SCHEMA_VERSION = "ordin.risk_rules.v1"
MAN_INDEX_SCHEMA_VERSION = "ordin.man_index.v1"
EFFECT_CATALOG_SCHEMA_VERSION = "ordin.effect_catalog.v1"
EFFECT_GRAPH_SCHEMA_VERSION = "ordin.effect_graph.v1"
PACK_MANIFEST_SCHEMA_VERSION = "ordin.command_pack.v1"
PACK_LIST_SCHEMA_VERSION = "ordin.pack_list.v1"

from .agent import AgentDecision, AgentDisposition, AgentGate
from .api import Ordin
from .context import ExecutionContext, ReviewRequest
from .policy import Decision, FailThreshold, ReviewPolicy
from .review import CommandReview
from .risk import RiskReview
from .search import SearchResult
from .trace import ActionTrace, TraceAction

__all__ = [
    "ACTION_TRACE_SCHEMA_VERSION",
    "ActionTrace",
    "AgentDecision",
    "AgentDisposition",
    "AgentGate",
    "CommandReview",
    "Decision",
    "EFFECT_CATALOG_SCHEMA_VERSION",
    "EFFECT_GRAPH_SCHEMA_VERSION",
    "ExecutionContext",
    "FailThreshold",
    "MAN_INDEX_SCHEMA_VERSION",
    "Ordin",
    "PACK_LIST_SCHEMA_VERSION",
    "PACK_MANIFEST_SCHEMA_VERSION",
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
]
