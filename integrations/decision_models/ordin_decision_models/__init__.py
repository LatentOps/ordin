"""Optional semantic decision layer. Import performs no inference/setup/network."""

from .protocol import (
    AsyncDecisionModel,
    DecisionModel,
    ProviderDescriptor,
    SanitizedDecisionState,
    SecurityQuestionSet,
)
from .privacy import (
    HostSemanticInspection,
    SelectedSnippet,
    request_semantic_inspection,
    sanitize_decision_state,
)
from .mock import MockDecisionModel
from .routing import RoutingPolicy, SemanticInspectionRouter
from .fusion import SemanticDecision

__all__ = [
    "AsyncDecisionModel",
    "DecisionModel",
    "ProviderDescriptor",
    "SanitizedDecisionState",
    "SecurityQuestionSet",
    "SelectedSnippet",
    "HostSemanticInspection",
    "request_semantic_inspection",
    "sanitize_decision_state",
    "MockDecisionModel",
    "RoutingPolicy",
    "SemanticInspectionRouter",
    "SemanticDecision",
]
