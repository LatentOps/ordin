"""Bounded graphs over sealed reviews and correlated evidence, never execution."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Sequence

from ordin.action import ActionEnvelope, ActionHistory, ActionReview
from ordin._runtime_json import digest as core_digest
from ordin.data import load_effect_catalog
from ordin.runtime_contract import derive_runtime_capability_contract
from ordin.runtime_observation import RuntimeEvidenceSource, RuntimeObservationHistory

from ._json import digest
from .gate import AssuranceDecision
from .host import AssuranceHostContext, HostEvidenceSource
from .models import (
    AttackEdge,
    AttackNode,
    AttackPathEvidence,
    EvidenceLink,
    InvariantSelectors,
    SecurityInvariant,
    SecurityProfileDraft,
    _EvidenceAuthority,
)
from .origins import InstructionOrigin, SourceUse, verify_source_use

_KINDS = {"shell", "tool", "mcp", "network", "file", "database", "process", "service", "unknown"}
_RESOURCES = {
    "path",
    "file",
    "directory",
    "url",
    "host",
    "endpoint",
    "tool",
    "secret",
    "credential",
    "unknown",
}


@dataclass(frozen=True)
class ReviewedAction:
    """Host correlation wrapper, checked again when constructing a graph."""

    decision: AssuranceDecision
    context: AssuranceHostContext

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        decision = self.decision
        if (
            not isinstance(decision, AssuranceDecision)
            or not isinstance(self.context, AssuranceHostContext)
            or not isinstance(decision.review, ActionReview)
        ):
            raise ValueError("graph input requires a sealed action review and host context")
        if (
            decision._authority is None
            or decision._authority.payload_digest != decision.evidence_digest
            or decision._authority.review_digest != core_digest(decision.review.as_dict())
            or decision.host_context_digest != self.context.digest
        ):
            raise ValueError("graph review/context binding changed")


def _evidence(
    origin, *, identity, action_digest=None, contract_id=None, session_digest=None, gaps=()
):
    values = dict(
        evidence_id=identity,
        origin=origin,
        source=None,
        action_digest=action_digest,
        contract_id=contract_id,
        session_digest=session_digest,
        proof_gaps=tuple(gaps),
    )
    preview = object.__new__(EvidenceLink)
    for key, value in values.items():
        object.__setattr__(preview, key, value)
    object.__setattr__(preview, "_authority", None)
    return EvidenceLink(**values, _authority=_EvidenceAuthority(preview.digest))


class _Graph:
    def __init__(self, max_nodes, max_edges, scope):
        self.nodes: dict[str, AttackNode] = {}
        self.edges: dict[str, AttackEdge] = {}
        self.max_nodes, self.max_edges = max_nodes, max_edges
        self.scope = scope
        self.gaps: set[str] = set()

    def node(self, kind, category, value, *, namespace=""):
        value_digest = core_digest(value)
        identity = (
            kind
            + ":"
            + digest("attack_node", [self.scope, namespace, kind, category, value_digest])[:24]
        )
        if identity not in self.nodes and len(self.nodes) >= self.max_nodes:
            self.gaps.add("Graph node budget reached; omitted relations remain unknown.")
            return None
        self.nodes.setdefault(identity, AttackNode(identity, kind, category, value_digest))
        return identity

    def edge(self, source, target, kind, evidence, *, gaps=(), confidence=None):
        if source is None or target is None:
            return
        identity = "edge:" + digest("attack_edge", [source, target, kind, evidence.digest])[:24]
        if identity not in self.edges and len(self.edges) >= self.max_edges:
            self.gaps.add("Graph edge budget reached; omitted relations remain unknown.")
            return
        kinds = {
            "runtime_backend_observed": "host_observed",
            "host_authenticated_source": "host_observed",
            "deterministically_derived": "deterministic_inference",
            "policy_verified": "deterministic_inference",
            "static_evidence": "deterministic_inference",
            "model_hypothesis": "model_hypothesis",
            "imported_claim": "imported_claim",
            "caller_asserted": "caller_asserted",
        }
        self.edges.setdefault(
            identity,
            AttackEdge(
                identity,
                source,
                target,
                kind,
                evidence,
                confidence,
                evidence_kind=kinds[evidence.origin],
                correlation_id=evidence.contract_id,
                proof_gaps=tuple(gaps),
            ),
        )


def build_attack_path(
    source: HostEvidenceSource,
    reviewed: Sequence[ReviewedAction],
    *,
    runtime_history: RuntimeObservationHistory | None = None,
    runtime_sources: Sequence[RuntimeEvidenceSource] = (),
    origins: Sequence[InstructionOrigin] = (),
    source_uses: Sequence[SourceUse] = (),
    hypotheses: Sequence[EvidenceLink] = (),
    max_nodes: int = 256,
    max_edges: int = 512,
) -> AttackPathEvidence:
    """Explain one same-principal/session/epoch sequence, focused on its final action.

    Reviewed effects predict requirements. Completed effects require correlated
    authenticated observations. Source spans establish bytes, not persuasion.
    Cross-agent paths require the later delegation verifier; they are refused
    here rather than merging histories by tool name or descriptive similarity.
    """
    if (
        not isinstance(source, HostEvidenceSource)
        or not isinstance(reviewed, (list, tuple))
        or not 1 <= len(reviewed) <= 32
        or any(not isinstance(row, ReviewedAction) for row in reviewed)
    ):
        raise ValueError("graph requires one to 32 typed host review records")
    if (
        type(max_nodes) is not int
        or not 1 <= max_nodes <= 256
        or type(max_edges) is not int
        or not 1 <= max_edges <= 512
    ):
        raise ValueError("invalid graph resource budget")
    for values, model, maximum in (
        (runtime_sources, RuntimeEvidenceSource, 32),
        (origins, InstructionOrigin, 128),
        (source_uses, SourceUse, 128),
        (hypotheses, EvidenceLink, 32),
    ):
        if (
            not isinstance(values, (list, tuple))
            or len(values) > maximum
            or any(not isinstance(v, model) for v in values)
        ):
            raise ValueError("graph requires bounded typed evidence collections")
    if len({v.origin_id for v in origins}) != len(origins) or len(
        {v.use_id for v in source_uses}
    ) != len(source_uses):
        raise ValueError("duplicate graph source handle")
    for row in reviewed:
        row.validate()
        if row.context.source.key != source.key:
            raise ValueError("cross-principal/session/epoch graph needs authenticated delegation")
    if any(
        s.session_digest != source.session_digest or s.policy_digest != source.runtime_policy_digest
        for s in runtime_sources
    ):
        raise ValueError("runtime source differs from graph host scope")
    if any(v.source_key != source.key for v in origins) or any(
        v.source_key != source.key for v in source_uses
    ):
        raise ValueError("instruction source belongs to another graph host scope")
    actions = tuple(
        ActionEnvelope.from_dict(row.decision.review.action.as_dict()) for row in reviewed
    )
    action_ids = [a.action_id for a in actions]
    if None in action_ids or len(set(action_ids)) != len(action_ids):
        raise ValueError("graph actions require unique retained IDs")
    history = ActionHistory(actions)
    if runtime_history is not None and not isinstance(runtime_history, RuntimeObservationHistory):
        raise ValueError("graph runtime evidence must be typed")
    runtime_history = runtime_history or RuntimeObservationHistory()
    correlated = runtime_history.correlate(history, allowed_sources=runtime_sources)
    if any(
        o.session_digest not in {None, source.session_digest}
        if o.trust == "caller_asserted"
        else o.session_digest != source.session_digest
        for o in runtime_history.observations
    ):
        raise ValueError("runtime observation belongs to another graph session")
    for row in reviewed:
        if row.decision.denied and any(
            o.outcome != "denied" for o in correlated.get(row.decision.review.action.action_id, ())
        ):
            raise ValueError("completed/allowed observation cannot follow an Assurance denial")
    graph = _Graph(max_nodes, max_edges, source.key)
    catalog = frozenset(load_effect_catalog())
    support: dict[str, EvidenceLink] = {}
    counter: dict[str, EvidenceLink] = {}
    principal = graph.node(
        "principal", "host_principal", {"principal": source.principal, "source_key": source.key}
    )
    action_nodes, decisions, contracts = {}, {}, {}
    observed_secret = predicted_secret = False
    completed_focus = refused_focus = False
    completed_focus_effects: set[str] = set()
    previous = None
    for index, row in enumerate(reviewed):
        decision, review = row.decision, row.decision.review
        assert isinstance(review, ActionReview)
        action_hash = core_digest(actions[index].as_dict())
        contract = derive_runtime_capability_contract(review)
        contracts[action_hash] = contract
        decisions[action_hash] = decision
        evidence = _evidence(
            "deterministically_derived",
            identity="review:" + action_hash[:24],
            action_digest=action_hash,
            contract_id=contract.contract_id,
            session_digest=source.session_digest,
            gaps=("Reviewed effects predict requirements; they do not establish execution.",),
        )
        support[evidence.digest] = evidence
        kind = review.action.kind if review.action.kind in _KINDS else "unknown"
        action_node = graph.node("action", kind, {"action_digest": action_hash})
        action_nodes[action_hash] = action_node
        graph.edge(action_node, principal, "proposed_by", evidence)
        if previous is not None:
            order_evidence = evidence
            prefix_digest = core_digest(ActionHistory(actions[:index]).as_dict())
            if (
                decision.history_digest != prefix_digest
                or row.context.history_digest != prefix_digest
            ):
                graph.gaps.add(
                    "Earlier history is outside this graph or ordering is caller supplied."
                )
                order_evidence = EvidenceLink(
                    "order:" + action_hash[:24],
                    "caller_asserted",
                    action_digest=action_hash,
                    session_digest=source.session_digest,
                    proof_gaps=(
                        "Supplied row order is not authenticated against the complete review history.",
                    ),
                )
            graph.edge(
                previous,
                action_node,
                "temporally_precedes",
                order_evidence,
                gaps=("Ordering establishes a temporal relation, not causal influence.",),
            )
        previous = action_node
        tool = graph.node(
            "tool_or_server",
            "normalized_identity",
            {
                "kind": review.action.kind,
                "runtime": review.action.parameters.get("runtime"),
                "server": review.action.parameters.get("server"),
                "tool": review.action.parameters.get("tool"),
                "operation": review.action.operation,
            },
        )
        graph.edge(action_node, tool, "requires_capability", evidence)
        capability = graph.node(
            "capability", "reviewed_requirements", {"contract_digest": contract.digest}
        )
        graph.edge(action_node, capability, "requires_capability", evidence)
        if len(review.resources) > 32 or len(review.effects) > 64:
            graph.gaps.add(
                "Review resource/effect detail exceeds graph budget; omitted detail remains unknown."
            )
        maxima = {
            "capability": [v.as_dict() for v in row.context.capability_authorities],
            "request": [v.as_dict() for v in row.context.request_authorities],
            "profile": decision.profile_digest,
        }
        boundary = graph.node(
            "boundary",
            "approved_maximum"
            if maxima["capability"] or maxima["request"]
            else "authority_unknown",
            maxima,
        )
        graph.edge(
            action_node,
            boundary,
            "crosses_boundary",
            evidence,
            gaps=("Declared software maxima require external enforcement at execution time.",),
        )
        for resource in review.resources[:32]:
            category = resource.type if resource.type in _RESOURCES else "unknown"
            if category in {"path", "file", "directory", "secret"}:
                if any(
                    effect in review.effects
                    for effect in ("filesystem.read", "filesystem.metadata_read", "secret.read")
                ):
                    target = graph.node(
                        "resource", category, resource.as_dict(), namespace=action_hash + ":input"
                    )
                    graph.edge(target, action_node, "read_from", evidence)
                if any(
                    effect in review.effects
                    for effect in (
                        "filesystem.write",
                        "filesystem.delete",
                        "filesystem.recursive_delete",
                        "filesystem.permission_change",
                    )
                ):
                    target = graph.node(
                        "resource", category, resource.as_dict(), namespace=action_hash + ":output"
                    )
                    graph.edge(action_node, target, "wrote_to", evidence)
            elif category in {"url", "host", "endpoint"}:
                target = graph.node("resource", category, resource.as_dict(), namespace=action_hash)
                graph.edge(
                    action_node,
                    target,
                    "sent_to",
                    evidence,
                    gaps=(
                        "A reviewed endpoint is an intended request target, not proof of transfer.",
                    ),
                )
        predicted_secret |= "secret.read" in review.effects
        if review.trajectory_categories:
            signal = graph.node(
                "control",
                "temporal_signal",
                {"categories": sorted(review.trajectory_categories)},
                namespace=action_hash,
            )
            graph.edge(
                action_node,
                signal,
                "correlates_to",
                evidence,
                gaps=("A temporal policy match is risk evidence, not causal or execution proof.",),
            )
        for effect in review.effects[:64]:
            safe_effect = effect if effect in catalog else "unknown_effect"
            if safe_effect == "unknown_effect":
                graph.gaps.add("An effect outside the fixed catalog has unknown semantics.")
            if effect in {
                "network.upload",
                "code.execute",
                "filesystem.write",
                "filesystem.delete",
                "filesystem.recursive_delete",
            }:
                sink = graph.node("sink", safe_effect, {"effect": effect}, namespace=action_hash)
                graph.edge(
                    action_node,
                    sink,
                    "sent_to" if effect == "network.upload" else "wrote_to",
                    evidence,
                )
        if decision.disposition != "execute":
            control = graph.node(
                "control",
                "review_denied" if decision.denied else "approval_required",
                {"decision_digest": decision.evidence_digest},
            )
            graph.edge(
                action_node,
                control,
                "enforced_by",
                evidence,
                gaps=(
                    "A review disposition records the caller-facing decision, not kernel enforcement.",
                ),
            )
            counter[evidence.digest] = evidence
        for evaluation in decision.invariant_evaluations:
            if evaluation.status in {"violated", "unsupported", "inconclusive"}:
                policy_evidence = _evidence(
                    "policy_verified",
                    identity="policy:" + evaluation.digest[:24],
                    action_digest=action_hash,
                    session_digest=source.session_digest,
                    gaps=(
                        "A protected profile match describes reviewed permission requirements, not runtime execution.",
                    ),
                )
                support[policy_evidence.digest] = policy_evidence
                control = graph.node(
                    "control",
                    "invariant_" + evaluation.status,
                    {"evaluation_digest": evaluation.digest},
                )
                graph.edge(action_node, control, "enforced_by", policy_evidence)
                counter[policy_evidence.digest] = policy_evidence
        action_id = review.action.action_id
        assert action_id is not None
        for observation in correlated.get(action_id, ()):
            authenticated = observation.trust in {"backend_observed", "backend_enforced"}
            obs_origin = "runtime_backend_observed" if authenticated else "caller_asserted"
            obs_evidence = _evidence(
                obs_origin,
                identity="observation:" + observation.digest[:24],
                action_digest=action_hash,
                contract_id=observation.contract_id,
                session_digest=source.session_digest,
                gaps=()
                if authenticated
                else ("Caller-asserted observation does not establish a completed effect.",),
            )
            observation_node = graph.node(
                "observation",
                "runtime_" + observation.outcome,
                {"observation_digest": observation.digest},
            )
            graph.edge(observation_node, action_node, "correlates_to", obs_evidence)
            support[obs_evidence.digest] = obs_evidence
            if authenticated and observation.outcome in {"denied", "failed"}:
                control = graph.node(
                    "control",
                    "backend_" + observation.outcome,
                    {"source_key": observation.source_key},
                    namespace=observation.digest,
                )
                graph.edge(action_node, control, "enforced_by", obs_evidence)
                counter[obs_evidence.digest] = obs_evidence
            observed_secret |= (
                authenticated
                and observation.outcome == "completed"
                and "secret.read" in observation.effects
            )
            if index == len(reviewed) - 1:
                if authenticated and observation.outcome == "completed":
                    completed_focus_effects.update(observation.effects)
                    if "secret.read" in observation.effects:
                        completed_focus_effects.add("filesystem.read")
                    if decision.requires_approval and not any(
                        a.action_digest == action_hash for a in row.context.approvals
                    ):
                        graph.gaps.add(
                            "Completion after escalation has no authenticated approval receipt in this graph."
                        )
                refused_focus |= authenticated and observation.outcome in {"denied", "failed"}
    origin_map = {v.digest: v for v in origins}
    for origin in origins:
        graph.node("source", origin.kind, {"origin_digest": origin.digest})
    sensitive_use = False
    for use in source_uses:
        used_origin = origin_map.get(use.origin_digest)
        action_node = action_nodes.get(use.action_digest)
        if (
            used_origin is None
            or use.action_digest not in decisions
            or not verify_source_use(
                source, used_origin, use, decisions[use.action_digest].review.action
            )
        ):
            raise ValueError("graph source use is not correlated to an exact retained action")
        source_node = graph.node("source", used_origin.kind, {"origin_digest": used_origin.digest})
        evidence = _evidence(
            "host_authenticated_source",
            identity="source-use:" + use.digest[:24],
            action_digest=use.action_digest,
            session_digest=source.session_digest,
            gaps=(
                "Host-declared exact byte inclusion does not establish persuasion or execution.",
            ),
        )
        graph.edge(source_node, action_node, "originated_from", evidence)
        support[evidence.digest] = evidence
        sensitive_use |= used_origin.classification == "sensitive"
        if used_origin.classification == "public":
            counter[evidence.digest] = evidence
            control = graph.node(
                "control", "host_classified_public", {"origin_digest": used_origin.digest}
            )
            graph.edge(
                source_node,
                control,
                "correlates_to",
                evidence,
                gaps=(
                    "Public classification is a scoped host declaration, not universal non-sensitivity proof.",
                ),
            )
        if use.usage == "instruction_context" and used_origin.kind != "authorized_user":
            hypothesis = EvidenceLink(
                "influence:" + use.digest[:24],
                "model_hypothesis",
                action_digest=use.action_digest,
                session_digest=source.session_digest,
                proof_gaps=("Untrusted instruction bytes were included; causation is unproven.",),
            )
            graph.edge(
                source_node,
                action_node,
                "hypothesized_influence",
                hypothesis,
                gaps=hypothesis.proof_gaps,
            )
            support[hypothesis.digest] = hypothesis
    focus_hash = core_digest(actions[-1].as_dict())
    focus_effects = set(reviewed[-1].decision.review.effects)
    relevant_effects = focus_effects & {
        "network.upload",
        "code.execute",
        "filesystem.write",
        "filesystem.delete",
        "filesystem.recursive_delete",
    }
    relevant_effects = relevant_effects or focus_effects
    completed_focus = bool(relevant_effects) and relevant_effects.issubset(completed_focus_effects)
    for hypothesis in hypotheses:
        if hypothesis.origin not in {
            "caller_asserted",
            "model_hypothesis",
            "imported_claim",
            "static_evidence",
        } or hypothesis.session_digest not in {None, source.session_digest}:
            raise ValueError("graph hypothesis cannot impersonate host evidence")
        if hypothesis.action_digest not in {None, focus_hash}:
            raise ValueError("graph hypothesis refers to another focus action")
        node = graph.node("source", "unknown_origin", {"evidence_digest": hypothesis.digest})
        graph.edge(
            node,
            action_nodes[focus_hash],
            "hypothesized_influence",
            hypothesis,
            gaps=hypothesis.proof_gaps,
        )
        support[hypothesis.digest] = hypothesis
    if not origins:
        graph.gaps.add(
            "Instruction/data origin spans are unavailable; influence remains unknown_origin."
        )
    if not completed_focus:
        graph.gaps.add("The focus action has no authenticated completed execution observation.")
    graph.gaps.add(
        "Temporal ordering and predicted effects do not prove a causal exploitation chain."
    )
    focus = reviewed[-1].decision
    focus_effects = set(focus.review.effects)
    impact = []
    if "network.upload" in focus_effects and (observed_secret or predicted_secret or sensitive_use):
        impact.append("possible_sensitive_data_egress")
    if (
        "trajectory_secret_exfiltration" in (focus.review.trajectory_categories or ())
        and not impact
    ):
        impact.append("possible_sensitive_data_egress")
        graph.gaps.add(
            "A temporal secret-flow signal alone does not establish authenticated secret exposure."
        )
        predicted_secret = True
    if "code.execute" in focus_effects:
        impact.append("possible_code_execution")
    if "trajectory_download_execute" in (focus.review.trajectory_categories or ()):
        impact.append("possible_untrusted_code_execution")
        graph.gaps.add(
            "Download/permission/execute ordering is a temporal hypothesis, not observed execution."
        )
    if "filesystem.write" in focus_effects:
        impact.append("possible_resource_mutation")
    statuses = [v.status for v in focus.invariant_evaluations]
    permissions = (
        "exceeds_boundary"
        if "violated" in statuses
        else "unsupported"
        if any(v in {"unsupported", "inconclusive"} for v in statuses)
        else "unknown"
    )
    boundary_digest = digest(
        "attack_authority_scope",
        {
            "source": source.key,
            "capability_maxima": [v.as_dict() for v in reviewed[-1].context.capability_authorities],
            "request_maxima": [v.as_dict() for v in reviewed[-1].context.request_authorities],
            "profile": focus.profile_digest,
            "configuration": focus.assurance_configuration_digest,
        },
    )
    cause_digest = digest(
        "attack_root_cause",
        {
            "boundary": boundary_digest,
            "kind": focus.review.action.kind,
            "operation": focus.review.action.operation,
            "impact": impact,
            "resource_digests": sorted(core_digest(r.as_dict()) for r in focus.review.resources),
            "controls": sorted(
                v.invariant_id for v in focus.invariant_evaluations if v.status != "satisfied"
            ),
        },
    )
    for row in reviewed:
        row.validate()  # Detect caller mutation while building, before returning evidence.
    return AttackPathEvidence(
        "path:"
        + digest(
            "attack_graph",
            [
                source.key,
                [v.decision.evidence_digest for v in reviewed],
                runtime_history.as_dict(),
                [v.digest for v in origins],
                [v.digest for v in source_uses],
            ],
        )[:24],
        source.repository,
        source.session_digest,
        tuple(graph.nodes[k] for k in sorted(graph.nodes)),
        tuple(graph.edges[k] for k in sorted(graph.edges)),
        tuple(support[k] for k in sorted(support)),
        tuple(counter[k] for k in sorted(counter)),
        tuple(sorted(graph.gaps)),
        exposure="established"
        if observed_secret or sensitive_use
        else "hypothesis"
        if predicted_secret
        else "unknown",
        reachability="blocked"
        if focus.denied or refused_focus
        else "established"
        if completed_focus
        else "hypothesis",
        possible_impact=tuple(impact),
        permissions=permissions,
        root_cause_digest=cause_digest,
        boundary_digest=boundary_digest,
        occurrence_ids=("occurrence:" + focus_hash[:24],),
        session_digests=(source.session_digest,),
    )


def deduplicate_attack_paths(paths: Sequence[AttackPathEvidence]) -> tuple[AttackPathEvidence, ...]:
    if (
        not isinstance(paths, (tuple, list))
        or len(paths) > 128
        or any(not isinstance(p, AttackPathEvidence) for p in paths)
    ):
        raise ValueError("deduplication requires bounded typed paths")
    grouped = {}
    for path in paths:
        key = (
            (
                path.root_cause_digest,
                path.boundary_digest,
                path.exposure,
                path.reachability,
                path.permissions,
            )
            if path.root_cause_digest and path.boundary_digest
            else (path.path_id,)
        )
        if key not in grouped:
            grouped[key] = path
        else:
            original = grouped[key]
            grouped[key] = replace(
                original,
                occurrence_ids=tuple(
                    dict.fromkeys((*original.occurrence_ids, *path.occurrence_ids))
                ),
            )
    return tuple(grouped.values())


def propose_attack_path_tests(path: AttackPathEvidence) -> SecurityProfileDraft:
    """Generate reviewable restrictions only; no test promotion or profile activation."""
    if not isinstance(path, AttackPathEvidence):
        raise ValueError("attack-path proposals require typed bounded evidence")
    suggestions = []
    if "possible_sensitive_data_egress" in path.possible_impact:
        suggestions.append(
            SecurityInvariant(
                "proposed-source-egress",
                "source_flow_guard",
                InvariantSelectors(effects=("network.upload",)),
                on_violation="escalate",
            )
        )
    if "possible_untrusted_code_execution" in path.possible_impact:
        suggestions.append(
            SecurityInvariant(
                "proposed-download-execute",
                "temporal_action_guard",
                InvariantSelectors(),
                authority_ref="trajectory_download_execute",
                on_violation="escalate",
            )
        )
    return SecurityProfileDraft(
        "graph-proposal:" + path.digest[:24],
        path.repository,
        "bounded_attack_path",
        risk_hypotheses=(
            "Path evidence identifies candidate invariants; safe reproduction and operator review are required.",
        ),
        unresolved_facts=tuple(
            dict.fromkeys(
                (*path.proof_gaps, "A graph does not confirm a vulnerability or install a policy.")
            )
        ),
        invariant_suggestions=tuple(suggestions),
        scan_digest=path.digest,
        completeness="partial",
    )


def render_attack_path(path: AttackPathEvidence) -> str:
    """Privacy-preserving Mermaid view; labels come from a fixed vocabulary."""
    if not isinstance(path, AttackPathEvidence):
        raise ValueError("renderer requires a typed bounded attack path")
    allowed = (
        _KINDS
        | _RESOURCES
        | {
            "host_principal",
            "normalized_identity",
            "reviewed_requirements",
            "approved_maximum",
            "authority_unknown",
            "authorized_user",
            "repository_file",
            "mcp_result",
            "web_content",
            "model_reasoning",
            "unknown_origin",
            "review_denied",
            "approval_required",
            "invariant_violated",
            "invariant_unsupported",
            "invariant_inconclusive",
            "temporal_signal",
            "backend_denied",
            "backend_failed",
            "runtime_completed",
            "runtime_denied",
            "runtime_failed",
            "runtime_allowed",
            "runtime_unknown",
            "host_classified_public",
            "delegation_denied",
            "delegation_approval",
            "network.upload",
            "filesystem.write",
            "filesystem.delete",
            "filesystem.recursive_delete",
            "code.execute",
        }
    )
    names = {node.node_id: f"n{index}" for index, node in enumerate(path.nodes)}
    lines = ["flowchart LR"]
    for node in path.nodes:
        category = node.category if node.category in allowed else "unknown"
        lines.append(f'  {names[node.node_id]}["{node.kind}: {category}"]')
    for edge in path.edges:
        lines.append(
            f"  {names[edge.source_id]} -->|{edge.kind} / {edge.evidence_kind}| {names[edge.target_id]}"
        )
    return "\n".join(lines)
