"""Authenticated parent/child graph composition without sharing child histories."""

from typing import Sequence

from ordin._runtime_json import digest as core_digest
from ordin.runtime_observation import RuntimeEvidenceSource, RuntimeObservationHistory

from ._json import digest
from .attack_paths import ReviewedAction, build_attack_path, _evidence
from .delegation import DelegationIssuer, IssuedDelegation
from .delegating_gate import DelegatedDecision
from .host import HostEvidenceSource
from .models import AttackEdge, AttackNode, AttackPathEvidence
from .origins import InstructionOrigin, SourceUse


def build_delegated_attack_path(
    issuer: DelegationIssuer,
    grant: IssuedDelegation,
    parent_source: HostEvidenceSource,
    child_source: HostEvidenceSource,
    parent_reviews: Sequence[ReviewedAction],
    child_reviews: Sequence[DelegatedDecision],
    *,
    child_origins: Sequence[InstructionOrigin] = (),
    child_source_uses: Sequence[SourceUse] = (),
    parent_runtime_history: RuntimeObservationHistory | None = None,
    parent_runtime_sources: Sequence[RuntimeEvidenceSource] = (),
    child_runtime_history: RuntimeObservationHistory | None = None,
    child_runtime_sources: Sequence[RuntimeEvidenceSource] = (),
) -> AttackPathEvidence:
    """Current issued relationship and exact host-declared cross-action source lineage.

    Delegation establishes an authority relationship, not causation. Parent and
    child reviews/observations remain independently scoped. No graph permission
    or backend execution is minted by composing their evidence.
    """
    if (
        not isinstance(issuer, DelegationIssuer)
        or not isinstance(grant, IssuedDelegation)
        or not isinstance(parent_source, HostEvidenceSource)
        or not isinstance(child_source, HostEvidenceSource)
        or not isinstance(parent_reviews, (list, tuple))
        or not isinstance(child_reviews, (list, tuple))
        or len(parent_reviews) + len(child_reviews) > 32
    ):
        raise ValueError("cross-agent graph requires bounded protected host inputs")
    with issuer._lock:
        now = issuer._now()
        issuer._require_current(grant, child_source, now)
        parent_id = grant.record.parent_grant_id
        parent = issuer._issued.get(parent_id) if parent_id is not None else None
        if parent is None or grant.record.parent_principal != parent_source.principal:
            raise ValueError("cross-agent graph has no authenticated current parent relationship")
        issuer._require_current(parent, parent_source, now)
        if not child_reviews or any(
            not isinstance(row, DelegatedDecision)
            or row._seal is None
            or row._seal.issuer_key != issuer._issuer_key
            or row._seal.payload_digest != row.digest
            or row.grant_digest != grant.digest
            or row.issuer_generation != issuer._generation
            or row._context.source.key != child_source.key
            for row in child_reviews
        ):
            raise ValueError("cross-agent child evidence lacks current sealed delegated reviews")
        child_rows = tuple(ReviewedAction(row.assurance, row._context) for row in child_reviews)
        if child_runtime_history is not None and any(
            row.denied
            and any(
                o.action_digest == row.action_digest and o.outcome != "denied"
                for o in child_runtime_history.observations
            )
            for row in child_reviews
        ):
            raise ValueError("completed evidence cannot follow a delegated denial")
        parent_graph = build_attack_path(
            parent_source,
            parent_reviews,
            runtime_history=parent_runtime_history,
            runtime_sources=parent_runtime_sources,
        )
        child_graph = build_attack_path(
            child_source,
            child_rows,
            origins=child_origins,
            source_uses=child_source_uses,
            runtime_history=child_runtime_history,
            runtime_sources=child_runtime_sources,
        )
        parent_actions = {row.decision.action_digest for row in parent_reviews}
        nodes = {n.node_id: n for n in (*parent_graph.nodes, *child_graph.nodes)}
        edges = {e.edge_id: e for e in (*parent_graph.edges, *child_graph.edges)}
        if len(nodes) > 256 or len(edges) + 1 > 512:
            raise ValueError("cross-agent graph exceeds bounded component budget")
        relation = _evidence(
            "policy_verified",
            identity="delegation:" + grant.digest[:24],
            gaps=(
                "Current delegation establishes bounded authority, not causal influence or physical process isolation.",
            ),
        )
        parent_principal = next(n.node_id for n in parent_graph.nodes if n.kind == "principal")
        child_principal = next(n.node_id for n in child_graph.nodes if n.kind == "principal")
        edge = AttackEdge(
            "delegated:" + grant.digest[:24],
            parent_principal,
            child_principal,
            "delegated_to",
            relation,
            correlation_id=grant.record.grant_id,
        )
        edges[edge.edge_id] = edge
        gaps = set((*parent_graph.proof_gaps, *child_graph.proof_gaps))
        support = {
            e.digest: e
            for e in (*parent_graph.supporting_evidence, *child_graph.supporting_evidence, relation)
        }
        counter = {
            e.digest: e for e in (*parent_graph.counterevidence, *child_graph.counterevidence)
        }
        for row in child_reviews:
            if not row.may_execute:
                action_node = next(
                    n.node_id
                    for n in child_graph.nodes
                    if n.kind == "action"
                    and n.value_digest == core_digest({"action_digest": row.action_digest})
                )
                control_id = "delegated-control:" + row.digest[:24]
                nodes[control_id] = AttackNode(
                    control_id,
                    "control",
                    "delegation_denied" if row.denied else "delegation_approval",
                    row.digest,
                )
                evidence = _evidence(
                    "policy_verified",
                    identity="delegated-review:" + row.digest[:24],
                    action_digest=row.action_digest,
                    session_digest=child_source.session_digest,
                    gaps=(
                        "The delegated disposition is a software review requirement, not physical enforcement.",
                    ),
                )
                link = AttackEdge(
                    "delegated-review:" + row.digest[:24],
                    action_node,
                    control_id,
                    "enforced_by",
                    evidence,
                )
                edges[link.edge_id] = link
                support[evidence.digest] = counter[evidence.digest] = evidence
        parent_nodes = {n.value_digest: n.node_id for n in parent_graph.nodes if n.kind == "action"}
        child_nodes = {n.value_digest: n.node_id for n in child_graph.nodes if n.kind == "source"}
        for origin in child_origins:
            if origin.parent_action_digest is not None:
                if origin.parent_action_digest not in parent_actions:
                    raise ValueError("child source references an unretained/foreign parent action")
                evidence = _evidence(
                    "host_authenticated_source",
                    identity="lineage:" + origin.digest[:24],
                    action_digest=origin.parent_action_digest,
                    gaps=(
                        "Host-declared parent output lineage does not prove persuasion or a completed cross-agent transfer.",
                    ),
                )
                parent_node = parent_nodes[
                    core_digest({"action_digest": origin.parent_action_digest})
                ]
                child_node = child_nodes[core_digest({"origin_digest": origin.digest})]
                link = AttackEdge(
                    "lineage:" + origin.digest[:24],
                    parent_node,
                    child_node,
                    "correlates_to",
                    evidence,
                    proof_gaps=evidence.proof_gaps,
                )
                edges[link.edge_id] = link
                support[evidence.digest] = evidence
        if len(edges) > 512 or len(nodes) > 256:
            raise ValueError("cross-agent correlation edge budget exceeded")
        if not any(o.parent_action_digest in parent_actions for o in child_origins):
            gaps.add(
                "No authenticated cross-action source span supplied; actions are related only by delegation."
            )
        boundary = digest(
            "delegated_graph_boundary",
            [parent_graph.boundary_digest, child_graph.boundary_digest, grant.digest],
        )
        return AttackPathEvidence(
            "delegated-path:"
            + digest("delegated_graph", [parent_graph.digest, child_graph.digest, grant.digest])[
                :24
            ],
            child_source.repository,
            session_digest=digest(
                "delegated_graph_sessions", [parent_source.key, child_source.key, grant.digest]
            ),
            nodes=tuple(nodes[k] for k in sorted(nodes)),
            edges=tuple(edges[k] for k in sorted(edges)),
            supporting_evidence=tuple(support[k] for k in sorted(support)),
            counterevidence=tuple(counter[k] for k in sorted(counter)),
            proof_gaps=tuple(sorted(gaps)),
            exposure=child_graph.exposure,
            reachability="blocked" if child_reviews[-1].denied else child_graph.reachability,
            permissions="exceeds_boundary"
            if child_reviews[-1].verification is not None
            and child_reviews[-1].verification.result == "exceeds_boundary"
            else child_graph.permissions,
            possible_impact=child_graph.possible_impact,
            root_cause_digest=child_graph.root_cause_digest,
            boundary_digest=boundary,
            occurrence_ids=tuple(
                dict.fromkeys((*parent_graph.occurrence_ids, *child_graph.occurrence_ids))
            ),
            session_digests=tuple(
                dict.fromkeys((parent_source.session_digest, child_source.session_digest))
            ),
        )
