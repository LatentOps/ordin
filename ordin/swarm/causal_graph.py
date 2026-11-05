"""Bounded redacted causal projections from authenticated event journals."""

from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from typing import Any

from ordin._runtime_json import digest, freeze, thaw
from ordin.assurance.models import evidence_kind_for_origin

from .events import SwarmEvent
from .ingest import HostEventSource, SwarmEventIngestor
from .lineage import SwarmDelegationLink
from .models import SwarmContext

EDGE_KINDS = frozenset(
    {
        "delegated_to",
        "message_sent/received",
        "artifact_written/read",
        "observed_data_flow",
        "depends_on",
        "hypothesized_influence",
    }
)


@dataclass(frozen=True, slots=True)
class SwarmGraphView:
    scope_digest: str
    snapshot_digest: str
    nodes: tuple[Any, ...]
    edges: tuple[Any, ...]
    proof_gaps: tuple[str, ...]
    truncated: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "ordin.swarm_causal_graph.v1",
            "scope_digest": self.scope_digest,
            "snapshot_digest": self.snapshot_digest,
            "nodes": [thaw(node) for node in self.nodes],
            "edges": [thaw(edge) for edge in self.edges],
            "proof_gaps": list(self.proof_gaps),
            "truncated": self.truncated,
            "successful_exploitation": "unknown",
            "execution_authority": False,
        }

    def reachable(
        self, source_event: str, target_event: str, *, include_hypotheses: bool = False
    ) -> bool:
        known = {node["event_id"] for node in self.nodes}
        if source_event not in known or target_event not in known:
            return False
        outgoing: dict[str, list[str]] = {}
        for edge in self.edges:
            if edge["kind"] == "hypothesized_influence" and not include_hypotheses:
                continue
            outgoing.setdefault(edge["source_id"], []).append(edge["target_id"])
        seen = set()
        pending = [source_event]
        while pending:
            current = pending.pop()
            if current in seen:
                continue
            seen.add(current)
            if current == target_event:
                return True
            pending.extend(outgoing.get(current, ()))
        return False

    def mermaid(self) -> str:
        names = {node["event_id"]: f"n{index}" for index, node in enumerate(self.nodes)}
        lines = ["flowchart LR"]
        for node in self.nodes:
            lines.append(f'  {names[node["event_id"]]}["{node["event_kind"]}: {node["phase"]}"]')
        for edge in self.edges:
            lines.append(
                f"  {names[edge['source_id']]} -->|{edge['kind']}| {names[edge['target_id']]}"
            )
        return "\n".join(lines)


def _origin(event: SwarmEvent) -> str:
    if event.evidence_class in {"backend_observed", "backend_enforced"}:
        return "runtime_backend_observed"
    if event.evidence_class == "host_authenticated":
        return "host_authenticated_source"
    return "caller_asserted"


class SwarmCausalGraph:
    def __init__(
        self,
        ingestor: SwarmEventIngestor,
        source: HostEventSource,
        context: SwarmContext,
        *,
        max_nodes: int = 256,
        max_edges: int = 1024,
        event_window: int = 1024,
        source_time_window: float = 3600,
    ) -> None:
        if type(ingestor) is not SwarmEventIngestor or type(context) is not SwarmContext:
            raise ValueError("causal graph requires protected event scope")
        for name, value, maximum in (
            ("max_nodes", max_nodes, 4096),
            ("max_edges", max_edges, 16384),
            ("event_window", event_window, 16384),
        ):
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError(f"invalid graph {name}")
        if type(source_time_window) not in {int, float} or not 1 <= source_time_window <= 86400:
            raise ValueError("invalid graph source time window")
        ingestor.snapshot_binding(source, context)
        self._ingestor, self._source, self._context = ingestor, source, context
        self._nodes, self._edges, self._window = max_nodes, max_edges, event_window
        self._time_window = source_time_window
        self._delegations: list[SwarmDelegationLink] = []
        self._lock = RLock()

    def bind_delegation(self, link: SwarmDelegationLink) -> None:
        if type(link) is not SwarmDelegationLink:
            raise ValueError("delegation graph binding requires protected issuer evidence")
        link.validate()
        self._require_current_context(link.parent_context)
        self._require_current_context(link.child_context)
        scope = (self._context.identity.tenant_id, self._context.identity.swarm_id)
        if (link.child_context.identity.tenant_id, link.child_context.identity.swarm_id) != scope:
            raise ValueError("cross-tenant delegation graph link")
        with self._lock:
            if len(self._delegations) >= 256:
                raise ValueError("delegation graph link capacity reached")
            self._delegations.append(link)

    def _require_current_context(self, context: SwarmContext) -> None:
        with self._ingestor._lock:
            for binding in self._ingestor._source_ids.values():
                if binding.context is context:
                    self._ingestor._registry.authenticate(context, binding.channel, binding.adapter)
                    return
        raise ValueError("graph delegation context has no protected current sender")

    def build(self) -> SwarmGraphView:
        with self._lock, self._ingestor._lock:
            before = self._ingestor.snapshot_binding(self._source, self._context)
            rows = list(self._ingestor.snapshot())
            gaps = set()
            truncated = len(rows) > self._window
            if truncated:
                gaps.add("event_window_truncated")
                rows = rows[-self._window :]
            latest: dict[str, float] = {}
            for row in rows:
                if row.event.evidence_class == "caller_asserted":
                    continue
                latest[row.event.source_id] = max(
                    latest.get(row.event.source_id, 0), row.event.timestamp
                )
            selected = {}
            scope = (self._context.identity.tenant_id, self._context.identity.swarm_id)
            for row in rows:
                event = row.event
                if event.digest != row.digest:
                    raise ValueError("stored event digest changed")
                if (event.identity.tenant_id, event.identity.swarm_id) != scope:
                    raise ValueError("cross-tenant graph event")
                if event.identity.policy_epoch != self._context.identity.policy_epoch:
                    gaps.add("stale_policy_epoch")
                    continue
                binding = self._ingestor._source_ids.get(event.source_id)
                if binding is None:
                    raise ValueError("graph event has no protected sender")
                if binding.collector is not None and binding.collector.key != binding.collector_key:
                    raise ValueError("graph runtime collector policy scope changed")
                if binding.contiguous < event.source_sequence:
                    gaps.add("source_sequence_gap")
                if event.evidence_class == "caller_asserted":
                    gaps.add("caller_asserted_event")
                try:
                    self._ingestor._registry.authenticate(
                        binding.context, binding.channel, binding.adapter
                    )
                except ValueError:
                    gaps.add("stale_principal_or_grant")
                    continue
                if (
                    event.timestamp
                    < latest.get(event.source_id, event.timestamp) - self._time_window
                ):
                    gaps.add("source_time_window_truncated")
                    truncated = True
                    continue
                selected[event.event_id] = event
            ordered = sorted(selected)
            if len(ordered) > self._nodes:
                gaps.add("node_budget_truncated")
                truncated = True
                ordered = ordered[: self._nodes]
                selected = {key: selected[key] for key in ordered}
            nodes = []
            for key in ordered:
                event = selected[key]
                phase = (
                    "unverified"
                    if event.evidence_class == "caller_asserted"
                    else "observed_completion"
                    if event.event_kind == "observed" and event.observed_outcome == "completed"
                    else "observed_attempt"
                    if event.event_kind == "observed"
                    else "host_result"
                    if event.event_kind in {"completed", "failed", "denied", "canceled"}
                    else "intended"
                )
                nodes.append(
                    freeze(
                        {
                            "event_id": event.event_id,
                            "event_digest": event.digest,
                            "event_kind": event.event_kind,
                            "actor_digest": digest(
                                {
                                    "registry_id": event.registry_id,
                                    "identity": event.identity.as_dict(),
                                }
                            ),
                            "session_digest": digest(
                                [
                                    event.registry_id,
                                    event.identity.session_id,
                                    event.identity.generation,
                                ]
                            ),
                            "action_digest": event.action_digest,
                            "resource_digests": list(event.resource_digests),
                            "phase": phase,
                            "evidence_class": event.evidence_class,
                            "observed_outcome": event.observed_outcome,
                        }
                    )
                )
            delegated = set()
            for link in self._delegations:
                link.validate()
                self._require_current_context(link.parent_context)
                self._require_current_context(link.child_context)
                delegated.add((link.parent_context.identity, link.child_context.identity))
            edges: list[Any] = []
            for key in ordered:
                target = selected[key]
                for ref in sorted(target.parent_event_ids, key=lambda value: value.event_id):
                    parent = selected.get(ref.event_id)
                    if parent is None:
                        gaps.add("unresolved_parent")
                        continue
                    kind = "depends_on"
                    origin = _origin(target)
                    if "caller_asserted" in {parent.evidence_class, target.evidence_class}:
                        kind, origin = "hypothesized_influence", "caller_asserted"
                    elif parent.identity != target.identity:
                        shared = set(parent.resource_digests).intersection(target.resource_digests)
                        if (
                            parent.event_kind == "message_sent"
                            and target.event_kind == "message_received"
                            and shared
                        ):
                            kind = "message_sent/received"
                        elif (
                            parent.event_kind == "artifact_write"
                            and target.event_kind == "artifact_read"
                            and shared
                        ):
                            kind = "artifact_written/read"
                        elif (
                            parent.event_kind == "delegated"
                            and (parent.identity, target.identity) in delegated
                        ):
                            kind, origin = "delegated_to", "policy_verified"
                        else:
                            gaps.add("unauthenticated_cross_agent_join")
                            continue
                    if len(edges) >= self._edges:
                        gaps.add("edge_budget_truncated")
                        truncated = True
                        continue
                    edges.append(
                        freeze(
                            {
                                "source_id": parent.event_id,
                                "target_id": target.event_id,
                                "kind": kind,
                                "evidence_origin": origin,
                                "evidence_kind": evidence_kind_for_origin(origin),
                                "resource_digests": sorted(
                                    set(parent.resource_digests).intersection(
                                        target.resource_digests
                                    )
                                ),
                            }
                        )
                    )
                    if (
                        kind in {"message_sent/received", "artifact_written/read"}
                        and len(edges) >= self._edges
                    ):
                        gaps.add("edge_budget_truncated")
                        truncated = True
                    if (
                        kind in {"message_sent/received", "artifact_written/read"}
                        and len(edges) < self._edges
                    ):
                        edges.append(
                            freeze(
                                {
                                    "source_id": parent.event_id,
                                    "target_id": target.event_id,
                                    "kind": "observed_data_flow",
                                    "evidence_origin": "host_authenticated_source",
                                    "evidence_kind": evidence_kind_for_origin(
                                        "host_authenticated_source"
                                    ),
                                    "resource_digests": sorted(
                                        set(parent.resource_digests).intersection(
                                            target.resource_digests
                                        )
                                    ),
                                }
                            )
                        )
            after = self._ingestor.snapshot_binding(self._source, self._context)
            if before != after:
                raise ValueError("graph evidence snapshot changed during projection")
            return SwarmGraphView(
                digest(scope), before, tuple(nodes), tuple(edges), tuple(sorted(gaps)), truncated
            )
