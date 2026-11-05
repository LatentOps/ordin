"""Bounded causal temporal evaluation over authenticated cross-agent evidence."""

from __future__ import annotations

from dataclasses import dataclass, replace
from contextlib import nullcontext
import hashlib
import heapq
from threading import RLock
import time
from typing import Any, Callable
from uuid import uuid4

from ordin.action import ActionEnvelope, ActionReview, _temporal_evidence_for_action
from ordin.agent import AgentGate
from ordin.api import Ordin
from ordin.assurance.origins import InstructionOrigin, _selected_value
from ordin._runtime_json import digest, freeze, thaw
from ordin.runtime_observation import RuntimeObservation
from ordin.session import configuration_digest
from ordin.temporal import TemporalActionEvidence

from .causal_graph import SwarmCausalGraph
from .events import ACTION_STAGES, SwarmEvent
from .facts import SwarmAssessment, SwarmAssessmentSource
from .ingest import HostEventSource
from .models import SwarmContext, SwarmIdentity, identifier, timestamp
from .source_flow import LineageHandle, LineageUse, SwarmSourceFlow
from .temporal_policy import (
    CompiledSwarmTemporalPolicy,
    SwarmTemporalPolicySet,
    SwarmTemporalPredicate,
    SwarmTemporalRule,
    default_swarm_temporal_policy,
    load_swarm_temporal_policy,
)

CURRENT = "@current"


@dataclass(frozen=True, slots=True)
class SwarmTemporalFinding:
    rule_id: str
    severity: str
    prevention: str
    aggregation: str
    evidence: tuple[Any, ...]
    path_event_ids: tuple[str, ...]
    current_action_digest: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "prevention": self.prevention,
            "aggregation": self.aggregation,
            "status": "matched",
            "evidence": [thaw(v) for v in self.evidence],
            "path_event_ids": list(self.path_event_ids),
            "current_action_digest": self.current_action_digest,
            "successful_exploitation": "unknown",
        }


@dataclass(frozen=True, slots=True)
class SwarmTemporalEvaluation:
    policy_digest: str
    snapshot_digest: str
    action_digest: str
    status: str
    findings: tuple[SwarmTemporalFinding, ...]
    proof_gaps: tuple[str, ...]
    states_examined: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "ordin.swarm_temporal_evaluation.v1",
            "policy_digest": self.policy_digest,
            "snapshot_digest": self.snapshot_digest,
            "action_digest": self.action_digest,
            "status": self.status,
            "findings": [v.as_dict() for v in self.findings],
            "proof_gaps": list(self.proof_gaps),
            "states_examined": self.states_examined,
            "execution_authority": False,
        }


@dataclass(frozen=True, slots=True)
class _Fact:
    event_id: str
    event_digest: str
    identity: SwarmIdentity
    source: HostEventSource
    observed_at: float
    semantics: TemporalActionEvidence
    labels: frozenset[str]
    origins: frozenset[str]
    sinks: frozenset[str]
    sink_kinds: frozenset[str]
    lineage: tuple[LineageHandle, ...]
    lineage_complete: bool
    observation: RuntimeObservation | None
    origin_handles: tuple[InstructionOrigin, ...]
    fingerprint: str


@dataclass(frozen=True, slots=True)
class _Node:
    event_id: str
    identity: SwarmIdentity
    event_kind: str
    evidence_class: str
    observed_at: float | None
    semantics: TemporalActionEvidence
    labels: frozenset[str]
    origins: frozenset[str]
    sinks: frozenset[str]
    sink_kinds: frozenset[str]
    lineage_complete: bool
    action_key: str
    related_labels: frozenset[str] = frozenset()
    related_origins: frozenset[str] = frozenset()
    related_complete: bool = False
    lineage_related: bool = False


@dataclass(frozen=True, slots=True)
class _State:
    matched: tuple[str, ...]
    path: tuple[str, ...]
    transfers: frozenset[str]


class SwarmTemporalEngine:
    """Protected host evaluator; JSON/timestamps alone never establish a fact.

    Collection is explicit. record_event captures normalized host-clock times,
    deterministic core semantics and optional original protected lineage/origins.
    A negative result needs a complete protected collection window. The engine
    never assumes that an empty, late-attached or truncated history is benign.
    """

    def __init__(
        self,
        graph: SwarmCausalGraph,
        policy: SwarmTemporalPolicySet | CompiledSwarmTemporalPolicy,
        *,
        flow: SwarmSourceFlow | None = None,
        ordin: Ordin | None = None,
        clock: Callable[[], float] = time.monotonic,
        max_facts: int = 4096,
        max_states: int = 4096,
        max_transitions: int = 65536,
    ) -> None:
        if type(graph) is not SwarmCausalGraph or not callable(clock):
            raise ValueError("protected graph and temporal host clock required")
        if flow is not None and (type(flow) is not SwarmSourceFlow or flow._graph is not graph):
            raise ValueError("temporal lineage must share the original protected graph")
        selected = policy.compile() if type(policy) is SwarmTemporalPolicySet else policy
        if type(selected) is not CompiledSwarmTemporalPolicy:
            raise ValueError("typed temporal policy required")
        selected.policy.__post_init__()
        if selected.patterns != tuple(rule.pattern for rule in selected.policy.rules):
            raise ValueError("compiled temporal policy changed")
        for value, maximum in ((max_facts, 16384), (max_states, 32768), (max_transitions, 262144)):
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError("invalid bounded temporal machine quota")
        if ordin is not None and type(ordin) is not Ordin:
            raise ValueError("temporal semantics require protected Ordin configuration")
        self._graph, self._flow, self._policy = graph, flow, selected
        self._policy_digest = selected.policy.digest
        self._ordin = replace(ordin or Ordin(), audit=None)
        self._semantic_digest = configuration_digest(AgentGate(self._ordin))
        self._clock, self._last_now = clock, 0.0
        self._fact_limit, self._state_limit, self._transition_limit = (
            max_facts,
            max_states,
            max_transitions,
        )
        self._facts: dict[str, _Fact] = {}
        self._coverage: dict[HostEventSource, tuple[SwarmContext, float]] = {}
        self._authorities: set[SwarmAssessmentSource] = set()
        self._incarnation = uuid4().hex
        self._generation = 0
        self._lock = RLock()

    def _now(self) -> float:
        now = timestamp(self._clock())
        if now < self._last_now:
            raise ValueError("temporal clock moved backward")
        self._last_now = now
        return now

    @property
    def policy_digest(self) -> str:
        with self._lock:
            return self._policy_digest

    @property
    def configuration_digest(self) -> str:
        with self._lock:
            if configuration_digest(AgentGate(self._ordin)) != self._semantic_digest:
                raise ValueError("protected temporal semantics changed")
            return digest(
                {
                    "policy": self.policy_digest,
                    "semantics": self._semantic_digest,
                    "incarnation": self._incarnation,
                    "generation": self._generation,
                    "max_facts": self._fact_limit,
                    "max_states": self._state_limit,
                    "max_transitions": self._transition_limit,
                }
            )

    @property
    def binding_digest(self) -> str:
        """Read-only bounded state binding for a host gate/coordinator snapshot."""
        with self._lock, self._flow._lock if self._flow else nullcontext():
            with self._graph._lock, self._graph._ingestor._lock:
                view = self._graph.build()
                sources = []
                for handle, binding in self._graph._ingestor._sources.items():
                    try:
                        state = self._graph._ingestor._registry.state(
                            binding.context, binding.channel, binding.adapter
                        )
                    except ValueError:
                        state = "unavailable"
                    sources.append((handle.source_id, digest(binding.context.as_dict()), state))
                return digest(
                    {
                        "configuration": self.configuration_digest,
                        "graph": view.as_dict(),
                        "facts": sorted(
                            (key, fact.fingerprint) for key, fact in self._facts.items()
                        ),
                        "coverage": sorted(
                            (source.source_id, digest(row[0].as_dict()), row[1])
                            for source, row in self._coverage.items()
                        ),
                        "sources": sorted(sources),
                    }
                )

    def _fence(self) -> None:
        for source in self._authorities:
            source.fence()

    def upgrade_policy(self, policy: SwarmTemporalPolicySet) -> None:
        """Host-only upgrade: fresh revision, cleared coverage and fenced old receipts."""
        if type(policy) is not SwarmTemporalPolicySet:
            raise ValueError("typed temporal policy required")
        policy.__post_init__()
        with self._lock:
            if (
                policy.policy_id != self._policy.policy.policy_id
                or policy.revision <= self._policy.policy.revision
            ):
                raise ValueError("temporal policy revision must increase")
            self._fence()
            self._policy = policy.compile()
            self._policy_digest = policy.digest
            self._coverage.clear()
            self._generation += 1

    def cover(self, source: HostEventSource, *, complete_from: float) -> None:
        """Host collector declares complete collection since this local clock point.

        This API must not be exposed to model/transport input. Pre-enrollment
        history cannot be declared complete, including an already-running agent.
        """
        with self._lock, self._graph._lock, self._graph._ingestor._lock:
            binding = self._graph._ingestor._source(source)
            start = timestamp(complete_from)
            if not binding.context.enrolled_at <= start <= self._now():
                raise ValueError("temporal coverage cannot authenticate pre-attach/future history")
            if binding.role == "asserted":
                raise ValueError("caller assertions cannot establish temporal coverage")
            previous = self._coverage.get(source)
            if previous is not None and start < previous[1]:
                raise ValueError("temporal coverage cannot be extended retrospectively")
            if previous == (binding.context, start):
                return
            self._coverage[source] = (binding.context, start)
            self._fence()

    def _sinks(self, action: ActionEnvelope) -> tuple[frozenset[str], frozenset[str]]:
        matches = (
            [sink for sink in self._flow._sinks.values() if sink.matches(action)]
            if self._flow
            else []
        )
        return frozenset(sink.sink_id for sink in matches), frozenset(
            sink.kind for sink in matches
        ) | (
            {action.kind}
            if action.kind in {"network", "mcp", "tool", "file", "database"}
            else set()
        )

    def _semantics(
        self,
        action: ActionEnvelope,
        observation: RuntimeObservation | None = None,
        *,
        review: ActionReview | None = None,
    ) -> TemporalActionEvidence:
        if configuration_digest(AgentGate(self._ordin)) != self._semantic_digest:
            raise ValueError("protected temporal action semantics changed")
        review = review if review is not None else self._ordin.review_action(action)
        if digest(review.action.as_dict()) != digest(action.as_dict()):
            raise ValueError("temporal action must be normalized before exact binding")
        evidence = _temporal_evidence_for_action(
            action,
            review=review,
            tool_semantics=self._ordin.tool_semantics,
            rest_semantics=self._ordin.rest_semantics,
            runtime_observations=(observation,) if observation else (),
        )
        if review.decision == "ask":
            evidence = TemporalActionEvidence(
                evidence.kind,
                evidence.operation,
                evidence.signals | {"signal:swarm-semantics-unavailable"},
            )
        return evidence

    def record_event(
        self,
        source: HostEventSource,
        event_id: str,
        *,
        action: ActionEnvelope | None = None,
        lineage: tuple[LineageHandle, ...] = (),
        origins: tuple[InstructionOrigin, ...] = (),
        observation: RuntimeObservation | None = None,
        observed_at: float | None = None,
    ) -> None:
        """Bind facts after actual authenticated ingest; never accept effect/label JSON."""
        identifier(event_id, "event_id")
        if (
            type(lineage) is not tuple
            or len(lineage) > 8
            or type(origins) is not tuple
            or len(origins) > 8
        ):
            raise ValueError("bounded original temporal evidence handles required")
        with self._lock:
            if self._flow:
                with self._flow._lock:
                    self._record_event(
                        source, event_id, action, lineage, origins, observation, observed_at
                    )
            else:
                self._record_event(
                    source, event_id, action, lineage, origins, observation, observed_at
                )

    def _record_event(
        self, source, event_id, action, lineage, origins, observation, observed_at
    ) -> None:
        with self._graph._lock, self._graph._ingestor._lock:
            ingestor = self._graph._ingestor
            binding = ingestor._source(source)
            row = ingestor._records.get(event_id)
            if (
                row is None
                or row.event.digest != row.digest
                or row.event.source_id != binding.source_id
                or row.event.identity != binding.context.identity
            ):
                raise ValueError("temporal fact does not match its original authenticated event")
            event = row.event
            if event.evidence_class == "caller_asserted":
                raise ValueError("caller assertions cannot issue temporal facts")
            ingestor._evidence(binding, event, observation)
            existing = self._facts.get(event_id)
            at = (
                (existing.observed_at if existing is not None else self._now())
                if observed_at is None
                else timestamp(observed_at)
            )
            if not binding.context.enrolled_at <= at <= self._now():
                raise ValueError("invalid protected temporal observation time")
            semantics = TemporalActionEvidence("event", event.event_kind, frozenset())
            sinks: frozenset[str] = frozenset()
            sink_kinds: frozenset[str] = frozenset()
            if action is not None:
                original_action = action
                action = (
                    ActionEnvelope.from_dict(action.as_dict())
                    if type(action) is ActionEnvelope
                    else action
                )
                if (
                    type(action) is not ActionEnvelope
                    or digest(action.as_dict()) != event.action_digest
                    or action.action_id != event.action_id
                ):
                    raise ValueError("temporal semantics belong to another exact action")
                semantics = self._semantics(action, observation)
                sinks, sink_kinds = self._sinks(action)
                if digest(original_action.as_dict()) != event.action_digest:
                    raise ValueError("temporal action changed during capture")
            elif observation is not None:
                raise ValueError("observed temporal effects require the original action")
            labels: set[str] = set()
            origin_kinds: set[str] = set()
            complete = False
            if lineage or origins:
                if self._flow is None:
                    raise ValueError(
                        "temporal source evidence requires its protected lineage service"
                    )
                actor = self._flow._actor(source)
                complete = bool(lineage)
                for handle in lineage:
                    data = self._flow._record(handle)
                    if (
                        data.actor is not actor
                        or data.event_id != event_id
                        or data.content_digest not in event.resource_digests
                    ):
                        raise ValueError("temporal lineage belongs to another source/event")
                    labels.update(data.sensitivity.labels)
                    complete = complete and data.complete and data.established
                for origin in origins:
                    if type(origin) is not InstructionOrigin:
                        raise ValueError("original protected instruction origin required")
                    origin.__post_init__()
                    if (
                        origin.source_key != actor.host_key
                        or origin.content_digest not in event.resource_digests
                    ):
                        raise ValueError("temporal origin belongs to another host or exact bytes")
                    origin_kinds.add(origin.kind)
            fingerprint = digest(
                [
                    row.digest,
                    at,
                    sorted(semantics.signals),
                    semantics.kind,
                    semantics.operation,
                    sorted(labels),
                    sorted(origin_kinds),
                    sorted(sinks),
                    sorted(sink_kinds),
                    complete,
                    [self._flow._digest(self._flow._record(h)) for h in lineage]
                    if self._flow
                    else [],
                    [o.digest for o in origins],
                    observation.digest if observation else None,
                ]
            )
            previous = self._facts.get(event_id)
            if previous is not None:
                if previous.fingerprint != fingerprint:
                    raise ValueError("temporal fact conflicts with its original capture")
                return
            if len(self._facts) >= self._fact_limit:
                raise ValueError("temporal fact capacity reached")
            self._facts[event_id] = _Fact(
                event_id,
                row.digest,
                event.identity,
                source,
                at,
                semantics,
                frozenset(labels),
                frozenset(origin_kinds),
                sinks,
                sink_kinds,
                lineage,
                complete,
                observation,
                origins,
                fingerprint,
            )
            self._fence()

    @staticmethod
    def _relation(candidate: SwarmIdentity, previous: SwarmIdentity, relation: str) -> bool:
        if relation == "any":
            return True
        if relation == "same":
            return candidate == previous
        if relation == "different":
            return candidate != previous
        if relation == "sibling":
            return (
                candidate != previous
                and candidate.parent_agent_id is not None
                and (candidate.parent_agent_id, candidate.parent_generation)
                == (previous.parent_agent_id, previous.parent_generation)
            )
        return (
            candidate.parent_agent_id == previous.agent_id
            and candidate.parent_generation == previous.generation
        )

    @staticmethod
    def _matches(
        predicate: SwarmTemporalPredicate,
        node: _Node,
        transfers: frozenset[str],
        *,
        previous: _Node | None = None,
        data_guard: bool = False,
    ) -> bool:
        labels, origins, complete = node.labels, node.origins, node.lineage_complete
        if data_guard and node.event_id != CURRENT:
            if (
                predicate.labels_any
                or predicate.origins_any
                or predicate.transfer_edges
                or predicate.requires_lineage
            ) and not node.lineage_related:
                return False
            labels, origins, complete = (
                node.related_labels,
                node.related_origins,
                node.related_complete,
            )
        return (
            node.evidence_class in predicate.evidence_classes
            and (not predicate.event_kinds or node.event_kind in predicate.event_kinds)
            and predicate.semantic_match(node.semantics)
            and (not predicate.labels_any or bool(labels.intersection(predicate.labels_any)))
            and (not predicate.origins_any or bool(origins.intersection(predicate.origins_any)))
            and (
                not predicate.transfer_edges
                or bool(transfers.intersection(predicate.transfer_edges))
            )
            and (not predicate.sink_ids or bool(node.sinks.intersection(predicate.sink_ids)))
            and (
                not predicate.sink_kinds or bool(node.sink_kinds.intersection(predicate.sink_kinds))
            )
            and (not predicate.requires_lineage or complete)
            and (not predicate.labels_any or complete)
            and (
                previous is None
                or SwarmTemporalEngine._relation(
                    node.identity, previous.identity, predicate.agent_relation
                )
            )
        )

    def _current(self, context, source, action, uses, now):
        ingestor = self._graph._ingestor
        binding = ingestor._source(source)
        if binding.context is not context:
            raise ValueError("current temporal proposal belongs to another protected context")
        if (
            type(uses) is not tuple
            or len(uses) > 8
            or any(type(use) is not LineageUse for use in uses)
        ):
            raise ValueError("bounded original current source uses required")
        labels: set[str] = set()
        lineage_events: set[str] = set()
        gaps: set[str] = set()
        complete = bool(uses)
        closure: dict[str, list[Any]] = {}
        if uses:
            if self._flow is None:
                raise ValueError("current temporal lineage requires its protected service")
            actor = self._flow._actor(source)
            for use in uses:
                use.__post_init__()
                row = self._flow._record(use.handle)
                raw = _selected_value(action, use.argument_path)
                if (
                    row.actor is not actor
                    or len(raw) != row.byte_length
                    or hashlib.sha256(raw).hexdigest() != row.content_digest
                ):
                    raise ValueError("current temporal use does not match exact proposed bytes")
                labels.update(row.sensitivity.labels)
                lineage_events.add(row.event_id)
                complete = complete and row.complete and row.established
                gaps.update(row.gaps)
            pending = [use.handle for use in uses]
            queued = set(pending)
            while pending:
                if len(queued) > min(self._state_limit, self._fact_limit):
                    complete = False
                    gaps.add("current_lineage_quota_exhausted")
                    break
                try:
                    row = self._flow._record(pending.pop())
                except ValueError:
                    complete = False
                    gaps.add("current_lineage_ancestor_unavailable")
                    continue
                closure.setdefault(row.event_id, []).append(row)
                complete = complete and row.complete and row.established
                for parent in row.parents:
                    if parent not in queued:
                        queued.add(parent)
                        pending.append(parent)
        sinks, kinds = self._sinks(action)
        current_review = self._ordin.review_action(action)
        if current_review.decision == "ask":
            gaps.add("current_semantics_unavailable")
        return (
            _Node(
                CURRENT,
                context.identity,
                "proposed",
                "current_proposal",
                now,
                self._semantics(action, review=current_review),
                frozenset(labels),
                frozenset(),
                sinks,
                kinds,
                complete,
                digest(action.as_dict()),
            ),
            lineage_events,
            gaps,
            closure,
        )

    def evaluate(
        self,
        context: SwarmContext,
        source: HostEventSource,
        action: ActionEnvelope,
        *,
        parent_event_ids: tuple[str, ...],
        uses: tuple[LineageUse, ...] = (),
    ) -> SwarmTemporalEvaluation:
        if (
            type(context) is not SwarmContext
            or type(action) is not ActionEnvelope
            or type(parent_event_ids) is not tuple
            or len(parent_event_ids) > 8
            or any(type(value) is not str for value in parent_event_ids)
            or len(set(parent_event_ids)) != len(parent_event_ids)
        ):
            raise ValueError("exact current temporal scope/action/parents required")
        for parent in parent_event_ids:
            identifier(parent, "parent_event_id")
        normalized = ActionEnvelope.from_dict(action.as_dict())
        action_digest = digest(normalized.as_dict())
        with self._lock:
            if self._flow:
                with self._flow._lock:
                    result = self._evaluate(context, source, normalized, parent_event_ids, uses)
            else:
                result = self._evaluate(context, source, normalized, parent_event_ids, uses)
            if digest(action.as_dict()) != action_digest or result.action_digest != action_digest:
                raise ValueError("current temporal action changed during evaluation")
            return result

    def _evaluate(self, context, source, action, parent_event_ids, uses) -> SwarmTemporalEvaluation:
        with self._graph._lock, self._graph._ingestor._lock:
            now = self._now()
            ingestor = self._graph._ingestor
            before = ingestor.snapshot_binding(source, context)
            view = self._graph.build()
            current, use_events, current_gaps, closure = self._current(
                context, source, action, uses, now
            )
            gaps = set(view.proof_gaps) | current_gaps
            nodes: dict[str, _Node] = {}
            for item in view.nodes:
                event_id = item["event_id"]
                event = ingestor._records[event_id].event
                fact = self._facts.get(event_id)
                if fact is not None:
                    self._validate_fact(fact, event)
                related = closure.get(event_id, ())
                related_labels = frozenset(
                    label for row in related for label in row.sensitivity.labels
                )
                content_digests = {row.content_digest for row in related}
                related_origins = set()
                if fact:
                    for content_digest in content_digests:
                        kinds = {
                            origin.kind
                            for origin in fact.origin_handles
                            if origin.content_digest == content_digest
                        }
                        if "authorized_user" in kinds and len(kinds) > 1:
                            gaps.add("source_origin_ambiguous")
                        else:
                            related_origins.update(kinds)
                nodes[event_id] = _Node(
                    event_id,
                    event.identity,
                    event.event_kind,
                    event.evidence_class,
                    fact.observed_at if fact else None,
                    fact.semantics
                    if fact
                    else TemporalActionEvidence("event", event.event_kind, frozenset()),
                    fact.labels if fact else frozenset(),
                    fact.origins if fact else frozenset(),
                    fact.sinks if fact else frozenset(),
                    fact.sink_kinds if fact else frozenset(),
                    fact.lineage_complete if fact else False,
                    digest(
                        [
                            event.registry_id,
                            event.identity.as_dict(),
                            event.action_id,
                            event.action_digest,
                        ]
                    )
                    if event.action_id
                    else event_id,
                    related_labels,
                    frozenset(related_origins),
                    bool(related) and all(row.complete and row.established for row in related),
                    bool(related),
                )
            incoming: dict[str, dict[str, set[str]]] = {key: {} for key in nodes}
            for edge in view.edges:
                if edge["kind"] != "hypothesized_influence":
                    incoming[edge["target_id"]].setdefault(edge["source_id"], set()).add(
                        edge["kind"]
                    )
            incoming[CURRENT] = {}
            for parent in parent_event_ids:
                if parent not in nodes:
                    gaps.add("current_parent_unavailable")
                elif nodes[parent].identity != context.identity:
                    gaps.add("current_cross_agent_handoff_unverified")
                else:
                    incoming[CURRENT][parent] = {"depends_on"}
            nodes[CURRENT] = current
            ancestors = self._ancestor_paths(CURRENT, incoming)
            if not use_events <= set(ancestors):
                gaps.add("current_source_use_not_causal")
            if any(nodes[key].observed_at is None for key in ancestors):
                gaps.add("host_observation_time_unavailable")
            findings = []
            states = 0
            applicable = False
            for rule in self._policy.policy.rules:
                if states >= self._transition_limit:
                    gaps.add("temporal_machine_quota_exhausted")
                    break
                final = rule.pattern[-1]
                if not final.semantic_match(current.semantics) or (
                    final.sink_kinds and not current.sink_kinds.intersection(final.sink_kinds)
                ):
                    continue
                # Unknown current provenance cannot turn a potentially sensitive
                # upload or code proposal into a definitive non-match.
                if (final.labels_any or final.requires_lineage) and not current.lineage_complete:
                    gaps.add("current_lineage_unavailable")
                    applicable = True
                    continue
                if final.sink_ids and not current.sinks:
                    gaps.add("protected_sink_identity_unavailable")
                    applicable = True
                    continue
                if not self._matches(
                    final, current, frozenset().union(*(incoming[CURRENT].values()))
                ):
                    continue
                applicable = True
                if any(
                    predicate.effects_any or predicate.action_kinds or predicate.operations
                    for predicate in rule.pattern[:-1]
                ):
                    if any(
                        key != CURRENT
                        and nodes[key].event_kind in ACTION_STAGES
                        and (
                            nodes[key].semantics.kind == "event"
                            or "signal:swarm-semantics-unavailable" in nodes[key].semantics.signals
                        )
                        and self._window(rule, ancestors[key], nodes, now)
                        for key in ancestors
                    ):
                        gaps.add("prior_action_semantics_unavailable")
                if rule.same_sink:
                    if not current.sinks:
                        gaps.add("protected_sink_identity_unavailable")
                        continue
                    if any(
                        key != CURRENT
                        and not nodes[key].sinks
                        and rule.pattern[0].semantic_match(nodes[key].semantics)
                        for key in ancestors
                    ):
                        gaps.add("protected_sink_identity_unavailable")
                if rule.scope == "task" and context.identity.task_id is None:
                    gaps.add("protected_task_identity_unavailable")
                    continue
                if (
                    "current_source_use_not_causal" in gaps
                    or "current_cross_agent_handoff_unverified" in gaps
                ):
                    continue
                if rule.aggregation == "causal_ancestors":
                    match, count, exceeded = self._count(rule, nodes, incoming, ancestors, now)
                else:
                    match, count, exceeded = self._path(rule, nodes, incoming, ancestors, now)
                states += count
                if exceeded or states > self._transition_limit:
                    gaps.add("temporal_machine_quota_exhausted")
                if match is not None:
                    findings.append(self._finding(rule, match[0], match[1], nodes, action))
                if not self._covered(rule, context, now):
                    gaps.add("complete_temporal_window_unavailable")
            if not applicable:
                gaps.intersection_update({"current_semantics_unavailable"})
            if before != ingestor.snapshot_binding(source, context):
                raise ValueError("temporal evidence changed during evaluation")
            status = "violated" if findings else "unknown" if gaps else "satisfied"
            return SwarmTemporalEvaluation(
                self.policy_digest,
                digest(
                    [
                        view.snapshot_digest,
                        self._incarnation,
                        self._generation,
                        sorted((key, fact.fingerprint) for key, fact in self._facts.items()),
                        sorted(
                            (handle.source_id, row[1]) for handle, row in self._coverage.items()
                        ),
                        list(parent_event_ids),
                        [
                            (self._flow._digest(self._flow._record(use.handle)), use.argument_path)
                            for use in uses
                        ]
                        if self._flow
                        else [],
                    ]
                ),
                digest(action.as_dict()),
                status,
                tuple(findings),
                tuple(sorted(gaps)),
                min(states, self._transition_limit + 1),
            )

    def _validate_fact(self, fact: _Fact, event: SwarmEvent) -> None:
        binding = self._graph._ingestor._source(fact.source)
        if event.digest != fact.event_digest or event.identity != fact.identity:
            raise ValueError("protected temporal event changed")
        self._graph._ingestor._evidence(binding, event, fact.observation)
        for origin in fact.origin_handles:
            origin.__post_init__()
            if self._flow is None or origin.source_key != self._flow._actor(fact.source).host_key:
                raise ValueError("protected temporal source scope changed")
        if self._flow:
            for handle in fact.lineage:
                self._flow._record(handle)

    @staticmethod
    def _ancestor_paths(target, incoming):
        paths = {}
        pending = [(1, (target,), target)]
        while pending:
            _, path, key = heapq.heappop(pending)
            if key in paths:
                continue
            paths[key] = path
            if len(path) >= 128:
                continue
            for parent in sorted(incoming.get(key, {})):
                if parent not in paths:
                    candidate = (parent,) + path
                    heapq.heappush(pending, (len(candidate), candidate, parent))
        return paths

    def _covered(self, rule, context, now):
        for handle, binding in self._graph._ingestor._sources.items():
            if binding.role == "asserted" or (
                rule.scope == "task"
                and binding.context.identity.task_id != context.identity.task_id
            ):
                continue
            try:
                self._graph._ingestor._registry.authenticate(
                    binding.context, binding.channel, binding.adapter
                )
            except ValueError:
                return False
            coverage = self._coverage.get(handle)
            if (
                coverage is None
                or coverage[0] is not binding.context
                or coverage[1] > now - rule.within_seconds
            ):
                return False
        return True

    @staticmethod
    def _window(rule, path, nodes, now):
        times = [nodes[key].observed_at for key in path]
        return len(path) <= rule.within_events and all(
            value is not None and now - rule.within_seconds <= value <= now for value in times
        )

    def _path(self, rule, nodes, incoming, ancestors, now):
        outgoing: dict[str, set[str]] = {key: set() for key in ancestors}
        degree = {key: 0 for key in ancestors}
        for key in ancestors:
            for parent in incoming.get(key, {}):
                if parent in ancestors:
                    outgoing[parent].add(key)
                    degree[key] += 1
        heap = [key for key, count in degree.items() if not count]
        heapq.heapify(heap)
        states: dict[str, set[_State]] = {}
        examined = 0
        retained = 0
        while heap:
            key = heapq.heappop(heap)
            node = nodes[key]
            here: set[_State] = set()
            if (
                key != CURRENT
                and (
                    rule.scope != "task" or node.identity.task_id == nodes[CURRENT].identity.task_id
                )
                and self._matches(
                    rule.pattern[0],
                    node,
                    frozenset().union(*(incoming.get(key, {}).values())),
                    data_guard=bool(
                        rule.pattern[-1].requires_lineage or rule.pattern[-1].labels_any
                    ),
                )
            ):
                here.add(_State((key,), (key,), frozenset()))
            for parent, kinds in sorted(incoming.get(key, {}).items()):
                for state in sorted(
                    states.get(parent, ()),
                    key=lambda value: (value.matched, value.path, sorted(value.transfers)),
                ):
                    examined += 1
                    if examined > self._transition_limit:
                        return None, examined, True
                    path = state.path + (key,)
                    if not self._window(rule, path, nodes, now) or (
                        rule.scope == "task"
                        and node.identity.task_id != nodes[CURRENT].identity.task_id
                    ):
                        continue
                    transfers = state.transfers | kinds
                    progress = len(state.matched)
                    if progress < len(rule.pattern) and self._matches(
                        rule.pattern[progress],
                        node,
                        frozenset(transfers),
                        previous=nodes[state.matched[-1]],
                        data_guard=bool(
                            rule.pattern[-1].requires_lineage or rule.pattern[-1].labels_any
                        ),
                    ):
                        matched = state.matched + (key,)
                        if len(matched) == len(rule.pattern) and key == CURRENT:
                            if not rule.same_sink or all(
                                nodes[event].sinks.intersection(nodes[CURRENT].sinks)
                                for event in matched[:-1]
                            ):
                                return (matched, path), examined, False
                        elif key != CURRENT:
                            here.add(_State(matched, path, frozenset()))
                    if key != CURRENT:
                        here.add(_State(state.matched, path, frozenset(transfers)))
                    if len(here) > self._state_limit:
                        return None, examined, True
            retained += len(here)
            if retained > self._state_limit:
                return None, examined, True
            states[key] = here
            for child in sorted(outgoing[key]):
                degree[child] -= 1
                if degree[child] == 0:
                    heapq.heappush(heap, child)
        return None, examined, False

    def _count(self, rule, nodes, incoming, ancestors, now):
        selected: dict[str, tuple[str, tuple[str, ...]]] = {}
        count = 0
        predicate = rule.pattern[0]
        current = nodes[CURRENT]
        for key in sorted(ancestors):
            if key == CURRENT:
                continue
            count += 1
            if count > self._state_limit or count > self._transition_limit:
                return None, count, True
            node = nodes[key]
            if not self._window(rule, ancestors[key], nodes, now) or (
                rule.scope == "task" and node.identity.task_id != current.identity.task_id
            ):
                continue
            if not self._matches(
                predicate,
                node,
                frozenset().union(*(incoming.get(key, {}).values())),
                previous=current,
                data_guard=bool(rule.pattern[-1].requires_lineage or rule.pattern[-1].labels_any),
            ):
                continue
            if rule.same_sink and not node.sinks.intersection(current.sinks):
                continue
            group = (
                digest(node.identity.as_dict())
                if rule.count_by == "agents"
                else node.action_key
                if rule.count_by == "actions"
                else key
            )
            selected.setdefault(group, (key, ancestors[key]))
        if len(selected) < rule.quota:
            return None, count, False
        chosen = sorted(selected.values(), key=lambda row: (len(row[1]), row[0]))[: rule.quota]
        matched = tuple(key for key, _ in chosen) + (CURRENT,)
        path = tuple(sorted({key for _, values in chosen for key in values if key != CURRENT})) + (
            CURRENT,
        )
        if len(path) > rule.within_events:
            return None, count, True
        return (matched, path), count, False

    @staticmethod
    def _finding(rule, matched, path, nodes, action):
        evidence = tuple(
            freeze(
                {
                    "event_id": key,
                    "evidence_class": nodes[key].evidence_class,
                    "actor_digest": digest(nodes[key].identity.as_dict()),
                    "event_kind": nodes[key].event_kind,
                    "effect_evidence": rule.pattern[
                        -1 if key == CURRENT else min(index, len(rule.pattern) - 2)
                    ].effect_evidence,
                }
            )
            for index, key in enumerate(matched)
            if key != CURRENT
        )
        return SwarmTemporalFinding(
            rule.rule_id,
            rule.severity,
            rule.prevention,
            rule.aggregation,
            evidence,
            tuple(key for key in path if key != CURRENT),
            digest(action.as_dict()),
        )

    def issue_assessment(
        self,
        context: SwarmContext,
        source: HostEventSource,
        action: ActionEnvelope,
        *,
        authority: SwarmAssessmentSource,
        policy_digest: str,
        snapshot_digest: str,
        parent_event_ids: tuple[str, ...],
        uses: tuple[LineageUse, ...] = (),
        check_id: str = "temporal",
        lifetime: float = 30,
    ) -> SwarmAssessment:
        if type(authority) is not SwarmAssessmentSource:
            raise ValueError("original protected temporal assessment authority required")
        with self._lock, self._flow._lock if self._flow else nullcontext():
            if authority not in self._authorities and len(self._authorities) >= 256:
                raise ValueError("temporal assessment authority capacity reached")
            self._authorities.add(authority)
            if self._flow:
                with self._flow._lock:
                    if (
                        authority not in self._flow._authorities
                        and len(self._flow._authorities) >= 256
                    ):
                        raise ValueError("lineage assessment authority capacity reached")
                    self._flow._authorities.add(authority)
            result = self.evaluate(
                context, source, action, parent_event_ids=parent_event_ids, uses=uses
            )
            if digest(action.as_dict()) != result.action_digest:
                raise ValueError("current temporal action changed before assessment")
            return authority.issue(
                check_id=check_id,
                status=result.status,
                action_digest=result.action_digest,
                context_digest=digest(context.as_dict()),
                policy_digest=policy_digest,
                snapshot_digest=snapshot_digest,
                lifetime=lifetime,
                reason_code="temporal." + result.status,
            )


__all__ = [
    "SwarmTemporalEngine",
    "SwarmTemporalFinding",
    "SwarmTemporalEvaluation",
    "SwarmTemporalPredicate",
    "SwarmTemporalRule",
    "SwarmTemporalPolicySet",
    "CompiledSwarmTemporalPolicy",
    "default_swarm_temporal_policy",
    "load_swarm_temporal_policy",
]
