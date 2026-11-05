"""Authenticated, bounded local ingest. Events do not grant execution authority."""

from __future__ import annotations

from dataclasses import dataclass, field
from threading import RLock

from ordin.runtime_observation import RuntimeEvidenceSource, RuntimeObservation
from ordin._runtime_json import digest as runtime_digest

from .events import EventRef, REVIEW_BOUND_STAGES, SwarmEvent, _hex, _text
from .identity import HostChannel
from .journal import EventJournal, JournalRecord, _MemoryEventJournal
from .models import SwarmContext, SwarmIdentity, identifier
from .registry import AgentRegistry

_LIFECYCLE = ("proposed", "reviewed", "reserved", "committed", "forwarded", "completed")


@dataclass(frozen=True, eq=False, slots=True)
class HostEventSource:
    """Opaque protected sender handle; constructing a matching value issues nothing."""

    source_id: str


@dataclass
class _Source:
    context: SwarmContext
    channel: HostChannel
    adapter: object
    source_id: str
    role: str
    collector: RuntimeEvidenceSource | None
    collector_key: str | None
    sequences: dict[int, str] = field(default_factory=dict)
    contiguous: int = 0


@dataclass(frozen=True, slots=True)
class ActionEventState:
    event_ids: tuple[str, ...]
    stages: tuple[str, ...]
    missing_stages: tuple[str, ...]
    unresolved_parents: tuple[EventRef, ...]
    sequence_incomplete: bool
    causally_complete: bool
    authenticated_completion: bool
    authenticated_observation: bool
    observed_outcomes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class IngestReceipt:
    event_id: str
    digest: str
    ingest_index: int
    duplicate: bool
    gaps: tuple[str, ...]


class SwarmEventIngestor:
    def __init__(
        self,
        registry: AgentRegistry,
        *,
        journal: EventJournal | None = None,
        max_events: int = 4096,
        max_sources: int = 256,
        sequence_window: int = 128,
        max_causal_depth: int = 64,
    ) -> None:
        for name, value, maximum in (
            ("max_events", max_events, 16384),
            ("max_sources", max_sources, 4096),
            ("sequence_window", sequence_window, 1024),
            ("max_causal_depth", max_causal_depth, 128),
        ):
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError(f"invalid bounded {name}")
        self._registry = registry
        self._journal = journal if journal is not None else _MemoryEventJournal(max_events)
        self._max_events, self._max_sources = max_events, max_sources
        self._window, self._max_depth = sequence_window, max_causal_depth
        self._sources: dict[HostEventSource, _Source] = {}
        self._source_ids: dict[str, _Source] = {}
        self._records: dict[str, JournalRecord] = {}
        self._depths: dict[str, int] = {}
        self._children: dict[str, set[str]] = {}
        self._action_records: dict[tuple[str, SwarmIdentity, str, str | None], list[str]] = {}
        self._action_digests: dict[tuple[str, SwarmIdentity, str], str] = {}
        self._action_reviews: dict[tuple[str, SwarmIdentity, str], str] = {}
        self._scope: tuple[str, str] | None = None
        self._lock = RLock()

    def bind_source(
        self,
        context: SwarmContext,
        channel: HostChannel,
        adapter: object,
        *,
        source_id: str,
        role: str = "gateway",
        collector: RuntimeEvidenceSource | None = None,
    ) -> HostEventSource:
        """Host-only: retain verified sender/collector instances outside agent control."""
        identifier(source_id, "source_id")
        if type(role) is not str or role not in {"gateway", "collector", "asserted"}:
            raise ValueError("unknown protected sender role")
        if role == "collector":
            if type(collector) is not RuntimeEvidenceSource:
                raise ValueError("collector source requires a protected runtime evidence source")
            collector.__post_init__()
        elif collector is not None:
            raise ValueError("unexpected runtime collector")
        with self._lock:
            self._registry.authenticate(context, channel, adapter)
            scope = (context.identity.tenant_id, context.identity.swarm_id)
            if self._scope is not None and self._scope != scope:
                raise ValueError("cross-scope event sender")
            if len(self._sources) >= self._max_sources or source_id in self._source_ids:
                raise ValueError("sender capacity reached or duplicate sender ID")
            source = HostEventSource(source_id)
            binding = _Source(
                context,
                channel,
                adapter,
                source_id,
                role,
                collector,
                collector.key if collector else None,
            )
            self._scope = scope
            self._sources[source] = binding
            self._source_ids[source_id] = binding
            return source

    def _source(self, source: HostEventSource) -> _Source:
        if type(source) is not HostEventSource:
            raise ValueError("unknown protected event sender")
        binding = self._sources.get(source)
        if binding is None or source.source_id != binding.source_id:
            raise ValueError("unknown or changed protected event sender")
        self._registry.authenticate(binding.context, binding.channel, binding.adapter)
        return binding

    def _evidence(
        self,
        binding: _Source,
        event: SwarmEvent,
        observation: RuntimeObservation | None,
    ) -> None:
        if event.evidence_class == "caller_asserted":
            if binding.role == "collector" or observation is not None:
                raise ValueError("caller assertions cannot masquerade as collector evidence")
            return
        if event.evidence_class == "host_authenticated":
            if (
                binding.role != "gateway"
                or observation is not None
                or event.event_kind == "observed"
            ):
                raise ValueError("event requires its protected host gateway")
            return
        if binding.role != "collector" or event.event_kind != "observed":
            raise ValueError("runtime evidence requires the protected collector path")
        if type(observation) is not RuntimeObservation or binding.collector is None:
            raise ValueError("runtime evidence requires an original sealed observation")
        observation.__post_init__()
        if (
            binding.collector.key != binding.collector_key
            or observation.source_key != binding.collector_key
            or observation.trust != event.evidence_class
            or observation.action_id != event.action_id
            or observation.action_digest != event.action_digest
            or observation.digest != event.observation_digest
            or observation.outcome != event.observed_outcome
            or event.resource_digests
            != tuple(
                sorted({runtime_digest(resource.as_dict()) for resource in observation.resources})
            )
        ):
            raise ValueError("runtime observation source or exact action mismatch")

    def _review(self, event: SwarmEvent) -> None:
        if event.event_kind not in REVIEW_BOUND_STAGES:
            return
        if event.review_event_id is None:
            raise ValueError("missing reviewed-action anchor")
        review = self._records.get(event.review_event_id)
        if (
            review is None
            or review.event.event_kind != "reviewed"
            or review.source_role != "gateway"
            or review.event.evidence_class != "host_authenticated"
            or review.event.identity != event.identity
            or review.event.registry_id != event.registry_id
            or (review.event.action_id, review.event.action_digest)
            != (event.action_id, event.action_digest)
        ):
            raise ValueError("action stage lacks an exact authenticated reviewed-action anchor")

    def _parents(self, event: SwarmEvent) -> dict[str, int]:
        # A late parent can change every already-recorded descendant's depth.
        # Check that affected subgraph before append; ordinary appends reuse
        # cached ancestor depths instead of scanning the entire journal.
        affected = {event.event_id}
        pending = [event.event_id]
        while pending:
            for child in self._children.get(pending.pop(), ()):
                if child not in affected:
                    affected.add(child)
                    pending.append(child)
        colors: dict[str, int] = {}
        depths: dict[str, int] = {}
        for root in sorted(affected):
            stack = [(root, False)]
            while stack:
                event_id, leaving = stack.pop()
                current = event if event_id == event.event_id else self._records[event_id].event
                if leaving:
                    depth = max(
                        (
                            1
                            + (
                                depths[ref.event_id]
                                if ref.event_id in affected
                                else self._depths.get(ref.event_id, 0)
                            )
                            for ref in current.parent_event_ids
                        ),
                        default=0,
                    )
                    if depth > self._max_depth:
                        raise ValueError("causal event depth limit reached")
                    depths[event_id] = depth
                    colors[event_id] = 2
                    continue
                if colors.get(event_id) == 2:
                    continue
                if colors.get(event_id) == 1:
                    raise ValueError("causal event cycle")
                colors[event_id] = 1
                stack.append((event_id, True))
                stack.extend(
                    (ref.event_id, False)
                    for ref in current.parent_event_ids
                    if ref.event_id in affected
                )
        return depths

    def ingest(
        self,
        source: HostEventSource,
        event: SwarmEvent,
        *,
        observation: RuntimeObservation | None = None,
    ) -> IngestReceipt:
        with self._lock:
            binding = self._source(source)
            if type(event) is not SwarmEvent:
                raise ValueError("ingest requires a validated immutable swarm event")
            digest = event.digest
            if (
                event.source_id != binding.source_id
                or event.identity != binding.context.identity
                or event.registry_id != binding.context.registry_id
            ):
                raise ValueError("event principal or sender does not match its protected channel")
            self._evidence(binding, event, observation)
            prior = self._records.get(event.event_id)
            if prior is not None:
                if prior.digest != digest:
                    raise ValueError("conflicting event ID replay")
                return self._receipt(prior, binding, duplicate=True)
            if len(self._records) >= self._max_events:
                raise ValueError("event journal capacity reached")
            if event.source_sequence in binding.sequences:
                raise ValueError("conflicting source sequence replay")
            if (
                event.source_sequence <= binding.contiguous
                or event.source_sequence > binding.contiguous + self._window
            ):
                raise ValueError("event sequence outside bounded receive window")
            action_key = None
            if event.action_id is not None and event.evidence_class != "caller_asserted":
                action_key = (event.registry_id, event.identity, event.action_id)
                expected_digest = self._action_digests.get(action_key)
                if expected_digest is not None and expected_digest != event.action_digest:
                    raise ValueError("action ID changed its canonical digest")
                if event.event_kind == "reviewed" and action_key in self._action_reviews:
                    raise ValueError("action attempt already has an authoritative review")
            self._review(event)
            depths = self._parents(event)
            record = JournalRecord(event, digest, len(self._records) + 1, binding.role)
            # Recheck immediately before storage; no execution permission is issued here.
            self._registry.authenticate(binding.context, binding.channel, binding.adapter)
            self._journal.append(record, expected_index=len(self._records))
            # Storage must commit atomically before any in-memory admission state changes.
            self._records[event.event_id] = record
            self._depths.update(depths)
            for parent in event.parent_event_ids:
                self._children.setdefault(parent.event_id, set()).add(event.event_id)
            if event.action_id is not None:
                self._action_records.setdefault(
                    (event.registry_id, event.identity, event.action_id, event.action_digest), []
                ).append(event.event_id)
            if action_key is not None:
                if event.action_digest is None:
                    raise AssertionError("validated action lost its digest")
                self._action_digests[action_key] = event.action_digest
                if event.event_kind == "reviewed":
                    self._action_reviews[action_key] = event.event_id
            binding.sequences[event.source_sequence] = event.event_id
            while binding.contiguous + 1 in binding.sequences:
                binding.contiguous += 1
            return self._receipt(record, binding, duplicate=False)

    def _receipt(
        self, record: JournalRecord, binding: _Source, *, duplicate: bool
    ) -> IngestReceipt:
        event = record.event
        gaps = set()
        if binding.contiguous < event.source_sequence:
            gaps.add("source_sequence_gap")
        if any(parent.event_id not in self._records for parent in event.parent_event_ids):
            gaps.add("causal_parent_gap")
        if event.evidence_class == "caller_asserted":
            gaps.add("caller_asserted_event")
        if event.action_id is not None:
            state = self._state(binding.context, event.action_id, event.action_digest)
            if state.missing_stages or not state.causally_complete:
                gaps.add("action_lifecycle_gap")
        return IngestReceipt(
            event.event_id, record.digest, record.ingest_index, duplicate, tuple(sorted(gaps))
        )

    def action_state(
        self,
        source: HostEventSource,
        *,
        action_id: str,
        action_digest: str,
    ) -> ActionEventState:
        """Protected read, not a permit or proof of physical enforcement."""
        _text(action_id, "action_id")
        _hex(action_digest, "action_digest")
        with self._lock:
            binding = self._source(source)
            return self._state(binding.context, action_id, action_digest)

    def _state(
        self, context: SwarmContext, action_id: str, action_digest: str | None
    ) -> ActionEventState:
        records = [
            self._records[event_id]
            for event_id in self._action_records.get(
                (context.registry_id, context.identity, action_id, action_digest), ()
            )
        ]
        trusted = [record for record in records if record.event.evidence_class != "caller_asserted"]
        stages = frozenset(record.event.event_kind for record in trusted)
        unresolved = {
            parent
            for record in trusted
            for parent in record.event.parent_event_ids
            if parent.event_id not in self._records
        }
        sequence_gap = any(
            self._source_ids[record.event.source_id].contiguous < record.event.source_sequence
            for record in trusted
        )
        chains: dict[str, str | None] = {
            record.event.event_id: None
            for record in trusted
            if record.event.event_kind == "proposed"
        }
        for stage in _LIFECYCLE[1:]:
            next_chains: dict[str, str | None] = {}
            for record in trusted:
                event = record.event
                if event.event_kind != stage or not any(
                    ref.event_id in chains for ref in event.parent_event_ids
                ):
                    continue
                if stage == "reviewed":
                    next_chains[event.event_id] = event.event_id
                elif not any(
                    parent.event_id in chains and chains[parent.event_id] == event.review_event_id
                    for parent in event.parent_event_ids
                ):
                    continue
                else:
                    next_chains[event.event_id] = event.review_event_id
            chains = next_chains
        return ActionEventState(
            tuple(sorted(record.event.event_id for record in records)),
            tuple(sorted(stages)),
            tuple(stage for stage in _LIFECYCLE if stage not in stages),
            tuple(sorted(unresolved, key=lambda ref: (ref.tenant_id, ref.swarm_id, ref.event_id))),
            sequence_gap,
            bool(chains) and not unresolved and not sequence_gap,
            "completed" in stages,
            "observed" in stages,
            tuple(
                sorted(
                    {
                        record.event.observed_outcome
                        for record in trusted
                        if record.event.observed_outcome is not None
                    }
                )
            ),
        )

    def snapshot(self) -> tuple[JournalRecord, ...]:
        """Host-only immutable fixture view; never restore authority from its JSON."""
        with self._lock:
            return tuple(self._records.values())
