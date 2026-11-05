"""Protected byte/artifact lineage and pre-egress assessments, never execution."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from threading import RLock
from typing import Any
from uuid import uuid4

from ordin.action import ActionEnvelope
from ordin._runtime_json import digest
from ordin.assurance.host import HostConstraintAssessment, HostEvidenceSource
from ordin.assurance.models import ApprovedSecurityProfile
from ordin.assurance.origins import InstructionOrigin, _selected_value

from .causal_graph import SwarmCausalGraph
from .events import SwarmEvent
from .facts import SwarmAssessment, SwarmAssessmentSource
from .ingest import HostEventSource
from .labels import Sensitivity
from .models import SwarmContext, identifier


@dataclass(frozen=True, eq=False, slots=True)
class LineageHandle:
    """Opaque handle; a copied identifier or serialized record conveys no authority."""

    lineage_id: str


@dataclass(frozen=True, slots=True)
class LineageUse:
    handle: LineageHandle
    argument_path: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            type(self.handle) is not LineageHandle
            or type(self.argument_path) is not tuple
            or not 2 <= len(self.argument_path) <= 8
            or self.argument_path[0] != "parameters"
        ):
            raise ValueError("invalid exact-byte lineage use")
        for part in self.argument_path:
            identifier(part, "argument_path")


@dataclass(frozen=True, slots=True)
class EgressSink:
    """Exact host-configured route and destination; no caller-selected allowlist."""

    sink_id: str
    kind: str
    action_kind: str
    operation: str
    destination_path: tuple[str, ...]
    destination: str
    allowed_labels: tuple[str, ...] = ("public",)

    def __post_init__(self) -> None:
        for name in ("sink_id", "action_kind", "operation"):
            identifier(getattr(self, name), name)
        if type(self.kind) is not str or self.kind not in {"network", "mcp", "tool", "message"}:
            raise ValueError("unknown mediated sink kind")
        if (
            type(self.destination) is not str
            or not 1 <= len(self.destination.encode("utf-8")) <= 2048
            or type(self.destination_path) is not tuple
            or not 2 <= len(self.destination_path) <= 8
            or self.destination_path[0] != "parameters"
            or type(self.allowed_labels) is not tuple
            or not 1 <= len(self.allowed_labels) <= 4
            or len(set(self.allowed_labels)) != len(self.allowed_labels)
            or any(
                v not in {"public", "secret", "pii", "private_code"} for v in self.allowed_labels
            )
        ):
            raise ValueError("invalid protected egress sink")
        for part in self.destination_path:
            identifier(part, "destination_path")

    def matches(self, action: ActionEnvelope) -> bool:
        self.__post_init__()
        try:
            return (
                action.kind == self.action_kind
                and action.operation == self.operation
                and _selected_value(action, self.destination_path)
                == self.destination.encode("utf-8")
            )
        except (ValueError, AttributeError):
            return False


@dataclass(frozen=True, slots=True)
class _Actor:
    context: SwarmContext
    source: HostEventSource
    host: HostEvidenceSource
    host_key: str


@dataclass(frozen=True, slots=True)
class _Lineage:
    handle: LineageHandle
    actor: _Actor
    event_id: str
    content_digest: str
    byte_length: int
    sensitivity: Sensitivity
    parents: tuple[LineageHandle, ...]
    established: bool
    complete: bool
    gaps: tuple[str, ...]
    declassification_digest: str | None = None


@dataclass(frozen=True, slots=True)
class SourceFlowResult:
    status: str
    reason_code: str
    labels: tuple[str, ...]
    lineage_digests: tuple[str, ...]
    proof_gaps: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "ordin.swarm_source_flow.v1",
            "kind": "swarm_source_flow",
            "status": self.status,
            "reason_code": self.reason_code,
            "labels": list(self.labels),
            "lineage_digests": list(self.lineage_digests),
            "proof_gaps": list(self.proof_gaps),
            "execution_authority": False,
            "observed_exfiltration": "unknown",
        }


class SwarmSourceFlow:
    """Host-owned bounded lineage service. Never expose its mutators to agents.

    Contents are hashed and discarded. Event resource hashes must explicitly
    include the content hash supplied by the protected adapter; generic runtime
    resource-metadata hashes alone cannot establish this correspondence.
    """

    def __init__(
        self,
        graph: SwarmCausalGraph,
        *,
        sinks: tuple[EgressSink, ...],
        operator: object,
        max_records: int = 4096,
        max_depth: int = 64,
    ) -> None:
        if type(graph) is not SwarmCausalGraph or type(operator) is not object:
            raise ValueError("protected graph and opaque operator capability required")
        if (
            type(sinks) is not tuple
            or not 1 <= len(sinks) <= 128
            or any(type(v) is not EgressSink for v in sinks)
            or len({v.sink_id for v in sinks}) != len(sinks)
            or type(max_records) is not int
            or not 1 <= max_records <= 16384
            or type(max_depth) is not int
            or not 1 <= max_depth <= 128
        ):
            raise ValueError("invalid bounded source-flow configuration")
        for sink in sinks:
            sink.__post_init__()
        graph.build()
        self._graph, self._operator = graph, operator
        self._sinks = {v.sink_id: v for v in sinks}
        self._limit, self._max_depth = max_records, max_depth
        self._actors: dict[HostEventSource, _Actor] = {}
        self._records: dict[LineageHandle, _Lineage] = {}
        self._ids: dict[LineageHandle, str] = {}
        self._depths: dict[LineageHandle, int] = {}
        self._audit: list[dict[str, Any]] = []
        self._authorities: set[SwarmAssessmentSource] = set()
        self._incarnation = uuid4().hex
        self._lock = RLock()

    def bind_actor(
        self, source: HostEventSource, context: SwarmContext, host: HostEvidenceSource
    ) -> None:
        with self._lock, self._graph._lock, self._graph._ingestor._lock:
            self._graph._ingestor.snapshot_binding(source, context)
            if (
                not isinstance(host, HostEvidenceSource)
                or host.principal != context.identity.agent_id
                or source in self._actors
                or len(self._actors) >= 256
            ):
                raise ValueError("invalid protected lineage actor binding")
            self._actors[source] = _Actor(context, source, host, host.key)

    def _actor(self, source: HostEventSource) -> _Actor:
        actor = self._actors.get(source)
        if actor is None or actor.host.key != actor.host_key:
            raise ValueError("unknown or changed protected lineage actor")
        self._graph._ingestor.snapshot_binding(source, actor.context)
        if actor.context.identity.policy_epoch != self._graph._context.identity.policy_epoch:
            raise ValueError("stale lineage policy epoch")
        return actor

    def _record(self, handle: LineageHandle) -> _Lineage:
        if type(handle) is not LineageHandle or handle not in self._records:
            raise ValueError("unknown original lineage handle")
        row = self._records[handle]
        if handle.lineage_id != self._ids[handle]:
            raise ValueError("changed lineage handle")
        self._actor(row.actor.source)
        return row

    def _event(self, actor: _Actor, event_id: str, content_digest: str) -> SwarmEvent:
        identifier(event_id, "event_id")
        row = self._graph._ingestor._records.get(event_id)
        if (
            row is None
            or row.event.digest != row.digest
            or row.event.identity != actor.context.identity
            or row.event.source_id != actor.source.source_id
            or row.event.evidence_class not in {"host_authenticated", "backend_observed"}
            or content_digest not in row.event.resource_digests
            or row.event.event_kind
            not in {
                "artifact_read",
                "artifact_write",
                "message_sent",
                "message_received",
                "observed",
            }
        ):
            raise ValueError("lineage requires authenticated exact-content event correspondence")
        return row.event

    def _save(
        self,
        actor: _Actor,
        event_id: str,
        content_digest: str,
        byte_length: int,
        sensitivity: Sensitivity,
        parents: tuple[LineageHandle, ...],
        *,
        established: bool,
        complete: bool,
        gaps: tuple[str, ...],
        declassification_digest: str | None = None,
    ) -> LineageHandle:
        if len(self._records) >= self._limit:
            raise ValueError("lineage capacity reached")
        depth = 1 + max((self._depths[p] for p in parents), default=0)
        if depth > self._max_depth:
            raise ValueError("lineage depth limit reached")
        # Label/declassification changes invalidate previously issued safe facts,
        # even when the event journal itself has not changed.
        for authority in self._authorities:
            authority.fence()
        handle = LineageHandle(str(len(self._records) + 1))
        self._records[handle] = _Lineage(
            handle,
            actor,
            event_id,
            content_digest,
            byte_length,
            sensitivity,
            parents,
            established,
            complete,
            gaps,
            declassification_digest,
        )
        self._ids[handle] = handle.lineage_id
        self._depths[handle] = depth
        return handle

    def register(
        self,
        source: HostEventSource,
        *,
        event_id: str,
        origin: InstructionOrigin,
        sensitivity: Sensitivity,
    ) -> LineageHandle:
        """Register actual host-classified bytes; labels from agent text are invalid."""
        with self._lock, self._graph._lock, self._graph._ingestor._lock:
            actor = self._actor(source)
            if type(origin) is not InstructionOrigin or type(sensitivity) is not Sensitivity:
                raise ValueError("protected origin and sensitivity required")
            origin.__post_init__()
            sensitivity.__post_init__()
            if (
                origin.source_key != actor.host_key
                or origin.span_start != 0
                or origin.span_digest != origin.content_digest
                or (origin.classification == "sensitive" and not sensitivity.sensitive)
                or (sensitivity.labels == ("public",) and origin.classification != "public")
                or (origin.classification == "unknown" and sensitivity.known)
            ):
                raise ValueError("origin scope or protected classification does not match")
            self._event(actor, event_id, origin.content_digest)
            view = self._graph.build()
            gaps = view.proof_gaps
            if event_id not in {n["event_id"] for n in view.nodes}:
                gaps = tuple(sorted(set(gaps) | {"lineage_event_outside_window"}))
            return self._save(
                actor,
                event_id,
                origin.content_digest,
                origin.span_end,
                sensitivity,
                (),
                established=not gaps,
                complete=not gaps,
                gaps=gaps,
            )

    def derive(
        self,
        source: HostEventSource,
        *,
        event_id: str,
        content: str | bytes,
        parents: tuple[LineageHandle, ...],
        complete: bool = False,
    ) -> LineageHandle:
        """Protected collector reports a transfer/transform, retaining all input labels."""
        if (
            type(parents) is not tuple
            or not 1 <= len(parents) <= 64
            or len(set(parents)) != len(parents)
            or type(complete) is not bool
            or type(content) not in {str, bytes}
            or len(content) > 1_048_576
        ):
            raise ValueError("bounded lineage transform required")
        try:
            raw = content.encode("utf-8") if isinstance(content, str) else content
        except UnicodeError:
            raise ValueError("invalid lineage content encoding") from None
        if len(raw) > 1_048_576:
            raise ValueError("lineage content byte limit exceeded")
        with self._lock, self._graph._lock, self._graph._ingestor._lock:
            actor = self._actor(source)
            rows = [self._record(p) for p in parents]
            content_digest = hashlib.sha256(raw).hexdigest()
            self._event(actor, event_id, content_digest)
            view = self._graph.build()
            # Delegation and hypotheses do not establish byte transfer.
            edges = [
                e for e in view.edges if e["kind"] not in {"delegated_to", "hypothesized_influence"}
            ]
            children: dict[str, list[str]] = {}
            for edge in edges:
                children.setdefault(edge["source_id"], []).append(edge["target_id"])

            def reaches(start: str) -> bool:
                pending, seen = [start], set()
                while pending:
                    node = pending.pop()
                    if node == event_id:
                        return True
                    if node not in seen:
                        seen.add(node)
                        pending.extend(children.get(node, ()))
                return False

            gaps = set(view.proof_gaps)
            for row in rows:
                gaps.update(row.gaps)
            linked = all(row.established and reaches(row.event_id) for row in rows)
            if not linked:
                gaps.add("unverified_transfer")
            if not complete:
                gaps.add("partial_transform_inputs")
            sensitivity = rows[0].sensitivity.join(*(v.sensitivity for v in rows[1:]))
            if not complete:
                sensitivity = sensitivity.join(Sensitivity())
            return self._save(
                actor,
                event_id,
                content_digest,
                len(raw),
                sensitivity,
                parents,
                established=linked and not view.proof_gaps,
                complete=complete and all(v.complete for v in rows) and not gaps,
                gaps=tuple(sorted(gaps)),
            )

    def declassify(
        self,
        handle: LineageHandle,
        *,
        operator: object,
        policy_epoch: int,
        sensitivity: Sensitivity,
        reason_code: str,
    ) -> LineageHandle:
        with self._lock, self._graph._lock, self._graph._ingestor._lock:
            row = self._record(handle)
            identifier(reason_code, "declassification_reason")
            if (
                operator is not self._operator
                or type(policy_epoch) is not int
                or policy_epoch != row.actor.context.identity.policy_epoch
                or type(sensitivity) is not Sensitivity
                or not sensitivity.known
                or not row.established
                or not row.complete
            ):
                raise ValueError("declassification requires current protected operator evidence")
            sensitivity.__post_init__()
            audit = {
                "policy_epoch": policy_epoch,
                "input_digest": self._digest(row),
                "labels": list(sensitivity.labels),
                "reason_code": reason_code,
            }
            audit_digest = digest(audit)
            result = self._save(
                row.actor,
                row.event_id,
                row.content_digest,
                row.byte_length,
                sensitivity,
                (handle,),
                established=True,
                complete=True,
                gaps=(),
                declassification_digest=audit_digest,
            )
            self._audit.append(audit)
            return result

    def _digest(self, row: _Lineage) -> str:
        return digest(
            {
                "store": self._incarnation,
                "handle": row.handle.lineage_id,
                "context": row.actor.context.as_dict(),
                "event": row.event_id,
                "content": row.content_digest,
                "length": row.byte_length,
                "labels": row.sensitivity.labels,
                "gaps": row.gaps,
                "declassification": row.declassification_digest,
            }
        )

    def audit(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            return tuple({**v, "labels": list(v["labels"])} for v in self._audit)

    def assess(
        self,
        source: HostEventSource,
        action: ActionEnvelope,
        *,
        sink_id: str,
        uses: tuple[LineageUse, ...],
        complete: bool = False,
    ) -> SourceFlowResult:
        """Pure pre-egress check. Complete is a protected collector declaration."""
        if (
            type(action) is not ActionEnvelope
            or type(uses) is not tuple
            or len(uses) > 64
            or any(type(v) is not LineageUse for v in uses)
            or type(complete) is not bool
        ):
            raise ValueError("bounded exact action lineage uses required")
        with self._lock, self._graph._lock, self._graph._ingestor._lock:
            actor = self._actor(source)
            view = self._graph.build()
            sink = self._sinks.get(sink_id)
            gaps = set(view.proof_gaps)
            if sink is None or not sink.matches(action):
                gaps.add("unmodeled_egress_sink")
            if not complete:
                gaps.add("partial_egress_inputs")
            rows = []
            for use in uses:
                use.__post_init__()
                row = self._record(use.handle)
                if row.actor is not actor:
                    raise ValueError("lineage input requires an authenticated local handoff")
                raw = _selected_value(action, use.argument_path)
                if (
                    len(raw) != row.byte_length
                    or hashlib.sha256(raw).hexdigest() != row.content_digest
                ):
                    raise ValueError("lineage input changed from exact proposed bytes")
                self._event(actor, row.event_id, row.content_digest)
                if row.event_id not in {n["event_id"] for n in view.nodes}:
                    gaps.add("lineage_event_outside_window")
                gaps.update(row.gaps)
                rows.append(row)
            labels = Sensitivity(("public",))
            for row in rows:
                labels = labels.join(row.sensitivity)
            violated = (
                sink is not None
                and sink.matches(action)
                and any(
                    row.established
                    and row.sensitivity.sensitive
                    and not set(row.sensitivity.labels).difference({"unclassified"})
                    <= set(sink.allowed_labels)
                    for row in rows
                )
            )
            if violated:
                status, reason = "violated", "source_flow.unauthorized_sensitive_egress"
            elif gaps or not labels.known or any(not v.complete for v in rows):
                status, reason = "unknown", "source_flow.incomplete_provenance"
            else:
                status, reason = "satisfied", "source_flow.allowed_mediated_egress"
            return SourceFlowResult(
                status,
                reason,
                labels.labels,
                tuple(sorted(self._digest(v) for v in rows)),
                tuple(sorted(gaps)),
            )

    def issue_assessment(
        self,
        source: HostEventSource,
        action: ActionEnvelope,
        *,
        authority: SwarmAssessmentSource,
        policy_digest: str,
        snapshot_digest: str,
        sink_id: str,
        uses: tuple[LineageUse, ...],
        complete: bool = False,
        check_id: str = "source_flow",
        lifetime: float = 30,
    ) -> SwarmAssessment:
        """Host bridge into mandatory SwarmGate checks, bound to its fresh snapshot."""
        if type(authority) is not SwarmAssessmentSource:
            raise ValueError("protected assessment authority required")
        with self._lock:
            if authority not in self._authorities and len(self._authorities) >= 256:
                raise ValueError("lineage assessment authority capacity reached")
            self._authorities.add(authority)
            result = self.assess(source, action, sink_id=sink_id, uses=uses, complete=complete)
            actor = self._actor(source)
            return authority.issue(
                check_id=check_id,
                status=result.status,
                action_digest=digest(action.as_dict()),
                context_digest=digest(actor.context.as_dict()),
                policy_digest=policy_digest,
                snapshot_digest=snapshot_digest,
                lifetime=lifetime,
                reason_code=result.reason_code,
            )

    def assurance_assessment(
        self,
        source: HostEventSource,
        action: ActionEnvelope,
        profile: ApprovedSecurityProfile,
        *,
        invariant_id: str,
        sink_id: str,
        uses: tuple[LineageUse, ...],
        complete: bool = False,
    ) -> HostConstraintAssessment:
        """Protected result for the additive Assurance assess_source_flow input."""
        with self._lock:
            result = self.assess(source, action, sink_id=sink_id, uses=uses, complete=complete)
            actor = self._actor(source)
            return actor.host.record_assessment(
                action,
                profile,
                assessment_id="swarm-source-flow:" + digest(result.as_dict())[:24],
                invariant_id=invariant_id,
                kind="source_flow_guard",
                status="inconclusive" if result.status == "unknown" else result.status,
                proof_gaps=result.proof_gaps if result.status == "unknown" else (),
            )
