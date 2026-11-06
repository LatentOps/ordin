"""Protected-source projections. Reports and telemetry never become permits."""

from __future__ import annotations

from collections import OrderedDict
from queue import Empty, Full, Queue
from threading import RLock, Thread
import time
import sqlite3
from typing import Any, TYPE_CHECKING

from ordin._runtime_json import digest

from .audit import SwarmAuditJournal
from .coordinator import CoordinatorScope, SwarmCoordinator
from .models import identifier
from .coordinator_store import decode, encode
from .registry import InMemoryAgentRegistry

if TYPE_CHECKING:
    from .causal_graph import SwarmCausalGraph


class SwarmAuditSource:
    """Host-owned bindings to original components, never model supplied JSON."""

    def __init__(
        self,
        journal: SwarmAuditJournal,
        coordinator: SwarmCoordinator,
        scope: CoordinatorScope,
        *,
        control,
        operator: object,
        containment=None,
    ):
        if (
            type(journal) is not SwarmAuditJournal
            or type(coordinator) is not SwarmCoordinator
            or operator is not coordinator._operator
        ):
            raise ValueError("original protected diagnostic components required")
        journal._check(operator)
        coordinator._control_check(control)
        native = coordinator._scope(scope)
        if (
            type(native.authenticator._registry) is not InMemoryAgentRegistry
            or native.authenticator._scope is None
        ):
            raise ValueError("original diagnostic registry/task scope required")
        if (
            journal._clock is not coordinator.clock
            or journal.redactor.ref("tenant", native.tenant_id) != journal.redactor.tenant_ref
        ):
            raise ValueError("diagnostic tenant and original DB clock must match")
        journal.bind_scope(scope.scope_key, operator=operator)
        if containment is not None:
            from .containment import SwarmContainmentController

            if (
                type(containment) is not SwarmContainmentController
                or containment._coordinator is not coordinator
                or containment._scope is not scope
                or containment._operator is not operator
            ):
                raise ValueError("original scoped containment controller required")
        self.journal = journal
        self._coordinator: SwarmCoordinator = coordinator
        self._scope: CoordinatorScope = scope
        self._control = control
        self._operator: object = operator
        self._containment = containment
        self._registry: InMemoryAgentRegistry = native.authenticator._registry
        self._tenant, self._swarm, self._task = (
            native.tenant_id,
            native.swarm_id,
            native.authenticator._scope[2],
        )
        self._seen: OrderedDict[str, None] = OrderedDict()
        self._fault, self._lock = False, RLock()
        self._closed, self._dropped = False, 0
        self._causal_graph: SwarmCausalGraph | None = None
        self._queue: Queue[Any] = Queue(maxsize=min(journal.policy.maximum_events, 256))
        self._worker = Thread(target=self._write_loop, name="ordin-private-audit", daemon=True)
        self._worker.start()
        coordinator.bind_audit(scope, self, control=control)
        for broker in native.brokers.values():
            broker.bind_audit(self, operator=operator)
            broker._gate.bind_audit(self, operator=operator)
        if containment is not None:
            containment.bind_audit(self, operator=operator)

    def _append(self, unique, *, kind, state, evidence, refs, facts):
        # Observation capture cannot weaken or replace an enforcement result.
        # A failed sink remains an explicit diagnostic gap until rebuilt.
        with self._lock:
            if unique in self._seen:
                self._seen.move_to_end(unique)
                return
            if self._fault or self._closed:
                return
            try:
                refs = {**refs, "scope": self._scope.scope_key}
                if self._task is not None:
                    refs["task"] = self._task
                data = decode(
                    encode(
                        {
                            "kind": kind,
                            "state": state,
                            "evidence": evidence,
                            "refs": refs,
                            "facts": facts,
                        },
                        65536,
                    ),
                    65536,
                )
                self._queue.put_nowait(data)
                self._seen[unique] = None
                while len(self._seen) > min(self.journal.policy.maximum_events * 2, 4096):
                    self._seen.popitem(last=False)
            except Full:
                self._dropped = min(self._dropped + 1, 2**53 - 1)
            except (ValueError, OSError, RuntimeError, sqlite3.Error):
                self._fault = True

    def _write_loop(self):
        while not self._closed or self._queue.unfinished_tasks:
            try:
                data = self._queue.get(timeout=0.05)
            except Empty:
                continue
            try:
                if not self._fault:
                    self.journal._append(**data, operator=self._operator)
            except (ValueError, OSError, RuntimeError, sqlite3.Error):
                self._fault = True
            finally:
                self._queue.task_done()

    def flush(self, *, operator: object, timeout: float = 2) -> bool:
        self._check(operator)
        if type(timeout) not in {int, float} or not 0 <= timeout <= 5:
            raise ValueError("bounded diagnostic flush timeout required")
        deadline = time.monotonic() + timeout
        while self._queue.unfinished_tasks and time.monotonic() < deadline:
            time.sleep(0.005)
        return not self._closed and not self._fault and not self._queue.unfinished_tasks

    def close(self, *, operator: object) -> bool:
        self._check(operator)
        with self._lock:
            self._closed = True
        self._worker.join(timeout=2)
        return not self._worker.is_alive() and not self._fault

    @staticmethod
    def _disposition(value):
        return value if value in {"execute", "escalate", "deny"} else "unknown"

    @staticmethod
    def _risk(value):
        return value if value in {"unknown", "low", "medium", "high", "critical"} else "unknown"

    @staticmethod
    def _tool_metadata(action, adapter):
        return {
            "kind": action.kind,
            "operation": action.operation,
            "adapter": adapter,
            "identifiers": {
                name: action.parameters[name]
                for name in ("runtime", "server", "tool", "method")
                if name in action.parameters and type(action.parameters[name]) is str
            },
        }

    def record_decision(self, gate, context, decision):
        from .gate import SwarmGate, SwarmDecision

        if (
            type(gate) is not SwarmGate
            or type(decision) is not SwarmDecision
            or gate._registry is not self._registry
            or decision._seal is None
            or decision._seal.owner is not gate._key
            or decision._seal.payload_digest != digest(decision.as_dict())
            or decision._seal.review_digest != digest(decision.review.as_dict())
            or decision.identity != context.identity
        ):
            raise ValueError("original scoped gate decision required")
        if digest(context.as_dict()) != decision.context_digest:
            raise ValueError("original reviewed context binding required")
        if (context.identity.tenant_id, context.identity.swarm_id, context.identity.task_id) != (
            self._tenant,
            self._swarm,
            self._task,
        ):
            raise ValueError("diagnostic decision scope mismatch")
        refs = {
            "actor": digest([self._tenant, self._swarm, context.identity.agent_id]),
            "session": context.identity.session_id,
            "action": decision.action_digest,
            "policy": decision.policy_digest,
            "tool": self._tool_metadata(decision.review.action, decision.review.adapter),
        }
        if self._task:
            refs["task"] = self._task
        facts = {
            "disposition": self._disposition(decision.disposition),
            "risk": self._risk(decision.review.risk),
            "policy_epoch": context.identity.policy_epoch,
            "reason_refs": [
                self.journal.redactor.ref("reason", value) for value in decision.reason_codes
            ],
            "proof_gaps": ["unmediated_paths_uncovered", "prehistory_unknown"],
        }
        self._append(
            digest(["decision", decision.as_dict()]),
            kind="decision",
            state="denied" if decision.disposition == "deny" else "reviewed",
            evidence="intent",
            refs=refs,
            facts=facts,
        )

    def record_coordinator(self, coordinator, scope, record):
        from .coordinator import CoordinatorRecord

        if (
            coordinator is not self._coordinator
            or scope is not self._scope
            or type(record) is not CoordinatorRecord
            or record.scope_digest != scope.scope_key
        ):
            raise ValueError("original scoped coordinator diagnostic source required")
        states = {
            "reserved": "reserved",
            "forwarding": "forwarded",
            "committed": "completed",
            "uncertain": "unknown",
            "canceled": "canceled",
            "denied": "denied",
            "execute": "reviewed",
            "escalate": "reviewed",
            "deny": "denied",
        }
        if record.status not in states:
            return
        refs = {"source": scope.scope_key}
        if record.subject_digest:
            refs["actor"] = record.subject_digest
        if record.action_digest:
            refs["action"] = record.action_digest
        self._append(
            digest(["coordinator", record.as_dict()]),
            kind="admission",
            state=states[record.status],
            evidence="reported"
            if record.status == "committed"
            else "unknown"
            if record.status in {"uncertain", "forwarding"}
            else "intent",
            refs=refs,
            facts={
                "policy_epoch": record.policy_epoch,
                "proof_gaps": ["unmediated_paths_uncovered", "prehistory_unknown"],
            },
        )

    def record_broker(self, broker, authorization, result):
        from .broker import SwarmExecutionBroker
        from .authorization import BrokerResult

        if (
            type(broker) is not SwarmExecutionBroker
            or type(result) is not BrokerResult
            or broker._service.authenticator._registry is not self._registry
            or not broker.verify_result(result, authorization)
        ):
            raise ValueError("original scoped broker result required")
        original = broker._pending.get(authorization)
        if original is None:
            raise ValueError("original broker job required")
        context = original.scope.context
        if (context.identity.tenant_id, context.identity.swarm_id, context.identity.task_id) != (
            self._tenant,
            self._swarm,
            self._task,
        ):
            raise ValueError("broker diagnostic scope mismatch")
        observed = bool(
            result.physical_enforcement
            and result.forwarded
            and result.executor_outcome is not None
            and broker._executor.verify_outcome(result.executor_outcome, original.scope.plan)
        )
        state = result.status if result.status in {"completed", "denied", "canceled"} else "unknown"
        self._append(
            digest(["broker", result.as_dict()]),
            kind="broker_result",
            state=state,
            evidence="observed"
            if observed
            else "intent"
            if not result.forwarded and state in {"denied", "canceled"}
            else "unknown",
            refs={
                "actor": digest([self._tenant, self._swarm, context.identity.agent_id]),
                "action": result.action_digest,
                "proof": result.authorization_digest,
                "policy": original.scope.plan.policy_digest,
                "session": context.identity.session_id,
                "tool": self._tool_metadata(
                    original.scope.action, original.scope.decision.review.adapter
                ),
            },
            facts={
                "physical_enforcement": observed,
                "policy_epoch": context.identity.policy_epoch,
                "observed_outcome": result.executor_outcome.observation.outcome
                if observed
                else "unknown",
                "proof_gaps": ["unmediated_paths_uncovered", "prehistory_unknown"],
            },
        )

    def record_incident(self, controller, receipt):
        if controller is not self._containment:
            raise ValueError("original scoped containment controller required")
        incident = controller._original(receipt)
        state = {"pause": "paused", "revoke": "revoked", "quarantine": "quarantined"}.get(
            receipt.operation, "unknown"
        )
        if incident.resumed:
            state = "resumed"
        self._append(
            digest(["incident", receipt.as_dict(), state]),
            kind="incident",
            state=state,
            evidence="intent",
            refs={"incident": receipt.incident_id, "source": receipt.scope_digest},
            facts={
                "revocation_epoch": receipt.revocation_epoch,
                "proof_gaps": ["unmediated_paths_uncovered", "prehistory_unknown"],
            },
        )

    def record_risk(
        self, *, severity: str, confidence: float, model_ref: str, action_ref: str, operator: object
    ):
        if (
            operator is not self._operator
            or type(confidence) not in {int, float}
            or not 0 <= confidence <= 1
        ):
            raise ValueError("protected diagnostic-only model risk input required")
        identifier(model_ref, "risk_model")
        self._append(
            digest(["risk", model_ref, action_ref, severity, confidence]),
            kind="risk_signal",
            state="risk_reported",
            evidence="diagnostic",
            refs={"source": model_ref, "action": action_ref},
            facts={
                "model_risk": self._risk(severity),
                "model_confidence": confidence,
                "proof_gaps": ["diagnostic_not_runtime_evidence"],
            },
        )

    def actor_ref(self, agent_id):
        return self.journal.redactor.ref("actor", digest([self._tenant, self._swarm, agent_id]))

    def bind_causal_graph(self, graph, *, operator: object):
        """Opt in to an original, current protected graph, never a supplied JSON graph."""
        from .causal_graph import SwarmCausalGraph

        self._check(operator)
        if (
            type(graph) is not SwarmCausalGraph
            or graph._ingestor._registry is not self._registry
            or (
                graph._context.identity.tenant_id,
                graph._context.identity.swarm_id,
                graph._context.identity.task_id,
            )
            != (self._tenant, self._swarm, self._task)
        ):
            raise ValueError("original task-scoped causal graph required")
        graph.build()
        with self._lock:
            if self._causal_graph is not None and self._causal_graph is not graph:
                raise ValueError("causal source already bound")
            graph._ingestor.bind_audit(self, operator=operator)
            self._causal_graph = graph

    def record_ingested(self, ingestor, record):
        """Capture message metadata only after the original ingest commit."""
        from .ingest import SwarmEventIngestor, JournalRecord

        if (
            type(ingestor) is not SwarmEventIngestor
            or ingestor._registry is not self._registry
            or type(record) is not JournalRecord
            or ingestor._records.get(record.event.event_id) is not record
            or record.digest != record.event.digest
        ):
            raise ValueError("original committed message event required")
        event = record.event
        if event.identity.task_id != self._task or event.event_kind not in {
            "message_sent",
            "message_received",
        }:
            return
        self._append(
            digest(["message", record.digest]),
            kind="message",
            state="forwarded" if event.event_kind == "message_sent" else "completed",
            evidence="reported" if event.evidence_class == "host_authenticated" else "diagnostic",
            refs={
                "actor": digest([self._tenant, self._swarm, event.identity.agent_id]),
                "session": event.identity.session_id,
                "message": event.event_id,
                "source": event.source_id,
            },
            facts={"proof_gaps": ["unmediated_paths_uncovered", "prehistory_unknown"]},
        )

    def import_trace(self, path, *, operator: object, maximum_events: int = 256):
        from ordin.trace_capture import read_capture

        self._check(operator)
        if type(maximum_events) is not int or not 1 <= maximum_events <= 4096:
            raise ValueError("bounded trace import required")
        records = read_capture(path, include_raw=False)["events"]
        for row in records[-maximum_events:]:
            if row["event"] not in {"review", "observation"}:
                continue
            review = row["event"] == "review"
            self._append(
                digest(["legacy_trace", row]),
                kind="legacy_review" if review else "legacy_observation",
                state="denied"
                if review and row["disposition"] == "deny"
                else "reviewed"
                if review
                else "unknown",
                evidence="diagnostic",
                refs={"action": row["action_key"], "session": row["session_key"]},
                facts={
                    "risk": self._risk(row.get("risk", "unknown")),
                    "proof_gaps": ["diagnostic_not_runtime_evidence", "observation_unverified"],
                },
            )
        return len(records[-maximum_events:])

    def import_audit(self, path, *, operator: object, maximum_events: int = 256):
        from ordin.audit import MAX_AUDIT_LINE_BYTES, MAX_AUDIT_BYTES
        from ordin._audit_storage import load_audit_line
        from pathlib import Path

        self._check(operator)
        if type(maximum_events) is not int or not 1 <= maximum_events <= 4096:
            raise ValueError("valid bounded legacy audit required")
        from collections import deque

        import io

        # Verify and parse one bounded immutable snapshot; no reopen race can
        # substitute an unverified history after validation.
        with Path(path).open("rb") as original:
            snapshot = original.read(MAX_AUDIT_BYTES + 1)
        if len(snapshot) > MAX_AUDIT_BYTES:
            raise ValueError("valid bounded legacy audit required")
        with io.BytesIO(snapshot) as stream:
            records = deque(
                (
                    load_audit_line(raw)
                    for raw in iter(lambda: stream.readline(MAX_AUDIT_LINE_BYTES + 1), b"")
                ),
                maxlen=maximum_events,
            )
        from ordin.audit import _event_hash
        from ordin.schema import validate_named_schema

        previous = None
        for raw in snapshot.splitlines(keepends=True):
            row = load_audit_line(raw)
            if (
                len(raw) > MAX_AUDIT_LINE_BYTES
                or not raw.endswith(b"\n")
                or validate_named_schema("audit_event", row)
                or row.get("previous_hash") != previous
                or row.get("event_hash") != _event_hash(row)
                or not row.get("event_hash")
            ):
                raise ValueError("valid bounded legacy audit required")
            provenance = row.get("provenance")
            if isinstance(provenance, dict) and (
                row.get("decision") != provenance.get("final_decision")
                or row.get("risk") != provenance.get("final_risk")
            ):
                raise ValueError("valid bounded legacy audit required")
            previous = row["event_hash"]
        for row in records:
            self._append(
                digest(["legacy_audit", row]),
                kind="legacy_review",
                state="denied" if row["decision"] == "block" else "reviewed",
                evidence="diagnostic",
                refs={"action": row["action_digest"]},
                facts={
                    "risk": self._risk(row["risk"]),
                    "proof_gaps": ["diagnostic_not_runtime_evidence"],
                },
            )
        return len(records)

    def _check(self, operator):
        if operator is not self._operator:
            raise ValueError("original diagnostic operator required")

    def current_actor(self, reference: str, *, operator: object):
        self._check(operator)
        with self._registry._lock:
            matches = [
                row.context
                for name, row in self._registry._agents.items()
                if self.actor_ref(name) == reference and row.context.identity.task_id == self._task
            ]
        if len(matches) != 1:
            raise ValueError("current scoped actor reference required")
        return matches[0]

    def _permissions(self):
        native = self._coordinator._scope(self._scope).native
        with native._lock:
            entries = tuple(
                (reference, row)
                for reference, row in native._grants.items()
                if (context := native.authenticator._enrollments[row.enrollment_id].context)
                is not None
                and context.identity.task_id == self._task
            )
        result = []
        truncated = len(entries) > 64
        for reference, row in entries[:64]:
            rights = row.handle.authority.as_dict()
            domains = []
            capability = rights["capability"]
            for kind in ("filesystem", "network", "tools", "credentials", "process"):
                values = capability.get(kind, ())
                if type(values) is not list:
                    values = [values] if values else []
                for value in values[:128]:
                    domains.append(
                        {
                            "kind": kind,
                            "resource_ref": self.journal.redactor.ref("resource", value),
                            "claim": "declared_boundary",
                            "operation": self._permission_operation(kind, value),
                        }
                    )
            for kind in ("requests", "network_grants", "rest_requests"):
                for value in rights.get(kind, ())[:128]:
                    domains.append(
                        {
                            "kind": "request",
                            "resource_ref": self.journal.redactor.ref("resource", value),
                            "claim": "declared_boundary",
                            "operation": "unknown",
                        }
                    )
            truncated = truncated or len(domains) > 16
            result.append(
                {
                    "grant_ref": self.journal.redactor.ref("grant", reference),
                    "authority_ref": self.journal.redactor.ref(
                        "authority", row.handle.authority.digest
                    ),
                    "requires_approval": rights["requires_approval"],
                    "capabilities": domains[:16],
                    "execution_authority": False,
                }
            )
        return result, truncated

    @staticmethod
    def _permission_operation(kind, value):
        if type(value) is not dict:
            return "unknown"
        selected = value.get("operation", value.get("access", "unknown"))
        return (
            selected
            if selected in {"read", "write", "read_write", "connect", "call"}
            else "unknown"
        )

    def _protected_graph(self, metric_events, gaps):
        graph = self._causal_graph
        if graph is None:
            gaps.append("protected_causal_source_unconfigured")
            return None
        redactor = self.journal.redactor
        try:
            with graph._ingestor._lock:
                view = graph.build()
                selected = {
                    row["event_id"]: graph._ingestor._records[row["event_id"]].event
                    for row in view.nodes
                    if graph._ingestor._records[row["event_id"]].event.identity.task_id
                    == self._task
                }
            if view.proof_gaps or view.truncated:
                gaps.append("protected_causal_history_incomplete")
            if view.truncated or len(view.nodes) > 256 or len(view.edges) > 1024:
                gaps.append("projection_truncated")
            selected = dict(list(selected.items())[:256])
            nodes = [
                {
                    "event_ref": redactor.ref("event", key),
                    "actor_ref": self.actor_ref(event.identity.agent_id),
                    "kind": event.event_kind,
                    "action_ref": redactor.ref("action", event.action_digest)
                    if event.action_digest
                    else None,
                    "evidence": "observed"
                    if event.evidence_class in {"backend_observed", "backend_enforced"}
                    else "reported"
                    if event.evidence_class == "host_authenticated"
                    else "diagnostic",
                }
                for key, event in selected.items()
            ]
            edges = []
            parents: dict[str, list[tuple[str, str]]] = {}
            for edge in view.edges[:1024]:
                source, target = edge["source_id"], edge["target_id"]
                if source not in selected or target not in selected:
                    if source in selected or target in selected:
                        gaps.append("protected_causal_history_incomplete")
                    continue
                edges.append(
                    {
                        "from_ref": redactor.ref("event", source),
                        "to_ref": redactor.ref("event", target),
                        "state": "known",
                        "kind": edge["kind"],
                    }
                )
                # Control ancestry and model hypotheses are never data flow.
                if edge["kind"] not in {"hypothesized_influence", "delegated_to"} and all(
                    selected[key].evidence_class != "caller_asserted" for key in (source, target)
                ):
                    parents.setdefault(target, []).append((source, edge["kind"]))
            reviews = {
                (
                    row["refs"].get("actor"),
                    row["refs"].get("session"),
                    row["refs"].get("action"),
                    row["facts"].get("policy_epoch"),
                ): row
                for row in metric_events
                if row["kind"] == "decision"
                and row["evidence"] == "intent"
                and row["facts"].get("disposition") in {"escalate", "deny"}
            }
            paths: list[dict[str, Any]] = []
            for key, event in selected.items():
                if event.event_kind != "reviewed" or event.evidence_class != "host_authenticated":
                    continue
                action_ref = redactor.ref("action", event.action_digest)
                review = reviews.get(
                    (
                        self.actor_ref(event.identity.agent_id),
                        redactor.ref("session", event.identity.session_id),
                        action_ref,
                        event.identity.policy_epoch,
                    )
                )
                if review is None:
                    continue
                # Enumerate a bounded number of explicit ancestor chains. A
                # candidate ends at reviewed intent, not successful exploitation.
                pending: list[tuple[list[str], list[str]]] = [([key], [])]
                while pending and len(paths) < 32:
                    chain, kinds = pending.pop()
                    prior = parents.get(chain[0], ())
                    if not prior or len(chain) >= 64:
                        if len(chain) > 1:
                            paths.append(
                                {
                                    "event_refs": [redactor.ref("event", item) for item in chain],
                                    "edge_kinds": kinds,
                                    "action_ref": action_ref,
                                    "risk": review["facts"]["risk"],
                                    "disposition": review["facts"]["disposition"],
                                    "evidence": "intent",
                                    "claim": "causal_review_candidate",
                                    "successful_exploitation": "unknown",
                                    "execution_authority": False,
                                }
                            )
                        if prior:
                            gaps.append("projection_truncated")
                        continue
                    for parent, kind in prior[:8]:
                        if parent not in chain:
                            pending.append(([parent, *chain], [kind, *kinds]))
                    if len(pending) > 64:
                        pending = pending[-64:]
                        gaps.append("projection_truncated")
                if pending:
                    gaps.append("projection_truncated")
            return {
                "nodes": nodes,
                "edges": edges,
                "paths": paths,
                "successful_exploitation": "unknown",
            }
        except (ValueError, OSError, RuntimeError, KeyError):
            gaps.append("protected_causal_source_unavailable")
            return {"nodes": [], "edges": [], "paths": [], "successful_exploitation": "unknown"}

    def _incidents(self, state):
        result = []
        truncated = False
        controller = self._containment
        if controller is not None:
            with controller._lock:
                entries = tuple(controller._incidents.values())
                truncated = len(entries) > 128 or any(
                    len(item.controls) > 128 for item in entries[-128:]
                )
                copies = [
                    (
                        item.receipt,
                        tuple(item.controls.items()),
                        len(item.affected),
                        item.done.is_set(),
                        item.resumed,
                        tuple(item.errors),
                        item.chain_digest,
                    )
                    for item in entries[-128:]
                ]
            for receipt, controls, affected, done, resumed, errors, chain in copies:
                outcomes = []
                for job, control in controls[:128]:
                    broker, authorization = job
                    outcomes.append(
                        control.status
                        if broker.verify_control_receipt(control, authorization)
                        else "unknown"
                    )
                result.append(
                    {
                        "incident_ref": self.journal.redactor.ref("incident", receipt.incident_id),
                        "scope_ref": self.journal.redactor.ref("source", receipt.scope_digest),
                        "operation": receipt.operation,
                        "revocation_epoch": receipt.revocation_epoch,
                        "affected_count": affected,
                        "notifications_complete": done,
                        "resumed": resumed,
                        "outcomes": outcomes or ["unknown"],
                        "freshness": "last_recorded",
                        "proof_gaps": ["unmediated_paths_uncovered"]
                        + (["source_unavailable"] if errors else []),
                        "chain_ref": self.journal.redactor.ref("proof", chain),
                        "execution_authority": False,
                    }
                )
        if state is not None:
            truncated = truncated or len(state["fences"]) > 128
            for epoch, intent in sorted(state["fences"].items(), key=lambda item: int(item[0]))[
                -128:
            ]:
                if not any(row["revocation_epoch"] == int(epoch) for row in result):
                    result.append(
                        {
                            "incident_ref": self.journal.redactor.ref(
                                "incident", [self._scope.scope_key, epoch]
                            ),
                            "scope_ref": self.journal.redactor.ref("source", self._scope.scope_key),
                            "operation": "unknown",
                            "revocation_epoch": int(epoch),
                            "affected_count": len(intent["subjects"]),
                            "notifications_complete": False,
                            "resumed": intent["reconciled"],
                            "outcomes": ["unknown"],
                            "freshness": "durable_metadata",
                            "proof_gaps": ["source_unavailable", "unmediated_paths_uncovered"],
                            "chain_ref": self.journal.redactor.ref("proof", digest(intent)),
                            "execution_authority": False,
                        }
                    )
        return result[-128:], truncated or len(result) > 128

    def snapshot(self, *, operator: object):
        self._check(operator)
        redactor = self.journal.redactor
        # Copy component metadata without holding a component lock across DB I/O.
        with self._registry._lock:
            hosts = [
                (row.context, row.phase, row.last_heartbeat)
                for row in self._registry._agents.values()
                if row.context.identity.task_id == self._task
            ]
            timeout = self._registry._timeout
        gaps = ["unmediated_paths_uncovered", "prehistory_unknown"]
        if not self.flush(operator=operator):
            gaps.append("capture_pending_or_unavailable")
        if self._dropped:
            gaps.append("capture_overflow")
        state, budgets, now = None, [], None
        try:
            with self._coordinator.store.transaction() as transaction:
                original = transaction.scope(self._scope.scope_key)
                transaction.verify_journal_head(self._scope.scope_key)
                state, now = decode(encode(original)), transaction.now
                rows = transaction.connection.execute(
                    "SELECT DISTINCT b.bucket FROM coordinator_buckets b JOIN coordinator_items i ON i.bucket=b.bucket WHERE i.scope_key=? LIMIT 257",
                    (self._scope.scope_key,),
                ).fetchall()
                from .coordinator import _bucket

                if len(rows) > 256:
                    gaps.append("projection_truncated")
                for row in rows[:256]:
                    row = _bucket(transaction.connection, row["bucket"])
                    if row is None or row["tenant_digest"] != digest(self._tenant):
                        raise ValueError("invalid diagnostic budget scope")
                    budgets.append(
                        {
                            "bucket_ref": redactor.ref("budget", row["bucket"]),
                            "metric": row["metric"],
                            "maximum": row["maximum"],
                            "held": row["held"],
                            "consumed": row["consumed"],
                            "remaining": max(0, row["maximum"] - row["held"] - row["consumed"]),
                            "claim": "admission_accounting",
                            "physical_enforcement": False,
                        }
                    )
        except (ValueError, OSError, RuntimeError, sqlite3.Error):
            state, budgets, now = None, [], None
            gaps.append("coordinator_unavailable")
        agents, coverage = [], []
        for context, phase, heartbeat in hosts[:256]:
            identity = context.identity
            subject = digest([self._tenant, self._swarm, identity.agent_id])
            durable = state["subjects"].get(subject) if state is not None else None
            live = (
                "unknown"
                if now is None
                else "stale"
                if now - heartbeat >= timeout
                else phase
                if phase in {"active", "paused", "ended", "retired", "failed", "exited"}
                else "unknown"
            )
            contained = (
                "unknown"
                if state is None
                else "permission_fenced"
                if durable and durable["revoked"]
                else "not_fenced_in_this_snapshot"
            )
            actor = self.actor_ref(identity.agent_id)
            agents.append(
                {
                    "actor_ref": actor,
                    "session_ref": redactor.ref("session", identity.session_id),
                    "parent_ref": self.actor_ref(identity.parent_agent_id)
                    if identity.parent_agent_id
                    else None,
                    "generation": identity.generation,
                    "policy_epoch": identity.policy_epoch,
                    "phase": live,
                    "containment": contained,
                    "reported_mode": context.coverage.mode,
                }
            )
            entries = context.coverage.entries
            if not entries:
                coverage.append(
                    {
                        "actor_ref": actor,
                        "capability": "unknown",
                        "route_ref": redactor.ref("route", "unlisted"),
                        "resource_ref": redactor.ref("resource", "unlisted"),
                        "reported_state": "coverage_gap",
                        "verified_state": "coverage_gap",
                        "proof_gaps": ["route_inventory_missing"],
                    }
                )
            for entry in entries:
                kind = (
                    entry.capability
                    if entry.capability
                    in {
                        "filesystem",
                        "network",
                        "tool",
                        "credential",
                        "process",
                        "message",
                        "storage",
                    }
                    else "unknown"
                )
                coverage.append(
                    {
                        "actor_ref": actor,
                        "capability": kind,
                        "route_ref": redactor.ref("route", entry.route),
                        "resource_ref": redactor.ref("resource", entry.resource),
                        "reported_state": entry.state,
                        "verified_state": "unsupported"
                        if entry.state == "unsupported"
                        else "observe_only"
                        if entry.state == "observe_only"
                        else "coverage_gap",
                        "proof_gaps": [
                            "no_current_runtime_attestation",
                            "unmediated_paths_uncovered",
                        ],
                    }
                )
        nodes, edges = [], []
        if state is not None:
            events = state["events"]
            selected = dict(list(sorted(events.items()))[-256:])
            for key, event in selected.items():
                node = redactor.ref("event", key)
                nodes.append(
                    {
                        "event_ref": node,
                        "actor_ref": redactor.ref("actor", event["subject"]),
                        "kind": event["kind"],
                        "action_ref": redactor.ref("action", event["action_digest"])
                        if event["action_digest"]
                        else None,
                        "evidence": "reported"
                        if event["evidence_class"] == "host_authenticated"
                        else "diagnostic",
                    }
                )
                for parent in event["parents"]:
                    edges.append(
                        {
                            "from_ref": redactor.ref("event", parent),
                            "to_ref": node,
                            "state": "known" if parent in selected else "missing_parent",
                        }
                    )
            if state["event_incomplete"] or state["incomplete"] or state["artifact_pending"]:
                gaps.append("durable_history_incomplete")
        try:
            bundle = self.journal.export(operator=operator)
            timeline = bundle["events"][-20:]
        except (ValueError, OSError, RuntimeError):
            bundle, timeline = None, []
            gaps.append("capture_unavailable")
        if self._fault or self._closed:
            gaps.append("capture_unavailable")
        metric_events = bundle["events"] if bundle else []
        protected_graph = self._protected_graph(metric_events, gaps)
        metrics = {
            "intent_reviews": sum(row["kind"] == "decision" for row in metric_events),
            "observed_completions": sum(
                row["kind"] == "broker_result"
                and row["state"] == "completed"
                and row["evidence"] == "observed"
                for row in metric_events
            ),
            "reported_completions": sum(
                row["state"] == "completed" and row["evidence"] == "reported"
                for row in metric_events
            ),
            "unknown_outcomes": sum(row["state"] == "unknown" for row in metric_events),
            "advisory_risk_signals": sum(row["kind"] == "risk_signal" for row in metric_events),
            "window": "retained_audit_only",
            "complete_history": False,
        }
        native = self._coordinator._scope(self._scope)
        policy = {
            "policy_ref": redactor.ref("policy", state["policy_digest"]) if state else None,
            "policy_epoch": state["policy_epoch"] if state else None,
            "owner_fence": state["owner"]["fence"] if state else None,
            "claim": "committed_metadata_not_permission",
            "budget_configured": [
                {
                    "scope": limit.scope,
                    "metric": limit.metric,
                    "maximum": limit.maximum,
                    "subject_ref": redactor.ref("subject", limit.subject)
                    if limit.subject
                    else None,
                }
                for limit in native.budget.limits
            ],
        }
        permissions, permission_cut = self._permissions()
        incidents, incident_cut = self._incidents(state)
        if (
            permission_cut
            or incident_cut
            or len(hosts) > 256
            or len(metric_events) > 20
            or len(coverage) > 512
            or len(edges) > 1024
            or state is not None
            and len(state["events"]) > 256
        ):
            gaps.append("projection_truncated")
        return {
            "schema_version": "ordin.swarm_operator_snapshot.v1",
            "tenant_ref": redactor.tenant_ref,
            "swarm_ref": redactor.ref("swarm", self._swarm),
            "scope_ref": redactor.ref("scope", self._scope.scope_key),
            "observed_at": now,
            "coordinator_online": bool(
                state is not None
                and self._coordinator._available
                and state["owner"]["id"] == self._coordinator._instance
                and now < state["owner"]["expires_at"]
            ),
            "verified_live_source": True,
            "agents": agents,
            "coverage": coverage[:512],
            "graph": protected_graph
            or {
                "nodes": nodes,
                "edges": edges[:1024],
                "paths": [],
                "successful_exploitation": "unknown",
            },
            "budgets": budgets,
            "permissions": permissions,
            "policy": policy,
            "incidents": incidents,
            "approvals": [],
            "timeline": timeline,
            "metrics": metrics,
            "proof_gaps": sorted(set(gaps)),
            "unmediated_paths": "uncovered",
            "prehistory": "unknown",
            "execution_authority": False,
        }
