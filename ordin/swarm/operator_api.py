"""Explicit mutual-TLS operator API. Data frames cannot carry identity or permits."""

from __future__ import annotations

import ssl
import struct
import time
import re
from typing import Any

from .coordinator_store import decode, encode
from .diagnostics import SwarmAuditSource
from .incident import IncidentScope
from .operator_auth import HumanOperatorChannel, SwarmOperatorDirectory
from .registry import InMemoryAgentRegistry

MAX_FRAME = 1024 * 1024
QUERIES = frozenset({"list", "status", "graph", "explain", "incidents", "policy", "coverage"})


def _read(connection, deadline):
    def exact(count):
        result = bytearray()
        while len(result) < count:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError("operator.deadline")
            connection.settimeout(min(remaining, 10))
            block = connection.recv(count - len(result))
            if not block:
                raise ValueError("operator.closed")
            result.extend(block)
        return bytes(result)

    length = struct.unpack("!I", exact(4))[0]
    if not 1 <= length <= MAX_FRAME:
        raise ValueError("operator.frame_limit")
    return decode(exact(length).decode("utf-8"), MAX_FRAME)


def _write(connection, value, deadline):
    data = encode(value, MAX_FRAME).encode()
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ValueError("operator.deadline")
    connection.settimeout(min(remaining, 10))
    connection.sendall(struct.pack("!I", len(data)) + data)


class SwarmOperatorAPI:
    def __init__(
        self,
        directory: SwarmOperatorDirectory,
        sources: tuple[SwarmAuditSource, ...],
        *,
        operator: object,
        governance=None,
    ):
        if (
            type(directory) is not SwarmOperatorDirectory
            or type(sources) is not tuple
            or not 1 <= len(sources) <= 64
        ):
            raise ValueError("original bounded operator directory and sources required")
        directory._operator_check(operator)
        registry = directory.authenticator._registry
        if type(registry) is not InMemoryAgentRegistry:
            raise ValueError("original operator registry required")
        self._sources: dict[str, SwarmAuditSource] = {}
        for source in sources:
            if (
                type(source) is not SwarmAuditSource
                or source._operator is not operator
                or (source._tenant, source._swarm) != (registry._tenant, registry._swarm)
            ):
                raise ValueError("operator sources must share protected tenant/swarm")
            reference = source.journal.redactor.ref("scope", source._scope.scope_key)
            if reference in self._sources:
                raise ValueError("duplicate operator scope")
            self._sources[reference] = source
        self.directory, self._operator, self._governance = directory, operator, governance
        if governance is not None:
            from .approval_service import SwarmApprovalService

            if (
                type(governance) is not SwarmApprovalService
                or governance.directory is not directory
                or not any(
                    governance.coordinator is source._coordinator
                    and governance.scope is source._scope
                    for source in sources
                )
            ):
                raise ValueError("original scoped governance service required")

    def _approval_rows(self, channel, source):
        service = self._governance
        if (
            service is None
            or service.coordinator is not source._coordinator
            or service.scope is not source._scope
        ):
            return [], False
        queue = service.snapshot(channel, task_id=self._task(source))
        result = []
        for entry in [*queue["requests"], *queue["recoveries"]][:128]:
            request = entry["request"]
            binding = request.get("binding", {})
            result.append(
                {
                    "request_ref": source.journal.redactor.ref("approval", request["request_id"]),
                    "action_ref": source.journal.redactor.ref("action", binding["action_digest"])
                    if binding.get("action_digest")
                    else None,
                    "mode": request.get("mode", "recovery"),
                    "disposition": request.get("disposition", "escalate"),
                    "risk": request.get("risk", "unknown"),
                    "quorum": request["quorum"],
                    "vote_count": entry["vote_count"],
                    "status": entry["status"],
                    "required_role_refs": [
                        source.journal.redactor.ref("role", role)
                        for role in request["required_roles"]
                    ],
                    "execution_authority": False,
                }
            )
        return result, len(queue["requests"]) + len(queue["recoveries"]) > 128

    @staticmethod
    def _task(source):
        return source._task or "swarm-control"

    def _require(self, channel, source, role):
        return self.directory.require(channel, task_id=self._task(source), roles=(role,))

    def handle(self, channel: HumanOperatorChannel, request: dict[str, Any]) -> dict[str, Any]:
        if (
            type(request) is not dict
            or set(request) != {"schema_version", "operation", "scope_ref", "arguments"}
            or request["schema_version"] != "ordin.swarm_operator_request.v1"
        ):
            raise ValueError("operator.request_shape")
        operation, arguments = request["operation"], request["arguments"]
        if type(operation) is not str or type(arguments) is not dict:
            raise ValueError("operator.request_shape")
        if operation == "list" and request["scope_ref"] is None:
            if arguments:
                raise ValueError("operator.list_shape")
            listed = []
            for reference, source in self._sources.items():
                try:
                    self._require(channel, source, "observe")
                except ValueError:
                    continue
                snapshot = source.snapshot(operator=self._operator)
                listed.append(
                    {
                        "scope_ref": reference,
                        "agents": snapshot["agents"],
                        "proof_gaps": snapshot["proof_gaps"],
                    }
                )
                self._require(channel, source, "observe")
            if not listed:
                raise ValueError("operator.authorization_required")
            return {
                "schema_version": "ordin.swarm_operator_list.v1",
                "scopes": listed,
                "execution_authority": False,
            }
        reference = request["scope_ref"]
        if reference is None and len(self._sources) == 1:
            reference = next(iter(self._sources))
        if type(reference) is not str or reference not in self._sources:
            raise ValueError("operator.authorization_required")
        source = self._sources[reference]
        if operation in QUERIES:
            self._require(channel, source, "observe")
            if set(arguments) - ({"action_ref"} if operation == "explain" else set()):
                raise ValueError("operator.query_shape")
            snapshot = source.snapshot(operator=self._operator)
            self._require(channel, source, "observe")
            snapshot["approvals"], approvals_cut = self._approval_rows(channel, source)
            if approvals_cut:
                snapshot["proof_gaps"] = sorted(
                    set(snapshot["proof_gaps"]) | {"projection_truncated"}
                )
            if operation in {"status", "list"}:
                return snapshot
            if operation == "explain":
                action = arguments.get("action_ref")
                if type(action) is not str or re.fullmatch(r"hmac:[a-f0-9]{64}", action) is None:
                    raise ValueError("operator.exact_action_reference_required")
                return {
                    "schema_version": "ordin.swarm_operator_explanation.v1",
                    "scope_ref": reference,
                    "action_ref": action,
                    "events": [
                        row
                        for row in source.journal.export(operator=self._operator)["events"]
                        if row["refs"].get("action") == action
                    ][-20:],
                    "proof_gaps": snapshot["proof_gaps"],
                    "successful_exploitation": "unknown",
                    "execution_authority": False,
                }
            return {
                "schema_version": "ordin.swarm_operator_view.v1",
                "scope_ref": reference,
                "view": operation,
                "data": snapshot[operation],
                "proof_gaps": snapshot["proof_gaps"],
                "execution_authority": False,
            }
        if operation == "export":
            self._require(channel, source, "export")
            if arguments:
                raise ValueError("operator.raw_export_forbidden")
            flushed = source.flush(operator=self._operator)
            bundle = source.journal.export(operator=self._operator)
            bundle["capture_status"] = {
                "flushed": flushed,
                "dropped_events": source._dropped,
                "complete_history": False,
                "export_window_truncated": False,
            }
            # A bounded transport window is an anchored suffix, never a claim
            # that omitted capture or earlier history was clean.
            while len(encode(bundle, 8 * MAX_FRAME).encode()) > MAX_FRAME - 4096:
                rows = bundle["events"]
                if len(rows) <= 1:
                    raise ValueError("operator.export_frame_limit")
                bundle["events"] = rows[len(rows) // 2 :]
                first = bundle["events"][0]
                bundle["first_sequence"], bundle["base_hash"] = (
                    first["sequence"],
                    first["previous_hash"],
                )
                bundle["capture_status"]["export_window_truncated"] = True
            self._require(channel, source, "export")
            return bundle
        if operation in {"pause", "revoke"}:
            self._require(channel, source, operation)
            if set(arguments) != {"scope_kind", "actor_ref"} or source._containment is None:
                raise ValueError("operator.control_shape")
            kind = arguments["scope_kind"]
            if kind == "agent":
                context = source.current_actor(arguments["actor_ref"], operator=self._operator)
                selected = IncidentScope(
                    "agent", source._tenant, source._swarm, agent_id=context.identity.agent_id
                )
            elif kind == "task" and arguments["actor_ref"] is None and source._task is not None:
                selected = IncidentScope(
                    "task", source._tenant, source._swarm, task_id=source._task
                )
            elif kind == "swarm" and arguments["actor_ref"] is None:
                self.directory.require(channel, task_id="swarm-control", roles=(operation,))
                selected = IncidentScope("swarm", source._tenant, source._swarm)
            else:
                raise ValueError("operator.control_scope")
            signal = source._containment._signals.operator_signal(
                selected, severity="high", operator=self._operator
            )
            self._require(channel, source, operation)
            receipt = getattr(source._containment, operation)(signal, operator=self._operator)
            return {
                "schema_version": "ordin.swarm_operator_control.v1",
                "scope_ref": reference,
                "operation": operation,
                "receipt_ref": source.journal.redactor.ref("incident", receipt.incident_id),
                "status": "logical_fence_recorded",
                "execution_authority": False,
            }
        if operation == "sweep":
            self._require(channel, source, "retain")
            if (
                set(arguments) != {"maximum_resources"}
                or type(arguments["maximum_resources"]) is not int
                or not 1 <= arguments["maximum_resources"] <= 256
            ):
                raise ValueError("operator.retention_shape")
            audit = source.journal.sweep(operator=self._operator)
            result = (
                source._coordinator.artifact_sweep(
                    source._scope,
                    control=source._control,
                    maximum_resources=arguments["maximum_resources"],
                )
                if source._coordinator._scope(source._scope).artifacts is not None
                else None
            )
            source._append(
                "retention-" + str(audit["tail_sequence"]) + "-" + str(audit["first_sequence"]),
                kind="retention",
                state="swept",
                evidence="diagnostic",
                refs={},
                facts={"count": result["versions_removed"] if result else 0},
            )
            return {
                "schema_version": "ordin.swarm_operator_retention.v1",
                "scope_ref": reference,
                "audit_first_sequence": audit["first_sequence"],
                "artifact_result": result,
                "execution_authority": False,
            }
        if operation in {"approve", "deny"}:
            return self._resolve_approval(channel, source, operation, arguments)
        raise ValueError("operator.operation_unsupported")

    def _resolve_approval(self, channel, source, operation, arguments):
        self._require(channel, source, operation)
        if self._governance is None or set(arguments) != {"request_ref", "idempotency_key"}:
            raise ValueError("operator.governance_service_required")
        # Only a committed original governance service may fulfill obligations.
        from .approval_service import SwarmApprovalService

        if (
            type(self._governance) is not SwarmApprovalService
            or self._governance.coordinator is not source._coordinator
            or self._governance.scope is not source._scope
        ):
            raise ValueError("operator.original_governance_required")
        snapshot = self._governance.snapshot(channel, task_id=self._task(source))
        candidates = [
            (
                row["request"]["request_id"],
                row["request"] in [entry["request"] for entry in snapshot["recoveries"]],
            )
            for row in [*snapshot["requests"], *snapshot["recoveries"]]
            if source.journal.redactor.ref("approval", row["request"]["request_id"])
            == arguments["request_ref"]
        ]
        if len(candidates) != 1:
            raise ValueError("operator.current_approval_reference_required")
        method = self._governance.resolve_recovery if candidates[0][1] else self._governance.resolve
        result = method(
            channel, candidates[0][0], operation, idempotency_key=arguments["idempotency_key"]
        )
        return {
            "schema_version": "ordin.swarm_operator_control.v1",
            "scope_ref": source.journal.redactor.ref("scope", source._scope.scope_key),
            "operation": operation,
            "receipt_ref": arguments["request_ref"],
            "status": result["status"]
            if result["status"] in {"pending", "approved", "denied", "expired", "stale"}
            else "unknown",
            "execution_authority": False,
        }

    def serve_one(self, connection: ssl.SSLSocket) -> None:
        channel = self.directory.authenticate(connection)
        deadline, previous = time.monotonic() + 10, connection.gettimeout()
        try:
            try:
                result = self.handle(channel, _read(connection, deadline))
                response = {
                    "schema_version": "ordin.swarm_operator_response.v1",
                    "status": "ok",
                    "result": result,
                    "execution_authority": False,
                }
            except (ValueError, TypeError, KeyError, OSError, RuntimeError):
                response = {
                    "schema_version": "ordin.swarm_operator_response.v1",
                    "status": "denied",
                    "result": None,
                    "execution_authority": False,
                }
            _write(connection, response, deadline)
        finally:
            if connection.fileno() >= 0:
                connection.settimeout(previous)

    def close_connection(self, connection):
        try:
            self.directory.close(self.directory.authenticate(connection))
        finally:
            connection.close()


class SwarmOperatorClient:
    def __init__(self, connection: ssl.SSLSocket):
        if (
            type(connection) is not ssl.SSLSocket
            or not connection.context.check_hostname
            or connection.context.verify_mode != ssl.CERT_REQUIRED
            or connection.context.minimum_version < ssl.TLSVersion.TLSv1_2
            or not connection.getpeercert(binary_form=True)
        ):
            raise ValueError("verified operator TLS connection required")
        self.connection = connection

    def request(self, operation: str, *, scope_ref=None, **arguments):
        deadline, previous = time.monotonic() + 10, self.connection.gettimeout()
        try:
            _write(
                self.connection,
                {
                    "schema_version": "ordin.swarm_operator_request.v1",
                    "operation": operation,
                    "scope_ref": scope_ref,
                    "arguments": arguments,
                },
                deadline,
            )
            result = _read(self.connection, deadline)
            if (
                set(result) != {"schema_version", "status", "result", "execution_authority"}
                or result["schema_version"] != "ordin.swarm_operator_response.v1"
                or result["execution_authority"] is not False
                or result["status"] != "ok"
            ):
                raise ValueError("operator.request_refused")
            return result["result"]
        finally:
            self.connection.settimeout(previous)
