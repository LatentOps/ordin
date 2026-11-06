"""Bounded mTLS coordinator transport; references remain online server lookups."""

from __future__ import annotations

import json
import ssl
import struct
import time
from typing import Any, Callable

from ordin.action import ActionEnvelope

from .coordinator import SwarmCoordinator, CoordinatorScope
from .coordinator_store import CoordinatorRejected, CoordinatorUnavailable, decode, encode
from .events import SwarmEvent
from .workload_auth import AuthorityChannel

MAX_FRAME = 65536


def _receive(connection, deadline):
    def exact(length):
        data = bytearray()
        while len(data) < length:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CoordinatorUnavailable("coordinator transport deadline")
            connection.settimeout(min(remaining, 10))
            block = connection.recv(length - len(data))
            if not block:
                raise CoordinatorUnavailable("coordinator transport closed")
            data.extend(block)
        return bytes(data)

    length = struct.unpack("!I", exact(4))[0]
    if not 1 <= length <= MAX_FRAME:
        raise CoordinatorRejected("coordinator.frame_limit")
    return decode(exact(length).decode("utf-8"), MAX_FRAME)


def _send(connection, value, deadline):
    raw = encode(value, MAX_FRAME).encode("utf-8")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise CoordinatorUnavailable("coordinator transport deadline")
    connection.settimeout(min(remaining, 10))
    connection.sendall(struct.pack("!I", len(raw)) + raw)


class CoordinatorEndpoint:
    """One configured task scope per listener; no JSON-selected tenant or role."""

    def __init__(self, coordinator: SwarmCoordinator, scope: CoordinatorScope):
        if type(coordinator) is not SwarmCoordinator:
            raise ValueError("original coordinator required")
        coordinator._scope(scope)
        self.coordinator, self.scope = coordinator, scope

    def handle(self, channel: AuthorityChannel, request: dict[str, Any]) -> Any:
        if (
            type(request) is not dict
            or set(request) != {"schema_version", "operation", "arguments"}
            or request["schema_version"] != "ordin.swarm_coordinator_request.v1"
        ):
            raise CoordinatorRejected("coordinator.request_shape")
        operation, args = request["operation"], request["arguments"]
        shapes = {
            "admit": set(),
            "renew": set(),
            "policy": {"lease"},
            "producer": {"lease"},
            "status": {"lease"},
            "budget": {"lease"},
            "bind_grant": {"lease", "grant"},
            "revoke_lease": {"lease"},
            "evaluate": {"lease", "grant", "action", "idempotency_key"},
            "reserve": {"lease", "evaluation", "action", "idempotency_key"},
            "cancel": {"lease", "reservation"},
            "event": {"lease", "event"},
            "forward": {"reservation"},
            "commit": {"reservation"},
            "uncertain": {"reservation"},
            "dispatch": {"reservation"},
        }
        if (
            type(operation) is not str
            or operation not in shapes
            or type(args) is not dict
            or set(args) != shapes[operation]
        ):
            raise CoordinatorRejected("coordinator.operation_shape")
        coordinator, scope = self.coordinator, self.scope
        result: Any
        method: Callable[..., Any]
        # Each service method verifies the original workload/broker channel again.
        if operation in {"admit", "renew"}:
            result = coordinator.admit(scope, channel)
        elif operation in {"policy", "producer", "status", "budget", "revoke_lease"}:
            method = {
                "policy": coordinator.policy_snapshot,
                "producer": coordinator.admission_context,
                "status": coordinator.workload_status,
                "budget": coordinator.budget_report,
                "revoke_lease": coordinator.revoke_lease,
            }[operation]
            result = method(scope, channel, args["lease"])
        elif operation == "bind_grant":
            result = coordinator.bind_grant(scope, channel, args["lease"], args["grant"])
        elif operation == "evaluate":
            result = coordinator.evaluate(
                scope,
                channel,
                args["lease"],
                args["grant"],
                ActionEnvelope.from_dict(args["action"]),
                idempotency_key=args["idempotency_key"],
            )
        elif operation == "reserve":
            result = coordinator.reserve(
                scope,
                channel,
                args["lease"],
                args["evaluation"],
                ActionEnvelope.from_dict(args["action"]),
                idempotency_key=args["idempotency_key"],
            )
        elif operation == "cancel":
            result = coordinator.cancel(scope, channel, args["lease"], args["reservation"])
        elif operation == "event":
            result = coordinator.ingest_event(
                scope, channel, args["lease"], SwarmEvent.from_dict(args["event"])
            )
        elif operation == "dispatch":
            result = coordinator.guarded_dispatch(scope, channel, args["reservation"])
        else:
            method = {
                "forward": coordinator.begin_forward,
                "commit": coordinator.commit,
                "uncertain": coordinator.uncertain,
            }[operation]
            result = method(scope, channel, args["reservation"])
        return (
            result.to_wire()
            if hasattr(result, "to_wire")
            else result.as_dict()
            if hasattr(result, "as_dict")
            else result
        )

    def serve_one(self, connection: ssl.SSLSocket) -> None:
        auth = self.coordinator._scope(self.scope).authenticator
        channel = auth.authenticate(connection)
        timeout = connection.gettimeout()
        deadline = time.monotonic() + 10
        try:
            try:
                result = self.handle(channel, _receive(connection, deadline))
                response = {
                    "schema_version": "ordin.swarm_coordinator_response.v1",
                    "status": "ok",
                    "result": result,
                    "reason_code": None,
                    "execution_authority": False,
                }
            except (ValueError, TypeError, KeyError, RecursionError, UnicodeError):
                response = {
                    "schema_version": "ordin.swarm_coordinator_response.v1",
                    "status": "denied",
                    "result": None,
                    "reason_code": "coordinator.request_refused",
                    "execution_authority": False,
                }
            _send(connection, response, deadline)
        except (OSError, ValueError):
            raise CoordinatorUnavailable(
                "coordinator transport unavailable; do not retry effects"
            ) from None
        finally:
            # Keep the original channel for subsequent requests on this same
            # connection; the listener must call close_connection on EOF.
            connection.settimeout(timeout)

    def close_connection(self, connection: ssl.SSLSocket) -> None:
        auth = self.coordinator._scope(self.scope).authenticator
        try:
            auth.close(auth.authenticate(connection))
        finally:
            connection.close()


class CoordinatorClient:
    """A request never retries on lost acknowledgement or reconnects silently."""

    def __init__(self, connection: ssl.SSLSocket):
        if (
            type(connection) is not ssl.SSLSocket
            or not connection.context.check_hostname
            or connection.context.verify_mode != ssl.CERT_REQUIRED
            or connection.context.minimum_version < ssl.TLSVersion.TLSv1_2
            or not connection.getpeercert(binary_form=True)
        ):
            raise ValueError("verified hostname-checking mutual TLS client socket required")
        self.connection = connection

    def request(self, operation: str, **arguments: Any) -> Any:
        deadline, timeout = time.monotonic() + 10, self.connection.gettimeout()
        try:
            _send(
                self.connection,
                {
                    "schema_version": "ordin.swarm_coordinator_request.v1",
                    "operation": operation,
                    "arguments": arguments,
                },
                deadline,
            )
            response = _receive(self.connection, deadline)
            if (
                set(response)
                != {"schema_version", "status", "result", "reason_code", "execution_authority"}
                or response["schema_version"] != "ordin.swarm_coordinator_response.v1"
                or response["execution_authority"] is not False
            ):
                raise CoordinatorUnavailable("coordinator response shape")
            if response["status"] != "ok":
                raise CoordinatorRejected("coordinator.request_refused")
            return response["result"]
        except (OSError, UnicodeError, json.JSONDecodeError):
            raise CoordinatorUnavailable(
                "coordinator transport unavailable; effect outcome unknown"
            ) from None
        finally:
            self.connection.settimeout(timeout)
