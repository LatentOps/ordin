"""Opt-in MCP round trips over host-owned stdio or Streamable HTTP transports."""

from __future__ import annotations

import json
from threading import RLock
from typing import Any, Callable, Mapping
from uuid import uuid4

from ordin.action import ActionEnvelope
from ordin.agent import AgentGate
from ordin.context import ExecutionContext
from ordin.mcp_proxy import (
    APPROVAL_REQUIRED_CODE,
    BLOCKED_CODE,
    MCPStdioSafetyProxy,
    _request_id_key,
)
from ordin.mcp_http import MCPHTTPConfig
from ordin.mcp_contracts import MCPContractLock
from ordin.assurance.delegating_gate import DelegatingAssuranceGate

from .gateway import GatewayAgent, GatewayOutcome, SwarmToolGateway


def _message(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("MCP transport requires a JSON object")
    try:
        raw = json.dumps(dict(value), ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        if len(raw.encode("utf-8")) > 1048576:
            raise ValueError("MCP transport message exceeds its byte limit")
        result = json.loads(raw)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ValueError("invalid bounded MCP transport message") from None
    return result


class SwarmMCPAdapter:
    """Own one actor/server MCP session; execution remains in the chosen transport.

    Every tools/call passes both the maintained MCP protocol/session reviewer
    and the bound swarm gateway. HTTP config is optional, explicit host data;
    transport callbacks own its connection/authentication/session headers.
    """

    def __init__(
        self,
        gateway: SwarmToolGateway,
        agent: GatewayAgent,
        *,
        server_id: str,
        shell_tools: frozenset[str] = frozenset(),
        contract_lock: MCPContractLock | None = None,
        http_config: MCPHTTPConfig | None = None,
    ) -> None:
        if type(gateway) is not SwarmToolGateway:
            raise ValueError("MCP swarm adapter requires a protected gateway")
        actor = gateway._actor(agent)
        if http_config is not None and (
            type(http_config) is not MCPHTTPConfig or http_config.server_id != server_id
        ):
            raise ValueError("MCP HTTP configuration belongs to a different server")
        self._gateway, self._agent, self._server_id = gateway, agent, server_id
        baseline = actor.gate._baseline
        if isinstance(baseline, DelegatingAssuranceGate):
            raise ValueError("MCP delegated execution requires the enforcing broker adapter")
        self._proxy = MCPStdioSafetyProxy(
            server_id=server_id,
            gate=AgentGate(baseline.ordin),
            shell_tools=shell_tools,
            contract_lock=contract_lock,
            context=ExecutionContext(agent=actor.context.identity.agent_id),
            session_id=actor.context.identity.session_id,
            runtime_id=actor.context.identity.runtime_id,
        )
        self._lock = RLock()

    def call(
        self,
        message: Mapping[str, Any],
        transport: Callable[[dict[str, Any]], Mapping[str, Any] | None],
    ) -> dict[str, Any] | None:
        if not callable(transport):
            raise ValueError("MCP forwarding requires its protected transport")
        actor = self._gateway._actor(self._agent)
        with self._lock, self._gateway._operation_lock, actor.lock:
            original = _message(message)
            if original.get("method") not in {
                "tools/call",
                "initialize",
                "notifications/initialized",
                "tools/list",
                "ping",
            }:
                return {
                    "jsonrpc": "2.0",
                    "id": original.get("id"),
                    "error": {
                        "code": -32601,
                        "message": "Uncovered MCP method requires an explicit adapter",
                    },
                }
            decision = self._proxy.process_client_message(original)
            request_id = original.get("id")
            if not decision.forward:
                response = decision.response
                if response is None:
                    raise ValueError("MCP reviewer did not produce a forwarding disposition")
                if (
                    not actor.approval_ui
                    and response.get("error", {}).get("code") == APPROVAL_REQUIRED_CODE
                ):
                    response = {
                        **response,
                        "error": {
                            **response["error"],
                            "code": BLOCKED_CODE,
                            "message": "Swarm gateway denies calls requiring unavailable approval",
                        },
                    }
                return response
            wire = _message(original)
            wire_id = None
            if "id" in wire:
                wire_id = "swarm-mcp-" + uuid4().hex
                wire["id"] = wire_id

            def roundtrip(_action=None):
                try:
                    raw = transport(_message(wire))
                    if wire_id is None and raw is None:
                        return GatewayOutcome(None)
                    if raw is None:
                        raise ValueError("MCP request requires a correlated response")
                    response = _message(raw)
                    if wire_id is not None:
                        if _request_id_key(response.get("id")) != _request_id_key(wire_id):
                            raise ValueError("MCP upstream response correlation mismatch")
                        response["id"] = request_id
                    observation = self._proxy.observe_server_message(response)
                    if original.get("method") == "tools/call":
                        if observation is None:
                            raise ValueError("MCP tool response lacks its exact pending call")
                        status = observation.metadata.get("status")
                        result_status = (
                            "completed"
                            if status == "success"
                            else "pending"
                            if status in {"task_accepted", "input_required"}
                            else "failed"
                        )
                        return GatewayOutcome(response, result_status)
                    return GatewayOutcome(response)
                except Exception:
                    if decision.action_id is not None:
                        self._proxy.observe_server_message(
                            {
                                "jsonrpc": "2.0",
                                "id": request_id,
                                "error": {
                                    "code": -32000,
                                    "message": "Protected MCP transport failed",
                                },
                            }
                        )
                    raise

            if original.get("method") != "tools/call":
                return roundtrip().value
            if decision.action_id is None:
                raise ValueError("MCP tool call lacks its host correlation ID")
            actions = self._proxy.session.snapshot()["history"]["actions"]
            action = next(
                (
                    ActionEnvelope.from_dict(value)
                    for value in actions
                    if value["action_id"] == decision.action_id
                ),
                None,
            )
            if action is None:
                raise ValueError("MCP reviewer lost its exact action")
            authorization = self._gateway.prepare(self._agent, action, route="mcp")
            if authorization.ticket is None:
                response = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {
                        "code": BLOCKED_CODE
                        if authorization.disposition == "deny"
                        else APPROVAL_REQUIRED_CODE,
                        "message": "Swarm policy denied or escalated the tool call",
                    },
                }
                self._proxy.observe_server_message(response)
                return response
            result = self._gateway.forward(self._agent, authorization.ticket, roundtrip)
            return result.value

    def observe_notification(self, message: Mapping[str, Any]) -> None:
        """Host transport reports upstream notifications without inventing effects."""
        with self._lock:
            self._proxy.observe_server_message(_message(message))
