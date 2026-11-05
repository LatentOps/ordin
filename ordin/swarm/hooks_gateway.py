"""Host-side adapters reusing maintained coding-agent payload normalization."""

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from ordin.action import ActionEnvelope
from ordin.agent import AgentGate
from ordin.claude_code import ClaudeCodeIntegration
from ordin.codex import CodexIntegration
from ordin.cursor import CursorIntegration
from ordin.hermes import HermesIntegration

from .gateway import GatewayAgent, GatewayAuthorization, GatewayResult, SwarmToolGateway


class _AdaptedAction(Exception):
    def __init__(self, action: ActionEnvelope):
        self.action = action
        super().__init__("maintained hook payload adapted")


@dataclass(frozen=True)
class _CaptureGate(AgentGate):
    def evaluate_action(self, action, **kwargs):
        raise _AdaptedAction(action)


class SwarmHookAdapter:
    """Protected host integration, not automatic instrumentation of hook JSON."""

    def __init__(self, gateway: SwarmToolGateway, agent: GatewayAgent, *, integration: str):
        if integration not in {"claude", "codex", "cursor", "hermes"}:
            raise ValueError("unsupported maintained hook integration")
        gateway._actor(agent)
        self._gateway, self._agent, self._integration = gateway, agent, integration

    def adapt(self, payload: Mapping[str, Any]) -> ActionEnvelope:
        if self._integration == "codex":
            return CodexIntegration().adapt(payload)
        if self._integration == "cursor":
            return CursorIntegration().adapt(payload)
        if self._integration == "hermes":
            return HermesIntegration().adapt(payload)
        try:
            ClaudeCodeIntegration(gate=_CaptureGate()).review_pre_tool(payload)
        except _AdaptedAction as captured:
            return captured.action
        raise ValueError("hook payload did not produce a normalized action")

    def call(
        self,
        payload: Mapping[str, Any],
        executor: Callable[[ActionEnvelope], Any],
    ) -> GatewayResult | GatewayAuthorization:
        action = self.adapt(payload)
        route = (
            action.kind
            if action.kind in {"shell", "file", "mcp", "database"}
            else ("http" if action.kind == "network" else "sdk")
        )
        authorization = self._gateway.prepare(self._agent, action, route=route)
        if authorization.ticket is None:
            return authorization
        return self._gateway.forward(self._agent, authorization.ticket, executor)
