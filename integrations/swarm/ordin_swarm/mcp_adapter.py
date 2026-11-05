"""Reuse the core bounded MCP adapter for explicit stdio/HTTP host transports."""

from ordin.swarm.mcp_gateway import SwarmMCPAdapter

__all__ = ["SwarmMCPAdapter"]
