"""Optional host integration entry points; import starts no transports."""

from .mcp_adapter import SwarmMCPAdapter
from .hooks import SwarmHookAdapter

__all__ = ["SwarmMCPAdapter", "SwarmHookAdapter"]
