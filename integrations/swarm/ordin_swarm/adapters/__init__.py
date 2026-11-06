"""Version-pinned optional adapters; framework imports occur only on explicit use."""

from .langgraph import LangGraphAdapter
from .crewai import CrewAIAdapter
from .autogen import AutoGenAdapter
from .custom import CustomRuntimeAdapter

__all__ = ["LangGraphAdapter", "CrewAIAdapter", "AutoGenAdapter", "CustomRuntimeAdapter"]
