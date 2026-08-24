from __future__ import annotations

from typing import Sequence

from .base import Analyzer, SemanticAnalysis, normalize_invocation

_REGISTRY: dict[str, Analyzer] = {}


def register(*executables: str):
    def decorator(analyzer: Analyzer) -> Analyzer:
        for executable in executables:
            _REGISTRY[executable] = analyzer
        return analyzer
    return decorator


def analyze_tokens(tokens: Sequence[str]) -> SemanticAnalysis | None:
    invocation = normalize_invocation(tokens)
    if invocation is None:
        return None
    analyzer = _REGISTRY.get(invocation.executable)
    if analyzer is None:
        return None
    return analyzer(invocation)


def supported_analyzers() -> tuple[str, ...]:
    return tuple(sorted(_REGISTRY))


from . import docker as _docker  # noqa: E402,F401
from . import filesystem as _filesystem  # noqa: E402,F401
from . import git as _git  # noqa: E402,F401
from . import network as _network  # noqa: E402,F401
from . import packages as _packages  # noqa: E402,F401

__all__ = [
    "SemanticAnalysis",
    "analyze_tokens",
    "register",
    "supported_analyzers",
]
