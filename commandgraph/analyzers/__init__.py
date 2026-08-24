from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from commandgraph.context import ExecutionContext
from commandgraph.packs import is_pack_enabled

from .base import Analyzer, SemanticAnalysis, normalize_invocation


@dataclass(frozen=True)
class AnalyzerRegistration:
    analyzer: Analyzer
    pack: str | None = None


_REGISTRY: dict[str, AnalyzerRegistration] = {}


def register(*executables: str, pack: str | None = None):
    def decorator(analyzer: Analyzer) -> Analyzer:
        for executable in executables:
            _REGISTRY[executable] = AnalyzerRegistration(
                analyzer=analyzer,
                pack=pack,
            )
        return analyzer
    return decorator


def analyze_tokens(
    tokens: Sequence[str],
    context: ExecutionContext | None = None,
) -> SemanticAnalysis | None:
    invocation = normalize_invocation(tokens, context=context)
    if invocation is None:
        return None
    registration = _REGISTRY.get(invocation.executable)
    if registration is None:
        return None
    if registration.pack is not None and not is_pack_enabled(registration.pack):
        return None
    return registration.analyzer(invocation)


def supported_analyzers(*, loaded_only: bool = False) -> tuple[str, ...]:
    names = []
    for executable, registration in _REGISTRY.items():
        if loaded_only and registration.pack is not None:
            if not is_pack_enabled(registration.pack):
                continue
        names.append(executable)
    return tuple(sorted(names))


def analyzer_pack_bindings() -> dict[str, str | None]:
    return {
        executable: registration.pack
        for executable, registration in sorted(_REGISTRY.items())
    }


from . import docker as _docker  # noqa: E402,F401
from . import filesystem as _filesystem  # noqa: E402,F401
from . import git as _git  # noqa: E402,F401
from . import network as _network  # noqa: E402,F401
from . import packages as _packages  # noqa: E402,F401

__all__ = [
    "SemanticAnalysis",
    "analyze_tokens",
    "analyzer_pack_bindings",
    "register",
    "supported_analyzers",
]
