from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from .analyzers import analyze_tokens
from .context import ExecutionContext
from .graph import EffectEvidence, effects_for_tokens
from .shell import split_shell_segments


@dataclass(frozen=True)
class SemanticEvidenceSet:
    """Normalized semantic evidence produced for one command or token sequence."""

    evidence: tuple[EffectEvidence, ...]
    analyzer_matched: bool = False

    @property
    def effects(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(item.effect for item in self.evidence))


def _unique_evidence(items: Sequence[EffectEvidence]) -> tuple[EffectEvidence, ...]:
    seen: set[tuple[str, str, str | None]] = set()
    result: list[EffectEvidence] = []
    for item in items:
        key = (item.effect, item.source, item.resource)
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return tuple(result)


def semantic_evidence_for_tokens(
    tokens: Sequence[str],
    *,
    context: ExecutionContext | None = None,
) -> SemanticEvidenceSet:
    """Resolve one tokenized command through the analyzer-first semantic path.

    Dedicated analyzers remain authoritative when they produce evidence. The
    typed command graph is the deterministic fallback for command families
    without invocation-specific evidence.
    """

    analysis = analyze_tokens(tokens, context=context)
    if analysis is not None and analysis.evidence:
        return SemanticEvidenceSet(
            evidence=_unique_evidence(analysis.evidence),
            analyzer_matched=True,
        )
    return SemanticEvidenceSet(
        evidence=_unique_evidence(tuple(effects_for_tokens(list(tokens)))),
        analyzer_matched=analysis is not None,
    )


def semantic_evidence_for_command(
    command: str,
    *,
    context: ExecutionContext | None = None,
) -> SemanticEvidenceSet:
    """Collect normalized evidence for every top-level executable segment."""

    try:
        segments, _ = split_shell_segments(command)
    except ValueError:
        return SemanticEvidenceSet(evidence=())

    evidence: list[EffectEvidence] = []
    analyzer_matched = False
    for segment in segments:
        resolved = semantic_evidence_for_tokens(segment, context=context)
        evidence.extend(resolved.evidence)
        analyzer_matched = analyzer_matched or resolved.analyzer_matched

    return SemanticEvidenceSet(
        evidence=_unique_evidence(evidence),
        analyzer_matched=analyzer_matched,
    )
