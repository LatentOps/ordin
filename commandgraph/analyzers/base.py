from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Callable, Sequence

from commandgraph.data import load_effect_catalog
from commandgraph.graph import EffectEvidence
from commandgraph.shell import _strip_wrappers


@dataclass(frozen=True)
class Invocation:
    executable: str
    args: tuple[str, ...]
    raw_tokens: tuple[str, ...]


@dataclass(frozen=True)
class SemanticAnalysis:
    command: str
    subcommand: str | None
    flags: tuple[str, ...]
    targets: tuple[str, ...]
    evidence: tuple[EffectEvidence, ...]
    analyzer: str
    notes: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {
            "command": self.command,
            "subcommand": self.subcommand,
            "flags": list(self.flags),
            "targets": list(self.targets),
            "analyzer": self.analyzer,
            "notes": list(self.notes),
            "effects": [
                {
                    "effect": item.effect,
                    "risk": item.risk,
                    "category": item.category,
                    "reason": item.reason,
                    "source": item.source,
                    "resource": item.resource,
                    "safer_next_step": item.safer_next_step,
                }
                for item in self.evidence
            ],
        }


Analyzer = Callable[[Invocation], SemanticAnalysis]


def _basename(token: str) -> str:
    return PurePosixPath(token).name if "/" in token else token


def normalize_invocation(tokens: Sequence[str]) -> Invocation | None:
    remaining = _strip_wrappers(tokens)
    if not remaining:
        return None

    executable = _basename(remaining[0]).lower()
    args = list(remaining[1:])
    if executable in {"python", "python3"} and len(args) >= 2 and args[0] == "-m":
        executable = _basename(args[1]).lower()
        args = args[2:]

    return Invocation(
        executable=executable,
        args=tuple(args),
        raw_tokens=tuple(tokens),
    )


def flag_present(
    args: Sequence[str],
    *names: str,
    short_chars: str = "",
) -> bool:
    wanted = set(names)
    for token in args:
        if token in wanted:
            return True
        if token.startswith("--"):
            key = token.split("=", 1)[0]
            if key in wanted:
                return True
        if (
            short_chars
            and token.startswith("-")
            and not token.startswith("--")
            and len(token) > 1
        ):
            cluster = token[1:]
            if any(char in cluster for char in short_chars):
                return True
    return False


def option_value(
    args: Sequence[str],
    *names: str,
    short_names: Sequence[str] = (),
) -> str | None:
    long_names = set(names)
    shorts = set(short_names)
    for index, token in enumerate(args):
        if token in long_names or token in shorts:
            if index + 1 < len(args):
                return args[index + 1]
            return None
        for name in long_names:
            prefix = f"{name}="
            if token.startswith(prefix):
                return token[len(prefix):]
        for name in shorts:
            if len(name) == 2 and token.startswith(name) and token != name:
                return token[len(name):]
    return None


def evidence(
    effect_name: str,
    source: str,
    resource: str | None = None,
) -> EffectEvidence:
    definition = load_effect_catalog()[effect_name]
    safer = definition.get("safer_next_step")
    return EffectEvidence(
        effect=effect_name,
        risk=definition["risk"],
        category=definition["category"],
        reason=definition["reason"],
        source=source,
        resource=resource,
        safer_next_step=safer if isinstance(safer, str) else None,
    )


def unique_evidence(items: Sequence[EffectEvidence]) -> tuple[EffectEvidence, ...]:
    seen: set[tuple[str, str, str | None]] = set()
    result: list[EffectEvidence] = []
    for item in items:
        key = (item.effect, item.source, item.resource)
        if key not in seen:
            seen.add(key)
            result.append(item)
    return tuple(result)
