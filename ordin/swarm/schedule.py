"""Bounded deterministic topological schedules; a scheduler never grants authority."""

from dataclasses import dataclass
import hashlib
from typing import Iterable

from ordin._runtime_json import digest
from .models import identifier


@dataclass(frozen=True, slots=True)
class ScheduledOperation:
    operation_id: str
    actor: int
    kind: str
    after: tuple[str, ...] = ()

    def __post_init__(self):
        identifier(self.operation_id, "operation_id")
        identifier(self.kind, "operation_kind")
        if (
            type(self.actor) is not int
            or not 0 <= self.actor < 10
            or type(self.after) is not tuple
            or len(self.after) > 32
        ):
            raise ValueError("invalid bounded schedule operation")
        for value in self.after:
            identifier(value, "dependency")


@dataclass(frozen=True, slots=True)
class ScheduleSet:
    schedules: tuple[tuple[ScheduledOperation, ...], ...]
    truncated: bool
    seed: int
    input_digest: str

    @property
    def digest(self):
        return digest(
            {
                "seed": self.seed,
                "input": self.input_digest,
                "schedules": [[v.operation_id for v in row] for row in self.schedules],
                "truncated": self.truncated,
            }
        )


def explore(
    operations: Iterable[ScheduledOperation], *, agents: int, seed: int = 0, limit: int = 128
) -> ScheduleSet:
    if (
        type(agents) is not int
        or not 2 <= agents <= 10
        or type(seed) is not int
        or not 0 <= seed < 2**32
        or type(limit) is not int
        or not 1 <= limit <= 4096
    ):
        raise ValueError("invalid bounded deterministic schedule parameters")
    values = tuple(operations)
    if not 1 <= len(values) <= 128 or any(
        type(v) is not ScheduledOperation or v.actor >= agents for v in values
    ):
        raise ValueError("invalid schedule operation inventory")
    by_id = {v.operation_id: v for v in values}
    if len(by_id) != len(values) or any(
        set(v.after) - set(by_id) or v.operation_id in v.after for v in values
    ):
        raise ValueError("duplicate, self, or unknown schedule dependencies")
    input_digest = digest([(v.operation_id, v.actor, v.kind, v.after) for v in values])
    order = sorted(
        by_id, key=lambda name: hashlib.sha256((str(seed) + ":" + name).encode()).digest()
    )
    schedules: list[tuple[ScheduledOperation, ...]] = []
    stack: list[tuple[tuple[str, ...], frozenset[str]]] = [((), frozenset())]
    truncated = False
    while stack:
        prefix, done = stack.pop()
        if len(done) == len(values):
            if len(schedules) == limit:
                truncated = True
                break
            schedules.append(tuple(by_id[name] for name in prefix))
            continue
        available = [name for name in order if name not in done and set(by_id[name].after) <= done]
        if not available:
            raise ValueError("cyclic schedule dependencies")
        # Reverse push preserves stable seeded order on this explicit DFS stack.
        for name in reversed(available):
            stack.append(((*prefix, name), done | {name}))
        if len(stack) > 16384:
            truncated = True
            break
    if not schedules:
        raise ValueError("schedule exploration produced no complete schedule")
    return ScheduleSet(tuple(schedules), truncated, seed, input_digest)


__all__ = ["ScheduledOperation", "ScheduleSet", "explore"]
