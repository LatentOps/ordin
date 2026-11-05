"""Protected append contract. Concrete durable coordination is a separate backend."""

from dataclasses import dataclass
from threading import RLock
from typing import Protocol

from .events import SwarmEvent


@dataclass(frozen=True, slots=True)
class JournalRecord:
    event: SwarmEvent
    digest: str
    ingest_index: int
    source_role: str


class EventJournal(Protocol):
    """Host-owned storage: append atomically or raise without changing the journal.

    The owner must protect this interface and persistence from agent writes.
    A digest is an integrity/deduplication value, not sender authentication.
    Implementations must preserve order, enforce the supplied expected index,
    reject duplicate/conflicting IDs, and return immutable records.
    """

    def append(self, record: JournalRecord, *, expected_index: int) -> None: ...


class _MemoryEventJournal:
    def __init__(self, limit: int) -> None:
        self._limit = limit
        self._records: list[JournalRecord] = []
        self._ids: set[str] = set()
        self._lock = RLock()

    def append(self, record: JournalRecord, *, expected_index: int) -> None:
        with self._lock:
            if len(self._records) != expected_index or record.ingest_index != expected_index + 1:
                raise ValueError("swarm journal append conflict")
            if len(self._records) >= self._limit:
                raise ValueError("swarm journal capacity reached")
            if record.event.event_id in self._ids:
                raise ValueError("duplicate swarm journal event")
            self._records.append(record)
            self._ids.add(record.event.event_id)
