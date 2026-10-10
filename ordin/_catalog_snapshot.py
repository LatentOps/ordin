"""Fresh, bounded catalog reuse within one synchronous review only.

Every retained byte stream, directory selection, loader root and catalog-setting
is checked again before a result leaves the outer review. Nothing survives it.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from functools import wraps
import json
import os
import sys
from pathlib import Path
import threading
from typing import Any, Callable, Iterator, TypeVar

MAX_FILES = 256
MAX_BYTES = 4 * 1024 * 1024
MAX_FILE_BYTES = 512 * 1024


class CatalogChanged(ValueError):
    def __init__(self):
        super().__init__(
            "catalog configuration changed during review; retry with fresh configuration"
        )


def _directory(path: Path, kind: str) -> tuple[Path, ...]:
    if kind == "directories":
        if not path.exists():
            return ()
        return tuple(sorted(child for child in path.iterdir() if child.is_dir()))
    return tuple(sorted(path.glob("*.json")))


def _same_bytes(path, raw):
    with path.open("rb") as handle:
        return handle.read(len(raw) + 1) == raw


def _owner():
    # A running asyncio task necessarily has its module loaded. Avoid importing
    # an event-loop implementation (including Windows Popen subclasses) during
    # ordinary no-provider imports/reviews.
    module = sys.modules.get("asyncio")
    current_task = getattr(module, "current_task", None)
    if current_task is None:
        return threading.get_ident(), None
    try:
        task = current_task()
    except RuntimeError:
        task = None
    return threading.get_ident(), task


@dataclass
class _Snapshot:
    owner: tuple = field(default_factory=_owner)
    active: bool = True
    environment: tuple = field(
        default_factory=lambda: (
            os.environ.get("ORDIN_PACKS"),
            os.environ.get("ORDIN_INDEX"),
            os.getcwd(),
        )
    )
    files: dict[Path, bytes] = field(default_factory=dict)
    directories: dict[tuple[Path, str], tuple[Path, ...]] = field(default_factory=dict)
    anchors: dict[Callable, Any] = field(default_factory=dict)
    existence: dict[Path, bool] = field(default_factory=dict)
    byte_count: int = 0

    def anchor(self, getter):
        if getter is None:
            return
        value = getter()
        if getter in self.anchors and self.anchors[getter] != value:
            raise CatalogChanged()
        self.anchors[getter] = value

    def verify(self):
        if self.environment != (
            os.environ.get("ORDIN_PACKS"),
            os.environ.get("ORDIN_INDEX"),
            os.getcwd(),
        ) or any(getter() != value for getter, value in self.anchors.items()):
            raise CatalogChanged()
        try:
            if any(not _same_bytes(path, raw) for path, raw in self.files.items()):
                raise CatalogChanged()
            if any(
                _directory(path, kind) != saved for (path, kind), saved in self.directories.items()
            ):
                raise CatalogChanged()
            if any(path.exists() != saved for path, saved in self.existence.items()):
                raise CatalogChanged()
        except OSError:
            raise CatalogChanged() from None

    def close(self):
        self.active = False
        self.owner = (None, None)
        self.files.clear()
        self.directories.clear()
        self.anchors.clear()
        self.existence.clear()
        self.byte_count = 0


_CURRENT: ContextVar[_Snapshot | None] = ContextVar("ordin_catalog_snapshot", default=None)
_BYPASS: ContextVar[bool] = ContextVar("ordin_catalog_snapshot_bypass", default=False)


def _current():
    value = _CURRENT.get()
    return (
        value
        if not _BYPASS.get() and value is not None and value.active and value.owner == _owner()
        else None
    )


@contextmanager
def catalog_snapshot(*, enabled=True) -> Iterator[None]:
    if not enabled:
        disabled = _BYPASS.set(True)
        try:
            yield
        finally:
            _BYPASS.reset(disabled)
        return
    if _BYPASS.get() or _current() is not None:
        yield
        return
    state = _Snapshot()
    token = _CURRENT.set(state)
    try:
        yield
        state.verify()
    finally:
        state.close()
        _CURRENT.reset(token)


F = TypeVar("F", bound=Callable)


def snapshot_review(function: F) -> F:
    @wraps(function)
    def call(*args, **kwargs):
        with catalog_snapshot():
            return function(*args, **kwargs)

    return call  # type: ignore[return-value]


def read_catalog_json(path: Path, *, anchor=None):
    state = _current()
    if state is None:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    state.anchor(anchor)
    selected = path if path.is_absolute() else path.absolute()
    saved = state.files.get(selected)
    if saved is not None:
        return json.loads(saved.decode("utf-8"))
    raw = path.read_bytes()
    value = json.loads(raw.decode("utf-8"))
    if (
        len(state.files) < MAX_FILES
        and len(raw) <= MAX_FILE_BYTES
        and state.byte_count + len(raw) <= MAX_BYTES
    ):
        state.files[selected] = raw
        state.byte_count += len(raw)
        return value
    # Oversized/extra catalogs preserve the original fresh-read behavior.
    return value


def catalog_paths(path: Path, kind: str, *, anchor=None):
    state = _current()
    if state is None:
        return _directory(path, kind)
    state.anchor(anchor)
    key = (path if path.is_absolute() else path.absolute(), kind)
    if key not in state.directories:
        values = _directory(*key)
        if len(values) > MAX_FILES or len(state.directories) >= MAX_FILES:
            return values
        state.directories[key] = values
    return state.directories[key]


def catalog_exists(path: Path):
    state = _current()
    if state is None:
        return path.exists()
    selected = path if path.is_absolute() else path.absolute()
    if selected not in state.existence:
        exists = path.exists()
        if len(state.existence) >= MAX_FILES:
            return exists
        state.existence[selected] = exists
    return state.existence[selected]
