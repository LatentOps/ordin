"""Bounded directory prefilter for one search; stdlib which makes the decision.

No executable result is cached. Unknown/large/inaccessible directories retain
the original probing behavior, and indexed membership is rechecked at return.
"""

from __future__ import annotations

from functools import wraps
from bisect import bisect_left
import os
import shutil
import sys
from typing import Callable, TypeVar

from ._catalog_snapshot import CatalogChanged

MAX_DIRECTORIES = 128
MAX_DIRECTORY_ENTRIES = 1024


def _environment():
    return (
        os.environ.get("PATH"),
        os.environ.get("PATHEXT"),
        os.environ.get("NoDefaultCurrentDirectoryInExePath"),
        os.getcwd(),
        sys.platform,
    )


def _names(directory):
    if directory.startswith(("\\\\", "//")):
        # Preserve original which probing for remote/device namespaces; the
        # ranking optimization must not enumerate a network share.
        return None
    try:
        names = set()
        with os.scandir(directory) as entries:
            for index, entry in enumerate(entries):
                if index >= MAX_DIRECTORY_ENTRIES:
                    return None
                # A conservative superset also supports case-sensitive Windows
                # directories. Stdlib which still verifies each real candidate.
                names.add(entry.name)
        return frozenset(names)
    except OSError:
        return None


class _Lookup:
    def __init__(self):
        self.environment = _environment()
        self.resolver = shutil.which
        path = self.environment[0]
        directories = () if not path else tuple(path.split(os.pathsep))
        self.directories = (
            directories if 0 < len(directories) <= MAX_DIRECTORIES and all(directories) else ()
        )
        self.index: dict[str, frozenset[str] | None] = {}
        self.folded: dict[str, tuple[str, ...]] = {}

    def which(self, command):
        if not self.directories or os.path.dirname(command):
            return self.resolver(command)
        prefix = command.casefold()
        selected = []
        for directory in self.directories:
            if directory not in self.index:
                self.index[directory] = _names(directory)
                names = self.index[directory]
                if names is not None:
                    self.folded[directory] = tuple(sorted(name.casefold() for name in names))
            names = self.index[directory]
            folded = self.folded.get(directory, ())
            position = bisect_left(folded, prefix)
            possible = position < len(folded) and folded[position].startswith(prefix)
            if names is None or possible:
                selected.append(directory)
        # Keep one original nonempty directory when there are no candidates:
        # passing an empty PATH would change stdlib's Windows cwd semantics.
        path = os.pathsep.join(selected or self.directories[:1])
        return self.resolver(command, path=path)

    def verify(self):
        if self.environment != _environment() or shutil.which is not self.resolver:
            raise CatalogChanged()
        for directory, names in self.index.items():
            if names is not None and _names(directory) != names:
                raise CatalogChanged()

    def close(self):
        self.index.clear()
        self.folded.clear()
        self.directories = ()
        self.environment = ()


F = TypeVar("F", bound=Callable)


def batch_path_lookup(function: F) -> F:
    @wraps(function)
    def call(*args, **kwargs):
        if kwargs.get("which") is not None:
            return function(*args, **kwargs)
        lookup = _Lookup()
        try:
            result = function(*args, **{**kwargs, "which": lookup.which})
            lookup.verify()
            return result
        finally:
            lookup.close()

    return call  # type: ignore[return-value]
