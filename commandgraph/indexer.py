from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from . import MAN_INDEX_SCHEMA_VERSION


DEFAULT_INDEX_PATH = Path.home() / ".cache" / "commandgraph" / "man_index.json"
APROPOS_LINE_RE = re.compile(r"^(?P<names>.+?)\s+\((?P<section>[^)]+)\)\s+-\s+(?P<summary>.+)$")
DEFAULT_SECTIONS = ("1", "8")


@dataclass(frozen=True)
class IndexResult:
    path: Path
    source: str
    entry_count: int
    skipped_count: int

    def as_dict(self) -> dict:
        return {
            "schema_version": MAN_INDEX_SCHEMA_VERSION,
            "path": str(self.path),
            "source": self.source,
            "entry_count": self.entry_count,
            "skipped_count": self.skipped_count,
        }


def parse_command_names(raw_names: str) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    for item in raw_names.split(","):
        name = item.strip().split()[0].strip()
        if not name or "/" in name:
            continue
        normalized = name.lower()
        if normalized not in seen:
            seen.add(normalized)
            names.append(normalized)
    return names


def section_is_allowed(section: str, allowed_sections: Iterable[str]) -> bool:
    normalized = section.strip().lower()
    return any(normalized.startswith(allowed) for allowed in allowed_sections)


def parse_apropos_line(
    line: str,
    allowed_sections: Iterable[str] = DEFAULT_SECTIONS,
) -> list[dict]:
    match = APROPOS_LINE_RE.match(line.strip())
    if not match:
        return []

    section = match.group("section").strip()
    if not section_is_allowed(section, allowed_sections):
        return []

    summary = match.group("summary").strip()
    entries = []
    for name in parse_command_names(match.group("names")):
        entries.append(
            {
                "schema_version": "commandgraph.command_card.v1",
                "command": name,
                "summary": summary,
                "aliases": [],
                "intents": [summary],
                "default_risk": "unknown",
                "risk_tags": ["man_page"],
                "examples": [],
                "templates": [],
                "source": "man_index",
                "man_section": section,
            }
        )
    return entries


def parse_apropos_lines(
    lines: Iterable[str],
    allowed_sections: Iterable[str] = DEFAULT_SECTIONS,
) -> tuple[list[dict], int]:
    entries: list[dict] = []
    skipped = 0
    seen: set[str] = set()

    for line in lines:
        parsed = parse_apropos_line(line, allowed_sections=allowed_sections)
        if not parsed:
            skipped += 1
            continue
        for entry in parsed:
            command = entry["command"]
            if command in seen:
                continue
            seen.add(command)
            entries.append(entry)

    return entries, skipped


def read_apropos_output(source: str, query: str, timeout: float = 15.0) -> list[str]:
    if source == "apropos":
        args = ["apropos", query]
    elif source == "man-k":
        args = ["man", "-k", query]
    else:
        raise ValueError(f"unsupported index source: {source}")

    completed = subprocess.run(
        args,
        capture_output=True,
        check=False,
        text=True,
        timeout=timeout,
    )
    if completed.returncode not in {0, 1}:
        message = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(message or f"{' '.join(args)} failed")
    return completed.stdout.splitlines()


def write_index(entries: list[dict], path: Path, source: str, skipped_count: int) -> IndexResult:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": MAN_INDEX_SCHEMA_VERSION,
        "source": source,
        "entries": entries,
    }
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return IndexResult(
        path=path,
        source=source,
        entry_count=len(entries),
        skipped_count=skipped_count,
    )


def build_index_from_lines(lines: Iterable[str], path: Path, source: str = "file") -> IndexResult:
    entries, skipped = parse_apropos_lines(lines)
    return write_index(entries, path=path, source=source, skipped_count=skipped)


def build_index(
    path: Path = DEFAULT_INDEX_PATH,
    source: str = "apropos",
    query: str = ".",
) -> IndexResult:
    lines = read_apropos_output(source=source, query=query)
    entries, skipped = parse_apropos_lines(lines)
    return write_index(entries, path=path, source=source, skipped_count=skipped)
