from __future__ import annotations

import re
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
MARKDOWN_LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


def _markdown_files() -> list[Path]:
    return [
        PROJECT_ROOT / "README.md",
        PROJECT_ROOT / "CONTRIBUTING.md",
        *sorted((PROJECT_ROOT / "docs").glob("*.md")),
    ]


def _local_link_targets(path: Path):
    text = path.read_text(encoding="utf-8")
    for raw_target in MARKDOWN_LINK_RE.findall(text):
        target = raw_target.strip().split("#", 1)[0]
        if not target:
            continue
        if target.startswith(("http://", "https://", "mailto:")):
            continue
        yield target


def test_local_markdown_links_resolve():
    failures: list[str] = []

    for markdown in _markdown_files():
        for target in _local_link_targets(markdown):
            resolved = (markdown.parent / target).resolve()
            if not resolved.exists():
                relative = markdown.relative_to(PROJECT_ROOT)
                failures.append(f"{relative}: missing local link target {target!r}")

    assert failures == []
