from __future__ import annotations

from pathlib import Path


TEXT_SUFFIXES = {".py", ".md", ".toml", ".json", ".jsonl", ".yml", ".yaml", ".txt"}
LEGACY_TOKENS = (
    "command" + "graph",
    "Command" + "Graph",
    "COMMAND" + "GRAPH",
    "cmd" + "graph",
    "command" + "-graph",
)


def repository_root() -> Path:
    return Path(__file__).resolve().parents[1]


def scan_roots(root: Path) -> tuple[Path, ...]:
    return (
        root / "ordin",
        root / "tests",
        root / "data",
        root / "schemas",
        root / "docs",
        root / "examples",
        root / "benchmarks",
        root / "scripts",
        root / "README.md",
        root / "CONTRIBUTING.md",
        root / "NOTICE",
        root / "pyproject.toml",
        root / ".pre-commit-config.yaml",
        root / ".github" / "workflows" / "tests.yml",
        root / ".github" / "workflows" / "release.yml",
    )


def _candidate_files(path: Path):
    if not path.exists():
        return
    if path.is_file():
        yield path
        return
    for candidate in path.rglob("*"):
        if candidate.is_file():
            yield candidate


def legacy_namespace_failures(root: Path | None = None) -> list[str]:
    base = root or repository_root()
    failures: list[str] = []

    for scan_root in scan_roots(base):
        for path in _candidate_files(scan_root):
            if path.suffix.lower() not in TEXT_SUFFIXES and path.name != "NOTICE":
                continue
            text = path.read_text(encoding="utf-8")
            for token in LEGACY_TOKENS:
                if token in text:
                    relative = path.relative_to(base)
                    failures.append(f"{relative}: contains legacy token {token!r}")

    return failures


def main() -> int:
    failures = legacy_namespace_failures()
    if failures:
        print("\n".join(failures))
        return 1
    print("Ordin namespace is clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
