"""Build all five source-bound base distributions; never publish or install extras."""

from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys
import tempfile

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.check_swarm_release import copy_build_source, source_identity
from scripts.release_bundle import PROJECTS, _source_projects, create_bundle_metadata


def build_bundle(source_root: Path, dist: Path, *, revision: str, tag: str | None = None) -> dict:
    source_root = source_root.resolve(strict=True)
    before, projects, _ = _source_projects(source_root, revision, None)
    # Never reuse a distribution directory containing stale or foreign artifacts.
    dist = dist.absolute()
    if dist.exists() or dist.is_symlink():
        raise ValueError("release builder requires a new artifact directory")
    dist.mkdir(parents=True, mode=0o700)
    with tempfile.TemporaryDirectory(prefix="ordin-release-build-") as name:
        build_source = copy_build_source(source_root, Path(name) / "source")
        for project, (relative, _) in PROJECTS.items():
            with (Path(name) / (project + ".log")).open("wb") as log:
                completed = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "build",
                        "--no-isolation",
                        "--outdir",
                        str(dist),
                        str(build_source / relative),
                    ],
                    cwd=build_source,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    timeout=900,
                )
            if completed.returncode:
                # Bounded diagnostics, while retaining the fresh failed directory for inspection.
                detail = (
                    (Path(name) / (project + ".log"))
                    .read_bytes()[-16384:]
                    .decode("utf-8", "replace")
                )
                raise ValueError(f"release build failed for {project}: {detail}")
    if source_identity(source_root, revision) != before:
        raise ValueError("release source changed during the build")
    return create_bundle_metadata(dist, source_root=source_root, revision=revision, tag=tag)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", required=True, type=Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--tag")
    args = parser.parse_args()
    result = build_bundle(
        Path(__file__).resolve().parents[1], args.dist, revision=args.revision, tag=args.tag
    )
    print(f"Built and verified {len(result['artifacts'])} distributions for {result['revision']}")


if __name__ == "__main__":
    main()
