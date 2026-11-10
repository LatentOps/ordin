"""Build all five source-bound base distributions; never publish or install extras."""

import sys

if __name__ == "__main__" and not sys.flags.isolated:
    raise SystemExit(
        "Release tooling requires isolated Python: use python -I -B scripts/"
        + __file__.replace("\\", "/").rsplit("/", 1)[-1]
    )


import argparse
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile


def _helper(filename):
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location("_ordin_release_" + path.stem, path)
    if spec is None:
        raise ValueError("exact release helper is unavailable")
    module = importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes(), str(path), "exec", dont_inherit=True), module.__dict__)
    return module


_SOURCE = _helper("check_swarm_release.py")
_BUNDLE = _helper("release_bundle.py")
copy_build_source, source_identity = _SOURCE.copy_build_source, _SOURCE.source_identity
PROJECTS, _source_projects, create_bundle_metadata = (
    _BUNDLE.PROJECTS,
    _BUNDLE._source_projects,
    _BUNDLE.create_bundle_metadata,
)


def build_bundle(source_root: Path, dist: Path, *, revision: str, tag: str | None = None) -> dict:
    source_root = source_root.resolve(strict=True)
    before, _, _ = _source_projects(source_root, revision, None)
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
                        "-I",
                        "-B",
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
                    env={
                        key: value
                        for key, value in os.environ.items()
                        if not key.upper().startswith(("PYTHON", "_PYPROJECT_HOOKS_", "PEP517_"))
                    },
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
