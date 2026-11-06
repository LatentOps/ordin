"""Build fixed installed-wheel evidence; never publish, deploy or authorize runtime work."""

from __future__ import annotations

import argparse
import email
import hashlib
from importlib import import_module
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
LOCKS = (
    "requirements/dev-baseline.txt",
    "requirements/coordinator-postgres.txt",
    "requirements/swarm-langgraph.txt",
    "requirements/swarm-crewai.txt",
    "requirements/swarm-autogen.txt",
)
GROUPS = ("mcp", "hooks", "coordinator_restart", "multi_host_epochs")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def git_environment():
    inherited = {
        key: value
        for key, value in os.environ.items()
        if key.upper()
        in {
            "PATH",
            "SYSTEMROOT",
            "WINDIR",
            "COMSPEC",
            "PATHEXT",
            "TEMP",
            "TMP",
            "TMPDIR",
            "LANG",
            "LC_ALL",
            "SYSTEMDRIVE",
        }
    }
    return {
        **inherited,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
    }


def git(root, *arguments):
    settings = git_environment()
    completed = subprocess.run(
        [
            "git",
            "--no-pager",
            "--no-optional-locks",
            "-c",
            "core.hooksPath=" + os.devnull,
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.autocrlf=input",
            "-c",
            "diff.external=",
            "-C",
            str(root),
            *arguments,
        ],
        check=False,
        capture_output=True,
        env=settings,
    )
    if completed.returncode:
        raise ValueError("release Git source check failed")
    return completed.stdout


def source_identity(root: Path, revision: str):
    if not re.fullmatch(r"[a-f0-9]{40}", revision):
        raise ValueError("release source must use an exact Git commit")
    current = git(root, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
    if current != revision:
        raise ValueError("release revision differs from the checkout")
    filters = subprocess.run(
        [
            "git",
            "--no-pager",
            "-C",
            str(root),
            "config",
            "--includes",
            "--get-regexp",
            r"^filter\..*\.(clean|smudge|process)$",
        ],
        check=False,
        capture_output=True,
        env=git_environment(),
    )
    if filters.returncode not in {0, 1} or filters.stdout:
        raise ValueError("repository content filters are unsupported by the release collector")
    # Inspect filters before diff: clean/smudge drivers are executable callbacks.
    git(
        root,
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--ignore-submodules=all",
        "--quiet",
        "HEAD",
        "--",
    )
    if git(root, "ls-files", "--others", "--exclude-standard", "-z"):
        raise ValueError("release source includes uncommitted files")
    material = {}
    tracked = set(git(root, "ls-files", "-z").decode().split("\0"))
    for package in (root / "ordin", root / "integrations/swarm/ordin_swarm"):
        for path in package.rglob("*"):
            if path.is_file() and path.suffix != ".pyc" and "__pycache__" not in path.parts:
                if path.is_symlink():
                    raise ValueError("release source has an unowned package link")
                relative = path.relative_to(root).as_posix()
                if relative not in tracked:
                    raise ValueError("unversioned package input cannot enter release artifacts")
                material[relative] = sha(path.read_bytes())
    for name in (*LOCKS, "pyproject.toml", "integrations/swarm/pyproject.toml"):
        material[name] = sha((root / name).read_bytes())
    return {
        "commit": current,
        "tree": git(root, "rev-parse", "HEAD^{tree}").decode().strip(),
        "clean": True,
        "source_bytes_verified": True,
        "git_hooks_executed": False,
        "code_resource_sha256": sha(
            json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
        ),
    }


def validate_build_metadata(root):
    tomllib = import_module("tomllib" if sys.version_info >= (3, 11) else "tomli")
    for package in (root, root / "integrations/swarm"):
        metadata = tomllib.loads((package / "pyproject.toml").read_text())
        if metadata["build-system"]["build-backend"] != "setuptools.build_meta" or metadata[
            "project"
        ].get("dynamic"):
            raise ValueError("release collector requires the declared static setuptools build")
        if any((package / name).exists() for name in ("setup.py", "setup.cfg")):
            raise ValueError("repository build hooks are unsupported by the release collector")
    if tomllib.loads((root / "pyproject.toml").read_text())["project"].get("dependencies", []):
        raise ValueError("the core release gate requires no mandatory external dependency")


def extract_test_fixtures(raw: bytes, destination: Path):
    if len(raw) > 67108864:
        raise ValueError("fixture archive exceeds its bound")
    destination.mkdir(mode=0o700)
    total = count = 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        for member in archive:
            relative = Path(member.name)
            if (
                relative.is_absolute()
                or ".." in relative.parts
                or not relative.parts
                or relative.parts[0] != "tests"
            ):
                raise ValueError("fixture archive contains an unowned path")
            target = destination / relative
            if not target.resolve().is_relative_to(destination.resolve()):
                raise ValueError("fixture archive escaped its owned directory")
            if member.isdir():
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
                continue
            if not member.isfile() or member.size > 2097152:
                raise ValueError("fixture archive contains an unsupported entry")
            count += 1
            total += member.size
            if count > 4096 or total > 67108864:
                raise ValueError("fixture inventory exceeds its bound")
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError("fixture data missing")
            descriptor = os.open(
                target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600
            )
            with stream, os.fdopen(descriptor, "wb") as output:
                output.write(stream.read(member.size + 1))
    return {
        "schema_version": "ordin.swarm_release_fixtures.v1",
        "archive_sha256": sha(raw),
        "files": count,
        "bytes": total,
        "versioned_only": True,
        "source_bytecode_used": False,
    }


def verify_wheels(root, directory):
    records = []
    for name, prefix, package in (
        ("ordin", "ordin-", root / "ordin"),
        ("ordin-swarm", "ordin_swarm-", root / "integrations/swarm/ordin_swarm"),
    ):
        candidates = list(directory.glob(prefix + "*.whl"))
        if len(candidates) != 1:
            raise ValueError("release wheel inventory is ambiguous")
        wheel = candidates[0]
        with zipfile.ZipFile(wheel) as archive:
            expected_files = set()
            for path in package.rglob("*"):
                if not path.is_file() or path.suffix == ".pyc" or "__pycache__" in path.parts:
                    continue
                relative = path.relative_to(package.parent).as_posix()
                expected_files.add(relative)
                if archive.read(relative) != path.read_bytes():
                    raise ValueError("release wheel differs from exact package source/resources")
            packaged_files = {
                path
                for path in archive.namelist()
                if path.startswith(package.name + "/") and not path.endswith("/")
            }
            if packaged_files != expected_files:
                raise ValueError("release wheel contains an unexpected package payload")
            metadata_names = [
                item for item in archive.namelist() if item.endswith(".dist-info/METADATA")
            ]
            if len(metadata_names) != 1:
                raise ValueError("release wheel metadata inventory is invalid")
            metadata = email.message_from_bytes(archive.read(metadata_names[0]))
            requirements = metadata.get_all("Requires-Dist", [])
            from packaging.requirements import Requirement

            mandatory = [
                Requirement(value).name
                for value in requirements
                if Requirement(value).marker is None
                or Requirement(value).marker.evaluate({"extra": ""})
            ]
            if mandatory != ([] if name == "ordin" else ["ordin"]):
                raise ValueError("wheel added an unexpected mandatory runtime dependency")
        records.append(
            {
                "name": name,
                "filename": wheel.name,
                "sha256": sha(wheel.read_bytes()),
                "bytes": wheel.stat().st_size,
                "requires_dist": requirements,
            }
        )
    return records


def write_json(path, value):
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write("\n")


def read_report(path):
    if path.is_symlink() or path.stat().st_size > 8388608:
        raise ValueError("release artifact is not a bounded owned report")
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--owned-fixture", action="store_true", required=True)
    args = parser.parse_args()
    if sys.platform not in {"linux", "win32"}:
        raise ValueError("explicit Linux or Windows release lane required")
    workspace = args.workspace.resolve()
    if workspace.is_relative_to(ROOT):
        raise ValueError("release artifacts must be outside the source checkout")
    source = source_identity(ROOT, args.revision)
    validate_build_metadata(ROOT)
    workspace.mkdir(parents=True, exist_ok=False)
    evidence, wheels, temporary = (workspace / name for name in ("evidence", "wheels", "tmp"))
    for directory in (evidence, wheels, temporary):
        directory.mkdir(mode=0o700)
    fixture_root = workspace / "fixtures"
    fixture_record = extract_test_fixtures(
        git(ROOT, "archive", "--format=tar", args.revision, "--", "tests"), fixture_root
    )
    fixture_record.update(commit=args.revision, tree=source["tree"])
    write_json(evidence / "test-fixtures.json", fixture_record)
    settings = git_environment()
    settings.update(
        {
            key: value
            for key, value in os.environ.items()
            if key.upper()
            in {
                "HTTP_PROXY",
                "HTTPS_PROXY",
                "ALL_PROXY",
                "NO_PROXY",
            }
        }
    )
    settings.update(
        TMPDIR=str(temporary),
        PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",
        PIP_DISABLE_PIP_VERSION_CHECK="1",
        CREWAI_TELEMETRY_DISABLED="true",
        OTEL_SDK_DISABLED="true",
        LANGSMITH_TRACING="false",
    )

    def run(command, *, accepted=(0,), timeout=900):
        completed = subprocess.run(
            command, cwd=workspace, env=settings, capture_output=True, timeout=timeout
        )
        if completed.returncode not in accepted:
            # Private diagnostics are deliberately excluded from the public manifest/artifact directory.
            descriptor = os.open(
                workspace / "private-failure.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
            )
            with os.fdopen(descriptor, "wb") as stream:
                stream.write((completed.stdout + completed.stderr)[-1048576:])
            raise ValueError("fixed release subprocess failed; inspect private owned diagnostics")
        return completed

    run(
        [
            sys.executable,
            "-m",
            "pip",
            "--isolated",
            "wheel",
            "--no-index",
            "--no-deps",
            "--no-build-isolation",
            "--wheel-dir",
            str(wheels),
            str(ROOT),
            str(ROOT / "integrations/swarm"),
        ]
    )
    wheel_records = verify_wheels(ROOT, wheels)
    environment_path = workspace / "env"
    run([sys.executable, "-m", "venv", str(environment_path)])
    python = environment_path / ("Scripts/python.exe" if os.name == "nt" else "bin/python")

    def installed(*arguments, accepted=(0,), timeout=900):
        return run([str(python), "-I", *arguments], accepted=accepted, timeout=timeout)

    def pip(*arguments):
        installed(
            "-m", "pip", "--isolated", "--cache-dir", str(workspace / "pip-cache"), *arguments
        )

    def probe(group):
        output = evidence / (group.replace("_", "-") + ".json")
        installed(
            str(ROOT / "scripts/swarm_release_probe.py"),
            group,
            "--output",
            str(output),
            "--basetemp",
            str(workspace / ("pytest-" + group)),
            "--fixtures-root",
            str(fixture_root),
        )
        return output

    pip("install", "--no-index", "--no-deps", str(wheels / wheel_records[0]["filename"]))
    probe("core_compatibility")
    pip("install", "--no-index", "--no-deps", str(wheels / wheel_records[1]["filename"]))
    quickstart = installed("-m", "ordin_swarm.quickstart")
    write_json(evidence / "quickstart.json", json.loads(quickstart.stdout))
    owned = installed("-m", "ordin_swarm.owned_demo", "--owned-fixture", accepted=(0, 2))
    write_json(evidence / "owned-demo.json", json.loads(owned.stdout))
    probe("environment")
    pip("install", "--require-hashes", "-r", str(ROOT / "requirements/dev-baseline.txt"))
    for group in GROUPS:
        probe(group)
    corpus_args = [
        "-m",
        "ordin.swarm.benchmark_cli",
        "corpus",
        "--revision",
        args.revision,
        "--output",
        str(evidence / "corpus.json"),
    ]
    if sys.platform == "linux":
        corpus_args.append("--kernel")
    installed(*corpus_args)
    if sys.platform == "linux":
        installed(
            "-m",
            "ordin.swarm.benchmark_cli",
            "overhead",
            "--revision",
            args.revision,
            "--samples",
            "32",
            "--long-actions",
            "1024",
            "--output",
            str(evidence / "overhead.json"),
        )
    if source_identity(ROOT, args.revision) != source:
        raise ValueError("release source changed while collecting evidence")
    # Manifest construction and final semantic checks run from the verified wheel,
    # not an import of the checkout or an arbitrary imported evidence manifest.
    inputs = {
        "source": source,
        "wheels": wheel_records,
        "locks": [
            {
                "name": name,
                "sha256": sha((ROOT / name).read_bytes()),
                "pin_format": "pip_require_hashes",
            }
            for name in LOCKS
        ],
        "workflow_hashes": {
            name: sha((ROOT / name).read_bytes())
            for name in (
                ".github/workflows/swarm-frameworks.yml",
                ".github/workflows/coordinator.yml",
                ".github/workflows/runtime-extension.yml",
            )
        },
    }
    write_json(workspace / "collector-inputs.json", inputs)
    installed(
        str(ROOT / "scripts/swarm_release_probe.py"),
        "manifest",
        "--output",
        str(evidence / "release-manifest.json"),
        "--inputs",
        str(workspace / "collector-inputs.json"),
    )
    report = read_report(evidence / "release-manifest.json")
    if not report["local_gate_passed"]:
        raise ValueError("required installed release checks did not pass")
    print("Installed release evidence passed; production/publication authorization remains false.")


if __name__ == "__main__":
    main()
