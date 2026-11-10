"""Build fixed installed-wheel evidence; never publish, deploy or authorize runtime work."""

from __future__ import annotations

import argparse
import email
import hashlib
from importlib import import_module
import io
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import stat
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
LOCKS = (
    "requirements/dev-baseline.txt",
    "requirements/coordinator-postgres.txt",
    "requirements/swarm-langgraph.txt",
    "requirements/swarm-autogen.txt",
)
GROUPS = ("mcp", "hooks", "coordinator_restart", "multi_host_epochs")
MAX_SOURCE_FILES = 4096
MAX_SOURCE_FILE_BYTES = 2097152
MAX_SOURCE_BYTES = 67108864


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
            "HOME",
            "USERPROFILE",
            "HOMEDRIVE",
            "HOMEPATH",
            "APPDATA",
            "LOCALAPPDATA",
        }
    }
    return {
        **inherited,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
    }


def trusted_git(root):
    path = Path(__file__).with_name("_release_tools.py")
    spec = importlib.util.spec_from_file_location("_ordin_release_tools", path)
    if spec is None:
        raise ValueError("exact release tool resolver is unavailable")
    module = importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes(), str(path), "exec", dont_inherit=True), module.__dict__)
    return module.trusted_executable("git", root)


def git(root, *arguments, executable=None, input=None):
    settings = git_environment()
    completed = subprocess.run(
        [
            executable or trusted_git(root),
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
        input=input,
    )
    if completed.returncode:
        raise ValueError("release Git source check failed")
    return completed.stdout


def _committed_source(root: Path, revision: str):
    """Read exact regular blobs, never checkout-converted bytes or replacement objects.

    Cleanliness/currentness is a separate prerequisite supplied by source_identity.
    All declared sizes are bounded before collecting one deduplicated binary batch.
    """
    if re.fullmatch(r"[a-f0-9]{40}", revision) is None:
        raise ValueError("canonical source requires a full trusted commit SHA")
    source_root = root.resolve(strict=True)
    records, objects, total = {}, {}, 0
    listing = git(root, "ls-tree", "-r", "-z", "-l", "--full-tree", revision)
    for entry in listing.split(b"\0"):
        if not entry:
            continue
        header, separator, encoded = entry.partition(b"\t")
        fields = header.split()
        if not separator or len(fields) != 4:
            raise ValueError("canonical source tree entry is malformed")
        mode, kind, oid, size = fields
        if (
            mode not in {b"100644", b"100755"}
            or kind != b"blob"
            or re.fullmatch(rb"[a-f0-9]{40}", oid) is None
            or not size.isdigit()
        ):
            raise ValueError("canonical source requires regular Git blob modes")
        name = encoded.decode("utf-8")
        relative = PurePosixPath(name)
        if (
            relative.is_absolute()
            or relative.as_posix() != name
            or "\\" in name
            or ":" in name
            or any(part in {".", ".."} for part in relative.parts)
            or any(ord(c) < 32 for c in name)
        ):
            raise ValueError("canonical source contains an unowned path")
        size = int(size)
        total += size
        if (
            name in records
            or len(records) >= MAX_SOURCE_FILES
            or size > MAX_SOURCE_FILE_BYTES
            or total > MAX_SOURCE_BYTES
        ):
            raise ValueError("canonical source inventory exceeds its bound")
        path = root / name
        info = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or not path.resolve(strict=True).is_relative_to(source_root)
        ):
            raise ValueError("canonical source worktree contains an unsupported link or file")
        for parent in path.parents:
            if parent == root:
                break
            if parent.is_symlink() or getattr(parent, "is_junction", lambda: False)():
                raise ValueError("canonical source worktree contains a linked directory")
        records[name] = (mode, oid)
        if oid in objects and objects[oid] != size:
            raise ValueError("canonical blob size is inconsistent")
        objects[oid] = size
    if not records:
        raise ValueError("canonical source tree is empty")
    raw = git(root, "cat-file", "--batch", input=b"\n".join(objects) + b"\n")
    maximum = sum(objects.values()) + len(objects) * 128
    if len(raw) > maximum:
        raise ValueError("canonical Git batch exceeds its declared bound")
    contents, offset = {}, 0
    for oid, size in objects.items():
        end = raw.find(b"\n", offset, offset + 128)
        if end < 0 or raw[offset:end] != oid + b" blob " + str(size).encode():
            raise ValueError("canonical Git batch object identity differs")
        offset = end + 1
        data = raw[offset : offset + size]
        offset += size
        if (
            len(data) != size
            or raw[offset : offset + 1] != b"\n"
            or hashlib.sha1(b"blob " + str(size).encode() + b"\0" + data).hexdigest().encode()
            != oid
        ):
            raise ValueError("canonical Git blob bytes do not match the trusted tree OID")
        offset += 1
        contents[oid] = data
    if offset != len(raw):
        raise ValueError("canonical Git batch contains unexpected output")
    return {name: contents[oid] for name, (_, oid) in records.items()}, records


def committed_files(root: Path, revision: str) -> dict[str, bytes]:
    return _committed_source(root, revision)[0]


def source_snapshot(root: Path, revision: str):
    if not re.fullmatch(r"[a-f0-9]{40}", revision):
        raise ValueError("release source must use an exact Git commit")
    executable = trusted_git(root)

    def checked_git(*arguments, **kwargs):
        return git(root, *arguments, executable=executable, **kwargs)

    current = checked_git("rev-parse", "--verify", "HEAD^{commit}").decode().strip()
    if current != revision:
        raise ValueError("release revision differs from the checkout")
    filters = subprocess.run(
        [
            executable,
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
    flags = checked_git("ls-files", "-v", "-z").split(b"\0")
    if any(entry and not entry.startswith(b"H ") for entry in flags):
        raise ValueError("canonical source rejects skipped or assumed-clean index entries")
    # Inspect filters before diff: clean/smudge drivers are executable callbacks.
    checked_git(
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--ignore-submodules=all",
        "--quiet",
        "HEAD",
        "--",
    )
    if checked_git("ls-files", "--others", "--exclude-standard", "-z"):
        raise ValueError("release source includes uncommitted files")
    committed, entries = _committed_source(root, revision)
    index = {}
    for entry in checked_git("ls-files", "--stage", "-z").split(b"\0"):
        if entry:
            header, name = entry.split(b"\t", 1)
            mode, oid, stage = header.split()
            if stage != b"0":
                raise ValueError("canonical source rejects unmerged index entries")
            index[name.decode("utf-8")] = (mode, oid)
    expected = {
        name: hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest().encode()
        for name, raw in committed.items()
    }
    if index != entries:
        raise ValueError("source index differs from the trusted committed tree")
    # Git's declared clean conversion may map a CRLF checkout to its LF blob.
    # Binary/-text inputs keep their exact bytes. External clean drivers were
    # rejected above, and no objects are written by this hash-only operation.
    names = list(committed)
    worktree = checked_git(
        "hash-object", "--stdin-paths", input=("\n".join(names) + "\n").encode()
    ).splitlines()
    if worktree != [expected[name] for name in names]:
        raise ValueError("worktree bytes differ from their trusted canonical Git blobs")
    material = {}
    tracked = set(committed)
    for package in (root / "ordin", root / "integrations/swarm/ordin_swarm"):
        for path in package.rglob("*"):
            if path.is_file() and path.suffix != ".pyc" and "__pycache__" not in path.parts:
                if path.is_symlink():
                    raise ValueError("release source has an unowned package link")
                relative = path.relative_to(root).as_posix()
                if relative not in tracked:
                    raise ValueError("unversioned package input cannot enter release artifacts")
                material[relative] = sha(committed[relative])
    for name in (*LOCKS, "pyproject.toml", "integrations/swarm/pyproject.toml"):
        material[name] = sha(committed[name])
    identity = {
        "commit": current,
        "tree": checked_git("rev-parse", revision + "^{tree}").decode().strip(),
        "clean": True,
        "source_bytes_verified": True,
        "git_hooks_executed": False,
        "code_resource_sha256": sha(
            json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
        ),
    }
    if checked_git("rev-parse", "--verify", "HEAD^{commit}").decode().strip() != revision:
        raise ValueError("source HEAD changed during canonical capture")
    return identity, committed, entries


def source_identity(root: Path, revision: str):
    return source_snapshot(root, revision)[0]


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


def copy_build_source(root: Path, destination: Path):
    """Stage canonical committed bytes, excluding ignored outputs and checkout EOL."""
    destination.mkdir(mode=0o700)
    revision = git(root, "rev-parse", "HEAD").decode().strip()
    before, committed, entries = source_snapshot(root, revision)
    for name, raw in committed.items():
        relative = Path(name)
        target = destination / relative
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(raw)
        target.chmod(0o755 if entries[name][0] == b"100755" else 0o644)
    if source_identity(root, revision) != before:
        raise ValueError("canonical source changed during build staging")
    return destination


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
    revision = git(root, "rev-parse", "HEAD").decode().strip()
    _, committed, _ = source_snapshot(root, revision)
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
            members = archive.namelist()
            if len(members) != len(set(members)):
                raise ValueError("release wheel contains duplicate archive entries")
            metadata_names = [item for item in members if item.endswith(".dist-info/METADATA")]
            if len(metadata_names) != 1:
                raise ValueError("release wheel metadata inventory is invalid")
            metadata_prefix = metadata_names[0].split("/", 1)[0] + "/"
            if not re.fullmatch(
                re.escape(package.name) + r"-[A-Za-z0-9_.!+]+\.dist-info/", metadata_prefix
            ):
                raise ValueError("release wheel metadata belongs to a different distribution")
            if any(
                "\\" in item
                or ".." in item.split("/")
                or not item.startswith((package.name + "/", metadata_prefix))
                for item in members
            ):
                raise ValueError("release wheel contains an unexpected top-level payload")
            expected_files = set()
            package_prefix = package.relative_to(root).as_posix() + "/"
            for selected, raw in committed.items():
                if not selected.startswith(package_prefix):
                    continue
                relative = package.name + "/" + selected[len(package_prefix) :]
                expected_files.add(relative)
                if archive.read(relative) != raw:
                    raise ValueError("release wheel differs from exact package source/resources")
            packaged_files = {
                path
                for path in archive.namelist()
                if path.startswith(package.name + "/") and not path.endswith("/")
            }
            if packaged_files != expected_files:
                raise ValueError("release wheel contains an unexpected package payload")
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
    build_source = copy_build_source(ROOT, workspace / "build-source")
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
            str(build_source),
            str(build_source / "integrations/swarm"),
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
