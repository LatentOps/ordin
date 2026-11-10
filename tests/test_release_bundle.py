"""Exact five-project bundle contracts and adversarial archive controls."""

import base64
import csv
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import zipfile

import pytest

from scripts.release_bundle import (
    PROJECTS,
    _archive,
    _record,
    create_bundle_metadata,
    verify_bundle,
)
from scripts.release_integrity import create_metadata, verify_metadata


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def wheel(path, files):
    prefix = next(name.rsplit("/", 1)[0] for name in files if name.endswith("/METADATA"))
    files = {name: raw for name, raw in files.items() if name != prefix + "/RECORD"}
    records = io.StringIO()
    writer = csv.writer(records, lineterminator="\n")
    for name, raw in files.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
        writer.writerow([name, "sha256=" + digest, len(raw)])
    writer.writerow([prefix + "/RECORD", "", ""])
    files[prefix + "/RECORD"] = records.getvalue().encode()
    with zipfile.ZipFile(path, "w") as archive:
        for name, raw in files.items():
            archive.writestr(name, raw)


def sdist(path, files):
    with tarfile.open(path, "w:gz") as archive:
        for name, raw in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))


@pytest.fixture
def bundle(tmp_path):
    root, dist = tmp_path / "source", tmp_path / "dist"
    root.mkdir()
    dist.mkdir()
    license_bytes = b"Apache License\nSynthetic owned fixture\n"
    for lock in ("dev-baseline", "coordinator-postgres", "swarm-langgraph", "swarm-autogen"):
        path = root / "requirements" / (lock + ".txt")
        path.parent.mkdir(exist_ok=True)
        path.write_text("# synthetic fixture\n")
    for name, (relative, module) in PROJECTS.items():
        project = root / relative
        project.mkdir(parents=True, exist_ok=True)
        package = project / module
        package.mkdir()
        version = "0.4.0.dev0" if name in {"ordin", "ordin-swarm"} else "0.1.0"
        source = f'__version__ = "{version}"\n'.encode()
        dependencies = [] if name == "ordin" else ["ordin>=0.4.0.dev0,<0.5"]
        metadata = (
            f"Metadata-Version: 2.4\nName: {name}\nVersion: {version}\nRequires-Python: >=3.10\n"
            "License: Apache-2.0\nLicense-File: LICENSE\n"
            + "".join(f"Requires-Dist: {value}\n" for value in dependencies)
            + "\nSynthetic package\n"
        ).encode()
        settings = (
            '[build-system]\nrequires=["setuptools>=68"]\nbuild-backend="setuptools.build_meta"\n'
            f'[project]\nname="{name}"\nversion="{version}"\nrequires-python=">=3.10"\n'
            f'dependencies={json.dumps(dependencies)}\nreadme="README.md"\nlicense={{text="Apache-2.0"}}\n'
            f'[tool.setuptools]\npackages=["{module}"]\n'
        ).encode()
        readme = b"Synthetic package\n"
        source_files = {
            module + "/__init__.py": source,
            "pyproject.toml": settings,
            "README.md": readme,
            "LICENSE": license_bytes,
        }
        for member, raw in source_files.items():
            (project / member).write_bytes(raw)
        normalized = name.replace("-", "_")
        prefix = f"{normalized}-{version}.dist-info/"
        wheel_files = {
            module + "/__init__.py": source,
            prefix + "METADATA": metadata,
            prefix + "WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
            prefix + "top_level.txt": (module + "\n").encode(),
            prefix + "licenses/LICENSE": license_bytes,
        }
        wheel(dist / f"{normalized}-{version}-py3-none-any.whl", wheel_files)
        egg = normalized + ".egg-info/"
        source_files.update(
            {
                "PKG-INFO": metadata,
                "setup.cfg": b"[egg_info]\ntag_build = \ntag_date = 0\n\n",
                egg + "PKG-INFO": metadata,
                egg + "dependency_links.txt": b"\n",
                egg + "top_level.txt": (module + "\n").encode(),
            }
        )
        if dependencies:
            source_files[egg + "requires.txt"] = ("\n".join(dependencies) + "\n").encode()
        source_files[egg + "SOURCES.txt"] = b""
        source_files[egg + "SOURCES.txt"] = (
            "\n".join(sorted(set(source_files) - {"PKG-INFO", "setup.cfg"})) + "\n"
        ).encode()
        sdist(
            dist / f"{normalized}-{version}.tar.gz",
            {f"{normalized}-{version}/{key}": value for key, value in source_files.items()},
        )
    git(root, "init", "-q")
    git(root, "config", "user.name", "Owned Release Fixture")
    git(root, "config", "user.email", "fixture@example.invalid")
    git(root, "add", ".")
    git(
        root,
        "-c",
        "core.hooksPath=" + str(tmp_path / "no-hooks"),
        "commit",
        "-qm",
        "source fixture",
    )
    return root, dist, git(root, "rev-parse", "HEAD")


def test_complete_bundle_binds_five_packages_and_both_formats_to_exact_source(bundle):
    root, dist, revision = bundle
    identity = create_bundle_metadata(dist, source_root=root, revision=revision, tag="candidate")
    assert set(identity["packages"]) == set(PROJECTS) and len(identity["artifacts"]) == 10
    assert identity["tree"] == git(root, "rev-parse", "HEAD^{tree}")
    assert not identity["origin_authenticated_by_json"]
    assert (
        verify_bundle(dist, source_root=root, revision=revision, tree=identity["tree"]) == identity
    )
    sbom = json.loads((dist / "sbom.cdx.json").read_text())
    assert len(sbom["components"]) == len(sbom["dependencies"]) == 5
    for changed in ({"revision": "a" * 40}, {"tree": "a" * 40}, {"tag": "wrong"}):
        with pytest.raises(ValueError):
            verify_bundle(
                dist, source_root=root, revision=changed.pop("revision", revision), **changed
            )


@pytest.mark.parametrize(
    "change", ["source", "dependency", "entrypoint", "license", "record", "foreign"]
)
def test_self_consistently_rehashed_wheel_cannot_change_source_contract(bundle, change):
    root, dist, revision = bundle
    path = next(dist.glob("ordin_runtime-*.whl"))
    files = _archive(path, wheel=True)
    prefix = "ordin_runtime-0.1.0.dist-info/"
    if change == "source":
        files["ordin_runtime/__init__.py"] += b"changed = True\n"
    elif change == "dependency":
        files[prefix + "METADATA"] = files[prefix + "METADATA"].replace(
            b"Requires-Dist: ordin", b"Requires-Dist: foreign"
        )
    elif change == "entrypoint":
        files[prefix + "entry_points.txt"] = b"[console_scripts]\nforeign = foreign:main\n"
    elif change == "license":
        files[prefix + "licenses/LICENSE"] = b"foreign license"
    elif change == "foreign":
        files["foreign.py"] = b"injected = True\n"
    wheel(path, files)
    if change == "record":
        with zipfile.ZipFile(path) as archive:
            files = {name: archive.read(name) for name in archive.namelist()}
        files[prefix + "RECORD"] = b"tampered\n"
        with zipfile.ZipFile(path, "w") as archive:
            for name, raw in files.items():
                archive.writestr(name, raw)
    with pytest.raises(ValueError):
        create_bundle_metadata(dist, source_root=root, revision=revision, tag="candidate")
    assert not (dist / "release.json").exists()


@pytest.mark.parametrize(
    "change",
    [
        "missing_package",
        "foreign_wheel",
        "mixed_sdist",
        "symlink",
        "metadata",
        "sbom",
        "checksum",
        "extra",
    ],
)
def test_bundle_rejects_incomplete_mixed_or_tampered_assets(bundle, change):
    root, dist, revision = bundle
    create_bundle_metadata(dist, source_root=root, revision=revision, tag="candidate")
    if change == "missing_package":
        next(dist.glob("ordin_runtime-*.whl")).unlink()
    elif change == "foreign_wheel":
        (dist / "foreign-1-py3-none-any.whl").write_bytes(b"foreign")
    elif change == "mixed_sdist":
        next(dist.glob("ordin_runtime-*.tar.gz")).write_bytes(
            next(dist.glob("ordin_security-*.tar.gz")).read_bytes()
        )
    elif change == "symlink":
        if not hasattr(Path, "symlink_to"):
            pytest.skip("symlinks unavailable")
        path = dist / "release.json"
        target = root.parent / "outside.json"
        target.write_bytes(path.read_bytes())
        path.unlink()
        try:
            path.symlink_to(target)
        except OSError:
            pytest.skip("host does not permit fixture symlinks")
    elif change in {"metadata", "sbom"}:
        path = dist / ("release.json" if change == "metadata" else "sbom.cdx.json")
        value = json.loads(path.read_text())
        value["foreign"] = True
        path.write_text(json.dumps(value))
    elif change == "checksum":
        (dist / "SHA256SUMS").write_text("a" * 64 + "  release.json\n")
    else:
        (dist / "unexpected.txt").write_text("foreign")
    with pytest.raises((ValueError, OSError, tarfile.TarError, zipfile.BadZipFile)):
        verify_bundle(dist, source_root=root, revision=revision)


def test_archive_traversal_duplicates_and_links_are_rejected(tmp_path):
    path = tmp_path / "archive.whl"
    for name in ("../foreign", "/absolute", "owned/../foreign", "owned\\foreign", "C:/foreign"):
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr(name, b"foreign")
        with pytest.raises(ValueError):
            _archive(path, wheel=True)
    with zipfile.ZipFile(path, "w") as archive:
        item = zipfile.ZipInfo("owned")
        item.external_attr = 0o120777 << 16
        archive.writestr(item, b"outside")
    with pytest.raises(ValueError):
        _archive(path, wheel=True)
    path = tmp_path / "archive.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        item = tarfile.TarInfo("owned/link")
        item.type = tarfile.SYMTYPE
        item.linkname = "outside"
        archive.addfile(item)
    with pytest.raises(ValueError):
        _archive(path, wheel=False)


def test_current_release_cannot_use_the_legacy_core_only_format(tmp_path):
    for operation in (create_metadata, verify_metadata):
        with pytest.raises((ValueError, OSError)):
            operation(tmp_path, version="0.4.0", revision="a" * 40, tag="v0.4.0")
