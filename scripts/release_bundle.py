"""Closed five-project release bundle validation; JSON never authenticates its producer."""

from __future__ import annotations

import base64
import ast
import configparser
import csv
import hashlib
import importlib
import importlib.metadata
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import zipfile
from email.parser import BytesParser
from typing import Any

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

from scripts.check_swarm_release import git, source_identity


PROJECTS = {
    "ordin": (".", "ordin"),
    "ordin-swarm": ("integrations/swarm", "ordin_swarm"),
    "ordin-runtime": ("integrations/runtime", "ordin_runtime"),
    "ordin-security": ("integrations/security", "ordin_security"),
    "ordin-decision-models": ("integrations/decision_models", "ordin_decision_models"),
}
SCHEMA = "ordin.release.v2"
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_MEMBER_BYTES = 8 * 1024 * 1024
MAX_MEMBERS = 8192


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file(path: Path, limit: int = MAX_ARCHIVE_BYTES) -> bytes:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
        raise ValueError("release input must be a bounded singly-linked regular file")
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    after = path.lstat()
    fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    if len(raw) > limit or any(getattr(after, key) != getattr(info, key) for key in fields):
        raise ValueError("release input changed or exceeded its bound")
    return raw


def _json(path: Path) -> Any:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate release JSON field")
            result[key] = value
        return result

    try:
        return json.loads(
            _file(path, MAX_MEMBER_BYTES),
            object_pairs_hook=unique,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError("nonfinite JSON")),
        )
    except (RecursionError, UnicodeError) as exc:
        raise ValueError("invalid release JSON") from exc


def _path(name: str) -> str:
    path = PurePosixPath(name)
    if (
        not name
        or len(name.encode("utf-8")) > 1024
        or "\\" in name
        or ":" in name
        or any(ord(c) < 32 for c in name)
        or path.is_absolute()
        or path.as_posix() != name.removesuffix("/")
        or any(part in {"", ".", ".."} for part in name.rstrip("/").split("/"))
    ):
        raise ValueError("unowned release archive path")
    return path.as_posix()


def _archive(path: Path, *, wheel: bool, roots: tuple[str, ...] | None = None) -> dict[str, bytes]:
    raw = _file(path)
    result: dict[str, bytes] = {}
    seen: set[str] = set()
    total = 0

    def add(name, size, regular, directory, stream):
        nonlocal total
        name = _path(name)
        if roots is not None and name.split("/", 1)[0] not in roots:
            raise ValueError("release archive contains an unowned top-level directory")
        if name in seen or len(seen) >= MAX_MEMBERS:
            raise ValueError("duplicate or excessive release archive entries")
        seen.add(name)
        if directory:
            return
        total += size
        if not regular or size > MAX_MEMBER_BYTES or total > MAX_ARCHIVE_BYTES:
            raise ValueError("unsupported release archive member type or size")
        data = stream.read(size + 1)
        if len(data) != size:
            raise ValueError("release archive member size mismatch")
        result[name] = data

    if wheel:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            for item in archive.infolist():
                if item.orig_filename != item.filename:
                    raise ValueError("wheel archive filename was normalized or NUL-truncated")
                mode = item.external_attr >> 16
                kind = stat.S_IFMT(mode)
                if (
                    item.flag_bits & 1
                    or kind not in {0, stat.S_IFREG, stat.S_IFDIR}
                    or (kind == stat.S_IFDIR and not item.is_dir())
                    or (kind == stat.S_IFREG and item.is_dir())
                ):
                    raise ValueError("unsupported encrypted or linked wheel member")
                with archive.open(item) as stream:
                    add(item.filename, item.file_size, not item.is_dir(), item.is_dir(), stream)
    else:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
            for item in archive:
                if item.isdir():
                    add(item.name, 0, False, True, None)
                elif item.isfile():
                    with archive.extractfile(item) as stream:
                        add(item.name, item.size, True, False, stream)
                else:
                    raise ValueError("source distribution contains a link or special entry")
    return result


def _requirements(project: dict) -> list[str]:
    values = list(project.get("dependencies", []))
    for extra, requirements in project.get("optional-dependencies", {}).items():
        for raw in requirements:
            requirement = Requirement(raw)
            if requirement.marker is not None:
                raw = raw.split(";", 1)[0] + f'; ({requirement.marker}) and extra == "{extra}"'
            else:
                raw += f'; extra == "{extra}"'
            values.append(raw)
    return sorted(str(Requirement(value)) for value in values)


def _metadata(raw: bytes, project: dict) -> list[str]:
    metadata = BytesParser().parsebytes(raw)
    for key, expected in (
        ("Name", project["name"]),
        ("Version", project["version"]),
        ("Requires-Python", project["requires-python"]),
    ):
        if metadata.get_all(key) != [expected]:
            raise ValueError("release distribution metadata identity mismatch")
    requirements = sorted(
        str(Requirement(value)) for value in metadata.get_all("Requires-Dist", [])
    )
    if requirements != _requirements(project):
        raise ValueError("release distribution dependency metadata differs from source")
    if metadata.get_all("Provides-Extra", []) != list(project.get("optional-dependencies", {})):
        # Order is not semantic, but duplicates and foreign extras are invalid.
        extras = metadata.get_all("Provides-Extra", [])
        if sorted(extras) != sorted(project.get("optional-dependencies", {})):
            raise ValueError("release distribution extras differ from source")
    if metadata.get("License-Expression", metadata.get("License", "")).strip() != "Apache-2.0":
        raise ValueError("release distribution Apache license metadata is missing")
    return requirements


def _entrypoints(raw: bytes | None, project: dict) -> dict[str, dict[str, str]]:
    expected = {}
    for source, group in (("scripts", "console_scripts"), ("gui-scripts", "gui_scripts")):
        if project.get(source):
            expected[group] = dict(project[source])
    expected.update(project.get("entry-points", {}))
    parsed = configparser.ConfigParser(interpolation=None, strict=True)
    parsed.optionxform = str
    if raw is not None:
        parsed.read_string(raw.decode("utf-8"))
    actual = {section: dict(parsed[section]) for section in parsed.sections()}
    if actual != expected:
        raise ValueError("release entrypoints differ from source")
    return actual


def _sdist_requirements(raw: bytes, project: dict) -> None:
    extra = marker = ""
    values = []
    for line in raw.decode("utf-8").splitlines():
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            extra, _, marker = line[1:-1].partition(":")
            continue
        requirement = Requirement(line)
        conditions = ([marker] if marker else []) + (
            [str(requirement.marker)] if requirement.marker else []
        )
        if extra:
            conditions.append(f'extra == "{extra}"')
        base = line.split(";", 1)[0]
        if conditions:
            base += "; " + " and ".join(conditions)
        values.append(str(Requirement(base)))
    if sorted(values) != _requirements(project):
        raise ValueError("source distribution egg-info dependencies differ from source")


def _record(files: dict[str, bytes], prefix: str) -> None:
    name = prefix + "/RECORD"
    if name not in files:
        raise ValueError("wheel RECORD is missing")
    records = {}
    for row in csv.reader(io.StringIO(files[name].decode("utf-8"))):
        if len(row) != 3 or row[0] in records:
            raise ValueError("invalid or duplicate wheel RECORD entry")
        records[row[0]] = row[1:]
    if set(records) != set(files) or records[name] != ["", ""]:
        raise ValueError("wheel RECORD inventory is incomplete")
    for member, raw in files.items():
        if member == name:
            continue
        value = base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
        if records[member] != ["sha256=" + value, str(len(raw))]:
            raise ValueError("wheel RECORD digest or size mismatch")


def _source_projects(root: Path, revision: str, tree: str | None):
    source = source_identity(root, revision)
    if tree is not None and source["tree"] != tree:
        raise ValueError("bundle source tree differs from trusted expected tree")
    tomllib = importlib.import_module("tomllib" if os.sys.version_info >= (3, 11) else "tomli")
    tracked = set(git(root, "ls-files", "-z").decode().split("\0")) - {""}
    projects = {}
    for name, (relative, module) in PROJECTS.items():
        directory = root / relative
        settings = tomllib.loads(_file(directory / "pyproject.toml").decode("utf-8"))
        project = settings["project"]
        build_requirements = [Requirement(value) for value in settings["build-system"]["requires"]]
        setuptools = settings.get("tool", {}).get("setuptools", {})
        if (
            settings["build-system"]["build-backend"] != "setuptools.build_meta"
            or set(settings["build-system"]) != {"requires", "build-backend"}
            or len(build_requirements) != 1
            or canonicalize_name(build_requirements[0].name) != "setuptools"
            or build_requirements[0].url
            or build_requirements[0].marker
            or set(setuptools) - {"packages", "package-data"}
            or project.get("dynamic")
            or project["name"] != name
            or any((directory / item).exists() for item in ("setup.py", "setup.cfg"))
        ):
            raise ValueError("bundle requires the closed static setuptools projects")
        packages = setuptools.get("packages")
        if isinstance(packages, list):
            if not packages or any(
                value != module and not value.startswith(module + ".") for value in packages
            ):
                raise ValueError("bundle package declaration escapes its owned module")
        elif packages != {"find": {"include": [module + "*"], "namespaces": False}}:
            raise ValueError("unsupported bundle package discovery")
        if any(key != module for key in setuptools.get("package-data", {})):
            raise ValueError("bundle package data escapes its owned module")
        for shadow in ("setuptools.py", "build.py", "setuptools/__init__.py", "build/__init__.py"):
            if (directory / shadow).relative_to(root).as_posix() in tracked:
                raise ValueError("tracked release backend shadowing is unsupported")
        version = project["version"]
        if (
            str(Version(version)) != version
            or re.fullmatch(r"\d+\.\d+\.\d+(?:\.dev\d+)?", version) is None
        ):
            raise ValueError("unsupported bundle version")
        mandatory = [Requirement(value) for value in project.get("dependencies", [])]
        if (name == "ordin" and mandatory) or (
            name != "ordin"
            and (len(mandatory) != 1 or canonicalize_name(mandatory[0].name) != "ordin")
        ):
            raise ValueError("bundle base projects require only the bundled core")
        payload = {}
        for path in (directory / module).rglob("*"):
            if path.is_dir() or path.suffix == ".pyc" or "__pycache__" in path.parts:
                continue
            if path.relative_to(root).as_posix() not in tracked:
                raise ValueError("untracked package input cannot enter a bundle")
            payload[path.relative_to(directory).as_posix()] = _file(path, MAX_MEMBER_BYTES)
        initial = payload.get(module + "/__init__.py")
        if initial is None:
            raise ValueError("bundle package initializer is missing")
        versions = [
            ast.literal_eval(node.value)
            for node in ast.parse(initial).body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "__version__"
                for target in node.targets
            )
        ]
        if (name == "ordin" and versions != [version]) or (versions and versions != [version]):
            raise ValueError("source runtime version differs from package metadata")
        license_bytes = _file(directory / "LICENSE", MAX_MEMBER_BYTES)
        if (
            license_bytes != _file(root / "LICENSE", MAX_MEMBER_BYTES)
            or b"Apache License" not in license_bytes
        ):
            raise ValueError("bundle package license differs from owned Apache license")
        projects[name] = (directory, project, payload)
    core_version = projects["ordin"][1]["version"]
    if projects["ordin-swarm"][1]["version"] != core_version:
        raise ValueError("core and swarm bundle versions must agree")
    for name, (_, project, _) in projects.items():
        if name != "ordin":
            requirement = Requirement(project["dependencies"][0])
            if (
                requirement.marker is not None
                or requirement.url
                or not requirement.specifier.contains(core_version, prereleases=True)
            ):
                raise ValueError("bundle dependency does not admit its exact bundled core")
    return source, projects, tracked


def _validate_assets(dist: Path, root: Path, revision: str, tree: str | None = None):
    source, projects, tracked = _source_projects(root, revision, tree)
    records = {}
    assets = {}
    for name, (directory, project, payload) in projects.items():
        normalized, version = name.replace("-", "_"), project["version"]
        wheel = f"{normalized}-{version}-py3-none-any.whl"
        sdist = f"{normalized}-{version}.tar.gz"
        prefix = f"{normalized}-{version}.dist-info"
        module = PROJECTS[name][1]
        files = _archive(dist / wheel, wheel=True, roots=(module, prefix))
        packaged = {key: raw for key, raw in files.items() if not key.startswith(prefix + "/")}
        if packaged != payload:
            raise ValueError("bundle wheel payload differs from exact source/resources")
        allowed = {"METADATA", "WHEEL", "RECORD", "entry_points.txt", "top_level.txt"}
        licenses = {"LICENSE": _file(directory / "LICENSE")}
        if (directory / "NOTICE").exists():
            licenses["NOTICE"] = _file(directory / "NOTICE")
        allowed |= {"licenses/" + key for key in licenses}
        if any(
            key[len(prefix) + 1 :] not in allowed for key in files if key.startswith(prefix + "/")
        ):
            raise ValueError("bundle wheel contains unexpected generated metadata")
        for filename, raw in licenses.items():
            if files.get(prefix + "/licenses/" + filename) != raw:
                raise ValueError("bundle wheel license/notice payload differs from source")
        requirements = _metadata(files.get(prefix + "/METADATA", b""), project)
        entrypoints = _entrypoints(files.get(prefix + "/entry_points.txt"), project)
        if files.get(prefix + "/top_level.txt", b"").decode().splitlines() != [module]:
            raise ValueError("wheel top-level package metadata differs from source")
        parsed_metadata = BytesParser().parsebytes(files[prefix + "/METADATA"])
        if (
            parsed_metadata.get_payload().replace("\r\n", "\n").strip()
            != _file(directory / project["readme"]).decode("utf-8").replace("\r\n", "\n").strip()
        ):
            raise ValueError("wheel description differs from tracked README")
        if sorted(parsed_metadata.get_all("License-File", [])) != sorted(licenses):
            raise ValueError("wheel license metadata inventory differs from source")
        wheel_metadata = BytesParser().parsebytes(files.get(prefix + "/WHEEL", b""))
        if (
            wheel_metadata.get_all("Tag") != ["py3-none-any"]
            or wheel_metadata.get("Root-Is-Purelib") != "true"
        ):
            raise ValueError("bundle requires universal pure-Python wheels")
        _record(files, prefix)
        stem = f"{normalized}-{version}/"
        source_files = _archive(dist / sdist, wheel=False, roots=(stem.rstrip("/"),))
        if any(not key.startswith(stem) for key in source_files):
            raise ValueError("source distribution has a foreign root")
        source_files = {key[len(stem) :]: raw for key, raw in source_files.items()}
        egg = normalized + ".egg-info/"
        _metadata(source_files.get("PKG-INFO", b""), project)
        if source_files.get(egg + "PKG-INFO") != source_files.get("PKG-INFO"):
            raise ValueError("source distribution generated metadata disagrees")
        _entrypoints(source_files.get(egg + "entry_points.txt"), project)
        _sdist_requirements(source_files.get(egg + "requires.txt", b""), project)
        if (
            source_files.get(egg + "top_level.txt", b"").decode().splitlines() != [module]
            or source_files.get(egg + "dependency_links.txt") != b"\n"
        ):
            raise ValueError("source distribution has unexpected package/link metadata")
        required = {**payload, **licenses, "pyproject.toml": _file(directory / "pyproject.toml")}
        readme = project.get("readme")
        if not isinstance(readme, str):
            raise ValueError("bundle projects require their tracked README")
        required[readme] = _file(directory / readme)
        if any(source_files.get(key) != raw for key, raw in required.items()):
            raise ValueError("source distribution omits or changes exact package source/license")
        generated = {
            "PKG-INFO",
            "setup.cfg",
            egg + "PKG-INFO",
            egg + "SOURCES.txt",
            egg + "dependency_links.txt",
            egg + "entry_points.txt",
            egg + "requires.txt",
            egg + "top_level.txt",
        }
        for key, raw in source_files.items():
            if key in generated:
                continue
            selected = directory / key
            if selected.relative_to(root).as_posix() not in tracked or _file(selected) != raw:
                raise ValueError("source distribution contains foreign or changed source")
        if (
            source_files.get("setup.cfg", b"").replace(b"\r\n", b"\n")
            != b"[egg_info]\ntag_build = \ntag_date = 0\n\n"
        ):
            raise ValueError("source distribution has unexpected generated build configuration")
        source_list = source_files.get(egg + "SOURCES.txt", b"").decode().splitlines()
        expected_list = set(source_files) - {"PKG-INFO", "setup.cfg"}
        if len(source_list) != len(set(source_list)) or set(source_list) != expected_list:
            raise ValueError("source distribution source inventory differs from its manifest")
        for filename in (wheel, sdist):
            assets[filename] = _hash(_file(dist / filename))
        records[name] = {
            "version": version,
            "wheel": wheel,
            "sdist": sdist,
            "requires_python": project["requires-python"],
            "requires_dist": requirements,
            "entry_points": entrypoints,
            "payload_sha256": {key: _hash(raw) for key, raw in sorted(payload.items())},
        }
    if set(path.name for path in dist.glob("*.whl")) | set(
        path.name for path in dist.glob("*.tar.gz")
    ) != set(assets):
        raise ValueError("bundle must contain exactly the five expected wheel/sdist pairs")
    return source, records, assets


def _sbom(identity: dict) -> dict:
    components = []
    for name, package in sorted(identity["packages"].items()):
        components.append(
            {
                "type": "library",
                "name": name,
                "version": package["version"],
                "bom-ref": name,
                "purl": f"pkg:pypi/{name}@{package['version']}",
                "scope": "required" if name in {"ordin", "ordin-swarm"} else "optional",
                "licenses": [{"license": {"id": "Apache-2.0"}}],
                "hashes": [{"alg": "SHA-256", "content": identity["artifacts"][package["wheel"]]}],
                "properties": [
                    {"name": "ordin:requires-dist", "value": value}
                    for value in package["requires_dist"]
                ],
            }
        )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "ordin-release-bundle",
                "version": identity["version"],
            },
            "properties": [
                {"name": "ordin:source-commit", "value": identity["revision"]},
                {"name": "ordin:source-tree", "value": identity["tree"]},
                {
                    "name": "ordin:scope",
                    "value": "Five bundled base distributions; framework/model/solver extras and native runtime executables are not bundled.",
                },
            ],
        },
        "components": components,
        "dependencies": [
            {"ref": name, "dependsOn": [] if name == "ordin" else ["ordin"]}
            for name in sorted(identity["packages"])
        ],
    }


def _write(path: Path, value: Any) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n")


def create_bundle_metadata(dist: Path, *, source_root: Path, revision: str, tag: str) -> dict:
    source, records, assets = _validate_assets(dist, source_root, revision)
    if set(path.name for path in dist.iterdir()) != set(assets):
        raise ValueError("bundle metadata requires a fresh artifact-only directory")
    if not isinstance(tag, str) or not re.fullmatch(r"[A-Za-z0-9_./-]{1,128}", tag):
        raise ValueError("invalid bundle tag identity")
    identity = {
        "schema_version": SCHEMA,
        "version": records["ordin"]["version"],
        "revision": revision,
        "tree": source["tree"],
        "tag": tag,
        "packages": records,
        "artifacts": assets,
        "origin_authenticated_by_json": False,
        "publication_authorized_by_json": False,
    }
    _write(dist / "release.json", identity)
    _write(dist / "sbom.cdx.json", _sbom(identity))
    paths = sorted([*assets, "release.json", "sbom.cdx.json"])
    with (dist / "SHA256SUMS").open("x", encoding="ascii", newline="\n") as stream:
        stream.write("".join(f"{_hash(_file(dist / name))}  {name}\n" for name in paths))
    return verify_bundle(
        dist, source_root=source_root, revision=revision, tag=tag, tree=source["tree"]
    )


def verify_bundle(
    dist: Path, *, source_root: Path, revision: str, tag: str | None = None, tree: str | None = None
) -> dict:
    identity = _json(dist / "release.json")
    source, records, assets = _validate_assets(dist, source_root, revision, tree)
    if not isinstance(identity, dict) or identity.get("schema_version") != SCHEMA:
        raise ValueError("current releases require the complete v2 bundle")
    expected = {
        "schema_version": SCHEMA,
        "version": records["ordin"]["version"],
        "revision": revision,
        "tree": source["tree"],
        "tag": tag if tag is not None else identity.get("tag"),
        "packages": records,
        "artifacts": assets,
        "origin_authenticated_by_json": False,
        "publication_authorized_by_json": False,
    }
    if identity != expected:
        raise ValueError("bundle source/package/tag identity mismatch")
    if _json(dist / "sbom.cdx.json") != _sbom(identity):
        raise ValueError("bundle SBOM differs from its verified artifacts")
    indexed = {
        **assets,
        "release.json": _hash(_file(dist / "release.json")),
        "sbom.cdx.json": _hash(_file(dist / "sbom.cdx.json")),
    }
    lines = _file(dist / "SHA256SUMS", MAX_MEMBER_BYTES).decode("ascii").splitlines()
    if lines != [f"{indexed[name]}  {name}" for name in sorted(indexed)]:
        raise ValueError("bundle checksum manifest mismatch")
    if set(path.name for path in dist.iterdir()) - {"provenance.sigstore.json"} != set(indexed) | {
        "SHA256SUMS"
    }:
        raise ValueError("unexpected or missing bundle assets")
    if (dist / "provenance.sigstore.json").exists():
        _file(dist / "provenance.sigstore.json", MAX_MEMBER_BYTES)
    return identity
