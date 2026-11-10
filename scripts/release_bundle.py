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
from pathlib import Path
import re
from email.parser import BytesParser
from typing import Any

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

import importlib.util


def _source_helper():
    spec = importlib.util.spec_from_file_location(
        "_ordin_release_source", Path(__file__).with_name("check_swarm_release.py")
    )
    if spec is None or spec.loader is None:
        raise ValueError("exact release source helper is unavailable")
    module = importlib.util.module_from_spec(spec)
    path = Path(__file__).with_name("check_swarm_release.py")
    exec(compile(path.read_bytes(), str(path), "exec", dont_inherit=True), module.__dict__)
    return module


def git(root, *arguments):
    return _source_helper().git(root, *arguments)


def source_identity(root, revision):
    return _source_helper().source_identity(root, revision)


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
BUILD_SCOPE = "Observed build process only; not bundled runtime dependencies or proof that optional SDK/model extras were installed."


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _archive_reader():
    path = Path(__file__).with_name("_release_archive.py")
    spec = importlib.util.spec_from_file_location("_ordin_release_archives", path)
    if spec is None:
        raise ValueError("exact bounded archive helper is unavailable")
    module = importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes(), str(path), "exec", dont_inherit=True), module.__dict__)
    return module


_ARCHIVES = _archive_reader()


def _file(path: Path, limit: int = MAX_ARCHIVE_BYTES) -> bytes:
    return _ARCHIVES.read_file(path, limit)


def _json(path: Path):
    return _ARCHIVES.read_json(path, MAX_MEMBER_BYTES)


def _path(name: str) -> str:
    return _ARCHIVES.safe_path(name)


def _archive(path: Path, *, wheel: bool, roots: tuple[str, ...] | None = None) -> dict[str, bytes]:
    return _ARCHIVES.read_archive(
        path,
        wheel=wheel,
        roots=roots,
        max_archive_bytes=MAX_ARCHIVE_BYTES,
        max_member_bytes=MAX_MEMBER_BYTES,
        max_members=MAX_MEMBERS,
    )


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
    expected_fields = {
        "Summary": [project["description"]] if project.get("description") else [],
        "Classifier": project.get("classifiers", []),
        "Keywords": [",".join(project["keywords"])] if project.get("keywords") else [],
        "Project-URL": [f"{key}, {value}" for key, value in project.get("urls", {}).items()],
        "Author": [", ".join(item["name"] for item in project["authors"] if "name" in item)]
        if project.get("authors")
        else [],
        "Description-Content-Type": ["text/markdown"]
        if project.get("readme", "").endswith(".md")
        else [],
    }
    for key, expected in expected_fields.items():
        if sorted(metadata.get_all(key, [])) != sorted(expected):
            raise ValueError("release descriptive metadata differs from source")
    allowed = {
        "Metadata-Version",
        "Name",
        "Version",
        "Requires-Python",
        "Requires-Dist",
        "Provides-Extra",
        "License",
        "License-Expression",
        "License-File",
        "Dynamic",
        *expected_fields,
    }
    if any(
        key.lower() not in {item.lower() for item in allowed} for key in metadata.keys()
    ) or metadata.get_all("Metadata-Version") != ["2.4"]:
        raise ValueError("release contains unsupported metadata headers")
    if metadata.get_all("Dynamic", []) not in ([], ["license-file"]):
        raise ValueError("release metadata unexpectedly declares dynamic fields")
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
    if parsed.defaults():
        raise ValueError("release entrypoints cannot inherit implicit defaults")
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
            if path.is_symlink():
                raise ValueError("linked source directories/files cannot enter the bundle")
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
        if (root / "NOTICE").exists() and _file(directory / "NOTICE") != _file(root / "NOTICE"):
            raise ValueError("bundle package notice differs from owned repository attribution")
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
        description = (
            files[prefix + "/METADATA"]
            .replace(b"\r\n", b"\n")
            .partition(b"\n\n")[2]
            .decode("utf-8")
        )
        if (
            description.strip()
            != _file(directory / project["readme"]).decode("utf-8").replace("\r\n", "\n").strip()
        ):
            raise ValueError("wheel description differs from tracked README")
        if sorted(parsed_metadata.get_all("License-File", [])) != sorted(licenses):
            raise ValueError("wheel license metadata inventory differs from source")
        wheel_metadata = BytesParser().parsebytes(files.get(prefix + "/WHEEL", b""))
        if (
            wheel_metadata.get_all("Tag") != ["py3-none-any"]
            or wheel_metadata.get_all("Root-Is-Purelib") != ["true"]
            or wheel_metadata.get_all("Wheel-Version") != ["1.0"]
            or set(wheel_metadata.keys()) - {"Wheel-Version", "Generator", "Root-Is-Purelib", "Tag"}
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
        if source_files["PKG-INFO"].replace(b"\r\n", b"\n") != files[prefix + "/METADATA"].replace(
            b"\r\n", b"\n"
        ):
            raise ValueError("wheel and source distribution metadata differ")
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


def _build_environment(value: Any = None) -> dict:
    if value is None:
        packages = {}
        for installed in importlib.metadata.distributions():
            name = installed.metadata.get("Name", "")
            if name:
                name = canonicalize_name(name)
                if name in packages and packages[name] != installed.version:
                    raise ValueError("observed build environment has ambiguous distributions")
                packages[name] = installed.version
        value = {
            "python": os.sys.version.split()[0],
            "implementation": os.sys.implementation.name,
            "platform": os.sys.platform,
            "packages": packages,
            "scope": BUILD_SCOPE,
            "dependency_security_clearance": "not_established",
        }
    if type(value) is not dict or set(value) != {
        "python",
        "implementation",
        "platform",
        "packages",
        "scope",
        "dependency_security_clearance",
    }:
        raise ValueError("invalid build-only environment record")
    if any(
        type(value[key]) is not str
        or not 1 <= len(value[key]) <= 128
        or any(ord(char) < 32 for char in value[key])
        for key in ("python", "implementation", "platform")
    ):
        raise ValueError("invalid build-only interpreter identity")
    if (
        value["scope"] != BUILD_SCOPE
        or value["dependency_security_clearance"] != "not_established"
        or type(value["packages"]) is not dict
        or len(value["packages"]) > 512
    ):
        raise ValueError("invalid build-only inventory scope or bound")
    for name, version in value["packages"].items():
        if (
            type(name) is not str
            or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,127}", name)
            or canonicalize_name(name) != name
            or type(version) is not str
            or not 1 <= len(version) <= 128
        ):
            raise ValueError("invalid observed build package identity")
        Version(version)
    return value


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
            "tools": {
                "components": [
                    {
                        "type": "library",
                        "name": name,
                        "version": version,
                        "bom-ref": "build-environment:" + name,
                        "scope": "excluded",
                        "properties": [{"name": "ordin:role", "value": BUILD_SCOPE}],
                    }
                    for name, version in sorted(identity["build_environment"]["packages"].items())
                ]
            },
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


def _same_json(actual, expected) -> bool:
    return json.dumps(actual, sort_keys=True, separators=(",", ":"), allow_nan=False) == json.dumps(
        expected, sort_keys=True, separators=(",", ":"), allow_nan=False
    )


def create_bundle_metadata(
    dist: Path, *, source_root: Path, revision: str, tag: str | None = None
) -> dict:
    source, records, assets = _validate_assets(dist, source_root, revision)
    if set(path.name for path in dist.iterdir()) != set(assets):
        raise ValueError("bundle metadata requires a fresh artifact-only directory")
    if tag is not None and (
        not isinstance(tag, str) or not re.fullmatch(r"[A-Za-z0-9_./-]{1,128}", tag)
    ):
        raise ValueError("invalid bundle tag identity")
    identity = {
        "schema_version": SCHEMA,
        "version": records["ordin"]["version"],
        "revision": revision,
        "tree": source["tree"],
        "tag": tag,
        "packages": records,
        "artifacts": assets,
        "build_environment": _build_environment(),
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
    if not isinstance(identity, dict) or identity.get("schema_version") != SCHEMA:
        raise ValueError("current releases require the complete v2 bundle")
    if identity.get("tag") is not None and (
        not isinstance(identity["tag"], str)
        or not re.fullmatch(r"[A-Za-z0-9_./-]{1,128}", identity["tag"])
    ):
        raise ValueError("invalid bundle tag identity")
    source, records, assets = _validate_assets(dist, source_root, revision, tree)
    expected = {
        "schema_version": SCHEMA,
        "version": records["ordin"]["version"],
        "revision": revision,
        "tree": source["tree"],
        "tag": tag,
        "packages": records,
        "artifacts": assets,
        "build_environment": _build_environment(identity.get("build_environment")),
        "origin_authenticated_by_json": False,
        "publication_authorized_by_json": False,
    }
    if not _same_json(identity, expected):
        raise ValueError("bundle source/package/tag identity mismatch")
    if not _same_json(_json(dist / "sbom.cdx.json"), _sbom(identity)):
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
