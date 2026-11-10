"""Exact five-project bundle contracts and adversarial archive controls."""

import base64
import csv
import hashlib
import io
import json
import shutil
from pathlib import Path
import subprocess
import sys
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
            "License: Apache-2.0\nLicense-File: LICENSE\nDescription-Content-Type: text/markdown\n"
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
    identity = create_bundle_metadata(dist, source_root=root, revision=revision)
    assert set(identity["packages"]) == set(PROJECTS) and len(identity["artifacts"]) == 10
    assert identity["tree"] == git(root, "rev-parse", "HEAD^{tree}")
    assert not identity["origin_authenticated_by_json"]
    assert identity["tag"] is None
    assert (
        verify_bundle(dist, source_root=root, revision=revision, tree=identity["tree"]) == identity
    )
    sbom = json.loads((dist / "sbom.cdx.json").read_text())
    assert len(sbom["components"]) == len(sbom["dependencies"]) == 5
    environment = identity["build_environment"]
    assert environment["dependency_security_clearance"] == "not_established"
    assert all(item["scope"] == "excluded" for item in sbom["metadata"]["tools"]["components"])
    assert {item["name"] for item in sbom["metadata"]["tools"]["components"]} == set(
        environment["packages"]
    )
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
        verify_bundle(dist, source_root=root, revision=revision, tag="candidate")


def test_archive_traversal_duplicates_and_links_are_rejected(tmp_path):
    path = tmp_path / "archive.whl"
    for name in ("../foreign", "/absolute", "owned/../foreign", "owned\\foreign", "C:/foreign"):
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr(name, b"foreign")
        if "\\" in name:
            # Windows normalizes writestr input before serialization. Put the
            # unsafe spelling into both raw headers so this tests a real input.
            path.write_bytes(path.read_bytes().replace(b"owned/foreign", b"owned\\foreign"))
        with pytest.raises(ValueError):
            _archive(path, wheel=True)
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("ownedXname", b"foreign")
    path.write_bytes(path.read_bytes().replace(b"ownedXname", b"owned\x00name"))
    with pytest.raises(ValueError):
        _archive(path, wheel=True)
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("owned", b"first")
        with pytest.warns(UserWarning, match="Duplicate name"):
            archive.writestr("owned", b"second")
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


def test_wrong_trusted_version_cannot_create_even_valid_bundle_metadata(tmp_path, monkeypatch):
    from scripts import release_integrity as module

    def forbidden(*args, **kwargs):
        pytest.fail("metadata producer ran before the trusted version comparison")

    monkeypatch.setattr(module, "create_bundle_metadata", forbidden)
    with pytest.raises(ValueError, match="trusted expected version"):
        module.create_metadata(tmp_path, version="9.9.9", revision="a" * 40, tag="v9.9.9")
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "raw",
    [
        b'{"tag":null,"tag":"foreign"}',
        b'{"t\\u0061g":null,"tag":"foreign"}',
        b'{"x":NaN}',
        b'{"x":Infinity}',
        b'{"x":1e999}',
        b'{"x":"\\ud800"}',
        b"[" * 20 + b"0" + b"]" * 20,
    ],
)
def test_manifest_and_sbom_json_reject_ambiguous_nonfinite_and_deep_data(tmp_path, raw):
    from scripts.release_bundle import _json

    for name in ("release.json", "sbom.cdx.json"):
        path = tmp_path / name
        path.write_bytes(raw)
        with pytest.raises(ValueError):
            _json(path)


def test_release_json_and_archives_are_bounded_before_parsing(tmp_path, monkeypatch):
    from scripts import release_bundle as module

    path = tmp_path / "release.json"
    path.write_bytes(b" " * 17)
    monkeypatch.setattr(module, "MAX_MEMBER_BYTES", 16)
    with pytest.raises(ValueError):
        module._json(path)
    path = tmp_path / "oversized.whl"
    path.write_bytes(b"x" * 17)
    monkeypatch.setattr(module, "MAX_ARCHIVE_BYTES", 16)
    with pytest.raises(ValueError):
        module._archive(path, wheel=True)


def test_descriptor_and_path_ctime_are_fenced_within_their_own_stat_apis(tmp_path, monkeypatch):
    from scripts import release_bundle as module
    from types import SimpleNamespace

    path = tmp_path / "owned.bin"
    path.write_bytes(b"owned release bytes")
    fstat = module.os.fstat
    changed = False
    calls = []

    def descriptor_stat(descriptor):
        info = fstat(descriptor)
        fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns")
        values = {key: getattr(info, key) for key in fields}
        calls.append(descriptor)
        values["st_ctime_ns"] = (
            info.st_ctime_ns + 1000 + (1 if changed and len(calls) % 2 == 0 else 0)
        )
        return SimpleNamespace(**values)

    monkeypatch.setattr(module.os, "fstat", descriptor_stat)
    assert module._file(path) == b"owned release bytes"
    changed = True
    with pytest.raises(ValueError, match="changed"):
        module._file(path)


def test_verifier_spec_import_does_not_add_checkout_to_installed_python_path(bundle):
    root, dist, revision = bundle
    create_bundle_metadata(dist, source_root=root, revision=revision)
    script = Path(__file__).resolve().parents[1] / "scripts/release_integrity.py"
    probe = """import importlib.util,pathlib,sys
before=list(sys.path)
spec=importlib.util.spec_from_file_location('owned_release_verifier',sys.argv[1])
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
manifest=module.verify_bundle(pathlib.Path(sys.argv[2]),source_root=pathlib.Path(sys.argv[3]),revision=sys.argv[4])
assert manifest['tag'] is None
assert sys.path==before
assert 'ordin' not in sys.modules
"""
    subprocess.run(
        [sys.executable, "-I", "-B", "-c", probe, str(script), str(dist), str(root), revision],
        cwd=dist,
        check=True,
        timeout=120,
    )


@pytest.mark.parametrize("hook", ["setup.py", "setup.cfg", "backend-path", "dynamic", "cmdclass"])
def test_static_bundle_builder_rejects_tracked_build_hooks_without_execution(bundle, hook):
    root, dist, _ = bundle
    settings = root / "pyproject.toml"
    if hook in {"setup.py", "setup.cfg"}:
        (root / hook).write_text("raise AssertionError('must never execute')\n")
    elif hook == "backend-path":
        settings.write_text(
            settings.read_text().replace("[project]", 'backend-path=["."]\n[project]')
        )
    elif hook == "dynamic":
        settings.write_text(
            settings.read_text().replace("[project]", '[project]\ndynamic=["version"]')
        )
    else:
        settings.write_text(
            settings.read_text() + '\n[tool.setuptools.cmdclass]\nsdist="foreign:code"\n'
        )
    git(root, "add", ".")
    git(
        root,
        "-c",
        "core.hooksPath=" + str(root.parent / "no-hooks"),
        "commit",
        "-qm",
        "owned unsupported build fixture",
    )
    revision = git(root, "rev-parse", "HEAD")
    with pytest.raises(ValueError, match="static setuptools"):
        create_bundle_metadata(dist, source_root=root, revision=revision)


def test_expanded_tar_headers_and_padding_are_bounded_before_parser(tmp_path, monkeypatch):
    from scripts import release_bundle as module

    path = tmp_path / "pax.tar.gz"
    with tarfile.open(path, "w:gz", format=tarfile.PAX_FORMAT) as archive:
        item = tarfile.TarInfo("owned/file")
        item.size = 1
        item.pax_headers = {"comment": "x" * 32768}
        archive.addfile(item, io.BytesIO(b"x"))
    assert path.stat().st_size < 4096
    monkeypatch.setattr(module, "MAX_ARCHIVE_BYTES", 4096)
    monkeypatch.setattr(module, "MAX_MEMBER_BYTES", 1024)
    with pytest.raises(ValueError, match="expanded"):
        module._archive(path, wheel=False)


@pytest.mark.parametrize("format", ["zip", "pax"])
def test_historical_v1_reads_use_the_same_bounded_archive_contract(tmp_path, monkeypatch, format):
    from scripts import release_integrity as module

    version = "0.3.0"
    metadata = b"Metadata-Version: 2.1\nName: ordin\nVersion: 0.3.0\n"
    runtime = b'__version__ = "0.3.0"\n'
    wheel_path = tmp_path / f"ordin-{version}-py3-none-any.whl"
    with zipfile.ZipFile(wheel_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            f"ordin-{version}.dist-info/METADATA",
            metadata + (b"x" * 2048 if format == "zip" else b""),
        )
        archive.writestr("ordin/__init__.py", runtime)
    with tarfile.open(
        tmp_path / f"ordin-{version}.tar.gz", "w:gz", format=tarfile.PAX_FORMAT
    ) as archive:
        for name, raw in (("PKG-INFO", metadata), ("ordin/__init__.py", runtime)):
            item = tarfile.TarInfo(f"ordin-{version}/" + name)
            item.size = len(raw)
            if format == "pax":
                item.pax_headers = {"comment": "x" * 32768}
            archive.addfile(item, io.BytesIO(raw))
    reader = module._bounded_inputs()
    original = reader.read_archive
    reader.read_archive = lambda path, *, wheel: original(
        path, wheel=wheel, max_archive_bytes=4096, max_member_bytes=1024
    )
    monkeypatch.setattr(module, "_bounded_inputs", lambda: reader)
    with pytest.raises(ValueError):
        module.validate_distributions(tmp_path, version)


@pytest.mark.parametrize(
    "name", ["build_release_bundle.py", "release_integrity.py", "check_release_bundle_install.py"]
)
@pytest.mark.parametrize("isolated", [False, True])
def test_release_cli_never_imports_repository_shadow_modules_before_validation(
    tmp_path, name, isolated
):
    source = Path(__file__).resolve().parents[1] / "scripts"
    root = tmp_path / "owned"
    scripts = root / "scripts"
    scripts.mkdir(parents=True)
    for helper in (
        name,
        "release_bundle.py",
        "_release_archive.py",
        "_release_tools.py",
        "check_swarm_release.py",
    ):
        shutil.copyfile(source / helper, scripts / helper)
    marker = tmp_path / "must-not-exist"
    body = f"raise AssertionError('untrusted shadow import')\n"
    # Opening the marker is solely a bounded owned-fixture observation.
    body = f"open({str(marker)!r},'w').write('forbidden')\n" + body
    (scripts / "json.py").write_text(body)
    for module in ("json", "packaging"):
        package = root / module
        package.mkdir()
        (package / "__init__.py").write_text(body)
    if isolated:
        import importlib.util
        import py_compile

        poison = tmp_path / "owned-poison.py"
        poison.write_text(body)
        cache = Path(importlib.util.cache_from_source(str(scripts / "release_bundle.py")))
        cache.parent.mkdir(exist_ok=True)
        py_compile.compile(
            str(poison),
            cfile=str(cache),
            invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
        )
    command = [sys.executable]
    if isolated:
        command += ["-I", "-B"]
    result = subprocess.run(
        [*command, str(scripts / name), "--help"],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert not marker.exists()
    assert result.returncode == (0 if isolated else 1), result.stderr
    if not isolated:
        assert "requires isolated Python" in result.stderr


@pytest.mark.parametrize(
    "left,right",
    [
        ({"flags": [False]}, {"flags": [0]}),
        ({"version": 1}, {"version": True}),
        ({"version": 1}, {"version": 1.0}),
    ],
)
def test_json_identity_comparison_preserves_boolean_and_number_types(left, right):
    from scripts.release_bundle import _same_json

    assert left == right
    assert not _same_json(left, right)
    assert _same_json(left, left)


def test_workflow_passes_candidate_null_and_tagged_identity_through_every_stage():
    workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/release.yml").read_text()
    blocks = {}
    current = None
    for line in workflow.splitlines():
        if line.startswith("      - name: "):
            current = line.split(": ", 1)[1]
            blocks[current] = []
        elif current:
            blocks[current].append(line)
    for label, command, variable in (
        (
            "Build all five source-bound wheel and source distributions",
            "build_release_bundle.py",
            "tag_args",
        ),
        (
            "Verify the complete offline installed bundle",
            "check_release_bundle_install.py",
            "tag_args",
        ),
        (
            "Bind distributions to source and record checksums/SBOM",
            "release_integrity.py",
            "publish_args",
        ),
    ):
        block = "\n".join(blocks[label])
        assert f"{variable}=()" in block
        assert 'if [[ "$GITHUB_EVENT_NAME" == push && "$GITHUB_REF_TYPE" == tag ]]' in block
        assert '--tag "$RELEASE_TAG"' in block
        assert f'"${{{variable}[@]}}"' in block
        assert f"python -I -B scripts/{command}" in block
    assert "python -m twine check dist/*.whl dist/*.tar.gz" in workflow
    assert "python -m twine check dist/*\n" not in workflow


def test_resealed_metadata_cannot_change_boolean_or_sbom_number_types(bundle):
    root, dist, revision = bundle
    create_bundle_metadata(dist, source_root=root, revision=revision)
    originals = {name: (dist / name).read_bytes() for name in ("release.json", "sbom.cdx.json")}
    for name, key, value in (
        ("release.json", "origin_authenticated_by_json", 0),
        ("release.json", "publication_authorized_by_json", 0.0),
        ("sbom.cdx.json", "version", True),
        ("sbom.cdx.json", "version", 1.0),
    ):
        for filename, raw in originals.items():
            (dist / filename).write_bytes(raw)
        payload = json.loads(originals[name])
        payload[key] = value
        (dist / name).write_text(json.dumps(payload))
        assets = sorted(path for path in dist.iterdir() if path.name != "SHA256SUMS")
        (dist / "SHA256SUMS").write_text(
            "".join(
                hashlib.sha256(path.read_bytes()).hexdigest() + "  " + path.name + "\n"
                for path in assets
            )
        )
        with pytest.raises(ValueError):
            verify_bundle(dist, source_root=root, revision=revision)


def test_tagged_bundle_requires_the_explicit_expected_tag(bundle):
    root, dist, revision = bundle
    create_bundle_metadata(dist, source_root=root, revision=revision, tag="v0.4.0")
    with pytest.raises(ValueError, match="identity mismatch"):
        verify_bundle(dist, source_root=root, revision=revision)
    assert verify_bundle(dist, source_root=root, revision=revision, tag="v0.4.0")["tag"] == "v0.4.0"


def test_child_environment_excludes_auth_preloads_and_install_overrides(tmp_path, monkeypatch):
    from scripts._release_tools import child_environment, qualification_environment

    secrets = {
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "PYTHONPATH",
        "PYTHONHOME",
        "LD_PRELOAD",
        "DYLD_INSERT_LIBRARIES",
        "PIP_TARGET",
        "PIP_PREFIX",
        "PIP_USER",
        "PIP_INDEX_URL",
        "_PYPROJECT_HOOKS_BACKEND_PATH",
    }
    for key in secrets:
        monkeypatch.setenv(key, "owned-synthetic-value")
    monkeypatch.setenv("HTTP_PROXY", "http://owned-proxy.invalid:8080")
    result = child_environment(tmp_path)
    assert not (set(result) & secrets)
    assert result["HOME"] == result["USERPROFILE"] == str(tmp_path / "home")
    assert result["TMPDIR"] == str(tmp_path / "tmp")
    assert result["PIP_CONFIG_FILE"] == __import__("os").devnull
    assert (
        result["PIP_NO_INDEX"] == "1" and result["HTTP_PROXY"] == "http://owned-proxy.invalid:8080"
    )
    qualification = qualification_environment()
    assert qualification["GH_TOKEN"] == "owned-synthetic-value"
    assert not (set(qualification) & (secrets - {"GH_TOKEN", "GITHUB_TOKEN"}))


@pytest.mark.parametrize("name", ["git", "gh"])
def test_release_tool_resolution_never_executes_local_workspace_shadows(
    tmp_path, monkeypatch, name
):
    from scripts import _release_tools as tools
    import os

    root = tmp_path / "source"
    root.mkdir()
    (root / (name + (".exe" if os.name == "nt" else ""))).write_bytes(b"")
    monkeypatch.setenv("PATH", str(root))
    monkeypatch.chdir(root)
    with pytest.raises(ValueError, match="trusted absolute"):
        tools.trusted_executable(name, root)
    if name == "git":
        from scripts import check_swarm_release as collector

        monkeypatch.setattr(
            collector.subprocess,
            "run",
            lambda *args, **kwargs: pytest.fail("project Git shadow was invoked"),
        )
        with pytest.raises(ValueError, match="trusted absolute"):
            collector.source_identity(root, "a" * 40)
    else:
        from scripts import release_integrity as integrity

        monkeypatch.setattr(
            integrity.subprocess,
            "check_output",
            lambda *args, **kwargs: pytest.fail("project GH shadow received qualification auth"),
        )
        with pytest.raises(ValueError, match="trusted absolute"):
            integrity._github_pages("LatentOps/ordin", "actions/runs")


def test_installer_venv_child_is_isolated_and_never_receives_ambient_credentials(
    tmp_path, monkeypatch
):
    from scripts import check_release_bundle_install as installer

    source = tmp_path / "source"
    source.mkdir()
    workspace = tmp_path / "work"
    monkeypatch.setenv("GH_TOKEN", "owned-gh-token")
    monkeypatch.setenv("PYTHONPATH", str(source))
    monkeypatch.setattr(installer, "verify_bundle", lambda *args, **kwargs: {"packages": {}})

    class Observed(Exception):
        pass

    def launch(command, **kwargs):
        assert command[1:5] == ["-I", "-B", "-m", "venv"]
        assert kwargs["cwd"] == workspace
        assert "GH_TOKEN" not in kwargs["env"] and "PYTHONPATH" not in kwargs["env"]
        assert kwargs["env"]["HOME"] == str(workspace / "home")
        raise Observed()

    monkeypatch.setattr(installer.subprocess, "run", launch)
    with pytest.raises(Observed):
        installer.check_install(tmp_path, workspace, source_root=source, revision="a" * 40)


@pytest.mark.parametrize("published", [False, True])
def test_integrity_git_children_receive_only_the_sanitized_git_envelope(
    tmp_path, monkeypatch, published
):
    from scripts import release_integrity as module
    from types import SimpleNamespace

    version = "0.4.0" if published else "0.3.0"
    revision = "a" * 40
    (tmp_path / "pyproject.toml").write_text(f'[project]\nversion="{version}"\n')
    (tmp_path / "ordin").mkdir()
    (tmp_path / "ordin/__init__.py").write_text(f'__version__="{version}"\n')
    monkeypatch.chdir(tmp_path)
    for key in ("GH_TOKEN", "OPENAI_API_KEY", "LD_PRELOAD", "GIT_SSH_COMMAND", "GIT_CONFIG_GLOBAL"):
        monkeypatch.setenv(key, "owned-synthetic-value")
    arguments = ["release_integrity.py", "verify", "--revision", revision, "--tag", "v" + version]
    if published:
        arguments.append("--publish")
        monkeypatch.setenv("GITHUB_EVENT_NAME", "push")
        monkeypatch.setenv("GITHUB_REF_TYPE", "tag")
        monkeypatch.setenv("GITHUB_REPOSITORY", "LatentOps/ordin")
    monkeypatch.setattr(module.sys, "argv", arguments)
    monkeypatch.setattr(module, "_trusted_tool", lambda name, *boundaries: "/trusted/" + name)
    monkeypatch.setattr(
        module,
        "_bundle_helper",
        lambda: SimpleNamespace(source_identity=lambda root, expected: {"commit": revision}),
    )
    monkeypatch.setattr(module, "verify_release_checks", lambda *args, **kwargs: None)
    monkeypatch.setattr(module, "verify_metadata", lambda *args, **kwargs: {})
    monkeypatch.setattr(module, "verify_bundle", lambda *args, **kwargs: {})
    calls = []

    def check(command, env):
        assert command[0] == "/trusted/git"
        assert not (set(env) & {"GH_TOKEN", "OPENAI_API_KEY", "LD_PRELOAD", "GIT_SSH_COMMAND"})
        assert env["GIT_CONFIG_GLOBAL"] == __import__("os").devnull
        assert env["GIT_CONFIG_VALUE_1"] == "false"
        calls.append(command[1])

    def output(command, *, text, env):
        check(command, env)
        if command[1] == "rev-parse":
            return revision + "\n"
        if command[1] == "ls-remote":
            return revision + "\trefs/tags/v0.4.0\n"
        return ""

    def run(command, *, env, **kwargs):
        check(command, env)
        return SimpleNamespace(returncode=1 if command[1] == "config" else 0, stdout=b"")

    monkeypatch.setattr(module.subprocess, "check_output", output)
    monkeypatch.setattr(module.subprocess, "run", run)
    module.main()
    assert calls == (
        ["merge-base", "ls-remote"] if published else ["config", "rev-parse", "status"]
    )


@pytest.mark.parametrize("name", ["git", "gh"])
def test_trusted_tool_may_be_under_cwd_when_outside_the_source_workspace(
    tmp_path, monkeypatch, name
):
    from scripts import _release_tools as tools
    import os

    source, binaries = tmp_path / "source", tmp_path / "tools"
    source.mkdir()
    binaries.mkdir()
    executable = binaries / (name + (".exe" if os.name == "nt" else ""))
    executable.write_bytes(b"Owned static fixture; never executed")
    executable.chmod(0o700)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PATH", str(binaries))
    assert tools.trusted_executable(name, source) == str(executable.resolve())
