"""Exact-source and artifact checks refuse hidden execution and stale wheels."""

import subprocess
import io
import tarfile
import os
from pathlib import Path
import zipfile

import pytest

from scripts.check_swarm_release import (
    LOCKS,
    source_identity,
    validate_build_metadata,
    verify_wheels,
    extract_test_fixtures,
    git_environment,
    copy_build_source,
)


def git(root, *args):
    return subprocess.run(
        ["git", "-C", str(root), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def repository(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    git(root, "init", "-q")
    git(root, "config", "user.name", "Synthetic Release Test")
    git(root, "config", "user.email", "fixture@example.invalid")
    git(root, "config", "core.autocrlf", "input")
    (root / ".gitignore").write_text("build/\n__pycache__/\n*.egg-info/\n")
    for name in LOCKS:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# synthetic lock identity\n")
    metadata = '[build-system]\nbuild-backend="setuptools.build_meta"\nrequires=["setuptools>=68"]\n[project]\nname="fixture"\nversion="1"\n'
    for name in ("pyproject.toml", "integrations/swarm/pyproject.toml"):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(metadata)
    (root / "ordin").mkdir()
    (root / "ordin/__init__.py").write_text("# synthetic owned package\n")
    (root / ".gitattributes").write_text("ordin/*.py filter=fixture\n")
    git(root, "add", ".")
    git(
        root,
        "-c",
        "core.hooksPath=" + str(tmp_path / "no-hooks"),
        "commit",
        "-qm",
        "owned source fixture",
    )
    return root, git(root, "rev-parse", "HEAD")


def test_source_identity_binds_exact_clean_commit_tree_and_locks(tmp_path):
    root, revision = repository(tmp_path)
    value = source_identity(root, revision)
    assert value["commit"] == revision and value["tree"] == git(root, "rev-parse", "HEAD^{tree}")
    assert value["clean"] and value["source_bytes_verified"] and not value["git_hooks_executed"]
    assert len(value["code_resource_sha256"]) == 64
    with pytest.raises(ValueError):
        source_identity(root, "HEAD")
    (root / "uncommitted.txt").write_text("owned fixture")
    with pytest.raises(ValueError):
        source_identity(root, revision)


def test_content_filters_are_rejected_before_a_dirty_diff_can_execute_them(tmp_path):
    root, revision = repository(tmp_path)
    marker = tmp_path / "must-not-exist"
    git(root, "config", "filter.fixture.clean", "echo forbidden > " + str(marker))
    (root / "ordin/__init__.py").write_text("# changed fixture\n")
    with pytest.raises(ValueError, match="content filters"):
        source_identity(root, revision)
    assert not marker.exists()


def test_source_probe_disables_repository_fsmonitor_callbacks(tmp_path):
    root, revision = repository(tmp_path)
    marker = tmp_path / "must-not-exist"
    git(root, "config", "core.fsmonitor", "echo forbidden > " + str(marker))
    assert source_identity(root, revision)["commit"] == revision
    assert not marker.exists()


def test_repository_setup_hooks_are_rejected_without_import(tmp_path):
    root, _ = repository(tmp_path)
    validate_build_metadata(root)
    marker = tmp_path / "must-not-exist"
    (root / "setup.py").write_text("raise AssertionError('must not import')\n")
    with pytest.raises(ValueError, match="build hooks"):
        validate_build_metadata(root)
    assert not marker.exists()


def test_build_source_preserves_tracked_bytes_and_excludes_ignored_outputs(tmp_path):
    root, revision = repository(tmp_path)
    for name in ("build/lib/ordin/stale.py", "ordin/__pycache__/__init__.cpython-312.pyc"):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"synthetic untracked build output")
    copied = copy_build_source(root, tmp_path / "private-build-source")
    for name in ("ordin/__init__.py", "pyproject.toml"):
        expected = subprocess.check_output(["git", "-C", str(root), "show", revision + ":" + name])
        assert (copied / name).read_bytes() == expected
    assert not (copied / "build").exists()
    assert not (copied / "ordin/__pycache__").exists()
    assert not (copied / ".git").exists()
    assert git(root, "rev-parse", "HEAD") == revision


def wheels(tmp_path, *, forbidden_dependency=False):
    root = tmp_path / "source"
    directory = tmp_path / "wheels"
    directory.mkdir()
    for name, parent in (("ordin", root), ("ordin_swarm", root / "integrations/swarm")):
        package = parent / name
        package.mkdir(parents=True)
        (package / "__init__.py").write_bytes(b"# exact synthetic bytes\n")
        (parent / "pyproject.toml").write_bytes(b"# owned metadata fixture\n")
        metadata = "Metadata-Version: 2.4\nName: " + name.replace("_", "-") + "\nVersion: 1\n"
        if name == "ordin_swarm":
            metadata += "Requires-Dist: ordin>=0.4\n"
        elif forbidden_dependency:
            metadata += "Requires-Dist: requests\n"
        with zipfile.ZipFile(directory / (name + "-1-py3-none-any.whl"), "w") as archive:
            archive.write(package / "__init__.py", name + "/__init__.py")
            archive.writestr(name + "-1.dist-info/METADATA", metadata)
    for name in LOCKS:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"# owned lock fixture\n")
    git(root, "init", "-q")
    git(root, "config", "user.name", "Owned Wheel Fixture")
    git(root, "config", "user.email", "fixture@example.invalid")
    git(root, "add", ".")
    git(root, "-c", "core.hooksPath=" + os.devnull, "commit", "-qm", "owned wheel source")
    return root, directory


def test_wheel_parity_refuses_a_stale_or_changed_package(tmp_path):
    root, directory = wheels(tmp_path)
    report = verify_wheels(root, directory)
    assert {row["name"] for row in report} == {"ordin", "ordin-swarm"}
    (root / "ordin/__init__.py").write_text("# source changed after wheel build\n")
    with pytest.raises(ValueError, match="source check failed|differs"):
        verify_wheels(root, directory)


def test_core_wheel_cannot_add_a_mandatory_service_or_model_dependency(tmp_path):
    root, directory = wheels(tmp_path, forbidden_dependency=True)
    with pytest.raises(ValueError, match="mandatory"):
        verify_wheels(root, directory)


def test_sanitized_child_environment_preserves_system_home_but_not_provider_secrets(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "SYNTHETIC_NOT_A_REAL_CREDENTIAL")
    original = Path.home()
    settings = git_environment()
    assert "OPENAI_API_KEY" not in settings and "PYTHONPATH" not in settings
    with monkeypatch.context() as patch:
        for name in tuple(os.environ):
            patch.delenv(name, raising=False)
        for name, value in settings.items():
            patch.setenv(name, value)
        assert Path.home() == original


def test_ignored_package_source_cannot_enter_a_release(tmp_path):
    root, _ = repository(tmp_path)
    (root / ".gitignore").write_text("ordin/hidden.py\n")
    git(root, "add", ".gitignore")
    git(
        root,
        "-c",
        "core.hooksPath=" + str(tmp_path / "no-hooks"),
        "commit",
        "-qm",
        "owned ignore fixture",
    )
    (root / "ordin/hidden.py").write_text("# unversioned package payload\n")
    with pytest.raises(ValueError, match="unversioned package"):
        source_identity(root, git(root, "rev-parse", "HEAD"))


def test_unexpected_wheel_code_cannot_borrow_source_parity(tmp_path):
    root, directory = wheels(tmp_path)
    with zipfile.ZipFile(directory / "ordin-1-py3-none-any.whl", "a") as archive:
        archive.writestr("ordin/injected.py", "# unversioned wheel payload\n")
    with pytest.raises(ValueError, match="unexpected package"):
        verify_wheels(root, directory)


@pytest.mark.parametrize("payload", ("injected.pth", "foreign.py", "ordin/../foreign.py"))
def test_extra_wheel_installation_payload_is_rejected_before_install(tmp_path, payload):
    root, directory = wheels(tmp_path)
    with zipfile.ZipFile(directory / "ordin-1-py3-none-any.whl", "a") as archive:
        archive.writestr(payload, "# unversioned installation payload\n")
    with pytest.raises(ValueError, match="top-level payload"):
        verify_wheels(root, directory)


def test_duplicate_wheel_entries_cannot_hide_behind_identical_source_bytes(tmp_path):
    root, directory = wheels(tmp_path)
    with zipfile.ZipFile(directory / "ordin-1-py3-none-any.whl", "a") as archive:
        with pytest.warns(UserWarning, match="Duplicate name"):
            archive.writestr("ordin/__init__.py", (root / "ordin/__init__.py").read_bytes())
    with pytest.raises(ValueError, match="duplicate archive"):
        verify_wheels(root, directory)


@pytest.mark.parametrize("kind", ("traversal", "link", "oversized"))
def test_git_fixture_extraction_refuses_unowned_or_unbounded_entries(tmp_path, kind):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w") as archive:
        member = tarfile.TarInfo("../outside" if kind == "traversal" else "tests/fixture.py")
        if kind == "link":
            member.type = tarfile.SYMTYPE
            member.linkname = "../outside"
        elif kind == "oversized":
            member.size = 2097153
        archive.addfile(member, io.BytesIO(b"x" * member.size) if member.size else None)
    with pytest.raises(ValueError):
        extract_test_fixtures(data.getvalue(), tmp_path / "fixtures")
    assert not (tmp_path / "outside").exists()
