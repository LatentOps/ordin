"""Runtime restart loading verifies protected installation bytes, without execution."""

import hashlib
import json
import os
from pathlib import Path
import sys
import sysconfig

import pytest

from ordin.swarm.confined_tests import (
    PythonRuntimeCatalog,
    _capture,
    _tree_digest,
    build_python_runtime_catalog,
    load_python_runtime_catalog,
)
from ordin.swarm.managed_process import _sha


def fixture_catalog(tmp_path):
    if sys.platform != "linux":
        pytest.skip("private owner/mode/no-follow installation state requires Linux")
    root = tmp_path / "runtime"
    root.mkdir(mode=0o700)
    (root / "stdlib").mkdir(mode=0o700)
    (root / "site").mkdir(mode=0o700)
    (root / "stdlib" / "fixture.py").write_text("VALUE = 1\n")
    interpreter = Path(getattr(sys, "_base_executable", sys.executable)).resolve()
    settings = {
        "interpreter": str(interpreter),
        "interpreter_digest": _sha(interpreter),
        "stdlib_virtual": str(Path(sysconfig.get_path("stdlib")).resolve()),
        "pytest_version": "fixture",
    }
    (root / "catalog.json").write_text(json.dumps(settings))
    for directory, _, files in os.walk(root, topdown=False):
        for name in files:
            (Path(directory) / name).chmod(0o444)
        Path(directory).chmod(0o555)
    records, _ = _capture(root, 4096, 192 * 1048576, ignored=frozenset())
    pin = root.parent / (root.name + ".pinned.json")
    payload = {
        "schema_version": "ordin.python_runtime_catalog.v1",
        "root": str(root),
        "digest": _tree_digest(records),
        **settings,
    }
    pin.write_text(json.dumps(payload))
    pin.chmod(0o600)
    catalog = PythonRuntimeCatalog(
        root,
        payload["digest"],
        interpreter,
        settings["interpreter_digest"],
        settings["stdlib_virtual"],
        "fixture",
    )
    return root, pin, payload, catalog, object()


def test_catalog_restart_reverifies_same_identity_without_rebuild_or_code_execution(tmp_path):
    root, pin, payload, catalog, operator = fixture_catalog(tmp_path)
    original = (pin.stat().st_ino, pin.read_bytes(), (root / "catalog.json").read_bytes())
    first = load_python_runtime_catalog(root, operator=operator)
    second = load_python_runtime_catalog(root, operator=operator)
    assert first == second == catalog and first is not second
    assert original == (pin.stat().st_ino, pin.read_bytes(), (root / "catalog.json").read_bytes())
    assert not (root / "__pycache__").exists()


@pytest.mark.parametrize(
    "mutation",
    [
        "content",
        "extra",
        "cache-extra",
        "link",
        "writable",
        "interpreter",
        "scope",
        "pin-mode",
        "pin-link",
        "missing",
    ],
)
def test_catalog_restart_rejects_tamper_extras_links_and_changed_interpreter(tmp_path, mutation):
    root, pin, payload, catalog, operator = fixture_catalog(tmp_path)
    assert load_python_runtime_catalog(root, operator=operator) == catalog
    if mutation == "content":
        target = root / "stdlib" / "fixture.py"
        target.chmod(0o644)
        target.write_text("VALUE = 2\n")
        target.chmod(0o444)
    elif mutation in {"extra", "cache-extra", "link"}:
        root.chmod(0o755)
        if mutation == "cache-extra":
            target = root / "__pycache__"
            target.mkdir()
            (target / "injected.py").write_text("raise AssertionError('never execute')\n")
            (target / "injected.py").chmod(0o444)
            target.chmod(0o555)
        elif mutation == "link":
            (root / "linked.py").symlink_to(root / "stdlib" / "fixture.py")
        else:
            (root / "extra.py").write_text("raise AssertionError('never execute')\n")
            (root / "extra.py").chmod(0o444)
        root.chmod(0o555)
    elif mutation == "writable":
        (root / "stdlib" / "fixture.py").chmod(0o644)
    elif mutation in {"interpreter", "scope"}:
        if mutation == "interpreter":
            payload["interpreter_digest"] = "0" * 64
        else:
            payload["root"] = str(tmp_path / "foreign")
        pin.write_text(json.dumps(payload))
    elif mutation == "pin-mode":
        pin.chmod(0o644)
    elif mutation == "pin-link":
        original = tmp_path / "saved-pin"
        pin.rename(original)
        pin.symlink_to(original)
    else:
        pin.unlink()
    with pytest.raises((ValueError, OSError)):
        load_python_runtime_catalog(root, operator=operator)


def test_catalog_loader_rejects_duplicate_manifest_fields(tmp_path):
    root, pin, payload, catalog, operator = fixture_catalog(tmp_path)
    data = pin.read_text().rstrip()
    pin.write_text(data[:-1] + ',"digest":"' + "0" * 64 + '"}')
    with pytest.raises(ValueError, match="duplicate"):
        load_python_runtime_catalog(root, operator=operator)


def test_catalog_missing_pin_never_triggers_rebuild(tmp_path, monkeypatch):
    root, pin, payload, catalog, operator = fixture_catalog(tmp_path)
    pin.unlink()

    def forbidden(*args, **kwargs):
        pytest.fail("loading attempted runtime installation")

    monkeypatch.setattr("ordin.swarm.confined_tests.build_python_runtime_catalog", forbidden)
    with pytest.raises(FileNotFoundError):
        load_python_runtime_catalog(root, operator=operator)
    assert not pin.exists()


def test_catalog_build_refuses_existing_pin_before_discovery_or_writes(tmp_path, monkeypatch):
    if sys.platform != "linux":
        pytest.skip("protected Linux installation state")
    root = tmp_path / "runtime"
    root.mkdir(mode=0o700)
    pin = tmp_path / "runtime.pinned.json"
    pin.write_text("original installation identity")
    pin.chmod(0o600)

    def forbidden(*args, **kwargs):
        pytest.fail("existing installation was rediscovered")

    monkeypatch.setattr("ordin.swarm.confined_tests.sysconfig.get_path", forbidden)
    with pytest.raises(ValueError, match="refuse rebuild"):
        build_python_runtime_catalog(root, operator=object())
    assert pin.read_text() == "original installation identity" and list(root.iterdir()) == []


def test_runtime_capture_counts_extra_cache_files(tmp_path):
    root = tmp_path / "tree"
    root.mkdir()
    (root / "__pycache__").mkdir()
    (root / "__pycache__" / "extra.py").write_bytes(b"secret")
    ignored, _ = _capture(root, 8, 30)
    complete, contents = _capture(root, 8, 30, ignored=frozenset())
    assert _tree_digest(ignored) != _tree_digest(complete)
    assert contents == {"__pycache__/extra.py": b"secret"}


@pytest.mark.skipif(sys.platform == "linux", reason="Linux has protected catalogue state")
def test_non_linux_catalog_load_and_build_refuse_without_writes(tmp_path):
    root = tmp_path / "runtime"
    root.mkdir()
    for operation in (build_python_runtime_catalog, load_python_runtime_catalog):
        with pytest.raises(ValueError, match="Linux"):
            operation(root, operator=object())
    assert list(root.iterdir()) == [] and not (tmp_path / "runtime.pinned.json").exists()
