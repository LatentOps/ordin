"""Runtime restart loading verifies protected installation bytes, without execution."""

import hashlib
import json
import os
from pathlib import Path
import sys
import sysconfig
from types import SimpleNamespace

import pytest

from ordin.swarm.confined_tests import (
    PythonRuntimeCatalog,
    _capture,
    _runtime_source,
    _stdlib_curation,
    _stdlib_sources,
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
        "stdlib_curation": _stdlib_curation(Path(sysconfig.get_path("stdlib")).resolve()),
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


def make_alias(alias, target, *, directory=False):
    try:
        alias.symlink_to(target, target_is_directory=directory)
    except OSError as error:
        if os.name == "nt" and getattr(error, "winerror", None) == 1314:
            pytest.skip("Windows account lacks file-symlink privilege")
        raise


def source_fixture(tmp_path):
    root = tmp_path / "trusted-stdlib"
    root.mkdir(mode=0o755)
    (root / "nested").mkdir(mode=0o755)
    target = root / "nested" / "actual.py"
    target.write_bytes(b"VALUE = 'trusted stdlib alias'\n")
    target.chmod(0o644)
    alias = root / "required_module_name.py"
    make_alias(alias, Path("nested") / "actual.py")
    return root, target, alias


def test_contained_stdlib_source_alias_materializes_regular_bytes_under_module_name(tmp_path):
    root, target, alias = source_fixture(tmp_path)
    data = _runtime_source(alias, root, 1024)
    assert data == target.read_bytes() and alias.is_symlink()
    image = tmp_path / "private-image"
    image.mkdir()
    materialized = image / alias.name
    materialized.write_bytes(data)
    records, contents = _capture(image, 8, 1024, ignored=frozenset())
    assert contents == {alias.name: data}
    assert materialized.is_file() and not materialized.is_symlink()
    assert all(kind in {"file", "directory"} for _, kind, _, _ in records)
    # The private image/project capture path still categorically refuses links.
    make_alias(image / "forbidden_alias.py", alias)
    with pytest.raises(ValueError, match="regular"):
        _capture(image, 8, 1024, ignored=frozenset())


def test_stdlib_source_alias_cannot_escape_or_use_a_parent_directory_alias(tmp_path, monkeypatch):
    root, target, alias = source_fixture(tmp_path)
    external = tmp_path / "outside.py"
    external.write_bytes(b"not part of trusted stdlib")
    alias.unlink()
    make_alias(alias, external)

    def no_read(*args):
        pytest.fail("external alias target bytes were read")

    with monkeypatch.context() as selected:
        selected.setattr(os, "read", no_read)
        with pytest.raises(ValueError, match="escapes"):
            _runtime_source(alias, root, 1024)
    parent = root / "directory_alias"
    make_alias(parent, root / "nested", directory=True)
    with pytest.raises((ValueError, OSError)):
        _runtime_source(parent / target.name, root, 1024)


@pytest.mark.parametrize(
    "target", ["nested/../required_module_name.py", "directory_alias/../module.py"]
)
def test_stdlib_source_alias_rejects_raw_parent_traversal_even_if_normalized_path_stays_inside(
    tmp_path, target
):
    root, actual, alias = source_fixture(tmp_path)
    alias.unlink()
    (root / "module.py").write_bytes(b"lexically normalized bytes")
    make_alias(alias, target)
    assert Path(os.path.normpath(root / target)).is_relative_to(root)
    with pytest.raises(ValueError, match="parent traversal"):
        _runtime_source(alias, root, 1024)


@pytest.mark.skipif(os.name != "posix", reason="POSIX symlink-before-dotdot path semantics")
def test_stdlib_source_alias_never_substitutes_lexical_bytes_for_posix_target(tmp_path):
    root, actual, alias = source_fixture(tmp_path)
    deep = root / "nested" / "deep"
    deep.mkdir(mode=0o755)
    (root / "module.py").write_bytes(b"lexically normalized bytes")
    (root / "nested" / "module.py").write_bytes(b"actual POSIX resolution bytes")
    make_alias(root / "directory_alias", deep, directory=True)
    alias.unlink()
    make_alias(alias, "directory_alias/../module.py")
    assert alias.read_bytes() == b"actual POSIX resolution bytes"
    assert (root / "module.py").read_bytes() != alias.read_bytes()
    with pytest.raises(ValueError, match="parent traversal"):
        _runtime_source(alias, root, 1024)


def test_stdlib_source_alias_rejects_raw_parent_traversal_in_later_alias_hops(tmp_path):
    root, actual, alias = source_fixture(tmp_path)
    (root / "module.py").write_bytes(b"lexically normalized bytes")
    second = root / "second_alias.py"
    make_alias(second, "nested/../module.py")
    alias.unlink()
    make_alias(alias, second.name)
    with pytest.raises(ValueError, match="parent traversal"):
        _runtime_source(alias, root, 1024)


@pytest.mark.skipif(os.name != "nt", reason="Windows path/fd ctime meanings differ")
def test_stdlib_source_alias_windows_compares_consistent_descriptor_identity(tmp_path, monkeypatch):
    root, target, alias = source_fixture(tmp_path)
    original = os.fstat

    def changed_time_semantics(descriptor):
        info = original(descriptor)
        fields = {
            key: getattr(info, key)
            for key in (
                "st_dev",
                "st_ino",
                "st_mode",
                "st_uid",
                "st_gid",
                "st_nlink",
                "st_size",
                "st_mtime_ns",
                "st_ctime_ns",
            )
        }
        fields["st_ctime_ns"] += 1000000
        return SimpleNamespace(**fields)

    monkeypatch.setattr(os, "fstat", changed_time_semantics)
    assert _runtime_source(alias, root, 1024) == target.read_bytes()


@pytest.mark.parametrize("mutation", ["alias", "target", "target-before-open"])
def test_stdlib_source_alias_or_target_race_refuses_original_capture(
    tmp_path, monkeypatch, mutation
):
    root, target, alias = source_fixture(tmp_path)
    second = root / "second.py"
    second.write_bytes(b"VALUE = 'changed'\n")
    second.chmod(0o644)
    read, opened = os.read, os.open
    mutated = []

    def mutate():
        if mutated:
            return
        mutated.append(True)
        if mutation == "alias":
            alias.unlink()
            alias.symlink_to(second)
        else:
            target.write_bytes(b"VALUE = 'changed during capture'\n")

    def racing_read(descriptor, maximum):
        part = read(descriptor, maximum)
        mutate()
        return part

    def racing_open(path, flags, *args, **kwargs):
        if str(path) in {target.name, str(target)}:
            mutate()
        return opened(path, flags, *args, **kwargs)

    if mutation == "target-before-open":
        monkeypatch.setattr(os, "open", racing_open)
    else:
        monkeypatch.setattr(os, "read", racing_read)
    with pytest.raises(ValueError, match="changed") as failure:
        _runtime_source(alias, root, 1024)
    assert mutated == [True], str(failure.value)


def test_stdlib_source_alias_retains_byte_and_alias_chain_bounds(tmp_path):
    root, target, alias = source_fixture(tmp_path)
    with pytest.raises(ValueError, match="byte"):
        _runtime_source(alias, root, 1)
    alias.unlink()
    make_alias(alias, alias.name)
    with pytest.raises(ValueError, match="chain"):
        _runtime_source(alias, root, 1024)


@pytest.mark.skipif(os.name != "posix", reason="Unix trusted-source ownership/mode rules")
@pytest.mark.parametrize("change", ["file-mode", "parent-mode", "root-mode"])
def test_stdlib_source_alias_rejects_writable_source_objects(tmp_path, change):
    root, target, alias = source_fixture(tmp_path)
    selected = (
        target if change == "file-mode" else target.parent if change == "parent-mode" else root
    )
    selected.chmod(0o666 if selected.is_file() else 0o777)
    with pytest.raises(ValueError, match="ownership/mode"):
        _runtime_source(alias, root, 1024)


def build_linker_fixture(tmp_path, monkeypatch):
    stdlib = tmp_path / "curated-source"
    stdlib.mkdir(mode=0o755)
    version = f"{sys.version_info.major}.{sys.version_info.minor}"
    config = stdlib / ("config-" + version + "-fixture")
    config.mkdir(mode=0o755)
    (stdlib / "lib-dynload").mkdir(mode=0o755)
    outside = tmp_path / ("libpython" + version + ".so.1")
    outside.write_bytes(b"outside build linker object must never enter image")
    linker = config / ("libpython" + version + ".so")
    make_alias(linker, outside)
    source = stdlib / "actual.py"
    source.write_bytes(b"VALUE = 1\n")
    make_alias(stdlib / "_sysconfigdata_required.py", source.name)
    extension = stdlib / "lib-dynload" / "selected_fixture.so"
    extension.write_bytes(b"selected extension bytes")
    original = sysconfig.get_config_var
    values = {"LIBPL": str(config), "LDVERSION": version, "LDLIBRARY": linker.name}
    monkeypatch.setattr(sysconfig, "get_config_var", lambda name: values.get(name, original(name)))
    return stdlib, config, linker, extension, outside


def test_exact_build_linker_is_excluded_without_following_while_import_modules_remain_selected(
    tmp_path, monkeypatch
):
    stdlib, config, linker, extension, outside = build_linker_fixture(tmp_path, monkeypatch)
    selected = {
        source.relative_to(stdlib).as_posix(): _runtime_source(source, stdlib, 1048576)
        for source in _stdlib_sources(stdlib)
    }
    assert linker.relative_to(stdlib).as_posix() not in selected
    assert selected["lib-dynload/selected_fixture.so"] == b"selected extension bytes"
    assert selected["_sysconfigdata_required.py"] == selected["actual.py"] == b"VALUE = 1\n"
    assert all(value != outside.read_bytes() for value in selected.values())
    assert _stdlib_curation(stdlib) == {
        "policy": "fixed-import-runtime-v1",
        "excluded_build_linker": linker.relative_to(stdlib).as_posix(),
    }


@pytest.mark.parametrize("kind", ["extension", "same-name-in-dynload", "different-ABI-in-config"])
def test_build_linker_exception_never_excludes_a_selected_outside_extension(
    tmp_path, monkeypatch, kind
):
    stdlib, config, linker, extension, outside = build_linker_fixture(tmp_path, monkeypatch)
    if kind == "extension":
        selected = extension
        extension.unlink()
    elif kind == "same-name-in-dynload":
        selected = extension.parent / linker.name
    else:
        selected = config / (linker.stem + "-different.so")
    make_alias(selected, outside)
    assert selected in tuple(_stdlib_sources(stdlib))
    with pytest.raises(ValueError, match="escapes"):
        for source in _stdlib_sources(stdlib):
            _runtime_source(source, stdlib, 1048576)


@pytest.mark.skipif(sys.platform != "linux", reason="full runtime installation is Linux only")
def test_catalog_build_pins_exact_linker_curation_and_materializes_stdlib_module_alias(
    tmp_path, monkeypatch
):
    stdlib, config, linker, extension, outside = build_linker_fixture(tmp_path, monkeypatch)
    original = sysconfig.get_path
    monkeypatch.setattr(
        sysconfig,
        "get_path",
        lambda name, *args, **kwargs: (
            str(stdlib) if name == "stdlib" else original(name, *args, **kwargs)
        ),
    )
    image = tmp_path / "installed-runtime"
    image.mkdir(mode=0o700)
    operator = object()
    catalog = build_python_runtime_catalog(image, operator=operator)
    assert load_python_runtime_catalog(image, operator=operator) == catalog
    assert not (image / "stdlib" / linker.relative_to(stdlib)).exists()
    assert (image / "stdlib/lib-dynload/selected_fixture.so").read_bytes() == extension.read_bytes()
    module = image / "stdlib/_sysconfigdata_required.py"
    assert module.read_bytes() == b"VALUE = 1\n" and not module.is_symlink()
    assert json.loads((image / "catalog.json").read_bytes())["stdlib_curation"] == _stdlib_curation(
        stdlib
    )
