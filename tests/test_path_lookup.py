"""Per-search directory filtering preserves stdlib resolution and source freshness."""

import json
import os
from pathlib import Path
import shutil

import pytest

from ordin._catalog_snapshot import CatalogChanged
from ordin._path_lookup import _Lookup, batch_path_lookup
from ordin.search import search, search_legacy


def program(path):
    path.write_bytes(b"Owned fixture bytes; this file is never executed.")
    path.chmod(0o755)


@pytest.fixture
def paths(tmp_path, monkeypatch):
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()
    second.mkdir()
    monkeypatch.setenv("PATH", str(first) + os.pathsep + str(second))
    monkeypatch.setenv("PATHEXT", ".EXE;.CMD;.COM")
    monkeypatch.chdir(tmp_path)
    return first, second


def test_literal_names_extensions_shadowing_and_explicit_paths_match_stdlib(paths):
    first, second = paths
    for name in ("alpha", "alpha.exe", "alpha.cmd", "neighbor-alpha.exe", "PrefixCase.EXE"):
        program(second / name)
    program(first / "alpha.exe")
    for command in (
        "alpha",
        "alpha.exe",
        "alpha.cmd",
        "prefixcase",
        "PrefixCase.EXE",
        "absent",
        str(second / "alpha.exe"),
    ):
        lookup = _Lookup()
        assert lookup.which(command) == shutil.which(command)
        lookup.verify()
        lookup.close()


@pytest.mark.parametrize("setting", ["", os.pathsep, "." + os.pathsep, None])
def test_empty_missing_and_cwd_path_forms_preserve_original_behavior(
    tmp_path, monkeypatch, setting
):
    monkeypatch.chdir(tmp_path)
    program(tmp_path / "local.exe")
    if setting is None:
        monkeypatch.delenv("PATH", raising=False)
    else:
        monkeypatch.setenv("PATH", setting)
    lookup = _Lookup()
    assert lookup.which("local") == shutil.which("local")
    lookup.verify()


def test_missing_command_keeps_stdlib_cwd_semantics(paths):
    program(Path.cwd() / "local.exe")
    lookup = _Lookup()
    assert lookup.which("local") == shutil.which("local")
    assert lookup.which("entirely-absent") == shutil.which("entirely-absent")
    lookup.verify()


def test_large_or_unreadable_directory_is_not_filtered(paths, monkeypatch):
    import ordin._path_lookup as module

    first, second = paths
    program(first / "other")
    program(second / "desired.exe")
    monkeypatch.setattr(module, "MAX_DIRECTORY_ENTRIES", 0)
    lookup = _Lookup()
    assert lookup.which("desired") == shutil.which("desired")
    assert all(names is None for names in lookup.index.values())
    lookup.verify()


def test_remote_and_device_namespaces_are_not_enumerated(monkeypatch):
    import ordin._path_lookup as module

    def forbidden(*args, **kwargs):
        raise AssertionError("PATH optimization enumerated a remote/device namespace")

    monkeypatch.setattr(os, "scandir", forbidden)
    assert module._names("//server/share") is None
    assert module._names("\\\\server\\share") is None
    assert module._names("\\\\?\\C:\\protected") is None


def test_new_membership_environment_and_resolver_changes_refuse_result(paths, monkeypatch):
    first, _ = paths
    lookup = _Lookup()
    lookup.which("new-name")
    program(first / "new-name.exe")
    with pytest.raises(CatalogChanged):
        lookup.verify()
    current = _Lookup()
    current.which("new-name")
    monkeypatch.setenv("PATHEXT", ".ALTERED")
    with pytest.raises(CatalogChanged):
        current.verify()
    current = _Lookup()
    monkeypatch.setattr(shutil, "which", lambda *a, **k: None)
    with pytest.raises(CatalogChanged):
        current.verify()


def test_case_only_membership_change_is_detected(paths):
    first, _ = paths
    old = first / "lower.exe"
    program(old)
    lookup = _Lookup()
    lookup.which("lower")
    renamed = first / "temporary.exe"
    old.rename(renamed)
    renamed.rename(first / "LOWER.exe")
    with pytest.raises(CatalogChanged):
        lookup.verify()


def test_decorator_leaves_injected_resolvers_unchanged():
    calls = []

    def injected(command):
        calls.append(command)
        return "explicit-resolution"

    @batch_path_lookup
    def caller(*, which=None):
        return which("configured")

    assert caller(which=injected) == "explicit-resolution"
    assert calls == ["configured"]


def test_result_is_not_cached_between_searches(paths):
    _, second = paths

    @batch_path_lookup
    def caller(*, which=None):
        return which("future")

    assert caller(which=None) is None
    program(second / ("future.exe" if os.name == "nt" else "future"))
    assert caller(which=None) == shutil.which("future")


def test_missing_directory_fallback_remains_fresh_within_search(tmp_path, monkeypatch):
    missing = tmp_path / "missing"
    monkeypatch.setenv("PATH", str(missing))
    lookup = _Lookup()
    assert lookup.which("newtool") is None
    missing.mkdir()
    program(missing / ("newtool.exe" if os.name == "nt" else "newtool"))
    assert lookup.which("newtool") == shutil.which("newtool")
    lookup.verify()


def test_decorated_search_refuses_mutation_before_return(paths, monkeypatch):
    first, _ = paths

    @batch_path_lookup
    def caller(*, which=None):
        result = which("newtool")
        program(first / "newtool.exe")
        return result

    with pytest.raises(CatalogChanged):
        caller(which=None)

    @batch_path_lookup
    def environment_change(*, which=None):
        result = which("newtool")
        monkeypatch.setenv("PATH", str(first))
        return result

    with pytest.raises(CatalogChanged):
        environment_change(which=None)


def test_actual_search_results_equal_injected_stdlib_over_every_safety_query():
    root = Path(__file__).resolve().parents[1]
    rows = [
        json.loads(line)
        for line in (root / "benchmarks/safety.jsonl").read_text(encoding="utf-8").splitlines()
        if line
    ]
    queries = list(
        dict.fromkeys(row.get("intent") or row.get("command") or row.get("tool") for row in rows)
    )
    for query in queries:
        for method in (search, search_legacy):
            original = [item.as_dict() for item in method(query, which=shutil.which)]
            optimized = [item.as_dict() for item in method(query)]
            assert optimized == original
