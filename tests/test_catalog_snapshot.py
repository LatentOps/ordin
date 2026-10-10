"""Snapshot freshness, mutation refusal, ownership and full-fixture parity."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
import json
import os
from pathlib import Path

import pytest

from ordin import ActionEnvelope, AgentGate
from ordin._catalog_snapshot import (
    CatalogChanged,
    catalog_snapshot,
    catalog_exists,
    catalog_paths,
    read_catalog_json,
    _CURRENT,
)


def write(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")


def test_returned_values_do_not_mutate_retained_catalog_and_scope_is_discarded(tmp_path):
    path = tmp_path / "data.json"
    write(path, {"nested": {"enabled": True}})
    with catalog_snapshot():
        state = _CURRENT.get()
        value = read_catalog_json(path)
        value["nested"]["enabled"] = False
        assert read_catalog_json(path)["nested"]["enabled"] is True
    assert state is not None and not state.active and not state.files and not state.anchors
    assert _CURRENT.get() is None
    write(path, {"nested": {"enabled": False}})
    with catalog_snapshot():
        assert read_catalog_json(path)["nested"]["enabled"] is False


def test_equal_size_equal_timestamp_change_still_refuses_result(tmp_path):
    path = tmp_path / "data.json"
    path.write_bytes(b'{"value":1}')
    before = path.stat()
    with pytest.raises(CatalogChanged):
        with catalog_snapshot():
            assert read_catalog_json(path)["value"] == 1
            path.write_bytes(b'{"value":2}')
            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    assert _CURRENT.get() is None
    with catalog_snapshot():
        assert read_catalog_json(path)["value"] == 2


@pytest.mark.parametrize("change", ["remove", "expand", "invalid_json"])
def test_changed_or_removed_source_never_returns_a_success(tmp_path, change):
    path = tmp_path / "data.json"
    path.write_bytes(b'{"value":1}')
    with pytest.raises(CatalogChanged):
        with catalog_snapshot():
            read_catalog_json(path)
            if change == "remove":
                path.unlink()
            else:
                path.write_bytes(b"{" if change == "invalid_json" else b"x" * 600000)


def test_new_pack_manifest_and_command_membership_are_not_ignored(tmp_path):
    pack = tmp_path / "pack"
    pack.mkdir()
    manifest = pack / "pack.json"
    with pytest.raises(CatalogChanged):
        with catalog_snapshot():
            assert not catalog_exists(manifest)
            write(manifest, {"name": "pack"})
            assert not catalog_exists(manifest)
    with pytest.raises(CatalogChanged):
        with catalog_snapshot():
            assert catalog_paths(tmp_path, "json") == ()
            write(tmp_path / "new.json", {})
    with pytest.raises(CatalogChanged):
        with catalog_snapshot():
            catalog_paths(tmp_path, "directories")
            (tmp_path / "other-pack").mkdir()


def test_environment_and_loader_anchor_changes_refuse_review(tmp_path, monkeypatch):
    path = tmp_path / "data.json"
    write(path, {})
    with pytest.raises(CatalogChanged):
        with catalog_snapshot():
            read_catalog_json(path)
            monkeypatch.setenv("ORDIN_PACKS", "deliberate-changed-selection")
    roots = [tmp_path]
    with pytest.raises(CatalogChanged):
        with catalog_snapshot():
            read_catalog_json(path, anchor=lambda: roots[0])
            roots[0] = tmp_path / "other"


def test_copied_thread_context_does_not_reuse_another_review(tmp_path):
    path = tmp_path / "data.json"
    write(path, {"value": 1})

    def child():
        write(path, {"value": 2})
        with catalog_snapshot():
            result = read_catalog_json(path)["value"]
        write(path, {"value": 1})
        return result

    with catalog_snapshot():
        read_catalog_json(path)
        copied = copy_context()
        with ThreadPoolExecutor(max_workers=1) as pool:
            assert pool.submit(copied.run, child).result() == 2
        assert read_catalog_json(path)["value"] == 1


def test_child_async_task_has_independent_snapshot(tmp_path):
    path = tmp_path / "data.json"
    write(path, {"value": 1})

    async def child():
        write(path, {"value": 2})
        with catalog_snapshot():
            result = read_catalog_json(path)["value"]
        write(path, {"value": 1})
        return result

    async def parent():
        with catalog_snapshot():
            read_catalog_json(path)
            assert await asyncio.create_task(child()) == 2
            assert read_catalog_json(path)["value"] == 1

    asyncio.run(parent())


def test_exception_discards_state_and_later_decode_uses_fresh_source(tmp_path):
    path = tmp_path / "data.json"
    path.write_bytes(b"{")
    with pytest.raises(json.JSONDecodeError):
        with catalog_snapshot():
            read_catalog_json(path)
    assert _CURRENT.get() is None
    write(path, {"value": 1})
    with catalog_snapshot():
        assert read_catalog_json(path)["value"] == 1


def test_memory_caps_keep_extra_files_fresh_without_retention(tmp_path, monkeypatch):
    import ordin._catalog_snapshot as module

    monkeypatch.setattr(module, "MAX_FILES", 1)
    first, extra = tmp_path / "first.json", tmp_path / "extra.json"
    write(first, {"value": 1})
    write(extra, {"value": 2})
    with catalog_snapshot():
        read_catalog_json(first)
        read_catalog_json(extra)
        write(extra, {"value": 3})
        assert read_catalog_json(extra)["value"] == 3
        assert len(_CURRENT.get().files) == 1


def test_complete_safety_fixture_reviews_equal_uncached_behavior():
    from ordin.safety_benchmark import load_safety_fixtures

    root = Path(__file__).resolve().parents[1]
    gate = AgentGate()
    fixtures = load_safety_fixtures(root / "benchmarks/safety.jsonl")
    assert len(fixtures) == 34
    for fixture in fixtures:
        action = fixture.build_action()
        history = fixture.build_history()
        with catalog_snapshot(enabled=False):
            baseline = gate.evaluate_action(action, history=history)
        result = gate.evaluate_action(action, history=history)
        assert result.disposition == baseline.disposition
        assert result.review.as_dict() == baseline.review.as_dict()


def test_actual_review_cannot_return_after_catalog_configuration_mutates(monkeypatch):
    from dataclasses import replace
    import ordin.analyzers as module

    original = module._REGISTRY["git"]

    def change_during_analysis(invocation):
        result = original.analyzer(invocation)
        monkeypatch.setenv("ORDIN_PACKS", "")
        return result

    monkeypatch.setitem(module._REGISTRY, "git", replace(original, analyzer=change_during_analysis))
    with pytest.raises(CatalogChanged):
        AgentGate().evaluate_action(ActionEnvelope.shell("git status --short"))
    assert _CURRENT.get() is None
