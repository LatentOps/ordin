import json
import os
import sqlite3
from dataclasses import replace

import pytest

from ordin_openshell.correlation import CorrelationBinding, CorrelationStore
from test_compiler import supported_contract
from test_observations import event_fixture, register_event, source_context


def test_atomic_private_bounded_binding_storage_and_round_trip(tmp_path):
    store = CorrelationStore(tmp_path / "mapping.db")
    binding = register_event(store, event_fixture(), supported_contract(), source_context())
    assert store.lookup(binding.event_id_digest) == binding
    assert CorrelationBinding.from_dict(binding.as_dict()) == binding
    assert "command" not in json.dumps(binding.as_dict())
    if os.name == "posix":
        assert store.path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(ValueError, match="duplicate"):
        store.register(binding)
    store.consume(binding)
    with pytest.raises(ValueError, match="duplicate"):
        store.consume(binding)
    with pytest.raises(ValueError, match="duplicate"):
        store.lookup(binding.event_id_digest)


def test_local_checksum_detects_corruption(tmp_path):
    store = CorrelationStore(tmp_path / "mapping.db")
    binding = register_event(store, event_fixture(), supported_contract(), source_context())
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE event_bindings SET payload='{}'")
    with pytest.raises(ValueError, match="corrupt"):
        store.lookup(binding.event_id_digest)


def test_store_capacity_rejects_without_evicting_replay_protection(tmp_path, monkeypatch):
    import ordin_openshell.correlation as module

    monkeypatch.setattr(module, "MAX_BINDINGS", 1)
    store = CorrelationStore(tmp_path / "mapping.db")
    binding = register_event(store, event_fixture(), supported_contract(), source_context())
    with pytest.raises(ValueError, match="capacity"):
        store.register(replace(binding, event_id_digest="c" * 64))
    assert store.lookup(binding.event_id_digest) == binding


@pytest.mark.parametrize(
    "change",
    [
        {"action_digest": "bad"},
        {"event_id_digest": "bad"},
        {"created_ms": True},
        {"expires_ms": 1000},
        {"expires_ms": 100_000_000},
    ],
)
def test_invalid_bindings_fail_before_storage(tmp_path, change):
    binding = register_event(
        CorrelationStore(tmp_path / "mapping.db"),
        event_fixture(),
        supported_contract(),
        source_context(),
    )
    with pytest.raises(ValueError):
        replace(binding, **change)


def test_symlink_database_and_other_database_type_are_rejected(tmp_path):
    from ordin._private_storage import private_database

    other = tmp_path / "other.db"
    with private_database(other, "trace"):
        pass
    store = CorrelationStore(other)
    with pytest.raises(ValueError, match="type mismatch"):
        register_event(store, event_fixture(), supported_contract(), source_context())
    if os.name == "posix":
        link = tmp_path / "link.db"
        link.symlink_to(other)
        with pytest.raises((OSError, ValueError)):
            register_event(
                CorrelationStore(link), event_fixture(), supported_contract(), source_context()
            )
